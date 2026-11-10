#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Synthetic UDP trial of adaptive traversal; does not complete a game join."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import secrets
import select
import socket
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from codstun.protocol import Address, traversal_packet


class Client:
    def __init__(self, primary, relay_ports, *, direct):
        self.primary, self.relay_ports, self.direct = primary, relay_ports, direct
        self.control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.control.bind(("0.0.0.0", 0))
        self.control.settimeout(3)
        self.peers, self.pending, self.resolved, self.received = {}, {}, {}, []
        try:
            self.control.sendto(bytes.fromhex("1e000100"), primary.socket_tuple())
            data, source = self.control.recvfrom(512)
            if (Address(*source) != primary or len(data) != 12
                    or data[:4] != bytes.fromhex("1f000100")):
                raise ValueError("unexpected discovery response")
            self.identity = Address.unpack(data[4:10])
            if self.is_relay(self.identity):
                raise ValueError("service advertised a virtual endpoint; adaptive mode is not active")
        except BaseException:
            self.close()
            raise

    def is_relay(self, address):
        return address.ip == self.primary.ip and self.relay_ports[0] <= address.port <= self.relay_ports[1]

    def peer(self, address):
        if address not in self.peers:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 0))
            self.peers[address] = sock
        return self.peers[address]

    def sockets(self):
        return [self.control, *self.peers.values()]

    def begin(self, other):
        identifier = int.from_bytes(hashlib.blake2s(other.identity.pack(), digest_size=4).digest(), "little")
        packet = traversal_packet(10, identifier, self.identity, other.identity, secrets.token_bytes(10))
        self.pending[other.identity] = dict(packet=packet, expected=b"\x0c" + packet[1:],
                                            sent=time.monotonic(), sends=1)
        # Native Moderate/Moderate also makes this direct attempt. Its opaque
        # authenticator is not the pending signed introduction's echo value.
        direct = traversal_packet(13, identifier, self.identity, other.identity, bytes(10))
        self.control.sendto(direct, other.identity.socket_tuple())
        self.control.sendto(packet, self.primary.socket_tuple())

    def tick(self, now):
        for pending in self.pending.values():
            if pending["sends"] < 6 and now - pending["sent"] >= 0.5:
                self.control.sendto(pending["packet"], self.primary.socket_tuple())
                pending["sent"], pending["sends"] = now, pending["sends"] + 1

    def receive(self, sock):
        packet, raw_source = sock.recvfrom(2048)
        source = Address(*raw_source)
        if len(packet) == 29 and packet[1:3] == bytes.fromhex("0200"):
            if packet[0] == 12:
                for peer, pending in list(self.pending.items()):
                    if packet == pending["expected"]:
                        self.resolved[peer] = source
                        del self.pending[peer]
                return
            if packet[0] in (11, 13):
                target = Address.unpack(packet[17:23])
                if packet[0] == 11 and source != self.primary:
                    return
                if self.is_relay(target):
                    self.peer(target).sendto(b"\x0c" + packet[1:], target.socket_tuple())
                elif self.direct:
                    self.control.sendto(b"\x0c" + packet[1:], target.socket_tuple())
                return
        self.received.append((packet, source))

    def send(self, target, packet):
        sock = self.peer(target) if self.is_relay(target) else self.control
        sock.sendto(packet, target.socket_tuple())

    def close(self):
        for sock in self.sockets():
            sock.close()


def drive(clients, predicate, timeout):
    deadline = time.monotonic() + timeout
    while not predicate():
        now = time.monotonic()
        if now >= deadline:
            raise TimeoutError("synthetic adaptive trial timed out")
        for client in clients:
            client.tick(now)
        sockets = {sock: client for client in clients for sock in client.sockets()}
        ready, _, _ = select.select(list(sockets), [], [], min(0.05, deadline - now))
        for sock in ready:
            sockets[sock].receive(sock)


def run_trial(host, *, port=2273, relay_ports=(20000, 20199), case="all", timeout=8):
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("timeout must be in (0, 30] seconds")
    primary = Address(socket.gethostbyname(host), port)
    results = {"game_admission": "not_tested"}
    for kind in (("direct", "relay") if case == "all" else (case,)):
        clients = []
        try:
            for _ in range(2 if kind == "direct" else 3):
                clients.append(Client(primary, relay_ports, direct=kind == "direct"))
            a, b = clients[:2]
            for receiver in clients[1:]:
                a.begin(receiver)
                drive(clients, lambda: receiver.identity in a.resolved, timeout)
                route = a.resolved[receiver.identity]
                if a.is_relay(route) != (kind == "relay"):
                    raise ValueError(f"expected {kind} resolution")
                initial = bytes.fromhex("010200000100") + b"adaptive-smoke-init"
                a.send(route, initial)
                drive(clients, lambda: bool(receiver.received), timeout)
                payload, source = receiver.received.pop(0)
                if payload != initial or receiver.is_relay(source) != (kind == "relay"):
                    raise ValueError("incorrect peer source or rewritten payload")
                answer = bytes.fromhex("020200000200") + b"adaptive-smoke-answer"
                receiver.send(source, answer)
                drive(clients, lambda: bool(a.received), timeout)
                payload, response_source = a.received.pop(0)
                if payload != answer or response_source != route:
                    raise ValueError("incorrect reply source or rewritten reply payload")
            results[kind] = "passed"
            if kind == "relay":
                results["mesh"] = "passed"
        finally:
            for client in clients:
                client.close()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=2273)
    parser.add_argument("--relay-ports", default="20000-20199")
    parser.add_argument("--case", choices=("all", "direct", "relay"), default="all",
                        help="direct case needs a working peer/hairpin path; relay case blocks it synthetically")
    parser.add_argument("--timeout", type=float, default=8)
    args = parser.parse_args()
    try:
        low, high = map(int, args.relay_ports.split("-"))
        if not 1 <= low <= high <= 65535:
            raise ValueError("invalid relay port range")
        result = run_trial(args.host, port=args.port, relay_ports=(low, high), case=args.case,
                           timeout=args.timeout)
    except (OSError, ValueError, TimeoutError) as error:
        parser.exit(1, f"Adaptive trial failed: {error}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
