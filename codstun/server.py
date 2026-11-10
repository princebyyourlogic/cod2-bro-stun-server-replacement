# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""UDP service and packet routing. Requires only Python's standard library."""

import argparse
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import ipaddress
import logging
import selectors
import signal
import socket
import time

from .diagnostics import Events, endpoint
from .relay import Relay
from .protocol import (Address, CHANGE_IP, CHANGE_PORT, INTRO_REQUEST, IP_REQUEST, Listener, Outbound,
                       KEEPALIVE, NAT_REQUEST, ProtocolError, forward_intro,
                       ip_reply, nat_reply, parse_request)

LOG = logging.getLogger("codstun")


@dataclass(frozen=True)
class Node:
    bind_ip: str
    public_ip: str

    def __post_init__(self):
        for name in ("bind_ip", "public_ip"):
            object.__setattr__(self, name, str(ipaddress.IPv4Address(getattr(self, name))))
        public = ipaddress.IPv4Address(self.public_ip)
        if public.is_unspecified or public.is_multicast or str(public) == "255.255.255.255":
            raise ValueError("advertised address must be a unicast IPv4 address")


@dataclass(frozen=True)
class Config:
    nodes: tuple[Node, ...]
    port: int = 2273
    alternate_port: int = 2274
    peer_ttl: float = 120.0
    max_peers: int = 16384
    relay_ports: tuple[int, int] | None = None
    relay_max_clients: int = 64

    def __post_init__(self):
        if len(self.nodes) not in (1, 2):
            raise ValueError("configure one or two server addresses")
        if any(not 1 <= p <= 65535 for p in (self.port, self.alternate_port)):
            raise ValueError("ports must be between 1 and 65535")
        if self.port == self.alternate_port:
            raise ValueError("the two UDP ports must differ")
        if len(self.nodes) == 2:
            if self.nodes[0].public_ip == self.nodes[1].public_ip:
                raise ValueError("two-address mode requires distinct public IPv4 addresses")
            if (self.nodes[0].bind_ip == self.nodes[1].bind_ip or
                    any(n.bind_ip == "0.0.0.0" for n in self.nodes)):
                raise ValueError("two-address mode requires two distinct, explicit bind addresses")
        if self.peer_ttl <= 0 or self.max_peers < 1:
            raise ValueError("peer TTL and capacity must be positive")
        if self.relay_ports is not None:
            lo, hi = self.relay_ports
            if len(self.nodes) != 1:
                raise ValueError("virtual relay mode currently uses one public IPv4 address")
            if not 1 <= lo <= hi <= 65535 or any(lo <= p <= hi for p in (self.port, self.alternate_port)):
                raise ValueError("relay port range must be valid and exclude discovery ports")
            if not 2 <= self.relay_max_clients <= min(256, hi - lo + 1):
                raise ValueError("relay capacity must be 2..256 and fit in the relay port range")

    def advertised(self, listener: tuple[int, int]) -> Address:
        node, port_index = listener
        return Address(self.nodes[node].public_ip, (self.port, self.alternate_port)[port_index])


class Router:
    def __init__(self, config: Config, allocate_relay=None, release_relay=None, events=None):
        self.config = config
        self.events = events or Events()
        self.relay = (Relay(allocate_relay, release_relay, events=self.events,
                            max_clients=config.relay_max_clients)
                      if config.relay_ports is not None else None)
        self.peers: OrderedDict[Address, float] = OrderedDict()
        self.buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self.attempts = OrderedDict()

    def _admit(self, ip: str, now: float) -> bool:
        tokens, last = self.buckets.pop(ip, (100.0, now))
        tokens = min(100.0, tokens + max(0.0, now - last) * 50.0)
        admitted = tokens >= 1.0
        self.buckets[ip] = (tokens - 1.0 if admitted else tokens, now)
        while len(self.buckets) > self.config.max_peers:
            self.buckets.popitem(last=False)
        return admitted

    def _remember(self, address: Address, now: float):
        self.peers.pop(address, None)
        self.peers[address] = now
        while self.peers:
            first, seen = next(iter(self.peers.items()))
            if len(self.peers) <= self.config.max_peers and now - seen <= self.config.peer_ttl:
                break
            self.peers.pop(first)

    def route(self, data: bytes, observed: Address, listener: tuple[int, int],
              now: float | None = None) -> list[Outbound]:
        now = time.monotonic() if now is None else now
        if not self._admit(observed.ip, now):
            return []
        request = parse_request(data)
        self._remember(observed, now)
        node, port_index = listener
        if request.kind == IP_REQUEST:
            advertised = observed
            if self.relay:
                client = self.relay.register(observed, now)
                if client is None:
                    return []
                advertised = client.virtual
            self.events.emit("ip_discovery", observed=endpoint(observed), advertised=endpoint(advertised),
                             mode="relay_virtual" if self.relay else "direct")
            return [Outbound(listener, observed, ip_reply(advertised), "public-address")]
        if request.kind == NAT_REQUEST:
            self.events.emit("nat_request", observed=endpoint(observed), flags=request.flags,
                             listener=list(listener), mode="relay_virtual" if self.relay else "physical")
            if self.relay:
                # In the virtual topology all advertised peers are reachable relay
                # endpoints. The original state machine compares the UDP source
                # port to the alternate field; choosing Q lets a same-socket reply
                # from P finish test 2 even behind strict physical NAT filtering.
                alternate = self.config.advertised((0, 1))
                return [Outbound((0, 0), observed, nat_reply(observed, alternate), "virtual-nat-topology")]
            if request.flags & CHANGE_IP and len(self.config.nodes) == 1:
                # Replying from the same IP here would falsely report Open NAT.
                LOG.debug("withholding change-IP reply in one-address mode")
                return []
            reply_node = node ^ bool(request.flags & CHANGE_IP)
            reply_port = port_index ^ bool(request.flags & CHANGE_PORT)
            alternate_node = node ^ 1 if len(self.config.nodes) == 2 else node
            alternate = self.config.advertised((alternate_node, port_index))
            return [Outbound((reply_node, reply_port), observed,
                             nat_reply(observed, alternate), f"nat-flags-{request.flags}")]
        if request.kind == KEEPALIVE:
            if self.relay:
                self.relay.keepalive(observed, now)
            LOG.debug("keepalive %s:%d", observed.ip, observed.port)
            return []
        if request.kind == INTRO_REQUEST:
            if self.relay:
                return self.relay.introduce(request, observed, now)
            attempt_key = hashlib.blake2s(request.raw, digest_size=8).hexdigest()
            first, _, count = self.attempts.pop(attempt_key, (now, now, 0))
            count += 1
            self.attempts[attempt_key] = first, now, count
            while len(self.attempts) > 1024:
                self.attempts.popitem(last=False)
            fields = dict(attempt=attempt_key, observed=endpoint(observed),
                          advertised=endpoint(request.source), target=endpoint(request.destination),
                          count=count, elapsed_ms=round((now - first) * 1000))
            # This also prevents forwarding arbitrary UDP to unrelated endpoints.
            # Hosts keep the introducer mapping alive with type 0x0e packets.
            if request.source != observed:
                self.events.emit("introduction_blocked", reason="source_mapping_mismatch", **fields)
                LOG.debug("introduction source does not match observed endpoint: %s", observed)
                return []
            destination = request.destination
            if destination is None or destination == observed:
                self.events.emit("introduction_blocked", reason="invalid_target", **fields)
                return []
            seen = self.peers.get(destination)
            if seen is None or now - seen > self.config.peer_ttl:
                self.events.emit("introduction_blocked", reason="target_not_recently_seen", **fields)
                LOG.debug("introduction target has no recent registration: %s", destination)
                return []
            self.events.emit("introduction_forwarded", outcome="direct_reply_unobserved", **fields)
            return [Outbound(listener, destination, forward_intro(request), "peer-introduction")]
        return []

    def tick(self, now=None):
        now = time.monotonic() if now is None else now
        for key, (first, last, count) in list(self.attempts.items()):
            if now - last > 6:
                del self.attempts[key]
                self.events.emit("introduction_observation_ended", attempt=key, count=count,
                                 duration_ms=round((last - first) * 1000), outcome="unobserved")
        return self.relay.tick(now) if self.relay else []


class Server:
    def __init__(self, config: Config):
        self.config = config
        self.selector = selectors.DefaultSelector()
        self.sockets: dict[Listener, socket.socket] = {}
        self.router = Router(config, self.allocate_relay, self.release_relay)
        self.running = False

    def allocate_relay(self, client_id):
        lo, hi = self.config.relay_ports
        node = self.config.nodes[0]
        used = {s.getsockname()[1] for s in self.sockets.values()}
        for port in range(lo, hi + 1):
            if port in used:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((node.bind_ip, port))
                sock.setblocking(False)
                key = ("relay", client_id)
                self.selector.register(sock, selectors.EVENT_READ, key)
            except OSError:
                sock.close()
                continue
            self.sockets[key] = sock
            return Address(node.public_ip, port)
        raise OSError("no free relay port")

    def release_relay(self, client_id):
        sock = self.sockets.pop(("relay", client_id), None)
        if sock:
            self.selector.unregister(sock)
            sock.close()

    def send(self, outbound):
        for reply in outbound:
            self.sockets[reply.listener].sendto(reply.payload, reply.destination.socket_tuple())
            LOG.debug("tx %s:%d via %s reason=%s bytes=%d", reply.destination.ip,
                      reply.destination.port, reply.listener, reply.reason, len(reply.payload))

    def open(self):
        try:
            for i, node in enumerate(self.config.nodes):
                for j, port in enumerate((self.config.port, self.config.alternate_port)):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        sock.bind((node.bind_ip, port))
                        sock.setblocking(False)
                        self.selector.register(sock, selectors.EVENT_READ, (i, j))
                    except BaseException:
                        sock.close()
                        raise
                    self.sockets[i, j] = sock
                    LOG.info("listening %s:%d/udp, advertised %s:%d", node.bind_ip, port,
                             node.public_ip, port)
        except BaseException:
            self.close()
            raise
        if self.router.relay:
            LOG.warning("experimental virtual relay enabled: advertised NAT type describes relay reachability")
        elif len(self.config.nodes) == 1:
            LOG.warning("one-address mode: NAT test 2 will time out; Open NAT cannot be measured")
        return self

    def poll(self, timeout: float = 0.5):
        for key, _ in self.selector.select(timeout):
            sock = key.fileobj
            try:
                # Discovery requests are <=29 bytes; relay datagrams are capped at 2048.
                data, peer = sock.recvfrom(2049)
                observed = Address(peer[0], peer[1])
                LOG.debug("rx %s:%d via %s bytes=%d", *peer, key.data, len(data))
                if key.data[0] == "relay":
                    outbound = self.router.relay.receive(key.data[1], data, observed, time.monotonic())
                else:
                    outbound = self.router.route(data, observed, key.data)
                self.send(outbound)
            except ProtocolError as exc:
                LOG.debug("ignored packet: %s", exc)
            except OSError:
                LOG.exception("UDP operation failed")
        try:
            self.send(self.router.tick())
        except OSError:
            LOG.exception("UDP timer send failed")

    def serve(self):
        self.running = True
        while self.running:
            self.poll()

    def stop(self, *_):
        self.running = False

    def close(self):
        self.running = False
        for sock in self.sockets.values():
            self.selector.unregister(sock)
            sock.close()
        self.sockets.clear()
        self.selector.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0", help="primary local IPv4 address")
    parser.add_argument("--public-ip", required=True, help="primary IPv4 address visible to PS2 clients")
    parser.add_argument("--secondary-bind", help="second local IPv4 address")
    parser.add_argument("--secondary-public-ip", help="second IPv4 address visible to clients")
    parser.add_argument("--port", type=int, default=2273)
    parser.add_argument("--alternate-port", type=int, default=2274)
    parser.add_argument("--relay", action="store_true", help="experimental virtual endpoint relay for unmodified clients")
    parser.add_argument("--relay-ports", default="20000-20199", help="public UDP port range for virtual endpoints")
    parser.add_argument("--relay-max-clients", type=int, default=64)
    parser.add_argument("--event-log", help="append structured observations as JSON lines to this file")
    parser.add_argument("--verbose", action="store_true", help="log routing decisions and byte counts")
    args = parser.parse_args(argv)
    if bool(args.secondary_bind) != bool(args.secondary_public_ip):
        parser.error("--secondary-bind and --secondary-public-ip must be supplied together")
    try:
        nodes = [Node(args.bind, args.public_ip)]
        if args.secondary_bind:
            nodes.append(Node(args.secondary_bind, args.secondary_public_ip))
        relay_ports = None
        if args.relay:
            lo, hi = args.relay_ports.split("-")
            relay_ports = int(lo), int(hi)
        config = Config(tuple(nodes), args.port, args.alternate_port,
                        relay_ports=relay_ports, relay_max_clients=args.relay_max_clients)
    except ValueError as exc:
        parser.error(str(exc))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.event_log:
        try:
            handler = logging.FileHandler(args.event_log)
        except OSError as exc:
            parser.error(str(exc))
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger("codstun.events").addHandler(handler)
    server = Server(config)
    signal.signal(signal.SIGTERM, server.stop)
    signal.signal(signal.SIGINT, server.stop)
    try:
        server.open()
        server.serve()
    except OSError as exc:
        LOG.error("could not start UDP service: %s", exc)
        return 1
    finally:
        server.close()
    return 0
