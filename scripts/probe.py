#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Exercise a hosted COD: Big Red One NAT service from a separate machine."""

import argparse
from pathlib import Path
import socket
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from codstun.protocol import Address


def exchange(sock, packet, destination, timeout, kind):
    for _ in range(2):
        sock.sendto(packet, destination.socket_tuple())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                data, source = sock.recvfrom(512)
            except socket.timeout:
                break
            expected_length = 12 if kind == 31 else 18
            if len(data) == expected_length and data[:4] == bytes([kind, 0, 1, 0]):
                return data, Address(*source)
    raise TimeoutError(f"no type 0x{kind:02x} reply from {destination.ip}:{destination.port}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="server IP or redirected hostname")
    parser.add_argument("--port", type=int, default=2273)
    parser.add_argument("--timeout", type=float, default=2)
    parser.add_argument("--relay", action="store_true", help="expect the virtual relay topology")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    primary = Address(socket.gethostbyname(args.host), args.port)
    print(f"Server: {args.host} -> {primary.ip}:{primary.port}/udp")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        reply, source = exchange(sock, bytes.fromhex("1e000100"), primary, args.timeout, 31)
        if source != primary:
            raise ValueError(f"IP discovery replied from unexpected endpoint {source}")
        public = Address.unpack(reply[4:10])
        print(f"IP discovery: {public.ip}:{public.port}")
    # Like the game, use a separate socket for NAT type discovery.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        reply, source = exchange(sock, bytes.fromhex("1400010000000000"), primary, args.timeout, 21)
        if source != primary:
            raise ValueError(f"NAT test 1 replied from unexpected endpoint {source}")
        mapped = Address.unpack(reply[4:10])
        alternate = Address.unpack(reply[12:18])
        print(f"NAT test 1: mapping {mapped.ip}:{mapped.port}, alternate {alternate.ip}:{alternate.port}")
        try:
            reply, source = exchange(sock, bytes.fromhex("1400010003000000"), primary, args.timeout, 21)
            if source.ip != alternate.ip or source.port == alternate.port:
                raise ValueError(f"NAT test 2 replied from incorrect endpoint {source}")
            if alternate.ip == primary.ip and not args.relay:
                raise ValueError("NAT test 2 requires a different public server IP")
            if args.relay:
                print("Virtual relay topology accepted: Open describes the advertised relay endpoints.")
                print("This probe does not establish a real game join or identify your physical NAT type.")
                return 0
            print(f"NAT test 2: reply from {source.ip}:{source.port}; this client would report Open")
            return 0
        except TimeoutError:
            print("NAT test 2: no reply (expected in one-address mode, or client NAT filtered it)")
        reply, source = exchange(sock, bytes.fromhex("1400010002000000"), alternate, args.timeout, 21)
        if source.ip != alternate.ip or source.port == alternate.port:
            raise ValueError(f"NAT test 3 replied from incorrect endpoint {source}")
        mapped_again = Address.unpack(reply[4:10])
        classification = "Moderate" if mapped_again == mapped else "Strict"
        print(f"NAT test 3: reply from {source.ip}:{source.port}; this client would report {classification}")
        if alternate.ip == primary.ip:
            print("One-address mode cannot measure filtering or mapping changes between server IPs.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TimeoutError, ValueError) as exc:
        print(f"Probe failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
