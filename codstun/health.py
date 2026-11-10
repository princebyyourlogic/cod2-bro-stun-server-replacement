# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Local UDP liveness check; does not reserve a virtual relay endpoint."""

import socket

from .protocol import Address


def check(host="127.0.0.1", port=2273, timeout=2):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(bytes.fromhex("1400010000000000"))
        data = sock.recv(512)
        if (len(data) != 18 or data[:4] != bytes.fromhex("15000100")
                or Address.unpack(data[4:10]).socket_tuple() != sock.getsockname()):
            raise ValueError("unexpected local NAT response")


if __name__ == "__main__":
    try:
        check()
    except (OSError, ValueError):
        raise SystemExit(1)
