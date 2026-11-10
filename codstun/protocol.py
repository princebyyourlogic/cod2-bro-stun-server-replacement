# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Wire formats recovered from SLUS_213.18's MP.BIN. See docs/protocol.md."""

from dataclasses import dataclass
import ipaddress
import struct


IP_REQUEST = 0x1E
IP_REPLY = 0x1F
NAT_REQUEST = 0x14
NAT_REPLY = 0x15
INTRO_REQUEST = 0x0A
INTRO_FORWARD = 0x0B
KEEPALIVE = 0x0E
INTRO_REPLY = 0x0C
CHANGE_IP = 1
CHANGE_PORT = 2

# Discovery sockets use (node, port_index); virtual relay sockets use ("relay", id).
Listener = tuple[int | str, int]


class ProtocolError(ValueError):
    """A datagram is not one of the supported game requests."""


@dataclass(frozen=True)
class Address:
    ip: str
    port: int

    def __post_init__(self):
        object.__setattr__(self, "ip", str(ipaddress.IPv4Address(self.ip)))
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be between 0 and 65535")

    def pack(self) -> bytes:
        # bdSockAddr writes the IPv4 bytes directly, then a host-order uint16.
        return ipaddress.IPv4Address(self.ip).packed + struct.pack("<H", self.port)

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) != 6:
            raise ProtocolError("a socket address must contain six bytes")
        return cls(str(ipaddress.IPv4Address(data[:4])), struct.unpack("<H", data[4:])[0])

    def socket_tuple(self):
        return self.ip, self.port


@dataclass(frozen=True)
class Request:
    kind: int
    flags: int = 0
    source: Address | None = None
    destination: Address | None = None
    raw: bytes = b""


@dataclass(frozen=True)
class Outbound:
    listener: Listener
    destination: Address
    payload: bytes
    reason: str


def traversal_packet(kind: int, identifier: int, source: Address,
                     destination: Address, authenticator: bytes) -> bytes:
    if len(authenticator) != 10:
        raise ValueError("traversal authenticator must contain ten bytes")
    return (bytes([kind, 2, 0]) + authenticator + struct.pack("<I", identifier)
            + source.pack() + destination.pack())


def parse_request(data: bytes) -> Request:
    if not data:
        raise ProtocolError("empty datagram")
    kind = data[0]
    if kind in (IP_REQUEST, NAT_REQUEST):
        size = 4 if kind == IP_REQUEST else 8
        if len(data) != size or data[2:4] != b"\x01\x00":
            raise ProtocolError("expected a padded version 1 discovery request")
        # The game leaves IP-request padding uninitialized; do not validate it.
        flags = data[4] if kind == NAT_REQUEST else 0
        if flags & ~3:
            raise ProtocolError("unsupported NAT change flags")
        return Request(kind=kind, flags=flags, raw=data)
    if kind in (INTRO_REQUEST, KEEPALIVE):
        # Traversal uses a packed version 2 header, unlike discovery's v1 header.
        if len(data) != 29 or data[1:3] != b"\x02\x00":
            raise ProtocolError("expected a packed version 2 traversal request")
        return Request(kind=kind, source=Address.unpack(data[17:23]),
                       destination=Address.unpack(data[23:29]), raw=data)
    raise ProtocolError(f"unsupported packet type 0x{kind:02x}")


def ip_reply(observed: Address) -> bytes:
    return b"\x1f\x00\x01\x00" + observed.pack() + b"\x00\x00"


def nat_reply(observed: Address, alternate: Address) -> bytes:
    return b"\x15\x00\x01\x00" + observed.pack() + b"\x00\x00" + alternate.pack()


def forward_intro(request: Request) -> bytes:
    if request.kind != INTRO_REQUEST:
        raise ProtocolError("only introduction requests can be forwarded")
    # The consoles authenticate ID + both addresses. Preserve all those bytes.
    return bytes([INTRO_FORWARD]) + request.raw[1:]
