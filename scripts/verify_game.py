#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Check the server against the original game's MIPS routines using Unicorn.

Requires a locally extracted MP.BIN and the optional `unicorn` Python package.
No game code or data is embedded in this script.
"""

import argparse
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codstun.protocol import Address, ip_reply, nat_reply, parse_request, forward_intro
from codstun.server import Config, Node, Router

EXPECTED_SHA256 = "94dc5b04d0a2048663fd6aa38adb58af19cfaa336d96da0f8fef8934b57a8338"


class Game:
    OBJ = 0x1000000
    BUF = 0x1001000
    OFFSET = 0x1002000
    SOURCE = 0x1003000
    REPLY = 0x1004000
    SOCKET = 0x1006000
    VTABLE = 0x1007000
    SENDTO = 0x1008000
    END = 0x1010000

    def __init__(self, path):
        import unicorn
        from unicorn import mips_const

        self.uc_module = unicorn
        self.reg = mips_const
        image = Path(path).read_bytes()
        if hashlib.sha256(image).hexdigest() != EXPECTED_SHA256:
            raise ValueError("MP.BIN does not match the analyzed US Collector's Edition build")
        self.uc = unicorn.Uc(unicorn.UC_ARCH_MIPS,
                             unicorn.UC_MODE_MIPS64 | unicorn.UC_MODE_LITTLE_ENDIAN)
        self.uc.ctl_set_cpu_model(mips_const.UC_CPU_MIPS64_MIPS64R2_GENERIC)
        self.uc.mem_map(0x100000, 0x500000)
        self.uc.mem_write(0x100000, image[0x80:0x486F8C])
        self.uc.mem_map(self.OBJ, 0x100000)
        self.sent = []
        self.intercepts = {}
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)

    def r(self, number):
        return self.uc.reg_read(getattr(self.reg, f"UC_MIPS_REG_{number}"))

    def hook(self, uc, address, size, _):
        if address in self.intercepts:
            self.intercepts[address](self)
        elif address == 0x3EC324:  # memcpy, replace PS2-specific optimized assembly
            dest, source, count = (self.r(i) for i in (4, 5, 6))
            uc.mem_write(dest, bytes(uc.mem_read(source, count)))
            uc.reg_write(self.reg.UC_MIPS_REG_V0, dest)
        elif address == 0x3EC4CC:  # memset, same optimized PS2 runtime
            dest, value, count = (self.r(i) for i in (4, 5, 6))
            uc.mem_write(dest, bytes([value & 255]) * count)
            uc.reg_write(self.reg.UC_MIPS_REG_V0, dest)
        elif address in (0x397368, 0x397380):  # logging only
            uc.reg_write(self.reg.UC_MIPS_REG_V0, 0)
        elif address == 0x399090:  # address-to-text formatting used only for logging
            uc.mem_write(self.r(5), b"peer\x00")
            uc.reg_write(self.reg.UC_MIPS_REG_V0, 1)
        elif address in (0x399CE8, self.SENDTO):  # capture socket sendTo instead of doing I/O
            destination = bytes(uc.mem_read(self.r(5), 6))
            payload = bytes(uc.mem_read(self.r(6), self.r(7)))
            self.sent.append((Address.unpack(destination), payload))
            uc.reg_write(self.reg.UC_MIPS_REG_V0, len(payload))
        else:
            return
        uc.reg_write(self.reg.UC_MIPS_REG_PC, self.r(31))

    def answer_introduction(self, packet, source):
        self.write(self.OBJ, bytes(96))
        self.write(self.OBJ + 12, struct.pack("<I", self.SOCKET))
        self.write(self.SOCKET + 4, struct.pack("<I", self.VTABLE))
        self.write(self.VTABLE + 0x28, struct.pack("<h", 0))
        self.write(self.VTABLE + 0x2C, struct.pack("<I", self.SENDTO))
        self.write(self.BUF, packet)
        self.write(self.SOURCE, source.pack())
        before = len(self.sent)
        self.call(0x3A5364, self.OBJ, self.SOURCE, self.BUF, len(packet))
        assert len(self.sent) == before + 1
        return self.sent[-1]

    def call(self, address, *args):
        self.uc.reg_write(self.reg.UC_MIPS_REG_SP, 0x10F0000)
        self.uc.reg_write(self.reg.UC_MIPS_REG_RA, self.END)
        for number, value in enumerate(args, 4):
            self.uc.reg_write(getattr(self.reg, f"UC_MIPS_REG_{number}"), value)
        self.uc.emu_start(address, self.END, count=100000)
        if self.uc.reg_read(self.reg.UC_MIPS_REG_PC) != self.END:
            raise RuntimeError(f"game routine 0x{address:x} exceeded instruction budget")
        return self.uc.reg_read(self.reg.UC_MIPS_REG_V0)

    def write(self, address, data):
        self.uc.mem_write(address, data)

    def read(self, address, length):
        return bytes(self.uc.mem_read(address, length))

    def u32(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def decode(self, routine, packet):
        self.write(self.REPLY, bytes(64))
        self.write(self.BUF, packet)
        self.write(self.OFFSET, bytes(4))
        result = self.call(routine, self.REPLY, self.BUF, len(packet), 0, self.OFFSET)
        assert result == 1, f"game rejected {packet.hex()}"
        assert self.u32(self.OFFSET) == len(packet)


def verify(path):
    game = Game(path)
    observed = Address("198.51.100.7", 31001)
    config = Config((Node("127.0.0.1", "192.0.2.10"), Node("127.0.0.2", "192.0.2.11")))
    router = Router(config)

    # Execute the game's IP request constructor and serializer, not a reimplementation.
    game.call(0x3C4018, game.OBJ)
    game.call(0x3C4030, game.OBJ, game.BUF, 512, 0, game.OFFSET)
    ip_request = game.read(game.BUF, game.u32(game.OFFSET))
    assert ip_request == bytes.fromhex("1e000100")
    response = router.route(ip_request, observed, (0, 0), now=0)[0]
    game.decode(0x3C413C, response.payload)
    assert game.read(game.REPLY + 4, 6) == observed.pack()
    print("PASS: original IP request serializer and IP reply parser")

    # Execute each NAT request serializer and feed server replies into the game's parser.
    for flags in (0, 1, 2, 3):
        game.call(0x3C4318, game.OBJ, flags)
        game.call(0x3C4334, game.OBJ, game.BUF, 512, 0, game.OFFSET)
        packet = game.read(game.BUF, game.u32(game.OFFSET))
        assert packet == bytes.fromhex("14000100") + bytes([flags, 0, 0, 0])
        response = router.route(packet, observed, (0, 0), now=0)[0]
        assert response.listener == (bool(flags & 1), bool(flags & 2))
        game.decode(0x3C4528, response.payload)
        assert game.read(game.REPLY + 4, 6) == observed.pack()
        assert game.read(game.REPLY + 12, 6) == config.advertised((1, 0)).pack()
    print("PASS: all original NAT request serializers and NAT reply parser")

    # Feed a first reply into the real state machine. It must send change-IP+port.
    game.write(game.OBJ, bytes(96))
    game.write(game.OBJ + 0x1C, config.advertised((0, 0)).pack())
    game.write(game.OBJ + 0x3C, struct.pack("<I", 1))
    game.decode(0x3C4528, nat_reply(observed, config.advertised((1, 0))))
    game.write(game.SOURCE, config.advertised((0, 0)).pack())
    game.call(0x3C3CE0, game.OBJ, game.SOURCE, game.REPLY)
    assert game.u32(game.OBJ + 0x3C) == 2
    destination, packet = game.sent[-1]
    assert destination == config.advertised((0, 0))
    assert parse_request(packet).flags == 3
    response = router.route(packet, observed, (0, 0), now=0)[0]
    game.decode(0x3C4528, response.payload)
    game.write(game.SOURCE, config.advertised(response.listener).pack())
    game.call(0x3C3CE0, game.OBJ, game.SOURCE, game.REPLY)
    assert game.u32(game.OBJ + 0x34) == 1  # Open
    assert game.u32(game.OBJ + 0x38) == 1  # Successful
    assert game.u32(game.OBJ + 0x3C) == 4  # Finished
    print("PASS: original NAT state machine reaches Open through two-address routing")

    # Test 3 classifies an unchanged mapping as Moderate and a changed one as Strict.
    for mapping, expected in ((observed, 2), (Address(observed.ip, observed.port + 1), 3)):
        game.write(game.OBJ + 0x3C, struct.pack("<I", 3))
        game.decode(0x3C4528, nat_reply(mapping, config.advertised((0, 0))))
        game.call(0x3C3CE0, game.OBJ, game.SOURCE, game.REPLY)
        assert game.u32(game.OBJ + 0x34) == expected
    print("PASS: original NAT state machine's Moderate and Strict results")

    # Packed traversal parser and serializer must preserve HMAC and both endpoints.
    target = Address("203.0.113.8", 3074)
    intro = b"\x0a\x02\x00" + bytes(range(10)) + struct.pack("<I", 0x12345678)
    intro += observed.pack() + target.pack()
    game.decode(0x3A8160, intro)
    game.call(0x3A8300, game.REPLY, 11)
    game.call(0x3A7FE4, game.REPLY, game.BUF, 512, 0, game.OFFSET)
    forwarded = game.read(game.BUF, game.u32(game.OFFSET))
    assert forward_intro(parse_request(intro)) == forwarded
    print("PASS: original traversal parser and forward serializer preserve signed fields")

    # Execute the host's actual introduction handler, with its socket replaced by a capture.
    game.write(game.OBJ, bytes(96))
    game.write(game.OBJ + 12, struct.pack("<I", game.SOCKET))
    game.write(game.SOCKET + 4, struct.pack("<I", game.VTABLE))
    game.write(game.VTABLE + 0x28, struct.pack("<h", 0))
    game.write(game.VTABLE + 0x2C, struct.pack("<I", game.SENDTO))
    game.write(game.BUF, forwarded)
    game.write(game.SOURCE, config.advertised((0, 0)).pack())
    game.call(0x3A5364, game.OBJ, game.SOURCE, game.BUF, len(forwarded))
    destination, reply = game.sent[-1]
    assert destination == observed
    assert reply == b"\x0c" + intro[1:]
    print("PASS: original host handler sends direct peer reply with unchanged signature")

    # Original IP parser must reject a truncated reply.
    game.write(game.BUF, ip_reply(observed)[:-1])
    assert game.call(0x3C413C, game.REPLY, game.BUF, 11, 0, game.OFFSET) == 0
    print("PASS: original IP parser rejects truncated response")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="research/private/MP.BIN")
    args = parser.parse_args()
    verify(args.binary)
