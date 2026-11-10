#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Validate relay mapping instructions and NAT policy against the original game."""

from collections import deque
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.verify_game import Game
from codstun.protocol import Address
from codstun.server import Config, Node, Router
from codstun.relay import Relay
from codstun.policy import route


class QuietEvents:
    def emit(self, *_args, **_kwargs):
        pass


def verify_relay(game):
    primary = Address("192.0.2.10", 2273)
    config = Config((Node("127.0.0.1", primary.ip),), relay_ports=(20000, 20199))
    router = Router(config, lambda i: Address(primary.ip, 20000 + i), lambda i: None,
                    events=QuietEvents())
    physical = Address("198.51.100.7", 31001)
    first = router.route(bytes.fromhex("1400010000000000"), physical, (0, 0), now=0)[0]
    game.write(game.OBJ, bytes(96))
    game.write(game.OBJ + 0x1C, primary.pack())
    game.write(game.OBJ + 0x3C, struct.pack("<I", 1))
    game.decode(0x3C4528, first.payload)
    game.write(game.SOURCE, primary.pack())
    game.call(0x3C3CE0, game.OBJ, game.SOURCE, game.REPLY)
    _, packet = game.sent[-1]
    second = router.route(packet, physical, (0, 0), now=0.1)[0]
    assert second.listener == (0, 0)
    game.decode(0x3C4528, second.payload)
    game.call(0x3C3CE0, game.OBJ, game.SOURCE, game.REPLY)
    assert game.u32(game.OBJ + 0x34) == 1
    assert game.u32(game.OBJ + 0x38) == 1
    print("PASS: original NAT state machine accepts one-IP virtual relay topology")

    relay = router.relay
    # Both players share a CGNAT public IP; each destination gets a new port.
    a = relay.register(physical, 0)
    b = relay.register(Address(physical.ip, 31002), 0)
    c = relay.register(Address(physical.ip, 31003), 0)
    controls = {client.control: client for client in (a, b, c)}

    def mapped(client_id, destination_id):
        return Address(physical.ip, 40000 + client_id * 100 + destination_id)

    payload = b"\x01\x02\x00\x00\x01\x00opaque-peer-handshake"
    queue = deque(relay.receive(b.id, payload, mapped(a.id, b.id), 0.2))
    delivered = []
    steps = 0
    while queue:
        action = queue.popleft()
        steps += 1
        assert steps < 100
        if action.listener == (0, 0):
            recipient = controls[action.destination]
            destination, reply = game.answer_introduction(action.payload, primary)
            assert reply == b"\x0c" + action.payload[1:]
            virtual_id = relay.virtuals[destination]
            queue.extend(relay.receive(virtual_id, reply, mapped(recipient.id, virtual_id), 0.3))
        else:
            delivered.append(action)
    assert len(delivered) == 1
    assert delivered[0].listener == ("relay", a.id)
    assert delivered[0].destination == mapped(b.id, a.id)
    assert delivered[0].payload == payload
    response = relay.receive(a.id, b"\x02\x02\x00\x00\x02\x00opaque-peer-reply",
                             mapped(b.id, a.id), 0.4)
    assert len(response) == 1
    assert response[0].listener == ("relay", b.id)
    assert response[0].destination == mapped(a.id, b.id)
    print("PASS: original client answers nonce probes with no pending join")
    print("PASS: shared-IP clients with destination-dependent ports are distinguished by nonce proofs")
    print("PASS: opaque peer packets retain stable virtual sources in both directions")


def verify_policy(game):
    local, remote, handle, state = 0x1020000, 0x1021000, 0x1022000, 0x1023000
    callback, table = 0x1024000, 0x1025000
    success, failure, intro = 0x1026000, 0x1027000, []

    def ret(value):
        game.uc.reg_write(game.reg.UC_MIPS_REG_V0, value)

    def lookup(g):
        g.write(g.r(6), struct.pack("<I", remote)); ret(1)

    def own(g):
        g.write(g.r(5), struct.pack("<I", local)); ret(1)

    results = []
    game.intercepts = {
        0x3C1F18: lookup, 0x3C2150: own,
        0x3C0F60: lambda g: ret(0), 0x3C0F88: lambda g: ret(0),
        0x3A7960: lambda g: ret(1), 0x3A7CF0: lambda g: ret(0),
        0x3A6DF4: lambda g: (intro.append(True), ret(1)),
        success: lambda g: results.append("direct"),
        failure: lambda g: results.append("reject"),
    }
    expected = [["direct", "introducer", "introducer"],
                ["direct", "introducer", "reject"],
                ["direct", "reject", "reject"]]
    game.write(0x51AF60, struct.pack("<I", 0x1030000))
    for own_nat in (1, 2, 3):
        row = []
        for peer_nat in (1, 2, 3):
            game.write(local, bytes(64)); game.write(remote, bytes(64))
            for addr, nat, ip in ((local, own_nat, "198.51.100.7"), (remote, peer_nat, "203.0.113.8")):
                game.write(addr, struct.pack("<I", 1000))
                game.write(addr + 20, Address(ip, 3074).pack())
                game.write(addr + 28, struct.pack("<I", 123))
                game.write(addr + 36, struct.pack("<I", nat))
            game.write(handle, struct.pack("<I", state))
            game.write(state, struct.pack("<I", 1000) + bytes(28))
            game.write(callback, struct.pack("<I", table))
            game.write(table, bytes(32))
            game.write(table + 12, struct.pack("<I", success))
            game.write(table + 20, struct.pack("<I", failure))
            results.clear(); intro.clear()
            game.call(0x3A4994, game.OBJ, handle, callback, 0)
            result = results[-1] if results else "introducer" if intro else "unknown"
            assert result == expected[own_nat - 1][peer_nat - 1], (own_nat, peer_nat, result)
            assert result == route(own_nat, peer_nat)
            row.append(result)
        print(f"PASS: original NAT policy local={own_nat}, peers Open/Moderate/Strict: {','.join(row)}")
    game.intercepts = {}


if __name__ == "__main__":
    binary = sys.argv[1] if len(sys.argv) > 1 else "research/private/MP.BIN"
    game = Game(binary)
    verify_relay(game)
    verify_policy(game)
