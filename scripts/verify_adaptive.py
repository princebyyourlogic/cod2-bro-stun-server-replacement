#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Execute original adaptive traversal branches against the production router.

Requires the analyzed private MP.BIN and Unicorn. Crypto, lookup, clock and socket
helpers are substituted. These checks do not establish a full console game join.
"""
from pathlib import Path
import sys, struct, hmac, hashlib
from collections import deque
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.verify_game import Game
from codstun.protocol import Address, parse_request, forward_intro
from codstun.server import Config, Node, Router

def ret(g, n=1):
    g.uc.reg_write(g.reg.UC_MIPS_REG_V0, n)

def context(g):
    g.write(g.OBJ, bytes(96))
    g.write(g.OBJ + 12, struct.pack('<I', g.SOCKET))
    g.write(g.SOCKET + 4, struct.pack('<I', g.VTABLE))
    g.write(g.VTABLE + 40, struct.pack('<h', 0))
    g.write(g.VTABLE + 44, struct.pack('<I', g.SENDTO))

def common(g, where, entries, public, identifier):
    g.write(where, struct.pack('<IIIII', 1000, 0, entries, 1, 1) + public.pack() + bytes(2) + struct.pack('<III', identifier, 1, 2))
    g.write(entries, Address('10.0.0.9', 3074).pack() + bytes(2))

def verify_introduction(g):
    primary = Address('192.0.2.10', 2273)
    a_real, b_real = (Address('198.51.100.7', 41000), Address('203.0.113.9', 41007))
    local, remote, record, handle, callback, table, success = (0x1020000, 0x1021000, 0x1024000, 0x1025000, 0x1026000, 0x1027000, 0x1028000)
    identifier = 12345
    common(g, local, 0x1022000, a_real, 54321)
    common(g, remote, 0x1023000, b_real, identifier)
    context(g)
    g.write(g.OBJ + 4, primary.pack())
    g.write(0x51af60, struct.pack('<I', 0x1030000))
    g.write(record, struct.pack('<IIIIII', handle, callback, 0, 0, 0, 1) + bytes(16))
    key = b'reference-key-for-routing-control-flow'
    crypto_inputs = []

    def mac(x):
        data = struct.pack('<I', x.r(5)) + x.read(x.r(6), 6) + x.read(x.r(7), 6)
        crypto_inputs.append(data)
        x.write(x.r(8), hmac.new(key, data, hashlib.sha1).digest()[:10])
        ret(x)

    def local_lookup(x):
        x.write(x.r(5), struct.pack('<I', local))
        ret(x)

    def remote_lookup(x):
        x.write(x.r(6), struct.pack('<I', remote))
        ret(x)
    g.intercepts = {0x3c1f18: remote_lookup, 0x3c2150: local_lookup, 0x3a7458: mac, 0x3c0f88: lambda x: ret(x)}
    g.call(0x3a6df4, g.OBJ, record)
    sent = g.sent[:]
    assert any((p[:3] == bytes.fromhex('0d0200') and dst == b_real for dst, p in sent))
    native = next((p for dst, p in sent if dst == primary.socket_tuple() or dst == primary))
    assert native[:3] == bytes.fromhex('0a0200') and native[17:23] == a_real.pack() and (native[23:29] == b_real.pack())
    print('PASS: original Moderate/Moderate sender tries the physical peer and requests introduction')
    signed_input = crypto_inputs[-1]
    _, direct_reply = g.answer_introduction(forward_intro(parse_request(native)), primary)
    assert direct_reply == b'\x0c' + native[1:]
    pending = [True]
    accepted = []

    def lookup(x):
        assert g.u32(x.r(5)) == identifier
        if pending[0]:
            x.write(x.r(6), struct.pack('<II', handle, callback) + bytes(24))
            ret(x)
        else:
            ret(x, 0)

    def remove(x):
        pending[0] = False
        ret(x)

    def compare(x):
        ret(x, 0 if x.read(x.r(4), x.r(6)) == x.read(x.r(5), x.r(6)) else 1)
    g.write(callback, struct.pack('<I', table))
    g.write(table, bytes(32))
    g.write(table + 12, struct.pack('<I', success))

    def receive(reply, source):
        context(g)
        g.intercepts = {0x3a7458: mac, 0x3ec290: compare, 0x3a7bd8: lookup, 0x3a7c18: remove, 0x3c0f60: lambda x: ret(x), 0x3a7cf0: lambda x: ret(x), success: lambda x: (accepted.append(source), ret(x))}
        g.write(g.BUF, reply)
        g.write(g.SOURCE, source.pack())
        g.call(0x3a69e8, g.OBJ, 0, g.SOURCE, g.BUF, len(reply))
    g.write(handle, bytes(32))
    receive(direct_reply, b_real)
    assert accepted == [b_real] and g.read(handle + 12, 6) == b_real.pack() and (g.u32(handle + 8) == 3)
    relay_b = Address(primary.ip, 20001)
    receive(b'\x0c' + native[1:], relay_b)
    assert accepted == [b_real] and g.read(handle + 12, 6) == b_real.pack()
    print('PASS: genuine direct reply resolves the real endpoint; late relay echo cannot replace completed traversal')
    pending[0] = True
    accepted.clear()
    g.write(handle, bytes(32))
    receive(b'\x0c' + native[1:], relay_b)
    assert accepted == [relay_b] and g.read(handle + 12, 6) == relay_b.pack() and (g.u32(handle + 8) == 3)
    assert all((data == signed_input for data in crypto_inputs))
    print('PASS: preserved signed introduction echoed from relay source resolves the relay, keeping physical identity fields')
    bad = b'\x0c' + native[1:3] + bytes(10) + native[13:]
    pending[0] = True
    accepted.clear()
    receive(bad, relay_b)
    assert not accepted
    print('PASS: original reply dispatch rejects a bad reference MAC')

    class Quiet:

        def emit(self, *a, **kw):
            pass
    router = Router(Config((Node('127.0.0.1', primary.ip),), relay_ports=(20000, 20199), adaptive_relay=True), lambda i: Address(primary.ip, 19999 + i), lambda i: None, events=Quiet())
    for peer in (a_real, b_real):
        advertised = router.route(bytes.fromhex('1e000100'), peer, (0, 0), now=0)[0]
        assert Address.unpack(advertised.payload[4:10]) == peer
    relay = router.relay
    a, b = (relay.clients[relay.controls[a_real]], relay.clients[relay.controls[b_real]])
    assert b.virtual == relay_b
    controls = {a_real: a, b_real: b}

    def mapped(client, dest):
        return Address(client.control.ip, 45000 + client.id * 100 + dest.id)
    first = router.route(native, a_real, (0, 0), now=0)
    assert any((action.payload == forward_intro(parse_request(native)) for action in first))
    queue = deque((action for action in first if action.reason == 'relay-mapping-probe'))
    while queue:
        action = queue.popleft()
        recipient = controls[action.destination]
        g.intercepts = {}
        target, echo = g.answer_introduction(action.payload, primary)
        dest = relay.clients[relay.virtuals[target]]
        queue.extend(relay.receive(dest.id, echo, mapped(recipient, dest), 0.1))
    assert relay._mapping(a.id, b.id, 0.1) == mapped(a, b)
    assert relay._mapping(b.id, a.id, 0.1) == mapped(b, a)
    payload = bytes.fromhex('010200000100') + b'opaque-peer-transport'
    assert relay.receive(b.id, payload, mapped(a, b), 0.2) == []
    actions = router.route(native, a_real, (0, 0), now=1.1)
    offer = next((action for action in actions if action.reason == 'adaptive-relay-resolution'))
    assert offer.listener == ('relay', b.id) and offer.destination == mapped(a, b)
    assert offer.payload == direct_reply
    pending[0] = True
    accepted.clear()
    g.write(handle, bytes(32))
    receive(offer.payload, b.virtual)
    assert accepted == [b.virtual] and g.read(handle + 12, 6) == b.virtual.pack()
    forwarded = relay.receive(b.id, payload, mapped(a, b), 1.2)
    assert len(forwarded) == 1 and forwarded[0].listener == ('relay', a.id)
    assert forwarded[0].destination == mapped(b, a) and forwarded[0].payload == payload
    print('PASS: existing relay nonce mapping and opaque forwarding work with physical advertised peer identities')
    print('LIMIT: crypto, lookup, and clock helpers substituted; full DTLS, game admission and real consoles remain untested')

def verify_nat(game):
    primary = Address('192.0.2.10', 2273)
    observed = Address('198.51.100.7', 41000)
    router = Router(Config((Node('127.0.0.1', primary.ip),), relay_ports=(20000, 20199), adaptive_relay=True), lambda i: Address(primary.ip, 20000 + i), lambda i: None)
    request = bytes.fromhex('1400010000000000')
    game.write(game.OBJ, bytes(96))
    game.write(game.OBJ + 28, primary.pack())
    game.write(game.OBJ + 60, struct.pack('<I', 1))
    game.decode(0x3c4528, router.route(request, observed, (0, 0), now=0)[0].payload)
    game.write(game.SOURCE, primary.pack())
    game.call(0x3c3ce0, game.OBJ, game.SOURCE, game.REPLY)
    assert game.u32(game.OBJ + 60) == 2
    assert game.sent[-1][0] == primary and parse_request(game.sent[-1][1]).flags == 3
    assert router.route(game.sent[-1][1], observed, (0, 0), now=0.1) == []
    game.call(0x3c3ce0, game.OBJ, game.SOURCE, game.REPLY)
    assert game.u32(game.OBJ + 60) == 2

    def elapsed(g):
        g.uc.reg_write(g.reg.UC_MIPS_REG_F0, struct.unpack('<I', struct.pack('<f', 100.0))[0])

    def noop(g):
        g.uc.reg_write(g.reg.UC_MIPS_REG_V0, 1)
    game.intercepts = {0x39b8bc: elapsed, 0x39b830: noop}
    for _ in range(6):
        game.call(0x3c397c, game.OBJ)
    assert game.u32(game.OBJ + 60) == 3
    game.call(0x3c3b28, game.OBJ)
    destination, request = game.sent[-1]
    assert destination == primary and parse_request(request).flags == 2
    game.decode(0x3c4528, router.route(request, observed, (0, 0), now=3.1)[0].payload)
    game.call(0x3c3ce0, game.OBJ, game.SOURCE, game.REPLY)
    assert game.u32(game.OBJ + 52) == 2
    assert game.u32(game.OBJ + 56) == 1 and game.u32(game.OBJ + 60) == 4
    print('PASS: original client reaches coordinated Moderate through one exact UDP endpoint')
    print('PASS: retries, duplicate stage-1 handling, stage-2 timeout and stage-3 request executed')
    print('PASS: source port never changes, so endpoint-dependent NAT mapping is not correlated by IP')
    print('NAT stage-2 retry delay:', struct.unpack('<f', game.read(0x570ad8, 4))[0])
if __name__ == '__main__':
    binary = sys.argv[1] if len(sys.argv) > 1 else 'research/private/MP.BIN'
    verify_nat(Game(binary))
    verify_introduction(Game(binary))
