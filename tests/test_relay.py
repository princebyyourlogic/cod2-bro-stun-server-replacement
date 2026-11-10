# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
from collections import deque
import unittest

from codstun.protocol import Address, parse_request, traversal_packet
from codstun.relay import Relay, BUFFER_LIFETIME, PROBE_LIFETIME
from codstun.server import Config, Node, Router


class Events:
    def __init__(self):
        self.rows = []

    def emit(self, name, **fields):
        self.rows.append((name, fields))


class Network:
    """Strict UDP filtering and optional per-destination mappings/IP pooling.

    Replies must come from the exact destination contacted on that mapping.
    This models reachability, not PS2 admission. The original handler's echo
    behavior is verified separately by scripts/verify_network.py.
    """

    def __init__(self, modes=("EDM", "EDM", "EDM"), pooled=False):
        self.primary = Address("192.0.2.10", 2273)
        self.modes, self.pooled = modes, pooled
        self.nats = [{} for _ in modes]
        self.allowed = {}
        self.owners = {}
        self.events = Events()
        self.closed = []
        self.relay = Relay(lambda i: Address(self.primary.ip, 20000 + i), self.closed.append,
                           events=self.events, max_clients=16)
        self.clients = []
        self.received = [[] for _ in modes]
        self.blocked = []
        for i in range(len(modes)):
            control = self.outgoing(i, self.primary)
            self.clients.append(self.relay.register(control, 0))

    def outgoing(self, index, destination):
        key = destination if self.modes[index] == "EDM" else None
        if key not in self.nats[index]:
            port = 30000 + index * 1000 + len(self.nats[index])
            ip = "198.51.100.7"
            if self.pooled and destination != self.primary:
                ip = f"203.0.113.{index + 10}"
            self.nats[index][key] = Address(ip, port)
        observed = self.nats[index][key]
        self.allowed.setdefault(observed, set()).add(destination)
        self.owners[observed] = index
        return observed

    def send(self, index, destination_id, data, now=1):
        virtual = self.clients[destination_id].virtual
        observed = self.outgoing(index, virtual)
        return self.relay.receive(self.clients[destination_id].id, data, observed, now)

    def pump(self, actions, now=1.1, answer_probes=True):
        queue = deque(actions)
        steps = 0
        while queue:
            action = queue.popleft()
            steps += 1
            assert steps < 1000
            source = (self.primary if action.listener == (0, 0)
                      else self.relay.clients[action.listener[1]].virtual)
            if source not in self.allowed.get(action.destination, set()):
                self.blocked.append(action)
                continue
            index = self.owners[action.destination]
            if action.listener == (0, 0):
                if not answer_probes:
                    continue
                assert action.payload[0] == 11
                destination = Address.unpack(action.payload[17:23])
                observed = self.outgoing(index, destination)
                response = b"\x0c" + action.payload[1:]
                queue.extend(self.relay.receive(self.relay.virtuals[destination], response, observed, now))
            else:
                self.received[index].append((source, action.payload))


PAYLOAD = b"\x01\x02\x00\x00\x01\x00opaque-handshake"


class RelayTests(unittest.TestCase):
    def test_strict_filtering_destination_dependent_and_shared_ip(self):
        for modes in (("EIM", "EIM", "EIM"), ("EDM", "EIM", "EDM"), ("EDM", "EDM", "EDM")):
            for pooled in (False, True):
                with self.subTest(modes=modes, pooled=pooled):
                    net = Network(modes, pooled)
                    net.pump(net.send(0, 1, PAYLOAD))
                    self.assertEqual(net.received[1], [(net.clients[0].virtual, PAYLOAD)])
                    self.assertEqual(net.received[2], [])
                    reply = b"\x02\x02\x00\x00\x01\x00opaque-answer"
                    net.pump(net.send(1, 0, reply, now=1.2))
                    self.assertEqual(net.received[0], [(net.clients[1].virtual, reply)])
                    self.assertEqual(net.blocked, [])

    def test_mesh_connections_remain_distinct(self):
        net = Network()
        for a, b in ((0, 1), (0, 2), (1, 2), (2, 0), (2, 1), (1, 0)):
            packet = PAYLOAD + bytes([a, b])
            net.pump(net.send(a, b, packet))
            self.assertEqual(net.received[b][-1], (net.clients[a].virtual, packet))
        self.assertEqual(len(net.relay.flows), 3)

    def test_nonce_replay_wrong_port_and_tampering_do_not_register(self):
        net = Network()
        actions = net.send(0, 1, PAYLOAD)
        instruction = actions[0].payload
        reply = b"\x0c" + instruction[1:]
        sender = net.outgoing(0, net.clients[1].virtual)
        self.assertEqual(net.relay.receive(net.clients[2].id, reply, sender, 1.1), [])
        self.assertEqual(net.relay.sources, {})
        corrupted = reply[:4] + bytes([reply[4] ^ 1]) + reply[5:]
        self.assertEqual(net.relay.receive(net.clients[1].id, corrupted, sender, 1.1), [])
        self.assertEqual(net.relay.sources, {})
        net.relay.receive(net.clients[1].id, reply, sender, 1.2)
        self.assertEqual(net.relay.sources[net.clients[1].id, sender], net.clients[0].id)
        self.assertEqual(net.relay.receive(net.clients[1].id, reply, sender, 1.3), [])

    def test_unanswered_probe_is_unknown_not_a_claimed_game_failure(self):
        net = Network()
        net.pump(net.send(0, 1, PAYLOAD), answer_probes=False)
        net.relay.tick(1 + PROBE_LIFETIME + 0.1)
        net.relay.tick(1 + BUFFER_LIFETIME + 0.1)
        self.assertEqual(net.received[1], [])
        rows = [fields for name, fields in net.events.rows if name == "relay_flow_unresolved"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["admission"], "unobserved")

    def test_expiry_closes_sockets_and_all_correlated_state(self):
        net = Network()
        net.pump(net.send(0, 1, PAYLOAD))
        net.relay.tick(1000)
        for name in ("clients", "controls", "virtuals", "mappings", "sources", "probes", "pending", "flows"):
            self.assertFalse(getattr(net.relay, name), name)
        self.assertEqual(sorted(net.closed), [1, 2, 3])

    def test_state_and_datagram_bounds(self):
        net = Network()
        self.assertEqual(net.relay.receive(2, bytes(2049), Address("203.0.113.99", 3000), 1), [])
        for port in range(1000, 1200):
            net.relay.receive(2, PAYLOAD, Address("203.0.113.99", port), (port - 1000) / 10)
        self.assertLessEqual(len(net.relay.pending), 64)
        self.assertLessEqual(len(net.relay.probes), net.relay.max_clients * 4)
        for _ in range(100):
            net.relay.receive(2, PAYLOAD, Address("203.0.113.99", 1000), 30)
        self.assertEqual(len(net.relay.pending[2, Address("203.0.113.99", 1000)].packets), 16)

    def test_signed_introduction_is_preserved_and_returns_through_relay(self):
        net = Network()
        a, b = net.clients[:2]
        raw = traversal_packet(10, 123, a.virtual, b.virtual, b"0123456789")
        actions = net.relay.introduce(parse_request(raw), a.control, 1)
        self.assertEqual(actions[-1].payload, b"\x0b" + raw[1:])
        net.pump(actions)
        self.assertIn((b.virtual, b"\x0c" + raw[1:]), net.received[0])

    def test_source_mapping_can_change_after_new_nonce_proof(self):
        net = Network()
        net.pump(net.send(0, 1, PAYLOAD))
        a, b = net.clients[:2]
        observed = net.outgoing(0, b.virtual)
        net.nats[0][b.virtual] = Address(observed.ip, observed.port + 500)
        net.pump(net.send(0, 1, PAYLOAD + b"rebound", now=2))
        self.assertEqual(net.received[1][-1], (a.virtual, PAYLOAD + b"rebound"))
        self.assertNotIn((b.id, observed), net.relay.sources)

    def test_default_router_observes_attempts_without_claiming_failure(self):
        events = Events()
        router = Router(Config((Node("127.0.0.1", "192.0.2.10"),)), events=events)
        a, b = Address("198.51.100.1", 3074), Address("203.0.113.1", 3074)
        raw = traversal_packet(10, 1, a, b, b"0123456789")
        router.route(raw, a, (0, 0), now=0)
        router.route(raw, a, (0, 0), now=1)
        router.tick(8)
        names = [name for name, _ in events.rows]
        self.assertEqual(names.count("introduction_blocked"), 2)
        self.assertEqual(events.rows[-1][0], "introduction_observation_ended")
        self.assertEqual(events.rows[-1][1]["outcome"], "unobserved")


if __name__ == "__main__":
    unittest.main()
