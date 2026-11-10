# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
from collections import deque
import math
import unittest
from unittest.mock import patch

from codstun.protocol import Address, traversal_packet
from codstun.server import Config, Node, Router
from test_relay import Events, Network, PAYLOAD


class AdaptiveNetwork(Network):
    def __init__(self, modes=("EDM", "EDM", "EDM"), pooled=False):
        super().__init__(modes, pooled)
        self.router = Router(Config((Node("127.0.0.1", self.primary.ip),),
                                    relay_ports=(20000, 20199), relay_max_clients=16,
                                    adaptive_relay=True),
                             lambda i: Address(self.primary.ip, 20000 + i),
                             self.closed.append, self.events)
        self.relay = self.router.relay
        self.clients = []
        self.pending = {}
        self.resolved = {}
        for i in range(len(modes)):
            control = self.outgoing(i, self.primary)
            action = self.router.route(bytes.fromhex("1e000100"), control, (0, 0), now=0)[0]
            assert Address.unpack(action.payload[4:10]) == control
            self.clients.append(self.relay.clients[self.relay.controls[control]])

    def introduction(self, a=0, b=1, now=0):
        source, target = self.clients[a].control, self.clients[b].control
        # Native Moderate/Moderate also sends a direct request before introduction.
        self.outgoing(a, target)
        packet = traversal_packet(10, b + 100, source, target, b"0123456789")
        self.pending[a, b] = b"\x0c" + packet[1:]
        return self.router.route(packet, source, (0, 0), now=now)

    def pump(self, actions, now=0.1, answer_probes=True):
        queue = deque(actions)
        for _ in range(1000):
            if not queue:
                return
            action = queue.popleft()
            source = (self.primary if action.listener == (0, 0)
                      else self.relay.clients[action.listener[1]].virtual)
            if source not in self.allowed.get(action.destination, set()):
                self.blocked.append(action)
                continue
            index = self.owners[action.destination]
            if action.listener == (0, 0):
                target = Address.unpack(action.payload[17:23])
                response = b"\x0c" + action.payload[1:]
                if target in self.relay.virtuals:
                    if answer_probes:
                        observed = self.outgoing(index, target)
                        queue.extend(self.relay.receive(self.relay.virtuals[target], response, observed, now))
                else:
                    observed = self.outgoing(index, target)
                    if observed in self.allowed.get(target, set()):
                        recipient = self.owners[target]
                        if self.pending.get((recipient, index)) == response:
                            del self.pending[recipient, index]
                            self.resolved[recipient, index] = observed
            elif action.payload[0] == 12:
                for key, expected in list(self.pending.items()):
                    if key[0] == index and action.payload == expected:
                        del self.pending[key]
                        self.resolved[key] = source
            else:
                self.received[index].append((source, action.payload))
        raise AssertionError("adaptive network did not quiesce")


class AdaptiveTests(unittest.TestCase):
    def test_one_endpoint_nat_and_real_discovery_keep_clients_distinct(self):
        net = AdaptiveNetwork()
        for client in net.clients:
            for flags in (0, 2):
                packet = bytes.fromhex("14000100") + bytes([flags, 0, 0, 0])
                action = net.router.route(packet, client.control, (0, 0), now=0)[0]
                self.assertEqual(action.listener, (0, 0))
                self.assertEqual(Address.unpack(action.payload[4:10]), client.control)
                self.assertEqual(Address.unpack(action.payload[12:18]), net.primary)
            self.assertEqual(net.router.route(bytes.fromhex("1400010003000000"), client.control,
                                             (0, 0), now=0), [])

    def test_direct_reachable_pair_creates_no_relay_flow_or_offer(self):
        net = AdaptiveNetwork(("EIM", "EIM", "EIM"))
        net.pump(net.introduction())
        self.assertEqual(net.resolved[0, 1], net.clients[1].control)
        net.pump(net.router.tick(now=1.5), now=1.5)
        self.assertFalse(net.relay.flows)
        self.assertFalse(net.router.adaptive.offered_pairs)
        self.assertEqual(net.send(0, 1, PAYLOAD), [])
        self.assertFalse(net.relay.pending)

    def test_strict_filtering_shared_ip_pooling_and_mesh_use_offered_relays(self):
        for modes in (("EDM", "EDM", "EDM"), ("EIM", "EDM", "EDM")):
            for pooled in (False, True):
                with self.subTest(modes=modes, pooled=pooled):
                    net = AdaptiveNetwork(modes, pooled)
                    for a, b in ((0, 1), (0, 2)):
                        net.pump(net.introduction(a, b, now=0))
                        self.assertNotIn((a, b), net.resolved)
                        net.pump(net.introduction(a, b, now=1.1), now=1.2)
                        self.assertEqual(net.resolved[a, b], net.clients[b].virtual)
                        net.pump(net.send(a, b, PAYLOAD, now=1.3), now=1.4)
                        self.assertEqual(net.received[b][-1], (net.clients[a].virtual, PAYLOAD))
                        net.pump(net.send(b, a, PAYLOAD + b"answer", now=1.5), now=1.6)
                        self.assertEqual(net.received[a][-1], (net.clients[b].virtual, PAYLOAD + b"answer"))
                    self.assertEqual(len(net.relay.flows), 2)
                    # A proved socket alone is insufficient: B/C never received
                    # a relay offer, even though A has offered links to both.
                    net.pump(net.relay.prepare_pair(2, 3, 2), now=2.1)
                    self.assertEqual(net.send(1, 2, PAYLOAD, now=2.2), [])

    def test_attempt_capacity_preserves_native_direct_introductions(self):
        net = AdaptiveNetwork()
        with patch("codstun.adaptive.MAX_ATTEMPTS", 1):
            net.introduction(0, 1)
            actions = net.introduction(0, 2)
        self.assertEqual(len(net.router.adaptive.attempts), 1)
        self.assertEqual([a.reason for a in actions], ["adaptive-direct-introduction"])

    def test_early_duplicates_and_silence_do_not_trigger_a_route_offer(self):
        net = AdaptiveNetwork()
        net.pump(net.introduction(), now=0.1)
        net.pump(net.introduction(now=0.2), now=0.3)
        net.pump(net.router.tick(now=1.2), now=1.2)
        self.assertFalse(net.router.adaptive.offered_pairs)
        net.router.tick(now=6.1)
        self.assertFalse(net.router.adaptive.attempts)
        ended = [row for name, row in net.events.rows if name == "adaptive_attempt_ended"]
        self.assertEqual(ended[0]["direct_outcome"], "unobserved")
        self.assertFalse(ended[0]["relay_offered"])

    def test_offer_waits_for_both_nonce_proofs_and_then_runs_from_tick(self):
        net = AdaptiveNetwork()
        net.pump(net.introduction(), answer_probes=False)
        actions = net.introduction(now=1.1)
        self.assertFalse(any(a.reason == "adaptive-relay-resolution" for a in actions))
        self.assertFalse(net.router.adaptive.offered_pairs)
        net.pump(net.router.tick(now=1.2), now=1.3)
        net.pump(net.router.tick(now=1.4), now=1.4)
        self.assertEqual(net.resolved[0, 1], net.clients[1].virtual)

    def test_offers_preserve_signed_bytes_and_are_rate_limited(self):
        net = AdaptiveNetwork()
        net.pump(net.introduction())
        actions = net.introduction(now=1.1)
        offered = [a for a in actions if a.reason == "adaptive-relay-resolution"]
        self.assertEqual(len(offered), 1)
        self.assertEqual(offered[0].payload, net.pending[0, 1])
        self.assertEqual(offered[0].listener, ("relay", net.clients[1].id))
        self.assertFalse(any(a.reason == "adaptive-relay-resolution"
                             for a in net.introduction(now=1.2)))

    def test_later_identical_join_gets_a_fresh_direct_window(self):
        net = AdaptiveNetwork()
        net.pump(net.introduction())
        net.pump(net.introduction(now=1.1), now=1.2)
        actions = net.introduction(now=7)
        self.assertFalse(any(a.reason == "adaptive-relay-resolution" for a in actions))
        self.assertEqual(net.router.adaptive.attempts[1, 2].requests, 1)
        self.assertIsNone(net.relay.mapping(1, 2, 7))
        self.assertIsNone(net.relay.mapping(2, 1, 7))
        self.assertFalse(any(a.reason == "adaptive-relay-resolution"
                             for a in net.introduction(now=8.1)))

    def test_offer_authorization_outlives_attempt_and_expires_with_idle_flow(self):
        net = AdaptiveNetwork()
        net.pump(net.introduction())
        net.pump(net.introduction(now=1.1), now=1.2)
        net.router.tick(now=7)
        net.pump(net.send(0, 1, PAYLOAD, now=100), now=100)
        self.assertTrue(net.router.adaptive.allows(1, 2, 181))
        net.router.route(bytes.fromhex("1e000100"), net.clients[0].control, (0, 0), now=181)
        net.router.route(bytes.fromhex("1e000100"), net.clients[1].control, (0, 0), now=181)
        net.router.tick(now=281)
        self.assertFalse(net.router.adaptive.offered_pairs)

    def test_unregistered_mismatched_expired_and_self_targets_are_blocked(self):
        net = AdaptiveNetwork()
        a, b = net.clients[:2]
        for source, target, observed in ((b.control, a.control, a.control),
                                         (a.control, a.control, a.control),
                                         (a.control, Address("203.0.113.99", 3074), a.control)):
            packet = traversal_packet(10, 1, source, target, b"0123456789")
            self.assertEqual(net.router.route(packet, observed, (0, 0), now=1), [])
        packet = traversal_packet(10, 1, a.control, b.control, b"0123456789")
        self.assertEqual(net.router.route(packet, a.control, (0, 0), now=181), [])

    def test_config_requires_ports_one_node_and_bounded_finite_window(self):
        with self.assertRaises(ValueError):
            Config((Node("127.0.0.1", "192.0.2.10"),), adaptive_relay=True)
        for value in (math.nan, math.inf, 0, 2.1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Config((Node("127.0.0.1", "192.0.2.10"),), direct_window=value)
