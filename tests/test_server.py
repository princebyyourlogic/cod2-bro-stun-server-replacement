# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from codstun.protocol import (Address, ProtocolError, forward_intro, ip_reply,
                              nat_reply, parse_request)
from codstun.server import Config, Node, Router, Server


IP_REQUEST = bytes.fromhex("1e000100")
NAT_REQUEST = bytes.fromhex("1400010000000000")


def traversal(kind, source, destination, tag=b"0123456789"):
    return bytes([kind, 2, 0]) + tag + struct.pack("<I", 0x12345678) + source.pack() + destination.pack()


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.config = Config((Node("127.0.0.1", "192.0.2.10"), Node("127.0.0.2", "192.0.2.11")))
        self.router = Router(self.config)
        self.client = Address("198.51.100.7", 31001)

    def test_wire_vectors(self):
        # IPv4 octets retain their order; uint16 ports are little endian on PS2.
        self.assertEqual(ip_reply(self.client).hex(), "1f000100c633640719790000")
        self.assertEqual(nat_reply(self.client, Address("192.0.2.11", 2273)).hex(),
                         "15000100c633640719790000c000020be108")

    def test_all_nat_routes_from_all_listeners(self):
        for node in (0, 1):
            for port in (0, 1):
                for flags in range(4):
                    packet = NAT_REQUEST[:4] + bytes([flags, 0, 0, 0])
                    reply, = self.router.route(packet, self.client, (node, port), now=0)
                    self.assertEqual(reply.listener, (node ^ (flags & 1), port ^ bool(flags & 2)))
                    self.assertEqual(reply.destination, self.client)
                    self.assertEqual(reply.payload,
                                     nat_reply(self.client, self.config.advertised((node ^ 1, port))))

    def test_padding_is_not_required_to_be_zero(self):
        self.assertEqual(parse_request(bytes.fromhex("1eff0100")).kind, 30)
        self.assertEqual(parse_request(bytes.fromhex("14ff010003abcdef")).flags, 3)

    def test_one_address_does_not_falsely_report_open(self):
        router = Router(Config((Node("127.0.0.1", "192.0.2.10"),)))
        for flags in (1, 3):
            self.assertEqual(router.route(NAT_REQUEST[:4] + bytes([flags, 0, 0, 0]),
                                          self.client, (0, 0), now=0), [])
        response, = router.route(bytes.fromhex("1400010002000000"), self.client, (0, 0), now=0)
        self.assertEqual(response.listener, (0, 1))

    def test_introduction_requires_live_target_and_preserves_signature(self):
        target = Address("203.0.113.8", 3074)
        packet = traversal(10, self.client, target)
        self.assertEqual(self.router.route(packet, self.client, (0, 0), now=0), [])
        self.router.route(traversal(14, Address("0.255.0.255", 0), Address("0.255.0.255", 0)),
                          target, (0, 0), now=1)
        reply, = self.router.route(packet, self.client, (0, 0), now=2)
        self.assertEqual(reply.destination, target)
        self.assertEqual(reply.payload, b"\x0b" + packet[1:])
        self.assertEqual(reply.payload, forward_intro(parse_request(packet)))
        self.assertEqual(self.router.route(packet, self.client, (0, 0), now=122), [])

    def test_introduction_cannot_rewrite_signed_source(self):
        target = Address("203.0.113.8", 3074)
        self.router.route(IP_REQUEST, target, (0, 0), now=0)
        spoof = traversal(10, Address("198.51.100.9", 3074), target)
        self.assertEqual(self.router.route(spoof, self.client, (0, 0), now=1), [])

    def test_malformed_packets(self):
        packets = [b"", b"\x1e", IP_REQUEST + b"\x00", b"\x1e\x00\x02\x00",
                   bytes.fromhex("1400010004000000"), b"\x0a\x02\x00", b"\xff" * 512]
        for packet in packets:
            with self.subTest(packet=packet), self.assertRaises(ProtocolError):
                parse_request(packet)

    def test_rate_limit_and_memory_bounds(self):
        config = Config(self.config.nodes, max_peers=3)
        router = Router(config)
        replies = [router.route(IP_REQUEST, self.client, (0, 0), now=0) for _ in range(101)]
        self.assertTrue(replies[99])
        self.assertFalse(replies[100])
        self.assertTrue(router.route(IP_REQUEST, self.client, (0, 0), now=1))
        for i in range(10):
            router.route(IP_REQUEST, Address(f"198.51.100.{i + 10}", 3074), (0, 0), now=2)
        self.assertLessEqual(len(router.peers), 3)
        self.assertLessEqual(len(router.buckets), 3)

    def test_config_rejects_overlapping_sockets(self):
        with self.assertRaises(ValueError):
            Config((Node("0.0.0.0", "192.0.2.1"), Node("127.0.0.2", "192.0.2.2")))
        with self.assertRaises(ValueError):
            Config((Node("127.0.0.1", "192.0.2.1"), Node("127.0.0.2", "192.0.2.1")))
        with self.assertRaises(ValueError):
            Config(self.config.nodes, port=2273, alternate_port=2273)


class DatagramTests(unittest.TestCase):
    def setUp(self):
        held = []
        try:
            for _ in range(2):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                held.append(sock)
            ports = [sock.getsockname()[1] for sock in held]
        finally:
            for sock in held:
                sock.close()
        self.config = Config((Node("127.0.0.1", "127.0.0.1"), Node("127.0.0.2", "127.0.0.2")),
                             port=ports[0], alternate_port=ports[1])
        self.server = Server(self.config).open()
        self.thread = threading.Thread(target=self.server.serve)
        self.thread.start()
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind(("127.0.0.1", 0))
        self.client.settimeout(2)
        self.observed = Address(*self.client.getsockname())

    def tearDown(self):
        self.client.close()
        self.server.stop()
        self.thread.join(timeout=3)
        self.server.close()
        self.assertFalse(self.thread.is_alive())

    def test_real_udp_source_addresses_and_ports(self):
        for node in (0, 1):
            for port_index in (0, 1):
                listener = (node, port_index)
                destination = self.config.advertised(listener).socket_tuple()
                self.client.sendto(IP_REQUEST, destination)
                payload, source = self.client.recvfrom(512)
                self.assertEqual(payload, ip_reply(self.observed))
                self.assertEqual(source, destination)
                for flags in range(4):
                    packet = NAT_REQUEST[:4] + bytes([flags, 0, 0, 0])
                    self.client.sendto(packet, destination)
                    payload, source = self.client.recvfrom(512)
                    expected = (node ^ bool(flags & 1), port_index ^ bool(flags & 2))
                    self.assertEqual(source, self.config.advertised(expected).socket_tuple())
                    self.assertEqual(payload, nat_reply(self.observed,
                                                       self.config.advertised((node ^ 1, port_index))))

    def test_real_udp_introduction_and_malformed_packet_recovery(self):
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            target_socket.bind(("127.0.0.1", 0))
            target_socket.settimeout(2)
            target = Address(*target_socket.getsockname())
            server_address = self.config.advertised((0, 0)).socket_tuple()
            # Register target and use a discovery response as an ordering barrier.
            target_socket.sendto(traversal(14, target, target), server_address)
            target_socket.sendto(IP_REQUEST, server_address)
            target_socket.recvfrom(512)
            self.client.sendto(b"\xff" * 512, server_address)
            packet = traversal(10, self.observed, target)
            self.client.sendto(packet, server_address)
            forwarded, source = target_socket.recvfrom(512)
            self.assertEqual(source, server_address)
            self.assertEqual(forwarded, b"\x0b" + packet[1:])
        finally:
            target_socket.close()

    def _probe(self):
        root = Path(__file__).resolve().parents[1]
        return subprocess.run([sys.executable, str(root / "scripts/probe.py"), "127.0.0.1",
                               "--port", str(self.config.port), "--timeout", "0.1"],
                              cwd=root, capture_output=True, text=True, timeout=5)

    def test_deployment_probe_two_addresses(self):
        result = self._probe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("would report Open", result.stdout)

    def test_deployment_probe_one_address(self):
        self.server.stop()
        self.thread.join(timeout=3)
        self.server.close()
        config = Config((self.config.nodes[0],), self.config.port, self.config.alternate_port)
        self.server = Server(config).open()
        self.thread = threading.Thread(target=self.server.serve)
        self.thread.start()
        result = self._probe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("would report Moderate", result.stdout)
        self.assertIn("One-address mode cannot measure", result.stdout)

    def test_cli_start_and_signal_shutdown(self):
        self.server.stop()
        self.thread.join(timeout=3)
        self.server.close()
        root = Path(__file__).resolve().parents[1]
        process = subprocess.Popen([sys.executable, "-m", "codstun", "--bind", "127.0.0.1",
                                    "--public-ip", "127.0.0.1", "--secondary-bind", "127.0.0.2",
                                    "--secondary-public-ip", "127.0.0.2", "--port", str(self.config.port),
                                    "--alternate-port", str(self.config.alternate_port)],
                                   cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.client.settimeout(0.1)
            deadline = time.monotonic() + 3
            while True:
                self.client.sendto(IP_REQUEST, ("127.0.0.1", self.config.port))
                try:
                    payload, _ = self.client.recvfrom(512)
                    break
                except socket.timeout:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        self.fail("CLI server did not become ready")
            self.assertEqual(payload, ip_reply(self.observed))
            process.terminate()
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertEqual(stderr.count("listening "), 4)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
