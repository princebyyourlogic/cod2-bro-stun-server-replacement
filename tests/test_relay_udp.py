# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
import select
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from codstun.protocol import Address
from codstun.health import check
from codstun.server import Config, Node, Server


class Client:
    def __init__(self, primary):
        self.control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.control.bind(("127.0.0.1", 0))
        self.control.settimeout(2)
        self.control.sendto(bytes.fromhex("1e000100"), primary)
        reply, source = self.control.recvfrom(2048)
        assert source == primary
        self.virtual = Address.unpack(reply[4:10])
        self.peers = {}
        self.received = []

    def peer(self, virtual):
        if virtual not in self.peers:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            self.peers[virtual] = sock
        return self.peers[virtual]

    def sockets(self):
        return [self.control, *self.peers.values()]

    def receive(self, sock):
        data, source = sock.recvfrom(2048)
        if sock is self.control:
            assert len(data) == 29 and data[0] == 11
            target = Address.unpack(data[17:23])
            self.peer(target).sendto(b"\x0c" + data[1:], target.socket_tuple())
        else:
            self.received.append((data, Address(*source)))

    def close(self):
        for sock in self.sockets():
            sock.close()


class RelayUDPTests(unittest.TestCase):
    def setUp(self):
        held = []
        try:
            for _ in range(2):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                held.append(sock)
            ports = [s.getsockname()[1] for s in held]
        finally:
            for sock in held:
                sock.close()
        self.config = Config((Node("127.0.0.1", "127.0.0.1"),), ports[0], ports[1],
                             relay_ports=(22000, 22199), relay_max_clients=16)
        self.server = Server(self.config).open()
        self.thread = threading.Thread(target=self.server.serve)
        self.thread.start()
        primary = self.config.advertised((0, 0)).socket_tuple()
        self.clients = [Client(primary) for _ in range(3)]

    def tearDown(self):
        self.server.stop()
        self.thread.join(timeout=3)
        self.server.close()
        for client in self.clients:
            client.close()
        self.assertFalse(self.thread.is_alive())

    def pump(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate():
            sockets = {sock: client for client in self.clients for sock in client.sockets()}
            ready, _, _ = select.select(list(sockets), [], [], 0.1)
            for sock in ready:
                sockets[sock].receive(sock)
            if time.monotonic() > deadline:
                self.fail("relay did not finish the mapping probes and forward buffered traffic")

    def test_real_udp_learns_changed_ports_and_preserves_virtual_peer_sources(self):
        a, b, c = self.clients
        initial = b"\x01\x02\x00\x00\x01\x00opaque-init"
        a.peer(b.virtual).sendto(initial, b.virtual.socket_tuple())
        self.pump(lambda: bool(b.received))
        self.assertEqual(b.received, [(initial, a.virtual)])
        self.assertEqual(c.received, [])
        answer = b"\x02\x02\x00\x00\x02\x00opaque-init-ack"
        b.peer(a.virtual).sendto(answer, a.virtual.socket_tuple())
        self.pump(lambda: bool(a.received))
        self.assertEqual(a.received, [(answer, b.virtual)])
        client_a = self.server.router.relay.virtuals[a.virtual]
        client_b = self.server.router.relay.virtuals[b.virtual]
        mapped, _ = self.server.router.relay.mappings[client_a, client_b]
        self.assertEqual(mapped.socket_tuple(), a.peer(b.virtual).getsockname())
        self.assertNotEqual(mapped.socket_tuple(), a.control.getsockname())
        # Open another mesh edge while keeping the same first client's virtual source.
        a.peer(c.virtual).sendto(initial + b"-mesh", c.virtual.socket_tuple())
        self.pump(lambda: bool(c.received))
        self.assertEqual(c.received, [(initial + b"-mesh", a.virtual)])

    def test_health_check_does_not_allocate_virtual_endpoints(self):
        before = set(self.server.router.relay.virtuals)
        check(port=self.config.port)
        self.assertEqual(set(self.server.router.relay.virtuals), before)

    def test_cli_relay_probe_json_log_and_report(self):
        self.server.stop()
        self.thread.join(timeout=3)
        self.server.close()
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            events = Path(tmp) / "events.jsonl"
            process = subprocess.Popen([sys.executable, "-m", "codstun", "--public-ip", "127.0.0.1",
                                        "--bind", "127.0.0.1", "--port", str(self.config.port),
                                        "--alternate-port", str(self.config.alternate_port), "--relay",
                                        "--relay-ports", "22000-22199", "--relay-max-clients", "16",
                                        "--event-log", str(events)],
                                       cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                control = self.clients[0].control
                control.settimeout(0.1)
                deadline = time.monotonic() + 3
                while True:
                    control.sendto(bytes.fromhex("1e000100"), ("127.0.0.1", self.config.port))
                    try:
                        control.recvfrom(2048)
                        break
                    except socket.timeout:
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail("relay CLI did not become ready")
                probe = subprocess.run([sys.executable, "scripts/probe.py", "127.0.0.1", "--port",
                                        str(self.config.port), "--relay", "--timeout", "0.1"],
                                       cwd=root, text=True, capture_output=True, timeout=5)
                self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
                self.assertIn("Virtual relay topology accepted", probe.stdout)
                process.terminate()
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                rows = [json.loads(line) for line in events.read_text().splitlines()]
                self.assertTrue(any(row["event"] == "relay_registered" for row in rows))
                self.assertTrue(any(row["event"] == "nat_request" and row["mode"] == "relay_virtual" for row in rows))
                report = subprocess.run([sys.executable, "scripts/report.py", str(events)], cwd=root,
                                        text=True, capture_output=True, timeout=3)
                self.assertEqual(report.returncode, 0, report.stderr)
                self.assertIn("Game admission is unobserved", report.stdout)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
