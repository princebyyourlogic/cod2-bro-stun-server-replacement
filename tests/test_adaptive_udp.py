# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
import socket
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from codstun.health import check
from codstun.server import Config, Node, Server
from scripts.smoke_adaptive import run_trial


class AdaptiveUDPTests(unittest.TestCase):
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
                             relay_ports=(22000, 22199), adaptive_relay=True, direct_window=0.25)
        self.server = Server(self.config).open()
        self.thread = threading.Thread(target=self.server.serve)
        self.thread.start()

    def tearDown(self):
        self.server.stop()
        self.thread.join(timeout=3)
        self.server.close()
        self.assertFalse(self.thread.is_alive())

    def trial(self, case):
        return run_trial("127.0.0.1", port=self.config.port, relay_ports=self.config.relay_ports,
                         case=case, timeout=4)

    def test_direct_udp_payload_and_reply_bypass_relay(self):
        self.assertEqual(self.trial("direct")["direct"], "passed")
        self.assertFalse(self.server.router.relay.flows)
        self.assertFalse(self.server.router.adaptive.offered_pairs)

    def test_three_clients_with_changed_ports_use_fallback_and_mesh(self):
        result = self.trial("relay")
        self.assertEqual(result["relay"], "passed")
        self.assertEqual(result["mesh"], "passed")
        self.assertEqual(len(self.server.router.relay.flows), 2)
        self.assertTrue(all(all(flow.packets) for flow in self.server.router.relay.flows.values()))

    def test_cli_discovery_trials_and_observation_report(self):
        self.server.stop()
        self.thread.join(timeout=3)
        self.server.close()
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile(mode="w+t") as errors:
            events = Path(temporary) / "events.jsonl"
            process = subprocess.Popen([sys.executable, "-m", "codstun", "--public-ip", "127.0.0.1",
                                        "--bind", "127.0.0.1", "--port", str(self.config.port),
                                        "--alternate-port", str(self.config.alternate_port), "--mode", "adaptive",
                                        "--relay-ports", "22000-22199", "--direct-window", "0.25",
                                        "--event-log", str(events)], cwd=root, stdout=subprocess.DEVNULL,
                                       stderr=errors)
            try:
                deadline = time.monotonic() + 3
                while True:
                    try:
                        check(port=self.config.port, timeout=0.05)
                        break
                    except (OSError, ValueError):
                        if process.poll() is not None or time.monotonic() > deadline:
                            errors.seek(0)
                            self.fail("adaptive CLI did not start: " + errors.read())
                probe = subprocess.run([sys.executable, "scripts/probe.py", "127.0.0.1", "--port",
                                        str(self.config.port), "--adaptive", "--timeout", "0.1"],
                                       cwd=root, capture_output=True, text=True, timeout=4)
                self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
                self.assertIn("Coordinated Moderate topology accepted", probe.stdout)
                trial = subprocess.run([sys.executable, "scripts/smoke_adaptive.py", "127.0.0.1",
                                        "--port", str(self.config.port), "--relay-ports", "22000-22199",
                                        "--timeout", "4"], cwd=root, capture_output=True, text=True, timeout=10)
                self.assertEqual(trial.returncode, 0, trial.stdout + trial.stderr)
                self.assertEqual(json.loads(trial.stdout), {"direct": "passed", "relay": "passed",
                                                          "mesh": "passed", "game_admission": "not_tested"})
                process.terminate()
                self.assertEqual(process.wait(timeout=3), 0)
                rows = [json.loads(line) for line in events.read_text().splitlines()]
                self.assertTrue(any(row["event"] == "adaptive_relay_offered" for row in rows))
                self.assertTrue(any(row["event"] == "relay_flow_bidirectional" for row in rows))
                self.assertEqual(len({row["run"] for row in rows}), 1)
                self.assertEqual([row["seq"] for row in rows], list(range(1, len(rows) + 1)))
                self.assertTrue(any(row["event"] == "service_started" and row["mode"] == "adaptive" for row in rows))
                self.assertTrue(any(row["event"] == "udp_summary" and row["packets"] > 0 for row in rows))
                self.assertEqual(rows[-1]["event"], "service_stopped")
                self.assertEqual(rows[-1]["reason"], "SIGTERM")
                self.assertEqual(events.stat().st_mode & 0o777, 0o600)
                report = subprocess.run([sys.executable, "scripts/report.py", str(events)], cwd=root,
                                        capture_output=True, text=True, timeout=3)
                self.assertEqual(report.returncode, 0, report.stderr)
                self.assertIn("Adaptive introduction requests", report.stdout)
                self.assertIn("Direct outcomes are unobserved", report.stdout)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
