# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from codstun.diagnostics import Events, Traffic
from codstun.protocol import Address, Outbound, traversal_packet
from codstun.server import Config, Node, Router, Server
from scripts.report import log_paths, main as report, read_events, summarize
from test_relay import Events as Capture, Network, PAYLOAD


class DiagnosticsTests(unittest.TestCase):
    def test_run_correlation_and_suppressed_drop_counts(self):
        with patch('codstun.diagnostics.time.monotonic', return_value=100), self.assertLogs('codstun.events') as logs:
            events = Events()
            for _ in range(35):
                events.emit('packet_dropped', reason='protocol_error')
            events.emit('service_started', version='test')
            events.flush(final=True)
        rows = [json.loads(record.getMessage()) for record in logs.records]
        self.assertEqual(len({row['run'] for row in rows}), 1)
        self.assertEqual([row['seq'] for row in rows], list(range(1, len(rows) + 1)))
        self.assertTrue(all(row['schema'] == 1 and row['uptime_ms'] == 0 for row in rows))
        self.assertEqual(sum(row['event'] == 'packet_dropped' for row in rows), 10)
        self.assertEqual(rows[-1]['counts'], {'packet_dropped:protocol_error': 25})
        self.assertEqual(events.counts['packet_dropped'], 35)
        self.assertNotEqual(events.run, Events().run)

    def test_global_event_limit_keeps_shutdown_and_exact_traffic_summaries(self):
        with patch('codstun.diagnostics.time.monotonic', return_value=100), self.assertLogs('codstun.events') as logs:
            events = Events()
            for _ in range(250):
                events.emit('adaptive_introduction', a=1, b=2)
            events.emit('udp_summary', packets=500)
            events.emit('service_stopped', reason='SIGTERM')
            events.flush(final=True)
        rows = [json.loads(record.getMessage()) for record in logs.records]
        self.assertEqual(sum(row['event'] == 'adaptive_introduction' for row in rows), 200)
        self.assertTrue(any(row['event'] == 'udp_summary' and row['packets'] == 500 for row in rows))
        self.assertTrue(any(row['event'] == 'service_stopped' for row in rows))
        self.assertEqual(rows[-1]['counts'], {'adaptive_introduction:': 50})

    def test_packet_metadata_sampling_and_summary_count_every_datagram(self):
        events = Capture()
        traffic = Traffic(events, interval=1, samples=2)
        traffic.last_flush = 0
        peer = Address('198.51.100.1', 3074)
        packet = b'\x01private-payload-authenticator'
        for _ in range(50):
            traffic.record('rx', ('relay', 2), peer, packet, now=1)
        traffic.record('rx', ('relay', 2), peer, b'\x02different-secret', now=1)
        traffic.flush(now=1)
        samples = [row for name, row in events.rows if name == 'udp_packet']
        summaries = [row for name, row in events.rows if name == 'udp_summary']
        self.assertEqual(len(samples), 3)
        self.assertEqual(summaries[0]['packets'], 51)
        self.assertEqual(summaries[0]['packet_types'], {'0x01': 50, '0x02': 1})
        self.assertEqual(summaries[0]['bytes'], len(packet) * 50 + len(b'\x02different-secret'))
        self.assertNotIn('private-payload', json.dumps(events.rows))
        self.assertNotIn('different-secret', json.dumps(events.rows))
        traffic.record('rx', ('relay', 2), peer, packet, now=2)
        traffic.flush(now=2, final=True)
        self.assertEqual(events.rows[-1][1]['packets'], 1)
        self.assertFalse(traffic.streams)

    def test_stream_capacity_and_disabled_samples_remain_bounded(self):
        events = Capture()
        traffic = Traffic(events, samples=0, max_streams=2)
        for port in range(3000, 3100):
            traffic.record('rx', (0, 0), Address('198.51.100.1', port), b'abc', now=1)
        self.assertEqual(len(traffic.streams), 2)
        traffic.flush(now=2, final=True)
        self.assertFalse(any(name == 'udp_packet' for name, _ in events.rows))
        capacity = next(row for name, row in events.rows if name == 'udp_tracking_capacity')
        self.assertEqual(capacity, {'rx_packets': 98, 'rx_bytes': 294})

    def test_discovery_rate_limit_has_an_explicit_reason(self):
        events = Capture()
        router = Router(Config((Node('127.0.0.1', '192.0.2.10'),)), events=events)
        for _ in range(101):
            router.route(bytes.fromhex('1e000100'), Address('198.51.100.1', 3074), (0, 0), now=1)
        self.assertEqual(events.rows[-1][0], 'packet_dropped')
        self.assertEqual(events.rows[-1][1]['reason'], 'discovery_rate_limit')

    def test_failed_send_is_logged_and_does_not_discard_other_actions(self):
        server = Server(Config((Node('127.0.0.1', '192.0.2.10'),)))
        bad, good = Mock(), Mock()
        bad.sendto.side_effect = OSError(errno.ENETUNREACH, 'unreachable')
        peer = Address('198.51.100.1', 3074)
        try:
            with patch.dict(server.sockets, {(0, 0): bad, (0, 1): good}), self.assertLogs('codstun.events') as logs:
                server.send([Outbound((0, 0), peer, b'abc', 'first'), Outbound((0, 1), peer, b'def', 'second')])
            rows = [json.loads(record.getMessage()) for record in logs.records]
            error = next(row for row in rows if row['event'] == 'udp_error')
            self.assertEqual(error['errno'], errno.ENETUNREACH)
            self.assertEqual(error['reason'], 'first')
            good.sendto.assert_called_once_with(b'def', peer.socket_tuple())
        finally:
            server.close()

    def test_probe_retry_timeout_buffer_loss_and_flow_types_are_visible(self):
        net = Network(('EDM', 'EDM'))
        net.send(0, 1, PAYLOAD, now=1)
        for _ in range(20):
            net.send(0, 1, PAYLOAD, now=1)
        net.relay.tick(1.6)
        self.assertTrue(any(name == 'relay_probe_retry' for name, _ in net.events.rows))
        self.assertTrue(any(name == 'relay_buffer_dropped' for name, _ in net.events.rows))
        net.relay.tick(8)
        unanswered = next(row for name, row in net.events.rows if name == 'relay_probe_unanswered')
        unresolved = next(row for name, row in net.events.rows if name == 'relay_flow_unresolved')
        self.assertEqual(unanswered['sends'], 2)
        self.assertIn('probe', unanswered)
        self.assertEqual(unresolved['dropped'], 5)
        net.pump(net.send(0, 1, PAYLOAD, now=9), now=9.1)
        net.pump(net.send(1, 0, b'\x02answer', now=9.2), now=9.3)
        net.relay.tick(20)
        flow = next(row for name, row in reversed(net.events.rows) if name == 'relay_flow_observation')
        self.assertEqual(flow['packet_types'], [{'0x01': 1}, {'0x02': 1}])
        self.assertTrue(flow['bidirectional'])

    def test_report_rotations_runs_filters_redaction_and_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'events.jsonl'
            registration = dict(event='relay_registered', client=1, control='198.51.100.7:3074',
                                virtual='192.0.2.10:20001')
            path.with_name(path.name + '.2').write_text(json.dumps(dict(registration, run='old', time=1)) + '\n')
            path.with_name(path.name + '.1').write_text(json.dumps(dict(registration, run='new', time=2)) + '\n')
            rows = [dict(event='packet_dropped', run='new', reason='protocol_error', time=3),
                    dict(event='events_suppressed', run='new', counts={'packet_dropped:protocol_error': 12}, time=4)]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            self.assertEqual(len(summarize(read_events(log_paths(path, True)))[1]), 2)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(report([str(path), '--all', '--run', 'new', '--since', '2',
                                         '--redact', '--timeline', '--tail', '1']), 0)
            text = output.getvalue()
            self.assertNotIn('198.51.100.7', text)
            self.assertNotIn('192.0.2.10', text)
            self.assertIn('ip-1:3074', text)
            self.assertIn('packet_dropped:protocol_error: 13', text)
            self.assertIn('service runs: 1', text)
            self.assertIn('Timeline: last 1 selected events', text)
            self.assertIn('Game admission is unobserved', text)

    def test_report_skips_partial_last_record_but_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'events.jsonl'
            path.write_text('{"event":"ok"}\n{"event":')
            with redirect_stderr(io.StringIO()) as warning:
                self.assertEqual(list(read_events([path])), [{'event': 'ok'}])
            self.assertIn('incomplete final record', warning.getvalue())
            path.write_text('bad json\n')
            with self.assertRaises(ValueError):
                list(read_events([path]))

    def test_cli_rotates_private_logs_and_records_malformed_packets(self):
        held = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        try:
            for sock in held:
                sock.bind(('127.0.0.1', 0))
            port, alternate = [sock.getsockname()[1] for sock in held]
        finally:
            for sock in held:
                sock.close()
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as errors:
            path = Path(temporary) / 'events.jsonl'
            process = subprocess.Popen([sys.executable, '-m', 'codstun', '--public-ip', '127.0.0.1',
                                        '--bind', '127.0.0.1', '--port', str(port), '--alternate-port', str(alternate),
                                        '--event-log', str(path), '--event-log-bytes', '4096',
                                        '--event-log-backups', '3'], cwd=root, stderr=errors, stdout=errors)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(.1)
                    deadline = time.monotonic() + 3
                    while True:
                        client.sendto(bytes.fromhex('1e000100'), ('127.0.0.1', port))
                        try:
                            client.recvfrom(512)
                            break
                        except socket.timeout:
                            if process.poll() is not None or time.monotonic() > deadline:
                                self.fail('CLI did not start')
                    for _ in range(80):
                        client.sendto(bytes.fromhex('1e000100'), ('127.0.0.1', port))
                        client.recvfrom(512)
                    client.sendto(b'\xffbad', ('127.0.0.1', port))
                    client.sendto(bytes.fromhex('1e000100'), ('127.0.0.1', port))
                    client.recvfrom(512)
                process.terminate()
                self.assertEqual(process.wait(timeout=3), 0)
                paths = log_paths(path, True)
                self.assertGreater(len(paths), 1)
                self.assertLessEqual(len(paths), 4)
                for log in paths:
                    self.assertEqual(log.stat().st_mode & 0o777, 0o600)
                    self.assertLessEqual(log.stat().st_size, 4096)
                rows = list(read_events(paths))
                self.assertEqual(len({row['run'] for row in rows}), 1)
                self.assertEqual([row['seq'] for row in rows], sorted(row['seq'] for row in rows))
                self.assertTrue(any(row['event'] == 'packet_dropped' and row['reason'] == 'protocol_error' for row in rows))
                self.assertEqual(rows[-1]['event'], 'service_stopped')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
