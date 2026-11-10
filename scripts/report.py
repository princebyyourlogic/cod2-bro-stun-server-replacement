#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Read rotated observations and produce a redacted troubleshooting timeline."""

import argparse
from collections import Counter, deque
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys


def log_paths(path, all_rotations=False):
    path = Path(path)
    backups = []
    if all_rotations:
        for candidate in path.parent.glob(path.name + ".*"):
            suffix = candidate.name[len(path.name) + 1:]
            if suffix.isdigit():
                backups.append((int(suffix), candidate))
    return [p for _, p in sorted(backups, reverse=True)] + [path]


def read_events(paths):
    for path in paths:
        with path.open() as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    if not line.endswith("\n"):
                        print(f"Warning: incomplete final record in {path.name}; skipped", file=sys.stderr)
                        break
                    raise ValueError(f"{path.name}:{number}: invalid JSON: {exc}") from exc
                if not isinstance(row, dict):
                    raise ValueError(f"{path.name}:{number}: expected an event object")
                yield row


def summarize(rows):
    counts = Counter()
    clients, flows, unresolved, blocked = {}, {}, deque(maxlen=100), deque(maxlen=100)
    for row in rows:
        event = row.get("event", "unknown")
        run = row.get("run", "legacy")
        counts[event] += 1
        if event == "relay_registered":
            clients[run, row["client"]] = row
        elif event == "relay_client_expired":
            clients.pop((run, row["client"]), None)
        elif event in ("relay_flow_observation", "relay_flow_bidirectional"):
            flows[run, row["a"], row["b"]] = row
        elif event == "relay_flow_started":
            flows.setdefault((run, row["a"], row["b"]), row)
        elif event == "relay_flow_unresolved":
            unresolved.append(row)
        elif event in ("introduction_blocked", "relay_introduction_rejected", "adaptive_introduction_blocked"):
            blocked.append(row)
    return counts, clients, flows, unresolved, blocked


class Redactor:
    def __init__(self):
        self.addresses = {}

    def __call__(self, text):
        def replace(match):
            address = match.group(0)
            return self.addresses.setdefault(address, f"ip-{len(self.addresses) + 1}")
        return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", replace, text)


def parse_time(value):
    try:
        return float(value)
    except ValueError:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", help="JSON lines event file")
    parser.add_argument("--all", action="store_true", help="also read numbered rotations, oldest first")
    parser.add_argument("--run", help="filter a service run ID")
    parser.add_argument("--since", type=parse_time, help="UTC ISO timestamp or Unix seconds")
    parser.add_argument("--timeline", action="store_true", help="print the most recent selected events")
    parser.add_argument("--tail", type=int, default=200, help="timeline length, 1..5000")
    parser.add_argument("--redact", action="store_true", help="replace IPv4 addresses with consistent labels")
    args = parser.parse_args(argv)
    if not 1 <= args.tail <= 5000:
        parser.error("tail must be 1..5000")
    redact = Redactor() if args.redact else lambda text: text
    def output(text):
        print(redact(text))

    timeline = deque(maxlen=args.tail)
    runs, attempts, starts = set(), {}, {}
    issues, suppressed = Counter(), Counter()
    totals = Counter()
    def selected():
        for row in read_events(log_paths(args.events, args.all)):
            run, event = row.get("run", "legacy"), row.get("event", "unknown")
            if args.run and run != args.run or args.since is not None and row.get("time", 0) < args.since:
                continue
            runs.add(run)
            if args.timeline:
                timeline.append(row)
            if event == "service_started":
                starts[run] = row
            if row.get("attempt"):
                attempts[run, row["attempt"]] = row
            if event in ("packet_dropped", "udp_error", "relay_buffer_dropped"):
                issues[event + ":" + str(row.get("reason", "unknown"))] += 1
            if event == "events_suppressed":
                suppressed.update(row.get("counts", {}))
            if event == "udp_summary":
                totals[row["direction"] + "_packets"] += row["packets"]
                totals[row["direction"] + "_bytes"] += row["bytes"]
            yield row
    try:
        counts, clients, flows, unresolved, blocked = summarize(selected())
    except (OSError, ValueError) as exc:
        parser.exit(1, redact(f"Report failed: {exc}\n"))
    output(f"Observations: {sum(counts.values())}, service runs: {len(runs)}, "
           f"registrations not expired in selection: {len(clients)}, observed relay pairs: {len(flows)}")
    for run in sorted(runs):
        row = starts.get(run, {})
        output(f"  Run {run}: version={row.get('version', 'unknown')} revision={row.get('revision', 'unknown')} "
               f"mode={row.get('mode', 'unknown')}")
    for (run, client_id), row in clients.items():
        output(f"  Client {run}/{client_id}: {row['control']} -> {row['virtual']}")
    for (run, a, b), row in flows.items():
        output(f"  Pair {run}/{a}/{b}: packets={row.get('packets', 'summary pending')}, "
               f"bytes={row.get('bytes', 'summary pending')}, bidirectional={row.get('bidirectional', False)}, "
               f"idle_ms={row.get('idle_ms', 'unknown')}, packet_types={row.get('packet_types', {})}")
    for (run, attempt), row in attempts.items():
        output(f"  Attempt {run}/{attempt}: pair={row.get('a')}/{row.get('b')}, "
               f"last_event={row['event']}, requests={row.get('requests', row.get('count', 0))}, "
               f"offers={row.get('offers', 0)}, elapsed_ms={row.get('elapsed_ms', 'unknown')}")
    output(f"Unanswered mapping probes: {counts['relay_probe_unanswered']}")
    output(f"Unresolved relay flows: {counts['relay_flow_unresolved']}, blocked introductions: "
           f"{sum(counts[name] for name in ('introduction_blocked', 'relay_introduction_rejected', 'adaptive_introduction_blocked'))}")
    output(f"Adaptive introduction requests: {counts['adaptive_introduction']}, "
           f"relay offers: {counts['adaptive_relay_offered']}")
    output("Traffic totals from summary intervals (samples are not counted twice): " + json.dumps(totals, sort_keys=True))
    for reason, number in sorted((issues + suppressed).items()):
        output(f"  Diagnostic {reason}: {number}")
    if suppressed:
        output("Repeated-event details were rate limited; the counts above include suppression summaries.")
    for row in (list(unresolved) + list(blocked))[-10:]:
        output("  " + json.dumps(row, sort_keys=True))
    if args.timeline:
        output(f"Timeline: last {len(timeline)} selected events (UTC Unix timestamps; seq is per run)")
        for row in timeline:
            output(json.dumps(row, sort_keys=True))
    output("Direct outcomes are unobserved; relay offers do not prove the route was used.")
    output("Game admission is unobserved: bidirectional packets alone do not prove a successful join.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
