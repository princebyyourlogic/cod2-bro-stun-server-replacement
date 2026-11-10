#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Summarize codstun's JSON observation log without guessing game admission."""

import argparse
from collections import Counter
import json


def summarize(rows):
    counts = Counter()
    clients, flows, unresolved, blocked = {}, {}, [], []
    for row in rows:
        event = row.get("event", "unknown")
        counts[event] += 1
        if event == "relay_registered":
            clients[row["client"]] = row
        elif event == "relay_client_expired":
            clients.pop(row["client"], None)
        elif event in ("relay_flow_observation", "relay_flow_bidirectional"):
            flows[row["a"], row["b"]] = row
        elif event == "relay_flow_started":
            flows.setdefault((row["a"], row["b"]), row)
        elif event == "relay_flow_unresolved":
            unresolved.append(row)
        elif event in ("introduction_blocked", "relay_introduction_rejected"):
            blocked.append(row)
    return counts, clients, flows, unresolved, blocked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", help="JSON lines file created with --event-log")
    args = parser.parse_args()
    rows = []
    with open(args.events) as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise SystemExit(f"line {number}: invalid JSON: {exc}")
                if not isinstance(row, dict):
                    raise SystemExit(f"line {number}: expected an event object")
                rows.append(row)
    counts, clients, flows, unresolved, blocked = summarize(rows)
    print(f"Observations: {len(rows)}, active registrations: {len(clients)}, observed relay pairs: {len(flows)}")
    for client_id, row in clients.items():
        print(f"  Client {client_id}: {row['control']} -> {row['virtual']}")
    for pair, row in flows.items():
        print(f"  Pair {pair[0]}/{pair[1]}: packets={row.get('packets', 'summary pending')}, "
              f"bidirectional={row.get('bidirectional', 'not yet summarized')}")
    print(f"Unanswered mapping probes: {counts['relay_probe_unanswered']}")
    print(f"Unresolved relay flows: {len(unresolved)}, blocked introductions: {len(blocked)}")
    for row in (unresolved + blocked)[-10:]:
        print("  " + json.dumps(row, sort_keys=True))
    print("Game admission is unobserved: bidirectional packets alone do not prove a successful join.")


if __name__ == "__main__":
    main()
