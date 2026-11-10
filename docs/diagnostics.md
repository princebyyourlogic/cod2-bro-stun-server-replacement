# Troubleshooting joins

The Docker deployment records structured events continuously in
`/opt/codstun/shared/logs/events.jsonl`. Each process has a random `run` ID, a
monotonic `seq` counter, UTC Unix `time`, and monotonic `uptime_ms`. Client IDs,
pair IDs, probe IDs and attempt IDs are scoped to that run. The startup event
includes the application version, deployed commit, routing configuration and
socket buffer sizes. Shutdown records the signal; a missing shutdown event can
mean the process was killed or its older records rotated away.

## What is recorded

| Events | What they establish |
| --- | --- |
| `ip_discovery`, `nat_request`, `nat_reply_withheld` | Discovery reached this service and which NAT responses were intentionally withheld. |
| `adaptive_attempt_started`, `adaptive_introduction` | The observed peers, signed request fingerprint, retry count and direct-attempt window. |
| `relay_probe_sent`, `relay_probe_retry`, `relay_probe_answered`, `relay_probe_unanswered` | The same nonce probe's sends, elapsed time and whether a reply reached the exact relay socket. |
| `relay_mapping_proved`, `relay_mapping_reset`, `relay_mapping_expired` | The observed per-destination UDP mapping, changes and freshness. Peers behind one public IP remain separate clients. |
| `adaptive_route_waiting`, `adaptive_relay_offered` | Which mapping proofs are missing, or the offered route and delivery endpoint. |
| `relay_flow_started`, `relay_flow_bidirectional`, `relay_flow_observation` | Per-direction packet/byte totals, packet-type counts, idle time and whether both directions carried traffic. Flow observations occur every ten seconds and on graceful shutdown. |
| `packet_dropped`, `relay_buffer_dropped`, `relay_flow_unresolved`, `udp_error` | Explicit drop reasons, buffer loss, incomplete mapping probes and local socket errors with errno. |
| `udp_packet`, `udp_summary` | Sampled packet metadata and interval totals for each direction/listener/peer stream. |
| `service_snapshot` | Registration, mapping, probe, pending-buffer, flow and attempt counts; processing time and timer gaps; cumulative event counts. |

Packet metadata contains type byte, length, direction, local listener, peer and a
short BLAKE2 fingerprint for correlation. Packet bodies, authenticators and
GameSpy security keys are excluded. A matching receive/transmit fingerprint helps
trace an unchanged relay datagram. All datagrams in a tracked stream contribute
to summaries, including those that were not individually sampled. A successful
local UDP send establishes that the kernel accepted the datagram; it cannot prove
the remote console received it.

Direct peer traffic bypasses this VPS. Direct success, encrypted handshake
completion and game admission remain unobserved. Missing retries can also mean a
cancelled attempt. A relay offer is a routing decision; a bidirectional relay flow
establishes traffic in both directions. Use the players' actual result to decide
whether the game joined.

## Collect a useful report

After a failed trial, record the UTC time, who hosted and joined, their displayed
NAT labels, the error text and whether the failure was repeatable. Ask everyone
to start fresh online and create a new room after a service mode change.

On the VPS, read the current file plus retained rotations and redact IPv4 addresses
before sharing the report:

```sh
sudo python3 /opt/codstun/current/scripts/report.py \
  /opt/codstun/shared/logs/events.jsonl --all --redact --timeline --tail 500
```

Narrow the report with `--since 2026-01-01T12:00:00Z` (use the actual trial time)
and `--run RUN_ID`. Times without a timezone are interpreted as UTC. IPv4 labels
are consistent within a report and preserve port numbers, so mapping changes are
visible. Client IDs can repeat after a restart; use the run ID with them. Older
logs without run metadata appear under `legacy`. A report selection may omit the
startup/registration events; its counts describe the selected records only.
Inspect a redacted report before posting it publicly.

For process failures and container restarts, also inspect:

```sh
sudo docker inspect --format '{{json .State}}' codstun-codstun-1
sudo docker logs --since 15m codstun-codstun-1
sudo journalctl -u codstun-update.service --since '15 minutes ago'
```

These raw outputs can contain player or server addresses. Keep them private.
The updater's successful deployment message identifies the exact release.
Container state records health, exit status and whether Docker observed an OOM
kill. These observations help distinguish routing failures from a process restart.

## Volume, retention and privacy

By default the event file rotates at 20 MiB with ten backups (up to about 220 MiB).
Docker retains three 10 MiB output files separately. Retention is based on volume;
heavy traffic shortens the time covered. Event files and newly created rotations
use mode 0600. The Docker deployment keeps the log directory under its private
installation directory and never uploads it to GitHub.

The first eight packets per UDP stream are sampled, plus up to eight new packet
types. Samples are capped at 100 per second, tracking is capped at 1,024 streams,
and inactive streams are removed after 60 seconds. `udp_tracking_capacity` counts
packets/bytes outside the tracking capacity. Full stream summaries are emitted
at ten-second intervals even when individual event details are rate limited.
Repeated drop details are limited to ten per reason per second; other individual
events share a 200-per-second budget. `events_suppressed` retains counts of omitted
details, while `service_snapshot.event_counts` retains cumulative event totals.
Process termination before the next flush can lose buffered interval summaries.

Private `runtime.env` can override `CODSTUN_LOG_BYTES`, `CODSTUN_LOG_BACKUPS`,
`CODSTUN_TRAFFIC_INTERVAL` (1–300 seconds) and `CODSTUN_PACKET_SAMPLES` (0–64).
Setting samples to zero keeps interval counts and routing events. A restart is
required for configuration changes and interrupts active relay traffic. The
matching standalone CLI options are `--event-log-bytes`, `--event-log-backups`,
`--traffic-interval` and `--packet-samples`. Defaults enable these diagnostics;
`--verbose` adds text debugging separately.
