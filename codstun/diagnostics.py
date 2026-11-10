# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Structured observations. These events never claim unobserved game admission."""

from collections import Counter, OrderedDict
from dataclasses import dataclass, field
import hashlib
import json
import logging
import time
import uuid

LOG = logging.getLogger("codstun.events")


class Events:
    """Correlated, bounded JSON events; repeated drops retain exact counters."""

    LIMITED = {"packet_dropped", "udp_error", "relay_buffer_dropped", "relay_capacity",
               "relay_probe_capacity", "relay_allocation_failed", "adaptive_introduction_blocked",
               "adaptive_attempt_capacity", "introduction_blocked"}
    # These are already bounded by timers, stream capacity or service lifecycle.
    UNLIMITED = {"service_started", "service_stopped", "service_failure", "service_snapshot",
                 "udp_summary", "udp_tracking_capacity"}

    def __init__(self):
        self.run = uuid.uuid4().hex[:12]
        self.started = time.monotonic()
        self.sequence = 0
        self.counts = Counter()
        self.suppressed = Counter()
        self.window = int(self.started)
        self.window_counts = Counter()
        self.last_flush = self.started

    def _write(self, event, fields, now):
        self.sequence += 1
        LOG.info(json.dumps({**fields, "schema": 1, "event": event, "run": self.run,
                            "seq": self.sequence, "time": round(time.time(), 3),
                            "uptime_ms": round((now - self.started) * 1000)},
                           sort_keys=True, separators=(",", ":")))

    def emit(self, event: str, **fields):
        now = time.monotonic()
        self.counts[event] += 1
        if event in self.UNLIMITED:
            self._write(event, fields, now)
            return
        if int(now) != self.window:
            self.window = int(now)
            self.window_counts.clear()
        key = event + ":" + str(fields.get("reason", ""))
        if (self.window_counts["total"] >= 200
                or event in self.LIMITED and self.window_counts[key] >= 10):
            self.suppressed[key] += 1
            return
        self.window_counts["total"] += 1
        self.window_counts[key] += 1
        self._write(event, fields, now)

    def flush(self, *, final=False):
        now = time.monotonic()
        if final or now - self.last_flush >= 10:
            if self.suppressed:
                self._write("events_suppressed", {"counts": dict(self.suppressed)}, now)
                self.suppressed.clear()
            self.last_flush = now


def endpoint(address):
    return f"{address.ip}:{address.port}"


def packet_type(packet):
    return f"0x{packet[0]:02x}" if packet else "empty"


@dataclass
class Stream:
    id: int
    first: float
    last: float
    packets: int = 0
    total: int = 0
    size: int = 0
    types: Counter = field(default_factory=Counter)
    reasons: Counter = field(default_factory=Counter)
    sampled_types: set = field(default_factory=set)
    samples: int = 0
    minimum: int | None = None
    maximum: int = 0
    max_gap: float = 0


class Traffic:
    """Sample metadata, never payloads; summarize every packet in bounded streams."""

    def __init__(self, events, *, interval=10.0, samples=8, max_streams=1024):
        self.events, self.interval, self.samples = events, interval, samples
        self.max_streams = max_streams
        self.streams = OrderedDict()
        self.next_id = 1
        self.last_flush = time.monotonic()
        self.sample_window = -1
        self.sample_count = 0
        self.untracked = Counter()

    def record(self, direction, listener, peer, packet, *, reason=None, now=None):
        now = time.monotonic() if now is None else now
        key = direction, listener, peer
        stream = self.streams.get(key)
        if stream is None:
            if len(self.streams) >= self.max_streams:
                self.untracked[direction + "_packets"] += 1
                self.untracked[direction + "_bytes"] += len(packet)
                return
            stream = Stream(self.next_id, now, now)
            self.next_id += 1
            self.streams[key] = stream
        kind = packet_type(packet)
        stream.max_gap = max(stream.max_gap, now - stream.last)
        stream.last = now
        stream.packets += 1
        stream.total += 1
        stream.size += len(packet)
        stream.types[kind] += 1
        if reason:
            stream.reasons[reason] += 1
        stream.minimum = len(packet) if stream.minimum is None else min(stream.minimum, len(packet))
        stream.maximum = max(stream.maximum, len(packet))
        if int(now) != self.sample_window:
            self.sample_window, self.sample_count = int(now), 0
        sample = (stream.samples < self.samples or kind not in stream.sampled_types
                  and stream.samples < self.samples + 8)
        if self.samples and sample and self.sample_count < 100:
            stream.samples += 1
            stream.sampled_types.add(kind)
            self.sample_count += 1
            self.events.emit("udp_packet", direction=direction, listener=list(listener),
                             peer=endpoint(peer), stream=stream.id, bytes=len(packet),
                             packet_type=kind, packet_tag=hashlib.blake2s(packet, digest_size=8).hexdigest(),
                             reason=reason, ordinal=stream.total)

    def flush(self, now=None, *, final=False):
        now = time.monotonic() if now is None else now
        if not final and now - self.last_flush < self.interval:
            return
        for key, stream in list(self.streams.items()):
            direction, listener, peer = key
            if stream.packets:
                self.events.emit("udp_summary", direction=direction, listener=list(listener),
                                 peer=endpoint(peer), stream=stream.id, packets=stream.packets,
                                 bytes=stream.size, packet_types=dict(stream.types),
                                 reasons=dict(stream.reasons), min_bytes=stream.minimum,
                                 max_bytes=stream.maximum, max_gap_ms=round(stream.max_gap * 1000),
                                 idle_ms=round((now - stream.last) * 1000),
                                 lifetime_ms=round((now - stream.first) * 1000), final=final)
                stream.packets = stream.size = stream.maximum = 0
                stream.minimum = None
                stream.max_gap = 0
                stream.types.clear()
                stream.reasons.clear()
            if final or now - stream.last > 60:
                del self.streams[key]
        if self.untracked:
            self.events.emit("udp_tracking_capacity", **dict(self.untracked))
            self.untracked.clear()
        self.last_flush = now
