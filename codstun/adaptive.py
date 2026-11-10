# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Direct introductions followed by authenticated-echo relay route offers."""

from collections import OrderedDict
from dataclasses import dataclass
import hashlib

from .protocol import Outbound, forward_intro
from .diagnostics import endpoint

ATTEMPT_TTL = 6.0
MAX_ATTEMPTS = 1024
OFFER_INTERVAL = 0.4


@dataclass
class Attempt:
    a: int
    b: int
    packet: bytes
    first: float
    last: float
    requests: int = 1
    pending_offer: bool = False
    offered: float | None = None
    offers: int = 0
    waiting_for: tuple | None = None

    @property
    def token(self):
        return hashlib.blake2s(self.packet, digest_size=8).hexdigest()


class Adaptive:
    def __init__(self, relay, events, direct_window=1.0):
        self.relay, self.events = relay, events
        self.direct_window = direct_window
        self.attempts: OrderedDict[tuple[int, int], Attempt] = OrderedDict()
        self.offered_pairs: dict[tuple[int, int], float] = {}
        relay.allow_pair = self.allows

    def allows(self, a, b, now):
        key = tuple(sorted((a, b)))
        offered = self.offered_pairs.get(key)
        if offered is None or a not in self.relay.clients or b not in self.relay.clients:
            return False
        flow = self.relay.flows.get(key)
        activity = max(offered, flow.last_seen if flow is not None else offered)
        return now - activity <= self.relay.ttl

    def _fields(self, attempt, now):
        return dict(a=attempt.a, b=attempt.b, attempt=attempt.token,
                    requests=attempt.requests, elapsed_ms=round((now - attempt.first) * 1000),
                    since_request_ms=round((now - attempt.last) * 1000), offers=attempt.offers,
                    admission="unobserved")

    def _ended(self, attempt, now, reason="attempt_timeout"):
        self.events.emit("adaptive_attempt_ended", relay_offered=attempt.offered is not None,
                         direct_outcome="unobserved", reason=reason, **self._fields(attempt, now))

    def introduce(self, request, observed, now):
        a = self.relay.controls.get(observed)
        b = self.relay.controls.get(request.destination)
        reason = None
        if request.source != observed:
            reason = "source_mapping_mismatch"
        elif a is None or b is None:
            reason = "endpoint_not_registered"
        elif a == b:
            reason = "self_target"
        elif any(now - self.relay.clients[i].last_seen > self.relay.ttl for i in (a, b)):
            reason = "registration_expired"
        if reason:
            self.events.emit("adaptive_introduction_blocked", reason=reason, observed=endpoint(observed),
                             advertised=endpoint(request.source), target=endpoint(request.destination),
                             a=a, b=b, admission="unobserved")
            return []
        key = a, b
        attempt = self.attempts.get(key)
        fresh = attempt is None
        # A bounded attempt lifetime also gives later joins a fresh direct window
        # when the native protocol reuses an identical signed request.
        if attempt is not None and (now - attempt.first > ATTEMPT_TTL
                                    or request.raw != attempt.packet):
            self._ended(attempt, now, "new_request" if request.raw != attempt.packet else "attempt_timeout")
            del self.attempts[key]
            attempt = None
            fresh = True
        if attempt is None:
            if len(self.attempts) >= MAX_ATTEMPTS:
                self.events.emit("adaptive_attempt_capacity", admission="unobserved")
                # Keep native direct traversal available even when offer tracking is full.
                return [Outbound((0, 0), self.relay.clients[b].control,
                                 forward_intro(request), "adaptive-direct-introduction")]
            attempt = Attempt(a, b, request.raw, now, now)
            self.attempts[key] = attempt
            self.events.emit("adaptive_attempt_started", source=endpoint(observed), target=endpoint(request.destination),
                             direct_window_ms=round(self.direct_window * 1000), **self._fields(attempt, now))
        else:
            attempt.requests += 1
            attempt.last = now
        self.relay.keepalive(observed, now)
        self.events.emit("adaptive_introduction", **self._fields(attempt, now))
        # A new traversal may follow a client/socket restart while the control
        # endpoint is reused. Require new pair proofs rather than offering stale
        # per-destination mappings cached by an earlier join.
        actions = self.relay.prepare_pair(a, b, now, refresh=fresh)
        # Preserve native introductions on retries as well, including while a
        # relay mapping is still being proved. No signed fields are rewritten.
        actions.append(Outbound((0, 0), self.relay.clients[b].control,
                                forward_intro(request), "adaptive-direct-introduction"))
        if attempt.requests >= 2 and now - attempt.first >= self.direct_window:
            attempt.pending_offer = True
            actions.extend(self._offer(attempt, now))
        return actions

    def _offer(self, attempt, now):
        if not attempt.pending_offer:
            return []
        if attempt.offered is not None and now - attempt.offered < OFFER_INTERVAL:
            return []
        target = self.relay.mapping(attempt.a, attempt.b, now)
        reverse = self.relay.mapping(attempt.b, attempt.a, now)
        if target is None or reverse is None:
            missing = tuple(client for client, mapping in ((attempt.a, target), (attempt.b, reverse)) if mapping is None)
            if missing != attempt.waiting_for:
                self.events.emit("adaptive_route_waiting", missing_clients=missing, **self._fields(attempt, now))
                attempt.waiting_for = missing
            return []
        attempt.pending_offer = False
        attempt.offered = now
        attempt.offers += 1
        self.offered_pairs[tuple(sorted((attempt.a, attempt.b)))] = now
        self.events.emit("adaptive_relay_offered", route=endpoint(self.relay.clients[attempt.b].virtual),
                         delivery=endpoint(target), **self._fields(attempt, now))
        # The client verifies its own authenticator over the original ID and
        # physical endpoints, then resolves the peer to this packet's UDP source.
        return [Outbound(("relay", attempt.b), target, b"\x0c" + attempt.packet[1:],
                         "adaptive-relay-resolution")]

    def tick(self, now):
        actions = []
        for key, attempt in list(self.attempts.items()):
            if (now - attempt.first > ATTEMPT_TTL or attempt.a not in self.relay.clients
                    or attempt.b not in self.relay.clients):
                self._ended(attempt, now)
                del self.attempts[key]
            else:
                actions.extend(self._offer(attempt, now))
        for key in list(self.offered_pairs):
            if not self.allows(*key, now):
                del self.offered_pairs[key]
                self.events.emit("adaptive_pair_expired", a=key[0], b=key[1], reason="idle_or_client_gone")
        return actions
