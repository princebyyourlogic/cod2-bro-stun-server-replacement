# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Experimental relay for the unmodified PS2 client, using virtual public endpoints.

IP discovery advertises a virtual endpoint before peers construct authenticated
packets. Server type-0x0b instructions make a client send type-0x0c to a chosen
virtual endpoint, proving its mapping toward that exact relay socket. The original
client's handler is exercised by scripts/verify_game.py. Live game verification
is still required; see docs/relay.md.
"""

from collections import OrderedDict, deque
from dataclasses import dataclass, field
import secrets

from .diagnostics import Events, endpoint
from .protocol import Address, Outbound, traversal_packet

PROBE_LIFETIME = 3.0
PROBE_INTERVAL = 0.5
PROBE_SENDS = 4
BUFFER_LIFETIME = 6.0
MAX_DATAGRAM = 2048
MAX_PENDING = 64
MAX_BUFFERED = 16


@dataclass
class Client:
    id: int
    control: Address
    virtual: Address
    last_seen: float


@dataclass
class Probe:
    client: int
    destination: int
    expected: bytes
    instruction: bytes
    created: float
    last_sent: float
    sends: int = 1


@dataclass
class Pending:
    destination: int
    observed: Address
    created: float
    packets: deque = field(default_factory=lambda: deque(maxlen=MAX_BUFFERED))
    candidates: set = field(default_factory=set)


@dataclass
class Flow:
    a: int
    b: int
    created: float
    last_seen: float
    packets: list = field(default_factory=lambda: [0, 0])
    sizes: list = field(default_factory=lambda: [0, 0])
    last_report: float = 0.0


class Relay:
    def __init__(self, allocate, release, *, events=None, max_clients=64, ttl=180.0):
        self.allocate = allocate  # id -> bound/advertised virtual Address
        self.release = release    # id -> close virtual socket
        self.events = events or Events()
        self.max_clients, self.ttl = max_clients, ttl
        self.clients: dict[int, Client] = {}
        self.controls: dict[Address, int] = {}
        self.virtuals: dict[Address, int] = {}
        self.mappings: dict[tuple[int, int], tuple[Address, float]] = {}
        self.sources: dict[tuple[int, Address], int] = {}
        self.probes: dict[bytes, Probe] = {}
        self.pending: OrderedDict[tuple[int, Address], Pending] = OrderedDict()
        self.flows: dict[tuple[int, int], Flow] = {}
        self.introductions = {}
        self.next_id = 1
        self.unknown_budgets = {}
        # Adaptive mode installs a predicate for offered pairs. Always-relay mode
        # retains its existing registered-client/nonce-proof behavior.
        self.allow_pair = None

    def _allowed(self, a, b, now):
        return self.allow_pair is None or self.allow_pair(a, b, now)

    def mapping(self, client, destination, now):
        return self._mapping(client, destination, now)

    def prepare_pair(self, a, b, now, *, refresh=False):
        actions = []
        for client, destination in ((a, b), (b, a)):
            if refresh:
                old = self.mappings.pop((client, destination), None)
                if old:
                    self.sources.pop((destination, old[0]), None)
            if self._mapping(client, destination, now) is None:
                actions.extend(self._probe(client, destination, now))
        return actions

    def _allow_unknown(self, destination, now):
        tokens, last = self.unknown_budgets.get(destination, (40.0, now))
        tokens = min(40.0, tokens + max(0, now - last) * 20)
        self.unknown_budgets[destination] = (max(0, tokens - 1), now)
        return tokens >= 1

    def register(self, observed: Address, now: float) -> Client | None:
        client_id = self.controls.get(observed)
        if client_id is not None:
            client = self.clients[client_id]
            client.last_seen = now
            return client
        if len(self.clients) >= self.max_clients:
            self.events.emit("relay_capacity", clients=len(self.clients))
            return None
        client_id = self.next_id
        self.next_id += 1
        try:
            virtual = self.allocate(client_id)
        except OSError as exc:
            self.events.emit("relay_allocation_failed", error=str(exc))
            return None
        client = Client(client_id, observed, virtual, now)
        self.clients[client_id] = client
        self.controls[observed] = client_id
        self.virtuals[virtual] = client_id
        self.events.emit("relay_registered", client=client_id, control=endpoint(observed),
                         virtual=endpoint(virtual))
        return client

    def keepalive(self, observed: Address, now: float):
        client_id = self.controls.get(observed)
        if client_id is not None:
            self.clients[client_id].last_seen = now

    def _probe(self, client_id: int, destination: int, now: float) -> list[Outbound]:
        if client_id == destination:
            return []
        if any(p.client == client_id and p.destination == destination for p in self.probes.values()):
            return []
        if len(self.probes) >= self.max_clients * 4:
            return []
        client, remote = self.clients[client_id], self.clients[destination]
        # The 80 random bits are an echo challenge, not a Demonware session MAC.
        # The original 0x0b handler copies them into its reply without verifying.
        instruction = traversal_packet(11, secrets.randbits(32), remote.virtual,
                                       client.virtual, secrets.token_bytes(10))
        expected = b"\x0c" + instruction[1:]
        self.probes[expected] = Probe(client_id, destination, expected, instruction, now, now)
        self.events.emit("relay_probe_sent", client=client_id, destination=destination)
        return [Outbound((0, 0), client.control, instruction, "relay-mapping-probe")]

    def _mapping(self, client: int, destination: int, now: float):
        entry = self.mappings.get((client, destination))
        if entry and now - entry[1] <= self.ttl:
            return entry[0]
        return None

    def _learn(self, client_id: int, destination: int, observed: Address, now: float):
        old = self.mappings.get((client_id, destination))
        if old:
            self.sources.pop((destination, old[0]), None)
        self.mappings[client_id, destination] = observed, now
        self.sources[destination, observed] = client_id
        self.clients[client_id].last_seen = now
        self.events.emit("relay_mapping_proved", client=client_id, destination=destination,
                         observed=endpoint(observed), changed=old is not None and old[0] != observed)

    def _deliver(self, sender: int, destination: int, observed: Address,
                 packet: bytes, now: float) -> list[Outbound]:
        if sender == destination or not self._allowed(sender, destination, now):
            return []
        self.mappings[sender, destination] = observed, now
        self.clients[sender].last_seen = now
        target = self._mapping(destination, sender, now)
        if target is None:
            return self._probe(destination, sender, now)
        key = tuple(sorted((sender, destination)))
        flow = self.flows.get(key)
        new = flow is None
        if flow is None:
            flow = Flow(*key, now, now, last_report=now)
            self.flows[key] = flow
        side = 0 if sender == flow.a else 1
        flow.packets[side] += 1
        flow.sizes[side] += len(packet)
        flow.last_seen = now
        if new or flow.packets[side] == 1 and flow.packets[1 - side] > 0:
            self.events.emit("relay_flow_started" if new else "relay_flow_bidirectional",
                             a=key[0], b=key[1], packets=list(flow.packets), bytes=list(flow.sizes),
                             bidirectional=all(flow.packets), packet_type=packet[0], admission="unobserved")
        return [Outbound(("relay", sender), target, packet, "relay-data")]

    def _flush(self, now: float) -> list[Outbound]:
        actions = []
        for key, pending in list(self.pending.items()):
            sender = self.sources.get((pending.destination, pending.observed))
            if sender is None or sender not in self.clients:
                continue
            if not self._allowed(sender, pending.destination, now):
                del self.pending[key]
                continue
            if self._mapping(pending.destination, sender, now) is None:
                actions += self._probe(pending.destination, sender, now)
                continue
            del self.pending[key]
            for packet in pending.packets:
                actions += self._deliver(sender, pending.destination, pending.observed, packet, now)
        return actions

    def receive(self, destination: int, packet: bytes, observed: Address, now: float) -> list[Outbound]:
        if destination not in self.clients or not packet or len(packet) > MAX_DATAGRAM:
            return []
        probe = self.probes.get(packet)
        if probe is not None:
            if probe.destination != destination or now - probe.created > PROBE_LIFETIME:
                return []
            del self.probes[packet]
            self._learn(probe.client, destination, observed, now)
            return self._flush(now)
        # Only forward a native 0x0c if it matches a previously observed signed
        # introduction. Other replies may be delayed/replayed mapping challenges.
        if packet[0] == 12:
            intro = self.introductions.get(packet)
            if intro is None or intro[0] != destination or now - intro[2] > BUFFER_LIFETIME:
                return []
        sender = self.sources.get((destination, observed))
        if sender is not None and not self._allowed(sender, destination, now):
            return []
        if sender is None and not self._allow_unknown(destination, now):
            return []
        if sender is None and self.allow_pair is not None:
            if not any(self._allowed(i, destination, now) for i in self.clients if i != destination):
                return []
        if sender is not None and sender in self.clients:
            target = self._mapping(destination, sender, now)
            if target is not None:
                return self._deliver(sender, destination, observed, packet, now)
        key = destination, observed
        pending = self.pending.get(key)
        if pending is None:
            if len(self.pending) >= MAX_PENDING:
                self.events.emit("relay_pending_capacity", destination=destination)
                return []
            pending = Pending(destination, observed, now)
            self.pending[key] = pending
            self.events.emit("relay_source_unmapped", destination=destination, observed=endpoint(observed))
        pending.packets.append(packet)
        actions = []
        if sender is not None:
            actions += self._probe(destination, sender, now)
        else:
            # Probe every registered candidate rather than equating public IP with
            # identity. CGNAT can share an IP or choose different IPs by destination.
            for client_id in self.clients:
                if (client_id != destination and client_id not in pending.candidates
                        and self._allowed(client_id, destination, now)):
                    created = self._probe(client_id, destination, now)
                    if created:
                        pending.candidates.add(client_id)
                    actions += created
        return actions

    def introduce(self, request, observed: Address, now: float) -> list[Outbound]:
        sender = self.controls.get(observed)
        destination = self.virtuals.get(request.destination)
        if sender is None or destination is None or request.source != self.clients[sender].virtual:
            self.events.emit("relay_introduction_rejected", observed=endpoint(observed))
            return []
        # Establish both exact relay mappings. No signed packet is rewritten.
        actions = self._probe(sender, destination, now)
        actions += self._probe(destination, sender, now)
        self.introductions[b"\x0c" + request.raw[1:]] = sender, destination, now
        if len(self.introductions) > MAX_PENDING:
            self.introductions.pop(next(iter(self.introductions)))
        actions.append(Outbound((0, 0), self.clients[destination].control,
                                b"\x0b" + request.raw[1:], "relay-native-introduction"))
        self.events.emit("relay_introduction_seen", a=sender, b=destination,
                         note="signed fields preserved; both relay mappings probed")
        return actions

    def tick(self, now: float) -> list[Outbound]:
        actions = []
        for key, (address, seen) in list(self.mappings.items()):
            if now - seen > self.ttl:
                del self.mappings[key]
                self.sources.pop((key[1], address), None)
        self.introductions = {k: v for k, v in self.introductions.items()
                              if now - v[2] <= BUFFER_LIFETIME}
        for expected, probe in list(self.probes.items()):
            if now - probe.created > PROBE_LIFETIME:
                del self.probes[expected]
                self.events.emit("relay_probe_unanswered", client=probe.client,
                                 destination=probe.destination, outcome="unobserved")
            elif probe.sends < PROBE_SENDS and now - probe.last_sent >= PROBE_INTERVAL:
                probe.last_sent = now
                probe.sends += 1
                actions.append(Outbound((0, 0), self.clients[probe.client].control,
                                        probe.instruction, "relay-mapping-probe-retry"))
        for key, pending in list(self.pending.items()):
            if now - pending.created > BUFFER_LIFETIME:
                del self.pending[key]
                self.events.emit("relay_flow_unresolved", destination=pending.destination,
                                 observed=endpoint(pending.observed), buffered=len(pending.packets),
                                 reason="mapping_probe_incomplete", admission="unobserved")
        for key, flow in list(self.flows.items()):
            if now - flow.last_report >= 30 or now - flow.last_seen > self.ttl:
                self.events.emit("relay_flow_observation", a=flow.a, b=flow.b,
                                 packets=list(flow.packets), bytes=list(flow.sizes),
                                 bidirectional=all(flow.packets), admission="unobserved")
                flow.last_report = now
            if now - flow.last_seen > self.ttl:
                del self.flows[key]
        expired = {i for i, client in self.clients.items() if now - client.last_seen > self.ttl}
        for client_id in expired:
            client = self.clients.pop(client_id)
            self.controls.pop(client.control, None)
            self.virtuals.pop(client.virtual, None)
            self.unknown_budgets.pop(client_id, None)
            self.release(client_id)
            self.events.emit("relay_client_expired", client=client_id)
        if expired:
            self.mappings = {k: v for k, v in self.mappings.items() if not expired.intersection(k)}
            self.sources = {k: v for k, v in self.sources.items() if k[0] not in expired and v not in expired}
            self.probes = {k: v for k, v in self.probes.items()
                           if v.client not in expired and v.destination not in expired}
            self.pending = OrderedDict((k, v) for k, v in self.pending.items() if v.destination not in expired)
            self.flows = {k: v for k, v in self.flows.items() if not expired.intersection(k)}
            self.introductions = {k: v for k, v in self.introductions.items()
                                  if v[0] not in expired and v[1] not in expired}
        return actions
