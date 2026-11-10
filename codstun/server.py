# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""UDP service and packet routing. Requires only Python's standard library."""

import argparse
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import math
import os
import re
import selectors
import signal
import socket
import time

from . import __version__
from .diagnostics import Events, Traffic, endpoint, packet_type
from .adaptive import Adaptive
from .relay import Relay
from .protocol import (Address, CHANGE_IP, CHANGE_PORT, INTRO_REQUEST, IP_REQUEST, Listener, Outbound,
                       KEEPALIVE, NAT_REQUEST, ProtocolError, forward_intro,
                       ip_reply, nat_reply, parse_request)

LOG = logging.getLogger("codstun")


@dataclass(frozen=True)
class Node:
    bind_ip: str
    public_ip: str

    def __post_init__(self):
        for name in ("bind_ip", "public_ip"):
            object.__setattr__(self, name, str(ipaddress.IPv4Address(getattr(self, name))))
        public = ipaddress.IPv4Address(self.public_ip)
        if public.is_unspecified or public.is_multicast or str(public) == "255.255.255.255":
            raise ValueError("advertised address must be a unicast IPv4 address")


@dataclass(frozen=True)
class Config:
    nodes: tuple[Node, ...]
    port: int = 2273
    alternate_port: int = 2274
    peer_ttl: float = 120.0
    max_peers: int = 16384
    relay_ports: tuple[int, int] | None = None
    relay_max_clients: int = 64
    adaptive_relay: bool = False
    direct_window: float = 1.0
    traffic_interval: float = 10.0
    packet_samples: int = 8

    def __post_init__(self):
        if len(self.nodes) not in (1, 2):
            raise ValueError("configure one or two server addresses")
        if any(not 1 <= p <= 65535 for p in (self.port, self.alternate_port)):
            raise ValueError("ports must be between 1 and 65535")
        if self.port == self.alternate_port:
            raise ValueError("the two UDP ports must differ")
        if len(self.nodes) == 2:
            if self.nodes[0].public_ip == self.nodes[1].public_ip:
                raise ValueError("two-address mode requires distinct public IPv4 addresses")
            if (self.nodes[0].bind_ip == self.nodes[1].bind_ip or
                    any(n.bind_ip == "0.0.0.0" for n in self.nodes)):
                raise ValueError("two-address mode requires two distinct, explicit bind addresses")
        if self.peer_ttl <= 0 or self.max_peers < 1:
            raise ValueError("peer TTL and capacity must be positive")
        if not math.isfinite(self.direct_window) or not 0.25 <= self.direct_window <= 2.0:
            raise ValueError("direct window must be a finite 0.25..2.0 seconds")
        if not math.isfinite(self.traffic_interval) or not 1 <= self.traffic_interval <= 300:
            raise ValueError("traffic interval must be 1..300 seconds")
        if not 0 <= self.packet_samples <= 64:
            raise ValueError("packet samples must be 0..64")
        if self.adaptive_relay and self.relay_ports is None:
            raise ValueError("adaptive mode requires relay ports")
        if self.relay_ports is not None:
            lo, hi = self.relay_ports
            if len(self.nodes) != 1:
                raise ValueError("relay modes use one public IPv4 address")
            if not 1 <= lo <= hi <= 65535 or any(lo <= p <= hi for p in (self.port, self.alternate_port)):
                raise ValueError("relay port range must be valid and exclude discovery ports")
            if not 2 <= self.relay_max_clients <= min(256, hi - lo + 1):
                raise ValueError("relay capacity must be 2..256 and fit in the relay port range")

    def advertised(self, listener: tuple[int, int]) -> Address:
        node, port_index = listener
        return Address(self.nodes[node].public_ip, (self.port, self.alternate_port)[port_index])


class Router:
    def __init__(self, config: Config, allocate_relay=None, release_relay=None, events=None):
        self.config = config
        self.events = events or Events()
        self.relay = (Relay(allocate_relay, release_relay, events=self.events,
                            max_clients=config.relay_max_clients)
                      if config.relay_ports is not None else None)
        self.peers: OrderedDict[Address, float] = OrderedDict()
        self.buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self.attempts = OrderedDict()
        self.adaptive = (Adaptive(self.relay, self.events, config.direct_window)
                         if config.adaptive_relay else None)

    def _admit(self, ip: str, now: float) -> bool:
        tokens, last = self.buckets.pop(ip, (100.0, now))
        tokens = min(100.0, tokens + max(0.0, now - last) * 50.0)
        admitted = tokens >= 1.0
        self.buckets[ip] = (tokens - 1.0 if admitted else tokens, now)
        while len(self.buckets) > self.config.max_peers:
            self.buckets.popitem(last=False)
        return admitted

    def _remember(self, address: Address, now: float):
        self.peers.pop(address, None)
        self.peers[address] = now
        while self.peers:
            first, seen = next(iter(self.peers.items()))
            if len(self.peers) <= self.config.max_peers and now - seen <= self.config.peer_ttl:
                break
            self.peers.pop(first)

    def route(self, data: bytes, observed: Address, listener: tuple[int, int],
              now: float | None = None) -> list[Outbound]:
        now = time.monotonic() if now is None else now
        if not self._admit(observed.ip, now):
            self.events.emit("packet_dropped", reason="discovery_rate_limit", observed=endpoint(observed),
                             listener=list(listener), bytes=len(data), packet_type=packet_type(data))
            return []
        request = parse_request(data)
        self._remember(observed, now)
        node, port_index = listener
        if request.kind == IP_REQUEST:
            advertised = observed
            if self.relay:
                client = self.relay.register(observed, now)
                if client is None:
                    return []
                if not self.adaptive:
                    advertised = client.virtual
            self.events.emit("ip_discovery", observed=endpoint(observed), advertised=endpoint(advertised),
                             client=client.id if self.relay else None,
                             mode="adaptive_real" if self.adaptive else "relay_virtual" if self.relay else "direct")
            return [Outbound(listener, observed, ip_reply(advertised), "public-address")]
        if request.kind == NAT_REQUEST:
            self.events.emit("nat_request", observed=endpoint(observed), flags=request.flags,
                             listener=list(listener), mode="coordinated" if self.adaptive
                             else "relay_virtual" if self.relay else "physical")
            if self.adaptive:
                if request.flags & CHANGE_IP:
                    self.events.emit("nat_reply_withheld", observed=endpoint(observed),
                                     flags=request.flags, reason="coordinated_test_2_timeout")
                    return []
                # All stages use the already contacted primary endpoint. The
                # original client ignores duplicate first replies in test 2 and
                # reaches logical Moderate after its native timeout and test 3.
                primary = self.config.advertised((0, 0))
                return [Outbound((0, 0), observed, nat_reply(observed, primary), "coordinated-nat")]
            if self.relay:
                # In the virtual topology all advertised peers are reachable relay
                # endpoints. The original state machine compares the UDP source
                # port to the alternate field; choosing Q lets a same-socket reply
                # from P finish test 2 even behind strict physical NAT filtering.
                alternate = self.config.advertised((0, 1))
                return [Outbound((0, 0), observed, nat_reply(observed, alternate), "virtual-nat-topology")]
            if request.flags & CHANGE_IP and len(self.config.nodes) == 1:
                # Replying from the same IP here would falsely report Open NAT.
                LOG.debug("withholding change-IP reply in one-address mode")
                self.events.emit("nat_reply_withheld", observed=endpoint(observed),
                                 flags=request.flags, reason="second_public_ip_unavailable")
                return []
            reply_node = node ^ bool(request.flags & CHANGE_IP)
            reply_port = port_index ^ bool(request.flags & CHANGE_PORT)
            alternate_node = node ^ 1 if len(self.config.nodes) == 2 else node
            alternate = self.config.advertised((alternate_node, port_index))
            return [Outbound((reply_node, reply_port), observed,
                             nat_reply(observed, alternate), f"nat-flags-{request.flags}")]
        if request.kind == KEEPALIVE:
            if self.relay:
                self.relay.keepalive(observed, now)
            LOG.debug("keepalive %s:%d", observed.ip, observed.port)
            return []
        if request.kind == INTRO_REQUEST:
            if self.adaptive:
                return self.adaptive.introduce(request, observed, now)
            if self.relay:
                return self.relay.introduce(request, observed, now)
            attempt_key = hashlib.blake2s(request.raw, digest_size=8).hexdigest()
            first, _, count = self.attempts.pop(attempt_key, (now, now, 0))
            count += 1
            self.attempts[attempt_key] = first, now, count
            while len(self.attempts) > 1024:
                self.attempts.popitem(last=False)
            fields = dict(attempt=attempt_key, observed=endpoint(observed),
                          advertised=endpoint(request.source), target=endpoint(request.destination),
                          count=count, elapsed_ms=round((now - first) * 1000))
            # This also prevents forwarding arbitrary UDP to unrelated endpoints.
            # Hosts keep the introducer mapping alive with type 0x0e packets.
            if request.source != observed:
                self.events.emit("introduction_blocked", reason="source_mapping_mismatch", **fields)
                LOG.debug("introduction source does not match observed endpoint: %s", observed)
                return []
            destination = request.destination
            if destination is None or destination == observed:
                self.events.emit("introduction_blocked", reason="invalid_target", **fields)
                return []
            seen = self.peers.get(destination)
            if seen is None or now - seen > self.config.peer_ttl:
                self.events.emit("introduction_blocked", reason="target_not_recently_seen", **fields)
                LOG.debug("introduction target has no recent registration: %s", destination)
                return []
            self.events.emit("introduction_forwarded", outcome="direct_reply_unobserved", **fields)
            return [Outbound(listener, destination, forward_intro(request), "peer-introduction")]
        return []

    def tick(self, now=None):
        now = time.monotonic() if now is None else now
        for key, (first, last, count) in list(self.attempts.items()):
            if now - last > 6:
                del self.attempts[key]
                self.events.emit("introduction_observation_ended", attempt=key, count=count,
                                 duration_ms=round((last - first) * 1000), outcome="unobserved")
        actions = self.relay.tick(now) if self.relay else []
        if self.adaptive:
            actions.extend(self.adaptive.tick(now))
        return actions


class Server:
    def __init__(self, config: Config):
        self.config = config
        self.selector = selectors.DefaultSelector()
        self.sockets: dict[Listener, socket.socket] = {}
        self.router = Router(config, self.allocate_relay, self.release_relay)
        self.events = self.router.events
        self.traffic = Traffic(self.events, interval=config.traffic_interval, samples=config.packet_samples)
        self.last_snapshot = time.monotonic()
        self.last_tick = self.last_snapshot
        self.max_tick_gap_ms = 0
        self.max_processing_ms = 0
        self.opened = False
        self.stop_reason = "closed"
        self.running = False

    def allocate_relay(self, client_id):
        lo, hi = self.config.relay_ports
        node = self.config.nodes[0]
        used = {s.getsockname()[1] for s in self.sockets.values()}
        for port in range(lo, hi + 1):
            if port in used:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((node.bind_ip, port))
                sock.setblocking(False)
                key = ("relay", client_id)
                self.selector.register(sock, selectors.EVENT_READ, key)
            except OSError:
                sock.close()
                continue
            self.sockets[key] = sock
            return Address(node.public_ip, port)
        raise OSError("no free relay port")

    def release_relay(self, client_id):
        sock = self.sockets.pop(("relay", client_id), None)
        if sock:
            self.selector.unregister(sock)
            sock.close()

    def send(self, outbound):
        for reply in outbound:
            try:
                self.sockets[reply.listener].sendto(reply.payload, reply.destination.socket_tuple())
            except OSError as exc:
                self.events.emit("udp_error", operation="send", listener=list(reply.listener),
                                 peer=endpoint(reply.destination), reason=reply.reason, errno=exc.errno,
                                 error=str(exc), bytes=len(reply.payload), packet_type=packet_type(reply.payload))
                continue
            self.traffic.record("tx", reply.listener, reply.destination, reply.payload, reason=reply.reason)
            LOG.debug("tx %s:%d via %s reason=%s bytes=%d", reply.destination.ip,
                      reply.destination.port, reply.listener, reply.reason, len(reply.payload))

    def open(self):
        try:
            for i, node in enumerate(self.config.nodes):
                for j, port in enumerate((self.config.port, self.config.alternate_port)):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        sock.bind((node.bind_ip, port))
                        sock.setblocking(False)
                        self.selector.register(sock, selectors.EVENT_READ, (i, j))
                    except BaseException:
                        sock.close()
                        raise
                    self.sockets[i, j] = sock
                    LOG.info("listening %s:%d/udp, advertised %s:%d", node.bind_ip, port,
                             node.public_ip, port)
        except BaseException:
            self.close()
            raise
        if self.router.adaptive:
            LOG.warning("experimental adaptive relay enabled: coordinated Moderate; direct window %.2fs",
                        self.config.direct_window)
        elif self.router.relay:
            LOG.warning("experimental virtual relay enabled: advertised NAT type describes relay reachability")
        elif len(self.config.nodes) == 1:
            LOG.warning("one-address mode: NAT test 2 will time out; Open NAT cannot be measured")
        self.opened = True
        revision = os.environ.get("CODSTUN_REVISION", "")
        self.events.emit("service_started", version=__version__,
                         revision=revision if re.fullmatch(r"[0-9a-f]{40}", revision) else "unknown",
                         mode="adaptive" if self.router.adaptive else "relay" if self.router.relay else "direct",
                         direct_window_ms=round(self.config.direct_window * 1000),
                         relay_ports=self.config.relay_ports, relay_max_clients=self.config.relay_max_clients,
                         traffic_interval=self.config.traffic_interval, packet_samples=self.config.packet_samples,
                         listeners=[dict(listener=list(key), bind=endpoint(Address(*sock.getsockname())),
                                         receive_buffer=sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                                         send_buffer=sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
                                    for key, sock in self.sockets.items()])
        return self

    def poll(self, timeout: float = 0.5):
        for key, _ in self.selector.select(timeout):
            sock = key.fileobj
            data, observed = b"", None
            processing_started = time.monotonic()
            try:
                # Discovery requests are <=29 bytes; relay datagrams are capped at 2048.
                data, peer = sock.recvfrom(2049)
                observed = Address(peer[0], peer[1])
                self.traffic.record("rx", key.data, observed, data)
                LOG.debug("rx %s:%d via %s bytes=%d", *peer, key.data, len(data))
                if key.data[0] == "relay":
                    outbound = self.router.relay.receive(key.data[1], data, observed, time.monotonic())
                else:
                    outbound = self.router.route(data, observed, key.data)
                self.send(outbound)
            except ProtocolError as exc:
                self.events.emit("packet_dropped", reason="protocol_error", error=str(exc),
                                 observed=endpoint(observed), listener=list(key.data),
                                 bytes=len(data), packet_type=packet_type(data))
                LOG.debug("ignored packet: %s", exc)
            except OSError as exc:
                self.events.emit("udp_error", operation="receive", listener=list(key.data),
                                 errno=exc.errno, error=str(exc), reason="socket_receive")
            self.max_processing_ms = max(self.max_processing_ms,
                                         (time.monotonic() - processing_started) * 1000)
        try:
            self.send(self.router.tick())
        except OSError:
            LOG.exception("UDP timer send failed")
        now = time.monotonic()
        self.max_tick_gap_ms = max(self.max_tick_gap_ms, (now - self.last_tick) * 1000)
        self.last_tick = now
        self.traffic.flush(now)
        if now - self.last_snapshot >= self.config.traffic_interval:
            relay, adaptive = self.router.relay, self.router.adaptive
            self.events.emit("service_snapshot", sockets=len(self.sockets), peers=len(self.router.peers),
                             clients=len(relay.clients) if relay else 0, mappings=len(relay.mappings) if relay else 0,
                             probes=len(relay.probes) if relay else 0, pending=len(relay.pending) if relay else 0,
                             buffered_packets=sum(len(p.packets) for p in relay.pending.values()) if relay else 0,
                             flows=len(relay.flows) if relay else 0,
                             attempts=len(adaptive.attempts) if adaptive else len(self.router.attempts),
                             offered_pairs=len(adaptive.offered_pairs) if adaptive else 0,
                             max_processing_ms=round(self.max_processing_ms, 3),
                             max_tick_gap_ms=round(self.max_tick_gap_ms, 3),
                             event_counts=dict(self.events.counts))
            self.last_snapshot, self.max_processing_ms, self.max_tick_gap_ms = now, 0, 0
        self.events.flush()

    def serve(self):
        self.running = True
        while self.running:
            self.poll()

    def stop(self, signum=None, *_):
        self.stop_reason = signal.Signals(signum).name if signum else "requested"
        self.running = False

    def close(self):
        self.running = False
        if self.opened:
            if self.router.relay:
                for flow in self.router.relay.flows.values():
                    self.router.relay.report_flow(flow, time.monotonic(), final=True)
            self.traffic.flush(final=True)
            self.events.emit("service_stopped", reason=self.stop_reason)
            self.events.flush(final=True)
            self.opened = False
        for sock in self.sockets.values():
            self.selector.unregister(sock)
            sock.close()
        self.sockets.clear()
        self.selector.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0", help="primary local IPv4 address")
    parser.add_argument("--public-ip", required=True, help="primary IPv4 address visible to PS2 clients")
    parser.add_argument("--secondary-bind", help="second local IPv4 address")
    parser.add_argument("--secondary-public-ip", help="second IPv4 address visible to clients")
    parser.add_argument("--port", type=int, default=2273)
    parser.add_argument("--alternate-port", type=int, default=2274)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--mode", choices=("direct", "relay", "adaptive"), help="routing mode; default direct")
    mode.add_argument("--relay", action="store_true", help="always use virtual public relay endpoints")
    mode.add_argument("--adaptive-relay", action="store_true", help="try native introductions before offering relay routes")
    parser.add_argument("--direct-window", type=float, default=1.0, help="adaptive direct-attempt window, 0.25..2 seconds")
    parser.add_argument("--relay-ports", default="20000-20199", help="public UDP port range for virtual endpoints")
    parser.add_argument("--relay-max-clients", type=int, default=64)
    parser.add_argument("--event-log", help="append structured observations as JSON lines to this file")
    parser.add_argument("--event-log-bytes", type=int, default=20 * 1024 * 1024)
    parser.add_argument("--event-log-backups", type=int, default=10)
    parser.add_argument("--traffic-interval", type=float, default=10,
                        help="seconds between packet/flow state summaries, 1..300")
    parser.add_argument("--packet-samples", type=int, default=8,
                        help="initial metadata samples per UDP stream, 0..64; no packet contents")
    parser.add_argument("--verbose", action="store_true", help="log routing decisions and byte counts")
    args = parser.parse_args(argv)
    if args.event_log_bytes < 1024 or not 1 <= args.event_log_backups <= 50:
        parser.error("event log size must be >=1024 bytes and backups must be 1..50")
    if bool(args.secondary_bind) != bool(args.secondary_public_ip):
        parser.error("--secondary-bind and --secondary-public-ip must be supplied together")
    try:
        selected_mode = args.mode or ("adaptive" if args.adaptive_relay else "relay" if args.relay else "direct")
        nodes = [Node(args.bind, args.public_ip)]
        if args.secondary_bind:
            nodes.append(Node(args.secondary_bind, args.secondary_public_ip))
        relay_ports = None
        if selected_mode != "direct":
            lo, hi = args.relay_ports.split("-")
            relay_ports = int(lo), int(hi)
        config = Config(tuple(nodes), args.port, args.alternate_port,
                        relay_ports=relay_ports, relay_max_clients=args.relay_max_clients,
                        adaptive_relay=selected_mode == "adaptive", direct_window=args.direct_window,
                        traffic_interval=args.traffic_interval, packet_samples=args.packet_samples)
    except ValueError as exc:
        parser.error(str(exc))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.event_log:
        try:
            os.umask(0o077)
            handler = RotatingFileHandler(args.event_log, maxBytes=args.event_log_bytes,
                                          backupCount=args.event_log_backups)
            os.chmod(args.event_log, 0o600)
        except OSError as exc:
            parser.error(str(exc))
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger("codstun.events").addHandler(handler)
    server = Server(config)
    signal.signal(signal.SIGTERM, server.stop)
    signal.signal(signal.SIGINT, server.stop)
    try:
        server.open()
        server.serve()
    except OSError as exc:
        server.events.emit("service_failure", error=str(exc), error_type=type(exc).__name__)
        server.stop_reason = "failure"
        LOG.error("could not start UDP service: %s", exc)
        return 1
    except Exception as exc:
        server.events.emit("service_failure", error=str(exc), error_type=type(exc).__name__)
        server.stop_reason = "failure"
        LOG.exception("UDP service failed")
        return 1
    finally:
        server.close()
    return 0
