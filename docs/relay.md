# One IPv4 relay trial and join diagnostics

This is an experimental relay for the unmodified PS2 client. It is implemented
and locally verified, including selected original game routines. It has not yet
completed a real console match. The first VPS trial must verify GameSpy metadata,
the full encrypted peer handshake, session admission, and sustained gameplay.

## Run on the VPS

Python 3.10+, no runtime packages:

The source bundle can be rebuilt with `python3 scripts/package.py`. It includes
code, tests and deployment notes, and excludes executables, Ghidra databases,
captures and local event logs. Extract it on the VPS and run inside its `codstun/`
directory, or install that package under `/opt/codstun/` for the supplied service.

```sh
python3 -m codstun --public-ip YOUR_VPS_IPV4 \
  --relay --relay-ports 20000-20199 --event-log events.jsonl
```

Allow UDP 2273, 2274 and 20000–20199 in the VPS/provider firewall. Use host
networking if containerized. The relay ports must preserve their numbers through
any server-side NAT. The VPS itself must be publicly reachable.

The existing revival DNS should return this VPS's IPv4 for exactly
`bro.stun.activision.com`. Keep the existing GameSpy/OpenSpy redirects. Every
participant must boot fresh and perform online discovery through this service
before the host creates a new room. Existing rooms and cached real endpoints are
not automatically converted to relay endpoints. Do not mix direct and relay modes
mid-session.

`deploy/codstun.service` and `deploy/codstun.env.example` are configured for this
one IP trial. Install code under `/opt/codstun/`; the unit creates
`/var/lib/codstun/` for its event file. Replace the example IP before starting it.

Smoke check from another machine:

```sh
python3 scripts/probe.py YOUR_VPS_IPV4 --relay
```

This checks discovery and the advertised virtual NAT topology. It is not a console
join test and does not measure the probing computer's physical NAT in relay mode.

## How the relay enters the client

Each gameplay socket's initial public address request gets a distinct virtual
endpoint, for example `VPS:20000` and `VPS:20001`. This occurs before the game
constructs its own address, publishes its GameSpy room metadata, and authenticates
peer traversal packets. Existing signed addresses and encrypted gameplay packets
are never rewritten by the relay.

The client publishes separate `DW_PUBLIC_IP`, `DW_PUBLIC_PORT`, and `DW_NAT_TYPE`
fields in its GameSpy metadata. Host creation at `0x002563d0` copies its Demonware
public endpoint into those fields. The query callback at `0x0026dd2c` reads those
fields into the server record; `0x00253b78` uses them to construct the remote
Demonware address. This provides a path through the existing revival backend if
it preserves those fields. Confirm that behavior during the live trial; source
analysis does not prove the deployed backend's behavior.

Relay mode presents Open **virtual** endpoints. It deliberately does not report
the physical NAT classification. The original client rejects some Moderate and
Strict combinations before trying the introducer, so returning virtual endpoints
while retaining those classifications would still prevent connections.

For its NAT test, the relay supplies the same server IP with alternate port Q and
answers from the already contacted primary port P. The original client compares
the reply's source IP to the advertised alternate IP and requires a source port
different from Q. This finishes its Open path without requiring an unsolicited
reply through the physical NAT. This behavior is enabled only by `--relay`.

## Learning destination-dependent mappings

A mapping observed at `VPS:2273` need not work at `VPS:20000`. The relay does not
guess these ports or infer player identity from a shared public IP.

The original type `0x0b` introduction handler at `0x003a5364` answers by changing
the first byte to `0x0c` and sending to the first embedded endpoint. It does so
without needing a pending join or validating the copied HMAC field. A server can
therefore send an unpredictable echo challenge from the existing control socket
and ask the client to send its response to an exact virtual peer endpoint.

The relay's challenge uses a random 32-bit identifier and 80 random bits in the
copied field. This is an echo proof, not a generated Demonware session MAC. The
relay accepts the exact expected response only once and only at the requested
virtual socket. It then knows that client's actual mapping toward that socket.

For clients A and B:

1. A sends a peer packet to B's advertised virtual port VB.
2. If A's source is not known, challenges ask registered clients to send to VB.
   Matching nonce responses identify A, including behind shared-IP CGNAT. The
   implementation also supports a different public IP toward the relay port.
3. A challenge asks B to send to A's virtual port VA. This opens B's filter toward
   VA and proves B's mapping for that exact destination.
4. Buffered A traffic is sent from VA to that proved B mapping. B replies to VA;
   the relay forwards from VB to A's proved mapping toward VB.

Each console sees its peer at a stable virtual endpoint. The scheme supports a
mesh of peers as well as a host/guest pair. The mapping proof replies are consumed
by the server. Normal peer payloads, including encrypted packets, are forwarded
unchanged. Native signed introduction replies are allowed only for introductions
the service actually observed.

The default is at most 64 registered clients; one virtual port is allocated per
client. Registrations, mappings and idle flows expire after 180 seconds without
activity. The game's control keepalive interval is 15 seconds. Probes are retried
four times at 0.5-second intervals, remain valid for three seconds, and unresolved
packet buffers expire after six seconds. State, unknown-source probe rates, and
buffer sizes are bounded. Rebinding requires another nonce proof.

## Predicting a direct join rejection

After local discovery fails, `0x003a4994` follows this table. Rows are the local
client's advertised NAT type; columns are the remote peer's advertised type.

| Local / remote | Open (1) | Moderate (2) | Strict (3) |
| --- | --- | --- | --- |
| Open (1) | Direct | Introducer | Introducer |
| Moderate (2) | Direct | Introducer | Reject |
| Strict (3) | Direct | Reject | Reject |

These decisions have been executed in the original MIPS function. A Reject cell
can explain why the introducer sees no request. A permitted cell does not prove
reachability: the original direct and introduced handlers reply to the embedded
advertised endpoint, which can be wrong for a destination-dependent mapping.

An operator can check advertised `DW_NAT_TYPE` values with:

```sh
python3 scripts/check_pair.py --local-nat strict --peer-nat moderate
```

Relay mode advertises Open virtual addresses so that policy permits the relay
path. It does not change the physical router or enable UDP when the network blocks
outbound UDP entirely.

## What join failures can be observed

The original session layer distinguishes host and other-peer connection stages.
`0x003bc4a4` sets session state 5 after a host connection failure and state 6 after
a peer connection failure. Callback `0x00241e1c` maps these to frontend states 9
and 10; `0x00261fb0` displays `CANNOT_CONNECT_TO_HOST` and
`CANNOT_CONNECT_TO_PEERS`. A host connection alone therefore does not establish
that every peer connection, admission, or session consistency step succeeded.

In direct mode, the NAT server can observe discovery, introductions and retries.
It cannot see direct replies, game admission, or gameplay. It reports the final
outcome as unobserved rather than labeling silence a failed join.

In relay mode, the server can additionally observe:

| Event | Established fact |
| --- | --- |
| `relay_registered` | observed control endpoint and assigned virtual endpoint |
| `relay_probe_sent` | instruction sent to learn an exact destination mapping |
| `relay_mapping_proved` | matching nonce returned at the requested relay socket |
| `relay_probe_unanswered` | no matching reply within this probe window |
| `relay_flow_started` | first opaque peer payload forwarded |
| `relay_flow_bidirectional` | peer payloads forwarded both ways |
| `relay_flow_unresolved` | mapping setup did not complete before buffer expiry |
| `relay_flow_observation` | packet/byte totals for the pair, every 30 seconds |

An unanswered probe can mean filtering, expired control mapping, a client not
running this handler yet, a disconnected console, or packet loss. It does not
identify which cause occurred. Bidirectional encrypted traffic is useful progress
evidence but does not establish successful admission. There is no authenticated
TSFP-style `PENT` event available to this standalone service, so automatic failed
join memory is not inferred from silence or low traffic counts.

`--event-log` writes JSON lines without packet bodies, HMACs, or GameSpy security
keys. `--verbose` adds routing byte counts rather than dumping payloads. A summary:

```sh
python3 scripts/report.py events.jsonl
```

## Console trial

1. Start the relay with the real VPS IP and confirm its public UDP firewall.
2. Confirm revival DNS resolves `bro.stun.activision.com` to the VPS from the
   console's actual network configuration.
3. Boot and sign in two clients. Expect two `relay_registered` events with
   different virtual ports. Record each player's role and the test start time.
4. Create a new room. If backend logs are available, confirm its
   `DW_PUBLIC_IP/PORT` points to the virtual endpoint and `DW_NAT_TYPE` is 1.
   Never include `DW_SECURITY_KEY` in a shared diagnostic log.
5. Join from a separate Internet connection. Expect nonce proofs, a flow start,
   and bidirectional traffic. Record the exact on-screen error if it fails.
6. After a successful two-player match, add a third player to exercise peer mesh
   setup. Then try a restrictive connection or CGNAT and two clients sharing a
   public IP.
7. Run long enough to exercise the 15-second keepalives and 30-second flow
   summaries, then test leaving and rejoining. Real game state and observed relay
   traffic should be correlated rather than equated.

For a packet capture when needed:

```sh
sudo tcpdump -ni any -s0 -w codbro-relay.pcap \
  'udp port 2273 or udp port 2274 or udp portrange 20000-20199'
```

## Validation boundaries

`scripts/verify_network.py` runs the original NAT policy matrix, the one-IP
virtual NAT response path, and actual original client responses to our nonce
instructions. It drives the relay with those responses to distinguish multiple
shared-IP clients using destination-dependent ports.

The unit suite additionally exercises synthetic strict filtering with stable and
destination-dependent mappings, public-IP pooling, peer mesh routing, replay
rejection, expiry, rebinding and bounds. A real UDP test uses three clients with
separate control and per-destination sockets, establishing the actual socket
source ports and byte-preserving forwarding.

These checks do not boot a console, complete the encrypted game handshake, or
prove that the revival backend preserves the virtual metadata. Those are the
remaining live validation steps. The relay remains opt-in until that trial.
