# codstun

A replacement Demonware NAT service for **Call of Duty 2: Big Red One on PS2**.
It supplies public IP discovery, NAT type discovery, NAT keepalives, and peer
introduction alongside an existing OpenSpy/GameSpy revival setup. Experimental
adaptive routing tries peers directly and offers a gameplay relay when traversal
keeps retrying. It uses one public VPS IPv4 and needs no OpenSpy changes.

The analyzed game connects to **`bro.stun.activision.com:2273/udp`**. This is a
custom Demonware protocol. An ordinary RFC STUN server will not answer its packets.
DNS redirection is sufficient for this component; the game executable needs no patch.

**Status:** adaptive routing, discovery, and relay mapping instructions are checked against the
original US Collector's Edition `MP.BIN` code in a MIPS emulator, plus local UDP
tests and synthetic NAT models. A match between
two real PS2/PCSX2 clients over the Internet has **not** been tested. The community
joining issue has not yet been reproduced, so this is a candidate fix, not a
confirmed diagnosis of every join failure.

## Run

Requires Python 3.10 or newer. Runtime dependencies: none. Run from this directory:

For the **one IPv4 adaptive VPS trial**:

```sh
python3 -m codstun --public-ip YOUR_SERVER_IPV4 \
  --mode adaptive --relay-ports 20000-20199 --event-log events.jsonl
```

Open UDP **2273, 2274, and 20000–20199**. Redirect only
`bro.stun.activision.com` to this VPS, preserving the existing revival redirects.
Boot every client fresh, sign in again, and create a new room after selecting a
mode. Every participant must use this service during discovery. Adaptive mode
advertises real endpoints and logical **Moderate** routing, then offers relay
resolution after another introduction request beyond the default one-second
direct window. Small mapping probes prepare the relay while direct traffic runs.
The label is a routing choice, not a physical NAT measurement. Discovery includes
the original client's roughly three-second test-2 timeout.

[Adaptive routing and console trial limits](docs/direct-first.md) explains the
direct attempt, retry-triggered relay offer, original-client evidence, and remaining
validation. A successful traversal response does not prove encrypted admission.

For the original **always-relay mode**, use `--mode relay` (or `--relay`). It
advertises virtual public endpoints and logical Open routing from startup.
[Relay transport design](docs/relay.md) describes the shared mapping and opaque
forwarding engine. Do not mix modes in a running room.

For **direct discovery only**, leave off `--relay`:

```sh
python3 -m codstun --public-ip YOUR_SERVER_IPV4 --verbose
```

This starts the one address mode on UDP 2273 and 2274. It supports public address
discovery and peer introduction. NAT test 2 times out by design; the game can then
finish test 3 and commonly reports Moderate. This mode cannot distinguish all NAT
types and does not give a restrictive router the connectivity of an open router.

For the complete NAT test, assign **two distinct public IPv4 addresses to one
host**, then bind both local addresses:

```sh
python3 -m codstun \
  --bind LOCAL_IP_A --public-ip PUBLIC_IP_A \
  --secondary-bind LOCAL_IP_B --secondary-public-ip PUBLIC_IP_B \
  --verbose
```

On a VPS where the public addresses are on its network interfaces, each local IP
equals its corresponding public IP. If there is server-side NAT, bind the private
interface addresses and advertise their public counterparts. Preserve the UDP
port numbers through that NAT. Two bind addresses must exist on the host; merely
entering a second public IP does not configure an interface.

Allow inbound and outbound UDP **2273 and 2274 on both IPs** in the host firewall
and provider firewall. Replies sometimes come from a different IP and port than
the request's destination; those replies must be allowed. Both addresses need
direct UDP reachability. An HTTP reverse proxy cannot carry this service.

## DNS redirect

Add an exact override to the DNS resolver the consoles already use:

```text
bro.stun.activision.com -> PUBLIC_IP_A
```

For dnsmasq, a hosts file entry read through `addn-hosts` is an exact override:

```text
PUBLIC_IP_A bro.stun.activision.com
```

Return the primary address for this hostname. The protocol supplies the second
address to clients. Keep the existing OpenSpy/GameSpy redirects in your resolver.
Use a plain DNS A record/override; DNS does not change the game's UDP port.

## Probe the deployment

From a separate Internet connection:

```sh
python3 scripts/probe.py PUBLIC_IP_A
python3 scripts/probe.py bro.stun.activision.com
```

Add `--adaptive` for adaptive discovery or `--relay` for always-relay discovery.
Those labels describe routing, not the probe computer's physical NAT. Exercise
synthetic direct/fallback traffic as well:

```sh
python3 scripts/probe.py PUBLIC_IP_A --adaptive
python3 scripts/smoke_adaptive.py PUBLIC_IP_A --case relay
```

The relay smoke trial uses three synthetic clients and suppresses their direct
responses. Use `--case all` on a host where the synthetic peers can reach each
other directly, such as on the VPS itself. The tool checks byte-preserving UDP
traffic and source ports, not a real encrypted match. Summarize observations:

```sh
python3 scripts/report.py events.jsonl --all --redact --timeline
```

Continuous [join diagnostics](docs/diagnostics.md) include a run ID and deployed
version, correlated attempt/probe events, mapping changes, drop reasons, packet
metadata samples and ten-second traffic/state summaries. Packet bodies and
authenticators are excluded; raw logs containing endpoint addresses stay private.

The hostname command uses that computer's configured resolver. It reaches your
service only if that resolver has the override. In direct mode, the probe's
classification describes the probe computer's connection.

For the first game trial, start with `--verbose`, have one player host and another
join from a different network, and collect server output. Expected packet types:

| Byte | Meaning |
| --- | --- |
| `1e` / `1f` | public address request / reply |
| `14` / `15` | NAT test request / reply |
| `0e` | keepalive from a peer |
| `0a` / `0b` | introduction request / server forward |
| `0c` | direct reply from host to joining peer, normally absent from server logs |

A capture can help distinguish DNS, discovery, and peer connectivity failures:

```sh
sudo tcpdump -ni any -s0 -w codbro-nat.pcap 'udp port 2273 or udp port 2274'
```

Successful direct connections carry gameplay between peers, normally using client
UDP 3074. Adaptive mode forwards gameplay only for offered relay pairs. This
service cannot observe direct admission or guarantee fallback after a later DTLS
or game-session failure.

## Run as a service

For a Linux Docker VPS with automatic deployment of tested `main` commits, use
the [Docker deployment guide](docs/deployment.md). This pull deployment keeps
server configuration on the VPS and needs no GitHub deployment secrets.

Copy this project's `codstun/` package to `/opt/codstun/codstun/`, with directories
readable/executable by the service user. Copy `deploy/codstun.env.example` to
`/etc/codstun.env` and set the actual addresses. Then:

```sh
sudo install -m 644 deploy/codstun.service /etc/systemd/system/codstun.service
sudo systemctl daemon-reload
sudo systemctl enable --now codstun
sudo journalctl -u codstun -f
```

The supplied environment example enables the one IP adaptive trial and records
observations under `/var/lib/codstun/`, created by the service unit.

For the one IP relay with Docker on Linux:

```sh
docker build -t codstun .
docker run --rm --network host codstun \
  --public-ip YOUR_SERVER_IPV4 --mode adaptive --relay-ports 20000-20199
```

The public address must reach the Docker host. Host networking also preserves
the advertised relay source ports. For two IP direct discovery, use the matching
bind/public arguments from the earlier example.

## Evidence and development

[Protocol notes](docs/protocol.md) document packet layouts, original function
addresses, NAT behavior, and implementation limits.

```sh
python3 -m unittest discover -s tests -v
```

Optional verification using the owner's game executable and the `unicorn` Python
package:

```sh
python3 scripts/extract_game.py "/path/to/Call of Duty 2 - Big Red One (USA) (Collector's Edition).iso"
python3 scripts/verify_game.py research/private/MP.BIN
python3 scripts/verify_network.py research/private/MP.BIN
python3 scripts/verify_adaptive.py research/private/MP.BIN
```

This executes the original request serializers, response parsers, NAT state
machine, and host introduction handler. It replaces logging, optimized PS2 memory routines,
and socket sends with local hooks. It does not boot the game or emulate a router.
The adaptive verifier additionally substitutes crypto and lookup helpers and
executes the real traversal dispatch against the production router. The standard
tests exercise direct, fallback, and mesh traffic over real loopback UDP sockets.

Game executables, disassembly, Ghidra projects, and raw decompiler exports stay in
ignored research directories. They are not required to run or deploy the server.

## License

Copyright (C) 2026 codstun contributors.

This project's original source is licensed under the **GNU General Public
License, version 3 only** (`GPL-3.0-only`). See [LICENSE](LICENSE) for the full
terms. This program is distributed without warranty.

The license covers this replacement server and its original research tooling;
game executables and third-party software are not included. Optional Ghidra and
Unicorn installations retain their own licenses.
