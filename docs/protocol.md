# Protocol recovered from the PS2 executable

This document describes the original direct protocol. The optional one IP
[virtual endpoint relay](relay.md) changes discovery advertisement before peers
sign their packets and adds nonce mapping probes and opaque forwarding.
[Adaptive mode](direct-first.md) retains real advertised endpoints, selects the
native coordinated traversal path, and supplies a relay resolution on retries.
Its logical Moderate result deliberately uses the same primary UDP endpoint for
tests 1 and 3; it does not measure the physical NAT type.

## Analyzed build and scope

- Disc: `Call of Duty 2 - Big Red One (USA) (Collector's Edition).iso`.
- Boot executable: `SLUS_213.18`.
- Multiplayer executable: `/MP.BIN;1`, a stripped little endian MIPS R5900 ELF.
- `MP.BIN` SHA-256: `94dc5b04d0a2048663fd6aa38adb58af19cfaa336d96da0f8fef8934b57a8338`.
- Multiplayer configuration at `0x002547d4` explicitly sets hostname
  `bro.stun.activision.com` and server port **2273** (`0x08e1`). The library's
  default configuration at `0x003b93e0` agrees. The local gameplay port defaults
  to **3074** (`0x0c02`); NAT type discovery creates a separate UDP socket.

Addresses below are ELF virtual addresses, not disc offsets. The executable's
load segment maps file offset `0x80` to virtual address `0x00100000`.

The binary contains `bdIPDiscoveryClient`, `bdNATTypeDiscoveryClient`,
`bdNATTravClient`, and `bdNATTraversalPacket` source path/log strings that identify
the relevant code. These are independent of the GameSpy server list and login
services. Only this exact executable has been analyzed; other editions/regions
need comparison or an actual packet capture before claiming compatibility.

This implements the game-facing behavior inferred from those clients. We do not
have an original Activision server capture or server implementation. In
particular, the secondary port **2274 is our choice**, not a recovered hardcoded
original server port. The client learns the alternate endpoint from a reply.

## Common encodings

Transport is UDP/IPv4. The packets here contain no RFC 5389 STUN header, magic
cookie, transaction ID, or attribute list.

`bdSockAddr` serializes an address to six bytes:

| Offset | Size | Encoding |
| --- | --- | --- |
| 0 | 4 | IPv4 octets in their usual network order |
| 4 | 2 | Port as a little endian unsigned integer |

The raw IPv4 bytes are copied through the PS2 socket APIs; there is no reversal
of the four octets. Example: `198.51.100.7:31001` becomes `c6 33 64 07 19 79`.
See address serialization `0x003991dc`, deserialization `0x0039926c`, IPv4
serialization `0x003995d0`, and deserialization `0x00399608`.

Discovery uses a **padded version 1** header. Peer traversal uses a **packed
version 2** header. Mixing the two layouts breaks the client.

Padding in discovery requests is not always initialized by the game. The server
ignores its value and emits zero padding in replies.

## Public address discovery

Request, four bytes:

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 1 | `0x1e` |
| 1 | 1 | ignored padding |
| 2 | 2 | version `1`, little endian |

Reply, twelve bytes:

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 1 | `0x1f` |
| 1 | 1 | padding |
| 2 | 2 | version `1`, little endian |
| 4 | 6 | client's observed UDP source endpoint |
| 10 | 2 | padding |

Reply from the same server IP and port that received the request. The client
checks the UDP source endpoint against the configured server. The IP reply
parser itself does not check the first byte; `0x1f` is the paired reply code
used by this implementation.

Relevant functions:

- `0x003c4018`: request constructor, type `0x1e`, version `1`.
- `0x003c4030`: request serializer.
- `0x003c413c`: reply parser.
- `0x003c2f40`: receive loop, server endpoint validation, retry, success state.

The reply parser can also read packed version 2 replies, but the analyzed client
sends version 1 requests. The server implements that observed request format.

## NAT type discovery

Request, eight bytes:

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 1 | `0x14` |
| 1 | 1 | ignored padding |
| 2 | 2 | version `1`, little endian |
| 4 | 1 | change flags |
| 5 | 3 | padding |

Flag bit 0 requests a different source IP; bit 1 requests a different source
port. The game's three tests send values `0`, `3`, and `2`, respectively.

Reply, eighteen bytes:

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 1 | `0x15` |
| 1 | 1 | padding |
| 2 | 2 | version `1`, little endian |
| 4 | 6 | client's observed source endpoint for this request |
| 10 | 2 | padding |
| 12 | 6 | alternate server endpoint |

For a server with public IPs **A** and **B**, primary port **P** (2273), and
secondary port **Q** (2274), the expected flow is:

| Test | Client sends to | Flags | Server replies from | Alternate endpoint in reply |
| --- | --- | --- | --- | --- |
| 1 | A:P | `0` | A:P | B:P |
| 2 | A:P | `3` | B:Q | B:P |
| 3, if test 2 times out | B:P | `2` | B:Q | A:P |

The client stores its observed mapping and B:P from test 1. It declares Open
when test 2 receives a response whose source IP equals B and whose source port
differs from P. If test 2 fails, it performs test 3: an unchanged client mapping
means Moderate, a changed mapping or timeout means Strict. These are the game's
own labels and compatibility decisions.

Discovery uses a socket separate from gameplay. Do not take the NAT test socket's
ephemeral source port and advertise it as the gameplay endpoint; public address
discovery reports the gameplay socket separately.

Relevant functions:

- `0x003c4318`: request constructor, type `0x14`, version `1`, flags.
- `0x003c4334`: request serializer.
- `0x003c4528`: reply parser (requires type `0x15` in the receive loop).
- `0x003c34d4`: initial test 1.
- `0x003c37d4`, `0x003c397c`, `0x003c3b28`: test retries with flags `0`, `3`, `2`.
- `0x003c3ce0`: response handling and classification.
- `0x003b8a80`: both public IP discovery and NAT discovery must succeed before
  the library constructs its local title address and continues startup.

With one public server IP, codstun advertises the same IP as the alternate and
withholds change-IP replies. The client progresses through its timeout into
test 3. Answering test 2 from the same IP but a different port would fool this
client into Open; codstun deliberately avoids that. One-address mode cannot
measure filtering or mapping changes between distinct server IPs and can label
an actually restrictive NAT Moderate. Use two public IPs for meaningful results.

## NAT keepalive and peer introduction

Traversal packets have **29 bytes**, with no padding:

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 1 | packet type |
| 1 | 2 | version `2`, little endian |
| 3 | 10 | truncated HMAC |
| 13 | 4 | identifier, little endian |
| 17 | 6 | initiating peer's public endpoint |
| 23 | 6 | target peer's public endpoint |

Relevant types:

| Type | Action |
| --- | --- |
| `0x0a` | initiator requests introduction through server |
| `0x0b` | server forwards introduction to target |
| `0x0c` | target replies directly to initiator |
| `0x0d` | direct request to an Open peer, handled by peer |
| `0x0e` | keepalive to introducer; no response required |
| `0x0f`, `0x10` | local discovery request/reply between peers |

For `0x0a`, forward to the endpoint at offset 23 and change only the type byte
to `0x0b`. The target changes the type to `0x0c` and sends directly to the
endpoint at offset 17. Its response's UDP source endpoint tells the initiator
the working route to the target.

The peers authenticate the identifier and both embedded addresses with a
10-byte HMAC generated at `0x003a7458`. Packet type is outside that authenticated
material. The service can preserve the HMAC without possessing the key. It must
not rewrite the signed addresses to compensate for a bad advertised address.

Keepalive `0x0e` constructs two default/unused endpoints and identifier zero;
its HMAC field is not useful for routing. The service remembers the actual UDP
source and emits no keepalive reply. The implementation records recently active
endpoints, limits state, and only forwards introductions to a recently observed
target. Default expiry is 120 seconds. A source endpoint inconsistent with the
signed source is rejected.

Relevant functions:

- `0x003a6df4`: initiator constructs and sends type `0x0a` to introducer.
- `0x003a7f88`: traversal constructor, version `2`.
- `0x003a7fe4`: packed serializer.
- `0x003a8160`: parser.
- `0x003a5364`: receive dispatch; type `0x0a` is server-only, type `0x0b`
  causes the target to reply with `0x0c` directly to the initiating address.
- `0x003a5df0`: periodic type `0x0e` keepalive.
- `0x003a4994`: game-side NAT compatibility decisions and traversal startup.

The original service's precise forwarding/registration policy is unknown.
The implemented forwarding behavior and unchanged signature were checked by
executing the real host receive handler. Stateful forwarding policy is our
operational choice, not recovered original server logic.

## Reproduce the analysis

Extract only the executable files with `scripts/extract_game.py`. Keep them
private; `.gitignore` excludes all local binary and Ghidra output directories.
Use the Emotion Engine extension from the existing Ghidra installation:

Set `GHIDRA_INSTALL_DIR` to your local Ghidra installation directory first.

```sh
mkdir -p research/ghidra /tmp/codstun-ghidra-home
JAVA_TOOL_OPTIONS='-Duser.home=/tmp/codstun-ghidra-home' \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  "$PWD/research/ghidra" codbro \
  -import "$PWD/research/private/MP.BIN" \
  -processor r5900:LE:32:default \
  -analysisTimeoutPerFile 240 \
  -scriptPath "$PWD/scripts" \
  -postScript Discover.java "$PWD/research/decompiled" \
  -log "$PWD/research/ghidra/analysis.log" \
  -scriptlog "$PWD/research/ghidra/script.log"
```

The local Ghidra project is `research/ghidra/codbro.gpr`. The export script finds
references to discovery/traversal strings and exports the related functions.
It does not modify the neighboring TimeSplitters project.

`scripts/verify_game.py` runs selected original MIPS functions using Unicorn's
MIPS64 engine. These routines use instructions shared with R5900. Hooks replace
logging/address formatting, the optimized PS2 memcpy, and socket sends. Checks:

1. Real public IP request constructor/serializer -> server -> real reply parser.
2. All NAT request flags from real serializer -> server -> real reply parser.
3. Real NAT state machine accepts two-address routing and reports Open.
4. Real test 3 handling reports Moderate/Strict for unchanged/changed mappings.
5. Real traversal parser/serializer preserves the signed bytes across forwarding.
6. Real host introduction handler emits a direct type `0x0c` reply.
7. Real IP reply parser rejects a truncated response.

The ordinary test suite additionally checks real loopback UDP source addresses
and ports, introduction forwarding, malformed input, state expiry, and rate limits.
Neither form of verification establishes that a real Internet match succeeds.

## Remaining live validation

Run two unmodified clients on different Internet connections using the existing
revival DNS plus the new exact hostname override. Confirm server discovery
replies, keepalives, and the `0x0a` -> `0x0b` introduction. Then confirm the direct
`0x0c` reply and game traffic on client-side captures. An absent `0x0a` can mean
the game chose direct traversal or rejected the peer's advertised NAT type.

The service supplies no GameSpy authentication/matchmaking. Its default direct
mode has no gameplay relay. DNS routing to that direct mode alone cannot fix peer firewall rules, symmetric NAT behavior,
or unrelated GameSpy revival bugs. Check these after reproducing a failed join;
the historical community symptom alone does not establish its exact cause.
