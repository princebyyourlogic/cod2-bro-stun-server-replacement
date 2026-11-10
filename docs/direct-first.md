# Direct first, relay fallback: feasibility and operator integration

**Status:** a candidate design for the analyzed US Collector's Edition client.
The live service still assigns relay endpoints. No OpenSpy deployment has been
changed, and direct-first room rewriting is not enabled by this project.
An OpenSpy backend change is currently unavailable. The integration below is
documented for a future opportunity; it is not assumed for the current service.

The original client has a useful path: try its peer's private/local candidate
with type `0x0f`, then use the public endpoint after local discovery fails. We can
potentially put the host's real Internet endpoint in the first candidate and keep
its virtual relay endpoint as the public address. The actual joining console
then tests the direct path, with its own NAT, before using the relay.

This does not require a second VPS IPv4 for the **joiner's candidate test**. A
separate host reachability probe is useful diagnostic evidence, but a single
server's successful probe is not proof about every player pair.

## Comparison with TSFP

The neighboring TSFP implementation probes a host with `PROB` from a fresh relay
port. Its theater controls per-join signaling and can put a relay endpoint in the
client's alternate-address field. It can also correlate admission with `PENT`.

CoD uses a separate Demonware discovery service plus GameSpy room reporting.
This service does not receive room-created, join-request, or admission events.
Its current virtual public address is assigned before the game constructs its
common address and creates a room. A host-time decision therefore needs a
matchmaking integration or another client-supported selection path.

## Original client evidence

These addresses refer to the privately analyzed `MP.BIN`, not file offsets:

| Routine | Finding |
| --- | --- |
| `0x0026dd2c` | Parses `DW_PRIVATE_IP/PORT`, `DW_PUBLIC_IP/PORT`, and other room fields. IP text uses a dash after every octet, including the last. |
| `0x00253b78` | Builds the remote common address with one private candidate and its public address. |
| `0x0039cd28` | Derives the common-address identifier from the public endpoint when it is present. Changing only the private candidate preserves its hash input. |
| `0x0039dbf0` | Begins address resolution through the local-candidate stage. |
| `0x003a4994` | Local stage sends candidate probes. The later Open public stage selects the advertised public endpoint. |
| `0x003a7204` | Sends type `0x0f` with the peer identifier and an authenticated pair of embedded addresses. |
| `0x003a5364`, type `0x0f` | Checks the identifier against the host's identity and sends `0x10` to the **observed UDP source**. |
| `0x003a5364`, type `0x10` | Checks the echoed authenticator and records the response's observed source as the working peer endpoint. |

The important separation is the stable public identity versus the resolved
transport endpoint. The host can remain identified as `VPS:20001` while a joining
client resolves a successful candidate to the host's real address. No signed
packet needs to be rewritten in flight, and no session key is needed by the
candidate selector.

Local research executed these selected original control-flow, serializer, parser,
and callback branches. It checked that changing the candidate preserves the
original identity hash **input**, that candidate success resolves
the physical peer, and that the public fallback selects the relay. Hash/HMAC and
runtime helpers are substituted in that test. It does not execute the original
crypto implementations or the retry timer, boot a console, or complete DTLS and
session admission. The proposed complete route still needs a live trial.

The prototype and emulator experiments remain under ignored local research, not
in the deployed runtime. Existing public protocol verification scripts retain
their original scope.

## Proposed room response

For one registered host, suppose:

- Its virtual endpoint is `192.0.2.10:20001`.
- Its real gameplay socket was observed at `198.51.100.9:41007`.
- Its original LAN candidate is `10.0.0.9:3074`.

For an appropriate Internet viewer, return a response-only patch:

```text
DW_PRIVATE_IP   = 198-51-100-9-
DW_PRIVATE_PORT = 41007
```

Keep `DW_PUBLIC_IP = 192-0-2-10-`, `DW_PUBLIC_PORT = 20001`, and the virtual
`DW_NAT_TYPE = 1`. Preserve the MAC, security ID/key, and all other room fields.

Expected path:

```text
Joiner -> host's real endpoint: native 0x0f candidate test
  matching 0x10 received -> resolve real source -> direct connection attempt
  candidate stage expires -> resolve virtual public endpoint -> existing relay
```

The direct candidate can be wrong for destination-dependent mappings or blocked
by filtering. The native fallback is what makes a trial useful without declaring
a host globally reachable. A candidate response is still not proof that DTLS or
game admission succeeds; a failure after candidate selection may not trigger a
new relay attempt. That failure path must be tested explicitly.

A future adapter should return only those two candidate fields after checking
that the listing matches the supplied live virtual registration. It should not
log or return the original room record, which may contain security keys. There
is currently no deployed candidate adapter or registration API.

Apply an operator-controlled, CoD-specific override to returned room fields
rather than overwriting shared room records. Keep the original LAN candidate
available for viewers where LAN/VPN routing may matter. A shared public IP does
not establish that two consoles share a LAN: CGNAT also shares addresses. The
first trial should use two clients on separate Internet connections, then test
same-LAN, shared-CGNAT, VPN, and additional-peer cases separately.

The full peer mesh is another boundary. The GameSpy listing supplies the host
candidate; addresses distributed later by the game/session itself can retain
their original private candidates. This design may remove the host/guest relay
hop while some guest/guest links continue to use the relay.

## OpenSpy integration points

Inspected public revisions:

- [`openspy-core` at `221c6a7`](https://github.com/openspy/openspy-core/tree/221c6a7931914362a04ffe6f374957eff2fe1bac).
- [`qr.service` at `d077fbe`](https://github.com/openspy/qr.service/tree/d077fbeb8cbe8e6124e44038961cfd429dcc12bc).

The core [QR heartbeat task](https://github.com/openspy/openspy-core/blob/221c6a7931914362a04ffe6f374957eff2fe1bac/code/qr/tasks/Heartbeat.cpp)
stores reported custom keys and publishes room new/update events. The
[server browsing loader](https://github.com/openspy/openspy-core/blob/221c6a7931914362a04ffe6f374957eff2fe1bac/code/serverbrowsing/tasks/GetServers.cpp)
loads those custom fields for list responses. Both the selected-key and all-key
paths would need consistent response overrides, including individual-server
lookups and subsequent updates.

The QR helper's [event listener](https://github.com/openspy/qr.service/blob/d077fbeb8cbe8e6124e44038961cfd429dcc12bc/src/ServerEventListener.go)
already distributes new/update/delete events to handlers. Its existing
[server prober](https://github.com/openspy/qr.service/blob/d077fbeb8cbe8e6124e44038961cfd429dcc12bc/src/Handlers/ServerProber.go)
uses GameSpy QR queries, which are a different path from CoD's Demonware gameplay
socket. Its result alone is not the required gameplay connectivity test.

The operator would need:

1. A private, authenticated way to obtain this relay's **current** virtual-to-real
   registration for the hosting gameplay socket. A separate NAT test socket,
   GameSpy QR source port, guessed port 3074, or IP-only association is unsuitable.
2. A narrowly scoped candidate override for the CoD title, based on that live
   registration, with original fields restored whenever state is missing/stale.
3. A room-created probe hook if host-time measurements are wanted, plus live
   tests confirming returned metadata, actual direct versus relayed traffic,
   fallback timing, encrypted admission, rejoin, and multi-player mesh behavior.

DNS redirection by itself does not change the GameSpy fields. No operator has
been contacted or granted access as part of this research.

## Manual host probe

A local prototype implements a bounded type `0x0d` probe for one consenting
console's **real** observed gameplay/control endpoint. The original handler
echoes `0x0c` to the embedded probe endpoint without a pending join. This tests
the low-level handler without creating a player or completing a room join.

The prototype was tested against loopback UDP peers and the original handler in
the emulator. It has not probed a real console. No automatic host probing was
added to the live service.

Such a probe must run with the public address clients see and a preserved UDP
source port. The console must have completed online initialization and consented
to the test. Use the live control endpoint from its relay registration, not
`VPS:20001` and not the NAT
classification socket. Probe observations contain private player endpoint data;
keep them out of public issues and logs.

The prototype distinguishes `same_ip_new_port_reply`, `other_ip_reply`, and
`unanswered`. A new port on the discovery server's IP cannot distinguish an
IP-filtered router from unrestricted inbound reachability. A different-IP reply
only describes that probe path; the client may already have contacted that IP
for another service. Unanswered probes can also mean an idle/disconnected client,
startup timing or packet loss. Consequently `relay_required` is always unknown,
and game join/pair-direct proof fields remain false. No automatic routing change
is made from this diagnostic result.
