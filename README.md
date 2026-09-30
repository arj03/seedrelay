# seedrelay: a relay for [seedkernel](https://github.com/arj03/seedkernel)

The app-neutral relay for seedkernel nodes. A node **registers** its key here by signing
a challenge, and reaches any registered key through a **splice**: two sockets the relay
joins, forwarding what one sends to the other. Apps meet each other's keys in **rooms**,
IRC-style, with the small client in `rooms.mjs`. That is how a node nobody can dial (a browser, or anything behind NAT) is
reached. Once linked, the nodes move to a direct link where they can (WebRTC, or an
address the node advertises), and close the splice behind them.

The package is **`relay.mjs`**, a bounded WebSocket server (`createRelay`),
**`server.mjs`**, the bin that runs it, and **`rooms.mjs`**, the room client apps use,
with no third-party dependencies. A node's side of registration and splices is the
seedkernel transport bundle, which speaks that wire itself (seedkernel §12.7); rooms are
the app's, and the transport knows nothing of them.

The relay is not trusted with traffic. The seedkernel channel handshake runs end to
end through a splice, so the relay forwards ciphertext it cannot read and cannot pose
as either end, and the callee's contact secret gates a call as it gates any dial. What
a relay does see: which keys are registered, which are in which room, who calls whom, and when
and how much they send until they move to a direct link.

This lives outside the seedkernel repo because a relay is a deployment concern, not
trusted runtime surface: the kernel ships no server, and its own tests use an
in-process relay. [seedchat](https://github.com/arj03/seedchat) and
[seedstore](https://github.com/arj03/seedstore) both use it.

**Contents:** [Quick start](#quick-start) · [Running the server](#running-the-server) ·
[Deploying publicly](#deploying-publicly) · [Joining a room](#joining-a-room) ·
[What's here](#whats-here) · [Troubleshooting](#troubleshooting)

## Quick start

### Prerequisites

- **Node.js ≥ 20.** There are no runtime dependencies.

An app that starts the relay from its own scripts depends on seedrelay as a sibling
checkout through a `file:` dependency (`"seedrelay": "file:../seedrelay"`), so the usual
layout is:

```
some-dir/
├── seedkernel/
├── seedrelay/    ← this repo
├── seedchat/
└── seedstore/
```

### Run and test

```sh
npm run start -- 8080     # → ws://127.0.0.1:8080
npm test
```

When installed as a dependency, the `seedrelay` bin runs the same server, which is
how seedchat's `npm run relay` starts it:

```sh
npx seedrelay 8080
```

| Script | What it does |
| --- | --- |
| `npm run start` | Starts the relay (`node server.mjs`). Arguments after `--` are passed through. |
| `npm test` | Runs the relay tests with `node --test`. |

## Running the server

```
seedrelay [port] [options]
```

The port defaults to `8080` and may also be given as `--port N`. The relay binds
`127.0.0.1` unless told otherwise, so by default only this machine can reach it.
A plain HTTP request gets `426 Upgrade Required`. On `SIGTERM` or `SIGINT` the relay
closes every socket with code `1012` (service restart) before it exits.

### Options

Environment variables seed the defaults; the matching flag overrides them.

| Flag | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--host HOST` | | `127.0.0.1` | Interface to bind. |
| `--port N` | | `8080` | Port to listen on (a bare number works too). |
| `--authority NAME` | `RELAY_AUTHORITIES` | the bound address's names | A `host[:port]` nodes dial this relay by, which registrations are signed for. Repeatable; the variable is comma-separated. See [The wire](#the-wire). |
| `--allow-origin ORIGIN` | | localhost pages | Allowed browser `Origin`. Repeatable; see [Origins](#origins). |
| `--max-conns N` | `RELAY_MAX_CONNS` | `2048` | Concurrent sockets across the relay, including those still awaiting upgrade. Splice sockets may take 7/8 of them. |
| `--max-rooms N` | `RELAY_MAX_ROOMS` | `512` | Concurrent rooms. |
| `--max-per-room N` | `RELAY_MAX_PER_ROOM` | `32` | Registered sockets per room. |
| `--max-per-ip N` | `RELAY_MAX_PER_IP` | `64` | Sockets charged to one client address: its own, and both ends of every splice it called. |
| `--max-per-room-ip N` | `RELAY_MAX_PER_ROOM_IP` | `16` | Registered sockets one client address may hold in one room. |
| `--ipv6-prefix N` | `RELAY_IPV6_PREFIX` | `64` | How many leading bits of an IPv6 address name one client, for every per-address limit. |
| `--register-rate N` | `RELAY_REGISTER_RATE` | `4` | Control sockets one client address may open per second, with two seconds of burst; `0` leaves them unmetered. |
| `--splice-rate N` | `RELAY_SPLICE_RATE` | `1024` | KiB/s one client address may send through its splices; `0` leaves them unmetered. |
| `--heartbeat-secs N` | `RELAY_HEARTBEAT_SECS` | `30` | Ping interval; a socket that misses a pong is reaped. `0` disables it. |
| `--trusted-proxy IP` | `RELAY_TRUSTED_PROXIES` | none | Trust `X-Forwarded-For` from this proxy address. Repeatable; the variable is comma-separated. See [Deploying publicly](#deploying-publicly). |
| `--stun [HOST:]PORT` | `RELAY_STUN` | off | Answer STUN Binding requests on this UDP port, on `--host` unless a host is named. Nodes ask a relay's port `3478`; see [STUN](#stun). |

A malformed value or an unknown option stops the relay at startup, rather than leaving it
running with a limit it was not given.

Without `--authority`, a relay bound to a loopback address answers to `localhost`,
`127.0.0.1` and `[::1]` at its port, and one bound to any other address to that
address. A relay bound to `0.0.0.0` or `::` has no name of its own and will not start
without `--authority`, and neither does a relay nodes reach by any other name, such as a
public one behind a proxy.

### Sockets

| Path | Socket |
| --- | --- |
| `/v1/` | A control socket: a node's transport registers its key, and places and takes calls |
| `/v1/rooms` | A room socket: an app registers its key, and joins and leaves rooms |
| `/v1/?splice=<32 hex>` | One end of a splice, named by the ticket a call gave it |

The first segment names the wire version. Any other path is refused with `404`, so a
relay and a node never guess at each other's wire. A splice socket with a ticket nobody
was given is refused with `404`, and a second socket for one ticket with `409`.

### The wire

Both kinds of socket carry binary frames whose first byte is the type. Keys are 32-byte
seedkernel identities, rooms 32-byte ids, tickets 16 random bytes chosen by the caller.
Both open with `0x00` challenge `[nonce 32]`, `0x01` register `[pk 32][sig 64]` and
`0x01` registered; then:

| Socket | Relay → client | | Client → relay | |
| --- | --- | --- | --- | --- |
| control | `0x05` incoming | `[from 32][ticket 16]` | `0x05` call | `[to 32][ticket 16]` |
| control | `0x06` unreachable | `[to 32][ticket 16]` | | |
| rooms | `0x02` members | `[room 32][pk 32]*` | `0x02` join | `[room 32]` |
| rooms | `0x03` joined | `[room 32][pk 32]` | `0x03` leave | `[room 32]` |
| rooms | `0x04` left | `[room 32][pk 32]` | | |
| rooms | `0x07` refused | `[room 32]` | | |

- **Registration.** The relay sends a nonce on upgrade, and the node must answer within
  10 seconds with its key and an Ed25519 signature over
  `"seedkernel-link-scope-v1\0" ‖ "seedkernel-relay-register-v1\0" ‖ authority ‖ nonce`,
  where `authority` is the relay's `Host`, lowercased and without a `:80` or `:443`
  port. The first prefix is the one seedkernel's host puts in front of everything its
  transport signs. A room socket's signature is over
  `"seedrelay-rooms-v1\0" ‖ authority ‖ nonce` instead, which the app makes itself; no
  seedkernel signature starts that way, so neither kind can register the other, and an
  app's rooms can never draw its node's calls. A socket whose `Host` is not one of the relay's own names
  (`--authority`) is refused with `421` before it gets a nonce: otherwise relay A could
  take a nonce from relay B, have one of its visitors sign it for `a.example`, present
  that to B as `Host: a.example`, and draw the visitor's calls on B. Anything else
  before registering, or a bad signature, drops the socket. Calls for a key go to the
  control socket that registered it most recently.
- **Rooms.** A registered room socket joins rooms by id, up to 16 at once, and leaves
  them, as IRC's `/join` and `/part` do. `rooms.mjs` makes a room's id by hashing its
  name, SHA-256 of `"seedrelay-room-v1\0" ‖ name`, so the relay never learns names. A join gets the room's other keys,
  over as many `members` frames as they need, then `joined` and `left` as keys come
  and go. Two sockets with one key are one member. A join the room has no seat for (see
  [Limits](#limits)) is answered `refused`, and the socket stays registered. A room
  exists for as long as anyone is in it.
- **Calls.** `call` sends `incoming` to the callee's socket only, with a ticket of the
  relay's own rather than the caller's, or answers `unreachable` when the key is not
  registered here, is the caller's own, the ticket is in use, or the caller's address
  has too many calls waiting (see [Limits](#limits)). Each end then opens
  `/v1/?splice=<its ticket>`, and the relay joins them once both are there, or drops
  them after 10 seconds.
- **Splices.** Data frames are streamed through unmasked, whatever their size or
  fragmentation, so the relay holds a chunk, never a whole message. Ping and pong stay on
  each hop, and a close ends both ends. A full receiver, or a sender past its
  address's budget, pauses the sender.

Rooms are not authenticated: **a room id is a bearer credential** for learning which
keys are in it, and a name is only as private as it is hard to guess. For a private
room, use at least 16 random bytes encoded as hex. Room ids travel inside the WebSocket,
never in a URL, so no proxy access log holds them, and the relay never logs them, nor
keys or request paths. Reaching a key needs no room at all, and the
callee's contact secret is what gates it.

### Origins

A browser names the page that opened a socket in `Origin`, and every socket a page opens
counts against its visitor's address. The allowlist says which pages may spend their
visitors' budgets here, so a hostile page cannot use its visitors to fill the relay or
lock them out of it. It is not authentication, and there is nothing to hijack: the relay
keeps no cookies or other ambient credentials. By default it covers `http://` and `https://` pages on
`localhost`, `127.0.0.1` and `[::1]`, with no port or on ports 80, 443, 3000, 5173,
8000, 8080 and 8443. Upgrades from any other origin get `403 Forbidden`.

**Passing `--allow-origin` replaces the defaults** rather than adding to them. To keep
local development working alongside a deployed page, list both:

```sh
seedrelay 8080 --allow-origin https://app.example --allow-origin http://localhost:3000
```

Opaque origins (`Origin: null`, which includes `file://` pages and sandboxed iframes)
are rejected. Serve local apps over HTTP, or opt in with `--allow-origin null` only
when that access is intended. Native clients that send no `Origin` header, such as
`wscat` or `websocat`, are always accepted.

### Limits

Control sockets carry a few small frames each; splices carry the traffic.

- **Control frames** from a node are binary and capped at 256 bytes; the largest, a
  registration, is 97. Text, fragmented frames and WebSocket extensions are
  unsupported. Both kinds of socket read frames with one parser and the same rules,
  lengths in their shortest encoding included.
- **Backlog.** Every write to a control socket, including ping/pong, respects a 256 KiB
  per-socket backlog cap; slow readers are disconnected. Splices use backpressure
  instead.
- **Handshakes** must complete within 10 seconds of the TCP connection, however
  slowly the input trickles in, and registration within 10 seconds of the upgrade.
- **Calls** are charged to the caller's address, not to a table everyone shares: it may
  have as many waiting as a room has seats (`--max-per-room`), and at most 8 splices to
  any one key, waiting or joined, since each makes the callee open a socket and run a
  handshake. Both ends of a splice count against the caller's `--max-per-ip`, so calls
  cannot spend the callee's share, or its NAT's.
- **Splices** are metered per client address: what an address sends through its
  splices, `--splice-rate` KiB/s (`RELAY_SPLICE_RATE`, default 1024) with two seconds of
  burst. Past it, that address's splice sockets are not read until the debt is paid
  back, so a sender is slowed, not disconnected. Without this, anyone holding two keys
  could splice them together and use the relay as an unmetered pipe.
- **Rooms.** One address may hold `--max-per-room-ip` registered sockets (default 16) in
  a room, so a single address cannot fill a public room, and an unregistered socket holds
  no seat.
- **Addresses.** An IPv6 client is accounted by its `/64` (`--ipv6-prefix`), since one
  host is routinely handed a whole `/64`. One address opens at most `--register-rate`
  control sockets a second (default 4, with two seconds of burst).
- **Traffic** on control sockets is metered by token buckets with two seconds of burst
  allowance. What a room announces is bounded by the registration rate: a joiner is never
  turned away for what announcing it costs.

| Scope | Sustained limit |
| --- | --- |
| Incoming per connection | 128 frames/s and 256 KiB/s |
| Incoming across the relay | 8,192 frames/s and 4 MiB/s |

Exceeding an incoming budget disconnects the sender; clients should reconnect with
backoff. A relay at `--max-conns` drops new TCP connections, and one whose splices hold
7/8 of it refuses new splice sockets with `503`, so nodes can still register. The other
socket caps are refused before the protocol switch with `429`; the room caps, checked at
each join, with `refused`. These limits bound abuse but do not protect
availability against a distributed denial of service.

### Sizing

Every room member links to every other, and a pair that cannot move to a direct link
stays on a splice of two sockets. A room of N members that all stay relayed costs
N(N−1) splice sockets plus N control sockets, and its smallest key, which calls the
rest, is charged 2(N−1) + 1 of them against its address. The defaults fit one such room
at `--max-per-room` (32 members: 992 splice sockets of the 1,792 splices may hold, and
63 of an address's 64). Pairs that move to WebRTC or an advertised address cost the relay
nothing, so most rooms need far less; a relay that hosts several large rooms of native
nodes behind NAT should raise `--max-conns` with the process's file limit.

### STUN

WebRTC connects two nodes behind NAT only once each knows the address the internet sees
it at, which it learns from a STUN server. The seedkernel transport asks the relay a
peer is linked through, at `stun:<relay host>:3478`: the relay already sees that
address, so no third party learns who is online. `--stun` answers those requests on UDP
(RFC 8489 Binding only, at most 20 a second to one address). Without it, pairs on
different networks mostly stay relayed.

## Deploying publicly

Terminate TLS at a reverse proxy, point clients at `wss://` URLs, and keep the relay
bound to loopback behind it:

```sh
seedrelay 8080 --authority relay.example --trusted-proxy 127.0.0.1 --allow-origin https://app.example
```

`--authority` names the relay as nodes dial it: they sign that name, and the relay
accepts no other. Give each name nodes use, one flag apiece.

Name each trusted proxy by its actual IP with `--trusted-proxy` or
`RELAY_TRUSTED_PROXIES`. The proxy must append the real client address to
`X-Forwarded-For`, or overwrite the header with it. The relay walks that chain from
right to left and stops at the first untrusted address, so a client-supplied leftmost
value is never believed. Forwarded headers from untrusted connections are ignored, and
a trusted connection with a missing or malformed chain is refused.

Trust only proxies you control. IP trust cannot tell apart processes sharing an
address, so block direct access to the backend port.

**Serve plain `ws://` too.** Browsers on HTTPS pages need `wss://`, but console nodes
(seedkernel's CLI on Node or the native binary) have no TLS and dial `ws://` only. Have
the proxy forward port 80 to the same relay as 443, so both reach one relay and meet in
the same rooms. Registration still matches: a node dialing `ws://relay.example` signs
`relay.example`, as one dialing `wss://relay.example` does. A splice's traffic is encrypted end to
end either way; over `ws://` an observer sees the room ids a node joins, the rooms'
keys and who calls whom, so a console node that needs a private room should reach its
peers by key, joining no room, instead.

**Answer STUN on the public address.** UDP does not pass through an HTTP proxy, so bind
STUN to a public interface, and open UDP 3478:

```sh
seedrelay 8080 --authority relay.example --trusted-proxy 127.0.0.1 --stun 0.0.0.0:3478
```

Connection accounting starts at the TCP level, before HTTP headers arrive. Direct
clients count toward the per-address cap immediately. Trusted proxies share only the
global cap at that stage, and each forwarded client is held to the per-address cap
once its headers arrive. Apply connection and request limits at the proxy as well.

## Joining a room

A seedkernel node registers on the relay through its transport bundle's host-only
`relay` operation; the transport opens the control socket itself, and reaches any peer
it is given as `<pk>@relay+wss://relay.example:443` (seedkernel §12.6, §12.7). Meeting
peers is the app's: `rooms.mjs` joins rooms on a room socket, and the app hands each
member it hears to the transport with its `addr` operation. An embedder supplies only
the sockets: a factory that can reach the relay and, for the move to WebRTC,
seedkernel's `RtcNetwork` for the peer connections.

```js
import { WsNetwork } from "seedkernel-wasm/net-ws";
import { RtcNetwork } from "seedkernel-wasm/net-rtc";
import { combineChannels } from "seedkernel-wasm/socket-seam";
import { OpArgs } from "seedkernel-wasm/op-frame";
import { roomClient } from "seedrelay/rooms";

const relay = "wss://relay.example";
const { shell } = await bootShell({ /* … */ transport: { channels: combineChannels(new WsNetwork(), new RtcNetwork()) } });
await shell.call("_net", new OpArgs("relay").text(relay).build());
const rooms = roomClient({
  relay, publicKey, sign: (m) => sodium.crypto_sign_detached(m, privateKey),
  onMember: (room, key, present) => {
    if (present) shell.call("_net", new OpArgs("addr").blob(fromHex(key)).blob(roomSecret).text(`relay+${relay}`).build());
  },
});
await rooms.join("my-room");
```

The transport redials a relay that drops, and its `relayState` operation reports
whether it is registered; the room client redials its own socket and joins its rooms
again. Linking is the app's too: a send dials, and the transport's `ready` operation
dials every peer it has been given.

## What's here

| Path | What it is |
| --- | --- |
| `relay.mjs` | The relay: `createRelay({ authorities, limits, clock, … })`, `stunResponse`, and `parseOptions` for the command line. |
| `rooms.mjs` | The room client apps use in the browser and on Node: `roomClient` and `roomId`. |
| `server.mjs` | The `seedrelay` bin: parses the command line, listens (on UDP too, with `--stun`), and closes with `1012` on shutdown. The option list is also in its header comment. |
| `test/relay.test.mjs` | Drives `createRelay` with fake sockets and a fake clock: registration and authorities, rooms and announcements, calls and splices, charging and caps, backpressure, frame validation, origins, proxy trust, options and log redaction; and one run of the bin over real sockets. |

## Troubleshooting

- **Upgrade refused with `403`.** The page's origin is not on the allowlist. Common
  causes are a dev server on a port outside the default list, a `file://` page
  (`Origin: null`), or an `--allow-origin` flag that replaced the localhost defaults.
  The relay logs `! rejected upgrade: origin not allowed`.
- **Upgrade refused with `421`.** The `Host` the node dialed is not one of the relay's
  names. Add it with `--authority`; behind a proxy, forward the original `Host`.
- **Upgrade refused with `404`.** The path is not under `/v1/`, so the client speaks
  another wire version (update it), or the splice ticket expired or was never given.
- **Upgrade refused with `400`.** Behind a trusted proxy, the `X-Forwarded-For` chain
  is missing or malformed.
- **Upgrade refused with `429`, or a join `refused`.** A connection or room cap, or the
  registration rate, was hit; the relay logs which one. Raise it with the matching
  option.
- **Other devices can't connect.** The relay binds `127.0.0.1` by default. Bind a
  reachable interface with `--host`, or better, put it behind a TLS proxy (see
  [Deploying publicly](#deploying-publicly)). A page served over HTTPS also needs a
  `wss://` relay URL.
- **Startup fails.** An option is malformed or unknown; the relay names it.
- **A client is disconnected mid-session.** It sent an oversize or invalid frame,
  exceeded a traffic budget, or missed a heartbeat pong. Reconnect with backoff.
- **A node never registers.** The relay logs `! dropped: bad registration`: the node
  signed for another authority than the `Host` the relay saw, which happens when a
  proxy rewrites `Host` to another of the relay's names. Forward the original `Host`.
- **A call comes back unreachable.** The callee is not registered on this relay, or the
  caller's address already has a room's worth of calls waiting, or 8 splices to that key.
- **Peers on different networks stay relayed.** The relay answers no STUN, so browsers
  cannot learn their public addresses. Start it with `--stun` and open UDP 3478.
- **Relayed traffic is slow.** The sending address is past `--splice-rate`; raise it,
  or `0` to leave splices unmetered.
