# seedrelay: a relay for [seedkernel](https://github.com/arj03/seedkernel)

The app-neutral relay for seedkernel nodes. A node holds one **relay link** here, a
seedkernel channel with the relay as its responder, pinned to the relay's key, so its
key, its calls and its rooms travel in records and nothing on the path names a key. The
link is its **registration**, and over it the node reaches any registered key through a
**splice**: two sockets the relay joins, forwarding what one sends to the other. That is how a node nobody can dial (a
browser, or anything behind NAT) is reached. Once linked, the nodes move to WebRTC where
they can, and close the splice behind them. Apps meet each other's keys in **rooms**,
IRC-style, with the small client in `rooms.mjs`, on that same link.

**The relay is a signed seedkernel bundle**, **`bundle/relay.skb`** (built from `guest/relay.js`),
which a seedkernel node runs as its transport: the node's sockets, listeners and UDP ports
are the relay's, and its code runs confined in the node's realm, with no authority beyond
them. The native seedkernel binary runs it with no Node at all. The package is that
bundle, **`relay.mjs`**, which runs it on a seedkernel node in this process
(`startRelay`), **`server.mjs`**, the bin, and **`rooms.mjs`**, the room client apps use. The
bundle answers each relay link with seedkernel's own channel code, which its build puts in
front of `guest/relay.js`. A node's side of the relay link and splices is the seedkernel
transport bundle (seedkernel §12.7); rooms are the app's, which the transport carries to
the relay unread and knows nothing of.

The relay is not trusted with traffic. The seedkernel channel handshake runs end to
end through a splice, so the relay forwards ciphertext it cannot read and cannot pose
as either end, and the callee's contact secret gates a call as it gates any dial. What
a relay does see: which keys are registered, which are in which room, who calls whom, and when
and how much they send until they move to a direct link.

This lives outside the seedkernel repo because a relay is a deployment concern, not
trusted runtime surface: the kernel ships no server, and its own tests use an
in-process relay. [seedshell](https://github.com/arj03/seedshell) and
[seedstore](https://github.com/arj03/seedstore) both use it.

**Contents:** [Quick start](#quick-start) · [Running the server](#running-the-server) ·
[Running natively](#running-natively) · [Deploying publicly](#deploying-publicly) ·
[Joining a room](#joining-a-room) · [What's here](#whats-here) ·
[Troubleshooting](#troubleshooting)

## Quick start

### Prerequisites

- **Natively:** a seedkernel binary, `relay.skb` and a few lines of settings; no Node. See
  [Running natively](#running-natively).
- **On Node:** Node.js ≥ 22 and a built seedkernel checkout beside this one (`npm run
  build` in `seedkernel/WASM`), which seedrelay depends on through
  `"seedkernel-wasm": "file:../seedkernel/WASM"` for the host the bin runs. It has no other
  dependency.
- **To change the relay:** the same, since `npm run build` signs `relay.skb` with
  seedkernel's bundle author.

An app that starts the relay from its own scripts depends on seedrelay as a sibling
checkout through a `file:` dependency (`"seedrelay": "file:../seedrelay"`), so the usual
layout is:

```
some-dir/
├── seedkernel/
├── seedrelay/    ← this repo
├── seedshell/
└── seedstore/
```

### Run and test

```sh
npm install
npm run start -- 8080     # → ws://<relay key>.<secret>@127.0.0.1:8080
npm test
```

The bin runs `relay.skb` on a seedkernel node in its own process. When installed as a
dependency, the `seedrelay` bin runs the same, which is how seedshell's `npm run relay`
starts it:

```sh
npx seedrelay 8080
```

| Script | What it does |
| --- | --- |
| `npm run start` | Starts the relay (`node server.mjs`). Arguments after `--` are passed through. |
| `npm run build` | Signs seedkernel's channel and `guest/relay.js` into `relay.skb` under `relay.key`, written on the first build. It rewrites `relay.skb` only when the bundle's content changed, since every signature differs. |
| `npm test` | Runs the relay tests with `node --test`, one of which fails while `relay.skb` is behind `guest/relay.js`. |

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
| `--allow-origin ORIGIN` | | localhost pages | Allowed browser `Origin`. Repeatable; see [Origins](#origins). |
| `--max-conns N` | `RELAY_MAX_CONNS` | `2048` | Concurrent sockets across the relay, including those still awaiting upgrade. Splice sockets may take 7/8 of them. |
| `--max-rooms N` | `RELAY_MAX_ROOMS` | `512` | Concurrent rooms. |
| `--max-per-room N` | `RELAY_MAX_PER_ROOM` | `32` | Registered sockets per room, at most 1024: filling a room costs announcements by the square of its size. |
| `--max-per-ip N` | `RELAY_MAX_PER_IP` | `72` | Sockets charged to one client address: its own, and both ends of every splice it called. |
| `--max-per-room-ip N` | `RELAY_MAX_PER_ROOM_IP` | `16` | Registered sockets one client address may hold in one room. |
| `--ipv6-prefix N` | `RELAY_IPV6_PREFIX` | `64` | How many leading bits of an IPv6 address name one client, for every per-address limit. |
| `--register-rate N` | `RELAY_REGISTER_RATE` | `4` | Relay links one client address may open per second, with two seconds of burst, and rooms it may join per second, with 32 at once; `0` leaves both unmetered. |
| `--splice-rate N` | `RELAY_SPLICE_RATE` | `1024` | KiB/s one client address may send through its splices; `0` leaves them unmetered. |
| `--heartbeat-secs N` | `RELAY_HEARTBEAT_SECS` | `30` | Ping interval; a socket that misses a pong is reaped. `0` disables it. |
| `--trusted-proxy IP` | `RELAY_TRUSTED_PROXIES` | none | Trust `X-Forwarded-For` from this proxy address. Repeatable; the variable is comma-separated. See [Deploying publicly](#deploying-publicly). |
| `--secret SECRET` | `RELAY_SECRETS` | the key's own | The contact secret a node must hold, 32 bytes in hex, in place of the one the relay derives from its key. Repeatable, so a new one can be rolled out before the old is dropped; the variable is comma-separated, and keeps secrets out of the process list. See [Private by default](#private-by-default). |
| `--open` | | off | Take any node, with no secret. An open relay is in public; see [Private by default](#private-by-default). |
| `--key FILE` | | none | Keep the relay's identity in `FILE`, a hex seed written on the first start. A relay link is pinned to the relay's key, and its secret is derived from it, both of which its URL carries, so without it the URL is new each run. |
| `--stun PORT`, `--stun off` | `RELAY_STUN` | `3478` | Answer STUN Binding requests on this UDP port and the next, on every interface, since UDP does not pass through an HTTP proxy; `0` lets the OS pick two, and `off` answers none. Nodes ask a relay's ports `3478` and `3479`; see [STUN](#stun). |
| `--print-config` | | | Print the settings the other flags make, as the JSON a native node takes with `--transport-config`, and exit. See [Running natively](#running-natively). |

A malformed value (including a whitespace-only number) or an unknown option stops the
relay at startup, rather than leaving it running with a limit it was not given. An
explicitly set `RELAY_SECRETS` must name at least one secret, or a `--secret` flag must
supply one; leave it unset for the relay's own. `--open` takes no secret.

### Sockets

| Path | Socket |
| --- | --- |
| `/v1/` | A relay link: a node's transport registers its key, places and takes calls, and joins rooms |
| `/v1/?splice=<32 hex>` | One end of a splice, named by the ticket a call gave it |

The first segment names the wire version. Any other path is refused with `404`, so a
relay and a node never guess at each other's wire. A splice socket with a ticket nobody
was given is refused with `404`, and a second socket for one ticket with `409`.

### The wire

A relay link runs seedkernel's channel handshake first (seedkernel's TRANSPORT.md,
Handshake), the node its initiator and the relay its responder, on the public network's
root, each message one binary WebSocket frame. The relay's key is what the node pins it
to and its contact secret what msg1 opens under, so a relay's address is
`ws://<key>.<secret>@host:port`, as the bin prints it, or `ws://<key>@host:port` for an
open relay. Then every
frame is a record, `[type u8][body]` inside it. Keys are 32-byte seedkernel identities,
rooms 32-byte ids, tickets 16 random bytes chosen by the caller.

| Relay → node | | Node → relay | |
| --- | --- | --- | --- |
| `0x01` registered | | `0x05` call | `[to 32][ticket 16]` |
| `0x05` incoming | `[from 32][ticket 16]` | `0x08` tell | `[message]` |
| `0x06` unreachable | `[to 32][ticket 16]` | | |
| `0x08` tell | `[message]` | | |

A tell carries rooms, which a node's transport passes between the relay and its host
unread (its `tell` operation and status). Their messages:

| Relay → node | | Node → relay | |
| --- | --- | --- | --- |
| `0x02` members | `[room 32][pk 32]*` | `0x02` join | `[room 32]` |
| `0x03` joined | `[room 32][pk 32]` | `0x03` leave | `[room 32]` |
| `0x04` left | `[room 32][pk 32]` | | |
| `0x07` refused | `[room 32]` | | |

- **Registration.** msg3 proves the node's key, and that is its registration: the relay
  says `registered` and routes calls for the key to the link that proved it most
  recently. A msg1 that does not open under the relay's contact secret (none for an open
  relay) draws silence until the handshake deadline, 10 seconds after the upgrade, as any
  seedkernel accept does. A record the wire has no use for, or one that does not open,
  drops the link.
- **Secrets.** Every relay has a contact secret unless it is opened: a node presents it
  at msg1 as a dial presents a peer's, so it never crosses the wire and nothing a listener
  sees can be tested against it.
- **Rooms.** A registered link joins rooms by id, up to 16 at once, and leaves
  them, as IRC's `/join` and `/part` do. `rooms.mjs` makes a room's id by hashing its
  name, SHA-256 of `"seedrelay-room-v1\0" ‖ name`, so the relay never learns names. A join gets the room's other keys
  in one `members` message, then `joined` and `left` as keys come and go. Two links with one key are one member. A join the room has no seat for (see
  [Limits](#limits)) is answered `refused`, and the link stays registered. A room
  exists for as long as anyone is in it.
- **Calls.** `call` sends `incoming` to the callee's link only, with a ticket of the
  relay's own rather than the caller's, or answers `unreachable` when the key is not
  registered here, is the caller's own, the ticket is in use, or the caller's address
  has too many calls waiting (see [Limits](#limits)). Each end then opens
  `/v1/?splice=<its ticket>`, and the relay joins them once both are there, or drops
  them after 10 seconds.
- **Splices.** Data frames are streamed through unmasked, whatever their size or
  fragmentation, so the relay holds a chunk, never a whole message. Ping and pong stay on
  each hop, and a close ends both ends. A receiver holding more than 64 KiB unread pauses
  its sender until it is down to 16 KiB, as does a sender past its address's budget until
  the debt is paid, and a receiver that does not drain for 2 minutes ends the splice.

Rooms are not authenticated: **a room id is a bearer credential** for learning which
keys are in it, and a name is only as private as it is hard to guess. For a private
room, use at least 16 random bytes encoded as hex. Room ids travel inside the relay
link's records, never in a URL, so no proxy access log or listener holds them, and the
relay never logs them, nor keys or request paths. Reaching a key needs no room at all,
and the callee's contact secret is what gates it.

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

Relay links carry a handshake and a few small records each; splices carry the traffic.

- **Frames** on a relay link are binary and capped at 2 KiB; the largest, msg1, is
  1,233 bytes. Text, fragmented frames and WebSocket extensions are unsupported. Relay
  links and splices read frames with one parser and the same rules, lengths in their
  shortest encoding included.
- **Backlog.** Every write to a relay link, including ping/pong, respects a 256 KiB
  per-socket backlog cap; slow readers are disconnected. Splices use backpressure
  instead.
- **Handshakes** must complete within 10 seconds of the TCP connection, however
  slowly the input trickles in, and the channel handshake within 10 seconds of the upgrade.
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
  relay links a second (default 4, with two seconds of burst), and joins
  rooms at the same rate, with 32 at once, so an app redialing joins all its rooms again.
- **Traffic** on relay links is metered by token buckets with two seconds of burst
  allowance. What a room announces is bounded by the join rate, however a socket leaves
  and joins again: a joiner is never turned away for what announcing it costs.

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
N(N−1) splice sockets plus N relay links, and its smallest key, which calls the rest,
is charged 2(N−1) + 1 of them against its address, its own relay link included. The defaults fit one such room at `--max-per-room` (32 members: 992
splice sockets of the 1,792 splices may hold, and 63 of an address's 72, leaving room
to redial). Pairs that move to WebRTC cost the relay
nothing, so most rooms need far less; a relay that hosts several large rooms of native
nodes behind NAT should raise `--max-conns` with the process's file limit.

Every socket is served by the one realm the bundle runs in. On a laptop's loopback, the
native binary carried one splice at 143 MB/s, far above the per-address meter, so the
meter is what a client of a busy relay feels first. Past what the realm can take, the
host stops reading sockets rather than dropping them.

### STUN

WebRTC connects two nodes behind NAT only once each knows the address the internet sees
it at, which it learns from a STUN server. The seedkernel transport asks the relay a
peer is linked through, at `stun:<relay host>:3478` and `:3479`: the relay already sees
that address, so no third party learns who is online. The relay answers those requests on
UDP 3478 and 3479 unless `--stun` says otherwise (RFC 8489 Binding only, at most 20 a
second to one address, and at most 256 new addresses a second, since UDP sources can be
forged).
Two ports, because a node whose two answers name different ports is behind a NAT that
gives each destination its own port, and its UDP path then takes more than a plain punch.
With `--stun off`, pairs on different networks mostly stay relayed.

## Running natively

The native seedkernel binary runs `bundle/relay.skb` as its transport, with no Node and
nothing to build: copy the binary and `relay.skb` to the server, write the settings, and
start it.
The binary must come from a seedkernel as new as this relay, whose host the relay relies
on (`link/pause` among others).

```sh
cat > relay.json <<'EOF'
{ "trustedProxies": [] }
EOF
seedkernel --transport bundle/relay.skb --key relay-id.key --listen ws=0.0.0.0:8080 --transport-config relay.json
```

The settings are the bin's options, as JSON. Every key is optional; a key left out keeps
the bin's default:

| Key | Flag | Value |
| --- | --- | --- |
| `allowOrigins` | `--allow-origin` | Allowed browser origins, replacing the localhost pages. |
| `trustedProxies` | `--trusted-proxy` | Proxy IP addresses whose `X-Forwarded-For` is believed. |
| `secrets` | `--secret` | The contact secrets, in hex, the relay registers nodes with, in place of its key's own. |
| `open` | `--open` | `true` for a relay that takes any node, with no secret. |
| `stun` | `--stun` | The first of the two STUN ports, `0` for two the OS picks, `null` for none. |
| `limits` | `--max-conns` and the rest | `{ "maxConns": 2048, "maxRooms": 512, "maxPerRoom": 32, "maxPerIp": 72, "maxPerRoomIp": 16, "ipv6Prefix": 64, "registerRate": 4, "spliceRate": 1024, "heartbeatSecs": 30 }`, any of them. |

Where Node is at hand, `node server.mjs 8080 --trusted-proxy 127.0.0.1 --print-config`
writes the file from the same flags the bin takes. The node's `--listen` takes the place of
`--host` and `--port`; every listener speaks HTTP and WebSocket, whatever its label. The
node's key (`--key`) is the relay's identity, the key its URL names, so keep that file;
it also keeps a data directory (`--dir`), which the relay does not use. Its log lines go to the node's console.
On a native node the heartbeat and STUN start with the first connection, since nothing
reaches the bundle before one, and `SIGINT` ends the process at once, without the `1012`
goodbye.

## Deploying publicly

Terminate TLS at a reverse proxy, point clients at `wss://` URLs, and keep the relay
bound to loopback behind it:

```sh
seedrelay 8080 --key relay-id.key --trusted-proxy 127.0.0.1 --allow-origin https://app.example
```

`--key` keeps the relay's identity across restarts, and with it the address nodes are
given, `wss://<relay key>.<secret>@relay.example`. The relay answers to whatever name a node dials
it by: the key, not the name, is what a node's relay link is pinned to.

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

**Open UDP 3478 and 3479.** UDP does not pass through an HTTP proxy, so the relay answers
STUN on every interface even when it is bound to loopback behind one:

```sh
seedrelay 8080 --key relay-id.key --trusted-proxy 127.0.0.1
```

Connection accounting starts at the TCP level, before HTTP headers arrive. Direct
clients count toward the per-address cap immediately. Trusted proxies share only the
global cap at that stage, and each forwarded client is held to the per-address cap
once its headers arrive. Apply connection and request limits at the proxy as well.

### Without a reverse proxy

A server that has a certificate and no proxy can run `scripts/https-front.mjs` in a
proxy's place: one Node process, with no third-party dependencies, that serves a page's
files over HTTPS and passes WebSocket upgrades under `/v1/` to the relay. It takes any
port, so it fits beside whatever already holds 80 and 443:

```sh
sudo node scripts/https-front.mjs --cert /etc/letsencrypt/live/relay.example/fullchain.pem \
  --key /etc/letsencrypt/live/relay.example/privkey.pem \
  --root ../seedshell/browser --index shell.html \
  --user www-data

seedrelay 8080 --key relay-id.key --trusted-proxy 127.0.0.1 \
  --allow-origin https://relay.example:8443
```

Then `https://relay.example:8443/` is the page and `wss://<relay key>.<secret>@relay.example:8443` the relay,
which is where a seedshell page served over HTTPS looks for it. Open TCP 8443 and UDP 3478 and 3479.

The front listens on `8443` unless given `--port`, serves `--root` with `index.html` at
`/` unless `--index` names another file (here a built seedshell's `browser/`, whose page
is `shell.html`), and dials the relay at `127.0.0.1:8080` unless given `--relay`. It
reads the certificate once, so restart it after a renewal. Root is only for the key and
the port: it reads one and binds the other, then runs as `--user` (and `--group`, default
that user's primary group), so `--root` must be readable by that user. Started as root
without `--user`, it refuses. Started as anyone else, it stays who it is: `--user` may name
only that user, and `--group` none. It holds at most 256 sockets and gives a client 10 seconds for its headers and 60
for its request, since the relay sees a client only once its headers are in. To the relay
it is a proxy like any other, and the page's origin carries the front's port.

To also take console nodes on plain `ws://`, and a page still under development on
`localhost`, bind the relay publicly and allow that page as well, since `--allow-origin`
replaces the localhost defaults:

```sh
seedrelay 8080 --host 0.0.0.0 --key relay-id.key \
  --trusted-proxy 127.0.0.1 --allow-origin https://relay.example:8443 \
  --allow-origin http://localhost:3000
```

### Private by default

A relay serves only nodes that hold its contact secret. Unless it is given one, it
derives its own from its key, a hash of its signature over a fixed tag that only the key's
holder can compute, and prints its URL with both at start:

```
seedrelay listening on ws://<relay key>.<secret>@127.0.0.1:8080
```

With `--key` the key, and so the secret and the URL, survive restarts. Hand the URL to
your nodes. Anyone without it draws silence, so it cannot register, call through the
relay, join a room or ask whether a key is here. Splice sockets need only their tickets,
which only registered links are handed. The secret is mixed into the handshake, so it
never crosses the wire, and nothing a listener sees can be tested against it.

`--secret` names the secret instead, which is how one is rotated without a new key: start
the relay with both old and new, move the clients over, then drop the old.

```sh
openssl rand -hex 32 > relay.secret
RELAY_SECRETS=$(cat relay.secret) seedrelay 8080 --key relay-id.key --trusted-proxy 127.0.0.1
```

`--open` takes any node, with no secret. **An open relay is in public**, and choosing it is
choosing that: anyone who can reach it can register, splice two keys of their own and use
it as a pipe (slowed only by the per-address limits), ask whether any key is online on it,
and make it do a handshake's public-key work for every msg1 it sends, a connection storm
that many sources can scale. Open a relay that is meant to be a public service, and
nothing else. Clients take the URL as [Joining a room](#joining-a-room) shows.

## Joining a room

A seedkernel node registers on the relay through its transport bundle's host-only
`relay` operation, with the relay's address as the bin prints it; the transport opens the
relay link itself, and reaches any peer it is given as
`<pk>.<secret>@relay+wss://<relay key>.<relay secret>@relay.example:443` (seedkernel §12.6, §12.7). Meeting peers is
the app's: `rooms.mjs` joins rooms through the transport's `tell` operation, reads what
the relay says from the transport's status, and the app hands each member it hears to the
transport with its `addr` operation. An embedder supplies only the sockets: a factory
that can reach the relay and, for the move to WebRTC, seedkernel's `RtcNetwork` for the
peer connections.

```js
import { bootShell } from "seedkernel-wasm/shell-core";
import { WsNetwork } from "seedkernel-wasm/net-ws";
import { RtcNetwork } from "seedkernel-wasm/net-rtc";
import { combineChannels } from "seedkernel-wasm/socket-seam";
import { OpArgs } from "seedkernel-wasm/op-frame";
import { roomClient, roomSecret } from "seedrelay/rooms";

const relay = "wss://<relay key>.<secret>@relay.example";
let rooms = null;
const { shell } = await bootShell({ /* … */ services: { transport: {
  channels: combineChannels(new WsNetwork(), new RtcNetwork()),
  onStatus: (status) => rooms?.status(status),
} } });
const net = (op) => shell.call("_net", op.build());
const secret = await roomSecret("my-room");
await net(new OpArgs("secrets").blob(secret));
rooms = roomClient({
  tell: async (bytes) => (await net(new OpArgs("tell").blob(bytes)))[0] === 1,
  onMember: (room, key, present) => {
    if (present) net(new OpArgs("addr").blob(fromHex(key)).blob(secret).text(`relay+${relay}`));
  },
});
await net(new OpArgs("relay").text(relay));
await rooms.join("my-room");
```

A room's secret (`roomSecret`) is derived from its name under a tag of its own, so the
relay, which sees only the room's id, cannot derive it, and everyone who knows the name
holds it. Joining a room is agreeing to be reached by everyone in it: the app hands the
transport the secrets of the rooms it is in with `secrets`, the whole list each time, and
a msg1 sealed under any of them is answered as one under the contact secret would be. It
calls a room-mate under that room's secret. The contact secret then gates only a caller
the node shares no room with. Nothing here trusts what the relay says a caller is, so a
relay cannot read which keys a node would answer. A room with a guessable name is a public
room, and its secret gates nothing.

The transport redials a relay that drops, and its status says whether it is registered;
the room client joins its rooms again each time it is, and who was in them stays as last
heard meanwhile. Linking is the app's too: a send dials, and the transport's `ready`
operation dials every peer it has been given. Its `forget` operation drops one peer, for
a room the app leaves.

The relay's contact secret travels in its URL as it prints it,
`wss://<relay key>.<secret>@relay.example`, or as a second text after one without it,
which keeps it out of addresses the app hands around:

```js
await net(new OpArgs("relay").text(relay).text(secret));
```

A node run from seedkernel's command line names a file holding the secret instead,
with `--relay-secret`.

## What's here

| Path | What it is |
| --- | --- |
| `bundle/relay.skb` | The relay bundle, signed: what the bin and a native node run. |
| `guest/relay.js` | Its source: the bundle's guest program, run by a seedkernel node as its link occupant. It reads its settings from the signed defaults and the operator's `LOCAL`, takes the host's link events (accepted sockets, their bytes, closes, datagrams, the wake), and answers the host-only `start` and `close` on the service id `_relay`. |
| `relay.mjs` | The Node side: `parseOptions` for the command line, `relayConfig` (the settings the bundle reads) and the signed defaults, and `startRelay`, which runs `relay.skb` on a seedkernel node in this process. |
| `rooms.mjs` | The room client apps use in the browser and on Node, over the node's transport: `roomClient` and `roomId`. |
| `server.mjs` | The `seedrelay` bin: parses the command line, starts the relay, prints what it serves and its log lines, and closes with `1012` on shutdown. The option list is also in its header comment. |
| `scripts/build.mjs` | Signs seedkernel's channel and `guest/relay.js` into `relay.skb` under `relay.key`, when its content changed; `--check` fails when it would. |
| `scripts/https-front.mjs` | A TLS front for a server with a certificate and no proxy: serves a page over HTTPS and passes `/v1/` upgrades to the relay. See [Without a reverse proxy](#without-a-reverse-proxy). |
| `test/harness.mjs` | The guest program in a realm of its own, behind a stand-in for seedkernel's host: links that record what the relay writes, a clock the test moves, and the host calls it makes. |
| `test/channel.mjs` | A node's side of a relay link as the tests speak it: the channel handshake as its initiator and records, written out from libsodium and the ML-KEM module. |
| `test/relay.test.mjs` | Drives the guest through the harness: the relay link's handshake and secrets, rooms and announcements, calls and splices, charging and caps, backpressure, frame and HTTP validation, origins, proxy trust, options and log redaction; and runs of the bin over real sockets, with seedkernel nodes as its clients. |

## Troubleshooting

- **Upgrade refused with `403`.** The page's origin is not on the allowlist. Common
  causes are a dev server on a port outside the default list, a `file://` page
  (`Origin: null`), or an `--allow-origin` flag that replaced the localhost defaults.
  The relay logs `! refused upgrade: origin not allowed`.
- **Upgrade refused with `404`.** The path is not under `/v1/`, so the client speaks
  another wire version (update it), or the splice ticket expired or was never given.
- **Upgrade refused with `400`.** Behind a trusted proxy, the `X-Forwarded-For` chain
  is missing or malformed.
- **Upgrade refused with `429`, or a join `refused`.** A connection or room cap, or the
  registration or join rate, was hit; the relay logs which one. Raise it with the matching
  option.
- **Other devices can't connect.** The relay binds `127.0.0.1` by default. Bind a
  reachable interface with `--host`, or better, put it behind a TLS proxy (see
  [Deploying publicly](#deploying-publicly)), or behind `scripts/https-front.mjs` where
  there is none. A page served over HTTPS also needs a `wss://` relay URL.
- **Startup fails.** An option is malformed or unknown, and the relay names it; or the
  STUN ports are taken (`relay: STUN cannot bind UDP port …`), which `--stun` moves; or
  `seedkernel-wasm` is missing, when the seedkernel checkout beside this one is not built.
- **The HTTPS front refuses to start as root.** Pass `--user`. If pages 404 after it
  starts, `--root` is not readable by that user.
- **A client is disconnected mid-session.** It sent an oversize or invalid frame,
  exceeded a traffic budget, or missed a heartbeat pong. Reconnect with backoff. A splice
  also ends when its far end does not drain for 2 minutes.
- **A node never registers, and the relay logs nothing.** The relay was started with
  `--secret` and the node has none or another one, or the node's URL names another key
  than the relay's: a relay restarted without `--key` has a new one. Both look like a
  relay that is down to the node, which redials.
- **A call comes back unreachable.** The callee is not registered on this relay, or the
  caller's address already has a room's worth of calls waiting, or 8 splices to that key.
- **Peers on different networks stay relayed.** Nodes cannot reach the relay's STUN, so they
  cannot learn their public addresses. Open UDP 3478 and 3479, and drop any `--stun off`.
- **Relayed traffic is slow.** The sending address is past `--splice-rate`; raise it,
  or `0` to leave splices unmetered.
