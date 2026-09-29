# seedrelay: a relay for [seedkernel](https://github.com/arj03/seedkernel)

The app-neutral relay for seedkernel nodes. A node **registers** its key here by signing
a challenge, meets the other members of a **room**, and reaches any registered key
through a **splice**: two sockets the relay joins, forwarding what one sends to the
other. That is how a node nobody can dial (a browser, or anything behind NAT) is
reached. Once linked, the nodes move to a direct link where they can (WebRTC, or an
address the node advertises), and the relay closes the splice.

The package is one piece: **`server.mjs`**, a bounded WebSocket server, with no
third-party dependencies. The other end is the seedkernel transport bundle, which
speaks the relay's wire itself (seedkernel §12.7), so there is no client library to
install.

The relay is not trusted with traffic. The seedkernel channel handshake runs end to
end through a splice, so the relay forwards ciphertext it cannot read and cannot pose
as either end, and the callee's contact secret gates a call as it gates any dial. What
a relay does see: which keys are registered and in which room, who calls whom, and when
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
npm run start -- 8080     # → ws://127.0.0.1:8080/<room>
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
| `npm test` | Runs the server tests with `node --test`. |

## Running the server

```
seedrelay [port] [options]
```

The port defaults to `8080` and may also be given as `--port N`. The relay binds
`127.0.0.1` unless told otherwise, so by default only this machine can reach it.
A plain HTTP request gets `426 Upgrade Required`.

### Options

Environment variables seed the defaults; the matching flag overrides them.

| Flag | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--host HOST` | | `127.0.0.1` | Interface to bind. |
| `--port N` | | `8080` | Port to listen on (a bare number works too). |
| `--allow-origin ORIGIN` | | localhost pages | Allowed browser `Origin`. Repeatable; see [Origins](#origins). |
| `--max-conns N` | `RELAY_MAX_CONNS` | `1024` | Concurrent sockets across the relay, including those still awaiting upgrade. |
| `--max-rooms N` | `RELAY_MAX_ROOMS` | `512` | Concurrent rooms. |
| `--max-per-room N` | `RELAY_MAX_PER_ROOM` | `64` | Sockets per room. |
| `--max-per-ip N` | `RELAY_MAX_PER_IP` | `64` | Sockets per client address, splice sockets included. |
| `--max-splices N` | `RELAY_MAX_SPLICES` | `1024` | Splices joined or waiting for their sockets. |
| `--heartbeat-secs N` | `RELAY_HEARTBEAT_SECS` | `30` | Ping interval; a socket that misses a pong is reaped. `0` disables it. |
| `--trusted-proxy IP` | `RELAY_TRUSTED_PROXIES` | none | Trust `X-Forwarded-For` from this proxy address. Repeatable; the variable is comma-separated. See [Deploying publicly](#deploying-publicly). |
| `--trust-proxy` | `RELAY_TRUST_PROXY=1` | | Legacy. Now fails at startup unless trusted proxy addresses are also given. |

Malformed numeric values fall back to the default.

### Sockets

| Path | Socket |
| --- | --- |
| `/<room>` | A control socket that joins `<room>` once registered |
| `/` | A control socket in no room: its key can be called, but it meets nobody |
| `/?splice=<32 hex>` | One end of a splice, named by a ticket its caller has called |

Room names are made of `[A-Za-z0-9._-]` and are at most 128 characters; anything else
is refused with `400 Bad Request`. A room exists for as long as anyone is in it. A
splice socket with a ticket nobody called is refused with `404`, and a third socket for
one ticket with `409`.

### The wire

A control socket carries binary frames whose first byte is the type. Keys are 32-byte
seedkernel identities, tickets 16 random bytes chosen by the caller.

| Relay → node | | Node → relay | |
| --- | --- | --- | --- |
| `0x00` challenge | `[nonce 32]` | `0x01` register | `[pk 32][sig 64]` |
| `0x01` registered | | `0x05` call | `[to 32][ticket 16]` |
| `0x02` members | `[pk 32]*`, the room, once | | |
| `0x03` joined | `[pk 32]` | | |
| `0x04` left | `[pk 32]` | | |
| `0x05` incoming | `[from 32][ticket 16]` | | |
| `0x06` unreachable | `[to 32][ticket 16]` | | |

- **Registration.** The relay sends a nonce on upgrade, and the node must answer within
  10 seconds with its key and an Ed25519 signature over
  `"seedkernel-link-scope-v1\0" ‖ "seedkernel-relay-register-v1\0" ‖ authority ‖ nonce`,
  where `authority` is the relay's `Host`, lowercased and without a `:80` or `:443`
  port. The first prefix is the one seedkernel's host puts in front of everything its
  transport signs. Anything else before registering, or a bad signature, drops the
  socket. Calls for a key go to the socket that registered it most recently.
- **Rooms.** A registered socket in a room gets the room's other keys once, then
  `joined` and `left` as keys come and go. Two sockets with one key are one member.
- **Calls.** `call` sends `incoming` to the callee's socket only, or answers
  `unreachable` when the key is not registered here, is the caller's own, or the ticket
  is in use. Both ends then open `/?splice=<ticket>`, and the relay joins them once
  both are there, or drops them after 10 seconds.
- **Splices.** Data frames are streamed through unmasked, whatever their size or
  fragmentation, so the relay holds a chunk, never a whole message. Ping and pong stay on
  each hop, and a close ends both ends. A full receiver pauses the sender.

Rooms are not authenticated: **a room name is a bearer credential** for learning which
keys are in it. For a private room, use at least 16 random bytes encoded as hex. The
relay never logs room names, keys or request paths; configure reverse-proxy access logs
and monitoring to omit or redact them too. Reaching a key needs no room at all, and the
callee's contact secret is what gates it.

### Origins

The origin allowlist is a browser protection against cross-site WebSocket hijacking,
not client authentication. By default it covers `http://` and `https://` pages on
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

- **Control frames** are binary and capped at 64 KiB. Text, fragmented frames and
  WebSocket extensions are unsupported.
- **Backlog.** Every write to a control socket, including ping/pong, respects a 256 KiB
  per-socket backlog cap; slow readers are disconnected. Splices use backpressure
  instead.
- **Handshakes** must complete within 10 seconds of the TCP connection, however
  slowly the input trickles in, and registration within 10 seconds of the upgrade.
- **Splices.** `--max-splices` (`RELAY_MAX_SPLICES`, default 1024) caps splices joined
  or waiting, and one control socket may have as many calls waiting as a room has
  members. A splice's bandwidth is not metered; cap it at a proxy if it has to be.
- **Traffic** on control sockets is metered by token buckets with two seconds of burst
  allowance. Announcing a room member counts every recipient.

| Scope | Sustained limit |
| --- | --- |
| Incoming per connection | 128 frames/s and 256 KiB/s |
| Incoming across the relay | 8,192 frames/s and 4 MiB/s |
| Outgoing announcements per room | 2,048 recipient frames/s and 2 MiB/s |
| Outgoing across the relay | 16,384 recipient frames/s and 16 MiB/s |

Exceeding a traffic budget disconnects the sender; clients should reconnect with
backoff. Connection caps are refused before the protocol switch, with `503` when the
relay is full and `429` for per-address, per-room and room-table caps. These limits
bound abuse but do not protect availability against a distributed denial of service.

## Deploying publicly

Terminate TLS at a reverse proxy, point clients at `wss://` URLs, and keep the relay
bound to loopback behind it:

```sh
seedrelay 8080 --trusted-proxy 127.0.0.1 --allow-origin https://app.example
```

Name each trusted proxy by its actual IP with `--trusted-proxy` or
`RELAY_TRUSTED_PROXIES`. The proxy must append the real client address to
`X-Forwarded-For`, or overwrite the header with it. The relay walks that chain from
right to left and stops at the first untrusted address, so a client-supplied leftmost
value is never believed. Forwarded headers from untrusted connections are ignored, and
a trusted connection with a missing or malformed chain is refused.

Trust only proxies you control. IP trust cannot tell apart processes sharing an
address, so block direct access to the backend port.

Connection accounting starts at the TCP level, before HTTP headers arrive. Direct
clients count toward the per-address cap immediately. Trusted proxies share only the
global cap at that stage, and each forwarded client is held to the per-address cap
once its headers arrive. Apply connection and request limits at the proxy as well.

## Joining a room

A seedkernel node joins through its transport bundle's host-only `relay` operation,
naming the room URL; the transport opens the WebSocket itself, registers, and calls the
members it meets there (seedkernel §12.6, §12.7). A peer outside any room is reached by
an address naming its relay, `<pk>@relay+wss://relay.example:443`. An embedder supplies
only the sockets: a factory that can reach the relay and, for the move to WebRTC,
seedkernel's `RtcNetwork` for the peer connections.

```js
import { WsNetwork } from "seedkernel-wasm/net-ws";
import { RtcNetwork } from "seedkernel-wasm/net-rtc";
import { combineChannels } from "seedkernel-wasm/socket-seam";
import { OpArgs } from "seedkernel-wasm/op-frame";

const { shell } = await bootShell({ /* … */ transport: { channels: combineChannels(new WsNetwork(), new RtcNetwork()) } });
await shell.call("_net", new OpArgs("relay").text("wss://relay.example/my-room").build());
```

The transport redials a relay that drops, and its `relayState` operation reports
whether it is registered.

## What's here

| Path | What it is |
| --- | --- |
| `server.mjs` | The relay server and the `seedrelay` bin. The option list is also in its header comment. |
| `test/server.test.mjs` | Drives the server with fake sockets: registration, rooms, calls and splices, frame validation, backlog caps, origins, proxy trust, connection caps, traffic budgets and log redaction; and one run over real sockets. |

## Troubleshooting

- **Upgrade refused with `403`.** The page's origin is not on the allowlist. Common
  causes are a dev server on a port outside the default list, a `file://` page
  (`Origin: null`), or an `--allow-origin` flag that replaced the localhost defaults.
  The relay logs `! rejected upgrade: origin not allowed`.
- **Upgrade refused with `400`.** The room name has characters outside
  `[A-Za-z0-9._-]` (base64 `+`, `/` and `=` included) or is longer than 128
  characters. Behind a trusted proxy, a missing or malformed `X-Forwarded-For` also
  gives `400`.
- **Upgrade refused with `429` or `503`.** A connection cap was hit; the relay logs
  which one. Raise it with the matching option.
- **Other devices can't connect.** The relay binds `127.0.0.1` by default. Bind a
  reachable interface with `--host`, or better, put it behind a TLS proxy (see
  [Deploying publicly](#deploying-publicly)). A page served over HTTPS also needs a
  `wss://` relay URL.
- **Startup fails with `--trust-proxy requires --trusted-proxy IP`.** The legacy
  flag or `RELAY_TRUST_PROXY=1` is set without an address; name the proxy with
  `--trusted-proxy`.
- **A client is disconnected mid-session.** It sent an oversize or invalid frame,
  exceeded a traffic budget, or missed a heartbeat pong. Reconnect with backoff.
- **A node never registers.** The relay logs `! dropped: bad registration`: the node
  signed for another authority than the `Host` the relay saw, which happens when a
  proxy rewrites `Host`. Forward the original `Host`.
- **A call comes back unreachable.** The callee is not registered on this relay, or
  the splice table (`--max-splices`) is full.
