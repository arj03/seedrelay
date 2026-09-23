# seedrelay — a signaling relay for [seedkernel](https://github.com/arj03/seedkernel)

The app-neutral rendezvous for seedkernel WebRTC meshes. Peers meet in a **room** on
the relay, exchange SDP offers/answers and ICE candidates as JSON, then open
peer-to-peer data channels and stop needing the relay. Once every pair of active
peers is linked, the relay can be killed without disrupting traffic; it only matters
for adding new peers.

The package holds the two pieces that must agree on that JSON-over-WebSocket hop:

- **`server.mjs`**, a bounded WebSocket broadcast server partitioned by room, with no
  third-party dependencies.
- **`client.js`**, a reconnectable adapter exposing the `Signaling` seam that
  seedkernel's `RtcNetwork` consumes.

The relay is deliberately dumb: every frame from one client is forwarded verbatim to
every other client in the same room. It carries only peer discovery, SDP and ICE, and
it is not trusted with anything else. Application data travels over the data
channels, and peer identity is authenticated inside those channels by the seedkernel
transport, so a relay can observe signaling metadata and refuse to forward, but can
never impersonate a peer.

This lives outside the seedkernel repo because a relay is a deployment concern, not
trusted runtime surface: the kernel ships no server, and its own tests signal
in-process. [seedchat](https://github.com/arj03/seedchat) and
[seedstore](https://github.com/arj03/seedstore) both consume this package.

**Contents:** [Quick start](#quick-start) · [Running the server](#running-the-server) ·
[Deploying publicly](#deploying-publicly) · [Using the client](#using-the-client) ·
[What's here](#whats-here) · [Troubleshooting](#troubleshooting)

## Quick start

### Prerequisites

- **Node.js ≥ 20.** There are no runtime dependencies.

Apps depend on seedrelay as a sibling checkout through a `file:` dependency
(`"seedrelay": "file:../seedrelay"`), so the usual layout is:

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
| `npm test` | Runs the server and client tests with `node --test`. |

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
| `--max-per-ip N` | `RELAY_MAX_PER_IP` | `64` | Sockets per client address. |
| `--heartbeat-secs N` | `RELAY_HEARTBEAT_SECS` | `30` | Ping interval; a socket that misses a pong is reaped. `0` disables it. |
| `--trusted-proxy IP` | `RELAY_TRUSTED_PROXIES` | none | Trust `X-Forwarded-For` from this proxy address. Repeatable; the variable is comma-separated. See [Deploying publicly](#deploying-publicly). |
| `--trust-proxy` | `RELAY_TRUST_PROXY=1` | | Legacy. Now fails at startup unless trusted proxy addresses are also given. |

Malformed numeric values fall back to the default.

### Rooms

Clients join `ws://host:port/<room>`. A bare `ws://host:port/` joins the default room
`global`, and any query string is ignored. Room names are made of `[A-Za-z0-9._-]` and
are at most 128 characters; anything else is refused with `400 Bad Request`. A room
exists for as long as anyone is in it.

Rooms are not authenticated: **a room name is a bearer credential.** For a private
room, use at least 16 random bytes encoded as hex. The relay never logs room names or
request paths; configure reverse-proxy access logs and monitoring to omit or redact
them too. Apps that need more than an unguessable name gate peers inside the
seedkernel transport, as seedchat's invite links do.

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

The relay is sized for signaling: SDPs are a few KB and ICE candidates a few hundred
bytes.

- **Frames** are capped at 64 KiB, and text frames must be valid UTF-8. Fragmented
  frames and WebSocket extensions are unsupported.
- **Backlog.** Every frame write, including ping/pong, respects a 256 KiB per-socket
  backlog cap; slow readers are disconnected.
- **Handshakes** must complete within 10 seconds of the TCP connection, however
  slowly the input trickles in.
- **Traffic** is metered by token buckets with two seconds of burst allowance.
  Broadcast cost counts every recipient.

| Scope | Sustained limit |
| --- | --- |
| Incoming per connection | 128 frames/s and 256 KiB/s |
| Incoming across the relay | 8,192 frames/s and 4 MiB/s |
| Outgoing per room | 2,048 recipient frames/s and 2 MiB/s |
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

## Using the client

```js
import { createRelaySignaling } from "seedrelay";
import { RtcNetwork } from "seedkernel-wasm/net-rtc";

const relay = createRelaySignaling({
  onStateChange: ({ state }) => updateNetworkUi(state),
});

const network = new RtcNetwork({ driver, signaling: relay.signaling });
relay.connect("wss://relay.example/my-room");
network.join();
```

`createRelaySignaling(options?)` takes:

| Option | Default | Meaning |
| --- | --- | --- |
| `webSocketFactory` | `(url) => new WebSocket(url)` | Builds each socket, e.g. to supply a WebSocket implementation outside the browser. |
| `onStateChange` | no-op | Called with `{ state, url, event? }`, where `state` is `"connecting"`, `"connected"`, `"disconnected"` or `"error"`. |

It returns:

| Member | Meaning |
| --- | --- |
| `signaling` | The `Signaling` object (`send`, `onMessage`, `close`) to hand to `RtcNetwork`. It stays the same across `connect()` calls. |
| `connect(url)` | Closes any current socket and opens one to `url`. Returns the new socket. |
| `disconnect()` | Closes the current socket and keeps queued messages. |

The client owns only serialization, queuing and socket turnover. Picking the URL and
room, reconnecting, and any UI stay with the application.

### Queuing

Messages sent while disconnected are queued for reconnection to the same URL, and
`disconnect()` keeps that queue. Connecting to a different URL discards it, even when
the replacement socket fails to open. Messages sent before the first `connect()`
belong to that first destination. Closing the `Signaling`, normally through
`RtcNetwork.close()`, discards the queue.

### Backpressure

Outgoing JSON is limited to 64 KiB per message, 256 queued messages, and 256 KiB of
queued UTF-8 bytes plus the socket's `bufferedAmount`. `send()` throws `RangeError`
when a limit would be exceeded; treat that as backpressure and retry with backoff.
Queued messages flush in order as capacity allows. A custom `webSocketFactory` should
report an accurate `bufferedAmount` for this to bound transport buffering.

Incoming text larger than 64 KiB disconnects the adapter. Binary frames and text that
is not valid JSON are ignored.

## What's here

| Path | What it is |
| --- | --- |
| `server.mjs` | The relay server and the `seedrelay` bin. The option list is also in its header comment. |
| `client.js` | `createRelaySignaling`, the package's only export. |
| `test/server.test.mjs` | Drives the server with fake sockets: frame validation, backlog caps, origins, proxy trust, connection caps, traffic budgets and log redaction. |
| `test/client.test.mjs` | Drives the adapter with fake sockets: queuing, reconnects, URL changes, backpressure and incoming size limits. |

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
- **`send()` throws `RangeError: seedrelay: signaling buffer is full`.** The queue is
  at its cap, usually because the socket is not open. Retry with backoff once
  `onStateChange` reports `connected`.
