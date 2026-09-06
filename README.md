# seedrelay

The app-neutral rendezvous for SeedKernel WebRTC meshes. It contains the two pieces that
must agree on the JSON-over-WebSocket hop but do not belong in the kernel:

- `server.mjs`: a bounded WebSocket broadcast server partitioned by room.
- `client.js`: a reconnectable adapter exposing the kernel's opaque `Signaling` seam.

The relay carries only peer discovery, SDP, and ICE. Application data travels over the
resulting peer-to-peer data channels and is authenticated inside those channels by the
SeedKernel transport.

## Server

```sh
npm run start -- 8080
# or, when installed as a dependency
seedrelay 8080
```

Clients join `ws://host:port/<room>`. The accepted flags are listed at the top of
`server.mjs` and include bind, origin, capacity, per-room/per-IP, proxy, and heartbeat
controls.

The default origin allowlist covers localhost development pages. Opaque origins
(`Origin: null`, including file pages and sandboxed iframes) are rejected. Serve
local apps over HTTP, or explicitly opt in with `--allow-origin null` only when
that access is intended. Native clients without an Origin header remain supported;
the origin allowlist is a browser protection, not client authentication.

For public deployment, terminate TLS at a reverse proxy and use `wss://` URLs.
Specify each trusted proxy's actual IP with repeatable `--trusted-proxy IP` flags
or the comma-separated `RELAY_TRUSTED_PROXIES` environment variable. For example:

```sh
seedrelay 8080 --trusted-proxy 127.0.0.1 --allow-origin https://app.example
```

The proxy must append the actual client address to `X-Forwarded-For` or overwrite
the header with it. The relay walks the chain from right to left, stopping at the
first untrusted address, and ignores forwarded headers from untrusted connections.
The old `--trust-proxy` / `RELAY_TRUST_PROXY=1` setting now requires explicit trusted
addresses. Trust only proxies you control; IP trust cannot distinguish processes
sharing an address. Restrict direct access to the backend when using a proxy.

Global connection limits include TCP sockets awaiting HTTP upgrade. Direct clients
also count toward per-IP limits immediately. Trusted proxies share the global TCP
limit, with forwarded per-client limits applied after headers arrive. Incomplete
handshakes expire after 10 seconds, regardless of trickled input. Apply connection
and request limits at the public proxy as well.

Frames are limited to 64 KiB; text must be valid UTF-8. Fragmented frames and
extensions are unsupported. Every frame write, including ping/pong, respects a
256 KiB backlog cap; slow readers are disconnected. Traffic uses token buckets
with two seconds of burst allowance:

| Scope | Sustained limit |
| --- | --- |
| Incoming per connection | 128 frames/s and 256 KiB/s |
| Incoming across the relay | 8,192 frames/s and 4 MiB/s |
| Outgoing per room | 2,048 recipient frames/s and 2 MiB/s |
| Outgoing across the relay | 16,384 recipient frames/s and 16 MiB/s |

Broadcast costs include every recipient. Exceeding a traffic budget disconnects
the sender; applications should retry with backoff. These limits bound abuse but
do not provide availability against distributed denial of service.

Room names are bearer credentials: choose at least 16 random bytes encoded as hex
for private rooms. The relay does not log room names or request paths. Configure
reverse-proxy access logs and monitoring to omit or redact those paths too.

## Client

```js
import { createRelaySignaling } from "seedrelay";

const relay = createRelaySignaling({
  webSocketFactory: (url) => new WebSocket(url),
  onStateChange: ({ state }) => updateNetworkUi(state),
});

const network = new RtcNetwork({ driver, signaling: relay.signaling });
relay.connect("wss://relay.example/my-room");
network.join();
```

`relay.signaling` is stable across `connect()` calls. Messages produced while disconnected
are queued for reconnection to the same URL. `disconnect()` preserves that queue;
changing the URL discards it, including when the replacement connection fails.
Messages sent before the first `connect()` belong to that first destination.
Closing the `Signaling` (normally through `RtcNetwork.close()`) discards the queue.

Outgoing JSON is limited to 64 KiB per message, 256 queued messages, and 256 KiB
combined queued UTF-8 bytes plus WebSocket `bufferedAmount`. `send()` throws
`RangeError` when a limit would be exceeded; callers should handle this as
backpressure and retry with backoff. Buffered messages flush in order as capacity
allows. Incoming text larger than 64 KiB disconnects the adapter. Custom WebSocket
factories should expose an accurate `bufferedAmount` to enforce transport buffering.
