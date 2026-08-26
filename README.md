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
are queued for the next connection. `disconnect()` preserves that queue; closing the
`Signaling` (normally through `RtcNetwork.close()`) discards it.
