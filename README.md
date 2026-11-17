# seedrelay: a relay for [seedkernel](https://github.com/arj03/seedkernel)

seedrelay lets seedkernel nodes that nobody can dial, such as browsers and nodes behind
NAT, reach each other. A node registers with the relay over one encrypted link, the
relay joins two nodes' sockets into a **splice**, and the pair moves to WebRTC when it
can. Apps find each other's keys in **rooms**, with the client in `rooms.mjs`.

The relay is a signed seedkernel bundle, `relay.skb`, which the seedkernel binary runs as
its transport. It forwards only ciphertext: the channel handshake runs end to end through
a splice. It does see which keys are registered, who is in which room, who calls whom,
and how much they send. [seedshell](https://github.com/arj03/seedshell) and
[seedstore](https://github.com/arj03/seedstore) use it. The wire format, limits and
design are in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Quick start

Download the seedkernel binary for your platform from the [seedkernel
release](https://github.com/arj03/seedkernel/releases/latest) (0.1 or later, renamed
`seedkernel` below), and `relay.skb` from the [seedrelay
release](https://github.com/arj03/seedrelay/releases/latest). Releases of `relay.skb` are
signed by bundle author `3946ed318bf777e840ae3cf17ce2e3124b83683f582437244af253eeb5837fcb`.

```sh
seedkernel --transport relay.skb --key relay-id.key --listen 127.0.0.1:8080
```

```
seedkernel-native <relay key>
  …
  tcp    listening on :8080
  contact <secret>
```

The relay's URL is `ws://<relay key>.<secret>@127.0.0.1:8080`; hand it to your nodes.
`relay-id.key` is the relay's identity, created on first start, so keep it: a new key
means a new URL. The relay also answers STUN on UDP 3478 and 3479, so nodes can find
their public addresses for WebRTC.

## Settings

Pass a JSON file with `--transport-config relay.json`. Every key is optional.

| Key | Default | Meaning |
| --- | --- | --- |
| `allowOrigins` | localhost pages | Browser origins allowed to connect. Replaces the defaults; `"null"` allows `file://` pages. |
| `trustedProxies` | `[]` | Proxy IPs whose `X-Forwarded-For` is believed. |
| `secrets` | the key's own | Contact secrets (64 hex) nodes must hold. List two to rotate. |
| `open` | `false` | Take any node, with no secret. Only for a relay meant to be public. |
| `stun` | `3478` | First of the two STUN ports; `0` lets the OS pick, `null` turns STUN off. |
| `limits` | | Any of the limits below. |

| Limit | Default | Meaning |
| --- | --- | --- |
| `maxConns` | `2048` | Sockets across the relay; splices may take 7/8 of them. |
| `maxRooms` | `512` | Rooms. |
| `maxPerRoom` | `32` | Members per room, at most 1024. |
| `maxPerIp` | `72` | Sockets charged to one client address, including both ends of its splices. |
| `maxPerRoomIp` | `16` | Members one address may hold in one room. |
| `ipv6Prefix` | `64` | Bits of an IPv6 address that count as one client. |
| `registerRate` | `4` | Registrations and room joins per second per address; `0` for unmetered. |
| `spliceRate` | `1024` | KiB/s per address through splices; `0` for unmetered. |
| `heartbeatSecs` | `30` | Ping interval; a socket that misses a pong is dropped. `0` disables it. |

## Deploying publicly

Put the relay behind a TLS reverse proxy on the same machine, listening on loopback and
trusting the proxy:

```sh
echo '{ "trustedProxies": ["127.0.0.1"], "allowOrigins": ["https://app.example"] }' > relay.json
seedkernel --transport relay.skb --key relay-id.key --listen 127.0.0.1:8080 --transport-config relay.json
```

Nodes then use `wss://<relay key>.<secret>@relay.example`. Also:

- **Forward plain `ws://` (port 80) to the same relay.** Console nodes have no TLS.
- **Open UDP 3478 and 3479.** STUN doesn't pass through an HTTP proxy; without it, pairs on
  different networks mostly stay relayed.
- **Block direct access to the relay's port**, so only the proxy can claim to forward for
  someone else.

With a certificate and no proxy, `scripts/https-front.mjs` (Node, no dependencies) can
serve a page over HTTPS and pass `/v1/` upgrades to the relay; see its header comment.

**Private by default.** A relay only takes nodes that hold its contact secret, which is
derived from its key unless `secrets` names one. The secret is never sent on the wire,
so a node without it gets silence. If `relay.json` holds secrets, make it readable by the
relay's user only. `"open": true` lets anyone register, use the relay as a pipe, and see
who is online.

## Joining a room

An app registers its node on the relay through the transport's `relay` operation, joins
rooms with `rooms.mjs`, and hands each member it hears to the transport with `addr`:

```js
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

The relay only sees a hash of the room name, and a room's secret is derived from the
name, so anyone who knows the name can join and reach its members. Use a long random name
for a private room. The transport redials a relay that drops, and the room client joins
its rooms again.

## Running on Node

The repo also runs `relay.skb` in a Node process, for developing the relay and for apps
that start one from their scripts (seedshell's `npm run relay`). It needs Node ≥ 22 and a
built seedkernel checkout beside this one, which it uses as
`"seedkernel-wasm": "file:../seedkernel/WASM"`. Apps depend on seedrelay the same way,
with `"seedrelay": "file:../seedrelay"`.

```sh
npm install
npm run start -- 8080     # or: npx seedrelay 8080
npm test
```

The `seedrelay` bin listens on `127.0.0.1:8080` by default and takes each setting as a
flag (`--allow-origin`, `--trusted-proxy`, `--secret`, `--open`, `--stun`,
`--max-conns`, …), listed in `server.mjs`. Without `--key FILE` its URL is new each run.
`--print-config` prints the flags as a `relay.json` for the binary.

| Script | What it does |
| --- | --- |
| `npm run build` | Signs `guest/relay.js` with seedkernel's channel code into `bundle/relay.skb`, under `relay.key` (created on first build). |
| `npm test` | Runs the tests, including one that fails while `relay.skb` is out of date. |
| `npm run release` | Tags `v<version>` and opens a draft GitHub release with `relay.skb`, once both repos are clean and the tests pass. |

## Troubleshooting

- **`403` on upgrade.** The page's origin isn't in `allowOrigins`.
- **`429`, or a room join refused.** A limit was hit; the relay logs which.
- **A node never registers.** Its URL has the wrong secret or key; a relay started with
  another `--key` has another URL.
- **Other devices can't connect.** `--listen 127.0.0.1:…` serves this machine only.
- **Peers on different networks stay relayed.** UDP 3478 and 3479 aren't reachable, or
  `stun` is `null`.
- **Relayed traffic is slow.** The sender is past `spliceRate`.
