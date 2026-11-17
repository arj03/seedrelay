# seedrelay: protocol and limits

What the relay speaks and enforces, for implementers and operators sizing a deployment.
The settings named here are the `relay.json` keys in the [README](../README.md#settings).

## Sockets

| Path | Socket |
| --- | --- |
| `/v1/` | A relay link: a node registers its key, places and takes calls, and joins rooms |
| `/v1/?splice=<32 hex>` | One end of a splice, named by the ticket a call gave it |

The first segment names the wire version; any other path gets `404`. A splice ticket
nobody was given gets `404`, a second socket for one ticket `409`, and a plain HTTP
request `426 Upgrade Required`.

## The wire

A relay link runs seedkernel's channel handshake first (seedkernel's TRANSPORT.md), the
node as initiator and the relay as responder, each message one binary WebSocket frame. The
node pins the relay's key, and msg1 opens under the relay's contact secret, so a relay's
address is `ws://<key>.<secret>@host:port`, or `ws://<key>@host:port` for an open relay.
After the handshake every frame is a record, `[type u8][body]`. Keys are 32-byte
seedkernel identities, rooms 32-byte ids, tickets 16 random bytes.

| Relay → node | | Node → relay | |
| --- | --- | --- | --- |
| `0x01` registered | | `0x05` call | `[to 32][ticket 16]` |
| `0x05` incoming | `[from 32][ticket 16]` | `0x08` tell | `[message]` |
| `0x06` unreachable | `[to 32][ticket 16]` | | |
| `0x08` tell | `[message]` | | |

A tell carries rooms, which the node's transport passes to and from the app unread:

| Relay → node | | Node → relay | |
| --- | --- | --- | --- |
| `0x02` members | `[room 32][pk 32]*` | `0x02` join | `[room 32]` |
| `0x03` joined | `[room 32][pk 32]` | `0x03` leave | `[room 32]` |
| `0x04` left | `[room 32][pk 32]` | | |
| `0x07` refused | `[room 32]` | | |

- **Registration.** msg3 proves the node's key, and that is its registration. Calls for a
  key go to the link that proved it most recently. A msg1 that doesn't open under the
  relay's secret gets silence until the handshake deadline, as any seedkernel accept does.
  A record the wire has no use for, or one that doesn't open, drops the link.
- **Rooms.** A link joins up to 16 rooms by id. `rooms.mjs` makes the id as SHA-256 of
  `"seedrelay-room-v1\0" ‖ name`, so the relay never learns names. A join gets the
  room's other keys in one `members` message, then `joined` and `left` as keys come and
  go; two links with one key are one member. A join with no seat is `refused`, and the link
  stays registered. A room exists while anyone is in it.
- **Calls.** `call` sends `incoming` to the callee's link only, with a ticket of the
  relay's own, or answers `unreachable` when the key isn't registered, is the caller's own,
  the ticket is in use, or the caller has too many calls waiting. Each end then opens
  `/v1/?splice=<its ticket>`; the relay joins them once both are there, or drops them
  after 10 seconds.
- **Splices.** Data frames stream through unmasked, whatever their size or
  fragmentation. Ping and pong stay on each hop, and a close ends both ends. A receiver
  holding more than 64 KiB unread pauses its sender until it is down to 16 KiB, and one that
  doesn't drain for 2 minutes ends the splice.

**A room id is a bearer credential** for learning which keys are in it. Room ids travel
inside records, never in a URL, and the relay never logs them, keys or request paths.
Reaching a key needs no room; the callee's contact secret gates it.

## Origins

Every socket a page opens counts against its visitor's address, so the origin allowlist
keeps a hostile page from spending its visitors' budgets here. It is not authentication;
the relay keeps no cookies or other ambient credentials. The default covers `http://` and
`https://` pages on `localhost`, `127.0.0.1` and `[::1]`, with no port or on 80, 443,
3000, 5173, 8000, 8080 and 8443. Other origins get `403`. Opaque origins (`null`) are
refused unless listed; clients that send no `Origin`, such as native nodes, are accepted.

## Proxies

The relay walks `X-Forwarded-For` from right to left and stops at the first address not
in `trustedProxies`, so a client-supplied value is never believed. Forwarded headers from
untrusted connections are ignored, and a trusted connection with a missing or malformed
chain gets `400`. IP trust can't tell apart processes sharing an address, so block direct
access to the relay's port.

Accounting starts at TCP, before headers arrive: a direct client counts against the
per-address cap at once, while a proxy's connections share only the global cap until each
client's headers name it.

Over plain `ws://` an observer sees the room ids a node joins, the rooms' keys and who
calls whom, though splice traffic stays encrypted end to end. A node dialing
`ws://relay.example` registers just as one dialing `wss://relay.example` does.

## Limits

- **Frames** on a relay link are binary and at most 2 KiB (msg1, the largest, is 1,233
  bytes). Text, fragmented frames and extensions are refused, and lengths must be in
  their shortest encoding, on splices too.
- **Backlog.** Writes to a relay link respect a 256 KiB per-socket cap; slow readers are
  dropped. Splices use backpressure instead.
- **Handshakes** must finish within 10 seconds of the TCP connection for HTTP, and 10
  seconds of the upgrade for the channel.
- **Calls** are charged to the caller's address: as many waiting as `maxPerRoom`, at most
  8 splices to one key, and both ends of each splice count against the caller's
  `maxPerIp`, so calls can't spend the callee's share.
- **Splices** are metered per address at `spliceRate` with two seconds of burst. Past it,
  the address's splice sockets aren't read until the debt is paid, so a sender is slowed,
  not dropped. Without it, two keys spliced together would be an unmetered pipe.
- **Rooms.** One address may hold `maxPerRoomIp` seats in a room.
- **Addresses.** IPv6 clients are counted by their `/64` (`ipv6Prefix`). One address opens
  at most `registerRate` relay links a second, and joins rooms at the same rate with 32 at
  once, so an app that redials can join all its rooms again.

| Incoming traffic | Sustained limit, two seconds of burst |
| --- | --- |
| Per connection | 128 frames/s and 256 KiB/s |
| Across the relay | 8,192 frames/s and 4 MiB/s |

Exceeding an incoming budget drops the sender. A relay at `maxConns` drops new TCP
connections, and one whose splices hold 7/8 of it refuses new splices with `503`, so
nodes can still register. Other socket caps get `429` before the upgrade; room caps get
`refused`. None of this protects against a distributed denial of service.

## Sizing

A room of N members that all stay relayed costs N(N−1) splice sockets plus N relay links,
and its smallest key, which calls the rest, is charged 2(N−1) + 1 against its address. The
defaults fit one such room of 32 (992 of the 1,792 splice sockets, and 63 of an address's
72). Pairs that move to WebRTC cost nothing, so most rooms need far less. A relay hosting
several large rooms of native nodes behind NAT should raise `maxConns` with the process's
file limit.

Every socket is served by the one realm the bundle runs in. On a laptop's loopback the
native binary carried one splice at 143 MB/s, far above the per-address meter. Past what
the realm can take, the host stops reading sockets rather than dropping them.

## STUN

The seedkernel transport asks the relay a peer is linked through for its public address,
at `stun:<relay host>:3478` and `:3479`, so no third party learns who is online. The relay
answers RFC 8489 Binding requests only, at most 20 a second to one address and 256 new
addresses a second, since UDP sources can be forged. Two ports, because a node whose two
answers name different ports is behind a NAT that gives each destination its own port,
and needs more than a plain hole punch.
