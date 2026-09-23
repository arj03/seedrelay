// Minimal WebSocket broadcast hub — the app-neutral signaling rendezvous for the
// kernel's RtcNetwork (seedkernel `host/net-rtc.ts`, §12.7). It lives in seedrelay
// because it is a deployment concern, not trusted runtime surface: the kernel ships
// no server and its own tests signal in-process. Seedchat and seedstore both consume
// this package.
//
// Used only as a WebRTC signaling rendezvous: clients exchange JSON SDP
// offers / answers and ICE candidates here, then open RTCDataChannels to
// each other and route kernel envelopes peer-to-peer. Once every pair of
// active peers has an open DataChannel, this process can be killed without
// disrupting traffic — it only matters for adding new peers.
//
// Clients pick a "room" by connecting to ws://host:port/<room>. Broadcasts
// are scoped to the room: a frame from a client in room "alpha" reaches
// only other clients in "alpha". A bare ws://host:port/ lands the client
// in the default room "global", so older clients keep working unchanged.
// Rooms exist for as long as anyone is in them; they are not authenticated
// — knowing the room name is the only credential, so callers who want
// privacy should pick a name with enough entropy that nobody else will
// guess it (e.g. 16+ random bytes hex).
//
// The relay is intentionally dumb: every frame from one client is forwarded
// verbatim to every other connected client in the same room. Signaling
// messages carry `from` / `to` peer-id fields so clients can filter; the
// relay itself does not inspect them. SeedKernel signatures and trust are
// still verified end-to-end inside each peer's kernel pipeline.
//
// No third-party dependencies.
//
// Run: seedrelay [port] [options]  (or: node server.mjs)
//   --port N               port to listen on (default 8080; a bare number works too)
//   --host HOST            interface to bind (default 127.0.0.1)
//   --allow-origin ORIGIN  allow this Origin (repeatable; replaces the localhost defaults)
//   --max-conns N          total concurrent sockets        (env RELAY_MAX_CONNS)
//   --max-rooms N          total concurrent rooms          (env RELAY_MAX_ROOMS)
//   --max-per-room N       sockets per room                (env RELAY_MAX_PER_ROOM)
//   --max-per-ip N         sockets per client address      (env RELAY_MAX_PER_IP)
//   --heartbeat-secs N     ping/reap interval, 0=off       (env RELAY_HEARTBEAT_SECS)
//   --trusted-proxy IP     trust this proxy address (repeatable; env RELAY_TRUSTED_PROXIES)
//   --trust-proxy          legacy flag; requires explicit trusted proxy addresses

import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { isUtf8 } from "node:buffer";
import { isIP } from "node:net";

// ─── CLI parsing ─────────────────────────────────────────────────────────

// Parse a non-negative number, falling back to `d` on anything malformed.
const num = (v, d) => { const n = Number(v); return Number.isFinite(n) && n >= 0 ? n : d; };

const args = process.argv.slice(2);
let PORT = 8080;
let HOST = "127.0.0.1";
const ALLOWED_ORIGINS = new Set();

// ─── resource limits ───────────────────────────────────────────────────────
//
// Independent caps that bound the relay's footprint against both accidental
// fan-out and deliberate exhaustion. Defaults are generous for signaling (a
// rendezvous group is small and short-lived) but finite. Env vars seed the
// defaults; matching CLI flags override them.
let MAX_CONNECTIONS    = num(process.env.RELAY_MAX_CONNS,        1024);
let MAX_ROOMS          = num(process.env.RELAY_MAX_ROOMS,         512);
let MAX_CONNS_PER_ROOM = num(process.env.RELAY_MAX_PER_ROOM,       64);
let MAX_CONNS_PER_IP   = num(process.env.RELAY_MAX_PER_IP,         64);
let HEARTBEAT_MS       = num(process.env.RELAY_HEARTBEAT_SECS,     30) * 1000;
let TRUST_PROXY        = process.env.RELAY_TRUST_PROXY === "1";
const TRUSTED_PROXIES = new Set();
function normalizeIp(value) {
  // Scoped IPv6 addresses are accepted by net.isIP but are not valid URL
  // hosts or portable forwarded addresses. Reject before URL normalization.
  if (value.includes("%") || !isIP(value)) return null;
  if (isIP(value) === 4) return value;
  const normalized = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(normalized);
  if (!mapped) return normalized;
  const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}
function trustProxy(value) {
  const ip = normalizeIp(value);
  if (!ip) throw new TypeError("trusted proxy must be an IP address");
  TRUSTED_PROXIES.add(ip);
}
for (const ip of (process.env.RELAY_TRUSTED_PROXIES ?? "").split(",")) {
  if (ip.trim()) trustProxy(ip.trim());
}

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--host") { HOST = args[++i] ?? HOST; }
  else if (a === "--allow-origin") { ALLOWED_ORIGINS.add(args[++i] ?? ""); }
  else if (a === "--port") { PORT = Number(args[++i]) || PORT; }
  else if (a === "--max-conns") { MAX_CONNECTIONS = num(args[++i], MAX_CONNECTIONS); }
  else if (a === "--max-rooms") { MAX_ROOMS = num(args[++i], MAX_ROOMS); }
  else if (a === "--max-per-room") { MAX_CONNS_PER_ROOM = num(args[++i], MAX_CONNS_PER_ROOM); }
  else if (a === "--max-per-ip") { MAX_CONNS_PER_IP = num(args[++i], MAX_CONNS_PER_IP); }
  else if (a === "--heartbeat-secs") { HEARTBEAT_MS = num(args[++i], HEARTBEAT_MS / 1000) * 1000; }
  else if (a === "--trust-proxy") { TRUST_PROXY = true; }
  else if (a === "--trusted-proxy") { trustProxy(args[++i] ?? ""); }
  else if (/^\d+$/.test(a)) { PORT = Number(a); }
}
if (TRUST_PROXY && TRUSTED_PROXIES.size === 0) {
  throw new Error("--trust-proxy requires --trusted-proxy IP or RELAY_TRUSTED_PROXIES");
}
TRUST_PROXY = TRUSTED_PROXIES.size > 0;
// Opaque origins (including file pages and sandboxed iframes) are not trusted
// by default. Operators can explicitly opt in with --allow-origin null.
if (ALLOWED_ORIGINS.size === 0) {
  for (const scheme of ["http", "https"]) {
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      ALLOWED_ORIGINS.add(`${scheme}://${host}`);
      for (const port of [80, 443, 3000, 5173, 8000, 8080, 8443]) {
        ALLOWED_ORIGINS.add(`${scheme}://${host}:${port}`);
      }
    }
  }
}

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ─── safety limits ───────────────────────────────────────────────────────
//
// Picked for signaling traffic — SDPs are a few KB, ICE candidates are a
// few hundred bytes. 64 KB is room for an unusually fat SDP; anything
// larger is almost certainly garbage or an attacker probing limits.
const MAX_FRAME_PAYLOAD = 64 * 1024;
// Every write, including control frames, shares the same hard backlog cap.
const MAX_SOCKET_BACKLOG = 256 * 1024;
const HANDSHAKE_TIMEOUT_MS = 10_000;

// Token buckets bound sustained traffic as well as bursts. Global budgets
// survive reconnects and room turnover; fan-out is charged per recipient.
function bucket(rate, burst = rate * 2) {
  return { rate, burst, tokens: burst, at: performance.now() };
}
function spend(b, amount) {
  const now = performance.now();
  b.tokens = Math.min(b.burst, b.tokens + (now - b.at) * b.rate / 1000);
  b.at = now;
  if (amount > b.tokens) return false;
  b.tokens -= amount;
  return true;
}
const incomingBytes = bucket(4 * 1024 * 1024);
const incomingFrames = bucket(8192);
const outgoingBytes = bucket(16 * 1024 * 1024);
const outgoingFrames = bucket(16384);

function writeFrame(sock, frame) {
  if (sock.destroyed || !sock.writable) return false;
  if (sock.writableLength + frame.length > MAX_SOCKET_BACKLOG) {
    sock.destroy();
    return false;
  }
  try { sock.write(frame); return true; }
  catch { sock.destroy(); return false; }
}

// ─── rooms ───────────────────────────────────────────────────────────────
//
// Rooms are looked up by name in a single Map<string, Set<sock>>. A socket
// joins exactly one room for its lifetime; teardown removes it from that
// room and drops the room entry when it goes empty so the table doesn't
// grow without bound.
//
// Room names are restricted to URL-safe characters and a length cap so the
// upgrade path can never be used to allocate giant strings or smuggle
// control characters into log lines.
const DEFAULT_ROOM = "global";
const MAX_ROOM_NAME = 128;
const ROOM_NAME_RE = /^[A-Za-z0-9._-]+$/;

const rooms = new Map();

function joinRoom(name, sock) {
  let set = rooms.get(name);
  if (!set) {
    set = new Set();
    set.bytes = bucket(2 * 1024 * 1024);
    set.frames = bucket(2048);
    rooms.set(name, set);
  }
  set.add(sock);
  return set;
}

function leaveRoom(name, sock) {
  const set = rooms.get(name);
  if (!set) return 0;
  set.delete(sock);
  if (set.size === 0) rooms.delete(name);
  return set.size;
}

// Pull the room name out of the upgrade request's path. Accepts:
//   /            → DEFAULT_ROOM
//   /foo         → "foo"
//   /foo?bar=1   → "foo"  (query string ignored)
// Returns null when the path is present but malformed (too long, illegal
// characters) so the caller can 400 the upgrade.
function roomFromRequest(req) {
  const url = typeof req.url === "string" ? req.url : "/";
  // Strip query / fragment, then the leading slash.
  const path = url.split(/[?#]/, 1)[0];
  const raw = path.startsWith("/") ? path.slice(1) : path;
  if (raw === "") return DEFAULT_ROOM;
  if (raw.length > MAX_ROOM_NAME) return null;
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch { return null; }
  if (!ROOM_NAME_RE.test(decoded)) return null;
  return decoded;
}

// ─── connection tracking ───────────────────────────────────────────────────
//
// `sockets` is every live upgraded socket. A socket already lives in exactly
// one room, but the flat set supports heartbeat sweeps. `ipCounts` tracks
// upgraded client addresses; `connections` and `addressCounts` include all
// accepted TCP sockets. Entries are deleted when their counts reach zero.
const sockets = new Set();
const ipCounts = new Map();
const connections = new Set();
const addressCounts = new Map();

// Walk from the actual remote address toward the client, stopping at the
// first untrusted hop. Never trust a client-supplied leftmost XFF value.
function clientIp(req, sock) {
  let ip = normalizeIp(sock.remoteAddress ?? "") ?? "unknown";
  if (TRUSTED_PROXIES.has(ip)) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff !== "string" || !xff) return null;
    const chain = xff.split(",").map((part) => normalizeIp(part.trim()));
    if (chain.some((part) => part === null)) return null;
    for (let i = chain.length - 1; i >= 0 && TRUSTED_PROXIES.has(ip); i--) ip = chain[i];
  }
  return ip;
}

// Refuse an upgrade with a short HTTP error and tear the socket down. Used for
// the resource-limit rejections before we ever switch protocols.
function refuse(sock, code, reason, note) {
  try {
    sock.write(`HTTP/1.1 ${code} ${reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
  } catch { /* socket already gone */ }
  sock.destroy();
  console.log(`! refused upgrade: ${note}`);
}

// ─── server ──────────────────────────────────────────────────────────────

const server = createServer((_req, res) => {
  res.writeHead(426, { "Content-Type": "text/plain", "Connection": "close" });
  res.end("WebSocket relay — connect with ws://<host>:<port>/<room>\n");
});

// Account for TCP sockets before any HTTP headers arrive. Trusted proxies
// share the global cap here; their forwarded clients are capped at upgrade.
server.on("connection", (sock) => {
  const address = normalizeIp(sock.remoteAddress ?? "") ?? "unknown";
  if (connections.size >= MAX_CONNECTIONS ||
      (!TRUSTED_PROXIES.has(address) && (addressCounts.get(address) ?? 0) >= MAX_CONNS_PER_IP)) {
    sock.destroy();
    return;
  }
  connections.add(sock);
  addressCounts.set(address, (addressCounts.get(address) ?? 0) + 1);
  sock._relayHandshakeTimer = setTimeout(() => sock.destroy(), HANDSHAKE_TIMEOUT_MS);
  sock._relayHandshakeTimer.unref();
  sock.on("error", () => sock.destroy());
  sock.once("close", () => {
    clearTimeout(sock._relayHandshakeTimer);
    connections.delete(sock);
    const remaining = addressCounts.get(address) - 1;
    if (remaining) addressCounts.set(address, remaining);
    else addressCounts.delete(address);
  });
});

server.on("upgrade", (req, sock, head) => {
  if (sock.destroyed || !connections.has(sock)) { sock.destroy(); return; }
  const key = req.headers["sec-websocket-key"];
  if (req.method !== "GET" || req.headers.upgrade?.toLowerCase() !== "websocket" ||
      req.headers["sec-websocket-version"] !== "13" ||
      typeof key !== "string" || !/^[A-Za-z0-9+/]{22}==$/.test(key) ||
      Buffer.from(key, "base64").length !== 16) { sock.destroy(); return; }

  // CSWSH defence: only accept upgrades whose Origin is on the allowlist.
  // The browser fills Origin from the page that initiated the WS, so a
  // drive-by from evil.example.com cannot impersonate the local shell.
  const origin = req.headers["origin"];
  // No origin header at all is suspicious from a browser but expected from
  // hand-rolled clients (`websocat`, `wscat`); we accept those as a
  // convenience. Comment out the next two lines if you want strict mode.
  const originStr = typeof origin === "string" ? origin : "";
  if (originStr && !ALLOWED_ORIGINS.has(originStr)) {
    sock.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    sock.destroy();
    console.log("! rejected upgrade: origin not allowed");
    return;
  }

  const room = roomFromRequest(req);
  if (room === null) {
    sock.write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
    sock.destroy();
    console.log("! rejected upgrade: bad room path");
    return;
  }

  // ─── resource limits ──────────────────────────────────────────────────
  // Refuse before switching protocols so a rejected client never consumes a
  // room slot or a frame buffer. Caps are independent; the first one tripped
  // wins. Counts are released in drop() when the socket closes.
  const ip = clientIp(req, sock);
  if (ip === null) { refuse(sock, 400, "Bad Request", "invalid proxy address chain"); return; }
  if (sockets.size >= MAX_CONNECTIONS) {
    refuse(sock, 503, "Service Unavailable", `at capacity (${sockets.size} conns)`);
    return;
  }
  if ((ipCounts.get(ip) ?? 0) >= MAX_CONNS_PER_IP) {
    refuse(sock, 429, "Too Many Requests", "per-ip cap");
    return;
  }
  const existingRoom = rooms.get(room);
  if (!existingRoom && rooms.size >= MAX_ROOMS) {
    refuse(sock, 429, "Too Many Requests", `room table full (${rooms.size} rooms)`);
    return;
  }
  if ((existingRoom?.size ?? 0) >= MAX_CONNS_PER_ROOM) {
    refuse(sock, 429, "Too Many Requests", "room full");
    return;
  }

  const accept = createHash("sha1").update(key + GUID).digest("base64");
  sock.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );

  const roomSet = joinRoom(room, sock);
  clearTimeout(sock._relayHandshakeTimer);
  sock._relayRoom = room;
  sock._relayIp = ip;
  sock._relayAlive = true;                // cleared each heartbeat, set on pong
  sockets.add(sock);
  ipCounts.set(ip, (ipCounts.get(ip) ?? 0) + 1);
  console.log(`+ client (${roomSet.size} in room, ${rooms.size} rooms, ${sockets.size} total)`);
  const byteBudget = bucket(256 * 1024);
  const frameBudget = bucket(128);

  // Chunk buffer: a list of incoming Buffers + the total bytes pending.
  // We only Buffer.concat when we have at least enough bytes to parse the
  // next frame header, and we slice the head off in one operation per
  // consumed frame. v1's per-chunk concat was O(n²) for any large frame.
  const chunks = [];
  let chunkTotal = 0;

  function consumeBytes(n) {
    // Drop the leading `n` bytes from the chunk list. If n == chunkTotal
    // we just empty the list; otherwise we walk forward until we've
    // accounted for `n` bytes and keep the tail of the current chunk.
    let remaining = n;
    while (remaining > 0 && chunks.length > 0) {
      const c = chunks[0];
      if (c.length <= remaining) {
        remaining -= c.length;
        chunks.shift();
      } else {
        chunks[0] = c.subarray(remaining);
        remaining = 0;
      }
    }
    chunkTotal -= n;
  }

  function peek(n) {
    // Return a contiguous view over the first `n` bytes, or null if we
    // don't have that many yet. Avoids the full concat in the common case
    // where the first chunk already covers `n` bytes.
    if (chunkTotal < n) return null;
    if (chunks[0].length >= n) return chunks[0].subarray(0, n);
    // Concat just enough to satisfy the read.
    const collected = [];
    let have = 0;
    for (const c of chunks) {
      collected.push(c);
      have += c.length;
      if (have >= n) break;
    }
    return Buffer.concat(collected).subarray(0, n);
  }

  const onData = (chunk) => {
    if (sock.destroyed) return;
    if (!spend(byteBudget, chunk.length) || !spend(incomingBytes, chunk.length)) {
      sock.destroy(); return;
    }
    chunks.push(chunk);
    chunkTotal += chunk.length;

    // Drain as many complete frames as we have.
    while (true) {
      const header = peek(2);
      if (!header) break;

      // Enforce FIN=1 (no fragmented frames). The relay is for short
      // signaling JSON; legitimate clients never need fragmentation.
      // A FIN=0 frame would be repacked as FIN=1 by encodeFrame below,
      // changing the semantics on the wire — better to refuse outright.
      const fin = (header[0] & 0x80) !== 0;
      if (!fin || (header[0] & 0x70) !== 0) {
        console.log("! dropped: fragmentation or reserved frame bits");
        sock.destroy();
        return;
      }

      const opcode = header[0] & 0x0f;
      if (![1, 2, 8, 9, 10].includes(opcode) ||
          (opcode >= 8 && (header[1] & 0x7f) > 125)) {
        sock.destroy(); return;
      }
      const masked = (header[1] & 0x80) !== 0;
      // Per RFC 6455 client→server frames MUST be masked.
      if (!masked) {
        console.log("! dropped: unmasked client frame");
        sock.destroy();
        return;
      }

      let payloadLen = header[1] & 0x7f;
      let headerLen = 2;
      if (payloadLen === 126) {
        const ext = peek(4);
        if (!ext) break;
        payloadLen = ext.readUInt16BE(2);
        if (payloadLen < 126) { sock.destroy(); return; }
        headerLen = 4;
      } else if (payloadLen === 127) {
        const ext = peek(10);
        if (!ext) break;
        const big = ext.readBigUInt64BE(2);
        // Bound the announced length BEFORE we ever try to allocate.
        if (big > BigInt(MAX_FRAME_PAYLOAD)) {
          console.log(`! dropped: oversize frame announced (${big})`);
          sock.destroy();
          return;
        }
        payloadLen = Number(big);
        if (payloadLen < 65536) { sock.destroy(); return; }
        headerLen = 10;
      }
      if (payloadLen > MAX_FRAME_PAYLOAD) {
        console.log(`! dropped: oversize frame (${payloadLen})`);
        sock.destroy();
        return;
      }

      const totalFrame = headerLen + 4 + payloadLen; // +4 mask
      const full = peek(totalFrame);
      if (!full) break;                              // wait for more bytes
      if (!spend(frameBudget, 1) || !spend(incomingFrames, 1)) {
        sock.destroy(); return;
      }

      const mask = full.subarray(headerLen, headerLen + 4);
      const masked_payload = full.subarray(headerLen + 4, totalFrame);
      const payload = Buffer.alloc(payloadLen);
      for (let i = 0; i < payloadLen; i++) {
        payload[i] = masked_payload[i] ^ mask[i % 4];
      }
      consumeBytes(totalFrame);

      // handleFrame returns false when it has torn the socket down (close
      // opcode, or an invalid frame) — stop draining so we don't keep parsing
      // and broadcasting buffered frames off a socket we just ended/destroyed.
      if (!handleFrame(opcode, payload)) return;
    }
  };
  sock.on("data", onData);

  // Returns true to keep draining buffered frames, false once the socket has
  // been torn down (close opcode or invalid frame) so the caller stops.
  function handleFrame(opcode, payload) {
    if (opcode === 0x8) { sock.destroy(); return false; }   // close
    if (opcode === 0x9) {                                     // ping → pong
      return writeFrame(sock, encodeFrame(0xA, payload));
    }
    if (opcode === 0xA) { sock._relayAlive = true; return true; }  // pong → still alive
    if (opcode === 0x1 || opcode === 0x2) {                   // text/binary
      if (opcode === 0x1 && !isUtf8(payload)) { sock.destroy(); return false; }
      const out = encodeFrame(opcode, payload);
      // Broadcasts stay inside the sender's room. A client in room "alpha"
      // never sees frames from room "beta"; the relay does no other routing.
      const peers = rooms.get(sock._relayRoom);
      if (!peers) return true;
      const recipients = peers.size - 1;
      if (!spend(peers.bytes, out.length * recipients) || !spend(peers.frames, recipients) ||
          !spend(outgoingBytes, out.length * recipients) || !spend(outgoingFrames, recipients)) {
        sock.destroy(); return false;
      }
      for (const other of peers) {
        if (other === sock) continue;
        if (!other.writable) continue;
        writeFrame(other, out);
      }
      return true;
    }
    // Continuation (0x0) and reserved opcodes (3-7, B-F) are not valid
    // here given FIN=1 was already enforced. Drop the connection.
    console.log(`! dropped: invalid opcode 0x${opcode.toString(16)}`);
    sock.destroy();
    return false;
  }

  let dropped = false;
  const drop = () => {
    if (dropped) return;
    dropped = true;
    sockets.delete(sock);
    const ipKey = sock._relayIp;
    if (ipKey !== undefined) {
      const n = (ipCounts.get(ipKey) ?? 0) - 1;
      if (n > 0) ipCounts.set(ipKey, n); else ipCounts.delete(ipKey);
    }
    const r = sock._relayRoom;
    if (r !== undefined) {
      const remaining = leaveRoom(r, sock);
      console.log(`- client (${remaining} in room, ${rooms.size} rooms, ${sockets.size} total)`);
    }
  };
  sock.on("close", drop);
  sock.on("error", drop);
  // Node may deliver the first frame with the HTTP upgrade request.
  if (head?.length) onData(head);
});

// Encode a server→client frame (unmasked per RFC 6455).
function encodeFrame(opcode, payload) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  header[0] = 0x80 | opcode;
  return Buffer.concat([header, payload]);
}

// ─── heartbeat / dead-socket reaping ──────────────────────────────────────
//
// NAT and firewall timeouts — the very thing this relay exists to punch
// through — leave half-open sockets that never emit 'close', so without a
// liveness probe a dropped peer would hold its room/IP slot forever. Each
// interval we ping every socket; any socket that did not answer the previous
// ping with a pong (opcode 0xA, which sets _relayAlive back to true) is
// presumed dead and destroyed, firing its normal drop() cleanup.
if (HEARTBEAT_MS > 0) {
  const PING = encodeFrame(0x9, Buffer.alloc(0));
  const beat = setInterval(() => {
    for (const sock of sockets) {
      if (sock._relayAlive === false) { sock.destroy(); continue; }
      sock._relayAlive = false;
      writeFrame(sock, PING);
    }
  }, HEARTBEAT_MS);
  beat.unref();  // a pending ping timer alone shouldn't keep the process alive
}

server.listen(PORT, HOST, () => {
  console.log(`SeedKernel signaling relay listening on ws://${HOST}:${server.address().port}/<room>`);
  console.log(`  origin allowlist: ${[...ALLOWED_ORIGINS].slice(0, 4).join(", ")}…`);
  console.log(`  frame cap: ${MAX_FRAME_PAYLOAD} B  socket backlog cap: ${MAX_SOCKET_BACKLOG} B`);
  console.log(`  rooms: any path component (chars [A-Za-z0-9._-], up to ${MAX_ROOM_NAME}); bare "/" = "${DEFAULT_ROOM}"`);
  console.log(`  limits: ${MAX_CONNECTIONS} conns, ${MAX_ROOMS} rooms, ${MAX_CONNS_PER_ROOM}/room, ${MAX_CONNS_PER_IP}/ip${TRUST_PROXY ? " (X-Forwarded-For trusted)" : ""}`);
  console.log(`  heartbeat: ${HEARTBEAT_MS > 0 ? `${HEARTBEAT_MS / 1000}s ping/reap` : "disabled"}`);
  if (HOST !== "127.0.0.1" && HOST !== "localhost" && HOST !== "::1") {
    console.log(`  ⚠  bound to ${HOST} — exposed to the network`);
  }
  console.log(`Signaling only — point an app's Network tab at this relay.`);
});
