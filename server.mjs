// The rendezvous and forwarder for seedkernel nodes (§12.7). A node registers its key
// here over a control socket, learns the other members of a room, and reaches any
// registered key through a splice: two fresh sockets the relay joins, copying bytes
// between them. The seedkernel channel handshake runs end to end through a splice, so
// the relay forwards ciphertext it cannot read, and cannot pose as either end. It lives
// in seedrelay because it is a deployment concern, not trusted runtime surface: the
// kernel ships no server and its own tests use an in-process relay. Seedchat and
// seedstore both use it.
//
// Sockets, by upgrade path:
//
//   ws://host:port/<room>           a control socket that joins <room>
//   ws://host:port/                 a control socket in no room: reachable by key only
//   ws://host:port/?splice=<hex>    one end of a splice, named by a 16-byte ticket
//
// A control socket must register before anything else: the relay sends a nonce, and the
// node signs it with its seedkernel identity key (`registerMessage`). The relay routes
// calls to the socket that registered a key most recently, and a room's membership is
// the set of keys registered in it. Rooms are not authenticated: a room name is a bearer
// credential for learning who is there, so a private room wants a name with 16+ random
// bytes. Reaching a node needs only its key, since the node's own contact secret gates
// its handshake end to end.
//
// A splice is set up by a call: the caller names the callee's key and a fresh ticket on
// its control socket, the relay passes the ticket to the callee's control socket only,
// and both ends open a splice socket with it. The relay joins the first two sockets
// presenting a ticket, and refuses one nobody called, so two strangers cannot use it as
// a pipe. One party holding two keys can, so what splices carry is metered per client
// address.
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
//   --max-per-room-ip N    sockets per address in one room (env RELAY_MAX_PER_ROOM_IP)
//   --splice-rate N        KiB/s an address sends through splices, 0=unmetered
//                                                          (env RELAY_SPLICE_RATE)
//   --heartbeat-secs N     ping/reap interval, 0=off       (env RELAY_HEARTBEAT_SECS)
//   --trusted-proxy IP     trust this proxy address (repeatable; env RELAY_TRUSTED_PROXIES)
//   --trust-proxy          legacy flag; requires explicit trusted proxy addresses

import { createServer } from "node:http";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
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
// fan-out and deliberate exhaustion. Defaults are generous for a rendezvous (a
// room is small and short-lived) but finite. Env vars seed the defaults;
// matching CLI flags override them.
let MAX_CONNECTIONS    = num(process.env.RELAY_MAX_CONNS,        1024);
let MAX_ROOMS          = num(process.env.RELAY_MAX_ROOMS,         512);
let MAX_CONNS_PER_ROOM = num(process.env.RELAY_MAX_PER_ROOM,       64);
let MAX_CONNS_PER_IP   = num(process.env.RELAY_MAX_PER_IP,         64);
let MAX_PER_ROOM_IP    = num(process.env.RELAY_MAX_PER_ROOM_IP,    16);
let SPLICE_RATE        = num(process.env.RELAY_SPLICE_RATE,      1024);
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
  else if (a === "--max-per-room-ip") { MAX_PER_ROOM_IP = num(args[++i], MAX_PER_ROOM_IP); }
  else if (a === "--splice-rate") { SPLICE_RATE = num(args[++i], SPLICE_RATE); }
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
// A control frame is a registration, a call or a membership list: a few KB at
// most. Splice frames are not measured, since the relay streams them through
// without holding one whole.
const MAX_FRAME_PAYLOAD = 64 * 1024;
// Every write to a control socket, including control frames, shares the same
// hard backlog cap.
const MAX_SOCKET_BACKLOG = 256 * 1024;
// From the TCP connection to the upgrade, and from the upgrade to registration.
const HANDSHAKE_TIMEOUT_MS = 10_000;
// How long a ticket waits for both of its splice sockets.
const SPLICE_WAIT_MS = 10_000;

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

// ─── the relay wire ────────────────────────────────────────────────────────
//
// Control sockets carry binary frames whose first byte is the type. Keys are
// 32-byte seedkernel identities, tickets 16 random bytes chosen by the caller.
//
//   relay → node                                  node → relay
//   0x00 challenge   [nonce 32]                   0x01 register  [pk 32][sig 64]
//   0x01 registered                               0x05 call      [to 32][ticket 16]
//   0x02 members     [pk 32]*  (the room, once)
//   0x03 joined      [pk 32]
//   0x04 left        [pk 32]
//   0x05 incoming    [from 32][ticket 16]
//   0x06 unreachable [to 32][ticket 16]
const T_CHALLENGE = 0x00, T_REGISTER = 0x01, T_MEMBERS = 0x02, T_JOINED = 0x03,
  T_LEFT = 0x04, T_CALL = 0x05, T_UNREACHABLE = 0x06;
const PK_LEN = 32, SIG_LEN = 64, NONCE_LEN = 32, TICKET_LEN = 16;

// A registration is an Ed25519 signature by the node's identity key over
//   DOMAIN_link_scope ‖ DOMAIN_relay ‖ authority ‖ nonce
// where DOMAIN_link_scope is the prefix seedkernel's host applies to everything
// its transport signs, DOMAIN_relay the transport's tag for this format, and
// authority the relay's host[:port] as the node dialed it (`canonicalAuthority`).
// The fresh nonce makes each signature good once, and the authority stops one
// relay from passing another relay's nonce through to register as its client.
const DOMAIN_LINK_SCOPE = Buffer.from("seedkernel-link-scope-v1\0");
const DOMAIN_RELAY = Buffer.from("seedkernel-relay-register-v1\0");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");

/** Lowercase, without a default port, so the Host a browser sends for
 *  wss://relay.example matches the relay.example:443 a node dials. */
function canonicalAuthority(host) {
  return host.toLowerCase().replace(/:(?:80|443)$/, "");
}

function registerMessage(authority, nonce) {
  return Buffer.concat([DOMAIN_LINK_SCOPE, DOMAIN_RELAY, Buffer.from(authority), nonce]);
}

function verifyRegistration(pk, sig, authority, nonce) {
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, pk]), format: "der", type: "spki" });
    return verify(null, registerMessage(authority, nonce), key, sig);
  } catch {
    return false;
  }
}

const typed = (type, ...parts) => encodeFrame(0x2, Buffer.concat([Buffer.of(type), ...parts]));

// ─── rooms and keys ──────────────────────────────────────────────────────
//
// Rooms are looked up by name in a single Map<string, Set<sock>>. A control
// socket joins at most one room for its lifetime; teardown removes it from that
// room and drops the room entry when it goes empty so the table doesn't grow
// without bound. A room's members are the distinct keys registered in it, so a
// node on two sockets is one member.
//
// Room names are restricted to URL-safe characters and a length cap so the
// upgrade path can never be used to allocate giant strings or smuggle
// control characters into log lines.
const MAX_ROOM_NAME = 128;
const ROOM_NAME_RE = /^[A-Za-z0-9._-]+$/;

const rooms = new Map();
// Registered key (hex) to the control socket calls for it are routed to: the
// latest registration.
const registered = new Map();

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

/** Whether a registered socket other than `sock` in `set` holds `key`. */
function keyInRoom(set, key, sock) {
  for (const s of set) if (s !== sock && s._relayKey === key) return true;
  return false;
}

/** The distinct keys registered in `set`, less `key`. */
function roomKeys(set, key) {
  const keys = new Set();
  for (const s of set) if (s._relayKey && s._relayKey !== key) keys.add(s._relayKey);
  return [...keys];
}

/** A registered socket's key joins its room: it gets the members, they get it.
 *  The fan-out is charged to the room and the relay's egress, and a room that
 *  cannot afford it drops the joiner. */
function announceJoin(sock) {
  const set = rooms.get(sock._relayRoom);
  if (!set) return true;
  const key = sock._relayKey;
  if (!writeFrame(sock, typed(T_MEMBERS, ...roomKeys(set, key).map((k) => Buffer.from(k, "hex"))))) return false;
  if (keyInRoom(set, key, sock)) return true;
  const out = typed(T_JOINED, Buffer.from(key, "hex"));
  const recipients = [...set].filter((s) => s !== sock && s._relayKey && s._relayKey !== key);
  if (!spend(set.bytes, out.length * recipients.length) || !spend(set.frames, recipients.length) ||
      !spend(outgoingBytes, out.length * recipients.length) || !spend(outgoingFrames, recipients.length)) {
    sock.destroy();
    return false;
  }
  for (const s of recipients) writeFrame(s, out);
  return true;
}

/** The last socket holding a key left a room: tell the rest. Each follows a
 *  `joined` that was charged, so it is not charged again. */
function announceLeave(name, key) {
  const set = rooms.get(name);
  if (!set || keyInRoom(set, key, null)) return;
  const out = typed(T_LEFT, Buffer.from(key, "hex"));
  for (const s of set) if (s._relayKey && s._relayKey !== key) writeFrame(s, out);
}

/** A registered socket closed: route its key to another live registration, if any. */
function unregister(sock) {
  const key = sock._relayKey;
  if (!key || registered.get(key) !== sock) return;
  registered.delete(key);
  for (const s of sockets) {
    if (s !== sock && s._relayKey === key && !s.destroyed) registered.set(key, s);
  }
}

// ─── splices ─────────────────────────────────────────────────────────────
//
// A call creates its ticket in `pending`, where it waits for both of its
// sockets and is joined once they are there. It expires unjoined after
// SPLICE_WAIT_MS. Waiting calls are charged to the caller's address, not to a
// table everyone shares: as many as a room has seats, enough to call a whole
// room at once, and at most MAX_CALLS_PER_CALLEE for any one key, since every
// call makes its callee open a socket here. A joined splice holds two sockets,
// which the socket caps bound.
const MAX_CALLS_PER_CALLEE = 8;
const pending = new Map();
const callsFrom = new Map(); // caller address to its calls waiting
const callsTo = new Map();   // caller address and callee key to the calls waiting between them

function bump(map, key, by) {
  const n = (map.get(key) ?? 0) + by;
  if (n > 0) map.set(key, n); else map.delete(key);
}

function pendingSplice(ticket, caller, callee) {
  const from = caller._relayIp, pair = `${from} ${callee}`;
  if (pending.has(ticket) || (callsFrom.get(from) ?? 0) >= MAX_CONNS_PER_ROOM ||
      (callsTo.get(pair) ?? 0) >= MAX_CALLS_PER_CALLEE) return null;
  const s = { ticket, from, pair, socks: [], timer: null };
  s.timer = setTimeout(() => expireSplice(s), SPLICE_WAIT_MS);
  s.timer.unref?.();
  bump(callsFrom, from, 1);
  bump(callsTo, pair, 1);
  pending.set(ticket, s);
  return s;
}

function settleSplice(s) {
  pending.delete(s.ticket);
  clearTimeout(s.timer);
  bump(callsFrom, s.from, -1);
  bump(callsTo, s.pair, -1);
}

function expireSplice(s) {
  if (pending.get(s.ticket) !== s) return;
  settleSplice(s);
  for (const sock of s.socks) sock.destroy();
}

/** End a socket gracefully, so what is queued for it still goes out, and give up
 *  on the far end after SPLICE_WAIT_MS. */
function endSoon(sock) {
  sock.end();
  const t = setTimeout(() => sock.destroy(), SPLICE_WAIT_MS);
  t.unref?.();
}

function tryJoin(s) {
  if (s.socks.length !== 2) return;
  settleSplice(s);
  const [a, b] = s.socks;
  a._relayPeer = b;
  b._relayPeer = a;
  for (const [src, dst] of [[a, b], [b, a]]) {
    const forward = spliceForwarder(src, dst);
    const take = (chunk) => { src._relayAlive = true; forward(chunk); meter(src, chunk.length); };
    src._relayHolds = 1;         // paused since its upgrade
    src.on("data", take);
    if (src._relayHead?.length) take(src._relayHead);
    src._relayHead = null;
    release(src);
  }
}

/** A splice socket is read only while nothing holds it: a far end that is full,
 *  or its address past its traffic budget. */
function hold(sock) { if (sock._relayHolds++ === 0) sock.pause(); }
function release(sock) { if (--sock._relayHolds === 0) sock.resume(); }

// What an address sends through its splices is metered, SPLICE_RATE KiB/s with
// two seconds of burst. Past it, the address's splice sockets are not read until
// the debt is paid back, so a sender is slowed, not cut off.
const spliceBudgets = new Map(); // client address to its bucket

function meter(sock, n) {
  if (SPLICE_RATE === 0) return;
  let b = spliceBudgets.get(sock._relayIp);
  if (!b) spliceBudgets.set(sock._relayIp, b = bucket(SPLICE_RATE * 1024));
  spend(b, 0);
  b.tokens -= n;
  if (b.tokens >= 0 || sock._relayMetered) return;
  sock._relayMetered = true;
  hold(sock);
  const t = setTimeout(() => { sock._relayMetered = false; release(sock); }, -b.tokens * 1000 / b.rate);
  t.unref?.();
}

/** An address with no sockets left keeps its budget until it has refilled, so
 *  reconnecting buys no fresh burst. */
function retireBudget(ip) {
  const b = spliceBudgets.get(ip);
  if (!b) return;
  spend(b, 0);
  const t = setTimeout(() => {
    spend(b, 0);
    if (!ipCounts.has(ip) && b.tokens >= b.burst) spliceBudgets.delete(ip);
  }, (b.burst - b.tokens) * 1000 / b.rate);
  t.unref?.();
}

/** Copies one splice socket's masked client frames to the other end as server
 *  frames, streaming: a frame's header goes out as soon as it is parsed and its
 *  payload as it arrives, so the relay holds a chunk, never a whole message.
 *  Control frames stay on the hop: a ping is answered, a close ends both ends
 *  once forwarded. Backpressure pauses the reading side. */
function spliceForwarder(src, dst) {
  const head = Buffer.alloc(14);
  let have = 0, need = 2;        // header bytes held, and wanted
  let remaining = -1;            // payload bytes left; -1 while in a header
  let mask = null, maskAt = 0, opcode = 0, control = null;

  const put = (bytes) => {
    if (dst.destroyed || !dst.writable) return;
    if (!dst.write(bytes) && !src._relayWaiting) {
      src._relayWaiting = true;
      hold(src);
      dst.once("drain", () => { src._relayWaiting = false; release(src); });
    }
  };
  const fail = () => { src.destroy(); dst.destroy(); };

  function parseHead() {
    const b0 = head[0], b1 = head[1];
    opcode = b0 & 0x0f;
    if ((b0 & 0x70) !== 0 || (b1 & 0x80) === 0 || ![0, 1, 2, 8, 9, 10].includes(opcode)) return false;
    let len = b1 & 0x7f, ext = 0;
    if (len === 126) { ext = 2; len = head.readUInt16BE(2); }
    else if (len === 127) {
      ext = 8;
      const big = head.readBigUInt64BE(2);
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) return false;
      len = Number(big);
    }
    if (opcode >= 8 && ((b0 & 0x80) === 0 || len > 125)) return false;
    mask = Buffer.from(head.subarray(2 + ext, 6 + ext));
    maskAt = 0;
    remaining = len;
    if (opcode >= 8) control = { bytes: Buffer.alloc(len), at: 0 };
    else {
      put(frameHead(b0, len));
      dst._relayMid = len > 0;
    }
    return true;
  }

  function endFrame() {
    remaining = -1; have = 0; need = 2;
    if (!control) { dst._relayMid = false; return; }
    const payload = control.bytes;
    control = null;
    if (opcode === 0x9 && !src._relayMid) writeFrame(src, encodeFrame(0xA, payload));
    else if (opcode === 0xA) src._relayAlive = true;
    else if (opcode === 0x8) {
      if (!dst._relayMid) put(encodeFrame(0x8, payload));
      endSoon(src); endSoon(dst);
    }
  }

  return (chunk) => {
    let off = 0;
    while (off < chunk.length) {
      if (remaining < 0) {
        const take = Math.min(need - have, chunk.length - off);
        chunk.copy(head, have, off, off + take);
        have += take; off += take;
        if (have < need) continue;
        if (need === 2) {
          const len = head[1] & 0x7f;
          need = 2 + (len === 126 ? 2 : len === 127 ? 8 : 0) + 4;
          if (have < need) continue;
        }
        if (!parseHead()) { fail(); return; }
        if (remaining === 0) endFrame();
        continue;
      }
      const n = Math.min(remaining, chunk.length - off);
      const piece = chunk.subarray(off, off + n);
      for (let i = 0; i < n; i++) piece[i] ^= mask[(maskAt + i) & 3];
      maskAt += n; off += n; remaining -= n;
      if (control) { piece.copy(control.bytes, control.at); control.at += n; }
      else put(piece);
      if (remaining === 0) endFrame();
    }
  };
}

// Pull the target out of the upgrade request. Accepts:
//   /                  → a control socket in no room
//   /foo               → a control socket in room "foo"
//   /?splice=<32 hex>  → a splice socket (the path is ignored)
// Returns null when the path is present but malformed (too long, illegal
// characters) so the caller can 400 the upgrade.
function targetFromRequest(req) {
  const url = typeof req.url === "string" ? req.url : "/";
  const q = url.indexOf("?");
  const query = q < 0 ? "" : url.slice(q + 1).split("#", 1)[0];
  const ticket = /(?:^|&)splice=([0-9a-f]{32})(?:&|$)/.exec(query);
  if (ticket) return { room: "", splice: ticket[1] };
  if (/(?:^|&)splice=/.test(query)) return null;
  const path = url.split(/[?#]/, 1)[0];
  const raw = path.startsWith("/") ? path.slice(1) : path;
  if (raw === "") return { room: "", splice: null };
  if (raw.length > MAX_ROOM_NAME) return null;
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch { return null; }
  if (!ROOM_NAME_RE.test(decoded)) return null;
  return { room: decoded, splice: null };
}

// ─── connection tracking ───────────────────────────────────────────────────
//
// `sockets` is every live upgraded socket, for heartbeat sweeps. `ipCounts`
// tracks upgraded client addresses; `connections` and `addressCounts` include
// all accepted TCP sockets. Entries are deleted when their counts reach zero.
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
  res.end("seedkernel relay: connect with ws://<host>:<port>/<room>\n");
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
  // native clients (a seedkernel node, `websocat`, `wscat`); we accept those.
  const originStr = typeof origin === "string" ? origin : "";
  if (originStr && !ALLOWED_ORIGINS.has(originStr)) {
    sock.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    sock.destroy();
    console.log("! rejected upgrade: origin not allowed");
    return;
  }

  const target = targetFromRequest(req);
  const host = req.headers.host;
  if (target === null || (target.splice === null && typeof host !== "string")) {
    sock.write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
    sock.destroy();
    console.log("! rejected upgrade: bad path");
    return;
  }
  const { room, splice } = target;

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
  const existingRoom = room ? rooms.get(room) : null;
  if (room && !existingRoom && rooms.size >= MAX_ROOMS) {
    refuse(sock, 429, "Too Many Requests", `room table full (${rooms.size} rooms)`);
    return;
  }
  if ((existingRoom?.size ?? 0) >= MAX_CONNS_PER_ROOM) {
    refuse(sock, 429, "Too Many Requests", "room full");
    return;
  }
  // One address takes a few seats, not the room.
  if (existingRoom && [...existingRoom].filter((s) => s._relayIp === ip).length >= MAX_PER_ROOM_IP) {
    refuse(sock, 429, "Too Many Requests", "per-ip room cap");
    return;
  }
  // A splice socket needs a ticket its caller has already called.
  const waiting = splice === null ? null : pending.get(splice);
  if (splice !== null && !waiting) { refuse(sock, 404, "Not Found", "no such splice"); return; }
  if (waiting && waiting.socks.length >= 2) { refuse(sock, 409, "Conflict", "splice already has both ends"); return; }

  const accept = createHash("sha1").update(key + GUID).digest("base64");
  sock.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );

  clearTimeout(sock._relayHandshakeTimer);
  sock._relayIp = ip;
  sock._relayAlive = true;                // cleared each heartbeat, set on pong
  sockets.add(sock);
  ipCounts.set(ip, (ipCounts.get(ip) ?? 0) + 1);

  let dropped = false;
  const drop = () => {
    if (dropped) return;
    dropped = true;
    sockets.delete(sock);
    const ipKey = sock._relayIp;
    const n = (ipCounts.get(ipKey) ?? 0) - 1;
    if (n > 0) ipCounts.set(ipKey, n); else { ipCounts.delete(ipKey); retireBudget(ipKey); }
    if (waiting) {
      const peer = sock._relayPeer;
      if (peer) {
        if (peer._relayPeer === sock) { peer._relayPeer = null; endSoon(peer); }
      } else {
        const i = waiting.socks.indexOf(sock);
        if (i >= 0) waiting.socks.splice(i, 1);
      }
      return;
    }
    clearTimeout(sock._relayRegisterTimer);
    unregister(sock);
    const r = sock._relayRoom;
    if (r) {
      const remaining = leaveRoom(r, sock);
      if (sock._relayKey) announceLeave(r, sock._relayKey);
      console.log(`- client (${remaining} in room, ${rooms.size} rooms, ${sockets.size} total)`);
    }
  };
  sock.on("close", drop);
  sock.on("error", drop);

  // A splice socket reads nothing until its ticket is joined; what came with the
  // upgrade is kept for then.
  if (waiting) {
    sock._relaySplice = true;
    sock._relayHead = head?.length ? Buffer.from(head) : null;
    sock.pause();
    waiting.socks.push(sock);
    tryJoin(waiting);
    return;
  }

  if (room) sock._relayRoom = room;
  const roomSet = room ? joinRoom(room, sock) : null;
  const authority = canonicalAuthority(host);
  const nonce = randomBytes(NONCE_LEN);
  sock._relayRegisterTimer = setTimeout(() => sock.destroy(), HANDSHAKE_TIMEOUT_MS);
  sock._relayRegisterTimer.unref?.();
  writeFrame(sock, typed(T_CHALLENGE, nonce));
  console.log(`+ client (${roomSet ? roomSet.size : 0} in room, ${rooms.size} rooms, ${sockets.size} total)`);
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

      // Enforce FIN=1 (no fragmented frames). Control messages are small;
      // legitimate clients never need fragmentation.
      const fin = (header[0] & 0x80) !== 0;
      if (!fin || (header[0] & 0x70) !== 0) {
        console.log("! dropped: fragmentation or reserved frame bits");
        sock.destroy();
        return;
      }

      const opcode = header[0] & 0x0f;
      if (![2, 8, 9, 10].includes(opcode) ||
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
      // opcode, or an invalid frame), so we stop parsing what is buffered.
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
    const type = payload[0];
    if (type === T_REGISTER && payload.length === 1 + PK_LEN + SIG_LEN && !sock._relayKey) {
      const pk = payload.subarray(1, 1 + PK_LEN);
      if (!verifyRegistration(pk, payload.subarray(1 + PK_LEN), authority, nonce)) {
        console.log("! dropped: bad registration");
        sock.destroy();
        return false;
      }
      clearTimeout(sock._relayRegisterTimer);
      sock._relayKey = pk.toString("hex");
      registered.set(sock._relayKey, sock);
      if (!writeFrame(sock, typed(T_REGISTER))) return false;
      return announceJoin(sock);
    }
    if (type === T_CALL && payload.length === 1 + PK_LEN + TICKET_LEN && sock._relayKey) {
      const to = payload.subarray(1, 1 + PK_LEN);
      const ticket = payload.subarray(1 + PK_LEN);
      const callee = registered.get(to.toString("hex"));
      const s = callee && callee._relayKey !== sock._relayKey
        ? pendingSplice(ticket.toString("hex"), sock, callee._relayKey) : null;
      // No such key here, too many calls waiting from this address, or a ticket
      // already in use: the caller learns now instead of waiting its splice
      // socket out.
      if (!s) return writeFrame(sock, typed(T_UNREACHABLE, to, ticket));
      writeFrame(callee, typed(T_CALL, Buffer.from(sock._relayKey, "hex"), ticket));
      return true;
    }
    // Anything else, including a call before registering, is not this wire.
    console.log("! dropped: unexpected control frame");
    sock.destroy();
    return false;
  }

  // Node may deliver the first frame with the HTTP upgrade request.
  if (head?.length) onData(head);
});

/** A server→client frame header for a payload of `len` bytes, with the client
 *  frame's own FIN and opcode byte. */
function frameHead(b0, len) {
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
  header[0] = b0;
  return header;
}

// Encode a server→client frame (unmasked per RFC 6455).
function encodeFrame(opcode, payload) {
  return Buffer.concat([frameHead(0x80 | opcode, payload.length), payload]);
}

// ─── heartbeat / dead-socket reaping ──────────────────────────────────────
//
// NAT and firewall timeouts leave half-open sockets that never emit 'close',
// so without a liveness probe a dropped peer would hold its room/IP slot
// forever. Each interval we ping every socket; any socket that did not answer
// the previous ping with a pong (opcode 0xA, which sets _relayAlive back to
// true) is presumed dead and destroyed, firing its normal drop() cleanup. A
// splice socket also counts any bytes it sent as alive, and is pinged only
// between the frames forwarded to it, never inside one.
if (HEARTBEAT_MS > 0) {
  const PING = encodeFrame(0x9, Buffer.alloc(0));
  const beat = setInterval(() => {
    for (const sock of sockets) {
      if (sock._relaySplice && (!sock._relayPeer || sock._relayMid)) continue;
      if (sock._relayAlive === false) { sock.destroy(); continue; }
      sock._relayAlive = false;
      writeFrame(sock, PING);
    }
  }, HEARTBEAT_MS);
  beat.unref();  // a pending ping timer alone shouldn't keep the process alive
}

server.listen(PORT, HOST, () => {
  console.log(`seedrelay listening on ws://${HOST}:${server.address().port}/<room>`);
  console.log(`  origin allowlist: ${[...ALLOWED_ORIGINS].slice(0, 4).join(", ")}…`);
  console.log(`  control frame cap: ${MAX_FRAME_PAYLOAD} B  socket backlog cap: ${MAX_SOCKET_BACKLOG} B`);
  console.log(`  rooms: any path component (chars [A-Za-z0-9._-], up to ${MAX_ROOM_NAME}); bare "/" = no room`);
  console.log(`  limits: ${MAX_CONNECTIONS} conns, ${MAX_ROOMS} rooms, ${MAX_CONNS_PER_ROOM}/room, ${MAX_CONNS_PER_IP}/ip, ${MAX_PER_ROOM_IP}/ip in a room, splices ${SPLICE_RATE > 0 ? `${SPLICE_RATE} KiB/s per ip` : "unmetered"}${TRUST_PROXY ? " (X-Forwarded-For trusted)" : ""}`);
  console.log(`  heartbeat: ${HEARTBEAT_MS > 0 ? `${HEARTBEAT_MS / 1000}s ping/reap` : "disabled"}`);
  if (HOST !== "127.0.0.1" && HOST !== "localhost" && HOST !== "::1") {
    console.log(`  ⚠  bound to ${HOST} — exposed to the network`);
  }
});
