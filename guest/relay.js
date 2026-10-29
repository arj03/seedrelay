// The relay as a seedkernel bundle: the guest of a node whose link occupant it is, so the
// host's sockets, listeners and datagram sockets are its own (seedkernel §12.1, §12.7).
// A node registers its key here over a control socket, its app meets other keys in rooms,
// and the node reaches any registered key through a splice: two fresh sockets the relay
// joins, copying frames between them. The seedkernel channel handshake runs end to end
// through a splice, so the relay forwards ciphertext it cannot read, and cannot pose as
// either end.
//
// Sockets, by upgrade path. The first segment names the wire version, and any other path
// is refused, so a relay and a node never guess at each other's wire:
//
//   ws://host:port/v1/                a control socket: a node's transport, reachable by key
//   ws://host:port/v1/rooms           a room socket: an app, meeting others in rooms
//   ws://host:port/v1/?splice=<hex>   one end of a splice, named by a 16-byte ticket
//
// Both kinds must register before anything else: the relay sends a nonce, and the key
// holder signs it for the name it dialed, which must be one this relay answers to. Both
// signatures are under the host's link scope, which `node/verify` checks here, each under
// a tag of its own, so neither kind can stand for the other. The relay routes calls to the
// control socket that registered a key most recently. Rooms are discovery only, named by
// 32-byte ids; a room id is a bearer credential for learning who is there.
//
// A call hands each end a ticket, and the relay joins the two splice sockets that bring
// them. What splices carry is metered per client address, and both ends are charged to
// the caller's address, which placed the call.
//
// This program reads its settings from `APP` (the signed defaults) and `LOCAL` (the
// operator's), takes the host's raw-link events, and answers the host-only ops `start`
// and `close` on its local service id. The op-frame prelude (callerOf, readOp, utf8Encode,
// utf8Decode) is injected at the marker at the end.

"use strict";

// ─── bytes ───────────────────────────────────────────────────────────────

const EMPTY = new Uint8Array(0);

function concatBytes(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
const of = (...bytes) => Uint8Array.from(bytes);
function u32(v) {
  return of(v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
}
const readU16 = (b, at) => (b[at] << 8) | b[at + 1];
const readU32 = (b, at) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const HEX = Array.from({ length: 256 }, (_, i) => (i < 16 ? "0" : "") + i.toString(16));
function toHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += HEX[b[i]];
  return s;
}
function fromHex(s) {
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
  return out;
}
/** Bytes as text one character each, as HTTP heads are read. */
function latin1(b) {
  let s = "";
  for (let i = 0; i < b.length; i += 4096) s += String.fromCharCode.apply(null, b.subarray(i, i + 4096));
  return s;
}
/** Whether two byte strings are equal, in time that depends on their length only. */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ─── the host ────────────────────────────────────────────────────────────

const N_SEND = "link/send", N_PAUSE = "link/pause", N_CLOSE = "link/close", N_STATUS = "link/status";
const N_UDP_BIND = "link/udpBind", N_UDP_SEND = "link/udpSend";
const N_TIMER_ARM = "timer/arm", N_VERIFY = "node/verify", N_HASH = "crypto/blake2b", N_RANDOM = "crypto/random";
/** This bundle's RFC 6455 module (seedkernel's ws.wasm): masking, and the accept value. */
const N_WS = "ws", WS_OP_MASK = 1, WS_OP_ACCEPT = 2;

/** What a link still holds for the wire, after writing `bytes` to it (none only asks). */
function linkSend(id, bytes) {
  return host.call(N_SEND, concatBytes([u32(id), bytes])).then((r) => readU32(r, 0), () => 0);
}
function linkPause(id, paused) { void host.call(N_PAUSE, concatBytes([u32(id), of(paused ? 1 : 0)])).catch(() => {}); }
function linkClose(id, graceful) { void host.call(N_CLOSE, concatBytes([u32(id), of(graceful ? 1 : 0)])).catch(() => {}); }
/** One line for the operator: the host prints a status that starts with a printable byte
 *  as it is. Never a key, a room or anything a client sent. */
function log(line) { void host.call(N_STATUS, utf8Encode(line)).catch(() => {}); }

/** Host entropy, drawn a block at a time. */
let pool = EMPTY, poolAt = 0;
async function random(n) {
  if (poolAt + n > pool.length) {
    pool = await host.call(N_RANDOM, u32(4096));
    poolAt = 0;
  }
  poolAt += n;
  return pool.slice(poolAt - n, poolAt);
}

// ─── time ────────────────────────────────────────────────────────────────
//
// One wake per realm: every deadline sits in this heap, and the wake is armed for the
// soonest. A cancelled timer stays in the heap, inert, until its time comes.

const now = () => performance.now();
const timers = [];
let armedAt = Infinity, waking = false;

function later(ms, fn) {
  const t = { at: now() + ms, fn };
  let i = timers.length;
  timers.push(t);
  while (i > 0) {
    const p = (i - 1) >> 1;
    if (timers[p].at <= t.at) break;
    timers[i] = timers[p];
    i = p;
  }
  timers[i] = t;
  if (!waking && t.at < armedAt) arm(t.at);
  return t;
}
function cancel(t) { if (t) t.fn = null; }
function every(ms, fn) { later(ms, () => { fn(); every(ms, fn); }); }

function popTimer() {
  const top = timers[0], last = timers.pop();
  if (timers.length > 0) {
    let i = 0;
    for (;;) {
      let c = 2 * i + 1;
      if (c >= timers.length) break;
      if (c + 1 < timers.length && timers[c + 1].at < timers[c].at) c++;
      if (timers[c].at >= last.at) break;
      timers[i] = timers[c];
      i = c;
    }
    timers[i] = last;
  }
  return top;
}

function arm(at) {
  armedAt = at;
  const ms = Math.min(0x7fffffff, Math.max(0, Math.ceil(at - now())));
  try { void host.call(N_TIMER_ARM, u32(ms)).catch(() => { armedAt = Infinity; }); } catch { armedAt = Infinity; }
}

function onWake() {
  armedAt = Infinity;
  waking = true;
  try {
    const t = now();
    while (timers.length > 0 && timers[0].at <= t) {
      const x = popTimer();
      const fn = x.fn;
      x.fn = null;
      if (fn) fn();
    }
  } finally {
    waking = false;
  }
  while (timers.length > 0 && !timers[0].fn) popTimer();
  if (timers.length > 0) arm(timers[0].at);
}

// Token buckets bound sustained traffic as well as bursts, with two seconds of burst
// unless told otherwise.
class Bucket {
  constructor(rate, burst = rate * 2) {
    this.rate = rate;
    this.burst = burst;
    this.tokens = burst;
    this.at = now();
  }

  refill() {
    const t = now();
    this.tokens = Math.min(this.burst, this.tokens + (t - this.at) * this.rate / 1000);
    this.at = t;
    return this.tokens;
  }

  /** Take `n` if there are that many. */
  spend(n) {
    if (n > this.refill()) return false;
    this.tokens -= n;
    return true;
  }

  /** Take `n` whatever is left, into debt if need be. */
  charge(n) {
    this.refill();
    this.tokens -= n;
  }
}

/** Buckets by client address. A bucket is forgotten once it has refilled, since a full
 *  bucket is what a new address gets anyway, so reconnecting buys no fresh burst. */
class AddressBudgets {
  constructor(rate, burst = rate * 2) {
    this.rate = rate;
    this.burst = burst;
    this.map = new Map();
  }

  has(addr) { return this.map.has(addr); }

  get(addr) {
    let b = this.map.get(addr);
    if (!b) {
      this.map.set(addr, b = new Bucket(this.rate, this.burst));
      this.retire(addr, b);
    }
    return b;
  }

  retire(addr, b) {
    later(Math.max(1000, (b.burst - b.refill()) * 1000 / b.rate), () => {
      if (b.refill() >= b.burst) this.map.delete(addr);
      else this.retire(addr, b);
    });
  }
}

function bump(map, key, by) {
  const n = (map.get(key) ?? 0) + by;
  if (n > 0) map.set(key, n); else map.delete(key);
}

// ─── addresses ───────────────────────────────────────────────────────────

/** An IPv4 address's four bytes, or null. */
function ipv4Bytes(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const b = m.slice(1).map(Number);
  return m.slice(1).every((p, i) => b[i] <= 255 && (p.length === 1 || p[0] !== "0")) ? Uint8Array.from(b) : null;
}

/** An IP address's bytes, four for IPv4 and sixteen for IPv6, or null for anything else,
 *  scoped IPv6 included, which is neither a URL host nor a portable forwarded address. */
function ipBytes(s) {
  if (!s.includes(":")) return ipv4Bytes(s);
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groups = halves.map((h) => (h === "" ? [] : h.split(":")));
  // An IPv4 tail, last of all, counts as two groups.
  const last = groups[groups.length - 1];
  const tail = last.length > 0 && last[last.length - 1].includes(".") ? ipv4Bytes(last.pop()) : undefined;
  if (tail === null) return null;
  const hex = groups.flat();
  if (!hex.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  const count = hex.length + (tail ? 2 : 0);
  if (halves.length === 2 ? count > 7 : count !== 8) return null;
  const words = hex.map((g) => parseInt(g, 16));
  if (tail) words.push((tail[0] << 8) | tail[1], (tail[2] << 8) | tail[3]);
  const fill = 8 - words.length, at = halves.length === 2 ? groups[0].length : 0;
  words.splice(at, 0, ...new Array(fill).fill(0));
  const out = new Uint8Array(16);
  words.forEach((w, i) => { out[2 * i] = w >> 8; out[2 * i + 1] = w & 255; });
  return out;
}

/** An address in one spelling: IPv4 dotted, IPv4-mapped IPv6 as IPv4, other IPv6 as RFC
 *  5952 writes it, which is how a URL host compresses it. */
function ipText(b) {
  if (b.length === 4) return b.join(".");
  if (b.subarray(0, 10).every((x) => x === 0) && b[10] === 255 && b[11] === 255) return b.subarray(12).join(".");
  const g = [];
  let run = -1, runLen = 1;
  for (let i = 0, zeros = 0; i < 8; i++) {
    const v = readU16(b, 2 * i);
    g.push(v.toString(16));
    zeros = v === 0 ? zeros + 1 : 0;
    if (zeros > runLen) { run = i - zeros + 1; runLen = zeros; }
  }
  return run < 0 ? g.join(":") : `${g.slice(0, run).join(":")}::${g.slice(run + runLen).join(":")}`;
}

function normalizeIp(s) {
  const b = typeof s === "string" ? ipBytes(s) : null;
  return b ? ipText(b) : null;
}

/** The client an address is accounted as: an IPv4 address itself, an IPv6 address its
 *  first `prefix` bits, since one host is routinely handed a whole /64 and would
 *  otherwise get a fresh set of limits from every address in it. */
function addressKey(ip, prefix) {
  if (!ip.includes(":")) return ip;
  const b = ipBytes(ip), groups = [];
  for (let i = 0; i < 8; i++) {
    const bits = Math.min(16, Math.max(0, prefix - 16 * i));
    groups.push((readU16(b, 2 * i) & (0xffff << (16 - bits)) & 0xffff).toString(16));
  }
  return groups.join(":") + "/" + prefix;
}

/** Lowercase, without a default port, so the Host a browser sends for
 *  wss://relay.example matches the relay.example:443 a node dials. */
function canonicalAuthority(host) {
  return host.toLowerCase().replace(/:(?:80|443)$/, "");
}

// ─── settings ────────────────────────────────────────────────────────────

/** A setting: the operator's, else the signed default. */
const setting = (name) => (Object.prototype.hasOwnProperty.call(LOCAL, name) ? LOCAL[name] : APP[name]);
function strings(name) {
  const v = setting(name) ?? [];
  if (!Array.isArray(v) || v.some((s) => typeof s !== "string")) throw new Error(`relay: config ${name} must be an array of strings`);
  return v;
}
const limits = { ...APP.limits, ...LOCAL.limits };
for (const [name, v] of Object.entries(limits)) {
  if (typeof v !== "number" || !(v >= 0) || v === Infinity) throw new Error(`relay: config limits.${name} must be a non-negative number`);
}
const authorities = new Set(strings("authorities").map(canonicalAuthority));
const origins = new Set(strings("allowOrigins"));
const proxies = new Set(strings("trustedProxies").map((ip) => {
  const n = normalizeIp(ip);
  if (!n) throw new Error(`relay: config trustedProxies has ${JSON.stringify(ip)}, not an IP address`);
  return n;
}));
const secrets = strings("secrets").map((s) => utf8Encode(s));
/** The first of the two UDP ports STUN is answered on; 0 lets the OS pick both, and null
 *  answers none. */
const stunPort = setting("stun");
if (stunPort !== null && !(Number.isInteger(stunPort) && stunPort >= 0 && stunPort <= 65534)) {
  throw new Error("relay: config stun must be a port from 0 to 65534, or null");
}

// ─── safety limits ───────────────────────────────────────────────────────
//
// A client sends a registration (97 bytes, 161 with a secret's MAC), a call (49) or a join
// or leave (33): a frame past this is not the wire. Splice frames are not measured, since
// the relay streams them through without holding one whole.
const MAX_CONTROL_PAYLOAD = 256;
// Every write to a control or room socket, including control frames, shares the same
// hard backlog cap.
const MAX_SOCKET_BACKLOG = 256 * 1024;
// From the TCP connection to the upgrade, and from the upgrade to registration.
const HANDSHAKE_TIMEOUT_MS = 10_000;
// How long a call waits for both of its splice sockets.
const SPLICE_WAIT_MS = 10_000;
// How long a sender may stay paused on a far end that does not drain. A paused socket is
// not pinged, since it cannot read the pong, so this is what reaps a dead receiver.
const SPLICE_HOLD_MS = 2 * 60_000;
// A far end holding more than this pauses its sender, which reads again once the far end
// is down to SPLICE_LOW, as the relay sees by asking every DRAIN_POLL_MS.
const SPLICE_HIGH = 64 * 1024, SPLICE_LOW = 16 * 1024, DRAIN_POLL_MS = 20;
// Splice sockets may take this share of maxConns and no more, so a relay busy with
// splices still has room for nodes to register.
const SPLICE_SHARE = 7 / 8;
// The close code the relay sends when it is going away: it is restarting.
const CLOSE_RESTART = 1012;
// An upgrade request's head past this is refused, as Node's HTTP server refuses one.
const MAX_HEAD_BYTES = 16 * 1024;
// A masked payload shorter than this is unmasked here; a longer one by the ws module.
const UNMASK_HERE_BELOW = 128;

const REFUSALS = { 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 409: "Conflict",
  421: "Misdirected Request", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
  503: "Service Unavailable" };

// ─── STUN ────────────────────────────────────────────────────────────────
//
// WebRTC and the seedkernel transport's UDP path connect two nodes behind NAT only once
// each has learned the address the internet sees it at, from a STUN Binding request
// (RFC 8489). The relay answers those on two UDP ports, and a transport asks the relay a
// peer is linked through, so nodes need no third-party STUN server. It answers Binding
// requests and nothing else, at most STUN_RATE a second to one address, and takes at most
// STUN_NEW_RATE new addresses a second, since UDP sources are easy to forge.
const STUN_COOKIE = 0x2112a442, STUN_RATE = 20, STUN_NEW_RATE = 256;

/** The Binding success response to a STUN Binding request from address bytes `ip` and
 *  `port`, carrying its XOR-MAPPED-ADDRESS; null for anything else. */
function stunResponse(msg, ip, port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (msg.length < 20 || msg.length % 4 !== 0 || readU16(msg, 0) !== 0x0001 ||
      readU16(msg, 2) !== msg.length - 20 || readU32(msg, 4) !== STUN_COOKIE) return null;
  const v6 = ip.length === 16;
  const out = new Uint8Array(28 + ip.length);
  out.set(of(0x01, 0x01, 0, 8 + ip.length), 0);
  out.set(msg.subarray(4, 20), 4);           // the cookie and transaction id
  out.set(of(0x00, 0x20, 0, 4 + ip.length, 0, v6 ? 2 : 1), 20); // XOR-MAPPED-ADDRESS
  const xport = port ^ (STUN_COOKIE >>> 16);
  out[26] = xport >> 8;
  out[27] = xport & 255;
  // The address XORed with the cookie, and for IPv6 the transaction id after it.
  for (let i = 0; i < ip.length; i++) out[28 + i] = ip[i] ^ out[4 + i];
  return out;
}

// ─── the relay wire ──────────────────────────────────────────────────────
//
// Both kinds of socket carry binary frames whose first byte is the type. Keys are 32-byte
// seedkernel identities, rooms 32-byte ids, tickets 16 random bytes.
//
//   relay → client                                client → relay
//   0x00 challenge   [nonce 32]                   0x01 register  [pk 32][sig 64][mac 64]?
//   0x01 registered
//
// then on a control socket                        on a room socket
//   0x05 incoming    [from 32][ticket 16]         0x02 join      [room 32]
//   0x06 unreachable [to 32][ticket 16]           0x03 leave     [room 32]
//   (node → relay 0x05 call [to 32][ticket 16])   0x02 members   [room 32][pk 32]*
//                                                 0x03 joined    [room 32][pk 32]
//                                                 0x04 left      [room 32][pk 32]
//                                                 0x07 refused   [room 32]
const T_CHALLENGE = 0x00, T_REGISTER = 0x01, T_MEMBERS = 0x02, T_JOINED = 0x03,
  T_LEFT = 0x04, T_CALL = 0x05, T_UNREACHABLE = 0x06, T_REFUSED = 0x07;
const T_JOIN = 0x02, T_LEAVE = 0x03;
const PK_LEN = 32, SIG_LEN = 64, MAC_LEN = 64, NONCE_LEN = 32, TICKET_LEN = 16, ROOM_LEN = 32;

// A registration is an Ed25519 signature by the node's identity key over
//   DOMAIN_link_scope ‖ DOMAIN_RELAY ‖ authority ‖ nonce     on a control socket
//   DOMAIN_link_scope ‖ DOMAIN_ROOMS ‖ authority ‖ nonce     on a room socket
// where DOMAIN_link_scope is the prefix seedkernel's host puts in front of everything its
// link occupant signs, and checks for it here through `node/verify`, so this program
// names only the tag after it. The authority is the relay's host[:port] as the client
// dialed it, and must be one of this relay's own names, never whatever Host a socket
// sends: otherwise relay A could take a nonce from relay B, have one of its visitors sign
// it for a.example, and present that to B as Host a.example.
const DOMAIN_RELAY = utf8Encode("seedkernel-relay-register-v1\0");
const DOMAIN_ROOMS = utf8Encode("seedrelay-rooms-v1\0");
// A relay with secrets takes a registration only with the MAC
//   BLAKE2b-512(DOMAIN_SECRET ‖ pk ‖ sig ‖ secret)
// after its signature, which binds it to the socket's nonce and key. BLAKE2b cannot be
// length-extended, so hashing the secret in makes a MAC.
const DOMAIN_SECRET = utf8Encode("seedrelay-secret-v1\0");

async function verifyRegistration(rooms, pk, sig, authority, nonce) {
  const r = await host.call(N_VERIFY, concatBytes([pk, sig, rooms ? DOMAIN_ROOMS : DOMAIN_RELAY, utf8Encode(authority), nonce]));
  return r[0] === 1;
}

/** Whether a registration's MAC shows it knows one of the secrets, if there are any. */
async function admits(pk, sig, mac) {
  if (secrets.length === 0) return true;
  if (mac.length !== MAC_LEN) return false;
  let known = false;
  for (const secret of secrets) {
    const proof = await host.call(N_HASH, concatBytes([of(64, 0), DOMAIN_SECRET, pk, sig, secret]));
    known = sameBytes(proof, mac) || known;
  }
  return known;
}

/** A server→client frame header for a payload of `len` bytes, with the client frame's own
 *  FIN and opcode byte. */
function frameHead(b0, len) {
  if (len < 126) return of(b0, len);
  if (len < 65536) return of(b0, 126, len >> 8, len & 255);
  return concatBytes([of(b0, 127), u32(Math.floor(len / 0x100000000)), u32(len >>> 0)]);
}

// Encode a server→client frame (unmasked per RFC 6455).
const encodeFrame = (opcode, payload) => concatBytes([frameHead(0x80 | opcode, payload.length), payload]);
const typed = (type, ...parts) => encodeFrame(0x2, concatBytes([of(type), ...parts]));
const closeFrame = (code) => encodeFrame(0x8, of(code >> 8, code & 255));
const PING = encodeFrame(0x9, EMPTY);

/** XOR `piece` in place under masking key bytes `key`, starting at key offset 0. */
function xorHere(piece, key) {
  for (let i = 0; i < piece.length; i++) piece[i] ^= key[i & 3];
  return piece;
}

/** Unmask a payload piece under `key`, already turned to its offset: here when it is
 *  short, by the ws module otherwise, as `[op][0x82][0x80][key][piece]`, a frame header
 *  whose length field the module does not read. */
async function unmask(piece, key) {
  if (piece.length < UNMASK_HERE_BELOW) return xorHere(piece, key);
  const req = new Uint8Array(7 + piece.length);
  req.set(of(WS_OP_MASK, 0x82, 0x80), 0);
  req.set(key, 3);
  req.set(piece, 7);
  return (await host.call(N_WS, req)).subarray(6);
}

// ─── client frames ───────────────────────────────────────────────────────
//
// Every socket reads client frames with one parser and one set of rules: RSV bits clear,
// a mask (RFC 6455 requires one from a client), lengths in their shortest encoding,
// control frames final and at most 125 bytes. A control or room socket takes whole binary
// frames up to MAX_CONTROL_PAYLOAD; a splice takes any data frame, fragments and all, of
// any size.
const CONTROL_FRAMES = { opcodes: [0x2, 0x8, 0x9, 0xA], whole: true, maxLen: MAX_CONTROL_PAYLOAD };
const SPLICE_FRAMES = { opcodes: [0x0, 0x1, 0x2, 0x8, 0x9, 0xA], whole: false, maxLen: Number.MAX_SAFE_INTEGER };

/** Reads masked client frames as they stream in, holding at most a header. A data frame
 *  comes out as `sink.head(b0, len)`, its payload in pieces, still masked, through
 *  `sink.data(piece, key)` with the key turned to the piece's offset, then `sink.end()`;
 *  a control frame whole and unmasked, through `sink.control(opcode, payload)`. A callback
 *  returning false stops the read. */
class FrameReader {
  constructor(sink, rules) {
    this.sink = sink;
    this.rules = rules;
    this.head = new Uint8Array(14);
    this.have = 0;           // header bytes held
    this.need = 2;           // header bytes wanted
    this.left = -1;          // payload bytes still to come; -1 while in a header
    this.mask = new Uint8Array(4);
    this.maskAt = 0;
    this.opcode = 0;
    this.control = null;     // a control frame's payload as it arrives
    this.controlAt = 0;
  }

  /** False when `chunk` breaks the rules, or a callback stopped the read. */
  push(chunk) {
    let off = 0;
    while (off < chunk.length) {
      if (this.left < 0) {
        const take = Math.min(this.need - this.have, chunk.length - off);
        this.head.set(chunk.subarray(off, off + take), this.have);
        this.have += take; off += take;
        if (this.have < this.need) continue;
        if (this.need === 2) {
          if (!this.checkStart()) return false;
          const len = this.head[1] & 0x7f;
          this.need = 6 + (len === 126 ? 2 : len === 127 ? 8 : 0);
          continue;
        }
        if (!this.parseHead()) return false;
        if (this.left === 0 && !this.endFrame()) return false;
        continue;
      }
      const n = Math.min(this.left, chunk.length - off);
      const piece = chunk.subarray(off, off + n), m = this.mask, a = this.maskAt;
      const key = of(m[a & 3], m[(a + 1) & 3], m[(a + 2) & 3], m[(a + 3) & 3]);
      this.maskAt += n; off += n; this.left -= n;
      if (this.control) { this.control.set(xorHere(piece, key), this.controlAt); this.controlAt += n; }
      else if (this.sink.data(piece, key) === false) return false;
      if (this.left === 0 && !this.endFrame()) return false;
    }
    return true;
  }

  /** What the first two bytes decide, checked before waiting for the rest. */
  checkStart() {
    const b0 = this.head[0], b1 = this.head[1], opcode = b0 & 0x0f, control = opcode >= 8;
    if ((b0 & 0x70) !== 0 || (b1 & 0x80) === 0 || !this.rules.opcodes.includes(opcode)) return false;
    return !((control || this.rules.whole) && (b0 & 0x80) === 0) && !(control && (b1 & 0x7f) > 125);
  }

  parseHead() {
    const b0 = this.head[0], opcode = b0 & 0x0f, control = opcode >= 8;
    let len = this.head[1] & 0x7f;
    if (len === 126) {
      len = readU16(this.head, 2);
      if (len < 126) return false;
    } else if (len === 127) {
      const hi = readU32(this.head, 2);
      len = hi * 0x100000000 + readU32(this.head, 6);
      if (len < 65536 || hi >= 0x200000) return false;
    }
    if (len > this.rules.maxLen) return false;
    this.mask.set(this.head.subarray(this.need - 4, this.need));
    this.maskAt = 0;
    this.opcode = opcode;
    this.left = len;
    if (control) {
      this.control = new Uint8Array(len);
      this.controlAt = 0;
      return true;
    }
    return this.sink.head(b0, len) !== false;
  }

  endFrame() {
    this.left = -1; this.have = 0; this.need = 2;
    if (!this.control) return this.sink.end() !== false;
    const payload = this.control;
    this.control = null;
    return this.sink.control(this.opcode, payload) !== false;
  }
}

// ─── sockets ─────────────────────────────────────────────────────────────
//
// Every link the host hands over, by its id: `{ id, ip, account, timer, conn, head,
// closed }`, the address it connects from, the address it is charged to (none for a
// trusted proxy before its client is known), its handshake deadline, its ControlConn or
// SpliceEnd once upgraded, the upgrade request read so far, and whether it is gone.
// `charges` counts sockets by address.
const conns = new Map();
const charges = new Map();

/** Write to a socket; one whose reader leaves more than the backlog cap unread is
 *  dropped. A splice pauses its sender long before (`SpliceEnd.forward`). */
function write(entry, bytes) {
  if (entry.closed) return;
  void linkSend(entry.id, bytes).then((backlog) => { if (backlog > MAX_SOCKET_BACKLOG) destroy(entry); });
}

/** A socket is done: tell the host, and forget it now. */
function shut(entry, graceful) {
  if (entry.closed) return;
  linkClose(entry.id, graceful);
  gone(entry);
}
const destroy = (entry) => shut(entry, false);
/** End a socket gracefully, so what is queued for it still goes out. */
const endSoon = (entry) => shut(entry, true);

function gone(entry) {
  if (entry.closed) return;
  entry.closed = true;
  cancel(entry.timer);
  conns.delete(entry.id);
  bill(entry, null);
  entry.conn?.onClose();
}

/** Move a socket's charge to `addr` (null for none). False, charging nothing, when that
 *  address already has its share. */
function bill(entry, addr) {
  if (entry.account === addr) return true;
  if (addr !== null && (charges.get(addr) ?? 0) >= limits.maxPerIp) return false;
  if (entry.account !== null) bump(charges, entry.account, -1);
  if (addr !== null) bump(charges, addr, 1);
  entry.account = addr;
  return true;
}

const addressOf = (ip) => addressKey(ip, limits.ipv6Prefix);

// ─── rooms ───────────────────────────────────────────────────────────────
//
// A registered room socket holds a seat in each room it joined, up to MAX_ROOMS_PER_CONN
// at once. A room's members are the distinct keys seated in it, so a key on two sockets
// is one member. A joiner is never turned away for what announcing it costs: an address
// joins rooms at the registration rate, after a burst of JOIN_BURST, which bounds how
// often it can make a room announce however it leaves and joins again.
const MAX_ROOMS_PER_CONN = 16;
// Two sockets' worth of rooms at once, so an app redialing a relay joins all of its
// rooms again, and a second tab too.
const JOIN_BURST = 2 * MAX_ROOMS_PER_CONN;
const rooms = new Map();

class Room {
  constructor(id) {
    this.id = id;              // hex
    this.idBytes = fromHex(id);
    this.conns = new Set();    // the room sockets seated here
  }

  seats(addr) {
    let n = 0;
    for (const c of this.conns) {
      if (c.addr === addr) n++;
    }
    return n;
  }

  holds(key) {
    for (const c of this.conns) {
      if (c.key === key) return true;
    }
    return false;
  }

  /** A socket takes its seat: it gets the room's other keys, and they get its key unless
   *  another socket already holds it here. */
  join(conn) {
    const known = new Map();
    let already = false;
    for (const c of this.conns) {
      if (c.key === conn.key) already = true; else known.set(c.key, c.pk);
    }
    this.conns.add(conn);
    conn.send(typed(T_MEMBERS, this.idBytes, ...known.values()));
    if (!already) this.tell(T_JOINED, conn);
  }

  /** A socket leaves; when it held the last seat for its key, the rest hear so. */
  leave(conn) {
    const seated = this.conns.delete(conn);
    if (this.conns.size === 0) rooms.delete(this.id);
    else if (seated && !this.holds(conn.key)) this.tell(T_LEFT, conn);
  }

  tell(type, conn) {
    const frame = typed(type, this.idBytes, conn.pk);
    for (const c of this.conns) {
      if (c.key !== conn.key) c.send(frame);
    }
  }
}

// ─── control and room sockets ────────────────────────────────────────────

const routes = new Map();     // key hex to its registered control sockets, the latest last

class ControlConn {
  constructor(entry, addr, authority, forRooms, nonce) {
    this.entry = entry;
    this.addr = addr;          // the client address, as accounted
    this.forRooms = forRooms;  // a room socket, rather than a node's control socket
    this.rooms = new Map();    // room id hex to the Room it holds a seat in
    this.authority = authority;
    this.nonce = nonce;
    this.key = null;           // hex, once registered
    this.pk = null;            // and its bytes
    this.alive = true;         // cleared each heartbeat, set on pong
    this.closing = false;      // told to go: nothing more it sends is read
    this.bytes = new Bucket(256 * 1024);
    this.frames = new Bucket(128);
    this.reader = new FrameReader(this, CONTROL_FRAMES);
    this.messages = [];        // whole messages read from one chunk, handled in order
    this.frame = null;         // a data frame's payload as it arrives
    this.frameAt = 0;
    this.registerTimer = later(HANDSHAKE_TIMEOUT_MS, () => destroy(entry));
    this.send(typed(T_CHALLENGE, nonce));
  }

  send(frame) { write(this.entry, frame); }

  /** One chunk: every byte is charged before it is parsed, every frame before it is acted
   *  on, and its messages are handled in order, each once the one before is done. */
  async onData(chunk) {
    if (this.entry.closed || this.closing) return;
    if (!this.bytes.spend(chunk.length) || !incomingBytes.spend(chunk.length)) { destroy(this.entry); return; }
    const ok = this.reader.push(chunk);
    for (const m of this.messages.splice(0)) {
      if (this.entry.closed || !(await this.onMessage(m))) return;
    }
    if (!ok && !this.closing) destroy(this.entry);
  }

  counted() {
    if (this.frames.spend(1) && incomingFrames.spend(1)) return true;
    destroy(this.entry);
    return false;
  }

  head(_b0, len) { this.frame = new Uint8Array(len); this.frameAt = 0; }
  data(piece, key) { this.frame.set(xorHere(piece, key), this.frameAt); this.frameAt += piece.length; }

  end() {
    const payload = this.frame;
    this.frame = null;
    if (!this.counted()) return false;
    this.messages.push(payload);
    return true;
  }

  control(opcode, payload) {
    if (!this.counted()) return false;
    if (opcode === 0x8) { destroy(this.entry); return false; }
    if (opcode === 0x9) this.send(encodeFrame(0xA, payload));
    else this.alive = true;
    return true;
  }

  /** False once the socket is torn down, which stops the read. */
  async onMessage(payload) {
    const type = payload[0], body = payload.subarray(1);
    if (type === T_REGISTER && (body.length === PK_LEN + SIG_LEN || body.length === PK_LEN + SIG_LEN + MAC_LEN) &&
        !this.key) {
      const sigEnd = PK_LEN + SIG_LEN;
      return this.register(body.subarray(0, PK_LEN), body.subarray(PK_LEN, sigEnd), body.subarray(sigEnd));
    }
    const forRooms = this.key && this.forRooms, calls = this.key && !this.forRooms;
    if (type === T_JOIN && body.length === ROOM_LEN && forRooms) return this.join(body);
    if (type === T_LEAVE && body.length === ROOM_LEN && forRooms) return this.leave(toHex(body));
    if (type === T_CALL && body.length === PK_LEN + TICKET_LEN && calls) {
      return this.call(body.subarray(0, PK_LEN), body.subarray(PK_LEN));
    }
    // Anything else, including a join or a call before registering or on the other kind
    // of socket, is not this wire.
    return this.drop("unexpected control frame");
  }

  /** Tear the socket down for `why`: false, which stops the read. */
  drop(why) {
    log(`! dropped: ${why}`);
    destroy(this.entry);
    return false;
  }

  async register(pk, sig, mac) {
    if (!(await admits(pk, sig, mac))) return this.drop("no secret");
    if (!(await verifyRegistration(this.forRooms, pk, sig, this.authority, this.nonce))) return this.drop("bad registration");
    if (this.entry.closed) return false;
    cancel(this.registerTimer);
    this.pk = pk.slice();
    this.key = toHex(this.pk);
    if (!this.forRooms) route(this);
    this.send(typed(T_REGISTER));
    return true;
  }

  join(idBytes) {
    const id = toHex(idBytes);
    if (this.rooms.has(id)) return true;
    let room = rooms.get(id) ?? null;
    const refusal = this.rooms.size >= MAX_ROOMS_PER_CONN ? "rooms per socket"
      : !room && rooms.size >= limits.maxRooms ? `room table full (${rooms.size} rooms)`
      : room && room.conns.size >= limits.maxPerRoom ? "room full"
      : room && room.seats(this.addr) >= limits.maxPerRoomIp ? "per-ip room cap"
      : joins && !joins.get(this.addr).spend(1) ? "join rate" : null;
    if (refusal) {
      log(`! refused join: ${refusal}`);
      this.send(typed(T_REFUSED, idBytes));
      return true;
    }
    if (!room) rooms.set(id, room = new Room(id));
    this.rooms.set(id, room);
    log(`+ member (${room.conns.size + 1} in room, ${rooms.size} rooms)`);
    room.join(this);
    return !this.entry.closed;
  }

  leave(id) {
    const room = this.rooms.get(id);
    if (!room) return true;
    this.rooms.delete(id);
    room.leave(this);
    log(`- member (${room.conns.size} in room, ${rooms.size} rooms)`);
    return true;
  }

  async call(to, ticket) {
    const callee = routeFor(toHex(to));
    // No such key here, the caller's own, too many calls from this address, or a ticket
    // already in use: the caller learns now instead of waiting its splice socket out.
    const splice = callee && callee.key !== this.key ? await openSplice(this, callee.key, ticket) : null;
    if (!splice) { this.send(typed(T_UNREACHABLE, to, ticket)); return true; }
    callee.send(typed(T_CALL, this.pk, fromHex(splice.calleeTicket)));
    return true;
  }

  beat() {
    if (!this.alive) { destroy(this.entry); return; }
    this.alive = false;
    this.send(PING);
  }

  /** Say goodbye (`closeAll`). */
  shutdown(code) {
    this.closing = true;
    this.send(closeFrame(code));
  }

  onClose() {
    cancel(this.registerTimer);
    unroute(this);
    for (const id of [...this.rooms.keys()]) this.leave(id);
  }
}

function route(conn) {
  const list = routes.get(conn.key);
  if (list) list.push(conn); else routes.set(conn.key, [conn]);
}

/** The socket calls for `key` go to: the latest registration still open. */
function routeFor(key) {
  return routes.get(key)?.at(-1) ?? null;
}

function unroute(conn) {
  const list = routes.get(conn.key);
  const i = list ? list.indexOf(conn) : -1;
  if (i < 0) return;
  list.splice(i, 1);
  if (list.length === 0) routes.delete(conn.key);
}

// ─── splices ─────────────────────────────────────────────────────────────
//
// A call creates a Splice with two tickets, the caller's and one the relay gives the
// callee, and waits for a socket bringing each. It is joined once both are there, and
// expires unjoined after SPLICE_WAIT_MS. Both ends are charged to the caller's address:
// a callee does not choose its calls, so a caller that places many cannot spend the
// callee's (or its NAT's) socket budget. The caller's address may have as many calls
// waiting as a room has seats, enough to call a whole room at once, and at most
// MAX_SPLICES_PER_CALLEE splices to any one key, waiting or joined, since every call
// makes its callee open a socket and run a handshake.
const MAX_SPLICES_PER_CALLEE = 8;
const pending = new Map();    // ticket hex to `{ splice, role }` until joined or expired
const callsFrom = new Map();  // caller address to its calls waiting
const splicesTo = new Map();  // caller address and callee key to their splices, waiting or joined
let spliceSockets = 0;        // upgraded splice sockets, against their SPLICE_SHARE

async function openSplice(caller, calleeKey, ticket) {
  const hex = toHex(ticket), pair = `${caller.addr} ${calleeKey}`;
  if (pending.has(hex) || (callsFrom.get(caller.addr) ?? 0) >= limits.maxPerRoom ||
      (splicesTo.get(pair) ?? 0) >= MAX_SPLICES_PER_CALLEE) return null;
  const calleeTicket = toHex(await random(TICKET_LEN));
  // The draw may have let another call take the ticket.
  return pending.has(hex) || pending.has(calleeTicket) ? null : new Splice(caller.addr, pair, hex, calleeTicket);
}

class Splice {
  constructor(from, pair, ticket, calleeTicket) {
    this.from = from;                    // the caller's address, which both ends are charged to
    this.pair = pair;                    // that address and the callee's key, as splicesTo counts them
    this.ticket = ticket;
    this.calleeTicket = calleeTicket;
    this.ends = { caller: null, callee: null }; // sockets that came and have not closed
    this.over = false;                   // joined or expired: its tickets are spent
    pending.set(ticket, { splice: this, role: "caller" });
    pending.set(calleeTicket, { splice: this, role: "callee" });
    bump(callsFrom, from, 1);
    bump(splicesTo, pair, 1);
    this.timer = later(SPLICE_WAIT_MS, () => this.expire());
  }

  attach(end) {
    this.ends[end.role] = end;
    if (this.ends.caller && this.ends.callee) this.join();
  }

  detach(end) {
    this.ends[end.role] = null;
    if (this.over && !this.ends.caller && !this.ends.callee) this.release();
  }

  settle() {
    this.over = true;
    pending.delete(this.ticket);
    pending.delete(this.calleeTicket);
    cancel(this.timer);
    bump(callsFrom, this.from, -1);
  }

  expire() {
    if (this.over) return;
    this.settle();
    const ends = Object.values(this.ends);
    if (!ends.some(Boolean)) this.release();
    for (const end of ends) {
      if (end) destroy(end.entry);
    }
  }

  /** Called once, when it is over and its last socket gone: nothing attaches once over. */
  release() {
    bump(splicesTo, this.pair, -1);
  }

  join() {
    this.settle();
    const { caller, callee } = this.ends;
    caller.link(callee);
    callee.link(caller);
  }
}

/** One socket of a splice. It is read only while nothing holds it: a far end that is
 *  full, its address past its traffic budget, or no far end yet. */
class SpliceEnd {
  constructor(entry, addr, splice, role, head) {
    this.entry = entry;
    this.addr = addr;          // where it connects from, whose budget its sends are metered on
    this.splice = splice;
    this.role = role;
    this.far = null;           // the other end, once joined
    this.linked = false;       // joined, and the far end has not closed
    this.mid = false;          // a frame forwarded to this socket is partly written
    this.alive = true;         // cleared each heartbeat, set on pong or on anything sent
    this.holds = 0;
    this.metered = false;      // held until its address's budget recovers
    this.holdTimer = null;     // held until the far end drains, and gives up on one that does not
    this.out = null;           // what one chunk forwards, in order, while it is read
    this.ending = false;       // a close came through: both ends go once it is forwarded
    this.early = head.length > 0 ? head : null; // what came with the upgrade
    this.reader = new FrameReader(this, SPLICE_FRAMES);
    spliceSockets++;
    this.hold(); // until joined
    splice.attach(this);
  }

  /** Joined: what came with the upgrade goes first, and the socket is read once it has. */
  link(far) {
    this.far = far;
    this.linked = true;
    const early = this.early;
    this.early = null;
    if (early) void this.take(early).then(() => this.release());
    else this.release();
  }

  hold() { if (this.holds++ === 0) linkPause(this.entry.id, true); }
  release() {
    if (--this.holds === 0 && !this.entry.closed) {
      // A socket is not dead because the relay stopped reading it; give it a full
      // heartbeat interval to answer before reaping it.
      this.alive = true;
      linkPause(this.entry.id, false);
    }
  }

  /** One chunk: its frames go to the far end as server frames, streaming: a frame's
   *  header goes out as soon as it is parsed and its payload as it arrives, so the relay
   *  holds a chunk, never a whole message. */
  async onData(chunk) {
    if (!this.linked) return;
    await this.take(chunk);
  }

  async take(chunk) {
    this.alive = true;
    this.out = [];
    const ok = this.reader.push(chunk);
    const parts = this.out;
    this.out = null;
    for (let i = 0; i < parts.length; i++) {
      if (parts[i].key) parts[i] = await unmask(parts[i].piece, parts[i].key);
    }
    if (parts.length > 0) this.forward(concatBytes(parts));
    if (this.ending) { endSoon(this.entry); endSoon(this.far.entry); return; }
    if (!ok) { this.kill(); return; }
    this.meter(chunk.length);
  }

  /** Drop both ends at once, neither ending the other gracefully on its way out. */
  kill() {
    this.linked = this.far.linked = false;
    destroy(this.entry);
    destroy(this.far.entry);
  }

  // What an address sends through its splices is metered, spliceRate KiB/s with two
  // seconds of burst. Past it, the address's splice sockets are not read until the debt
  // is paid back, so a sender is slowed, not cut off.
  meter(n) {
    if (!spliceBudgets) return;
    const b = spliceBudgets.get(this.addr);
    b.charge(n);
    if (b.tokens >= 0 || this.metered) return;
    this.metered = true;
    this.hold();
    later(-b.tokens * 1000 / b.rate, () => { this.metered = false; this.release(); });
  }

  /** Write to the far end; a far end holding more than SPLICE_HIGH holds this one until it
   *  is down to SPLICE_LOW, or gives up on both after SPLICE_HOLD_MS of not draining. */
  forward(bytes) {
    const far = this.far.entry;
    if (far.closed) return;
    void linkSend(far.id, bytes).then((backlog) => {
      if (backlog <= SPLICE_HIGH || this.holdTimer !== null || this.entry.closed) return;
      this.hold();
      this.holdTimer = later(SPLICE_HOLD_MS, () => this.kill());
      this.waitDrain();
    });
  }

  waitDrain() {
    later(DRAIN_POLL_MS, () => {
      if (this.holdTimer === null) return;
      void linkSend(this.far.entry.id, EMPTY).then((backlog) => {
        if (backlog <= SPLICE_LOW || this.far.entry.closed) this.drained();
        else this.waitDrain();
      });
    });
  }

  drained() {
    if (this.holdTimer === null) return;
    cancel(this.holdTimer);
    this.holdTimer = null;
    this.release();
  }

  head(b0, len) {
    this.out.push(frameHead(b0, len));
    this.far.mid = len > 0;
  }

  data(piece, key) { this.out.push({ piece, key }); }
  end() { this.far.mid = false; }

  // Control frames stay on the hop: a ping is answered, a close ends both ends once
  // forwarded.
  control(opcode, payload) {
    if (opcode === 0x9) {
      if (!this.mid) write(this.entry, encodeFrame(0xA, payload));
    } else if (opcode === 0x8) {
      if (!this.far.mid) this.out.push(encodeFrame(0x8, payload));
      this.ending = true;
      return false;
    }
    return true;
  }

  /** Pinged only while joined, between frames, and not paused: a paused socket cannot read
   *  the pong, so reaping it as silent would cut a healthy transfer. */
  beat() {
    if (!this.linked || this.mid || this.holds > 0) return;
    if (!this.alive) { destroy(this.entry); return; }
    this.alive = false;
    write(this.entry, PING);
  }

  /** Say goodbye (`closeAll`). */
  shutdown(code) {
    if (!this.mid) write(this.entry, closeFrame(code));
  }

  onClose() {
    cancel(this.holdTimer);
    this.holdTimer = null;
    spliceSockets--;
    this.linked = false;
    if (this.far?.linked) {
      this.far.linked = false;
      endSoon(this.far.entry);
    }
    this.splice.detach(this);
  }
}

// ─── the relay ───────────────────────────────────────────────────────────

// Global budgets survive reconnects and room turnover.
const incomingBytes = new Bucket(4 * 1024 * 1024);
const incomingFrames = new Bucket(8192);
const registrations = limits.registerRate > 0 ? new AddressBudgets(limits.registerRate) : null;
const joins = limits.registerRate > 0 ? new AddressBudgets(limits.registerRate, Math.max(2 * limits.registerRate, JOIN_BURST)) : null;
const spliceBudgets = limits.spliceRate > 0 ? new AddressBudgets(limits.spliceRate * 1024) : null;
const stunBudgets = new AddressBudgets(STUN_RATE);
const stunNewAddresses = new Bucket(STUN_NEW_RATE);

/** The datagram sockets STUN is answered on, once bound. */
let stunReady = null;
const stunSockets = new Set();

/** Start what runs without a client: the heartbeat, and STUN on its two ports. Once, on
 *  the first event, since nothing reaches the host before one. Answers the STUN ports. */
function start() {
  if (stunReady) return stunReady;
  // NAT and firewall timeouts leave half-open sockets that never close, so without a
  // liveness probe a dropped peer would hold its room and address slots forever. Each
  // interval every upgraded socket is pinged, and one that did not answer the previous
  // ping is presumed dead and destroyed.
  if (limits.heartbeatSecs > 0) {
    every(limits.heartbeatSecs * 1000, () => {
      for (const entry of [...conns.values()]) entry.conn?.beat();
    });
  }
  // Two ports, so a node can tell a NAT that gives each destination its own port: the two
  // answers then name different ones. Port 0 asks the OS for two.
  const ports = stunPort === null ? [] : stunPort === 0 ? [0, 0] : [stunPort, stunPort + 1];
  stunReady = Promise.all(ports.map(async (port) => {
    const r = await host.call(N_UDP_BIND, of(port >> 8, port & 255));
    const id = readU32(r, 0);
    if (id === 0) throw new Error(`relay: STUN cannot bind UDP port ${port}`);
    stunSockets.add(id);
    return readU16(r, 4);
  }));
  stunReady.catch((e) => log(`! ${e.message}`));
  return stunReady;
}

/** The answer to a STUN request on one of the relay's ports, or null. */
function stun(msg, ipB, port) {
  const addr = addressOf(ipText(ipB));
  if (!stunBudgets.has(addr) && !stunNewAddresses.spend(1)) return null;
  if (!stunBudgets.get(addr).spend(1)) return null;
  return stunResponse(msg, ipB, port);
}

// Refuse an upgrade with a short HTTP error and end the socket, before the protocol
// switch, so a refused client never holds a room seat or a frame buffer.
function refuse(entry, status, note) {
  write(entry, utf8Encode(`HTTP/1.1 ${status} ${REFUSALS[status]}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`));
  endSoon(entry);
  if (note) log(`! refused upgrade: ${note}`);
}

/** A TCP socket the host accepted, accounted before any HTTP header arrives. Trusted
 *  proxies share the global cap here; their forwarded clients are charged at upgrade. */
function opened(id, remote) {
  const ip = normalizeIp(remote) ?? "unknown";
  const entry = { id, ip, account: null, timer: null, conn: null, head: EMPTY, closed: false };
  if (conns.size >= limits.maxConns || (!proxies.has(ip) && !bill(entry, addressOf(ip)))) {
    linkClose(id, false);
    return;
  }
  conns.set(id, entry);
  entry.timer = later(HANDSHAKE_TIMEOUT_MS, () => destroy(entry));
}

/** Bytes on a socket: the upgrade request until it is whole, then frames. */
async function onBytes(entry, bytes) {
  if (entry.conn) { await entry.conn.onData(bytes); return; }
  const head = entry.head.length > 0 ? concatBytes([entry.head, bytes]) : bytes.slice();
  const end = indexOfHeadEnd(head, Math.max(0, entry.head.length - 3));
  if (end < 0) {
    entry.head = head;
    if (head.length > MAX_HEAD_BYTES) refuse(entry, 431);
    return;
  }
  entry.head = EMPTY;
  const req = parseRequest(latin1(head.subarray(0, end)));
  if (!req) { refuse(entry, 400); return; }
  if (!req.upgrade) {
    // A plain HTTP request: say what this is, and close.
    const body = utf8Encode("seedrelay: connect a WebSocket to ws://<host>:<port>/v1/\n");
    write(entry, concatBytes([utf8Encode("HTTP/1.1 426 Upgrade Required\r\nContent-Type: text/plain\r\n" +
      `Content-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]));
    endSoon(entry);
    return;
  }
  await upgrade(entry, req, head.subarray(end + 4));
}

/** Where `\r\n\r\n` starts in `b`, looking from `from`; -1 if it is not there. */
function indexOfHeadEnd(b, from) {
  for (let i = from; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  }
  return -1;
}

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** An HTTP/1.1 request head as `{ method, url, headers, upgrade }`, headers by lowercase
 *  name, or null when it is malformed. Repeats of `host` are dropped and those of any other
 *  header joined with ", ", as Node's HTTP server does. */
function parseRequest(text) {
  const lines = text.split("\r\n");
  const m = /^([A-Z]+) (\S+) HTTP\/1\.[01]$/.exec(lines[0]);
  if (!m) return null;
  const headers = Object.create(null);
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":");
    if (colon <= 0 || /[\0-\x08\n-\x1f\x7f]/.test(line)) return null;
    const name = line.slice(0, colon).toLowerCase();
    if (!TOKEN.test(name)) return null;
    const value = line.slice(colon + 1).replace(/^[ \t]+|[ \t]+$/g, "");
    if (!(name in headers)) headers[name] = value;
    else if (name !== "host") headers[name] += ", " + value;
  }
  const connection = (headers.connection ?? "").toLowerCase().split(",").map((s) => s.trim());
  return { method: m[1], url: m[2], headers, upgrade: connection.includes("upgrade") && "upgrade" in headers };
}

/** What an upgrade asks for, `{ splice, rooms }` (splice null for a control or room
 *  socket), or the status refusing it: 404 for any path but the wire version's own, 400
 *  for a malformed ticket. */
function targetFromUrl(url) {
  const q = url.indexOf("?");
  const path = (q < 0 ? url : url.slice(0, q)).split("#", 1)[0];
  const query = q < 0 ? "" : url.slice(q + 1).split("#", 1)[0];
  if (path === "/v1/rooms") return { splice: null, rooms: true };
  if (path !== "/v1" && path !== "/v1/") return 404;
  const ticket = /(?:^|&)splice=([0-9a-f]{32})(?:&|$)/.exec(query);
  if (ticket) return { splice: ticket[1], rooms: false };
  if (/(?:^|&)splice=/.test(query)) return 400;
  return { splice: null, rooms: false };
}

// Walk from the actual remote address `ip` toward the client, stopping at the first
// untrusted hop. Never trust a client-supplied leftmost XFF value.
function clientIp(headers, ip) {
  if (proxies.has(ip)) {
    const xff = headers["x-forwarded-for"];
    if (!xff) return null;
    const chain = xff.split(",").map((part) => normalizeIp(part.trim()));
    if (chain.some((part) => part === null)) return null;
    for (let i = chain.length - 1; i >= 0 && proxies.has(ip); i--) ip = chain[i];
  }
  return ip;
}

async function upgrade(entry, req, head) {
  const key = req.headers["sec-websocket-key"];
  if (req.method !== "GET" || req.headers.upgrade.toLowerCase() !== "websocket" ||
      req.headers["sec-websocket-version"] !== "13" || !/^[A-Za-z0-9+/]{22}==$/.test(key ?? "")) {
    destroy(entry);
    return;
  }

  // A browser names the page that opened a socket in Origin, and every socket a page
  // opens counts against its visitor's address. The allowlist says which pages may spend
  // visitors' budgets here, so a hostile page cannot use its visitors to fill the relay or
  // lock them out of it. It is not authentication: the relay has no cookies or ambient
  // credentials to hijack, and a native client (a seedkernel node, `websocat`) sends no
  // Origin at all and is accepted.
  const origin = req.headers.origin;
  if (origin && !origins.has(origin)) { refuse(entry, 403, "origin not allowed"); return; }

  const target = targetFromUrl(req.url);
  if (typeof target === "number") {
    refuse(entry, target, target === 404 ? "not a path of the wire this relay speaks" : "bad ticket");
    return;
  }
  const ip = clientIp(req.headers, entry.ip);
  if (ip === null) { refuse(entry, 400, "invalid proxy address chain"); return; }
  const addr = addressOf(ip);

  if (target.splice !== null) {
    // A splice socket needs a ticket a call handed out, and is charged to its caller.
    const waiting = pending.get(target.splice);
    if (!waiting) { refuse(entry, 404, "no such splice"); return; }
    if (waiting.splice.ends[waiting.role]) { refuse(entry, 409, "splice end already taken"); return; }
    if (spliceSockets >= Math.floor(limits.maxConns * SPLICE_SHARE)) {
      refuse(entry, 503, "splices at their share of the relay");
      return;
    }
    if (!bill(entry, waiting.splice.from)) { refuse(entry, 429, "per-ip cap"); return; }
    if (!(await accept(entry, key))) return;
    // The splice may have expired, or the end been taken, while the accept was made.
    if (waiting.splice.over || waiting.splice.ends[waiting.role]) { destroy(entry); return; }
    entry.conn = new SpliceEnd(entry, addr, waiting.splice, waiting.role, head);
    return;
  }

  const authority = canonicalAuthority(req.headers.host ?? "");
  if (!authorities.has(authority)) { refuse(entry, 421, "not a name this relay answers to"); return; }
  if (!bill(entry, addr)) { refuse(entry, 429, "per-ip cap"); return; }
  if (registrations && !registrations.get(addr).spend(1)) { refuse(entry, 429, "registration rate"); return; }
  if (!(await accept(entry, key))) return;
  const nonce = await random(NONCE_LEN);
  if (entry.closed) return;
  entry.conn = new ControlConn(entry, addr, authority, target.rooms, nonce);
  // A client may send its first frame with the upgrade request.
  if (head.length > 0) await entry.conn.onData(head);
}

/** Switch protocols: false when the socket went meanwhile. */
async function accept(entry, key) {
  const value = utf8Decode(await host.call(N_WS, concatBytes([of(WS_OP_ACCEPT), utf8Encode(key)])));
  if (entry.closed) return false;
  write(entry, utf8Encode("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${value}\r\n\r\n`));
  cancel(entry.timer);
  return true;
}

/** Tell every socket the relay is restarting (close code 1012) and end it, and drop those
 *  still mid-handshake. Every goodbye is written first, since ending one end of a splice
 *  ends the other. */
function closeAll() {
  const all = [...conns.values()];
  for (const entry of all) entry.conn?.shutdown(CLOSE_RESTART);
  for (const entry of all) shut(entry, entry.conn !== null);
}

// ─── the one entrypoint ──────────────────────────────────────────────────
//
// `handle([caller 32][op envelope])`. The host's raw-link events, its wake and the host's
// own ops come from the host's caller id; this program takes nothing from an app.

/** Each event's fields, read in the order the host writes them (seedkernel §12.2). */
function fields(args) {
  let at = 0;
  return {
    u8: () => args[at++],
    u32: () => { at += 4; return readU32(args, at - 4); },
    blob: () => { const n = readU32(args, at); at += 4 + n; return args.subarray(at - n, at); },
    more: () => at < args.length,
  };
}

const ops = {
  wake() { onWake(); },
  linkOpen(r) {
    const id = r.u32();
    r.u8(); r.blob(); r.u32(); // stream, listener, via: every listener here speaks HTTP
    opened(id, utf8Decode(r.blob()));
  },
  async linkBytes(r) {
    const entry = conns.get(r.u32());
    if (entry && !entry.closed) await onBytes(entry, r.blob());
  },
  linkClosed(r) {
    const entry = conns.get(r.u32());
    if (entry) gone(entry);
  },
  datagrams(r) {
    const answers = [];
    while (r.more()) {
      const socket = r.u32(), b = r.blob();
      if (!stunSockets.has(socket)) continue;
      for (let at = 0; at + 5 <= b.length;) {
        const n = b[at];
        const ip = b.subarray(at + 1, at + 1 + n);
        const port = readU16(b, at + 1 + n), len = readU16(b, at + 3 + n);
        const msg = b.subarray(at + 5 + n, at + 5 + n + len);
        at += 5 + n + len;
        const answer = stun(msg, ip, port);
        if (!answer) continue;
        const to = utf8Encode(ipText(ip));
        answers.push(u32(socket), of(to.length), to, of(port >> 8, port & 255, answer.length >> 8, answer.length & 255), answer);
      }
    }
    if (answers.length > 0) void host.call(N_UDP_SEND, concatBytes(answers)).catch(() => {});
  },
  /** `start [authority text]*`: the names the relay also answers to, which its runner
   *  knows once the port is bound. Answers the STUN ports, `[port u16]*`. */
  async start(r) {
    while (r.more()) authorities.add(canonicalAuthority(utf8Decode(r.blob())));
    const ports = await start();
    return concatBytes(ports.map((p) => of(p >> 8, p & 255)));
  },
  /** Tell every socket the relay is restarting. */
  close() { closeAll(); },
};

function handle(argBytes) {
  const { fromHost, body } = callerOf(argBytes);
  if (!fromHost) throw new Error("relay: takes nothing from an app");
  const { op, args } = readOp(body);
  const fn = Object.prototype.hasOwnProperty.call(ops, op) ? ops[op] : null;
  if (!fn) throw new Error("relay: no op '" + op + "'");
  if (op !== "start") start();
  const out = fn(fields(args));
  return out instanceof Promise ? out.then((v) => v ?? EMPTY) : out ?? EMPTY;
}

/* @seedkernel-op-frame */
