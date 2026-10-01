// The rendezvous and forwarder for seedkernel nodes (§12.7). A node registers its key
// here over a control socket, its app meets other keys in rooms, and the node reaches any
// registered key through a splice: two fresh sockets the relay joins, copying bytes
// between them. The seedkernel channel handshake runs end to end through a splice, so
// the relay forwards ciphertext it cannot read, and cannot pose as either end. It lives
// in seedrelay because it is a deployment concern, not trusted runtime surface: the
// kernel ships no server and its own tests use an in-process relay. Seedchat and
// seedstore both use it.
//
// Sockets, by upgrade path. The first segment names the wire version, and any other path
// is refused, so a relay and a node never guess at each other's wire:
//
//   ws://host:port/v1/                a control socket: a node's transport, reachable by key
//   ws://host:port/v1/rooms           a room socket: an app, meeting others in rooms
//   ws://host:port/v1/?splice=<hex>   one end of a splice, named by a 16-byte ticket
//
// Both kinds must register before anything else: the relay sends a nonce, and the key
// holder signs it for the name it dialed, which must be one this relay answers to
// (`registerMessage`). The relay routes calls to the control socket that registered a key
// most recently. A room socket joins and leaves rooms, named by 32-byte ids (`rooms.mjs`
// hashes a room's name into its id, so the relay never learns names), and a room's
// membership is the set of keys joined to it. Rooms are only discovery: an app hands the
// keys it meets to its transport, which reaches them through a control socket. Rooms are
// not authenticated: a room id is a bearer credential for learning who is there, so a
// private room wants a name with 16+ random bytes. Reaching a node needs only its key,
// since the node's own contact secret gates its handshake end to end.
//
// A relay started with a secret (`--secret`) serves only those who know it: both kinds
// of registration must carry a MAC under it (`secretProof`). Splice sockets need no proof
// of their own, since only registered sockets place and take the calls that hand out
// tickets.
//
// A splice is set up by a call: the caller names the callee's key and a fresh ticket on
// its control socket, the relay passes the callee a ticket of its own on the callee's
// control socket only, and each end opens a splice socket with its ticket. The relay
// joins the two, and refuses a ticket nobody was given, so two strangers cannot use it
// as a pipe. One party holding two keys can, so what splices carry is metered per client
// address. Both ends are charged to the caller's address, which placed the call.
//
// `createRelay(options)` builds one; `server.mjs` is the bin, and `parseOptions` reads its
// command line. No third-party dependencies.

import { createServer } from "node:http";
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from "node:crypto";
import { isIP } from "node:net";

// ─── limits ──────────────────────────────────────────────────────────────
//
// Independent caps that bound the relay's footprint against both accidental fan-out and
// deliberate exhaustion. A room whose N members all stay relayed costs N(N-1) splice
// sockets, N control sockets and N room sockets, and its smallest key, which calls the
// rest, is charged 2(N-1) + 2 of them, its app's room socket included. The defaults fit
// one full room so relayed on its share of the relay (992 of 1792 splice sockets) and
// within its caller's share of an address (64 of 72, with room to redial); rooms whose
// pairs move to direct links cost far less.
const DEFAULT_LIMITS = Object.freeze({
  maxConns: 2048,      // sockets across the relay, including those still awaiting upgrade
  maxRooms: 512,       // rooms
  maxPerRoom: 32,      // registered sockets in one room
  maxPerIp: 72,        // sockets charged to one client address
  maxPerRoomIp: 16,    // registered sockets one address holds in one room
  ipv6Prefix: 64,      // the bits of an IPv6 address that name one client
  registerRate: 4,     // sockets an address registers, and rooms it joins, per second; 0 = unmetered
  spliceRate: 1024,    // KiB/s an address sends through splices, 0 = unmetered
  heartbeatSecs: 30,   // ping/reap interval, 0 = off
});

// Filling a room of N costs N(N-1) announcements, and each joiner gets all N keys in one
// members frame, so no room takes more seats than this: a members frame of 32 KiB.
const MAX_PER_ROOM = 1024;

// The command line, flag by flag: its `createRelay` option, environment variable, and the
// largest integer it takes (Infinity for any number).
const LIMIT_FLAGS = {
  "--max-conns":       ["maxConns",      "RELAY_MAX_CONNS",       Number.MAX_SAFE_INTEGER],
  "--max-rooms":       ["maxRooms",      "RELAY_MAX_ROOMS",       Number.MAX_SAFE_INTEGER],
  "--max-per-room":    ["maxPerRoom",    "RELAY_MAX_PER_ROOM",    MAX_PER_ROOM],
  "--max-per-ip":      ["maxPerIp",      "RELAY_MAX_PER_IP",      Number.MAX_SAFE_INTEGER],
  "--max-per-room-ip": ["maxPerRoomIp",  "RELAY_MAX_PER_ROOM_IP", Number.MAX_SAFE_INTEGER],
  "--ipv6-prefix":     ["ipv6Prefix",    "RELAY_IPV6_PREFIX",     128],
  "--register-rate":   ["registerRate",  "RELAY_REGISTER_RATE",   Infinity],
  "--splice-rate":     ["spliceRate",    "RELAY_SPLICE_RATE",     Infinity],
  "--heartbeat-secs":  ["heartbeatSecs", "RELAY_HEARTBEAT_SECS",  Infinity],
};

/** The bin's options from its arguments and environment, as `createRelay` takes them,
 *  plus `port` and `host`. Anything malformed or unknown throws: a relay that starts
 *  with a limit it was not given is worse than one that does not start. */
export function parseOptions(argv, env = {}) {
  const options = { port: 8080, host: "127.0.0.1", authorities: [], allowOrigins: [], trustedProxies: [], secrets: [],
    limits: {}, stun: null };
  const number = (flag, value, max) => {
    const n = Number(value);
    if (value === undefined || value === "" || !Number.isFinite(n) || n < 0 || n > max ||
        (max !== Infinity && !Number.isInteger(n))) {
      throw new Error(`${flag} takes ${max === Infinity ? "a non-negative number" : `an integer from 0 to ${max}`}, not ${JSON.stringify(value ?? "")}`);
    }
    return n;
  };
  const list = (value) => (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  for (const [flag, [name, variable, max]] of Object.entries(LIMIT_FLAGS)) {
    if (env[variable] !== undefined) options.limits[name] = number(variable, env[variable], max);
  }
  for (const a of list(env.RELAY_AUTHORITIES)) options.authorities.push(authorityOption(a));
  for (const ip of list(env.RELAY_TRUSTED_PROXIES)) options.trustedProxies.push(proxyOption(ip));
  for (const secret of list(env.RELAY_SECRETS)) options.secrets.push(secretOption(secret));
  const stun = (flag, value) => {
    const m = /^(?:\[?([^\]\s]+?)\]?:)?(\d+)$/.exec(value);
    if (!m) throw new Error(`${flag} takes [host:]port, not ${JSON.stringify(value)}`);
    return { host: m[1] ?? null, port: number(flag, m[2], 65535) };
  };
  if (env.RELAY_STUN !== undefined) options.stun = stun("RELAY_STUN", env.RELAY_STUN);

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a in LIMIT_FLAGS) options.limits[LIMIT_FLAGS[a][0]] = number(a, value(), LIMIT_FLAGS[a][2]);
    else if (a === "--port") options.port = number(a, value(), 65535);
    else if (a === "--host") options.host = value();
    else if (a === "--authority") options.authorities.push(authorityOption(value()));
    else if (a === "--allow-origin") options.allowOrigins.push(value());
    else if (a === "--trusted-proxy") options.trustedProxies.push(proxyOption(value()));
    else if (a === "--secret") options.secrets.push(secretOption(value()));
    else if (a === "--stun") options.stun = stun(a, value());
    else if (/^\d+$/.test(a)) options.port = number("the port", a, 65535);
    else throw new Error(`unknown option ${a}`);
  }
  if (options.authorities.length === 0 && (options.host === "0.0.0.0" || options.host === "::")) {
    throw new Error(`a relay bound to ${options.host} needs --authority: the host[:port] nodes dial it by`);
  }
  if (options.stun && options.stun.host === null) options.stun.host = options.host;
  return options;
}

function authorityOption(value) {
  if (!/^[^\s/?#@]+$/.test(value)) throw new Error(`--authority takes host[:port] as nodes dial it, not ${JSON.stringify(value)}`);
  return canonicalAuthority(value);
}

// A listener who saw one registration can test guesses at the secret against its MAC
// offline, so a secret must be too long to guess.
const MIN_SECRET_LEN = 16;

/** A secret as it reads from --secret, RELAY_SECRETS and a client's file alike: the
 *  variable splits on commas and trims, as seedkernel trims its file, so neither may be
 *  in one. */
function secretOption(value) {
  if (value.length < MIN_SECRET_LEN) throw new Error(`a secret takes at least ${MIN_SECRET_LEN} characters`);
  if (value.includes(",") || value !== value.trim()) {
    throw new Error("a secret takes no commas, and no whitespace at either end");
  }
  return value;
}

function proxyOption(value) {
  const ip = normalizeIp(value);
  if (!ip) throw new Error(`a trusted proxy must be an IP address, not ${JSON.stringify(value)}`);
  return ip;
}

/** The names a relay bound to `host` answers to when none are given: the loopback names
 *  on a loopback address, else the address itself. A relay nodes reach under any other
 *  name (a public one, behind a proxy), or bound to every interface, needs `--authority`. */
export function localAuthorities(host, port) {
  const at = (h) => canonicalAuthority(`${h.includes(":") ? `[${h}]` : h}:${port}`);
  if (host === "localhost" || host === "::1" || /^127\./.test(host)) return ["localhost", "127.0.0.1", "::1"].map(at);
  return [at(host)];
}

// Opaque origins (including file pages and sandboxed iframes) are not allowed by default.
// Operators can explicitly opt in with --allow-origin null.
const LOCAL_ORIGINS = [];
for (const scheme of ["http", "https"]) {
  for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
    LOCAL_ORIGINS.push(`${scheme}://${host}`);
    for (const port of [80, 443, 3000, 5173, 8000, 8080, 8443]) LOCAL_ORIGINS.push(`${scheme}://${host}:${port}`);
  }
}

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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
// How long a call waits for both of its splice sockets, and how long a socket the relay
// ended is given to close before it is destroyed.
const SPLICE_WAIT_MS = 10_000;
// Splice sockets may take this share of --max-conns and no more, so a relay busy with
// splices still has room for nodes to register.
const SPLICE_SHARE = 7 / 8;
// The close code the relay sends when it is going away: it is restarting.
const CLOSE_RESTART = 1012;

const REFUSALS = { 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 409: "Conflict",
  421: "Misdirected Request", 429: "Too Many Requests", 503: "Service Unavailable" };

const realClock = {
  now: () => performance.now(),
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (t) => clearTimeout(t),
  setInterval: (fn, ms) => setInterval(fn, ms),
  clearInterval: (t) => clearInterval(t),
};

/** A timer that does not keep the process alive. */
function later(clock, fn, ms) {
  const t = clock.setTimeout(fn, ms);
  t.unref?.();
  return t;
}

// Token buckets bound sustained traffic as well as bursts, with two seconds of burst
// unless told otherwise.
class Bucket {
  constructor(clock, rate, burst = rate * 2) {
    this.clock = clock;
    this.rate = rate;
    this.burst = burst;
    this.tokens = burst;
    this.at = clock.now();
  }

  refill() {
    const now = this.clock.now();
    this.tokens = Math.min(this.burst, this.tokens + (now - this.at) * this.rate / 1000);
    this.at = now;
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
  constructor(clock, rate, burst = rate * 2) {
    this.clock = clock;
    this.rate = rate;
    this.burst = burst;
    this.map = new Map();
  }

  has(addr) { return this.map.has(addr); }

  get(addr) {
    let b = this.map.get(addr);
    if (!b) {
      this.map.set(addr, b = new Bucket(this.clock, this.rate, this.burst));
      this.retire(addr, b);
    }
    return b;
  }

  retire(addr, b) {
    later(this.clock, () => {
      if (b.refill() >= b.burst) this.map.delete(addr);
      else this.retire(addr, b);
    }, Math.max(1000, (b.burst - b.refill()) * 1000 / b.rate));
  }
}

function bump(map, key, by) {
  const n = (map.get(key) ?? 0) + by;
  if (n > 0) map.set(key, n); else map.delete(key);
}

function writeFrame(sock, frame) {
  if (sock.destroyed || !sock.writable) return false;
  if (sock.writableLength + frame.length > MAX_SOCKET_BACKLOG) {
    sock.destroy();
    return false;
  }
  try { sock.write(frame); return true; }
  catch { sock.destroy(); return false; }
}

/** End a socket gracefully, so what is queued for it still goes out, and give up on the
 *  far end after SPLICE_WAIT_MS. */
function endSoon(clock, sock) {
  sock.end();
  later(clock, () => sock.destroy(), SPLICE_WAIT_MS);
}

// ─── addresses ───────────────────────────────────────────────────────────

/** An IP address in one spelling: IPv4 dotted, IPv4-mapped IPv6 as IPv4, other IPv6 as
 *  URL hosts compress it. Null for anything else, scoped IPv6 included, which is a valid
 *  `isIP` but neither a URL host nor a portable forwarded address. */
function normalizeIp(value) {
  if (value.includes("%") || !isIP(value)) return null;
  if (isIP(value) === 4) return value;
  const normalized = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(normalized);
  if (!mapped) return normalized;
  const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

/** The client an address is accounted as: an IPv4 address itself, an IPv6 address its
 *  first `prefix` bits, since one host is routinely handed a whole /64 and would
 *  otherwise get a fresh set of limits from every address in it. */
function addressKey(ip, prefix) {
  if (!ip.includes(":")) return ip;
  return ipv6Groups(ip).map((g, i) => {
    const bits = Math.min(16, Math.max(0, prefix - 16 * i));
    return (g & (0xffff << (16 - bits)) & 0xffff).toString(16);
  }).join(":") + "/" + prefix;
}

/** A normalized IPv6 address's eight 16-bit groups. */
function ipv6Groups(ip) {
  const [head, tail] = ip.split("::");
  const left = head ? head.split(":") : [], right = tail ? tail.split(":") : [];
  return [...left, ...Array(8 - left.length - right.length).fill("0"), ...right].map((g) => parseInt(g, 16));
}

// ─── STUN ────────────────────────────────────────────────────────────────
//
// WebRTC connects two nodes behind NAT only once each has learned the address the
// internet sees it at, from a STUN Binding request (RFC 8489). The relay answers those on
// UDP (`--stun`), and a seedkernel transport asks the relay a peer is linked through,
// so nodes need no third-party STUN server: the relay already sees every address it
// would tell. It answers Binding requests and nothing else, at most STUN_RATE a second to
// one address, which leaves it of little use as a reflector. Each address it answers is
// remembered for a second or so, and UDP sources are easy to forge, so it takes at most
// STUN_NEW_RATE new addresses a second: a flood of forged ones goes unanswered, not
// remembered, while addresses already known keep their own rate.
const STUN_COOKIE = 0x2112a442, STUN_RATE = 20, STUN_NEW_RATE = 256;

/** The Binding success response to a STUN Binding request from `ip`:`port`, carrying its
 *  XOR-MAPPED-ADDRESS; null for anything else. */
export function stunResponse(msg, ip, port) {
  if (msg.length < 20 || msg.length % 4 !== 0 || msg.readUInt16BE(0) !== 0x0001 ||
      msg.readUInt16BE(2) !== msg.length - 20 || msg.readUInt32BE(4) !== STUN_COOKIE) return null;
  const v6 = ip.includes(":");
  const addr = v6 ? Buffer.from(ipv6Groups(ip).flatMap((g) => [g >> 8, g & 255])) : Buffer.from(ip.split(".").map(Number));
  const out = Buffer.alloc(28 + addr.length);
  out.writeUInt16BE(0x0101, 0);
  out.writeUInt16BE(out.length - 20, 2);
  msg.copy(out, 4, 4, 20);                 // the cookie and transaction id
  out.writeUInt16BE(0x0020, 20);           // XOR-MAPPED-ADDRESS
  out.writeUInt16BE(4 + addr.length, 22);
  out[25] = v6 ? 2 : 1;
  out.writeUInt16BE(port ^ (STUN_COOKIE >>> 16), 26);
  // The address XORed with the cookie, and for IPv6 the transaction id after it.
  for (let i = 0; i < addr.length; i++) out[28 + i] = addr[i] ^ out[4 + i];
  return out;
}

// ─── the relay wire ────────────────────────────────────────────────────────
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
//
// A join is answered with the room's other keys in a members frame, or refused when the
// room has no seat for the socket or its address is joining too fast.
const T_CHALLENGE = 0x00, T_REGISTER = 0x01, T_MEMBERS = 0x02, T_JOINED = 0x03,
  T_LEFT = 0x04, T_CALL = 0x05, T_UNREACHABLE = 0x06, T_REFUSED = 0x07;
const T_JOIN = 0x02, T_LEAVE = 0x03;
const PK_LEN = 32, SIG_LEN = 64, MAC_LEN = 64, NONCE_LEN = 32, TICKET_LEN = 16, ROOM_LEN = 32;

// A registration is an Ed25519 signature by the node's identity key over
//   DOMAIN_link_scope ‖ DOMAIN_relay ‖ authority ‖ nonce       on a control socket
//   DOMAIN_ROOMS ‖ authority ‖ nonce                            on a room socket
// where DOMAIN_link_scope is the prefix seedkernel's host applies to everything its
// transport signs, DOMAIN_relay the transport's tag for this format, and authority the
// relay's host[:port] as the node dialed it (`canonicalAuthority`). An app signs a room
// socket's itself, under a tag no seedkernel signature starts with, so neither kind can
// stand for the other: an app's rooms can never draw the transport's calls. The fresh nonce makes
// each signature good once. The authority must be one of this relay's own names, never
// whatever Host a socket sends: otherwise relay A could take a nonce from relay B, have
// one of its visitors sign it for a.example, and present that to B as Host a.example,
// registering the visitor's key on B and drawing its calls.
const DOMAIN_LINK_SCOPE = Buffer.from("seedkernel-link-scope-v1\0");
const DOMAIN_RELAY = Buffer.from("seedkernel-relay-register-v1\0");
const DOMAIN_ROOMS = Buffer.from("seedrelay-rooms-v1\0");
const DOMAIN_SECRET = Buffer.from("seedrelay-secret-v1\0");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");

/** Lowercase, without a default port, so the Host a browser sends for
 *  wss://relay.example matches the relay.example:443 a node dials. */
function canonicalAuthority(host) {
  return host.toLowerCase().replace(/:(?:80|443)$/, "");
}

function registerMessage(rooms, authority, nonce) {
  const domain = rooms ? [DOMAIN_ROOMS] : [DOMAIN_LINK_SCOPE, DOMAIN_RELAY];
  return Buffer.concat([...domain, Buffer.from(authority), nonce]);
}

function verifyRegistration(rooms, pk, sig, authority, nonce) {
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, pk]), format: "der", type: "spki" });
    return verify(null, registerMessage(rooms, authority, nonce), key, sig);
  } catch {
    return false;
  }
}

const typed = (type, ...parts) => encodeFrame(0x2, Buffer.concat([Buffer.of(type), ...parts]));

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

const closeFrame = (code) => encodeFrame(0x8, Buffer.of(code >> 8, code & 255));

// ─── client frames ─────────────────────────────────────────────────────────
//
// Every socket reads client frames with one parser and one set of rules: RSV bits clear,
// a mask (RFC 6455 requires one from a client), lengths in their shortest encoding,
// control frames final and at most 125 bytes. A control or room socket takes whole binary
// frames up to MAX_CONTROL_PAYLOAD; a splice takes any data frame, fragments and all, of
// any size.
const CONTROL_FRAMES = { opcodes: [0x2, 0x8, 0x9, 0xA], whole: true, maxLen: MAX_CONTROL_PAYLOAD };
const SPLICE_FRAMES = { opcodes: [0x0, 0x1, 0x2, 0x8, 0x9, 0xA], whole: false, maxLen: Number.MAX_SAFE_INTEGER };

/** Reads masked client frames as they stream in, holding at most a header. A data frame
 *  comes out as `sink.head(b0, len)`, its payload unmasked in pieces through
 *  `sink.data(piece)`, then `sink.end()`; a control frame whole, through
 *  `sink.control(opcode, payload)`. A callback returning false stops the read. */
class FrameReader {
  constructor(sink, rules) {
    this.sink = sink;
    this.rules = rules;
    this.head = Buffer.alloc(14);
    this.have = 0;           // header bytes held
    this.need = 2;           // header bytes wanted
    this.left = -1;          // payload bytes still to come; -1 while in a header
    this.mask = Buffer.alloc(4);
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
        chunk.copy(this.head, this.have, off, off + take);
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
      const piece = chunk.subarray(off, off + n);
      for (let i = 0; i < n; i++) piece[i] ^= this.mask[(this.maskAt + i) & 3];
      this.maskAt += n; off += n; this.left -= n;
      if (this.control) { piece.copy(this.control, this.controlAt); this.controlAt += n; }
      else if (this.sink.data(piece) === false) return false;
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
      len = this.head.readUInt16BE(2);
      if (len < 126) return false;
    } else if (len === 127) {
      const big = this.head.readBigUInt64BE(2);
      if (big < 65536n || big > BigInt(Number.MAX_SAFE_INTEGER)) return false;
      len = Number(big);
    }
    if (len > this.rules.maxLen) return false;
    this.head.copy(this.mask, 0, this.need - 4, this.need);
    this.maskAt = 0;
    this.opcode = opcode;
    this.left = len;
    if (control) {
      this.control = Buffer.alloc(len);
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

// ─── rooms ─────────────────────────────────────────────────────────────────
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

class Room {
  constructor(relay, id) {
    this.relay = relay;
    this.id = id;              // hex
    this.idBytes = Buffer.from(id, "hex");
    this.conns = new Set();    // the room sockets seated here
  }

  seats(addr) {
    let n = 0;
    for (const c of this.conns) if (c.addr === addr) n++;
    return n;
  }

  holds(key) {
    for (const c of this.conns) if (c.key === key) return true;
    return false;
  }

  /** A socket takes its seat: it gets the room's other keys, and they get its key unless
   *  another socket already holds it here. */
  join(conn) {
    const known = new Map();
    for (const c of this.conns) if (c.key !== conn.key) known.set(c.key, c.pk);
    const already = this.holds(conn.key);
    this.conns.add(conn);
    if (!conn.send(typed(T_MEMBERS, this.idBytes, ...known.values()))) return false;
    if (!already) this.tell(T_JOINED, conn);
    return true;
  }

  /** A socket leaves; when it held the last seat for its key, the rest hear so. */
  leave(conn) {
    const seated = this.conns.delete(conn);
    if (this.conns.size === 0) this.relay.rooms.delete(this.id);
    else if (seated && !this.holds(conn.key)) this.tell(T_LEFT, conn);
  }

  tell(type, conn) {
    const frame = typed(type, this.idBytes, conn.pk);
    for (const c of this.conns) if (c.key !== conn.key) c.send(frame);
  }
}

// ─── control and room sockets ──────────────────────────────────────────────

class ControlConn {
  constructor(relay, sock, addr, authority, forRooms) {
    this.relay = relay;
    this.sock = sock;
    this.addr = addr;          // the client address, as accounted
    this.forRooms = forRooms;  // a room socket, rather than a node's control socket
    this.rooms = new Map();    // room id hex to the Room it holds a seat in
    this.authority = authority;
    this.nonce = randomBytes(NONCE_LEN);
    this.key = null;           // hex, once registered
    this.pk = null;            // and its bytes
    this.alive = true;         // cleared each heartbeat, set on pong
    this.closing = false;      // told to go: nothing more it sends is read
    this.bytes = new Bucket(relay.clock, 256 * 1024);
    this.frames = new Bucket(relay.clock, 128);
    this.reader = new FrameReader(this, CONTROL_FRAMES);
    this.frame = null;         // a data frame's payload as it arrives
    this.frameAt = 0;
    this.registerTimer = later(relay.clock, () => sock.destroy(), HANDSHAKE_TIMEOUT_MS);
    sock.on("data", (chunk) => this.onData(chunk));
    sock.once("close", () => this.onClose());
    this.send(typed(T_CHALLENGE, this.nonce));
  }

  send(frame) { return writeFrame(this.sock, frame); }

  onData(chunk) {
    if (this.sock.destroyed || this.closing) return;
    if (!this.bytes.spend(chunk.length) || !this.relay.incomingBytes.spend(chunk.length) ||
        (!this.reader.push(chunk) && !this.closing)) this.sock.destroy();
  }

  /** Every whole frame, control or data, is charged before it is acted on. */
  counted() {
    if (this.frames.spend(1) && this.relay.incomingFrames.spend(1)) return true;
    this.sock.destroy();
    return false;
  }

  head(_b0, len) { this.frame = Buffer.alloc(len); this.frameAt = 0; }
  data(piece) { piece.copy(this.frame, this.frameAt); this.frameAt += piece.length; }

  end() {
    const payload = this.frame;
    this.frame = null;
    return this.counted() && this.onMessage(payload);
  }

  control(opcode, payload) {
    if (!this.counted()) return false;
    if (opcode === 0x8) { this.sock.destroy(); return false; }
    if (opcode === 0x9) return this.send(encodeFrame(0xA, payload));
    this.alive = true;
    return true;
  }

  /** False once the socket is torn down, which stops the read. */
  onMessage(payload) {
    const type = payload[0], body = payload.subarray(1);
    if (type === T_REGISTER && (body.length === PK_LEN + SIG_LEN || body.length === PK_LEN + SIG_LEN + MAC_LEN) &&
        !this.key) {
      const sigEnd = PK_LEN + SIG_LEN;
      return this.register(body.subarray(0, PK_LEN), body.subarray(PK_LEN, sigEnd), body.subarray(sigEnd));
    }
    const rooms = this.key && this.forRooms, calls = this.key && !this.forRooms;
    if (type === T_JOIN && body.length === ROOM_LEN && rooms) return this.join(body);
    if (type === T_LEAVE && body.length === ROOM_LEN && rooms) return this.leave(body.toString("hex"));
    if (type === T_CALL && body.length === PK_LEN + TICKET_LEN && calls) {
      return this.call(body.subarray(0, PK_LEN), body.subarray(PK_LEN));
    }
    // Anything else, including a join or a call before registering or on the other kind
    // of socket, is not this wire.
    this.relay.log("! dropped: unexpected control frame");
    this.sock.destroy();
    return false;
  }

  register(pk, sig, mac) {
    const { relay } = this;
    if (!relay.admits(pk, sig, mac)) {
      relay.log("! dropped: no secret");
      this.sock.destroy();
      return false;
    }
    if (!verifyRegistration(this.forRooms, pk, sig, this.authority, this.nonce)) {
      relay.log("! dropped: bad registration");
      this.sock.destroy();
      return false;
    }
    relay.clock.clearTimeout(this.registerTimer);
    this.pk = Buffer.from(pk);
    this.key = this.pk.toString("hex");
    if (!this.forRooms) relay.route(this);
    return this.send(typed(T_REGISTER));
  }

  join(idBytes) {
    const { relay } = this, { limits } = relay, id = idBytes.toString("hex");
    if (this.rooms.has(id)) return true;
    let room = relay.rooms.get(id) ?? null;
    const refusal = this.rooms.size >= MAX_ROOMS_PER_CONN ? "rooms per socket"
      : !room && relay.rooms.size >= limits.maxRooms ? `room table full (${relay.rooms.size} rooms)`
      : room && room.conns.size >= limits.maxPerRoom ? "room full"
      : room && room.seats(this.addr) >= limits.maxPerRoomIp ? "per-ip room cap"
      : relay.joins && !relay.joins.get(this.addr).spend(1) ? "join rate" : null;
    if (refusal) {
      relay.log(`! refused join: ${refusal}`);
      return this.send(typed(T_REFUSED, idBytes));
    }
    if (!room) relay.rooms.set(id, room = new Room(relay, id));
    // Held before any write, so a socket that fails one leaves the room.
    this.rooms.set(id, room);
    relay.log(`+ member (${room.conns.size + 1} in room, ${relay.rooms.size} rooms)`);
    return room.join(this);
  }

  leave(id) {
    const room = this.rooms.get(id);
    if (!room) return true;
    this.rooms.delete(id);
    room.leave(this);
    this.relay.log(`- member (${room.conns.size} in room, ${this.relay.rooms.size} rooms)`);
    return true;
  }

  call(to, ticket) {
    const callee = this.relay.routeFor(to.toString("hex"));
    // No such key here, the caller's own, too many calls from this address, or a ticket
    // already in use: the caller learns now instead of waiting its splice socket out.
    const splice = callee && callee.key !== this.key ? this.relay.openSplice(this, callee.key, ticket) : null;
    if (!splice) return this.send(typed(T_UNREACHABLE, to, ticket));
    callee.send(typed(T_CALL, this.pk, Buffer.from(splice.calleeTicket, "hex")));
    return true;
  }

  beat() {
    if (!this.alive) { this.sock.destroy(); return; }
    this.alive = false;
    this.send(PING);
  }

  shutdown(code) {
    this.closing = true;
    this.send(closeFrame(code));
    endSoon(this.relay.clock, this.sock);
  }

  onClose() {
    this.relay.clock.clearTimeout(this.registerTimer);
    this.relay.unroute(this);
    for (const id of [...this.rooms.keys()]) this.leave(id);
  }
}

// ─── splices ───────────────────────────────────────────────────────────────
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

class Splice {
  constructor(relay, from, calleeKey, ticket) {
    this.relay = relay;
    this.from = from;                    // the caller's address, which both ends are charged to
    this.pair = `${from} ${calleeKey}`;
    this.ticket = ticket;
    this.calleeTicket = randomBytes(TICKET_LEN).toString("hex");
    this.ends = { caller: null, callee: null };
    this.live = 0;                       // sockets that came and have not closed
    this.over = false;                   // joined or expired: its tickets are spent
    relay.pending.set(ticket, { splice: this, role: "caller" });
    relay.pending.set(this.calleeTicket, { splice: this, role: "callee" });
    bump(relay.callsFrom, from, 1);
    bump(relay.splicesTo, this.pair, 1);
    this.timer = later(relay.clock, () => this.expire(), SPLICE_WAIT_MS);
  }

  attach(end) {
    this.ends[end.role] = end;
    this.live++;
    if (this.ends.caller && this.ends.callee) this.join();
  }

  detach(end) {
    this.live--;
    if (!this.over) this.ends[end.role] = null;
    else if (this.live === 0) this.release();
  }

  settle() {
    this.over = true;
    this.relay.pending.delete(this.ticket);
    this.relay.pending.delete(this.calleeTicket);
    this.relay.clock.clearTimeout(this.timer);
    bump(this.relay.callsFrom, this.from, -1);
  }

  expire() {
    if (this.over) return;
    this.settle();
    if (this.live === 0) this.release();
    for (const end of Object.values(this.ends)) end?.sock.destroy();
  }

  /** Called once, when it is over and its last socket gone: nothing attaches once over. */
  release() {
    bump(this.relay.splicesTo, this.pair, -1);
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
  constructor(relay, sock, addr, splice, role, head) {
    this.relay = relay;
    this.sock = sock;
    this.addr = addr;          // where it connects from, whose budget its sends are metered on
    this.splice = splice;
    this.role = role;
    this.far = null;           // the other end, once joined
    this.linked = false;       // joined, and the far end has not closed
    this.mid = false;          // a frame forwarded to this socket is partly written
    this.alive = true;         // cleared each heartbeat, set on pong or on anything sent
    this.holds = 1;            // paused until joined
    this.waiting = false;      // held until the far end drains
    this.metered = false;      // held until its address's budget recovers
    this.early = head?.length ? Buffer.from(head) : null; // what came with the upgrade
    this.reader = new FrameReader(this, SPLICE_FRAMES);
    sock.pause();
    sock.once("close", () => this.onClose());
    relay.spliceSockets++;
    splice.attach(this);
  }

  link(far) {
    this.far = far;
    this.linked = true;
    this.sock.on("data", (chunk) => this.take(chunk));
    if (this.early) this.take(this.early);
    this.early = null;
    this.release();
  }

  hold() { if (this.holds++ === 0) this.sock.pause(); }
  release() { if (--this.holds === 0) this.sock.resume(); }

  take(chunk) {
    this.alive = true;
    if (!this.reader.push(chunk)) { this.sock.destroy(); this.far.sock.destroy(); return; }
    this.relay.meter(this, chunk.length);
  }

  /** Write to the far end; a far end that cannot take more holds this one until it drains. */
  forward(bytes) {
    const dst = this.far.sock;
    if (dst.destroyed || !dst.writable) return;
    if (!dst.write(bytes) && !this.waiting) {
      this.waiting = true;
      this.hold();
      dst.once("drain", () => { this.waiting = false; this.release(); });
    }
  }

  // Data frames are copied to the far end as server frames, streaming: a frame's header
  // goes out as soon as it is parsed and its payload as it arrives, so the relay holds a
  // chunk, never a whole message. Control frames stay on the hop: a ping is answered, a
  // close ends both ends once forwarded.
  head(b0, len) {
    this.forward(frameHead(b0, len));
    this.far.mid = len > 0;
  }

  data(piece) { this.forward(piece); }
  end() { this.far.mid = false; }

  control(opcode, payload) {
    if (opcode === 0x9) { if (!this.mid) writeFrame(this.sock, encodeFrame(0xA, payload)); }
    else if (opcode === 0x8) {
      if (!this.far.mid) this.forward(encodeFrame(0x8, payload));
      endSoon(this.relay.clock, this.sock);
      endSoon(this.relay.clock, this.far.sock);
    }
  }

  /** Pinged only while joined and between the frames forwarded to it. */
  beat() {
    if (!this.linked || this.mid) return;
    if (!this.alive) { this.sock.destroy(); return; }
    this.alive = false;
    writeFrame(this.sock, PING);
  }

  shutdown(code) {
    if (!this.mid) writeFrame(this.sock, closeFrame(code));
    endSoon(this.relay.clock, this.sock);
  }

  onClose() {
    this.relay.spliceSockets--;
    this.linked = false;
    if (this.far?.linked) {
      this.far.linked = false;
      endSoon(this.relay.clock, this.far.sock);
    }
    this.splice.detach(this);
  }
}

const PING = encodeFrame(0x9, Buffer.alloc(0));

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

// ─── the relay ───────────────────────────────────────────────────────────

// A relay with secrets takes a registration only with the MAC
//   BLAKE2b-512(DOMAIN_SECRET ‖ pk ‖ sig ‖ secret)
// after its signature, which binds it to the socket's nonce and key. BLAKE2b cannot be
// length-extended, so hashing the secret in makes a MAC; unkeyed, as Node has no keyed
// BLAKE2b. A relay without secrets ignores a MAC. The README's wire section has the rest.
function secretProof(secret, pk, sig) {
  return createHash("blake2b512").update(DOMAIN_SECRET).update(pk).update(sig).update(secret).digest();
}

/** A relay: `server` is an HTTP server to listen with; `connection` and `upgrade` are its
 *  handlers, which a test may drive with its own sockets. `authorities` holds the
 *  host[:port] names nodes may register under, and can be filled in once the port is
 *  known. `close` tells every socket the relay is restarting. */
export function createRelay(options = {}) {
  return new Relay(options);
}

class Relay {
  constructor({ authorities = [], allowOrigins = [], trustedProxies = [], secrets = [], limits = {}, clock = realClock,
    log = (line) => console.log(line) } = {}) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
    this.clock = clock;
    this.log = log;
    this.authorities = new Set(authorities.map(canonicalAuthority));
    this.origins = new Set(allowOrigins.length ? allowOrigins : LOCAL_ORIGINS);
    this.proxies = new Set(trustedProxies.map(proxyOption));
    this.secrets = secrets.map((secret) => Buffer.from(secret));

    // Every accepted TCP socket, to `{ account, timer, conn }`: the address it is charged
    // to (none for a trusted proxy before its client is known), its handshake deadline,
    // and its ControlConn or SpliceEnd once upgraded. `charges` counts sockets by address.
    this.connections = new Map();
    this.charges = new Map();
    this.rooms = new Map();
    this.routes = new Map();     // key hex to its registered control sockets, the latest last
    this.pending = new Map();    // ticket hex to `{ splice, role }` until joined or expired
    this.callsFrom = new Map();  // caller address to its calls waiting
    this.splicesTo = new Map();  // caller address and callee key to their splices, waiting or joined
    this.spliceSockets = 0;      // upgraded splice sockets, against their SPLICE_SHARE

    // Global budgets survive reconnects and room turnover.
    this.incomingBytes = new Bucket(clock, 4 * 1024 * 1024);
    this.incomingFrames = new Bucket(clock, 8192);
    const { registerRate, spliceRate, heartbeatSecs } = this.limits;
    this.registrations = registerRate > 0 ? new AddressBudgets(clock, registerRate) : null;
    this.joins = registerRate > 0 ? new AddressBudgets(clock, registerRate, Math.max(2 * registerRate, JOIN_BURST)) : null;
    this.spliceBudgets = spliceRate > 0 ? new AddressBudgets(clock, spliceRate * 1024) : null;
    this.stunBudgets = new AddressBudgets(clock, STUN_RATE);
    this.stunNewAddresses = new Bucket(clock, STUN_NEW_RATE);

    // NAT and firewall timeouts leave half-open sockets that never emit 'close', so
    // without a liveness probe a dropped peer would hold its room and address slots
    // forever. Each interval every upgraded socket is pinged, and one that did not answer
    // the previous ping is presumed dead and destroyed.
    this.heartbeat = null;
    if (heartbeatSecs > 0) {
      this.heartbeat = clock.setInterval(() => {
        for (const { conn } of this.connections.values()) conn?.beat();
      }, heartbeatSecs * 1000);
      this.heartbeat.unref?.();
    }

    this.server = createServer((_req, res) => {
      res.writeHead(426, { "Content-Type": "text/plain", "Connection": "close" });
      res.end("seedrelay: connect a WebSocket to ws://<host>:<port>/v1/\n");
    });
    this.server.on("connection", (sock) => this.connection(sock));
    this.server.on("upgrade", (req, sock, head) => this.upgrade(req, sock, head));
  }

  /** Move a socket's charge to `addr` (null for none). False, charging nothing, when
   *  that address already has its share. */
  bill(entry, addr) {
    if (entry.account === addr) return true;
    if (addr !== null && (this.charges.get(addr) ?? 0) >= this.limits.maxPerIp) return false;
    if (entry.account !== null) bump(this.charges, entry.account, -1);
    if (addr !== null) bump(this.charges, addr, 1);
    entry.account = addr;
    return true;
  }

  // Walk from the actual remote address toward the client, stopping at the first
  // untrusted hop. Never trust a client-supplied leftmost XFF value.
  clientIp(req, sock) {
    let ip = normalizeIp(sock.remoteAddress ?? "") ?? "unknown";
    if (this.proxies.has(ip)) {
      const xff = req.headers["x-forwarded-for"];
      if (typeof xff !== "string" || !xff) return null;
      const chain = xff.split(",").map((part) => normalizeIp(part.trim()));
      if (chain.some((part) => part === null)) return null;
      for (let i = chain.length - 1; i >= 0 && this.proxies.has(ip); i--) ip = chain[i];
    }
    return ip;
  }

  // Refuse an upgrade with a short HTTP error and tear the socket down, before the
  // protocol switch, so a refused client never holds a room seat or a frame buffer.
  refuse(sock, status, note) {
    try {
      sock.write(`HTTP/1.1 ${status} ${REFUSALS[status]}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    } catch { /* socket already gone */ }
    sock.destroy();
    this.log(`! refused upgrade: ${note}`);
  }

  // Account for TCP sockets before any HTTP headers arrive. Trusted proxies share the
  // global cap here; their forwarded clients are charged at upgrade.
  connection(sock) {
    const ip = normalizeIp(sock.remoteAddress ?? "") ?? "unknown";
    const entry = { account: null, timer: null, conn: null };
    if (this.connections.size >= this.limits.maxConns ||
        (!this.proxies.has(ip) && !this.bill(entry, addressKey(ip, this.limits.ipv6Prefix)))) {
      sock.destroy();
      return;
    }
    entry.timer = later(this.clock, () => sock.destroy(), HANDSHAKE_TIMEOUT_MS);
    this.connections.set(sock, entry);
    sock.on("error", () => sock.destroy());
    sock.once("close", () => {
      this.clock.clearTimeout(entry.timer);
      this.connections.delete(sock);
      this.bill(entry, null);
    });
  }

  upgrade(req, sock, head) {
    const entry = this.connections.get(sock);
    if (!entry || entry.conn || sock.destroyed) { sock.destroy(); return; }
    const key = req.headers["sec-websocket-key"];
    if (req.method !== "GET" || req.headers.upgrade?.toLowerCase() !== "websocket" ||
        req.headers["sec-websocket-version"] !== "13" ||
        typeof key !== "string" || !/^[A-Za-z0-9+/]{22}==$/.test(key) ||
        Buffer.from(key, "base64").length !== 16) { sock.destroy(); return; }

    // A browser names the page that opened a socket in Origin, and every socket a page
    // opens counts against its visitor's address. The allowlist says which pages may
    // spend visitors' budgets here, so a hostile page cannot use its visitors to fill the
    // relay or lock them out of it. It is not authentication: the relay has no cookies or
    // ambient credentials to hijack, and a native client (a seedkernel node, `websocat`)
    // sends no Origin at all and is accepted.
    const origin = req.headers["origin"];
    if (typeof origin === "string" && origin && !this.origins.has(origin)) {
      this.refuse(sock, 403, "origin not allowed");
      return;
    }

    const target = targetFromUrl(typeof req.url === "string" ? req.url : "/");
    if (typeof target === "number") {
      this.refuse(sock, target, target === 404 ? "not a path of the wire this relay speaks" : "bad ticket");
      return;
    }
    const ip = this.clientIp(req, sock);
    if (ip === null) { this.refuse(sock, 400, "invalid proxy address chain"); return; }
    const addr = addressKey(ip, this.limits.ipv6Prefix);

    if (target.splice !== null) {
      // A splice socket needs a ticket a call handed out, and is charged to its caller.
      const waiting = this.pending.get(target.splice);
      if (!waiting) { this.refuse(sock, 404, "no such splice"); return; }
      if (waiting.splice.ends[waiting.role]) { this.refuse(sock, 409, "splice end already taken"); return; }
      if (this.spliceSockets >= Math.floor(this.limits.maxConns * SPLICE_SHARE)) {
        this.refuse(sock, 503, "splices at their share of the relay");
        return;
      }
      if (!this.bill(entry, waiting.splice.from)) { this.refuse(sock, 429, "per-ip cap"); return; }
      this.accept(sock, entry, key);
      entry.conn = new SpliceEnd(this, sock, addr, waiting.splice, waiting.role, head);
      return;
    }

    const host = req.headers.host;
    const authority = typeof host === "string" ? canonicalAuthority(host) : "";
    if (!this.authorities.has(authority)) { this.refuse(sock, 421, "not a name this relay answers to"); return; }
    if (!this.bill(entry, addr)) { this.refuse(sock, 429, "per-ip cap"); return; }
    if (this.registrations && !this.registrations.get(addr).spend(1)) {
      this.refuse(sock, 429, "registration rate");
      return;
    }
    this.accept(sock, entry, key);
    entry.conn = new ControlConn(this, sock, addr, authority, target.rooms);
    // Node may deliver the first frame with the HTTP upgrade request.
    if (head?.length) entry.conn.onData(head);
  }

  accept(sock, entry, key) {
    const accept = createHash("sha1").update(key + GUID).digest("base64");
    sock.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    this.clock.clearTimeout(entry.timer);
  }

  /** Whether a registration's MAC shows it knows one of the secrets, if there are any. */
  admits(pk, sig, mac) {
    if (this.secrets.length === 0) return true;
    return mac.length === MAC_LEN && this.secrets.some((secret) => timingSafeEqual(secretProof(secret, pk, sig), mac));
  }

  route(conn) {
    const list = this.routes.get(conn.key);
    if (list) list.push(conn); else this.routes.set(conn.key, [conn]);
  }

  /** The socket calls for `key` go to: the latest registration still open. */
  routeFor(key) {
    return this.routes.get(key)?.at(-1) ?? null;
  }

  unroute(conn) {
    const list = this.routes.get(conn.key);
    const i = list ? list.indexOf(conn) : -1;
    if (i < 0) return;
    list.splice(i, 1);
    if (list.length === 0) this.routes.delete(conn.key);
  }

  openSplice(caller, calleeKey, ticket) {
    const hex = ticket.toString("hex"), pair = `${caller.addr} ${calleeKey}`;
    if (this.pending.has(hex) || (this.callsFrom.get(caller.addr) ?? 0) >= this.limits.maxPerRoom ||
        (this.splicesTo.get(pair) ?? 0) >= MAX_SPLICES_PER_CALLEE) return null;
    return new Splice(this, caller.addr, calleeKey, hex);
  }

  /** The answer to a datagram on the STUN port from `address`:`port`, or null. */
  stun(msg, address, port) {
    const ip = normalizeIp(address);
    if (!ip) return null;
    const addr = addressKey(ip, this.limits.ipv6Prefix);
    if (!this.stunBudgets.has(addr) && !this.stunNewAddresses.spend(1)) return null;
    if (!this.stunBudgets.get(addr).spend(1)) return null;
    return stunResponse(msg, ip, port);
  }

  // What an address sends through its splices is metered, spliceRate KiB/s with two
  // seconds of burst. Past it, the address's splice sockets are not read until the debt
  // is paid back, so a sender is slowed, not cut off.
  meter(end, n) {
    if (!this.spliceBudgets) return;
    const b = this.spliceBudgets.get(end.addr);
    b.charge(n);
    if (b.tokens >= 0 || end.metered) return;
    end.metered = true;
    end.hold();
    later(this.clock, () => { end.metered = false; end.release(); }, -b.tokens * 1000 / b.rate);
  }

  /** Tell every socket the relay is restarting (close code 1012) and end it, and drop
   *  those still mid-handshake. The caller closes `server`. */
  close() {
    if (this.heartbeat) this.clock.clearInterval(this.heartbeat);
    for (const [sock, { conn }] of [...this.connections]) {
      if (conn) conn.shutdown(CLOSE_RESTART); else sock.destroy();
    }
  }
}
