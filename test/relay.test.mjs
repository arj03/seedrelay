import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import { request } from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { createSocket } from "node:dgram";
import { createRelay, localAuthorities, parseOptions, stunResponse } from "../relay.mjs";
import { roomClient } from "../rooms.mjs";

const SERVER = fileURLToPath(new URL("../server.mjs", import.meta.url));

// The relay's handlers driven with a controlled clock and fake sockets, so slow readers,
// exact budget boundaries and timeouts are deterministic.
class Socket extends EventEmitter {
  writable = true;
  writableLength = 0;
  destroyed = false;
  ended = false;
  paused = false;
  full = false;       // a slow reader: writes report the buffer full until `drain`
  writes = [];
  write(bytes) { this.writes.push(Buffer.from(bytes)); return !this.full; }
  pause() { this.paused = true; }
  resume() { this.paused = false; }
  end() { this.ended = true; }
  drain() { this.full = false; this.emit("drain"); }
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true; this.writable = false; this.emit("close");
  }
}
/** A relay answering to relay.test unless `args` name its authorities. */
function fixture(args = []) {
  const logs = [], timers = new Set(), intervals = new Set();
  let now = 0;
  const clock = {
    now: () => now,
    setTimeout(fn, ms) { const t = { fn, at: now + ms, unref() {} }; timers.add(t); return t; },
    clearTimeout: (t) => timers.delete(t),
    setInterval(fn) { const t = { fn, unref() {} }; intervals.add(t); return t; },
    clearInterval: (t) => intervals.delete(t),
  };
  const options = parseOptions(args);
  if (options.authorities.length === 0) options.authorities.push("relay.test");
  const relay = createRelay({ ...options, clock, log: (s) => logs.push(s) });
  function tcp(address = "127.0.0.1") {
    const s = new Socket(); s.remoteAddress = address;
    relay.connection(s); return s;
  }
  function upgrade(s, { path = "/v1/", headers = {}, head } = {}) {
    relay.upgrade({ method: "GET", url: path, headers: {
      upgrade: "websocket", "sec-websocket-version": "13", host: "relay.test",
      "sec-websocket-key": "AAAAAAAAAAAAAAAAAAAAAA==", ...headers,
    } }, s, head);
    return s;
  }
  const join = (options, address) => upgrade(tcp(address), options);
  /** A control socket that has registered `id` (a fresh one by default). */
  function member(options = {}, id = identity(), address) {
    const s = join(options, address);
    s.emit("data", frame(2, registration(id, "relay.test", challenge(s))));
    s.id = id;
    return s;
  }
  /** A room socket that has registered `id` and joined `room`, or no room for null. */
  function roomMember({ room = "room", ...options } = {}, id = identity(), address) {
    const s = join({ path: "/v1/rooms", ...options }, address);
    s.emit("data", frame(2, roomRegistration(id, "relay.test", challenge(s))));
    if (room !== null) s.emit("data", joinRoom(room));
    s.id = id;
    return s;
  }
  /** Call `b` from `a` and open both ends of the splice: [the caller's, the callee's]. */
  function splice(a, b, { callerAddress, calleeAddress } = {}) {
    const ticket = randomBytes(16);
    a.emit("data", call(b.id.pk, ticket));
    return [join({ path: splicePath(ticket.toString("hex")) }, callerAddress),
      join({ path: splicePath(calleeTicket(b)) }, calleeAddress)];
  }
  return { relay, tcp, upgrade, logs, join, member, roomMember, splice,
    beat() { for (const t of [...intervals]) t.fn(); },
    /** Move the clock on, firing each timer due by then at its own time. */
    advance(ms) {
      const until = now + ms;
      for (;;) {
        let next = null;
        for (const t of timers) if (t.at <= until && (!next || t.at < next.at)) next = t;
        if (!next) break;
        timers.delete(next);
        now = Math.max(now, next.at);
        next.fn();
      }
      now = until;
    },
  };
}
/** A client frame: masked, as RFC 6455 requires. */
function frame(opcode, payload = Buffer.alloc(0), mask = Buffer.from([1, 2, 3, 4])) {
  const h = Buffer.alloc(payload.length < 126 ? 6 : payload.length < 65536 ? 8 : 14);
  h[0] = 0x80 | opcode;
  h[1] = 0x80 | (h.length === 6 ? payload.length : h.length === 8 ? 126 : 127);
  if (h.length === 8) h.writeUInt16BE(payload.length, 2);
  if (h.length === 14) h.writeBigUInt64BE(BigInt(payload.length), 2);
  mask.copy(h, h.length - 4);
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3];
  return Buffer.concat([h, body]);
}
/** The server frames written to a fake socket after its 101 response. */
function serverFrames(sock) {
  const bytes = Buffer.concat(sock.writes.slice(1));
  const out = [];
  for (let off = 0; off + 2 <= bytes.length;) {
    let len = bytes[off + 1] & 0x7f, h = 2;
    if (len === 126) { len = bytes.readUInt16BE(off + 2); h = 4; }
    else if (len === 127) { len = Number(bytes.readBigUInt64BE(off + 2)); h = 10; }
    if (off + h + len > bytes.length) break;
    out.push({ b0: bytes[off], opcode: bytes[off] & 0x0f, payload: bytes.subarray(off + h, off + h + len) });
    off += h + len;
  }
  return out;
}
const status = (sock) => Number(/^HTTP\/1\.1 (\d+)/.exec(sock.writes[0]?.toString() ?? "")?.[1]);
const typed = (sock) => serverFrames(sock).filter((f) => f.opcode === 2).map((f) => f.payload);
const ofType = (sock, type) => typed(sock).filter((p) => p[0] === type);
const challenge = (sock) => typed(sock)[0].subarray(1);
const calleeTicket = (sock) => ofType(sock, 0x05).at(-1).subarray(33).toString("hex");
const splicePath = (hex) => `/v1/?splice=${hex}`;
const closeCode = (sock) => serverFrames(sock).filter((f) => f.opcode === 8).map((f) => f.payload.readUInt16BE(0)).at(-1);

function identity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pk: publicKey.export({ format: "der", type: "spki" }).subarray(12), key: privateKey };
}
const DOMAINS = Buffer.from("seedkernel-link-scope-v1\0seedkernel-relay-register-v1\0");
function registration(id, authority, nonce) {
  const sig = sign(null, Buffer.concat([DOMAINS, Buffer.from(authority), nonce]), id.key);
  return Buffer.concat([Buffer.of(1), id.pk, sig]);
}
/** A room socket's registration: the app signs under the rooms tag itself. */
function roomRegistration(id, authority, nonce) {
  const sig = sign(null, Buffer.concat([Buffer.from("seedrelay-rooms-v1\0"), Buffer.from(authority), nonce]), id.key);
  return Buffer.concat([Buffer.of(1), id.pk, sig]);
}
const call = (to, ticket) => frame(2, Buffer.concat([Buffer.of(5), to, ticket]));
/** A room's id, as a node would name it: any 32 bytes do. */
const roomId = (name) => createHash("sha256").update(name).digest();
const joinRoom = (name) => frame(2, Buffer.concat([Buffer.of(2), roomId(name)]));
const leaveRoom = (name) => frame(2, Buffer.concat([Buffer.of(3), roomId(name)]));
/** A members, joined or left frame's payload for `room`. */
const roomFrame = (type, room, ...pks) => Buffer.concat([Buffer.of(type), roomId(room), ...pks]);

test("a node registers by signing the nonce for a name this relay answers to", () => {
  const f = fixture(), id = identity();
  const good = f.join({ headers: { host: "Relay.Test:443" } });
  assert.equal(typed(good)[0][0], 0x00);
  assert.equal(challenge(good).length, 32);
  good.emit("data", frame(2, registration(id, "relay.test", challenge(good))));
  assert.equal(good.destroyed, false);
  assert.deepEqual([...typed(good)[1]], [0x01]);

  const replay = f.join();
  replay.emit("data", frame(2, registration(id, "relay.test", challenge(good))));
  assert.equal(replay.destroyed, true, "a signature over another socket's nonce");
  const elsewhere = f.join();
  elsewhere.emit("data", frame(2, registration(id, "other.test", challenge(elsewhere))));
  assert.equal(elsewhere.destroyed, true, "a signature for another relay");
  const late = f.join();
  f.advance(10_000);
  assert.equal(late.destroyed, true, "no registration in time");
  const early = f.join();
  early.emit("data", call(id.pk, randomBytes(16)));
  assert.equal(early.destroyed, true, "a call before registering");
});

test("a Host this relay does not answer to is refused, so no relay can pass another's nonce through", () => {
  // Relay A takes a nonce from B, has one of its own visitors sign it for a.test, and
  // presents the signature to B as Host a.test.
  const b = fixture(["--authority", "b.test"]), visitor = identity();
  const posing = b.join({ headers: { host: "a.test" } });
  assert.equal(posing.destroyed, true);
  assert.equal(status(posing), 421);
  assert.equal(posing.writes.length, 1, "it never gets a nonce");
  assert.equal(status(b.join({ headers: { host: undefined } })), 421, "nor does a socket with no Host");
  const own = b.join({ headers: { host: "B.test:80" } });
  own.emit("data", frame(2, registration(visitor, "b.test", challenge(own))));
  assert.equal(ofType(own, 0x01).length, 1, "registered");
});

test("with no --authority a relay answers to the names of the address it is bound to, if it has one", () => {
  assert.deepEqual(localAuthorities("127.0.0.1", 8080), ["localhost:8080", "127.0.0.1:8080", "[::1]:8080"]);
  assert.deepEqual(localAuthorities("192.0.2.1", 80), ["192.0.2.1"]);
  assert.deepEqual(localAuthorities("2001:db8::1", 8443), ["[2001:db8::1]:8443"]);
});

test("malformed or unknown options fail at startup instead of falling back", () => {
  for (const args of [["--max-conns", "lots"], ["--max-conns", "-1"], ["--max-conns", "1.5"], ["--max-conns"],
    ["--ipv6-prefix", "129"], ["--port", "70000"], ["--frobnicate"], ["--trust-proxy"],
    ["--trusted-proxy", "bogus"], ["--authority", "wss://relay.example"]]) {
    assert.throws(() => parseOptions(args), Error, args.join(" "));
  }
  assert.throws(() => parseOptions([], { RELAY_MAX_CONNS: "many" }), /RELAY_MAX_CONNS/);
  const o = parseOptions(["9000", "--splice-rate", "0.5", "--authority", "Relay.Example:443"], { RELAY_MAX_CONNS: "10" });
  assert.equal(o.port, 9000);
  assert.equal(o.limits.spliceRate, 0.5);
  assert.equal(o.limits.maxConns, 10);
  assert.deepEqual(o.authorities, ["relay.example"]);
  assert.throws(() => parseOptions(["--host", "0.0.0.0"]), /--authority/, "a wildcard bind has no name of its own");
  assert.equal(parseOptions(["--host", "::", "--authority", "relay.lan:8080"]).host, "::");
  assert.deepEqual(parseOptions(["--stun", "3478"]).stun, { host: "127.0.0.1", port: 3478 }, "on --host unless named");
  assert.deepEqual(parseOptions(["--stun", "[::]:3478"]).stun, { host: "::", port: 3478 });
  assert.throws(() => parseOptions(["--stun", "0.0.0.0:stun"]), /--stun/);
  const bin = spawnSync(process.execPath, [SERVER, "--max-conns", "lots"], { encoding: "utf8", windowsHide: true });
  assert.equal(bin.status, 2);
  assert.match(bin.stderr, /--max-conns/);
});

test("a path outside the wire version this relay speaks is refused", () => {
  const f = fixture();
  for (const path of ["/", "/room", "/v2/", "/v1/room", "/v1x", `/?splice=${"00".repeat(16)}`]) {
    const s = f.join({ path });
    assert.equal(s.destroyed, true, path);
    assert.equal(status(s), 404, path);
  }
  assert.equal(f.join({ path: "/v1" }).destroyed, false);
  assert.equal(f.join({ path: "/v1/" }).destroyed, false);
});

test("text frames, unknown types and a second registration drop the sender", () => {
  for (const bytes of [frame(1, Buffer.from("hi")), frame(2, Buffer.of(9)), frame(2, Buffer.alloc(0)), joinRoom("room")]) {
    const f = fixture(), s = f.join();
    s.emit("data", bytes);
    assert.equal(s.destroyed, true, bytes.toString("hex"));
  }
  const f = fixture(), s = f.member();
  s.emit("data", frame(2, registration(s.id, "relay.test", challenge(s))));
  assert.equal(s.destroyed, true);
});

test("a room's members are the keys joined to it, announced as they join and leave", () => {
  const f = fixture();
  const a = f.roomMember(), b = f.roomMember(), outsider = f.roomMember({ room: "other" }), roomless = f.roomMember({ room: null });
  assert.deepEqual(typed(b).at(-1), roomFrame(0x02, "room", a.id.pk), "the newcomer gets the room");
  assert.deepEqual(typed(a).at(-1), roomFrame(0x03, "room", b.id.pk), "the room gets the newcomer");
  assert.equal(typed(outsider).length, 3, "another room hears nothing");
  assert.equal(typed(roomless).length, 2, "a socket in no room gets no members");
  const heard = typed(a).length;
  const b2 = f.roomMember({}, b.id);
  assert.equal(typed(a).length, heard, "a second socket for the same key is not a new member");
  b.destroy();
  assert.equal(typed(a).length, heard, "the key is still in the room");
  b2.destroy();
  assert.deepEqual(typed(a).at(-1), roomFrame(0x04, "room", b.id.pk));
});

test("rooms and calls take separate sockets, so an app's rooms never draw a node's calls", () => {
  const f = fixture(), node = f.member(), app = f.roomMember({ room: null });
  node.emit("data", joinRoom("room"));
  assert.equal(node.destroyed, true, "a control socket joins no room");
  app.emit("data", call(f.member().id.pk, randomBytes(16)));
  assert.equal(app.destroyed, true, "a room socket places no call");
  const roomsOnly = f.roomMember(), caller = f.member();
  caller.emit("data", call(roomsOnly.id.pk, randomBytes(16)));
  assert.equal(typed(caller).at(-1)[0], 0x06, "a key on a room socket only cannot be called");
  const id = identity(), control = f.join();
  control.emit("data", frame(2, roomRegistration(id, "relay.test", challenge(control))));
  assert.equal(control.destroyed, true, "a room signature does not register a control socket");
  const rooms = f.join({ path: "/v1/rooms" });
  rooms.emit("data", frame(2, registration(id, "relay.test", challenge(rooms))));
  assert.equal(rooms.destroyed, true, "nor a control signature a room socket");
});

test("one socket joins and leaves several rooms", () => {
  const f = fixture(), a = f.roomMember(), b = f.roomMember({ room: "other" });
  a.emit("data", joinRoom("other"));
  assert.deepEqual(typed(a).at(-1), roomFrame(0x02, "other", b.id.pk), "a second room's members");
  assert.deepEqual(typed(b).at(-1), roomFrame(0x03, "other", a.id.pk));
  a.emit("data", joinRoom("other"));
  assert.deepEqual(typed(a).at(-1), roomFrame(0x02, "other", b.id.pk), "joining again is nothing new");
  a.emit("data", leaveRoom("other"));
  assert.deepEqual(typed(b).at(-1), roomFrame(0x04, "other", a.id.pk));
  assert.equal(a.destroyed, false);
  for (let i = 0; i < 16; i++) a.emit("data", joinRoom(`r${i}`));
  assert.deepEqual(typed(a).at(-1), roomFrame(0x07, "r15"), "a seventeenth room is refused");
  assert.equal(a.destroyed, false, "and only the join");
});

test("a room too big for one frame is sent over several", () => {
  const f = fixture(["--max-conns", "3000", "--max-per-room", "2000", "--max-per-ip", "3000",
    "--max-per-room-ip", "2000", "--register-rate", "0"]);
  const ids = Array.from({ length: 1025 }, () => identity());
  for (const id of ids) f.roomMember({}, id);
  const s = f.roomMember();
  const members = ofType(s, 0x02);
  assert.deepEqual(members.map((p) => (p.length - 33) / 32), [1024, 1]);
  assert.deepEqual(members[1].subarray(33), ids[1024].pk);
});

test("a call rings only the callee, with a ticket of its own, and joins the two ends", () => {
  const f = fixture();
  const a = f.member(), b = f.member(), c = f.member();
  const ticket = randomBytes(16), hex = ticket.toString("hex");
  a.emit("data", call(b.id.pk, ticket));
  const ring = ofType(b, 0x05).at(-1);
  assert.deepEqual(ring.subarray(0, 33), Buffer.concat([Buffer.of(0x05), a.id.pk]));
  assert.equal(ring.length, 49);
  assert.notEqual(calleeTicket(b), hex, "the callee's ticket is not the caller's");
  assert.equal(ofType(c, 0x05).length, 0, "no one else sees a ticket");

  const sa = f.join({ path: splicePath(hex), head: frame(2, Buffer.from("msg1")) });
  assert.equal(sa.paused, true, "a lone end waits");
  assert.equal(status(f.join({ path: splicePath(hex) })), 409, "a ticket opens its own end, once");
  const sb = f.join({ path: splicePath(calleeTicket(b)) });
  assert.equal(sa.paused, false);
  assert.deepEqual(serverFrames(sb).map((x) => x.payload.toString()), ["msg1"], "what came early is forwarded");
  sb.emit("data", frame(2, Buffer.from("msg2")));
  assert.deepEqual(serverFrames(sa).at(-1).payload.toString(), "msg2");
  assert.equal(status(f.join({ path: splicePath(hex) })), 404, "a joined splice's tickets are spent");
  assert.equal(status(f.join({ path: splicePath("00".repeat(16)) })), 404, "a ticket nobody was given is refused");
  assert.equal(status(f.join({ path: "/v1/?splice=zz" })), 400, "a malformed ticket is refused");
});

test("an unknown callee, the caller's own key or a reused ticket is unreachable at once", () => {
  const f = fixture();
  const a = f.member(), b = f.member(), ticket = randomBytes(16);
  a.emit("data", call(identity().pk, ticket));
  assert.equal(typed(a).at(-1)[0], 0x06);
  a.emit("data", call(a.id.pk, ticket));
  assert.equal(typed(a).at(-1)[0], 0x06, "a node cannot call itself");
  const a2 = f.member({}, a.id);
  a.emit("data", call(a.id.pk, ticket));
  assert.equal(typed(a).at(-1)[0], 0x06, "nor its own key on another socket");
  assert.equal(ofType(a2, 0x05).length, 0);
  a.emit("data", call(b.id.pk, ticket));
  a.emit("data", call(b.id.pk, ticket));
  assert.deepEqual(typed(a).at(-1), Buffer.concat([Buffer.of(0x06), b.id.pk, ticket]));
  assert.equal(a.destroyed, false);
});

test("the latest registration of a key takes its calls, and the one before takes over", () => {
  const f = fixture(), id = identity(), a = f.member();
  const old = f.member({}, id), latest = f.member({}, id);
  a.emit("data", call(id.pk, randomBytes(16)));
  assert.equal(typed(latest).at(-1)[0], 0x05);
  latest.destroy();
  a.emit("data", call(id.pk, randomBytes(16)));
  assert.equal(typed(old).at(-1)[0], 0x05);
});

test("splice frames stream through with any size, unmasked, fragments and all", () => {
  const f = fixture(), [sa, sb] = f.splice(f.member(), f.member());
  const big = randomBytes(300 * 1024);
  const bytes = frame(2, big);
  for (let off = 0; off < bytes.length; off += 7777) sa.emit("data", Buffer.from(bytes.subarray(off, off + 7777)));
  sa.emit("data", Buffer.concat([frame(0, Buffer.from("ab")).fill(0x02, 0, 1), frame(0, Buffer.from("cd"))]));
  const got = serverFrames(sb);
  assert.deepEqual(got[0].payload, big);
  assert.equal(got[1].b0, 0x02, "a fragment keeps its FIN and opcode");
  assert.deepEqual(got.slice(1).map((x) => x.payload.toString()), ["ab", "cd"]);
});

test("splice control frames stay on the hop, and a close ends both ends", () => {
  const f = fixture(), [sa, sb] = f.splice(f.member(), f.member());
  sa.emit("data", frame(9, Buffer.from("p")));
  assert.equal(serverFrames(sa).at(-1).opcode, 0xA, "a ping is answered by the relay");
  assert.equal(serverFrames(sb).length, 0, "and not forwarded");
  sa.emit("data", frame(8, Buffer.from([3, 232])));
  assert.equal(serverFrames(sb).at(-1).opcode, 8);
  assert.equal(sa.ended && sb.ended, true);
  sa.emit("data", frame(9, Buffer.alloc(200)));
  assert.equal(sa.destroyed, true, "an oversize control frame fails the splice");
});

test("one end closing ends the other, and an unjoined call expires", () => {
  const f = fixture(), a = f.member(), b = f.member();
  const [sa, sb] = f.splice(a, b);
  const t2 = randomBytes(16);
  a.emit("data", call(b.id.pk, t2));
  sa.destroy();
  assert.equal(sb.ended, true);
  f.advance(10_000);
  assert.equal(sb.destroyed, true, "a far end that never closes is given up on");
  assert.equal(status(f.join({ path: splicePath(t2.toString("hex")) })), 404, "the call expired unjoined");
});

test("calls are charged to the caller's address: a room's worth waiting, eight splices to a key", () => {
  const f = fixture(), a = f.member(), b = f.member();
  const rings = () => ofType(b, 0x05).length;
  for (let i = 0; i < 9; i++) a.emit("data", call(b.id.pk, randomBytes(16)));
  assert.equal(rings(), 8);
  assert.equal(typed(a).at(-1)[0], 0x06, "a ninth call to one key from one address is unreachable");
  f.member({}, identity(), "192.0.2.7").emit("data", call(b.id.pk, randomBytes(16)));
  assert.equal(rings(), 9, "another address still gets through");

  const g = fixture(), c = g.member(), d = g.member();
  const splices = Array.from({ length: 8 }, () => g.splice(c, d));
  c.emit("data", call(d.id.pk, randomBytes(16)));
  assert.equal(typed(c).at(-1)[0], 0x06, "joined splices count as waiting calls do");
  for (const end of splices[0]) end.destroy();
  c.emit("data", call(d.id.pk, randomBytes(16)));
  assert.equal(ofType(d, 0x05).length, 9, "a splice both ends have left is given back");

  const h = fixture(["--max-per-room", "2"]), e = h.member(), k = h.member(), m = h.member();
  e.emit("data", call(k.id.pk, randomBytes(16)));
  m.emit("data", call(k.id.pk, randomBytes(16)));
  e.emit("data", call(m.id.pk, randomBytes(16)));
  assert.equal(typed(e).at(-1)[0], 0x06, "the address has a room's worth of calls waiting, over all its sockets");
  h.advance(10_000);
  e.emit("data", call(m.id.pk, randomBytes(16)));
  assert.equal(typed(m).at(-1)[0], 0x05, "calls that expired are given back");
});

test("both ends of a splice are charged to the caller's address, so calls cannot fill the callee's", () => {
  const V = "192.0.2.1", X = "192.0.2.2";
  const f = fixture(["--max-per-ip", "4"]);
  const victim = f.member({}, identity(), V), attacker = f.member({}, identity(), X);
  const [, first] = f.splice(attacker, victim, { callerAddress: X, calleeAddress: V });
  assert.equal(first.destroyed, false);
  const [, second] = f.splice(attacker, victim, { callerAddress: X, calleeAddress: V });
  assert.equal(status(second), 429, "the caller's address is full, so the callee's end is refused");
  for (let i = 0; i < 3; i++) assert.equal(f.join({}, V).destroyed, false, "the callee's address keeps its whole share");
});

test("splices take at most their share of the relay, so nodes can still register", () => {
  const f = fixture(["--max-conns", "32"]), a = f.member(), b = f.member(), c = f.member();
  for (let i = 0; i < 8; i++) f.splice(a, b);
  for (let i = 0; i < 6; i++) f.splice(a, c);
  const [caller, callee] = f.splice(a, c);
  assert.equal(status(caller), 503, "a 29th splice socket is past 7/8 of 32");
  assert.equal(callee.destroyed, true, "and so is its call's other end");
  assert.equal(f.member().ended, false, "a control socket still fits");
});

/** A STUN Binding request with `txid`. */
const binding = (txid = randomBytes(12)) => Buffer.concat([Buffer.from([0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]), txid]);
/** The address and port a Binding response's XOR-MAPPED-ADDRESS names. */
function mapped(res) {
  assert.equal(res.readUInt16BE(0), 0x0101);
  assert.equal(res.readUInt16BE(20), 0x0020);
  const port = res.readUInt16BE(26) ^ 0x2112;
  const bytes = Buffer.from(res.subarray(28).map((b, i) => b ^ res[4 + i]));
  if (res[25] === 1) return [[...bytes].join("."), port];
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(bytes.readUInt16BE(i).toString(16));
  return [groups.join(":"), port];
}

test("STUN: a Binding request learns the address it came from, and nothing else is answered", () => {
  const txid = randomBytes(12);
  const res = stunResponse(binding(txid), "192.0.2.1", 54321);
  assert.deepEqual(mapped(res), ["192.0.2.1", 54321]);
  assert.deepEqual(res.subarray(8, 20), txid, "the transaction id comes back");
  assert.deepEqual(mapped(stunResponse(binding(), "2001:db8::7", 9)), ["2001:db8:0:0:0:0:0:7", 9]);
  const request = binding();
  for (const bad of [request.subarray(0, 19), Buffer.concat([request, Buffer.alloc(4)]),
    Buffer.from(request).fill(0x11, 1, 2), Buffer.from(request).fill(0, 4, 5)]) {
    assert.equal(stunResponse(bad, "192.0.2.1", 1), null, bad.toString("hex"));
  }
  const f = fixture();
  assert.deepEqual(mapped(f.relay.stun(binding(), "::ffff:192.0.2.9", 7)), ["192.0.2.9", 7], "a mapped address is IPv4");
  let answered = 0;
  for (let i = 0; i < 100; i++) if (f.relay.stun(binding(), "192.0.2.8", 7)) answered++;
  assert.equal(answered, 40, "at most two seconds' worth to one address");
});

test("one address takes only a few of a room's seats: past them a join is refused, not the socket", () => {
  const f = fixture(["--max-per-room-ip", "2"]);
  assert.equal(ofType(f.roomMember(), 0x07).length, 0);
  assert.equal(ofType(f.roomMember(), 0x07).length, 0);
  const third = f.roomMember();
  assert.deepEqual(typed(third).at(-1), roomFrame(0x07, "room"), "a third from the address is refused");
  assert.equal(third.ended || third.destroyed, false, "and stays registered");
  assert.equal(ofType(f.roomMember({}, identity(), "192.0.2.7"), 0x07).length, 0, "another address still fits");
  assert.equal(ofType(f.roomMember({ room: "other" }), 0x07).length, 0, "and the address fits in another room");
});

test("splice traffic is metered per address: past its budget a sender is paused, not cut", () => {
  const f = fixture(["--splice-rate", "1"]), [sa, sb] = f.splice(f.member(), f.member());
  sa.emit("data", frame(2, randomBytes(1024)));
  assert.equal(sa.paused, false, "within the two-second burst");
  sa.emit("data", frame(2, randomBytes(2048)));
  assert.equal(sa.paused, true, "past it, the sender is not read");
  assert.equal(sa.destroyed, false);
  assert.equal(serverFrames(sb).length, 2, "what it sent was forwarded");
  f.advance(2000);
  assert.equal(sa.paused, false, "read again once the debt is paid back");
});

test("a far end that cannot keep up pauses only the splice it is on", () => {
  const f = fixture(), a = f.member(), b = f.member(), c = f.member();
  const [ab, ba] = f.splice(a, b), [ac, ca] = f.splice(a, c);
  ba.full = true;
  ab.emit("data", frame(2, Buffer.from("to b")));
  assert.equal(ab.paused, true, "a sender whose far end is full is not read");
  ac.emit("data", frame(2, Buffer.from("to c")));
  assert.equal(ac.paused, false, "its splice to another peer still is");
  assert.equal(serverFrames(ca).at(-1).payload.toString(), "to c");
  ba.drain();
  assert.equal(ab.paused, false, "read again once the far end drains");
});

test("invalid control sizes, RSV, fragmentation, masking and lengths are rejected", () => {
  const invalid = [frame(9, Buffer.alloc(126)), frame(10, Buffer.alloc(65535)), frame(2, Buffer.alloc(300)),
    Buffer.from([0xc1, 0x80, 0, 0, 0, 0]), Buffer.from([0x01, 0x80, 0, 0, 0, 0]),
    Buffer.from([0x82, 0]), Buffer.from([0x82, 0xfe, 0, 1, 0, 0, 0, 0, 65]),
    Buffer.from([0x82, 0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 65])];
  for (const bytes of invalid) {
    const f = fixture(), s = f.join(); s.emit("data", bytes);
    assert.equal(s.destroyed, true, bytes.toString("hex"));
  }
});

test("splices hold lengths to their shortest encoding too", () => {
  for (const bytes of [Buffer.from([0x82, 0xfe, 0, 1, 0, 0, 0, 0, 65]),
    Buffer.from([0x82, 0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 65])]) {
    const f = fixture(), [sa, sb] = f.splice(f.member(), f.member());
    sa.emit("data", bytes);
    assert.equal(sa.destroyed && sb.destroyed, true, bytes.toString("hex"));
  }
});

test("pong, announcement and heartbeat writes respect the complete backlog cap", () => {
  for (const kind of ["pong", "announcement", "heartbeat"]) {
    const f = fixture(), s = kind === "announcement" ? f.roomMember() : f.member();
    const before = s.writes.length;
    s.writableLength = 256 * 1024 - 1;
    if (kind === "pong") s.emit("data", frame(9));
    if (kind === "heartbeat") f.beat();
    if (kind === "announcement") f.roomMember();
    assert.equal(s.destroyed, true, kind);
    assert.equal(s.writes.length, before, kind);
  }
  const f = fixture(), s = f.join();
  s.emit("data", frame(9, Buffer.from("ping")));
  assert.equal(s.writes.at(-1).toString("hex"), "8a0470696e67");
  const t = f.roomMember({ room: null });
  t.writableLength = 256 * 1024 - 1;
  t.emit("data", joinRoom("lonely"));
  assert.equal(t.destroyed, true);
  assert.equal(f.relay.rooms.size, 0, "a join it could not answer leaves no room behind");
});

test("the heartbeat reaps a socket that missed a pong, and pings a splice only between frames", () => {
  const f = fixture(), a = f.member(), b = f.member();
  const [sa, sb] = f.splice(a, b);
  f.beat();
  a.emit("data", frame(10));
  sa.emit("data", frame(2, Buffer.from("x")));
  sb.emit("data", Buffer.from(frame(2, Buffer.alloc(10)).subarray(0, 8)));
  const pings = serverFrames(sa).filter((x) => x.opcode === 9).length;
  f.beat();
  assert.equal(a.destroyed, false, "answered");
  assert.equal(b.destroyed, true, "silent");
  assert.equal(sa.destroyed, false, "a splice end that sent something is alive");
  assert.equal(serverFrames(sa).filter((x) => x.opcode === 9).length, pings, "not pinged inside a frame");
});

test("null Origin is rejected by default and requires explicit opt-in", () => {
  const f = fixture();
  assert.equal(status(f.join({ headers: { origin: "null" } })), 403);
  assert.equal(status(f.join({ headers: { origin: "https://evil.test" } })), 403);
  assert.equal(f.join({ headers: { origin: "http://localhost:3000" } }).destroyed, false);
  assert.equal(f.join().destroyed, false);
  assert.equal(fixture(["--allow-origin", "null"]).join({ headers: { origin: "null" } }).destroyed, false);
});

test("XFF cannot spoof clients through a trusted appending proxy", () => {
  const f = fixture(["--trusted-proxy", "127.0.0.1", "--max-per-ip", "1"]);
  assert.equal(f.join({ headers: { "x-forwarded-for": "1.1.1.1, 192.0.2.1" } }).destroyed, false);
  assert.equal(f.join({ headers: { "x-forwarded-for": "2.2.2.2, 192.0.2.1" } }).destroyed, true);
  assert.equal(f.join({ headers: { "x-forwarded-for": "192.0.2.2" } }).destroyed, false);
  assert.equal(f.join({ headers: { "x-forwarded-for": "bogus" } }).destroyed, true);
  assert.equal(f.join({ headers: { "x-forwarded-for": "fe80::1%eth0" } }).destroyed, true);
  assert.equal(f.join().destroyed, true);
});

test("explicitly trusted proxy chains use canonical IPv6 addresses", () => {
  const f = fixture(["--trusted-proxy", "127.0.0.1", "--trusted-proxy", "2001:db8::1", "--max-per-ip", "1"]);
  assert.equal(f.join({ headers: { "x-forwarded-for": "192.0.2.1, 2001:0db8:0:0:0:0:0:1" } }).destroyed, false);
  assert.equal(f.join({ headers: { "x-forwarded-for": "192.0.2.1, 2001:db8::1" } }).destroyed, true);
});

test("direct clients cannot opt into proxy trust, and mapped IPs share limits", () => {
  const f = fixture(["--trusted-proxy", "192.0.2.10", "--max-per-ip", "1"]);
  const s = f.join({ headers: { "x-forwarded-for": "1.1.1.1" } });
  assert.equal(s.destroyed, false);
  assert.equal(f.join({ headers: { "x-forwarded-for": "2.2.2.2" } }, "::ffff:127.0.0.1").destroyed, true);
  s.destroy();
  assert.equal(f.join({}, "::ffff:7f00:1").destroyed, false);
});

test("IPv6 clients are accounted by their /64, or the prefix given", () => {
  const f = fixture(["--max-per-ip", "1"]);
  assert.equal(f.tcp("2001:db8:1:2::1").destroyed, false);
  assert.equal(f.tcp("2001:db8:1:2:ffff::9").destroyed, true, "another address in the same /64");
  assert.equal(f.tcp("2001:db8:1:3::1").destroyed, false, "another /64");
  const g = fixture(["--max-per-ip", "1", "--ipv6-prefix", "48"]);
  assert.equal(g.tcp("2001:db8:1:2::1").destroyed, false);
  assert.equal(g.tcp("2001:db8:1:3::1").destroyed, true, "the same /48");
  const h = fixture(["--trusted-proxy", "127.0.0.1", "--max-per-ip", "1"]);
  assert.equal(h.join({ headers: { "x-forwarded-for": "2001:db8::1" } }).destroyed, false);
  assert.equal(h.join({ headers: { "x-forwarded-for": "2001:db8::2" } }).destroyed, true, "forwarded ones too");
});

test("TCP caps cover incomplete handshakes and release slots on close", () => {
  const f = fixture(["--max-conns", "2", "--max-per-ip", "1"]);
  const first = f.tcp("192.0.2.1");
  assert.equal(f.tcp("192.0.2.1").destroyed, true);
  const second = f.tcp("192.0.2.2");
  assert.equal(f.tcp("192.0.2.3").destroyed, true);
  first.destroy();
  const third = f.tcp("192.0.2.3");
  assert.equal(third.destroyed, false);
  f.upgrade(third);
  third.emit("data", frame(2, registration(identity(), "relay.test", challenge(third))));
  f.advance(10_000);
  assert.equal(second.destroyed, true);
  assert.equal(third.destroyed, false);
});

test("frame and input byte floods disconnect their sender", () => {
  const f = fixture(), s = f.join();
  s.emit("data", Buffer.concat(Array.from({ length: 257 }, () => frame(10))));
  assert.equal(s.destroyed, true);
  const large = f.join();
  large.emit("data", Buffer.alloc(600 * 1024));
  assert.equal(large.destroyed, true, "bytes are charged before they are parsed");
});

test("an address opens control sockets at the registration rate", () => {
  const f = fixture(["--register-rate", "1"]);
  assert.equal(f.join().destroyed, false);
  assert.equal(f.join().destroyed, false);
  assert.equal(status(f.join()), 429, "past the two-second burst");
  assert.equal(f.join({}, "192.0.2.7").destroyed, false, "another address has its own");
  f.advance(1000);
  assert.equal(f.join().destroyed, false, "and the rate refills");
});

test("closing the relay tells every socket it is restarting", () => {
  const f = fixture(), a = f.member(), b = f.member(), handshaking = f.tcp();
  const [sa, sb] = f.splice(a, b);
  f.relay.close();
  for (const s of [a, b, sa, sb]) {
    assert.equal(s.ended, true);
    assert.equal(closeCode(s), 1012);
  }
  assert.equal(handshaking.destroyed, true, "a socket still mid-handshake is dropped");
});

test("room ids, keys and request headers never appear in event logs", () => {
  const f = fixture(["--max-per-room", "1"]), secret = "secret-capability";
  const s = f.roomMember({ room: secret });
  f.roomMember({ room: secret });
  s.destroy();
  f.join({ path: `/v1/${secret}?${secret}` });
  f.join({ headers: { origin: `https://${secret}.test` } });
  f.join({ headers: { host: `${secret}.test` } });
  assert.ok(f.logs.some((line) => line.includes("room full")));
  const logs = f.logs.join("\n");
  assert.equal(logs.includes(secret) || logs.includes(roomId(secret).toString("hex")), false);
  assert.equal(logs.includes(s.id.pk.toString("hex")), false);
});

test("a registration split across the upgrade head and later reads is accepted", () => {
  const f = fixture(), id = identity();
  const s = f.join();
  const packet = frame(2, registration(id, "relay.test", challenge(s)));
  s.emit("data", packet.subarray(0, 3));
  s.emit("data", packet.subarray(3));
  assert.equal(typed(s)[1][0], 0x01);
});

test("real sockets: register, call and splice through a running relay", { timeout: 10000 }, async (t) => {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("RELAY_")));
  const child = spawn(process.execPath, [SERVER, "0", "--stun", "127.0.0.1:0"],
    { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  t.after(() => child.kill());
  const [port, stunPort] = await new Promise((resolve, reject) => {
    let output = "";
    child.stdout.on("data", (data) => {
      output += data;
      const ws = /listening on ws:\/\/127\.0\.0\.1:(\d+)\//.exec(output);
      const udp = /STUN on udp:\/\/127\.0\.0\.1:(\d+)/.exec(output);
      if (ws && udp) resolve([Number(ws[1]), Number(udp[1])]);
    });
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`server exited ${code}`)));
  });
  const open = (path) => new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, headers: {
      Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13",
      "Sec-WebSocket-Key": "AAAAAAAAAAAAAAAAAAAAAA==",
    } });
    req.once("error", reject);
    req.once("upgrade", (_res, socket, head) => {
      t.after(() => socket.destroy());
      socket.got = Buffer.from(head);
      socket.on("data", (d) => { socket.got = Buffer.concat([socket.got, d]); socket.emit("got"); });
      resolve(socket);
    });
    req.once("response", (res) => { res.resume(); reject(new Error(`HTTP ${res.statusCode}`)); });
    req.end();
  });
  const frames = (s) => serverFrames({ writes: [Buffer.alloc(0), s.got] });
  const until = async (s, pred) => { while (!pred(frames(s))) await once(s, "got"); return frames(s); };
  const register = async (s, id) => {
    const [c] = await until(s, (fs) => fs.length >= 1);
    s.write(frame(2, registration(id, `127.0.0.1:${port}`, c.payload.subarray(1))));
    await until(s, (fs) => fs.some((x) => x.payload[0] === 0x01));
  };
  const ida = identity(), idb = identity();
  const a = await open("/v1/"), b = await open("/v1/");
  await register(a, ida);
  await register(b, idb);
  const ticket = randomBytes(16);
  a.write(call(idb.pk, ticket));
  const ring = (await until(b, (fs) => fs.some((x) => x.payload[0] === 0x05))).find((x) => x.payload[0] === 0x05);
  const sa = await open(splicePath(ticket.toString("hex")));
  const sb = await open(splicePath(ring.payload.subarray(33).toString("hex")));
  const payload = randomBytes(100_000);
  sa.write(frame(2, payload));
  const [got] = await until(sb, (fs) => fs.length >= 1);
  assert.deepEqual(got.payload, payload);

  const udp = createSocket("udp4");
  t.after(() => udp.close());
  udp.bind(0, "127.0.0.1");
  await once(udp, "listening");
  udp.send(binding(), stunPort, "127.0.0.1");
  const [res] = await once(udp, "message");
  assert.deepEqual(mapped(res), ["127.0.0.1", udp.address().port], "the relay answers STUN");

  // Two apps meet in a room through rooms.mjs, as seedchat and seedstore do.
  const heard = [];
  const client = (id) => {
    const c = roomClient({ relay: `ws://127.0.0.1:${port}`, publicKey: id.pk, sign: (m) => sign(null, m, id.key),
      onMember: (room, key, present) => heard.push([id.pk.toString("hex"), room, key, present]), WebSocket: TestWebSocket });
    t.after(() => c.close());
    return c;
  };
  const ra = client(ida), rb = client(idb);
  await ra.join("lobby");
  await rb.join("lobby");
  const saw = (who, key, present) => heard.some(([w, room, k, p]) => w === who && room === "lobby" && k === key && p === present);
  const [ha, hb] = [ida.pk.toString("hex"), idb.pk.toString("hex")];
  while (!(saw(ha, hb, true) && saw(hb, ha, true))) await new Promise((r) => setTimeout(r, 10));
  await rb.leave("lobby");
  while (!saw(ha, hb, false)) await new Promise((r) => setTimeout(r, 10));
});

/** Just enough of a browser WebSocket over node:http for rooms.mjs: binary messages in and
 *  out, and a close. */
class TestWebSocket {
  constructor(url) {
    const u = new URL(url);
    const req = request({ host: u.hostname, port: u.port, path: u.pathname, headers: {
      Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13",
      "Sec-WebSocket-Key": "AAAAAAAAAAAAAAAAAAAAAA==",
    } });
    req.once("upgrade", (_res, socket, head) => {
      this.socket = socket;
      let buf = Buffer.from(head);
      const take = (d) => {
        buf = Buffer.concat([buf, d]);
        for (;;) {
          const [f] = serverFrames({ writes: [Buffer.alloc(0), buf] });
          if (!f) return;
          buf = buf.subarray((f.payload.length < 126 ? 2 : f.payload.length < 65536 ? 4 : 10) + f.payload.length);
          if (f.opcode === 2) this.onmessage?.({ data: f.payload.buffer.slice(f.payload.byteOffset, f.payload.byteOffset + f.payload.length) });
        }
      };
      socket.on("data", take);
      socket.once("close", () => this.onclose?.());
      take(Buffer.alloc(0));
    });
    req.once("error", () => this.onclose?.());
    req.end();
  }
  send(bytes) { this.socket.write(frame(2, Buffer.from(bytes))); }
  close() { this.socket?.destroy(); }
}
