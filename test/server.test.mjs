import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { EventEmitter, once } from "node:events";
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { isIP } from "node:net";
import { fileURLToPath } from "node:url";
import { request } from "node:http";
import { spawn } from "node:child_process";
import vm from "node:vm";

// Run the production handlers with a controlled clock and sockets so slow
// readers, exact budget boundaries and timeouts are deterministic.
const source = readFileSync(new URL("../server.mjs", import.meta.url), "utf8")
  .replace(/^import .*;\r?\n/gm, "");
class Socket extends EventEmitter {
  writable = true;
  writableLength = 0;
  destroyed = false;
  ended = false;
  paused = false;
  writes = [];
  write(bytes) { this.writes.push(Buffer.from(bytes)); return true; }
  pause() { this.paused = true; }
  resume() { this.paused = false; }
  end() { this.ended = true; }
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true; this.writable = false; this.emit("close");
  }
}
function fixture(args = []) {
  const server = new EventEmitter();
  server.listen = () => {};
  const logs = [], timers = new Set(), beats = [];
  let now = 0;
  const context = {
    Buffer, URL, createHash, createPublicKey, randomBytes, verify, isIP,
    performance: { now: () => now },
    process: { argv: ["node", "server", ...args], env: {} },
    console: { log: (s) => logs.push(s) },
    createServer: () => server,
    setTimeout(fn, ms) { const t = { fn, at: now + ms, unref() {} }; timers.add(t); return t; },
    clearTimeout: (t) => timers.delete(t),
    setInterval(fn) { beats.push(fn); return { unref() {} }; },
  };
  vm.runInNewContext(source, context);
  function tcp(address = "127.0.0.1") {
    const s = new Socket(); s.remoteAddress = address;
    server.emit("connection", s); return s;
  }
  function upgrade(s, { room = "room", path = `/${room}`, headers = {}, head } = {}) {
    server.emit("upgrade", { method: "GET", url: path, headers: {
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
  return { tcp, upgrade, logs, beats, join, member,
    advance(ms) { now += ms; for (const t of timers) if (t.at <= now) { timers.delete(t); t.fn(); } },
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
const typed = (sock) => serverFrames(sock).filter((f) => f.opcode === 2).map((f) => f.payload);
const challenge = (sock) => typed(sock)[0].subarray(1);

function identity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pk: publicKey.export({ format: "der", type: "spki" }).subarray(12), key: privateKey };
}
const DOMAINS = Buffer.from("seedkernel-link-scope-v1\0seedkernel-relay-register-v1\0");
function registration(id, authority, nonce) {
  const sig = sign(null, Buffer.concat([DOMAINS, Buffer.from(authority), nonce]), id.key);
  return Buffer.concat([Buffer.of(1), id.pk, sig]);
}
const call = (to, ticket) => frame(2, Buffer.concat([Buffer.of(5), to, ticket]));

test("a node registers by signing the nonce for this relay's authority", () => {
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

test("text frames, unknown types and a second registration drop the sender", () => {
  for (const bytes of [frame(1, Buffer.from("hi")), frame(2, Buffer.of(9)), frame(2, Buffer.alloc(0))]) {
    const f = fixture(), s = f.join();
    s.emit("data", bytes);
    assert.equal(s.destroyed, true, bytes.toString("hex"));
  }
  const f = fixture(), s = f.member();
  s.emit("data", frame(2, registration(s.id, "relay.test", challenge(s))));
  assert.equal(s.destroyed, true);
});

test("a room's members are its registered keys, announced on join and leave", () => {
  const f = fixture();
  const a = f.member(), b = f.member(), outsider = f.member({ room: "other" }), roomless = f.member({ path: "/" });
  const lastB = typed(b).at(-1);
  assert.equal(lastB[0], 0x02);
  assert.deepEqual(lastB.subarray(1), a.id.pk, "the newcomer gets the room");
  assert.deepEqual(typed(a).at(-1), Buffer.concat([Buffer.of(0x03), b.id.pk]), "the room gets the newcomer");
  assert.equal(typed(outsider).length, 3, "another room hears nothing");
  assert.equal(typed(roomless).length, 2, "a socket in no room gets no members");
  const heard = typed(a).length;
  const b2 = f.member({}, b.id);
  assert.equal(typed(a).length, heard, "a second socket for the same key is not a new member");
  b.destroy();
  assert.equal(typed(a).length, heard, "the key is still in the room");
  b2.destroy();
  assert.deepEqual(typed(a).at(-1), Buffer.concat([Buffer.of(0x04), b.id.pk]));
});

test("a call rings only the callee, and joins the two sockets that bring its ticket", () => {
  const f = fixture();
  const a = f.member(), b = f.member({ path: "/" }), c = f.member();
  const ticket = randomBytes(16), hex = ticket.toString("hex");
  a.emit("data", call(b.id.pk, ticket));
  assert.deepEqual(typed(b).at(-1), Buffer.concat([Buffer.of(0x05), a.id.pk, ticket]));
  assert.equal(typed(c).filter((p) => p[0] === 0x05).length, 0, "no one else sees the ticket");

  const sa = f.join({ path: `/?splice=${hex}`, head: frame(2, Buffer.from("msg1")) });
  assert.equal(sa.paused, true, "a lone end waits");
  const sb = f.join({ path: `/?splice=${hex}` });
  assert.equal(sa.paused, false);
  assert.deepEqual(serverFrames(sb).map((x) => x.payload.toString()), ["msg1"], "what came early is forwarded");
  sb.emit("data", frame(2, Buffer.from("msg2")));
  assert.deepEqual(serverFrames(sa).at(-1).payload.toString(), "msg2");
  const third = f.join({ path: `/?splice=${hex}` });
  assert.equal(third.destroyed, true, "a ticket joins two sockets, no more");
  assert.equal(f.join({ path: `/?splice=${"00".repeat(16)}` }).destroyed, true, "an uncalled ticket is refused");
  assert.equal(f.join({ path: "/?splice=zz" }).destroyed, true, "a malformed ticket is refused");
});

test("an unknown callee or a reused ticket is unreachable at once", () => {
  const f = fixture();
  const a = f.member(), b = f.member(), ticket = randomBytes(16);
  a.emit("data", call(identity().pk, ticket));
  assert.equal(typed(a).at(-1)[0], 0x06);
  a.emit("data", call(a.id.pk, ticket));
  assert.equal(typed(a).at(-1)[0], 0x06, "a node cannot call itself");
  a.emit("data", call(b.id.pk, ticket));
  a.emit("data", call(b.id.pk, ticket));
  assert.deepEqual(typed(a).at(-1), Buffer.concat([Buffer.of(0x06), b.id.pk, ticket]));
  assert.equal(a.destroyed, false);
});

test("the latest registration of a key takes its calls, and the one before takes over", () => {
  const f = fixture(), id = identity(), a = f.member();
  const old = f.member({ path: "/" }, id), latest = f.member({ path: "/" }, id);
  a.emit("data", call(id.pk, randomBytes(16)));
  assert.equal(typed(latest).at(-1)[0], 0x05);
  latest.destroy();
  a.emit("data", call(id.pk, randomBytes(16)));
  assert.equal(typed(old).at(-1)[0], 0x05);
});

test("splice frames stream through with any size, unmasked, fragments and all", () => {
  const f = fixture(), a = f.member(), b = f.member(), ticket = randomBytes(16);
  a.emit("data", call(b.id.pk, ticket));
  const path = `/?splice=${ticket.toString("hex")}`;
  const sa = f.join({ path }), sb = f.join({ path });
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
  const f = fixture(), a = f.member(), b = f.member(), ticket = randomBytes(16);
  a.emit("data", call(b.id.pk, ticket));
  const path = `/?splice=${ticket.toString("hex")}`;
  const sa = f.join({ path }), sb = f.join({ path });
  sa.emit("data", frame(9, Buffer.from("p")));
  assert.equal(serverFrames(sa).at(-1).opcode, 0xA, "a ping is answered by the relay");
  assert.equal(serverFrames(sb).length, 0, "and not forwarded");
  sa.emit("data", frame(8, Buffer.from([3, 232])));
  assert.equal(serverFrames(sb).at(-1).opcode, 8);
  assert.equal(sa.ended && sb.ended, true);
  sa.emit("data", frame(9, Buffer.alloc(200)));
  assert.equal(sa.destroyed, true, "an oversize control frame fails the splice");
});

test("one end closing ends the other, and an unjoined ticket expires", () => {
  const f = fixture(), a = f.member(), b = f.member();
  const t1 = randomBytes(16), t2 = randomBytes(16);
  a.emit("data", call(b.id.pk, t1));
  a.emit("data", call(b.id.pk, t2));
  const sa = f.join({ path: `/?splice=${t1.toString("hex")}` }), sb = f.join({ path: `/?splice=${t1.toString("hex")}` });
  sa.destroy();
  assert.equal(sb.ended, true);
  f.advance(10_000);
  assert.equal(sb.destroyed, true, "a far end that never closes is given up on");
  const lone = f.join({ path: `/?splice=${t2.toString("hex")}` });
  assert.equal(lone.destroyed, true, "the ticket expired with the first join's clock");
});

test("waiting calls are charged to the caller's address, at most eight to one key", () => {
  const f = fixture(), a = f.member(), b = f.member();
  const rings = () => typed(b).filter((p) => p[0] === 0x05).length;
  for (let i = 0; i < 9; i++) a.emit("data", call(b.id.pk, randomBytes(16)));
  assert.equal(rings(), 8);
  assert.equal(typed(a).at(-1)[0], 0x06, "a ninth call to one key from one address is unreachable");
  f.member({}, identity(), "192.0.2.7").emit("data", call(b.id.pk, randomBytes(16)));
  assert.equal(rings(), 9, "another address still gets through");

  const g = fixture(["--max-per-room", "2"]), c = g.member(), d = g.member(), e = g.member({ path: "/" });
  c.emit("data", call(d.id.pk, randomBytes(16)));
  e.emit("data", call(d.id.pk, randomBytes(16)));
  c.emit("data", call(e.id.pk, randomBytes(16)));
  assert.equal(typed(c).at(-1)[0], 0x06, "the address has a room's worth of calls waiting, over all its sockets");
  g.advance(10_000);
  c.emit("data", call(e.id.pk, randomBytes(16)));
  assert.equal(typed(e).at(-1)[0], 0x05, "calls that expired are given back");
});

test("one address takes only a few of a room's seats", () => {
  const f = fixture(["--max-per-room-ip", "2"]);
  assert.equal(f.join().destroyed, false);
  assert.equal(f.join().destroyed, false);
  assert.equal(f.join().destroyed, true, "a third socket from the address is refused");
  assert.equal(f.join({}, "192.0.2.7").destroyed, false, "another address still fits");
  assert.equal(f.join({ room: "other" }).destroyed, false, "and the address fits in another room");
});

test("splice traffic is metered per address: past its budget a sender is paused, not cut", () => {
  const f = fixture(["--splice-rate", "1"]), a = f.member(), b = f.member(), ticket = randomBytes(16);
  a.emit("data", call(b.id.pk, ticket));
  const path = `/?splice=${ticket.toString("hex")}`;
  const sa = f.join({ path }), sb = f.join({ path });
  sa.emit("data", frame(2, randomBytes(1024)));
  assert.equal(sa.paused, false, "within the two-second burst");
  sa.emit("data", frame(2, randomBytes(2048)));
  assert.equal(sa.paused, true, "past it, the sender is not read");
  assert.equal(sa.destroyed, false);
  assert.equal(serverFrames(sb).length, 2, "what it sent was forwarded");
  f.advance(2000);
  assert.equal(sa.paused, false, "read again once the debt is paid back");
});

test("invalid control sizes, RSV, fragmentation, masking and lengths are rejected", () => {
  const invalid = [frame(9, Buffer.alloc(126)), frame(10, Buffer.alloc(65535)),
    Buffer.from([0xc1, 0x80, 0, 0, 0, 0]), Buffer.from([0x01, 0x80, 0, 0, 0, 0]),
    Buffer.from([0x82, 0]), Buffer.from([0x82, 0xfe, 0, 1, 0, 0, 0, 0, 65])];
  for (const bytes of invalid) {
    const f = fixture(), s = f.join(); s.emit("data", bytes);
    assert.equal(s.destroyed, true, bytes.toString("hex"));
  }
});

test("pong, announcement and heartbeat writes respect the complete backlog cap", () => {
  for (const kind of ["pong", "announcement", "heartbeat"]) {
    const f = fixture(), s = f.member();
    const before = s.writes.length;
    s.writableLength = 256 * 1024 - 1;
    if (kind === "pong") s.emit("data", frame(9));
    if (kind === "heartbeat") f.beats[0]();
    if (kind === "announcement") f.member();
    assert.equal(s.destroyed, true, kind);
    assert.equal(s.writes.length, before, kind);
  }
  const f = fixture(), s = f.join();
  s.emit("data", frame(9, Buffer.from("ping")));
  assert.equal(s.writes.at(-1).toString("hex"), "8a0470696e67");
});

test("null Origin is rejected by default and requires explicit opt-in", () => {
  const f = fixture();
  assert.equal(f.join({ headers: { origin: "null" } }).destroyed, true);
  assert.equal(f.join({ headers: { origin: "https://evil.test" } }).destroyed, true);
  assert.equal(f.join({ headers: { origin: "http://localhost:3000" } }).destroyed, false);
  assert.equal(f.join().destroyed, false);
  assert.equal(fixture(["--allow-origin", "null"]).join({ headers: { origin: "null" } }).destroyed, false);
});

test("a control socket needs a Host to register against", () => {
  const f = fixture();
  assert.equal(f.join({ headers: { host: undefined } }).destroyed, true);
});

test("proxy trust cannot be enabled without specifying proxy addresses", () => {
  assert.throws(() => fixture(["--trust-proxy"]), /requires/);
  assert.throws(() => fixture(["--trusted-proxy", "bogus"]), /IP address/);
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

test("join announcements are charged to the room and refill over time", () => {
  const f = fixture(["--max-per-room", "200", "--max-per-ip", "1000", "--max-per-room-ip", "1000"]);
  const peers = [];
  while (peers.length < 200 && !peers.at(-1)?.destroyed) peers.push(f.member());
  assert.equal(peers.at(-1).destroyed, true, "a room that cannot afford the fan-out refuses the joiner");
  assert.ok(peers.length > 60, `the budget covers a full default room, got ${peers.length}`);
  f.advance(2000);
  assert.equal(f.member().destroyed, false);
});

test("room names, keys and request headers never appear in event logs", () => {
  const f = fixture(["--max-per-room", "1"]), secret = "secret-capability";
  const s = f.member({ room: secret });
  f.join({ room: secret });
  s.destroy();
  f.join({ room: `${secret}/invalid?${secret}` });
  f.join({ headers: { origin: `https://${secret}.test` } });
  assert.ok(f.logs.length > 0);
  assert.equal(f.logs.join("\n").includes(secret), false);
  assert.equal(f.logs.join("\n").includes(s.id.pk.toString("hex")), false);
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
  const child = spawn(process.execPath, [fileURLToPath(new URL("../server.mjs", import.meta.url)), "0"],
    { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  t.after(() => child.kill());
  const port = await new Promise((resolve, reject) => {
    let output = "";
    child.stdout.on("data", (data) => {
      output += data;
      const match = /listening on ws:\/\/127\.0\.0\.1:(\d+)\//.exec(output);
      if (match) resolve(Number(match[1]));
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
  const a = await open("/room"), b = await open("/room");
  await register(a, ida);
  await register(b, idb);
  const ticket = randomBytes(16);
  a.write(call(idb.pk, ticket));
  await until(b, (fs) => fs.some((x) => x.payload[0] === 0x05));
  const sa = await open(`/?splice=${ticket.toString("hex")}`);
  const sb = await open(`/?splice=${ticket.toString("hex")}`);
  const payload = randomBytes(100_000);
  sa.write(frame(2, payload));
  const [got] = await until(sb, (fs) => fs.length >= 1);
  assert.deepEqual(got.payload, payload);
});
