import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { EventEmitter, once } from "node:events";
import { createHash } from "node:crypto";
import { isUtf8 } from "node:buffer";
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
  writes = [];
  write(bytes) { this.writes.push(Buffer.from(bytes)); return true; }
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
    Buffer, URL, createHash, isUtf8, isIP,
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
  function upgrade(s, { room = "room", headers = {}, head } = {}) {
    server.emit("upgrade", { method: "GET", url: `/${room}`, headers: {
      upgrade: "websocket", "sec-websocket-version": "13",
      "sec-websocket-key": "AAAAAAAAAAAAAAAAAAAAAA==", ...headers,
    } }, s, head);
    return s;
  }
  return { tcp, upgrade, logs, beats,
    join: (options, address) => upgrade(tcp(address), options),
    advance(ms) { now += ms; for (const t of timers) if (t.at <= now) { timers.delete(t); t.fn(); } },
  };
}
function frame(opcode, payload = Buffer.alloc(0)) {
  const h = Buffer.alloc(payload.length < 126 ? 6 : payload.length < 65536 ? 8 : 14);
  h[0] = 0x80 | opcode;
  h[1] = 0x80 | (h.length === 6 ? payload.length : h.length === 8 ? 126 : 127);
  if (h.length === 8) h.writeUInt16BE(payload.length, 2);
  if (h.length === 14) h.writeBigUInt64BE(BigInt(payload.length), 2);
  return Buffer.concat([h, payload]);
}
const textFrame = (s) => frame(1, Buffer.from(s));

test("malformed UTF-8 drops the sender without forwarding or disconnecting peers", () => {
  const f = fixture(), receiver = f.join(), attacker = f.join();
  attacker.emit("data", frame(1, Buffer.from([0xff])));
  assert.equal(attacker.destroyed, true);
  assert.equal(receiver.destroyed, false);
  assert.equal(receiver.writes.length, 1); // handshake only
  const sender = f.join(); sender.emit("data", textFrame('{"hello":"世界"}'));
  assert.equal(receiver.writes.at(-1).subarray(2).toString(), '{"hello":"世界"}');
});

test("invalid control sizes, RSV, fragmentation, masking and lengths are rejected", () => {
  const invalid = [frame(9, Buffer.alloc(126)), frame(10, Buffer.alloc(65535)),
    Buffer.from([0xc1, 0x80, 0, 0, 0, 0]), Buffer.from([0x01, 0x80, 0, 0, 0, 0]),
    Buffer.from([0x81, 0]), Buffer.from([0x81, 0xfe, 0, 1, 0, 0, 0, 0, 65])];
  for (const bytes of invalid) {
    const f = fixture(), s = f.join(); s.emit("data", bytes);
    assert.equal(s.destroyed, true, bytes.toString("hex"));
  }
});

test("pong, broadcast and heartbeat writes respect the complete backlog cap", () => {
  for (const kind of ["pong", "broadcast", "heartbeat"]) {
    const f = fixture(), s = f.join();
    s.writableLength = 256 * 1024 - 1;
    if (kind === "pong") s.emit("data", frame(9));
    if (kind === "heartbeat") f.beats[0]();
    if (kind === "broadcast") f.join().emit("data", textFrame("hello"));
    assert.equal(s.destroyed, true, kind);
    assert.equal(s.writes.length, 1, kind);
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
  f.advance(10_000);
  assert.equal(second.destroyed, true);
  assert.equal(third.destroyed, false);
});

test("frame and input byte floods disconnect their sender", () => {
  const f = fixture(), s = f.join();
  s.emit("data", Buffer.concat(Array.from({ length: 257 }, () => frame(10))));
  assert.equal(s.destroyed, true);
  const large = f.join();
  for (let i = 0; i < 9; i++) large.emit("data", frame(2, Buffer.alloc(65536)));
  assert.equal(large.destroyed, true);
});

test("room fan-out budgets aggregate senders and refill over time", () => {
  const f = fixture(), peers = Array.from({ length: 64 }, () => f.join());
  const large = frame(2, Buffer.alloc(65536));
  peers[0].emit("data", large);
  assert.equal(peers[0].destroyed, false);
  peers[1].emit("data", large);
  assert.equal(peers[1].destroyed, true);
  f.advance(2000);
  peers[2].emit("data", large);
  assert.equal(peers[2].destroyed, false);
});

test("global egress budgets survive room turnover", () => {
  const f = fixture(["--max-per-ip", "1024"]);
  let limited = false;
  for (let i = 0; i < 10; i++) {
    const peers = Array.from({ length: 64 }, () => f.join({ room: `room${i}` }));
    peers[0].emit("data", frame(2, Buffer.alloc(65536)));
    limited ||= peers[0].destroyed;
    peers.forEach((s) => s.destroy());
  }
  assert.equal(limited, true);
});

test("room names and request headers never appear in event logs", () => {
  const f = fixture(["--max-per-room", "1"]), secret = "secret-capability";
  const s = f.join({ room: secret });
  f.join({ room: secret });
  s.destroy();
  f.join({ room: `${secret}/invalid?${secret}` });
  f.join({ headers: { origin: `https://${secret}.test` } });
  assert.ok(f.logs.length > 0);
  assert.equal(f.logs.join("\n").includes(secret), false);
});

test("frames in the upgrade head and split across reads preserve room isolation", () => {
  const f = fixture(), receiver = f.join(), outsider = f.join({ room: "other" });
  const packet = textFrame("hello");
  const sender = f.join({ head: packet.subarray(0, 3) });
  sender.emit("data", packet.subarray(3));
  assert.equal(receiver.writes.at(-1).toString("hex"), "810568656c6c6f");
  assert.equal(outsider.writes.length, 1);
});

test("real HTTP upgrade broadcasts valid text and isolates malformed senders", { timeout: 10000 }, async (t) => {
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
  const join = () => new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path: "/integration", headers: {
      Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13",
      "Sec-WebSocket-Key": "AAAAAAAAAAAAAAAAAAAAAA==",
    } });
    req.once("error", reject);
    req.once("upgrade", (_res, socket) => { t.after(() => socket.destroy()); resolve(socket); });
    req.once("response", (res) => { res.resume(); reject(new Error(`HTTP ${res.statusCode}`)); });
    req.end();
  });
  const receiver = await join(), sender = await join();
  let received = Buffer.alloc(0);
  receiver.on("data", (data) => { received = Buffer.concat([received, data]); });
  const closed = once(sender, "close");
  sender.write(frame(1, Buffer.from([0xff])));
  sender.resume();
  await closed;
  const healthy = await join();
  const data = once(receiver, "data");
  healthy.write(textFrame("ok"));
  await data;
  assert.equal(received.toString("hex"), "81026f6b");
});
