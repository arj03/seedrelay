// The relay bundle's guest program, as relay.skb carries it, in a realm of its own behind a
// host that stands in for seedkernel's: links that record what the relay writes, a clock
// the test moves, and the host calls the relay makes (`node/verify` under the link scope,
// BLAKE2b, entropy, and the ws module's masking and accept value). Slow readers, exact
// budget boundaries and timeouts are deterministic this way; test/relay.test.mjs also runs
// the bin over real sockets.

import vm from "node:vm";
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { loadCrypto } from "seedkernel-wasm";
import { verifyBundle } from "seedkernel-wasm/bundle";
import { OpArgs } from "seedkernel-wasm/op-frame";
import { DEFAULT_LIMITS, parseOptions, RELAY_BUNDLE, relayConfig } from "../relay.mjs";

const ZERO32 = new Uint8Array(32);
const DOMAIN_LINK_SCOPE = Buffer.from("seedkernel-link-scope-v1\0");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const u32 = (v) => Buffer.from([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
const settle = () => new Promise((r) => setImmediate(r));
const { guestSource: source, manifest } = verifyBundle(await loadCrypto(), readFileSync(RELAY_BUNDLE));

/** What seedkernel's ws.wasm answers: a frame masked under the key its header carries, or
 *  the accept value for a key. */
function wsModule(req) {
  if (req[0] === 2) return Buffer.from(createHash("sha1").update(Buffer.from(req.subarray(1)).toString() + WS_GUID).digest("base64"));
  const f = Buffer.from(req.subarray(1)), len7 = f[1] & 0x7f, head = (len7 === 127 ? 10 : len7 === 126 ? 4 : 2) + 4;
  for (let i = head; i < f.length; i++) f[i] ^= f[head - 4 + ((i - head) & 3)];
  return f;
}

/** One socket as the relay sees it, and what the test does to it. `backlog` is what its
 *  reader has not yet taken: a reader keeping up takes each write at once, and one behind
 *  holds it too. `full` is a reader that has stopped well behind. */
class Link {
  writes = [];
  closed = false;
  destroyed = false;
  ended = false;
  paused = false;
  backlog = 0;
  constructor(relay, linkId) { this.relay = relay; this.linkId = linkId; }
  set full(on) { this.backlog = on ? 128 * 1024 : 0; }
  /** Bytes from the client. */
  data(bytes) { return this.relay.event(new OpArgs("linkBytes").u32(this.linkId).blob(bytes)); }
  /** The reader catches up. */
  drain() { this.backlog = 0; }
  /** The client goes. */
  destroy() {
    if (this.closed) return settle();
    this.closed = this.destroyed = true;
    return this.relay.event(new OpArgs("linkClosed").u32(this.linkId));
  }
}

/** A relay started with `args` on the command line, answering to relay.test unless they
 *  name its authorities. */
export async function relayRealm(args = []) {
  const options = parseOptions(args);
  if (options.authorities.length === 0) options.authorities.push("relay.test");
  const logs = [], links = new Map(), sent = [];
  let now = 0, wakeAt = Infinity, nextId = 0, nextSocket = 0;
  const answer = (bytes) => Promise.resolve(new Uint8Array(bytes));
  const calls = {
    "link/send": (a) => {
      const link = links.get(a.readUInt32BE(0)), bytes = a.subarray(4);
      if (!link || link.closed) return answer(u32(0));
      if (bytes.length > 0) link.writes.push(Buffer.from(bytes));
      if (link.backlog > 0) link.backlog += bytes.length;
      return answer(u32(link.backlog));
    },
    "link/pause": (a) => { const link = links.get(a.readUInt32BE(0)); if (link) link.paused = a[4] === 1; return answer([]); },
    "link/close": (a) => {
      const link = links.get(a.readUInt32BE(0));
      if (link && !link.closed) {
        link.closed = true;
        if (a[4] === 1) link.ended = true; else link.destroyed = true;
        queueMicrotask(() => relay.event(new OpArgs("linkClosed").u32(link.linkId)));
      }
      return answer([]);
    },
    "link/status": (a) => { logs.push(a.toString()); return answer([]); },
    "link/udpBind": (a) => answer(Buffer.concat([u32(++nextSocket), a.subarray(0, 2)])),
    "link/udpSend": (a) => { sent.push(Buffer.from(a)); return answer([]); },
    "timer/arm": (a) => { wakeAt = now + a.readUInt32BE(0); return answer([]); },
    "node/verify": (a) => {
      const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, a.subarray(0, 32)]), format: "der", type: "spki" });
      return answer([verify(null, Buffer.concat([DOMAIN_LINK_SCOPE, a.subarray(96)]), key, a.subarray(32, 96)) ? 1 : 0]);
    },
    "crypto/blake2b": (a) => answer(createHash("blake2b512").update(a.subarray(2 + a[1])).digest()),
    "crypto/random": (a) => answer(randomBytes(a.readUInt32BE(0))),
    ws: (a) => answer(wsModule(a)),
  };
  // As seedkernel's host writes them in front of a guest: HOST, APP and LOCAL.
  const preamble = (name, value) => `const ${name} = JSON.parse(${JSON.stringify(JSON.stringify(value))});\n`;
  const context = vm.createContext({
    performance: { now: () => now },
    host: { call: (name, bytes) => calls[name](Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)) },
  });
  vm.runInContext(preamble("HOST", {}) + preamble("APP", manifest.guest.config) + preamble("LOCAL", relayConfig(options)) + source, context);

  const relay = {
    logs, links, sent,
    /** Hand the relay one event from the host, and let everything it set off finish. */
    async event(args) {
      await context.handle(args.build(ZERO32));
      await settle();
    },
    /** A TCP socket accepted from `address`. */
    async tcp(address = "127.0.0.1") {
      const link = new Link(relay, ++nextId);
      links.set(link.linkId, link);
      await relay.event(new OpArgs("linkOpen").u32(link.linkId).u8(1).text("ws").u32(0).text(address));
      return link;
    },
    /** The host's `start` and `close`, on the relay's service id. */
    call: (op) => relay.event(new OpArgs(op)),
    /** A datagram on the first STUN socket from `ip`:`port`: the relay's answer, or null. */
    async stun(msg, ip, port) {
      const bytes = ip.includes(":") ? ipv6(ip) : Buffer.from(ip.split(".").map(Number));
      const batch = Buffer.concat([Buffer.of(bytes.length), bytes, Buffer.from([port >> 8, port & 255, msg.length >> 8, msg.length & 255]), msg]);
      const before = sent.length;
      await relay.event(new OpArgs("datagrams").u32(1).blob(batch));
      if (sent.length === before) return null;
      const out = sent.at(-1), p = 5 + out[4];
      return out.subarray(p + 4);
    },
    /** Move the clock on, waking the relay at each time it asked to be woken by then. */
    async advance(ms) {
      const until = now + ms;
      while (wakeAt <= until) {
        now = Math.max(now, wakeAt);
        wakeAt = Infinity;
        await relay.event(new OpArgs("wake"));
      }
      now = until;
    },
    /** Move the clock to the next heartbeat. */
    beat() { return relay.advance(options.limits.heartbeatSecs * 1000 - (now % (options.limits.heartbeatSecs * 1000))); },
  };
  options.limits = { ...DEFAULT_LIMITS, ...options.limits };
  return relay;
}

/** The sixteen bytes of an IPv6 address. */
function ipv6(text) {
  const [head, tail] = text.split("::");
  const groups = (part) => (part ? part.split(":").map((g) => parseInt(g, 16)) : []);
  const front = groups(head), back = groups(tail);
  const all = tail === undefined ? front : [...front, ...new Array(8 - front.length - back.length).fill(0), ...back];
  return Buffer.from(all.flatMap((w) => [w >> 8, w & 255]));
}
