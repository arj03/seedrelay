// The relay bundle's guest program, as relay.skb carries it, in a realm of its own behind a
// host that stands in for seedkernel's: links that record what the relay writes, a clock
// the test moves, and the host calls the relay makes (`node/sign` and `node/verify` under
// the link scope with the relay's own key, BLAKE2b, ChaCha20-Poly1305, X25519, entropy,
// the ML-KEM module, and the ws module's masking and accept value). Slow readers, exact
// budget boundaries and timeouts are deterministic this way; test/relay.test.mjs also runs
// the bin over real sockets.

import vm from "node:vm";
import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { verifyBundle } from "seedkernel-wasm/bundle";
import { DOMAIN_LINK_SCOPE, mlkem, sodium } from "./channel.mjs";
import { OpArgs } from "seedkernel-wasm/op-frame";
import { DEFAULT_LIMITS, parseOptions, RELAY_BUNDLE, relayConfig } from "../relay.mjs";

const ZERO32 = new Uint8Array(32);
const CONTACT_TAG = Buffer.from("seedkernel-contact-secret-v1\0");
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const u32 = (v) => Buffer.from([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
const settle = () => new Promise((r) => setImmediate(r));
const { guestSource: source, manifest } = verifyBundle(sodium, readFileSync(RELAY_BUNDLE));

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

/** A relay started with `args` on the command line. */
export async function relayRealm(args = []) {
  const options = parseOptions(args);
  const logs = [], links = new Map(), sent = [];
  let now = 0, wakeAt = Infinity, nextId = 0, nextSocket = 0;
  const id = sodium.crypto_sign_keypair();
  /** `[npub 12][key 32][adLen u32][ad][msg]`, as seedkernel's guest seam reads it. */
  const aead = (a) => {
    const adLen = a.readUInt32BE(44);
    return { npub: a.subarray(0, 12), key: a.subarray(12, 44), ad: adLen ? a.subarray(48, 48 + adLen) : null, msg: a.subarray(48 + adLen) };
  };
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
    "node/sign": (a) => answer(sodium.crypto_sign_detached(Buffer.concat([DOMAIN_LINK_SCOPE, a]), id.privateKey)),
    "node/verify": (a) => answer([sodium.crypto_sign_verify_detached(a.subarray(32, 96), Buffer.concat([DOMAIN_LINK_SCOPE, a.subarray(96)]), a.subarray(0, 32)) ? 1 : 0]),
    "crypto/blake2b": (a) => answer(sodium.crypto_generichash(a[0], a.subarray(2 + a[1]), a[1] ? a.subarray(2, 2 + a[1]) : null)),
    "crypto/chacha20poly1305-ietf/seal": (a) => {
      const { npub, key, ad, msg } = aead(a);
      return answer(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(msg, ad, null, npub, key));
    },
    "crypto/chacha20poly1305-ietf/open": (a) => {
      const { npub, key, ad, msg } = aead(a);
      try { return answer(Buffer.concat([Buffer.of(1), sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, msg, ad, npub, key)])); }
      catch { return answer([0]); }
    },
    "crypto/x25519/dh": (a) => {
      try { return answer(Buffer.concat([Buffer.of(1), sodium.crypto_scalarmult(a.subarray(0, 32), a.subarray(32, 64))])); }
      catch { return answer([0]); }
    },
    mlkem: (a) => mlkem(a),
    "crypto/random": (a) => answer(randomBytes(a.readUInt32BE(0))),
    ws: (a) => answer(wsModule(a)),
  };
  // As seedkernel's host writes them in front of a guest: HOST, APP and LOCAL.
  const preamble = (name, value) => `const ${name} = JSON.parse(${JSON.stringify(JSON.stringify(value))});\n`;
  const context = vm.createContext({
    performance: { now: () => now },
    host: { call: (name, bytes) => calls[name](Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)) },
  });
  vm.runInContext(preamble("HOST", { identity: Buffer.from(id.publicKey).toString("hex") }) + preamble("APP", manifest.guest.config) + preamble("LOCAL", relayConfig(options)) + source, context);

  const relay = {
    logs, links, sent,
    /** The relay's key, which a relay link is pinned to. */
    pk: Buffer.from(id.publicKey),
    /** The contact secret a node presents, hex, as its URL carries it: the operator's
     *  first, or the one the relay derives from its key, a hash of its signature over a
     *  fixed tag (seedkernel's `keySecret`), worked out here apart from the guest; null
     *  for an open relay. */
    secret: options.open ? null : options.secrets[0] ?? Buffer.from(sodium.crypto_generichash(32,
      Buffer.concat([CONTACT_TAG, sodium.crypto_sign_detached(Buffer.concat([DOMAIN_LINK_SCOPE, CONTACT_TAG]), id.privateKey)]), null)).toString("hex"),
    /** Hand the relay one event from the host, let everything it set off finish, and give
     *  its answer. */
    async event(args) {
      const out = await context.handle(args.build(ZERO32));
      await settle();
      return out;
    },
    /** A TCP socket accepted from `address`. */
    async tcp(address = "127.0.0.1") {
      const link = new Link(relay, ++nextId);
      links.set(link.linkId, link);
      await relay.event(new OpArgs("linkOpen").u32(link.linkId).u8(1).text("ws").u32(0).text(address));
      return link;
    },
    /** The host's `start`, `close` and `contact`, on the relay's service id: the answer. */
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
