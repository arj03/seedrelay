// The node's side of a relay link, as a test speaks it: seedkernel's channel handshake as
// its initiator, pinned to the relay's key, then records (seedkernel docs/TRANSPORT.md,
// Handshake and §12.6.1). Written out from libsodium and the ML-KEM module rather than
// borrowed from the transport, so a relay that drifts from the construction fails here.

import { readFileSync } from "node:fs";
import { loadCrypto } from "seedkernel-wasm";
import { ModuleTable } from "seedkernel-wasm/module-table";

export const sodium = await loadCrypto();
const kem = await new ModuleTable().build([
  { name: "mlkem", wasm: readFileSync(new URL(import.meta.resolve("seedkernel-wasm/mlkem768.wasm"))) },
]);
/** One call into the ML-KEM module, as a bundle makes it. */
export const mlkem = async (req) => (await kem.call("mlkem", req)).bytes;

const utf8 = (s) => Buffer.from(s);
const cat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
const H = (...parts) => Buffer.from(sodium.crypto_generichash(32, cat(...parts), null));
const ZERO32 = Buffer.alloc(32), NONCE0 = Buffer.alloc(12);
export const DOMAIN_LINK_SCOPE = utf8("seedkernel-link-scope-v1\0");
const DOMAIN_CHANNEL = utf8("seedkernel-channel-id-v1\0");
const L = (s) => utf8(`seedkernel-${s}-v1\0`);
/** The public network's root, which every relay link is on. */
const ROOT = H(DOMAIN_CHANNEL, ZERO32);

const seal = (key, nonce, pt) => Buffer.from(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(pt, null, null, nonce, key));
function open(key, nonce, ct) {
  try { return Buffer.from(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ct, null, nonce, key)); }
  catch { return null; }
}
const recordNonce = (ctr) => { const n = Buffer.alloc(12); n.writeUInt32BE(ctr, 8); return n; };

/** A node identity: an Ed25519 keypair, `pk` its public half. */
export function identity() {
  const kp = sodium.crypto_sign_keypair();
  return { pk: Buffer.from(kp.publicKey), sk: kp.privateKey };
}

/** Sign as seedkernel's `node/sign` does, under the host's link scope. */
export const nodeSign = (id, msg) => Buffer.from(sodium.crypto_sign_detached(cat(DOMAIN_LINK_SCOPE, msg), id.sk));

/** A relay link from `id` to the relay whose key is `relayPk`, presenting `secret` (the
 *  relay's contact secret, none for an open relay). `msg1` is the first message; `msg3(w2)`
 *  checks the relay's and answers the third, or null when the relay did not prove
 *  `relayPk`; then `seal` and `open` carry records. */
export async function relayLink(id, relayPk, secret = ZERO32) {
  const sk = Buffer.from(sodium.randombytes_buf(32));
  const eph = Buffer.from(sodium.crypto_scalarmult(sk, Buffer.of(9, ...Buffer.alloc(31))));
  const kp = await mlkem(cat(Buffer.of(0), sodium.randombytes_buf(64)));
  const kemPk = kp.subarray(0, 1184), kemSk = kp.subarray(1184);
  const head1 = cat(Buffer.of(3), eph, kemPk);
  const msg1 = cat(head1, seal(H(secret, H(ROOT, Buffer.of(3), eph, kemPk), L("c-probe")), NONCE0, Buffer.alloc(0)));
  const h1 = H(ROOT, msg1);
  const link = { msg1, send: null, recv: null };
  link.msg3 = async (w2) => {
    if (w2.length !== 1200) return null;
    const head = w2.subarray(0, 1120);
    const ee = Buffer.from(sodium.crypto_scalarmult(sk, head.subarray(0, 32)));
    const r = await mlkem(cat(Buffer.of(2), kemSk, head.subarray(32)));
    const pq = r.subarray(1);
    const hs = H(h1, head);
    const sig = open(H(ee, pq, secret, hs, L("c-msg2")), NONCE0, w2.subarray(1120));
    if (!sig || !sodium.crypto_sign_verify_detached(sig, cat(DOMAIN_LINK_SCOPE, DOMAIN_CHANNEL, ROOT, hs, relayPk), relayPk)) return null;
    const h2 = H(h1, w2);
    const w3 = seal(H(ee, pq, secret, h2, L("c-msg3")), NONCE0, cat(id.pk, nodeSign(id, cat(DOMAIN_CHANNEL, ROOT, h2, id.pk))));
    const h3 = H(h2, w3);
    link.send = { key: H(ee, pq, secret, h3, L("session-i->r")), ctr: 0 };
    link.recv = { key: H(ee, pq, secret, h3, L("session-r->i")), ctr: 0 };
    return w3;
  };
  link.seal = (pt) => seal(link.send.key, recordNonce(link.send.ctr++), pt);
  link.open = (ct) => {
    const pt = open(link.recv.key, recordNonce(link.recv.ctr), ct);
    if (pt) link.recv.ctr++;
    return pt;
  };
  return link;
}
