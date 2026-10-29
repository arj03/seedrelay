// Sign the relay bundle into bundle/relay.skb, which the bin and a native node run as it
// is, so running the relay needs no signing and no build:
//
//   seedkernel --transport bundle/relay.skb --listen ws=0.0.0.0:8080 --transport-config relay.json
//
// The bundle is the guest (guest/relay.js, with the op-frame seedkernel's host speaks put in
// at its marker) and seedkernel's ws.wasm, under the signed defaults (relay.mjs). relay.skb
// is rewritten only when that content changed, since every signature differs; `--check`
// fails instead when it would be. The author key is `--key <hex seed>` or relay.key,
// written on the first build.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { loadCrypto } from "seedkernel-wasm";
import { envelopeBody } from "seedkernel-wasm/bundle";
import { authorBundle, guestOpFraming, hybridAuthorKeysFromSeed } from "seedkernel-wasm/bundle-author";
import { RELAY_BUNDLE, RELAY_DEFAULTS, RELAY_SERVICE } from "../relay.mjs";

const check = process.argv.includes("--check");
const keyFile = new URL("../relay.key", import.meta.url);
const flag = process.argv.indexOf("--key");
let seed;
if (check) seed = randomBytes(32);
else if (flag >= 0) seed = Buffer.from(process.argv[flag + 1] ?? "", "hex");
else if (existsSync(keyFile)) seed = Buffer.from(readFileSync(keyFile, "utf8").trim(), "hex");
else {
  seed = randomBytes(32);
  writeFileSync(keyFile, seed.toString("hex") + "\n", { mode: 0o600 });
  console.log("  wrote relay.key (keep it; this clone's builds are signed by it)");
}

const sodium = await loadCrypto();
const guest = readFileSync(new URL("../guest/relay.js", import.meta.url), "utf8")
  .replace("/* @seedkernel-op-frame */", () => guestOpFraming());
const { blob } = authorBundle(sodium, hybridAuthorKeysFromSeed(sodium, new Uint8Array(seed)), {
  app: "relay",
  version: 1,
  services: [RELAY_SERVICE],
  modules: [{ name: "ws", wasm: readFileSync(new URL(import.meta.resolve("seedkernel-wasm/ws.wasm"))) }],
  guestSource: guest,
  guestRequires: ["node", "link", "timer"],
  guestConfig: RELAY_DEFAULTS,
});

const current = existsSync(RELAY_BUNDLE) &&
  Buffer.compare(envelopeBody(readFileSync(RELAY_BUNDLE), "relay.skb"), envelopeBody(blob, "relay.skb")) === 0;
if (check) {
  if (!current) {
    console.error("bundle/relay.skb is not the bundle of guest/relay.js and the defaults in relay.mjs: run npm run build");
    process.exit(1);
  }
} else if (current) {
  console.log("  bundle/relay.skb is current");
} else {
  mkdirSync(new URL(".", RELAY_BUNDLE), { recursive: true });
  writeFileSync(RELAY_BUNDLE, blob);
  console.log(`  relay bundle: bundle/relay.skb (${blob.length} B)`);
}
