#!/usr/bin/env node
// A TLS front for a relay and a page, for a server with a certificate and no proxy: it
// serves the files under --root over HTTPS and passes WebSocket upgrades under /v1/ to the
// relay, so https://NAME:PORT/ is the page and wss://NAME:PORT the relay. No dependencies.
//
// Run: node scripts/https-front.mjs --cert FILE --key FILE --root DIR [options]
//   --cert FILE        the certificate chain, PEM (Let's Encrypt's fullchain.pem)
//   --key FILE         its private key, PEM (Let's Encrypt's privkey.pem)
//   --root DIR         the directory to serve
//   --port N           port to listen on (default 8443)
//   --host HOST        interface to bind (default every one)
//   --index FILE       the file served for / (default index.html)
//   --relay HOST:PORT  where the relay listens (default 127.0.0.1:8080)
//
// The relay sees this front as its client, so it needs --trusted-proxy with the address
// this front dials it from (127.0.0.1) to read the visitor's own from X-Forwarded-For,
// --authority NAME:PORT, and --allow-origin https://NAME:PORT for the page.
//
// The certificate is read once: restart the front after it renews.

import { createServer } from "node:https";
import { connect } from "node:net";
import { createReadStream, readFileSync, statSync } from "node:fs";
import { extname, resolve, sep } from "node:path";

function fail(message) {
  console.error(`https-front: ${message}`);
  process.exit(2);
}

const options = { cert: null, key: null, root: null, port: "8443", host: null, index: "index.html", relay: "127.0.0.1:8080" };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 2) {
  const name = argv[i].startsWith("--") ? argv[i].slice(2) : "";
  if (!Object.hasOwn(options, name)) fail(`unknown option ${argv[i]}`);
  if (i + 1 >= argv.length) fail(`${argv[i]} needs a value`);
  options[name] = argv[i + 1];
}
for (const name of ["cert", "key", "root"]) if (!options[name]) fail(`--${name} is required`);

const port = Number(options.port);
if (!Number.isInteger(port) || port < 0 || port > 65535) fail(`--port takes a port, not ${JSON.stringify(options.port)}`);
const target = /^\[?([^\]\s]+?)\]?:(\d+)$/.exec(options.relay);
if (!target) fail(`--relay takes host:port, not ${JSON.stringify(options.relay)}`);
const relay = { host: target[1], port: Number(target[2]) };

const root = resolve(options.root);
let tls;
try {
  if (!statSync(root).isDirectory()) fail(`--root ${root} is not a directory`);
  tls = { cert: readFileSync(options.cert), key: readFileSync(options.key) };
} catch (e) {
  fail(e.message);
}

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".wasm": "application/wasm", // a browser compiles a streamed module only under this type
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

// How long a socket this front ended is given to close before it is destroyed.
const END_WAIT_MS = 10_000;

/** End a socket so what is queued for it still goes out, and give up on its far end
 *  after END_WAIT_MS. */
function endSoon(sock) {
  sock.end();
  setTimeout(() => sock.destroy(), END_WAIT_MS).unref();
}

const server = createServer(tls, (req, res) => {
  const answer = (status) => { res.writeHead(status, { "Content-Length": 0 }); res.end(); };
  if (req.method !== "GET" && req.method !== "HEAD") { answer(405); return; }
  let path;
  try { path = decodeURIComponent(new URL(req.url, "http://front").pathname); } catch { answer(400); return; }
  if (path.includes("\0")) { answer(400); return; }
  // Resolved and then checked, so no spelling of `..` leaves the root.
  const file = resolve(root, "." + (path === "/" ? `/${options.index}` : path));
  let stat = null;
  try { if (file.startsWith(root + sep)) stat = statSync(file); } catch { /* no such file */ }
  if (!stat?.isFile()) { answer(404); return; }
  res.writeHead(200, {
    "Content-Type": TYPES[extname(file).toLowerCase()] ?? "application/octet-stream",
    "Content-Length": stat.size,
    // Revalidated on every load, so a page is never run against a stale vendor/.
    "Cache-Control": "no-cache",
  });
  if (req.method === "HEAD") { res.end(); return; }
  createReadStream(file).on("error", () => res.destroy()).pipe(res);
});

// The upgrade request goes to the relay as it came, Host included, since that is the name
// registrations are signed for. The relay answers it, refusals too.
server.on("upgrade", (req, sock, head) => {
  if (!req.url.startsWith("/v1/")) { sock.destroy(); return; }
  const lines = [`${req.method} ${req.url} HTTP/1.1`];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    // The relay trusts this header from this front, so a visitor's own never reaches it.
    if (req.rawHeaders[i].toLowerCase() === "x-forwarded-for") continue;
    lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
  }
  lines.push(`X-Forwarded-For: ${sock.remoteAddress}`);
  const up = connect(relay.port, relay.host, () => {
    up.write(lines.join("\r\n") + "\r\n\r\n");
    if (head.length) up.write(head);
    up.pipe(sock);
    sock.pipe(up);
  });
  up.on("error", () => sock.destroy());
  sock.on("error", () => up.destroy());
  up.on("close", () => endSoon(sock));
  sock.on("close", () => endSoon(up));
});

server.on("error", (e) => { console.error(`https-front: ${e.message}`); process.exit(1); });
server.listen(port, options.host ?? undefined, () => {
  const at = server.address();
  console.log(`https-front listening on https://${at.address.includes(":") ? `[${at.address}]` : at.address}:${at.port}/`);
  console.log(`  serving ${root}, with ${options.index} at /`);
  console.log(`  /v1/ upgrades go to the relay at ${relay.host}:${relay.port}`);
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.once(signal, () => {
    server.close();
    server.closeAllConnections();
    // Spliced sockets are not the server's to close, and hold the process no longer than this.
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
