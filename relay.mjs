// The rendezvous and forwarder for seedkernel nodes (§12.7), as a signed seedkernel bundle,
// bundle/relay.skb (guest/relay.js, signed by scripts/build.mjs), that a node runs as its
// link occupant: the relay's sockets are that node's, and its code runs confined in the
// node's realm. This module is the Node side: the command line (`parseOptions`), the
// settings the bundle reads (`relayConfig`), and `startRelay`, which runs it on a
// seedkernel node in this process. The native binary runs the same bundle (`seedkernel
// --transport bundle/relay.skb`). It lives in seedrelay because it is a deployment concern,
// not trusted runtime surface: the kernel ships no server and its own tests use an
// in-process relay.

import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { loadCrypto } from "seedkernel-wasm";
import { bootShell } from "seedkernel-wasm/shell-core";
import { nodeChannels, nodeDatagrams } from "seedkernel-wasm/shell-node";
import { OpArgs } from "seedkernel-wasm/op-frame";

// ─── limits ──────────────────────────────────────────────────────────────
//
// Independent caps that bound the relay's footprint against both accidental fan-out and
// deliberate exhaustion. A room whose N members all stay relayed costs N(N-1) splice
// sockets, N control sockets and N room sockets, and its smallest key, which calls the
// rest, is charged 2(N-1) + 2 of them, its app's room socket included. The defaults fit
// one full room so relayed on its share of the relay (992 of 1792 splice sockets) and
// within its caller's share of an address (64 of 72, with room to redial); rooms whose
// pairs move to direct links cost far less.
export const DEFAULT_LIMITS = Object.freeze({
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

/** The UDP port STUN is answered on by default, and the next. */
const STUN_PORT = 3478;

/** The local service id the bundle claims, for the host's `start` and `close`. */
export const RELAY_SERVICE = "_relay";

// The command line, flag by flag: its limit, environment variable, and the largest integer
// it takes (Infinity for any number).
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

/** The bin's options from its arguments and environment: `port`, `host`, `stun` (the first
 *  of two UDP ports, 0 for two the OS picks, null for none), and the relay's settings.
 *  Anything malformed or unknown throws: a relay that starts with a limit it was not given
 *  is worse than one that does not start. */
export function parseOptions(argv, env = {}) {
  const options = { port: 8080, host: "127.0.0.1", authorities: [], allowOrigins: [], trustedProxies: [], secrets: [],
    limits: {}, stun: STUN_PORT };
  const number = (flag, value, max) => {
    const n = Number(value);
    if (typeof value !== "string" || value.trim() === "" || !Number.isFinite(n) || n < 0 || n > max ||
        (max !== Infinity && !Number.isInteger(n))) {
      throw new Error(`${flag} takes ${max === Infinity ? "a non-negative number" : `an integer from 0 to ${max}`}, not ${JSON.stringify(value ?? "")}`);
    }
    return n;
  };
  const list = (value) => (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  for (const [name, variable, max] of Object.values(LIMIT_FLAGS)) {
    if (env[variable] !== undefined) options.limits[name] = number(variable, env[variable], max);
  }
  for (const a of list(env.RELAY_AUTHORITIES)) options.authorities.push(authorityOption(a));
  for (const ip of list(env.RELAY_TRUSTED_PROXIES)) options.trustedProxies.push(proxyOption(ip));
  for (const secret of list(env.RELAY_SECRETS)) options.secrets.push(secretOption(secret));
  const stun = (flag, value) => (value === "off" ? null : number(flag, value, 65534));
  if (env.RELAY_STUN !== undefined) options.stun = stun("RELAY_STUN", env.RELAY_STUN);

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a in LIMIT_FLAGS) options.limits[LIMIT_FLAGS[a][0]] = number(a, value(), LIMIT_FLAGS[a][2]);
    else if (a === "--port") options.port = number(a, value(), 65535);
    else if (a === "--host") options.host = unbracket(value());
    else if (a === "--authority") options.authorities.push(authorityOption(value()));
    else if (a === "--allow-origin") options.allowOrigins.push(value());
    else if (a === "--trusted-proxy") options.trustedProxies.push(proxyOption(value()));
    else if (a === "--secret") options.secrets.push(secretOption(value()));
    else if (a === "--stun") options.stun = stun(a, value());
    else if (/^\d+$/.test(a)) options.port = number("the port", a, 65535);
    else throw new Error(`unknown option ${a}`);
  }
  if (env.RELAY_SECRETS !== undefined && options.secrets.length === 0) {
    // An explicitly set variable with no secret is a half-configured private relay,
    // unless a --secret flag supplied one.
    throw new Error("RELAY_SECRETS is set but names no secret; unset it for an open relay");
  }
  if (options.authorities.length === 0 && isWildcardHost(options.host)) {
    const bound = options.host === "" ? "every interface" : options.host;
    throw new Error(`a relay bound to ${bound} needs --authority: the host[:port] nodes dial it by`);
  }
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

/** Whether binding `host` listens on every interface. Node treats an empty host and every
 *  spelling of an unspecified address as a wildcard, so the --authority guard must too. */
function isWildcardHost(host) {
  const ip = normalizeIp(host);
  return host === "" || ip === "0.0.0.0" || ip === "::";
}

const LOOPBACK_NAMES = ["localhost", "127.0.0.1", "::1"];

/** Whether `host`, as `parseOptions` gives it, is reachable from this machine only. */
export function isLoopbackHost(host) {
  const ip = normalizeIp(host);
  return host === "localhost" || ip === "::1" || /^127\./.test(ip ?? "");
}

/** The names a relay bound to `host` answers to when none are given: the loopback names
 *  on a loopback address, else the address itself. A relay nodes reach under any other
 *  name (a public one, behind a proxy), or bound to every interface, needs `--authority`. */
export function localAuthorities(host, port) {
  const names = isLoopbackHost(host) ? LOOPBACK_NAMES : [normalizeIp(host) ?? host];
  return names.map((name) => canonicalAuthority(`${bracket(name)}:${port}`));
}

// Opaque origins (including file pages and sandboxed iframes) are not allowed by default.
// Operators can explicitly opt in with --allow-origin null.
const LOCAL_ORIGINS = [];
for (const scheme of ["http", "https"]) {
  for (const host of LOOPBACK_NAMES.map(bracket)) {
    LOCAL_ORIGINS.push(`${scheme}://${host}`);
    for (const port of [80, 443, 3000, 5173, 8000, 8080, 8443]) LOCAL_ORIGINS.push(`${scheme}://${host}:${port}`);
  }
}

/** A host without the brackets a URL puts around an IPv6 address. */
function unbracket(host) {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/** A host as a URL or an authority names it: an IPv6 address in brackets. */
export function bracket(host) {
  return host.includes(":") ? `[${host}]` : host;
}

/** An IP address in one spelling, as the bundle spells it: IPv4 dotted, IPv4-mapped IPv6
 *  as IPv4, other IPv6 as URL hosts compress it. Null for anything else, scoped IPv6
 *  included. */
function normalizeIp(value) {
  const version = value.includes("%") ? 0 : isIP(value);
  if (version === 0) return null;
  if (version === 4) return value;
  const normalized = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(normalized);
  if (!mapped) return normalized;
  const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

/** Lowercase, without a default port, so the Host a browser sends for
 *  wss://relay.example matches the relay.example:443 a node dials. */
function canonicalAuthority(host) {
  return host.toLowerCase().replace(/:(?:80|443)$/, "");
}

// ─── the bundle ──────────────────────────────────────────────────────────

/** The signed bundle, as scripts/build.mjs writes it. */
export const RELAY_BUNDLE = new URL("./bundle/relay.skb", import.meta.url);

/** The bundle's signed settings; the operator's override any of them (`relayConfig`). */
export const RELAY_DEFAULTS = { limits: DEFAULT_LIMITS, authorities: [], allowOrigins: LOCAL_ORIGINS, trustedProxies: [],
  secrets: [], stun: STUN_PORT };

/** The operator's settings, from `parseOptions`, as the bundle reads them: what a node
 *  passes it as `--transport-config`. An empty `allowOrigins` keeps the localhost
 *  defaults. */
export function relayConfig(options) {
  const config = { limits: options.limits, authorities: options.authorities, trustedProxies: options.trustedProxies,
    secrets: options.secrets, stun: options.stun };
  if (options.allowOrigins.length > 0) config.allowOrigins = options.allowOrigins;
  return config;
}

/** Run the relay on a seedkernel node in this process, listening on `options.host` and
 *  `options.port`. Answers the port it bound, the STUN ports, the names it answers to, and
 *  `close`, which tells every socket the relay is restarting and then stops the node. Each
 *  of the relay's log lines goes to `log`. */
export async function startRelay(options, log = (line) => console.log(line)) {
  const sodium = await loadCrypto();
  const { shell, transport } = await bootShell({
    sodium,
    identity: sodium.crypto_sign_keypair(),
    fs: false,
    transport: {
      bundle: readFileSync(RELAY_BUNDLE),
      listen: [{ label: "ws", host: options.host, port: options.port }],
      config: relayConfig(options),
      channels: nodeChannels(),
      datagrams: nodeDatagrams(),
      onStatus: (line) => log(new TextDecoder().decode(line)),
      suppressLinkLog: true,
    },
  });
  try {
    const port = transport.portOf("ws");
    const authorities = options.authorities.length > 0 ? options.authorities : localAuthorities(options.host, port);
    const start = new OpArgs("start");
    for (const name of authorities) start.text(name);
    const answer = await shell.call(RELAY_SERVICE, start.build());
    const stunPorts = [];
    for (let at = 0; at + 2 <= answer.length; at += 2) stunPorts.push((answer[at] << 8) | answer[at + 1]);
    return {
      port, stunPorts, authorities,
      async close(graceMs = 2000) {
        await shell.call(RELAY_SERVICE, new OpArgs("close").build());
        await new Promise((r) => setTimeout(r, graceMs).unref());
        shell.close();
      },
    };
  } catch (err) {
    shell.close();
    throw err;
  }
}
