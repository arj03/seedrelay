#!/usr/bin/env node
// The seedrelay bin: the relay bundle (bundle/relay.skb) on a seedkernel node in this
// process, on a port. On SIGTERM or SIGINT it tells every socket the relay is restarting
// (close code 1012) before it exits. `--print-config` prints the settings the flags make,
// as the JSON a native node takes with `--transport-config`, and exits.
//
// Run: seedrelay [port] [options]  (or: node server.mjs)
//   --port N               port to listen on (default 8080; a bare number works too)
//   --host HOST            interface to bind (default 127.0.0.1)
//   --authority NAME       a host[:port] nodes dial this relay by (repeatable; env
//                          RELAY_AUTHORITIES; default the bound address's own names)
//   --allow-origin ORIGIN  allow this Origin (repeatable; replaces the localhost defaults)
//   --max-conns N          total concurrent sockets        (env RELAY_MAX_CONNS)
//   --max-rooms N          total concurrent rooms          (env RELAY_MAX_ROOMS)
//   --max-per-room N       registered sockets per room, at most 1024
//                                                          (env RELAY_MAX_PER_ROOM)
//   --max-per-ip N         sockets per client address      (env RELAY_MAX_PER_IP)
//   --max-per-room-ip N    sockets per address in one room (env RELAY_MAX_PER_ROOM_IP)
//   --ipv6-prefix N        IPv6 bits that name one client  (env RELAY_IPV6_PREFIX)
//   --register-rate N      sockets an address registers, and rooms it joins, per second,
//                          0=unmetered                     (env RELAY_REGISTER_RATE)
//   --splice-rate N        KiB/s an address sends through splices, 0=unmetered
//                                                          (env RELAY_SPLICE_RATE)
//   --heartbeat-secs N     ping/reap interval, 0=off       (env RELAY_HEARTBEAT_SECS)
//   --trusted-proxy IP     trust this proxy address (repeatable; env RELAY_TRUSTED_PROXIES)
//   --secret SECRET        register only nodes and apps given this secret, 16+ characters,
//                          no commas (repeatable; env RELAY_SECRETS, which keeps it out of `ps`)
//   --stun PORT|off        answer STUN on this UDP port and the next, on every interface
//                          (default 3478; 0 for two the OS picks; env RELAY_STUN)
//   --print-config         print the settings as a native node's --transport-config, and exit

import { bracket, DEFAULT_LIMITS, isLoopbackHost, localAuthorities, parseOptions, relayConfig, startRelay } from "./relay.mjs";

const args = process.argv.slice(2);
const printConfig = args.includes("--print-config");
let options;
try {
  options = parseOptions(args.filter((a) => a !== "--print-config"), process.env);
} catch (e) {
  console.error(`seedrelay: ${e.message}`);
  process.exit(2);
}

if (printConfig) {
  const config = relayConfig(options);
  if (config.authorities.length === 0) config.authorities = localAuthorities(options.host, options.port);
  console.log(JSON.stringify(config, null, 2));
  process.exit(0);
}

const { host } = options;
let relay;
try {
  relay = await startRelay(options);
} catch (e) {
  console.error(`seedrelay: ${e.message}`);
  process.exit(1);
}
const l = { ...DEFAULT_LIMITS, ...options.limits };
console.log(`seedrelay listening on ws://${bracket(host)}:${relay.port}/v1/`);
console.log(`  answers to: ${relay.authorities.join(", ")}`);
console.log(`  origin allowlist: ${options.allowOrigins.length ? options.allowOrigins.slice(0, 4).join(", ") : "localhost pages"}`);
console.log(`  registration: ${options.secrets.length ? `needs a secret (${options.secrets.length} accepted)` : "open to any key"}`);
console.log(`  limits: ${l.maxConns} conns, ${l.maxRooms} rooms, ${l.maxPerRoom}/room, ${l.maxPerIp}/ip, ${l.maxPerRoomIp}/ip in a room, ` +
  `IPv6 by /${l.ipv6Prefix}, registrations ${l.registerRate > 0 ? `${l.registerRate}/s per ip` : "unmetered"}, ` +
  `splices ${l.spliceRate > 0 ? `${l.spliceRate} KiB/s per ip` : "unmetered"}${options.trustedProxies.length ? " (X-Forwarded-For trusted)" : ""}`);
for (const port of relay.stunPorts) console.log(`  STUN on udp port ${port}`);
console.log(`  heartbeat: ${l.heartbeatSecs > 0 ? `${l.heartbeatSecs}s ping/reap` : "disabled"}`);
if (!isLoopbackHost(host)) console.log(`  ⚠  bound to ${host || "every interface"}: exposed to the network`);

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.once(signal, () => {
    // Sockets whose far ends never close hold the process no longer than this.
    setTimeout(() => process.exit(0), 3000).unref();
    void relay.close().then(() => process.exit(0));
  });
}
