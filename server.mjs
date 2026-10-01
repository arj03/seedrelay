#!/usr/bin/env node
// The seedrelay bin: the relay (relay.mjs) on a port. On SIGTERM or SIGINT it tells every
// socket the relay is restarting (close code 1012) before it exits.
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
//   --stun [HOST:]PORT     answer STUN on this UDP port, on --host unless named (env RELAY_STUN)

import { createSocket } from "node:dgram";
import { createRelay, localAuthorities, parseOptions } from "./relay.mjs";

let options;
try {
  options = parseOptions(process.argv.slice(2), process.env);
} catch (e) {
  console.error(`seedrelay: ${e.message}`);
  process.exit(2);
}

const relay = createRelay(options);
const { host } = options;
const bracket = (h) => (h.includes(":") ? `[${h}]` : h);

let udp = null;
if (options.stun) {
  udp = createSocket(options.stun.host.includes(":") ? "udp6" : "udp4");
  udp.on("message", (msg, from) => {
    const answer = relay.stun(msg, from.address, from.port);
    if (answer) udp.send(answer, from.port, from.address);
  });
  udp.on("error", (e) => { console.error(`seedrelay: STUN: ${e.message}`); process.exit(1); });
  udp.bind(options.stun.port, options.stun.host, () => {
    console.log(`  STUN on udp://${bracket(options.stun.host)}:${udp.address().port}`);
  });
}
relay.server.listen(options.port, host, () => {
  const port = relay.server.address().port;
  if (relay.authorities.size === 0) for (const name of localAuthorities(host, port)) relay.authorities.add(name);
  const l = relay.limits;
  console.log(`seedrelay listening on ws://${bracket(host)}:${port}/v1/`);
  console.log(`  answers to: ${[...relay.authorities].join(", ")}`);
  console.log(`  origin allowlist: ${[...relay.origins].slice(0, 4).join(", ")}…`);
  console.log(`  registration: ${relay.secrets.length ? `needs a secret (${relay.secrets.length} accepted)` : "open to any key"}`);
  console.log(`  limits: ${l.maxConns} conns, ${l.maxRooms} rooms, ${l.maxPerRoom}/room, ${l.maxPerIp}/ip, ${l.maxPerRoomIp}/ip in a room, ` +
    `IPv6 by /${l.ipv6Prefix}, registrations ${l.registerRate > 0 ? `${l.registerRate}/s per ip` : "unmetered"}, ` +
    `splices ${l.spliceRate > 0 ? `${l.spliceRate} KiB/s per ip` : "unmetered"}${relay.proxies.size ? " (X-Forwarded-For trusted)" : ""}`);
  console.log(`  heartbeat: ${l.heartbeatSecs > 0 ? `${l.heartbeatSecs}s ping/reap` : "disabled"}`);
  if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
    console.log(`  ⚠  bound to ${host}: exposed to the network`);
  }
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.once(signal, () => {
    relay.close();
    relay.server.close();
    udp?.close();
    // Sockets whose far ends never close hold the process no longer than this.
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
