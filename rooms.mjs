// The app side of a seedrelay's rooms (relay.mjs): an app meets other keys in rooms, and
// hands the ones it meets to its seedkernel transport as `relay+` addresses, which the
// transport reaches through its own control socket. Rooms are discovery only; the
// transport knows nothing of them. Browser and Node alike: it needs WebSocket, WebCrypto's
// SHA-256, and a way to sign with the node's key; on a private relay, BLAKE2b too.

const utf8 = (s) => new TextEncoder().encode(s);
const DOMAIN_ROOMS = utf8("seedrelay-rooms-v1\0");
const DOMAIN_SECRET = utf8("seedrelay-secret-v1\0");
const ROOM_TAG = utf8("seedrelay-room-v1\0");
const T_CHALLENGE = 0x00, T_REGISTER = 0x01, T_JOIN = 0x02, T_LEAVE = 0x03,
  T_MEMBERS = 0x02, T_JOINED = 0x03, T_LEFT = 0x04, T_REFUSED = 0x07;
const ID_LEN = 32, NONCE_LEN = 32;
/** A dropped relay is dialed again after a wait that starts here and doubles with each
 *  drop in a row, drawn from its upper half so a relay's clients do not all come back at
 *  once. */
const RETRY_MS = 2000, RETRY_MAX_MS = 60_000;

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** A room's id, hex: SHA-256 of its name under ROOM_TAG, so the relay and anything in
 *  front of it never learn names, though the id is all it takes to join. */
export async function roomId(name) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", concat(ROOM_TAG, utf8(name)))));
}

/** Stay on the relay at `relay` (`ws[s]://host[:port]`) as `publicKey`, signing its
 *  challenges with `sign(message)` (the node's Ed25519 key, detached), and in the rooms
 *  `join` names. A relay started with `--secret` takes only a client given that `secret`,
 *  which it proves with a MAC and never sends; the MAC needs `blake2b(message)`, unkeyed
 *  BLAKE2b-512, which browsers lack: `(m) => sodium.crypto_generichash(64, m)`.
 *  `onMember(room, keyHex, present)` hears each key as it comes and goes, and
 *  `onRefused(room)` a room the relay had no seat for, which is then left. A dropped relay
 *  is redialed and its rooms joined again. */
export function roomClient({ relay, publicKey, sign, secret = null, blake2b = null, onMember, onRefused = () => {},
  WebSocket = globalThis.WebSocket }) {
  if (secret !== null && typeof blake2b !== "function") throw new Error("roomClient: a secret needs blake2b");
  const url = new URL(relay);
  const authority = url.host.toLowerCase(); // a URL drops a default port, as the relay does
  const wanted = new Map();  // room id to its name
  const heard = new Map();   // room id to the keys heard in it, for rooms asked for
  let ws = null, registered = false, closed = false, retryMs = RETRY_MS, timer = null;

  const send = (type, body) => { if (registered) ws.send(concat(Uint8Array.of(type), body)); };
  const ask = (id) => { heard.set(id, new Set()); send(T_JOIN, fromHex(id)); };
  const forget = (id) => {
    const keys = heard.get(id);
    heard.delete(id);
    for (const key of keys ?? []) onMember(wanted.get(id), key, false);
  };

  async function onMessage(m) {
    const type = m[0], body = m.subarray(1);
    if (type === T_CHALLENGE && body.length === NONCE_LEN && !registered) {
      const sig = new Uint8Array(await sign(concat(DOMAIN_ROOMS, utf8(authority), body)));
      // With a secret, BLAKE2b-512 over the signature and it: proof the relay can check,
      // which a listener cannot reuse, since the signature is over this socket's nonce.
      const mac = secret === null ? new Uint8Array(0)
        : new Uint8Array(await blake2b(concat(DOMAIN_SECRET, publicKey, sig, utf8(secret))));
      ws.send(concat(Uint8Array.of(T_REGISTER), publicKey, sig, mac));
    } else if (type === T_REGISTER && !registered) {
      registered = true;
      retryMs = RETRY_MS;
      for (const id of wanted.keys()) ask(id);
    } else if ((type === T_MEMBERS || type === T_JOINED || type === T_LEFT) &&
        body.length >= ID_LEN && (body.length - ID_LEN) % 32 === 0) {
      const id = hex(body.subarray(0, ID_LEN)), keys = heard.get(id);
      if (!keys) return; // a room left since
      for (let off = ID_LEN; off < body.length; off += 32) {
        const key = hex(body.subarray(off, off + 32));
        const changed = type === T_LEFT ? keys.delete(key) : !keys.has(key) && keys.add(key);
        if (changed) onMember(wanted.get(id), key, type !== T_LEFT);
      }
    } else if (type === T_REFUSED && body.length === ID_LEN) {
      const id = hex(body), name = wanted.get(id);
      if (!heard.has(id)) return;
      heard.delete(id);
      wanted.delete(id);
      onRefused(name);
    }
  }

  function connect() {
    timer = null;
    ws = new WebSocket(`${url.protocol}//${url.host}/v1/rooms`);
    ws.binaryType = "arraybuffer";
    ws.onmessage = (e) => { void onMessage(new Uint8Array(e.data)).catch(() => ws.close()); };
    ws.onclose = () => {
      registered = false;
      for (const id of [...heard.keys()]) forget(id);
      if (closed) return;
      timer = setTimeout(connect, retryMs * (1 + Math.random()) / 2);
      retryMs = Math.min(2 * retryMs, RETRY_MAX_MS);
    };
  }
  connect();

  return {
    /** Join the room named `name`. */
    async join(name) {
      const id = await roomId(name);
      if (wanted.has(id)) return;
      wanted.set(id, name);
      if (registered) ask(id);
    },
    /** Leave it: its members are heard leaving. */
    async leave(name) {
      const id = await roomId(name);
      if (!wanted.has(id)) return;
      if (heard.has(id)) { forget(id); send(T_LEAVE, fromHex(id)); }
      wanted.delete(id);
    },
    close() {
      closed = true;
      clearTimeout(timer);
      for (const id of [...heard.keys()]) forget(id);
      ws?.close();
    },
  };
}
