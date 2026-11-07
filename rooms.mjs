// The app side of a seedrelay's rooms (guest/relay.js): an app meets other keys in rooms,
// and hands the ones it meets to its seedkernel transport as `relay+` addresses. Rooms
// travel on the node's own relay link, inside its records, as tells: the transport's
// `tell` op hands a message to the home relay unread, and the relay's come back in the
// transport's status after a first byte of 1. Rooms are discovery only; the transport
// knows nothing of them. Browser and Node alike: it needs WebCrypto's SHA-256.
const utf8 = (s) => new TextEncoder().encode(s);
const ROOM_TAG = utf8("seedrelay-room-v1\0");
const ROOM_SECRET_TAG = utf8("seedrelay-room-secret-v1\0");
const T_JOIN = 0x02, T_LEAVE = 0x03, T_MEMBERS = 0x02, T_JOINED = 0x03, T_LEFT = 0x04, T_REFUSED = 0x07;
const ID_LEN = 32, PK_LEN = 32;
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
const message = (type, id) => {
  const out = new Uint8Array(1 + ID_LEN);
  out[0] = type;
  out.set(fromHex(id), 1);
  return out;
};

const sha256 = async (tag, name) => new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...tag, ...utf8(name)])));

/** A room's id, hex: SHA-256 of its name under ROOM_TAG, so the relay and anything in
 *  front of it never learn names, though the id is all it takes to join. */
export async function roomId(name) {
  return hex(await sha256(ROOM_TAG, name));
}

/** A room's secret, 32 bytes: SHA-256 of its name under a tag of its own, so the relay,
 *  which sees only the id, cannot derive it. Everyone who knows the name holds it, which is
 *  who the room admits: a node hands it to its transport's `secrets`, so room-mates are
 *  answered, and dials them under it (`addr`). A guessable name is a public room, and its
 *  secret gates nothing. */
export async function roomSecret(name) {
  return sha256(ROOM_SECRET_TAG, name);
}

/** Rooms on the node's home relay. `tell(bytes)` hands one message to the transport's
 *  `tell` op and resolves to whether it went; feed `status` every status the transport
 *  says (`onStatus`): it reads what the relay told the node, and asks for every room again
 *  each time the node registers on its relay again, since a relay forgets the seats of a
 *  link that went. `onMember(room, keyHex, present)` hears each key as it comes and goes,
 *  and `onRefused(room)` a room the relay had no seat for, which is then left. Who is in a
 *  room stays as last heard while the relay is away: the keys have not gone anywhere, and
 *  one that has is heard leaving once the room is joined again. */
export function roomClient({ tell, onMember, onRefused = () => {} }) {
  const wanted = new Map();  // room id to its name
  const heard = new Map();   // room id to the keys heard in it, for rooms asked for
  const ask = (id) => {
    if (!heard.has(id)) heard.set(id, new Set());
    return tell(message(T_JOIN, id));
  };
  let registered = false;
  const forget = (id) => {
    const keys = heard.get(id);
    heard.delete(id);
    for (const key of keys ?? []) onMember(wanted.get(id), key, false);
  };

  return {
    /** Join the room named `name`. Resolves to whether the relay was told; one it was not
     *  is asked at the next `registered`. */
    async join(name) {
      const id = await roomId(name);
      if (wanted.has(id)) return true;
      wanted.set(id, name);
      return ask(id);
    },
    /** Leave it: its members are heard leaving. */
    async leave(name) {
      const id = await roomId(name);
      if (!wanted.has(id)) return;
      forget(id);
      wanted.delete(id);
      await tell(message(T_LEAVE, id));
    },
    /** One status of the transport's: `[0][relay u8]…`, its standing, or `[1]` and what
     *  the relay told the node. */
    status(s) {
      if (s[0] === 0) {
        if (s[1] === 1 && !registered) for (const id of wanted.keys()) void ask(id);
        registered = s[1] === 1;
        return;
      }
      if (s[0] !== 1) return;
      const type = s[1], body = s.subarray(2);
      if ((type === T_MEMBERS || type === T_JOINED || type === T_LEFT) &&
          body.length >= ID_LEN && (body.length - ID_LEN) % PK_LEN === 0) {
        const id = hex(body.subarray(0, ID_LEN)), keys = heard.get(id);
        if (!keys) return; // a room left since
        const named = [];
        for (let off = ID_LEN; off < body.length; off += PK_LEN) named.push(hex(body.subarray(off, off + PK_LEN)));
        if (type === T_MEMBERS) {
          // The room as it stands: a key heard before a redial that is not in it has left.
          const there = new Set(named);
          for (const key of [...keys]) {
            if (!there.has(key) && keys.delete(key)) onMember(wanted.get(id), key, false);
          }
        }
        for (const key of named) {
          const changed = type === T_LEFT ? keys.delete(key) : !keys.has(key) && keys.add(key);
          if (changed) onMember(wanted.get(id), key, type !== T_LEFT);
        }
      } else if (type === T_REFUSED && body.length === ID_LEN) {
        const id = hex(body), name = wanted.get(id);
        if (!heard.has(id)) return;
        forget(id);
        wanted.delete(id);
        onRefused(name);
      }
    },
    /** Every member is heard leaving, and nothing more is asked. */
    close() {
      for (const id of [...heard.keys()]) forget(id);
      wanted.clear();
    },
  };
}
