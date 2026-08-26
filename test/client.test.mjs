import test from "node:test";
import assert from "node:assert/strict";

import { createRelaySignaling } from "../client.js";

class FakeWebSocket {
  static OPEN = 1;
  readyState = 0;
  sent = [];
  closed = false;
  #listeners = new Map();

  constructor(url) { this.url = url; }
  addEventListener(type, callback) {
    const callbacks = this.#listeners.get(type) ?? [];
    callbacks.push(callback);
    this.#listeners.set(type, callbacks);
  }
  send(value) { this.sent.push(value); }
  close() { this.closed = true; this.readyState = 3; }
  dispatch(type, fields = {}) {
    if (type === "open") this.readyState = FakeWebSocket.OPEN;
    for (const callback of this.#listeners.get(type) ?? []) callback({ type, ...fields });
  }
}

function fixture() {
  const sockets = [];
  const states = [];
  const relay = createRelaySignaling({
    webSocketFactory: (url) => {
      const socket = new FakeWebSocket(url);
      sockets.push(socket);
      return socket;
    },
    onStateChange: ({ state, url }) => states.push([state, url]),
  });
  return { relay, sockets, states };
}

test("queues JSON until connected and decodes text messages", () => {
  const { relay, sockets, states } = fixture();
  const received = [];
  relay.signaling.onMessage((message) => received.push(message));
  relay.signaling.send({ type: "hello" });

  relay.connect("ws://relay.test/alpha");
  assert.deepEqual(states, [["connecting", "ws://relay.test/alpha"]]);
  assert.deepEqual(sockets[0].sent, []);
  sockets[0].dispatch("open");
  assert.deepEqual(sockets[0].sent, ['{"type":"hello"}']);
  assert.deepEqual(states.at(-1), ["connected", "ws://relay.test/alpha"]);

  sockets[0].dispatch("message", { data: '{"type":"ice","candidate":{}}' });
  sockets[0].dispatch("message", { data: "not json" });
  sockets[0].dispatch("message", { data: new Uint8Array([1]) });
  assert.deepEqual(received, [{ type: "ice", candidate: {} }]);
});

test("reconnects without letting stale socket events escape", () => {
  const { relay, sockets, states } = fixture();
  const received = [];
  relay.signaling.onMessage((message) => received.push(message));
  relay.connect("ws://relay.test/one");
  sockets[0].dispatch("open");

  relay.connect("ws://relay.test/two");
  assert.equal(sockets[0].closed, true);
  sockets[0].dispatch("close");
  sockets[0].dispatch("message", { data: '{"stale":true}' });
  assert.deepEqual(states.at(-1), ["connecting", "ws://relay.test/two"]);
  assert.deepEqual(received, []);

  relay.signaling.send({ fresh: true });
  sockets[1].dispatch("open");
  assert.deepEqual(sockets[1].sent, ['{"fresh":true}']);
  sockets[1].dispatch("message", { data: '{"fresh":true}' });
  assert.deepEqual(received, [{ fresh: true }]);
});

test("disconnect preserves pending messages while Signaling.close discards them", () => {
  const { relay, sockets, states } = fixture();
  relay.connect("ws://relay.test/room");
  relay.signaling.send({ before: "disconnect" });
  relay.disconnect();
  assert.deepEqual(states.at(-1), ["disconnected", "ws://relay.test/room"]);

  relay.connect("ws://relay.test/room");
  sockets[1].dispatch("open");
  assert.deepEqual(sockets[1].sent, ['{"before":"disconnect"}']);
  relay.disconnect();
  relay.signaling.send({ before: "close" });
  relay.signaling.close();
  relay.connect("ws://relay.test/room");
  sockets[2].dispatch("open");
  assert.deepEqual(sockets[2].sent, []);
});

test("rejects invalid factories, callbacks, URLs, and non-JSON messages", () => {
  assert.throws(() => createRelaySignaling({ webSocketFactory: 1 }), /webSocketFactory/);
  assert.throws(() => createRelaySignaling({ onStateChange: 1 }), /onStateChange/);
  const { relay } = fixture();
  assert.throws(() => relay.connect(""), /connect URL/);
  assert.throws(() => relay.signaling.onMessage(null), /callback/);
  assert.throws(() => relay.signaling.send(undefined), /JSON-serializable/);
});
