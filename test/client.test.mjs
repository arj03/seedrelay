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

test("queued signaling never crosses room or server boundaries", () => {
  const { relay, sockets } = fixture();
  relay.connect("wss://relay.test/private");
  relay.signaling.send({ sdp: "private offer" });
  relay.disconnect();
  relay.connect("wss://relay.test/public");
  sockets[1].dispatch("open");
  assert.deepEqual(sockets[1].sent, []);
  relay.disconnect();
  relay.signaling.send({ candidate: "private address" });
  relay.connect("wss://different.test/public");
  sockets[2].dispatch("open");
  assert.deepEqual(sockets[2].sent, []);
});

test("failed destination changes cannot retain another room's messages", () => {
  const sockets = [];
  const relay = createRelaySignaling({ webSocketFactory(url) {
    if (url.endsWith("/bad")) throw new Error("failed");
    const socket = new FakeWebSocket(url); sockets.push(socket); return socket;
  } });
  relay.connect("wss://relay.test/private");
  relay.signaling.send({ secret: true });
  assert.throws(() => relay.connect("wss://relay.test/bad"), /failed/);
  relay.connect("wss://relay.test/public");
  sockets[1].dispatch("open");
  assert.deepEqual(sockets[1].sent, []);
});

test("offline queue has message and UTF-8 byte limits, freed on close", () => {
  const { relay, sockets } = fixture();
  for (let i = 0; i < 256; i++) relay.signaling.send({ i });
  assert.throws(() => relay.signaling.send({ overflow: true }), /buffer is full/);
  relay.signaling.close();
  // Each JSON string is exactly 64 KiB in UTF-8, despite fewer JS characters.
  const message = "é".repeat(32767);
  for (let i = 0; i < 4; i++) relay.signaling.send(message);
  assert.throws(() => relay.signaling.send("x"), /buffer is full/);
  assert.throws(() => relay.signaling.send(message + "é"), /exceeds 64 KiB/);
  relay.connect("wss://relay.test/room");
  sockets[0].dispatch("open");
  assert.equal(sockets[0].sent.length, 4);
  relay.signaling.send("after drain");
  assert.equal(sockets[0].sent.length, 5);
});

test("connected sends account for the WebSocket's own buffered bytes", () => {
  const { relay, sockets } = fixture();
  relay.connect("wss://relay.test/room");
  sockets[0].dispatch("open");
  sockets[0].bufferedAmount = 256 * 1024;
  assert.throws(() => relay.signaling.send("x"), /buffer is full/);
  assert.deepEqual(sockets[0].sent, []);
  sockets[0].bufferedAmount = 0;
  relay.signaling.send("x");
  assert.deepEqual(sockets[0].sent, ['"x"']);
});

test("a failed flush preserves its message for the same destination", () => {
  const { relay, sockets, states } = fixture();
  relay.connect("wss://relay.test/room");
  relay.signaling.send({ retry: true });
  sockets[0].send = () => { throw new Error("closed"); };
  sockets[0].dispatch("open");
  assert.equal(states.at(-1)[0], "disconnected");
  relay.connect("wss://relay.test/room");
  sockets[1].dispatch("open");
  assert.deepEqual(sockets[1].sent, ['{"retry":true}']);
});

test("queued messages wait for transport capacity and resume in order", async () => {
  const { relay, sockets } = fixture();
  relay.connect("wss://relay.test/room");
  relay.signaling.send({ first: true });
  relay.signaling.send({ second: true });
  sockets[0].bufferedAmount = 256 * 1024;
  sockets[0].dispatch("open");
  assert.deepEqual(sockets[0].sent, []);
  sockets[0].bufferedAmount = 0;
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(sockets[0].sent, ['{"first":true}', '{"second":true}']);
  relay.signaling.close();
});

test("oversized incoming text is disconnected before reaching the consumer", () => {
  const { relay, sockets } = fixture();
  let calls = 0;
  relay.signaling.onMessage(() => calls++);
  relay.connect("wss://relay.test/room");
  sockets[0].dispatch("open");
  sockets[0].dispatch("message", { data: JSON.stringify("é".repeat(32768)) });
  assert.equal(sockets[0].closed, true);
  assert.equal(calls, 0);
});
