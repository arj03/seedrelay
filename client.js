// JSON-over-WebSocket signaling for an application-owned relay URL. The returned
// Signaling object is stable: an RtcNetwork can retain it while connect() replaces a
// failed socket or points it at another room. URL selection and UI lifecycle stay with
// the application; this module owns only serialization, queuing, and socket turnover.

const OPEN = 1;

/**
 * @param {{
 *   webSocketFactory?: (url: string) => WebSocket,
 *   onStateChange?: (change: {
 *     state: "connecting" | "connected" | "disconnected" | "error",
 *     url: string | null,
 *     event?: Event,
 *   }) => void,
 * }} [options]
 */
export function createRelaySignaling(options = {}) {
  const makeWebSocket = options.webSocketFactory
    ?? ((url) => new WebSocket(url));
  const onStateChange = options.onStateChange ?? (() => {});
  if (typeof makeWebSocket !== "function")
    throw new TypeError("seedrelay: webSocketFactory must be a function");
  if (typeof onStateChange !== "function")
    throw new TypeError("seedrelay: onStateChange must be a function");

  let socket = null;
  let socketGeneration = 0;
  let currentUrl = null;
  let receive = () => {};
  const pending = [];

  const emit = (state, event) => onStateChange({ state, url: currentUrl, event });

  function replaceSocket(url) {
    const previous = socket;
    socket = null;
    socketGeneration++;
    if (previous) {
      try { previous.close(); } catch { /* already closed */ }
    }

    const next = makeWebSocket(url);
    if (!next || typeof next.addEventListener !== "function"
        || typeof next.send !== "function" || typeof next.close !== "function") {
      try { next?.close?.(); } catch { /* best effort */ }
      throw new TypeError("seedrelay: webSocketFactory returned an invalid socket");
    }
    const generation = socketGeneration;
    socket = next;
    currentUrl = url;

    next.addEventListener("open", (event) => {
      if (socket !== next || socketGeneration !== generation) return;
      while (pending.length > 0) {
        try { next.send(pending[0]); }
        catch { break; }
        pending.shift();
      }
      emit("connected", event);
    });
    next.addEventListener("message", (event) => {
      if (socket !== next || socketGeneration !== generation || typeof event.data !== "string") return;
      let message;
      try { message = JSON.parse(event.data); }
      catch { return; }
      receive(message);
    });
    next.addEventListener("close", (event) => {
      if (socket !== next || socketGeneration !== generation) return;
      socket = null;
      emit("disconnected", event);
    });
    next.addEventListener("error", (event) => {
      if (socket !== next || socketGeneration !== generation) return;
      emit("error", event);
    });
    emit("connecting");
    return next;
  }

  function disconnect() {
    const previous = socket;
    socket = null;
    socketGeneration++;
    if (previous) {
      try { previous.close(); } catch { /* already closed */ }
    }
    if (currentUrl !== null) emit("disconnected");
  }

  const signaling = {
    send(message) {
      const encoded = JSON.stringify(message);
      if (typeof encoded !== "string")
        throw new TypeError("seedrelay: signaling message is not JSON-serializable");
      if (socket?.readyState === OPEN) socket.send(encoded);
      else pending.push(encoded);
    },
    onMessage(callback) {
      if (typeof callback !== "function")
        throw new TypeError("seedrelay: signaling callback must be a function");
      receive = callback;
    },
    close() {
      disconnect();
      pending.length = 0;
      currentUrl = null;
    },
  };

  return {
    signaling,
    connect(url) {
      if (typeof url !== "string" || url.length === 0)
        throw new TypeError("seedrelay: connect URL must be a non-empty string");
      return replaceSocket(url);
    },
    disconnect,
  };
}
