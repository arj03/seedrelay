// JSON-over-WebSocket signaling for an application-owned relay URL. The returned
// Signaling object is stable: an RtcNetwork can retain it while connect() replaces a
// failed socket or points it at another room. URL selection and UI lifecycle stay with
// the application; this module owns only serialization, queuing, and socket turnover.

const OPEN = 1;
const MAX_MESSAGE_BYTES = 64 * 1024;
const MAX_BUFFER_BYTES = 256 * 1024;
const MAX_PENDING_MESSAGES = 256;
const utf8 = new TextEncoder();

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
  let pendingBytes = 0;
  let flushTimer = null;

  function clearPending() {
    pending.length = 0;
    pendingBytes = 0;
  }
  function stopFlush() {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  function flush() {
    stopFlush();
    const next = socket;
    if (next?.readyState !== OPEN) return;
    while (pending.length > 0) {
      const item = pending[0];
      if ((next.bufferedAmount ?? 0) + item.bytes > MAX_BUFFER_BYTES) break;
      try { next.send(item.encoded); }
      catch { disconnect(); return; }
      pending.shift();
      pendingBytes -= item.bytes;
    }
    if (pending.length > 0) {
      flushTimer = setTimeout(flush, 25);
      flushTimer.unref?.();
    }
  }

  const emit = (state, event) => onStateChange({ state, url: currentUrl, event });

  function replaceSocket(url) {
    stopFlush();
    // The first URL owns pre-connect messages. Later destination changes
    // discard them even when creation of the replacement socket fails.
    if (currentUrl !== null && currentUrl !== url) clearPending();
    currentUrl = url;
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

    next.addEventListener("open", (event) => {
      if (socket !== next || socketGeneration !== generation) return;
      flush();
      if (socket !== next) return;
      emit("connected", event);
    });
    next.addEventListener("message", (event) => {
      if (socket !== next || socketGeneration !== generation || typeof event.data !== "string") return;
      if (event.data.length > MAX_MESSAGE_BYTES || utf8.encode(event.data).length > MAX_MESSAGE_BYTES) {
        disconnect(); return;
      }
      let message;
      try { message = JSON.parse(event.data); }
      catch { return; }
      receive(message);
    });
    next.addEventListener("close", (event) => {
      if (socket !== next || socketGeneration !== generation) return;
      stopFlush();
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
    stopFlush();
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
      if (encoded.length > MAX_MESSAGE_BYTES)
        throw new RangeError("seedrelay: signaling message exceeds 64 KiB");
      const bytes = utf8.encode(encoded).length;
      if (bytes > MAX_MESSAGE_BYTES)
        throw new RangeError("seedrelay: signaling message exceeds 64 KiB");
      if (pending.length >= MAX_PENDING_MESSAGES ||
          pendingBytes + bytes + (socket?.bufferedAmount ?? 0) > MAX_BUFFER_BYTES)
        throw new RangeError("seedrelay: signaling buffer is full");
      pending.push({ encoded, bytes });
      pendingBytes += bytes;
      flush();
    },
    onMessage(callback) {
      if (typeof callback !== "function")
        throw new TypeError("seedrelay: signaling callback must be a function");
      receive = callback;
    },
    close() {
      disconnect();
      clearPending();
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
