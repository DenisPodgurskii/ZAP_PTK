/* Offscreen host for running the SAST worker in Chrome MV3 */

const runtime = (typeof chrome !== "undefined" && chrome.runtime)
  ? chrome.runtime
  : (typeof browser !== "undefined" && browser.runtime ? browser.runtime : null);

if (!runtime) {
  console.error("SAST offscreen: runtime API unavailable");
}

const workerUrl = runtime?.getURL("ptk/background/sast/sast_worker.js");
const sastWorker = workerUrl
  ? new Worker(workerUrl, { type: "module" })
  : null;

runtime?.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.channel !== "ptk_bg2offscreen_sast" || !sastWorker) return;

  const { type, scanId } = msg;

  if (type === "start_scan") {
    const { scanStrategy, policy, opts } = msg;
    sastWorker.postMessage({ type, scanId, scanStrategy, policy, opts });
    sendResponse?.({ ok: true });
    return true;
  }

  if (type === "scan_code") {
    const { scripts, html, file } = msg;
    sastWorker.postMessage({ type, scanId, scripts, html, file });
    sendResponse?.({ ok: true });
    return true;
  }

  if (type === "stop_scan") {
    sastWorker.postMessage({ type, scanId });
    sendResponse?.({ ok: true });
    return true;
  }
});

const relayMessage = (data) => {
  runtime?.sendMessage({
    channel: "ptk_offscreen2background_sast",
    ...data,
  });
};

if (sastWorker) {
  sastWorker.onmessage = (event) => relayMessage(event.data || {});
  sastWorker.onerror = (err) => {
    relayMessage({
      type: "error",
      error: err?.message || String(err),
    });
  };
  sastWorker.onmessageerror = (err) => {
    relayMessage({
      type: "error",
      error: err?.message || "sast_worker_message_error",
    });
  };
}
