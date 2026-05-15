/* Dedicated SAST worker to keep heavy analysis off the background thread */

import { sastEngine } from "./sastEngine.js";

// Track engines per scan id so multiple scans can be isolated if needed
const engines = new Map();

self.onmessage = async (event) => {
  const msg = event.data || {};
  const { type, scanId } = msg;

  if (!type) return;

  if (type === "start_scan") {
    try {
      const scanStrategy = msg.scanStrategy ?? msg.policy ?? 0;
      const engine = new sastEngine(scanStrategy, { ...((msg.opts || {})), scanId });
      engines.set(scanId, engine);

      const forward = (name, payload) => {
        self.postMessage({ type: name, scanId, ...(payload || {}) });
      };

      const eventNames = [
        "progress",
        "scan:start",
        "collection:start",
        "collection:payload",
        "collection:analysis:start",
        "file:start",
        "file:end",
        "module:start",
        "module:end",
        "findings:partial",
        "collection:summary",
        "collection:error",
        "scan:summary",
        "scan:error"
      ];

      for (const ev of eventNames) {
        engine.events.subscribe(ev, (data) => forward(ev, ev === "progress" ? { info: data } : { ...data }));
      }
    } catch (err) {
      self.postMessage({
        type: "error",
        scanId,
        error: err?.message || String(err),
      });
    }
    return;
  }

  if (type === "scan_code") {
    const { scripts, html, file, generation, collectionId } = msg;
    const engine = engines.get(scanId);
    if (!engine) {
      self.postMessage({ type: "error", scanId, error: "no_engine_for_scan" });
      return;
    }

    try {
      const detail = await engine.scanCodeDetailed(scripts, html, file, { generation, collectionId });
      self.postMessage({
        type: "scan_result",
        scanId,
        file,
        findings: Array.isArray(detail?.findings) ? detail.findings : [],
        artifacts: detail?.artifacts || null
      });
    } catch (err) {
      self.postMessage({
        type: "error",
        scanId,
        error: err?.message || String(err),
      });
    }
    return;
  }

  if (type === "stop_scan") {
    engines.delete(scanId);
    return;
  }
};
