/* Author: Denis Podgurskii */

const worker = self;

export class SastTransport {
  constructor({
    asyncSession,
    eventHandler = null,
    browserApi = browser,
    chromeApi = typeof chrome !== "undefined" ? chrome : null,
    WorkerCtor = typeof Worker !== "undefined" ? Worker : null,
  } = {}) {
    this.asyncSession = asyncSession;
    this.eventHandler = typeof eventHandler === "function" ? eventHandler : null;
    this.browserApi = browserApi;
    this.chromeApi = chromeApi;
    this.WorkerCtor = WorkerCtor;
    this.sastWorker = null;
    this.offscreenInitPromise = null;
  }

  setEventHandler(handler) {
    this.eventHandler = typeof handler === "function" ? handler : null;
  }

  emit(event) {
    if (typeof this.eventHandler === "function") {
      this.eventHandler(event);
    }
  }

  handleExternalMessage(message) {
    if (!message || message.channel !== "ptk_offscreen2background_sast") {
      return false;
    }
    this.emit(message);
    return true;
  }

  ensureFirefoxWorker() {
    if (!worker.isFirefox || !this.WorkerCtor) return;
    if (this.sastWorker) return;

    const candidates = [
      "ptk/background/sast/sast_worker.js",
      "background/sast/sast_worker.js",
    ];

    for (const path of candidates) {
      try {
        this.sastWorker = new this.WorkerCtor(this.browserApi.runtime.getURL(path), { type: "module" });
        this.sastWorker.onmessage = (event) => this.emit(event?.data || {});
        this.sastWorker.onmessageerror = (err) =>
          console.error("SAST worker message error", err, "path:", path);
        this.sastWorker.onerror = (err) =>
          console.error("SAST worker error", err, "path:", path);
        return;
      } catch (err) {
        console.error("Failed to init SAST worker", path, err);
        this.sastWorker = null;
      }
    }
  }

  async ensureOffscreenDocument() {
    if (worker.isFirefox) return;
    if (typeof this.chromeApi === "undefined" || !this.chromeApi?.offscreen?.createDocument) return;

    if (!this.offscreenInitPromise) {
      this.offscreenInitPromise = (async () => {
        if (this.chromeApi.offscreen.hasDocument) {
          const has = await this.chromeApi.offscreen.hasDocument();
          if (has) return;
        }

        await this.chromeApi.offscreen.createDocument({
          url: "ptk/offscreen/sast_offscreen.html",
          reasons: ["IFRAME_SCRIPTING"],
          justification: "Run CPU-heavy SAST engine outside the MV3 service worker",
        });
      })();
    }

    return this.offscreenInitPromise;
  }

  async startRemoteScan({ scanId, scanStrategyCode, opts } = {}) {
    if (worker.isFirefox) {
      this.ensureFirefoxWorker();
      if (!this.sastWorker) return false;
      this.sastWorker.postMessage({
        type: "start_scan",
        scanId,
        scanStrategy: scanStrategyCode,
        opts
      });
      return true;
    }

    await this.ensureOffscreenDocument();
    try {
      await this.browserApi.runtime.sendMessage({
        channel: "ptk_bg2offscreen_sast",
        type: "start_scan",
        scanId,
        scanStrategy: scanStrategyCode,
        opts
      });
      return true;
    } catch (err) {
      console.error("Failed to start SAST offscreen worker", err);
      return false;
    }
  }

  async scanCodeRemote({ scanId, scripts, html, file, timeoutMs = 30000 } = {}) {
    if (worker.isFirefox) {
      if (!this.sastWorker) return null;
      this.sastWorker.postMessage({
        type: "scan_code",
        scanId,
        scripts,
        html,
        file
      });
      return this.asyncSession.waitForScanResult(file, timeoutMs);
    }

    await this.ensureOffscreenDocument();
    try {
      await this.browserApi.runtime.sendMessage({
        channel: "ptk_bg2offscreen_sast",
        type: "scan_code",
        scanId,
        scripts,
        html,
        file
      });
    } catch (err) {
      console.error("Failed to send code to SAST offscreen worker", err);
    }
    return this.asyncSession.waitForScanResult(file, timeoutMs);
  }

  stopRemoteScan(scanId) {
    if (!scanId) return;
    if (worker.isFirefox) {
      if (this.sastWorker) {
        this.sastWorker.postMessage({ type: "stop_scan", scanId });
      }
      return;
    }
    this.browserApi.runtime.sendMessage({
      channel: "ptk_bg2offscreen_sast",
      type: "stop_scan",
      scanId
    }).catch(e => e);
  }

  async requestScriptsFromTab(tabId, timeoutMs = 8000) {
    const requestId = `sast_scripts_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const promise = this.asyncSession.createScriptRequest(requestId, timeoutMs);

    try {
      await this.browserApi.tabs.sendMessage(tabId, {
        channel: "ptk_background2content_sast",
        type: "collect_scripts",
        requestId,
      });
    } catch (err) {
      this.asyncSession.rejectScriptRequest(requestId, err);
      throw err;
    }
    return promise;
  }

  async requestScriptsWithRetry(tabId, opts = {}) {
    const attempts = Number.isFinite(Number(opts?.attempts))
      ? Math.max(1, Number(opts.attempts))
      : 3;
    const timeoutMs = Number.isFinite(Number(opts?.timeoutMs))
      ? Math.max(1000, Number(opts.timeoutMs))
      : 12000;
    const retryDelayMs = Number.isFinite(Number(opts?.retryDelayMs))
      ? Math.max(100, Number(opts.retryDelayMs))
      : 600;

    let lastError = null;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      try {
        const payload = await this.requestScriptsFromTab(tabId, timeoutMs);
        if (payload && Array.isArray(payload.scripts)) {
          return payload;
        }
        lastError = new Error("sast_scripts_empty_payload");
      } catch (err) {
        lastError = err;
      }

      if (attempt < attempts) {
        const tabUrl = await this.browserApi.tabs.get(tabId).then((tab) => tab?.url || "").catch(() => "");
        console.warn("[SAST] Script collection retry scheduled", {
          attempt,
          attempts,
          tabId,
          tabUrl,
          error: lastError?.message || String(lastError)
        });
        await this.waitForSpaIdle(tabId, retryDelayMs * attempt);
      }
    }

    throw lastError || new Error("sast_scripts_collect_failed");
  }

  async setSpaHash(tabId, hash) {
    return this.browserApi.tabs.sendMessage(tabId, {
      channel: "ptk_background2content_sast",
      type: "sast_set_hash",
      hash
    });
  }

  async waitForSpaIdle(tabId, delayMs = 500) {
    try {
      await this.browserApi.tabs.sendMessage(tabId, {
        channel: "ptk_background2content_sast",
        type: "sast_wait_ready",
        delayMs
      });
    } catch (_) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

export default SastTransport;
