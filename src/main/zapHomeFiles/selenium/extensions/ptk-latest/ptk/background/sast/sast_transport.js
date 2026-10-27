/* Author: Denis Podgurskii */

import { OffscreenRuntimeManager } from "../offscreen/offscreenRuntimeManager.js";

const worker = self;

export class SastTransport {
  constructor({
    asyncSession,
    eventHandler = null,
    browserApi = browser,
    chromeApi = typeof chrome !== "undefined" ? chrome : null,
    WorkerCtor = typeof Worker !== "undefined" ? Worker : null,
    disableRemote = false,
    offscreenManager = null,
  } = {}) {
    this.asyncSession = asyncSession;
    this.eventHandler = typeof eventHandler === "function" ? eventHandler : null;
    this.browserApi = browserApi;
    this.chromeApi = chromeApi;
    this.WorkerCtor = WorkerCtor;
    this.disableRemote = disableRemote === true;
    this.offscreenManager = offscreenManager || new OffscreenRuntimeManager({ chromeApi });
    this.sastWorker = null;
    this.offscreenInitPromise = null;
    this.remoteOwner = null;
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
        const instance = this.sastWorker;
        this.sastWorker.onmessage = (event) => { if (this.sastWorker === instance) this.emit(event?.data || {}); };
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
    if (worker.isFirefox) return false;
    return this.offscreenManager.ensureDocument();
  }

  async tryEnsureOffscreenDocument(reason = "unknown") {
    try {
      return await this.ensureOffscreenDocument() === true;
    } catch (err) {
      this.offscreenInitPromise = null;
      console.error("Failed to initialize SAST offscreen document", {
        reason,
        error: err?.message || String(err)
      });
      return false;
    }
  }

  async startRemoteScan({ scanId, scanStrategyCode, opts } = {}) {
    if (this.disableRemote) return false;
    const owner = { scanId, cancelled: false, dispatched: false };
    if (this.remoteOwner && this.remoteOwner.scanId !== scanId) throw new Error('sast_worker_owner_conflict');
    this.remoteOwner = owner;

    if (worker.isFirefox) {
      this.ensureFirefoxWorker();
      if (!this.sastWorker) return false;
      if (owner.cancelled || this.remoteOwner !== owner) return false;
      owner.dispatched = true;
      this.sastWorker.postMessage({
        type: "start_scan",
        scanId,
        scanStrategy: scanStrategyCode,
        opts
      });
      return true;
    }

    if (!await this.tryEnsureOffscreenDocument("start_scan")) {
      return false;
    }
    if (owner.cancelled || this.remoteOwner !== owner) return false;
    try {
      owner.dispatched = true;
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

  async scanCodeRemote({ scanId, scripts, html, file, generation = null, collectionId = null, timeoutMs = 30000 } = {}) {
    if (this.disableRemote) return null;
    const owner = this.remoteOwner;
    if (owner?.cancelled || owner && owner.scanId !== scanId) throw new Error('sast_scan_cancelled');

    if (worker.isFirefox) {
      if (!this.sastWorker) return null;
      const result = this.asyncSession.waitForScanResult(file, timeoutMs);
      try { this.sastWorker.postMessage({
        type: "scan_code",
        scanId,
        scripts,
        html,
        file,
        generation,
        collectionId
      }); } catch (error) { this.asyncSession.rejectScanResult(file, error, result); }
      return result;
    }

    if (!await this.tryEnsureOffscreenDocument("scan_code")) {
      return null;
    }
    if (owner && (owner.cancelled || this.remoteOwner !== owner)) throw new Error('sast_scan_cancelled');
    const result = this.asyncSession.waitForScanResult(file, timeoutMs);
    try {
      Promise.resolve(this.browserApi.runtime.sendMessage({
        channel: "ptk_bg2offscreen_sast",
        type: "scan_code",
        scanId,
        scripts,
        html,
        file,
        generation,
        collectionId
      })).catch(error => this.asyncSession.rejectScanResult(file, error, result));
    } catch (err) {
      console.error("Failed to send code to SAST offscreen worker", err);
      this.asyncSession.rejectScanResult(file, err, result);
    }
    return result;
  }

  stopRemoteScan(scanId) {
    if (!scanId) return;
    if (this.disableRemote) return;
    if (worker.isFirefox) {
      if (this.sastWorker) {
        this.sastWorker.postMessage({ type: "stop_scan", scanId });
      }
      if (this.remoteOwner?.scanId === scanId) this.remoteOwner = null;
      return;
    }
    return this.browserApi.runtime.sendMessage({
      channel: "ptk_bg2offscreen_sast",
      type: "stop_scan",
      scanId
    }).then(result => { if (this.remoteOwner?.scanId === scanId) this.remoteOwner = null; return result; }).catch(e => e);
  }

  async cancelRemoteScan(scanId) {
    const owner = this.remoteOwner;
    if (this.disableRemote) return;
    if (!owner || owner.scanId !== scanId) throw new Error('sast_worker_owner_conflict');
    owner.cancelled = true;
    if (worker.isFirefox) {
      if (owner.dispatched && this.sastWorker) {
        const stopped = this.sastWorker;
        stopped.terminate();
        if (this.sastWorker === stopped) this.sastWorker = null;
      }
    } else if (owner.dispatched) {
      const result = await this.browserApi.runtime.sendMessage({ channel: 'ptk_bg2offscreen_sast', type: 'cancel_scan', scanId });
      if (result?.ok !== true || result.cancelled !== true) throw new Error('sast_worker_owner_conflict');
    }
    if (this.remoteOwner === owner) this.remoteOwner = null;
  }

  async requestScriptsFromTab(tabId, timeoutMs = 8000, binding = null) {
    const requestId = `sast_scripts_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const promise = this.asyncSession.createScriptRequest(requestId, timeoutMs, binding?.accept || null);

    try {
      Promise.resolve(this.browserApi.tabs.sendMessage(tabId, {
        channel: "ptk_background2content_sast",
        type: "collect_scripts",
        requestId,
      }, binding ? { frameId: binding.identity.frameId, documentId: binding.identity.documentId } : undefined))
        .catch(err => this.asyncSession.rejectScriptRequest(requestId, err));
    } catch (err) {
      this.asyncSession.rejectScriptRequest(requestId, err);
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
        const missingReceiver = isMissingReceiverError(lastError);
        console.warn("[SAST] Script collection retry scheduled", {
          attempt,
          attempts,
          tabId,
          tabUrl,
          reason: missingReceiver ? "content_receiver_missing" : "collection_failed",
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

  async waitForSpaIdle(tabId, delayMs = 500, binding = null) {
    if (binding) {
      let timer;
      try {
        const response = await Promise.race([
          Promise.resolve().then(() => this.browserApi.tabs.sendMessage(tabId, {
            channel: "ptk_background2content_sast", type: "sast_wait_ready", delayMs
          }, { frameId: binding.identity.frameId, documentId: binding.identity.documentId })),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error("sast_readiness_timeout")), binding.timeoutMs);
          })
        ]);
        if (response?.ok !== true) throw new Error("sast_document_inactive");
        return;
      } finally { clearTimeout(timer); }
    }
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

function isMissingReceiverError(error) {
  const message = String(error?.message || error || "");
  return /receiving end does not exist|could not establish connection|message port closed/i.test(message);
}

export default SastTransport;
