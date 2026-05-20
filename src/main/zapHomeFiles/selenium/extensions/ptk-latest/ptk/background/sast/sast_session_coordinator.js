/* Author: Denis Podgurskii */
import { isHashOnlyNavigation } from "./spa_utils.js";

export class SastSessionCoordinator {
  constructor({
    transport,
    browserApi = browser,
    schedulePersist = () => {},
    updateScanResult = () => {},
    scanCode = async () => [],
    stopBackgroundScan = () => {},
    getProgressSnapshot = () => ({}),
    getProgressStatus = () => "Scanning",
    recordTiming = () => {},
    sendPopupMessage = null
  } = {}) {
    this.transport = transport;
    this.browserApi = browserApi;
    this.schedulePersist = schedulePersist;
    this.updateScanResult = updateScanResult;
    this.scanCode = scanCode;
    this.stopBackgroundScan = stopBackgroundScan;
    this.getProgressSnapshot = getProgressSnapshot;
    this.getProgressStatus = getProgressStatus;
    this.recordTiming = typeof recordTiming === "function" ? recordTiming : () => {};
    this.sendPopupMessage = typeof sendPopupMessage === "function" ? sendPopupMessage : null;

    this.reset();
  }

  reset() {
    this.isScanRunning = false;
    this.sessionState = "idle";
    this.collectionState = "idle";
    this.analysisState = "idle";
    this.activeTabId = null;
    this.multiPageScanActive = false;
    this.spaPageSet = new Set();
    this.spaScanInFlight = new Set();
    this.scanHeartbeatTimer = null;
    this.scanStartMs = null;
    this.scanningRequest = false;
    this.firstCollectionStarted = false;
    this.firstCollectionSettled = false;
    this.firstCollectionError = null;
    this.activeCollectionCount = 0;
    this.pendingCollectionCount = 0;
    this.collectionQueue = Promise.resolve([]);
    this.lastCollectionState = "idle";
    this.currentGeneration = 0;
    this.lastCompletedGeneration = 0;
    this.currentCollectionId = null;
    this.currentCollectionFile = null;
    this.currentCollectionScriptsCount = null;
    this.currentCollectionHtmlChars = null;
    this.currentCollectionFindingsCount = null;
    this.currentCollectionStartedAt = null;
    this.currentCollectionPayloadAt = null;
    this.lastCompletedFile = null;
    this.lastCompletedModule = null;
    this.lastCompletedCollectionId = null;
    this.lastCompletedScriptsCount = null;
    this.lastCompletedHtmlChars = null;
    this.lastCompletedFindingsCount = null;
    this.lastCompletedArtifactsCount = null;
    this.lastCompletedAt = null;
    this.initialCollectionDeferred = null;
  }

  beginSession(tabId) {
    this.isScanRunning = true;
    this.sessionState = "running";
    this.collectionState = "collection_pending";
    this.analysisState = "waiting";
    this.activeTabId = tabId;
    this.scanningRequest = false;
    this.firstCollectionStarted = false;
    this.firstCollectionSettled = false;
    this.firstCollectionError = null;
    this.activeCollectionCount = 0;
    this.lastCollectionState = "collection_pending";
    this.currentGeneration = 0;
    this.lastCompletedGeneration = 0;
    this.currentCollectionId = null;
    this.currentCollectionFile = null;
    this.currentCollectionScriptsCount = null;
    this.currentCollectionHtmlChars = null;
    this.currentCollectionFindingsCount = null;
    this.currentCollectionStartedAt = null;
    this.currentCollectionPayloadAt = null;
    this.lastCompletedFile = null;
    this.lastCompletedModule = null;
    this.lastCompletedCollectionId = null;
    this.lastCompletedScriptsCount = null;
    this.lastCompletedHtmlChars = null;
    this.lastCompletedFindingsCount = null;
    this.lastCompletedArtifactsCount = null;
    this.lastCompletedAt = null;
    this.initialCollectionDeferred = null;
    this.startHeartbeat();
  }

  getAutomationState() {
    return {
      sessionState: this.sessionState || (this.isScanRunning ? "running" : "idle"),
      collectionState: this.collectionState || this.lastCollectionState || "idle",
      analysisState: this.analysisState || "idle",
      isSessionRunning: this.isScanRunning === true,
      isAnalysisRunning: this.analysisState === "analyzing" || this.activeCollectionCount > 0,
      firstCollectionStarted: this.firstCollectionStarted,
      firstCollectionSettled: this.firstCollectionSettled,
      firstCollectionError: this.firstCollectionError,
      activeCollectionCount: this.activeCollectionCount,
      pendingCollectionCount: this.pendingCollectionCount,
      lastCollectionState: this.lastCollectionState || "idle",
      currentGeneration: this.currentGeneration,
      lastCompletedGeneration: this.lastCompletedGeneration,
      currentCollectionId: this.currentCollectionId,
      currentCollectionFile: this.currentCollectionFile,
      currentCollectionScriptsCount: this.currentCollectionScriptsCount,
      currentCollectionHtmlChars: this.currentCollectionHtmlChars,
      currentCollectionFindingsCount: this.currentCollectionFindingsCount,
      currentCollectionStartedAt: this.currentCollectionStartedAt,
      currentCollectionPayloadAt: this.currentCollectionPayloadAt,
      lastCompletedFile: this.lastCompletedFile,
      lastCompletedModule: this.lastCompletedModule,
      lastCompletedCollectionId: this.lastCompletedCollectionId,
      lastCompletedScriptsCount: this.lastCompletedScriptsCount,
      lastCompletedHtmlChars: this.lastCompletedHtmlChars,
      lastCompletedFindingsCount: this.lastCompletedFindingsCount,
      lastCompletedArtifactsCount: this.lastCompletedArtifactsCount,
      lastCompletedAt: this.lastCompletedAt,
      initialCollectionDeferred: this.initialCollectionDeferred
    };
  }

  isCollectionIdle() {
    if (!this.isScanRunning) return true;
    if (this.pendingCollectionCount > 0 || this.activeCollectionCount > 0 || this.scanningRequest) return false;
    if (!this.firstCollectionStarted) return false;
    return this.firstCollectionSettled === true
      || this.collectionState === "waiting_for_page_activity"
      || this.analysisState === "complete";
  }

  async waitForCollectionIdle({ timeoutMs = 5000, pollMs = 100 } = {}) {
    const deadline = Date.now() + Math.max(0, Number(timeoutMs) || 0);
    const interval = Math.max(25, Number(pollMs) || 100);
    while (Date.now() <= deadline) {
      if (this.isCollectionIdle()) return true;
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    return this.isCollectionIdle();
  }

  handleRemoved(tabId) {
    if (this.activeTabId !== tabId) return;
    this.activeTabId = null;
    this.isScanRunning = false;
    this.sessionState = "stopped";
    this.collectionState = "stopped";
    this.analysisState = "idle";
    this.stopHeartbeat();
  }

  markStopped(status = "stopped") {
    this.isScanRunning = false;
    this.sessionState = status || "stopped";
    this.collectionState = "stopped";
    this.analysisState = "idle";
    this.activeTabId = null;
    this.multiPageScanActive = false;
    this.spaScanInFlight.clear();
    this.activeCollectionCount = 0;
    this.pendingCollectionCount = 0;
    this.collectionQueue = Promise.resolve([]);
    this.scanningRequest = false;
    this.stopHeartbeat();
  }

  beginCollection() {
    const generation = Number(this.currentGeneration || 0) + 1;
    this.currentGeneration = generation;
    this.currentCollectionId = `sast_collection_${generation}`;
    this.currentCollectionFile = null;
    this.currentCollectionScriptsCount = null;
    this.currentCollectionHtmlChars = null;
    this.currentCollectionFindingsCount = null;
    this.currentCollectionStartedAt = new Date().toISOString();
    this.currentCollectionPayloadAt = null;
    this.collectionState = "collection_pending";
    this.analysisState = "collecting";
    this.lastCollectionState = "collection_pending";
    return {
      generation,
      collectionId: this.currentCollectionId
    };
  }

  deferInitialCollection(reason = "deferred", details = {}) {
    if (!this.isScanRunning || this.firstCollectionStarted) return false;
    this.collectionState = "waiting_for_page_activity";
    this.analysisState = "waiting";
    this.lastCollectionState = "waiting_for_page_activity";
    this.initialCollectionDeferred = {
      reason: reason || "deferred",
      at: new Date().toISOString(),
      currentUrl: details.currentUrl || null,
      targetUrl: details.targetUrl || null
    };
    return true;
  }

  markPayloadReceived(generation, details = {}) {
    if (Number(generation || 0) !== Number(this.currentGeneration || 0)) return false;
    this.currentCollectionFile = details.file || this.currentCollectionFile || null;
    this.currentCollectionScriptsCount = Number.isFinite(Number(details.scriptsCount))
      ? Number(details.scriptsCount)
      : this.currentCollectionScriptsCount;
    this.currentCollectionHtmlChars = Number.isFinite(Number(details.htmlChars))
      ? Number(details.htmlChars)
      : this.currentCollectionHtmlChars;
    this.currentCollectionPayloadAt = new Date().toISOString();
    this.collectionState = "payload_received";
    this.analysisState = "payload_received";
    this.lastCollectionState = "payload_received";
    return true;
  }

  enqueueCollectionTask(task) {
    if (typeof task !== "function") return Promise.resolve([]);
    this.pendingCollectionCount += 1;
    const run = this.collectionQueue
      .catch(() => [])
      .then(async () => {
        if (!this.isScanRunning) return [];
        return task();
      });
    this.collectionQueue = run.finally(() => {
      this.pendingCollectionCount = Math.max(0, this.pendingCollectionCount - 1);
    });
    return run;
  }

  markCollectionAnalysis(generation) {
    if (Number(generation || 0) !== Number(this.currentGeneration || 0)) return false;
    this.collectionState = "analysis_running";
    this.analysisState = "analyzing";
    this.lastCollectionState = "scan_in_flight";
    return true;
  }

  completeCollection(generation, details = {}) {
    const value = Number(generation || 0);
    if (!Number.isFinite(value) || value < Number(this.lastCompletedGeneration || 0)) {
      return false;
    }
    this.lastCompletedGeneration = value;
    this.lastCompletedFile = details.file || this.lastCompletedFile || null;
    this.lastCompletedModule = details.module || this.lastCompletedModule || null;
    this.lastCompletedCollectionId = this.currentCollectionId || this.lastCompletedCollectionId || null;
    this.lastCompletedScriptsCount = Number.isFinite(Number(details.scriptsCount))
      ? Number(details.scriptsCount)
      : (this.currentCollectionScriptsCount ?? this.lastCompletedScriptsCount);
    this.lastCompletedHtmlChars = Number.isFinite(Number(details.htmlChars))
      ? Number(details.htmlChars)
      : (this.currentCollectionHtmlChars ?? this.lastCompletedHtmlChars);
    this.lastCompletedFindingsCount = Number.isFinite(Number(details.findingsCount))
      ? Number(details.findingsCount)
      : (this.currentCollectionFindingsCount ?? this.lastCompletedFindingsCount);
    this.lastCompletedArtifactsCount = Number.isFinite(Number(details.artifactsCount))
      ? Number(details.artifactsCount)
      : (this.lastCompletedArtifactsCount ?? null);
    this.lastCompletedAt = new Date().toISOString();
    this.currentCollectionFindingsCount = this.lastCompletedFindingsCount;
    this.collectionState = this.isScanRunning ? "waiting_for_page_activity" : "completed";
    this.analysisState = "complete";
    this.lastCollectionState = this.collectionState;
    return true;
  }

  failCollection(generation, error = null) {
    const value = Number(generation || 0);
    if (Number.isFinite(value) && value < Number(this.lastCompletedGeneration || 0)) {
      return false;
    }
    this.firstCollectionError = error?.message || error || this.firstCollectionError || null;
    this.collectionState = "collection_failed";
    this.analysisState = "error";
    this.lastCollectionState = "collection_failed";
    return true;
  }

  async handleUpdated(tabId, info, tab) {
    if (!this.isScanRunning) return;
    if (this.activeTabId !== tabId) return;
    if (this.multiPageScanActive) return;
    if (String(info?.status || "").toLowerCase() !== "complete") return;
    const url = String(tab?.url || info?.url || "").trim();
    if (!url || /^(about|edge|chrome|moz-extension|chrome-extension|devtools):/i.test(url)) {
      return;
    }
    try {
      await this.collectAndScanTab(tabId, {
        delayMs: 100,
        attempts: 3,
        timeoutMs: 12000,
        retryDelayMs: 600,
        expectedUrl: url
      });
    } catch (err) {
      console.error("[SAST] Auto-collect after tab update failed", err);
    }
  }

  primeSpaPages(scanResult) {
    this.spaPageSet = new Set();
    const pages = Array.isArray(scanResult?.pages) ? scanResult.pages : [];
    pages.forEach(entry => {
      const url = typeof entry === "string" ? entry : entry?.url;
      if (url) this.spaPageSet.add(url);
    });
  }

  registerSpaPage(scanResult, url) {
    if (!url) return false;
    if (!Array.isArray(scanResult.pages)) {
      scanResult.pages = [];
    }
    if (this.spaPageSet.has(url)) return false;
    this.spaPageSet.add(url);
    scanResult.pages.push(url);
    this.schedulePersist();
    return true;
  }

  async onSpaUrlChanged(rawUrl, tabId, scanResult, payload = null) {
    if (!rawUrl || !tabId) return;
    if (!this.isScanRunning || this.activeTabId !== tabId) return;
    const normalized = this.normalizeSpaPages([rawUrl], null)[0];
    if (!normalized) return;
    const isNew = this.registerSpaPage(scanResult, normalized);
    if (this.multiPageScanActive) return;
    if (!isNew) return;
    if (this.spaScanInFlight.has(normalized)) return;
    this.spaScanInFlight.add(normalized);
    try {
      if (this.isCollectedPayloadUsable(payload)) {
        await this.scanCollectedPayload(tabId, payload, {
          source: "content_route_payload",
          expectedUrl: normalized
        });
      } else {
        await this.collectAndScanTab(tabId, {
          delayMs: 100,
          attempts: 3,
          expectedUrl: normalized
        });
      }
    } finally {
      this.spaScanInFlight.delete(normalized);
    }
  }

  startHeartbeat() {
    this.stopHeartbeat();
    this.scanStartMs = Date.now();
    if (!this.sendPopupMessage) {
      return;
    }
    this.scanHeartbeatTimer = setInterval(() => {
      if (!this.isScanRunning) return;
      const elapsedMs = Date.now() - (this.scanStartMs || Date.now());
      const totalSeconds = Math.max(0, Math.floor(elapsedMs / 1000));
      const mins = String(Math.floor(totalSeconds / 60)).padStart(2, "0");
      const secs = String(totalSeconds % 60).padStart(2, "0");
      this.sendPopupMessage({
        channel: "ptk_background2popup_sast",
        type: "progress",
        info: {
          message: this.getProgressStatus(),
          file: `${mins}:${secs} elapsed`,
          progress: this.getProgressSnapshot()
        }
      });
    }, 2000);
  }

  stopHeartbeat() {
    if (this.scanHeartbeatTimer) {
      clearInterval(this.scanHeartbeatTimer);
      this.scanHeartbeatTimer = null;
    }
    this.scanStartMs = null;
  }

  async collectAndScanTab(tabId, opts = {}) {
    return this.enqueueCollectionTask(() => this._collectAndScanTabNow(tabId, opts));
  }

  async _collectAndScanTabNow(tabId, opts = {}) {
    if (!this.isScanRunning) return [];
    this.scanningRequest = true;
    let collectionLockHeld = true;
    this.activeCollectionCount += 1;
    const collection = this.beginCollection();
    if (!this.firstCollectionStarted) {
      this.firstCollectionStarted = true;
    }
    const releaseCollectionLock = () => {
      if (!collectionLockHeld) return;
      collectionLockHeld = false;
      this.scanningRequest = false;
    };
    try {
      const delayMs = Number.isFinite(Number(opts?.delayMs))
        ? Math.max(0, Number(opts.delayMs))
        : 500;
      const attempts = Number.isFinite(Number(opts?.attempts))
        ? Math.max(1, Number(opts.attempts))
        : 3;
      const timeoutMs = Number.isFinite(Number(opts?.timeoutMs))
        ? Math.max(1000, Number(opts.timeoutMs))
        : 12000;
      const retryDelayMs = Number.isFinite(Number(opts?.retryDelayMs))
        ? Math.max(100, Number(opts.retryDelayMs))
        : 600;

      await this.transport.waitForSpaIdle(tabId, delayMs);
      const payload = await this.transport.requestScriptsWithRetry(tabId, {
        attempts,
        timeoutMs,
        retryDelayMs
      });
      if (opts?.expectedUrl && payload?.file && !sameDocumentUrl(payload.file, opts.expectedUrl)) {
        this.recordTiming("sast.payload.stale", {
          expectedUrl: opts.expectedUrl,
          actualUrl: payload.file
        }, null, "sast.payload.stale");
        return [];
      }
      const scriptsCount = Array.isArray(payload?.scripts) ? payload.scripts.length : 0;
      const htmlChars = typeof payload?.html === "string"
        ? payload.html.length
        : (Array.isArray(payload?.html) ? payload.html.length : 0);
      this.markPayloadReceived(collection.generation, {
        file: payload?.file || null,
        scriptsCount,
        htmlChars
      });
      this.recordTiming("sast.payload.received", {
        scriptsCount,
        htmlChars,
        file: payload?.file || null
      }, null, "sast.payload.received");
      if (!payload?.scripts) return [];
      this.markCollectionAnalysis(collection.generation);
      const findings = await this.scanCode(payload.scripts, payload.html, payload.file, {
        generation: collection.generation,
        collectionId: collection.collectionId
      });
      const findingsCount = Array.isArray(findings) ? findings.length : 0;
      this.completeCollection(collection.generation, {
        file: payload.file || null,
        scriptsCount,
        htmlChars,
        findingsCount
      });
      return findings;
    } catch (err) {
      this.failCollection(collection.generation, err?.message || String(err));
      throw err;
    } finally {
      releaseCollectionLock();
      this.activeCollectionCount = Math.max(0, this.activeCollectionCount - 1);
      if (this.firstCollectionStarted && this.activeCollectionCount === 0) {
        this.firstCollectionSettled = true;
        if (this.lastCollectionState !== "collection_failed" && this.collectionState !== "waiting_for_page_activity") {
          this.completeCollection(collection.generation);
        }
      }
    }
  }

  isCollectedPayloadUsable(payload) {
    return !!(
      payload &&
      typeof payload === "object" &&
      Array.isArray(payload.scripts) &&
      typeof payload.file === "string" &&
      payload.file.trim()
    );
  }

  async scanCollectedPayload(tabId, payload, opts = {}) {
    return this.enqueueCollectionTask(() => this._scanCollectedPayloadNow(tabId, payload, opts));
  }

  async _scanCollectedPayloadNow(tabId, payload, opts = {}) {
    if (!this.isScanRunning) return [];
    if (this.activeTabId !== tabId) return [];
    if (!this.isCollectedPayloadUsable(payload)) return [];
    if (opts?.expectedUrl && payload?.file && !sameDocumentUrl(payload.file, opts.expectedUrl)) {
      return [];
    }

    this.scanningRequest = true;
    this.activeCollectionCount += 1;
    const collection = this.beginCollection();
    if (!this.firstCollectionStarted) {
      this.firstCollectionStarted = true;
    }
    try {
      const scriptsCount = Array.isArray(payload?.scripts) ? payload.scripts.length : 0;
      const htmlChars = typeof payload?.html === "string"
        ? payload.html.length
        : (Array.isArray(payload?.html) ? payload.html.length : 0);
      this.markPayloadReceived(collection.generation, {
        file: payload?.file || null,
        scriptsCount,
        htmlChars
      });
      this.recordTiming("sast.payload.received", {
        source: opts?.source || "content_payload",
        scriptsCount,
        htmlChars,
        file: payload?.file || null
      }, null, "sast.payload.received");
      this.markCollectionAnalysis(collection.generation);
      const findings = await this.scanCode(payload.scripts, payload.html, payload.file, {
        generation: collection.generation,
        collectionId: collection.collectionId,
        source: opts?.source || "content_payload"
      });
      const findingsCount = Array.isArray(findings) ? findings.length : 0;
      this.completeCollection(collection.generation, {
        file: payload.file || null,
        scriptsCount,
        htmlChars,
        findingsCount
      });
      return findings;
    } catch (err) {
      this.failCollection(collection.generation, err?.message || String(err));
      throw err;
    } finally {
      this.scanningRequest = false;
      this.activeCollectionCount = Math.max(0, this.activeCollectionCount - 1);
      if (this.firstCollectionStarted && this.activeCollectionCount === 0) {
        this.firstCollectionSettled = true;
        if (this.lastCollectionState !== "collection_failed" && this.collectionState !== "waiting_for_page_activity") {
          this.completeCollection(collection.generation);
        }
      }
    }
  }

  normalizeSpaPages(pages, baseUrl) {
    if (!Array.isArray(pages)) return [];
    const normalized = [];
    const seen = new Set();
    for (const entry of pages) {
      const raw = (entry || "").toString().trim();
      if (!raw) continue;
      let url = raw;
      try {
        if (baseUrl) {
          url = new URL(raw, baseUrl).toString();
        } else if (!/^https?:\/\//i.test(raw)) {
          continue;
        }
      } catch {
        continue;
      }
      if (!seen.has(url)) {
        seen.add(url);
        normalized.push(url);
      }
    }
    return normalized;
  }

  async scanSpaPages(tabId, pages, opts = {}) {
    const delayMs = Number(opts.spaDelayMs || opts.pageDelayMs || 1000);
    for (const pageUrl of pages) {
      if (!this.isScanRunning || this.activeTabId !== tabId) break;
      if (!pageUrl) continue;
      const tab = await this.browserApi.tabs.get(tabId).catch(() => null);
      const currentUrl = tab?.url || "";
      const useHashNav = isHashOnlyNavigation(currentUrl, pageUrl);
      if (useHashNav) {
        const hash = new URL(pageUrl).hash || "";
        try {
          await this.transport.setSpaHash(tabId, hash);
        } catch (err) {
          console.error("[SAST] Failed to set SPA hash", hash, err);
        }
      } else {
        try {
          await this.browserApi.tabs.update(tabId, { url: pageUrl });
        } catch (err) {
          console.error("[SAST] Failed to navigate to page", pageUrl, err);
          continue;
        }
      }
      try {
        await this.collectAndScanTab(tabId, {
          delayMs,
          attempts: 3
        });
      } catch (err) {
        console.error("[SAST] Failed to collect scripts for page", pageUrl, err);
      }
    }
    if (this.multiPageScanActive && this.isScanRunning && this.activeTabId === tabId) {
      this.stopBackgroundScan();
    }
  }
}

function sameDocumentUrl(left, right) {
  try {
    const a = new URL(String(left || ""));
    const b = new URL(String(right || ""));
    return a.origin === b.origin &&
      a.pathname === b.pathname &&
      a.search === b.search &&
      a.hash === b.hash;
  } catch (_) {
    return String(left || "") === String(right || "");
  }
}

export default SastSessionCoordinator;
