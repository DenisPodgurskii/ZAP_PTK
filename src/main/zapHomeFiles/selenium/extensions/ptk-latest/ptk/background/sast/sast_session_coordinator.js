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
    this.lastCollectionState = "idle";
    this.currentGeneration = 0;
    this.lastCompletedGeneration = 0;
    this.currentCollectionId = null;
    this.lastCompletedFile = null;
    this.lastCompletedModule = null;
    this.lastCompletedAt = null;
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
    this.lastCompletedFile = null;
    this.lastCompletedModule = null;
    this.lastCompletedAt = null;
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
      lastCollectionState: this.lastCollectionState || "idle",
      currentGeneration: this.currentGeneration,
      lastCompletedGeneration: this.lastCompletedGeneration,
      currentCollectionId: this.currentCollectionId,
      lastCompletedFile: this.lastCompletedFile,
      lastCompletedModule: this.lastCompletedModule,
      lastCompletedAt: this.lastCompletedAt
    };
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
    this.scanningRequest = false;
    this.stopHeartbeat();
  }

  beginCollection() {
    const generation = Number(this.currentGeneration || 0) + 1;
    this.currentGeneration = generation;
    this.currentCollectionId = `sast_collection_${generation}`;
    this.collectionState = "collection_pending";
    this.analysisState = "collecting";
    this.lastCollectionState = "collection_pending";
    return {
      generation,
      collectionId: this.currentCollectionId
    };
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
    this.lastCompletedAt = new Date().toISOString();
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
        delayMs: 500,
        attempts: 3,
        timeoutMs: 12000,
        retryDelayMs: 600
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

  async onSpaUrlChanged(rawUrl, tabId, scanResult) {
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
      await this.collectAndScanTab(tabId, {
        delayMs: 500,
        attempts: 3
      });
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
    if (!this.isScanRunning) return [];
    if (this.scanningRequest) return [];
    this.scanningRequest = true;
    this.activeCollectionCount += 1;
    const collection = this.beginCollection();
    if (!this.firstCollectionStarted) {
      this.firstCollectionStarted = true;
    }
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
      this.collectionState = "payload_received";
      this.analysisState = "payload_received";
      this.lastCollectionState = "payload_received";
      this.recordTiming("sast.payload.received", {
        scriptsCount: Array.isArray(payload?.scripts) ? payload.scripts.length : 0,
        htmlChars: typeof payload?.html === "string"
          ? payload.html.length
          : (Array.isArray(payload?.html) ? payload.html.length : 0)
      }, null, "sast.payload.received");
      if (!payload?.scripts) return [];
      this.markCollectionAnalysis(collection.generation);
      const findings = await this.scanCode(payload.scripts, payload.html, payload.file, {
        generation: collection.generation,
        collectionId: collection.collectionId
      });
      this.completeCollection(collection.generation, { file: payload.file || null });
      return findings;
    } catch (err) {
      this.failCollection(collection.generation, err?.message || String(err));
      throw err;
    } finally {
      this.activeCollectionCount = Math.max(0, this.activeCollectionCount - 1);
      if (this.firstCollectionStarted && this.activeCollectionCount === 0) {
        this.firstCollectionSettled = true;
        if (this.lastCollectionState !== "collection_failed" && this.collectionState !== "waiting_for_page_activity") {
          this.completeCollection(collection.generation);
        }
      }
      this.scanningRequest = false;
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

export default SastSessionCoordinator;
