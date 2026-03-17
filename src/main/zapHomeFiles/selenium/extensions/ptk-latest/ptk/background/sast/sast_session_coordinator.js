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
    this.sendPopupMessage = typeof sendPopupMessage === "function" ? sendPopupMessage : null;

    this.reset();
  }

  reset() {
    this.isScanRunning = false;
    this.activeTabId = null;
    this.multiPageScanActive = false;
    this.spaPageSet = new Set();
    this.spaScanInFlight = new Set();
    this.scanHeartbeatTimer = null;
    this.scanStartMs = null;
    this.scanningRequest = false;
  }

  beginSession(tabId) {
    this.isScanRunning = true;
    this.activeTabId = tabId;
    this.scanningRequest = false;
    this.startHeartbeat();
  }

  handleRemoved(tabId) {
    if (this.activeTabId !== tabId) return;
    this.activeTabId = null;
    this.isScanRunning = false;
    this.stopHeartbeat();
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
      if (!payload?.scripts) return [];
      return await this.scanCode(payload.scripts, payload.html, payload.file);
    } finally {
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
