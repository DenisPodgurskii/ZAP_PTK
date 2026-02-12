/* Author: Denis Podgurskii */
import {
  ptk_utils,
  ptk_logger,
  ptk_storage,
} from "../background/utils.js";

import { sastEngine } from "./sast/sastEngine.js";
import { SastScanBus } from "./sast/sast_scan_bus.js";
import { loadRulepack } from "./common/moduleRegistry.js";
import {
  createScanResultEnvelope,
  addFindingToGroup,
} from "./common/scanResults.js";
import {
  normalizeRulepack,
  resolveEffectiveSeverity,
} from "./common/severity_utils.js";
import { resolveFindingTaxonomy } from "./common/resolveFindingTaxonomy.js";
import normalizeFinding from "./common/findingNormalizer.js";
import buildExportScanResult from "./export/buildExportScanResult.js";
import { applyRouteToFinding, isHashOnlyNavigation } from "./sast/spa_utils.js";

const worker = self;

export class ptk_sast {
  constructor(settings) {
    this.settings = settings;
    this.storageKey = "ptk_sast";
    this.activeTabId = null;
    this.resetScanResult();
    this.defaultModulesCache = null;
    this._persistTimer = null;
    this._persistDebounceMs = 1000;
    this._rulesIndex = new Set();

    this.onSastWorkerMessage = this.onSastWorkerMessage.bind(this);
    this.onOffscreenMessage = this.onOffscreenMessage.bind(this);
    this.sastWorker = null;
    this.offscreenInitPromise = null;
    this.pendingScriptRequests = new Map();
    this.pendingScanResults = new Map();
    this.multiPageScanActive = false;
    this.spaPageSet = new Set();
    this.spaScanInFlight = new Set();
    this.scanHeartbeatTimer = null;
    this.scanStartMs = null;

    this.addMessageListeners();
    this.ensureFirefoxWorker();
  }

  async getDefaultModules(rulepack = null) {
    if (rulepack && Array.isArray(rulepack.modules)) {
      this.defaultModulesCache = rulepack.modules;
      return this.defaultModulesCache;
    }
    if (Array.isArray(this.defaultModulesCache) && this.defaultModulesCache.length) {
      return this.defaultModulesCache;
    }
    try {
      const localPack = await loadRulepack("SAST");
      normalizeRulepack(localPack, { engine: "SAST", childKey: "rules" });
      this.defaultModulesCache = localPack.modules || [];
    } catch (err) {
      console.warn("[PTK SAST] Failed to load default SAST modules", err);
      this.defaultModulesCache = [];
    }
    return this.defaultModulesCache;
  }

  async _prepareSastOptions(scanStrategyRaw, opts = {}) {
    let rulepack = opts?.rulepack;
    let catalog = opts?.catalog;

    if (!rulepack || !catalog) {
      [rulepack, catalog] = await Promise.all([
        loadRulepack("SAST"),
        fetch(browser.runtime.getURL("ptk/background/sast/modules/catalog.json")).then(res => res.json())
      ]);
    }

    normalizeRulepack(rulepack, { engine: "SAST", childKey: "rules" });
    if (rulepack && Array.isArray(rulepack.modules)) {
      this.defaultModulesCache = rulepack.modules;
    }

    const scanStrategySettings = (scanStrategyRaw && typeof scanStrategyRaw === "object") ? scanStrategyRaw : {};
    let scanStrategyCode = (typeof scanStrategyRaw === "number" || typeof scanStrategyRaw === "string")
      ? Number(scanStrategyRaw)
      : Number(scanStrategySettings.scanStrategyCode ?? scanStrategySettings.scanStrategy ?? scanStrategySettings.policyCode ?? scanStrategySettings.policy ?? 0);
    if (!Number.isFinite(scanStrategyCode)) scanStrategyCode = 0;
    const scanStrategy = Object.assign({}, scanStrategySettings, { scanStrategyCode });

    const pages = Array.isArray(opts?.pages) ? opts.pages : null;
    const mergedOpts = Object.assign({}, opts, {
      rulepack,
      catalog,
      pages: pages || scanStrategy.pages || scanStrategy.routes || [],
      spaDelayMs: opts?.spaDelayMs || scanStrategy.spaDelayMs || scanStrategy.spaDelay || null,
      scanStrategyCode,
    });

    return { scanStrategy, opts: mergedOpts, scanStrategyCode };
  }

  async init() {
    this.storage = await ptk_storage.getItem(this.storageKey);
    if (!this.storage || !Object.keys(this.storage).length) return;

    const storedPayload = this._unwrapStoredScanResult(this.storage);
    const stored = this._normalizeEnvelope(storedPayload);
    const storedFindings = Array.isArray(stored?.findings) ? stored.findings.length : 0;
    const currentFindings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    const currentScanId = this.scanResult?.scanId || null;
    const storedScanId = stored?.scanId || null;

    if (!currentScanId || currentScanId !== storedScanId || currentFindings === 0) {
      this.scanResult = stored;
      this._primeSpaPages();
      this._seedRulesIndexFromFindings();
    } else if (this.isScanRunning && storedFindings > currentFindings) {
      this.scanResult = stored;
      this._primeSpaPages();
      this._seedRulesIndexFromFindings();
    }
  }

  _cloneScanResultForUi() {
    const clone = JSON.parse(JSON.stringify(this.scanResult || {}));
    if (clone && typeof clone === "object") {
      clone.__normalized = true;
    }
    return clone;
  }

  resetScanResult() {
    this.isScanRunning = false;
    this.activeTabId = null;
    this.multiPageScanActive = false;
    this.spaPageSet = new Set();
    this.spaScanInFlight = new Set();
    this.scanResult = this.getScanResultSchema();
    this._rulesIndex = new Set();
    if (this._persistTimer) {
      clearTimeout(this._persistTimer);
      this._persistTimer = null;
    }
  }

  getScanResultSchema() {
    const envelope = createScanResultEnvelope({
      engine: "SAST",
      scanId: null,
      host: null,
      tabId: null,
      startedAt: new Date().toISOString(),
      settings: {}
    });
    delete envelope.type;
    delete envelope.tabId;
    delete envelope.items;
    envelope.files = Array.isArray(envelope.files) ? envelope.files : [];
    envelope.pages = Array.isArray(envelope.pages) ? envelope.pages : [];
    return this._normalizeEnvelope(envelope);
  }

  async reset() {
    ptk_storage.setItem(this.storageKey, {});
    this.resetScanResult();
  }

  addMessageListeners() {
    this.onMessage = this.onMessage.bind(this);
    browser.runtime.onMessage.addListener(this.onMessage);
  }

  addListeners() {
    this.onRemoved = this.onRemoved.bind(this);
    browser.tabs.onRemoved.addListener(this.onRemoved);

    this.onUpdated = this.onUpdated.bind(this);
    browser.tabs.onUpdated.addListener(this.onUpdated);

    this.onCompleted = this.onCompleted.bind(this);
    browser.webRequest.onCompleted.addListener(
      this.onCompleted,
      { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
      ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
    );
  }

  async onUpdated(tabId, info, tab) { }

  removeListeners() {
    browser.tabs.onRemoved.removeListener(this.onRemoved);
    browser.tabs.onUpdated.removeListener(this.onUpdated);
    browser.webRequest.onCompleted.removeListener(this.onCompleted);
  }

  sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  onRemoved(tabId, info) {
    if (this.activeTabId === tabId) {
      this.activeTabId = null;
      this.isScanRunning = false;
    }
  }

  onCompleted(response) { }

  onMessage(message, sender, sendResponse) {
    if (message.channel == "ptk_offscreen2background_sast") {
      this.onOffscreenMessage(message);
      return;
    }

    if (message.channel == "ptk_popup2background_sast") {
      if (this["msg_" + message.type]) {
        return this["msg_" + message.type](message);
      }
      return Promise.resolve({ result: false });
    }

    if (message.channel == "ptk_content_sast2background_sast") {
      if (message.type == "scripts_collected") {
        const requestId = message.requestId || null;
        if (requestId && this.pendingScriptRequests.has(requestId)) {
          const pending = this.pendingScriptRequests.get(requestId);
          this.pendingScriptRequests.delete(requestId);
          pending.resolve(message);
          return;
        }
        if (this.multiPageScanActive) return;
        if (this.isScanRunning && this.activeTabId == sender.tab.id) {
          this.scanCode(message.scripts, message.html, message.file).catch(e => console.error("SAST scanCode failed", e));
        }
      }
      if (message.type == "spa_url_changed" && sender?.tab?.id) {
        this.onSpaUrlChanged(message.url, sender.tab.id).catch(err => {
        });
        return Promise.resolve({ ok: true });
      }
    }
  }

  _primeSpaPages() {
    this.spaPageSet = new Set();
    const pages = Array.isArray(this.scanResult?.pages) ? this.scanResult.pages : [];
    pages.forEach(entry => {
      const url = typeof entry === "string" ? entry : entry?.url;
      if (url) this.spaPageSet.add(url);
    });
  }

  _registerSpaPage(url) {
    if (!url) return false;
    if (!Array.isArray(this.scanResult.pages)) {
      this.scanResult.pages = [];
    }
    if (this.spaPageSet.has(url)) return false;
    this.spaPageSet.add(url);
    this.scanResult.pages.push(url);
    this._schedulePersistScanResult();
    return true;
  }

  async onSpaUrlChanged(rawUrl, tabId) {
    if (!rawUrl || !tabId) return;
    if (!this.isScanRunning || this.activeTabId !== tabId) return;
    const normalized = this.normalizeSpaPages([rawUrl], null)[0];
    if (!normalized) return;
    const isNew = this._registerSpaPage(normalized);
    if (this.multiPageScanActive) return;
    if (!isNew) return;
    if (this.spaScanInFlight.has(normalized)) return;
    this.spaScanInFlight.add(normalized);
    try {
      await this.waitForSpaIdle(tabId, 500);
      const payload = await this.requestScriptsFromTab(tabId).catch(() => null);
      if (!payload?.scripts) return;
      await this.scanCode(payload.scripts, payload.html, payload.file)
        .catch((err) => console.error("SAST scanCode failed", err));
    } finally {
      this.spaScanInFlight.delete(normalized);
    }
  }

  onOffscreenMessage(message) {
    const { type, scanId, info, file, findings, error } = message;
    if (!this.scanResult?.scanId) {
      this.scanResult = this._normalizeEnvelope(createScanResultEnvelope({
        engine: "SAST",
        scanId: scanId || null,
        host: null,
        tabId: null,
        startedAt: new Date().toISOString(),
        settings: {}
      }));
      this.isScanRunning = true;
    }
    if (scanId !== this.scanResult.scanId) {
      const currentFindings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
      const currentFiles = Array.isArray(this.scanResult?.files) ? this.scanResult.files.length : 0;
      const hasData = currentFindings > 0 || currentFiles > 0;
      if (!hasData && scanId) {
        this.scanResult.scanId = scanId;
        this.isScanRunning = true;
        this._schedulePersistScanResult();
      } else {
        return;
      }
    }

    if (this.isStructuredEvent(type)) {
      this.handleStructuredEvent(type, message);
      return;
    }

    if (type === "progress") {
      this.handleProgress(info);
      return;
    }

    if (type === "scan_result") {
      this.handleScanResultFromWorker(file, findings);
      this.resolvePendingScanResult(file, findings);
      return;
    }
    if (type === "findings:partial") {
      this.handleScanResultFromWorker(file, findings);
      return;
    }

    if (type === "error") {
      this.isScanRunning = false;
      console.error("SAST worker error", error);
    }
  }

  handleProgress(data) {
    if (data?.file && !data.file.startsWith("about:") && !this.scanResult.files.includes(data.file)) {
      this.scanResult.files.push(data.file);
    }

    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "progress",
      info: data
    }).catch(e => e);
  }

  handleScanResultFromWorker(file, findings = []) {
    const normalized = Array.isArray(findings) ? findings : [];
    const pageUrl = file || "";
    const pageCanon = this.canonicalFileId(pageUrl);

    if (!normalized.length) return;

    if (!this.isScanRunning) {
      this.isScanRunning = true;
      this._startScanHeartbeat();
    }
    const unifiedFindings = [];
    normalized.forEach((finding, index) => {
      finding.pageUrl = pageUrl;
      finding.pageCanon = pageCanon;
      applyRouteToFinding(finding, pageUrl);
      const unified = this._addUnifiedFinding(finding, index);
      if (unified) unifiedFindings.push(unified);
    });
    this.updateScanResult();
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "findings_delta",
      findings: unifiedFindings.length ? unifiedFindings : normalized,
      stats: this.scanResult.stats || {},
      files: pageUrl ? [pageUrl] : [],
      isScanRunning: this.isScanRunning
    }).catch(e => e);
  }

  isStructuredEvent(type) {
    return [
      "scan:start",
      "file:start",
      "file:end",
      "module:start",
      "module:end",
      "scan:summary",
      "scan:error"
    ].includes(type);
  }

  handleStructuredEvent(type, payload) {
    const data = payload?.payload || payload || {};
    const clone = () => JSON.parse(JSON.stringify(this.scanResult));
    const file = data.file;
    if (type === "scan:start") {
      this.isScanRunning = true;
      this._startScanHeartbeat();
    }
    if (type === "scan:summary") {
      this.isScanRunning = false;
      this._stopScanHeartbeat();
      this._rebuildGroupsFromFindings();
      this.updateScanResult();
      this._flushPersistScanResult();
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data
      }).catch(() => { });
      return;
    }
    if (type === "file:start") {
      if (file && !file.startsWith("about:") && !this.scanResult.files.includes(file)) {
        this.scanResult.files.push(file);
        this.updateScanResult();
      }
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data,
        scanResult: clone()
      }).catch(() => { });
      return;
    }

    if (type === "file:end" || type === "scan:start") {
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data
      }).catch(() => { });
      return;
    }

    if (type === "module:start" || type === "module:end") {
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data
      }).catch(() => { });
      return;
    }

    if (type === "scan:error") {
      this.isScanRunning = false;
      this._stopScanHeartbeat();
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type,
        payload: data
      }).catch(() => { });
    }
  }

  _startScanHeartbeat() {
    this._stopScanHeartbeat();
    this.scanStartMs = Date.now();
    this.scanHeartbeatTimer = setInterval(() => {
      if (!this.isScanRunning) return;
      const elapsedMs = Date.now() - (this.scanStartMs || Date.now());
      const totalSeconds = Math.max(0, Math.floor(elapsedMs / 1000));
      const mins = String(Math.floor(totalSeconds / 60)).padStart(2, "0");
      const secs = String(totalSeconds % 60).padStart(2, "0");
      browser.runtime.sendMessage({
        channel: "ptk_background2popup_sast",
        type: "progress",
        info: { message: "Scanning", file: `${mins}:${secs} elapsed` }
      }).catch(() => { });
    }, 2000);
  }

  _stopScanHeartbeat() {
    if (this.scanHeartbeatTimer) {
      clearInterval(this.scanHeartbeatTimer);
      this.scanHeartbeatTimer = null;
    }
    this.scanStartMs = null;
  }

  onSastWorkerMessage(event) {
    const { type, scanId, info, file, findings, error } = event.data || {};
    if (!this.scanResult?.scanId) {
      this.scanResult = this._normalizeEnvelope(createScanResultEnvelope({
        engine: "SAST",
        scanId: scanId || null,
        host: null,
        tabId: null,
        startedAt: new Date().toISOString(),
        settings: {}
      }));
      this.isScanRunning = true;
    }
    if (scanId !== this.scanResult.scanId) {
      const currentFindings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
      const currentFiles = Array.isArray(this.scanResult?.files) ? this.scanResult.files.length : 0;
      const hasData = currentFindings > 0 || currentFiles > 0;
      if (!hasData && scanId) {
        this.scanResult.scanId = scanId;
        this.isScanRunning = true;
        this._schedulePersistScanResult();
      } else {
        return;
      }
    }

    if (this.isStructuredEvent(type)) {
      this.handleStructuredEvent(type, event.data);
      return;
    }

    if (type === "progress") {
      this.handleProgress(info);
      return;
    }

    if (type === "scan_result") {
      this.handleScanResultFromWorker(file, findings);
      this.resolvePendingScanResult(file, findings);
      return;
    }
    if (type === "findings:partial") {
      this.handleScanResultFromWorker(file, findings);
      return;
    }

    if (type === "error") {
      this.isScanRunning = false;
      console.error("SAST worker error", error);
    }
  }

  ensureFirefoxWorker() {
    if (!worker.isFirefox || typeof Worker === "undefined") return;
    if (this.sastWorker) return;

    const candidates = [
      "ptk/background/sast/sast_worker.js",
      "background/sast/sast_worker.js",
    ];

    for (const path of candidates) {
      try {
        this.sastWorker = new Worker(browser.runtime.getURL(path), { type: "module" });
        this.sastWorker.onmessage = this.onSastWorkerMessage;
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

  async ensureSastOffscreenDocument() {
    if (worker.isFirefox) return;
    if (typeof chrome === "undefined" || !chrome?.offscreen?.createDocument) return;

    if (!this.offscreenInitPromise) {
      this.offscreenInitPromise = (async () => {
        if (chrome.offscreen.hasDocument) {
          const has = await chrome.offscreen.hasDocument();
          if (has) return;
        }

        await chrome.offscreen.createDocument({
          url: "ptk/offscreen/sast_offscreen.html",
          reasons: ["IFRAME_SCRIPTING"],
          justification: "Run CPU-heavy SAST engine outside the MV3 service worker",
        });
      })();
    }

    return this.offscreenInitPromise;
  }

  updateScanResult() {
    if (!Array.isArray(this.scanResult.findings)) {
      this.scanResult.findings = [];
    }
    this._ensureStats();
    this.scanResult.stats.filesCount = Array.isArray(this.scanResult.files)
      ? this.scanResult.files.length
      : 0;
    this.scanResult.stats.rulesCount = this._rulesIndex ? this._rulesIndex.size : 0;
    this._schedulePersistScanResult();
  }

  _schedulePersistScanResult() {
    if (this._persistTimer) return;
    this._persistTimer = setTimeout(() => {
      this._persistTimer = null;
      // Debounce storage writes to reduce MV2 overhead.
      ptk_storage.setItem(this.storageKey, this.scanResult);
    }, this._persistDebounceMs);
  }

  _flushPersistScanResult() {
    if (this._persistTimer) {
      clearTimeout(this._persistTimer);
      this._persistTimer = null;
    }
    ptk_storage.setItem(this.storageKey, this.scanResult);
  }

  _ensureStats() {
    if (!this.scanResult.stats || typeof this.scanResult.stats !== "object") {
      this.scanResult.stats = {
        findingsCount: 0,
        filesCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        rulesCount: 0
      };
    }
  }

  _applySeverityDelta(severity, delta) {
    this._ensureStats();
    const sev = String(severity || "info").toLowerCase();
    const field = (sev === "critical" || sev === "high" || sev === "medium" || sev === "low" || sev === "info")
      ? sev
      : "info";
    this.scanResult.stats[field] = Math.max(0, (this.scanResult.stats[field] || 0) + delta);
  }

  _trackRuleId(ruleId) {
    if (!ruleId) return;
    if (!this._rulesIndex) this._rulesIndex = new Set();
    this._rulesIndex.add(ruleId);
    this.scanResult.stats.rulesCount = this._rulesIndex.size;
  }

  _seedRulesIndexFromFindings() {
    this._rulesIndex = new Set();
    const findings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings : [];
    findings.forEach((finding) => {
      if (finding?.ruleId) this._rulesIndex.add(finding.ruleId);
    });
    this._ensureStats();
    this.scanResult.stats.rulesCount = this._rulesIndex.size;
  }

  _recalculateStats(envelope) {
    if (!envelope) return;
    const findings = Array.isArray(envelope.findings) ? envelope.findings : [];
    const filesCount = Array.isArray(envelope.files) ? envelope.files.length : 0;
    const stats = {
      findingsCount: findings.length,
      filesCount,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      rulesCount: 0
    };
    const uniqueRuleIds = new Set();
    findings.forEach(finding => {
      const sev = (finding?.severity || "").toLowerCase();
      if (sev === "critical") stats.critical += 1;
      else if (sev === "high") stats.high += 1;
      else if (sev === "medium") stats.medium += 1;
      else if (sev === "low") stats.low += 1;
      else stats.info += 1;
      if (finding?.ruleId) uniqueRuleIds.add(finding.ruleId);
    });
    stats.rulesCount = uniqueRuleIds.size;
    envelope.stats = stats;
  }

  // ---- URL / file canonicalization helpers ----

  // Normalize a URL so query/hash/cache-busters don't fragment duplicates
  canonicalizeUrl(raw, base) {
    if (!raw) return "";
    try {
      const u = new URL(String(raw), base || (typeof document !== "undefined" ? document.baseURI : undefined));

      // lower-case host
      u.hostname = (u.hostname || "").toLowerCase();

      // strip query + hash
      u.search = "";
      u.hash = "";

      // strip default ports
      const isHttp = u.protocol === "http:";
      const isHttps = u.protocol === "https:";
      if ((isHttp && u.port === "80") || (isHttps && u.port === "443")) {
        u.port = "";
      }

      // collapse multiple slashes in path and remove trailing slash (except root)
      let p = u.pathname || "/";
      p = p.replace(/\/{2,}/g, "/");
      if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
      u.pathname = p;

      // return schema://host[:port]/path
      return u.toString();
    } catch {
      // Fallback for non-URLs or if URL() not available
      const s = String(raw);
      const noHash = s.split("#")[0];
      const noQuery = noHash.split("?")[0];
      // best-effort trailing slash trim (not for root)
      return noQuery.length > 1 && noQuery.endsWith("/") ? noQuery.slice(0, -1) : noQuery;
    }
  }

  // Recognize our inline labels, e.g. "…/page.html :: inline-onclick[#1]"


  // Build a stable file identifier for deduping.
  // - For page/scripts: canonical URL without query/hash.
  // - For inline handlers/scripts: "<canonicalPage> :: <inline-label>"
  canonicalFileId(raw, base) {
    const INLINE_SPLIT_RE = /\s+::\s+/;
    if (!raw) return "";

    // if we already store "page :: inline-label"
    if (INLINE_SPLIT_RE.test(raw)) {
      const [page, inlinePart] = raw.split(INLINE_SPLIT_RE);
      const canonPage = this.canonicalizeUrl(page, base);
      return `${canonPage} :: ${inlinePart}`;
    }

    // plain URL/file path
    return this.canonicalizeUrl(raw, base);
  }



  async scanCode(scripts, html, file) {
    if (worker.isFirefox && this.sastWorker) {
      this.sastWorker.postMessage({
        type: "scan_code",
        scanId: this.scanResult.scanId,
        scripts,
        html,
        file
      });
      return this.waitForScanResult(file);
    }

    if (!worker.isFirefox) {
      await this.ensureSastOffscreenDocument();
      try {
        await browser.runtime.sendMessage({
          channel: "ptk_bg2offscreen_sast",
          type: "scan_code",
          scanId: this.scanResult.scanId,
          scripts,
          html,
          file
        });
      } catch (err) {
        console.error("Failed to send code to SAST offscreen worker", err);
      }
      return this.waitForScanResult(file);
    }

    if (!this.sastEngine) return [];
    const findings = await this.sastEngine.scanCode(scripts, html, file);
    this.handleScanResultFromWorker(file, findings);
    return findings;
  }

  waitForScanResult(file, timeoutMs = 30000) {
    if (!file) return Promise.resolve([]);
    if (this.pendingScanResults.has(file)) {
      return this.pendingScanResults.get(file).promise;
    }
    let resolve;
    const promise = new Promise((res) => {
      resolve = res;
    });
    const timer = setTimeout(() => {
      if (this.pendingScanResults.has(file)) {
        this.pendingScanResults.delete(file);
      }
      resolve([]);
    }, timeoutMs);
    this.pendingScanResults.set(file, { resolve, timer, promise });
    return promise;
  }

  resolvePendingScanResult(file, findings) {
    if (!file) return;
    const pending = this.pendingScanResults.get(file);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pendingScanResults.delete(file);
    pending.resolve(findings || []);
  }

  async requestScriptsFromTab(tabId, timeoutMs = 8000) {
    const requestId = `sast_scripts_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingScriptRequests.delete(requestId);
        reject(new Error("sast_scripts_timeout"));
      }, timeoutMs);
      this.pendingScriptRequests.set(requestId, {
        resolve: (payload) => {
          clearTimeout(timer);
          resolve(payload);
        },
        reject,
      });
    });

    try {
      await browser.tabs.sendMessage(tabId, {
        channel: "ptk_background2content_sast",
        type: "collect_scripts",
        requestId,
      });
    } catch (err) {
      this.pendingScriptRequests.delete(requestId);
      throw err;
    }
    return promise;
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
      if (!pageUrl) continue;
      const tab = await browser.tabs.get(tabId).catch(() => null);
      const currentUrl = tab?.url || "";
      const useHashNav = isHashOnlyNavigation(currentUrl, pageUrl);
      if (useHashNav) {
        const hash = new URL(pageUrl).hash || "";
        try {
          await browser.tabs.sendMessage(tabId, {
            channel: "ptk_background2content_sast",
            type: "sast_set_hash",
            hash
          });
        } catch (err) {
          console.error("[SAST] Failed to set SPA hash", hash, err);
        }
      } else {
        try {
          await browser.tabs.update(tabId, { url: pageUrl });
        } catch (err) {
          console.error("[SAST] Failed to navigate to page", pageUrl, err);
          continue;
        }
      }
      await this.waitForSpaIdle(tabId, delayMs);
      let payload;
      try {
        payload = await this.requestScriptsFromTab(tabId);
      } catch (err) {
        console.error("[SAST] Failed to collect scripts for page", pageUrl, err);
        continue;
      }
      if (!payload?.scripts) continue;
      await this.scanCode(payload.scripts, payload.html, payload.file)
        .catch((err) => console.error("SAST scanCode failed", err));
    }
  }

  async waitForSpaIdle(tabId, delayMs = 500) {
    try {
      await browser.tabs.sendMessage(tabId, {
        channel: "ptk_background2content_sast",
        type: "sast_wait_ready",
        delayMs
      });
    } catch (err) {
      await this.sleep(delayMs);
    }
  }

  async msg_init(message) {
    await this.init();
    const defaultModules = await this.getDefaultModules();
    const count = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    return Promise.resolve({
      scanResult: this._cloneScanResultForUi(),
      isScanRunning: this.isScanRunning,
      activeTab: worker.ptk_app.proxy.activeTab,
      default_modules: defaultModules
    });
  }

  async msg_reset(message) {
    this.reset();
    const defaultModules = await this.getDefaultModules();
    return Promise.resolve({
      scanResult: this._cloneScanResultForUi(),
      activeTab: worker.ptk_app.proxy.activeTab,
      default_modules: defaultModules
    });
  }

  async msg_loadfile(message) {
    this.reset();
    //await this.init()

    return new Promise((resolve, reject) => {
      var fr = new FileReader();
      fr.onload = () => {
        resolve(this.msg_save(fr.result));
      };
      fr.onerror = reject;
      fr.readAsText(message.file);
    });
  }

  async msg_save(message) {
    const raw = JSON.parse(message.json || "{}");
    const imported = this._normalizeImportedScan(raw);
    if (!imported) {
      return Promise.reject(new Error("Wrong format or empty scan result"));
    }
    this.reset();
    const normalized = this._normalizeEnvelope(imported);
    this.scanResult = normalized;
    this._seedRulesIndexFromFindings();
    this._recalculateStats(this.scanResult);
    this._flushPersistScanResult();
    return Promise.resolve({
      scanResult: this._cloneScanResultForUi(),
      isScanRunning: this.isScanRunning,
      activeTab: worker.ptk_app.proxy.activeTab,
    });
  }



  async msg_run_bg_scan(message) {
    try {
      const scanStrategyRaw = message.scanStrategy ?? message.policy;
      const opts = {
        pages: Array.isArray(message.pages) ? message.pages : null,
        spaDelayMs: message.spaDelayMs || null,
      };

      await this.runBackgroundScan(message.tabId, message.host, scanStrategyRaw, opts);
      const defaultModules = await this.getDefaultModules();

      return {
        isScanRunning: this.isScanRunning,
        scanResult: this._cloneScanResultForUi(),
        success: true,
        default_modules: defaultModules
      };
    } catch (err) {
      console.error("Failed to start SAST scan", err);
      this.isScanRunning = false;
      return { success: false, error: "modules_load_failed", message: err?.message || String(err) };
    }
  }

  msg_stop_bg_scan(message) {
    this.stopBackgroundScan();
    return Promise.resolve({
      scanResult: this._cloneScanResultForUi(),
    });
  }

  async msg_get_projects(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const url = this.buildPortalUrl(profile.projects_endpoint, profile);
    if (!url) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    const response = await fetch(url, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (httpResponse.ok) {
          return { success: true, json };
        }
        return { success: false, json: json || { message: "Unable to load projects" } };
      })
      .catch(e => ({ success: false, json: { message: "Error while loading projects: " + e.message } }));
    return response;
  }

  async msg_save_scan(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const findingCount = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    if (!findingCount) {
      return { success: false, json: { message: "Scan result is empty" } };
    }
    const url = this.buildPortalUrl(profile.scans_endpoint, profile);
    if (!url) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    const payload = buildExportScanResult(this.scanResult?.scanId, {
      target: "portal",
      scanResult: this.scanResult
    });
    if (!payload) {
      return { success: false, json: { message: "Scan result is empty" } };
    }
    if (message?.projectId) {
      payload.projectId = message.projectId;
    }
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      cache: 'no-cache',
      body: JSON.stringify(payload)
    })
      .then(async (httpResponse) => {
        if (httpResponse.status === 201) {
          return { success: true };
        }
        const json = await httpResponse.json().catch(() => ({ message: httpResponse.statusText }));
        return { success: false, json };
      })
      .catch(e => ({ success: false, json: { message: "Error while saving report: " + e.message } }));
    return response;
  }

  async msg_export_scan_result(message) {
    if (!this.scanResult || Object.keys(this.scanResult).length === 0) {
      const stored = await ptk_storage.getItem(this.storageKey);
      if (stored && Object.keys(stored).length) {
        this.scanResult = this._normalizeEnvelope(this._unwrapStoredScanResult(stored));
      }
    }
    if (!this.scanResult) return null;
    try {
      return buildExportScanResult(this.scanResult?.scanId, {
        target: message?.target || "download",
        scanResult: this.scanResult
      });
    } catch (err) {
      console.error("[PTK SAST] Failed to export scan result", err);
      throw err;
    }
  }

  async msg_download_scans(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const baseUrl = this.buildPortalUrl(profile.scans_endpoint, profile);
    if (!baseUrl) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    let requestUrl = baseUrl;
    try {
      const url = new URL(baseUrl);
      if (message?.projectId) {
        url.searchParams.set('projectId', message.projectId);
      }
      const engine = message?.engine || 'sast';
      if (engine) {
        url.searchParams.set('engine', engine);
      }
      requestUrl = url.toString();
    } catch (err) {
      return { success: false, json: { message: "Invalid scans endpoint." } };
    }
    const response = await fetch(requestUrl, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (httpResponse.ok) {
          return { success: true, json };
        }
        return { success: false, json: json || { message: "Unable to load scans" } };
      })
      .catch(e => ({ success: false, json: { message: "Error while loading scans: " + e.message } }));
    return response;
  }

  async msg_download_scan_by_id(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    if (!message?.scanId) {
      return { success: false, json: { message: "Scan identifier is required." } };
    }
    const baseUrl = this.buildPortalUrl(profile.scans_endpoint, profile);
    if (!baseUrl) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    const normalizedBase = baseUrl.replace(/\/+$/, "");
    const downloadUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}/download`;
    const response = await fetch(downloadUrl, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (!httpResponse.ok) {
          return { success: false, json: json || { message: "Unable to download scan" } };
        }
        if (json) {
          this.scanResult = this._normalizeEnvelope(json);
          this._seedRulesIndexFromFindings();
          this._flushPersistScanResult();
        }
        return json;
      })
      .catch(e => ({ success: false, json: { message: "Error while downloading scan: " + e.message } }));
    return response;
  }

  async msg_delete_scan_by_id(message) {
    const profile = worker.ptk_app.settings.profile || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    if (!message?.scanId) {
      return { success: false, json: { message: "Scan identifier is required." } };
    }
    const baseUrl = this.buildPortalUrl(profile.storage_endpoint, profile);
    if (!baseUrl) {
      return { success: false, json: { message: "Storage endpoint is not configured." } };
    }
    const normalizedBase = baseUrl.replace(/\/+$/, "");
    const deleteUrl = `${normalizedBase}/${encodeURIComponent(message.scanId)}`;
    const response = await fetch(deleteUrl, {
      method: 'DELETE',
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (!httpResponse.ok) {
          return { success: false, json: json || { message: "Unable to delete scan" } };
        }
        return json || { success: true };
      })
      .catch(e => ({ success: false, json: { message: "Error while deleting scan: " + e.message } }));
    return response;
  }

  buildPortalUrl(endpoint, profile) {
    profile = profile || worker.ptk_app.settings.profile || {};
    const baseUrl = (profile.base_url || profile.api_url || "").trim();
    const apiBase = (profile.api_base || "").trim();
    const resolvedEndpoint = (endpoint || "").trim();
    if (!baseUrl || !apiBase || !resolvedEndpoint) return null;
    const normalizedBase = baseUrl.replace(/\/+$/, "");
    let normalizedApiBase = apiBase.replace(/\/+$/, "");
    if (!normalizedApiBase.startsWith('/')) normalizedApiBase = '/' + normalizedApiBase;
    let normalizedEndpoint = resolvedEndpoint;
    if (!normalizedEndpoint.startsWith('/')) normalizedEndpoint = '/' + normalizedEndpoint;
    return normalizedBase + normalizedApiBase + normalizedEndpoint;
  }

  async runBackgroundScan(tabId, host, scanStrategyRaw, opts = {}) {
    if (this.isScanRunning) return false;

    const prepared = await this._prepareSastOptions(scanStrategyRaw, opts);
    const scanStrategy = prepared.scanStrategy;
    opts = prepared.opts;

    this.reset();
    this.isScanRunning = true;
    this.scanningRequest = false;
    this.activeTabId = tabId;
    const scanId = ptk_utils.UUID();
    this._startScanHeartbeat();
    const scanStrategyCode = Number.isFinite(opts?.scanStrategyCode)
      ? Number(opts.scanStrategyCode)
      : (typeof scanStrategy === "number" || typeof scanStrategy === "string")
        ? Number(scanStrategy)
        : 0;
    const settings = (scanStrategy && typeof scanStrategy === "object") ? scanStrategy : { scanStrategyCode };
    this.scanResult = this._normalizeEnvelope(createScanResultEnvelope({
      engine: "SAST",
      scanId,
      host,
      tabId,
      startedAt: new Date().toISOString(),
      settings
    }));
    this.scanResult.host = host;
    this.scanResult.scanStrategy = settings;
    this._schedulePersistScanResult();
    opts = Object.assign({}, opts, { scanId: this.scanResult.scanId });

    if (worker.isFirefox) {
      this.ensureFirefoxWorker();
    }

    if (worker.isFirefox && this.sastWorker) {
      this.sastEngine = null;
      this.sastWorker.postMessage({
        type: "start_scan",
        scanId: this.scanResult.scanId,
        scanStrategy: scanStrategyCode,
        opts
      });
    } else if (!worker.isFirefox) {
      await this.ensureSastOffscreenDocument();
      try {
        await browser.runtime.sendMessage({
          channel: "ptk_bg2offscreen_sast",
          type: "start_scan",
          scanId: this.scanResult.scanId,
          scanStrategy: scanStrategyCode,
          opts
        });
      } catch (err) {
        console.error("Failed to start SAST offscreen worker", err);
      }
    } else {
      this.sastEngine = new sastEngine(scanStrategyCode, opts);
      if (this.scanBus) this.scanBus = null;
      this.scanBus = new SastScanBus(this, this.sastEngine);
      this.scanBus.attach();
      this.sastEngine.events.subscribe('progress', (data) => {
        this.handleProgress(data);
      });
    }
    
    this.addListeners();

    let baseUrl = host || null;
    try {
      const tab = await browser.tabs.get(tabId);
      baseUrl = tab?.url || baseUrl;
    } catch { }

    const pages = this.normalizeSpaPages(
      opts?.pages || scanStrategy?.pages || scanStrategy?.routes || [],
      baseUrl
    );
    this.multiPageScanActive = pages.length > 0;
    if (pages.length) {
      this.scanResult.pages = pages;
      this._primeSpaPages();
      this.scanSpaPages(tabId, pages, opts).catch((err) => {
        console.error("[SAST] Multi-page SPA scan failed", err);
      });
    } else {
      this.waitForSpaIdle(tabId, opts?.spaDelayMs || 500)
        .then(() => this.requestScriptsFromTab(tabId))
        .then((payload) => {
          if (!payload?.scripts) return;
          return this.scanCode(payload.scripts, payload.html, payload.file);
        })
        .catch((err) => {
          console.error("[SAST] Initial script collection failed", err);
        });
    }
  }

  stopBackgroundScan() {
    if (this.scanResult?.scanId) {
      if (worker.isFirefox && this.sastWorker) {
        this.sastWorker.postMessage({ type: "stop_scan", scanId: this.scanResult.scanId });
      } else if (!worker.isFirefox) {
        browser.runtime.sendMessage({
          channel: "ptk_bg2offscreen_sast",
          type: "stop_scan",
          scanId: this.scanResult.scanId
        }).catch(e => e);
      }
    }

    this.isScanRunning = false;
    this._stopScanHeartbeat();
    this.activeTabId = null;
    if (this.scanResult) {
      const finished = new Date().toISOString();
      this.scanResult.finishedAt = finished;
    }
    this.pendingScriptRequests.clear();
    this.pendingScanResults.clear();
    this.multiPageScanActive = false;
    this.sastEngine = null;
    this.scanBus = null;
    const findingsCount = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    const filesCount = Array.isArray(this.scanResult?.files) ? this.scanResult.files.length : 0;
    const pagesCount = Array.isArray(this.scanResult?.pages) ? this.scanResult.pages.length : 0;
    const groupsCount = Array.isArray(this.scanResult?.groups) ? this.scanResult.groups.length : 0;
    const hasContent = findingsCount > 0 || filesCount > 0 || pagesCount > 0 || groupsCount > 0;
    if (hasContent) {
      this._rebuildGroupsFromFindings();
      this.updateScanResult();
      this._flushPersistScanResult();
    }
    this.removeListeners();
  }

  _addUnifiedFinding(finding, index = 0) {
    const unifiedFinding = this._composeUnifiedFinding(finding, index, this.scanResult);
    if (!unifiedFinding) return;
    this._upsertUnifiedFinding(unifiedFinding);
    return unifiedFinding;
  }

  _composeUnifiedFinding(finding, index = 0, targetEnvelope = null) {
    if (!finding || typeof finding !== "object") return null;
    const envelopeRef = targetEnvelope && typeof targetEnvelope === "object" ? targetEnvelope : this.scanResult;
    const moduleMeta = finding.module_metadata || {};
    const ruleMeta = finding.metadata || {};
    const locationMeta = finding.location || {};
    const moduleId = moduleMeta.id || moduleMeta.moduleId || "module";
    const ruleId = ruleMeta.id || ruleMeta.rule_id || ruleMeta.name || `rule-${index}`;
    const severity = resolveEffectiveSeverity({
      override: finding.severity,
      moduleMeta,
      ruleMeta
    });
    const description = ruleMeta.description || moduleMeta.description || null;
    const recommendation = ruleMeta.recommendation || moduleMeta.recommendation || null;
    const mergedLinks = Object.assign({}, moduleMeta.links || {}, ruleMeta.links || {});
    const links = Object.keys(mergedLinks).length ? mergedLinks : null;
    const scanId = envelopeRef?.scanId || this.scanResult?.scanId || null;
    const createdAt = envelopeRef?.finishedAt || this.scanResult?.finishedAt || new Date().toISOString();
    const fingerprint = finding.fingerprint || this._buildSastFingerprintFromRaw(finding)
    const pageUrl = locationMeta.pageUrl || locationMeta.url || finding.pageUrl || finding.pageCanon || null;
    const runtimeUrl = locationMeta.runtimeUrl || pageUrl || null;
    const location = {
      file: locationMeta.file || finding.codeFile || finding.file || null,
      line: locationMeta.line ?? finding?.sink?.sinkLoc?.start?.line ?? finding?.source?.sourceLoc?.start?.line ?? null,
      column: locationMeta.column ?? finding?.sink?.sinkLoc?.start?.column ?? finding?.source?.sourceLoc?.start?.column ?? null,
      runtimeUrl,
      pageUrl,
      url: pageUrl || null,
      param: locationMeta.param || finding.param || null
    };
    const tracePayload = Array.isArray(finding.trace)
      ? finding.trace
      : (Array.isArray(finding?.evidence?.sast?.trace) ? finding.evidence.sast.trace : []);
    const confidence = Number.isFinite(finding.confidence) ? finding.confidence : null;
    const confidenceSignals = Array.isArray(finding?.evidence?.sast?.confidenceSignals)
      ? finding.evidence.sast.confidenceSignals
      : [];
    const unifiedFinding = {
      id: `${scanId || 'scan'}::SAST::${moduleId}::${ruleId}::${index}`,
      engine: "SAST",
      scanId,
      moduleId,
      moduleName: moduleMeta.name || moduleId,
      ruleId,
      ruleName: ruleMeta.name || ruleId,
      vulnId: moduleMeta.vulnId || moduleMeta.category || moduleId,
      category: moduleMeta.category || ruleMeta.category || "sast",
      severity,
      owasp: moduleMeta.owasp || null,
      cwe: moduleMeta.cwe || null,
      tags: moduleMeta.tags || ruleMeta.tags || [],
      description,
      recommendation,
      links,
      location,
      createdAt,
      fingerprint,
      confidence,
      evidence: {
        sast: {
          codeSnippet: finding.codeSnippet || null,
          source: finding.source || null,
          sink: finding.sink || null,
          nodeType: finding.nodeType || null,
          trace: tracePayload || [],
          mode: finding.mode || finding?.evidence?.sast?.mode || null,
          confidenceSignals
        }
      }
    };
    resolveFindingTaxonomy({
      finding: unifiedFinding,
      ruleMeta,
      moduleMeta
    });
    const normalizedFinding = normalizeFinding({
      engine: "SAST",
      moduleMeta,
      ruleMeta,
      scanId,
      finding: unifiedFinding
    });
    return normalizedFinding;
  }

  _registerFindingGroup(envelope, unifiedFinding) {
    if (!envelope || !unifiedFinding) return;
    const groupKeyParts = [
      "SAST",
      unifiedFinding.vulnId,
      unifiedFinding.moduleId,
      unifiedFinding.ruleId,
      unifiedFinding.location.file || "",
      unifiedFinding.location.line || ""
    ];
    const groupKey = groupKeyParts.join('@@');
    addFindingToGroup(envelope, unifiedFinding, groupKey, {
      file: unifiedFinding.location.file,
      sink: unifiedFinding.evidence?.sast?.sink?.label || null
    });
  }

  _collectLegacyItems(rawItems) {
    if (Array.isArray(rawItems)) {
      return rawItems.filter(Boolean);
    }
    if (rawItems && typeof rawItems === "object") {
      return Object.keys(rawItems)
        .sort()
        .map((key) => rawItems[key])
        .filter(Boolean);
    }
    return [];
  }

  _normalizeImportedScan(raw) {
    if (!raw || typeof raw !== "object") return null;
    const payload = raw.scanResult && typeof raw.scanResult === "object"
      ? raw.scanResult
      : raw;
    const engineValue = typeof payload.engine === "string" ? payload.engine.toUpperCase() : "";
    const typeValue = typeof payload.type === "string" ? payload.type.toLowerCase() : "";
    const isSast = !engineValue && !typeValue
      ? true
      : (engineValue === "SAST" || typeValue === "sast");
    const hasFindings = Array.isArray(payload.findings) && payload.findings.length > 0;
    const legacyItems = this._collectLegacyItems(payload.items);
    if (!isSast && !legacyItems.length) {
      return null;
    }
    if (!hasFindings && !legacyItems.length) {
      return null;
    }
    return payload;
  }

  _buildSastFingerprintFromRaw(finding) {
    if (!finding || typeof finding !== "object") return ""
    const ruleMeta = finding.metadata || {}
    const ruleId = ruleMeta.id || ruleMeta.rule_id || ruleMeta.name || ""
    const severity = ruleMeta.severity || finding.severity || ""
    const srcFile = this.canonicalFileId(finding?.source?.sourceFileFull || finding?.source?.sourceFile || "", finding?.pageUrl)
    const sinkFile = this.canonicalFileId(finding?.sink?.sinkFileFull || finding?.sink?.sinkFile || "", finding?.pageUrl)
    const srcLoc = finding?.source?.sourceLoc ? JSON.stringify(finding.source.sourceLoc) : ""
    const sinkLoc = finding?.sink?.sinkLoc ? JSON.stringify(finding.sink.sinkLoc) : ""
    return [ruleId, severity, srcFile, sinkFile, srcLoc, sinkLoc].join('@@')
  }

  _buildSastFingerprintFromUnified(finding) {
    if (finding?.fingerprint) return finding.fingerprint
    const ruleId = finding?.ruleId || ""
    const severity = finding?.severity || ""
    const file = finding?.location?.file || ""
    const line = finding?.location?.line || ""
    const column = finding?.location?.column || ""
    const pageUrl = finding?.location?.pageUrl || finding?.location?.url || ""
    return [ruleId, severity, file, line, column, pageUrl].join('@@')
  }

  _upsertUnifiedFinding(finding) {
    if (!finding) return
    if (!Array.isArray(this.scanResult.findings)) {
      this.scanResult.findings = []
    }
    const fingerprint = this._buildSastFingerprintFromUnified(finding)
    finding.fingerprint = fingerprint
    const idx = this.scanResult.findings.findIndex(item => this._buildSastFingerprintFromUnified(item) === fingerprint)
    if (idx === -1) {
      this.scanResult.findings.push(finding)
      this._ensureStats()
      this.scanResult.stats.findingsCount += 1
      this._applySeverityDelta(finding?.severity, 1)
      this._trackRuleId(finding?.ruleId)
    } else {
      const prev = this.scanResult.findings[idx]
      const prevSeverity = String(prev?.severity || "info").toLowerCase()
      const nextSeverity = String(finding?.severity || "info").toLowerCase()
      this.scanResult.findings[idx] = finding
      if (prevSeverity !== nextSeverity) {
        this._applySeverityDelta(prevSeverity, -1)
        this._applySeverityDelta(nextSeverity, 1)
      }
      if (prev?.ruleId !== finding?.ruleId) {
        this._trackRuleId(finding?.ruleId)
      }
    }
  }

  _rebuildGroupsFromFindings() {
    this.scanResult.groups = []
    const findings = Array.isArray(this.scanResult.findings) ? this.scanResult.findings : []
    findings.forEach(finding => this._registerFindingGroup(this.scanResult, finding))
  }

  _normalizeEnvelope(envelope) {
    const out = envelope && typeof envelope === "object" ? envelope : {};
    if (!Array.isArray(out.files)) out.files = [];
    if (!Array.isArray(out.findings)) out.findings = [];
    if (!Array.isArray(out.groups)) out.groups = [];
    out.version = out.version || "1.0";
    out.engine = out.engine || "SAST";
    out.startedAt = out.startedAt || out.date || new Date().toISOString();
    if (out.date) delete out.date;
    if (typeof out.finishedAt === "undefined") {
      out.finishedAt = out.finished || null;
    }
    if (out.finished) delete out.finished;
    if (out.tabId !== undefined) delete out.tabId;
    if (out.type !== undefined) delete out.type;
    if (!out.settings || typeof out.settings !== "object") out.settings = {};
    const statsDefaults = {
      findingsCount: 0,
      filesCount: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      rulesCount: 0
    };
    const legacyItems = this._collectLegacyItems(envelope?.items);
    const hasFindings = Array.isArray(out.findings) && out.findings.length > 0;
    if (!hasFindings && legacyItems.length) {
      out.findings = [];
      out.groups = [];
      out.stats = Object.assign({}, statsDefaults);
      legacyItems.forEach((item, index) => {
        const unifiedFinding = this._composeUnifiedFinding(item, index, out);
        if (!unifiedFinding) return;
        out.findings.push(unifiedFinding);
      });
    } else {
      out.stats = Object.assign({}, statsDefaults, out.stats || {});
    }
    if (Array.isArray(out.findings)) {
      out.findings = out.findings.map(f => {
        if (!f) return f
        f.fingerprint = this._buildSastFingerprintFromUnified(f)
        return f
      }).filter(Boolean)
    }
    if (out.items !== undefined) delete out.items;
    this._recalculateStats(out);
    return out;
  }

  _unwrapStoredScanResult(stored) {
    if (!stored || typeof stored !== "object") return stored;
    if (stored.scanResult && typeof stored.scanResult === "object") {
      return stored.scanResult;
    }
    return stored;
  }
}
