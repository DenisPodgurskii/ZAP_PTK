/* Author: Denis Podgurskii */
import {
  ptk_utils,
  ptk_storage,
} from "../background/utils.js";

import { sastEngine } from "./sast/sastEngine.js";
import { SastScanBus } from "./sast/sast_scan_bus.js";
import {
  createScanResultEnvelope,
} from "./common/scanResults.js";
import buildExportScanResult from "./export/buildExportScanResult.js";
import { applyScanAnalysis } from "./analysis/scanAnalysisEngine.js";
import { compressScanPayload } from "./export/compressScanPayload.js";
import { ExportChunkStore } from "./export/exportChunkStore.js";
import { parseUploadedScanFile } from "./export/parseUploadedScanFile.js";
import { loadRulepack } from "./common/moduleRegistry.js";
import { normalizeRulepack } from "./common/severity_utils.js";
import { SastConfigService } from "./sast/sast_config_service.js";
import { SastAsyncSession } from "./sast/sast_async_session.js";
import { SastNotifier } from "./sast/sast_notifier.js";
import { SastPortalClient } from "./sast/sast_portal_client.js";
import { SastResultStore } from "./sast/sast_result_store.js";
import { SastSessionCoordinator } from "./sast/sast_session_coordinator.js";
import { SastTransport } from "./sast/sast_transport.js";
import {
  countSastArtifacts,
  mergeSastArtifacts
} from "./sast/sast_artifacts.js";
import {
  buildSastProgressSnapshot,
  createSastProgressState,
} from "./sast/sast_progress.js";

const worker = self;

export class ptk_sast {
  constructor(settings) {
    this.settings = settings;
    this.storageKey = "ptk_sast";
    this.resultStore = new SastResultStore({
      storageKey: this.storageKey,
      persistDebounceMs: 1000,
      canonicalFileId: this.canonicalFileId.bind(this)
    });
    this.portalClient = new SastPortalClient({
      getProfile: () => worker?.ptk_app?.settings?.profile || {}
    });
    this.exportChunkStore = new ExportChunkStore({ prefix: "sast" });
    this.configService = new SastConfigService({
      browserApi: browser,
      loadRulepackFn: loadRulepack,
      normalizeRulepackFn: normalizeRulepack
    });

    this.asyncSession = new SastAsyncSession();
    this.progressState = createSastProgressState();
    this.transport = new SastTransport({
      asyncSession: this.asyncSession,
      eventHandler: this.handleTransportEvent.bind(this)
    });
    this.sessionCoordinator = new SastSessionCoordinator({
      transport: this.transport,
      browserApi: browser,
      schedulePersist: this._schedulePersistScanResult.bind(this),
      updateScanResult: this.updateScanResult.bind(this),
      scanCode: this.scanCode.bind(this),
      stopBackgroundScan: this.stopBackgroundScan.bind(this),
      getProgressSnapshot: this._buildSastProgressSnapshot.bind(this),
      getProgressStatus: () => this.progressState?.lastStatus || "Scanning",
      sendPopupMessage: (message) => {
        browser.runtime.sendMessage(message).catch(() => { });
      }
    });
    this.notifier = new SastNotifier({
      browserApi: browser,
      getScanResult: () => this.scanResult,
      getIsScanRunning: () => this.isScanRunning,
      setIsScanRunning: (value) => {
        this.isScanRunning = value;
      },
      getProgressState: () => this.progressState,
      setProgressState: (value) => {
        this.progressState = value;
      },
      buildProgressSnapshot: this._buildSastProgressSnapshot.bind(this),
      countArtifacts: this._countSastArtifacts.bind(this),
      mergeArtifacts: this._mergeSastArtifacts.bind(this),
      addUnifiedFinding: this._addUnifiedFinding.bind(this),
      updateScanResult: this.updateScanResult.bind(this),
      rebuildGroupsFromFindings: this._rebuildGroupsFromFindings.bind(this),
      flushPersist: this._flushPersistScanResult.bind(this),
      startHeartbeat: this.sessionCoordinator.startHeartbeat.bind(this.sessionCoordinator),
      stopHeartbeat: this.sessionCoordinator.stopHeartbeat.bind(this.sessionCoordinator)
    });
    this.resetScanResult();

    this.addMessageListeners();
    this.transport.ensureFirefoxWorker();
  }

  get scanResult() {
    return this.resultStore.scanResult;
  }

  set scanResult(value) {
    this.resultStore.scanResult = value;
  }

  get _persistTimer() {
    return this.resultStore.persistTimer;
  }

  set _persistTimer(value) {
    this.resultStore.persistTimer = value;
  }

  get _rulesIndex() {
    return this.resultStore.rulesIndex;
  }

  set _rulesIndex(value) {
    this.resultStore.rulesIndex = value;
  }

  get isScanRunning() {
    return this.sessionCoordinator?.isScanRunning ?? false;
  }

  set isScanRunning(value) {
    if (this.sessionCoordinator) {
      this.sessionCoordinator.isScanRunning = !!value;
    }
  }

  get activeTabId() {
    return this.sessionCoordinator?.activeTabId ?? null;
  }

  set activeTabId(value) {
    if (this.sessionCoordinator) {
      this.sessionCoordinator.activeTabId = value ?? null;
    }
  }

  get multiPageScanActive() {
    return this.sessionCoordinator?.multiPageScanActive ?? false;
  }

  set multiPageScanActive(value) {
    if (this.sessionCoordinator) {
      this.sessionCoordinator.multiPageScanActive = !!value;
    }
  }

  get spaPageSet() {
    return this.sessionCoordinator?.spaPageSet ?? new Set();
  }

  set spaPageSet(value) {
    if (this.sessionCoordinator) {
      this.sessionCoordinator.spaPageSet = value instanceof Set ? value : new Set();
    }
  }

  get spaScanInFlight() {
    return this.sessionCoordinator?.spaScanInFlight ?? new Set();
  }

  set spaScanInFlight(value) {
    if (this.sessionCoordinator) {
      this.sessionCoordinator.spaScanInFlight = value instanceof Set ? value : new Set();
    }
  }

  get scanHeartbeatTimer() {
    return this.sessionCoordinator?.scanHeartbeatTimer ?? null;
  }

  set scanHeartbeatTimer(value) {
    if (this.sessionCoordinator) {
      this.sessionCoordinator.scanHeartbeatTimer = value ?? null;
    }
  }

  get scanStartMs() {
    return this.sessionCoordinator?.scanStartMs ?? null;
  }

  set scanStartMs(value) {
    if (this.sessionCoordinator) {
      this.sessionCoordinator.scanStartMs = value ?? null;
    }
  }

  get scanningRequest() {
    return this.sessionCoordinator?.scanningRequest ?? false;
  }

  set scanningRequest(value) {
    if (this.sessionCoordinator) {
      this.sessionCoordinator.scanningRequest = !!value;
    }
  }

  async getDefaultModules(rulepack = null) {
    return this.configService.getDefaultModules(rulepack);
  }

  async _prepareSastOptions(scanStrategyRaw, opts = {}) {
    return this.configService.prepareOptions(scanStrategyRaw, opts);
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
      this.sessionCoordinator.primeSpaPages(this.scanResult);
      this._seedRulesIndexFromFindings();
    } else if (this.isScanRunning && storedFindings > currentFindings) {
      this.scanResult = stored;
      this.sessionCoordinator.primeSpaPages(this.scanResult);
      this._seedRulesIndexFromFindings();
    }
  }

  _cloneScanResultForUi() {
    return this.resultStore.cloneForUi();
  }

  resetScanResult() {
    this.sessionCoordinator.reset();
    this.resultStore.reset();
    this.progressState = createSastProgressState();
  }

  getScanResultSchema() {
    return this.resultStore.getScanResultSchema();
  }

  async reset() {
    this.stopBackgroundScan({ discardResults: true });
    await ptk_storage.setItem(this.storageKey, {});
    this.resetScanResult();
  }

  _markScanIdIgnored(scanId) {
    this.asyncSession.markIgnoredScanId(scanId);
  }

  _shouldIgnoreWorkerEvent(scanId) {
    return this.asyncSession.shouldIgnoreWorkerEvent(scanId);
  }

  _clearPendingAsyncState() {
    this.asyncSession.clearPendingAsyncState();
  }

  _buildSastProgressSnapshot() {
    return buildSastProgressSnapshot({
      state: this.progressState,
      scanResult: this.scanResult,
      countArtifacts: countSastArtifacts,
      scanStartMs: this.scanStartMs,
      isRunning: this.isScanRunning
    });
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

  async onUpdated(tabId, info, tab) {
    return this.sessionCoordinator.handleUpdated(tabId, info, tab);
  }

  removeListeners() {
    browser.tabs.onRemoved.removeListener(this.onRemoved);
    browser.tabs.onUpdated.removeListener(this.onUpdated);
    browser.webRequest.onCompleted.removeListener(this.onCompleted);
  }

  onRemoved(tabId, info) {
    this.sessionCoordinator.handleRemoved(tabId);
  }

  onCompleted(response) { }

  onMessage(message, sender, sendResponse) {
    if (this.transport.handleExternalMessage(message)) {
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
        if (requestId && this.asyncSession.resolveScriptRequest(requestId, message)) {
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

  handleTransportEvent(message) {
    const { type, scanId, info, file, findings, artifacts, error } = message || {};
    if (this._shouldIgnoreWorkerEvent(scanId)) {
      return;
    }
    if (!scanId && !this.scanResult?.scanId) {
      if (type === "error" && error) {
        console.error("SAST worker error", error);
      }
      return;
    }
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

    if (this.notifier.isStructuredEvent(type)) {
      this.notifier.handleStructuredEvent(type, message);
      return;
    }

    if (type === "progress") {
      this.notifier.handleProgress(info);
      return;
    }

    if (type === "scan_result") {
      this.notifier.handleScanResultFromWorker(file, findings, artifacts, {
        canonicalizeFileId: this.canonicalFileId.bind(this)
      });
      this.resolvePendingScanResult(file, findings);
      return;
    }
    if (type === "findings:partial") {
      this.notifier.handleScanResultFromWorker(file, findings, artifacts, {
        canonicalizeFileId: this.canonicalFileId.bind(this)
      });
      return;
    }

    if (type === "error") {
      this.isScanRunning = false;
      console.error("SAST worker error", error);
    }
  }

  async onSpaUrlChanged(rawUrl, tabId) {
    return this.sessionCoordinator.onSpaUrlChanged(rawUrl, tabId, this.scanResult);
  }

  updateScanResult() {
    this.resultStore.updateScanResult();
  }

  _schedulePersistScanResult() {
    this.resultStore.schedulePersist();
  }

  _flushPersistScanResult() {
    this.resultStore.flushPersist();
  }

  _ensureStats() {
    this.resultStore.ensureStats();
  }

  _countSastArtifacts(sastArtifacts = null) {
    return countSastArtifacts(sastArtifacts);
  }

  _mergeSastArtifacts(artifacts = null, { pageUrl = "", pageCanon = "" } = {}) {
    mergeSastArtifacts(this.scanResult, artifacts, { pageUrl, pageCanon });
  }

  _applySeverityDelta(severity, delta) {
    this.resultStore.applySeverityDelta(severity, delta);
  }

  _trackRuleId(ruleId) {
    this.resultStore.trackRuleId(ruleId);
  }

  _seedRulesIndexFromFindings() {
    this.resultStore.seedRulesIndexFromFindings();
  }

  _recalculateStats(envelope) {
    this.resultStore.recalculateStats(envelope);
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
    const remoteResult = await this.transport.scanCodeRemote({
      scanId: this.scanResult.scanId,
      scripts,
      html,
      file,
      timeoutMs: 30000
    });
    if (remoteResult !== null) {
      return remoteResult;
    }

    if (!this.sastEngine) return [];
    const detail = await this.sastEngine.scanCodeDetailed(scripts, html, file);
    const findings = Array.isArray(detail?.findings) ? detail.findings : [];
    this.notifier.handleScanResultFromWorker(file, findings, detail?.artifacts || null, {
      canonicalizeFileId: this.canonicalFileId.bind(this)
    });
    return findings;
  }

  async collectAndScanTab(tabId, opts = {}) {
    return this.sessionCoordinator.collectAndScanTab(tabId, opts);
  }

  waitForScanResult(file, timeoutMs = 30000) {
    return this.asyncSession.waitForScanResult(file, timeoutMs);
  }

  resolvePendingScanResult(file, findings) {
    this.asyncSession.resolveScanResult(file, findings);
  }

  normalizeSpaPages(pages, baseUrl) {
    return this.sessionCoordinator.normalizeSpaPages(pages, baseUrl);
  }

  async scanSpaPages(tabId, pages, opts = {}) {
    return this.sessionCoordinator.scanSpaPages(tabId, pages, opts);
  }

  async msg_init(message) {
    await this.init();
    const defaultModules = await this.getDefaultModules();
    const count = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    return Promise.resolve({
      scanResult: this._cloneScanResultForUi(),
      isScanRunning: this.isScanRunning,
      progress: this._buildSastProgressSnapshot(),
      activeTab: worker.ptk_app.proxy.activeTab,
      default_modules: defaultModules
    });
  }

  async msg_reset(message) {
    await this.reset();
    const defaultModules = await this.getDefaultModules();
    return Promise.resolve({
      scanResult: this._cloneScanResultForUi(),
      isScanRunning: this.isScanRunning,
      progress: this._buildSastProgressSnapshot(),
      activeTab: worker.ptk_app.proxy.activeTab,
      default_modules: defaultModules
    });
  }

  async msg_loadfile(message) {
    await this.reset();
    const parsed = await parseUploadedScanFile(message?.file);
    if (!parsed?.ok || !parsed?.json) {
      return Promise.reject(new Error("Wrong format or empty scan result"));
    }
    return this.msg_save({ json: JSON.stringify(parsed.json) });
  }

  async msg_save(message) {
    const raw = JSON.parse(message.json || "{}");
    const imported = this._normalizeImportedScan(raw);
    if (!imported) {
      return Promise.reject(new Error("Wrong format or empty scan result"));
    }
    await this.reset();
    const normalized = this._normalizeEnvelope(imported);
    this.scanResult = normalized;
    this._seedRulesIndexFromFindings();
    this._recalculateStats(this.scanResult);
    this._flushPersistScanResult();
    return Promise.resolve({
      scanResult: this._cloneScanResultForUi(),
      isScanRunning: this.isScanRunning,
      progress: this._buildSastProgressSnapshot(),
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
        progress: this._buildSastProgressSnapshot(),
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
      isScanRunning: this.isScanRunning,
      progress: this._buildSastProgressSnapshot(),
    });
  }

  async msg_get_projects(message) {
    return this.portalClient.getProjects();
  }

  async msg_save_scan(message) {
    return this.portalClient.saveScan({
      scanResult: this.scanResult,
      projectId: message?.projectId || null
    });
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
      const payload = buildExportScanResult(this.scanResult?.scanId, {
        target: message?.target || "download",
        scanResult: this.scanResult
      });
      if (!payload) return null;
      const compressed = await compressScanPayload(payload);
      const descriptor = this.exportChunkStore.createEntry({
        bytes: compressed.body,
        fileName: message?.fileName || "PTK_SAST_scan.json",
        contentType: compressed.contentType,
        compression: compressed.compression
      });
      if (!descriptor) {
        return { success: false, error: "empty_export_payload" };
      }
      return {
        success: true,
        exportMode: "chunked",
        ...descriptor
      };
    } catch (err) {
      console.error("[PTK SAST] Failed to export scan result", err);
      throw err;
    }
  }

  async msg_export_scan_chunk(message) {
    const chunk = this.exportChunkStore.getChunk(message?.exportId, message?.index);
    if (!chunk) {
      return { success: false, error: "export_not_found_or_expired" };
    }
    return {
      success: true,
      exportMode: "chunked",
      exportId: chunk.exportId,
      index: chunk.index,
      chunkCount: chunk.chunkCount,
      chunk: chunk.chunk
    };
  }

  async msg_release_export_scan(message) {
    const released = this.exportChunkStore.release(message?.exportId);
    return { success: released };
  }

  async msg_download_scans(message) {
    return this.portalClient.downloadScans({
      projectId: message?.projectId || null,
      engine: message?.engine || "sast"
    });
  }

  async msg_download_scan_by_id(message) {
    const response = await this.portalClient.downloadScanById({
      scanId: message?.scanId
    });
    if (response?.success === false) {
      return response;
    }
    if (response) {
      this.scanResult = this._normalizeEnvelope(response);
      this._seedRulesIndexFromFindings();
      this._flushPersistScanResult();
    }
    return response;
  }

  async msg_delete_scan_by_id(message) {
    return this.portalClient.deleteScanById({ scanId: message?.scanId });
  }

  buildPortalUrl(endpoint, profile) {
    return this.portalClient.buildPortalUrl(endpoint, profile);
  }

  _getZapManualEngineOptions() {
    const bridge = worker?.ptk_app?.automation?.zap;
    if (!bridge || typeof bridge.getManualEngineConfig !== 'function') {
      return null;
    }
    const config = bridge.getManualEngineConfig('SAST');
    return (config && typeof config === 'object') ? config : null;
  }

  async runBackgroundScan(tabId, host, scanStrategyRaw, opts = {}) {
    if (this.isScanRunning) return false;

    const zapManualOpts = this._getZapManualEngineOptions();
    const effectiveOpts = Object.assign({}, zapManualOpts || {}, opts || {});
    const prepared = await this._prepareSastOptions(scanStrategyRaw, effectiveOpts);
    const scanStrategy = prepared.scanStrategy;
    opts = prepared.opts;

    await this.reset();
    const scanId = ptk_utils.UUID();
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
    this.sessionCoordinator.beginSession(tabId);
    this._schedulePersistScanResult();
    opts = Object.assign({}, opts, { scanId: this.scanResult.scanId });

    const startedRemote = await this.transport.startRemoteScan({
      scanId: this.scanResult.scanId,
      scanStrategyCode,
      opts
    });

    if (!startedRemote) {
      this.sastEngine = new sastEngine(scanStrategyCode, opts);
      if (this.scanBus) this.scanBus = null;
      this.scanBus = new SastScanBus(this, this.sastEngine);
      this.scanBus.attach();
      this.sastEngine.events.subscribe('progress', (data) => {
        this.notifier.handleProgress(data);
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
      this.sessionCoordinator.primeSpaPages(this.scanResult);
      this.scanSpaPages(tabId, pages, opts).catch((err) => {
        console.error("[SAST] Multi-page SPA scan failed", err);
      });
    } else {
      this.collectAndScanTab(tabId, {
        delayMs: opts?.spaDelayMs || 500,
        attempts: 4,
        timeoutMs: 12000,
        retryDelayMs: 600
      })
        .catch((err) => {
          console.error("[SAST] Initial script collection failed", err);
        });
    }
  }

  stopBackgroundScan(opts = {}) {
    const discardResults = !!opts?.discardResults;
    const scanId = this.scanResult?.scanId || null;
    if (scanId) {
      this._markScanIdIgnored(scanId);
    }
    if (scanId) {
      this.transport.stopRemoteScan(scanId);
    }

    if (this.scanResult) {
      const finished = new Date().toISOString();
      this.scanResult.finishedAt = finished;
    }
    this.sessionCoordinator.reset();
    this._clearPendingAsyncState();
    this.sastEngine = null;
    this.scanBus = null;
    if (discardResults) {
      this.removeListeners();
      return;
    }
    const findingsCount = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    const filesCount = Array.isArray(this.scanResult?.files) ? this.scanResult.files.length : 0;
    const pagesCount = Array.isArray(this.scanResult?.pages) ? this.scanResult.pages.length : 0;
    const groupsCount = Array.isArray(this.scanResult?.groups) ? this.scanResult.groups.length : 0;
    const hasContent = findingsCount > 0 || filesCount > 0 || pagesCount > 0 || groupsCount > 0;
    if (hasContent) {
      this._rebuildGroupsFromFindings();
      this.updateScanResult();
      try {
        applyScanAnalysis(this.scanResult, { force: true });
      } catch (_) { }
      this._flushPersistScanResult();
    }
    this.removeListeners();
  }

  _addUnifiedFinding(finding, index = 0) {
    return this.resultStore.addUnifiedFinding(finding, index);
  }

  _composeUnifiedFinding(finding, index = 0, targetEnvelope = null) {
    return this.resultStore.composeUnifiedFinding(finding, index, targetEnvelope);
  }

  _registerFindingGroup(envelope, unifiedFinding) {
    return this.resultStore.registerFindingGroup(envelope, unifiedFinding);
  }

  _collectLegacyItems(rawItems) {
    return this.resultStore.collectLegacyItems(rawItems);
  }

  _normalizeImportedScan(raw) {
    return this.resultStore.normalizeImportedScan(raw);
  }

  _buildSastFingerprintFromRaw(finding) {
    return this.resultStore.buildSastFingerprintFromRaw(finding);
  }

  _buildSastFingerprintFromUnified(finding) {
    return this.resultStore.buildSastFingerprintFromUnified(finding);
  }

  _upsertUnifiedFinding(finding) {
    return this.resultStore.upsertUnifiedFinding(finding);
  }

  _rebuildGroupsFromFindings() {
    return this.resultStore.rebuildGroupsFromFindings();
  }

  _normalizeEnvelope(envelope) {
    return this.resultStore.normalizeEnvelope(envelope);
  }

  _unwrapStoredScanResult(stored) {
    return this.resultStore.unwrapStoredScanResult(stored);
  }
}
