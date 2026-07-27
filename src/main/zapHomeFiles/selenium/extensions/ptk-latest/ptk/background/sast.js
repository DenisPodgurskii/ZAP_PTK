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
import { portalPolicyRuntimeStore } from "./common/portalPolicyRuntimeStore.js";

const worker = typeof self !== "undefined" ? self : globalThis;

const SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_PAGES = 100;
const SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

function decodeSastHtmlEntities(value) {
  const named = {
    amp: "&",
    quot: "\"",
    apos: "'",
    lt: "<",
    gt: ">"
  };
  return String(value || "").replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|quot|apos|lt|gt);/g, (match, entity) => {
    if (entity[0] !== "#") return named[entity] ?? match;
    const isHex = entity[1]?.toLowerCase() === "x";
    const codePoint = parseInt(entity.slice(isHex ? 2 : 1), isHex ? 16 : 10);
    if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff) return match;
    try {
      return String.fromCodePoint(codePoint);
    } catch (_) {
      return match;
    }
  });
}

function canonicalSastPageUrl(rawUrl) {
  try {
    const url = new URL(String(rawUrl || ""));
    if (url.protocol !== "http:" && url.protocol !== "https:") return "";
    url.hash = "";
    return url.href;
  } catch (_) {
    return "";
  }
}

export function deriveSastPageSourceScope(rawUrl) {
  try {
    const url = new URL(String(rawUrl || ""));
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    const path = url.pathname || "/";
    let prefix = path;
    if (!prefix.endsWith("/")) {
      const slash = prefix.lastIndexOf("/");
      prefix = slash >= 0 ? prefix.slice(0, slash + 1) : "/";
    }
    if (/\/index\.html?$/i.test(path)) {
      prefix = path.replace(/index\.html?$/i, "");
    }
    return {
      origin: url.origin,
      prefix: prefix || "/"
    };
  } catch (_) {
    return null;
  }
}

export function extractSastPageLinksForScope(html, baseUrl, options = {}) {
  if (typeof html !== "string" || !html || !baseUrl) return [];
  const scope = options?.scope || deriveSastPageSourceScope(baseUrl);
  if (!scope?.origin || !scope?.prefix) return [];
  const maxLinks = Number.isFinite(Number(options?.maxLinks))
    ? Math.max(0, Number(options.maxLinks))
    : SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_PAGES;
  const links = [];
  const seen = new Set();
  const add = (candidate) => {
    const canonical = canonicalSastPageUrl(candidate);
    if (!canonical || seen.has(canonical)) return;
    try {
      const url = new URL(canonical);
      if (url.origin !== scope.origin) return;
      if (!url.pathname.startsWith(scope.prefix)) return;
      seen.add(canonical);
      links.push(canonical);
    } catch (_) { }
  };

  add(baseUrl);
  const anchorRe = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;
  let match;
  while ((match = anchorRe.exec(html)) !== null && links.length < maxLinks) {
    const rawHref = decodeSastHtmlEntities(match[1] ?? match[2] ?? match[3] ?? "").trim();
    if (!rawHref || /^(?:javascript|mailto|tel|data):/i.test(rawHref)) continue;
    try {
      add(new URL(rawHref, baseUrl).href);
    } catch (_) { }
  }
  return links.slice(0, maxLinks);
}

export function normalizeSastPageSourceUrls(urls, startUrl = "", options = {}) {
  const maxUrls = Number.isFinite(Number(options?.maxUrls))
    ? Math.max(0, Number(options.maxUrls))
    : SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_PAGES;
  if (!maxUrls) return [];

  const seed = canonicalSastPageUrl(startUrl);
  const scope = options?.scope || deriveSastPageSourceScope(seed || startUrl);
  if (!scope?.origin || !scope?.prefix) return [];

  const normalized = [];
  const seen = new Set();
  const add = (rawUrl) => {
    const canonical = canonicalSastPageUrl(rawUrl);
    if (!canonical || seen.has(canonical)) return;
    if (isZapCallbackPageUrl(canonical)) return;
    try {
      const url = new URL(canonical);
      if (url.origin !== scope.origin) return;
      if (!url.pathname.startsWith(scope.prefix)) return;
      seen.add(canonical);
      normalized.push(canonical);
    } catch (_) { }
  };

  if (seed) add(seed);
  for (const rawUrl of Array.isArray(urls) ? urls : []) {
    if (normalized.length >= maxUrls) break;
    add(rawUrl);
  }
  return normalized.slice(0, maxUrls);
}

export function isSastJavaScriptResource(url, contentType = "") {
  const normalizedType = String(contentType || "").toLowerCase();
  if (/(?:^|[\/+.-])(?:javascript|ecmascript|jscript)(?:$|[;+\s-])/.test(normalizedType)) {
    return true;
  }
  try {
    const parsed = new URL(String(url || ""));
    return /\.(?:mjs|cjs|js)$/i.test(parsed.pathname || "");
  } catch (_) {
    return /\.(?:mjs|cjs|js)(?:[?#]|$)/i.test(String(url || ""));
  }
}

function isSastExecutableScriptType(type = "") {
  const normalized = String(type || "").trim().toLowerCase();
  if (!normalized) return true;
  return /^(?:text|application)\/(?:javascript|ecmascript|x-javascript)(?:\s*;|$)/i.test(normalized)
    || /^(?:module|importmap|speculationrules)$/i.test(normalized);
}

function looksLikeSastJavaScriptText(text = "") {
  const sample = String(text || "").slice(0, 4096);
  if (!sample.trim()) return false;
  return /\b(?:var|let|const|function|class|import|export)\b/.test(sample)
    || /\b(?:document|window|localStorage|sessionStorage|eval|setTimeout|addEventListener)\s*(?:\.|\(|=)/.test(sample);
}

function extractSastExternalScriptUrls(html, pageUrl, { maxScripts = 48 } = {}) {
  if (typeof html !== "string" || !html || !pageUrl) return [];
  let pageOrigin = "";
  try {
    pageOrigin = new URL(pageUrl).origin;
  } catch (_) {
    return [];
  }
  const scripts = [];
  const seen = new Set();
  const scriptRe = /<script\b([^>]*)>(?:[\s\S]*?)<\/script\s*>/gi;
  const attrRe = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  const parseAttrs = (rawAttrs = "") => {
    const attrs = Object.create(null);
    let match;
    while ((match = attrRe.exec(rawAttrs)) !== null) {
      const name = String(match[1] || "").trim().toLowerCase();
      if (!name) continue;
      attrs[name] = decodeSastHtmlEntities(match[2] ?? match[3] ?? match[4] ?? "");
    }
    return attrs;
  };

  let match;
  while ((match = scriptRe.exec(html)) !== null && scripts.length < maxScripts) {
    const attrs = parseAttrs(match[1] || "");
    if (!attrs.src || !isSastExecutableScriptType(attrs.type || "")) continue;
    try {
      const resolved = new URL(attrs.src, pageUrl);
      if (resolved.protocol !== "http:" && resolved.protocol !== "https:") continue;
      if (resolved.origin !== pageOrigin) continue;
      resolved.hash = "";
      const href = resolved.href;
      if (seen.has(href)) continue;
      seen.add(href);
      scripts.push(href);
    } catch (_) { }
  }
  return scripts;
}

async function fetchSastExternalScriptsForPage(html, pageUrl, { maxBytes = SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_BYTES } = {}) {
  const scriptUrls = extractSastExternalScriptUrls(html, pageUrl);
  const scripts = [];
  for (const scriptUrl of scriptUrls) {
    const resource = await fetchSastPageResource(scriptUrl, { maxBytes });
    if (!resource.text) continue;
    if (!isSastJavaScriptResource(scriptUrl, resource.contentType) && !looksLikeSastJavaScriptText(resource.text)) {
      continue;
    }
    scripts.push({
      src: scriptUrl,
      code: resource.text
    });
  }
  return scripts;
}

async function fetchSastPageResource(url, { maxBytes = SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_BYTES } = {}) {
  const canonical = canonicalSastPageUrl(url);
  if (!canonical || typeof fetch !== "function") return { url: canonical || "", text: "", contentType: "" };
  try {
    const response = await fetch(canonical, { credentials: "include" });
    if (!response?.ok) return { url: canonical, text: "", contentType: "" };
    const text = await response.text();
    const limit = Number.isFinite(Number(maxBytes)) ? Math.max(0, Number(maxBytes)) : 0;
    return {
      url: canonical,
      text: limit > 0 && text.length > limit ? text.slice(0, limit) : text,
      contentType: typeof response.headers?.get === "function" ? String(response.headers.get("content-type") || "") : ""
    };
  } catch (_) {
    return { url: canonical, text: "", contentType: "" };
  }
}

async function fetchSastPageText(url, { maxBytes = SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_BYTES } = {}) {
  const resource = await fetchSastPageResource(url, { maxBytes });
  return resource.text || "";
}

function isZapCallbackPageUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl) return false;
  try {
    const parsed = new URL(rawUrl);
    return /^\/zapCallBackUrl\/[^/?#]+/i.test(parsed.pathname);
  } catch (_) {
    return /\/zapCallBackUrl\//i.test(String(rawUrl || ""));
  }
}

function sameDocumentUrlForSast(left, right) {
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

async function refreshFinishedDastAnalysisIfNeeded() {
  const dast = worker?.ptk_app?.dast || worker?.ptk_app?.rattacker;
  if (!dast || typeof dast !== "object") return;
  if (dast?.engine?.isRunning === true) return;
  const scanResult = dast?.scanResult;
  if (!(scanResult?.finishedAt || scanResult?.finished)) return;
  try {
    await dast.analysisService?.hydratePersistedRelatedScans?.(scanResult);
    if (typeof dast._applyAnalysis === "function") {
      dast._applyAnalysis(scanResult, true);
    }
    await dast._flushPersistScanResult?.();
  } catch (_) { }
}

function getPortalApiKey() {
  return String(worker?.ptk_app?.settings?.profile?.api_key || "").trim();
}

function getSastPolicyState() {
  return portalPolicyRuntimeStore.getState("SAST");
}

function getSelectedSastPolicy() {
  return portalPolicyRuntimeStore.getSelectedPolicy("SAST");
}

function getSastRulepackSelection() {
  return portalPolicyRuntimeStore.getRulepackSelection("SAST");
}

function hasRenderableSastScanData(scanResult = {}) {
  if (!scanResult || typeof scanResult !== "object") return false;
  if (Array.isArray(scanResult.findings) && scanResult.findings.length > 0) return true;
  const items = scanResult.items;
  if (Array.isArray(items) && items.length > 0) return true;
  if (items && typeof items === "object" && Object.keys(items).length > 0) return true;
  const artifacts = scanResult?.codeArtifacts?.sast;
  if (artifacts && typeof artifacts === "object") {
    return Object.values(artifacts).some((value) => Array.isArray(value) && value.length > 0);
  }
  return false;
}

const IMPORT_TRANSFER_TTL_MS = 10 * 60 * 1000;
const IMPORT_TRANSFER_MAX_ENTRIES = 2;
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
      eventHandler: this.handleTransportEvent.bind(this),
      disableRemote: settings?.disableRemoteWorker === true || settings?.disableRemote === true
    });
    this.sessionCoordinator = new SastSessionCoordinator({
      transport: this.transport,
      browserApi: browser,
      schedulePersist: this._schedulePersistScanResult.bind(this),
      updateScanResult: this.updateScanResult.bind(this),
      scanCode: this.scanCode.bind(this),
      stopBackgroundScan: this.stopBackgroundScan.bind(this),
      getProgressSnapshot: this._buildSastProgressSnapshot.bind(this),
      getProgressStatus: this._getSastProgressStatus.bind(this),
      recordTiming: this._recordZapTiming.bind(this),
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
    this.importTransfers = new Map();
    this.resetScanResult();

    this.addMessageListeners();
    this.transport.ensureFirefoxWorker();
  }

  _cleanupImportTransfers(now = Date.now()) {
    for (const [id, entry] of this.importTransfers.entries()) {
      if (!entry || Number(entry.expiresAt || 0) <= now) {
        this.importTransfers.delete(id);
      }
    }
  }

  _enforceImportTransferLimit() {
    if (this.importTransfers.size <= IMPORT_TRANSFER_MAX_ENTRIES) return;
    const sorted = Array.from(this.importTransfers.entries()).sort((a, b) => {
      const left = Number(a?.[1]?.createdAt || 0);
      const right = Number(b?.[1]?.createdAt || 0);
      return left - right;
    });
    while (sorted.length && this.importTransfers.size > IMPORT_TRANSFER_MAX_ENTRIES) {
      const oldest = sorted.shift();
      if (oldest?.[0]) this.importTransfers.delete(oldest[0]);
    }
  }

  _normalizeImportChunk(chunk) {
    if (chunk instanceof Uint8Array) return chunk;
    if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk);
    if (ArrayBuffer.isView(chunk)) {
      return new Uint8Array(chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength));
    }
    if (Array.isArray(chunk)) return Uint8Array.from(chunk);
    if (chunk && typeof chunk === "object") return Uint8Array.from(Object.values(chunk));
    return new Uint8Array(0);
  }

  _createImportTransfer(fileMeta = {}) {
    const now = Date.now();
    const size = Number(fileMeta?.size || 0);
    const chunkCount = Number(fileMeta?.chunkCount || 0);
    const importId = `sast-import-${now}-${Math.random().toString(36).slice(2, 10)}`;
    const entry = {
      id: importId,
      name: String(fileMeta?.name || ""),
      type: String(fileMeta?.type || ""),
      size,
      chunkCount,
      createdAt: now,
      expiresAt: now + IMPORT_TRANSFER_TTL_MS,
      chunks: new Array(chunkCount).fill(null),
      receivedChunks: 0,
      receivedBytes: 0
    };
    this.importTransfers.set(importId, entry);
    this._enforceImportTransferLimit();
    return entry;
  }

  _getImportTransfer(importId) {
    this._cleanupImportTransfers();
    const key = String(importId || "");
    if (!key) return null;
    return this.importTransfers.get(key) || null;
  }

  _deleteImportTransfer(importId) {
    const key = String(importId || "");
    if (key) this.importTransfers.delete(key);
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

  _getCurrentZapTiming(opts = null) {
    const direct = opts?.zapTiming;
    if (direct && typeof direct === "object") {
      return direct;
    }
    const stored = this.scanResult?.settings?.zapTiming;
    return (stored && typeof stored === "object") ? stored : null;
  }

  _recordZapTiming(phase, extra = null, opts = null, onceKey = null) {
    const timing = this._getCurrentZapTiming(opts);
    const bridge = worker?.ptk_app?.automation?.zap;
    if (!timing || typeof bridge?.recordTiming !== "function") {
      return false;
    }
    return bridge.recordTiming({
      phase,
      zapid: timing?.zapid || null,
      zapSessionKey: timing?.zapSessionKey || null,
      automationSessionId: timing?.automationSessionId || null,
      tabId: Number.isInteger(timing?.tabId) ? timing.tabId : (this.scanResult?.tabId ?? null),
      targetUrl: timing?.targetUrl || this.scanResult?.targetUrl || null,
      onceKey,
      extra
    });
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
    this.sessionCoordinator.markStopped("stopped");
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

  _getSastProgressStatus() {
    const snapshot = this._buildSastProgressSnapshot();
    return snapshot?.lastStatus || this.progressState?.lastStatus || "Scanning";
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
    if (message?.channel === "ptk_offscreen2background_sast") {
      if (!ptk_utils.isTrustedExtensionPageSender(sender)) return;
      this.transport.handleExternalMessage(message);
      return;
    }

    if (message.channel == "ptk_popup2background_sast") {
      if (!ptk_utils.isTrustedExtensionPageSender(sender)) {
        return Promise.resolve({ result: false, error: "untrusted_extension_sender" });
      }
      if (this["msg_" + message.type]) {
        return this["msg_" + message.type](message);
      }
      return Promise.resolve({ result: false });
    }

    if (message.channel == "ptk_content_sast2background_sast") {
      if (!ptk_utils.isTrustedContentSender(sender)) return;
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
        this.onSpaUrlChanged(message.url, sender.tab.id, message.sastPayload || null).catch(err => {
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

  async onSpaUrlChanged(rawUrl, tabId, payload = null) {
    return this.sessionCoordinator.onSpaUrlChanged(rawUrl, tabId, this.scanResult, payload);
  }

  updateScanResult() {
    this.resultStore.updateScanResult();
  }

  _schedulePersistScanResult() {
    this.resultStore.schedulePersist();
  }

  _flushPersistScanResult() {
    return this.resultStore.flushPersist();
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

  async scanCode(scripts, html, file, options = {}) {
    this._recordZapTiming("sast.scan.start", {
      file: file || null,
      scriptsCount: Array.isArray(scripts) ? scripts.length : 0,
      generation: options?.generation || null,
      collectionId: options?.collectionId || null
    }, null, "sast.scan.start");
    const remoteResult = await this.transport.scanCodeRemote({
      scanId: this.scanResult.scanId,
      scripts,
      html,
      file,
      generation: options?.generation || null,
      collectionId: options?.collectionId || null,
      timeoutMs: 30000
    });
    if (remoteResult !== null) {
      return remoteResult;
    }

    if (!this.sastEngine) return [];
    const detail = await this.sastEngine.scanCodeDetailed(scripts, html, file, options);
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

  scanZapManagedPageSources(urls, opts = {}) {
    return this.sessionCoordinator.enqueueCollectionTask(() => this._scanZapManagedPageSourcesNow(urls, opts));
  }

  async _scanZapManagedPageSourcesNow(urls, opts = {}) {
    if (!this.isScanRunning) return [];
    if (!this.sastEngine && !this.scanResult?.scanId) return [];

    const maxPages = Number.isFinite(Number(opts?.sastPageSourceMaxPages ?? opts?.maxPageSourcePages))
      ? Math.max(1, Number(opts?.sastPageSourceMaxPages ?? opts?.maxPageSourcePages))
      : SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_PAGES;
    const startUrl = opts?.startUrl || opts?.targetUrl || opts?.zapTiming?.targetUrl || urls?.[0] || "";
    let pageUrls = normalizeSastPageSourceUrls(urls, startUrl, { maxUrls: maxPages });

    if (opts?.enableSastPageSourceLinkDiscovery === true && pageUrls[0]) {
      const html = await fetchSastPageText(pageUrls[0], {
        maxBytes: opts?.sastPageSourceMaxBytes || SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_BYTES
      });
      const discovered = extractSastPageLinksForScope(html, pageUrls[0], { maxLinks: maxPages });
      pageUrls = normalizeSastPageSourceUrls([...pageUrls, ...discovered], pageUrls[0], { maxUrls: maxPages });
    }

    if (!pageUrls.length) return [];

    this.scanningRequest = true;
    this.sessionCoordinator.activeCollectionCount += 1;
    const collection = this.sessionCoordinator.beginCollection();
    if (!this.sessionCoordinator.firstCollectionStarted) {
      this.sessionCoordinator.firstCollectionStarted = true;
    }

    try {
      this.sessionCoordinator.markPayloadReceived(collection.generation, {
        file: pageUrls[0],
        scriptsCount: pageUrls.length,
        htmlChars: 0
      });
      this._recordZapTiming("sast.page_source_seed.received", {
        source: opts?.source || "zap_history_seed",
        pageCount: pageUrls.length,
        firstUrl: pageUrls[0]
      }, null, "sast.page_source_seed.received");
      this.sessionCoordinator.markCollectionAnalysis(collection.generation);

      const findings = [];
      for (const pageUrl of pageUrls) {
        if (!this.isScanRunning) break;
        const resource = await fetchSastPageResource(pageUrl, {
          maxBytes: opts?.sastPageSourceMaxBytes || SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_BYTES
        });
        const isJavaScript = isSastJavaScriptResource(pageUrl, resource.contentType);
        const html = isJavaScript ? "" : (resource.text || "");
        const scripts = isJavaScript && resource.text
          ? [{ src: pageUrl, code: resource.text }]
          : await fetchSastExternalScriptsForPage(html, pageUrl, {
            maxBytes: opts?.sastPageSourceMaxBytes || SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_BYTES
          });
        const pageFindings = await this.scanCode(
          scripts,
          html,
          pageUrl,
          {
            generation: collection.generation,
            collectionId: collection.collectionId,
            source: opts?.source || "zap_history_seed"
          }
        );
        if (Array.isArray(pageFindings) && pageFindings.length) {
          findings.push(...pageFindings);
        }
      }

      this.sessionCoordinator.completeCollection(collection.generation, {
        file: pageUrls[0],
        scriptsCount: pageUrls.length,
        htmlChars: 0,
        findingsCount: findings.length
      });
      return findings;
    } catch (err) {
      this.sessionCoordinator.failCollection(collection.generation, err?.message || String(err));
      throw err;
    } finally {
      this.scanningRequest = false;
      this.sessionCoordinator.activeCollectionCount = Math.max(0, this.sessionCoordinator.activeCollectionCount - 1);
      if (this.sessionCoordinator.firstCollectionStarted && this.sessionCoordinator.activeCollectionCount === 0) {
        this.sessionCoordinator.firstCollectionSettled = true;
        if (this.sessionCoordinator.lastCollectionState !== "collection_failed" && this.sessionCoordinator.collectionState !== "waiting_for_page_activity") {
          this.sessionCoordinator.completeCollection(collection.generation);
        }
      }
    }
  }

  async msg_init(message) {
    await this.init();
    const scanResult = this._cloneScanResultForUi();
    const hasRenderableData = hasRenderableSastScanData(scanResult);
    return Promise.resolve({
      scanResult,
      isScanRunning: this.isScanRunning,
      viewState: this.isScanRunning ? "running" : (hasRenderableData ? "idle_with_data" : "idle_empty"),
      progress: this._buildSastProgressSnapshot(),
      activeTab: worker.ptk_app.proxy.activeTab,
      policyState: getSastPolicyState(),
      rulepackSelection: getSastRulepackSelection()
    });
  }

  async msg_get_default_modules(message) {
    return Promise.resolve({
      success: true,
      default_modules: await this.getDefaultModules(await loadRulepack("SAST")),
      policyState: getSastPolicyState(),
      rulepackSelection: getSastRulepackSelection()
    });
  }

  async msg_reset(message) {
    await this.reset();
    return Promise.resolve({
      scanResult: this._cloneScanResultForUi(),
      isScanRunning: this.isScanRunning,
      progress: this._buildSastProgressSnapshot(),
      activeTab: worker.ptk_app.proxy.activeTab,
      policyState: getSastPolicyState(),
      rulepackSelection: getSastRulepackSelection()
    });
  }

  async msg_get_policy_state(message) {
    return Promise.resolve({
      success: true,
      policyState: getSastPolicyState(),
      rulepackSelection: getSastRulepackSelection()
    });
  }

  async msg_load_policy_metadata(message) {
    const apiKey = getPortalApiKey();
    if (!apiKey) {
      return {
        success: false,
        error: "missing_api_key",
        policyState: getSastPolicyState()
      };
    }
    try {
      const policyState = await portalPolicyRuntimeStore.loadMetadata({ apiKey, engine: "SAST" });
      return {
        success: true,
        policyState
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || String(err),
        policyState: getSastPolicyState()
      };
    }
  }

  async msg_select_policy(message) {
    try {
      const apiKey = getPortalApiKey();
      const policyState = await portalPolicyRuntimeStore.selectPolicy({
        engine: "SAST",
        policyId: message?.policyId,
        policyName: message?.policyName || null,
        apiKey: apiKey || null
      });
      return {
        success: true,
        policyState,
        rulepackSelection: getSastRulepackSelection(),
        default_modules: await this.getDefaultModules(await loadRulepack("SAST"))
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || String(err),
        policyState: getSastPolicyState()
      };
    }
  }

  async msg_clear_policy(message) {
    const policyState = portalPolicyRuntimeStore.clearPolicy("SAST");
    return {
      success: true,
      policyState,
      rulepackSelection: getSastRulepackSelection(),
      default_modules: await this.getDefaultModules(await loadRulepack("SAST"))
    };
  }

  async msg_loadfile(message) {
    await this.reset();
    const parsed = await parseUploadedScanFile(message?.file);
    if (!parsed?.ok || !parsed?.json) {
      return Promise.reject(new Error("Wrong format or empty scan result"));
    }
    return this.msg_save({ json: JSON.stringify(parsed.json) });
  }

  async msg_loadfile_init(message) {
    const fileMeta = message?.fileMeta || {};
    const size = Number(fileMeta?.size || 0);
    const chunkCount = Number(fileMeta?.chunkCount || 0);
    if (!size || size <= 0 || !chunkCount || chunkCount <= 0) {
      throw new Error("Invalid file payload.");
    }
    this._cleanupImportTransfers();
    const entry = this._createImportTransfer(fileMeta);
    return {
      success: true,
      importId: entry.id,
      chunkCount: entry.chunkCount,
      size: entry.size
    };
  }

  async msg_loadfile_chunk(message) {
    const entry = this._getImportTransfer(message?.importId);
    if (!entry) {
      throw new Error("Import transfer expired.");
    }
    const index = Number(message?.index);
    if (!Number.isInteger(index) || index < 0 || index >= entry.chunkCount) {
      throw new Error("Invalid file payload.");
    }
    const normalized = this._normalizeImportChunk(message?.chunk);
    if (!normalized?.byteLength) {
      throw new Error("Invalid file payload.");
    }
    const previous = entry.chunks[index];
    if (previous?.byteLength) {
      entry.receivedBytes -= previous.byteLength;
    } else {
      entry.receivedChunks += 1;
    }
    entry.chunks[index] = normalized;
    entry.receivedBytes += normalized.byteLength;
    entry.expiresAt = Date.now() + IMPORT_TRANSFER_TTL_MS;
    return {
      success: true,
      importId: entry.id,
      index,
      receivedChunks: entry.receivedChunks,
      receivedBytes: entry.receivedBytes
    };
  }

  async msg_loadfile_finish(message) {
    const entry = this._getImportTransfer(message?.importId);
    if (!entry) {
      throw new Error("Import transfer expired.");
    }
    try {
      if (entry.receivedChunks !== entry.chunkCount || entry.chunks.some((chunk) => !chunk?.byteLength)) {
        throw new Error("Incomplete file payload.");
      }
      const totalBytes = entry.chunks.reduce((sum, chunk) => sum + Number(chunk?.byteLength || 0), 0);
      const combined = new Uint8Array(totalBytes);
      let offset = 0;
      for (const chunk of entry.chunks) {
        combined.set(chunk, offset);
        offset += chunk.byteLength;
      }
      const parsed = await parseUploadedScanFile({
        name: entry.name,
        type: entry.type,
        size: entry.size || combined.byteLength,
        bytes: Array.from(combined)
      });
      if (!parsed?.ok || !parsed?.json) {
        throw new Error("Wrong format or empty scan result");
      }
      return this.msg_save({ json: JSON.stringify(parsed.json) });
    } finally {
      this._deleteImportTransfer(entry.id);
    }
  }

  async msg_release_import(message) {
    this._deleteImportTransfer(message?.importId);
    return { success: true };
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
      const opts = await this._resolveSastRunOptions(Object.assign({}, (message?.opts && typeof message.opts === "object") ? message.opts : {}, {
        pages: Array.isArray(message.pages) ? message.pages : null,
        spaDelayMs: message.spaDelayMs || null,
      }));

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

  async msg_stop_bg_scan(message) {
    await this.stopBackgroundScan();
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
    if (!Array.isArray(this.scanResult?.findings) || this.scanResult.findings.length === 0) {
      const stored = await ptk_storage.getItem(this.storageKey);
      if (stored && Object.keys(stored).length) {
        this.scanResult = this._normalizeEnvelope(this._unwrapStoredScanResult(stored));
        this._seedRulesIndexFromFindings();
      }
    }
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
        includeSecrets: message?.includeSecrets === true,
        scanResult: this.scanResult
      });
      if (!payload) return null;
      const compressed = await compressScanPayload(payload);
      const descriptor = this.exportChunkStore.createEntry({
        bytes: compressed.body,
        fileName: message?.fileName || "PTK_SAST_scan.json",
        contentType: compressed.contentType,
        compression: compressed.compression,
        owner: message?.owner || null
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
    const chunk = this.exportChunkStore.getChunk(message?.exportId, message?.index, message?.owner || null);
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
    const released = this.exportChunkStore.release(message?.exportId, message?.owner || null);
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
    const zapTiming = (effectiveOpts?.zapTiming && typeof effectiveOpts.zapTiming === "object")
      ? Object.assign({}, effectiveOpts.zapTiming)
      : null;
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
    if (zapTiming) {
      this.scanResult.settings = Object.assign({}, this.scanResult.settings || {}, {
        zapTiming
      });
      if (!this.scanResult.targetUrl && zapTiming.targetUrl) {
        this.scanResult.targetUrl = zapTiming.targetUrl;
      }
      this._recordZapTiming("sast.collection.requested", {
        host,
        scanStrategyCode
      }, zapTiming, "sast.collection.requested");
    }
    this.sessionCoordinator.beginSession(tabId);
    this.notifier.handleStructuredEvent("scan:start", {
      scanId,
      scanStrategy: settings,
      totalFiles: 0,
      totalModules: 0
    });
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

    const zapTargetUrl = typeof opts?.zapTiming?.targetUrl === "string" && opts.zapTiming.targetUrl
      ? opts.zapTiming.targetUrl
      : null;
    const deferZapCallbackCollection = opts?.zapManaged === true
      && isZapCallbackPageUrl(baseUrl)
      && zapTargetUrl
      && !sameDocumentUrlForSast(baseUrl, zapTargetUrl);

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
    } else if (deferZapCallbackCollection) {
      this.sessionCoordinator.deferInitialCollection("zap_callback_wait_for_target_page", {
        currentUrl: baseUrl,
        targetUrl: zapTargetUrl
      });
      this._recordZapTiming("sast.collection.deferred_zap_callback", {
        currentUrl: baseUrl,
        targetUrl: zapTargetUrl
      }, zapTiming, "sast.collection.deferred_zap_callback");
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

    if (opts?.zapManaged === true && opts?.sastPageSourceCrawl !== false) {
      const seedUrls = Array.isArray(opts?.zapPageSourceUrls)
        ? opts.zapPageSourceUrls
        : (Array.isArray(opts?.zapHistorySeedUrls) ? opts.zapHistorySeedUrls : []);
      const startUrl = zapTargetUrl || baseUrl;
      const pageSourceUrls = normalizeSastPageSourceUrls(seedUrls, startUrl, {
        maxUrls: opts?.sastPageSourceMaxPages || SAST_PAGE_SOURCE_CRAWL_DEFAULT_MAX_PAGES
      });
      if (pageSourceUrls.length) {
        this.scanZapManagedPageSources(pageSourceUrls, {
          startUrl,
          zapTiming,
          source: "zap_history_seed",
          sastPageSourceMaxPages: opts?.sastPageSourceMaxPages,
          sastPageSourceMaxBytes: opts?.sastPageSourceMaxBytes,
          enableSastPageSourceLinkDiscovery: opts?.enableSastPageSourceLinkDiscovery === true
        }).catch((err) => {
          console.warn("[SAST] ZAP page-source seed collection failed", err?.message || String(err));
        });
      }
    }
  }

  async _resolveSastRunOptions(opts = {}) {
    const effectiveOpts = Object.assign({}, opts || {});
    if (effectiveOpts.rulepack && typeof effectiveOpts.rulepack === "object") {
      return effectiveOpts;
    }
    const explicitPolicyId = String(effectiveOpts.policyId || "").trim();
    const selectedPolicy = getSelectedSastPolicy();
    const selectedPolicyId = String(selectedPolicy?.id || "").trim();
    const shouldUsePortal = effectiveOpts.preferPortal === true || !!explicitPolicyId || !!selectedPolicyId;
    if (!shouldUsePortal) {
      delete effectiveOpts.preferPortal;
      delete effectiveOpts.policyId;
      delete effectiveOpts.policyName;
      return effectiveOpts;
    }
    const apiKey = getPortalApiKey();
    if (!apiKey) {
      const err = new Error("missing_api_key");
      err.code = "missing_api_key";
      throw err;
    }
    effectiveOpts.preferPortal = true;
    effectiveOpts.policyId = explicitPolicyId || selectedPolicyId;
    effectiveOpts.policyName = effectiveOpts.policyName || selectedPolicy?.name || null;
    effectiveOpts.apiKey = apiKey;
    return effectiveOpts;
  }

  async stopBackgroundScan(opts = {}) {
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
      this._recordZapTiming("sast.scan.finish", {
        findingsCount: Array.isArray(this.scanResult.findings) ? this.scanResult.findings.length : 0,
        filesCount: Array.isArray(this.scanResult.files) ? this.scanResult.files.length : 0,
        pagesCount: Array.isArray(this.scanResult.pages) ? this.scanResult.pages.length : 0
      }, null, "sast.scan.finish");
    }
    this.sessionCoordinator.reset();
    this._clearPendingAsyncState();
    this.sastEngine = null;
    this.scanBus = null;
    if (discardResults) {
      this.removeListeners();
      return this.scanResult;
    }
    const findingsCount = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    const filesCount = Array.isArray(this.scanResult?.files) ? this.scanResult.files.length : 0;
    const pagesCount = Array.isArray(this.scanResult?.pages) ? this.scanResult.pages.length : 0;
    const groupsCount = Array.isArray(this.scanResult?.groups) ? this.scanResult.groups.length : 0;
    const hasContent = findingsCount > 0 || filesCount > 0 || pagesCount > 0 || groupsCount > 0;
    if (hasContent) {
      this._rebuildGroupsFromFindings();
      this.updateScanResult();
      if (opts?.skipPostStopAnalysis !== true) {
        try {
          applyScanAnalysis(this.scanResult, { force: true });
        } catch (_) { }
      }
      await this._flushPersistScanResult();
    }
    this.removeListeners();
    if (opts?.skipPostStopAnalysis !== true) {
      await refreshFinishedDastAnalysisIfNeeded();
    }
    return this.scanResult;
  }

  async waitForCollectionIdle(opts = {}) {
    if (!this.sessionCoordinator || typeof this.sessionCoordinator.waitForCollectionIdle !== "function") {
      return true;
    }
    return this.sessionCoordinator.waitForCollectionIdle(opts);
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
