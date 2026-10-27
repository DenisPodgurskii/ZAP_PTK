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
import { sastCompletedCollectionKey, cloneSastReuseFindings, serializeSastReuseValue, sastAnalysisReceiptBytes } from "./sast/sast_completed_collection.js";
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

function safeSastCollectionReason(error) {
  try {
    const reason = error?.message;
    return ['capture_context_unavailable', 'capture_collection_unavailable', 'capture_payload_invalid',
      'sast_readiness_timeout', 'sast_source_owner_changed'].includes(reason) ? reason : 'collection_error';
  } catch (_) { return 'collection_error'; }
}

function safeSastCollectionStage(error) {
  try { return ['precheck', 'candidate_zero', 'candidate_many', 'dispatch', 'context_changed',
    'collector_exception', 'missing_value', 'oversize', 'manager_validation', 'candidate_duplicate_identity',
    'candidate_probe_failed', 'candidate_many_valid', 'candidate_zero_valid'].includes(error?.sastCollectionStage)
    ? error.sastCollectionStage : 'unspecified'; } catch (_) { return 'unspecified'; }
}

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
    if (Object.values(artifacts).some((value) => Array.isArray(value) && value.length > 0)) return true;
  }
  const started = Date.parse(scanResult.startedAt), finished = Date.parse(scanResult.finishedAt);
  return typeof scanResult.scanId === 'string' && !!scanResult.scanId.trim()
    && Number.isFinite(started) && Number.isFinite(finished) && finished >= started;
}

const IMPORT_TRANSFER_TTL_MS = 10 * 60 * 1000;
const IMPORT_TRANSFER_MAX_ENTRIES = 2;
export class ptk_sast {
  constructor(settings, { offscreenManager = null } = {}) {
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
      disableRemote: settings?.disableRemoteWorker === true || settings?.disableRemote === true,
      offscreenManager
    });
    this.sessionCoordinator = new SastSessionCoordinator({
      transport: this.transport,
      browserApi: browser,
      schedulePersist: this._schedulePersistScanResult.bind(this),
      updateScanResult: this.updateScanResult.bind(this),
      scanCode: this.scanCode.bind(this),
      collectPayload: this.collectCapturedPayload.bind(this),
      // Native originals and independently admitted content pushes need no
      // per-collection readiness or script-request message on any browser.
      collectPayloadOwnsReadiness: true,
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
    this.scopedTabCoordinator = null;
    this.browserCaptureManager = null;
    this.browserCaptureLeases = new Map();
    this.preparedBrowserCapture = null;
    this.resetScanResult();

    this.addMessageListeners();
    this.transport.ensureFirefoxWorker();
  }

  setScopedTabCoordinator(coordinator) {
    this.scopedTabCoordinator = coordinator || null;
    return this;
  }

  setBrowserCaptureManager(manager) {
    this.browserCaptureManager = manager || null;
    return this;
  }

  adoptBrowserCaptureLease({ tabId, lease, zapid, onClaim, onRelease }) {
    if (!Number.isInteger(tabId) || lease?.tabId !== tabId || !zapid || !lease.getSnapshot()?.prepared || this.preparedBrowserCapture) {
      throw new Error('sast_source_capture_adoption_invalid');
    }
    const pending = { tabId, lease, zapid, onClaim, onRelease };
    this.preparedBrowserCapture = pending;
    // Provider cleanup may revoke only its exact pending adoption. A claimed
    // lease belongs to SAST drainage and must not be cancelled by this handle.
    return () => {
      if (this.preparedBrowserCapture === pending) this.preparedBrowserCapture = null;
    };
  }

  isBrowserCaptureOwnerActive({ ownerId, tabId }) {
    const entry = this.browserCaptureLeases?.get(tabId);
    return !!(entry && entry.ownerId === ownerId && entry.scanId === this.scanResult?.scanId
      && this.isScanRunning && this.sessionCoordinator.isTrackedScanTab(tabId));
  }

  async _acquireBrowserCapture(tabId, scope, opts = {}) {
    const scanId = this.scanResult.scanId;
    const ownerId = `sast:${scanId}:${tabId}`;
    const entry = { ownerId, tabId, scanId, lease: null, initialDocuments: new Set(), gaps: [] };
    this.browserCaptureLeases.set(tabId, entry);
    try {
      const prepared = this.preparedBrowserCapture;
      if (prepared) {
        entry.lease = prepared.lease;
        entry.onRelease = prepared.onRelease;
        if (opts.zapManaged !== true || prepared.tabId !== tabId || prepared.zapid !== opts?.zapTiming?.zapid
          || !prepared.lease.getSnapshot()?.active || !prepared.lease.getSnapshot()?.prepared) throw new Error('sast_source_capture_adoption_invalid');
        await prepared.lease.updateScope(scope);
        if (prepared.onClaim?.({ scanId }) === false) throw new Error('sast_source_capture_adoption_invalid');
        entry.ownerId = prepared.lease.ownerId;
        this.preparedBrowserCapture = null;
      } else {
        if (!this.browserCaptureManager) throw new Error('sast_source_capture_unsupported');
        entry.lease = await this.browserCaptureManager.acquire({ ownerId, tabId, scope, capabilities: ['network', 'sources'] });
      }
      if (!this.isBrowserCaptureOwnerActive({ ownerId: entry.ownerId, tabId }) || !entry.lease.getSnapshot().ready) throw new Error('sast_source_owner_changed');
      entry.initialDocuments = new Set(entry.lease.getDocuments().map(document => this._nativeDocumentKey(document)));
      entry.unsubscribe = entry.lease.subscribe(event => {
        if (event.type === 'gap' && event.record?.affectsSources !== false && entry.gaps.length < 128) entry.gaps.push(event.record);
        if (event.type === 'gap' && ['source_batch_incomplete', 'source_batch_delivery_failed',
          'sast_dom_push_failed', 'sast_push_unavailable'].includes(event.record?.reason)) {
          entry.sourceBatchError = 'sast_captured_source_partial:1';
        }
        if (event.type === 'gap' && event.record?.affectsSources !== false && entry.pendingNativeAcquisition
          && ['request_failed', 'request_cancelled', 'body_read_unavailable'].includes(event.record.reason)) this._queueCapturedSourceCollection(entry);
        if ((event.type === 'body' || event.type === 'script') && event.record?.complete === true
          && (event.type === 'script' || ['Document', 'main_frame', 'sub_frame', 'Script', 'script'].includes(event.record.resourceType))) {
          const record = event.record;
          const current = entry.lease.getDocuments().some(document => document.epoch === record.epoch && document.tabId === record.tabId
            && (document.sessionId || '') === (record.sessionId || '') && document.frameId === record.frameId
            && document.documentId === (record.documentId ?? record.loaderId)
            && document.sessionGeneration === record.sessionGeneration && document.navigationGeneration === record.navigationGeneration);
          if (current) this._queueCapturedSourceCollection(entry);
        }
        // Never return analysis to capture delivery: collection drains capture.
      });
      const token = this.sessionCoordinator.sessionToken;
      entry.unsubscribeSources = entry.lease.subscribeSourceBatches?.(batch => {
        // Synchronous admission only. Returning the analysis promise to capture
        // drainage would deadlock collections which themselves drain capture.
        this.sessionCoordinator.enqueueSourceBatch(() => this._scanSourceBatch(entry, batch, token), () => batch.release())
          .catch(error => {
            if (this.sessionCoordinator.sessionToken === token && this.browserCaptureLeases.get(tabId) === entry
              && this.scanResult?.scanId === entry.scanId) this.sessionCoordinator.failCollection(this.sessionCoordinator.currentGeneration, error?.message || String(error));
          });
      });
      entry.pendingDomBatches = new Set();
      entry.unsubscribeDom = entry.lease.subscribeSastPayload(batch => {
        entry.pendingDomBatches.add(batch);
        this._queueSastDomBatch(entry, batch);
      });
      if (this._sastProducerRun === scanId) await entry.lease.setSastState({ active: true, scanId });
      return entry.lease;
    } catch (error) {
      if (this.browserCaptureLeases.get(tabId) === entry) this.browserCaptureLeases.delete(tabId);
      if (this.preparedBrowserCapture?.lease === entry.lease) this.preparedBrowserCapture = null;
      try { await entry.lease?.release('sast_start_failed'); }
      catch (_) { try { if (error && typeof error === 'object') error.sastCleanupErrorCode = 'sast_start_cleanup_failed'; } catch (_) {} }
      try { await entry.onRelease?.(); }
      catch (_) { try { if (error && typeof error === 'object') error.sastCleanupErrorCode = 'sast_start_cleanup_failed'; } catch (_) {} }
      throw error;
    }
  }

  _nativeDocumentKey(document) {
    return JSON.stringify([document.epoch, document.captureId, document.tabId, document.sessionId || '', document.frameId,
      document.documentId, document.sessionGeneration, document.navigationGeneration]);
  }

  _queueCapturedSourceCollection(entry) {
    if (this.sessionCoordinator.admissionFrozen || !this.isBrowserCaptureOwnerActive(entry)) return;
    for (const batch of entry.pendingDomBatches || []) this._queueSastDomBatch(entry, batch);
    entry.sourceCollectionDirty = true;
    if (entry.sourceCollectionPending) return;
    entry.sourceCollectionPending = true;
    const token = this.sessionCoordinator.sessionToken;
    this.sessionCoordinator.enqueueSourceBatch(async () => {
      try {
        do {
          entry.sourceCollectionDirty = false;
          if (this.sessionCoordinator.sessionToken !== token || !this.isBrowserCaptureOwnerActive(entry)) return;
          try { await this.sessionCoordinator._collectAndScanTabNow(entry.tabId, { delayMs: 0 }); }
          catch (error) {
            if (this.sessionCoordinator.sessionToken === token && this.isBrowserCaptureOwnerActive(entry)) {
              this.sessionCoordinator.failCollection(this.sessionCoordinator.currentGeneration, error?.message || String(error));
            }
          }
        } while (entry.sourceCollectionDirty);
      } finally {
        entry.sourceCollectionPending = false;
        // A completion may have arrived while its DOM task was still marked
        // queued. Reconsider the charged handle after that task has yielded,
        // without waiting on a task enqueued behind this same serial queue.
        for (const batch of entry.pendingDomBatches || []) this._queueSastDomBatch(entry, batch);
      }
    }, () => { entry.sourceCollectionPending = false; entry.sourceCollectionDirty = false; }).catch(() => {});
  }

  _queueSastDomBatch(entry, batch) {
    if (entry.queuedDomBatches?.has(batch)) return;
    if (!batch.active || this.sessionCoordinator.admissionFrozen || !this.isBrowserCaptureOwnerActive(entry)) {
      entry.pendingDomBatches.delete(batch); batch.release(); return;
    }
    entry.queuedDomBatches ||= new Set(); entry.queuedDomBatches.add(batch);
    const token = this.sessionCoordinator.sessionToken;
    const release = () => { entry.queuedDomBatches.delete(batch); entry.pendingDomBatches.delete(batch); batch.release(); };
    this.sessionCoordinator.enqueueCollectionTask(async () => {
      let pending = false;
      try {
        if (!batch.active || this.sessionCoordinator.sessionToken !== token || !this.isBrowserCaptureOwnerActive(entry)) return;
        const options = batch.browserDocument ? { browserBatch: batch } : { domBatch: batch };
        await this.sessionCoordinator._collectAndScanTabNow(entry.tabId, options);
        pending = options.pendingNativeAcquisition === true && batch.active && !this.sessionCoordinator.admissionFrozen;
      } finally {
        entry.queuedDomBatches.delete(batch);
        if (!pending) release();
      }
    }, { onDiscard: release }).catch(() => {});
  }

  _assertNativeDocument(entry, document) {
    if (!this.isBrowserCaptureOwnerActive({ ownerId: entry.ownerId, tabId: entry.tabId }) || !entry.lease.getSnapshot().active
      || !entry.lease.getDocuments().some(current => this._nativeDocumentKey(current) === this._nativeDocumentKey(document))) {
      const token = this.sessionCoordinator.sessionToken, run = this._completedAnalysisRun, engine = this.sastEngine;
      const superseded = () => this.sessionCoordinator.sessionToken === token && this._completedAnalysisRun === run && this.sastEngine === engine
        && this.browserCaptureLeases.get(entry.tabId) === entry && this.isBrowserCaptureOwnerActive(entry)
        && entry.lease.getSnapshot().active && entry.lease.hasRetiredSastSources?.(document) === true;
      if (superseded()) {
        const error = new Error('sast_native_collection_superseded');
        // Revalidate the private proof when the owning coordinator catches it;
        // revocation cannot turn into a successful or obsolete collection.
        Object.defineProperty(error, 'sastNativeCollectionSuperseded', { get: superseded });
        throw error;
      }
      throw new Error('sast_source_owner_changed');
    }
  }

  _assertAnalysisContext(context) {
    if (context?.cancelled) throw new Error('sast_scan_cancelled');
    if (!context?.sourceBatch) return this._assertNativeDocument(context?.entry, context?.identity);
    const { entry, sourceBatch, sessionToken } = context;
    if (this.browserCaptureLeases.get(entry.tabId) !== entry
      || !this.isBrowserCaptureOwnerActive({ ownerId: entry.ownerId, tabId: entry.tabId })
      || this.sessionCoordinator.sessionToken !== sessionToken || !entry.lease.getSnapshot().active
      || !sourceBatch.isActive()) throw new Error('sast_source_owner_changed');
  }

  async _scanSourceBatch(entry, batch, sessionToken) {
    const context = { entry, sourceBatch: batch, sessionToken };
    let borrowed;
    try {
      this._assertAnalysisContext(context);
      borrowed = batch.acquireAnalysisReceipt();
      const { identity, records, incompleteCount, reason, unresolvedSourceReferences = [] } = batch.read();
      if (identity.epoch !== entry.lease.epoch || identity.captureId !== entry.lease.captureId
        || identity.tabId !== entry.tabId || identity.ownerId !== entry.ownerId) throw new Error('sast_source_owner_changed');
      const complete = records.filter(record => !record.base64Encoded && typeof record.body === 'string');
      const original = complete.find(record => ['Document', 'main_frame', 'sub_frame'].includes(record.resourceType));
      const originalType = original?.response?.mimeType || (Array.isArray(original?.response?.headers)
        ? original.response.headers.find(header => header.name?.toLowerCase() === 'content-type')?.value : '');
      const originalIsScript = original && isSastJavaScriptResource(original.url, originalType);
      const scripts = complete.filter(record => record.scriptId || ['Script', 'script'].includes(record.resourceType))
        .map(record => ({ src: record.url, code: record.body, capturedSource: true, truncated: false }));
      const originalScripts = original && !originalIsScript
        ? sastEngine.prototype.extractScriptsFromPageSource(original.body, identity.url) : [];
      for (const script of scripts) {
        const kinds = new Set(originalScripts.filter(item => item.src === script.src).map(item => item.scriptKind));
        if (kinds.size) script.scriptKind = kinds.size === 1 ? [...kinds][0] : 'unknown';
      }
      scripts.push(...originalScripts.filter(script => !script.src));
      if (originalIsScript) scripts.push({ src: original.url, code: original.body, capturedSource: true, truncated: false });
      const present = new Set(scripts.filter(script => script.src).map(script => script.src));
      const missing = new Set([...originalScripts.filter(script => script.src && !present.has(script.src)).map(script => script.src),
        ...unresolvedSourceReferences]);
      const sourceGaps = incompleteCount + records.length - complete.length + missing.size + (!original ? 1 : 0);
      if (reason === 'final' && incompleteCount) {
        throw new Error(`sast_captured_source_partial:${sourceGaps}`);
      }
      const originalHtml = original && !originalIsScript ? original.body : [];
      const originalKey = await this._completedOriginalCollectionKey(scripts, originalHtml, identity.url, identity);
      this._assertAnalysisContext(context);
      const previous = borrowed.value;
      const reuse = originalKey && previous?.originalKey === originalKey
        && previous.run === this._completedAnalysisRun && previous.engine === this.sastEngine && previous.token === sessionToken;
      if (reason === 'final' && originalKey && previous?.failedOriginalKey === originalKey
        && previous.run === this._completedAnalysisRun && previous.engine === this.sastEngine && previous.token === sessionToken) {
        previous.failurePhase = 'final';
        this._retainCompletedAnalysis(entry, identity, previous, batch);
        throw new Error(previous.failedOriginalCode);
      }
      const collection = this.sessionCoordinator.beginCollection();
      this.sessionCoordinator.markPayloadReceived(collection.generation, { file: identity.url, scriptsCount: scripts.length,
        htmlChars: original && !originalIsScript ? original.body.length : 0 });
      this.sessionCoordinator.markCollectionAnalysis(collection.generation);
      // A sealed original batch may reuse only the original partition of the
      // successful pair, never its live-DOM findings. Drain/release stays owned
      // by this task even on a hit.
      const completion = {};
      const findings = reuse ? structuredClone(previous.findings.slice(0, previous.originalCount))
        : await this._scanCodeNow(scripts, originalHtml, identity.url, {
        tabId: entry.tabId, nativeDocument: identity, sourceBatch: batch, sessionToken,
        generation: collection.generation, collectionId: collection.collectionId, completion
      });
      this._assertAnalysisContext(context);
      if (!reuse && originalKey && completion.success) {
        const retained = cloneSastReuseFindings(findings);
        if (retained !== null) this._retainCompletedAnalysis(entry, identity, { originalKey, findings: retained,
          originalCount: retained.length, run: this._completedAnalysisRun, engine: this.sastEngine, token: sessionToken }, batch);
      }
      // Original response analysis never promises a retired live-DOM snapshot.
      // Incomplete/unsupported response bytes and missing owned externals stay
      // explicit partials after publishing the available original-source work.
      if (sourceGaps) {
        const message = `sast_captured_source_partial:${sourceGaps}`;
        throw new Error(message);
      }
      this.sessionCoordinator.completeCollection(collection.generation, { file: identity.url, scriptsCount: scripts.length,
        htmlChars: original && !originalIsScript ? original.body.length : 0, findingsCount: findings?.length || 0 });
      return findings;
    } catch (error) {
      if (this.browserCaptureLeases.get(entry.tabId) === entry && this.scanResult?.scanId === entry.scanId
        && this.sessionCoordinator.sessionToken === sessionToken
        && !['sast_source_owner_changed', 'capture_source_batch_unavailable', 'sast_native_collection_superseded', 'sast_scan_cancelled', 'sast_scan_stopping'].includes(error?.message)) {
        entry.sourceBatchError = /^sast_captured_source_partial:\d+$/.test(error?.message || '') ? error.message
          : ['sast_analysis_timeout', 'sast_worker_error', 'no_engine_for_scan'].includes(error?.message) ? error.message : 'sast_analysis_failed';
      }
      throw error;
    } finally { borrowed?.release(); batch.release(); }
  }

  async collectCapturedPayload(tabId, opts = {}) {
    const entry = this.browserCaptureLeases.get(tabId);
    if (!entry?.lease) throw new Error('sast_source_capture_required');
    if (opts.domBatch && !opts.domBatch.active) throw new Error('sast_source_owner_changed');
    const documents = entry.lease.getDocuments().filter(document => !opts.domBatch
      || opts.domBatch.active && this._nativeDocumentKey(document) === this._nativeDocumentKey(opts.domBatch.identity)).sort((a, b) =>
      Number(a.parentFrameId != null && a.parentFrameId !== -1) - Number(b.parentFrameId != null && b.parentFrameId !== -1));
    if (!documents.length) throw new Error('capture_collection_unavailable');
    const payloads = [];
    let pendingNativeAcquisition = false;
    // Local diagnostic only: no source/identity values enter payloads or results.
    const diagnostic = { generation: Number.isInteger(opts.generation) ? opts.generation : null,
      documents: documents.length, preloadedIdentityMatches: 0, collectorGaps: 0,
      missingOriginal: 0, missingExternal: 0, retainedGaps: 0, failedDocuments: 0, reasons: {}, collectorStages: {},
      failedRootDocuments: 0, failedChildDocuments: 0, retainedGapReasons: {} };
    const causes = new Map();
    Object.defineProperty(diagnostic, 'noteCause', { value: (identity, cause) => {
      const key = this._nativeDocumentKey(identity);
      if (!causes.has(key)) causes.set(key, new Set());
      causes.get(key).add(cause);
    } });
    let failures = 0, lastError;
    for (const identity of documents) {
      if (!this.sessionCoordinator.admissionFrozen && entry.lease.isSastDocumentPending?.(identity) === true) {
        pendingNativeAcquisition = true;
        entry.pendingNativeAcquisition = true;
        continue;
      }
      if (entry.initialDocuments.has(this._nativeDocumentKey(identity))) diagnostic.preloadedIdentityMatches++;
      try {
        const payload = await this._collectCapturedDocument(entry, identity, opts, diagnostic);
        if (payload.pendingNativeAcquisition === true) {
          pendingNativeAcquisition = entry.pendingNativeAcquisition = true;
        }
        payloads.push(payload);
      }
      catch (error) {
        if (!this.isBrowserCaptureOwnerActive({ ownerId: entry.ownerId, tabId }) || !entry.lease.getSnapshot().active) throw error;
        if (error?.sastNativeCollectionSuperseded === true) {
          pendingNativeAcquisition = true;
          continue;
        }
        failures++;
        diagnostic.failedDocuments++;
        diagnostic[identity.parentFrameId != null && identity.parentFrameId !== -1 ? 'failedChildDocuments' : 'failedRootDocuments']++;
        const reason = safeSastCollectionReason(error);
        diagnostic.noteCause(identity, `failed:${reason}`);
        diagnostic.reasons[reason] = (diagnostic.reasons[reason] || 0) + 1;
        lastError = error;
      }
    }
    const sourceGaps = payloads.reduce((sum, payload) => sum + Number(payload.sourceGaps || 0), failures);
    if (sourceGaps) {
      // Diagnostic deduplication is scoped to current native documents, not
      // collection generation; it cannot suppress a gap or successful analysis.
      const current = new Set(documents.map(identity => this._nativeDocumentKey(identity)));
      const warned = entry.sourceGapWarnings || (entry.sourceGapWarnings = new Map());
      for (const key of warned.keys()) if (!current.has(key)) warned.delete(key);
      const fresh = [...causes].some(([key, reasons]) => [...reasons].some(reason => !warned.get(key)?.has(reason)));
      let emitted = !fresh && causes.size > 0;
      if (fresh) try {
        console.warn('[SAST] Source collection gap summary ' + JSON.stringify({ ...diagnostic, sourceGaps }));
        for (const [key, reasons] of causes) {
          if (!warned.has(key)) warned.set(key, new Set());
          for (const reason of reasons) warned.get(key).add(reason);
        }
        emitted = true;
      } catch (_) { }
      if (emitted) this.sessionCoordinator.sourceGapSummaryGeneration = opts.generation;
    }
    entry.pendingNativeAcquisition = pendingNativeAcquisition;
    if (!payloads.length && failures) throw lastError;
    if (!payloads.length && pendingNativeAcquisition) return { scripts: [], payloads: [], pendingNativeAcquisition: true };
    if (!payloads.length) throw lastError || new Error('capture_collection_unavailable');
    payloads[0].sourceGaps += failures;
    return { ...payloads[0], payloads, pendingNativeAcquisition };
  }

  async _collectCapturedDocument(entry, identity, opts, diagnostic = null) {
    const tabId = entry.tabId;
    this._assertNativeDocument(entry, identity);
    const domBatch = opts.domBatch;
    if (domBatch && (!domBatch.active || this._nativeDocumentKey(domBatch.identity) !== this._nativeDocumentKey(identity))) throw new Error('sast_source_owner_changed');
    const payload = domBatch ? domBatch.payload : { file: identity.url, scripts: [], html: [] };
    const collectionGap = 0, collectorReason = null;
    this._assertNativeDocument(entry, identity);
    // Drain accepted native body completions before snapshotting the batch.
    await entry.lease.drain();
    this._assertNativeDocument(entry, identity);
    const resources = entry.lease.getResources({ documentId: identity.documentId, frameId: identity.frameId,
      sessionId: identity.sessionId, sessionGeneration: identity.sessionGeneration })
      .filter(record => (record.sessionId || '') === (identity.sessionId || ''));
    const complete = resources.filter(record => record.complete === true && !record.base64Encoded && typeof record.body === 'string');
    const original = complete.find(record => ['Document', 'main_frame', 'sub_frame'].includes(record.resourceType));
    const nativeScripts = complete.filter(record => ['Script', 'script'].includes(record.resourceType))
      .map(record => ({ src: record.url, code: record.body, capturedSource: true, truncated: false }));
    const originalType = original?.response?.mimeType || (Array.isArray(original?.response?.headers)
      ? original.response.headers.find(header => header.name?.toLowerCase() === 'content-type')?.value : '');
    const originalIsScript = original && isSastJavaScriptResource(original.url, originalType);
    if (originalIsScript) nativeScripts.push({ src: original.url, code: original.body, capturedSource: true, truncated: false });
    const originalScripts = original && !originalIsScript ? sastEngine.prototype.extractScriptsFromPageSource(original.body, identity.url) : [];
    for (const script of nativeScripts) {
      const kinds = new Set([...originalScripts, ...payload.scripts]
        .filter(item => item.src === script.src && ['classic', 'module'].includes(item.scriptKind)).map(item => item.scriptKind));
      if (kinds.size) script.scriptKind = kinds.size === 1 ? [...kinds][0] : 'unknown';
    }
    const scripts = [...nativeScripts, ...originalScripts.filter(script => !script.src), ...payload.scripts.filter(script => !script.src)];
    const present = new Set(nativeScripts.map(script => script.src));
    const outsideEpoch = entry.initialDocuments.has(this._nativeDocumentKey(identity));
    const missing = new Set([...originalScripts, ...payload.scripts].filter(script => script.src && !present.has(script.src)).map(script => script.src));
    const gaps = entry.gaps.filter(gap => !gap.documentId || gap.documentId === identity.documentId && gap.frameId === identity.frameId);
    // A current intermediate snapshot is not native acquisition closure. Keep
    // exact refs in the charged native obligation, while analysing available
    // originals now. Only captured bodies (not a later DOM omission) resolve it.
    const acquisition = !outsideEpoch && original
      ? entry.lease.reconcileSastSourceReferences(identity,
        !this.sessionCoordinator.admissionFrozen && !gaps.length ? [...missing] : [])
      : { unresolved: 0, refused: false, references: [] };
    if (acquisition.refused) throw new Error('sast_captured_source_partial:1');
    const unresolved = new Set([...missing, ...acquisition.references]);
    const provisional = !this.sessionCoordinator.admissionFrozen && !collectionGap && original && !gaps.length
      && acquisition.unresolved > 0;
    const sourceGaps = collectionGap + (!outsideEpoch && !original ? 1 : 0)
      + (!outsideEpoch && !provisional ? unresolved.size : 0) + gaps.length;
    if (diagnostic) {
      diagnostic.collectorGaps += collectionGap;
      diagnostic.missingOriginal += !outsideEpoch && !original ? 1 : 0;
      diagnostic.missingExternal += !outsideEpoch && !provisional ? unresolved.size : 0;
      if (!outsideEpoch && !original) diagnostic.noteCause(identity, 'missing_original');
      if (!outsideEpoch && !provisional && unresolved.size) diagnostic.noteCause(identity, 'missing_external');
      diagnostic.retainedGaps += gaps.length;
      for (const gap of gaps) {
        const reason = ['resource_budget', 'tab_budget', 'global_budget', 'source_batch_incomplete',
          'source_batch_delivery_failed', 'capture_detached', 'frame_detached', 'response_body_unavailable',
          'redirect_body_unavailable', 'child_domains_failed', 'identity_budget_exceeded', 'loading_failed'].includes(gap.reason)
          ? gap.reason : 'other_gap';
        diagnostic.retainedGapReasons[reason] = (diagnostic.retainedGapReasons[reason] || 0) + 1;
        diagnostic.noteCause(identity, `retained:${reason}`);
      }
      if (collectorReason) diagnostic.reasons[collectorReason] = (diagnostic.reasons[collectorReason] || 0) + 1;
    }

    return { file: payload.file, scripts, html: payload.html,
      // Captured Script bodies are independently executable original inputs
      // even when this epoch has no Document body. Empty HTML is not a claim
      // that response HTML was captured; missing-original accounting stays.
      originalHtml: originalIsScript ? [] : original?.body ?? (nativeScripts.length ? [] : undefined),
      originalScripts: [...nativeScripts, ...originalScripts.filter(script => !script.src)], nativeDocument: identity, sourceGaps,
      originalOnly: !domBatch, pendingNativeAcquisition: provisional };
  }

  async _releaseBrowserCapture(tabId, reason = 'sast_complete') {
    const entry = this.browserCaptureLeases?.get(tabId);
    if (!entry) return;
    entry.unsubscribe?.();
    entry.unsubscribeSources?.();
    entry.unsubscribeDom?.();
    try { await entry.lease?.release(reason); }
    finally {
      if (this.browserCaptureLeases.get(tabId) === entry) this.browserCaptureLeases.delete(tabId);
      await entry.onRelease?.();
    }
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

  async reset(opts = {}) {
    await this.stopBackgroundScan({ discardResults: true, preservePreparedSources: opts.preservePreparedSources === true,
      preserveStartToken: opts.preserveStartToken === true });
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
    this._releaseBrowserCapture(tabId, 'tab_removed').catch(() => console.warn('[SAST] Source-capture cleanup failed'));
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
      if (message.type === "get_collection_context") {
        return Promise.resolve(this.browserCaptureLeases.get(sender.tab.id)?.lease?.getSastState(sender)
          || { active: false, revision: 0, transport: 'runtime' });
      }
      if (message.type === 'dom_snapshot' || message.type === 'dom_candidate' || message.type === 'producer_error') {
        // Transport admission only: never return queued analysis as a runtime
        // response or require its acknowledgement to initiate another snapshot.
        return Promise.resolve(this.browserCaptureLeases.get(sender.tab.id)?.lease?.acceptSastPush(sender, message))
          .then(accepted => ({ accepted: accepted === true }));
      }
      if (message.type == "scripts_collected") {
        return;
      }
      if (message.type == "spa_url_changed" && sender?.tab?.id) {
        this.onSpaUrlChanged(message.url, sender.tab.id, null).catch(err => {
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
    // A worker response never establishes scan ownership, even when the current
    // result is empty. Startup always installs the owned envelope first.
    if (!scanId || scanId !== this.scanResult?.scanId) return;
    const context = this._nativeAnalysisContext;
    if (context) {
      // File/URL alone cannot bind a late worker result to a later analysis of
      // that same URL. These are existing private collection ownership fields.
      if ((type === "scan_result" || type === "findings:partial" || type === "error")
        && (message.generation !== context.generation || message.collectionId !== context.collectionId
          || message.file !== context.file || !Number.isFinite(context.generation) || !context.collectionId)) return;
      try { this._assertAnalysisContext(context); }
      catch (_) {
        if (type === "scan_result") this.resolvePendingScanResult(file, []);
        if (type === 'error') this.asyncSession.rejectScanResult(file,
          new Error(typeof error === 'string' ? error : 'sast_worker_error'));
        return;
      }
    } else if (type === "scan_result" || type === "findings:partial"
      || type === 'error' && (message.generation != null || message.collectionId || file)) {
      return;
    }
    if (this.notifier.isStructuredEvent(type)) {
      if (context && (type === 'collection:error' || type === 'scan:error')) context.failed = true;
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
      context.completed = Array.isArray(findings);
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
      if (context) context.failed = true;
      if (context) this.asyncSession.rejectScanResult(file, new Error(typeof error === 'string' ? error : 'sast_worker_error'));
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

  async _completedOriginalCollectionKey(scripts, html, file, identity) {
    const engine = this.sastEngine;
    const policy = engine ? serializeSastReuseValue([engine._scanStrategy, engine._catalog, engine._rulepack,
      engine._activeLibs, engine._FINDINGS_LIMIT], undefined, true) : null;
    if (engine && policy === null) return null;
    return sastCompletedCollectionKey([file, this._nativeDocumentKey(identity), identity.url, scripts, html, policy]);
  }

  _retainCompletedAnalysis(entry, identity, value, batch = null) {
    const bytes = sastAnalysisReceiptBytes(value);
    if (bytes === null) return false;
    return batch ? batch.setAnalysisReceipt(value, bytes)
      : entry.lease.setSastAnalysisReceipt(identity, value, bytes);
  }

  async scanCode(scripts, html, file, options = {}) {
    const entry = this.browserCaptureLeases?.get(options.tabId ?? this.activeTabId);
    if (!entry || !options.nativeDocument) throw new Error('sast_source_capture_required');
    if (options.browserBatch) {
      if (options.browserBatch.identity !== options.nativeDocument || !options.browserBatch.isActive()
        || this.browserCaptureLeases.get(entry.tabId) !== entry) throw new Error('sast_source_owner_changed');
      return this._scanCodeNow(scripts, html, file, { ...options, sourceBatch: options.browserBatch,
        sessionToken: this.sessionCoordinator.sessionToken });
    }
    const token = this.sessionCoordinator.sessionToken;
    const run = this._completedAnalysisRun;
    const engine = this.sastEngine;
    const assertOwner = () => {
      if (this.sessionCoordinator.sessionToken !== token || this._completedAnalysisRun !== run || this.sastEngine !== engine) {
        throw new Error('sast_source_owner_changed');
      }
      this._assertNativeDocument(entry, options.nativeDocument);
    };
    assertOwner();
    const borrowed = entry.lease.acquireSastAnalysisReceipt(options.nativeDocument);
    try {
    // A bounded receipt belongs to this exact native document. Policy is fixed at worker creation
    // for this run; a local engine's effective catalogue/rules are also keyed.
    // Collection generation is deliberately not a semantic input: the fresh
    // coordinator collection still completes normally when work is reused.
    const localPolicy = engine ? serializeSastReuseValue([engine._scanStrategy, engine._catalog, engine._rulepack,
      engine._activeLibs, engine._FINDINGS_LIMIT], undefined, true) : null;
    const hasOriginal = typeof options.originalHtml === 'string' || Array.isArray(options.originalHtml);
    const key = options.originalOnly !== true && run?.scanId === this.scanResult.scanId && (!engine || localPolicy !== null)
      && options.allowCompletedReuse !== false
      ? await sastCompletedCollectionKey([file, this._nativeDocumentKey(options.nativeDocument),
        options.nativeDocument.url, scripts, html, options.originalScripts || scripts,
        hasOriginal ? options.originalHtml : null,
        localPolicy]) : null;
    assertOwner();
    const previous = borrowed.value;
    if (key && previous?.key === key && previous.run === run && previous.engine === engine && previous.token === token) {
      if (options.sourceGaps) throw new Error(`sast_captured_source_partial:${options.sourceGaps}`);
      return structuredClone(previous.findings);
    }
    const originalKey = options.allowCompletedReuse !== false && hasOriginal
      ? await this._completedOriginalCollectionKey(options.originalScripts || scripts, options.originalHtml, options.nativeDocument.url, options.nativeDocument) : null;
    assertOwner();
    const originalCompletion = {}, liveCompletion = {};
    const reuseOriginal = originalKey && previous?.originalKey === originalKey
      && previous.run === run && previous.engine === engine && previous.token === token;
    // A notification about the same original response does not invalidate the
    // independently successful live partition (or its unresolved failure).
    if (options.originalOnly === true && reuseOriginal) {
      if (options.sourceGaps) throw new Error(`sast_captured_source_partial:${options.sourceGaps}`);
      return structuredClone(previous.findings.slice(0, previous.originalCount));
    }
    if (reuseOriginal) originalCompletion.success = true;
    // Original response HTML and current/transient DOM keep independent evidence
    // inputs; every same-document JS source shares the live taint batch.
    let originalFindings = [];
    if (hasOriginal) {
      if (reuseOriginal) originalFindings = structuredClone(previous.findings.slice(0, previous.originalCount));
      else try {
        originalFindings = await this._scanCodeNow(options.originalScripts || scripts, options.originalHtml, options.nativeDocument.url, { ...options,
          collectionId: `${options.collectionId}:original`, completion: originalCompletion });
      } catch (error) {
        let stillOwned = false;
        try { assertOwner(); stillOwned = true; } catch (_) { }
        if (stillOwned && originalKey && !['sast_source_owner_changed', 'sast_scan_cancelled', 'sast_scan_stopping'].includes(error?.message)) {
          const code = ['sast_analysis_timeout', 'sast_worker_error', 'no_engine_for_scan'].includes(error?.message)
            ? error.message : 'sast_analysis_failed';
          this._retainCompletedAnalysis(entry, options.nativeDocument, { failedOriginalKey: originalKey, failedOriginalCode: code, failurePhase: 'original', run, engine, token });
        }
        throw error;
      }
    }
    assertOwner();
    // Keep the independently completed original partition even if the live
    // snapshot subsequently fails or changes. This bounded native-document
    // receipt is not a success receipt for the whole collection.
    if (originalKey && originalCompletion.success) {
      const retainedOriginal = cloneSastReuseFindings(originalFindings);
      if (retainedOriginal !== null) this._retainCompletedAnalysis(entry, options.nativeDocument, { originalKey, findings: retainedOriginal,
        originalCount: retainedOriginal.length, run, engine, token });
    }
    if (options.originalOnly === true) {
      if (options.sourceGaps) throw new Error(`sast_captured_source_partial:${options.sourceGaps}`);
      return originalFindings;
    }
    let liveFindings;
    try {
      liveFindings = await this._scanCodeNow(scripts, html, file, { ...options,
        collectionId: `${options.collectionId}:live`, completion: liveCompletion });
    } catch (error) {
      let stillOwned = false;
      try { assertOwner(); stillOwned = true; } catch (_) { }
      if (stillOwned && !['sast_source_owner_changed', 'sast_scan_cancelled', 'sast_scan_stopping'].includes(error?.message)) {
        const current = entry.lease.acquireSastAnalysisReceipt(options.nativeDocument);
        try { this._retainCompletedAnalysis(entry, options.nativeDocument,
          { ...(current.value?.originalKey === originalKey ? current.value : { run, engine, token }),
            failedLiveCode: ['sast_analysis_timeout', 'sast_worker_error', 'no_engine_for_scan'].includes(error?.message) ? error.message : 'sast_analysis_failed' }); }
        finally { current.release(); }
      }
      throw error;
    }
    assertOwner();
    const findings = [...(originalFindings || []), ...(liveFindings || [])];
    if (key && liveCompletion.success && (!hasOriginal || originalCompletion.success)) {
      const retained = cloneSastReuseFindings(findings);
      if (retained !== null) this._retainCompletedAnalysis(entry, options.nativeDocument, { key, findings: retained, run, engine, token,
        originalKey, originalCount: originalFindings.length });
    }
    // This receipt proves an exact engine pass, never complete acquisition.
    // A gap still fails the owning collection even when analysis is reused.
    if (options.sourceGaps) throw new Error(`sast_captured_source_partial:${options.sourceGaps}`);
    return findings;
    } finally { borrowed.release(); }
  }

  async _scanCodeNow(scripts, html, file, options = {}) {
    const entry = this.browserCaptureLeases.get(options.tabId ?? this.activeTabId);
    const context = { entry, identity: options.nativeDocument, sourceBatch: options.sourceBatch, sessionToken: options.sessionToken,
      generation: options.generation, collectionId: options.collectionId, file };
    this._assertAnalysisContext(context);
    this._nativeAnalysisContext = context;
    try {
      this._recordZapTiming("sast.scan.start", {
        file: file || null, scriptsCount: Array.isArray(scripts) ? scripts.length : 0,
        generation: options?.generation || null, collectionId: options?.collectionId || null
      }, null, "sast.scan.start");
      const remoteResult = await this.transport.scanCodeRemote({
        scanId: this.scanResult.scanId, scripts, html, file,
        generation: options?.generation || null, collectionId: options?.collectionId || null,
        timeoutMs: 30000
      });
      this._assertAnalysisContext(context);
      if (remoteResult !== null) return remoteResult;
      if (!this.sastEngine) return [];
      const detail = await this.sastEngine.scanCodeDetailed(scripts, html, file, options);
      // Analysis can await assets/rules; ownership must still hold at publication.
      this._assertAnalysisContext(context);
      const findings = Array.isArray(detail?.findings) ? detail.findings : [];
      this.notifier.handleScanResultFromWorker(file, findings, detail?.artifacts || null, {
        canonicalizeFileId: this.canonicalFileId.bind(this)
      });
      context.completed = true;
      return findings;
    } finally {
      if (options.completion) options.completion.success = context.completed === true && !context.failed;
      if (this._nativeAnalysisContext === context) this._nativeAnalysisContext = null;
    }
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
    const tabId = opts.tabId ?? this.activeTabId;
    const entry = this.browserCaptureLeases.get(tabId);
    if (!entry?.lease) throw new Error('sast_source_capture_required');
    // History URLs select only already-owned current native documents. They
    // cannot resolve a response body or authorize a URL-only capture lookup.
    // Unobserved historical URLs are outside this network epoch, not failed
    // capture requests. Only native observed gaps can make this batch partial.
    return this.sessionCoordinator._collectAndScanTabNow(tabId, opts);
  }

  async msg_init(message) {
    await this.init();
    if (!this.isScanRunning && this.scanResult?.finishedAt) applyScanAnalysis(this.scanResult, { force: true });
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
    await this.stopBackgroundScan({ manualCancel: true });
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
    if (this.isScanRunning || this._sastStartToken) return false;
    const token = { cancelled: false };
    this._sastStartToken = token;
    try { return await this._runBackgroundScanNow(tabId, host, scanStrategyRaw, opts, token); }
    finally { if (this._sastStartToken === token) this._sastStartToken = null; }
  }

  async _runBackgroundScanNow(tabId, host, scanStrategyRaw, opts, startToken) {
    const assertStart = () => { if (startToken.cancelled) throw new Error('sast_scan_cancelled'); };

    const zapManualOpts = this._getZapManualEngineOptions();
    const effectiveOpts = Object.assign({}, zapManualOpts || {}, opts || {});
    const zapTiming = (effectiveOpts?.zapTiming && typeof effectiveOpts.zapTiming === "object")
      ? Object.assign({}, effectiveOpts.zapTiming)
      : null;
    const prepared = await this._prepareSastOptions(scanStrategyRaw, effectiveOpts);
    assertStart();
    const scanStrategy = prepared.scanStrategy;
    opts = prepared.opts;

    const preservePreparedSources = opts?.zapManaged === true && this.preparedBrowserCapture?.tabId === tabId
      && this.preparedBrowserCapture.zapid === opts?.zapTiming?.zapid;
    await this.reset({ preservePreparedSources, preserveStartToken: true });
    assertStart();
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
    let baseUrl = host || null;
    try {
      const tab = await browser.tabs.get(tabId);
      baseUrl = tab?.url || baseUrl;
    } catch { }
    const zapTargetUrl = typeof opts?.zapTiming?.targetUrl === "string" && opts.zapTiming.targetUrl
      ? opts.zapTiming.targetUrl : null;
    const scopedTargetUrl = zapTargetUrl || baseUrl;
    const captureScope = { targetUrl: scopedTargetUrl, mode: opts?.zapManaged === true && zapTargetUrl ? 'path' : 'origin' };
    try {
      await this._acquireBrowserCapture(tabId, captureScope, opts);
      assertStart();
    } catch (error) {
      try { await this._releaseBrowserCapture(tabId, 'sast_start_failed'); }
      catch (_) { try { if (error && typeof error === 'object') error.sastCleanupErrorCode = 'sast_start_cleanup_failed'; } catch (_) {} }
      if (this.scanResult?.scanId === scanId) {
        this.sessionCoordinator.failCollection(0, error.message);
        this.isScanRunning = false;
      }
      throw error;
    }
    try {
    this.notifier.handleStructuredEvent("scan:start", {
      scanId,
      scanStrategy: settings,
      totalFiles: 0,
      totalModules: 0
    });
    this._schedulePersistScanResult();
    opts = Object.assign({}, opts, { scanId: this.scanResult.scanId });
    opts.allowFetchPageSourceScripts = false;
    opts.allowFetchExternalScripts = false;
    this._completedAnalysisRun = Object.freeze({ scanId });

    const startedRemote = await this.transport.startRemoteScan({
      scanId: this.scanResult.scanId,
      scanStrategyCode,
      opts
    });
    assertStart();

    if (!startedRemote) {
      this.sastEngine = new sastEngine(scanStrategyCode, opts);
      const sourceEngine = this.sastEngine;
      const subscribe = (name, listener) => sourceEngine.events.subscribe(name, data => {
        const context = this._nativeAnalysisContext;
        if (!context || this.scanResult?.scanId !== scanId || !this.isScanRunning) return;
        if (name === 'findings:partial' && (data?.generation !== context.generation || data?.collectionId !== context.collectionId
          || data?.file !== context.file || !Number.isFinite(context.generation) || !context.collectionId)) return;
        try { this._assertAnalysisContext(context); }
        catch (_) { return; }
        listener(data);
      });
      if (this.scanBus) this.scanBus = null;
      this.scanBus = new SastScanBus(this, { events: { subscribe } });
      this.scanBus.attach();
      subscribe('progress', (data) => {
        this.notifier.handleProgress(data);
      });
    }
    
    this.addListeners();

    await this.scopedTabCoordinator?.registerSession?.('SAST', {
      primaryTabId: tabId,
      targetUrl: scopedTargetUrl,
      scopeMode: opts?.zapManaged === true && zapTargetUrl ? 'path' : 'origin',
      onEnroll: async (meta) => {
        if (this.sessionCoordinator.admissionFrozen) throw new Error('sast_scan_stopping');
        this.sessionCoordinator.registerRelatedScanTab(meta.tabId, meta);
        try { await this._acquireBrowserCapture(meta.tabId, captureScope); }
        catch (error) { this.sessionCoordinator.releaseRelatedScanTab(meta.tabId); throw error; }
      },
      onRelease: (meta) => {
        this.sessionCoordinator.releaseRelatedScanTab(meta.tabId);
        this._releaseBrowserCapture(meta.tabId, 'scope_released').catch(() => {});
      }
    });
    assertStart();
    this._sastProducerRun = scanId;
    for (const entry of this.browserCaptureLeases.values()) {
      await entry.lease.setSastState({ active: true, scanId });
      assertStart();
    }
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
          if (err?.sastPartialSummaryEmitted !== true) console.error("[SAST] Initial script collection failed", err);
        });
    }

    // ZAP seed URLs still drive its discovered-page traversal. Source analysis now
    // follows captured, owned document responses through scanCode, never target fetches.
    } catch (error) {
      try { await this.stopBackgroundScan({ discardResults: true, skipPostStopAnalysis: true }); }
      catch (_) { try { if (error && typeof error === 'object') error.sastCleanupErrorCode = 'sast_start_cleanup_failed'; } catch (_) {} }
      throw error;
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
    if (opts.preserveStartToken !== true && this._sastStartToken) this._sastStartToken.cancelled = true;
    if (this._sastStopPromise) return this._sastStopPromise;
    const stop = this._stopBackgroundScanNow(opts);
    this._sastStopPromise = stop;
    try { return await stop; }
    finally { if (this._sastStopPromise === stop) this._sastStopPromise = null; }
  }

  async _stopBackgroundScanNow(opts = {}) {
    this.sessionCoordinator.freezeAdmission();
    this._sastProducerRun = null;
    const deactivations = [];
    for (const entry of this.browserCaptureLeases?.values() || []) {
      const deactivation = Promise.resolve(entry.lease?.setSastState({ active: false }));
      deactivation.catch(() => {});
      deactivations.push(deactivation);
    }
    const discardResults = !!opts?.discardResults;
    const scanId = this.scanResult?.scanId || null;
    const captureEntries = [...this.browserCaptureLeases?.values() || []];
    const hadOwnedSession = this.isScanRunning || !!this._sastStartToken || captureEntries.length > 0;
    let captureCleanupError = null;
    let cancellationError = null;
    try {
      if (opts.manualCancel === true) {
        const unfinished = this.sessionCoordinator.cancelCollections();
        this._completedAnalysisRun = null;
        if (this._nativeAnalysisContext) {
          this._nativeAnalysisContext.failed = true;
          this._nativeAnalysisContext.cancelled = true;
        }
        if (scanId) this._markScanIdIgnored(scanId);
        this.asyncSession.cancelPendingScanResults(new Error('sast_scan_cancelled'));
        const incomplete = captureEntries.some(entry => {
          const status = entry.lease?.getSastAcquisitionStatus?.();
          return entry.pendingDomBatches?.size || status?.unresolved || status?.unresolvedSources
            || entry.lease?.getDocuments().some(identity => entry.lease.hasPendingSastSources?.(identity));
        });
        if (unfinished || incomplete) {
          this.sessionCoordinator.analysisState = 'error';
          this.sessionCoordinator.collectionState = 'collection_failed';
          this.sessionCoordinator.firstCollectionError ||= 'sast_scan_cancelled';
        }
        if (scanId && hadOwnedSession) await this.transport.cancelRemoteScan(scanId);
      } else {
      // Accepted collections still need the live lease to collect their exact
      // native DOM batch. Freeze native admission only after this queue settles.
      await this.sessionCoordinator.drainCollections();
      for (const entry of this.browserCaptureLeases?.values() || []) await entry.lease?.drain();
      // Current-source completions already schedule collection while running.
      // Stop drains those accepted tasks; it must not request a fresh DOM batch.
      for (const entry of this.browserCaptureLeases?.values() || []) entry.lease?.freeze();
      for (const entry of this.browserCaptureLeases?.values() || []) await entry.lease?.drain();
      await this.sessionCoordinator.drainCollections();
      const pendingDocuments = captureEntries.reduce((count, entry) => count + (entry.lease?.getDocuments()
        .filter(identity => (entry.lease.hasPendingSastSources?.(identity) ?? entry.lease.isSastDocumentPending?.(identity)) === true).length || 0), 0);
      const missingDom = captureEntries.reduce((count, entry) => {
        const status = entry.lease?.getSastAcquisitionStatus?.();
        return count + (status?.unresolved || 0) + (status?.unresolvedSources || 0);
      }, 0);
      if (pendingDocuments || missingDom) {
        this.sessionCoordinator.failCollection(this.sessionCoordinator.currentGeneration, `sast_captured_source_partial:${pendingDocuments + missingDom}`);
      }
      const failedFinal = captureEntries.find(entry => entry.sourceBatchError || entry.lease?.getSastAnalysisFailure?.());
      if (failedFinal) this.sessionCoordinator.failCollection(this.sessionCoordinator.currentGeneration,
        failedFinal.sourceBatchError || failedFinal.lease?.getSastAnalysisFailure());
      if (scanId) await this.transport.stopRemoteScan(scanId);
      if (scanId) this._markScanIdIgnored(scanId);
      }
    } catch (error) {
      if (opts.manualCancel !== true) throw error;
      cancellationError = error;
    } finally {
      const released = cancellationError ? [] : await Promise.allSettled([...(this.browserCaptureLeases?.keys() || [])].map(tabId => this._releaseBrowserCapture(tabId)));
      // Release may retry deactivation successfully after the first operation
      // failed. Join the original operation too; its result remains authoritative.
      const deactivated = await Promise.allSettled(deactivations);
      if (this.preparedBrowserCapture && opts.preservePreparedSources !== true) {
        const prepared = this.preparedBrowserCapture;
        this.preparedBrowserCapture = null;
        try { await prepared.lease.release('sast_prepared_cancelled'); }
        finally { await prepared.onRelease?.(); }
      }
      this.scopedTabCoordinator?.unregisterSession?.('SAST');
      // Revocation alone is not proof of physical cleanup. In particular a
      // native binding ownership/removal failure cannot become a clean Stop.
      const failedRelease = [...deactivated, ...released].find(result => result.status === 'rejected');
      if (failedRelease) captureCleanupError = failedRelease.reason;
    }

    if (this.scanResult && !cancellationError) {
      const finished = new Date().toISOString();
      this.scanResult.finishedAt = finished;
      this._recordZapTiming("sast.scan.finish", {
        findingsCount: Array.isArray(this.scanResult.findings) ? this.scanResult.findings.length : 0,
        filesCount: Array.isArray(this.scanResult.files) ? this.scanResult.files.length : 0,
        pagesCount: Array.isArray(this.scanResult.pages) ? this.scanResult.pages.length : 0
      }, null, "sast.scan.finish");
    }
    // Dashboard owns this transient result sink. Capture terminal native truth
    // after final drainage, before reset clears the coordinator; never export it.
    if (opts.dashboardStopOutcome && typeof opts.dashboardStopOutcome === 'object') {
      const native = this.sessionCoordinator.getAutomationState();
      const failed = native.analysisState === 'error' || native.collectionState === 'collection_failed';
      // Analysis failure is incomplete coverage, not failure to shut down.
      // The original collection error remains logged by its owning operation.
      opts.dashboardStopOutcome.status = captureCleanupError || cancellationError ? 'failed' : failed ? 'partial' : 'stopped';
    }
    if (!cancellationError) {
      this.sessionCoordinator.reset();
      this._clearPendingAsyncState();
      this.sastEngine = null;
      this.scanBus = null;
    }
    if (discardResults) {
      this.removeListeners();
      if (cancellationError) throw cancellationError;
      if (captureCleanupError) throw captureCleanupError;
      return this.scanResult;
    }
    const findingsCount = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings.length : 0;
    const filesCount = Array.isArray(this.scanResult?.files) ? this.scanResult.files.length : 0;
    const pagesCount = Array.isArray(this.scanResult?.pages) ? this.scanResult.pages.length : 0;
    const groupsCount = Array.isArray(this.scanResult?.groups) ? this.scanResult.groups.length : 0;
    const hasContent = findingsCount > 0 || filesCount > 0 || pagesCount > 0 || groupsCount > 0;
    if (hasContent || scanId) {
      this._rebuildGroupsFromFindings();
      this.updateScanResult();
      await this._flushPersistScanResult();
    }
    this.removeListeners();
    if (cancellationError) throw cancellationError;
    if (captureCleanupError) throw captureCleanupError;
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
