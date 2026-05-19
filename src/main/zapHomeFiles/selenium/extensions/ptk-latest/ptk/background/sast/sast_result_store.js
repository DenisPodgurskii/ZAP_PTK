/* Author: Denis Podgurskii */
import { ptk_storage } from "../utils.js";
import {
  createScanResultEnvelope,
  addFindingToGroup,
} from "../common/scanResults.js";
import {
  resolveEffectiveSeverity,
} from "../common/severity_utils.js";
import { resolveFindingTaxonomy } from "../common/resolveFindingTaxonomy.js";
import normalizeFinding from "../common/findingNormalizer.js";
import { ensureSastCodeArtifacts } from "./sast_artifacts.js";

function toNonEmptyString(value) {
  if (value === undefined || value === null) return null;
  const normalized = String(value).trim();
  return normalized.length ? normalized : null;
}

function uniqueStringList(values = []) {
  const seen = new Set();
  const result = [];
  const addValue = (value) => {
    if (Array.isArray(value)) {
      value.forEach(addValue);
      return;
    }
    const normalized = toNonEmptyString(value);
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    result.push(normalized);
  };
  addValue(values);
  return result;
}

function collectObservedPageUrls(...sources) {
  const collected = [];
  sources.forEach((source) => {
    if (!source || typeof source !== "object") return;
    collected.push(
      source.pageUrls,
      source.runtimeUrls,
      source.urls,
      source.observedUrls,
      source.pageUrl,
      source.runtimeUrl,
      source.url,
      source.route
    );
  });
  return uniqueStringList(collected);
}

function stableHashHex(value) {
  const text = String(value || "");
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return `${(h2 >>> 0).toString(16).padStart(8, "0")}${(h1 >>> 0).toString(16).padStart(8, "0")}`;
}

function sanitizeIdPart(value, fallback = "part") {
  const normalized = toNonEmptyString(value) || fallback;
  return normalized.replace(/[^a-zA-Z0-9_.:-]+/g, "_").slice(0, 80) || fallback;
}

export class SastResultStore {
  constructor({
    storageKey = "ptk_sast",
    persistDebounceMs = 1000,
    canonicalFileId = null,
  } = {}) {
    this.storageKey = storageKey;
    this.persistDebounceMs = persistDebounceMs;
    this._canonicalFileId =
      typeof canonicalFileId === "function" ? canonicalFileId : ((raw) => String(raw || ""));
    this.persistTimer = null;
    this.rulesIndex = new Set();
    this.scanResult = this.getScanResultSchema();
  }

  setCanonicalFileId(fn) {
    if (typeof fn === "function") {
      this._canonicalFileId = fn;
    }
  }

  cloneForUi() {
    const clone = JSON.parse(JSON.stringify(this.scanResult || {}));
    if (clone && typeof clone === "object") {
      clone.__normalized = true;
    }
    return clone;
  }

  reset() {
    this.scanResult = this.getScanResultSchema();
    this.rulesIndex = new Set();
    if (this.persistTimer) {
      clearTimeout(this.persistTimer);
      this.persistTimer = null;
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
    return this.normalizeEnvelope(envelope);
  }

  updateScanResult() {
    if (!Array.isArray(this.scanResult.findings)) {
      this.scanResult.findings = [];
    }
    ensureSastCodeArtifacts(this.scanResult);
    this.ensureStats();
    this.scanResult.stats.filesCount = Array.isArray(this.scanResult.files)
      ? this.scanResult.files.length
      : 0;
    this.scanResult.stats.rulesCount = this.rulesIndex ? this.rulesIndex.size : 0;
    this.schedulePersist();
  }

  schedulePersist() {
    if (this.persistTimer) return;
    this.persistTimer = setTimeout(() => {
      this.persistTimer = null;
      ptk_storage.setItem(this.storageKey, this.scanResult);
    }, this.persistDebounceMs);
  }

  flushPersist() {
    if (this.persistTimer) {
      clearTimeout(this.persistTimer);
      this.persistTimer = null;
    }
    return ptk_storage.setItem(this.storageKey, this.scanResult);
  }

  ensureStats() {
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

  applySeverityDelta(severity, delta) {
    this.ensureStats();
    const sev = String(severity || "info").toLowerCase();
    const field = (sev === "critical" || sev === "high" || sev === "medium" || sev === "low" || sev === "info")
      ? sev
      : "info";
    this.scanResult.stats[field] = Math.max(0, (this.scanResult.stats[field] || 0) + delta);
  }

  trackRuleId(ruleId) {
    if (!ruleId) return;
    if (!this.rulesIndex) this.rulesIndex = new Set();
    this.rulesIndex.add(ruleId);
    this.scanResult.stats.rulesCount = this.rulesIndex.size;
  }

  seedRulesIndexFromFindings() {
    this.rulesIndex = new Set();
    const findings = Array.isArray(this.scanResult?.findings) ? this.scanResult.findings : [];
    findings.forEach((finding) => {
      if (finding?.ruleId) this.rulesIndex.add(finding.ruleId);
    });
    this.ensureStats();
    this.scanResult.stats.rulesCount = this.rulesIndex.size;
  }

  recalculateStats(envelope) {
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

  addUnifiedFinding(finding, index = 0) {
    const unifiedFinding = this.composeUnifiedFinding(finding, index, this.scanResult);
    if (!unifiedFinding) return null;
    return this.upsertUnifiedFinding(unifiedFinding);
  }

  composeUnifiedFinding(finding, index = 0, targetEnvelope = null) {
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
    const fingerprint = finding.fingerprint || this.buildSastFingerprintFromRaw(finding);
    const pageUrl = locationMeta.pageUrl || locationMeta.url || finding.pageUrl || finding.pageCanon || null;
    const runtimeUrl = locationMeta.runtimeUrl || pageUrl || null;
    const observedPageUrls = collectObservedPageUrls(locationMeta, {
      pageUrl,
      runtimeUrl,
      url: pageUrl || null
    });
    const primaryPageUrl = observedPageUrls[0] || pageUrl || null;
    const location = {
      file: locationMeta.file || finding.codeFile || finding.file || null,
      line: locationMeta.line ?? finding?.sink?.sinkLoc?.start?.line ?? finding?.source?.sourceLoc?.start?.line ?? null,
      column: locationMeta.column ?? finding?.sink?.sinkLoc?.start?.column ?? finding?.source?.sourceLoc?.start?.column ?? null,
      runtimeUrl: runtimeUrl || primaryPageUrl || null,
      runtimeUrls: observedPageUrls,
      pageUrl: primaryPageUrl,
      pageUrls: observedPageUrls,
      url: primaryPageUrl || null,
      param: locationMeta.param || finding.param || null
    };
    const tracePayload = Array.isArray(finding.trace)
      ? finding.trace
      : (Array.isArray(finding?.evidence?.sast?.trace) ? finding.evidence.sast.trace : []);
    const confidence = Number.isFinite(finding.confidence) ? finding.confidence : null;
    const confidenceSignals = Array.isArray(finding?.evidence?.sast?.confidenceSignals)
      ? finding.evidence.sast.confidenceSignals
      : [];
    const findingKind = finding.findingKind || finding?.evidence?.sast?.findingKind || "finding";
    const sinkContext = finding?.evidence?.sast?.sinkContext || null;
    const sourceTier = finding?.evidence?.sast?.sourceTier || null;
    const stableFindingId = [
      scanId || "scan",
      "SAST",
      sanitizeIdPart(moduleId, "module"),
      sanitizeIdPart(ruleId, "rule"),
      stableHashHex(fingerprint)
    ].join("::");
    const unifiedFinding = {
      id: stableFindingId,
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
      findingKind,
      confidence,
      evidence: {
        sast: {
          codeSnippet: finding.codeSnippet || null,
          source: finding.source || null,
          sink: finding.sink || null,
          nodeType: finding.nodeType || null,
          trace: tracePayload || [],
          mode: finding.mode || finding?.evidence?.sast?.mode || null,
          confidenceSignals,
          findingKind,
          sinkContext,
          sourceTier
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

  registerFindingGroup(envelope, unifiedFinding) {
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

  collectLegacyItems(rawItems) {
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

  normalizeImportedScan(raw) {
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
    const legacyItems = this.collectLegacyItems(payload.items);
    if (!isSast && !legacyItems.length) {
      return null;
    }
    if (!hasFindings && !legacyItems.length) {
      return null;
    }
    return payload;
  }

  buildSastFingerprintFromRaw(finding) {
    if (!finding || typeof finding !== "object") return "";
    const ruleMeta = finding.metadata || {};
    const ruleId = ruleMeta.id || ruleMeta.rule_id || ruleMeta.name || "";
    const severity = ruleMeta.severity || finding.severity || "";
    const srcFile = this._canonicalFileId(
      finding?.source?.sourceFileFull || finding?.source?.sourceFile || "",
      finding?.pageUrl
    );
    const sinkFile = this._canonicalFileId(
      finding?.sink?.sinkFileFull || finding?.sink?.sinkFile || "",
      finding?.pageUrl
    );
    const srcLoc = finding?.source?.sourceLoc ? JSON.stringify(finding.source.sourceLoc) : "";
    const sinkLoc = finding?.sink?.sinkLoc ? JSON.stringify(finding.sink.sinkLoc) : "";
    return [ruleId, severity, srcFile, sinkFile, srcLoc, sinkLoc].join('@@');
  }

  buildSastFingerprintFromUnified(finding) {
    if (finding?.fingerprint) return finding.fingerprint;
    const ruleId = finding?.ruleId || "";
    const severity = finding?.severity || "";
    const file = finding?.location?.file || "";
    const line = finding?.location?.line || "";
    const column = finding?.location?.column || "";
    const pageUrl = finding?.location?.pageUrl || finding?.location?.url || "";
    return [ruleId, severity, file, line, column, pageUrl].join('@@');
  }

  upsertUnifiedFinding(finding) {
    if (!finding) return null;
    if (!Array.isArray(this.scanResult.findings)) {
      this.scanResult.findings = [];
    }
    const fingerprint = this.buildSastFingerprintFromUnified(finding);
    finding.fingerprint = fingerprint;
    const idx = this.scanResult.findings.findIndex(item => this.buildSastFingerprintFromUnified(item) === fingerprint);
    if (idx === -1) {
      this.scanResult.findings.push(finding);
      this.ensureStats();
      this.scanResult.stats.findingsCount += 1;
      this.applySeverityDelta(finding?.severity, 1);
      this.trackRuleId(finding?.ruleId);
      return { finding, isNew: true, isUpdated: false };
    } else {
      const prev = this.scanResult.findings[idx];
      const prevSeverity = String(prev?.severity || "info").toLowerCase();
      const nextSeverity = String(finding?.severity || "info").toLowerCase();
      const mergedPageUrls = collectObservedPageUrls(prev?.location, finding?.location);
      const mergedFinding = {
        ...prev,
        ...finding,
        pageUrl: prev?.pageUrl || finding?.pageUrl || mergedPageUrls[0] || null,
        location: {
          ...(prev?.location && typeof prev.location === "object" ? prev.location : {}),
          ...(finding?.location && typeof finding.location === "object" ? finding.location : {}),
          pageUrl: prev?.location?.pageUrl || finding?.location?.pageUrl || mergedPageUrls[0] || null,
          pageUrls: mergedPageUrls,
          runtimeUrl: prev?.location?.runtimeUrl || finding?.location?.runtimeUrl || mergedPageUrls[0] || null,
          runtimeUrls: mergedPageUrls,
          url: prev?.location?.url || finding?.location?.url || mergedPageUrls[0] || null
        }
      };
      this.scanResult.findings[idx] = mergedFinding;
      if (prevSeverity !== nextSeverity) {
        this.applySeverityDelta(prevSeverity, -1);
        this.applySeverityDelta(nextSeverity, 1);
      }
      if (prev?.ruleId !== finding?.ruleId) {
        this.trackRuleId(finding?.ruleId);
      }
      return { finding: mergedFinding, isNew: false, isUpdated: true };
    }
  }

  rebuildGroupsFromFindings() {
    this.scanResult.groups = [];
    const findings = Array.isArray(this.scanResult.findings) ? this.scanResult.findings : [];
    findings.forEach(finding => this.registerFindingGroup(this.scanResult, finding));
  }

  normalizeEnvelope(envelope) {
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
    const legacyItems = this.collectLegacyItems(envelope?.items);
    const hasFindings = Array.isArray(out.findings) && out.findings.length > 0;
    if (!hasFindings && legacyItems.length) {
      out.findings = [];
      out.groups = [];
      out.stats = Object.assign({}, statsDefaults);
      legacyItems.forEach((item, index) => {
        const unifiedFinding = this.composeUnifiedFinding(item, index, out);
        if (!unifiedFinding) return;
        out.findings.push(unifiedFinding);
      });
    } else {
      out.stats = Object.assign({}, statsDefaults, out.stats || {});
    }
    if (Array.isArray(out.findings)) {
      out.findings = out.findings.map(f => {
        if (!f) return f;
        f.fingerprint = this.buildSastFingerprintFromUnified(f);
        return f;
      }).filter(Boolean);
    }
    if (out.analysisVersion && out.analysis && !out.analysis.version) {
      out.analysis.version = out.analysisVersion;
    }
    ensureSastCodeArtifacts(out);
    if (out.items !== undefined) delete out.items;
    this.recalculateStats(out);
    return out;
  }

  unwrapStoredScanResult(stored) {
    if (!stored || typeof stored !== "object") return stored;
    if (stored.scanResult && typeof stored.scanResult === "object") {
      return stored.scanResult;
    }
    return stored;
  }
}

export default SastResultStore;
