/* Author: Denis Podgurskii */
import { ptk_controller_sast } from "../../../controller/sast.js";
import { ptk_utils } from "../../../background/utils.js";
import { ptk_decoder } from "../../../background/decoder.js";
import * as rutils from "../js/rutils.js";
import { normalizeScanResult } from "../js/scanResultViewModel.js";
import { downloadScanExportResult, readScanFileText } from "../js/scanCompression.js";

const controller = new ptk_controller_sast();
const decoder = new ptk_decoder();
const sastFilterState = {
  fileCanon: null,
  ruleKey: null,
  scope: "finding",
  view: "findings",
};
const RULE_FILTER_ALL_VALUE = "__sast_all_rules__";
const RULE_FILTER_DROPDOWN_SELECTOR = "#rule_filter_dropdown";
let isRuleDropdownSyncing = false;
const SAST_DELTA_QUEUE = [];
const SAST_FLUSH_INTERVAL_MS = 300;
let sastFlushTimer = null;
const SAST_PROGRESS_RENDER = {
  timer: null,
  flushMs: 150,
  details: null,
  status: "",
  metrics: "",
  lastActivityAt: 0,
  scanning: false,
};
const SAST_BUCKET_ORDER = ["critical", "high", "medium", "low", "info"];
const SAST_DISCOVERY_GROUPS = [
  { key: "routes", title: "Routes", empty: "No code-discovered routes yet." },
  { key: "endpoints", title: "Endpoints", empty: "No endpoint artifacts yet." },
  { key: "graphql", title: "GraphQL", empty: "No GraphQL artifacts yet." },
  { key: "surfaces", title: "Gated Surfaces", empty: "No gated surfaces yet." },
  { key: "hiddenParams", title: "Params", empty: "No parameter hints yet." },
  { key: "gadgets", title: "Gadgets", empty: "No gadget hints yet." },
];
const SAST_RESULT_VIEWS = new Set(["findings", ...SAST_DISCOVERY_GROUPS.map((group) => group.key)]);
const DISCOVERY_SEVERITY_VISUALS = {
  critical: { color: "ptk-sev-critical", icon: "fire", order: 0, highlight: true },
  high: { color: "ptk-sev-high", icon: "exclamation triangle", order: 1, highlight: true },
  medium: { color: "ptk-sev-medium", icon: "exclamation triangle", order: 2, highlight: false },
  low: { color: "ptk-sev-low", icon: "exclamation triangle", order: 3, highlight: false },
  info: { color: "ptk-sev-info", icon: "info circle", order: 4, highlight: false },
};

function isSastDiscoveryView(view) {
  return view !== "findings" && SAST_DISCOVERY_GROUPS.some((group) => group.key === view);
}

function normalizeSastViewKey(view, scanResult = null) {
  if (view === "discovery") {
    return firstPopulatedSastDiscoveryGroup(scanResult) || SAST_DISCOVERY_GROUPS[0].key;
  }
  if (SAST_RESULT_VIEWS.has(view)) return view;
  return "findings";
}

function firstPopulatedSastDiscoveryGroup(scanResult) {
  const artifacts = normalizeSastArtifacts(scanResult);
  const match = SAST_DISCOVERY_GROUPS.find((group) => (artifacts[group.key]?.length || 0) > 0);
  return match ? match.key : null;
}

function normalizeSastSeverityKey(value) {
  const key = String(value || "").toLowerCase();
  if (key === "critical" || key === "high" || key === "medium" || key === "low" || key === "info") {
    return key;
  }
  if (key === "informational") return "info";
  return "info";
}

function getSastBucket(item) {
  const severity = item?.metadata?.severity || item?.severity || "";
  return normalizeSastSeverityKey(severity);
}

function buildSastBucketHtml() {
  return SAST_BUCKET_ORDER
    .map((bucket) => `<div class="sast_bucket" data-bucket="${bucket}"></div>`)
    .join("");
}

function ensureSastBuckets() {
  const $container = $("#attacks_info");
  if ($container.find(".sast_bucket").length) return;
  $container.html(buildSastBucketHtml());
}

function appendSastToBucket(attackHtml, bucketKey) {
  if (!attackHtml) return;
  ensureSastBuckets();
  const selector = `.sast_bucket[data-bucket="${bucketKey}"]`;
  const $bucket = $("#attacks_info").find(selector);
  $bucket.addClass("has-items");
  $bucket.append(attackHtml);
}

function resetSastProgressRender({ hide = true } = {}) {
  if (SAST_PROGRESS_RENDER.timer) {
    clearTimeout(SAST_PROGRESS_RENDER.timer);
    SAST_PROGRESS_RENDER.timer = null;
  }
  SAST_PROGRESS_RENDER.details = null;
  SAST_PROGRESS_RENDER.status = "";
  SAST_PROGRESS_RENDER.metrics = "";
  SAST_PROGRESS_RENDER.lastActivityAt = 0;
  SAST_PROGRESS_RENDER.scanning = false;
  if (hide) {
    $("#progress_message").hide();
  }
}

function normalizeSastArtifacts(scanResult) {
  const sast = scanResult?.codeArtifacts?.sast;
  if (!sast || typeof sast !== "object") {
    return {
      routes: [],
      endpoints: [],
      graphql: [],
      surfaces: [],
      hiddenParams: [],
      gadgets: [],
    };
  }
  return {
    routes: Array.isArray(sast.routes) ? sast.routes : [],
    endpoints: Array.isArray(sast.endpoints) ? sast.endpoints : [],
    graphql: Array.isArray(sast.graphql) ? sast.graphql : [],
    surfaces: Array.isArray(sast.surfaces) ? sast.surfaces : [],
    hiddenParams: Array.isArray(sast.hiddenParams) ? sast.hiddenParams : [],
    gadgets: Array.isArray(sast.gadgets) ? sast.gadgets : [],
  };
}

function countSastDiscoveryItems(scanResult) {
  const artifacts = normalizeSastArtifacts(scanResult);
  return SAST_DISCOVERY_GROUPS.reduce((total, group) => total + (artifacts[group.key]?.length || 0), 0);
}

function getSastDiscoveryGroupMeta(groupKey) {
  return SAST_DISCOVERY_GROUPS.find((group) => group.key === groupKey) || { key: groupKey, title: groupKey || "Discovery" };
}

function hasRenderableSastData(scanResult) {
  if (!scanResult) return false;
  if (Array.isArray(scanResult.findings) && scanResult.findings.length) return true;
  const items = scanResult.items;
  if (Array.isArray(items) && items.length) return true;
  if (items && typeof items === "object" && Object.keys(items).length) return true;
  if (countSastDiscoveryItems(scanResult) > 0) return true;
  return false;
}

function normalizeLegacySastItems(items) {
  if (Array.isArray(items)) return items;
  if (items && typeof items === "object") {
    return Object.keys(items)
      .sort()
      .map((key) => items[key])
      .filter(Boolean);
  }
  return [];
}

function formatSeverityLabel(value) {
  if (!value) return "Info";
  const lower = String(value).toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

function normalizeSastScope(value) {
  return String(value || "").trim().toLowerCase() === "hint" ? "hint" : "finding";
}

function normalizeSastFindingKind(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "hint" || normalized === "artifact") return normalized;
  return "finding";
}

function getSastFindingFingerprint(finding) {
  if (!finding || typeof finding !== "object") return "";
  if (finding.fingerprint) return String(finding.fingerprint);
  const loc = finding.location || {};
  const ruleId = finding.ruleId || finding.rule_id || finding.id || finding?.metadata?.id || "";
  const severity = finding.severity || finding?.metadata?.severity || "";
  const file = loc.file || finding.pageUrl || "";
  const line = loc.line ?? "";
  const column = loc.column ?? "";
  const pageUrl = loc.pageUrl || loc.url || finding.pageUrl || "";
  return [ruleId, severity, file, line, column, pageUrl].join("@@");
}

function sastScopeMatchesKind(kind, scope = sastFilterState.scope) {
  const normalizedScope = normalizeSastScope(scope);
  const normalizedKind = normalizeSastFindingKind(kind);
  if (normalizedScope === "hint") return normalizedKind !== "finding";
  return normalizedKind === "finding";
}

function sastFindingMatchesScope(finding, scope = sastFilterState.scope) {
  return sastScopeMatchesKind(
    finding?.findingKind || finding?.evidence?.sast?.findingKind || finding?.metadata?.findingKind,
    scope
  );
}

function sastItemMatchesScope(item, scope = sastFilterState.scope) {
  return sastScopeMatchesKind(item?.findingKind || item?.metadata?.findingKind, scope);
}

function updateSastScopeUI() {
  const scope = normalizeSastScope(sastFilterState.scope);
  const showScopeActive = normalizeSastViewKey(sastFilterState.view, controller?.scanViewModel || controller?.scanResult?.scanResult || null) === "findings";
  $("#sast_view_findings_button")
    .toggleClass("active", showScopeActive && scope === "finding")
    .toggleClass("primary", showScopeActive && scope === "finding");
  $("#sast_view_hints_button")
    .toggleClass("active", showScopeActive && scope === "hint")
    .toggleClass("primary", showScopeActive && scope === "hint");
  $("#sast_scope_count_label").text(scope === "hint" ? "Hints" : "Findings");
}

function buildSastItemFromFinding(finding, index) {
  if (!finding) return null;
  const loc = finding.location || {};
  const ev = (finding.evidence && finding.evidence.sast) || {};
  const findingKind = normalizeSastFindingKind(finding.findingKind || ev.findingKind);
  const severity = formatSeverityLabel(finding.severity);
  const owaspArray = Array.isArray(finding.owasp) ? finding.owasp : [];
  const owaspPrimary = finding.owaspPrimary || (owaspArray.length ? owaspArray[0] : null);
  const owaspLegacy = finding.owaspLegacy || (owaspPrimary ? `${owaspPrimary.id}:${owaspPrimary.version}-${owaspPrimary.name}` : "");
  const ruleId = finding.ruleId || finding.id || `rule-${index}`;
  const description = finding.description || ev.description || "";
  const recommendation = finding.recommendation || ev.recommendation || "";
  const metadata = {
    id: ruleId,
    rule_id: ruleId,
    name: finding.ruleName || finding.moduleName || ruleId,
    severity,
    findingKind,
    description,
    recommendation,
  };
  const moduleMeta = {
    id: finding.moduleId || null,
    name: finding.moduleName || null,
    severity,
    category: finding.category || null,
    owasp: owaspArray,
    owaspPrimary,
    owaspLegacy,
    cwe: finding.cwe || null,
    tags: finding.tags || [],
    links: finding.links || {},
  };
  const sourceRaw = ev.source || {};
  const sinkRaw = ev.sink || {};
  const source = Object.assign(
    {
      sourceName: sourceRaw.sourceName || sourceRaw.label || "Source",
      label: sourceRaw.label || sourceRaw.sourceName || "Source",
      sourceFile: sourceRaw.sourceFile || loc.file || "",
      sourceFileFull: sourceRaw.sourceFileFull || sourceRaw.sourceFile || loc.file || "",
      sourceLoc: sourceRaw.sourceLoc || null,
      sourceSnippet: sourceRaw.sourceSnippet || ev.codeSnippet || "",
    },
    sourceRaw
  );
  const sink = Object.assign(
    {
      sinkName: sinkRaw.sinkName || sinkRaw.label || "Sink",
      label: sinkRaw.label || sinkRaw.sinkName || "Sink",
      sinkFile: sinkRaw.sinkFile || loc.file || "",
      sinkFileFull: sinkRaw.sinkFileFull || sinkRaw.sinkFile || loc.file || "",
      sinkLoc: sinkRaw.sinkLoc || null,
      sinkSnippet: sinkRaw.sinkSnippet || "",
    },
    sinkRaw
  );
  return {
    codeFile: loc.file || sink.sinkFile || source.sourceFile || null,
    codeSnippet: ev.codeSnippet || "",
    pageUrl: loc.pageUrl || loc.url || null,
    pageCanon: loc.pageUrl || loc.url || null,
    metadata,
    module_metadata: moduleMeta,
    owasp: owaspArray,
    owaspPrimary,
    owaspLegacy,
    source,
    sink,
    trace: ev.trace || finding.trace || [],
    nodeType: ev.nodeType || finding.nodeType || null,
    confidence: Number.isFinite(finding.confidence) ? finding.confidence : null,
    findingKind,
    requestId: index,
    type: "sast",
  };
}

function artifactList(values) {
  return Array.isArray(values)
    ? Array.from(new Set(values.map((value) => String(value || "").trim()).filter(Boolean)))
    : [];
}

function artifactCount(value) {
  const count = Number(value || 0);
  return Number.isFinite(count) && count > 0 ? count : 0;
}

function discoveryArtifactTitle(artifact, groupKey) {
  if (!artifact) return "Artifact";
  if (groupKey === "routes") return artifact.path || artifact.routeKey || "Route";
  if (groupKey === "endpoints") return `${artifact.method || "GET"} ${artifact.resolvedUrl || artifact.url || artifact.routeKey || "Endpoint"}`;
  if (groupKey === "graphql") {
    const op = artifactList(artifact.operationNames)[0] || artifactList(artifact.rootFields)[0];
    return op ? `GraphQL ${op}` : "GraphQL operation";
  }
  if (groupKey === "surfaces") return artifact.label || artifact.surfaceType || "Gated surface";
  if (groupKey === "hiddenParams") return `${artifact.container || "param"}:${artifact.paramName || "unknown"}`;
  if (groupKey === "gadgets") return artifact.label || artifact.gadgetType || "Gadget";
  return artifact.label || artifact.id || "Artifact";
}

function discoveryArtifactSeverityModel(artifact, groupKey) {
  let score = 0;
  if (!artifact || typeof artifact !== "object") {
    return {
      severity: "info",
      score: 0,
      visual: DISCOVERY_SEVERITY_VISUALS.info,
    };
  }

  if (groupKey === "routes") {
    if (artifact.adminLike) score += 6;
    score += Math.min(4, artifactList(artifact.authHints).length * 2);
    if (artifactList(artifact.protocolHints).length) score += 2;
    if (artifactList(artifact.environmentHints).length) score += 1;
  } else if (groupKey === "endpoints") {
    const discoveryTags = artifactList(artifact.discoveryTags);
    const protocolHints = artifactList(artifact.protocolHints);
    const environmentHints = artifactList(artifact.environmentHints);
    const storageHints = artifactList(artifact.storageHints);
    const uploadSignals = artifactList(artifact.uploadSignals);
    if (artifact.adminLike) score += 7;
    if (String(artifact.method || "GET").toUpperCase() !== "GET") score += 3;
    if (artifact.transport === "websocket" || artifact.transport === "eventsource") score += 1;
    if (artifactList(artifact.authHints).length) score += 3;
    if (artifactList(artifact.bodyKeys).length) score += 2;
    if (artifactList(artifact.headerNames).length) score += 1;
    if (protocolHints.includes("oauth") || protocolHints.includes("oidc") || protocolHints.includes("saml")) score += 3;
    if (discoveryTags.includes("signed-url")) score += 4;
    if (discoveryTags.includes("object-storage")) score += 3;
    if (discoveryTags.includes("upload")) score += 3;
    if (discoveryTags.includes("internal-host")) score += 4;
    if (environmentHints.length) score += 2;
    if (storageHints.length) score += 1;
    if (uploadSignals.length) score += 1;
  } else if (groupKey === "graphql") {
    const operationTypes = artifactList(artifact.operationTypes);
    if (operationTypes.includes("mutation")) score += 6;
    if (operationTypes.includes("subscription")) score += 4;
    if (artifact.adminLike) score += 5;
    if (artifactList(artifact.variableNames).length >= 2) score += 1;
  } else if (groupKey === "surfaces") {
    if (artifact.surfaceType === "role-gate") score += 5;
    else if (artifact.surfaceType === "auth-flow") score += 4;
    else if (artifact.surfaceType === "feature-flag") score += 2;
    else if (artifact.surfaceType === "debug-toggle") score += 1;
    if (artifact.adminLike) score += 4;
    score += Math.min(2, artifactList(artifact.hintNames).length);
  } else if (groupKey === "hiddenParams") {
    const hintTypes = artifactList(artifact.hintTypes).concat(artifact.hintType ? [artifact.hintType] : []);
    const actions = artifactList(artifact.actions).concat(artifact.action ? [artifact.action] : []);
    if (hintTypes.includes("auth")) score += 6;
    if (hintTypes.includes("navigation")) score += 4;
    if (hintTypes.includes("feature-flag")) score += 3;
    if (hintTypes.includes("debug")) score += 1;
    if ((artifact.container || "") === "header") score += 2;
    if (actions.includes("write")) score += 2;
    if (artifact.adminLike) score += 3;
    score += Math.min(2, Math.max(0, artifactCount(artifact.occurrenceCount) - 1));
  } else if (groupKey === "gadgets") {
    if (artifact.gadgetType === "code-exec-sink") score += 10;
    else if (artifact.gadgetType === "prototype-mutation") score += 9;
    else if (artifact.gadgetType === "dom-html-sink") score += 6;
    else if (artifact.gadgetType === "message-listener" || artifact.gadgetType === "postmessage-emitter") score += 4;
    score += Math.min(2, Math.max(0, artifactCount(artifact.occurrenceCount) - 1));
  }

  let severity = "info";
  if (score >= 10) severity = "high";
  else if (score >= 6) severity = "medium";
  else if (score >= 3) severity = "low";

  return {
    severity,
    score,
    visual: DISCOVERY_SEVERITY_VISUALS[severity] || DISCOVERY_SEVERITY_VISUALS.info,
  };
}

function discoveryArtifactPrimaryContext(artifact) {
  return String(artifact?.resolvedUrl || artifact?.url || artifact?.routeKey || artifact?.pageUrl || "").trim();
}

function withSastArtifactTitle(baseText, title) {
  const base = String(baseText || "").trim().replace(/[.]+$/, "");
  const artifactTitle = String(title || "").trim();
  if (!base) return artifactTitle ? `${artifactTitle}.` : "Code discovery signal identified in the client.";
  if (!artifactTitle) return `${base}.`;
  return `${base}: ${artifactTitle}.`;
}

function renderSastDiscoveryLead(text) {
  const raw = String(text || "").trim();
  const splitIndex = raw.indexOf(":");
  if (splitIndex === -1) {
    return ptk_utils.escapeHtml(raw);
  }
  const prefix = raw.slice(0, splitIndex + 1).trim();
  const suffix = raw.slice(splitIndex + 1).trim();
  if (!suffix) return ptk_utils.escapeHtml(prefix);
  return `${ptk_utils.escapeHtml(prefix)} <b>${ptk_utils.escapeHtml(suffix)}</b>`;
}

function renderSastDiscoveryValue(value) {
  return `<b>${ptk_utils.escapeHtml(String(value || "").trim())}</b>`;
}

function formatSastArtifactClassifierLabel(value) {
  return String(value || "")
    .split(/[_-]+/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function getSastDiscoveryPrimaryLabel(artifact, groupKey) {
  if (!artifact || typeof artifact !== "object") return "";
  if (groupKey === "routes") {
    if (artifact.adminLike) return "Admin-like route";
    if (artifactList(artifact.authHints).length) return "Auth-related route";
    return "Discovered route";
  }
  if (groupKey === "endpoints") {
    const discoveryTags = artifactList(artifact.discoveryTags);
    if (artifact.adminLike) return "Privileged endpoint";
    if (discoveryTags.includes("signed-url")) return "Signed URL endpoint";
    if (discoveryTags.includes("object-storage")) return "Object storage endpoint";
    if (discoveryTags.includes("upload")) return "Upload endpoint";
    if (discoveryTags.includes("internal-host")) return "Internal host endpoint";
    if (artifactList(artifact.authHints).length) return "Auth-related endpoint";
    if (String(artifact.method || "GET").toUpperCase() !== "GET") return "Writable endpoint";
    return "Discovered endpoint";
  }
  if (groupKey === "graphql") {
    const operationTypes = artifactList(artifact.operationTypes);
    if (operationTypes.includes("mutation")) return "GraphQL mutation";
    if (operationTypes.includes("subscription")) return "GraphQL subscription";
    if (operationTypes.includes("query")) return "GraphQL query";
    return "GraphQL operation";
  }
  if (groupKey === "surfaces") {
    const exact = {
      "role-gate": "Role or privilege gate",
      "auth-flow": "Authentication flow",
      "feature-flag": "Feature flag",
      "debug-toggle": "Debug or internal toggle"
    };
    return exact[String(artifact.surfaceType || "").trim()] || "Gated surface";
  }
  if (groupKey === "hiddenParams") {
    const hintTypes = artifactList(artifact.hintTypes).concat(artifact.hintType ? [artifact.hintType] : []);
    if (hintTypes.includes("auth")) return "Auth-related parameter";
    if (hintTypes.includes("navigation")) return "Navigation parameter";
    if (hintTypes.includes("feature-flag")) return "Feature flag parameter";
    if (hintTypes.includes("debug")) return "Debug parameter";
    if ((artifact.container || "") === "header") return "Header parameter";
    return "Hidden parameter";
  }
  if (groupKey === "gadgets") {
    const exact = {
      "code-exec-sink": "Code execution gadget",
      "prototype-mutation": "Prototype mutation gadget",
      "dom-html-sink": "DOM HTML gadget",
      "message-listener": "Message listener gadget",
      "postmessage-emitter": "postMessage emitter gadget"
    };
    return exact[String(artifact.gadgetType || "").trim()] || "Reusable gadget";
  }
  return "";
}

function buildSastDiscoveryWhyInteresting(artifact, groupKey) {
  if (!artifact || typeof artifact !== "object") return "Code discovery signal identified in the client.";
  const title = discoveryArtifactTitle(artifact, groupKey);
  if (groupKey === "routes") {
    if (artifact.adminLike) return withSastArtifactTitle("Admin-like or gated route is discoverable in client code", title);
    if (artifactList(artifact.authHints).length) return withSastArtifactTitle("Route includes auth or role hints in client code", title);
    return withSastArtifactTitle("Client code exposes a routable path that may not be obvious from normal navigation", title);
  }
  if (groupKey === "endpoints") {
    if (artifact.adminLike) return withSastArtifactTitle("Client code exposes an admin-like or privileged endpoint shape", title);
    if (artifactList(artifact.authHints).length) return withSastArtifactTitle("Endpoint includes auth-related behavior or headers in client code", title);
    if (artifactList(artifact.discoveryTags).includes("signed-url")) return withSastArtifactTitle("Client code exposes a signed URL or object storage request shape", title);
    if (artifactList(artifact.discoveryTags).includes("upload")) return withSastArtifactTitle("Client code exposes an upload-capable endpoint and request shape", title);
    return withSastArtifactTitle("Client code exposes a concrete request target, method, and parameter shape", title);
  }
  if (groupKey === "graphql") {
    const opTypes = artifactList(artifact.operationTypes);
    if (opTypes.includes("mutation")) return withSastArtifactTitle("Client code exposes a GraphQL mutation that may affect privileged state", title);
    if (opTypes.includes("subscription")) return withSastArtifactTitle("Client code exposes a GraphQL subscription or event stream", title);
    return withSastArtifactTitle("Client code exposes GraphQL operations, fields, or variables not obvious from the UI", title);
  }
  if (groupKey === "surfaces") {
    if (artifact.surfaceType === "role-gate") return withSastArtifactTitle("Client code contains a role or privilege gate for a feature or flow", title);
    if (artifact.surfaceType === "auth-flow") return withSastArtifactTitle("Client code exposes an authentication-related flow or guard", title);
    if (artifact.surfaceType === "feature-flag") return withSastArtifactTitle("Feature-flagged behavior is discoverable in the client", title);
    if (artifact.surfaceType === "debug-toggle") return withSastArtifactTitle("Debug or internal-only behavior is exposed through client-side switches", title);
    return withSastArtifactTitle("Client code exposes a gated surface that may hide reachable functionality", title);
  }
  if (groupKey === "hiddenParams") {
    if (artifactList(artifact.hintTypes).includes("auth") || artifact.hintType === "auth") {
      return withSastArtifactTitle("Hidden parameter suggests an auth, session, or privilege-related control path", title);
    }
    if (artifactList(artifact.hintTypes).includes("navigation") || artifact.hintType === "navigation") {
      return withSastArtifactTitle("Hidden parameter influences route or navigation behavior", title);
    }
    return withSastArtifactTitle("Client code exposes a hidden or non-obvious parameter name and usage path", title);
  }
  if (groupKey === "gadgets") {
    if (artifact.gadgetType === "code-exec-sink") return withSastArtifactTitle("Client code contains a gadget that could support code execution if attacker-controlled data reaches it", title);
    if (artifact.gadgetType === "dom-html-sink") return withSastArtifactTitle("Client code contains an HTML injection gadget that may support DOM XSS chains", title);
    if (artifact.gadgetType === "prototype-mutation") return withSastArtifactTitle("Client code contains a prototype mutation gadget that may support prototype pollution impact", title);
    return withSastArtifactTitle("Client code contains a reusable gadget that may support an exploit chain", title);
  }
  return withSastArtifactTitle("Code discovery signal identified in the client", title);
}

function buildSastDiscoveryNextCheck(artifact, groupKey) {
  if (!artifact || typeof artifact !== "object") return "Validate whether the discovered path is reachable and security-relevant.";
  if (groupKey === "routes") {
    return "Try direct navigation, hidden routes, and role-bypass paths to confirm whether the route is actually reachable.";
  }
  if (groupKey === "endpoints") {
    return "Replay this request shape in R-Builder and test authz, hidden parameters, and method abuse.";
  }
  if (groupKey === "graphql") {
    return "Test unauthorized operation execution, hidden variables, and field-level authorization on this GraphQL surface.";
  }
  if (groupKey === "surfaces") {
    return "Try to reach the same behavior through route tampering, client-state changes, or direct requests.";
  }
  if (groupKey === "hiddenParams") {
    return "Inject this parameter into requests, routes, headers, or storage-backed flows and watch for behavior changes.";
  }
  if (groupKey === "gadgets") {
    return "Look for attacker-controlled data that can be routed into this gadget through DOM, message, route, or storage flows.";
  }
  return "Validate whether the discovered path is reachable and security-relevant.";
}

function buildSastDiscoveryRawRequest(artifact, groupKey) {
  if (groupKey !== "endpoints" || !artifact) return null;
  const method = String(artifact.method || "GET").toUpperCase();
  const targetUrl = String(artifact.resolvedUrl || artifact.url || "").trim();
  if (!targetUrl) return null;
  let requestTarget = targetUrl;
  let hostHeader = "";
  try {
    const parsed = new URL(targetUrl, window.location.href);
    requestTarget = parsed.href || targetUrl;
    hostHeader = parsed.host || "";
  } catch (_) {
    requestTarget = targetUrl;
  }
  const headers = [];
  if (hostHeader) headers.push(`Host: ${hostHeader}`);
  headers.push("User-Agent: PentestKit-SAST");
  headers.push("Accept: */*");
  const headerNames = artifactList(artifact.headerNames);
  if (headerNames.length) {
    headerNames.forEach((name) => {
      headers.push(`${name}: <value>`);
    });
  }
  let body = "";
  const bodyKeys = artifactList(artifact.bodyKeys);
  if (method !== "GET" && method !== "HEAD" && bodyKeys.length) {
    headers.push("Content-Type: application/json");
    const payload = {};
    bodyKeys.forEach((key) => {
      payload[key] = "<value>";
    });
    body = JSON.stringify(payload, null, 2);
  }
  const lines = [`${method} ${requestTarget || "/"} HTTP/1.1`, ...headers];
  if (body) {
    lines.push("");
    lines.push(body);
  }
  return lines.join("\n");
}

function discoveryArtifactDetails(artifact, groupKey) {
  if (!artifact) return [];
  const details = [];
  const push = (label, value) => {
    const normalized = Array.isArray(value) ? artifactList(value).join(", ") : String(value || "").trim();
    if (!normalized) return;
    details.push({ label, value: normalized });
  };
  if (groupKey === "routes") {
    push("Framework", artifact.framework);
    push("Auth hints", artifact.authHints);
    push("Protocols", artifact.protocolHints);
    push("Environment", artifact.environmentHints);
    push("Route key", artifact.routeKey);
  } else if (groupKey === "endpoints") {
    push("Transport", artifact.transport);
    push("Params", artifact.paramNames);
    push("Body keys", artifact.bodyKeys);
    push("Headers", artifact.headerNames);
    push("Auth hints", artifact.authHints);
    push("Protocols", artifact.protocolHints);
    push("Discovery", artifact.discoveryTags);
    push("Environment", artifact.environmentHints);
    push("Storage", artifact.storageHints);
    push("Uploads", artifact.uploadSignals);
  } else if (groupKey === "graphql") {
    push("Operations", artifact.operationNames);
    push("Types", artifact.operationTypes);
    push("Root fields", artifact.rootFields);
    push("Variables", artifact.variableNames);
    push("Transport", artifact.transport || artifact.clientKind);
  } else if (groupKey === "surfaces") {
    push("Hints", artifact.hintNames);
    push("Protocols", artifact.protocolHints);
    push("Occurrences", artifact.occurrenceCount);
    if (Array.isArray(artifact.sourceFiles) && artifact.sourceFiles.length > 1) {
      push("Files", artifact.sourceFiles);
    }
  } else if (groupKey === "hiddenParams") {
    push("Actions", artifact.actions || artifact.action);
    push("Hints", artifact.hintTypes || artifact.hintType);
    push("Occurrences", artifact.occurrenceCount);
    if (Array.isArray(artifact.sourceFiles) && artifact.sourceFiles.length > 1) {
      push("Files", artifact.sourceFiles);
    }
    push("Route key", artifact.routeKey);
  } else if (groupKey === "gadgets") {
    push("Occurrences", artifact.occurrenceCount);
    if (Array.isArray(artifact.sourceFiles) && artifact.sourceFiles.length > 1) {
      push("Files", artifact.sourceFiles);
    }
    push("Route key", artifact.routeKey);
  }
  const showSingularSource = !(
    (groupKey === "surfaces" || groupKey === "hiddenParams" || groupKey === "gadgets")
    && Number(artifact.occurrenceCount || 0) > 1
  );
  if (showSingularSource) {
    push("Source", artifact.sourceFile || artifact.pageUrl);
    if (artifact.sourceLoc?.line) {
      push("Location", `line ${artifact.sourceLoc.line}${Number.isFinite(artifact.sourceLoc.column) ? `:${artifact.sourceLoc.column}` : ""}`);
    }
  }
  return details;
}

function discoveryArtifactSignals(artifact, groupKey, severity = "info") {
  const signals = [];
  const push = (value) => {
    const normalized = String(value || "").trim();
    if (!normalized || signals.includes(normalized)) return;
    signals.push(normalized);
  };
  if (severity === "critical") push("critical");
  else if (severity === "high") push("high");
  if (artifact?.adminLike) push("admin-like");
  if (artifact?.surfaceType) push(artifact.surfaceType);
  if (artifact?.gadgetType) push(artifact.gadgetType);
  if (artifact?.hintType) push(artifact.hintType);
  if (artifact?.method && groupKey !== "endpoints") push(artifact.method);
  return signals;
}

function buildSastDiscoveryItem(artifact, groupKey, index) {
  if (!artifact) return "";
  const risk = discoveryArtifactSeverityModel(artifact, groupKey);
  const severity = normalizeSastSeverityKey(risk.severity);
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);
  const attackClass = risk.visual.highlight
    ? `vuln success visible ${severityLabel} severity-${severity}`
    : "nonvuln visible";
  const sourceCanonList = Array.isArray(artifact.sourceFiles) && artifact.sourceFiles.length
    ? artifact.sourceFiles.map((value) => {
      return typeof rutils?.canonicalizeSastFileId === "function"
        ? rutils.canonicalizeSastFileId(value)
        : String(value || "");
    }).filter(Boolean)
    : [artifact.sourceFile && typeof rutils?.canonicalizeSastFileId === "function"
      ? rutils.canonicalizeSastFileId(artifact.sourceFile)
      : (artifact.sourceFile || "")].filter(Boolean);
  const sourceCanon = sourceCanonList.join("\n");
  const pageCanon = artifact.pageUrl && typeof rutils?.canonicalizeSastFileId === "function"
    ? rutils.canonicalizeSastFileId(artifact.pageUrl)
    : (artifact.pageUrl || "");
  const details = discoveryArtifactDetails(artifact, groupKey);
  const context = discoveryArtifactPrimaryContext(artifact);
  const whyInteresting = buildSastDiscoveryWhyInteresting(artifact, groupKey);
  const nextCheck = buildSastDiscoveryNextCheck(artifact, groupKey);
  const primaryLabel = getSastDiscoveryPrimaryLabel(artifact, groupKey);
  const rawRequest = buildSastDiscoveryRawRequest(artifact, groupKey);
  const headerIcon = risk.visual.highlight
    ? `<i class="${ptk_utils.escapeHtml(risk.visual.icon)} ${ptk_utils.escapeHtml(risk.visual.color)} icon"></i>`
    : "";
  const actionLinks = [
    `<a href="#" class="sast-discovery-details-toggle" data-visible="false">Details</a>`,
  ];
  if (rawRequest) {
    const encodedRequest = decoder.base64_encode(encodeURIComponent(JSON.stringify(rawRequest)));
    actionLinks.push(`<a href="#" class="sast-discovery-open-rbuilder" data-raw-request="${ptk_utils.escapeHtml(encodedRequest)}">Open in R-Builder</a>`);
  }
  const detailsHtml = details.map((entry) => {
    return `<div>${ptk_utils.escapeHtml(entry.label)}: ${renderSastDiscoveryValue(entry.value)}</div>`;
  }).join("");
  return `
    <div class="ui message attack_info sast-discovery-item ${attackClass}"
      style="overflow:auto"
      data-index="${index}"
      data-order="${risk.visual.order}"
      data-group="${ptk_utils.escapeHtml(groupKey)}"
      data-severity="${ptk_utils.escapeHtml(severity)}"
      data-source-canon="${ptk_utils.escapeHtml(sourceCanon)}"
      data-page-canon="${ptk_utils.escapeHtml(pageCanon)}">
      <div class="description">
        ${primaryLabel ? `<div><b>${ptk_utils.escapeHtml(primaryLabel)}</b></div>` : ""}
        <div>${renderSastDiscoveryLead(whyInteresting)}</div>
        <div style="margin-top:6px">${ptk_utils.escapeHtml(nextCheck)}</div>
        <div style="margin-top:6px">${actionLinks.join(" &middot; ")}</div>
        <div class="sast-discovery-details-content" style="display:none; margin-top:6px">
          ${context ? `<div>Target: ${renderSastDiscoveryValue(context)}</div>` : ""}
          ${detailsHtml}
        </div>
      </div>
    </div>
  `;
}

function renderSastDiscovery(scanResult) {
  const artifacts = normalizeSastArtifacts(scanResult);
  let renderIndex = 0;
  const sections = SAST_DISCOVERY_GROUPS.map((group) => {
    const entries = Array.isArray(artifacts[group.key]) ? artifacts[group.key] : [];
    const sortedEntries = entries.slice().sort((left, right) => {
      const leftRisk = discoveryArtifactSeverityModel(left, group.key);
      const rightRisk = discoveryArtifactSeverityModel(right, group.key);
      const orderDiff = (leftRisk.visual.order || 99) - (rightRisk.visual.order || 99);
      if (orderDiff !== 0) return orderDiff;
      const scoreDiff = (rightRisk.score || 0) - (leftRisk.score || 0);
      if (scoreDiff !== 0) return scoreDiff;
      const occurrenceDiff = artifactCount(right?.occurrenceCount) - artifactCount(left?.occurrenceCount);
      if (occurrenceDiff !== 0) return occurrenceDiff;
      return discoveryArtifactTitle(left, group.key).localeCompare(discoveryArtifactTitle(right, group.key));
    });
    const itemsHtml = sortedEntries.map((artifact) => {
      const html = buildSastDiscoveryItem(artifact, group.key, renderIndex);
      renderIndex += 1;
      return html;
    }).join("");
    return `
      <div class="sast-discovery-panel" data-discovery-group="${ptk_utils.escapeHtml(group.key)}">
        <div class="sast-discovery-cards">${itemsHtml || `
          <div class="ui small message">
            <div class="header">${ptk_utils.escapeHtml(group.title)}</div>
            <p>${ptk_utils.escapeHtml(group.empty)}</p>
          </div>
        `}</div>
      </div>
    `;
  });
  $("#discovery_info").html(sections.join(""));
}

function getSastAttackItem(index) {
  if (Number.isNaN(Number(index))) return null;
  const items = Array.isArray(controller?.sastAttackItems)
    ? controller.sastAttackItems
    : null;
  if (items && items[index]) {
    return items[index];
  }
  const legacyItems = controller?.scanResult?.scanResult?.items;
  if (!legacyItems) return null;
  if (Array.isArray(legacyItems)) return legacyItems[index] || null;
  if (typeof legacyItems === "object") {
    const values = normalizeLegacySastItems(legacyItems);
    return values[index] || null;
  }
  return null;
}

function extractSastFindingsForStats(raw, vm) {
  if (Array.isArray(vm?.findings) && vm.findings.length) return vm.findings;
  if (Array.isArray(raw?.findings) && raw.findings.length) return raw.findings;
  if (raw?.items) return normalizeLegacySastItems(raw.items);
  if (Array.isArray(controller?.sastAttackItems) && controller.sastAttackItems.length) {
    return controller.sastAttackItems;
  }
  return [];
}

function summarizeSastFindings(findings, scope = sastFilterState.scope) {
  const summary = {
    findingsCount: 0,
    rulesCount: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  if (!Array.isArray(findings) || !findings.length) {
    return summary;
  }
  const rules = new Set();
  findings.forEach((finding) => {
    if (!finding) return;
    if (!sastFindingMatchesScope(finding, scope)) return;
    summary.findingsCount += 1;
    const severity = String(finding?.severity || finding?.metadata?.severity || "").toLowerCase();
    if (severity === "critical") summary.critical += 1;
    else if (severity === "high") summary.high += 1;
    else if (severity === "medium") summary.medium += 1;
    else if (severity === "low") summary.low += 1;
    else summary.info += 1;
    const candidates = [
      finding?.ruleId,
      finding?.rule_id,
      finding?.id,
      finding?.metadata?.id,
      finding?.module_metadata?.id,
    ];
    const id = candidates.find((value) => value !== undefined && value !== null && String(value).trim());
    if (id) {
      rules.add(String(id).trim());
    }
  });
  summary.rulesCount = rules.size;
  return summary;
}

function triggerSastStatsEvent(rawScanResult, viewModel) {
  const raw = rawScanResult || {};
  const vm = viewModel || normalizeScanResult(raw);
  const derived = summarizeSastFindings(extractSastFindingsForStats(raw, vm), sastFilterState.scope);
  const stats = Object.assign({}, vm.stats || raw.stats || {}, derived);
  $(document).trigger("bind_stats", Object.assign({}, raw, { stats }));
}

jQuery(function () {
  // initialize all modals
  $(".modal.coupled").modal({
    allowMultiple: true,
  });

  $(document).on("click", ".showHtml", function () {
    rutils.showHtml($(this));
  });
  $(document).on("click", ".showHtmlNew", function () {
    rutils.showHtml($(this), true);
  });

  const $sastSaveScanModal = $('#sast_save_scan_modal')
  let $sastSaveScanProjectDropdown = $('#sast_save_scan_project_select')
  const $sastSaveScanModalError = $('#sast_save_scan_modal_error')
  const sastSaveScanProjectMap = new Map()
  const $downloadScansModal = $('#download_scans')
  let $sastDownloadProjectDropdown = $('#download_project_select')
  const sastDownloadProjectMap = new Map()

  function showSastResultModal(header, message) {
    $('#result_header').text(header)
    $('#result_message').text(message || '')
    $('#result_dialog').modal('show')
  }

  function handleSastSaveScanResponse(result) {
    if (result instanceof Error) {
      showSastResultModal('Error', result.message || 'Unable to save scan')
      return
    }
    if (result?.success) {
      showSastResultModal('Success', 'Scan saved')
    } else {
      const message = result?.json?.message || result?.message || 'Unable to save scan'
      showSastResultModal('Error', message)
    }
  }

  function extractProjectsFromPayload(payload) {
    if (!payload) return []
    if (Array.isArray(payload)) return payload
    if (typeof payload !== 'object') return []
    const containers = ['projects', 'data', 'items', 'results']
    for (const key of containers) {
      const value = payload[key]
      if (!value) continue
      if (Array.isArray(value)) {
        return value
      }
      const nested = extractProjectsFromPayload(value)
      if (nested.length) {
        return nested
      }
    }
    return []
  }

  function normalizeProjectOption(project) {
    if (project === null || project === undefined) return null
    if (typeof project === 'string' || typeof project === 'number' || typeof project === 'boolean') {
      const value = project
      return { value: String(value), text: String(value), raw: value }
    }
    if (typeof project !== 'object') return null
    const idFields = ['id', 'projectId', 'project_id', '_id', 'uuid', 'slug', 'key']
    let value = null
    for (const field of idFields) {
      if (project[field] !== undefined && project[field] !== null && project[field] !== '') {
        value = project[field]
        break
      }
    }
    if (!value && project?.name) {
      value = project.name
    }
    if (!value) return null
    const text = project.name || project.title || project.projectName || project.display_name || project.displayName || project.slug || project.key || String(value)
    return { value: String(value), text, raw: value }
  }

  function buildProjectOptions(payload) {
    const rawProjects = extractProjectsFromPayload(payload)
    const options = []
    rawProjects.forEach(project => {
      const option = normalizeProjectOption(project)
      if (option) {
        options.push(option)
      }
    })
    return options
  }

  function rebuildProjectDropdown($dropdown, projectMap, projectOptions, placeholderText) {
    projectMap.clear()
    if (!$dropdown || !$dropdown.length) return $dropdown
    try {
      $dropdown.dropdown('destroy')
    } catch (err) { }
    $dropdown = resetSemanticDropdown($dropdown)
    if (!$dropdown) return $dropdown
    const placeholder = document.createElement('option')
    placeholder.value = ''
    placeholder.textContent = placeholderText || 'Select a project'
    $dropdown.append(placeholder)
    projectOptions.forEach(opt => {
      const option = document.createElement('option')
      option.value = opt.value
      option.textContent = opt.text
      projectMap.set(opt.value, opt.raw)
      $dropdown.append(option)
    })
    $dropdown.dropdown()
    $dropdown.dropdown('clear')
    return $dropdown
  }

  function rebuildSastProjectDropdown(projectOptions) {
    $sastSaveScanProjectDropdown = rebuildProjectDropdown($sastSaveScanProjectDropdown, sastSaveScanProjectMap, projectOptions, 'Select a project')
  }

  function rebuildSastDownloadProjectDropdown(projectOptions) {
    $sastDownloadProjectDropdown = rebuildProjectDropdown($sastDownloadProjectDropdown, sastDownloadProjectMap, projectOptions, 'Select a project')
    if (!$sastDownloadProjectDropdown) return
    $sastDownloadProjectDropdown.off('change').on('change', function () {
      const selected = $(this).val()
      if (!selected) {
        clearDownloadScansTable()
        setDownloadScansError('')
        return
      }
      const projectId = sastDownloadProjectMap.get(selected) ?? selected
      loadSastScansForProject(projectId)
    })
  }

  function resetSemanticDropdown($dropdown) {
    if (!$dropdown || !$dropdown.length) {
      return $dropdown
    }
    const id = $dropdown.attr('id') || ''
    const classes = $dropdown.attr('class') || 'ui dropdown'
    const $newDropdown = $(`<select id="${id}" class="${classes}"></select>`)
    const $existingWrapper = $dropdown.closest('.ui.dropdown.selection')
    if ($existingWrapper.length) {
      $existingWrapper.replaceWith($newDropdown)
    } else {
      $dropdown.replaceWith($newDropdown)
    }
    return $newDropdown
  }

  function hideSastSaveScanModalError() {
    $sastSaveScanModalError.hide().text('')
  }

  function showSastSaveScanModalError(message) {
    $sastSaveScanModalError.text(message || '').show()
  }

  function runSastSaveScan(projectId, $loader) {
    hideSastSaveScanModalError()
    if ($loader) {
      $loader.addClass('active')
    }
    $sastSaveScanModal.addClass('loading')
    controller.saveScan(projectId).then(result => {
      handleSastSaveScanResponse(result)
      $sastSaveScanModal.modal('hide')
    }).catch(err => {
      showSastResultModal('Error', err?.message || 'Unable to save scan')
    }).finally(() => {
      if ($loader) {
        $loader.removeClass('active')
      }
      $sastSaveScanModal.removeClass('loading')
    })
  }

  function showSastSaveScanModal($loader) {
    hideSastSaveScanModalError()
    $sastSaveScanModal
      .modal({
        allowMultiple: true,
        onApprove: function () {
          const projectId = $sastSaveScanProjectDropdown.val()
          if (!projectId) {
            showSastSaveScanModalError('Select a project to continue.')
            return false
          }
          const payloadProjectId = sastSaveScanProjectMap.get(projectId) ?? projectId
          runSastSaveScan(payloadProjectId, $loader)
          return false
        }
      })
      .modal('show')
  }

  function fetchSastPortalProjects() {
    return controller.getProjects().then(result => {
      if (!result?.success) {
        const message = result?.json?.message || result?.message || 'Unable to load projects. Check your PTK+ configuration.'
        throw new Error(message)
      }
      const projectOptions = buildProjectOptions(result.json)
      if (!projectOptions.length) {
        throw new Error('No projects available. Create a project in the portal and try again.')
      }
      return projectOptions
    })
  }

  function requestSastProjectsAndShowModal($loader) {
    if ($loader) {
      $loader.addClass('active')
    }
    fetchSastPortalProjects()
      .then(projectOptions => {
        rebuildSastProjectDropdown(projectOptions)
        showSastSaveScanModal($loader)
      })
      .catch(err => {
        showSastResultModal('Error', err?.message || 'Unable to load projects. Check your PTK+ configuration.')
      })
      .finally(() => {
        if ($loader) {
          $loader.removeClass('active')
        }
      })
  }

  function setDownloadScansError(message) {
    if (message) {
      $('#download_error').text(message)
      $('#download_scans_error').show()
    } else {
      $('#download_error').text('')
      $('#download_scans_error').hide()
    }
  }

  function extractDownloadScans(payload, inheritedHost = '') {
    if (!payload) return []
    if (Array.isArray(payload)) {
      return payload.reduce((acc, item) => acc.concat(extractDownloadScans(item, inheritedHost)), [])
    }
    if (typeof payload !== 'object') return []
    const host = payload.hostname || payload.host || payload.domain || payload.project || payload.name || inheritedHost || ''
    if (Array.isArray(payload.scans)) {
      return payload.scans.reduce((acc, item) => acc.concat(extractDownloadScans(item, host)), [])
    }
    const scanId = payload.scanId || payload.id
    if (scanId) {
      const rawDate = payload.scanDate || payload.finished_at || payload.created_at || payload.started_at || payload.meta?.scanDate
      return [{ hostname: host, scanId, scanDate: rawDate, raw: payload }]
    }
    const containers = ['items', 'data', 'results', 'entries', 'projects', 'records']
    return containers.reduce((acc, key) => {
      if (!payload[key]) return acc
      return acc.concat(extractDownloadScans(payload[key], host))
    }, [])
  }

  function renderDownloadScansTable(items) {
    const entries = extractDownloadScans(items)
    const dt = []
    entries.forEach(entry => {
      if (!entry) return
      const scanId = entry.scanId || ''
      const hostname = entry.hostname || entry.raw?.meta?.hostname || ''
      const rawDate = entry.scanDate || entry.raw?.finished_at || entry.raw?.created_at || entry.raw?.started_at
      const dateObj = rawDate ? new Date(rawDate) : null
      const scanDate = dateObj && !isNaN(dateObj.getTime()) ? dateObj.toLocaleString() : ''
      const link = `<div class="ui mini icon button download_scan_by_id" style="position: relative" data-scan-id="${scanId}"><i class="download alternate large icon"
                                        title="Download"></i>
                                        <div style="position:absolute; top:1px;right: 2px">
                                             <div class="ui  centered inline inverted loader"></div>
                                        </div>
                                </div>`
      const del = ` <div class="ui mini icon button delete_scan_by_id" data-scan-id="${scanId}" data-scan-host="${hostname}"><i  class="trash alternate large icon "
                    title="Delete"></i></div>`
      dt.push([hostname, scanId, scanDate, link, del])
    })

    dt.sort(function (a, b) {
      if (a[0] === b[0]) {
        return 0
      } else {
        return a[0] < b[0] ? -1 : 1
      }
    })
    var groupColumn = 0;
    let params = {
      data: dt,
      columnDefs: [{
        "visible": false, "targets": groupColumn
      }],
      "order": [[groupColumn, 'asc']],
      "drawCallback": function (settings) {
        var api = this.api();
        var rows = api.rows({ page: 'current' }).nodes();
        var last = null;

        api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
          if (last !== group) {
            $(rows).eq(i).before(
              '<tr class="group" ><td colspan="4"><div class="ui black ribbon label">' + group + '</div></td></tr>'
            )
            last = group
          }
        })
      }
    }
    bindTable('#tbl_scans', params)
  }

  function clearDownloadScansTable() {
    renderDownloadScansTable([])
  }

  function loadSastDownloadProjects() {
    setDownloadScansError('')
    clearDownloadScansTable()
    $downloadScansModal.addClass('loading')
    fetchSastPortalProjects()
      .then(options => {
        rebuildSastDownloadProjectDropdown(options)
      })
      .catch(err => {
        setDownloadScansError(err?.message || 'Unable to load projects. Check your PTK+ configuration.')
      })
      .finally(() => {
        $downloadScansModal.removeClass('loading')
      })
  }

  function loadSastScansForProject(projectId) {
    if (!projectId) {
      setDownloadScansError('Select a project to load scans.')
      clearDownloadScansTable()
      return
    }
    setDownloadScansError('')
    $downloadScansModal.addClass('loading')
    controller.downloadScans(projectId, 'sast').then(result => {
      if (!result?.success) {
        const message = result?.json?.message || result?.message || 'Unable to load scans.'
        setDownloadScansError(message)
        clearDownloadScansTable()
        return
      }
      setDownloadScansError('')
      renderDownloadScansTable(result.json)
    }).catch(err => {
      setDownloadScansError(err?.message || 'Unable to load scans.')
      clearDownloadScansTable()
    }).finally(() => {
      $downloadScansModal.removeClass('loading')
    })
  }

  $(document).on("click", ".generate_report", function () {
    browser.windows.create({
      type: "popup",
      url: browser.runtime.getURL("/ptk/browser/report.html?sast_report"),
    });
  });

  $(document).on("click", ".save_scan", function () {
    const $loader = $(this).find('.loader')
    requestSastProjectsAndShowModal($loader)
  });

  $(document).on("click", ".run_scan_runtime", function () {
    controller
      .init()
      .then(async function (result) {
        if (!result?.activeTab?.url) {
          $("#result_header").text("Error");
          $("#result_message").text(
            "Active tab not set. Reload required tab to activate tracking."
          );
          $("#result_dialog").modal("show");
          return false;
        }

        let h = new URL(result.activeTab.url).host;
        $("#scan_host").text(h);
        // $('#scan_domains').text(h)
        window._ptkSastReloadWarningClosed = false;
        let contentReady = true;
        contentReady = await rutils.pingContentScript(result.activeTab.tabId, { timeoutMs: 700 });
        if (!window._ptkSastReloadWarningClosed) {
          $("#ptk_scan_reload_warning").toggle(!contentReady);
        }

        $("#run_scan_dlg")
          .modal({
            allowMultiple: true,
            onApprove: function () {
              if (!contentReady) {
                $("#ptk_scan_reload_warning").show();
                return false;
              }
              let scanStrategy = $("#sast-scan-strategy").val();
              if (scanStrategy === undefined || scanStrategy === null || scanStrategy === '') {
                scanStrategy = 0;
              }
              const pagesRaw = $("#sast_pages").val() || "";
              const pages = String(pagesRaw)
                .split(/[\n,]+/)
                .map((entry) => entry.trim())
                .filter(Boolean);
              controller
                .runBackgroundScan(result.activeTab.tabId, h, scanStrategy, pages)
                .then(function (result) {
                  resetSastLiveState(result);
                  changeView(result);
                }).catch(e => e)
            },
          })
          .modal("show");
        $('#sast_scans_form .question')
          .popup({
            inline: true,
            hoverable: true,
            delay: {
              show: 300,
              hide: 800
            }
          })
      })
      .catch((e) => e);

    return false;
  });

  $(document).on("click", "#ptk_scan_reload_warning_close_sast", function () {
    window._ptkSastReloadWarningClosed = true;
    $("#ptk_scan_reload_warning").hide();
  });

  $(document).on("click", ".stop_scan_runtime", function () {
    controller.stopBackgroundScan().then(function (result) {
      changeView(result);
      bindScanResult(result);
    }).catch(e => e)
    return false;
  });

  $(".settings.rattacker").on("click", function () {
    $("#settings").modal("show");
  });

  $(".cloud_download_scans").on("click", function () {
    $downloadScansModal.modal("show");
    loadSastDownloadProjects();
  });

  $(document).on("click", ".download_scan_by_id", function () {
    $(this).parent().find(".loader").addClass("active");
    let scanId = $(this).attr("data-scan-id");
    controller.downloadScanById(scanId).then(function (result) {
      if (result?.success === false) {
        const message = result?.json?.message || result?.message || 'Unable to download scan'
        showSastResultModal('Error', message)
        return
      }
      let info = { isScanRunning: false, scanResult: result };
      changeView(info);
      if (hasRenderableSastData(info.scanResult)) {
        bindScanResult(info);
      }
      $("#download_scans").modal("hide");
    }).catch(err => {
      showSastResultModal('Error', err?.message || 'Unable to download scan')
    });
  });

  $(".import_export").on("click", function () {
    controller.init().then(function (result) {
      if (!hasRenderableSastData(result.scanResult)) {
        $(".export_scan_btn").addClass("disabled");
      } else {
        $(".export_scan_btn").removeClass("disabled");
      }
      hideExportProgress();
      $("#import_export_dlg").modal("show");
    }).catch(e => e)
  });

  const $exportScanBtn = $(".export_scan_btn");
  const $scanExportProgress = $("#scan_export_progress");
  const $scanExportProgressBar = $("#scan_export_progress_bar");
  const $scanExportProgressText = $("#scan_export_progress_text");
  let exportInProgress = false;

  function setExportProgress(percent, text) {
    const safePercent = Math.max(0, Math.min(100, Number(percent) || 0));
    $scanExportProgress.show();
    $scanExportProgressBar.css("width", `${safePercent}%`);
    $scanExportProgressText.text(text || `Exporting... ${safePercent}%`);
  }

  function hideExportProgress() {
    $scanExportProgress.hide();
    $scanExportProgressBar.css("width", "0%");
    $scanExportProgressText.text("Preparing export...");
  }

  function updateExportProgressFromChunk(event) {
    const phase = String(event?.phase || "");
    const completed = Number(event?.completed || 0);
    const total = Number(event?.total || 0);
    if (phase === "chunk_start") {
      setExportProgress(15, total > 1 ? `Downloading export chunks... 0/${total}` : "Preparing download...");
      return;
    }
    if (phase === "chunk_download") {
      const percent = total > 0 ? Math.floor((completed / total) * 100) : 0;
      setExportProgress(percent, `Downloading export chunks... ${completed}/${total}`);
      return;
    }
    if (phase === "done") {
      setExportProgress(100, "Export complete.");
    }
  }

  $(".export_scan_btn").on("click", function () {
    if (exportInProgress) return;
    exportInProgress = true;
    $exportScanBtn.addClass("disabled loading");
    setExportProgress(5, "Preparing export payload...");

    controller.exportScanResult().then(async function (scanResult) {
      if (scanResult?.exportMode === "chunked") {
        setExportProgress(10, "Preparing chunked download...");
        await downloadScanExportResult(controller, scanResult, "PTK_SAST_scan.json", {
          onProgress: updateExportProgressFromChunk
        });
      } else if (scanResult && hasRenderableSastData(scanResult)) {
        setExportProgress(60, "Compressing export payload...");
        await downloadScanExportResult(controller, scanResult, "PTK_SAST_scan.json", {
          onProgress: updateExportProgressFromChunk
        });
      } else {
        hideExportProgress();
        showSastResultModal('Error', 'Nothing to export yet.')
      }
    }).catch(err => {
      hideExportProgress();
      showSastResultModal('Error', err?.message || 'Unable to export scan')
    }).finally(() => {
      exportInProgress = false;
      $exportScanBtn.removeClass("disabled loading");
      setTimeout(() => {
        if (!exportInProgress) hideExportProgress();
      }, 800);
    });
  });

  $(".import_scan_file_btn").on("click", function (e) {
    $("#import_scan_file_input").trigger("click");
    e.stopPropagation();
    e.preventDefault();
  });

  $("#import_scan_file_input").on("change", function (e) {
    e.stopPropagation();
    e.preventDefault();
    let file = $("#import_scan_file_input").prop("files")[0];
    loadFile(file);
    $("#import_scan_file_input").val(null);
  });

  async function loadFile(file) {
    try {
      const text = await readScanFileText(file);
      controller
        .save(text)
        .then((result) => {
          changeView(result);
          if (hasRenderableSastData(result.scanResult)) {
            bindScanResult(result);
          }
          $("#import_export_dlg").modal("hide");
        })
        .catch((e) => {
          $("#result_message").text("Could not import SAST scan");
          $("#result_dialog").modal("show");
        });
    } catch (e) {
      $("#result_message").text("Could not import SAST scan");
      $("#result_dialog").modal("show");
    }
  }

  $(".import_scan_text_btn").on("click", function () {
    let scan = $("#import_scan_json").val();
    controller
      .save(scan)
      .then((result) => {
        changeView(result);
        if (hasRenderableSastData(result.scanResult)) {
          bindScanResult(result);
        }
        $("#import_export_dlg").modal("hide");
      })
      .catch((e) => {
        $("#result_message").text("Could not import SAST scan");
        $("#result_dialog").modal("show");
      });
  });

  $(document).on("click", ".delete_scan_by_id", function () {
    let scanId = $(this).attr("data-scan-id");
    let scanHost = $(this).attr("data-scan-host");
    $("#scan_hostname").val("");
    $("#scan_delete_message").text("");
    $("#delete_scan_dlg")
      .modal({
        allowMultiple: true,
        onApprove: function () {
          if ($("#scan_hostname").val() == scanHost) {
            return controller.deleteScanById(scanId).then(function (result) {
              $(".cloud_download_scans").trigger("click");
              //console.log(result)
              return true;
            });
          } else {
            $("#scan_delete_message").text(
              "Type scan hostname to confirm delete"
            );
            return false;
          }
        },
      })
      .modal("show");
  });

  $(document).on("click", ".reset", function () {
    $("#request_info").html("");
    $("#attacks_info").html("");
    $("#discovery_info").html("");
    clearSastRequestFilter();
    $(".generate_report").hide();
    $(".save_scan").hide();
    //$('.exchange').hide()

    hideRunningForm();
    showWelcomeForm();
    controller.reset().then(function (result) {
      triggerSastStatsEvent(result.scanResult);
      if (Array.isArray(result?.default_modules) && result.default_modules.length) {
        bindModules(result);
      }
    });
  });

  $(".send_rbuilder").on("click", function () {
    let request = $("#raw_request").val().trim();
    window.location.href =
      "rbuilder.html?rawRequest=" +
      decoder.base64_encode(encodeURIComponent(JSON.stringify(request)));
    return false;
  });

  $(document).on("click", "#sast_result_tabs .item", function () {
    const nextView = $(this).attr("data-view") || "findings";
    setSastView(nextView);
  });

  $("#sast_view_findings_button").on("click", function () {
    setSastScope("finding");
  });

  $("#sast_view_hints_button").on("click", function () {
    setSastScope("hint");
  });

  $(document).on("click", "#request_info .filter.icon", function (e) {
    e.stopPropagation();
    const file = $(this).closest(".title.short_message_text").attr("data-file");
    toggleSastRequestFilter(file);
  });

  $(document).on("click", "#request_info .title.short_message_text", function (e) {
    if ($(e.target).closest(".filter.icon").length) {
      return;
    }
    const file = $(this).attr("data-file");
    toggleSastRequestFilter(file);
  });
  setSastView("findings");
  initRuleFilterDropdown();

  $(document).on("click", ".btn_stacktrace", function () {
    let el = $(this).parent().find(".content.stacktrace");
    if (this.textContent.trim().startsWith('Show')) {
      this.textContent = "Hide";
      $(el).show();
    } else {
      $(this).parent().find(".content.stacktrace").hide();
      this.textContent = "Show code and recommendation";
    }
  });

  $(document).on("click", ".close.icon.stacktrace", function () {
    $(this).parent().hide();
    $(this).parent().parent().find(".btn_stacktrace").text("Show code and recommendation");
  });

  $(document).on("click", ".sast-trace-toggle", function (e) {
    e.preventDefault();
    const $toggle = $(this);
    let $wrapper = $toggle.closest(".sast-trace");
    if (!$wrapper.length) {
      $wrapper = $toggle.nextAll(".sast-trace").first();
    }
    if (!$wrapper.length) return;
    const expanded = $wrapper.attr("data-expanded") === "true";
    const next = !expanded;
    $wrapper.attr("data-expanded", next ? "true" : "false");
    $toggle.text(next ? "Hide full trace" : "Show full trace");
    $toggle.attr("aria-expanded", next ? "true" : "false");
  });

  $(document).on("click", ".sast-discovery-details-toggle", function (e) {
    e.preventDefault();
    const $toggle = $(this);
    const $content = $toggle.closest(".sast-discovery-item").find(".sast-discovery-details-content").first();
    if (!$content.length) return;
    const isVisible = $content.is(":visible");
    if (isVisible) {
      $content.slideUp(120);
      $toggle.attr("data-visible", "false").text("Details");
    } else {
      $content.slideDown(120);
      $toggle.attr("data-visible", "true").text("Hide details");
    }
  });

  $(document).on("click", ".sast-discovery-open-rbuilder", function (e) {
    e.preventDefault();
    const encodedRequest = $(this).attr("data-raw-request") || "";
    if (!encodedRequest) return;
    window.location.href = `rbuilder.html?rawRequest=${encodedRequest}`;
  });

  $(document).on("bind_stats", function (e, scanResult) {
    if (scanResult?.stats) {
      rutils.bindStats(scanResult.stats, "sast");
      updateSastScopeUI();
    }
    return false;
  });

  $.fn.selectRange = function (start, end) {
    var e = document.getElementById($(this).attr("id")); // I don't know why... but $(this) don't want to work today :-/
    if (!e) return;
    else if (e.setSelectionRange) {
      e.focus();
      e.setSelectionRange(start, end);
    } /* WebKit */ else if (e.createTextRange) {
      var range = e.createTextRange();
      range.collapse(true);
      range.moveEnd("character", end);
      range.moveStart("character", start);
      range.select();
    } /* IE */ else if (e.selectionStart) {
      e.selectionStart = start;
      e.selectionEnd = end;
    }
  };

  controller.init().then(function (result) {
    const initCount = Array.isArray(result?.scanResult?.findings) ? result.scanResult.findings.length : 0;
    changeView(result);
    if (result.isScanRunning) {
      showRunningForm(result);
      if (hasRenderableSastData(result.scanResult)) {
        bindScanResult(result);
      }
      if (result.progress) {
        scheduleSastProgressUpdate({ message: "Scan running", progress: result.progress });
      }
    } else if (hasRenderableSastData(result.scanResult)) {
      bindScanResult(result);
    } else if (Array.isArray(result?.default_modules) && result.default_modules.length) {
      bindModules(result);
      showWelcomeForm();
    } else {
      showWelcomeForm();
    }
  }).catch(() => { })
});

function showWelcomeForm() {
  setSastPageLoader(false);
  $("#main").hide();
  $("#welcome_message").show();
  $("#run_scan_bg_control").show();
}

function hideWelcomeForm() {
  $("#welcome_message").hide();
  $("#main").show();
}

function showRunningForm(result) {
  setSastPageLoader(false);
  $("#main").show();
  $("#scanning_url").text(result.scanResult.host);
  $(".scan_info").show();
  $("#stop_scan_bg_control").show();
}

function hideRunningForm() {
  $("#scanning_url").text("");
  $(".scan_info").hide();
  $("#stop_scan_bg_control").hide();
}

function showScanForm(result) {
  setSastPageLoader(false);
  $("#main").show();
  $("#run_scan_bg_control").show();
}

function hideScanForm() {
  $("#run_scan_bg_control").hide();
}

function setSastPageLoader(show) {
  const $loader = $("#sast_page_loader");
  if (!$loader.length) return;
  $loader.toggle(!!show);
}

function changeView(result) {
  $("#init_loader").removeClass("active");
  if (result.isScanRunning) {
    hideWelcomeForm();
    hideScanForm();
    showRunningForm(result);
  } else if (hasRenderableSastData(result.scanResult)) {
    hideWelcomeForm();
    hideRunningForm(result);
    showScanForm();
  } else {
    hideRunningForm();
    hideScanForm();
    showWelcomeForm();
  }
}

$(document).on("click", ".attack_details", function () {
  $('.metadata .item').tab()
  const indexAttr = $(this).attr("data-index")
  const index = typeof indexAttr !== "undefined" ? Number(indexAttr) : NaN
  const attack = getSastAttackItem(index)
  if (!attack) return
  rutils.bindAttackDetails_SAST($(this), attack)
  $('.metadata .item').tab('change tab', 'first');
})

function bindRequest(info) {
  const raw = info === undefined || info === null ? "" : String(info);
  const escapedRaw = ptk_utils.escapeHtml(raw);
  const canon = typeof rutils?.canonicalizeSastFileId === "function"
    ? rutils.canonicalizeSastFileId(raw)
    : raw;
  const escapedCanon = ptk_utils.escapeHtml(canon || "");
  let item = `
                <div>
                <div class="title short_message_text" data-file="${escapedRaw}" data-file-canon="${escapedCanon}" style="overflow-y: hidden;height: 34px;background-color: #eeeeee;margin:1px 0 0 0;cursor:pointer; position: relative">
                    ${escapedRaw}<i class="filter icon" style="float:right; position: absolute; top: 3px; right: -3px;" title="Filter by request"></i>
                    
                </div>
                `
  return item
}

function resetSastLiveState(result = null) {
  controller.scanResult = result || { scanResult: normalizeScanResult({}), isScanRunning: false };
  controller.scanViewModel = normalizeScanResult(result?.scanResult || {});
  controller.sastAttackItems = [];
  controller._sastIsScanning = typeof result?.isScanRunning === "boolean" ? result.isScanRunning : false;
  controller._sastKnownFilesCanon = new Set();
  controller._sastKnownRuleIds = new Set();
  controller._sastRuleCounts = new Map();
  controller._sastKnownFindingFingerprints = new Set();
  SAST_DELTA_QUEUE.length = 0;
  if (sastFlushTimer) {
    clearTimeout(sastFlushTimer);
    sastFlushTimer = null;
  }
  resetSastProgressRender({ hide: true });
  $("#request_info").html("");
  $("#attacks_info").html("");
  $("#discovery_info").html("");
  triggerSastStatsEvent(result?.scanResult || {});
}

function appendSastRequestIfNeeded(file) {
  if (!file) return;
  if (/^inline[-‐]/i.test(String(file))) return;
  const canon = typeof rutils?.canonicalizeSastFileId === "function"
    ? rutils.canonicalizeSastFileId(file)
    : String(file);
  if (!canon) return;
  if (!(controller._sastKnownFilesCanon instanceof Set)) {
    controller._sastKnownFilesCanon = new Set();
  }
  if (controller._sastKnownFilesCanon.has(canon)) return;
  controller._sastKnownFilesCanon.add(canon);
  $("#request_info").append(bindRequest(file));
}

function bindScanResult(result) {
  if (!result.scanResult) return;
  const raw = result.scanResult || {};
  const vm = raw.__normalized ? raw : normalizeScanResult(raw);
  controller.scanResult = result;
  controller.scanViewModel = vm;
  const scanning = typeof result.isScanRunning === "boolean"
    ? result.isScanRunning
    : !!controller._sastIsScanning;
  controller._sastIsScanning = scanning;
  if (!scanning) {
    resetSastProgressRender({ hide: true });
  }
  $(".generate_report").show();
  $(".save_scan").show();
  $("#request_info").html("");
  $("#attacks_info").html("");
  $("#discovery_info").html("");
  hideWelcomeForm();
  SAST_DELTA_QUEUE.length = 0;
  if (sastFlushTimer) {
    clearTimeout(sastFlushTimer);
    sastFlushTimer = null;
  }
  controller._sastKnownFilesCanon = new Set();
  controller._sastKnownRuleIds = new Set();
  controller._sastRuleCounts = new Map();
  controller._sastKnownFindingFingerprints = new Set();

  const findings = Array.isArray(vm.findings) ? vm.findings : [];
  const legacyItems = normalizeLegacySastItems(raw.items);
  let files = Array.isArray(raw.files) ? raw.files.slice() : [];
  if (findings.length) {
    const fileCandidates = findings
      .map((finding) => finding?.location?.file)
      .filter(Boolean);
    files = files.concat(fileCandidates);
  } else if (!files.length && legacyItems.length) {
    files = legacyItems
      .map((item) => item?.codeFile || item?.file || null)
      .filter(Boolean);
  }
  files = files
    .filter((item, i, ar) => ar.indexOf(item) === i)
    .filter((item) => item && !/^inline/i.test(item));

  const requestMarkup = [];
  files.forEach((file) => {
    if (!file) return;
    const canon = typeof rutils?.canonicalizeSastFileId === "function"
      ? rutils.canonicalizeSastFileId(file)
      : file;
    if (canon) controller._sastKnownFilesCanon.add(canon);
    requestMarkup.push(bindRequest(file));
  });
  $("#request_info").html(requestMarkup.join(""));

  let attackItems = [];
  if (findings.length) {
    findings.forEach((finding) => {
      const fingerprint = getSastFindingFingerprint(finding);
      if (fingerprint) controller._sastKnownFindingFingerprints.add(fingerprint);
    });
    attackItems = findings
      .map((finding, index) => buildSastItemFromFinding(finding, index))
      .filter(Boolean);
  } else if (legacyItems.length) {
    attackItems = legacyItems.map((item, index) => {
      if (item) {
        item.requestId = index;
      }
      return item;
    }).filter(Boolean);
  }
  controller.sastAttackItems = attackItems;
  renderSastDiscovery(vm);

  const bucketMarkup = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: []
  };
  attackItems.forEach((item, index) => {
    if (!item) return;
    const attackHtml = rutils.bindSASTAttack(item, index);
    const bucket = getSastBucket(item);
    bucketMarkup[bucket].push(attackHtml);
  });
  $("#attacks_info").html([
    `<div class="sast_bucket${bucketMarkup.critical.length ? " has-items" : ""}" data-bucket="critical">${bucketMarkup.critical.join("")}</div>`,
    `<div class="sast_bucket${bucketMarkup.high.length ? " has-items" : ""}" data-bucket="high">${bucketMarkup.high.join("")}</div>`,
    `<div class="sast_bucket${bucketMarkup.medium.length ? " has-items" : ""}" data-bucket="medium">${bucketMarkup.medium.join("")}</div>`,
    `<div class="sast_bucket${bucketMarkup.low.length ? " has-items" : ""}" data-bucket="low">${bucketMarkup.low.join("")}</div>`,
    `<div class="sast_bucket${bucketMarkup.info.length ? " has-items" : ""}" data-bucket="info">${bucketMarkup.info.join("")}</div>`
  ].join(""));

  const deferWork = () => {
    if (!scanning) {
      resetSastProgressRender({ hide: true });
    } else if (result.progress) {
      scheduleSastProgressUpdate({ message: "Scan running", progress: result.progress });
    }
    // Keep bucket ordering; avoid DOM re-sorts.
    if (findings.length) {
      populateSastRuleFilterOptionsFromFindings(findings);
    } else {
      populateSastRuleFilterOptions(attackItems);
    }
    triggerSastStatsEvent(raw, vm);
    const discoveryCount = countSastDiscoveryItems(vm);
    if (!attackItems.length && discoveryCount > 0) {
      setSastView(firstPopulatedSastDiscoveryGroup(vm) || "routes");
    } else if (discoveryCount === 0 && isSastDiscoveryView(sastFilterState.view)) {
      setSastView("findings");
    } else {
      setSastView(sastFilterState.view);
    }
    refreshSastFiltersAfterRender();
  };
  if (typeof requestAnimationFrame === "function") {
    requestAnimationFrame(deferWork);
  } else {
    setTimeout(deferWork, 0);
  }
}

function bindModules(result) {
  const modules = Array.isArray(result?.default_modules)
    ? result.default_modules
    : (Array.isArray(result) ? result : []);
  const rows = [];
  modules.forEach((mod) => {
    if (!mod) return;
    const moduleName = mod.name || mod.metadata?.name || mod.metadata?.module_name || mod.id || "Module";
    const defaultSeverity = formatSeverityLabel(mod.metadata?.severity);
    const rules = Array.isArray(mod.rules) ? mod.rules : [];
    if (rules.length) {
      rules.forEach((rule) => {
        const ruleName = rule?.name || rule?.metadata?.name || rule?.id || "Rule";
        const severity = formatSeverityLabel(rule?.severity || rule?.metadata?.severity || defaultSeverity || "info");
        rows.push([ruleName, moduleName, severity]);
      });
    } else {
      rows.push([moduleName, moduleName, defaultSeverity]);
    }
  });
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  rows.sort((a, b) => {
    const leftSeverity = String(a[2] || "").toLowerCase();
    const rightSeverity = String(b[2] || "").toLowerCase();
    const severityDiff =
      (severityOrder[leftSeverity] ?? 99) - (severityOrder[rightSeverity] ?? 99);
    if (severityDiff !== 0) return severityDiff;
    const nameLeft = (a[0] || "").toLowerCase();
    const nameRight = (b[0] || "").toLowerCase();
    return nameLeft.localeCompare(nameRight);
  });
  bindTable("#sast_rules_table", { data: rows });
}

function bindAttackProgress(message) {
  scheduleSastProgressUpdate(message?.info || null);
}

function normalizeSastProgressPayload(payload) {
  if (!payload) return {};
  if (typeof payload === "string") return { message: payload };
  if (typeof payload === "object") return payload;
  return {};
}

function shortProgressLabel(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  try {
    const url = new URL(text);
    if (url.pathname && url.pathname !== "/") {
      const leaf = url.pathname.split("/").filter(Boolean).pop();
      if (leaf) return leaf;
    }
    return url.host || text;
  } catch {
    const normalized = text.replace(/^inline[-‐]/i, "inline ");
    if (normalized.length <= 80) return normalized;
    return `${normalized.slice(0, 77)}...`;
  }
}

function formatSastElapsed(valueMs) {
  const elapsedMs = Math.max(0, Number(valueMs || 0));
  const totalSeconds = Math.floor(elapsedMs / 1000);
  const mins = String(Math.floor(totalSeconds / 60)).padStart(2, "0");
  const secs = String(totalSeconds % 60).padStart(2, "0");
  return `${mins}:${secs}`;
}

function formatSastProgressDetails(progress) {
  if (!progress || typeof progress !== "object") {
    return "Files 0/0 | Module 0/0 | Findings 0 | Hints 0 | Discovery 0";
  }
  const totalFiles = Math.max(0, Number(progress.totalFiles || 0));
  const completedFiles = Math.max(0, Number(progress.completedFiles || 0));
  const currentFileIndex = Math.max(0, Number(progress.currentFileIndex || 0));
  const filesDone = Math.max(completedFiles, currentFileIndex ? currentFileIndex - 1 : completedFiles);
  const totalModules = Math.max(0, Number(progress.totalModules || 0));
  const completedModules = Math.max(0, Number(progress.completedModules || 0));
  const currentModuleIndex = Math.max(0, Number(progress.currentModuleIndex || 0));
  const moduleDone = Math.max(completedModules, currentModuleIndex ? currentModuleIndex - 1 : completedModules);
  const findings = Math.max(0, Number(progress.findings || 0));
  const hints = Math.max(0, Number(progress.hints || 0));
  const discovery = Math.max(0, Number(progress.discovery || 0));
  return `Files ${filesDone}/${totalFiles} | Module ${moduleDone}/${totalModules} | Findings ${findings} | Hints ${hints} | Discovery ${discovery}`;
}

function composeSastProgressStatus(info = {}) {
  const progress = info.progress && typeof info.progress === "object" ? info.progress : {};
  const phase = String(progress.phase || "").toLowerCase();
  const currentFile = shortProgressLabel(progress.currentFile || info.file || "");
  const currentModule = shortProgressLabel(progress.currentModule || info.moduleName || "");
  const baseMessage = String(info.message || "").trim();
  const elapsedSuffix = Number(progress.elapsedMs || 0) > 0
    ? ` (${formatSastElapsed(progress.elapsedMs)})`
    : "";
  const moduleIndex = Math.max(0, Number(progress.currentModuleIndex || 0));
  const totalModules = Math.max(0, Number(progress.totalModules || 0));
  const moduleSuffix = moduleIndex > 0 && totalModules > 0
    ? ` [${moduleIndex}/${totalModules}]`
    : "";

  if (phase === "module" && currentModule) {
    return currentFile
      ? `Running ${currentModule}${moduleSuffix} on ${currentFile}${elapsedSuffix}`
      : `Running ${currentModule}${moduleSuffix}${elapsedSuffix}`;
  }
  if (phase === "module_complete" && currentModule) {
    return currentFile
      ? `Completed ${currentModule}${moduleSuffix} on ${currentFile}${elapsedSuffix}`
      : `Completed ${currentModule}${moduleSuffix}${elapsedSuffix}`;
  }
  if ((phase === "file" || phase === "file_complete") && currentFile) {
    if (phase === "file_complete") {
      return `Finished ${currentFile}${elapsedSuffix}`;
    }
    if (totalModules > 0) {
      const completedModules = Math.max(0, Number(progress.completedModules || 0));
      return `Analyzing ${currentFile} [${completedModules}/${totalModules}]${elapsedSuffix}`;
    }
    return `Analyzing ${currentFile}${elapsedSuffix}`;
  }
  if (phase === "summary") {
    return baseMessage || "Scan completed";
  }
  if (phase === "waiting") {
    return baseMessage || "Waiting for next page activity";
  }
  if (baseMessage && currentFile) {
    return `${baseMessage}: ${currentFile}${elapsedSuffix}`;
  }
  if (baseMessage && currentModule) {
    return `${baseMessage}: ${currentModule}${moduleSuffix}${elapsedSuffix}`;
  }
  return `${baseMessage || "Scan running"}${elapsedSuffix}`;
}

function scheduleSastProgressUpdate(payload) {
  const info = normalizeSastProgressPayload(payload);
  if (info.progress && typeof info.progress === "object") {
    SAST_PROGRESS_RENDER.details = info.progress;
  }
  SAST_PROGRESS_RENDER.metrics = formatSastProgressDetails(SAST_PROGRESS_RENDER.details);
  SAST_PROGRESS_RENDER.status = composeSastProgressStatus(info);
  SAST_PROGRESS_RENDER.lastActivityAt = Date.now();
  SAST_PROGRESS_RENDER.scanning = true;
  if (SAST_PROGRESS_RENDER.timer) return;
  SAST_PROGRESS_RENDER.timer = setTimeout(() => {
    SAST_PROGRESS_RENDER.timer = null;
    $("#progress_scan_metrics").text(SAST_PROGRESS_RENDER.metrics || "Files 0/0 | Module 0/0 | Findings 0 | Hints 0 | Discovery 0");
    $("#progress_attack_name").text(SAST_PROGRESS_RENDER.status || "Scan running");
    $("#progress_message").show();
  }, SAST_PROGRESS_RENDER.flushMs);
}

function applySastFindingsDelta(message) {
  const findings = Array.isArray(message?.findings) ? message.findings : [];
  if (!findings.length) return;
  if (!controller.scanViewModel) {
    if (message?.scanResult) {
      bindScanResult({ scanResult: message.scanResult, isScanRunning: message?.isScanRunning });
    } else {
      const raw = controller?.scanResult?.scanResult || {};
      if (raw && typeof raw === "object" && (Array.isArray(raw.findings) || Array.isArray(raw.files))) {
        bindScanResult({
          scanResult: raw,
          isScanRunning: typeof message?.isScanRunning === "boolean"
            ? message.isScanRunning
            : !!controller._sastIsScanning,
          progress: message?.progress || null
        });
      } else {
        controller.scanViewModel = normalizeScanResult(raw);
        if (!Array.isArray(controller.scanViewModel.findings)) {
          controller.scanViewModel.findings = [];
        }
        if (!Array.isArray(controller.sastAttackItems)) {
          controller.sastAttackItems = [];
        }
      }
    }
  }
  if (!Array.isArray(controller.scanViewModel.findings)) {
    controller.scanViewModel.findings = [];
  }
  if (!Array.isArray(controller.sastAttackItems)) {
    controller.sastAttackItems = [];
  }
  controller._sastIsScanning = typeof message?.isScanRunning === "boolean"
    ? message.isScanRunning
    : controller._sastIsScanning;
  findings.forEach((finding) => {
    if (!finding) return;
    SAST_DELTA_QUEUE.push(finding);
  });
  if (!sastFlushTimer) {
    sastFlushTimer = setTimeout(flushSastQueue, SAST_FLUSH_INTERVAL_MS);
  }
  if (message?.stats) {
    rutils.bindStats(message.stats, "sast");
    updateSastScopeUI();
  }
  if (message?.progress) {
    scheduleSastProgressUpdate({ message: "Analyzing code", progress: message.progress });
  }
}

function flushSastQueue() {
  sastFlushTimer = null;
  if (!SAST_DELTA_QUEUE.length) return;
  const batch = SAST_DELTA_QUEUE.splice(0, SAST_DELTA_QUEUE.length);
  const attackMarkup = [];
  const requestMarkup = [];
  const knownFiles = controller._sastKnownFilesCanon || new Set();
  const knownFingerprints = controller._sastKnownFindingFingerprints || new Set();

  batch.forEach((finding) => {
    if (!finding) return;
    const fingerprint = getSastFindingFingerprint(finding);
    if (fingerprint && knownFingerprints.has(fingerprint)) {
      return;
    }
    if (fingerprint) {
      knownFingerprints.add(fingerprint);
    }
    controller.scanViewModel.findings.push(finding);
    const file = finding?.location?.file || finding?.pageUrl || null;
    if (file) {
      const canon = typeof rutils?.canonicalizeSastFileId === "function"
        ? rutils.canonicalizeSastFileId(file)
        : file;
      if (canon && !knownFiles.has(canon)) {
        knownFiles.add(canon);
        requestMarkup.push(bindRequest(file));
      }
    }
    const index = controller.sastAttackItems.length;
    const item = buildSastItemFromFinding(finding, index);
    if (!item) return;
    controller.sastAttackItems.push(item);
    const attackHtml = rutils.bindSASTAttack(item, index);
    const bucket = getSastBucket(item);
    attackMarkup.push({ html: attackHtml, bucket });
  });

  controller._sastKnownFilesCanon = knownFiles;
  controller._sastKnownFindingFingerprints = knownFingerprints;
  if (requestMarkup.length) {
    $("#request_info").append(requestMarkup.join(""));
  }
  if (attackMarkup.length) {
    ensureSastBuckets();
    attackMarkup.forEach(({ html, bucket }) => {
      appendSastToBucket(html, bucket);
    });
  }
  populateSastRuleFilterOptions(controller.sastAttackItems);
  refreshSastFiltersAfterRender();
  triggerSastStatsEvent(controller?.scanResult?.scanResult || controller.scanViewModel || {}, controller.scanViewModel);
}

function handleStructuredSastMessage(type, payload, scanResult) {
  const data = payload || {};
  const sessionRunning = typeof data?.isScanRunning === "boolean"
    ? data.isScanRunning
    : (typeof data?.progress?.isRunning === "boolean" ? data.progress.isRunning : null);
  if (type === "scan:start") {
    bindAttackProgress({ info: { message: "Scan started", progress: data.progress } });
    controller._sastIsScanning = true;
    showRunningForm({ scanResult: controller.scanResult?.scanResult || { host: data.host || "" } });
    hideScanForm();
    hideWelcomeForm();
  }
  if (type === "file:start") {
    bindAttackProgress({ info: { message: "Analyzing file", file: data.file || "", progress: data.progress } });
    appendSastRequestIfNeeded(data.file || "");
  }
  if (type === "file:end") {
    bindAttackProgress({ info: { message: "Finished file", file: data.file || "", progress: data.progress } });
  }
  if (type === "module:start") {
    bindAttackProgress({ info: { message: "Running module", file: data.moduleName || data.moduleId || "", progress: data.progress } });
  }
  if (type === "module:end") {
    bindAttackProgress({ info: { message: "Completed module", file: data.moduleName || data.moduleId || "", progress: data.progress } });
  }
  if (type === "scan:summary") {
    bindAttackProgress({
      info: {
        message: sessionRunning
          ? "Waiting for next page activity"
          : `Scan completed (${data.totalFindings || 0} findings)`,
        progress: data.progress
      }
    });
    controller._sastIsScanning = sessionRunning === null ? controller._sastIsScanning : sessionRunning;
    const finalFindings = Array.isArray(scanResult?.findings) ? scanResult.findings.length : 0;
    const renderedFindings = Array.isArray(controller?.scanViewModel?.findings) ? controller.scanViewModel.findings.length : 0;
    const finalFiles = Array.isArray(scanResult?.files)
      ? scanResult.files.filter((file) => file && !/^inline[-‐]/i.test(String(file))).length
      : 0;
    const renderedFiles = controller?._sastKnownFilesCanon instanceof Set
      ? controller._sastKnownFilesCanon.size
      : $("#request_info .title.short_message_text").length;
    if (scanResult && (finalFindings > renderedFindings || finalFiles > renderedFiles)) {
      bindScanResult({
        scanResult: scanResult,
        isScanRunning: controller._sastIsScanning,
        progress: data.progress
      });
      return;
    }
  }
  if (type === "scan:error") {
    bindAttackProgress({ info: { message: "Scan error", file: data.error || "", progress: data.progress } });
    controller._sastIsScanning = false;
  }
  if (scanResult && !controller.scanViewModel) {
    bindScanResult({
      scanResult: scanResult,
      isScanRunning: controller._sastIsScanning,
      progress: data.progress
    });
  }
}

function canonicalizeRequestFilterValue(raw) {
  if (raw === undefined || raw === null) return "";
  const value = String(raw);
  if (typeof rutils?.canonicalizeSastFileId === "function") {
    return rutils.canonicalizeSastFileId(value);
  }
  return value.trim();
}

function toggleSastRequestFilter(raw) {
  const canon = canonicalizeRequestFilterValue(raw);
  if (!canon) {
    clearSastRequestFilter();
    return;
  }
  if (sastFilterState.fileCanon === canon) {
    clearSastRequestFilter();
    return;
  }
  sastFilterState.fileCanon = canon;
  updateRequestFilterUI();
  applySastFilters();
}

function clearSastRequestFilter() {
  sastFilterState.fileCanon = null;
  updateRequestFilterUI();
  applySastFilters();
}

function setSastRuleFilter(ruleKey, syncDropdown = true) {
  const normalized =
    ruleKey && ruleKey !== RULE_FILTER_ALL_VALUE ? String(ruleKey) : null;
  sastFilterState.ruleKey = normalized && normalized.length ? normalized : null;
  if (syncDropdown) {
    syncRuleDropdownSelection(sastFilterState.ruleKey);
  }
  applySastFilters();
}

function setSastScope(scope) {
  const normalized = normalizeSastScope(scope);
  const changed = sastFilterState.scope !== normalized;
  sastFilterState.scope = normalized;
  updateSastScopeUI();
  if (Array.isArray(controller?.scanViewModel?.findings) && controller.scanViewModel.findings.length) {
    populateSastRuleFilterOptionsFromFindings(controller.scanViewModel.findings);
  } else {
    populateSastRuleFilterOptions(controller.sastAttackItems);
  }
  if (sastFilterState.view !== "findings") {
    setSastView("findings");
    return;
  }
  if (changed) {
    triggerSastStatsEvent(controller?.scanResult?.scanResult || controller.scanViewModel || {}, controller.scanViewModel);
  }
  applySastFilters();
}

function setSastView(view) {
  const scanResult = controller?.scanViewModel || controller?.scanResult?.scanResult || null;
  const normalized = normalizeSastViewKey(view, scanResult);
  sastFilterState.view = normalized;
  const showFindingsFilters = normalized === "findings";
  $("#sast_result_tabs .item").removeClass("active");
  if (!showFindingsFilters) {
    $(`#sast_result_tabs .item[data-view="${normalized}"]`).addClass("active");
  }
  updateSastScopeUI();
  $("#sast_findings_filters .rule-filter-wrap").toggle(showFindingsFilters);
  $("#attacks_info").toggle(showFindingsFilters);
  $("#discovery_info").toggle(!showFindingsFilters);
  applySastFilters();
}

function populateSastRuleFilterOptions(items) {
  const map = new Map();
  const scope = normalizeSastScope(sastFilterState.scope);
  const collection = Array.isArray(items)
    ? items
    : (items && typeof items === "object"
      ? Object.keys(items).map((key) => items[key])
      : []);
  if (collection.length) {
    collection.forEach((item) => {
      if (!item) return;
      if (!sastItemMatchesScope(item, scope)) return;
      const rawId = item?.metadata?.id || item?.module_metadata?.id || "";
      if (!rawId) return;
      const key = encodeURIComponent(rawId);
      const entry =
        map.get(key) ||
        {
          label: item?.metadata?.name || item?.module_metadata?.name || rawId,
          count: 0,
        };
      entry.count += 1;
      map.set(key, entry);
    });
  }
  controller._sastKnownRuleIds = new Set(map.keys());
  controller._sastRuleCounts = map;
  renderSastRuleFilterMenu(map);
}

function populateSastRuleFilterOptionsFromFindings(findings) {
  const map = new Map();
  const scope = normalizeSastScope(sastFilterState.scope);
  if (Array.isArray(findings)) {
    findings.forEach((finding) => {
      if (!finding) return;
      if (!sastFindingMatchesScope(finding, scope)) return;
      const rawId = finding.ruleId || finding.id || "";
      if (!rawId) return;
      const key = encodeURIComponent(rawId);
      const entry =
        map.get(key) ||
        {
          label: finding.ruleName || finding.moduleName || rawId,
          count: 0,
        };
      entry.count += 1;
      map.set(key, entry);
    });
  }
  controller._sastKnownRuleIds = new Set(map.keys());
  controller._sastRuleCounts = map;
  renderSastRuleFilterMenu(map);
}

function renderSastRuleFilterMenu(map) {
  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  const menuItems = [
    `<div class="item" data-value="${RULE_FILTER_ALL_VALUE}">All rules</div>`,
  ];
  map.forEach((entry, key) => {
    const label = entry?.label || key;
    const count = typeof entry?.count === "number" ? entry.count : 0;
    menuItems.push(
      `<div class="item" data-value="${key}"><span class="description">${ptk_utils.escapeHtml(
        String(count)
      )}</span>${ptk_utils.escapeHtml(label)}</div>`
    );
  });
  $dropdown.find(".menu").html(menuItems.join(""));
  $dropdown.dropdown("refresh");
  if (sastFilterState.ruleKey && !map.has(sastFilterState.ruleKey)) {
    sastFilterState.ruleKey = null;
  }
  syncRuleDropdownSelection(sastFilterState.ruleKey);
  $dropdown.toggleClass("disabled", map.size === 0);
}

function applySastFilters() {
  if (isSastDiscoveryView(sastFilterState.view)) {
    const groupKey = sastFilterState.view;
    const $panels = $("#discovery_info .sast-discovery-panel");
    $panels.hide();
    const $panel = $panels.filter(`[data-discovery-group="${groupKey}"]`);
    $panel.show();
    const $items = $panel.find(".sast-discovery-item");
    const fileCanon = sastFilterState.fileCanon;
    let $visible = $items;
    if (fileCanon) {
      $visible = $items.filter(function () {
        return sastDiscoveryMatchesFile($(this), fileCanon);
      });
    }
    $items.hide();
    $visible.show();
    return;
  }

  const $attacks = $("#attacks_info .attack_info");
  if (!$attacks.length) {
    updateSastStatsFromCollection($attacks);
    return;
  }

  const fileCanon = sastFilterState.fileCanon;
  let $subset = $attacks.filter(function () {
    return sastScopeMatchesKind($(this).attr("data-finding-kind") || "finding", sastFilterState.scope);
  });
  if (fileCanon) {
    $subset = $subset.filter(function () {
      return sastAttackMatchesFile($(this), fileCanon);
    });
  }

  if (sastFilterState.ruleKey) {
    const ruleKey = sastFilterState.ruleKey;
    $subset = $subset.filter(function () {
      return ($(this).attr("data-rule-key") || "") === ruleKey;
    });
  }

  $attacks.removeClass("sast-filter-visible");
  $attacks.hide();
  const $visible = $subset;
  $visible.addClass("sast-filter-visible");
  $visible.show();
  updateSastBucketVisibility();
  updateSastStatsFromCollection($visible);
}

function updateSastBucketVisibility() {
  const $buckets = $("#attacks_info .sast_bucket");
  if (!$buckets.length) return;
  $buckets.each(function () {
    const $bucket = $(this);
    const hasVisibleItems = $bucket.find(".attack_info.sast-filter-visible").length > 0;
    $bucket.toggleClass("has-visible-items", hasVisibleItems);
    $bucket.toggle(hasVisibleItems);
  });
}

function initRuleFilterDropdown() {
  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  $dropdown.dropdown({
    onChange(value) {
      if (isRuleDropdownSyncing) return;
      setSastRuleFilter(value || RULE_FILTER_ALL_VALUE, false);
    },
  });
  syncRuleDropdownSelection(sastFilterState.ruleKey);
}

function getRuleFilterDropdown() {
  return $(RULE_FILTER_DROPDOWN_SELECTOR);
}

function syncRuleDropdownSelection(ruleKey) {
  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  const value = ruleKey || RULE_FILTER_ALL_VALUE;
  const current = $dropdown.dropdown("get value");
  if (current === value) return;
  isRuleDropdownSyncing = true;
  $dropdown.dropdown("set selected", value);
  isRuleDropdownSyncing = false;
}

function ensureSastRequestFilterIsValid() {
  if (!sastFilterState.fileCanon) return;
  const exists = $("#request_info .title.short_message_text").filter(function () {
    return ($(this).attr("data-file-canon") || "") === sastFilterState.fileCanon;
  }).length > 0;
  if (!exists) {
    sastFilterState.fileCanon = null;
  }
}

function ensureSastRuleFilterIsValid() {
  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  if (!sastFilterState.ruleKey) {
    syncRuleDropdownSelection(null);
    return;
  }
  const exists =
    $dropdown.find(`.item[data-value="${sastFilterState.ruleKey}"]`).length > 0;
  if (!exists) {
    sastFilterState.ruleKey = null;
    syncRuleDropdownSelection(null);
  }
}

function updateRequestFilterUI() {
  const current = sastFilterState.fileCanon;
  $("#request_info .title.short_message_text").each(function () {
    const matches = current && ($(this).attr("data-file-canon") || "") === current;
    $(this).toggleClass("active", !!matches);
    $(this).find(".filter.icon").toggleClass("primary", !!matches);
  });
}

function refreshSastFiltersAfterRender() {
  ensureSastRequestFilterIsValid();
  ensureSastRuleFilterIsValid();
  updateRequestFilterUI();
  applySastFilters();
}

function sastAttackMatchesFile($el, fileCanon) {
  if (!fileCanon) return true;
  const attrs = [
    "data-source-canon",
    "data-sink-canon",
    "data-source-base",
    "data-sink-base",
  ];
  for (const attr of attrs) {
    const value = $el.attr(attr);
    if (value && canonMatchesRequest(value, fileCanon)) {
      return true;
    }
  }
  return false;
}

function sastDiscoveryMatchesFile($el, fileCanon) {
  if (!fileCanon) return true;
  const attrs = [
    "data-source-canon",
    "data-page-canon",
  ];
  for (const attr of attrs) {
    const value = $el.attr(attr);
    const candidates = String(value || "").split(/\n+/).map((entry) => entry.trim()).filter(Boolean);
    if (candidates.some((candidate) => canonMatchesRequest(candidate, fileCanon))) {
      return true;
    }
  }
  return false;
}

function updateSastStatsFromCollection($collection) {
  const stats = collectSastStats($collection);
  rutils.bindStats(stats, "sast");
  updateSastScopeUI();
}

function collectSastStats($collection) {
  const stats = {
    findingsCount: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    rulesCount: 0,
  };
  if (!$collection || !$collection.length) {
    return stats;
  }

  const rules = new Set();
  stats.findingsCount = $collection.length;
  $collection.each(function () {
    const severity = ($(this).attr("data-severity") || "").toLowerCase();
    const ruleId = ($(this).attr("data-rule-id") || "").trim();
    if (severity === "critical") stats.critical++;
    else if (severity === "high") stats.high++;
    else if (severity === "medium") stats.medium++;
    else if (severity === "low") stats.low++;
    else if (severity === "info" || severity === "informational") stats.info++;
    if (ruleId) {
      rules.add(ruleId);
    }
  });
  stats.rulesCount = rules.size;
  return stats;
}

function canonMatchesRequest(value, fileCanon) {
  if (!value || !fileCanon) return false;
  const trimmed = String(value).trim();
  if (!trimmed) return false;
  if (trimmed === fileCanon) return true;
  if (trimmed.startsWith(fileCanon + " ::")) return true;
  const split = trimmed.split(/\s+::\s+/);
  if (split.length > 1 && split[0].trim() === fileCanon) return true;
  if (typeof rutils?.canonicalizeSastFileId === "function") {
    const aligned = rutils.canonicalizeSastFileId(trimmed);
    if (aligned && aligned === fileCanon) return true;
  }
  return false;
}

////////////////////////////////////
/* Chrome runtime events handlers */
////////////////////////////////////

browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message.channel == "ptk_background2popup_sast") {
    const { type, payload, scanResult, info } = message;
    switch (type) {
      case "scan:start":
      case "file:start":
      case "file:end":
      case "module:start":
      case "module:end":
      case "scan:summary":
      case "scan:error":
        handleStructuredSastMessage(type, payload || message, scanResult);
        break;
    case "progress":
      bindAttackProgress({ info: info || payload });
      if (!controller._sastIsScanning) {
        controller._sastIsScanning = true;
        showRunningForm({ scanResult: controller.scanResult?.scanResult || { host: info?.host || "" } });
        hideScanForm();
        hideWelcomeForm();
      }
      break;
      case "findings_delta":
        applySastFindingsDelta(message);
        break;
      case "update findings":
        bindScanResult(message);
        break;
      default:
        break;
    }
  }
})
