function formatSeverityLabel(value) {
  if (!value) return "Info";
  const lower = String(value).toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

function normalizeSastFindingKind(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "hint" || normalized === "artifact") return normalized;
  return "finding";
}

export function buildSastItemFromFinding(finding, index = 0) {
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
