"use strict";

// reporting.js — finding builders for pattern and taint rules

/* ───────────────────────────────────── Utilities ───────────────────────────────────── */

export function exprToShortLabel(node, { code, max = 120 } = {}) {
  if (!node) return "";
  try {
    switch (node.type) {
      case "Literal":
        return typeof node.value === "string"
          ? JSON.stringify(node.value).slice(0, max)
          : String(node.value);
      case "Identifier":
        return node.name;
      case "MemberExpression": {
        const parts = [];
        let cur = node;
        while (cur && cur.type === "MemberExpression") {
          if (cur.property) {
            if (cur.property.type === "Identifier") parts.unshift(cur.property.name);
            else if (cur.property.type === "Literal") parts.unshift(String(cur.property.value));
          }
          cur = cur.object;
        }
        if (cur) {
          if (cur.type === "Identifier") parts.unshift(cur.name);
          else if (cur.type === "ThisExpression") parts.unshift("this");
        }
        return parts.join(".");
      }
      case "CallExpression":
        return exprToShortLabel(node.callee, { code, max });
      case "AssignmentExpression":
        return exprToShortLabel(node.left, { code, max });
      default:
        return (code && node.loc)
          ? getCodeSnippet(code, node.loc, { maxContextLines: 0 })
          : (node.type || "Node");
    }
  } catch {
    return "";
  }
}

function _nodeFileDisplay(node) {
  if (!node) return null;
  return node.sourceFileFull || node.sourceFile || (node.loc && node.loc.sourceFile) || null;
}

function extractPath(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const parts = [];
    let cur = node;
    while (cur && cur.type === "MemberExpression") {
      if (cur.property) {
        if (cur.property.type === "Identifier") parts.unshift(cur.property.name);
        else if (cur.property.type === "Literal") parts.unshift(String(cur.property.value));
      }
      cur = cur.object;
    }
    if (cur) {
      if (cur.type === "Identifier") parts.unshift(cur.name);
      else if (cur.type === "ThisExpression") parts.unshift("this");
    }
    return parts.join(".");
  }
  return "";
}

function normalizePathLabel(label) {
  if (!label || typeof label !== "string") return null;
  const trimmed = label.trim();
  if (!trimmed) return null;
  if (/^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/.test(trimmed)) return trimmed;
  return null;
}

function extractAngularQueryParamPath(label) {
  if (!label || typeof label !== "string") return null;
  const direct = label.match(/queryParams\.([A-Za-z_$][\w$]*)/);
  if (direct) return `queryParams.${direct[1]}`;
  const bracket = label.match(/queryParams\\[['"]([^'"]+)['"]\\]/);
  if (bracket) return `queryParams.${bracket[1]}`;
  const getter = label.match(/queryParams\\.get\\(['"]([^'"]+)['"]\\)/);
  if (getter) return `queryParams.${getter[1]}`;
  return null;
}

function _nodeType(node) {
  return node?.type || "Node";
}

// Compact snippet extractor (consistent with sastEngine helpers)
export function getCodeSnippet(code, loc, opts = {}) {
  if (!code || !loc || !loc.start || !loc.end) return "";
  const cfg = {
    maxContextLines: 2,
    maxCharsPerLine: 220,
    ...opts,
  };
  const lines = String(code).split(/\r?\n/);
  const sLine = Math.max(1, loc.start.line | 0) - 1;
  const eLine = Math.max(1, loc.end.line | 0) - 1;
  const start = Math.max(0, sLine - cfg.maxContextLines);
  const end = Math.min(lines.length - 1, eLine + cfg.maxContextLines);

  const windowLines = lines.slice(start, end + 1).map((ln) => {
    let out = String(ln);
    if (cfg.maxCharsPerLine && out.length > cfg.maxCharsPerLine) {
      const colStart = Math.max(0, (loc.start.column | 0) - Math.floor(cfg.maxCharsPerLine / 2));
      const colEnd = colStart + cfg.maxCharsPerLine;
      out = out.slice(colStart, colEnd) + "…";
    }
    return out.replace(/\s+$/u, "");
  });

  while (windowLines.length && !windowLines[0].trim()) windowLines.shift();
  while (windowLines.length && !windowLines[windowLines.length - 1].trim()) windowLines.pop();

  const indents = windowLines
    .filter((line) => /\S/.test(line))
    .map((line) => {
      const match = line.match(/^([ \t]*)/);
      return match ? match[0].replace(/\t/g, "  ").length : 0;
    });
  const baseIndent = indents.length ? Math.min(...indents) : 0;
  const snippet = windowLines.map((line) => {
    if (!baseIndent) return line;
    let idx = 0;
    let removed = 0;
    while (idx < line.length && removed < baseIndent) {
      const ch = line[idx];
      if (ch === "\t") removed += 2;
      else if (ch === " ") removed += 1;
      else break;
      idx += 1;
    }
    return line.slice(idx);
  }).join("\n");

  return snippet.trimEnd();
}

function resolveCodeForFile(codeByFile, key, fallbackFile) {
  if (!codeByFile) return "";
  if (key && codeByFile[key]) return codeByFile[key];
  if (key) {
    const noQ = String(key).split(/[?#]/)[0];
    const base = noQ.split("/").pop();
    if (codeByFile[noQ]) return codeByFile[noQ];
    if (codeByFile[base]) return codeByFile[base];
  }
  if (fallbackFile && codeByFile[fallbackFile]) return codeByFile[fallbackFile];
  const first = Object.keys(codeByFile)[0];
  return first ? codeByFile[first] : "";
}

function literalStringValue(node) {
  if (!node) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && (node.expressions || []).length === 0) {
    return (node.quasis || []).map((q) => q?.value?.cooked || "").join("");
  }
  return null;
}

function memberPropName(node) {
  if (!node || node.type !== "MemberExpression") return null;
  if (node.computed) {
    if (node.property?.type === "Literal") return String(node.property.value);
    if (node.property?.type === "Identifier") return node.property.name;
    return null;
  }
  if (node.property?.type === "Identifier") return node.property.name;
  if (node.property?.type === "Literal") return String(node.property.value);
  return null;
}

function _pickSinkLabel({ sinkNode, code }) {
  if (!sinkNode) return "";
  if (sinkNode.type === "CallExpression") {
    const innerHtmlArg = literalStringValue(sinkNode.arguments?.[0]);
    const setPropArg = literalStringValue(sinkNode.arguments?.[1]);
    const calleeName = extractPath(sinkNode.callee) || "";
    if (/ɵɵproperty$/.test(calleeName) && /^(innerHTML|outerHTML)$/.test(innerHtmlArg || "")) {
      return `${calleeName}('${innerHtmlArg}', ...)`;
    }
    if (/setProperty$/.test(calleeName) && /^(innerHTML|outerHTML)$/.test(setPropArg || "")) {
      return `${calleeName}('${setPropArg}', ...)`;
    }
    const cal = sinkNode.callee;
    const label = extractPath(cal);
    return label || exprToShortLabel(cal, { code });
  }
  if (sinkNode.type === "AssignmentExpression") {
    return extractPath(sinkNode.left) || exprToShortLabel(sinkNode.left, { code });
  }
  return exprToShortLabel(sinkNode, { code });
}

function _pickSourceLabel({ sourceNode, sinkNode, code }) {
  if (sourceNode?._ptkOriginLabel) return sourceNode._ptkOriginLabel;
  if (sourceNode) return exprToShortLabel(sourceNode, { code });
  if (sinkNode?.type === "AssignmentExpression") return exprToShortLabel(sinkNode.right, { code });
  return exprToShortLabel(sinkNode, { code });
}

function urlSearchParamsHintFromTrace(trace) {
  if (!Array.isArray(trace)) return null;
  for (const step of trace) {
    const node = step?.node;
    if (!node || node.type !== "CallExpression") continue;
    const callee = node.callee;
    if (!callee || callee.type !== "MemberExpression") continue;
    const prop = memberPropName(callee);
    if (!prop || prop.toLowerCase() !== "get") continue;
    const obj = callee.object;
    if (obj?._ptkIsURLSearchParams && obj._ptkUrlSourceHint) {
      return obj._ptkUrlSourceHint;
    }
  }
  return null;
}

function paramNameFromTrace(trace) {
  if (!Array.isArray(trace)) return null;
  for (const step of trace) {
    const node = step?.node;
    if (!node || node.type !== "CallExpression") continue;
    const callee = node.callee;
    if (!callee || callee.type !== "MemberExpression") continue;
    const prop = memberPropName(callee);
    if (!prop || prop.toLowerCase() !== "get") continue;
    const arg = node.arguments?.[0];
    const name = literalStringValue(arg);
    if (name) return name;
  }
  return null;
}

function clampConfidence(value) {
  if (!Number.isFinite(value)) return null;
  return Math.min(100, Math.max(0, Math.round(value)));
}

function normalizeContextList(value) {
  if (Array.isArray(value)) {
    return value
      .map((entry) => String(entry || "").trim().toLowerCase())
      .filter(Boolean);
  }
  if (typeof value === "string" && value.trim()) {
    return [value.trim().toLowerCase()];
  }
  return [];
}

function primaryContext(value) {
  const contexts = normalizeContextList(value);
  return contexts[0] || null;
}

function resolveFindingKind({ ruleMeta = {}, moduleMeta = {} } = {}) {
  const raw = ruleMeta.findingKind ?? moduleMeta.findingKind ?? "finding";
  const normalized = String(raw || "finding").trim().toLowerCase();
  if (normalized === "hint" || normalized === "artifact") return normalized;
  return "finding";
}

function sourceTierFromOrigin(origin = null) {
  const kind = String(origin?.kind || "").trim().toLowerCase();
  switch (kind) {
    case "webmsg":
      return "webmsg";
    case "network":
      return "network";
    case "url":
      return "url";
    case "cookie":
      return "cookie";
    case "storage":
      return "storage";
    case "dom-input":
      return "dom-input";
    default:
      return kind || "code";
  }
}

function sourceTierScore(sourceTier) {
  switch (String(sourceTier || "").toLowerCase()) {
    case "webmsg":
      return 8;
    case "network":
      return 7;
    case "url":
      return 6;
    case "cookie":
      return 4;
    case "storage":
      return 3;
    case "dom-input":
      return 2;
    default:
      return 0;
  }
}

function sinkContextScore(sinkContext) {
  switch (String(sinkContext || "").toLowerCase()) {
    case "script":
      return 12;
    case "html":
      return 8;
    case "url":
      return 5;
    case "network":
      return 3;
    case "selector":
      return -2;
    case "css":
      return -1;
    case "storage":
      return -2;
    case "generic":
      return -6;
    default:
      return 0;
  }
}

function findingKindScore(findingKind) {
  switch (String(findingKind || "").toLowerCase()) {
    case "hint":
      return -20;
    case "artifact":
      return -30;
    default:
      return 0;
  }
}

function bundleLikePenalty(fileHints = []) {
  const files = Array.isArray(fileHints) ? fileHints.filter(Boolean).map((entry) => String(entry)) : [];
  if (!files.length) return { delta: 0, signal: null };
  const looksBundled = files.some((file) => (
    /(^|\/)(vendor|runtime|polyfills)([-.\w]*)\.js([?#]|$)/i.test(file) ||
    /\.min\.js([?#]|$)/i.test(file)
  ));
  if (!looksBundled) return { delta: 0, signal: null };
  return { delta: -16, signal: "bundle_like:-16" };
}

function resolveSastConfidence({ mode, ruleMeta = {}, moduleMeta = {}, trace = [], findingKind = "finding", sinkContext = null, sourceTier = null, fileHints = [] }) {
  const signals = [];
  const ruleOverride = ruleMeta.confidence ?? ruleMeta.confidenceDefault;
  const moduleOverride = moduleMeta.confidenceDefault;
  if (Number.isFinite(ruleOverride)) {
    const value = clampConfidence(ruleOverride);
    return { confidence: value, signals: [`override:rule:${value}`] };
  }
  if (Number.isFinite(moduleOverride)) {
    const value = clampConfidence(moduleOverride);
    return { confidence: value, signals: [`override:module:${value}`] };
  }

  let confidence = mode === "taint" ? 78 : 58;
  signals.push(`base:${mode}:${confidence}`);

  const kindDelta = findingKindScore(findingKind);
  if (kindDelta) {
    confidence += kindDelta;
    signals.push(`finding_kind:${findingKind}:${kindDelta}`);
  }

  const sinkDelta = sinkContextScore(sinkContext);
  if (sinkDelta) {
    confidence += sinkDelta;
    signals.push(`sink_context:${sinkContext}:${sinkDelta > 0 ? "+" : ""}${sinkDelta}`);
  }

  const sourceDelta = sourceTierScore(sourceTier);
  if (sourceDelta) {
    confidence += sourceDelta;
    signals.push(`source_tier:${sourceTier}:+${sourceDelta}`);
  }

  const traceLen = Array.isArray(trace) ? trace.length : 0;
  if (mode === "taint") {
    if (traceLen === 0) {
      confidence -= 10;
      signals.push("trace:none:-10");
    } else if (traceLen <= 3) {
      confidence += 10;
      signals.push(`trace_len:${traceLen}:+10`);
    } else if (traceLen >= 8) {
      confidence -= 10;
      signals.push(`trace_len:${traceLen}:-10`);
    }
  } else {
    const bundlePenalty = bundleLikePenalty(fileHints);
    if (bundlePenalty.delta) {
      confidence += bundlePenalty.delta;
      signals.push(bundlePenalty.signal);
    }
  }

  return { confidence: clampConfidence(confidence), signals };
}

/* ───────────────────────────────────── Pattern findings ───────────────────────────────────── */

export function reportPatternFinding({ rule, context, matchNode, valueNode, extras = {} }) {
  const codeByFile = (context && context.codeByFile) || {};
  const fallbackFile = context?.codeFile || Object.keys(codeByFile)[0] || "(inline-script)";
  const preferredSourceFile = _nodeFileDisplay(valueNode || matchNode);
  const preferredSinkFile = _nodeFileDisplay(matchNode);
  const sourceFileKey = preferredSourceFile || fallbackFile;
  const sinkFileKey = preferredSinkFile || sourceFileKey;
  const sourceCode = resolveCodeForFile(codeByFile, sourceFileKey, fallbackFile);
  const sinkCode = resolveCodeForFile(codeByFile, sinkFileKey, fallbackFile);

  const sinkLabel = _pickSinkLabel({ sinkNode: matchNode, code: sinkCode });
  const sourceLoc = (valueNode || matchNode)?.loc;
  const sinkLoc = (matchNode?.type === "AssignmentExpression" ? matchNode.left : matchNode)?.loc;

  let sourceSnippet = sourceLoc ? getCodeSnippet(sourceCode, sourceLoc) : "";
  if (!sourceSnippet) {
    sourceSnippet = exprToShortLabel(valueNode || matchNode, { code: sourceCode }) || "";
  }
  let sinkSnippet = sinkLoc ? getCodeSnippet(sinkCode, sinkLoc) : "";
  if (!sinkSnippet) {
    sinkSnippet = exprToShortLabel(matchNode, { code: sinkCode }) || "";
  }

  const sourceInfo = { codeFile: sourceFileKey, snippet: sourceSnippet };
  const sinkInfo = { codeFile: sinkFileKey, snippet: sinkSnippet };
  const sourcePath = extractPath(valueNode || matchNode) || normalizePathLabel(sourceInfo.snippet);

  const ruleMeta = rule?.metadata || {};
  const moduleMeta = extras.module_metadata || {};
  const findingKind = resolveFindingKind({ ruleMeta, moduleMeta });
  const { confidence, signals } = resolveSastConfidence({
    mode: "pattern",
    ruleMeta,
    moduleMeta,
    trace: [],
    findingKind,
    fileHints: [sourceFileKey, sinkFileKey]
  });

  const out = {
    async: false,
    codeFile: sourceFileKey,
    codeSnippet: `Source context:\n${sourceInfo.snippet}\n\nSink context:\n${sinkInfo.snippet}`,
    file: "",
    metadata: rule.metadata,
    module_metadata: extras.module_metadata || {},
    nodeType: _nodeType(matchNode),
    sink: {
      kind: matchNode?.type === "CallExpression" ? "call" : (matchNode?.type === "AssignmentExpression" ? "assign" : "node"),
      label: sinkLabel,
      path: [],
      sinkFile: sinkFileKey,
      sinkFileFull: sinkFileKey,
      sinkLoc,
      sinkName: sinkLabel,
      sinkSnippet: sinkInfo.snippet,
    },
    source: {
      label: exprToShortLabel(valueNode || matchNode, { code: sourceCode }),
      path: sourcePath || null,
      sourceFile: sourceFileKey,
      sourceFileFull: sourceFileKey,
      sourceLoc,
      sourceName: exprToShortLabel(valueNode || matchNode, { code: sourceCode }),
      sourceSnippet: sourceInfo.snippet,
    },
    success: true,
    mode: "pattern",
    type: _nodeType(matchNode),
    findingKind,
    confidence,
    evidence: {
      sast: {
        confidenceSignals: signals,
        findingKind,
        sinkContext: primaryContext(ruleMeta.sinkContext || moduleMeta.sinkContext),
        sourceTier: null
      }
    }
  };

  if (valueNode) out.valueExpr = exprToShortLabel(valueNode, { code: sourceCode });
  return out;
}

/* ───────────────────────────────────── Taint findings ───────────────────────────────────── */

function traceFromPathKeys(pathKeys, graph) {
  if (!Array.isArray(pathKeys) || !graph) return [];
  const steps = [];
  for (let i = 0; i < pathKeys.length; i++) {
    const key = pathKeys[i];
    const [nodeIdStr] = String(key || "").split("|");
    const id = Number(nodeIdStr);
    if (!Number.isFinite(id)) continue;
    const node = graph.astNodeForId(id);
    if (!node) continue;
    const kind = i === 0 ? "source" : (i === pathKeys.length - 1 ? "sink" : "propagation");
    steps.push({ kind, node });
  }
  return steps;
}

function traceToSummaries(trace, codeByFile, fallbackFile) {
  if (!Array.isArray(trace) || !trace.length) return [];
  const summaries = [];
  for (const step of trace) {
    if (!step) continue;
    const node = step.node || null;
    const fileKey = _nodeFileDisplay(node) || fallbackFile || null;
    const code = fileKey ? resolveCodeForFile(codeByFile, fileKey, fallbackFile) : "";
    const label = node ? exprToShortLabel(node, { code }) : (step.label || "");
    const entry = {
      kind: step.kind || null,
      label: label || null,
      file: fileKey,
      loc: node?.loc || null
    };
    if (entry.kind || entry.label || entry.file || entry.loc) summaries.push(entry);
  }
  return summaries;
}

export function reportTaintFinding({ rule, context, sourceNode, sinkNode, taintTrace, extras = {} }) {
  const graph = extras.graph || null;
  if ((!taintTrace || !taintTrace.length) && Array.isArray(extras.pathKeys) && graph) {
    taintTrace = traceFromPathKeys(extras.pathKeys, graph);
    if (!sourceNode && taintTrace.length) sourceNode = taintTrace[0].node;
  }

  const codeByFile = (context && context.codeByFile) || {};
  const sinkKey = (sinkNode && sinkNode.sourceFile) || context?.codeFile || Object.keys(codeByFile)[0] || "(inline-script)";
  const sourceKey = (sourceNode && sourceNode.sourceFile) || sinkKey;

  const sinkCode = resolveCodeForFile(codeByFile, sinkKey, context?.codeFile);
  const sourceCode = resolveCodeForFile(codeByFile, sourceKey, context?.codeFile);
  const traceSummary = traceToSummaries(taintTrace, codeByFile, context?.codeFile);

  const isCall = sinkNode?.type === "CallExpression";
  const target = isCall ? sinkNode.callee : (sinkNode?.left || sinkNode);
  const sinkPath = extractPath(target);
  const sourcePath = extractPath(sourceNode || sinkNode);

  const sinkLabel = _pickSinkLabel({ sinkNode, code: sinkCode });
  let sourceLabel = _pickSourceLabel({ sourceNode, sinkNode, code: sourceCode });
  const ruleId = rule?.metadata?.id || "";
  const urlHint = urlSearchParamsHintFromTrace(taintTrace);
  const paramName = paramNameFromTrace(taintTrace);
  const isLocationLabel = /(^|\.)location\.(hash|search|href)$/.test(sourceLabel || "");
  const isDocumentUrlLabel = /(^|\.)document\.URL$/.test(sourceLabel || "");
  if (
    urlHint &&
    (ruleId === "dom-xss-taint" || ruleId === "dom-xss-taint-angular") &&
    (isLocationLabel || isDocumentUrlLabel)
  ) {
    sourceLabel = `URLSearchParams.get from ${urlHint}`;
  }

  const sourceLoc = (sourceNode || sinkNode)?.loc;
  const sinkLoc = (sinkNode?.type === "AssignmentExpression" ? sinkNode.left : sinkNode)?.loc;

  let sourceSnippet = sourceLoc ? getCodeSnippet(sourceCode, sourceLoc) : "";
  if (!sourceSnippet) {
    sourceSnippet = exprToShortLabel(sourceNode || sinkNode, { code: sourceCode }) || "";
  }
  let sinkSnippet = sinkLoc ? getCodeSnippet(sinkCode, sinkLoc) : "";
  if (!sinkSnippet) {
    sinkSnippet = exprToShortLabel(sinkNode, { code: sinkCode }) || "";
  }

  const sourceInfo = { codeFile: sourceKey, snippet: sourceSnippet };
  const sinkInfo = { codeFile: sinkKey, snippet: sinkSnippet };
  const sinkMeta = extras.sinkMeta || {};
  let sourcePathCandidate = sourcePath || normalizePathLabel(sourceLabel);
  if (!sourcePathCandidate) {
    const angularPath = extractAngularQueryParamPath(sourceLabel);
    if (angularPath) sourcePathCandidate = angularPath;
  }
  if (paramName && urlHint && (!sourcePathCandidate || !/searchparams|queryparams/i.test(sourcePathCandidate))) {
    sourcePathCandidate = `searchParams.${paramName}`;
  }

  const ruleMeta = rule?.metadata || {};
  const moduleMeta = extras.module_metadata || {};
  const findingKind = resolveFindingKind({ ruleMeta, moduleMeta });
  const sinkContext = primaryContext(sinkMeta.context || ruleMeta.sinkContext || moduleMeta.sinkContext);
  const sourceTier = sourceTierFromOrigin(extras.origin);
  const { confidence, signals } = resolveSastConfidence({
    mode: "taint",
    ruleMeta,
    moduleMeta,
    trace: taintTrace || [],
    findingKind,
    sinkContext,
    sourceTier,
    fileHints: [sourceKey, sinkKey]
  });

  return {
    async: false,
    codeFile: sinkKey,
    codeSnippet: `Source context:\n${sourceInfo.snippet}\n\nSink context:\n${sinkInfo.snippet}`,
    file: "",
    location: paramName ? { param: paramName } : undefined,
    metadata: rule.metadata,
    module_metadata: extras.module_metadata || {},
    nodeType: _nodeType(sinkNode),
    sink: {
      kind: isCall ? "call" : (sinkNode?.type === "AssignmentExpression" ? "assign" : "node"),
      label: sinkLabel,
      path: sinkPath ? sinkPath.split(".") : [],
      framework: sinkMeta.framework || null,
      api: sinkMeta.api || null,
      argIndex: typeof sinkMeta.argIndex === "number" ? sinkMeta.argIndex : null,
      sinkFile: sinkKey,
      sinkFileFull: sinkKey,
      sinkLoc,
      sinkName: sinkLabel,
      sinkSnippet: sinkInfo.snippet,
    },
    source: {
      label: sourceLabel,
      path: sourcePathCandidate || null,
      sourceFile: sourceKey,
      sourceFileFull: sourceKey,
      sourceLoc,
      sourceName: sourceLabel,
      sourceSnippet: sourceInfo.snippet,
    },
    success: true,
    mode: "taint",
    type: _nodeType(sinkNode),
    trace: traceSummary,
    findingKind,
    confidence,
    evidence: {
      sast: {
        confidenceSignals: signals,
        findingKind,
        sinkContext,
        sourceTier
      }
    }
  };
}
