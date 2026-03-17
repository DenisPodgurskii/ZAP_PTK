"use strict";

import { queryTaintForRule } from "./taint_propagation.js";
import { reportTaintFinding, reportPatternFinding, exprToShortLabel } from "./reporting.js";
import { compilePattern, calleeNameFromPattern, getEventHandlerSink, isDomSelectorCall } from "./_internals.js";

/* ────────────────────────────── Helpers ────────────────────────────── */

function _memberPropName(mem) {
  if (!mem || mem.type !== "MemberExpression" || mem.computed) return null;
  if (mem.property && mem.property.type === "Identifier") return mem.property.name;
  if (mem.property && mem.property.type === "Literal") return String(mem.property.value);
  return null;
}

function _isLocationExpression(node) {
  if (!node) return false;
  if (node.type === "Identifier" && typeof node.name === "string") {
    return node.name.toLowerCase() === "location";
  }
  if (node.type === "MemberExpression") {
    if (!node.computed && node.property && node.property.type === "Identifier") {
      if (node.property.name && node.property.name.toLowerCase() === "location") return true;
    }
    return _isLocationExpression(node.object);
  }
  return false;
}

function _guardScriptText(node) {
  if (!node || node.type !== "AssignmentExpression") return false;
  const left = node.left;
  if (!left || left.type !== "MemberExpression" || left.computed) return false;
  const prop = _memberPropName(left);
  if (prop !== "textContent" && prop !== "innerHTML") return false;
  const obj = left.object;
  if (!obj) return false;
  return !!obj._ptkIsScript;
}

function _guardExcludeLocation(node) {
  if (!node) return true;
  let target = null;
  if (node.type === "AssignmentExpression") {
    target = node.left && node.left.type === "MemberExpression" ? node.left.object : null;
  } else if (node.type === "CallExpression") {
    target = node.callee && node.callee.type === "MemberExpression" ? node.callee.object : null;
  } else if (node.type === "MemberExpression") {
    target = node.object || null;
  }
  if (!target) return true;
  return !_isLocationExpression(target);
}

function _applySinkGuard(kind, node) {
  if (!kind) return true;
  if (kind === "script_text") return _guardScriptText(node);
  if (kind === "exclude_location") return _guardExcludeLocation(node);
  if (kind === "dom_selector") return !!isDomSelectorCall(node);
  if (kind === "event_handler_string") return !!getEventHandlerSink(node);
  return true;
}

function _normalizeSpec(spec) {
  if (typeof spec === "string") return { id: spec, overlay: null };
  if (spec && typeof spec === "object" && spec.id) return { id: spec.id, overlay: spec.overlay || null };
  throw new Error("Invalid rule reference spec: " + JSON.stringify(spec));
}

function _collectPatterns(entry) {
  if (!entry || !entry.pattern) return [];
  return Array.isArray(entry.pattern) ? entry.pattern : [entry.pattern];
}

function _applyOverlayToPattern(pattern, overlay) {
  if (!overlay) return pattern;
  try {
    const merged = JSON.parse(JSON.stringify(pattern));
    if (overlay.args && merged.call && merged.call.args) {
      const args = overlay.args;
      for (const k of Object.keys(args)) {
        const idx = String(k);
        const ov = args[k];
        if (Array.isArray(merged.call.args)) {
          const i = Number(idx);
          if (!Number.isNaN(i) && merged.call.args[i]) {
            Object.assign(merged.call.args[i], ov);
          }
        } else if (merged.call.args && merged.call.args[idx]) {
          Object.assign(merged.call.args[idx], ov);
        }
      }
    }
    return merged;
  } catch {
    return pattern;
  }
}

function selectPayload(node, pattern) {
  if (!node) return null;
  if (node.type === "AssignmentExpression") return node.right || null;
  if (node.type === "CallExpression") {
    const idx = (pattern && pattern.call && typeof pattern.call.argIndex === "number") ? pattern.call.argIndex : (node.arguments.length - 1);
    return node.arguments[idx] || null;
  }
  if (node.type === "NewExpression") {
    const idx = (pattern && pattern.new && typeof pattern.new.argIndex === "number") ? pattern.new.argIndex : 0;
    return node.arguments[idx] || null;
  }
  return null;
}

function _pickFileFromNode(node, ctx) {
  return node?.sourceFile || node?.loc?.sourceFile || ctx?.codeFile || ctx?.file || null;
}

function _stringValueFromNode(node) {
  if (!node) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && (node.expressions || []).length === 0) {
    return (node.quasis || []).map((q) => q?.value?.cooked || "").join("");
  }
  return null;
}

function _normalizeRegexPattern(raw) {
  if (typeof raw !== "string") return raw;
  return raw.replace(/\u0008/g, "\\b");
}

function _normalizeContextList(value) {
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

function _inferSinkContext(id, meta) {
  const explicit = _normalizeContextList(meta?.context);
  if (explicit.length) return explicit;
  const sinkId = String(id || "").trim();
  if (!sinkId) return ["generic"];
  if (
    /^dom:(?:innerHTML|outerHTML|document_write|document_writeln|srcdoc|setAttribute_srcdoc|DOMParser_parseFromString_html|createContextualFragment|insertAdjacentHTML|template_innerHTML|angular_property_innerHTML|angular_renderer_setProperty|angular_bypassSecurityTrust)$/i.test(sinkId) ||
    /^jquery:(?:html|append|prepend|wrap|before_after|insert_ops)$/i.test(sinkId)
  ) {
    return ["html"];
  }
  if (
    /^(?:eval:constructor|js:(?:execscript|script_text|settimeout_code|setinterval_code|setimmediate_code|function_constructor_body)|ajax:jquery_globaleval|jquery:globaleval_getscript|dom:(?:event_handler_assign|setattribute_on|prop_on))$/i.test(sinkId)
  ) {
    return ["script"];
  }
  if (
    /^(?:dom:location_assign|dom:location_host|dom:location_hostname|window:open|ws:constructor_url|nav:|link:|form:action_assign|form:setattribute_action|jquery:(?:attr_href_set|prop_href_set)|ajax:(?:fetch_url|xhr_open_url)|net:webtransport_url)$/i.test(sinkId)
  ) {
    return ["url"];
  }
  if (
    /^(?:selector:|dom:Element_matches_selector|dom:Element_closest_selector|jquery:on_selector)/i.test(sinkId)
  ) {
    return ["selector"];
  }
  if (/^(?:dom:style_|dom:setattribute_style)/i.test(sinkId)) {
    return ["css"];
  }
  if (/^(?:storage:)/i.test(sinkId)) {
    return ["storage"];
  }
  if (/^(?:ajax:(?:xhr_set_header|request_header|fetch_options|xhr_open|xhr_send)|client:(?:json_parse|jquery_parsejson|sql_execute|xpath_evaluate))$/i.test(sinkId)) {
    return ["network"];
  }
  return ["generic"];
}

function _inferSinkCriticality(contexts) {
  const set = new Set(_normalizeContextList(contexts));
  if (set.has("script")) return "critical";
  if (set.has("html") || set.has("url")) return "high";
  if (set.has("selector") || set.has("css") || set.has("network") || set.has("storage")) return "medium";
  return "low";
}

/* ────────────────────────────── Rule compilation ────────────────────────────── */

function compileSinkMatchers(sinks, catalogs) {
  return sinks.map((spec) => {
    const { id, overlay } = _normalizeSpec(spec);
    const cat = catalogs.sinks[id];
    const pats = _collectPatterns(cat).map((p) => _applyOverlayToPattern(p, overlay));
    const compiled = pats.map((p) => {
      const match = compilePattern(p);
      return { pattern: p, match };
    });
    const guardKind = (overlay && overlay.guard) || (cat && cat.guard) || null;
    const sinkMeta = Object.assign({}, cat || {});
    sinkMeta.context = _inferSinkContext(id, cat);
    sinkMeta.criticality = sinkMeta.criticality || _inferSinkCriticality(sinkMeta.context);
    return {
      id,
      meta: sinkMeta,
      match: (node, ancestors) => {
        try {
          const hit = compiled.some((c) => c.match(node, ancestors));
          if (!hit) return false;
          if (guardKind && !_applySinkGuard(guardKind, node)) return false;
          return true;
        } catch {
          return false;
        }
      },
      payload: (node) => {
        if (guardKind && !_applySinkGuard(guardKind, node)) return null;
        const hit = compiled.find((c) => { try { return c.match(node, []); } catch { return false; } });
        const pat = hit ? hit.pattern : null;
        return selectPayload(node, pat);
      }
    };
  });
}

function buildTaintSemantics(rule, catalogs) {
  const ruleMeta = rule?.metadata || {};
  const sem = {
    sourceKinds: [],
    sanitizers: { ids: new Set(), callees: new Set(), contexts: new Map() },
    depthLimit: 200,
    originLimit: 5,
    taintKinds: new Set(),
  };
  const depthVal =
    typeof ruleMeta.depthLimit === "number" ? ruleMeta.depthLimit : rule?.depthLimit;
  if (typeof depthVal === "number" && depthVal > 0) {
    sem.depthLimit = depthVal;
  }
  const originVal =
    typeof ruleMeta.originLimit === "number" ? ruleMeta.originLimit : rule?.originLimit;
  if (typeof originVal === "number" && originVal > 0) {
    sem.originLimit = originVal;
  }

  const srcIds = Array.isArray(rule.sources) ? rule.sources : [];
  for (const id of srcIds) {
    const ent = catalogs.sources[id];
    if (ent && ent.origin_kind) sem.sourceKinds.push(ent.origin_kind);
  }

  const sanIds = Array.isArray(rule.sanitizers) ? rule.sanitizers : [];
  for (const sid of sanIds) {
    sem.sanitizers.ids.add(sid);
    const ent = catalogs.sanitizers[sid];
    if (!ent) continue;
    const contexts = _normalizeContextList(ent.context);
    sem.sanitizers.contexts.set(sid, contexts);
    for (const p of _collectPatterns(ent)) {
      const name = calleeNameFromPattern(p.call || p);
      if (name) sem.sanitizers.callees.add(name);
    }
  }
  const kindIds = Array.isArray(rule.taint_kinds) ? rule.taint_kinds : [];
  for (const kid of kindIds) {
    if (typeof kid === "string" && kid.trim()) {
      sem.taintKinds.add(kid.trim());
    }
  }
  return sem;
}

function compilePatternMatchers(rule, compileFn) {
  const typeOf = (pat) => pat && typeof pat === "object" ? Object.keys(pat)[0] : null;
  const out = [];
  if (!Array.isArray(rule.matches) || !compileFn) return out;
  for (const pat of rule.matches) {
    const nodeType = typeOf(pat);
    if (nodeType === "comment") {
      const spec = pat.comment || {};
      const re = spec.regex ? new RegExp(_normalizeRegexPattern(spec.regex), spec.flags || "") : null;
      out.push({
        id: "pattern",
        nodeType,
        matchComment: (comment) => {
          if (!comment || typeof comment.text !== "string" || !re) return false;
          return re.test(comment.text);
        }
      });
      continue;
    }
    if (nodeType === "string") {
      const spec = pat.string || {};
      const re = spec.regex ? new RegExp(_normalizeRegexPattern(spec.regex), spec.flags || "") : null;
      out.push({
        id: "pattern",
        nodeType,
        match: (node) => {
          if (!node || !re) return false;
          const value = _stringValueFromNode(node);
          return value != null && re.test(value);
        }
      });
      continue;
    }
    if (nodeType === "declarator") {
      const spec = pat.declarator || {};
      const leftSpec = spec.left || {};
      const rightSpec = spec.right || {};
      const re = leftSpec.identifierRegex
        ? new RegExp(_normalizeRegexPattern(leftSpec.identifierRegex), leftSpec.caseInsensitive ? "i" : "")
        : null;
      const requireString = !!rightSpec.isString;
      out.push({
        id: "pattern",
        nodeType,
        match: (node) => {
          if (!node || node.type !== "VariableDeclarator") return false;
          if (!node.id || node.id.type !== "Identifier") return false;
          if (re && !re.test(node.id.name)) return false;
          if (requireString) {
            const value = _stringValueFromNode(node.init);
            if (value == null) return false;
          }
          return true;
        }
      });
      continue;
    }
    try {
      const fn = compileFn(pat);
      if (typeof fn === "function") {
        out.push({
          id: "pattern",
          nodeType,
          match: (node, ancestors) => {
            if (nodeType === "call" && node.type !== "CallExpression") return false;
            if (nodeType === "assignment" && node.type !== "AssignmentExpression") return false;
            if (nodeType === "member" && node.type !== "MemberExpression") return false;
            if (nodeType === "new" && node.type !== "NewExpression") return false;
            return !!fn(node, ancestors);
          }
        });
      }
    } catch { /* ignore bad matcher */ }
  }
  return out;
}

/* ────────────────────────────── Module class ────────────────────────────── */

export class ptk_sast_module {
  constructor(moduleJson, opts = {}) {
    if (!moduleJson || typeof moduleJson !== "object") throw new Error("moduleJson required");
    this.raw = moduleJson;
    this.id = moduleJson.id;
    this.module_metadata = Object.assign({}, moduleJson.metadata, {
      id: this.id,
      name: moduleJson.name,
      vulnId: moduleJson.vulnId || moduleJson.metadata?.vulnId || this.id
    });
    this.maxFindings = (moduleJson.metadata && moduleJson.metadata.maxFindings != null)
      ? moduleJson.metadata.maxFindings
      : moduleJson.maxFindings;

    this._catalogs = {
      sources: opts.sources || {},
      sinks: opts.sinks || {},
      sanitizers: opts.sanitizers || {},
      propagators: opts.propagators || {},
    };

    this.rules = [];
    this._taintDedup = new Map();
    this._compileAllRules(moduleJson.rules || []);
  }

  _compileRule(rule) {
    const mode = rule.mode || rule.type || "pattern";
    const sinkSpecs = Array.isArray(rule.sinks) ? rule.sinks : [];
    const metadata = Object.assign({}, rule.metadata, { id: rule.id, rule_id: rule.id, name: rule.name, mode });
    if (metadata.severity == null && rule.severity != null) {
      metadata.severity = rule.severity;
    }
    if (metadata.findingKind == null && rule.findingKind != null) {
      metadata.findingKind = rule.findingKind;
    }
    const pack = {
      metadata,
      type: rule.type || "static",
      extras: rule.extras || {},
      sinks: [],
      matches: [],
      taintSemantics: null,
    };

    if (mode === "pattern") {
      pack.matches = compilePatternMatchers(rule, compilePattern);
    } else if (mode === "taint") {
      pack.sinks = compileSinkMatchers(sinkSpecs, this._catalogs);
      pack.taintSemantics = buildTaintSemantics(rule, this._catalogs);
      pack.sourceIds = Array.isArray(rule.sources) ? [...rule.sources] : [];
      pack.taintKinds = Array.isArray(rule.taint_kinds)
        ? rule.taint_kinds.filter((k) => typeof k === "string" && k.trim())
        : [];
    } else {
      pack.sourceIds = [];
      pack.taintKinds = [];
    }
    return pack;
  }

  _compileAllRules(rules) {
    this.rules = [];
    for (const r of rules) {
      const pack = this._compileRule(r);
      if (pack) this.rules.push(pack);
    }
  }

  _buildTraceFromPath(hit, graph, codeByFile, ctx) {
    const nodes = [];
    for (const key of hit.pathKeys || []) {
      const [idStr] = String(key || "").split("|");
      const id = Number(idStr);
      if (!Number.isFinite(id)) continue;
      const node = graph.astNodeForId(id);
      if (node && typeof node.type === "string") nodes.push(node);
    }
    if (!nodes.length && hit.originNode) nodes.push(hit.originNode);
    if (hit.sinkNode && (!nodes.length || nodes[nodes.length - 1] !== hit.sinkNode)) nodes.push(hit.sinkNode);

    const trace = [];
    const codeByFiles = ctx.codeByFile || {};
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      const loc = node?.loc?.start;
      const type = node?.type;
      const label = exprToShortLabel(node, { code: codeByFiles[_pickFileFromNode(node, ctx)] });
      const prev = trace[trace.length - 1];
      const sameLoc = prev && prev.node?.type === type &&
        prev.node?.loc?.start?.line === loc?.line &&
        prev.node?.loc?.start?.column === loc?.column;
      const sameLabel = prev && prev.label === label && prev.node?.type === type;
      if (sameLoc || sameLabel) {
        continue;
      }
      trace.push({
        kind: i === 0 ? "source" : (i === nodes.length - 1 ? "sink" : "propagation"),
        node,
        label
      });
    }
    return trace;
  }

  _emitPatternFinding(pack, node, ctx) {
    const mode = "pattern";
    const context = { ...ctx, module_metadata: this.module_metadata, metadata: pack.metadata, codeFile: ctx.codeFile || ctx.file, mode };
    const code = ctx.codeByFile?.[ctx.codeFile || ctx.file];
    const extras = { mode, sinkExact: exprToShortLabel(node, { code }), module_metadata: this.module_metadata };
    return reportPatternFinding({ rule: pack, context, matchNode: node, extras });
  }

  _emitTaintFinding(pack, node, ctx, hit, globalTaintCtx, trace, sinkMeta) {
    const mode = "taint";
    const context = { ...ctx, module_metadata: this.module_metadata, metadata: pack.metadata, codeFile: ctx.codeFile || ctx.file, mode };
    const code = ctx.codeByFile?.[ctx.codeFile || ctx.file];
    const extras = {
      mode,
      sinkExact: exprToShortLabel(node, { code }),
      sourceExact: hit.origin ? hit.origin.label : undefined,
      module_metadata: this.module_metadata,
      graph: globalTaintCtx?.graph || null,
      pathKeys: hit.pathKeys || [],
      sinkMeta: sinkMeta || null,
      origin: hit.origin || null
    };
    return reportTaintFinding({
      rule: pack,
      context,
      sourceNode: hit.originNode || hit.origin?.node || trace?.[0]?.node || node,
      sinkNode: node,
      taintTrace: trace,
      extras
    });
  }

  _dedupKey(pack, origin, sinkNode) {
    const sinkLoc = sinkNode?.loc?.start;
    const sinkFile = _pickFileFromNode(sinkNode) || "";
    const label = exprToShortLabel(sinkNode, {});
    const normOrigin = origin?.label || origin?.kind || "";
    const originFile = origin?.node?.sourceFileFull || origin?.node?.sourceFile || "";
    const originLoc = origin?.node?.loc?.start;
    return [
      pack?.metadata?.id || "",
      normOrigin,
      originFile,
      originLoc ? `${originLoc.line ?? ""}:${originLoc.column ?? ""}` : "",
      sinkFile,
      sinkLoc ? `${sinkLoc.line}:${sinkLoc.column}` : "",
      label || ""
    ].join("|");
  }

  removeDuplicates(issues) {
    const seen = new Set();
    return issues.filter((i) => {
      const loc = i?.sink?.sinkLoc?.start;
      const srcLoc = i.source?.sourceLoc?.start || i.source?.sourceLoc;
      const key = [
        i.metadata?.rule_id || i.metadata?.id || "",
        i.source?.label || i.source?.sourceName || "",
        i.source?.sourceFileFull || "",
        srcLoc ? srcLoc.line ?? "" : "",
        srcLoc ? srcLoc.column ?? "" : "",
        loc ? `${loc.line ?? ""}:${loc.column ?? ""}` : "",
        i.sink?.sinkFileFull || "",
        i.sink?.sinkName || ""
      ].join("|");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  runRules(masterAST, ctx, ancestorWalk, options = {}) {
    const findings = [];
    if (!masterAST || typeof ancestorWalk !== "function") return findings;

    const scanStrategy = options.scanStrategy ?? options.policy ?? 0;
    const globalTaintCtx = options.globalTaintCtx || null;
    this._taintDedup.clear();

    const packs = (this.rules || []).filter(Boolean);
    if (!packs.length) return findings;

    if (scanStrategy === 0) {
      const comments = Array.isArray(ctx?.comments) ? ctx.comments : [];
      if (comments.length) {
        for (const pack of packs) {
          if (pack.metadata.mode !== "pattern") continue;
          const commentMatchers = (pack.matches || []).filter((m) => m.nodeType === "comment" && typeof m.matchComment === "function");
          if (!commentMatchers.length) continue;
          for (const comment of comments) {
            for (const m of commentMatchers) {
              if (!m.matchComment(comment)) continue;
              const commentNode = {
                type: "Comment",
                loc: comment.loc,
                sourceFile: comment.sourceFile
              };
              const finding = this._emitPatternFinding(pack, commentNode, ctx);
              if (finding) findings.push(finding);
              if (findings.length >= (this.maxFindings || Infinity)) return findings;
            }
          }
        }
      }
    }

    const self = this;
    const processNode = (node, ancestors) => {
      for (const pack of packs) {
        if (pack.metadata.mode === "pattern" && scanStrategy === 0) {
          for (const m of (pack.matches || [])) {
            if (typeof m.match !== "function") continue;
            if (m.match(node, ancestors)) {
              const finding = self._emitPatternFinding(pack, node, ctx);
              if (finding) findings.push(finding);
              if (findings.length >= (self.maxFindings || Infinity)) return;
            }
          }
        } else if (pack.metadata.mode === "taint") {
          if (!globalTaintCtx || !pack.sinks || !pack.sinks.length) continue;
          for (const s of pack.sinks) {
            if (!s.match(node, ancestors)) continue;
            const payload = s.payload(node);
            if (!payload) continue;
            const hits = queryTaintForRule(globalTaintCtx, pack, payload, { sinkNode: node, sinkMeta: s.meta }) || [];
            for (const hit of hits) {
              const trace = this._buildTraceFromPath(hit, globalTaintCtx.graph, ctx.codeByFile || {}, ctx);
              const finding = this._emitTaintFinding(pack, node, ctx, hit, globalTaintCtx, trace, s.meta);
              if (!finding) continue;
              const key = this._dedupKey(pack, hit.origin, node);
              if (this._taintDedup.has(key)) {
                continue;
              }
              this._taintDedup.set(key, true);
              findings.push(finding);
              if (findings.length >= (self.maxFindings || Infinity)) return;
            }
          }
        }
      }
    };

    const visitors = {
      CallExpression: processNode,
      MemberExpression: processNode,
      AssignmentExpression: processNode,
      NewExpression: processNode,
      VariableDeclarator: processNode,
      Literal: processNode,
      TemplateLiteral: processNode,
    };

    try {
      ancestorWalk(masterAST, visitors);
    } catch (err) {
      console.warn("[SAST] visitor error swallowed:", err && err.message);
    }

    return this.removeDuplicates(findings);
  }
}
