"use strict";

import { ancestor } from "../acorn/walk.mjs";
import { TaintGraph, Origin, compilePattern, calleeNameFromPattern, calleeNameFromCall } from "./_internals.js";

const DEFAULT_DEPTH_LIMIT = 200;
const DEFAULT_ORIGIN_LIMIT = 5;
const MESSAGE_FALLBACK_ORIGIN_ID = "dom:message_data";

function isFunctionNode(node) {
  return !!(node && (
    node.type === "FunctionDeclaration" ||
    node.type === "FunctionExpression" ||
    node.type === "ArrowFunctionExpression"
  ));
}

function originLabelForNode(node) {
  if (!node) return "";
  if (node._ptkOriginLabel) return node._ptkOriginLabel;
  if (node.type === "Identifier") return node.name || "";
  if (node.type === "Literal") return node.raw || String(node.value || "");
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
    if (cur?.type === "Identifier") parts.unshift(cur.name);
    else if (cur?.type === "ThisExpression") parts.unshift("this");
    return parts.join(".");
  }
  if (node.type === "CallExpression") {
    return calleeNameFromCall(node) || "call";
  }
  if (node.type === "NewExpression") {
    return calleeNameFromCall(node) || "new";
  }
  return node.type || "";
}

let nextFunctionId = 1;
function ensureFunctionId(node) {
  if (!isFunctionNode(node)) return null;
  if (typeof node._ptkFnId === "number") return node._ptkFnId;
  Object.defineProperty(node, "_ptkFnId", {
    value: nextFunctionId++,
    enumerable: false,
    configurable: true,
  });
  return node._ptkFnId;
}

function scopeIdsFromAncestorList(ancestors) {
  if (!Array.isArray(ancestors) || !ancestors.length) return [];
  const ids = [];
  for (let i = 0; i < ancestors.length - 1; i++) {
    const anc = ancestors[i];
    if (!isFunctionNode(anc)) continue;
    const id = ensureFunctionId(anc);
    if (id != null) ids.push(id);
  }
  return ids;
}

function stateKey(nodeId, sanitized) {
  return `${nodeId}|${sanitized ? 1 : 0}`;
}

function markFunctionParamsAsMessage(fnNode) {
  if (!fnNode || !Array.isArray(fnNode.params)) return;
  for (const param of fnNode.params) {
    if (param && param.type === "Identifier") {
      param._ptkIsMessageParam = true;
    }
  }
}

function markFunctionParamsAsDomEvent(fnNode) {
  if (!fnNode || !Array.isArray(fnNode.params)) return;
  for (const param of fnNode.params) {
    if (param && param.type === "Identifier") {
      param._ptkIsDomEventParam = true;
    }
  }
}

function literalStringValue(node) {
  if (!node) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && (node.expressions || []).length === 0) {
    return (node.quasis || []).map((q) => q?.value?.cooked || "").join("");
  }
  return null;
}

function memberPropName(mem) {
  if (!mem || mem.type !== "MemberExpression") return null;
  if (mem.computed) {
    if (mem.property?.type === "Literal") return String(mem.property.value);
    if (mem.property?.type === "Identifier") return mem.property.name;
    return null;
  }
  if (mem.property?.type === "Identifier") return mem.property.name;
  if (mem.property?.type === "Literal") return String(mem.property.value);
  return null;
}

function selectorTargetsScript(selector) {
  if (!selector) return false;
  return String(selector)
    .split(",")
    .some((raw) => {
      const part = raw.trim();
      if (!part) return false;
      return /(^|[\s>+~,])script(?=($|[\s.#[:>+~,]))/i.test(" " + part);
    });
}

function likelyScriptIdentifier(value) {
  if (!value) return false;
  const trimmed = String(value).trim();
  if (!trimmed) return false;
  return /script/i.test(trimmed);
}

function markNodeAsScript(node) {
  if (!node || typeof node !== "object") return;
  node._ptkIsScript = true;
}

function propagateScriptFlag(fromNode, targetNode) {
  if (!fromNode?._ptkIsScript || !targetNode) return;
  if (targetNode.type === "Identifier") {
    targetNode._ptkIsScript = true;
  } else if (targetNode.type === "MemberExpression" && targetNode.object) {
    targetNode.object._ptkIsScript = true;
  }
}

function markUrlParamsNode(node) {
  if (!node || typeof node !== "object") return;
  node._ptkIsURLSearchParams = true;
}

function propagateUrlParamsFlag(fromNode, targetNode) {
  if (!fromNode?._ptkIsURLSearchParams || !targetNode) return;
  if (targetNode.type === "Identifier") {
    targetNode._ptkIsURLSearchParams = true;
  } else if (targetNode.type === "MemberExpression" && targetNode.object) {
    targetNode.object._ptkIsURLSearchParams = true;
  }
}

function markUrlInstance(node) {
  if (!node || typeof node !== "object") return;
  node._ptkIsURLInstance = true;
}

function propagateUrlInstanceFlag(fromNode, targetNode) {
  if (!fromNode?._ptkIsURLInstance || !targetNode) return;
  if (targetNode.type === "Identifier") {
    targetNode._ptkIsURLInstance = true;
  } else if (targetNode.type === "MemberExpression" && targetNode.object) {
    targetNode.object._ptkIsURLInstance = true;
  }
}

function copyUrlSourceHint(fromNode, targetNode) {
  if (!fromNode?._ptkUrlSourceHint || !targetNode) return;
  const hint = fromNode._ptkUrlSourceHint;
  if (targetNode.type === "Identifier") {
    targetNode._ptkUrlSourceHint = hint;
  } else if (targetNode.type === "MemberExpression" && targetNode.object) {
    targetNode.object._ptkUrlSourceHint = hint;
  }
}

function memberChainParts(node) {
  if (!node || node.type !== "MemberExpression") return null;
  const parts = [];
  let cur = node;
  while (cur && cur.type === "MemberExpression") {
    const prop = memberPropName(cur);
    if (prop == null) return null;
    parts.unshift(prop);
    cur = cur.object;
  }
  if (cur?.type === "Identifier") parts.unshift(cur.name);
  else if (cur?.type === "ThisExpression") parts.unshift("this");
  else return null;
  return parts;
}

function calleeNameFromNew(node) {
  if (!node || node.type !== "NewExpression") return null;
  if (node.callee?.type === "Identifier") return node.callee.name;
  if (node.callee?.type === "MemberExpression") {
    const parts = memberChainParts(node.callee);
    return parts ? parts.join(".") : null;
  }
  return null;
}

function normalizeUrlSourceHint(expr) {
  if (!expr) return null;
  if (expr.type === "MemberExpression") {
    const parts = memberChainParts(expr);
    if (!parts) return null;
    const lowered = parts.map((p) => String(p).toLowerCase());
    const whole = lowered.join(".");
    if (whole === "location" || whole === "window.location" || whole === "document.location") return "location.href";
    const tail = lowered.slice(-2).join(".");
    if (tail === "location.hash") return "location.hash";
    if (tail === "location.search") return "location.search";
    if (tail === "location.href") return "location.href";
    if (tail === "location.pathname") return "location.pathname";
    if (tail === "document.url") return "document.URL";
    if (tail === "document.urlunencoded") return "document.URL";
    if (tail === "document.documenturi") return "document.documentURI";
    if (tail === "document.baseuri") return "document.baseURI";
    if (tail === "document.referrer") return "document.referrer";
    if (tail === "window.name") return "window.name";
    const tail3 = lowered.slice(-3).join(".");
    if (tail3 === "document.location.hash") return "location.hash";
    if (tail3 === "document.location.search") return "location.search";
    if (tail3 === "document.location.href") return "location.href";
    if (tail3 === "document.location.pathname") return "location.pathname";
    if (tail3 === "window.location.href") return "location.href";
    if (tail3 === "window.location.hash") return "location.hash";
    if (tail3 === "window.location.search") return "location.search";
    if (tail3 === "window.location.pathname") return "location.pathname";
  }
  if (expr.type === "CallExpression" && expr.callee?.type === "MemberExpression") {
    const prop = memberPropName(expr.callee);
    const name = prop ? prop.toLowerCase() : "";
    if (["slice", "substr", "substring", "trim", "trimstart", "trimend", "tostring", "concat"].includes(name)) {
      return normalizeUrlSourceHint(expr.callee.object);
    }
  }
  if ((expr.type === "CallExpression" || expr.type === "NewExpression") && expr.arguments?.length) {
    let callName = null;
    if (expr.type === "CallExpression") {
      callName = calleeNameFromCall(expr);
    } else if (expr.callee?.type === "Identifier") {
      callName = expr.callee.name;
    } else if (expr.callee?.type === "MemberExpression") {
      callName = memberPropName(expr.callee) || null;
    }
    const lower = callName ? callName.toLowerCase() : "";
    if (lower === "url" || lower.endsWith(".url") || lower.endsWith("urlsearchparams")) {
      return normalizeUrlSourceHint(expr.arguments[0]);
    }
  }
  return null;
}

function sourceIdForUrlSourceHint(hint) {
  switch (hint) {
    case "location.hash": return "location:hash";
    case "location.search": return "location:search";
    case "location.href": return "location:href";
    case "location.pathname": return "location:pathname";
    case "document.URL": return "document:url";
    case "document.documentURI": return "document:documentURI";
    case "document.baseURI": return "document:baseURI";
    case "document.referrer": return "document:referrer";
    case "window.name": return "window:name";
    default: return null;
  }
}

function maybeMarkScriptFromCall(callNode, callName) {
  if (!callNode || !callName) return;
  const lower = callName.toLowerCase();
  const firstArg = literalStringValue(callNode.arguments && callNode.arguments[0]);
  const secondArg = literalStringValue(callNode.arguments && callNode.arguments[1]);
  const mark = () => markNodeAsScript(callNode);

  if (lower.endsWith("createelementns")) {
    const candidate = secondArg || firstArg;
    if (candidate && /script/i.test(candidate)) mark();
  } else if (lower.endsWith("createelement")) {
    if (firstArg && /script/i.test(firstArg)) mark();
  } else if (lower.endsWith("queryselector") || lower.endsWith("queryselectorall")) {
    if (firstArg && selectorTargetsScript(firstArg)) mark();
  } else if (lower.endsWith("getelementsbytagname")) {
    if (firstArg && /script/i.test(firstArg)) mark();
  } else if (lower.endsWith("getelementbyid")) {
    if (firstArg && likelyScriptIdentifier(firstArg)) mark();
  } else if (lower.endsWith("getelementsbyclassname") || lower.endsWith("getelementsbyname")) {
    if (firstArg && likelyScriptIdentifier(firstArg)) mark();
  } else if (lower === "$" || lower === "jquery") {
    if (firstArg && selectorTargetsScript(firstArg)) mark();
  }
}

function nodeFromPathKey(key, graph) {
  if (!key || !graph) return null;
  const [idStr] = String(key).split("|");
  const id = Number(idStr);
  if (!Number.isFinite(id)) return null;
  return graph.astNodeForId(id);
}

// Build a quick lookup: sanitizer callee name -> [sanitizerId, ...]
function buildSanitizerIndex(catalog) {
  const out = new Map();
  const entries = catalog?.sanitizers || {};
  for (const [sid, entry] of Object.entries(entries)) {
    const patterns = Array.isArray(entry.pattern) ? entry.pattern : (entry.pattern ? [entry.pattern] : []);
    for (const pat of patterns) {
      const call = pat.call || {};
      const name = calleeNameFromPattern(call.callee || call);
      if (!name) continue;
      if (!out.has(name)) out.set(name, []);
      out.get(name).push(sid);
    }
  }
  return out;
}

function buildSourceMatchers(catalog) {
  const out = [];
  const sources = catalog?.sources || {};
  for (const [sid, entry] of Object.entries(sources)) {
    if (!entry) continue;
    const originKind = entry.origin_kind || "generic";
    const patterns = Array.isArray(entry.pattern) ? entry.pattern : (entry.pattern ? [entry.pattern] : []);
    const compiled = patterns
      .map((p) => {
        if (!p || typeof p !== "object") return null;
        try {
          const fn = compilePattern(p);
          return typeof fn === "function" ? fn : null;
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    if (!compiled.length && entry.kind !== "engine_builtin") continue;
    out.push({ id: sid, originKind, compiled, raw: entry });
  }
  return out;
}

function buildCallPassthroughConfig(catalog) {
  const config = {
    matchers: [],
    methods: new Set(),
    anyMethod: false
  };
  const propagators = catalog?.propagators || {};
  for (const entry of Object.values(propagators)) {
    if (!entry || entry.kind !== "call_passthrough") continue;
    const patterns = Array.isArray(entry.patterns)
      ? entry.patterns
      : (entry.pattern ? [entry.pattern] : []);
    for (const pat of patterns) {
      if (!pat || typeof pat !== "object") continue;
      const call = pat.call || {};
      const argIndex = (call && typeof call.argIndex === "number") ? call.argIndex : null;
      try {
        const fn = compilePattern(pat);
        if (typeof fn === "function") {
          config.matchers.push({ match: fn, argIndex });
        }
      } catch {
        /* ignore invalid pattern */
      }
    }
    const passthroughCalls = entry.propagate?.passthrough_call;
    if (passthroughCalls === "*") {
      config.anyMethod = true;
    } else if (Array.isArray(passthroughCalls)) {
      for (const name of passthroughCalls) {
        if (typeof name === "string" && name.trim()) {
          config.methods.add(name.toLowerCase());
        }
      }
    }
  }
  return config;
}

function buildCtorConfig(catalog) {
  const config = [];
  const propagators = catalog?.propagators || {};
  for (const entry of Object.values(propagators)) {
    if (!entry || entry.kind !== "ctor") continue;
    const patterns = Array.isArray(entry.patterns)
      ? entry.patterns
      : (entry.pattern ? [entry.pattern] : []);
    for (const pat of patterns) {
      if (!pat || typeof pat !== "object") continue;
      const newSpec = pat.new || {};
      const argIndex = (newSpec && typeof newSpec.argIndex === "number") ? newSpec.argIndex : 0;
      try {
        const fn = compilePattern(pat);
        if (typeof fn === "function") {
          config.push({ match: fn, argIndex, id: entry.id });
        }
      } catch {
        /* ignore invalid pattern */
      }
    }
  }
  return config;
}

function buildPromiseAdapterConfig(catalog) {
  const config = [];
  const propagators = catalog?.propagators || {};
  for (const entry of Object.values(propagators)) {
    if (!entry || entry.kind !== "promise_adapter") continue;
    const patterns = Array.isArray(entry.patterns)
      ? entry.patterns
      : (entry.pattern ? [entry.pattern] : []);
    for (const pat of patterns) {
      if (!pat || typeof pat !== "object") continue;
      const callSpec = pat.call || {};
      const argIndex = (callSpec && typeof callSpec.argIndex === "number") ? callSpec.argIndex : 0;
      try {
        const fn = compilePattern(pat);
        if (typeof fn === "function") {
          config.push({ match: fn, argIndex });
        }
      } catch {
        /* ignore invalid pattern */
      }
    }
  }
  return config;
}

function buildCallbackAdapterConfig(catalog) {
  const config = [];
  const propagators = catalog?.propagators || {};
  for (const entry of Object.values(propagators)) {
    if (!entry || entry.kind !== "callback_adapter") continue;
    const callbackParamSource = entry.callbackParamSource && typeof entry.callbackParamSource === "object"
      ? {
          id: entry.callbackParamSource.id || entry.id || "callback:value",
          originKind: entry.callbackParamSource.originKind || entry.callbackParamSource.origin_kind || "generic",
          taintKinds: Array.isArray(entry.callbackParamSource.taintKinds)
            ? entry.callbackParamSource.taintKinds.filter((kind) => typeof kind === "string" && kind.trim())
            : null
        }
      : null;
    const patterns = Array.isArray(entry.patterns)
      ? entry.patterns
      : (entry.pattern ? [entry.pattern] : []);
    for (const pat of patterns) {
      if (!pat || typeof pat !== "object") continue;
      const callSpec = pat.call || {};
      const argIndex = (callSpec && typeof callSpec.argIndex === "number") ? callSpec.argIndex : 0;
      try {
        const fn = compilePattern(pat);
        if (typeof fn === "function") {
          const wantsReturn = typeof entry.id === "string" && entry.id.includes("array_map");
          config.push({ match: fn, argIndex, wantsReturn, callbackParamSource });
        }
      } catch {
        /* ignore invalid pattern */
      }
    }
  }
  return config;
}

function hasReturnPassthrough(catalog) {
  const propagators = catalog?.propagators || {};
  for (const entry of Object.values(propagators)) {
    if (!entry || entry.kind !== "return_passthrough") continue;
    if (entry.propagate?.return_value) return true;
  }
  return false;
}

function buildSourceTaintKindMap(modules) {
  const map = new Map();
  if (!Array.isArray(modules)) return map;
  for (const mod of modules) {
    const packs = Array.isArray(mod?.rules) ? mod.rules : [];
    for (const pack of packs) {
      if (!pack || pack.metadata?.mode !== "taint") continue;
      const kinds = Array.isArray(pack.taintKinds) ? pack.taintKinds.filter(Boolean) : [];
      if (!kinds.length) continue;
      const sourceIds = Array.isArray(pack.sourceIds) ? pack.sourceIds : [];
      for (const sid of sourceIds) {
        if (!sid) continue;
        if (!map.has(sid)) map.set(sid, new Set());
        const set = map.get(sid);
        kinds.forEach((k) => set.add(k));
      }
    }
  }
  return map;
}

function fileIndexFor(node, cache) {
  const fileId = node?.sourceFile || node?.loc?.sourceFile || null;
  if (!fileId) return null;
  if (!cache.map.has(fileId)) {
    cache.map.set(fileId, cache.list.length);
    cache.list.push(fileId);
  }
  return cache.map.get(fileId);
}

function addOriginForNode(node, matcher, graph, originTable, fileCache, sourceTaintKinds) {
  const nodeId = graph.nodeIdForAstNode(node);
  if (!nodeId) return;
  const label = originLabelForNode(node) || matcher?.id || calleeNameFromCall(node) || "";
  const fileId = fileIndexFor(node, fileCache);
  const loc = node?.loc?.start ? { line: node.loc.start.line, column: node.loc.start.column } : null;
  let taintKinds = null;
  if (matcher?.taintKinds && matcher.taintKinds.length) {
    taintKinds = new Set(matcher.taintKinds);
  } else if (matcher?.id && sourceTaintKinds?.has(matcher.id)) {
    taintKinds = new Set(sourceTaintKinds.get(matcher.id));
  }
  const origin = new Origin(
    matcher.originKind,
    node,
    label,
    fileId,
    loc,
    matcher?.id || null,
    taintKinds
  );
  const originId = originTable.length;
  originTable.push(origin);
  graph.markNodeAsSource(nodeId);
  graph.markNodeWithOrigin(nodeId, originId);
  return originId;
}

function propagateExpressionChildren(node, graph) {
  if (!node) return;
  switch (node.type) {
    case "BinaryExpression":
    case "LogicalExpression":
      if (node.left) graph.addEdge(node.left, node, "expr");
      if (node.right) graph.addEdge(node.right, node, "expr");
      break;
    case "ConditionalExpression":
      if (node.consequent) graph.addEdge(node.consequent, node, "expr");
      if (node.alternate) graph.addEdge(node.alternate, node, "expr");
      break;
    case "TemplateLiteral":
      (node.expressions || []).forEach((e) => graph.addEdge(e, node, "expr"));
      break;
    case "ArrayExpression":
      (node.elements || []).forEach((el) => el && graph.addEdge(el, node, "expr"));
      break;
    case "ObjectExpression":
      (node.properties || []).forEach((p) => {
        if (!p) return;
        if (p.type === "Property" && p.value) graph.addEdge(p.value, node, "expr");
        if (p.type === "SpreadElement" && p.argument) graph.addEdge(p.argument, node, "expr");
      });
      break;
    case "CallExpression":
    case "NewExpression":
      (node.arguments || []).forEach((arg) => arg && graph.addEdge(arg, node, "arg"));
      if (node.callee) {
        graph.addEdge(node.callee, node, "callee");
        if (node.callee.type === "MemberExpression" && node.callee.object) {
          graph.addEdge(node.callee.object, node, "receiver");
        }
      }
      break;
    case "ChainExpression":
      if (node.expression) {
        graph.addEdge(node.expression, node, "chain");
        propagateExpressionChildren(node.expression, graph);
      }
      break;
    default:
      break;
  }
}

const GLOBAL_ASSIGNED_FN_BASES = new Set(["window", "globalThis", "self", "global", "top"]);

function buildFunctionIndex(ast) {
  const byName = new Map();
  const returnNodeByFn = new WeakMap();

  const register = (name, node, ancestors) => {
    if (!name || !node) return;
    ensureFunctionId(node);
    const entry = { node, scopeIds: scopeIdsFromAncestorList(ancestors || []) };
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(entry);
  };

  const registerFromGlobalAssignment = (funcNode, ancestors) => {
    let child = funcNode;
    for (let i = ancestors.length - 2; i >= 0; i--) {
      const anc = ancestors[i];
      if (anc.type === "AssignmentExpression" && anc.right === child) {
        const left = anc.left;
        if (
          left?.type === "MemberExpression" &&
          !left.computed &&
          left.property?.type === "Identifier" &&
          left.object?.type === "Identifier" &&
          GLOBAL_ASSIGNED_FN_BASES.has(left.object.name)
        ) {
          register(left.property.name, funcNode, ancestors);
          break;
        }
      }
      child = anc;
    }
  };

  function propertyKeyName(key, computed) {
    if (!key) return null;
    if (!computed) {
      if (key.type === "Identifier") return key.name;
      if (key.type === "Literal") return String(key.value);
      return null;
    }
    if (key.type === "Literal") return String(key.value);
    return null;
  }

  const GLOBAL_NAMES = new Set(["window", "globalThis", "self", "global", "top"]);

  function memberExpressionToParts(node) {
    if (!node || node.type !== "MemberExpression" || node.computed) return null;
    const parts = [];
    let cur = node;
    while (cur && cur.type === "MemberExpression" && !cur.computed) {
      if (cur.property?.type !== "Identifier") return null;
      parts.unshift(cur.property.name);
      cur = cur.object;
    }
    if (cur?.type === "Identifier") {
      parts.unshift(cur.name);
      return parts;
    }
    return null;
  }

  function aliasBasesFromTarget(target) {
    if (!target) return [];
    if (target.type === "Identifier") return [target.name];
    if (target.type === "MemberExpression" && !target.computed) {
      const parts = memberExpressionToParts(target);
      if (!parts || !parts.length) return [];
      const bases = [parts.join(".")];
      if (GLOBAL_NAMES.has(parts[0]) && parts.length > 1) {
        bases.push(parts.slice(1).join("."));
      }
      return Array.from(new Set(bases));
    }
    return [];
  }

  function registerAlias(name, node) {
    if (!name || !node) return;
    const scopeIds = Array.isArray(node._ptkScopeIds) ? node._ptkScopeIds : [];
    const entry = { node, scopeIds };
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(entry);
  }

  function registerObjectAliases(target, objExpr) {
    if (!objExpr || objExpr.type !== "ObjectExpression") return;
    const bases = aliasBasesFromTarget(target);
    if (!bases.length) return;
    for (const prop of objExpr.properties || []) {
      if (!prop || prop.type !== "Property") continue;
      if (prop.kind !== "init") continue;
      const keyName = propertyKeyName(prop.key, prop.computed);
      if (!keyName) continue;
      let fnNodes = [];
      if (isFunctionNode(prop.value)) {
        fnNodes = [prop.value];
      } else if (prop.value?.type === "Identifier" && byName.has(prop.value.name)) {
        fnNodes = byName.get(prop.value.name).map((entry) => entry.node);
      }
      if (!fnNodes.length) continue;
      for (const base of bases) {
        const aliasName = `${base}.${keyName}`;
        fnNodes.forEach((fnNode) => registerAlias(aliasName, fnNode));
      }
    }
  }

  ancestor(ast, {
    FunctionDeclaration(node, ancestors) {
      if (node.id?.name) register(node.id.name, node, ancestors);
      node._ptkScopeIds = scopeIdsFromAncestorList(ancestors || []);
      returnNodeByFn.set(node, { kind: "FunctionReturn", fn: node });
    },
    FunctionExpression(node, ancestors) {
      if (node.id?.name) register(node.id.name, node, ancestors);
      node._ptkScopeIds = scopeIdsFromAncestorList(ancestors || []);
      const parent = ancestors[ancestors.length - 2];
      if (parent?.type === "VariableDeclarator" && parent.id?.type === "Identifier") {
        register(parent.id.name, node, ancestors);
      }
      registerFromGlobalAssignment(node, ancestors);
      returnNodeByFn.set(node, { kind: "FunctionReturn", fn: node });
    },
    ArrowFunctionExpression(node, ancestors) {
      node._ptkScopeIds = scopeIdsFromAncestorList(ancestors || []);
      const parent = ancestors[ancestors.length - 2];
      if (parent?.type === "VariableDeclarator" && parent.id?.type === "Identifier") {
        register(parent.id.name, node, ancestors);
      }
      registerFromGlobalAssignment(node, ancestors);
      returnNodeByFn.set(node, { kind: "FunctionReturn", fn: node });
    }
  });
  ancestor(ast, {
    VariableDeclarator(node) {
      if (node.init && node.init.type === "ObjectExpression" && node.id?.type === "Identifier") {
        registerObjectAliases(node.id, node.init);
      }
    },
    AssignmentExpression(node) {
      if (node.right && node.right.type === "ObjectExpression") {
        registerObjectAliases(node.left, node.right);
      }
    }
  });
  return { byName, returnNodeByFn };
}

function selectFunctionForCall(name, callScopeIds, fnIndex) {
  if (!fnIndex?.byName?.has(name)) return null;
  const entries = fnIndex.byName.get(name);
  if (!entries || !entries.length) return null;
  const scope = Array.isArray(callScopeIds) ? callScopeIds : [];
  let bestEntry = null;
  let bestScore = -1;
  for (const entry of entries) {
    const fnScope = entry.scopeIds || [];
    if (fnScope.length > scope.length) continue;
    let matches = true;
    for (let i = 0; i < fnScope.length; i++) {
      if (scope[i] !== fnScope[i]) {
        matches = false;
        break;
      }
    }
    if (!matches) continue;
    if (fnScope.length > bestScore) {
      bestEntry = entry;
      bestScore = fnScope.length;
    }
  }
  return bestEntry ? bestEntry.node : entries[0]?.node || null;
}

export function buildGlobalTaintContext(ast, options = {}) {
  const graph = new TaintGraph();
  const originTable = [];
  const sanitizerIndex = buildSanitizerIndex(options.catalog || {});
  const sourceMatchers = buildSourceMatchers(options.catalog || {});
  const callPassthroughConfig = buildCallPassthroughConfig(options.catalog || {});
  const ctorConfig = buildCtorConfig(options.catalog || {});
  const promiseAdapterConfig = buildPromiseAdapterConfig(options.catalog || {});
  const callbackAdapterConfig = buildCallbackAdapterConfig(options.catalog || {});
  const returnPassthroughEnabled = hasReturnPassthrough(options.catalog || {});
  const sourceTaintKindMap = buildSourceTaintKindMap(options.modules || []);
  const fnIndex = buildFunctionIndex(ast);

  const fileCache = { map: new Map(), list: [] };
  const rootScope = { parent: null, bindings: new Map(), isFunctionScope: true };
  const fallbackOrigins = [];

  function bind(scope, name, node, opts = {}) {
    if (!name || !scope) return;
    if (opts.hoistToFunction) {
      let target = scope;
      while (target && !target.isFunctionScope) target = target.parent;
      (target || scope).bindings.set(name, node);
      return;
    }
    let target = scope;
    while (target) {
      if (target.bindings.has(name)) {
        target.bindings.set(name, node);
        return;
      }
      target = target.parent;
    }
    scope.bindings.set(name, node);
  }
  function lookup(scope, name) {
    let cur = scope;
    while (cur) {
      if (cur.bindings.has(name)) return cur.bindings.get(name);
      cur = cur.parent;
    }
    return null;
  }

  function resolveFnFromBinding(binding) {
    if (!binding) return null;
    if (isFunctionNode(binding)) return binding;
    if (binding._ptkInitFn && isFunctionNode(binding._ptkInitFn)) return binding._ptkInitFn;
    return null;
  }

  function addMessageDataOriginsInFunction(fnNode) {
    if (!fnNode || !Array.isArray(fnNode.params) || !fnNode.body) return;
    const paramNames = new Set(
      fnNode.params
        .filter(param => param?.type === "Identifier" && param._ptkIsMessageParam)
        .map(param => param.name)
    );
    if (!paramNames.size) return;
    ancestor(fnNode.body, {
      MemberExpression(node) {
        if (memberPropName(node) !== "data") return;
        const objIdent = node.object?.type === "Identifier" ? node.object : null;
        if (!objIdent || !paramNames.has(objIdent.name)) return;
        addOriginForNode(
          node,
          { originKind: "webmsg", id: "webmsg:data", taintKinds: ["web-message-taint"] },
          graph,
          originTable,
          fileCache,
          sourceTaintKindMap
        );
      }
    });
  }

  function markMessageHandlerArg(handlerNode, scope) {
    if (!handlerNode) return;
    if (handlerNode.type === "FunctionExpression" || handlerNode.type === "ArrowFunctionExpression") {
      markFunctionParamsAsMessage(handlerNode);
      return;
    }
    if (handlerNode.type === "Identifier") {
      const binding = lookup(scope, handlerNode.name);
      const fn = resolveFnFromBinding(binding);
      if (fn) {
        markFunctionParamsAsMessage(fn);
        addMessageDataOriginsInFunction(fn);
      }
    }
  }

  function isDomEventTargetValueRead(node) {
    if (memberPropName(node) !== "value") return false;
    const targetMember = node.object;
    if (!targetMember || targetMember.type !== "MemberExpression") return false;
    if (memberPropName(targetMember) !== "target") return false;
    const eventParam = targetMember.object;
    return !!(eventParam?.type === "Identifier" && eventParam._ptkIsDomEventParam);
  }

  function addDomEventValueOriginsInFunction(fnNode) {
    if (!fnNode || !Array.isArray(fnNode.params) || !fnNode.body) return;
    const paramNames = new Set(
      fnNode.params
        .filter(param => param?.type === "Identifier" && param._ptkIsDomEventParam)
        .map(param => param.name)
    );
    if (!paramNames.size) return;
    ancestor(fnNode.body, {
      MemberExpression(node) {
        if (memberPropName(node) !== "value") return;
        const targetMember = node.object;
        if (!targetMember || targetMember.type !== "MemberExpression") return;
        if (memberPropName(targetMember) !== "target") return;
        const eventParam = targetMember.object;
        if (!eventParam || eventParam.type !== "Identifier" || !paramNames.has(eventParam.name)) return;
        addOriginForNode(
          node,
          { originKind: "dom-input", id: "dom:event_target_value" },
          graph,
          originTable,
          fileCache,
          sourceTaintKindMap
        );
      }
    });
  }

  function markDomEventHandlerArg(handlerNode, scope) {
    if (!handlerNode) return;
    if (handlerNode.type === "FunctionExpression" || handlerNode.type === "ArrowFunctionExpression") {
      markFunctionParamsAsDomEvent(handlerNode);
      return;
    }
    if (handlerNode.type === "Identifier") {
      const binding = lookup(scope, handlerNode.name);
      const fn = resolveFnFromBinding(binding);
      if (fn) {
        markFunctionParamsAsDomEvent(fn);
        addDomEventValueOriginsInFunction(fn);
      }
    }
  }

  function attachCallbackParams(handlerNode, scope, sourceNode, opts = {}) {
    if (!handlerNode || !sourceNode) return;
    const attachParams = (fnNode) => {
      if (!fnNode || !Array.isArray(fnNode.params)) return;
      for (const param of fnNode.params) {
        if (param && param.type === "Identifier") {
          if (opts.callbackParamSource) {
            addOriginForNode(
              param,
              opts.callbackParamSource,
              graph,
              originTable,
              fileCache,
              sourceTaintKindMap
            );
          }
          graph.addEdge(sourceNode, param, opts.edgeKind || "callback_param");
        }
      }
      if (opts.returnToCall) {
        const retNode = fnIndex.returnNodeByFn.get(fnNode);
        if (retNode) {
          graph.nodeIdForAstNode(retNode);
          graph.addEdge(retNode, opts.returnToCall, "callback_return");
        }
      }
    };
    const resolveHandler = (node) => {
      if (!node) return;
      if (node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
        attachParams(node);
        return;
      }
      if (node.type === "Identifier") {
        const binding = lookup(scope, node.name);
        const fn = resolveFnFromBinding(binding);
        if (fn) attachParams(fn);
      }
    };
    if (handlerNode.type === "ObjectExpression") {
      for (const prop of handlerNode.properties || []) {
        if (!prop || prop.type !== "Property") continue;
        const keyName = prop.key?.type === "Identifier"
          ? prop.key.name
          : (prop.key?.type === "Literal" ? String(prop.key.value) : null);
        if (!keyName) continue;
        const lowerKey = keyName.toLowerCase();
        if (lowerKey !== "next" && lowerKey !== "error" && lowerKey !== "complete") continue;
        resolveHandler(prop.value);
      }
      return;
    }
    resolveHandler(handlerNode);
  }

  function canonicalNameForExpr(expr, scope) {
    if (!expr) return null;
    if (expr.type === "Identifier") {
      if (expr._ptkCanonicalName) return expr._ptkCanonicalName;
      if (expr.name === "document") return "document";
      if (expr.name === "location") return "location";
      if (GLOBAL_ASSIGNED_FN_BASES.has(expr.name)) return "window";
      return null;
    }
    if (expr.type === "MemberExpression" && !expr.computed) {
      const base = canonicalNameForExpr(expr.object, scope);
      if (!base) return null;
      if (expr.property?.type !== "Identifier") return null;
      const prop = expr.property.name;
      if (base === "window" && prop === "window") return "window";
      if (base === "window" && prop === "document") return "document";
      if (base === "window" && prop === "location") return "location";
      if (base === "window" && prop === "global") return "window";
    }
    return null;
  }

  function canonicalizeBaseName(raw) {
    if (!raw) return raw;
    const lowered = String(raw).toLowerCase();
    if (GLOBAL_ASSIGNED_FN_BASES.has(lowered)) return "window";
    return raw;
  }

  function visit(node, scope, parents, fnStack) {
    if (!node) return;
    const activeFnStack = Array.isArray(fnStack) ? fnStack : [];
    graph.nodeIdForAstNode(node);
    const nextParents = parents.concat(node);
    let shouldWalkChildren = true;

    switch (node.type) {
      case "Program":
        node.body.forEach((stmt) => visit(stmt, scope, nextParents, activeFnStack));
        return;

      case "BlockStatement": {
        const childScope = { parent: scope, bindings: new Map(), isFunctionScope: false };
        node.body.forEach((stmt) => visit(stmt, childScope, nextParents, activeFnStack));
        return;
      }

      case "FunctionDeclaration": {
        if (node.id?.name) bind(scope, node.id.name, node);
        const fnScope = { parent: scope, bindings: new Map(), isFunctionScope: true };
        (node.params || []).forEach((p) => {
          if (p.type === "Identifier") bind(fnScope, p.name, p);
        });
        const fnId = ensureFunctionId(node);
        const childStack = fnId ? activeFnStack.concat(fnId) : activeFnStack;
        visit(node.body, fnScope, nextParents, childStack);
        return;
      }

      case "FunctionExpression":
      case "ArrowFunctionExpression": {
        const fnScope = { parent: scope, bindings: new Map(), isFunctionScope: true };
        if (node.id?.name) bind(scope, node.id.name, node);
        (node.params || []).forEach((p) => {
          if (p.type === "Identifier") bind(fnScope, p.name, p);
        });
        const fnId = ensureFunctionId(node);
        const childStack = fnId ? activeFnStack.concat(fnId) : activeFnStack;
        if (node.body) visit(node.body, fnScope, nextParents, childStack);
        return;
      }

      case "VariableDeclaration":
        (node.declarations || []).forEach((d) => {
          d._ptkDeclKind = node.kind || "var";
          visit(d, scope, nextParents, activeFnStack);
          delete d._ptkDeclKind;
        });
        return;

      case "VariableDeclarator": {
        if (node.init) visit(node.init, scope, nextParents, activeFnStack);
        if (node.id?.type === "Identifier") {
          const idNode = node.id;
          const hoist = node._ptkDeclKind === "var";
          bind(scope, idNode.name, idNode, { hoistToFunction: hoist });
          if (node.init) graph.addEdge(node.init, idNode, "init");
          if (node.init && (node.init.type === "FunctionExpression" || node.init.type === "ArrowFunctionExpression")) {
            // register function aliases handled in buildFunctionIndex
            idNode._ptkInitFn = node.init;
          }
          propagateScriptFlag(node.init, idNode);
          propagateUrlParamsFlag(node.init, idNode);
          propagateUrlInstanceFlag(node.init, idNode);
          copyUrlSourceHint(node.init, idNode);
          const canonical = canonicalNameForExpr(node.init, scope);
          if (canonical) idNode._ptkCanonicalName = canonical;
        }
        return;
      }

      case "AssignmentExpression": {
        if (!node.left.computed && node.left.type === "MemberExpression") {
          const prop = memberPropName(node.left);
          if (prop && prop.toLowerCase() === "onmessage") {
            markMessageHandlerArg(node.right, scope);
          }
        }
        visit(node.right, scope, nextParents, activeFnStack);
        visit(node.left, scope, nextParents, activeFnStack);
        graph.addEdge(node.right, node.left, "assign");
        if (node.left.type === "Identifier") {
          bind(scope, node.left.name, node.left);
          if (node.right && (node.right.type === "FunctionExpression" || node.right.type === "ArrowFunctionExpression")) {
            node.left._ptkInitFn = node.right;
          }
          const canonical = canonicalNameForExpr(node.right, scope);
          if (canonical) node.left._ptkCanonicalName = canonical;
        }
        propagateExpressionChildren(node.right, graph);
        const targetForFlag = node.left.type === "Identifier" ? node.left : (node.left.type === "MemberExpression" ? node.left.object : null);
        propagateScriptFlag(node.right, targetForFlag);
        propagateUrlParamsFlag(node.right, targetForFlag);
        propagateUrlInstanceFlag(node.right, targetForFlag);
        copyUrlSourceHint(node.right, targetForFlag);
        return;
      }

      case "ReturnStatement": {
        if (node.argument) {
          visit(node.argument, scope, nextParents, activeFnStack);
          const fnNode = [...parents].reverse().find((p) => p && (p.type === "FunctionDeclaration" || p.type === "FunctionExpression" || p.type === "ArrowFunctionExpression"));
          const retNode = fnIndex.returnNodeByFn.get(fnNode);
          if (retNode && returnPassthroughEnabled) {
            graph.nodeIdForAstNode(retNode);
            graph.addEdge(node.argument, retNode, "return");
          }
        }
        return;
      }

      case "MemberExpression": {
        if (node.object?._ptkIsScript) node._ptkIsScript = true;
        if (node.object?._ptkIsURLInstance) node._ptkIsURLInstance = true;
        if (node.object?._ptkIsURLSearchParams) node._ptkIsURLSearchParams = true;
        if (node.object?._ptkUrlSourceHint) node._ptkUrlSourceHint = node.object._ptkUrlSourceHint;
        if (node.object) visit(node.object, scope, nextParents, activeFnStack);
        if (node.property) visit(node.property, scope, nextParents, activeFnStack);
        if (node.object) graph.addEdge(node.object, node, "member");
        if (node.computed && node.property) graph.addEdge(node.property, node, "member");
        shouldWalkChildren = false;
        // Heuristic: message data origins (event.data / e.data / etc.)
        const propName = (!node.computed && node.property && node.property.type === "Identifier")
          ? node.property.name
          : (node.property && node.property.type === "Literal" ? String(node.property.value) : null);
        const objIdent = (!node.computed && node.object && node.object.type === "Identifier") ? node.object : null;
        if (propName === "data" && objIdent) {
          if (objIdent._ptkIsMessageParam) {
            addOriginForNode(
              node,
              { originKind: "webmsg", id: "webmsg:data", taintKinds: ["web-message-taint"] },
              graph,
              originTable,
              fileCache,
              sourceTaintKindMap
            );
          }
        }
        if (isDomEventTargetValueRead(node)) {
          addOriginForNode(
            node,
            { originKind: "dom-input", id: "dom:event_target_value" },
            graph,
            originTable,
            fileCache,
            sourceTaintKindMap
          );
        }
        if (propName === "searchParams" && node.object?._ptkIsURLInstance) {
          markUrlParamsNode(node);
          if (node.object?._ptkUrlSourceHint) node._ptkUrlSourceHint = node.object._ptkUrlSourceHint;
          if (node.object) graph.addEdge(node.object, node, "url_searchparams");
        }
        break;
      }

      case "ChainExpression": {
        if (node.expression) visit(node.expression, scope, nextParents, activeFnStack);
        break;
      }

      case "CallExpression":
      case "NewExpression": {
        const callName =
          node.type === "CallExpression"
            ? calleeNameFromCall(node)
            : calleeNameFromNew(node);
        const lowerName = callName ? callName.toLowerCase() : "";
        if (node.type === "CallExpression" && (node.callee?.type === "FunctionExpression" || node.callee?.type === "ArrowFunctionExpression")) {
          const params = node.callee.params || [];
          params.forEach((param, idx) => {
            if (!param || param.type !== "Identifier") return;
            const arg = node.arguments?.[idx];
            const canonical = canonicalNameForExpr(arg, scope);
            if (canonical) param._ptkCanonicalName = canonical;
          });
        }
        if (node.type === "CallExpression" && lowerName.endsWith("addeventlistener")) {
          const evtArg = node.arguments?.[0];
          const evtName = literalStringValue(evtArg)?.toLowerCase();
          const handlerArg = node.arguments?.[1];
          if (evtName === "message") {
            markMessageHandlerArg(handlerArg, scope);
          } else if (handlerArg) {
            markDomEventHandlerArg(handlerArg, scope);
          }
        }
        if (node.callee) visit(node.callee, scope, nextParents, activeFnStack);
        (node.arguments || []).forEach((arg) => arg && visit(arg, scope, nextParents, activeFnStack));
        propagateExpressionChildren(node, graph);

        if (node.type === "CallExpression" && callName) {
          maybeMarkScriptFromCall(node, callName);
        }
        const callNameLower = callName ? callName.toLowerCase() : "";
        if (callName && sanitizerIndex.has(callName)) {
          const ids = sanitizerIndex.get(callName);
          const callId = graph.nodeIdForAstNode(node);
          graph.markNodeAsSanitized(callId, ids);
        }

        if (node.type === "CallExpression") {
          for (const adapter of promiseAdapterConfig) {
            let matched = false;
            try {
              matched = adapter.match(node, parents);
            } catch {
              matched = false;
            }
            if (!matched) continue;
            if (node.callee?.type === "MemberExpression") {
              const receiver = node.callee.object;
              const handlerArg = node.arguments?.[adapter.argIndex];
              if (receiver && handlerArg) {
                attachCallbackParams(handlerArg, scope, receiver, { edgeKind: "promise_then" });
              }
            }
          }
          for (const adapter of callbackAdapterConfig) {
            let matched = false;
            try {
              matched = adapter.match(node, parents);
            } catch {
              matched = false;
            }
            if (!matched) continue;
            if (node.callee?.type === "MemberExpression") {
              const receiver = node.callee.object;
              const handlerArg = node.arguments?.[adapter.argIndex];
              if (receiver && handlerArg) {
                attachCallbackParams(handlerArg, scope, receiver, {
                  edgeKind: "callback_adapter",
                  returnToCall: adapter.wantsReturn ? node : null,
                  callbackParamSource: adapter.callbackParamSource || null
                });
              }
            }
          }
        }

        if (node.type === "NewExpression") {
          for (const entry of ctorConfig) {
            let matched = false;
            try {
              matched = entry.match(node, parents);
            } catch {
              matched = false;
            }
            if (!matched) continue;
            const arg = node.arguments?.[entry.argIndex];
            if (arg) graph.addEdge(arg, node, "ctor");
            if (entry.id === "prop:url_ctor") {
              markUrlInstance(node);
              const hint = normalizeUrlSourceHint(arg);
              if (hint) node._ptkUrlSourceHint = hint;
            }
            if (entry.id === "prop:urlsearchparams_ctor") {
              markUrlParamsNode(node);
              const hint = normalizeUrlSourceHint(arg);
              if (hint) node._ptkUrlSourceHint = hint;
            }
          }
        }

        if (node.type === "CallExpression") {
          for (const matcher of callPassthroughConfig.matchers) {
            try {
              if (!matcher.match(node, parents)) continue;
            } catch {
              continue;
            }
            if (typeof matcher.argIndex === "number" && node.arguments?.[matcher.argIndex]) {
              graph.addEdge(node.arguments[matcher.argIndex], node, "call_passthrough");
            } else if (node.callee?.type === "MemberExpression" && node.callee.object) {
              graph.addEdge(node.callee.object, node, "call_passthrough");
            }
          }
          if (node.callee?.type === "MemberExpression") {
            const prop = memberPropName(node.callee);
            if (prop) {
              const propLower = prop.toLowerCase();
              if (callPassthroughConfig.anyMethod || callPassthroughConfig.methods.has(propLower)) {
                if (node.callee.object) graph.addEdge(node.callee.object, node, "call_passthrough");
              }
            }
          }
        }

        // Known function mapping: arg -> param, return -> call result
        let targetFn = null;
        if (node.type === "CallExpression" && node.callee && (node.callee.type === "FunctionExpression" || node.callee.type === "ArrowFunctionExpression")) {
          targetFn = node.callee;
        } else if (node.type === "CallExpression" && callName && fnIndex.byName.has(callName)) {
          targetFn = selectFunctionForCall(callName, activeFnStack, fnIndex);
        }
        if (targetFn) {
          const params = targetFn.params || [];
          params.forEach((param, idx) => {
            if (param?.type === "Identifier" && node.arguments[idx]) {
              graph.addEdge(node.arguments[idx], param, "arg_to_param");
            }
          });
          const retNode = fnIndex.returnNodeByFn.get(targetFn);
          if (retNode) {
            graph.nodeIdForAstNode(retNode);
            graph.addEdge(retNode, node, "ret_to_call");
          }
        }
        shouldWalkChildren = false;
        break;
      }

      case "AwaitExpression": {
        let matched = false;
        for (const adapter of promiseAdapterConfig) {
          try {
            if (adapter.match(node, parents)) {
              matched = true;
              break;
            }
          } catch {
            /* ignore */
          }
        }
        if (matched && node.argument) {
          visit(node.argument, scope, nextParents, activeFnStack);
          graph.addEdge(node.argument, node, "await");
          return;
        }
        break;
      }

      case "Identifier": {
        const isDecl = parents[parents.length - 2]?.type === "VariableDeclarator" && parents[parents.length - 2].id === node;
        const isParam = parents[parents.length - 2]?.type === "FunctionDeclaration" || parents[parents.length - 2]?.type === "FunctionExpression" || parents[parents.length - 2]?.type === "ArrowFunctionExpression";
        const isAssignLhs = parents[parents.length - 2]?.type === "AssignmentExpression" && parents[parents.length - 2].left === node;
        if (!isDecl && !isParam && !isAssignLhs) {
          const binding = lookup(scope, node.name);
          if (binding) {
            graph.addEdge(binding, node, "alias");
            if (binding._ptkIsScript) node._ptkIsScript = true;
            if (binding._ptkIsMessageParam) node._ptkIsMessageParam = true;
            if (binding._ptkIsDomEventParam) node._ptkIsDomEventParam = true;
            if (binding._ptkIsURLSearchParams) node._ptkIsURLSearchParams = true;
            if (binding._ptkIsURLInstance) node._ptkIsURLInstance = true;
            if (binding._ptkUrlSourceHint) node._ptkUrlSourceHint = binding._ptkUrlSourceHint;
            if (binding._ptkCanonicalName) node._ptkCanonicalName = binding._ptkCanonicalName;
          }
        }
        break;
      }

      default:
        break;
    }

    propagateExpressionChildren(node, graph);

    // generic traversal for child nodes
    if (shouldWalkChildren) {
      const keys = Object.keys(node);
      for (const k of keys) {
        if (k === "loc" || k === "range" || k === "sourceFile") continue;
        const child = node[k];
        if (Array.isArray(child)) {
          child.forEach((c) => {
            if (c && typeof c.type === "string") visit(c, scope, nextParents, activeFnStack);
          });
        } else if (child && typeof child.type === "string") {
          visit(child, scope, nextParents, activeFnStack);
        }
      }
    }

    // source detection: after ensuring nodeId exists
    for (const matcher of sourceMatchers) {
      if (matcher.compiled.length === 0) continue;
      for (const fn of matcher.compiled) {
        try {
          if (fn(node, parents)) {
            if (
              node.type === "MemberExpression" &&
              parents[parents.length - 1] &&
              parents[parents.length - 1].type === "MemberExpression" &&
              parents[parents.length - 1].object === node
            ) {
              const parentNode = parents[parents.length - 1];
              let parentIsSource = false;
              for (const parentMatcher of sourceMatchers) {
                if (parentMatcher.compiled.length === 0) continue;
                for (const parentFn of parentMatcher.compiled) {
                  try {
                    if (parentFn(parentNode, parents.slice(0, -1))) {
                      parentIsSource = true;
                      break;
                    }
                  } catch {
                    /* ignore matcher errors */
                  }
                }
                if (parentIsSource) break;
              }
              if (parentIsSource) {
                return; // suppress base origin only when parent member is also a source
              }
            }
            addOriginForNode(node, matcher, graph, originTable, fileCache, sourceTaintKindMap);
            return; // one match per node is enough
          }
        } catch {
          /* ignore matcher errors */
        }
      }
    }

    const urlSourceHint = node.type === "MemberExpression" ? normalizeUrlSourceHint(node) : null;
    const urlSourceId = sourceIdForUrlSourceHint(urlSourceHint);
    if (urlSourceId) {
      addOriginForNode(
        node,
        { originKind: "url", id: urlSourceId },
        graph,
        originTable,
        fileCache,
        sourceTaintKindMap
      );
    }
  }

  visit(ast, rootScope, [ast], []);
  for (const entry of fallbackOrigins) {
    const objOrigins = entry.objNodeId ? graph.getOrigins(entry.objNodeId) : null;
    if (objOrigins && objOrigins.size > 0) {
      graph.removeOrigin(entry.nodeId, entry.originId);
    }
  }
  return { ast, graph, originTable, stats: { totalOrigins: originTable.length } };
}

export function queryTaintForRule(globalCtx, rulePack, sinkPayloadNode, queryOptions = {}) {
  if (!globalCtx || !globalCtx.graph || !sinkPayloadNode) return [];
  const sem = rulePack?.taintSemantics || {};
  const sourceKinds = new Set(sem.sourceKinds || []);
  const sanitizerIds = sem.sanitizers?.ids || new Set();
  const sanitizerContexts = sem.sanitizers?.contexts || new Map();
  const depthLimit = sem.depthLimit || DEFAULT_DEPTH_LIMIT;
  const originLimit = sem.originLimit || DEFAULT_ORIGIN_LIMIT;
  const allowedKinds =
    sem.taintKinds && sem.taintKinds.size ? new Set(sem.taintKinds) : null;
  const sinkContexts = normalizeContextList(queryOptions?.sinkMeta?.context);

  const graph = globalCtx.graph;
  const startId = graph.nodeIdForAstNode(sinkPayloadNode);
  if (!startId) return [];

  const queue = [{ nodeId: startId, sanitized: false, depth: 0, key: stateKey(startId, false) }];
  const visited = new Set([stateKey(startId, false)]);
  const parent = new Map();
  let hits = [];

  const startKey = stateKey(startId, false);
  parent.set(startKey, null);

  while (queue.length) {
    const cur = queue.shift();
    if (cur.depth > depthLimit) continue;

    const currentSanitizers = graph.getSanitizers(cur.nodeId) || [];
    const isSanitizedHere = currentSanitizers.some((sid) => {
      if (!sanitizerIds.has(sid)) return false;
      return sanitizerMatchesSinkContext(sanitizerContexts.get(sid), sinkContexts);
    });
    const nextSanitized = cur.sanitized || isSanitizedHere;

    const originIds = graph.getOrigins(cur.nodeId);
    if (originIds && originIds.size && !nextSanitized) {
      for (const originId of originIds) {
        const origin = globalCtx.originTable[originId];
        if (!origin) continue;
        if (sourceKinds.size && !sourceKinds.has(origin.kind)) continue;
        if (allowedKinds && allowedKinds.size) {
          const originKinds = origin.taintKinds;
          if (!originKinds || !originKinds.size) continue;
          let matches = false;
          for (const kind of originKinds) {
            if (allowedKinds.has(kind)) {
              matches = true;
              break;
            }
          }
          if (!matches) continue;
        }
        const canonicalId = origin.node ? graph.nodeIdForAstNode(origin.node) : null;
        if (canonicalId && canonicalId !== cur.nodeId) continue;
        const path = [];
        let key = cur.key;
        while (key != null) {
          path.push(key);
          key = parent.get(key) || null;
        }
        if (shouldSkipBaseIdentifierOrigin(origin, path, graph)) continue;
        hits.push({
          origin,
          originNode: origin.node,
          originId,
          sinkNode: queryOptions.sinkNode || sinkPayloadNode,
          pathKeys: path, // from origin -> sink
          parent,
        });
        if (hits.length >= originLimit) return hits;
      }
    }

    const upstream = graph.getUpstream(cur.nodeId);
    if (graph.isSourceNode && graph.isSourceNode(cur.nodeId)) {
      continue;
    }
    for (const edge of upstream) {
      const key = stateKey(edge.fromNodeId, nextSanitized);
      if (visited.has(key)) continue;
      visited.add(key);
      parent.set(key, cur.key);
      queue.push({ nodeId: edge.fromNodeId, sanitized: nextSanitized, depth: cur.depth + 1, key });
    }
  }

  if (hits.length > 1) {
    const filtered = [];
    const sinkNodeIds = new Map();
    for (const hit of hits) {
      const sinkId = hit.sinkNode ? graph.nodeIdForAstNode(hit.sinkNode) : null;
      sinkNodeIds.set(hit, sinkId);
    }
    for (const hit of hits) {
      if (hit.origin?.sourceId === MESSAGE_FALLBACK_ORIGIN_ID) {
        const sinkId = sinkNodeIds.get(hit);
        const hasPrimary = hits.some((other) =>
          other !== hit &&
          sinkNodeIds.get(other) === sinkId &&
          other.origin?.sourceId !== MESSAGE_FALLBACK_ORIGIN_ID
        );
        if (hasPrimary) continue;
      }
      filtered.push(hit);
    }
    hits = filtered;
  }

  return hits;
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

function sanitizerMatchesSinkContext(sanitizerContexts, sinkContexts) {
  const sanSet = new Set(normalizeContextList(sanitizerContexts));
  const sinkSet = new Set(normalizeContextList(sinkContexts));
  if (!sanSet.size) return true;
  if (!sinkSet.size) return true;

  for (const sanCtx of sanSet) {
    if (sinkSet.has(sanCtx)) return true;
    if (sanCtx === "css" && sinkSet.has("selector")) return true;
    if (sanCtx === "dom" && sinkSet.has("html")) return true;
    if (sanCtx === "generic" && (sinkSet.has("generic") || sinkSet.has("network") || sinkSet.has("storage"))) {
      return true;
    }
  }
  return false;
}

function shouldSkipBaseIdentifierOrigin(origin, pathKeys, graph) {
  if (!origin?.node || origin.node.type !== "Identifier") return false;
  if (!Array.isArray(pathKeys) || pathKeys.length < 2) return false;
  const nextNode = nodeFromPathKey(pathKeys[1], graph);
  if (!nextNode || nextNode.type !== "MemberExpression") return false;
  if (!nextNode.object || nextNode.object.type !== "Identifier") return false;
  if (nextNode.object.name !== origin.node.name) return false;
  if (!nextNode.property) return false;
  return true;
}
    const registerFromGlobalAssignment = (ancestors) => {
      let child = node;
      for (let i = ancestors.length - 2; i >= 0; i--) {
        const anc = ancestors[i];
        if (anc.type === "AssignmentExpression" && anc.right === child) {
          const left = anc.left;
          if (
            left?.type === "MemberExpression" &&
            !left.computed &&
            left.property?.type === "Identifier" &&
            left.object?.type === "Identifier" &&
            GLOBAL_ASSIGNED_FN_BASES.has(left.object.name)
          ) {
            register(left.property.name, node, ancestors);
            break;
          }
        }
        child = anc;
      }
    };
