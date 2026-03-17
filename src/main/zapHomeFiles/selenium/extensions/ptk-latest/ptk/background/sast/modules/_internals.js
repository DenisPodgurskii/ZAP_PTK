"use strict";

/**
 * Lightweight SAST internals shared by the taint engine and rule runner.
 *
 * Exports:
 *  - compilePattern(pattern): builds a matcher for call/assignment/member/new/etc.
 *  - Origin: canonical taint source descriptor
 *  - TaintGraph: rule-agnostic, global dataflow graph
 *  - calleeNameFromPattern / calleeNameFromCall: helpers for sanitizer lookup
 */

/* ───────────────────────── Pattern compiler (kept compatible with legacy JSON) ───────────────────────── */

// Loose equality that tolerates wildcards
function _wildEq(a, b) {
  if (a === "*" || b === "*") return true;
  return String(a) === String(b);
}

function _memberPropertyName(node) {
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

function _matchMemberChain(node, chain) {
  if (!node || node.type !== "MemberExpression") return false;
  const parts = [];
  let cur = node;
  while (cur && cur.type === "MemberExpression") {
    const prop = _memberPropertyName(cur);
    if (prop == null) break;
    parts.unshift(prop);
    cur = cur.object;
  }
  if (cur?.type === "Identifier") {
    parts.unshift(_canonicalizeBasePart(cur._ptkCanonicalName || cur.name));
  } else if (cur?.type === "ThisExpression") {
    parts.unshift("this");
  } else if (cur?.type === "CallExpression") {
    const name = calleeNameFromCall(cur);
    if (name) parts.unshift(name);
  }
  const normalized = [];
  for (const part of parts) {
    const canon = _canonicalizeBasePart(part);
    if (canon === "window" && normalized[normalized.length - 1] === "window") continue;
    normalized.push(canon);
  }
  const partsToUse = normalized.length ? normalized : parts;
  const pat = chain || [];
  if (pat.length && pat[0] === "*" && pat.length <= partsToUse.length) {
    const offset = partsToUse.length - pat.length;
    for (let i = 0; i < pat.length; i++) {
      if (!_wildEq(partsToUse[i + offset], pat[i])) return false;
    }
    return true;
  }
  if (partsToUse.length !== pat.length) return false;
  for (let i = 0; i < partsToUse.length; i++) {
    if (!_wildEq(partsToUse[i], pat[i])) return false;
  }
  return true;
}

function _canonicalizeBasePart(name) {
  if (!name) return name;
  const lowered = String(name).toLowerCase();
  if (["global", "globalthis", "self", "top"].includes(lowered)) return "window";
  return name;
}

function _getCachedRegex(holder, cacheKey, source, flags = "") {
  if (!source) return null;
  if (!holder || typeof holder !== "object") return new RegExp(source, flags);
  if (!Object.prototype.hasOwnProperty.call(holder, "__ptkRegexCache")) {
    Object.defineProperty(holder, "__ptkRegexCache", {
      value: Object.create(null),
      enumerable: false,
      configurable: false,
      writable: false,
    });
  }
  const key = `${cacheKey}:${source}/${flags}`;
  if (!holder.__ptkRegexCache[key]) {
    holder.__ptkRegexCache[key] = new RegExp(source, flags);
  }
  return holder.__ptkRegexCache[key];
}

function _cacheFlagsFromSpec(spec = {}) {
  if (typeof spec.flags === "string" && spec.flags) return spec.flags;
  if (spec.caseInsensitive || spec.ci) return "i";
  return "";
}

function _nodeToStaticString(node) {
  if (!node) return null;
  if (node.type === "Literal") return node.value != null ? String(node.value) : null;
  if (node.type === "TemplateLiteral" && (node.expressions || []).length === 0) {
    return node.quasis.map((q) => q?.value?.cooked || "").join("");
  }
  return null;
}

function _isFunctionLike(node) {
  if (!node) return false;
  return node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression";
}

function _matchValueConstraint(node, spec = {}) {
  if (!spec || typeof spec !== "object") return true;
  if (!node) return !spec.required;

  if (Array.isArray(spec.disallowTypes) && spec.disallowTypes.includes(node.type)) {
    return false;
  }
  if (spec.disallowFunction && _isFunctionLike(node)) {
    return false;
  }
  if (spec.requireStaticString && _nodeToStaticString(node) == null) {
    return false;
  }
  if ((spec.requireString || spec.isString) && !isStringIshExpression(node)) {
    return false;
  }
  if (spec.binaryExpression) {
    if (!node || node.type !== "BinaryExpression") return false;
    const op = spec.binaryExpression.operator;
    if (op && node.operator !== op) return false;
  }
  if (spec.regex) {
    const re = _getCachedRegex(spec, "value.regex", spec.regex, _cacheFlagsFromSpec(spec));
    const val = _nodeToStaticString(node);
    if (val == null || !re.test(String(val))) return false;
  }
  if (spec.equals != null) {
    const val = _nodeToStaticString(node);
    if (val == null) return false;
    const actual = String(val);
    const expected = String(spec.equals);
    if (spec.caseInsensitive || spec.ci) {
      if (actual.toLowerCase() !== expected.toLowerCase()) return false;
    } else if (actual !== expected) {
      return false;
    }
  }
  return true;
}

function _isStaticStringLiteral(node) {
  if (!node) return false;
  if (node.type === "Literal") return typeof node.value === "string";
  if (node.type === "StringLiteral") return true;
  return false;
}

function _isStableMemberProperty(node) {
  if (!node || node.type !== "MemberExpression") return false;
  if (!node.computed) return true;
  return _isStaticStringLiteral(node.property);
}

function _isDocumentReceiver(node) {
  if (!node) return false;
  if (node.type === "Identifier") return node.name === "document";
  if (node.type === "MemberExpression") {
    return _matchMemberChain(node, ["window", "document"]);
  }
  return false;
}

function _isJqueryCallee(callee) {
  if (!callee) return false;
  if (callee.type === "Identifier") {
    return callee.name === "$" || callee.name === "jQuery";
  }
  if (callee.type === "MemberExpression") {
    return _matchMemberChain(callee, ["window", "$"]) ||
      _matchMemberChain(callee, ["window", "jQuery"]) ||
      _matchMemberChain(callee, ["globalThis", "$"]) ||
      _matchMemberChain(callee, ["globalThis", "jQuery"]);
  }
  return false;
}

function _isJqueryChain(node, depth = 0) {
  if (!node || depth > 3) return false;
  if (node.type === "CallExpression") {
    if (_isJqueryCallee(node.callee)) return true;
    if (node.callee?.type === "MemberExpression") {
      const prop = _memberPropertyName(node.callee);
      if ((prop === "find" || prop === "on") && _isJqueryChain(node.callee.object, depth + 1)) {
        return true;
      }
    }
  }
  return false;
}

export function isStringIshExpression(expr) {
  if (!expr) return false;
  if (expr.type === "Literal") return typeof expr.value === "string";
  if (expr.type === "StringLiteral") return true;
  if (expr.type === "TemplateLiteral") return true;
  if (expr.type === "Identifier") return true;
  if (expr.type === "BinaryExpression" && expr.operator === "+") {
    return isStringIshExpression(expr.left) || isStringIshExpression(expr.right);
  }
  return false;
}

function _isDynamicStringCarrier(expr) {
  if (!expr) return false;
  if (isStringIshExpression(expr)) return true;
  return expr.type === "MemberExpression";
}

const INLINE_EVENT_HANDLER_PROPERTIES = new Set([
  "onabort", "onafterprint", "onanimationcancel", "onanimationend", "onanimationiteration", "onanimationstart",
  "onauxclick", "onbeforeinput", "onbeforematch", "onbeforeprint", "onbeforetoggle", "onbeforeunload",
  "onblur", "oncancel", "oncanplay", "oncanplaythrough", "onchange", "onclick", "onclose", "oncontextlost",
  "oncontextmenu", "oncontextrestored", "oncopy", "oncuechange", "oncut", "ondblclick", "ondrag", "ondragend",
  "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop", "ondurationchange", "onemptied", "onended",
  "onerror", "onfocus", "onformdata", "onfullscreenchange", "onfullscreenerror", "ongotpointercapture", "oninput",
  "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onload", "onloadeddata", "onloadedmetadata", "onloadstart",
  "onlostpointercapture", "onmessage", "onmessageerror", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove",
  "onmouseout", "onmouseover", "onmouseup", "onoffline", "ononline", "onpagehide", "onpageshow", "onpaste",
  "onpause", "onplay", "onplaying", "onpointercancel", "onpointerdown", "onpointerenter", "onpointerleave",
  "onpointermove", "onpointerout", "onpointerover", "onpointerup", "onpopstate", "onprogress", "onratechange",
  "onreadystatechange", "onreset", "onresize", "onscroll", "onscrollend", "onsecuritypolicyviolation", "onseeked",
  "onseeking", "onselect", "onselectstart", "onslotchange", "onstalled", "onstorage", "onsubmit", "onsuspend", "ontimeupdate",
  "ontoggle", "ontransitioncancel", "ontransitionend", "ontransitionrun", "ontransitionstart", "onunhandledrejection",
  "onunload", "onvolumechange", "onwaiting", "onwheel"
]);

export function isOnEventProperty(memberExpr) {
  if (!memberExpr || memberExpr.type !== "MemberExpression") return false;
  if (!_isStableMemberProperty(memberExpr)) return false;
  const prop = _memberPropertyName(memberExpr);
  if (!prop) return false;
  return INLINE_EVENT_HANDLER_PROPERTIES.has(String(prop).toLowerCase());
}

export function getEventHandlerSink(node) {
  if (!node) return null;
  if (node.type === "CallExpression") {
    const callee = node.callee;
    if (!callee || callee.type !== "MemberExpression") return null;
    if (!_isStableMemberProperty(callee)) return null;
    const prop = _memberPropertyName(callee);
    if (prop !== "setAttribute") return null;
    const nameNode = node.arguments?.[0];
    const valueNode = node.arguments?.[1];
    const name = _nodeToStaticString(nameNode);
    if (!name || !/^on[a-z]+$/i.test(String(name))) return null;
    if (!_isDynamicStringCarrier(valueNode)) return null;
    return { api: "setAttribute", eventName: String(name), valueNode };
  }
  if (node.type === "AssignmentExpression") {
    const left = node.left;
    if (!left || left.type !== "MemberExpression") return null;
    if (!isOnEventProperty(left)) return null;
    const valueNode = node.right;
    if (!_isDynamicStringCarrier(valueNode)) return null;
    const prop = _memberPropertyName(left);
    return { api: "property", eventName: String(prop || ""), valueNode };
  }
  return null;
}

function _calleeName(node) {
  if (!node) return "";
  if (node.type === "CallExpression" || node.type === "NewExpression") {
    return calleeNameFromCall(node) || "";
  }
  if (node.type === "Identifier") return node.name || "";
  if (node.type === "MemberExpression") return _memberPropertyName(node) || "";
  return "";
}

function _identifierLikeName(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name || "";
  if (node.type === "ThisExpression") return "this";
  if (node.type === "MemberExpression") {
    const prop = _memberPropertyName(node);
    if (prop) return prop;
  }
  return "";
}

function _looksLikeTemplateOutput(node) {
  if (!node) return false;
  if (node.type === "CallExpression") {
    const name = String(_calleeName(node) || "").toLowerCase();
    return /(?:template|tmpl|render|compile|mustache|handlebars|makehtml|tohtml|createhtml|unsafehtml|lit|jsx|html)$/.test(name);
  }
  if (node.type === "Identifier") {
    return /(?:template|tmpl|render|output|markup|html|content)/i.test(node.name || "");
  }
  if (node.type === "TemplateLiteral") {
    return (node.expressions || []).length > 0;
  }
  return false;
}

function _isHtmlSinkMember(node) {
  if (!node || node.type !== "MemberExpression") return false;
  const prop = _memberPropertyName(node);
  return /^(innerHTML|outerHTML)$/i.test(String(prop || ""));
}

export function isTemplateOutputDomInjection(node) {
  if (!node) return false;
  if (node.type === "AssignmentExpression") {
    if (!_isHtmlSinkMember(node.left)) return false;
    return _looksLikeTemplateOutput(node.right);
  }
  if (node.type === "CallExpression") {
    if (node.callee?.type !== "MemberExpression") return false;
    const prop = _memberPropertyName(node.callee);
    if (String(prop || "").toLowerCase() !== "html") return false;
    return _looksLikeTemplateOutput(node.arguments?.[0]);
  }
  return false;
}

export function isServiceWorkerCachePutCall(node) {
  if (!node || node.type !== "CallExpression") return false;
  if (node.arguments.length < 2) return false;
  if (node.callee?.type !== "MemberExpression") return false;
  const prop = _memberPropertyName(node.callee);
  if (prop !== "put") return false;
  const receiverName = String(_identifierLikeName(node.callee.object) || "").toLowerCase();
  if (!receiverName || !/cache/.test(receiverName)) return false;
  const firstArg = node.arguments?.[0];
  if (!firstArg) return false;
  if (_nodeToStaticString(firstArg) != null) return false;
  return true;
}

export function isDomSelectorCall(node) {
  if (!node || node.type !== "CallExpression") return null;
  const callee = node.callee;
  if (!callee) return null;
  if (_isJqueryCallee(callee)) {
    return { api: "jquery_root", argIndex: 0 };
  }
  if (callee.type !== "MemberExpression") return null;
  if (!_isStableMemberProperty(callee)) return null;
  const prop = _memberPropertyName(callee);
  if (!prop) return null;

  const documentOnly = new Set([
    "getElementById",
    "getElementsByClassName",
    "getElementsByTagName"
  ]);
  const queryMethods = new Set(["querySelector", "querySelectorAll"]);
  const elementOnly = new Set(["closest", "matches"]);
  const jqueryOnly = new Set(["find", "on"]);

  const receiver = callee.object;
  const isElementReceiver = receiver &&
    (receiver.type === "Identifier" || receiver.type === "MemberExpression" || receiver.type === "ThisExpression");

  if (documentOnly.has(prop)) {
    if (_isDocumentReceiver(receiver)) return { api: prop, argIndex: 0 };
    return null;
  }
  if (queryMethods.has(prop)) {
    if (_isDocumentReceiver(receiver) || isElementReceiver) return { api: prop, argIndex: 0 };
    return null;
  }
  if (elementOnly.has(prop)) {
    if (isElementReceiver) return { api: prop, argIndex: 0 };
    return null;
  }
  if (jqueryOnly.has(prop)) {
    if (_isJqueryChain(receiver)) {
      return { api: prop, argIndex: prop === "on" ? 1 : 0 };
    }
    return null;
  }
  return null;
}

function _matchCallee(callee, spec) {
  if (!callee || !spec) return false;
  if (spec.identifier || spec.name) {
    const id = callee.type === "Identifier" ? callee.name : null;
    const expect = spec.identifier || spec.name;
    if (!_wildEq(id, expect)) return false;
  }
  if (spec.identifierRegex) {
    const id = callee.type === "Identifier" ? callee.name : "";
    const re = _getCachedRegex(spec, "callee.identifierRegex", spec.identifierRegex, spec.caseInsensitive ? "i" : "");
    if (!re.test(String(id))) return false;
  }
  if (spec.member) {
    if (callee.type !== "MemberExpression") return false;
    if (!_matchMemberChain(callee, spec.member)) return false;
  }
  if (spec.memberAny?.of && Array.isArray(spec.memberAny.of)) {
    if (callee.type !== "MemberExpression") return false;
    const ok = spec.memberAny.of.some((cand) => _matchMemberChain(callee, cand));
    if (!ok) return false;
  }
  return true;
}

export function compilePattern(pattern) {
  try {
    const testers = [];

    if (pattern.custom) {
      const name = pattern.custom;
      testers.push((node) => {
        if (name === "dom_selector") return !!isDomSelectorCall(node);
        if (name === "event_handler_string") return !!getEventHandlerSink(node);
        if (name === "template_output_dom_injection") return !!isTemplateOutputDomInjection(node);
        if (name === "service_worker_cache_put") return !!isServiceWorkerCachePutCall(node);
        return false;
      });
    }

    if (pattern.identifier || pattern.identifierRegex) {
      const name = pattern.identifier;
      const re = pattern.identifierRegex ? _getCachedRegex(pattern, "pattern.identifierRegex", pattern.identifierRegex, pattern.caseInsensitive ? "i" : "") : null;
      testers.push((node) => {
        if (!node || node.type !== "Identifier") return false;
        if (name && !_wildEq(node.name, name)) return false;
        if (re && !re.test(String(node.name || ""))) return false;
        return true;
      });
    }

    if (pattern.call) {
      const p = pattern.call;
      const hasDisc = !!(p.callee || p.calleeProp || p.calleePropRegex);
      testers.push((node) => {
        if (!node || node.type !== "CallExpression") return false;
        if (typeof p.maxArgs === "number" && node.arguments.length > p.maxArgs) return false;
        if (!hasDisc && !(Array.isArray(p.args) && p.args.length)) return false;
        if (p.callee && !_matchCallee(node.callee, p.callee)) return false;
        if (p.calleeProp) {
          if (node.callee?.type !== "MemberExpression") return false;
          const prop = _memberPropertyName(node.callee);
          if (!_wildEq(prop, p.calleeProp)) return false;
        }
        if (p.calleePropRegex) {
          if (node.callee?.type !== "MemberExpression") return false;
          const prop = _memberPropertyName(node.callee) || "";
          const re = _getCachedRegex(p, "call.calleePropRegex", p.calleePropRegex, p.calleePropCaseInsensitive ? "i" : "");
          if (!re.test(String(prop))) return false;
        }
        if (Array.isArray(p.args)) {
          for (const argSpec of p.args) {
            const idx = Number(argSpec.index ?? -1);
            if (!Number.isFinite(idx) || idx < 0) continue;
            const hasArg = idx < node.arguments.length;
            if (!hasArg) {
              if (argSpec.optional) continue;
              return false;
            }
            const argNode = node.arguments[idx];
            if (!_matchValueConstraint(argNode, argSpec)) {
              return false;
            }
          }
        }
        return true;
      });
    }

    if (pattern.new) {
      const p = pattern.new;
      testers.push((node) => {
        if (!node || node.type !== "NewExpression") return false;
        if (p.callee && !_matchCallee(node.callee, p.callee)) return false;
        return true;
      });
    }

    if (pattern.member) {
      const m = pattern.member;
      testers.push((node) => {
        if (!node || node.type !== "MemberExpression") return false;
        return _matchMemberChain(node, m);
      });
    }

    if (pattern.await) {
      testers.push((node) => {
        if (!node || node.type !== "AwaitExpression") return false;
        return true;
      });
    }

    if (pattern.memberAny?.of && Array.isArray(pattern.memberAny.of)) {
      const candidates = pattern.memberAny.of;
      testers.push((node) => {
        if (!node || node.type !== "MemberExpression") return false;
        return candidates.some((cand) => _matchMemberChain(node, cand));
      });
    }

    if (pattern.assignment) {
      const a = pattern.assignment;
      const hasLeft = !!(a.leftMember || (a.left && (a.left.member || a.left.memberProp || a.left.memberPropRegex || a.left.identifier || a.left.chainMember)));
      testers.push((node) => {
        if (!node || node.type !== "AssignmentExpression") return false;
        const left = (a && a.left) || {};
        const hasConstraint = !!(a.leftMember || left.member || left.memberProp || left.memberPropRegex || left.identifier || left.chainMember);
        if (!hasConstraint) return false;

        if (a.leftMember) {
          if (!(node.left && node.left.type === "MemberExpression")) return false;
          if (!_matchMemberChain(node.left, a.leftMember)) return false;
        }
        if (left.member) {
          if (!(node.left && node.left.type === "MemberExpression")) return false;
          if (!_matchMemberChain(node.left, left.member)) return false;
        }
        if (left.memberProp) {
          if (!(node.left && node.left.type === "MemberExpression")) return false;
          const prop = _memberPropertyName(node.left);
          if (!_wildEq(prop, left.memberProp)) return false;
        }
        if (left.memberPropRegex) {
          if (!(node.left && node.left.type === "MemberExpression")) return false;
          const prop = _memberPropertyName(node.left) || "";
          const re2 = new RegExp(left.memberPropRegex, left.caseInsensitive ? "i" : "");
          if (!re2.test(String(prop))) return false;
        }
        if (left.identifier) {
          if (!(node.left && node.left.type === "Identifier" && _wildEq(node.left.name, left.identifier))) return false;
        }
        if (left.chainMember) {
          let cur = node.left;
          let found = false;
          while (cur && cur.type === "MemberExpression") {
            const prop = _memberPropertyName(cur);
            if (prop === left.chainMember) { found = true; break; }
            cur = cur.object;
          }
          if (!found) return false;
        }
        if (a.right && !_matchValueConstraint(node.right, a.right)) {
          return false;
        }
        return true;
      });
    }

    if (!testers.length) return () => false;
    const expectedType = (
      pattern.call ? "CallExpression" :
        pattern.assignment ? "AssignmentExpression" :
          pattern.member ? "MemberExpression" :
            pattern.new ? "NewExpression" :
              null
    );

    return (node, ancestors) => {
      if (expectedType && node.type !== expectedType) return false;
      try {
        for (const t of testers) {
          if (!t(node, ancestors)) return false;
        }
        return true;
      } catch {
        return false;
      }
    };
  } catch {
    return () => false;
  }
}

/* ────────────────────────────── Taint graph primitives ────────────────────────────── */

export class Origin {
  constructor(kind, node, label, fileId, loc, sourceId, taintKinds) {
    this.kind = kind || "generic";
    this.node = node || null;
    this.label = label || "";
    this.fileId = fileId ?? null;
    this.loc = loc || null;
    this.sourceId = sourceId || null;
    this.taintKinds = taintKinds ? new Set(taintKinds) : null;
  }
}

const MAX_ORIGINS_PER_NODE = 12;

export class TaintGraph {
  constructor() {
    this._nodeIds = new WeakMap();      // astNode -> nodeId
    this._idToNode = new Map();         // nodeId -> astNode
    this._nextNodeId = 1;

    this._edges = new Map();            // toId -> [{ fromNodeId, edgeKind, meta }]
    this._origins = new Map();          // nodeId -> Set(originId)
    this._sanitizers = new Map();       // nodeId -> Set(sanitizerId)
    this._sourceNodes = new Set();      // nodeId -> explicit source origin
  }

  nodeIdForAstNode(node) {
    if (!node) return null;
    if (this._nodeIds.has(node)) return this._nodeIds.get(node);
    const id = this._nextNodeId++;
    this._nodeIds.set(node, id);
    this._idToNode.set(id, node);
    return id;
  }

  astNodeForId(id) {
    return this._idToNode.get(id) || null;
  }

  _mergeOriginSets(targetSet, sourceSet) {
    if (!sourceSet || !sourceSet.size) return targetSet;
    const out = targetSet || new Set();
    for (const o of sourceSet) {
      out.add(o);
      if (out.size >= MAX_ORIGINS_PER_NODE) break;
    }
    return out;
  }

  addEdge(fromNode, toNode, edgeKind = "flow", meta = null) {
    const fromId = this.nodeIdForAstNode(fromNode);
    const toId = this.nodeIdForAstNode(toNode);
    if (!fromId || !toId) return;
    const entry = { fromNodeId: fromId, edgeKind, meta: meta || null };
    if (!this._edges.has(toId)) this._edges.set(toId, []);
    this._edges.get(toId).push(entry);

    // propagate origins
    if (this._sourceNodes.has(toId)) return;
    const fromOrigins = this._origins.get(fromId);
    if (fromOrigins && fromOrigins.size) {
      const merged = this._mergeOriginSets(this._origins.get(toId), fromOrigins);
      if (merged) this._origins.set(toId, merged);
    }
  }

  markNodeAsSource(nodeId) {
    if (nodeId == null) return;
    this._sourceNodes.add(nodeId);
    this._origins.delete(nodeId);
  }

  isSourceNode(nodeId) {
    return this._sourceNodes.has(nodeId);
  }

  getUpstream(nodeId) {
    if (!nodeId) return [];
    return this._edges.get(nodeId) || [];
  }

  markNodeWithOrigin(nodeId, originId) {
    if (nodeId == null || originId == null) return;
    const set = this._origins.get(nodeId) || new Set();
    if (set.size < MAX_ORIGINS_PER_NODE) set.add(originId);
    this._origins.set(nodeId, set);
  }

  getOrigins(nodeId) {
    return this._origins.get(nodeId);
  }

  removeOrigin(nodeId, originId) {
    if (nodeId == null || originId == null) return;
    const set = this._origins.get(nodeId);
    if (!set) return;
    set.delete(originId);
    if (!set.size) this._origins.delete(nodeId);
  }

  markNodeAsSanitized(nodeId, sanitizerIds) {
    if (!nodeId || !sanitizerIds || !sanitizerIds.length) return;
    const existing = this._sanitizers.get(nodeId) || new Set();
    for (const s of sanitizerIds) existing.add(s);
    this._sanitizers.set(nodeId, existing);
  }

  getSanitizers(nodeId) {
    const set = this._sanitizers.get(nodeId);
    return set ? Array.from(set) : undefined;
  }
}

/* ───────────────────────────── Utility: callee stringifiers ───────────────────────────── */

export function calleeNameFromPattern(pat) {
  if (!pat) return null;
  if (pat.member && Array.isArray(pat.member)) return pat.member.join(".");
  if (pat.identifier) return String(pat.identifier);
  if (pat.name) return String(pat.name);
  if (pat.calleeProp) return String(pat.calleeProp);
  return null;
}

export function calleeNameFromCall(node) {
  if (!node || node.type !== "CallExpression") return null;
  const callee = node.callee;
  if (!callee) return null;
  if (callee.type === "Identifier") return callee.name;
  if (callee.type === "MemberExpression") {
    const parts = [];
    let cur = callee;
    while (cur && cur.type === "MemberExpression") {
      const prop = _memberPropertyName(cur);
      if (prop == null) break;
      parts.unshift(prop);
      cur = cur.object;
    }
    if (cur?.type === "Identifier") parts.unshift(cur.name);
    else if (cur?.type === "ThisExpression") parts.unshift("this");
    return parts.length ? parts.join(".") : null;
  }
  return null;
}
