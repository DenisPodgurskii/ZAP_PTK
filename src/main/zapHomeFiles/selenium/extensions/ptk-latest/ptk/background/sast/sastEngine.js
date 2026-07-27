/* Author: Denis Podgurskii */

import * as acorn from "./acorn/acorn.mjs";
import { Parser } from "./acorn/acorn.mjs";
import { full, ancestor, base } from "./acorn/walk.mjs";
import { ptk_sast_module } from "./modules/module.js";
import { assertRulepackCatalogCompatibility } from "./catalog_validation.js";
import { buildGlobalTaintContext } from "./modules/taint_propagation.js";
import { extractSastCodeArtifacts } from "./artifactExtraction.js";
import { createEmitter } from '../lib/emitter.js';
import { normalizeRulepack } from '../common/severity_utils.js';

const NAMED_ENTITIES = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: "\"",
  apos: "'",
  nbsp: "\u00a0",
  sol: "/",
  slash: "/"
};

const LOCAL_SAST_RULEPACK_URL = new URL("./modules/modules.json", import.meta.url);
const LOCAL_SAST_CATALOG_URL = new URL("./modules/catalog.json", import.meta.url);

async function loadJsonAsset(url) {
  const assetUrl = url instanceof URL ? url : new URL(String(url || ""), import.meta.url);
  if (assetUrl.protocol === "file:") {
    // Node-based tests hit file:// URLs while the extension uses fetchable extension URLs.
    const dynamicImport = new Function("specifier", "return import(specifier)");
    const fs = await dynamicImport("node:fs/promises");
    const raw = await fs.readFile(assetUrl, "utf8");
    return JSON.parse(raw);
  }
  const response = await fetch(assetUrl.href);
  if (!response.ok) {
    throw new Error(`[SAST] Failed to load asset ${assetUrl.href}: HTTP ${response.status}`);
  }
  return response.json();
}

function safeOrigin(value) {
  try {
    return new URL(String(value || "")).origin || null;
  } catch {
    return null;
  }
}

function isThirdPartyScriptForPage(scriptUrl, pageUrl) {
  const scriptOrigin = safeOrigin(scriptUrl);
  const pageOrigin = safeOrigin(pageUrl);
  if (!scriptOrigin || !pageOrigin) return false;
  return scriptOrigin !== pageOrigin;
}

function isLikelyTruncatedExternalScriptCapture(script, code) {
  if (!script?.src || typeof code !== "string") return false;
  if (script.truncated === true) return true;
  const length = code.length;
  return length === 512 * 1024 || length === 1024 * 1024;
}

function hasCatalogData(catalog) {
  if (!catalog || typeof catalog !== "object") return false;
  return [
    "sources",
    "sinks",
    "sanitizers",
    "propagators",
    "libraries",
    "libraryBindings"
  ].some((key) => {
    const value = catalog[key];
    return !!(value && typeof value === "object" && Object.keys(value).length);
  });
}

function decodeHtmlEntities(str) {
  if (typeof str !== "string" || !str.includes("&")) return str;
  return str.replace(/&(#x?[0-9a-fA-F]+|\w+);/g, (match, entity) => {
    if (!entity) return match;
    if (entity[0] === "#") {
      const isHex = entity[1]?.toLowerCase() === "x";
      const num = parseInt(entity.slice(isHex ? 2 : 1), isHex ? 16 : 10);
      if (Number.isFinite(num)) {
        try {
          return String.fromCodePoint(num);
        } catch {
          return match;
        }
      }
      return match;
    }
    const decoded = NAMED_ENTITIES[entity.toLowerCase()];
    return decoded !== undefined ? decoded : match;
  });
}

function isExecutableScriptType(rawType) {
  const type = String(rawType || "").trim().toLowerCase();
  if (!type || type === "module") return true;
  return /^(?:text|application)\/(?:javascript|ecmascript|x-javascript|x-ecmascript)$/i.test(type);
}

function normalizeInlineHandlerSnippetKey(value) {
  return String(value || "").trim().replace(/\s+/g, " ").replace(/;+\s*$/g, "");
}

/* ──────────────────────────────── Library-ignore helpers (catalog-driven) ─────────────────────────────── */

function miniMatch(pathname, glob) {
  // tiny nocase minimatch subset good enough for **/node_modules/x/**
  // supports "**" and "*" wildcards only
  const esc = (s) => s.replace(/[.+^${}()|[\]\\*]/g, "\\$&");
  const pat = String(glob)
    .split("**")
    .map((chunk) => esc(chunk).replace(/\\\*/g, "[^/]*"))
    .join(".*");
  const re = new RegExp("^" + pat + "$", "i");
  return re.test(pathname);
}

// Cross-runtime byte length (works in browser and Node)
function byteLen(str) {
  try {
    if (typeof TextEncoder !== "undefined") {
      return new TextEncoder().encode(str || "").length;
    }
  } catch (_) { /* ignore */ }
  // Fallback: UTF-8 length via encodeURIComponent
  try {
    return unescape(encodeURIComponent(str || "")).length;
  } catch (_) {
    return (str || "").length; // last resort
  }
}

// Normalize a file id / URL into multiple comparable keys
function normKeys(raw) {
  if (!raw) return [];
  const s = String(raw);
  const noHash = s.split('#')[0];
  const noQuery = noHash.split('?')[0];
  try {
    const u = new URL(noQuery);
    const hostPath = u.hostname + u.pathname;     // e.g., "code.jquery.com/jquery-3.7.1.min.js"
    const base = u.pathname.split('/').pop();     // e.g., "jquery-3.7.1.min.js"
    return Array.from(new Set([s, noHash, noQuery, hostPath, base]));
  } catch {
    const base = noQuery.split('/').pop();
    return Array.from(new Set([s, noHash, noQuery, base]));
  }
}


function getActiveLibraryDefs(catalog) {
  const libs = catalog?.libraries || {};
  const lb = catalog?.libraryBindings || {};
  if (!lb || lb.enabled === false) return { defs: [], unignore: [] };

  const defs = (lb.bindings || [])
    .map((b) => {
      const base = libs[b.id];
      if (!base) return null;
      return {
        id: base.id,
        displayName: b.displayName || base.displayName || base.id,
        match: b.match || base.match || {},
        mode: b.mode || base.mode || "parse_no_report",
        notes: base.notes || "",
      };
    })
    .filter(Boolean);

  return { defs, unignore: lb.overrides?.unignore || [] };
}

function matchesLibrary(fileMeta, libDef) {
  const m = libDef.match || {};
  const byPkg =
    Array.isArray(m.packageNames) &&
    Array.isArray(fileMeta.packages) &&
    fileMeta.packages.some((p) => m.packageNames.includes(p));
  const byPath =
    Array.isArray(m.paths) &&
    m.paths.some((g) => miniMatch(fileMeta.path || "", g));
  const byBanner = m.bannerRegex
    ? new RegExp(m.bannerRegex).test(fileMeta.banner || "")
    : false;
  const byHash =
    Array.isArray(m.fileHashes) &&
    (fileMeta.sha1 ? m.fileHashes.includes(fileMeta.sha1) : false);

  return !!(byPkg || byPath || byBanner || byHash);
}

function classifyFileLibrary(fileMeta, active) {
  if (!active || !active.defs || !active.defs.length) return null;
  if (
    Array.isArray(active.unignore) &&
    active.unignore.some((g) => miniMatch(fileMeta.path || "", g))
  )
    return null;

  for (const lib of active.defs) {
    if (matchesLibrary(fileMeta, lib)) {
      return { libId: lib.id, mode: lib.mode, displayName: lib.displayName };
    }
  }
  return null;
}

/* ───────────────────────────────────────────────────────────────────────────── */

export class sastEngine {
  constructor(scanStrategy, opts) {
    // Old (sync) approach depended on immediate imports.
    // Now we load JSON packs asynchronously, so keep a promise.
    this.rules = [];
    this._scanStrategy = scanStrategy;
    this._scanId = opts?.scanId || null;
    this._FINDINGS_LIMIT = opts?.FINDINGS_LIMIT || 300
    this._allowFetchExternalScripts = opts?.allowFetchExternalScripts !== false;
    this._allowFetchPageSourceScripts = opts?.allowFetchPageSourceScripts !== false;
    this._maxFetchedPageSourceBytes = Number.isFinite(Number(opts?.maxFetchedPageSourceBytes))
      ? Math.max(0, Number(opts.maxFetchedPageSourceBytes))
      : 2 * 1024 * 1024;
    this._pageSourceScriptCache = new Map();

    // Catalog-driven libraries (optional; no policy needed)
    this._catalog = {};
    this._activeLibs = getActiveLibraryDefs(this._catalog);
    this._libByFile = new Map(); // fileId -> { libId, mode, displayName }
    this._runtimeAssetsReady = false;

    this._setCatalog(opts?.catalog || {});
    this._setRulepack(opts?.rulepack || opts?.modules || {});
    this.events = createEmitter({ async: true, replay: 1 });
  }

  async fetchExternalScriptCode(scriptUrl, pageUrl = "") {
    let script;
    let page;
    try {
      script = new URL(String(scriptUrl || ""));
      page = new URL(String(pageUrl || ""));
    } catch {
      throw new Error("invalid_script_url");
    }
    if (!["http:", "https:"].includes(script.protocol) || !["http:", "https:"].includes(page.protocol)) {
      throw new Error("unsupported_script_protocol");
    }
    if (script.origin !== page.origin) {
      throw new Error("external_script_outside_page_origin");
    }
    const res = await fetch(script.href, {
      credentials: "include",
      cache: "force-cache",
      redirect: "error"
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return res.text();
  }

  _setCatalog(catalog) {
    this._catalog = (catalog && typeof catalog === "object") ? catalog : {};
    this._activeLibs = getActiveLibraryDefs(this._catalog);
  }

  _setRulepack(rulepack) {
    const nextRulepack = (rulepack && typeof rulepack === "object") ? rulepack : {};
    normalizeRulepack(nextRulepack, { engine: "SAST", childKey: "rules" });
    if (hasCatalogData(this._catalog)) {
      assertRulepackCatalogCompatibility(nextRulepack, this._catalog, { label: "SAST engine rulepack" });
    }
    this._rulepack = nextRulepack;
    this._rulepackEngine = nextRulepack.engine || null;
    this._rulepackVersion = nextRulepack.version || null;
    const rawModules = nextRulepack?.modules;
    const moduleDefs = Array.isArray(rawModules)
      ? rawModules
      : Object.values(rawModules || {});
    this.modules = moduleDefs.map(
      (m) =>
        new ptk_sast_module(m, {
          sources: this._catalog.sources || {},
          sinks: this._catalog.sinks || {},
          sanitizers: this._catalog.sanitizers || {},
          propagators: this._catalog.propagators || {},
        })
    );
  }

  async _ensureRuntimeAssets() {
    const catalogReady = hasCatalogData(this._catalog);
    const modulesReady = Array.isArray(this.modules) && this.modules.length > 0;
    if (catalogReady && modulesReady && this._runtimeAssetsReady) {
      return;
    }

    let catalogChanged = false;
    if (!catalogReady) {
      this._setCatalog(await loadJsonAsset(LOCAL_SAST_CATALOG_URL));
      catalogChanged = true;
    }

    if (!modulesReady) {
      this._setRulepack(await loadJsonAsset(LOCAL_SAST_RULEPACK_URL));
      this._runtimeAssetsReady = true;
      return;
    }

    if (catalogChanged) {
      // Recompile rules so taint source/sink bindings use the now-loaded catalog.
      this._setRulepack(this._rulepack || {});
    }

    this._runtimeAssetsReady = true;
  }

  /**
   * Add a single rule at runtime
   */
  addRule(rule) {
    if (!this.rules) this.rules = [];
    this.rules.push(rule);
  }

  // Deprecated: kept for compatibility; always returns false now.
  // Classification is handled via catalog/libraryBindings instead.
  shouldIgnoreLibrary(_fileId = "", _code = "") {
    return false;
  }

  async buildMergedAST(files) {
    // files: [ { code: string, sourceFile: string }, { … } ]
    // Parse the first file normally:
    let mergedAst = Parser.parse(files[0].code, {
      ecmaVersion: "latest",
      sourceType: "module",
      locations: true,
      sourceFile: files[0].sourceFile,
    });

    // For each subsequent file, parse with `program: mergedAst` so its top‐level nodes append into mergedAst.body
    for (let i = 1; i < files.length; i++) {
      const { code, sourceFile } = files[i];
      mergedAst = Parser.parse(code, {
        ecmaVersion: "latest",
        sourceType: "module",
        locations: true,
        sourceFile,
        program: mergedAst,
      });
    }

    return mergedAst; // this is a Program node, with `mergedAst.body = […]`
  }

  // extractInlineHandlers(htmlText) {
  //   const patterns = [
  //     "onclick",
  //     "ondblclick",
  //     "onmousedown",
  //     "onmouseup",
  //     "onmouseover",
  //     "onmouseout",
  //     "onmousemove",
  //     "onmouseenter",
  //     "onmouseleave",
  //     "onkeydown",
  //     "onkeyup",
  //     "onkeypress",
  //     "oninput",
  //     "onchange",
  //     "onfocus",
  //     "onblur",
  //     "onsubmit",
  //     "onreset",
  //     "onselect",
  //     "oncontextmenu",
  //     "onwheel",
  //     "ondrag",
  //     "ondrop",
  //     "onload",
  //     "onunload",
  //     "onabort",
  //     "onerror",
  //     "onresize",
  //     "onscroll",
  //   ];

  //   const snippets = [];
  //   for (const attr of patterns) {
  //     const re = new RegExp(
  //       `\\b${attr}\\s*=\\s*"(?:[\\s\\S]*?)"|\\b${attr}\\s*=\\s*'(?:[\\s\\S]*?)'`,
  //       "gi"
  //     );
  //     let match;
  //     while ((match = re.exec(htmlText))) {
  //       const full = match[0];
  //       const inner = full
  //         .replace(new RegExp(`^\\s*${attr}\\s*=\\s*["']`), "")
  //         .replace(/["']\s*$/, "");
  //       snippets.push(inner);
  //     }
  //   }
  //   return snippets;
  // }

  extractInlineHandlers(htmlText) {
    const patterns = new Set([
      "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmouseout",
      "onmousemove", "onmouseenter", "onmouseleave", "onkeydown", "onkeyup", "onkeypress",
      "oninput", "onchange", "onfocus", "onblur", "onsubmit", "onreset", "onselect",
      "oncontextmenu", "onwheel", "ondrag", "ondrop", "onload", "onunload", "onabort",
      "onerror", "onresize", "onscroll",
    ]);
    const snippets = [];
    const seen = new Set();
    const re = /\bon[a-z]+\s*=\s*(['"])/gi;
    let match;
    while ((match = re.exec(htmlText))) {
      const attr = match[0].split("=")[0].trim().toLowerCase();
      if (!patterns.has(attr)) continue;
      const quote = match[1];
      let idx = match.index + match[0].length;
      let inBracket = 0;
      while (idx < htmlText.length) {
        const ch = htmlText[idx];
        if (ch === "\\") {
          idx += 2;
          continue;
        }
        if (ch === "[") {
          inBracket += 1;
        } else if (ch === "]" && inBracket) {
          inBracket -= 1;
        }
        if (ch === quote && !inBracket) {
          const nextChar = htmlText[idx + 1];
          if (!nextChar || /\s|>|\/|$/.test(nextChar)) {
            re.lastIndex = idx + 1;
            break;
          }
        }
        idx += 1;
      }
      const decoded = decodeHtmlEntities(htmlText.slice(match.index + match[0].length, idx));
      const key = decoded.trim().replace(/\s+/g, " ").replace(/;+\s*$/g, "");
      if (!seen.has(key)) {
        seen.add(key);
        snippets.push(decoded);
      }
    }
    return snippets;
  }

  normalizeInlineHandlersPayload(htmlPayload) {
    if (!Array.isArray(htmlPayload)) {
      return this.extractInlineHandlers(htmlPayload || "");
    }

    const snippets = [];
    const seen = new Set();
    for (const entry of htmlPayload) {
      if (typeof entry !== "string") continue;
      const key = normalizeInlineHandlerSnippetKey(entry);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      snippets.push(entry);
    }
    return snippets;
  }

  extractInlineJavaScriptUrls(htmlText) {
    if (typeof htmlText !== "string" || !htmlText) return [];
    const snippets = [];
    const seen = new Set();
    const attrRe = /\b(?:href|xlink:href|action|formaction|src|data)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;
    let match;
    while ((match = attrRe.exec(htmlText)) !== null) {
      const rawValue = match[1] ?? match[2] ?? match[3] ?? "";
      const decoded = decodeHtmlEntities(rawValue).trim();
      if (!/^javascript\s*:/i.test(decoded)) continue;
      const snippet = decoded.replace(/^javascript\s*:/i, "").trim();
      const key = normalizeInlineHandlerSnippetKey(snippet);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      snippets.push(snippet);
    }
    return snippets;
  }

  extractScriptsFromPageSource(html, pageUrl = "") {
    if (typeof html !== "string" || !html) return [];
    const pageOrigin = safeOrigin(pageUrl);
    const scripts = [];
    const seen = new Set();
    const scriptTagRe = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
    const attrRe = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

    const parseAttrs = (rawAttrs = "") => {
      const attrs = Object.create(null);
      let match;
      while ((match = attrRe.exec(rawAttrs)) !== null) {
        const name = String(match[1] || "").trim().toLowerCase();
        if (!name) continue;
        attrs[name] = decodeHtmlEntities(match[2] ?? match[3] ?? match[4] ?? "");
      }
      return attrs;
    };

    const addScript = (script) => {
      if (!script) return;
      const src = script.src || null;
      const code = src ? null : String(script.code || "");
      if (!src && !code.trim()) return;
      const key = src ? `src:${src}` : `inline:${code}`;
      if (seen.has(key)) return;
      seen.add(key);
      scripts.push({ src, code });
    };

    let match;
    while ((match = scriptTagRe.exec(html)) !== null) {
      const attrs = parseAttrs(match[1] || "");
      if (!isExecutableScriptType(attrs.type || "")) continue;
      if (attrs.src) {
        try {
          const resolved = new URL(attrs.src, pageUrl).href;
          if (pageOrigin && safeOrigin(resolved) !== pageOrigin) continue;
          addScript({ src: resolved, code: null });
        } catch (_) { }
        continue;
      }
      addScript({ src: null, code: decodeHtmlEntities(match[2] || "") });
    }

    return scripts;
  }

  async collectPageSourceScripts(pageUrl = "") {
    if (!this._allowFetchPageSourceScripts || !pageUrl) return [];
    let fetchUrl;
    try {
      const parsed = new URL(pageUrl);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return [];
      parsed.hash = "";
      fetchUrl = parsed.href;
    } catch (_) {
      return [];
    }

    if (this._pageSourceScriptCache.has(fetchUrl)) {
      return this._pageSourceScriptCache.get(fetchUrl);
    }

    try {
      const response = await fetch(fetchUrl, { credentials: "include" });
      if (!response?.ok) {
        this._pageSourceScriptCache.set(fetchUrl, []);
        return [];
      }
      const text = await response.text();
      const bounded = this._maxFetchedPageSourceBytes > 0 && text.length > this._maxFetchedPageSourceBytes
        ? text.slice(0, this._maxFetchedPageSourceBytes)
        : text;
      const scripts = this.extractScriptsFromPageSource(bounded, fetchUrl);
      this._pageSourceScriptCache.set(fetchUrl, scripts);
      return scripts;
    } catch (err) {
      console.warn("[SAST] page source fetch failed:", fetchUrl, err?.message || String(err));
      this._pageSourceScriptCache.set(fetchUrl, []);
      return [];
    }
  }

  async scanCodeDetailed(scripts, html = "", file = "", options = {}) {
    try {
      await this._ensureRuntimeAssets();
      const generation = Number(options?.generation || 0) || null;
      const collectionId = options?.collectionId || null;

      if (!Array.isArray(this.modules) || !this.modules.length) {
        console.warn("SAST: modules not loaded; skipping scan.");
        return {
          findings: [],
          artifacts: {
            sast: {
              version: 2,
              routes: [],
              endpoints: [],
              graphql: [],
              surfaces: [],
              hiddenParams: [],
              gadgets: []
            }
          }
        };
      }

      const pageSourceScripts = await this.collectPageSourceScripts(file);
      if (pageSourceScripts.length) {
        const indexByKey = new Map();
        const merged = [];
        const keyForScript = (script) => {
          if (script?.src) return `src:${script.src}`;
          const code = typeof script?.code === "string" ? script.code : "";
          return code.trim() ? `inline:${code}` : "";
        };
        const addScript = (script) => {
          const key = keyForScript(script);
          if (!key) return;
          if (indexByKey.has(key)) {
            const index = indexByKey.get(key);
            const existing = merged[index] || null;
            const existingCode = typeof existing?.code === "string" ? existing.code : "";
            const nextCode = typeof script?.code === "string" ? script.code : "";
            if (!existingCode.trim() && nextCode.trim()) {
              merged[index] = script;
            }
            return;
          }
          indexByKey.set(key, merged.length);
          merged.push(script);
        };
        (Array.isArray(scripts) ? scripts : []).forEach(addScript);
        pageSourceScripts.forEach(addScript);
        scripts = merged;
      }

      scripts = (Array.isArray(scripts) ? scripts : []).sort((a, b) => {
        const aIsInline = a.src === null;
        const bIsInline = b.src === null;
        if (aIsInline === bIsInline) return 0;
        return aIsInline ? 1 : -1;
      });

      // Content-side collection can send inline handlers directly so we do not
      // have to serialize the full DOM HTML for SAST.
      const inlineHandlerSnippets = this.normalizeInlineHandlersPayload(html);
      const inlineJavaScriptUrlSnippets = Array.isArray(html)
        ? []
        : this.extractInlineJavaScriptUrls(html || "");
      const inlineSnippets = [
        ...inlineHandlerSnippets.map((code, index) => ({
          code,
          label: `inline-onclick[#${index}]`,
          parseLabel: "inline onclick snippet"
        })),
        ...inlineJavaScriptUrlSnippets.map((code, index) => ({
          code,
          label: `inline-js-url[#${index}]`,
          parseLabel: "inline javascript URL snippet"
        }))
      ];
      const totalFiles = (Array.isArray(scripts) ? scripts.length : 0) + inlineSnippets.length;
      let collectionSummaryEmitted = false;
      const emptySastArtifacts = () => ({
        sast: {
          version: 2,
          routes: [],
          endpoints: [],
          graphql: [],
          surfaces: [],
          hiddenParams: [],
          gadgets: []
        }
      });
      const countSastArtifacts = (artifactBundle = null) => {
        const sastArtifacts = artifactBundle?.sast && typeof artifactBundle.sast === "object"
          ? artifactBundle.sast
          : {};
        return {
          routes: Array.isArray(sastArtifacts.routes) ? sastArtifacts.routes.length : 0,
          endpoints: Array.isArray(sastArtifacts.endpoints) ? sastArtifacts.endpoints.length : 0,
          graphql: Array.isArray(sastArtifacts.graphql) ? sastArtifacts.graphql.length : 0,
          surfaces: Array.isArray(sastArtifacts.surfaces) ? sastArtifacts.surfaces.length : 0,
          hiddenParams: Array.isArray(sastArtifacts.hiddenParams) ? sastArtifacts.hiddenParams.length : 0,
          gadgets: Array.isArray(sastArtifacts.gadgets) ? sastArtifacts.gadgets.length : 0
        };
      };
      const emitCollectionSummary = ({ findings = [], artifacts = null } = {}) => {
        if (collectionSummaryEmitted) return;
        collectionSummaryEmitted = true;
        this.events.emit("collection:summary", {
          scanId: this._scanId,
          collectionId,
          generation,
          totalFiles,
          totalModules: Array.isArray(this.modules) ? this.modules.length : 0,
          totalFindings: Array.isArray(findings) ? findings.length : Number(findings || 0),
          totalArtifacts: countSastArtifacts(artifacts)
        });
      };
      this.events.emit("collection:analysis:start", {
        scanId: this._scanId,
        collectionId,
        generation,
        scanStrategy: this._scanStrategy,
        totalFiles
      });

      const codeByFile = Object.create(null);
      const allBodies = [];
      const allComments = [];
      const seenFiles = [];
      const seenSet = new Set();
      const fetchedScriptFiles = [];
      const fetchFailures = [];
      const parseFailures = [];
      const skippedLibraries = [];
      let templateAST = null;
      let fileIndex = 0;

      const pushFile = (id) => {
        if (!seenSet.has(id)) {
          seenSet.add(id);
          seenFiles.push({ file: id, index: fileIndex++ });
        }
      };
      const pageScopedInlineFileId = (label) => file ? `${file} :: ${label}` : label;

      for (const script of scripts) {
        const fileId = script.src || pageScopedInlineFileId(`inline-script[#${allBodies.length}]`);
        this.events.emit("file:start", { scanId: this._scanId, collectionId, generation, file: fileId, index: seenFiles.length, totalFiles });
        pushFile(fileId);

        const captured = typeof script.code === "string" ? script.code : "";
        const hasCaptured = Boolean(captured && captured.trim().length);
        let code = hasCaptured ? captured : "";

        const capturedLooksTruncated = isLikelyTruncatedExternalScriptCapture(script, captured);
        if (script.src && (!hasCaptured || capturedLooksTruncated)) {
          if (this._allowFetchExternalScripts) {
            this.events.emit("progress", { message: "Parsing external scripts", file: script.src });
            try {
              code = await this.fetchExternalScriptCode(script.src, file);
              fetchedScriptFiles.push(fileId);
            } catch (err) {
              const errorText = err?.message || String(err);
              const thirdParty = isThirdPartyScriptForPage(fileId, file);
              fetchFailures.push({
                file: fileId,
                error: capturedLooksTruncated
                  ? `truncated_capture_refetch_failed:${errorText}`
                  : errorText,
                thirdParty
              });
              if (!thirdParty) {
                console.warn("[SAST] external script fetch failed:", fileId, errorText);
              }
              continue;
            }
          } else if (!hasCaptured || capturedLooksTruncated) {
            continue;
          }
        }
        codeByFile[fileId] = code;

        const bannerMatch = code.match(/^\/\*![\s\S]*?\*\//);
        const fileMeta = {
          path: String(fileId),
          packages: null,
          banner: (bannerMatch && bannerMatch[0]) || "",
          sha1: null,
          sizeKB: Math.ceil(byteLen(code) / 1024),
        };

        const lib = classifyFileLibrary(fileMeta, this._activeLibs);
        if (lib) {
          const keys = normKeys(fileId);
          for (const k of keys) this._libByFile.set(k, lib);
          //console.info('[LIB:match]', lib.libId, lib.mode, '=>', keys.join(' | '));
        } else {
          //console.info('[LIB:nomatch]', fileId);
        }

        if (lib?.mode === "skip_parse") {
          console.info("[SAST] Skipping library file (skip_parse):", fileId);
          skippedLibraries.push({
            file: fileId,
            libId: lib.libId,
            mode: lib.mode
          });
          continue;
        }

        const comments = [];
        let thisAST = null;
        try {
          thisAST = acorn.parse(code, {
            ecmaVersion: "latest",
            sourceType: "module",
            locations: true,
            onComment: (isBlock, text, start, end, startLoc, endLoc) => {
              comments.push({
                isBlock,
                text,
                loc: { start: startLoc, end: endLoc },
                sourceFile: fileId,
              });
            },
          });
        } catch (e) {
          console.warn("Failed to parse <script>:", fileId, e);
          parseFailures.push({
            file: fileId,
            error: e?.message || String(e)
          });
          continue;
        }

        full(thisAST, (node) => {
          node.sourceFile = fileId;
        });
        if (!templateAST) {
          templateAST = thisAST;
        }

        allBodies.push(thisAST.body);
        allComments.push(...comments);
      }

      if (inlineSnippets.length) {
        this.events.emit("progress", { message: "Parsing inline scripts", file });
        for (let i = 0; i < inlineSnippets.length; i++) {
          const snippet = inlineSnippets[i].code;
          const normalizedSnippet = snippet.replace(/(https?:)\/\//g, "$1:\\/\\/");
          const fileId = pageScopedInlineFileId(inlineSnippets[i].label);
          this.events.emit("file:start", { scanId: this._scanId, collectionId, generation, file: fileId, index: seenFiles.length, totalFiles });
          pushFile(fileId);
          const comments = [];
          let snippetAST = null;
          try {
            snippetAST = acorn.parse(normalizedSnippet, {
              ecmaVersion: "latest",
              sourceType: "script",
              locations: true,
              onComment: (isBlock, text, start, end, startLoc, endLoc) => {
                comments.push({ isBlock, text, loc: { start: startLoc, end: endLoc }, sourceFile: fileId });
              }
            });
          } catch {
            const wrapped = `(function(){
${normalizedSnippet}
})();`;
            try {
              snippetAST = acorn.parse(wrapped, {
                ecmaVersion: "latest",
                sourceType: "script",
                locations: true,
                onComment: (isBlock, text, start, end, startLoc, endLoc) => {
                  comments.push({ isBlock, text, loc: { start: startLoc, end: endLoc }, sourceFile: fileId });
                }
              });
            } catch (e2) {
              console.warn(`Failed to parse ${inlineSnippets[i].parseLabel}:`, snippet, e2);
              parseFailures.push({
                file: fileId,
                error: e2?.message || String(e2)
              });
              continue;
            }
          }
          full(snippetAST, (node) => { node.sourceFile = fileId; });
          if (!templateAST) {
            templateAST = snippetAST;
          }
          allBodies.push(snippetAST.body);
          codeByFile[fileId] = snippet;
          allComments.push(...comments);
        }
      }

      if (allBodies.length === 0) {
        const artifacts = emptySastArtifacts();
        emitCollectionSummary({ findings: [], artifacts });
        return {
          findings: [],
          artifacts
        };
      }
      //console.info("[DBG] codeByFile keys:", Object.keys(codeByFile || {}));

      if (!templateAST) {
        const artifacts = emptySastArtifacts();
        emitCollectionSummary({ findings: [], artifacts });
        return {
          findings: [],
          artifacts
        };
      }

      templateAST.body = allBodies.flat();
      const masterAST = templateAST;

      const topFuncs = masterAST.body.flatMap((node) => {
        if (node.type === "FunctionDeclaration" && node.id?.name) return [node.id.name];
        if (node.type === "VariableDeclaration") {
          return node.declarations
            .filter((d) =>
              d.id?.type === "Identifier" &&
              d.init &&
              (d.init.type === "FunctionExpression" || d.init.type === "ArrowFunctionExpression")
            )
            .map((d) => d.id.name);
        }
        if (node.type === "ExpressionStatement" &&
          node.expression.type === "AssignmentExpression" &&
          node.expression.left.type === "Identifier" &&
          node.expression.right &&
          (node.expression.right.type === "FunctionExpression" || node.expression.right.type === "ArrowFunctionExpression")) {
          return [node.expression.left.name];
        }
        return [];
      });
      const rawFindings = [];

      const hasTaintRules = this.modules.some(m =>
        Array.isArray(m.rules) &&
        m.rules.some(r => r.metadata?.mode === "taint")
      );

      let globalTaintCtx = null;
      if (hasTaintRules) {
        try {
          globalTaintCtx = buildGlobalTaintContext(masterAST, {
            catalog: this._catalog,
            modules: this.modules,
            codeByFile,
          });
        } catch (err) {
          console.warn("[TAINT] global taint context build failed:", err?.message);
          globalTaintCtx = null;
        }
      }

      const filterFindingsByLibrary = (issues) => {
        return issues.filter((issue) => {
          const candidates = [
            issue?.sinkFile,
            issue?.sinkFileFull,
            issue?.file,
            issue?.sourceFile,
            issue?.sourceFileFull
          ].filter(Boolean).flatMap(normKeys);

          if (!candidates.length) return true;

          for (const k of candidates) {
            const lib = this._libByFile.get(k);
            if (lib && (lib.mode === "parse_no_report" || lib.mode === "summarize")) {
              return false;
            }
          }
          return true;
        });
      };

      const filterArtifactsByLibrary = (artifactBundle) => {
        const bundle = artifactBundle && typeof artifactBundle === "object" ? artifactBundle : {};
        const sastArtifacts = bundle.sast && typeof bundle.sast === "object" ? bundle.sast : {};
        const shouldKeep = (entry) => {
          const candidates = [
            entry?.sourceFile
          ].filter(Boolean).flatMap(normKeys);

          if (!candidates.length) return true;

          for (const key of candidates) {
            const lib = this._libByFile.get(key);
            if (lib && (lib.mode === "parse_no_report" || lib.mode === "summarize")) {
              return false;
            }
          }
          return true;
        };

        return {
          sast: {
            version: Number(sastArtifacts.version || 2) || 2,
            routes: Array.isArray(sastArtifacts.routes) ? sastArtifacts.routes.filter(shouldKeep) : [],
            endpoints: Array.isArray(sastArtifacts.endpoints) ? sastArtifacts.endpoints.filter(shouldKeep) : [],
            graphql: Array.isArray(sastArtifacts.graphql) ? sastArtifacts.graphql.filter(shouldKeep) : [],
            surfaces: Array.isArray(sastArtifacts.surfaces) ? sastArtifacts.surfaces.filter(shouldKeep) : [],
            hiddenParams: Array.isArray(sastArtifacts.hiddenParams) ? sastArtifacts.hiddenParams.filter(shouldKeep) : [],
            gadgets: Array.isArray(sastArtifacts.gadgets) ? sastArtifacts.gadgets.filter(shouldKeep) : []
          }
        };
      };

      const rawArtifacts = extractSastCodeArtifacts(masterAST, {
        pageUrl: file || null,
        hostHint: file || null
      });
      const artifacts = filterArtifactsByLibrary(rawArtifacts);
      const perModuleCounts = [];
      const perModuleRawCounts = [];

      for (const module of this.modules) {
        const moduleIndex = perModuleCounts.length + 1;
        this.events.emit("module:start", {
          scanId: this._scanId,
          collectionId,
          generation,
          file,
          moduleIndex,
          totalModules: this.modules.length,
          moduleId: module.id,
          moduleName: module.module_metadata?.name || module.id
        });

        const moduleFindings = module.runRules(
          masterAST,
          { file, comments: allComments, codeByFile },
          ancestor,
          {
            scanStrategy: this._scanStrategy,
            globalTaintCtx
          }
        );

        this.events.emit("module:end", {
          scanId: this._scanId,
          collectionId,
          generation,
          file,
          moduleIndex,
          totalModules: this.modules.length,
          moduleId: module.id,
          moduleName: module.module_metadata?.name || module.id,
          findingsCount: Array.isArray(moduleFindings) ? moduleFindings.length : 0
        });

        perModuleRawCounts.push({
          moduleId: module.id,
          findings: Array.isArray(moduleFindings) ? moduleFindings.length : 0
        });
        const partialFindings = Array.isArray(moduleFindings) ? filterFindingsByLibrary(moduleFindings) : [];
        perModuleCounts.push({
          moduleId: module.id,
          findings: partialFindings.length
        });
        if (partialFindings.length) {
          this.events.emit("findings:partial", {
            scanId: this._scanId,
            file,
            moduleId: module.id,
            findings: partialFindings
          });
        }

        rawFindings.push(...moduleFindings);
        if (rawFindings.length >= this._FINDINGS_LIMIT) break;
      }

      const filteredFindings = filterFindingsByLibrary(rawFindings);

      const perFileCounts = new Map();
      const bumpCount = (key) => {
        if (!key) return;
        const curr = perFileCounts.get(key) || 0;
        perFileCounts.set(key, curr + 1);
      };

      for (const issue of filteredFindings) {
        const candidates = [
          issue?.sinkFileFull,
          issue?.sinkFile,
          issue?.sourceFileFull,
          issue?.sourceFile,
          issue?.file,
          file
        ].filter(Boolean);
        for (const c of candidates) bumpCount(c);
      }

      seenFiles.forEach(({ file: f, index }) => {
        const count = perFileCounts.get(f) || 0;
        this.events.emit("file:end", {
          scanId: this._scanId,
          collectionId,
          generation,
          file: f,
          index,
          totalFiles,
          findingsCount: count
        });
      });

      emitCollectionSummary({ findings: filteredFindings, artifacts });

      return {
        findings: filteredFindings,
        artifacts
      };
    } catch (err) {
      this.events.emit("collection:error", {
        scanId: this._scanId,
        collectionId,
        generation,
        error: err?.message || String(err)
      });
      throw err;
    }
  }

  async scanCode(scripts, html = "", file = "", options = {}) {
    const detail = await this.scanCodeDetailed(scripts, html, file, options);
    return Array.isArray(detail?.findings) ? detail.findings : [];
  }

  // ---------- NEW: robust code buffer resolution ----------
  resolveCodeForFile(codeByFile, key, fallbackFile) {
    if (!codeByFile) return "";
    if (key && codeByFile[key]) return codeByFile[key];

    // try without query/hash and with basename
    if (key) {
      const noQ = String(key).split(/[?#]/)[0];
      const base = noQ.split("/").pop();
      if (codeByFile[noQ]) return codeByFile[noQ];
      if (codeByFile[base]) return codeByFile[base];
    }

    // inline markers like "inline:... in somefile"
    if (
      key &&
      /^inline/i.test(key) &&
      fallbackFile &&
      codeByFile[fallbackFile]
    ) {
      return codeByFile[fallbackFile];
    }

    if (fallbackFile && codeByFile[fallbackFile])
      return codeByFile[fallbackFile];
    return "";
  }

  // ---------- FIXED: slice by loc across lines (no 1-char "f") ----------
  // Compact + safe snippet extractor (drop-in replacement)
  // Usage stays the same: getCodeSnippet(code, loc)
  // Optional 3rd arg lets you tweak limits: getCodeSnippet(code, loc, { maxContextLines: 2, ... })
  getCodeSnippet(code, loc, opts = {}) {
    if (!code || !loc || !loc.start || !loc.end) return "";

    const cfg = {
      maxContextLines: 2, // lines before & after the target span
      maxCharsPerLine: 220, // trim long lines
      maxTotalChars: 500, // hard cap for whole snippet
      minColumnWindow: 220, // for single-line/minified, show ~this many chars around the span
      ...opts,
    };

    const lines = code.split(/\r?\n/);
    const sLine = Math.max(1, loc.start.line | 0) - 1; // 0-based
    const eLine = Math.max(1, loc.end.line | 0) - 1;
    if (
      sLine < 0 ||
      sLine >= lines.length ||
      eLine < 0 ||
      eLine >= lines.length
    )
      return "";

    // Helper to trim a line either by absolute window [L..R) or by total length
    function trimLine(line, leftIdx = null, rightIdx = null) {
      if (line == null) return "";
      // Windowed trim takes precedence (used for single-line focus)
      if (leftIdx !== null && rightIdx !== null) {
        const L = Math.max(0, leftIdx);
        const R = Math.min(line.length, Math.max(L, rightIdx));
        const slice = line.slice(L, R);
        const leftEll = L > 0 ? "…" : "";
        const rightEll = R < line.length ? "…" : "";
        return leftEll + slice + rightEll;
      }
      // Generic (length-based) trim
      if (line.length <= cfg.maxCharsPerLine) return line;
      const half = Math.floor(cfg.maxCharsPerLine / 2);
      return line.slice(0, half) + "…" + line.slice(line.length - half);
    }

    let out = [];
    let total = 0;

    // SINGLE LINE: show a focused column window around [startCol..endCol)
    // If maxContextLines > 0, expand single-line spans to include surrounding
    // lines so the returned snippet may be multi-line. Otherwise keep the
    // previous tight single-line focus behavior.
    if (sLine === eLine) {
      const line = lines[sLine] ?? "";
      const startCol = Math.max(0, loc.start.column | 0);
      const endCol = Math.max(
        startCol,
        Math.min(line.length, loc.end.column | 0)
      );

      // If caller requested surrounding context, build a small multi-line
      // snippet using the same trimming rules as the multi-line path.
      if (cfg.maxContextLines && cfg.maxContextLines > 0) {
        const from = Math.max(0, sLine - cfg.maxContextLines);
        const to = Math.min(lines.length - 1, eLine + cfg.maxContextLines);
        const out = [];
        let total = 0;

        if (from > 0) {
          out.push("…");
          total += 1;
        }

        for (let i = from; i <= to; i++) {
          let raw = lines[i] ?? "";

          if (i === sLine) {
            // Clamp the single (target) line to the node columns
            raw = raw.slice(Math.max(0, startCol), Math.min(raw.length, endCol));
          }

          raw = trimLine(raw);
          out.push(raw);
          total += raw.length + 1;
          if (total >= cfg.maxTotalChars) break;
        }

        if (to < lines.length - 1 && total < cfg.maxTotalChars) {
          out.push("…");
        }

        let snippet = out.join("\n").trim();
        if (snippet.length > cfg.maxTotalChars) {
          snippet = snippet.slice(0, cfg.maxTotalChars - 1) + "…";
        }
        return snippet;
      }

      // Fallback: original single-line focused window behavior
      const spanLen = Math.max(1, endCol - startCol);
      const pad = Math.max(cfg.minColumnWindow - spanLen, 0);
      const leftPad = Math.floor(pad / 2);
      const rightPad = pad - leftPad;
      const L = Math.max(0, startCol - leftPad);
      const R = Math.min(line.length, endCol + rightPad);
      const trimmed = trimLine(line, L, R);
      return trimmed.length > cfg.maxTotalChars
        ? trimmed.slice(0, cfg.maxTotalChars - 1) + "…"
        : trimmed;
    }

    // MULTI-LINE: include a few context lines around the span
    const from = Math.max(0, sLine - cfg.maxContextLines);
    const to = Math.min(lines.length - 1, eLine + cfg.maxContextLines);

    // If we skipped lines at the top, mark with ellipsis
    if (from > 0) {
      out.push("…");
      total += 1;
    }

    for (let i = from; i <= to; i++) {
      let raw = lines[i] ?? "";

      // Clamp the first and last lines to the node columns
      if (i === sLine) {
        const startCol = Math.max(0, loc.start.column | 0);
        raw = raw.slice(startCol);
      }
      if (i === eLine) {
        const endCol = Math.max(0, loc.end.column | 0);
        raw = raw.slice(0, Math.min(raw.length, endCol));
      }

      // Trim long lines
      raw = trimLine(raw);

      out.push(raw);
      total += raw.length + 1; // +1 for newline
      if (total >= cfg.maxTotalChars) break;
    }

    // If we cut before the real end, show ellipsis
    if (to < lines.length - 1 && total < cfg.maxTotalChars) {
      out.push("…");
    }

    let snippet = out.join("\n").trim();

    if (snippet.length > cfg.maxTotalChars) {
      snippet = snippet.slice(0, cfg.maxTotalChars - 1) + "…";
    }
    return snippet;
  }

  getCodeSnippetExt(code, location) {
    // Use the same robust slicer; caller adds its own labels
    const cfg = {
      maxContextLines: 2,
      maxCharsPerLine: 220,
      maxTotalChars: 1500,
      minColumnWindow: 220,
    };
    return this.getCodeSnippet(code, location, { maxTotalChars: 1500 });
  }
}
