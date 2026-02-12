/* Author: Denis Podgurskii */

import * as acorn from "./acorn/acorn.mjs";
import { Parser } from "./acorn/acorn.mjs";
import { full, ancestor, base } from "./acorn/walk.mjs";
import { ptk_sast_module } from "./modules/module.js";
import { buildGlobalTaintContext } from "./modules/taint_propagation.js";
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

    // Catalog-driven libraries (optional; no policy needed)
    this._catalog = opts?.catalog || {};
    this._activeLibs = getActiveLibraryDefs(this._catalog);
    this._libByFile = new Map(); // fileId -> { libId, mode, displayName }


    const rulepack = opts?.rulepack || opts?.modules || {}
    normalizeRulepack(rulepack, { engine: 'SAST', childKey: 'rules' })
    this._rulepack = rulepack
    this._rulepackEngine = rulepack.engine || null
    this._rulepackVersion = rulepack.version || null
    const rawModules = rulepack?.modules
    const moduleDefs = Array.isArray(rawModules)
      ? rawModules
      : Object.values(rawModules || {})

    this.modules = moduleDefs.map(
      (m) =>
        new ptk_sast_module(m, {
          sources: this._catalog.sources || {},
          sinks: this._catalog.sinks || {},
          sanitizers: this._catalog.sanitizers || {},
          propagators: this._catalog.propagators || {},
        })
    );
    this.events = createEmitter({ async: true, replay: 1 });
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

  async scanCode(scripts, html = "", file = "") {
    try {
      if (!Array.isArray(this.rules)) {
        console.warn("SAST: rules not loaded; skipping scan.");
        return [];
      }

      scripts = scripts.sort((a, b) => {
        const aIsInline = a.src === null;
        const bIsInline = b.src === null;
        if (aIsInline === bIsInline) return 0;
        return aIsInline ? 1 : -1;
      });

      const inlineSnippets = Array.isArray(html) ? [] : this.extractInlineHandlers(html || "");
      const totalFiles = (Array.isArray(scripts) ? scripts.length : 0) + inlineSnippets.length;
      this.events.emit("scan:start", {
        scanId: this._scanId,
        scanStrategy: this._scanStrategy,
        totalFiles
      });

      const codeByFile = Object.create(null);
      const allBodies = [];
      const allComments = [];
      const seenFiles = [];
      const seenSet = new Set();
      let fileIndex = 0;

      const pushFile = (id) => {
        if (!seenSet.has(id)) {
          seenSet.add(id);
          seenFiles.push({ file: id, index: fileIndex++ });
        }
      };

      for (const script of scripts) {
        const fileId = script.src || `inline-script[#${allBodies.length}]`;
        this.events.emit("file:start", { scanId: this._scanId, file: fileId, index: seenFiles.length, totalFiles });
        pushFile(fileId);

        const captured = typeof script.code === "string" ? script.code : "";
        const hasCaptured = Boolean(captured && captured.trim().length);
        let code = hasCaptured ? captured : "";

        if (script.src && hasCaptured) {
        }

        if (script.src && !hasCaptured) {
          if (this._allowFetchExternalScripts) {
            this.events.emit("progress", { message: "Parsing external scripts", file: script.src });
            try {
              const res = await fetch(script.src);
              if (!res.ok) {
                throw new Error(`HTTP ${res.status}`);
              }
              code = await res.text();
            } catch (err) {
              continue;
            }
          } else if (!hasCaptured) {
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
          console.warn(`Failed to parse <script> ${fileId}:`, e);
          continue;
        }

        full(thisAST, (node) => {
          node.sourceFile = fileId;
        });

        allBodies.push(thisAST.body);
        allComments.push(...comments);
      }

      if (inlineSnippets.length) {
        this.events.emit("progress", { message: "Parsing inline scripts", file });
        for (let i = 0; i < inlineSnippets.length; i++) {
          const snippet = inlineSnippets[i];
          const normalizedSnippet = snippet.replace(/(https?:)\/\//g, "$1:\\/\\/");
          const fileId = `inline‐onclick[#${i}]`;
          this.events.emit("file:start", { scanId: this._scanId, file: fileId, index: seenFiles.length, totalFiles });
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
              console.warn("Failed to parse inline onclick snippet:", snippet, e2);
              continue;
            }
          }
          full(snippetAST, (node) => { node.sourceFile = fileId; });
          allBodies.push(snippetAST.body);
          codeByFile[fileId] = snippet;
          allComments.push(...comments);
        }
      }

      if (allBodies.length === 0) {
        return [];
      }
      //console.info("[DBG] codeByFile keys:", Object.keys(codeByFile || {}));

      const firstFileId = Object.keys(codeByFile)[0] || "inline‐first";
      const firstCode = codeByFile[firstFileId] || "";
      const templateAST = acorn.parse(firstCode, {
        ecmaVersion: "latest",
        sourceType: "module",
        locations: true,
      });

      full(templateAST, (node) => {
        if (!node.sourceFile) {
          node.sourceFile = firstFileId;
        }
      });

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

      for (const module of this.modules) {
        this.events.emit("module:start", {
          scanId: this._scanId,
          file,
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
          file,
          moduleId: module.id,
          moduleName: module.module_metadata?.name || module.id,
          findingsCount: Array.isArray(moduleFindings) ? moduleFindings.length : 0
        });

        const partialFindings = Array.isArray(moduleFindings) ? filterFindingsByLibrary(moduleFindings) : [];
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
          file: f,
          index,
          totalFiles,
          findingsCount: count
        });
      });

      this.events.emit("scan:summary", {
        scanId: this._scanId,
        totalFiles,
        totalModules: this.modules.length,
        totalFindings: filteredFindings.length
      });

      return filteredFindings;
    } catch (err) {
      this.events.emit("scan:error", {
        scanId: this._scanId,
        error: err?.message || String(err)
      });
      throw err;
    }
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
