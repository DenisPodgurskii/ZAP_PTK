import { normalizeCwe, normalizeOwasp } from "../../common/normalizeMappings.js"

export const CANONICAL_SCHEMA = "ptk-sast-rulepack/v1"
export const LEGACY_SCHEMA = "ptk-modules-v1"

function cloneValue(value) {
  if (typeof globalThis.structuredClone === "function") {
    try {
      return globalThis.structuredClone(value)
    } catch (_) {
      // fall through
    }
  }
  return JSON.parse(JSON.stringify(value))
}

function clonePlainObject(value, fallback = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return cloneValue(fallback)
  return cloneValue(value)
}

function extractTopLevelExtras(rulepack = {}) {
  const extras = {}
  Object.entries(rulepack || {}).forEach(([key, value]) => {
    if (key === "schema" || key === "engine" || key === "version" || key === "modules") return
    extras[key] = cloneValue(value)
  })
  return extras
}

function normalizeString(value, fallback = "") {
  const text = typeof value === "string" ? value.trim() : ""
  return text || fallback
}

function normalizeCode(value, fallback = "") {
  const normalized = normalizeString(value, fallback).toLowerCase()
  return normalized.replace(/[^a-z0-9_:-]/g, "") || fallback
}

function uniqueStrings(values = []) {
  const out = []
  const seen = new Set()
  const list = Array.isArray(values) ? values : [values]
  for (const value of list) {
    const text = normalizeString(value)
    if (!text || seen.has(text)) continue
    seen.add(text)
    out.push(text)
  }
  return out
}

function normalizeSeverity(value, fallback = "medium") {
  const text = normalizeString(value).toLowerCase()
  if (["critical", "high", "medium", "low", "info"].includes(text)) return text
  return fallback
}

function normalizeFindingKind(value, fallback = "finding") {
  const text = normalizeString(value).toLowerCase()
  if (text === "finding" || text === "hint") return text
  return fallback
}

function normalizeRuleMode(value, fallback = "pattern") {
  const text = normalizeString(value).toLowerCase()
  if (text === "pattern" || text === "taint") return text
  return fallback
}

function normalizeOwaspStrings(value) {
  return uniqueStrings(normalizeOwasp(value).map((entry) => {
    if (!entry) return ""
    const version = entry.version && entry.version !== "unknown" ? entry.version : null
    const id = entry.id && entry.id !== "unknown" ? entry.id : null
    const name = normalizeString(entry.name)
    if (id && version && name) return `${id}:${version} - ${name}`
    if (id && version) return `${id}:${version}`
    return name
  }))
}

function normalizeCweStrings(value) {
  return uniqueStrings(normalizeCwe(value))
}

function normalizeModuleMetadata(moduleDef = {}) {
  const meta = moduleDef?.metadata || {}
  return {
    taxonomy: {
      severity: normalizeSeverity(meta.severity, "medium"),
      category: normalizeString(meta.category, "sast"),
      vulnId: normalizeString(moduleDef?.vulnId || meta.vulnId, normalizeString(meta.category, "sast")),
      owasp: normalizeOwaspStrings(meta.owasp),
      cwe: normalizeCweStrings(meta.cwe),
      tags: uniqueStrings(meta.tags)
    },
    docs: {
      description: normalizeString(meta.description, moduleDef?.name || "PTK SAST module"),
      recommendation: normalizeString(meta.recommendation, "Review and remediate the identified weakness."),
      links: clonePlainObject(meta.links, {})
    },
    execution: {
      findingKind: normalizeFindingKind(meta.findingKind, "finding"),
      maxFindings: Number.isInteger(meta.maxFindings) && meta.maxFindings > 0
        ? meta.maxFindings
        : (Number.isInteger(moduleDef?.maxFindings) && moduleDef.maxFindings > 0 ? moduleDef.maxFindings : null),
      confidenceDefault: typeof meta.confidenceDefault === "number"
        ? Math.max(0, Math.min(100, meta.confidenceDefault))
        : null
    },
    constants: clonePlainObject(meta.constants, {}),
    extensions: clonePlainObject(meta.extensions, {})
  }
}

function hasOwn(obj, key) {
  return !!obj && Object.prototype.hasOwnProperty.call(obj, key)
}

function normalizeRuleTaxonomy(ruleDef = {}) {
  const meta = ruleDef?.metadata || {}
  const taxonomy = {}
  if (hasOwn(meta, "severity") || hasOwn(ruleDef, "severity")) {
    taxonomy.severity = normalizeSeverity(meta.severity ?? ruleDef.severity, "medium")
  }
  if (hasOwn(meta, "category") || hasOwn(ruleDef, "category")) {
    taxonomy.category = normalizeString(meta.category ?? ruleDef.category)
  }
  if (hasOwn(meta, "vulnId") || hasOwn(ruleDef, "vulnId")) {
    taxonomy.vulnId = normalizeString(meta.vulnId ?? ruleDef.vulnId)
  }
  if (hasOwn(meta, "owasp")) {
    taxonomy.owasp = normalizeOwaspStrings(meta.owasp)
  }
  if (hasOwn(meta, "cwe")) {
    taxonomy.cwe = normalizeCweStrings(meta.cwe)
  }
  if (hasOwn(meta, "tags")) {
    taxonomy.tags = uniqueStrings(meta.tags)
  }
  return taxonomy
}

function normalizeRuleDocs(ruleDef = {}) {
  const meta = ruleDef?.metadata || {}
  const docs = {}
  if (hasOwn(meta, "description") || hasOwn(ruleDef, "description")) {
    docs.description = normalizeString(meta.description ?? ruleDef.description)
  }
  if (hasOwn(meta, "recommendation") || hasOwn(ruleDef, "recommendation")) {
    docs.recommendation = normalizeString(meta.recommendation ?? ruleDef.recommendation)
  }
  if (hasOwn(meta, "links") || hasOwn(ruleDef, "links")) {
    docs.links = clonePlainObject(meta.links ?? ruleDef.links, {})
  }
  return docs
}

function normalizeRuleExecution(ruleDef = {}, moduleMeta = {}) {
  const meta = ruleDef?.metadata || {}
  const mode = normalizeRuleMode(ruleDef?.mode || ruleDef?.type, "pattern")
  const maxFindings = Number.isInteger(meta.maxFindings) && meta.maxFindings > 0
    ? meta.maxFindings
    : (Number.isInteger(ruleDef?.maxFindings) && ruleDef.maxFindings > 0 ? ruleDef.maxFindings : null)
  const originLimit = Number.isInteger(meta.originLimit) && meta.originLimit > 0
    ? meta.originLimit
    : (Number.isInteger(ruleDef?.originLimit) && ruleDef.originLimit > 0 ? ruleDef.originLimit : null)
  const depthLimit = Number.isInteger(meta.depthLimit) && meta.depthLimit > 0
    ? meta.depthLimit
    : (Number.isInteger(ruleDef?.depthLimit) && ruleDef.depthLimit > 0 ? ruleDef.depthLimit : null)
  return {
    findingKind: normalizeFindingKind(meta.findingKind ?? ruleDef.findingKind ?? moduleMeta?.execution?.findingKind, "finding"),
    maxFindings,
    originLimit: mode === "pattern" ? null : originLimit,
    depthLimit: mode === "pattern" ? null : depthLimit,
    confidenceDefault: typeof meta.confidenceDefault === "number"
      ? Math.max(0, Math.min(100, meta.confidenceDefault))
      : null
  }
}

function normalizeCatalogRefs(values) {
  if (!Array.isArray(values)) return []
  return values
    .map((entry) => {
      if (!entry) return null
      if (typeof entry === "string") {
        const id = normalizeString(entry)
        return id || null
      }
      if (typeof entry === "object") {
        const id = normalizeString(entry.id)
        if (!id) return null
        const out = { id }
        if (entry.overlay && typeof entry.overlay === "object" && !Array.isArray(entry.overlay)) {
          out.overlay = clonePlainObject(entry.overlay, {})
        }
        return out
      }
      return null
    })
    .filter(Boolean)
}

function normalizeRuleDetector(ruleDef = {}) {
  const mode = normalizeRuleMode(ruleDef?.mode || ruleDef?.type, "pattern")
  if (mode === "taint") {
    return {
      sources: normalizeCatalogRefs(ruleDef.sources),
      sinks: normalizeCatalogRefs(ruleDef.sinks),
      sanitizers: normalizeCatalogRefs(ruleDef.sanitizers),
      propagators: normalizeCatalogRefs(ruleDef.propagate || ruleDef.propagators),
      taintKinds: uniqueStrings(ruleDef.taint_kinds || ruleDef.taintKinds)
    }
  }
  return {
    matches: Array.isArray(ruleDef.matches) ? cloneValue(ruleDef.matches) : []
  }
}

function normalizeRule(ruleDef = {}, moduleDef = {}, index = 0) {
  const moduleMeta = normalizeModuleMetadata(moduleDef)
  const mode = normalizeRuleMode(ruleDef?.mode || ruleDef?.type, "pattern")
  return {
    id: normalizeCode(ruleDef?.id || ruleDef?.code, `rule_${index + 1}`),
    name: normalizeString(ruleDef?.name, normalizeCode(ruleDef?.id || ruleDef?.code, `rule_${index + 1}`)),
    mode,
    metadata: {
      taxonomy: normalizeRuleTaxonomy(ruleDef),
      docs: normalizeRuleDocs(ruleDef),
      execution: normalizeRuleExecution(ruleDef, moduleMeta),
      constants: clonePlainObject(ruleDef?.metadata?.constants, {}),
      extensions: clonePlainObject(ruleDef?.metadata?.extensions || ruleDef?.extras, {})
    },
    detector: normalizeRuleDetector(ruleDef)
  }
}

function sanitizeCanonicalRule(ruleDef = {}, index = 0) {
  const mode = normalizeRuleMode(ruleDef?.mode, "pattern")
  const metadata = ruleDef?.metadata && typeof ruleDef.metadata === "object" ? ruleDef.metadata : {}
  const taxonomy = metadata?.taxonomy && typeof metadata.taxonomy === "object" ? metadata.taxonomy : {}
  const docs = metadata?.docs && typeof metadata.docs === "object" ? metadata.docs : {}
  const execution = metadata?.execution && typeof metadata.execution === "object" ? metadata.execution : {}
  const detector = ruleDef?.detector && typeof ruleDef.detector === "object" ? ruleDef.detector : {}
  return {
    id: normalizeCode(ruleDef?.id, `rule_${index + 1}`),
    name: normalizeString(ruleDef?.name, normalizeCode(ruleDef?.id, `rule_${index + 1}`)),
    mode,
    metadata: {
      taxonomy: {
        ...(hasOwn(taxonomy, "severity") ? { severity: normalizeSeverity(taxonomy.severity, "medium") } : {}),
        ...(hasOwn(taxonomy, "category") ? { category: normalizeString(taxonomy.category) } : {}),
        ...(hasOwn(taxonomy, "vulnId") ? { vulnId: normalizeString(taxonomy.vulnId) } : {}),
        ...(hasOwn(taxonomy, "owasp") ? { owasp: uniqueStrings(taxonomy.owasp) } : {}),
        ...(hasOwn(taxonomy, "cwe") ? { cwe: uniqueStrings(taxonomy.cwe) } : {}),
        ...(hasOwn(taxonomy, "tags") ? { tags: uniqueStrings(taxonomy.tags) } : {}),
      },
      docs: {
        ...(hasOwn(docs, "description") ? { description: normalizeString(docs.description) } : {}),
        ...(hasOwn(docs, "recommendation") ? { recommendation: normalizeString(docs.recommendation) } : {}),
        ...(hasOwn(docs, "links") ? { links: clonePlainObject(docs.links, {}) } : {}),
      },
      execution: {
        findingKind: normalizeFindingKind(execution.findingKind, "finding"),
        maxFindings: Number.isInteger(execution.maxFindings) && execution.maxFindings > 0 ? execution.maxFindings : null,
        originLimit: mode === "pattern" ? null : (Number.isInteger(execution.originLimit) && execution.originLimit > 0 ? execution.originLimit : null),
        depthLimit: mode === "pattern" ? null : (Number.isInteger(execution.depthLimit) && execution.depthLimit > 0 ? execution.depthLimit : null),
        confidenceDefault: typeof execution.confidenceDefault === "number"
          ? Math.max(0, Math.min(100, execution.confidenceDefault))
          : null,
      },
      constants: clonePlainObject(metadata.constants, {}),
      extensions: clonePlainObject(metadata.extensions, {})
    },
    detector: mode === "taint"
      ? {
          sources: normalizeCatalogRefs(detector.sources),
          sinks: normalizeCatalogRefs(detector.sinks),
          sanitizers: normalizeCatalogRefs(detector.sanitizers),
          propagators: normalizeCatalogRefs(detector.propagators),
          taintKinds: uniqueStrings(detector.taintKinds)
        }
      : {
          matches: Array.isArray(detector.matches) ? cloneValue(detector.matches) : []
        }
  }
}

function sanitizeCanonicalModule(moduleDef = {}, index = 0) {
  const metadata = moduleDef?.metadata && typeof moduleDef.metadata === "object" ? moduleDef.metadata : {}
  const taxonomy = metadata?.taxonomy && typeof metadata.taxonomy === "object" ? metadata.taxonomy : {}
  const docs = metadata?.docs && typeof metadata.docs === "object" ? metadata.docs : {}
  const execution = metadata?.execution && typeof metadata.execution === "object" ? metadata.execution : {}
  const rules = Array.isArray(moduleDef?.rules) ? moduleDef.rules : []
  return {
    id: normalizeCode(moduleDef?.id, `module_${index + 1}`),
    name: normalizeString(moduleDef?.name, normalizeCode(moduleDef?.id, `module_${index + 1}`)),
    type: "static",
    async: moduleDef?.async === true,
    metadata: {
      taxonomy: {
        severity: normalizeSeverity(taxonomy.severity, "medium"),
        category: normalizeString(taxonomy.category, "sast"),
        vulnId: normalizeString(taxonomy.vulnId, normalizeString(taxonomy.category, "sast")),
        owasp: uniqueStrings(taxonomy.owasp),
        cwe: uniqueStrings(taxonomy.cwe),
        tags: uniqueStrings(taxonomy.tags)
      },
      docs: {
        description: normalizeString(docs.description, moduleDef?.name || "PTK SAST module"),
        recommendation: normalizeString(docs.recommendation, "Review and remediate the identified weakness."),
        links: clonePlainObject(docs.links, {})
      },
      execution: {
        findingKind: normalizeFindingKind(execution.findingKind, "finding"),
        maxFindings: Number.isInteger(execution.maxFindings) && execution.maxFindings > 0 ? execution.maxFindings : null,
        confidenceDefault: typeof execution.confidenceDefault === "number"
          ? Math.max(0, Math.min(100, execution.confidenceDefault))
          : null
      },
      constants: clonePlainObject(metadata.constants, {}),
      extensions: clonePlainObject(metadata.extensions, {})
    },
    rules: rules.map((rule, ruleIndex) => sanitizeCanonicalRule(rule, ruleIndex))
  }
}

export function isCanonicalSastRulepack(rulepack) {
  return !!rulepack && typeof rulepack === "object" && rulepack.schema === CANONICAL_SCHEMA
}

export function normalizeLegacySastRulepack(rulepack) {
  if (!rulepack || typeof rulepack !== "object") {
    throw new Error("[PTK SAST] rulepack must be an object")
  }
  if (rulepack?.schema && rulepack.schema !== LEGACY_SCHEMA && rulepack.schema !== CANONICAL_SCHEMA) {
    throw new Error(`[PTK SAST] Unsupported SAST schema: ${rulepack.schema}`)
  }

  const modules = Array.isArray(rulepack?.modules)
    ? rulepack.modules
    : Object.values(rulepack?.modules || {})
  const extras = extractTopLevelExtras(rulepack)

  if (isCanonicalSastRulepack(rulepack)) {
    return {
      ...extras,
      schema: CANONICAL_SCHEMA,
      engine: "SAST",
      version: 1,
      modules: modules.map((moduleDef, index) => sanitizeCanonicalModule(moduleDef, index))
    }
  }

  return {
    ...extras,
    schema: CANONICAL_SCHEMA,
    engine: "SAST",
    version: 1,
    modules: modules.map((moduleDef, index) => {
      const normalizedModule = {
        id: normalizeCode(moduleDef?.id, `module_${index + 1}`),
        name: normalizeString(moduleDef?.name, normalizeCode(moduleDef?.id, `module_${index + 1}`)),
        type: "static",
        async: moduleDef?.async === true,
        metadata: normalizeModuleMetadata(moduleDef),
        rules: []
      }
      const rules = Array.isArray(moduleDef?.rules) ? moduleDef.rules : []
      normalizedModule.rules = rules.map((ruleDef, ruleIndex) => normalizeRule(ruleDef, moduleDef, ruleIndex))
      return normalizedModule
    })
  }
}

export default normalizeLegacySastRulepack
