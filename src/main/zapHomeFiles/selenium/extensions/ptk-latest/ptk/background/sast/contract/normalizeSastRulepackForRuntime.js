import loadCanonicalSastRulepack from "./loadCanonicalSastRulepack.js"

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

function uniqueStrings(values = []) {
  const out = []
  const seen = new Set()
  const list = Array.isArray(values) ? values : [values]
  for (const value of list) {
    const text = typeof value === "string" ? value.trim() : ""
    if (!text || seen.has(text)) continue
    seen.add(text)
    out.push(text)
  }
  return out
}

function mergeLinks(moduleLinks, ruleLinks) {
  const merged = Object.assign({}, moduleLinks || {}, ruleLinks || {})
  return Object.keys(merged).length ? merged : undefined
}

function flattenModuleMetadata(moduleDef = {}) {
  const metadata = moduleDef?.metadata || {}
  const taxonomy = metadata?.taxonomy || {}
  const docs = metadata?.docs || {}
  const execution = metadata?.execution || {}
  const out = {
    description: docs.description,
    recommendation: docs.recommendation,
    severity: taxonomy.severity || "medium",
    category: taxonomy.category || "sast",
    vulnId: taxonomy.vulnId || taxonomy.category || moduleDef?.id || "sast",
    findingKind: execution.findingKind || "finding",
  }
  if (execution.maxFindings != null) out.maxFindings = execution.maxFindings
  if (execution.confidenceDefault != null) out.confidenceDefault = execution.confidenceDefault
  if (Array.isArray(taxonomy.tags) && taxonomy.tags.length) out.tags = uniqueStrings(taxonomy.tags)
  if (Array.isArray(taxonomy.cwe) && taxonomy.cwe.length) out.cwe = uniqueStrings(taxonomy.cwe)
  if (Array.isArray(taxonomy.owasp) && taxonomy.owasp.length) out.owasp = uniqueStrings(taxonomy.owasp)
  if (docs.links && typeof docs.links === "object" && !Array.isArray(docs.links)) out.links = clonePlainObject(docs.links, {})
  if (metadata.constants && typeof metadata.constants === "object" && !Array.isArray(metadata.constants)) {
    out.constants = clonePlainObject(metadata.constants, {})
  }
  if (metadata.extensions && typeof metadata.extensions === "object" && !Array.isArray(metadata.extensions)) {
    out.extensions = clonePlainObject(metadata.extensions, {})
  }
  return out
}

function flattenRuleMetadata(ruleDef = {}, moduleMeta = {}) {
  const metadata = ruleDef?.metadata || {}
  const taxonomy = metadata?.taxonomy || {}
  const docs = metadata?.docs || {}
  const execution = metadata?.execution || {}
  const out = {
    severity: taxonomy.severity || moduleMeta.severity || "medium",
    category: taxonomy.category || undefined,
    vulnId: taxonomy.vulnId || undefined,
    findingKind: execution.findingKind || moduleMeta.findingKind || "finding",
  }
  if (docs.description) out.description = docs.description
  if (docs.recommendation) out.recommendation = docs.recommendation
  const links = mergeLinks(moduleMeta.links, docs.links)
  if (links) out.links = links
  if (execution.maxFindings != null) out.maxFindings = execution.maxFindings
  if (execution.originLimit != null) out.originLimit = execution.originLimit
  if (execution.depthLimit != null) out.depthLimit = execution.depthLimit
  if (execution.confidenceDefault != null) out.confidenceDefault = execution.confidenceDefault
  if (Array.isArray(taxonomy.tags) && taxonomy.tags.length) out.tags = uniqueStrings(taxonomy.tags)
  if (Array.isArray(taxonomy.cwe) && taxonomy.cwe.length) out.cwe = uniqueStrings(taxonomy.cwe)
  if (Array.isArray(taxonomy.owasp) && taxonomy.owasp.length) out.owasp = uniqueStrings(taxonomy.owasp)
  if (metadata.constants && typeof metadata.constants === "object" && !Array.isArray(metadata.constants)) {
    out.constants = clonePlainObject(metadata.constants, {})
  }
  if (metadata.extensions && typeof metadata.extensions === "object" && !Array.isArray(metadata.extensions)) {
    out.extensions = clonePlainObject(metadata.extensions, {})
  }
  return out
}

function flattenRule(ruleDef = {}, moduleMeta = {}) {
  const mode = String(ruleDef?.mode || "pattern").toLowerCase() === "taint" ? "taint" : "pattern"
  const metadata = flattenRuleMetadata(ruleDef, moduleMeta)
  const base = {
    id: ruleDef?.id,
    name: ruleDef?.name,
    mode,
    metadata,
    severity: metadata.severity,
    findingKind: metadata.findingKind,
  }
  if (metadata.maxFindings != null) base.maxFindings = metadata.maxFindings
  if (metadata.originLimit != null) base.originLimit = metadata.originLimit
  if (metadata.depthLimit != null) base.depthLimit = metadata.depthLimit
  if (mode === "taint") {
    const detector = ruleDef?.detector || {}
    base.sources = Array.isArray(detector.sources) ? cloneValue(detector.sources) : []
    base.sinks = Array.isArray(detector.sinks) ? cloneValue(detector.sinks) : []
    if (Array.isArray(detector.sanitizers) && detector.sanitizers.length) {
      base.sanitizers = cloneValue(detector.sanitizers)
    }
    if (Array.isArray(detector.propagators) && detector.propagators.length) {
      base.propagate = cloneValue(detector.propagators)
    }
    if (Array.isArray(detector.taintKinds) && detector.taintKinds.length) {
      base.taint_kinds = uniqueStrings(detector.taintKinds)
    }
  } else {
    base.matches = Array.isArray(ruleDef?.detector?.matches) ? cloneValue(ruleDef.detector.matches) : []
  }
  return base
}

export function normalizeSastRulepackForRuntime(rulepack, opts = {}) {
  const canonical = loadCanonicalSastRulepack(rulepack, opts)
  const extras = {}
  Object.entries(rulepack || {}).forEach(([key, value]) => {
    if (key === "schema" || key === "engine" || key === "version" || key === "modules") return
    extras[key] = cloneValue(value)
  })
  return {
    ...extras,
    schema: canonical.schema,
    engine: canonical.engine,
    version: canonical.version,
    modules: (canonical.modules || []).map((moduleDef) => {
      const metadata = flattenModuleMetadata(moduleDef)
      const out = {
        id: moduleDef.id,
        name: moduleDef.name,
        type: moduleDef.type || "static",
        async: moduleDef.async === true,
        vulnId: metadata.vulnId,
        metadata,
        rules: Array.isArray(moduleDef.rules)
          ? moduleDef.rules.map((ruleDef) => flattenRule(ruleDef, metadata))
          : []
      }
      if (metadata.maxFindings != null) out.maxFindings = metadata.maxFindings
      return out
    })
  }
}

export default normalizeSastRulepackForRuntime
