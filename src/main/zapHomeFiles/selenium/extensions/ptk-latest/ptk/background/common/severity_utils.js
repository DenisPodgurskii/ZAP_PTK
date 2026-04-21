import { normalizeCwe, normalizeOwasp } from "./normalizeMappings.js"
import { normalizeSastRulepackForRuntime } from "../sast/contract/index.js"

const DEFAULT_SEVERITY = 'medium'
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

function applyMappingNormalization(meta) {
  if (!meta || typeof meta !== 'object') return
  meta.owasp = normalizeOwasp(meta.owasp)
  meta.cwe = normalizeCwe(meta.cwe)
}

function coerceSeverity(value) {
  if (value === null || value === undefined) return null
  const normalized = String(value).trim().toLowerCase()
  if (VALID_SEVERITIES.includes(normalized)) {
    return normalized
  }
  if (!Number.isNaN(Number(normalized))) {
    const numeric = Number(normalized)
    if (numeric >= 8) return 'high'
    if (numeric >= 5) return 'medium'
    if (numeric > 0) return 'low'
  }
  return null
}

function extractSeverity(meta) {
  if (!meta || typeof meta !== 'object') return null
  return (
    coerceSeverity(meta.severity) ||
    coerceSeverity(meta.taxonomy?.severity)
  )
}

export function normalizeSeverityValue(value, fallback = DEFAULT_SEVERITY) {
  return coerceSeverity(value) || fallback
}

function firstSastModule(rulepack) {
  const modules = rulepack?.modules
  if (Array.isArray(modules)) return modules[0] || null
  if (modules && typeof modules === "object") {
    const firstKey = Object.keys(modules)[0]
    return firstKey ? modules[firstKey] : null
  }
  return null
}

function isRuntimeNormalizedSastRulepack(rulepack) {
  const moduleDef = firstSastModule(rulepack)
  if (!moduleDef || typeof moduleDef !== "object") return false
  const moduleMeta = moduleDef.metadata && typeof moduleDef.metadata === "object" ? moduleDef.metadata : {}
  const rules = Array.isArray(moduleDef.rules) ? moduleDef.rules : []
  const ruleDef = rules[0] && typeof rules[0] === "object" ? rules[0] : null
  const ruleMeta = ruleDef?.metadata && typeof ruleDef.metadata === "object" ? ruleDef.metadata : {}

  const moduleLooksRuntime = (
    Object.prototype.hasOwnProperty.call(moduleMeta, "severity")
    || Object.prototype.hasOwnProperty.call(moduleMeta, "findingKind")
    || Object.prototype.hasOwnProperty.call(moduleDef, "vulnId")
  )
  const ruleLooksRuntime = !!ruleDef && (
    Object.prototype.hasOwnProperty.call(ruleMeta, "severity")
    || Object.prototype.hasOwnProperty.call(ruleMeta, "findingKind")
    || Array.isArray(ruleDef.matches)
    || Array.isArray(ruleDef.sources)
    || Array.isArray(ruleDef.sinks)
    || Array.isArray(ruleDef.sanitizers)
    || Array.isArray(ruleDef.propagate)
    || Array.isArray(ruleDef.taint_kinds)
  )

  return moduleLooksRuntime || ruleLooksRuntime
}

export function normalizeChildDefinition(child, { engine = 'Engine', parentId = 'module' } = {}) {
  if (!child || typeof child !== 'object') return child
  const meta = child.metadata = child.metadata || {}

  if (meta.severity == null && Object.prototype.hasOwnProperty.call(child, 'severity')) {
    meta.severity = child.severity
  }

  if (meta.severity != null) {
    const normalized = coerceSeverity(meta.severity)
    if (normalized) {
      meta.severity = normalized
    } else {
      console.warn(`[PTK ${engine}] ${parentId || 'module'} child "${child.id || child.name || 'rule'}" has invalid severity "${meta.severity}", inheriting from parent`)
      delete meta.severity
    }
  }

  if (Object.prototype.hasOwnProperty.call(child, 'severity')) {
    delete child.severity
  }

  applyMappingNormalization(meta)

  return child
}

export function normalizeModuleDefinition(moduleDef, { engine = 'Engine', childKey } = {}) {
  if (!moduleDef || typeof moduleDef !== 'object') return moduleDef
  const meta = moduleDef.metadata = moduleDef.metadata || {}
  const normalized = coerceSeverity(meta.severity)
  if (normalized) {
    meta.severity = normalized
  } else {
    console.warn(`[PTK ${engine}] module "${moduleDef.id || moduleDef.name || 'unknown'}" missing metadata.severity; defaulting to "medium"`)
    meta.severity = DEFAULT_SEVERITY
  }

  applyMappingNormalization(meta)

  if (childKey && Array.isArray(moduleDef[childKey])) {
    moduleDef[childKey] = moduleDef[childKey].map((child, index) =>
      normalizeChildDefinition(child, { engine, parentId: moduleDef.id || `module-${index}` })
    )
  }

  return moduleDef
}

export function normalizeRulepack(rulepack, { engine = 'Engine', childKey } = {}) {
  if (!rulepack || typeof rulepack !== 'object') return rulepack
  if (
    String(engine || '').toUpperCase() === 'SAST'
    && rulepack.schema === 'ptk-sast-rulepack/v1'
    && !isRuntimeNormalizedSastRulepack(rulepack)
  ) {
    const normalized = normalizeSastRulepackForRuntime(rulepack, { label: engine })
    Object.keys(rulepack).forEach((key) => {
      delete rulepack[key]
    })
    Object.assign(rulepack, normalized)
  }
  const modules = rulepack.modules
  if (Array.isArray(modules)) {
    rulepack.modules = modules.map((mod) => normalizeModuleDefinition(mod, { engine, childKey }))
  } else if (modules && typeof modules === 'object') {
    Object.keys(modules).forEach((key) => {
      modules[key] = normalizeModuleDefinition(modules[key], { engine, childKey })
    })
  }
  return rulepack
}

export function resolveEffectiveSeverity({ override, moduleMeta = {}, attackMeta = {}, ruleMeta = {} } = {}) {
  return (
    coerceSeverity(override) ||
    extractSeverity(ruleMeta) ||
    extractSeverity(attackMeta) ||
    extractSeverity(moduleMeta) ||
    DEFAULT_SEVERITY
  )
}

export function getModuleSeverity(module) {
  return normalizeSeverityValue(extractSeverity(module?.metadata))
}

export function getRuleSeverity(rule, module) {
  const moduleSeverity = getModuleSeverity(module)
  return normalizeSeverityValue(
    extractSeverity(rule?.metadata || rule) || moduleSeverity
  )
}

export function getAttackSeverity(attack, module) {
  const moduleSeverity = getModuleSeverity(module)
  const attackMeta = attack?.metadata || attack || {}
  return normalizeSeverityValue(
    extractSeverity(attackMeta) || moduleSeverity
  )
}

export function getEffectiveSeverity(engine, module, item) {
  switch (engine) {
    case 'DAST':
      return getAttackSeverity(item, module)
    case 'SAST':
    case 'IAST':
      return getRuleSeverity(item, module)
    default:
      return DEFAULT_SEVERITY
  }
}
