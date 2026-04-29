import { normalizeCwe, normalizeOwasp } from "../../common/normalizeMappings.js"
import { normalizeSeverityValue } from "../../common/severity_utils.js"

export const IAST_CANONICAL_SCHEMA = "ptk-iast-rulepack/v1"
export const IAST_LEGACY_SCHEMA = "ptk-modules-v1"
const DEFAULT_MODULE_TYPE = "runtime"
const DEFAULT_CATEGORY = "runtime_issue"
const DEFAULT_RECOMMENDATION = "Review and remediate the identified runtime issue."
const VALID_HOOK_KINDS = new Set(["propertySetter", "methodCall", "constructor", "attribute", "event"])
const VALID_SANITIZER_ACTIONS = new Set(["suppress", "lower_confidence"])
const VALID_FINDING_AGGREGATION_MODES = new Set([
    "route-source-sink",
    "route-source-sink-callsite",
    "source-sink",
    "source-sink-callsite"
])

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

function normalizeString(value, fallback = "") {
    const text = typeof value === "string" ? value.trim() : ""
    return text || fallback
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

function normalizeExtensionVersion(value) {
    return normalizeString(value)
}

function normalizeSchemaFeatureList(values) {
    return uniqueStrings(values)
}

function hasOwn(obj, key) {
    return !!obj && Object.prototype.hasOwnProperty.call(obj, key)
}

function normalizeLinks(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
    const links = {}
    Object.entries(value).forEach(([key, raw]) => {
        const linkKey = normalizeString(key)
        const linkValue = normalizeString(raw)
        if (!linkKey || !linkValue) return
        links[linkKey] = linkValue
    })
    return Object.keys(links).length ? links : undefined
}

function normalizePresentation(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
    const aggregate = normalizeString(value.aggregate).toLowerCase()
    if (!VALID_FINDING_AGGREGATION_MODES.has(aggregate)) return undefined
    return { aggregate }
}

function normalizePolicy(policy) {
    if (!policy || typeof policy !== "object" || Array.isArray(policy)) return undefined
    const normalized = {}
    ;["id", "name", "description", "updated_at"].forEach((key) => {
        const value = normalizeString(policy[key])
        if (value) normalized[key] = value
    })
    return Object.keys(normalized).length ? normalized : undefined
}

function normalizeModuleMetadata(moduleDef = {}) {
    const meta = moduleDef?.metadata && typeof moduleDef.metadata === "object" && !Array.isArray(moduleDef.metadata)
        ? moduleDef.metadata
        : {}
    const moduleId = normalizeString(moduleDef?.id)
    const moduleName = normalizeString(moduleDef?.name, moduleId || "PTK IAST module")
    const category = normalizeString(meta.category, DEFAULT_CATEGORY)
    const metadata = {
        description: normalizeString(meta.description, moduleName),
        recommendation: normalizeString(meta.recommendation, DEFAULT_RECOMMENDATION),
        severity: normalizeSeverityValue(meta.severity ?? moduleDef?.severity, "medium"),
        category,
        vulnId: normalizeString(moduleDef?.vulnId || meta.vulnId, moduleId || category),
        owasp: uniqueStrings(normalizeOwasp(meta.owasp).map((entry) => {
            if (!entry) return ""
            const version = entry.version && entry.version !== "unknown" ? entry.version : null
            const id = entry.id && entry.id !== "unknown" ? entry.id : null
            const name = normalizeString(entry.name)
            if (id && version && name) return `${id}:${version} - ${name}`
            if (id && version) return `${id}:${version}`
            return name
        })),
        cwe: uniqueStrings(normalizeCwe(meta.cwe)),
        tags: uniqueStrings(meta.tags)
    }
    const links = normalizeLinks(meta.links)
    if (links) metadata.links = links
    const presentation = normalizePresentation(meta.presentation)
    if (presentation) metadata.presentation = presentation
    return metadata
}

function normalizeHook(hook) {
    if (!hook || typeof hook !== "object" || Array.isArray(hook)) return {}
    const kind = normalizeString(hook.kind)
    if (!VALID_HOOK_KINDS.has(kind)) {
        return kind ? { kind } : {}
    }

    const normalized = { kind }
    switch (kind) {
    case "propertySetter":
        if (normalizeString(hook.objectType)) normalized.objectType = normalizeString(hook.objectType)
        if (normalizeString(hook.objectPath)) normalized.objectPath = normalizeString(hook.objectPath)
        if (normalizeString(hook.property)) normalized.property = normalizeString(hook.property)
        break
    case "methodCall":
        if (normalizeString(hook.objectType)) normalized.objectType = normalizeString(hook.objectType)
        if (normalizeString(hook.objectPath)) normalized.objectPath = normalizeString(hook.objectPath)
        if (normalizeString(hook.method)) normalized.method = normalizeString(hook.method)
        if (hook.argIndex !== undefined && hook.argIndex !== null && String(hook.argIndex).trim() !== "") {
            const parsed = Number(hook.argIndex)
            if (Number.isFinite(parsed) && parsed >= 0) {
                normalized.argIndex = Math.trunc(parsed)
            }
        }
        break
    case "constructor":
        if (normalizeString(hook.objectPath)) normalized.objectPath = normalizeString(hook.objectPath)
        break
    case "attribute":
        if (normalizeString(hook.objectType)) normalized.objectType = normalizeString(hook.objectType)
        if (normalizeString(hook.attribute)) normalized.attribute = normalizeString(hook.attribute)
        if (normalizeString(hook.attributePrefix)) normalized.attributePrefix = normalizeString(hook.attributePrefix)
        break
    case "event":
        if (normalizeString(hook.objectPath)) normalized.objectPath = normalizeString(hook.objectPath)
        if (normalizeString(hook.event)) normalized.event = normalizeString(hook.event)
        break
    }
    return normalized
}

function normalizeConditions(conditions) {
    if (!conditions || typeof conditions !== "object" || Array.isArray(conditions)) return undefined
    const normalized = {}
    if (conditions.requiresTaint === true || conditions.requiresTaint === false) {
        normalized.requiresTaint = conditions.requiresTaint === true
    }
    if (conditions.requiresCrossOrigin === true || conditions.requiresCrossOrigin === false) {
        normalized.requiresCrossOrigin = conditions.requiresCrossOrigin === true
    }
    return Object.keys(normalized).length ? normalized : undefined
}

function normalizeLimits(limits) {
    if (!limits || typeof limits !== "object" || Array.isArray(limits)) return undefined
    const normalized = {}
    if (limits.maxTriggersPerSession !== undefined && limits.maxTriggersPerSession !== null) {
        const parsed = Number(limits.maxTriggersPerSession)
        if (Number.isFinite(parsed) && parsed >= 1) {
            normalized.maxTriggersPerSession = Math.trunc(parsed)
        }
    }
    if (limits.maxReports !== undefined && limits.maxReports !== null) {
        const parsed = Number(limits.maxReports)
        if (Number.isFinite(parsed) && parsed >= 1) {
            normalized.maxReports = Math.trunc(parsed)
        }
    }
    return Object.keys(normalized).length ? normalized : undefined
}

function normalizeRuleMetadata(ruleDef = {}) {
    const meta = ruleDef?.metadata && typeof ruleDef.metadata === "object" && !Array.isArray(ruleDef.metadata)
        ? ruleDef.metadata
        : {}
    const normalized = {}
    const description = normalizeString(meta.description || ruleDef.description)
    if (description) normalized.description = description
    const recommendation = normalizeString(meta.recommendation || ruleDef.recommendation)
    if (recommendation) normalized.recommendation = recommendation
    const severity = meta.severity ?? ruleDef.severity
    if (severity !== undefined && severity !== null) {
        normalized.severity = normalizeSeverityValue(severity, "medium")
    }
    const category = normalizeString(meta.category || ruleDef.category)
    if (category) normalized.category = category
    const vulnId = normalizeString(meta.vulnId || ruleDef.vulnId)
    if (vulnId) normalized.vulnId = vulnId
    if (meta.confidence !== undefined && meta.confidence !== null && String(meta.confidence).trim() !== "") {
        const parsed = Number(meta.confidence)
        if (Number.isFinite(parsed)) {
            normalized.confidence = Math.min(100, Math.max(1, Math.round(parsed)))
        }
    }
    const owasp = uniqueStrings(normalizeOwasp(meta.owasp).map((entry) => {
        if (!entry) return ""
        const version = entry.version && entry.version !== "unknown" ? entry.version : null
        const id = entry.id && entry.id !== "unknown" ? entry.id : null
        const name = normalizeString(entry.name)
        if (id && version && name) return `${id}:${version} - ${name}`
        if (id && version) return `${id}:${version}`
        return name
    }))
    if (owasp.length) normalized.owasp = owasp
    const cwe = uniqueStrings(normalizeCwe(meta.cwe))
    if (cwe.length) normalized.cwe = cwe
    const tags = uniqueStrings(meta.tags)
    if (tags.length) normalized.tags = tags
    const links = normalizeLinks(meta.links)
    if (links) normalized.links = links
    const presentation = normalizePresentation(meta.presentation)
    if (presentation) normalized.presentation = presentation
    return Object.keys(normalized).length ? normalized : undefined
}

function normalizeRule(ruleDef = {}, index = 0) {
    const ruleId = normalizeString(ruleDef?.id || ruleDef?.code)
    const name = normalizeString(ruleDef?.name, ruleId || `rule_${index + 1}`)
    const sinkId = normalizeString(ruleDef?.sinkId || ruleDef?.sink)
    const normalized = {
        id: ruleId || `rule_${index + 1}`,
        name,
        sinkId
    }
    const hook = normalizeHook(ruleDef?.hook)
    if (Object.keys(hook).length) normalized.hook = hook
    const schemaVersion = normalizeString(ruleDef?.schemaVersion)
    if (schemaVersion) normalized.schemaVersion = schemaVersion
    const severity = ruleDef?.severity
    if (severity !== undefined && severity !== null) {
        normalized.severity = normalizeSeverityValue(severity, "medium")
    }
    const sources = uniqueStrings(ruleDef?.sources)
    if (sources.length) normalized.sources = sources
    const sanitizersAllowed = uniqueStrings(ruleDef?.sanitizersAllowed)
    if (sanitizersAllowed.length) normalized.sanitizersAllowed = sanitizersAllowed
    const onSanitized = normalizeString(ruleDef?.onSanitized)
    if (VALID_SANITIZER_ACTIONS.has(onSanitized)) normalized.onSanitized = onSanitized
    const conditions = normalizeConditions(ruleDef?.conditions)
    if (conditions) normalized.conditions = conditions
    const limits = normalizeLimits(ruleDef?.limits)
    if (limits) normalized.limits = limits
    const metadata = normalizeRuleMetadata(ruleDef)
    if (metadata) normalized.metadata = metadata
    return normalized
}

function normalizeModule(moduleDef = {}, index = 0) {
    const moduleId = normalizeString(moduleDef?.id) || `module_${index + 1}`
    const name = normalizeString(moduleDef?.name, moduleId)
    const rules = Array.isArray(moduleDef?.rules)
        ? moduleDef.rules.map((rule, ruleIndex) => normalizeRule(rule, ruleIndex))
        : []
    return {
        id: moduleId,
        type: normalizeString(moduleDef?.type, DEFAULT_MODULE_TYPE),
        async: moduleDef?.async !== false,
        name,
        metadata: normalizeModuleMetadata({
            ...moduleDef,
            id: moduleId,
            name
        }),
        rules
    }
}

export function isCanonicalIastRulepack(rulepack) {
    return !!(
        rulepack
        && typeof rulepack === "object"
        && !Array.isArray(rulepack)
        && rulepack.schema === IAST_CANONICAL_SCHEMA
        && String(rulepack.engine || "").toUpperCase() === "IAST"
    )
}

export function normalizeLegacyIastRulepack(rulepack) {
    const input = rulepack && typeof rulepack === "object" && !Array.isArray(rulepack)
        ? cloneValue(rulepack)
        : {}
    const modules = Array.isArray(input.modules) ? input.modules : []
    const canonical = {
        schema: IAST_CANONICAL_SCHEMA,
        engine: "IAST",
        version: 1,
        modules: modules.map((moduleDef, index) => normalizeModule(moduleDef, index))
    }
    if (hasOwn(input, "minExtensionVersion")) {
        const minExtensionVersion = normalizeExtensionVersion(input.minExtensionVersion)
        canonical.minExtensionVersion = minExtensionVersion || cloneValue(input.minExtensionVersion)
    }
    if (hasOwn(input, "requiresSchemaFeatures")) {
        const rawFeatures = input.requiresSchemaFeatures
        if (Array.isArray(rawFeatures)) {
            const allFeaturesValid = rawFeatures.length === 0
                || rawFeatures.every((value) => typeof value === "string" && value.trim().length > 0)
            const normalized = normalizeSchemaFeatureList(rawFeatures)
            const hasDuplicates = normalized.length !== rawFeatures.length
            canonical.requiresSchemaFeatures = allFeaturesValid && !hasDuplicates
                ? normalized
                : cloneValue(rawFeatures)
        } else {
            canonical.requiresSchemaFeatures = cloneValue(rawFeatures)
        }
    }
    const policy = normalizePolicy(input.policy)
    if (policy) canonical.policy = policy
    return canonical
}

export default normalizeLegacyIastRulepack
