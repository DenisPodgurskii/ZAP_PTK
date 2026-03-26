import { normalizeCwe, normalizeOwasp } from "../../common/normalizeMappings.js"
import { normalizeSeverityValue } from "../../common/severity_utils.js"

const CANONICAL_SCHEMA = "ptk-dast-rulepack/v1"
const LEGACY_SCHEMA = "ptk-modules-v1"
const SAFETY_CAPABILITIES = new Set(["boolean", "error", "union", "time", "oast", "xmlEncoding"])
const MODULE_CONSTANT_KEYS = ["regex", "regexLoginUrl", "regexLoggedIn"]
const ATTACK_CONSTANT_KEYS = ["regex", "regex1", "resultRegex"]
const TEMPLATE_FOLLOWUP_HOOK = "template_render_followup"

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

function normalizeString(value, fallback = "") {
    const text = typeof value === "string" ? value.trim() : ""
    return text || fallback
}

function uniqueStrings(values = []) {
    const out = []
    const seen = new Set()
    for (const value of Array.isArray(values) ? values : [values]) {
        const text = normalizeString(value)
        if (!text || seen.has(text)) continue
        seen.add(text)
        out.push(text)
    }
    return out
}

function compactObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return {}
    const out = {}
    Object.entries(value).forEach(([key, raw]) => {
        if (raw === null || raw === undefined) return
        if (Array.isArray(raw)) {
            out[key] = cloneValue(raw)
            return
        }
        if (typeof raw === "object") {
            const nested = compactObject(raw)
            if (Object.keys(nested).length) {
                out[key] = nested
            }
            return
        }
        out[key] = raw
    })
    return out
}

function normalizeSeverity(value) {
    return normalizeSeverityValue(value, "medium")
}

function normalizeModuleTaxonomy(moduleDef = {}) {
    const meta = moduleDef?.metadata || {}
    return {
        severity: normalizeSeverity(meta.severity),
        category: normalizeString(meta.category, "unknown"),
        vulnId: normalizeString(moduleDef?.vulnId || meta.vulnId, normalizeString(meta.category, "unknown")),
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
}

function normalizeAttackTaxonomy(attackDef = {}) {
    const meta = attackDef?.metadata || {}
    const out = {}
    if (meta.severity != null) out.severity = normalizeSeverity(meta.severity)
    if (meta.category != null) out.category = normalizeString(meta.category)
    if (attackDef?.vulnId != null || meta.vulnId != null) {
        out.vulnId = normalizeString(attackDef?.vulnId || meta.vulnId)
    }
    if (meta.owasp != null) {
        out.owasp = uniqueStrings(normalizeOwasp(meta.owasp).map((entry) => {
            if (!entry) return ""
            const version = entry.version && entry.version !== "unknown" ? entry.version : null
            const id = entry.id && entry.id !== "unknown" ? entry.id : null
            const name = normalizeString(entry.name)
            if (id && version && name) return `${id}:${version} - ${name}`
            if (id && version) return `${id}:${version}`
            return name
        }))
    }
    if (meta.cwe != null) out.cwe = uniqueStrings(normalizeCwe(meta.cwe))
    if (meta.tags != null) out.tags = uniqueStrings(meta.tags)
    return out
}

function normalizeModuleDocs(moduleDef = {}) {
    const meta = moduleDef?.metadata || {}
    return {
        description: normalizeString(meta.description, moduleDef?.name || "PTK DAST module"),
        recommendation: normalizeString(meta.recommendation, "Review and remediate the identified weakness."),
        links: clonePlainObject(meta.links, {})
    }
}

function normalizeAttackDocs(attackDef = {}) {
    const description = normalizeString(attackDef?.description)
    if (!description) return {}
    return { description }
}

function normalizeModuleConstants(moduleDef = {}) {
    const constants = {}
    const meta = moduleDef?.metadata || {}
    MODULE_CONSTANT_KEYS.forEach((key) => {
        if (meta[key] !== undefined) constants[key] = cloneValue(meta[key])
    })
    return constants
}

function normalizeAttackConstants(attackDef = {}) {
    const constants = {}
    ATTACK_CONSTANT_KEYS.forEach((key) => {
        if (attackDef[key] !== undefined) constants[key] = cloneValue(attackDef[key])
    })
    return constants
}

function normalizeAllowStrategyBulk(moduleDef = {}) {
    if (typeof moduleDef?.supportsAtomic === "boolean") return moduleDef.supportsAtomic
    if (typeof moduleDef?.atomic === "boolean") return moduleDef.atomic
    if (typeof moduleDef?.metadata?.supportsAtomic === "boolean") return moduleDef.metadata.supportsAtomic
    return true
}

function normalizeFindingSemantics(moduleDef = {}) {
    const value = moduleDef?.metadata?.unique
    return value === true ? "unique" : "repeatable"
}

function normalizeCapabilities(moduleDef = {}) {
    const techniques = Array.isArray(moduleDef?.metadata?.techniques)
        ? moduleDef.metadata.techniques
        : []
    const capabilities = techniques
        .map((value) => normalizeString(value))
        .filter((value) => SAFETY_CAPABILITIES.has(value))
    const hasOastAttack = Array.isArray(moduleDef?.attacks)
        && moduleDef.attacks.some((attack) => attack?.oast?.enabled === true)
    if (hasOastAttack) capabilities.push("oast")
    return uniqueStrings(capabilities)
}

function normalizeRuntimeMode(moduleDef = {}) {
    const techniques = uniqueStrings(moduleDef?.metadata?.techniques || [])
    if (moduleDef?.metadata?.spa === true) return "spa"
    const hasDeserializationProfile = Array.isArray(moduleDef?.attacks)
        && moduleDef.attacks.some((attack) => attack?.metadata?.deserProfile && typeof attack.metadata.deserProfile === "object")
    if (hasDeserializationProfile) return "deserialization"
    if (techniques.some((value) => value.toLowerCase() === "deserialization")) return "deserialization"
    return "standard"
}

function normalizeRuntimeHooks(moduleDef = {}) {
    const techniques = uniqueStrings(moduleDef?.metadata?.techniques || []).map((value) => value.toLowerCase())
    return techniques.includes("template_injection") ? [TEMPLATE_FOLLOWUP_HOOK] : []
}

function normalizeModuleRuntime(moduleDef = {}) {
    const mode = normalizeRuntimeMode(moduleDef)
    const config = {}
    if (mode === "deserialization") {
        config.deserialization = {}
    } else if (mode === "spa") {
        config.spa = {}
    }
    return {
        mode,
        hooks: normalizeRuntimeHooks(moduleDef),
        confirmation: {},
        config
    }
}

function normalizeModuleExecution(moduleDef = {}) {
    const meta = moduleDef?.metadata || {}
    return {
        findingSemantics: normalizeFindingSemantics(moduleDef),
        capabilities: normalizeCapabilities(moduleDef),
        requiredEngineCapabilities: [],
        allowStrategyBulk: normalizeAllowStrategyBulk(moduleDef),
        allowAuthLikeTargets: meta.allowAuthLikeTargets === true,
        allowHardDeniedTargets: clonePlainObject(meta.allowHardDeniedTargets, {}),
        ignoreGlobalExcludes: meta.ignoreGlobalExcludes === true,
        prefilters: normalizeExecutionPrefilters(moduleDef)
    }
}

function normalizeExecutionPrefilters(moduleDef = {}) {
    const meta = moduleDef?.metadata || {}
    const source = (
        meta?.execution?.prefilters && typeof meta.execution.prefilters === "object"
    )
        ? meta.execution.prefilters
        : (
            meta?.prefilters && typeof meta.prefilters === "object"
                ? meta.prefilters
                : {}
        )
    const methods = uniqueStrings(source?.methods || []).map((value) => value.toUpperCase())
    const out = {}
    if (methods.length) out.methods = methods
    if (source?.requiresBody === true) out.requiresBody = true
    if (source?.requiresJsonBody === true) out.requiresJsonBody = true
    if (source?.requiresXmlBody === true) out.requiresXmlBody = true
    if (source?.requiresQueryParams === true) out.requiresQueryParams = true
    if (source?.requiresQueryOrBodyParams === true) out.requiresQueryOrBodyParams = true
    if (source?.requiresCookies === true) out.requiresCookies = true
    if (source?.requiresHeaders === true) out.requiresHeaders = true
    return out
}

function normalizeRequestGrouping(attackDef = {}) {
    if (attackDef?.atomic === false) return "bulk"
    if (attackDef?.atomic === true) return "per_target"
    return "inherit"
}

function normalizeValidation(attackDef = {}) {
    if (attackDef?.validation && typeof attackDef.validation === "object") {
        const validation = clonePlainObject(attackDef.validation, {})
        if (!Object.prototype.hasOwnProperty.call(validation, "proof") && attackDef?.proof && typeof attackDef.proof === "object") {
            validation.proof = cloneValue(attackDef.proof)
        }
        if (!Object.prototype.hasOwnProperty.call(validation, "rule")) {
            validation.rule = false
        }
        return validation
    }
    return { rule: false }
}

function normalizeAttackRuntime(attackDef = {}) {
    const confirmation = {}
    if (attackDef?.oast && typeof attackDef.oast === "object") {
        confirmation.oast = compactObject(attackDef.oast)
    }
    if (attackDef?.tracking && typeof attackDef.tracking === "object") {
        confirmation.tracking = compactObject(attackDef.tracking)
    }

    const config = {}
    if (attackDef?.metadata?.deserProfile && typeof attackDef.metadata.deserProfile === "object") {
        config.deserialization = compactObject(attackDef.metadata.deserProfile)
    }
    if (attackDef?.spa && typeof attackDef.spa === "object") {
        config.spa = compactObject(attackDef.spa)
    }

    return {
        hooks: [],
        confirmation,
        config
    }
}

function normalizeAttackMetadata(attackDef = {}) {
    const extensions = {}
    if (attackDef?.metadata?.deserProfile && typeof attackDef.metadata.deserProfile === "object") {
        extensions.deserialization = clonePlainObject(attackDef.metadata.deserProfile, {})
    }
    return {
        taxonomy: normalizeAttackTaxonomy(attackDef),
        docs: normalizeAttackDocs(attackDef),
        constants: normalizeAttackConstants(attackDef),
        extensions
    }
}

function normalizeAttack(attackDef = {}) {
    return {
        id: normalizeString(attackDef?.id),
        name: normalizeString(attackDef?.name, normalizeString(attackDef?.id, "attack")),
        runtime: normalizeAttackRuntime(attackDef),
        action: clonePlainObject(attackDef?.action, {}),
        validation: normalizeValidation(attackDef),
        condition: attackDef?.condition !== undefined ? cloneValue(attackDef.condition) : {},
        target: clonePlainObject(attackDef?.target, {}),
        requestGrouping: normalizeRequestGrouping(attackDef),
        metadata: normalizeAttackMetadata(attackDef)
    }
}

function normalizeModuleMetadata(moduleDef = {}) {
    const meta = moduleDef?.metadata || {}
    const extensions = {}
    if (meta.unique === false) {
        extensions.legacy = {
            uniqueBehavior: "skip_after_success"
        }
    }
    return {
        taxonomy: normalizeModuleTaxonomy(moduleDef),
        docs: normalizeModuleDocs(moduleDef),
        execution: normalizeModuleExecution(moduleDef),
        constants: normalizeModuleConstants(moduleDef),
        extensions
    }
}

function normalizeModule(moduleDef = {}) {
    return {
        id: normalizeString(moduleDef?.id),
        name: normalizeString(moduleDef?.name, normalizeString(moduleDef?.id, "module")),
        type: normalizeString(moduleDef?.type, "active"),
        async: moduleDef?.async !== false,
        runtime: normalizeModuleRuntime(moduleDef),
        metadata: normalizeModuleMetadata(moduleDef),
        attacks: Array.isArray(moduleDef?.attacks) ? moduleDef.attacks.map((attack) => normalizeAttack(attack)) : []
    }
}

export function isCanonicalDastRulepack(rulepack) {
    return rulepack?.schema === CANONICAL_SCHEMA && rulepack?.engine === "DAST"
}

export function normalizeLegacyDastRulepack(rulepack) {
    if (!rulepack || typeof rulepack !== "object") {
        throw new Error("[PTK DAST] Expected rulepack object")
    }
    if (isCanonicalDastRulepack(rulepack)) {
        return cloneValue(rulepack)
    }
    if (rulepack?.schema && rulepack.schema !== LEGACY_SCHEMA) {
        throw new Error(`[PTK DAST] Unsupported legacy DAST schema: ${rulepack.schema}`)
    }

    return {
        schema: CANONICAL_SCHEMA,
        engine: "DAST",
        version: 1,
        modules: Array.isArray(rulepack?.modules) ? rulepack.modules.map((moduleDef) => normalizeModule(moduleDef)) : []
    }
}

export default normalizeLegacyDastRulepack
