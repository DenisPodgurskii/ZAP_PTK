import { normalizeCwe, normalizeOwasp } from "../../common/normalizeMappings.js"
import { normalizeSeverityValue } from "../../common/severity_utils.js"

const CANONICAL_SCHEMA = "ptk-dast-rulepack/v1"
const LEGACY_SCHEMA = "ptk-modules-v1"
const SAFETY_CAPABILITIES = new Set(["boolean", "error", "union", "time", "oast", "xmlEncoding"])
const ENGINE_CAPABILITY_ALIASES = Object.freeze({
    raw_http1: "smuggling_h1",
    http2: "smuggling_h2"
})
const ENGINE_CAPABILITIES = new Set([
    "smuggling_h1",
    "smuggling_h2",
    "websocket_handshake",
    "websocket_frames",
    "oast_callbacks",
    "race_burst",
    "multipart_files",
    "multi_identity"
])
const MODULE_CONSTANT_KEYS = ["regex", "regexLoginUrl", "regexLoggedIn"]
const ATTACK_CONSTANT_KEYS = ["regex", "regex1", "resultRegex"]
const TEMPLATE_FOLLOWUP_HOOK = "template_render_followup"
const SELECTOR_REGEX_REF_FIELDS = Object.freeze([
    ["nameRegexRef", "nameRegex"],
    ["excludeNameRegexRef", "excludeNameRegex"],
    ["valueRegexRef", "valueRegex"],
    ["pathRegexRef", "pathRegex"],
    ["jsonPathRegexRef", "jsonPathRegex"]
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
    const taxonomy = meta?.taxonomy && typeof meta.taxonomy === "object" ? meta.taxonomy : {}
    return {
        severity: normalizeSeverity(taxonomy?.severity ?? meta.severity),
        category: normalizeString(taxonomy?.category ?? meta.category, "unknown"),
        vulnId: normalizeString(taxonomy?.vulnId ?? moduleDef?.vulnId ?? meta.vulnId, normalizeString(taxonomy?.category ?? meta.category, "unknown")),
        owasp: uniqueStrings(normalizeOwasp(taxonomy?.owasp ?? meta.owasp).map((entry) => {
            if (!entry) return ""
            const version = entry.version && entry.version !== "unknown" ? entry.version : null
            const id = entry.id && entry.id !== "unknown" ? entry.id : null
            const name = normalizeString(entry.name)
            if (id && version && name) return `${id}:${version} - ${name}`
            if (id && version) return `${id}:${version}`
            return name
        })),
        cwe: uniqueStrings(normalizeCwe(taxonomy?.cwe ?? meta.cwe)),
        tags: uniqueStrings(taxonomy?.tags ?? meta.tags)
    }
}

function normalizeAttackTaxonomy(attackDef = {}) {
    const meta = attackDef?.metadata || {}
    const taxonomy = meta?.taxonomy && typeof meta.taxonomy === "object" ? meta.taxonomy : {}
    const out = {}
    if (taxonomy?.severity != null || meta?.severity != null) out.severity = normalizeSeverity(taxonomy?.severity ?? meta.severity)
    if (taxonomy?.category != null || meta?.category != null) out.category = normalizeString(taxonomy?.category ?? meta.category)
    if (attackDef?.vulnId != null || taxonomy?.vulnId != null || meta?.vulnId != null) {
        out.vulnId = normalizeString(attackDef?.vulnId || taxonomy?.vulnId || meta.vulnId)
    }
    if (taxonomy?.owasp != null || meta?.owasp != null) {
        out.owasp = uniqueStrings(normalizeOwasp(taxonomy?.owasp ?? meta.owasp).map((entry) => {
            if (!entry) return ""
            const version = entry.version && entry.version !== "unknown" ? entry.version : null
            const id = entry.id && entry.id !== "unknown" ? entry.id : null
            const name = normalizeString(entry.name)
            if (id && version && name) return `${id}:${version} - ${name}`
            if (id && version) return `${id}:${version}`
            return name
        }))
    }
    if (taxonomy?.cwe != null || meta?.cwe != null) out.cwe = uniqueStrings(normalizeCwe(taxonomy?.cwe ?? meta.cwe))
    if (taxonomy?.tags != null || meta?.tags != null) out.tags = uniqueStrings(taxonomy?.tags ?? meta.tags)
    return out
}

function normalizeModuleDocs(moduleDef = {}) {
    const meta = moduleDef?.metadata || {}
    const docs = meta?.docs && typeof meta.docs === "object" ? meta.docs : {}
    return {
        description: normalizeString(docs?.description ?? meta.description, moduleDef?.name || "PTK DAST module"),
        recommendation: normalizeString(docs?.recommendation ?? meta.recommendation, "Review and remediate the identified weakness."),
        links: clonePlainObject(docs?.links ?? meta.links, {})
    }
}

function normalizeAttackDocs(attackDef = {}) {
    const docs = attackDef?.metadata?.docs && typeof attackDef.metadata.docs === "object" ? attackDef.metadata.docs : {}
    const description = normalizeString(docs?.description ?? attackDef?.description)
    const recommendation = normalizeString(docs?.recommendation)
    const links = clonePlainObject(docs?.links, {})
    const out = {}
    if (description) out.description = description
    if (recommendation) out.recommendation = recommendation
    if (Object.keys(links).length) out.links = links
    return out
}

function normalizeModuleConstants(moduleDef = {}) {
    const constants = clonePlainObject(moduleDef?.metadata?.constants, {})
    const meta = moduleDef?.metadata || {}
    MODULE_CONSTANT_KEYS.forEach((key) => {
        if (meta[key] !== undefined) constants[key] = cloneValue(meta[key])
    })
    return constants
}

function normalizeAttackConstants(attackDef = {}) {
    const constants = clonePlainObject(attackDef?.metadata?.constants, {})
    ATTACK_CONSTANT_KEYS.forEach((key) => {
        if (attackDef[key] !== undefined) constants[key] = cloneValue(attackDef[key])
    })
    return constants
}

function normalizeAllowStrategyBulk(moduleDef = {}) {
    if (typeof moduleDef?.metadata?.execution?.allowStrategyBulk === "boolean") return moduleDef.metadata.execution.allowStrategyBulk
    if (typeof moduleDef?.metadata?.allowStrategyBulk === "boolean") return moduleDef.metadata.allowStrategyBulk
    if (typeof moduleDef?.supportsAtomic === "boolean") return moduleDef.supportsAtomic
    if (typeof moduleDef?.atomic === "boolean") return moduleDef.atomic
    if (typeof moduleDef?.metadata?.supportsAtomic === "boolean") return moduleDef.metadata.supportsAtomic
    return true
}

function normalizeFindingSemantics(moduleDef = {}) {
    const canonical = normalizeString(moduleDef?.metadata?.execution?.findingSemantics).toLowerCase()
    if (canonical === "unique" || canonical === "repeatable") return canonical
    const value = moduleDef?.metadata?.unique
    return value === true ? "unique" : "repeatable"
}

function normalizeCapabilities(moduleDef = {}) {
    const executionCaps = Array.isArray(moduleDef?.metadata?.execution?.capabilities)
        ? moduleDef.metadata.execution.capabilities
        : []
    const techniques = executionCaps.length
        ? executionCaps
        : Array.isArray(moduleDef?.metadata?.techniques)
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

function normalizeEngineCapabilities(values = []) {
    return uniqueStrings(values)
        .map((value) => String(value || "").trim())
        .map((value) => ENGINE_CAPABILITY_ALIASES[value] || ENGINE_CAPABILITY_ALIASES[value.toLowerCase()] || value)
        .filter((value) => ENGINE_CAPABILITIES.has(value))
}

function normalizeRuntimeMode(moduleDef = {}) {
    const runtimeMode = normalizeString(moduleDef?.runtime?.mode).toLowerCase()
    if (runtimeMode === "standard" || runtimeMode === "deserialization" || runtimeMode === "spa" || runtimeMode === "browser_nav" || runtimeMode === "browser_workflow") {
        return runtimeMode
    }
    const techniques = uniqueStrings(moduleDef?.metadata?.techniques || [])
    if (moduleDef?.metadata?.spa === true) return "spa"
    const hasBrowserNavConfig = Array.isArray(moduleDef?.attacks)
        && moduleDef.attacks.some((attack) => attack?.runtime?.config?.browserNav && typeof attack.runtime.config.browserNav === "object")
    if (hasBrowserNavConfig) return "browser_nav"
    const hasBrowserWorkflowConfig = Array.isArray(moduleDef?.attacks)
        && moduleDef.attacks.some((attack) => attack?.runtime?.config?.browserWorkflow && typeof attack.runtime.config.browserWorkflow === "object")
    if (hasBrowserWorkflowConfig) return "browser_workflow"
    const hasDeserializationProfile = Array.isArray(moduleDef?.attacks)
        && moduleDef.attacks.some((attack) => attack?.metadata?.deserProfile && typeof attack.metadata.deserProfile === "object")
    if (hasDeserializationProfile) return "deserialization"
    if (techniques.some((value) => value.toLowerCase() === "deserialization")) return "deserialization"
    return "standard"
}

function normalizeRuntimeHooks(moduleDef = {}) {
    const runtimeHooks = uniqueStrings(moduleDef?.runtime?.hooks || [])
    if (runtimeHooks.length) return runtimeHooks
    const techniques = uniqueStrings(moduleDef?.metadata?.techniques || []).map((value) => value.toLowerCase())
    return techniques.includes("template_injection") ? [TEMPLATE_FOLLOWUP_HOOK] : []
}

function normalizeModuleRuntime(moduleDef = {}) {
    const mode = normalizeRuntimeMode(moduleDef)
    const runtime = moduleDef?.runtime && typeof moduleDef.runtime === "object" ? moduleDef.runtime : {}
    const config = clonePlainObject(runtime?.config, {})
    if (mode === "deserialization" && !config.deserialization) {
        config.deserialization = {}
    } else if (mode === "spa" && !config.spa) {
        config.spa = {}
    } else if (mode === "browser_nav" && !config.browserNav) {
        config.browserNav = {}
    } else if (mode === "browser_workflow" && !config.browserWorkflow) {
        config.browserWorkflow = {}
    }
    return {
        mode,
        hooks: normalizeRuntimeHooks(moduleDef),
        confirmation: clonePlainObject(runtime?.confirmation, {}),
        config
    }
}

function normalizeModuleExecution(moduleDef = {}) {
    const meta = moduleDef?.metadata || {}
    const execution = meta?.execution && typeof meta.execution === "object" ? meta.execution : {}
    return {
        findingSemantics: normalizeFindingSemantics(moduleDef),
        capabilities: normalizeCapabilities(moduleDef),
        requiredEngineCapabilities: normalizeEngineCapabilities(execution?.requiredEngineCapabilities || meta?.requiredEngineCapabilities || []),
        allowStrategyBulk: normalizeAllowStrategyBulk(moduleDef),
        allowAuthLikeTargets: execution.allowAuthLikeTargets === true || meta.allowAuthLikeTargets === true,
        allowHardDeniedTargets: clonePlainObject(execution?.allowHardDeniedTargets || meta.allowHardDeniedTargets, {}),
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
    const canonical = normalizeString(attackDef?.requestGrouping).toLowerCase()
    if (canonical === "inherit" || canonical === "bulk" || canonical === "per_target") return canonical
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
    const runtime = attackDef?.runtime && typeof attackDef.runtime === "object" ? attackDef.runtime : {}
    const confirmation = {}
    if (runtime?.confirmation?.oast && typeof runtime.confirmation.oast === "object") {
        confirmation.oast = compactObject(runtime.confirmation.oast)
    } else if (attackDef?.oast && typeof attackDef.oast === "object") {
        confirmation.oast = compactObject(attackDef.oast)
    }
    if (runtime?.confirmation?.tracking && typeof runtime.confirmation.tracking === "object") {
        confirmation.tracking = compactObject(runtime.confirmation.tracking)
    } else if (attackDef?.tracking && typeof attackDef.tracking === "object") {
        confirmation.tracking = compactObject(attackDef.tracking)
    }

    const config = clonePlainObject(runtime?.config, {})
    if (!config.deserialization && attackDef?.metadata?.deserProfile && typeof attackDef.metadata.deserProfile === "object") {
        config.deserialization = compactObject(attackDef.metadata.deserProfile)
    }
    if (!config.spa && attackDef?.spa && typeof attackDef.spa === "object") {
        config.spa = compactObject(attackDef.spa)
    }
    if (!config.browserNav && attackDef?.browserNav && typeof attackDef.browserNav === "object") {
        config.browserNav = compactObject(attackDef.browserNav)
    }
    if (!config.browserWorkflow && attackDef?.browserWorkflow && typeof attackDef.browserWorkflow === "object") {
        config.browserWorkflow = compactObject(attackDef.browserWorkflow)
    }

    return {
        hooks: uniqueStrings(runtime?.hooks || []),
        confirmation,
        config
    }
}

function normalizeAttackMetadata(attackDef = {}) {
    const meta = attackDef?.metadata || {}
    const extensions = clonePlainObject(meta?.extensions, {})
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

function buildSelectorConstantMap(moduleDef = {}, attackDef = {}) {
    return Object.assign({}, normalizeModuleConstants(moduleDef), normalizeAttackConstants(attackDef))
}

function expandSelectorRegexRefs(value, constants = {}, ctx = {}) {
    const label = [
        ctx?.moduleId ? `module ${ctx.moduleId}` : null,
        ctx?.attackId ? `attack ${ctx.attackId}` : null
    ].filter(Boolean).join(" ")

    const walk = (node, path = "") => {
        if (Array.isArray(node)) {
            return node.map((item, index) => walk(item, `${path}[${index}]`))
        }
        if (!node || typeof node !== "object") return cloneValue(node)

        const out = {}
        Object.entries(node).forEach(([key, raw]) => {
            out[key] = walk(raw, path ? `${path}.${key}` : key)
        })

        SELECTOR_REGEX_REF_FIELDS.forEach(([refKey, targetKey]) => {
            if (!Object.prototype.hasOwnProperty.call(out, refKey)) return
            if (typeof out[targetKey] !== "string" || !out[targetKey].trim()) {
                const refName = normalizeString(out[refKey])
                if (!refName) {
                    throw new Error(`[PTK DAST] Invalid empty selector ref ${refKey} at ${label || "rulepack"} ${path}`.trim())
                }
                const resolved = constants[refName]
                if (typeof resolved !== "string" || !resolved.trim()) {
                    throw new Error(`[PTK DAST] Unknown or non-string selector constant "${refName}" for ${refKey} at ${label || "rulepack"} ${path}`.trim())
                }
                out[targetKey] = resolved
            }
            delete out[refKey]
        })

        return out
    }

    return walk(value)
}

function normalizeAttack(attackDef = {}, moduleDef = {}) {
    const selectorConstants = buildSelectorConstantMap(moduleDef, attackDef)
    return {
        id: normalizeString(attackDef?.id),
        name: normalizeString(attackDef?.name, normalizeString(attackDef?.id, "attack")),
        runtime: normalizeAttackRuntime(attackDef),
        action: expandSelectorRegexRefs(clonePlainObject(attackDef?.action, {}), selectorConstants, {
            moduleId: normalizeString(moduleDef?.id),
            attackId: normalizeString(attackDef?.id)
        }),
        validation: normalizeValidation(attackDef),
        condition: attackDef?.condition !== undefined ? cloneValue(attackDef.condition) : {},
        target: expandSelectorRegexRefs(clonePlainObject(attackDef?.target, {}), selectorConstants, {
            moduleId: normalizeString(moduleDef?.id),
            attackId: normalizeString(attackDef?.id)
        }),
        requestGrouping: normalizeRequestGrouping(attackDef),
        metadata: normalizeAttackMetadata(attackDef)
    }
}

function normalizeModuleMetadata(moduleDef = {}) {
    const meta = moduleDef?.metadata || {}
    return {
        taxonomy: normalizeModuleTaxonomy(moduleDef),
        docs: normalizeModuleDocs(moduleDef),
        execution: normalizeModuleExecution(moduleDef),
        constants: normalizeModuleConstants(moduleDef),
        extensions: clonePlainObject(meta?.extensions, {})
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
        attacks: Array.isArray(moduleDef?.attacks) ? moduleDef.attacks.map((attack) => normalizeAttack(attack, moduleDef)) : []
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
