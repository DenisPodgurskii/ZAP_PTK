import normalizeLegacyDastRulepack, {
    isCanonicalDastRulepack
} from "./normalizeLegacyDastRulepack.js"
import {
    assertValidDastRulepack
} from "./validateDastRulepack.js"

function isPlainObject(value) {
    return !!value && typeof value === "object" && !Array.isArray(value)
}

function toRuntimeMode(value, fallback = "standard") {
    const direct = typeof value === "string" ? value.trim().toLowerCase() : ""
    if (direct === "standard" || direct === "deserialization" || direct === "spa" || direct === "browser_nav" || direct === "browser_workflow") return direct
    const nested = typeof value?.mode === "string" ? value.mode.trim().toLowerCase() : ""
    if (nested === "standard" || nested === "deserialization" || nested === "spa" || nested === "browser_nav" || nested === "browser_workflow") return nested
    return fallback
}

function repairModuleRuntime(runtime) {
    const mode = toRuntimeMode(runtime, "standard")
    const runtimeObj = isPlainObject(runtime) ? runtime : {}
    const config = isPlainObject(runtimeObj.config) ? { ...runtimeObj.config } : {}
    if (!Object.keys(config).length && mode === "deserialization") {
        config.deserialization = {}
    } else if (!Object.keys(config).length && mode === "spa") {
        config.spa = {}
    } else if (!Object.keys(config).length && mode === "browser_nav") {
        config.browserNav = {}
    } else if (!Object.keys(config).length && mode === "browser_workflow") {
        config.browserWorkflow = {}
    }
    return {
        mode,
        hooks: Array.isArray(runtimeObj.hooks) ? runtimeObj.hooks.slice() : [],
        confirmation: isPlainObject(runtimeObj.confirmation) ? { ...runtimeObj.confirmation } : {},
        config
    }
}

function repairAttackRuntime(runtime) {
    const runtimeObj = isPlainObject(runtime) ? runtime : {}
    return {
        hooks: Array.isArray(runtimeObj.hooks) ? runtimeObj.hooks.slice() : [],
        confirmation: isPlainObject(runtimeObj.confirmation) ? { ...runtimeObj.confirmation } : {},
        config: isPlainObject(runtimeObj.config) ? { ...runtimeObj.config } : {}
    }
}

function repairMalformedCanonicalRuntime(rulepack) {
    if (!isCanonicalDastRulepack(rulepack) || !Array.isArray(rulepack?.modules)) return null
    let changed = false
    const repaired = JSON.parse(JSON.stringify(rulepack))
    repaired.modules = repaired.modules.map((moduleDef) => {
        if (!isPlainObject(moduleDef)) return moduleDef
        const nextModule = { ...moduleDef }
        if (!isPlainObject(nextModule.runtime)) {
            nextModule.runtime = repairModuleRuntime(nextModule.runtime)
            changed = true
        }
        if (Array.isArray(nextModule.attacks)) {
            nextModule.attacks = nextModule.attacks.map((attackDef) => {
                if (!isPlainObject(attackDef)) return attackDef
                if (isPlainObject(attackDef.runtime)) return attackDef
                changed = true
                return {
                    ...attackDef,
                    runtime: repairAttackRuntime(attackDef.runtime)
                }
            })
        }
        return nextModule
    })
    return changed ? repaired : null
}

function hasLegacyModuleMetadataShape(moduleDef = {}) {
    const meta = isPlainObject(moduleDef?.metadata) ? moduleDef.metadata : {}
    return (
        typeof meta.description === "string"
        || typeof meta.recommendation === "string"
        || meta.severity != null
        || meta.category != null
        || meta.vulnId != null
        || meta.unique != null
        || meta.techniques != null
        || meta.prefilters != null
        || meta.execution?.prefilters != null
    )
}

function hasLegacyAttackShape(attackDef = {}) {
    const meta = isPlainObject(attackDef?.metadata) ? attackDef.metadata : {}
    return (
        typeof attackDef?.description === "string"
        || attackDef?.vulnId != null
        || attackDef?.atomic != null
        || attackDef?.proof != null
        || meta?.deserProfile != null
    )
}

function looksLikeCanonicalLabelledLegacyRulepack(rulepack) {
    if (!isCanonicalDastRulepack(rulepack)) return false
    const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
    return modules.some((moduleDef) => {
        if (!isPlainObject(moduleDef)) return false
        if (hasLegacyModuleMetadataShape(moduleDef)) return true
        const attacks = Array.isArray(moduleDef.attacks) ? moduleDef.attacks : []
        return attacks.some((attackDef) => hasLegacyAttackShape(attackDef))
    })
}

function coerceCanonicalLabelToLegacy(rulepack) {
    const legacyCandidate = JSON.parse(JSON.stringify(rulepack || {}))
    legacyCandidate.schema = "ptk-modules-v1"
    return legacyCandidate
}

export function loadCanonicalDastRulepack(rulepack, opts = {}) {
    if (isCanonicalDastRulepack(rulepack)) {
        try {
            assertValidDastRulepack(rulepack, opts)
            return rulepack
        } catch (err) {
            const repairedCanonical = repairMalformedCanonicalRuntime(rulepack)
            if (repairedCanonical) {
                try {
                    assertValidDastRulepack(repairedCanonical, opts)
                    return repairedCanonical
                } catch (_) {
                    // fall through to legacy compatibility if applicable
                }
            }
            if (!looksLikeCanonicalLabelledLegacyRulepack(rulepack)) {
                throw err
            }
            const canonical = normalizeLegacyDastRulepack(coerceCanonicalLabelToLegacy(rulepack))
            assertValidDastRulepack(canonical, opts)
            return canonical
        }
    }

    const canonical = normalizeLegacyDastRulepack(rulepack)
    assertValidDastRulepack(canonical, opts)
    return canonical
}

export default loadCanonicalDastRulepack
