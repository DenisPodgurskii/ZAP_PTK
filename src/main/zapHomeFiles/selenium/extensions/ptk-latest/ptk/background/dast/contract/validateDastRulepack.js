import {
    formatValidationFailure,
    isNonEmptyString,
    isPlainObject,
    pushRequiredError,
    pushTypeError
} from "../../common/simpleRulepackValidation.js"

function contextFor(moduleId = null, attackId = null) {
    return {
        moduleId: moduleId || null,
        attackId: attackId || null
    }
}

function validateModuleRuntime(runtime, path, errors, ctx) {
    if (!isPlainObject(runtime)) {
        pushTypeError(errors, path, "object", ctx)
        return
    }
    if (!isNonEmptyString(runtime.mode)) {
        pushRequiredError(errors, path, "mode", ctx)
    }
    if (!Array.isArray(runtime.hooks)) {
        pushRequiredError(errors, path, "hooks", ctx)
    }
    if (!isPlainObject(runtime.confirmation)) {
        pushRequiredError(errors, path, "confirmation", ctx)
    }
    if (!isPlainObject(runtime.config)) {
        pushRequiredError(errors, path, "config", ctx)
    }
}

function validateAttackRuntime(runtime, path, errors, ctx) {
    if (!isPlainObject(runtime)) {
        pushTypeError(errors, path, "object", ctx)
        return
    }
    if (!Array.isArray(runtime.hooks)) {
        pushRequiredError(errors, path, "hooks", ctx)
    }
    if (!isPlainObject(runtime.confirmation)) {
        pushRequiredError(errors, path, "confirmation", ctx)
    }
    if (!isPlainObject(runtime.config)) {
        pushRequiredError(errors, path, "config", ctx)
    }
}

function validateMetadata(metadata, path, errors, ctx, { requireExecution = false } = {}) {
    if (!isPlainObject(metadata)) {
        pushTypeError(errors, path, "object", ctx)
        return
    }
    if (!isPlainObject(metadata.taxonomy)) {
        pushRequiredError(errors, path, "taxonomy", ctx)
    }
    if (!isPlainObject(metadata.docs)) {
        pushRequiredError(errors, path, "docs", ctx)
    }
    if (requireExecution && !isPlainObject(metadata.execution)) {
        pushRequiredError(errors, path, "execution", ctx)
    }
    if (!isPlainObject(metadata.constants)) {
        pushRequiredError(errors, path, "constants", ctx)
    }
    if (!isPlainObject(metadata.extensions)) {
        pushRequiredError(errors, path, "extensions", ctx)
    }
}

function validateAttack(attackDef, moduleId, index, errors) {
    const path = `/modules/${index}/attacks`
    const ctx = contextFor(moduleId, attackDef?.id || null)
    if (!isPlainObject(attackDef)) {
        pushTypeError(errors, `${path}/${index}`, "object", ctx)
        return
    }
    if (!isNonEmptyString(attackDef.id)) pushRequiredError(errors, `${path}/${index}`, "id", ctx)
    if (!isNonEmptyString(attackDef.name)) pushRequiredError(errors, `${path}/${index}`, "name", ctx)
    if (!isPlainObject(attackDef.action)) pushRequiredError(errors, `${path}/${index}`, "action", ctx)
    if (!isPlainObject(attackDef.validation)) pushRequiredError(errors, `${path}/${index}`, "validation", ctx)
    if (!isPlainObject(attackDef.condition)) pushRequiredError(errors, `${path}/${index}`, "condition", ctx)
    if (!isPlainObject(attackDef.target)) pushRequiredError(errors, `${path}/${index}`, "target", ctx)
    if (!isNonEmptyString(attackDef.requestGrouping)) pushRequiredError(errors, `${path}/${index}`, "requestGrouping", ctx)
    validateAttackRuntime(attackDef.runtime, `${path}/${index}/runtime`, errors, ctx)
    validateMetadata(attackDef.metadata, `${path}/${index}/metadata`, errors, ctx)
}

function validateModule(moduleDef, index, errors) {
    const path = `/modules/${index}`
    const ctx = contextFor(moduleDef?.id || null, null)
    if (!isPlainObject(moduleDef)) {
        pushTypeError(errors, path, "object", ctx)
        return
    }
    if (!isNonEmptyString(moduleDef.id)) pushRequiredError(errors, path, "id", ctx)
    if (!isNonEmptyString(moduleDef.name)) pushRequiredError(errors, path, "name", ctx)
    if (!isNonEmptyString(moduleDef.type)) pushRequiredError(errors, path, "type", ctx)
    if (typeof moduleDef.async !== "boolean") pushRequiredError(errors, path, "async", ctx)
    validateModuleRuntime(moduleDef.runtime, `${path}/runtime`, errors, ctx)
    validateMetadata(moduleDef.metadata, `${path}/metadata`, errors, ctx, { requireExecution: true })
    if (!Array.isArray(moduleDef.attacks)) {
        pushRequiredError(errors, path, "attacks", ctx)
        return
    }
    moduleDef.attacks.forEach((attackDef, attackIndex) => validateAttack(attackDef, moduleDef.id, attackIndex, errors))
}

export function validateDastRulepack(rulepack) {
    const errors = []
    if (!isPlainObject(rulepack)) {
        pushTypeError(errors, "/", "object")
        return { valid: false, errors }
    }
    if (rulepack.schema !== "ptk-dast-rulepack/v1") pushRequiredError(errors, "/", "schema")
    if (rulepack.engine !== "DAST") pushRequiredError(errors, "/", "engine")
    if (rulepack.version !== 1) pushRequiredError(errors, "/", "version")
    if (!Array.isArray(rulepack.modules)) {
        pushRequiredError(errors, "/", "modules")
    } else {
        rulepack.modules.forEach((moduleDef, index) => validateModule(moduleDef, index, errors))
    }
    return {
        valid: errors.length === 0,
        errors
    }
}

export function assertValidDastRulepack(rulepack, opts = {}) {
    const result = validateDastRulepack(rulepack)
    if (result.valid) return rulepack
    throw new Error(formatValidationFailure(result, {
        label: opts.label,
        prefix: "[PTK DAST] Invalid canonical rulepack",
        scopeKeys: ["moduleId", "attackId"]
    }))
}

export default validateDastRulepack
