import {
    formatValidationFailure,
    isNonEmptyString,
    isPlainObject,
    pushRequiredError,
    pushTypeError
} from "../../common/simpleRulepackValidation.js"

function contextFor(moduleId = null, ruleId = null) {
    return {
        moduleId: moduleId || null,
        ruleId: ruleId || null
    }
}

function validateModule(moduleDef, index, errors) {
    const path = `/modules/${index}`
    const ctx = contextFor(moduleDef?.id || null, null)
    if (!isPlainObject(moduleDef)) {
        pushTypeError(errors, path, "object", ctx)
        return
    }
    if (!isNonEmptyString(moduleDef.id)) pushRequiredError(errors, path, "id", ctx)
    if (!isNonEmptyString(moduleDef.type)) pushRequiredError(errors, path, "type", ctx)
    if (typeof moduleDef.async !== "boolean") pushRequiredError(errors, path, "async", ctx)
    if (!isNonEmptyString(moduleDef.name)) pushRequiredError(errors, path, "name", ctx)
    if (!isPlainObject(moduleDef.metadata)) pushRequiredError(errors, path, "metadata", ctx)
    if (!Array.isArray(moduleDef.rules)) {
        pushRequiredError(errors, path, "rules", ctx)
        return
    }
    moduleDef.rules.forEach((ruleDef, ruleIndex) => {
        const rulePath = `${path}/rules/${ruleIndex}`
        const ruleCtx = contextFor(moduleDef.id, ruleDef?.id || null)
        if (!isPlainObject(ruleDef)) {
            pushTypeError(errors, rulePath, "object", ruleCtx)
            return
        }
        if (!isNonEmptyString(ruleDef.id)) pushRequiredError(errors, rulePath, "id", ruleCtx)
        if (!isNonEmptyString(ruleDef.name)) pushRequiredError(errors, rulePath, "name", ruleCtx)
        if (!isNonEmptyString(ruleDef.sinkId)) pushRequiredError(errors, rulePath, "sinkId", ruleCtx)
        if (ruleDef.hook !== undefined && !isPlainObject(ruleDef.hook)) pushTypeError(errors, `${rulePath}/hook`, "object", ruleCtx)
        if (ruleDef.conditions !== undefined && !isPlainObject(ruleDef.conditions)) pushTypeError(errors, `${rulePath}/conditions`, "object", ruleCtx)
        if (ruleDef.limits !== undefined && !isPlainObject(ruleDef.limits)) pushTypeError(errors, `${rulePath}/limits`, "object", ruleCtx)
        if (ruleDef.metadata !== undefined && !isPlainObject(ruleDef.metadata)) pushTypeError(errors, `${rulePath}/metadata`, "object", ruleCtx)
    })
}

export function validateIastRulepack(rulepack) {
    const errors = []
    if (!isPlainObject(rulepack)) {
        pushTypeError(errors, "/", "object")
        return { valid: false, errors }
    }
    if (rulepack.schema !== "ptk-iast-rulepack/v1") pushRequiredError(errors, "/", "schema")
    if (rulepack.engine !== "IAST") pushRequiredError(errors, "/", "engine")
    if (rulepack.version !== 1) pushRequiredError(errors, "/", "version")
    if (rulepack.minExtensionVersion !== undefined && !isNonEmptyString(rulepack.minExtensionVersion)) {
        pushTypeError(errors, "/minExtensionVersion", "non-empty string")
    }
    if (rulepack.requiresSchemaFeatures !== undefined) {
        if (!Array.isArray(rulepack.requiresSchemaFeatures)) {
            pushTypeError(errors, "/requiresSchemaFeatures", "array")
        } else {
            rulepack.requiresSchemaFeatures.forEach((feature, featureIndex) => {
                if (!isNonEmptyString(feature)) {
                    pushTypeError(errors, `/requiresSchemaFeatures/${featureIndex}`, "non-empty string")
                }
            })
        }
    }
    if (rulepack.policy !== undefined && !isPlainObject(rulepack.policy)) pushTypeError(errors, "/policy", "object")
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

export function assertValidIastRulepack(rulepack, opts = {}) {
    const result = validateIastRulepack(rulepack)
    if (result.valid) return rulepack
    throw new Error(formatValidationFailure(result, {
        label: opts.label,
        prefix: "[PTK IAST] Invalid canonical rulepack",
        scopeKeys: ["moduleId", "ruleId"]
    }))
}

export default validateIastRulepack
