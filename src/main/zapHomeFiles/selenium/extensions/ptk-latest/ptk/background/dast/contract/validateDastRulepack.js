import {
    formatValidationFailure,
    isNonEmptyString,
    isPlainObject,
    pushRequiredError,
    pushTypeError
} from "../../common/simpleRulepackValidation.js"

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

const SELECTOR_MODES = new Set([
    "filter",
    "score"
])

const FINDING_AGGREGATION_MODES = new Set([
    "scan",
    "route",
    "route-param",
    "route-sink",
    "route-param-sink"
])

function contextFor(moduleId = null, attackId = null) {
    return {
        moduleId: moduleId || null,
        attackId: attackId || null
    }
}

function pushValueError(errors, path, message, ctx = {}) {
    errors.push({
        path,
        message,
        ...ctx
    })
}

function validateStringArrayLike(value, path, errors, ctx, {
    allowScalar = false,
    label = "string array"
} = {}) {
    if (value == null) return
    const values = Array.isArray(value)
        ? value
        : (allowScalar ? [value] : null)
    if (!values) {
        pushTypeError(errors, path, label, ctx)
        return
    }
    values.forEach((entry, index) => {
        if (!isNonEmptyString(entry)) {
            pushTypeError(errors, `${path}/${index}`, "string", ctx)
        }
    })
}

function validateSelectorObject(selector, path, errors, ctx) {
    if (!isPlainObject(selector)) {
        pushTypeError(errors, path, "object", ctx)
        return
    }
    const regexLikeKeys = [
        "nameRegex",
        "nameRegexRef",
        "excludeNameRegex",
        "excludeNameRegexRef",
        "valueRegex",
        "valueRegexRef",
        "pathRegex",
        "pathRegexRef",
        "jsonPathRegex",
        "jsonPathRegexRef"
    ]
    regexLikeKeys.forEach((key) => {
        if (key in selector && !isNonEmptyString(selector[key])) {
            pushTypeError(errors, `${path}/${key}`, "string", ctx)
        }
    })
    ;["name", "flags", "valueFlags", "pathFlags", "jsonPathFlags"].forEach((key) => {
        if (key in selector && !isNonEmptyString(selector[key])) {
            pushTypeError(errors, `${path}/${key}`, "string", ctx)
        }
    })
    if ("selectorMode" in selector) {
        if (!isNonEmptyString(selector.selectorMode)) {
            pushTypeError(errors, `${path}/selectorMode`, "string", ctx)
        } else if (!SELECTOR_MODES.has(String(selector.selectorMode).trim().toLowerCase())) {
            pushValueError(errors, `${path}/selectorMode`, `unsupported selector mode: ${selector.selectorMode}`, ctx)
        }
    }
    if ("weight" in selector && !Number.isFinite(Number(selector.weight))) {
        pushTypeError(errors, `${path}/weight`, "number", ctx)
    }
    if ("scoredFallback" in selector && typeof selector.scoredFallback !== "boolean") {
        pushTypeError(errors, `${path}/scoredFallback`, "boolean", ctx)
    }
    if ("location" in selector) {
        validateStringArrayLike(selector.location, `${path}/location`, errors, ctx, {
            allowScalar: true,
            label: "string or string array"
        })
    }
    if ("valueTypeIn" in selector) {
        validateStringArrayLike(selector.valueTypeIn, `${path}/valueTypeIn`, errors, ctx, {
            allowScalar: true
        })
    }
    if ("semanticTagsAny" in selector) {
        validateStringArrayLike(selector.semanticTagsAny, `${path}/semanticTagsAny`, errors, ctx)
    }
}

function validateSelectorContainers(container, path, errors, ctx) {
    if (!isPlainObject(container)) return
    ;["params", "json", "xml", "headers", "cookies"].forEach((key) => {
        if (!(key in container)) return
        const value = container[key]
        if (!Array.isArray(value)) {
            pushTypeError(errors, `${path}/${key}`, "array", ctx)
            return
        }
        value.forEach((selector, index) => {
            validateSelectorObject(selector, `${path}/${key}/${index}`, errors, ctx)
        })
    })
}

function validateActionValueListContainers(action, path, errors, ctx) {
    const allowedSources = new Set(["attacked.value", "attacked.name"])
    const allowedTransforms = new Set(["trim", "lowercase", "uppercase"])
    if (!isPlainObject(action)) return
    ;["props", "params", "headers", "cookies"].forEach((bucket) => {
        if (!(bucket in action)) return
        const entries = action[bucket]
        if (!Array.isArray(entries)) return
        entries.forEach((entry, index) => {
            if (!isPlainObject(entry)) return
            if ("valueListRef" in entry && !isNonEmptyString(entry.valueListRef)) {
                pushTypeError(errors, `${path}/${bucket}/${index}/valueListRef`, "string", ctx)
            }
            if ("valueListLimit" in entry) {
                const parsed = Number(entry.valueListLimit)
                if (!Number.isFinite(parsed) || parsed < 1) {
                    pushTypeError(errors, `${path}/${bucket}/${index}/valueListLimit`, "positive number", ctx)
                }
            }
            if ("valueFrom" in entry) {
                if (!isPlainObject(entry.valueFrom)) {
                    pushTypeError(errors, `${path}/${bucket}/${index}/valueFrom`, "object", ctx)
                } else {
                    if (!isNonEmptyString(entry.valueFrom.source)) {
                        pushTypeError(errors, `${path}/${bucket}/${index}/valueFrom/source`, "string", ctx)
                    } else if (!allowedSources.has(String(entry.valueFrom.source).trim())) {
                        pushTypeError(errors, `${path}/${bucket}/${index}/valueFrom/source`, "supported valueFrom source", ctx)
                    }
                    if ("transforms" in entry.valueFrom) {
                        if (!Array.isArray(entry.valueFrom.transforms)) {
                            pushTypeError(errors, `${path}/${bucket}/${index}/valueFrom/transforms`, "array", ctx)
                        } else {
                            entry.valueFrom.transforms.forEach((transform, transformIndex) => {
                                if (!isNonEmptyString(transform)) {
                                    pushTypeError(errors, `${path}/${bucket}/${index}/valueFrom/transforms/${transformIndex}`, "string", ctx)
                                } else if (!allowedTransforms.has(String(transform).trim().toLowerCase())) {
                                    pushTypeError(errors, `${path}/${bucket}/${index}/valueFrom/transforms/${transformIndex}`, "supported transform", ctx)
                                }
                            })
                        }
                    }
                }
            }
            if ("valueListRef" in entry && "valueFrom" in entry) {
                pushTypeError(errors, `${path}/${bucket}/${index}`, "choose valueListRef or valueFrom, not both", ctx)
            }
        })
    })
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
        return
    }
    if (!isPlainObject(metadata.constants)) {
        pushRequiredError(errors, path, "constants", ctx)
    }
    if (!isPlainObject(metadata.extensions)) {
        pushRequiredError(errors, path, "extensions", ctx)
    }
    if ("presentation" in metadata) {
        if (!isPlainObject(metadata.presentation)) {
            pushTypeError(errors, `${path}/presentation`, "object", ctx)
        } else if ("aggregate" in metadata.presentation) {
            const aggregate = String(metadata.presentation.aggregate || "").trim().toLowerCase()
            if (!FINDING_AGGREGATION_MODES.has(aggregate)) {
                pushValueError(errors, `${path}/presentation/aggregate`, `unsupported finding aggregation mode: ${metadata.presentation.aggregate}`, ctx)
            }
        }
    }
    if (!requireExecution || !isPlainObject(metadata.execution)) return

    const execution = metadata.execution
    if (!Array.isArray(execution.requiredEngineCapabilities)) {
        pushRequiredError(errors, `${path}/execution`, "requiredEngineCapabilities", ctx)
    } else {
        execution.requiredEngineCapabilities.forEach((value, index) => {
            if (!isNonEmptyString(value)) {
                pushTypeError(errors, `${path}/execution/requiredEngineCapabilities/${index}`, "string", ctx)
                return
            }
            if (!ENGINE_CAPABILITIES.has(value)) {
                pushValueError(
                    errors,
                    `${path}/execution/requiredEngineCapabilities/${index}`,
                    `unsupported engine capability: ${value}`,
                    ctx
                )
            }
        })
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
    validateSelectorContainers(attackDef.action, `${path}/${index}/action`, errors, ctx)
    validateSelectorContainers(attackDef.target, `${path}/${index}/target`, errors, ctx)
    validateActionValueListContainers(attackDef.action, `${path}/${index}/action`, errors, ctx)
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
