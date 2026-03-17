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

export function isPlainObject(value) {
    return !!value && typeof value === "object" && !Array.isArray(value)
}

export function isNonEmptyString(value) {
    return typeof value === "string" && value.trim().length > 0
}

export function toPath(path = "") {
    return String(path || "") || "/"
}

export function buildValidationError(path, message, extra = {}) {
    const out = {
        keyword: extra.keyword || "structure",
        path: toPath(path),
        message: message || "schema validation error",
        params: cloneValue(extra.params || {})
    }
    Object.entries(extra).forEach(([key, value]) => {
        if (key === "keyword" || key === "params") return
        out[key] = value
    })
    return out
}

export function pushRequiredError(errors, path, property, extra = {}) {
    errors.push(buildValidationError(path, `must have required property '${property}'`, {
        ...extra,
        keyword: "required",
        params: {
            missingProperty: property
        }
    }))
}

export function pushTypeError(errors, path, expected, extra = {}) {
    errors.push(buildValidationError(path, `must be ${expected}`, {
        ...extra,
        keyword: "type"
    }))
}

export function formatValidationFailure(result, opts = {}) {
    const label = opts.label ? ` for ${opts.label}` : ""
    const details = (Array.isArray(result?.errors) ? result.errors : [])
        .map((error) => {
            const scope = (Array.isArray(opts.scopeKeys) ? opts.scopeKeys : [])
                .map((key) => {
                    const value = error?.[key]
                    return value ? `${key}=${value}` : null
                })
                .filter(Boolean)
                .join(" ")
            return `${error.path}: ${error.message}${scope ? ` (${scope})` : ""}`
        })
        .join("; ")
    return `${opts.prefix || "[PTK] Invalid rulepack"}${label}: ${details}`
}

export default {
    buildValidationError,
    formatValidationFailure,
    isNonEmptyString,
    isPlainObject,
    pushRequiredError,
    pushTypeError,
    toPath
}
