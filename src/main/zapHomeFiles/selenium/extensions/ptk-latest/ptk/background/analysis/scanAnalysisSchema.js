const EXPLORER_BUCKETS = Object.freeze([
    "routes",
    "endpoints",
    "graphql",
    "hiddenParams",
    "surfaces",
    "gadgets"
])

const OPTIONAL_EXPLORER_BUCKETS = new Set()
const STRING_ARRAY_FIELDS = new Set([
    "enginesPresent",
    "sources",
    "authHints",
    "protocolHints",
    "environmentHints",
    "frameworks",
    "sourceKinds",
    "hintNames",
    "pageUrls",
    "transports",
    "contentTypes",
    "paramNames",
    "bodyKeys",
    "headerNames",
    "discoveryTags",
    "operationTypes",
    "operationNames",
    "rootFields",
    "variableNames",
    "hintTypes",
    "actions"
])

function isObject(value) {
    return Boolean(value && typeof value === "object" && !Array.isArray(value))
}

function pushError(errors, path, reason) {
    errors.push({ path, reason })
}

function validateStringArray(value, path, errors) {
    if (value === undefined) return
    if (!Array.isArray(value)) {
        pushError(errors, path, "not_array")
        return
    }
    value.forEach((item, index) => {
        if (typeof item !== "string") {
            pushError(errors, `${path}[${index}]`, "not_string")
        }
    })
}

function validateEvidenceRefs(value, path, errors) {
    if (value === undefined) return
    if (!Array.isArray(value)) {
        pushError(errors, path, "not_array")
        return
    }
    value.forEach((item, index) => {
        if (!isObject(item)) {
            pushError(errors, `${path}[${index}]`, "not_object")
            return
        }
        if (item.type !== undefined && typeof item.type !== "string") {
            pushError(errors, `${path}[${index}].type`, "not_string")
        }
        if (item.id !== undefined && item.id !== null && typeof item.id !== "string") {
            pushError(errors, `${path}[${index}].id`, "not_string_or_null")
        }
        if (item.loc !== undefined && !isObject(item.loc)) {
            pushError(errors, `${path}[${index}].loc`, "not_object")
        }
    })
}

function validateExplorerItem(item, path, errors) {
    if (!isObject(item)) {
        pushError(errors, path, "not_object")
        return
    }
    if (item.id !== undefined && item.id !== null && typeof item.id !== "string") {
        pushError(errors, `${path}.id`, "not_string_or_null")
    }
    if (item.routeKey !== undefined && item.routeKey !== null && typeof item.routeKey !== "string") {
        pushError(errors, `${path}.routeKey`, "not_string_or_null")
    }
    if (item.method !== undefined && typeof item.method !== "string") {
        pushError(errors, `${path}.method`, "not_string")
    }
    if (item.path !== undefined && typeof item.path !== "string") {
        pushError(errors, `${path}.path`, "not_string")
    }
    if (item.url !== undefined && item.url !== null && typeof item.url !== "string") {
        pushError(errors, `${path}.url`, "not_string_or_null")
    }
    if (item.adminLike !== undefined && typeof item.adminLike !== "boolean") {
        pushError(errors, `${path}.adminLike`, "not_boolean")
    }
    Object.keys(item).forEach((key) => {
        if (STRING_ARRAY_FIELDS.has(key)) {
            validateStringArray(item[key], `${path}.${key}`, errors)
        }
    })
    validateEvidenceRefs(item.evidenceRefs, `${path}.evidenceRefs`, errors)
}

function validateExplorerBucket(explorer, bucket, errors) {
    const value = explorer[bucket]
    if (value === undefined) {
        if (!OPTIONAL_EXPLORER_BUCKETS.has(bucket)) {
            pushError(errors, `explorer.${bucket}`, "missing")
        }
        return 0
    }
    if (!Array.isArray(value)) {
        pushError(errors, `explorer.${bucket}`, "not_array")
        return 0
    }
    value.forEach((item, index) => validateExplorerItem(item, `explorer.${bucket}[${index}]`, errors))
    return value.length
}

export function validateAnalysisExplorerV1(explorer = null) {
    const errors = []
    const buckets = {}
    if (!isObject(explorer)) {
        return {
            ok: false,
            schema: "ptk-scan-analysis-v1",
            reason: "explorer_not_object",
            buckets,
            errors: [{ path: "explorer", reason: "not_object" }]
        }
    }
    if (!isObject(explorer.summary)) {
        pushError(errors, "explorer.summary", "missing_or_not_object")
    }
    EXPLORER_BUCKETS.forEach((bucket) => {
        buckets[bucket] = validateExplorerBucket(explorer, bucket, errors)
    })
    return {
        ok: errors.length === 0,
        schema: "ptk-scan-analysis-v1",
        reason: errors[0] ? `${errors[0].path}:${errors[0].reason}` : null,
        buckets,
        errorCount: errors.length,
        errors: errors.slice(0, 50)
    }
}

export function validateScanAnalysisV1(analysis = null) {
    const errors = []
    if (!isObject(analysis)) {
        return {
            ok: false,
            schema: "ptk-scan-analysis-v1",
            reason: "analysis_not_object",
            errors: [{ path: "analysis", reason: "not_object" }]
        }
    }
    if (typeof analysis.version !== "string" || !analysis.version.trim()) {
        pushError(errors, "analysis.version", "missing_or_not_string")
    }
    const explorer = validateAnalysisExplorerV1(analysis.explorer)
    errors.push(...(explorer.errors || []).map((error) => ({
        ...error,
        path: error.path.startsWith("analysis.") ? error.path : `analysis.${error.path}`
    })))
    return {
        ok: errors.length === 0,
        schema: "ptk-scan-analysis-v1",
        reason: errors[0] ? `${errors[0].path}:${errors[0].reason}` : null,
        explorer: {
            ok: explorer.ok,
            buckets: explorer.buckets || {}
        },
        errorCount: errors.length,
        errors: errors.slice(0, 50)
    }
}

export default validateScanAnalysisV1
