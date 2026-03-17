export const GAP_CATALOG = Object.freeze({
    DAST_AUTH_REQUIRED: Object.freeze({
        code: "DAST_AUTH_REQUIRED",
        severity: "high",
        engine: "DAST",
        recommendedActionKey: "ACTION_ADD_AUTH_FLOW",
        defaultDetail: "Authentication redirects prevented full DAST coverage."
    }),
    DAST_JWT_DEFERRED_SKIPPED: Object.freeze({
        code: "DAST_JWT_DEFERRED_SKIPPED",
        severity: "med",
        engine: "DAST",
        recommendedActionKey: "ACTION_ENABLE_JWT_CONTEXT",
        defaultDetail: "Some JWT-dependent checks were deferred by strategy."
    }),
    DAST_LOW_CRAWL_COVERAGE: Object.freeze({
        code: "DAST_LOW_CRAWL_COVERAGE",
        severity: "med",
        engine: "DAST",
        recommendedActionKey: "ACTION_BROADEN_CRAWL_SCOPE",
        defaultDetail: "DAST crawl coverage was limited."
    }),
    IAST_NO_RUNTIME_EVENTS: Object.freeze({
        code: "IAST_NO_RUNTIME_EVENTS",
        severity: "high",
        engine: "IAST",
        recommendedActionKey: "ACTION_ENABLE_IAST_INSTRUMENTATION",
        defaultDetail: "IAST runtime instrumentation produced no events."
    }),
    SAST_NO_SOURCEMAPS: Object.freeze({
        code: "SAST_NO_SOURCEMAPS",
        severity: "low",
        engine: "SAST",
        recommendedActionKey: "ACTION_ADD_SOURCEMAPS",
        defaultDetail: "SAST results have weak source mapping context."
    }),
    SCA_NO_LOCKFILE_OR_PACKAGE_GRAPH: Object.freeze({
        code: "SCA_NO_LOCKFILE_OR_PACKAGE_GRAPH",
        severity: "med",
        engine: "SCA",
        recommendedActionKey: "ACTION_PROVIDE_DEP_GRAPH",
        defaultDetail: "SCA did not receive lockfile or package graph data."
    }),
    ANALYSIS_INPUT_TRUNCATED: Object.freeze({
        code: "ANALYSIS_INPUT_TRUNCATED",
        severity: "low",
        engine: "ANALYSIS",
        recommendedActionKey: "ACTION_REDUCE_SCAN_SCOPE",
        defaultDetail: "Analysis input was truncated due to processing caps."
    })
})

export function getGapCatalogEntry(code) {
    if (!code || typeof code !== "string") return null
    return GAP_CATALOG[code] || null
}

export function listGapCatalogEntries() {
    return Object.values(GAP_CATALOG)
}

