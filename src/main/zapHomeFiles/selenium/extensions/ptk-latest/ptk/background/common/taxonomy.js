const CATEGORIES = [
    "injection",
    "xss",
    "access_control",
    "auth_session",
    "crypto",
    "security_misconfiguration",
    "sensitive_data",
    "ssrf",
    "path_traversal",
    "deserialization",
    "xxe",
    "insecure_design",
    "supply_chain",
    "logging_monitoring",
    "client_side",
    "hardening",
    "other"
]

const VULN_IDS = [
    "reflected_xss",
    "stored_xss",
    "dom_xss",
    "sql_injection",
    "nosql_injection",
    "command_injection",
    "code_injection",
    "ssrf",
    "open_redirect",
    "path_traversal",
    "file_upload",
    "xxe",
    "deserialization",
    "broken_access_control",
    "auth_failures",
    "csrf",
    "clickjacking",
    "security_headers",
    "insecure_cors",
    "sensitive_storage",
    "token_leak",
    "data_exfiltration",
    "info_disclosure",
    "vulnerable_component",
    "integrity_failure",
    "logging_failure",
    "exception_handling",
    "other"
]

const CATEGORY_BY_VULN_ID = {
    reflected_xss: "xss",
    stored_xss: "xss",
    dom_xss: "xss",
    sql_injection: "injection",
    nosql_injection: "injection",
    command_injection: "injection",
    code_injection: "injection",
    ssrf: "ssrf",
    open_redirect: "client_side",
    path_traversal: "path_traversal",
    file_upload: "security_misconfiguration",
    xxe: "xxe",
    deserialization: "deserialization",
    broken_access_control: "access_control",
    auth_failures: "auth_session",
    csrf: "client_side",
    clickjacking: "client_side",
    security_headers: "hardening",
    insecure_cors: "security_misconfiguration",
    sensitive_storage: "sensitive_data",
    token_leak: "sensitive_data",
    data_exfiltration: "sensitive_data",
    info_disclosure: "sensitive_data",
    vulnerable_component: "supply_chain",
    integrity_failure: "supply_chain",
    logging_failure: "logging_monitoring",
    exception_handling: "other",
    other: "other"
}

function normalizeKey(str) {
    if (str === undefined || str === null) return ""
    return String(str)
        .trim()
        .toLowerCase()
        .replace(/[\s\-]+/g, "_")
        .replace(/[^a-z0-9_]/g, "")
        .replace(/_+/g, "_")
}

function validateCategory(category) {
    const normalized = normalizeKey(category)
    return CATEGORIES.includes(normalized)
}

function validateVulnId(vulnId) {
    const normalized = normalizeKey(vulnId)
    return VULN_IDS.includes(normalized)
}

function resolveCategory({ category, vulnId } = {}) {
    const normalizedVulnId = normalizeKey(vulnId)
    const normalizedCategory = normalizeKey(category)
    if (!normalizedCategory && normalizedVulnId && CATEGORY_BY_VULN_ID[normalizedVulnId]) {
        return CATEGORY_BY_VULN_ID[normalizedVulnId]
    }
    if (validateCategory(normalizedCategory)) {
        return normalizedCategory
    }
    return "other"
}

export {
    CATEGORIES,
    VULN_IDS,
    CATEGORY_BY_VULN_ID,
    normalizeKey,
    validateCategory,
    validateVulnId,
    resolveCategory
}
