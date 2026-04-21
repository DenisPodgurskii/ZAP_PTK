export const OWASP_TOP10 = {
    "2025": {
        A01: "Broken Access Control",
        A02: "Security Misconfiguration",
        A03: "Software Supply Chain Failures",
        A04: "Cryptographic Failures",
        A05: "Injection",
        A06: "Insecure Design",
        A07: "Authentication Failures",
        A08: "Software or Data Integrity Failures",
        A09: "Security Logging & Alerting Failures",
        A10: "Mishandling of Exceptional Conditions"
    },
    "2021": {
        A01: "Broken Access Control",
        A02: "Cryptographic Failures",
        A03: "Injection",
        A04: "Insecure Design",
        A05: "Security Misconfiguration",
        A06: "Vulnerable and Outdated Components",
        A07: "Identification and Authentication Failures",
        A08: "Software and Data Integrity Failures",
        A09: "Security Logging and Monitoring Failures",
        A10: "Server-Side Request Forgery"
    },
    "2017": {
        A01: "Injection",
        A02: "Broken Authentication",
        A03: "Sensitive Data Exposure",
        A04: "XML External Entities (XXE)",
        A05: "Broken Access Control",
        A06: "Security Misconfiguration",
        A07: "Cross-Site Scripting (XSS)",
        A08: "Insecure Deserialization",
        A09: "Using Components with Known Vulnerabilities",
        A10: "Insufficient Logging & Monitoring"
    }
}

const OWASP_VERSION_ALIASES = {
    "25": "2025",
    "2025": "2025",
    "21": "2021",
    "2021": "2021",
    "17": "2017",
    "2017": "2017"
}

const OWASP_ID_PATTERN = /^A\s*(\d{1,2})$/i
const OWASP_STRING_VERSION = /(20(17|21|25))/
const OWASP_ID_EXTRACTOR = /A\s*\d{1,2}/i

function canonicalizeOwaspId(value) {
    if (!value && value !== 0) return null
    const str = String(value).trim()
    if (!str) return null
    const directMatch = str.match(OWASP_ID_PATTERN)
    if (directMatch && directMatch[1]) {
        return `A${directMatch[1].padStart(2, "0")}`
    }
    const digits = str.replace(/[^0-9]/g, "")
    if (!digits) return null
    return `A${digits.padStart(2, "0")}`
}

function canonicalizeOwaspVersion(value) {
    if (!value && value !== 0) return null
    const str = String(value).trim()
    if (!str) return null
    if (OWASP_VERSION_ALIASES[str]) {
        return OWASP_VERSION_ALIASES[str]
    }
    const digits = str.match(OWASP_STRING_VERSION)
    if (digits && digits[1]) {
        const canonical = OWASP_VERSION_ALIASES[digits[1]]
        if (canonical) return canonical
        return digits[1]
    }
    const numeric = str.replace(/[^0-9]/g, "")
    if (OWASP_VERSION_ALIASES[numeric]) {
        return OWASP_VERSION_ALIASES[numeric]
    }
    return null
}

function lookupOwaspName(version, id) {
    if (!version || !id) return null
    const versionMap = OWASP_TOP10[version]
    if (!versionMap) return null
    return versionMap[id] || null
}

function buildOwaspEntry({ version, id, name, fallback }) {
    const entry = {
        version: version || "unknown",
        id: id || "unknown",
        name: name && String(name).trim()
            ? String(name).trim()
            : lookupOwaspName(version, id) || fallback || "Unknown"
    }
    if (!entry.name) {
        entry.name = fallback || "Unknown"
    }
    return entry
}

function parseOwaspString(raw) {
    const str = String(raw || "").trim()
    if (!str) return null
    const idMatch = str.match(OWASP_ID_EXTRACTOR)
    const versionMatch = str.match(OWASP_STRING_VERSION)
    const id = canonicalizeOwaspId(idMatch ? idMatch[0] : null)
    const version = canonicalizeOwaspVersion(versionMatch ? versionMatch[1] : null)
    let name = null
    const dashIndex = str.indexOf("-")
    if (dashIndex >= 0 && dashIndex < str.length - 1) {
        name = str.slice(dashIndex + 1).trim()
    }
    if (!name) {
        const altDash = str.indexOf("–")
        if (altDash >= 0 && altDash < str.length - 1) {
            name = str.slice(altDash + 1).trim()
        }
    }
    if (!name && versionMatch) {
        const afterVersion = str.slice(str.indexOf(versionMatch[1]) + versionMatch[1].length)
        const trimmed = afterVersion.replace(/^[:\s-]+/, "").trim()
        if (trimmed) {
            name = trimmed
        }
    }
    if (!id && !version) {
        return {
            version: "unknown",
            id: "unknown",
            name: str
        }
    }
    return buildOwaspEntry({
        version,
        id,
        name,
        fallback: str
    })
}

function normalizeOwaspObject(obj = {}) {
    const id = canonicalizeOwaspId(obj.id || obj.category || obj.key)
    const version = canonicalizeOwaspVersion(obj.version || obj.year || obj.top10 || obj.owasp_version)
    const name = obj.name || obj.title || obj.description || null
    if (!id && !version && !name) {
        return null
    }
    return buildOwaspEntry({
        version,
        id,
        name,
        fallback: name || null
    })
}

export function normalizeOwasp(value) {
    if (!value && value !== 0) return []
    const rawEntries = Array.isArray(value) ? value : [value]
    const dedup = new Set()
    const result = []
    rawEntries.forEach((entry) => {
        if (entry === null || entry === undefined) return
        let normalized = null
        if (typeof entry === "string" || typeof entry === "number") {
            normalized = parseOwaspString(entry)
        } else if (typeof entry === "object") {
            normalized = normalizeOwaspObject(entry)
        }
        if (!normalized) return
        const key = `${normalized.version || "unknown"}::${normalized.id || "unknown"}`
        if (dedup.has(key)) return
        dedup.add(key)
        result.push(normalized)
    })
    return result
}

export function normalizeCwe(value) {
    if (!value && value !== 0) return []
    const rawEntries = Array.isArray(value) ? value : [value]
    const dedup = new Set()
    const result = []
    rawEntries.forEach((entry) => {
        if (entry === null || entry === undefined) return
        let str = String(entry).trim()
        if (!str) return
        if (/^\d+$/.test(str)) {
            str = `CWE-${str}`
        } else if (/^cwe[-\s]?/i.test(str)) {
            const digits = str.replace(/^cwe[-\s]?/i, "")
            str = digits ? `CWE-${digits}` : "CWE-unknown"
        }
        const normalized = str.toUpperCase()
        if (dedup.has(normalized)) return
        dedup.add(normalized)
        result.push(normalized)
    })
    return result
}

export function toLegacyOwaspString(owaspArr) {
    if (!Array.isArray(owaspArr) || !owaspArr.length) return ""
    const primary = owaspArr[0]
    if (!primary) return ""
    const version = primary.version && primary.version !== "unknown" ? primary.version : null
    const id = primary.id && primary.id !== "unknown" ? primary.id : null
    const name = primary.name || null
    if (id && version && name) {
        return `${id}:${version}-${name}`
    }
    if (id && version) {
        return `${id}:${version}`
    }
    if (name) return name
    return ""
}
