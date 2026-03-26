function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function normalizeLoc(loc) {
    if (!loc || typeof loc !== "object") return null
    const out = {}
    const allowed = ["method", "path", "route", "module", "rule", "kind", "host", "param", "severity", "title"]
    allowed.forEach((key) => {
        const value = toNonEmptyString(loc[key])
        if (value) out[key] = value
    })
    return Object.keys(out).length ? out : null
}

function isTimestampLike(value) {
    const raw = toNonEmptyString(value)
    if (!raw) return false
    if (/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(raw)) return true
    if (/\b1\d{12,13}\b/.test(raw)) return true
    if (/^\d{16,}$/.test(raw)) return true
    return false
}

function locToStableString(loc) {
    const normalized = normalizeLoc(loc)
    if (!normalized) return null
    return Object.keys(normalized)
        .sort((a, b) => a.localeCompare(b))
        .map((key) => `${key}=${normalized[key]}`)
        .join("&")
}

function stableEvidenceKey(ref) {
    if (!ref || typeof ref !== "object") return null
    const type = toNonEmptyString(ref.type) || "evidence"
    const id = toNonEmptyString(ref.id)
    const locator = locToStableString(ref.loc)
    if (id && !(String(type).toLowerCase() === "runtimeevent" && isTimestampLike(id))) {
        return `${type}:${id}`
    }
    if (locator) {
        return `${type}:loc:${locator}`
    }
    return null
}

export function normalizeEvidenceRefs(refs = [], { maxRefs = 12 } = {}) {
    if (!Array.isArray(refs) || !refs.length) return []
    const out = []
    const seen = new Set()
    refs.forEach((ref) => {
        if (!ref || typeof ref !== "object") return
        const type = toNonEmptyString(ref.type) || "evidence"
        const id = toNonEmptyString(ref.id)
        const loc = normalizeLoc(ref.loc)
        if (!id && !loc) return
        const normalizedRef = {
            type,
            id: id || null,
            ...(loc ? { loc } : {})
        }
        const stableKey = stableEvidenceKey(normalizedRef)
            || `${type}:${id || ""}:${locToStableString(loc) || ""}`
        if (seen.has(stableKey)) return
        seen.add(stableKey)
        out.push(normalizedRef)
    })
    out.sort((a, b) => {
        const aType = `${a.type || ""}`
        const bType = `${b.type || ""}`
        const typeCmp = aType.localeCompare(bType)
        if (typeCmp !== 0) return typeCmp
        const aId = `${a.id || ""}`
        const bId = `${b.id || ""}`
        const idCmp = aId.localeCompare(bId)
        if (idCmp !== 0) return idCmp
        const aLoc = locToStableString(a.loc) || ""
        const bLoc = locToStableString(b.loc) || ""
        return aLoc.localeCompare(bLoc)
    })
    return out.slice(0, Math.max(1, Number(maxRefs) || 12))
}

export function buildStableEvidenceKeySet(refs = []) {
    if (!Array.isArray(refs) || !refs.length) return ""
    const keys = new Set()
    refs.forEach((ref) => {
        const key = stableEvidenceKey(ref)
        if (key) keys.add(key)
    })
    return Array.from(keys).sort((a, b) => a.localeCompare(b)).join("|")
}
