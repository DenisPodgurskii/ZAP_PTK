import { normalizeKey, resolveCategory as mapCategory } from "./taxonomy.js"

function extractMetaValue(source, field, { allowDirectFallback = false } = {}) {
    if (!source || typeof source !== "object") return null
    if (source.metadata && typeof source.metadata === "object") {
        const nested = source.metadata[field]
        if (nested !== undefined && nested !== null) {
            return nested
        }
    }
    if (allowDirectFallback || !("metadata" in source)) {
        const direct = source[field]
        if (direct !== undefined && direct !== null) {
            return direct
        }
    }
    return null
}

export function resolveFindingTaxonomy({ finding = {}, ruleMeta = {}, moduleMeta = {} } = {}) {
    const normalizedFindingVulnId = normalizeKey(
        extractMetaValue(finding, "vulnId", { allowDirectFallback: true })
    )
    const normalizedRuleVulnId = normalizeKey(extractMetaValue(ruleMeta, "vulnId"))
    const normalizedModuleVulnId = normalizeKey(extractMetaValue(moduleMeta, "vulnId"))

    let vulnId = normalizedFindingVulnId || normalizedRuleVulnId || normalizedModuleVulnId || "other"

    const normalizedFindingCategory = normalizeKey(
        extractMetaValue(finding, "category", { allowDirectFallback: true })
    )
    const normalizedRuleCategory = normalizeKey(extractMetaValue(ruleMeta, "category"))
    const normalizedModuleCategory = normalizeKey(extractMetaValue(moduleMeta, "category"))

    let category = normalizedFindingCategory || normalizedRuleCategory || normalizedModuleCategory || ""
    category = mapCategory({ category, vulnId })

    finding.vulnId = vulnId
    finding.category = category
    return finding
}
