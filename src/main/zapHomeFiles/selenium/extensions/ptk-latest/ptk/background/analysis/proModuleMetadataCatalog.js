import PRO_MODULE_METADATA_CATALOGS from "./proModuleMetadataCatalog.generated.js"

function normalizeEngine(engine) {
    const normalized = String(engine || "").trim().toUpperCase()
    return normalized === "DAST" || normalized === "SAST" || normalized === "IAST" ? normalized : null
}

function cloneEntry(entry) {
    return entry && typeof entry === "object" ? {
        engine: entry.engine || null,
        moduleId: entry.moduleId || null,
        name: entry.name || null,
        tier: entry.tier || null,
        category: entry.category || null,
        severity: entry.severity || null,
        vulnId: entry.vulnId || null,
        tags: Array.isArray(entry.tags) ? entry.tags.slice() : [],
        description: entry.description || null,
        recommendationSummary: entry.recommendationSummary || null,
        links: entry.links && typeof entry.links === "object" ? { ...entry.links } : {},
        surfaceHints: Array.isArray(entry.surfaceHints) ? entry.surfaceHints.slice() : [],
        metadataVersion: entry.metadataVersion || null,
        sourceHash: entry.sourceHash || null
    } : null
}

export function getProModuleMetadataCatalog(engine = null) {
    const normalized = normalizeEngine(engine)
    if (!normalized) return null
    const catalog = PRO_MODULE_METADATA_CATALOGS?.[normalized]
    if (!catalog || typeof catalog !== "object") return null
    return {
        schema: catalog.schema || null,
        engine: normalized,
        metadataVersion: catalog.metadataVersion || null,
        moduleCount: Number.isFinite(catalog.moduleCount) ? Number(catalog.moduleCount) : 0,
        modules: Array.isArray(catalog.modules) ? catalog.modules.map(cloneEntry).filter(Boolean) : []
    }
}

export function getAllProModuleMetadataEntries() {
    return ["DAST", "SAST", "IAST"].flatMap((engine) => getProModuleMetadataCatalog(engine)?.modules || [])
}

export default getAllProModuleMetadataEntries
