import normalizeFinding from "../common/findingNormalizer.js"

export const DEFAULT_SCA_TAGS = ["sca", "dependency"]
export const DEFAULT_SCA_OWASP = [
    "A03:2025 - Software Supply Chain Failures",
    "A06:2021 - Vulnerable and Outdated Components"
]

const MODULE_METADATA = {
    id: "sca",
    name: "Software Composition Analysis",
    metadata: {
        category: "supply_chain",
        vulnId: "vulnerable_component",
        owasp: DEFAULT_SCA_OWASP,
        tags: DEFAULT_SCA_TAGS
    }
}

export function normalizeLegacyComponents(source) {
    if (!source) return []
    let entries = []
    if (Array.isArray(source)) {
        entries = source
    } else if (typeof source === "object") {
        entries = Object.values(source)
    } else {
        return []
    }
    return entries
        .map(entry => normalizeComponentEntry(entry))
        .filter(Boolean)
}

export function normalizeComponentEntry(entry) {
    if (!entry || typeof entry !== "object") return null
    const component = entry.component || entry.library || entry.name || entry.module || null
    const version = entry.version || entry.libraryVersion || entry.libVersion || null
    const base = {
        component,
        version,
        npmname: entry.npmname || entry.npm || null,
        basePurl: entry.basePurl || entry.purl || null,
        detection: entry.detection || null,
        file: entry.file || entry.url || entry.path || null,
        source: entry.source || null,
        findings: normalizeLegacyVulnerabilities(entry.findings || entry.vulnerabilities || entry.vulns || [])
    }
    return base
}

export function buildFindingsFromComponents(components = [], { scanId = null, createdAt = null } = {}) {
    const timestamp = createdAt || new Date().toISOString()
    const result = []
    components.forEach(component => {
        const vulns = Array.isArray(component?.findings) ? component.findings : []
        vulns.forEach((vuln, index) => {
            const finding = buildScaFinding(component, vuln, index, { scanId, createdAt: timestamp })
            if (finding) {
                result.push(finding)
            }
        })
    })
    return mergeScaFindingLists(result)
}

export function buildFindingsFromLegacyScan(raw = {}, { scanId = null, createdAt = null } = {}) {
    const components = normalizeLegacyComponents(
        raw.findings || raw.items || raw.components || raw.dependencies || []
    )
    return buildFindingsFromComponents(components, { scanId, createdAt })
}

export function normalizeExistingScaFindings(list = [], { scanId = null } = {}) {
    if (!Array.isArray(list)) return []
    return mergeScaFindingLists(list
        .map((entry, index) => normalizeFinding({
            engine: "SCA",
            scanId,
            finding: {
                ...entry,
                id: entry.id || buildFindingId({
                    scanId,
                    ruleId: entry.ruleId || `rule-${index}`,
                    componentKey: `existing-${index}`
                })
            },
            moduleMeta: MODULE_METADATA
        }))
        .filter(Boolean))
}

export function isFlatScaFindingList(list = []) {
    if (!Array.isArray(list)) return false
    if (!list.length) return false
    return list.every(finding => finding && typeof finding === "object" && finding.engine === "SCA" && finding.evidence && finding.evidence.sca)
}

function normalizeLegacyVulnerabilities(list) {
    if (!Array.isArray(list)) return []
    return list
        .map(vuln => {
            if (!vuln || typeof vuln !== "object") return null
            const clone = { ...vuln }
            clone.severity = mapSeverity(clone.severity)
            clone.info = normalizeList(clone.info)
            clone.identifiers = normalizeIdentifiers(clone.identifiers)
            clone.cwe = normalizeList(clone.cwe)
            clone.versionRange = {
                atOrAbove: clone.atOrAbove || null,
                above: clone.above || null,
                atOrBelow: clone.atOrBelow || null,
                below: clone.below || null
            }
            return clone
        })
        .filter(Boolean)
}

function buildScaFinding(component, vuln, index, { scanId, createdAt }) {
    const componentName = ensureString(component.component) || "Dependency"
    const componentVersion = ensureString(component.version) || "unknown"
    const sourceFile = component.file || null
    const identifiers = normalizeIdentifiers(vuln.identifiers)
    const githubIds = normalizeList(identifiers.githubID)
    const cves = normalizeList(identifiers.CVE)
    const ruleId = githubIds[0] || cves[0] || ensureString(identifiers.retid) || `sca-${componentName}-${componentVersion}`
    const summary = ensureString(identifiers.summary) || ensureString(vuln.summary) || null
    const ruleName = summary || ruleId
    const severity = mapSeverity(vuln.severity)
    const description = summary
        ? `${summary}`
        : `Vulnerable dependency detected: ${componentName}@${componentVersion}`
    const recommendation = buildRecommendation(componentName, componentVersion, ruleId)
    const referenceLinks = buildLinkMap(vuln.info)
    const componentKey = buildComponentKey(componentName, componentVersion, {
        npmname: component.npmname || null,
        basePurl: component.basePurl || null
    })
    const id = buildFindingId({ scanId, ruleId, componentKey, index })
    const evidencePayload = buildEvidencePayload(component, vuln, { sourceFile, summary })
    const tags = buildTags(component.detection)
    const baseFinding = {
        id,
        engine: "SCA",
        scanId: scanId || null,
        moduleId: "sca",
        moduleName: "Software Composition Analysis",
        ruleId,
        ruleName,
        severity,
        category: "supply_chain",
        vulnId: "vulnerable_component",
        cwe: normalizeList(vuln.cwe),
        owasp: DEFAULT_SCA_OWASP,
        tags,
        links: referenceLinks,
        location: {
            kind: "package",
            file: sourceFile || null
        },
        description,
        recommendation,
        createdAt: createdAt || new Date().toISOString(),
        evidence: {
            sca: evidencePayload
        }
    }
    return normalizeFinding({
        engine: "SCA",
        scanId,
        finding: baseFinding,
        moduleMeta: MODULE_METADATA
    })
}

function buildEvidencePayload(component, vuln, { sourceFile, summary }) {
    const identifiers = normalizeIdentifiers(vuln.identifiers)
    if (summary && (!identifiers.summary || !identifiers.summary.length)) {
        identifiers.summary = summary
    }
    if (!identifiers.cwe && Array.isArray(vuln.cwe) && vuln.cwe.length) {
        identifiers.cwe = vuln.cwe.slice()
    }
    const versionRange = vuln.versionRange || {
        atOrAbove: vuln.atOrAbove || null,
        above: vuln.above || null,
        atOrBelow: vuln.atOrBelow || null,
        below: vuln.below || null
    }
    const name = component.component || null
    const version = component.version || null
    const purl = buildPurl({
        basePurl: component.basePurl || null,
        npmname: component.npmname || null,
        name,
        version
    })
    const ecosystem = inferEcosystem(purl, component.npmname || component.basePurl || null)
    const locations = sourceFile ? [sourceFile] : []
    return {
        component: {
            name,
            version,
            npmname: component.npmname || null,
            purl,
            basePurl: component.basePurl || null,
            detection: component.detection || null,
            source: component.source || null,
            ecosystem,
            locations
        },
        identifiers,
        versionRange,
        info: normalizeList(vuln.info),
        summary: summary || null,
        sourceFile: sourceFile || null
    }
}

function normalizeIdentifiers(raw = {}) {
    if (!raw || typeof raw !== "object") return {}
    const result = {}
    Object.entries(raw).forEach(([key, value]) => {
        if (value === undefined || value === null) return
        if (Array.isArray(value)) {
            const normalized = value.map(v => ensureString(v)).filter(Boolean)
            if (normalized.length) {
                result[key] = normalized
            }
        } else if (typeof value === "object") {
            if (key === "summary") {
                const summaryValue = ensureString(value)
                if (summaryValue) result[key] = summaryValue
            } else {
                const nested = normalizeIdentifiers(value)
                if (Object.keys(nested).length) {
                    result[key] = nested
                }
            }
        } else {
            const str = ensureString(value)
            if (str) {
                result[key] = str
            }
        }
    })
    return result
}

function normalizeList(value) {
    if (value === undefined || value === null) return []
    if (Array.isArray(value)) {
        return value.map(v => ensureString(v) || v).filter(item => item !== null && item !== undefined && item !== "")
    }
    const str = ensureString(value)
    return str ? [str] : []
}

function ensureString(value) {
    if (value === undefined || value === null) return null
    const str = String(value).trim()
    return str.length ? str : null
}

function mapSeverity(value) {
    const normalized = String(value || "").toLowerCase()
    if (normalized === "critical") return "critical"
    if (normalized === "high") return "high"
    if (normalized === "medium") return "medium"
    if (normalized === "low") return "low"
    if (normalized === "info") return "info"
    return "medium"
}

function buildRecommendation(componentName, componentVersion, ruleId) {
    const safeComponent = componentName || "the affected dependency"
    const safeVersion = componentVersion || "a vulnerable version"
    return `Upgrade ${safeComponent} (currently ${safeVersion}) to a secure release that is not affected by ${ruleId || "this advisory"}.`
}

function buildComponentKey(name, version, component = {}) {
    const basePurl = ensureString(component?.basePurl)
    if (basePurl) {
        return `${basePurl}${version && !basePurl.includes("@") ? `@${version}` : ""}`.toLowerCase()
    }
    const npmname = ensureString(component?.npmname)
    const normName = (npmname || name || "component").toLowerCase()
    const normVersion = String(version || "unknown").toLowerCase()
    return `${normName}@${normVersion}`
}

function buildFindingId({ scanId, ruleId, componentKey, index }) {
    const key = componentKey || `component::${index}`
    const rule = ruleId || `rule-${index}`
    return `${scanId || "scan"}::SCA::sca::${rule}::${key}`
}

function buildTags(detection) {
    const list = DEFAULT_SCA_TAGS.slice()
    const normalized = ensureString(detection)
    if (normalized && !list.includes(normalized)) {
        list.push(normalized)
    }
    return list
}

function buildLinkMap(list) {
    const references = normalizeList(list)
    if (!references.length) return {}
    return references.reduce((acc, url, index) => {
        acc[`ref_${index + 1}`] = url
        return acc
    }, {})
}

function buildPurl({ basePurl, npmname, name, version }) {
    const base = ensureString(basePurl)
    if (base) {
        if (!version || base.includes("@")) return base
        return `${base}@${version}`
    }
    const pkgName = ensureString(npmname) || ensureString(name)
    if (!pkgName) return null
    const encoded = pkgName.startsWith("@")
        ? `%40${pkgName.slice(1)}`
        : pkgName
    const safe = encoded.replace(/\\/g, "/")
    return version ? `pkg:npm/${safe}@${version}` : `pkg:npm/${safe}`
}

function inferEcosystem(purl, fallback) {
    const value = ensureString(purl || fallback)
    if (!value) return null
    const lowered = value.toLowerCase()
    if (lowered.startsWith("pkg:npm/")) return "npm"
    if (lowered.includes("npm")) return "npm"
    return null
}

function mergeUniqueStrings(...sources) {
    const result = []
    const seen = new Set()
    const add = (value) => {
        if (value === undefined || value === null) return
        if (Array.isArray(value)) {
            value.forEach(add)
            return
        }
        const str = ensureString(value)
        if (!str || seen.has(str)) return
        seen.add(str)
        result.push(str)
    }
    sources.forEach(add)
    return result
}

function mergeScaFindingRecord(existing, incoming) {
    if (!existing) return incoming
    if (!incoming) return existing

    const existingEvidence = existing?.evidence?.sca || {}
    const incomingEvidence = incoming?.evidence?.sca || {}
    const existingComponent = existingEvidence.component || {}
    const incomingComponent = incomingEvidence.component || {}
    const mergedLocations = mergeUniqueStrings(
        existingComponent.locations,
        incomingComponent.locations,
        existingEvidence.sourceFile,
        incomingEvidence.sourceFile,
        existing?.location?.file,
        incoming?.location?.file
    )
    const primaryFile = mergedLocations[0] || incoming?.location?.file || existing?.location?.file || null

    return {
        ...existing,
        ...incoming,
        createdAt: existing.createdAt || incoming.createdAt,
        updatedAt: incoming.updatedAt || incoming.createdAt || existing.updatedAt,
        tags: mergeUniqueStrings(existing.tags, incoming.tags),
        cwe: mergeUniqueStrings(existing.cwe, incoming.cwe),
        owasp: mergeUniqueStrings(existing.owasp, incoming.owasp),
        location: {
            ...(existing.location || {}),
            ...(incoming.location || {}),
            file: primaryFile
        },
        links: {
            ...(existing.links || {}),
            ...(incoming.links || {})
        },
        evidence: {
            ...(existing.evidence || {}),
            ...(incoming.evidence || {}),
            sca: {
                ...existingEvidence,
                ...incomingEvidence,
                sourceFile: primaryFile,
                info: mergeUniqueStrings(existingEvidence.info, incomingEvidence.info),
                component: {
                    ...existingComponent,
                    ...incomingComponent,
                    locations: mergedLocations
                }
            }
        }
    }
}

export function mergeScaFindingLists(...lists) {
    const merged = new Map()
    for (const list of lists) {
        if (!Array.isArray(list)) continue
        for (const finding of list) {
            if (!finding || typeof finding !== "object") continue
            const key = finding.id || finding.fingerprint || null
            if (!key) continue
            merged.set(key, mergeScaFindingRecord(merged.get(key), finding))
        }
    }
    return Array.from(merged.values())
}
