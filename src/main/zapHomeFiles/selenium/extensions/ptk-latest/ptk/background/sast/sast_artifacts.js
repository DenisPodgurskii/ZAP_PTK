function mergeStringList(left = [], right = []) {
  return Array.from(
    new Set(
      [...(left || []), ...(right || [])]
        .map((value) => String(value || "").trim())
        .filter(Boolean)
    )
  ).sort((a, b) => a.localeCompare(b))
}

export function ensureSastCodeArtifacts(target) {
  if (!target || typeof target !== "object") return
  if (!target.codeArtifacts || typeof target.codeArtifacts !== "object") {
    target.codeArtifacts = {}
  }
  if (!target.codeArtifacts.sast || typeof target.codeArtifacts.sast !== "object") {
    target.codeArtifacts.sast = {}
  }
  const sastArtifacts = target.codeArtifacts.sast
  if (!Array.isArray(sastArtifacts.routes)) sastArtifacts.routes = []
  if (!Array.isArray(sastArtifacts.endpoints)) sastArtifacts.endpoints = []
  if (!Array.isArray(sastArtifacts.graphql)) sastArtifacts.graphql = []
  if (!Array.isArray(sastArtifacts.surfaces)) sastArtifacts.surfaces = []
  if (!Array.isArray(sastArtifacts.hiddenParams)) sastArtifacts.hiddenParams = []
  if (!Array.isArray(sastArtifacts.gadgets)) sastArtifacts.gadgets = []
  sastArtifacts.version = Number(sastArtifacts.version || 2) || 2
}

export function countSastArtifacts(sastArtifacts = null) {
  if (!sastArtifacts || typeof sastArtifacts !== "object") return 0
  const keys = ["routes", "endpoints", "graphql", "surfaces", "hiddenParams", "gadgets"]
  return keys.reduce((acc, key) => {
    return acc + (Array.isArray(sastArtifacts[key]) ? sastArtifacts[key].length : 0)
  }, 0)
}

export function mergeSastArtifactList(current = [], incoming = [], annotator = null) {
  const map = new Map()

  const push = (entry) => {
    if (!entry || typeof entry !== "object") return
    const id = entry.id || `${entry.artifactType || "artifact"}::${map.size + 1}`
    const next = Object.assign({}, entry)
    if (typeof annotator === "function") {
      annotator(next)
    }
    if (!map.has(id)) {
      map.set(id, next)
      return
    }
    const existing = map.get(id)
    map.set(id, Object.assign({}, existing, next, {
      authHints: mergeStringList(existing.authHints, next.authHints),
      protocolHints: mergeStringList(existing.protocolHints, next.protocolHints),
      discoveryTags: mergeStringList(existing.discoveryTags, next.discoveryTags),
      environmentHints: mergeStringList(existing.environmentHints, next.environmentHints),
      storageHints: mergeStringList(existing.storageHints, next.storageHints),
      uploadSignals: mergeStringList(existing.uploadSignals, next.uploadSignals),
      paramNames: mergeStringList(existing.paramNames, next.paramNames),
      bodyKeys: mergeStringList(existing.bodyKeys, next.bodyKeys),
      headerNames: mergeStringList(existing.headerNames, next.headerNames),
      operationTypes: mergeStringList(existing.operationTypes, next.operationTypes),
      operationNames: mergeStringList(existing.operationNames, next.operationNames),
      rootFields: mergeStringList(existing.rootFields, next.rootFields),
      variableNames: mergeStringList(existing.variableNames, next.variableNames),
      hintNames: mergeStringList(existing.hintNames, next.hintNames),
      hintTypes: mergeStringList(existing.hintTypes, next.hintTypes),
      actions: mergeStringList(existing.actions, next.actions),
      transports: mergeStringList(existing.transports, next.transports),
      sourceFiles: mergeStringList(existing.sourceFiles, next.sourceFiles),
      occurrenceCount: Math.max(1, Number(existing.occurrenceCount || 0) + Number(next.occurrenceCount || 0))
    }))
  }

  ;(Array.isArray(current) ? current : []).forEach(push)
  ;(Array.isArray(incoming) ? incoming : []).forEach(push)
  return Array.from(map.values())
}

export function mergeSastArtifacts(targetEnvelope, artifacts = null, { pageUrl = "", pageCanon = "" } = {}) {
  if (!artifacts || typeof artifacts !== "object") return
  ensureSastCodeArtifacts(targetEnvelope)
  const next = artifacts?.sast && typeof artifacts.sast === "object" ? artifacts.sast : {}
  const target = targetEnvelope.codeArtifacts.sast
  const annotate = (entry) => {
    if (!entry.pageUrl && pageUrl) entry.pageUrl = pageUrl
    if (!entry.pageCanon && pageCanon) entry.pageCanon = pageCanon
  }
  target.routes = mergeSastArtifactList(target.routes, next.routes, annotate)
  target.endpoints = mergeSastArtifactList(target.endpoints, next.endpoints, annotate)
  target.graphql = mergeSastArtifactList(target.graphql, next.graphql, annotate)
  target.surfaces = mergeSastArtifactList(target.surfaces, next.surfaces, annotate)
  target.hiddenParams = mergeSastArtifactList(target.hiddenParams, next.hiddenParams, annotate)
  target.gadgets = mergeSastArtifactList(target.gadgets, next.gadgets, annotate)
  target.version = Math.max(Number(target.version || 2) || 2, Number(next.version || 2) || 2)
}

export default {
  ensureSastCodeArtifacts,
  countSastArtifacts,
  mergeSastArtifactList,
  mergeSastArtifacts
}
