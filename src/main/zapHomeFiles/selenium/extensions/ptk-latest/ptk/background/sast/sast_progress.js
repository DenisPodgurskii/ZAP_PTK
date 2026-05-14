export const SAST_STRUCTURED_EVENT_TYPES = new Set([
  "scan:start",
  "collection:start",
  "collection:payload",
  "collection:analysis:start",
  "collection:summary",
  "collection:error",
  "file:start",
  "file:end",
  "module:start",
  "module:end",
  "scan:summary",
  "scan:error"
])

export function createSastProgressState() {
  return {
    phase: "idle",
    totalFiles: 0,
    completedFiles: 0,
    currentFile: null,
    currentFileIndex: 0,
    totalModules: 0,
    completedModules: 0,
    currentModule: null,
    currentModuleIndex: 0,
    currentGeneration: 0,
    completedGeneration: 0,
    lastCompletedFile: null,
    lastCompletedModule: null,
    analysisState: "idle",
    collectionState: "idle",
    lastStatus: ""
  }
}

export function countSastFindingKinds(target = null) {
  const findings = Array.isArray(target?.findings) ? target.findings : []
  const counts = { finding: 0, hint: 0 }
  findings.forEach((finding) => {
    const kind = String(finding?.findingKind || finding?.evidence?.sast?.findingKind || "finding").toLowerCase()
    if (kind === "hint" || kind === "artifact") counts.hint += 1
    else counts.finding += 1
  })
  return counts
}

export function buildSastProgressSnapshot({
  state = null,
  scanResult = null,
  countArtifacts = () => 0,
  scanStartMs = null,
  isRunning = false
} = {}) {
  const progressState = state || createSastProgressState()
  const findingKinds = countSastFindingKinds(scanResult)
  const totalFiles = Number(progressState.totalFiles || 0)
  const completedFiles = Number(progressState.completedFiles || 0)
  const totalModules = Number(progressState.totalModules || 0)
  const completedModules = Number(progressState.completedModules || 0)
  const currentFile = progressState.currentFile || null
  const currentModule = progressState.currentModule || null
  const filesComplete = totalFiles > 0 && completedFiles >= totalFiles
  const modulesComplete = totalModules > 0 && completedModules >= totalModules
  const stateText = `${progressState.analysisState || ""} ${progressState.collectionState || ""}`
  const stateLooksComplete = /complete|completed|waiting_for_page_activity|idle/i.test(stateText)
    && !/analysis_running|analyzing|payload_received|collecting|collection_pending/i.test(stateText)
  const collectionLooksComplete = (filesComplete || modulesComplete)
    && (!currentFile || stateLooksComplete)
    && (!currentModule || stateLooksComplete)
    && !/error|failed/i.test(`${progressState.analysisState || ""} ${progressState.collectionState || ""}`)
  const phase = collectionLooksComplete ? "waiting" : (progressState.phase || "idle")
  const analysisState = collectionLooksComplete ? "complete" : (progressState.analysisState || "idle")
  const collectionState = collectionLooksComplete
    ? (isRunning ? "waiting_for_page_activity" : "completed")
    : (progressState.collectionState || "idle")
  const lastStatus = collectionLooksComplete
    ? (isRunning ? "Waiting for next page activity" : "SAST analysis complete")
    : (progressState.lastStatus || "")
  return {
    phase,
    totalFiles,
    completedFiles,
    currentFile: collectionLooksComplete ? null : currentFile,
    currentFileIndex: Number(progressState.currentFileIndex || 0),
    totalModules,
    completedModules,
    currentModule: collectionLooksComplete ? null : currentModule,
    currentModuleIndex: Number(progressState.currentModuleIndex || 0),
    currentGeneration: Number(progressState.currentGeneration || 0),
    completedGeneration: Number(progressState.completedGeneration || 0),
    lastCompletedFile: progressState.lastCompletedFile || null,
    lastCompletedModule: progressState.lastCompletedModule || null,
    analysisState,
    collectionState,
    lastStatus,
    findings: findingKinds.finding,
    hints: findingKinds.hint,
    discovery: countArtifacts(scanResult?.codeArtifacts?.sast),
    elapsedMs: scanStartMs ? Math.max(0, Date.now() - scanStartMs) : 0,
    isRunning: !!isRunning,
    isAnalysisRunning: !collectionLooksComplete && /analyzing|running|payload_received|collecting/i.test(`${analysisState} ${collectionState}`)
  }
}

export function isStructuredSastEvent(type) {
  return SAST_STRUCTURED_EVENT_TYPES.has(type)
}

export function applyStructuredSastProgressEvent(state = null, type, data = {}) {
  const next = state || createSastProgressState()
  const generation = Number(data.generation || data.collectionGeneration || 0)
  const completedGeneration = Number(next.completedGeneration || 0)
  const completedState = /complete|completed|waiting_for_page_activity/i.test(`${next.analysisState || ""} ${next.collectionState || ""}`)
  const regressiveAfterCompletion = new Set([
    "collection:analysis:start",
    "file:start",
    "file:end",
    "module:start",
    "module:end"
  ])
  if (
    generation <= 0 &&
    completedGeneration > 0 &&
    completedState &&
    regressiveAfterCompletion.has(type)
  ) {
    return next
  }
  if (
    generation > 0 &&
    completedGeneration > 0 &&
    generation <= completedGeneration &&
    !["collection:summary", "scan:summary"].includes(type)
  ) {
    return next
  }

  if (type === "scan:start") {
    next.phase = "scan_start"
    next.totalFiles = Number(data.totalFiles || 0)
    next.totalModules = Number(data.totalModules || 0)
    next.analysisState = "waiting"
    next.collectionState = "collection_pending"
    next.lastStatus = "Scan started"
    return next
  }

  if (type === "collection:start") {
    next.phase = "collecting"
    next.currentGeneration = generation || Number(next.currentGeneration || 0)
    next.collectionState = "collection_pending"
    next.analysisState = "collecting"
    next.lastStatus = "Collecting page scripts"
    return next
  }

  if (type === "collection:payload") {
    next.phase = "payload_received"
    next.currentGeneration = generation || Number(next.currentGeneration || 0)
    next.collectionState = "payload_received"
    next.analysisState = "payload_received"
    next.lastStatus = "Page scripts collected"
    return next
  }

  if (type === "collection:analysis:start") {
    next.phase = "analysis"
    next.currentGeneration = generation || Number(next.currentGeneration || 0)
    next.totalFiles = Math.max(Number(next.totalFiles || 0), Number(data.totalFiles || 0))
    next.totalModules = Math.max(Number(next.totalModules || 0), Number(data.totalModules || 0))
    next.collectionState = "analysis_running"
    next.analysisState = "analyzing"
    next.lastStatus = "Analyzing collected scripts"
    return next
  }

  if (type === "file:start") {
    next.phase = "file"
    next.currentGeneration = generation || Number(next.currentGeneration || 0)
    next.analysisState = "analyzing"
    next.collectionState = "analysis_running"
    next.currentFile = data.file || null
    next.currentFileIndex = Math.max(1, Number(data.index || 0) + 1)
    next.totalFiles = Math.max(Number(next.totalFiles || 0), Number(data.totalFiles || 0))
    next.completedModules = 0
    next.currentModule = null
    next.currentModuleIndex = 0
    next.lastStatus = "Analyzing file"
    return next
  }

  if (type === "file:end") {
    next.phase = "file_complete"
    next.currentGeneration = generation || Number(next.currentGeneration || 0)
    next.currentFile = data.file || next.currentFile || null
    next.currentFileIndex = Math.max(next.currentFileIndex || 0, Number(data.index || 0) + 1)
    next.totalFiles = Math.max(Number(next.totalFiles || 0), Number(data.totalFiles || 0))
    next.completedFiles = Math.max(Number(next.completedFiles || 0), Number(data.index || 0) + 1)
    next.completedModules = next.totalModules || next.completedModules
    next.lastCompletedFile = next.currentFile
    next.lastStatus = "Finished file"
    return next
  }

  if (type === "module:start") {
    next.phase = "module"
    next.currentGeneration = generation || Number(next.currentGeneration || 0)
    next.analysisState = "analyzing"
    next.collectionState = "analysis_running"
    next.currentFile = data.file || next.currentFile || null
    next.currentModule = data.moduleName || data.moduleId || null
    next.currentModuleIndex = Number(data.moduleIndex || next.currentModuleIndex || 0)
    next.totalModules = Math.max(Number(next.totalModules || 0), Number(data.totalModules || 0))
    next.lastStatus = "Running module"
    return next
  }

  if (type === "module:end") {
    next.phase = "module_complete"
    next.currentGeneration = generation || Number(next.currentGeneration || 0)
    next.currentFile = data.file || next.currentFile || null
    next.currentModule = data.moduleName || data.moduleId || next.currentModule || null
    next.currentModuleIndex = Number(data.moduleIndex || next.currentModuleIndex || 0)
    next.totalModules = Math.max(Number(next.totalModules || 0), Number(data.totalModules || 0))
    next.completedModules = Math.max(Number(next.completedModules || 0), Number(data.moduleIndex || 0))
    next.lastCompletedModule = next.currentModule
    next.lastStatus = "Completed module"
    return next
  }

  if (type === "collection:summary" || type === "scan:summary") {
    next.phase = "waiting"
    next.completedGeneration = Math.max(Number(next.completedGeneration || 0), generation || Number(next.currentGeneration || 0))
    next.completedFiles = Math.max(Number(next.totalFiles || 0), Number(next.completedFiles || 0))
    next.completedModules = Math.max(Number(next.totalModules || 0), Number(next.completedModules || 0))
    next.lastCompletedFile = next.currentFile || next.lastCompletedFile || null
    next.lastCompletedModule = next.currentModule || next.lastCompletedModule || null
    next.currentFile = null
    next.currentFileIndex = 0
    next.currentModule = null
    next.currentModuleIndex = 0
    next.analysisState = "complete"
    next.collectionState = "waiting_for_page_activity"
    next.lastStatus = "Waiting for next page activity"
    return next
  }

  if (type === "collection:error" || type === "scan:error") {
    next.phase = "error"
    next.analysisState = "error"
    next.collectionState = "collection_failed"
    next.lastStatus = "Scan error"
    return next
  }

  return next
}

export default {
  SAST_STRUCTURED_EVENT_TYPES,
  createSastProgressState,
  countSastFindingKinds,
  buildSastProgressSnapshot,
  isStructuredSastEvent,
  applyStructuredSastProgressEvent
}
