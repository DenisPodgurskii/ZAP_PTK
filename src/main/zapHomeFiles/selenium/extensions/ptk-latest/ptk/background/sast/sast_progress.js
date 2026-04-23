export const SAST_STRUCTURED_EVENT_TYPES = new Set([
  "scan:start",
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
  return {
    phase: progressState.phase || "idle",
    totalFiles: Number(progressState.totalFiles || 0),
    completedFiles: Number(progressState.completedFiles || 0),
    currentFile: progressState.currentFile || null,
    currentFileIndex: Number(progressState.currentFileIndex || 0),
    totalModules: Number(progressState.totalModules || 0),
    completedModules: Number(progressState.completedModules || 0),
    currentModule: progressState.currentModule || null,
    currentModuleIndex: Number(progressState.currentModuleIndex || 0),
    findings: findingKinds.finding,
    hints: findingKinds.hint,
    discovery: countArtifacts(scanResult?.codeArtifacts?.sast),
    elapsedMs: scanStartMs ? Math.max(0, Date.now() - scanStartMs) : 0,
    isRunning: !!isRunning
  }
}

export function isStructuredSastEvent(type) {
  return SAST_STRUCTURED_EVENT_TYPES.has(type)
}

export function applyStructuredSastProgressEvent(state = null, type, data = {}) {
  const next = state || createSastProgressState()

  if (type === "scan:start") {
    next.phase = "scan_start"
    next.totalFiles = Number(data.totalFiles || 0)
    next.totalModules = Number(data.totalModules || 0)
    next.lastStatus = "Scan started"
    return next
  }

  if (type === "file:start") {
    next.phase = "file"
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
    next.currentFile = data.file || next.currentFile || null
    next.currentFileIndex = Math.max(next.currentFileIndex || 0, Number(data.index || 0) + 1)
    next.totalFiles = Math.max(Number(next.totalFiles || 0), Number(data.totalFiles || 0))
    next.completedFiles = Math.max(Number(next.completedFiles || 0), Number(data.index || 0) + 1)
    next.completedModules = next.totalModules || next.completedModules
    next.lastStatus = "Finished file"
    return next
  }

  if (type === "module:start") {
    next.phase = "module"
    next.currentFile = data.file || next.currentFile || null
    next.currentModule = data.moduleName || data.moduleId || null
    next.currentModuleIndex = Number(data.moduleIndex || next.currentModuleIndex || 0)
    next.totalModules = Math.max(Number(next.totalModules || 0), Number(data.totalModules || 0))
    next.lastStatus = "Running module"
    return next
  }

  if (type === "module:end") {
    next.phase = "module_complete"
    next.currentFile = data.file || next.currentFile || null
    next.currentModule = data.moduleName || data.moduleId || next.currentModule || null
    next.currentModuleIndex = Number(data.moduleIndex || next.currentModuleIndex || 0)
    next.totalModules = Math.max(Number(next.totalModules || 0), Number(data.totalModules || 0))
    next.completedModules = Math.max(Number(next.completedModules || 0), Number(data.moduleIndex || 0))
    next.lastStatus = "Completed module"
    return next
  }

  if (type === "scan:summary") {
    next.phase = "waiting"
    next.completedFiles = Math.max(Number(next.totalFiles || 0), Number(next.completedFiles || 0))
    next.completedModules = Math.max(Number(next.totalModules || 0), Number(next.completedModules || 0))
    next.currentModule = null
    next.currentModuleIndex = 0
    next.lastStatus = "Waiting for next page activity"
    return next
  }

  if (type === "scan:error") {
    next.phase = "error"
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
