export class SastAsyncSession {
  constructor() {
    this.pendingScriptRequests = new Map()
    this.pendingScanResults = new Map()
    this.ignoredScanIds = new Set()
  }

  markIgnoredScanId(scanId) {
    const normalized = typeof scanId === "string" ? scanId.trim() : ""
    if (!normalized) return
    this.ignoredScanIds.add(normalized)
    if (this.ignoredScanIds.size > 64) {
      const staleKey = this.ignoredScanIds.values().next().value
      if (staleKey) this.ignoredScanIds.delete(staleKey)
    }
  }

  shouldIgnoreWorkerEvent(scanId) {
    const normalized = typeof scanId === "string" ? scanId.trim() : ""
    return !!(normalized && this.ignoredScanIds.has(normalized))
  }

  clearPendingAsyncState() {
    this.pendingScriptRequests.forEach((pending) => {
      if (pending?.timer) {
        clearTimeout(pending.timer)
      }
      if (typeof pending?.reject === "function") {
        try {
          pending.reject(new Error("sast_scan_cancelled"))
        } catch (_) {}
      }
    })
    this.pendingScriptRequests.clear()

    this.pendingScanResults.forEach((pending) => {
      if (pending?.timer) {
        clearTimeout(pending.timer)
      }
      if (typeof pending?.resolve === "function") {
        try {
          pending.resolve([])
        } catch (_) {}
      }
    })
    this.pendingScanResults.clear()
  }

  resolveScriptRequest(requestId, payload) {
    if (!requestId || !this.pendingScriptRequests.has(requestId)) return false
    const pending = this.pendingScriptRequests.get(requestId)
    this.pendingScriptRequests.delete(requestId)
    if (pending?.timer) clearTimeout(pending.timer)
    pending.resolve(payload)
    return true
  }

  rejectScriptRequest(requestId, error) {
    if (!requestId || !this.pendingScriptRequests.has(requestId)) return false
    const pending = this.pendingScriptRequests.get(requestId)
    this.pendingScriptRequests.delete(requestId)
    if (pending?.timer) clearTimeout(pending.timer)
    pending.reject(error)
    return true
  }

  createScriptRequest(requestId, timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingScriptRequests.delete(requestId)
        reject(new Error("sast_scripts_timeout"))
      }, timeoutMs)
      this.pendingScriptRequests.set(requestId, { timer, resolve, reject })
    })
  }

  waitForScanResult(file, timeoutMs = 30000) {
    if (!file) return Promise.resolve([])
    if (this.pendingScanResults.has(file)) {
      return this.pendingScanResults.get(file).promise
    }
    let resolve
    const promise = new Promise((res) => {
      resolve = res
    })
    const timer = setTimeout(() => {
      if (this.pendingScanResults.has(file)) {
        this.pendingScanResults.delete(file)
      }
      resolve([])
    }, timeoutMs)
    this.pendingScanResults.set(file, { resolve, timer, promise })
    return promise
  }

  resolveScanResult(file, findings) {
    if (!file) return false
    const pending = this.pendingScanResults.get(file)
    if (!pending) return false
    clearTimeout(pending.timer)
    this.pendingScanResults.delete(file)
    pending.resolve(findings || [])
    return true
  }
}

export default SastAsyncSession
