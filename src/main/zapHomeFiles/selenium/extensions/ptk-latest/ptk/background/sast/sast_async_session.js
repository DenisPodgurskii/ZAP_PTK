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

  resolveScriptRequest(requestId, payload, sender) {
    if (!requestId || !this.pendingScriptRequests.has(requestId)) return false
    const pending = this.pendingScriptRequests.get(requestId)
    // Invalid/foreign responses must not consume an owned pending request.
    if (pending.accept) {
      try { payload = pending.accept(payload, sender) } catch (_) { return false }
    }
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

  createScriptRequest(requestId, timeoutMs = 8000, accept = null) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingScriptRequests.delete(requestId)
        reject(new Error("sast_scripts_timeout"))
      }, timeoutMs)
      this.pendingScriptRequests.set(requestId, { timer, resolve, reject, accept })
    })
  }

  waitForScanResult(file, timeoutMs = 30000) {
    if (!file) return Promise.resolve([])
    if (this.pendingScanResults.has(file)) {
      return this.pendingScanResults.get(file).promise
    }
    let resolve, reject
    const promise = new Promise((res, rej) => {
      resolve = res
      reject = rej
    })
    const timer = setTimeout(() => {
      if (this.pendingScanResults.has(file)) {
        this.pendingScanResults.delete(file)
      }
      reject(new Error('sast_analysis_timeout'))
    }, timeoutMs)
    this.pendingScanResults.set(file, { resolve, reject, timer, promise })
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

  rejectScanResult(file, error, expectedPromise = null) {
    const pending = this.pendingScanResults.get(file)
    if (!pending || expectedPromise && pending.promise !== expectedPromise) return false
    clearTimeout(pending.timer)
    this.pendingScanResults.delete(file)
    pending.reject(error)
    return true
  }

  cancelPendingScanResults(error = new Error('sast_scan_cancelled')) {
    for (const [file, pending] of [...this.pendingScanResults]) {
      this.rejectScanResult(file, error, pending.promise)
    }
    for (const requestId of [...this.pendingScriptRequests.keys()]) this.rejectScriptRequest(requestId, error)
  }
}

export default SastAsyncSession
