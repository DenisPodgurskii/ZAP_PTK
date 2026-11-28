// Coordinates an existing native executor without owning detection or storage.
// Acknowledgement, model completion and settled native cleanup are distinct.
export function createScanSessionService({ execute, readLive = () => null, id = () => crypto.randomUUID() }) {
    let active = null, completed = null, cleanupBlocked = false
    const copy = value => structuredClone(value)
    function find(ownerId, scanId) {
        if (typeof ownerId !== 'string' || !ownerId) return null
        return [active, completed].find(item => item?.ownerId === ownerId && (!scanId || item.scanId === scanId)) || null
    }
    function snapshot(item) {
        if (item.result) return copy(item.result)
        const live = readLive(item.ownerId, item.scanId)
        return copy({ ...(live || { status: 'starting', engines: [], states: {} }), scanId: item.scanId,
            cleanupComplete: null, ...(item.controller.signal.aborted ? { status: 'stopping' } : {}) })
    }
    function status(ownerId, scanId) {
        const item = find(ownerId, scanId)
        return item ? snapshot(item) : { status: 'idle' }
    }
    function required(ownerId, scanId) {
        const item = find(ownerId, scanId)
        if (!item || !scanId) throw new Error('Scan is unavailable to this owner')
        return item
    }
    async function start(options) {
        if (typeof options?.ownerId !== 'string' || !options.ownerId) throw new Error('A scan owner is required')
        options.signal?.throwIfAborted()
        if (active || cleanupBlocked) throw new Error('PTK scanner is busy or its previous cleanup is unresolved')
        // Reserve synchronously, before any native initialization can yield.
        const item = { ownerId: options.ownerId, scanId: id(), controller: new AbortController(), result: null }
        active = item
        let acknowledge
        const acknowledged = new Promise(resolve => { acknowledge = resolve })
        const abort = () => item.controller.abort()
        options.signal?.addEventListener('abort', abort, { once: true })
        if (options.signal?.aborted) abort()
        const failed = () => {
            cleanupBlocked = true
            item.result = { scanId: item.scanId, status: 'failed', cleanupComplete: false, engines: [],
                error: 'Native scan execution failed; cleanup was not confirmed.' }
            return item.result
        }
        item.completion = Promise.resolve().then(() => execute({ ...options, scanId: item.scanId, signal: item.controller.signal,
            onReady: () => {
                if (!item.controller.signal.aborted) acknowledge(snapshot(item))
            } })).then(result => {
            if (!result || typeof result.cleanupComplete !== 'boolean') return failed()
            try { item.result = { ...copy(result), scanId: item.scanId } } catch { return failed() }
            if (result.cleanupComplete === false) cleanupBlocked = true
            return item.result
        }, failed).finally(() => {
            options.signal?.removeEventListener('abort', abort)
            completed = item
            if (active === item) active = null
            acknowledge(copy(item.result))
        })
        return acknowledged
    }
    async function wait(ownerId, scanId) { return copy(await required(ownerId, scanId).completion) }
    async function stop(ownerId, scanId) {
        const item = find(ownerId, scanId)
        if (!item) return { status: 'idle' }
        if (!item.result) item.controller.abort()
        return copy(await item.completion)
    }
    function evidence(ownerId, scanId) { return snapshot(required(ownerId, scanId)) }
    function findings(ownerId, scanId) {
        const view = evidence(ownerId, scanId)
        return { scanId, status: view.status, cleanupComplete: view.cleanupComplete,
            findings: (view.engines || []).flatMap(engine => engine.findings || []),
            truncated: (view.engines || []).some(engine => engine.findingsTruncated) }
    }
    function forget(ownerId) {
        if (active?.ownerId === ownerId) throw new Error('Native cleanup is still in progress')
        if (completed?.ownerId === ownerId) completed = null
    }
    return { start, status, wait, stop, evidence, findings, forget }
}
