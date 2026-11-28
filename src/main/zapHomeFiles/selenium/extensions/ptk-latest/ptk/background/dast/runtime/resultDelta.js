const RESULT_DELTA_BATCH_SIZE = 64

function clone(value) {
    if (value == null) return value
    return typeof structuredClone === "function"
        ? structuredClone(value)
        : JSON.parse(JSON.stringify(value))
}

function identity(kind, item, index) {
    if (kind === "findings") return String(item?.id || `finding:${index}`)
    if (kind === "findingGroups") return String(item?.id || `finding-group:${index}`)
    if (kind === "recon") return String(item?.id || item?.dedupeKey || `recon:${index}`)
    return String(item?.id || item?.dedupeKey || `recon-group:${index}`)
}

function projectCollection(kind, values) {
    const map = new Map()
    for (const [index, value] of (Array.isArray(values) ? values : []).entries()) {
        const key = identity(kind, value, index)
        map.set(key, { key, value: clone(value), serialized: JSON.stringify(value) })
    }
    return map
}

export function createDastResultProjection(scanResult = {}) {
    return {
        findings: projectCollection("findings", scanResult.findings),
        findingGroups: projectCollection("findingGroups", scanResult.findingGroups || scanResult.groups),
        recon: projectCollection("recon", scanResult.recon),
        reconGroups: projectCollection("reconGroups", scanResult.reconGroups),
        stats: clone(scanResult.stats || {})
    }
}

/**
 * Build bounded, replay-safe result deltas. Only presentation/result domains
 * cross the worker boundary; request and response records remain offscreen.
 */
export function buildDastResultDeltas(previous, scanResult, { revision, mutation = null } = {}) {
    const next = createDastResultProjection(scanResult)
    const operations = []
    for (const kind of ["findings", "findingGroups", "recon", "reconGroups"]) {
        const before = previous?.[kind] instanceof Map ? previous[kind] : new Map()
        const after = next[kind]
        for (const [key, entry] of after) {
            if (before.get(key)?.serialized !== entry.serialized) {
                operations.push({ kind, action: "upsert", key, value: entry.value })
            }
        }
        for (const key of before.keys()) {
            if (!after.has(key)) operations.push({ kind, action: "remove", key })
        }
    }

    const chunkCount = Math.max(1, Math.ceil(operations.length / RESULT_DELTA_BATCH_SIZE))
    const deltas = []
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        const delta = {
            version: 1,
            revision: Math.max(0, Math.trunc(Number(revision) || 0)),
            chunkIndex,
            chunkCount,
            finalChunk: chunkIndex === chunkCount - 1,
            mutation: clone(mutation),
            findings: { upsert: [], remove: [] },
            findingGroups: { upsert: [], remove: [] },
            recon: { upsert: [], remove: [] },
            reconGroups: { upsert: [], remove: [] },
            stats: clone(next.stats)
        }
        for (const operation of operations.slice(
            chunkIndex * RESULT_DELTA_BATCH_SIZE,
            (chunkIndex + 1) * RESULT_DELTA_BATCH_SIZE
        )) {
            if (operation.action === "upsert") delta[operation.kind].upsert.push({ key: operation.key, value: operation.value })
            else delta[operation.kind].remove.push(operation.key)
        }
        deltas.push(delta)
    }
    return { projection: next, deltas }
}

function applyCollection(current, changes = {}, kind) {
    const values = Array.isArray(current) ? current : []
    const byKey = new Map(values.map((value, index) => [identity(kind, value, index), value]))
    for (const key of changes.remove || []) byKey.delete(String(key))
    for (const entry of changes.upsert || []) {
        if (!entry || !entry.key) continue
        byKey.set(String(entry.key), clone(entry.value))
    }
    return Array.from(byKey.values())
}

export function applyDastResultDelta(scanResult = {}, delta = {}) {
    scanResult.findings = applyCollection(scanResult.findings, delta.findings, "findings")
    scanResult.groups = applyCollection(scanResult.groups, delta.findingGroups, "findingGroups")
    scanResult.recon = applyCollection(scanResult.recon, delta.recon, "recon")
    scanResult.reconGroups = applyCollection(scanResult.reconGroups, delta.reconGroups, "reconGroups")
    scanResult.stats = clone(delta.stats || {})
    return scanResult
}

export { RESULT_DELTA_BATCH_SIZE }
