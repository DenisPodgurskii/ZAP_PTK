'use strict'

import { toDastFinding } from './zapDastMapper.js'
import { toIastFinding } from './zapIastMapper.js'
import { toSastFindings } from './zapSastMapper.js'
import { isZapExportableFinding } from './zapFindingFilter.js'

const ENGINES = ['DAST', 'IAST', 'SAST']
const POLL_INTERVAL_MS = 2000
const ALERT_CHUNK_SIZE = 200
const MAX_KEYS = 50
const KEY_IDLE_EVICT_MS = 10 * 60 * 1000
const PUBLISHED_STATE_CAP_PER_KEY = 5000
const ZAP_SESSION_SCAN_LOOKBACK_MS = 30 * 1000
const TERMINAL_DRAIN_MIN_STABLE_PASSES = 2
const ACK_RESOLVED_STATUSES = new Set([
    'accepted_raised',
    'accepted_duplicate',
    'rejected_missing_mapping',
    'rejected_invalid_url',
    'rejected_missing_site_tree_match',
    'rejected_raise_failed'
])

function createPublisherBatchId() {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
        return globalThis.crypto.randomUUID()
    }
    return `ptk-zap-batch-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`
}

function chunkArray(items, size) {
    if (!Array.isArray(items) || !items.length) return []
    const chunks = []
    for (let i = 0; i < items.length; i += size) {
        chunks.push(items.slice(i, i + size))
    }
    return chunks
}

function stableStringify(value) {
    if (value === null || value === undefined) return 'null'
    if (typeof value === 'string') return JSON.stringify(value)
    if (typeof value === 'number' || typeof value === 'boolean') return String(value)
    if (Array.isArray(value)) {
        return `[${value.map((entry) => stableStringify(entry)).join(',')}]`
    }
    if (typeof value === 'object') {
        return `{${Object.keys(value).sort((a, b) => a.localeCompare(b)).map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`
    }
    return JSON.stringify(String(value))
}

function toSourceFindingKey(finding) {
    if (!finding || typeof finding !== 'object') return ''
    const evidence = finding?.evidence?.dast && typeof finding.evidence.dast === 'object'
        ? finding.evidence.dast
        : {}
    const location = finding?.location && typeof finding.location === 'object'
        ? finding.location
        : {}
    const fingerprint = typeof finding?.fingerprint === 'string' ? finding.fingerprint.trim() : ''
    if (fingerprint) return fingerprint
    const id = typeof finding?.id === 'string' ? finding.id.trim() : ''
    if (id) return id
    return [
        String(finding.engine || ''),
        String(finding.outputKind || ''),
        String(evidence.attackId || ''),
        String(evidence.requestId || ''),
        String(finding.ruleId || ''),
        String(finding.moduleId || ''),
        String(location.url || ''),
        String(location.method || ''),
        String(location.param || '')
    ].join('|')
}

function toDastMergeKey(finding) {
    if (!finding || typeof finding !== 'object') return ''
    const evidence = finding?.evidence?.dast && typeof finding.evidence.dast === 'object'
        ? finding.evidence.dast
        : {}
    const location = finding?.location && typeof finding.location === 'object'
        ? finding.location
        : {}
    const attackId = String(evidence.attackId || evidence.attack?.id || finding.attackId || '')
    const requestId = String(evidence.requestId || evidence.attack?.requestId || finding.requestId || '')
    const moduleId = String(finding.moduleId || '')
    const ruleId = String(finding.ruleId || '')
    const payload = evidence.payload === undefined || evidence.payload === null
        ? ''
        : String(evidence.payload)
    const proof = evidence.proof === undefined || evidence.proof === null
        ? ''
        : String(evidence.proof)

    if (requestId || attackId) {
        return [
            'dast',
            moduleId,
            ruleId,
            requestId,
            attackId,
            String(location.url || ''),
            String(location.method || ''),
            String(location.param || '')
        ].join('|')
    }

    return [
        'dast',
        moduleId,
        ruleId,
        String(finding.outputKind || ''),
        String(location.url || ''),
        String(location.method || ''),
        String(location.param || ''),
        payload,
        proof
    ].join('|')
}

function isReportableDastAttack(attack) {
    if (!attack || typeof attack !== 'object') return false
    if (!attack.success) return false
    if (attack?.validation?.rule === false) return false
    if (attack?.metadata?.validation?.rule === false) return false
    return true
}

function normalizeScanIds(value) {
    const raw = Array.isArray(value) ? value : (value ? [value] : [])
    const seen = new Set()
    return raw
        .map(scanId => String(scanId || '').trim())
        .filter(scanId => {
            if (!scanId || seen.has(scanId)) return false
            seen.add(scanId)
            return true
        })
}

export default class ZapPublisher {
    constructor(app, zapBridge, resultsRegistry) {
        this.app = app
        this.zapBridge = zapBridge
        this.resultsRegistry = resultsRegistry

        this.timerId = null
        this.pollInFlight = false
        this.wasActive = false
        this.disabled = false
        this.apiValidated = false
        this.missingApiWarned = false
        this.activeSinceMs = null

        this.publishedState = new Map()
        this.lastSeen = new Map()
        this.inFlightBatches = new Map()
        this.batchSeq = 0
        this.lastAckedBatchSeq = 0
        this._pollIdleWaiters = new Set()
        this.flushRequested = false
    }

    start() {
        if (this.timerId || this.disabled) return
        void this._pollOnce()
        this.timerId = setInterval(() => {
            void this._pollOnce()
        }, POLL_INTERVAL_MS)
    }

    stop() {
        if (!this.timerId) return
        clearInterval(this.timerId)
        this.timerId = null
    }

    async flushOnce() {
        await this._pollOnce()
    }

    requestFlush() {
        if (this.disabled) return
        this.flushRequested = true
        void this._pollOnce()
    }

    async flushPendingForTerminal({ maxPasses = 4 } = {}) {
        if (this.disabled) {
            return {
                drained: true,
                pendingFindings: 0,
                pendingByEngine: {},
                inFlightBatches: 0,
                inFlightByEngine: {},
                lastAckedBatchSeq: this.lastAckedBatchSeq,
                passes: 0,
                stablePasses: 0
            }
        }

        let lastState = {
            drained: true,
            pendingFindings: 0,
            pendingByEngine: {},
            inFlightBatches: 0,
            inFlightByEngine: {},
            lastAckedBatchSeq: this.lastAckedBatchSeq,
            passes: 0,
            stablePasses: 0
        }
        let stablePasses = 0

        for (let pass = 1; pass <= Math.max(1, Number(maxPasses) || 1); pass += 1) {
            await this._waitForPollIdle()
            await this._pollOnce()
            await this._waitForPollIdle()

            lastState = await this.getDrainState()
            if (lastState.drained) {
                stablePasses += 1
                if (stablePasses >= TERMINAL_DRAIN_MIN_STABLE_PASSES) {
                    return Object.assign({}, lastState, {
                        passes: pass,
                        stablePasses
                    })
                }
            } else {
                stablePasses = 0
            }
        }

        return Object.assign({}, lastState, {
            passes: Math.max(1, Number(maxPasses) || 1),
            stablePasses
        })
    }

    async getDrainState() {
        if (!this._validateRegistryApi()) {
            return {
                drained: true,
                pendingFindings: 0,
                pendingByEngine: {},
                inFlightBatches: 0,
                inFlightByEngine: {},
                lastAckedBatchSeq: this.lastAckedBatchSeq
            }
        }

        const active = this.zapBridge.isActive()
        if (!active) {
            return {
                drained: true,
                pendingFindings: 0,
                pendingByEngine: {},
                inFlightBatches: 0,
                inFlightByEngine: {},
                lastAckedBatchSeq: this.lastAckedBatchSeq
            }
        }

        const host = typeof this.zapBridge?.getActiveTargetHost === 'function'
            ? this.zapBridge.getActiveTargetHost()
            : null
        const pendingByEngine = {}
        let pendingFindings = 0

        for (const engine of ENGINES) {
            const scanIds = await this._resolveScanIdsForEngine(engine, host)
            let enginePending = 0

            for (const scanId of scanIds) {
                const scanResult = await this.resultsRegistry.get(engine, scanId)
                if (!scanResult) continue
                enginePending += this._countPendingFindingsForScan(engine, scanId, scanResult)
            }

            if (enginePending > 0) {
                pendingByEngine[engine] = enginePending
                pendingFindings += enginePending
            }
        }

        return {
            drained: pendingFindings === 0 && !this.pollInFlight && this.inFlightBatches.size === 0,
            pendingFindings,
            pendingByEngine,
            inFlightBatches: this.inFlightBatches.size,
            inFlightByEngine: this._countInFlightByEngine(),
            lastAckedBatchSeq: this.lastAckedBatchSeq
        }
    }

    resetState() {
        this.publishedState.clear()
        this.lastSeen.clear()
        this.inFlightBatches.clear()
        this.batchSeq = 0
        this.lastAckedBatchSeq = 0
        this.wasActive = false
        this.activeSinceMs = Date.now()
    }

    _disablePublisher() {
        this.disabled = true
        this.stop()
    }

    _validateRegistryApi() {
        if (this.apiValidated) {
            return !this.disabled
        }

        this.apiValidated = true
        const hasFindScanIdForEngine = typeof this.resultsRegistry?.findScanIdForEngine === 'function'
        const hasFindScanIdsForEngine = typeof this.resultsRegistry?.findScanIdsForEngine === 'function'
        const hasGet = typeof this.resultsRegistry?.get === 'function'

        if ((!hasFindScanIdForEngine && !hasFindScanIdsForEngine) || !hasGet) {
            if (!this.missingApiWarned) {
                console.warn('[PTK ZAP] resultsRegistry API missing required methods; publisher disabled')
                this.missingApiWarned = true
            }
            this._disablePublisher()
            return false
        }

        return true
    }

    async _pollOnce() {
        if (this.disabled) return
        if (this.pollInFlight) {
            this.flushRequested = true
            return
        }
        this.pollInFlight = true

        try {
            let passes = 0
            do {
                this.flushRequested = false
                passes += 1
                await this._runPoll()
            } while (this.flushRequested && !this.disabled && passes < 3)
        } catch (err) {
            console.warn('[PTK ZAP] Poll cycle failed:', err)
        } finally {
            this.pollInFlight = false
            this._notifyPollIdle()
            if (this.flushRequested && !this.disabled) {
                void this._pollOnce()
            }
        }
    }

    async _runPoll() {
        if (!this._validateRegistryApi()) return

        const active = this.zapBridge.isActive()
        if (active && !this.wasActive) {
            this.resetState()
        }
        this.wasActive = active

        if (!active) return

        for (const engine of ENGINES) {
            await this._pollEngine(engine)
        }

        this._evictStaleKeys()
    }

    async _pollEngine(engine) {
        try {
            const host = typeof this.zapBridge?.getActiveTargetHost === 'function'
                ? this.zapBridge.getActiveTargetHost()
                : null
            const scanIds = await this._resolveScanIdsForEngine(engine, host)
            if (!scanIds.length) return

            for (const scanId of scanIds) {
                const scanResult = await this.resultsRegistry.get(engine, scanId)
                if (!scanResult) continue

                const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
                const key = `${engine}:${scanId}`
                this._touchKey(key)
                if (engine === 'DAST') {
                    const dastSource = this._collectDastSourceFindings(scanResult)
                    await this._publishDastFindings({
                        key,
                        scanId,
                        scanResult,
                        findings: dastSource.findings,
                        rawCount: dastSource.rawCount,
                        reconCount: dastSource.reconCount,
                        synthesizedCount: dastSource.synthesizedCount
                    })
                    continue
                }

                if (engine === 'IAST') {
                    await this._publishEngineFindingsBatch({
                        key,
                        engine,
                        scanId,
                        findings,
                        scanResult,
                        mapper: toIastFinding,
                        sender: (payload) => this.zapBridge.sendIastFindingsBatch(payload)
                    })
                    continue
                }

                if (engine === 'SAST') {
                    await this._publishEngineFindingsBatch({
                        key,
                        engine,
                        scanId,
                        findings,
                        scanResult,
                        mapper: toSastFindings,
                        sender: (payload) => this.zapBridge.sendSastFindingsBatch(payload)
                    })
                    continue
                }
            }

        } catch (err) {
            console.warn('[PTK ZAP] Engine publish iteration failed', {
                engine,
                error: err?.message || String(err)
            })
        }
    }

    async _resolveScanIdsForEngine(engine, host) {
        const managedScanIds = normalizeScanIds(
            typeof this.zapBridge?.getManagedScanIdsForEngine === 'function'
                ? await this.zapBridge.getManagedScanIdsForEngine(engine)
                : []
        )
        let storedScanIds = []

        if (typeof this.resultsRegistry?.findScanIdsForEngine === 'function') {
            const hints = { host: host || null }
            if (Number.isFinite(this.activeSinceMs)) {
                hints.startedAfterMs = Math.max(0, this.activeSinceMs - ZAP_SESSION_SCAN_LOOKBACK_MS)
            }
            storedScanIds = normalizeScanIds(await this.resultsRegistry.findScanIdsForEngine(engine, hints))
        }

        const scanIds = normalizeScanIds([...managedScanIds, ...storedScanIds])
        if (scanIds.length) return scanIds

        if (typeof this.resultsRegistry?.findScanIdForEngine === 'function') {
            const scanId = await this.resultsRegistry.findScanIdForEngine(engine, {
                host: host || null
            })
            return normalizeScanIds(scanId)
        }
        return []
    }

    _collectDastSourceFindings(scanResult) {
        const rawFindings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        const reconFindings = Array.isArray(scanResult?.recon) ? scanResult.recon : []
        const synthesizedFindings = this._synthesizeDastFindingsFromRequests(scanResult)
        const merged = []
        const seen = new Set()
        for (const finding of [...rawFindings, ...synthesizedFindings, ...reconFindings]) {
            if (!finding || typeof finding !== 'object') continue
            const key = toDastMergeKey(finding) || toSourceFindingKey(finding)
            if (key && seen.has(key)) continue
            if (key) seen.add(key)
            merged.push(finding)
        }
        return {
            findings: merged,
            rawCount: rawFindings.length,
            reconCount: reconFindings.length,
            synthesizedCount: synthesizedFindings.length
        }
    }

    _synthesizeDastFindingsFromRequests(scanResult) {
        const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
        const findings = []
        let fallbackSeq = 0

        for (const record of requests) {
            if (!record || typeof record !== 'object') continue
            const requestId = record.id || `req-${fallbackSeq + 1}`
            const originalRequest = record?.original?.request || {}
            const attacks = Array.isArray(record.attacks) ? record.attacks : []

            for (const attack of attacks) {
                if (!isReportableDastAttack(attack)) continue
                fallbackSeq += 1
                const meta = attack?.metadata && typeof attack.metadata === 'object' ? attack.metadata : {}
                const attackId = attack.id || `atk-${fallbackSeq}`
                const req = attack.request || originalRequest || {}
                const attacked = meta.attacked
                const paramName = attack.param
                    || meta.param
                    || (typeof attacked === 'string' ? attacked : attacked?.name)
                    || null
                findings.push({
                    id: `zap-ui-dast-${scanResult?.scanId || 'scan'}-${requestId}-${attackId}`,
                    engine: 'DAST',
                    scanId: scanResult?.scanId || null,
                    moduleId: attack.moduleId || meta.moduleId || null,
                    moduleName: attack.moduleName || meta.moduleName || meta.module || null,
                    ruleId: attack.ruleId || meta.id || meta.attackId || attackId,
                    ruleName: attack.ruleName || attack.name || meta.name || meta.id || null,
                    vulnId: attack.vulnId || meta.vulnId || meta.category || null,
                    category: attack.category || meta.category || null,
                    severity: attack.severity || meta.severity || 'medium',
                    confidence: attack.confidence ?? meta.confidence ?? null,
                    outputKind: attack.outputKind || meta.outputKind || null,
                    reconKind: attack.reconKind || meta.reconKind || null,
                    presentationAggregate: attack.presentationAggregate || meta.presentationAggregate || null,
                    uiSurface: attack.uiSurface || meta.uiSurface || null,
                    location: {
                        url: req.url || req.href || originalRequest?.url || null,
                        method: req.method || originalRequest?.method || null,
                        param: paramName
                    },
                    evidence: {
                        dast: {
                            attackId,
                            requestId,
                            param: attack.param || meta.param || null,
                            payload: attack.payload || meta.payload || null,
                            proof: attack.proof || null
                        }
                    }
                })
            }
        }

        return findings
    }

    _beginBatch({ engine, scanId, entries = [] } = {}) {
        const batchSeq = this.batchSeq + 1
        this.batchSeq = batchSeq
        const batchId = createPublisherBatchId()
        const state = {
            batchId,
            batchSeq,
            engine,
            scanId,
            entries,
            startedAt: Date.now()
        }
        this.inFlightBatches.set(batchId, state)
        return state
    }

    _finishBatch(batch) {
        if (!batch?.batchId) return
        this.inFlightBatches.delete(batch.batchId)
    }

    _countInFlightByEngine() {
        const counts = {}
        for (const batch of this.inFlightBatches.values()) {
            const engine = String(batch?.engine || '').toUpperCase()
            if (!engine) continue
            counts[engine] = (counts[engine] || 0) + 1
        }
        return counts
    }

    _resolveAckedEntries(ack, batch) {
        const entries = Array.isArray(batch?.entries) ? batch.entries : []
        if (!entries.length) return []

        if (!ack || typeof ack !== 'object') {
            return []
        }

        const findingResults = Array.isArray(ack.findingResults) ? ack.findingResults : []
        const resultMap = new Map()
        for (const result of findingResults) {
            if (!result || typeof result !== 'object') continue
            const status = String(result.status || '').trim()
            if (!ACK_RESOLVED_STATUSES.has(status)) continue
            for (const key of [
                result.id,
                result.findingId,
                result.fingerprint,
                result.findingKey
            ]) {
                if (typeof key === 'string' && key.trim()) {
                    resultMap.set(key.trim(), result)
                }
            }
        }

        if (resultMap.size === 0) {
            if (findingResults.length > 0) {
                return []
            }
            const contractVersion = Number(ack.contractVersion)
            const isV2Structured = contractVersion >= 2 || ack.structuredAck === true
            const isExplicitLegacy = ack.legacyAck === true || (Number.isFinite(contractVersion) && contractVersion < 2)
            if (isV2Structured) {
                if (ack.structuredAck === true
                    && ack.allFindingsAccepted === true
                    && ack.accepted === entries.length
                    && ack.received === entries.length) {
                    return entries
                }
                return []
            }
            if (isExplicitLegacy && (ack.result === 'OK' || ack.accepted === entries.length || ack.received === entries.length)) {
                return entries
            }
            return []
        }

        return entries.filter((entry) => {
            const mapped = entry?.mapped || {}
            const candidates = [
                mapped.id,
                mapped.fingerprint,
                entry.findingKey
            ].filter(value => typeof value === 'string' && value.trim())
            return candidates.some(candidate => resultMap.has(candidate.trim()))
        })
    }

    _pollControlAfterAck(source) {
        try {
            this.zapBridge?.pollControlMonitors?.({ source })
        } catch (err) {
            this.zapBridge?._debugLog?.('[PTK ZAP] Control poll after alert acknowledgement failed:', {
                source,
                error: err?.message || String(err)
            })
        }
    }

    async _publishDastFindings({ key, scanId, scanResult, findings: sourceFindings, rawCount = 0, reconCount = 0, synthesizedCount = 0 }) {
        const {
            entries: findings,
            skippedFilter,
            skippedMapper,
            alreadyPublished
        } = this._collectPendingMappedFindings({
            key,
            engine: 'DAST',
            scanId,
            sourceFindings,
            scanResult,
            mapper: toDastFinding
        })

        if (!findings.length) return

        this.zapBridge?._debugLog?.('[PTK ZAP] Publish stats:', {
            engine: 'DAST',
            scanId,
            total: Array.isArray(sourceFindings) ? sourceFindings.length : 0,
            rawFindings: rawCount,
            reconFindings: reconCount,
            synthesizedFindings: synthesizedCount,
            exportable: (Array.isArray(sourceFindings) ? sourceFindings.length : 0) - skippedFilter,
            toSend: findings.length,
            alreadyPublished,
            skippedFilter,
            skippedMapper
        })

        const chunks = chunkArray(findings, ALERT_CHUNK_SIZE)
        for (const chunk of chunks) {
            const batch = this._beginBatch({ engine: 'DAST', scanId, entries: chunk })
            try {
                const ack = await this.zapBridge.sendDastFindingsBatch({
                    scanId,
                    findings: chunk.map((entry) => entry.mapped),
                    truncated: false,
                    batchId: batch.batchId,
                    batchSeq: batch.batchSeq
                })
                const resolvedEntries = this._resolveAckedEntries(ack, batch)
                resolvedEntries.forEach((entry) => this._markFindingVersionPublished(key, entry.findingKey, entry.signature))
                if (resolvedEntries.length > 0) {
                    this.lastAckedBatchSeq = Math.max(this.lastAckedBatchSeq, batch.batchSeq)
                    this._pollControlAfterAck('publisher_ack')
                }
            } catch (err) {
                console.warn('[PTK ZAP] Failed to send DAST findings chunk; dropping chunk', {
                    engine: 'DAST',
                    scanId,
                    error: err?.message || String(err)
                })
            } finally {
                this._finishBatch(batch)
            }
        }
    }

    async _publishEngineFindingsBatch({ key, engine, scanId, findings: sourceFindings, scanResult, mapper, sender }) {
        const {
            entries: findings,
            skippedFilter,
            skippedMapper,
            alreadyPublished
        } = this._collectPendingMappedFindings({
            key,
            engine,
            scanId,
            sourceFindings,
            scanResult,
            mapper
        })

        if (!findings.length) return

        this.zapBridge?._debugLog?.('[PTK ZAP] Publish stats:', {
            engine,
            scanId,
            total: Array.isArray(sourceFindings) ? sourceFindings.length : 0,
            exportable: (Array.isArray(sourceFindings) ? sourceFindings.length : 0) - skippedFilter,
            toSend: findings.length,
            alreadyPublished,
            skippedFilter,
            skippedMapper
        })

        const chunks = chunkArray(findings, ALERT_CHUNK_SIZE)
        for (const chunk of chunks) {
            const batch = this._beginBatch({ engine, scanId, entries: chunk })
            try {
                const ack = await sender({
                    scanId,
                    findings: chunk.map((entry) => entry.mapped),
                    truncated: false,
                    batchId: batch.batchId,
                    batchSeq: batch.batchSeq
                })
                const resolvedEntries = this._resolveAckedEntries(ack, batch)
                resolvedEntries.forEach((entry) => this._markFindingVersionPublished(key, entry.findingKey, entry.signature))
                if (resolvedEntries.length > 0) {
                    this.lastAckedBatchSeq = Math.max(this.lastAckedBatchSeq, batch.batchSeq)
                    this._pollControlAfterAck('publisher_ack')
                }
            } catch (err) {
                console.warn('[PTK ZAP] Failed to send findings chunk; dropping chunk', {
                    engine,
                    scanId,
                    error: err?.message || String(err)
                })
            } finally {
                this._finishBatch(batch)
            }
        }
    }

    _touchKey(key) {
        this.lastSeen.set(key, Date.now())
    }

    _notifyPollIdle() {
        if (!this._pollIdleWaiters.size) return
        const waiters = Array.from(this._pollIdleWaiters)
        this._pollIdleWaiters.clear()
        for (const resolve of waiters) {
            try {
                resolve()
            } catch (_) {
                // no-op
            }
        }
    }

    _waitForPollIdle() {
        if (!this.pollInFlight) {
            return Promise.resolve()
        }
        return new Promise((resolve) => {
            this._pollIdleWaiters.add(resolve)
        })
    }

    _collectPendingMappedFindings({ key, engine, scanId, sourceFindings, scanResult, mapper }) {
        const entries = []
        let skippedFilter = 0
        let skippedMapper = 0
        let alreadyPublished = 0

        for (const finding of Array.isArray(sourceFindings) ? sourceFindings : []) {
            if (!isZapExportableFinding(engine, finding)) {
                skippedFilter += 1
                continue
            }

            const mappedResult = mapper(finding, { scanId, scanResult })
            const mappedFindings = Array.isArray(mappedResult)
                ? mappedResult.filter(Boolean)
                : (mappedResult ? [mappedResult] : [])
            if (!mappedFindings.length) {
                skippedMapper += 1
                continue
            }

            for (const mapped of mappedFindings) {
                const findingKey = this._getMappedFindingKey(mapped)
                const signature = stableStringify(mapped)
                if (!this._shouldPublishFindingVersion(key, findingKey, signature)) {
                    alreadyPublished += 1
                    continue
                }

                entries.push({ mapped, findingKey, signature })
            }
        }

        return {
            entries,
            skippedFilter,
            skippedMapper,
            alreadyPublished
        }
    }

    _countPendingFindingsForScan(engine, scanId, scanResult) {
        const key = `${engine}:${scanId}`

        if (engine === 'DAST') {
            const dastSource = this._collectDastSourceFindings(scanResult)
            return this._collectPendingMappedFindings({
                key,
                engine,
                scanId,
                sourceFindings: dastSource.findings,
                scanResult,
                mapper: toDastFinding
            }).entries.length
        }

        const mapper = engine === 'IAST' ? toIastFinding : toSastFindings
        const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        return this._collectPendingMappedFindings({
            key,
            engine,
            scanId,
            sourceFindings: findings,
            scanResult,
            mapper
        }).entries.length
    }

    _getPublishedStateForKey(key) {
        if (!this.publishedState.has(key)) {
            this.publishedState.set(key, new Map())
        }
        return this.publishedState.get(key)
    }

    _getMappedFindingKey(mapped) {
        const fingerprint = typeof mapped?.fingerprint === 'string' ? mapped.fingerprint.trim() : ''
        if (fingerprint) return fingerprint
        const id = typeof mapped?.id === 'string' ? mapped.id.trim() : ''
        if (id) return id
        return stableStringify(mapped)
    }

    _shouldPublishFindingVersion(key, findingKey, signature) {
        const state = this._getPublishedStateForKey(key)
        return state.get(findingKey) !== signature
    }

    _markFindingVersionPublished(key, findingKey, signature) {
        if (!findingKey) return
        const state = this._getPublishedStateForKey(key)
        if (state.has(findingKey)) {
            state.delete(findingKey)
        }
        state.set(findingKey, signature)

        while (state.size > PUBLISHED_STATE_CAP_PER_KEY) {
            const oldestKey = state.keys().next().value
            state.delete(oldestKey)
        }
    }

    _evictStaleKeys() {
        const now = Date.now()

        for (const [key, lastSeenAt] of this.lastSeen.entries()) {
            if (now - lastSeenAt > KEY_IDLE_EVICT_MS) {
                this._dropKey(key)
            }
        }

        while (this.publishedState.size > MAX_KEYS) {
            const oldest = [...this.lastSeen.entries()].sort((a, b) => a[1] - b[1])[0]
            if (!oldest) break
            this._dropKey(oldest[0])
        }
    }

    _dropKey(key) {
        this.lastSeen.delete(key)
        this.publishedState.delete(key)
    }
}
