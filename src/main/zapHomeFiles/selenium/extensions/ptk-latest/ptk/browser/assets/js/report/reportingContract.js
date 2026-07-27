const REPORT_ENGINES = Object.freeze(['dast', 'iast', 'sast', 'sca'])
const REPORT_SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info'])
const SAST_DISCOVERY_KINDS = new Set(['artifact', 'discovery', 'hint', 'recon'])
const DAST_RECON_AGGREGATE_MODES = new Set(['scan', 'route'])

function normalizeEngine(engine) {
    return String(engine || '').trim().toLowerCase()
}

export function normalizeReportSeverity(value) {
    const normalized = String(value || '').trim().toLowerCase()
    if (normalized === 'informational') return 'info'
    return REPORT_SEVERITIES.includes(normalized) ? normalized : 'info'
}

function getFindingKinds(finding = {}) {
    return [
        finding?.outputKind,
        finding?.findingKind,
        finding?.reconKind,
        finding?.metadata?.outputKind,
        finding?.metadata?.findingKind,
        finding?.metadata?.reconKind
    ]
        .map((value) => String(value || '').trim().toLowerCase())
        .filter(Boolean)
}

export function isReportDiscovery(engine, finding = {}) {
    const normalizedEngine = normalizeEngine(engine || finding?.engine)
    const kinds = getFindingKinds(finding)
    if (normalizedEngine === 'sast') {
        return kinds.some((kind) => SAST_DISCOVERY_KINDS.has(kind))
    }
    return false
}

export function isIastReportFinding(finding = {}) {
    return normalizeReportSeverity(
        finding?.severity
        || finding?.effectiveSeverity
        || finding?.metadata?.severity
    ) !== 'info'
}

export function partitionReportFindings(engine, findings = []) {
    const normalizedEngine = normalizeEngine(engine)
    const partitioned = { findings: [], discoveries: [], excluded: [] }
    ;(Array.isArray(findings) ? findings : []).forEach((finding) => {
        if (!finding || typeof finding !== 'object') return
        if (isReportDiscovery(engine, finding)) {
            partitioned.discoveries.push(finding)
        } else if (normalizedEngine === 'iast' && !isIastReportFinding(finding)) {
            partitioned.excluded.push(finding)
        } else {
            partitioned.findings.push(finding)
        }
    })
    return partitioned
}

export function summarizeReportFindings(findings = []) {
    const summary = {
        findingsCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    }
    ;(Array.isArray(findings) ? findings : []).forEach((finding) => {
        if (!finding || typeof finding !== 'object') return
        const severity = normalizeReportSeverity(finding.severity || finding?.metadata?.severity)
        summary.findingsCount += 1
        summary[severity] += 1
    })
    return summary
}

function normalizeRoutePath(urlValue = '') {
    const raw = String(urlValue || '').trim()
    if (!raw) return '/'
    try {
        return String(new URL(raw, 'http://localhost').pathname || '/').trim().toLowerCase() || '/'
    } catch (_) {
        return raw.replace(/[?#].*$/, '').trim().toLowerCase() || '/'
    }
}

function resolveRequest(attack = {}, record = {}) {
    return attack?.request || record?.original?.request || record?.original || {}
}

function resolveFinding(attack = {}, findingLookup = new Map()) {
    const findingId = attack?.findingId
    if (findingId === null || findingId === undefined || findingId === '') return null
    return findingLookup.get(String(findingId)) || null
}

function resolveAttackValue(attack, finding, field) {
    const metadata = attack?.metadata && typeof attack.metadata === 'object' ? attack.metadata : {}
    return attack?.[field] ?? finding?.[field] ?? metadata?.[field] ?? null
}

function resolveAttackOutputKind(attack, finding) {
    return String(resolveAttackValue(attack, finding, 'outputKind') || '').trim().toLowerCase()
}

function resolveAttackAggregateMode(attack, finding) {
    const metadata = attack?.metadata && typeof attack.metadata === 'object' ? attack.metadata : {}
    const value = resolveAttackValue(attack, finding, 'presentationAggregate')
        || metadata?.extensions?.ptk?.presentation?.aggregate
        || finding?.metadata?.extensions?.ptk?.presentation?.aggregate
        || finding?.extensions?.ptk?.presentation?.aggregate
        || ''
    const normalized = String(value).trim().toLowerCase()
    return DAST_RECON_AGGREGATE_MODES.has(normalized) ? normalized : 'none'
}

function buildReconPresentationKey(attack, finding, record) {
    if (resolveAttackOutputKind(attack, finding) !== 'recon') return null
    const request = resolveRequest(attack, record)
    const method = String(request?.method || '').trim().toUpperCase() || 'GET'
    const path = normalizeRoutePath(request?.url || request?.ui_url || request?.target || '')
    const ruleId = String(resolveAttackValue(attack, finding, 'ruleId') || '').trim().toLowerCase()
    const mode = resolveAttackAggregateMode(attack, finding)
    if (mode === 'scan') {
        return ruleId ? `recon-group|${ruleId}` : null
    }
    if (mode === 'route') {
        return ruleId ? `recon-group|${ruleId}|${method}|${path}` : null
    }
    const moduleId = String(resolveAttackValue(attack, finding, 'moduleId') || '').trim().toLowerCase()
    const metadata = attack?.metadata && typeof attack.metadata === 'object' ? attack.metadata : {}
    const param = String(
        resolveAttackValue(attack, finding, 'param')
        || (typeof metadata?.attacked === 'string' ? metadata.attacked : metadata?.attacked?.name)
        || finding?.location?.param
        || ''
    ).trim().toLowerCase()
    return `recon|${moduleId}|${ruleId}|${method}|${path}|${param}`
}

function buildPassiveAggregateKey(attack, finding, record) {
    const metadata = attack?.metadata && typeof attack.metadata === 'object' ? attack.metadata : {}
    const moduleId = String(
        resolveAttackValue(attack, finding, 'moduleId')
        || metadata?.moduleId
        || metadata?.id
        || ''
    ).trim().toLowerCase()
    if (moduleId !== 'headers') return null
    const aggregateValue = resolveAttackValue(attack, finding, 'presentationAggregate')
        || metadata?.extensions?.ptk?.presentation?.aggregate
        || finding?.metadata?.extensions?.ptk?.presentation?.aggregate
        || finding?.extensions?.ptk?.presentation?.aggregate
        || ''
    const aggregateMode = String(aggregateValue).trim().toLowerCase()
    if (aggregateMode && aggregateMode !== 'scan') return null
    const ruleId = String(
        resolveAttackValue(attack, finding, 'ruleId')
        || metadata?.ruleId
        || metadata?.id
        || ''
    ).trim().toLowerCase()
    const request = resolveRequest(attack, record)
    const aggregateHost = String(finding?.evidence?.dast?.aggregate?.scopeHost || '').trim().toLowerCase()
    let scopeHost = aggregateHost
    if (!scopeHost) {
        const rawUrl = String(request?.url || request?.ui_url || request?.target || '').trim()
        try {
            scopeHost = new URL(rawUrl, 'http://localhost').host.toLowerCase()
        } catch (_) {
            scopeHost = ''
        }
    }
    return ruleId && scopeHost ? `passive|scan|${moduleId}|${ruleId}|${scopeHost}` : null
}

export function countDastPresentationAttacks(scanResult = {}) {
    const normalizedFindings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
    const findingLookup = new Map()
    normalizedFindings.forEach((finding) => {
        if (finding?.id !== null && finding?.id !== undefined && finding?.id !== '') {
            findingLookup.set(String(finding.id), finding)
        }
    })

    let records = Array.isArray(scanResult?.requests) ? scanResult.requests : []
    if (!records.length && Array.isArray(scanResult?.items)) {
        records = scanResult.items.map((item, index) => ({
            id: item?.id || `legacy-${index + 1}`,
            original: item?.original || null,
            attacks: Array.isArray(item?.attacks) ? item.attacks : []
        }))
    }
    if (!records.length) {
        const fallback = Number(scanResult?.stats?.attacksCount)
        return Number.isFinite(fallback) && fallback >= 0 ? fallback : 0
    }

    const seenPresentationKeys = new Set()
    let count = 0
    records.forEach((record) => {
        const attacks = Array.isArray(record?.attacks) ? record.attacks : []
        attacks.forEach((attack) => {
            if (!attack || typeof attack !== 'object') return
            const finding = resolveFinding(attack, findingLookup)
            const reconKey = buildReconPresentationKey(attack, finding, record)
            const aggregateMode = resolveAttackAggregateMode(attack, finding)
            if (resolveAttackOutputKind(attack, finding) === 'recon' && aggregateMode !== 'none' && !reconKey) {
                return
            }
            const presentationKey = reconKey || buildPassiveAggregateKey(attack, finding, record)
            if (presentationKey) {
                if (seenPresentationKeys.has(presentationKey)) return
                seenPresentationKeys.add(presentationKey)
            }
            count += 1
        })
    })
    return count
}

export async function captureReportEngineSnapshots(getController, { engines = REPORT_ENGINES, now = () => new Date() } = {}) {
    const capturedAt = now().toISOString()
    const entries = await Promise.all(engines.map(async (engine) => {
        try {
            const controller = await getController(engine)
            const result = await controller.init()
            if (result instanceof Error || result?.success === false) {
                throw new Error(result?.message || result?.error || 'snapshot_unavailable')
            }
            return [engine, {
                captured: true,
                capturedAt,
                scanResult: result?.scanResult ?? null
            }]
        } catch (error) {
            return [engine, {
                captured: true,
                capturedAt,
                scanResult: null,
                error: String(error?.message || 'snapshot_unavailable')
            }]
        }
    }))
    return Object.fromEntries(entries)
}

export async function resolveReportEngineResult({ snapshots = null, engine, loadLive }) {
    const key = normalizeEngine(engine)
    if (snapshots && typeof snapshots === 'object' && Object.prototype.hasOwnProperty.call(snapshots, key)) {
        const snapshot = snapshots[key] || {}
        return {
            scanResult: snapshot.scanResult ?? null,
            reportSnapshot: {
                captured: true,
                capturedAt: snapshot.capturedAt || null,
                error: snapshot.error || null
            }
        }
    }
    return typeof loadLive === 'function' ? loadLive() : { scanResult: null }
}

export { REPORT_ENGINES, REPORT_SEVERITIES }
