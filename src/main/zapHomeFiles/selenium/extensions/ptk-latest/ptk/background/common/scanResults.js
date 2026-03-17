const DEFAULT_VERSION = '1.0'

function getToolVersion() {
  try {
    const manifest = typeof browser !== "undefined" && browser?.runtime?.getManifest
      ? browser.runtime.getManifest()
      : null
    return manifest?.version || "unknown"
  } catch (_) {
    return "unknown"
  }
}

/**
 * Create a shared scan-result envelope used by all engines.
 * Keeps legacy fields (items[]) so existing UI continues to render.
 */
export function createScanResultEnvelope({ engine, scanId, host, tabId, startedAt, settings } = {}) {
  return {
    version: DEFAULT_VERSION,
    type: 'scan_result',
    engine: engine || null,
    scanId: scanId || null,
    host: host || null,
    tabId: typeof tabId === 'undefined' ? null : tabId,
    startedAt: startedAt || new Date().toISOString(),
    finishedAt: null,
    settings: settings || {},
    toolVersion: getToolVersion(),

    stats: {
      findingsCount: 0,
      attacksCount: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },

    findings: [],
    groups: [],
    codeArtifacts: {
      sast: {
        version: 2,
        routes: [],
        endpoints: [],
        graphql: [],
        surfaces: [],
        hiddenParams: [],
        gadgets: []
      }
    },

    // Legacy field set preserved for backward compatibility with current UI.
    items: []
  }
}

/**
 * Normalize severity strings to low/medium/high/info.
 */
export function normalizeSeverity(severity) {
  if (!severity) return 'medium'
  const s = ('' + severity).toLowerCase()
  if (s === 'critical') return 'critical'
  if (s === 'high') return 'high'
  if (s === 'medium') return 'medium'
  if (s === 'low') return 'low'
  if (s === 'info' || s === 'informational') return 'info'
  return 'medium'
}

/**
 * Update stats counters for a given severity.
 */
export function bumpStatsForSeverity(stats = {}, severity) {
  const normalized = normalizeSeverity(severity)
  stats.findingsCount = (stats.findingsCount || 0) + 1
  stats[normalized] = (stats[normalized] || 0) + 1
  return stats
}

/**
 * Append a finding to the envelope and update stats.
 */
export function addFinding(envelope, finding) {
  if (!envelope || !finding) return
  if (!Array.isArray(envelope.findings)) {
    envelope.findings = []
  }
  envelope.findings.push(finding)
  bumpStatsForSeverity(envelope.stats, finding.severity)
}

function buildGroupId(finding, meta = {}) {
  if (meta.signature) return meta.signature
  const runtimeUrl = meta.runtimeUrl ?? finding?.location?.runtimeUrl ?? finding?.location?.url ?? null
  const parts = [
    finding.engine || 'engine',
    finding.vulnId || 'vuln',
    meta.url ?? runtimeUrl ?? '',
    meta.file ?? finding?.location?.file ?? '',
    meta.param ?? finding?.location?.param ?? '',
    meta.sink ?? ''
  ]
  return parts.join('@@')
}

/**
 * Add a finding occurrence into a deduped group.
 * groupMeta can include url/file/param/sink overrides or a signature string.
 */
export function addFindingToGroup(envelope, finding, groupId, groupMeta = {}) {
  if (!envelope || !finding) return
  const id = groupId || buildGroupId(finding, groupMeta)
  if (!Array.isArray(envelope.groups)) {
    envelope.groups = []
  }
  let group = envelope.groups.find(g => g.id === id)
  if (!group) {
    const runtimeUrl = groupMeta.runtimeUrl ?? finding?.location?.runtimeUrl ?? finding?.location?.url ?? null
    group = {
      id,
      engine: finding.engine,
      scanId: finding.scanId,
      vulnId: finding.vulnId,
      category: finding.category,
      severity: finding.severity,
      correlationKey: finding.correlationKey || null,
      location: {
        url: groupMeta.url ?? runtimeUrl ?? null,
        runtimeUrl: runtimeUrl,
        file: groupMeta.file ?? finding?.location?.file ?? null,
        param: groupMeta.param ?? finding?.location?.param ?? null,
        sink: groupMeta.sink ?? finding?.location?.sink ?? null
      },
      occurrenceIds: [],
      count: 0
    }
    envelope.groups.push(group)
  }
  const occurrenceId = finding.id || `${finding.engine || 'fx'}@@${group.occurrenceIds.length + 1}`
  group.occurrenceIds.push(occurrenceId)
  group.count = group.occurrenceIds.length
}
