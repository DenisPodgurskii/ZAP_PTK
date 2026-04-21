import { fetchPortalPolicyMetadata, loadPortalRulepack } from "./moduleRegistry.js"

export const PORTAL_POLICY_ENGINES = Object.freeze(["DAST", "SAST", "IAST"])
const PORTAL_POLICY_RUNTIME_STORAGE_KEY = "ptk_portal_policy_runtime_selection_v1"

function cloneValue(value) {
  if (value === undefined) return undefined
  return JSON.parse(JSON.stringify(value))
}

function normalizeText(value) {
  if (value === undefined || value === null) return null
  const text = String(value).trim()
  return text || null
}

function normalizePolicyId(value) {
  const text = normalizeText(value)
  if (!text) return null
  try {
    return BigInt(text) > 0n ? text : null
  } catch (_) {
    return null
  }
}

function normalizeEngine(engine) {
  const text = normalizeText(engine)
  if (!text) return null
  const upper = text.toUpperCase()
  return PORTAL_POLICY_ENGINES.includes(upper) ? upper : null
}

function buildSelectionLabel({ id = null, name = null } = {}) {
  if (name) return name
  if (id) return `Policy #${id}`
  return "Portal policy"
}

function normalizeMetadataEntry(engine, entry = {}) {
  if (!entry || typeof entry !== "object") return null
  const id = normalizePolicyId(entry.id || entry.policyId || entry.value)
  const name = normalizeText(entry.name || entry.policyName || entry.title || entry.label)
  if (!id && !name) return null
  return {
    engine,
    id,
    name,
    label: buildSelectionLabel({ id, name }),
    description: normalizeText(entry.description || entry.summary),
    updatedAt: normalizeText(entry.updatedAt || entry.updated_at || entry.modifiedAt || entry.modified_at)
  }
}

function dedupeMetadata(entries = []) {
  const seen = new Set()
  return entries.filter((entry) => {
    if (!entry) return false
    const key = entry.id || `${entry.engine}:${entry.name || entry.label}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function createEngineState(engine) {
  return {
    engine,
    metadata: [],
    selectedPolicy: null,
    selectedRulepack: null,
    packStatus: null,
    loadedAt: null,
    lastError: null
  }
}

function serializeRuntimeError(err) {
  if (!err) return null
  const code = normalizeText(err.code || err.error || null)
  const message = normalizeText(err.portalMessage || err.message || err.error || null)
  const status = Number.isFinite(Number(err.status)) ? Number(err.status) : null
  if (!code && !message && status == null) return null
  return {
    code,
    message,
    status
  }
}

function classifyPackStatus(err) {
  const code = normalizeText(err?.code || err?.error || "").toLowerCase()
  if (!code) return null
  if (code === "quarantined_schema" || code === "portal_rulepack_invalid_schema" || code === "portal_rulepack_invalid_payload") {
    return "quarantined_schema"
  }
  if (code === "quarantined_extension_version" || code === "portal_rulepack_extension_version_unsupported") {
    return "quarantined_extension_version"
  }
  if (code === "quarantined_schema_features" || code === "portal_rulepack_schema_features_unsupported") {
    return "quarantined_schema_features"
  }
  if (code === "no_compatible_variant" || code === "portal_policy_rulepack_unavailable") {
    return "no_compatible_variant"
  }
  return null
}

function createDefaultStorage() {
  if (typeof browser === "undefined" || !browser?.storage?.local) return null
  return {
    async getItem(key) {
      const result = await browser.storage.local.get(key)
      const value = result?.[key]
      return value && typeof value === "object" ? value : {}
    },
    async setItem(key, value) {
      return browser.storage.local.set({ [key]: value })
    }
  }
}

export class PortalPolicyRuntimeStore {
  constructor({
    fetchMetadataFn = fetchPortalPolicyMetadata,
    loadRulepackFn = loadPortalRulepack,
    storage = createDefaultStorage(),
    storageKey = PORTAL_POLICY_RUNTIME_STORAGE_KEY
  } = {}) {
    this.fetchMetadataFn = fetchMetadataFn
    this.loadRulepackFn = loadRulepackFn
    this.storage = storage
    this.storageKey = storageKey
    this.hydrated = false
    this.hydrationPromise = null
    this.state = Object.fromEntries(
      PORTAL_POLICY_ENGINES.map((engine) => [engine, createEngineState(engine)])
    )
  }

  _getBucket(engine) {
    const safeEngine = normalizeEngine(engine)
    if (!safeEngine) {
      throw new Error(`unsupported_policy_engine:${engine || "unknown"}`)
    }
    return this.state[safeEngine]
  }

  _toPublicState(bucket) {
    return {
      engine: bucket.engine,
      metadata: cloneValue(bucket.metadata) || [],
      selectedPolicy: cloneValue(bucket.selectedPolicy) || null,
      hasSnapshot: !!(bucket.selectedRulepack && Array.isArray(bucket.selectedRulepack.modules)),
      source: bucket.selectedPolicy ? "portal" : "local",
      packStatus: bucket.packStatus || null,
      loadedAt: bucket.loadedAt || null,
      lastError: cloneValue(bucket.lastError) || null
    }
  }

  _toStoragePayload() {
    return Object.fromEntries(
      PORTAL_POLICY_ENGINES.map((engine) => {
        const bucket = this._getBucket(engine)
        return [
          engine.toLowerCase(),
          {
            selectedPolicy: cloneValue(bucket.selectedPolicy) || null
          }
        ]
      })
    )
  }

  async _persistSelections() {
    if (!this.storage?.setItem) return false
    await this.storage.setItem(this.storageKey, this._toStoragePayload())
    return true
  }

  async ensureLoaded({ force = false } = {}) {
    if (this.hydrated && !force) {
      return this.getState()
    }
    if (this.hydrationPromise && !force) {
      return this.hydrationPromise
    }
    this.hydrationPromise = (async () => {
      const persisted = this.storage?.getItem
        ? await this.storage.getItem(this.storageKey)
        : {}
      PORTAL_POLICY_ENGINES.forEach((engine) => {
        const bucket = this._getBucket(engine)
        const storedBucket = persisted?.[engine.toLowerCase()]
        const selected = normalizeMetadataEntry(engine, storedBucket?.selectedPolicy || {}) || null
        bucket.selectedPolicy = selected ? { ...selected } : null
        bucket.selectedRulepack = null
        bucket.packStatus = null
        bucket.lastError = null
      })
      this.hydrated = true
      return this.getState()
    })()
    try {
      return await this.hydrationPromise
    } finally {
      this.hydrationPromise = null
    }
  }

  getState(engine = null) {
    const safeEngine = normalizeEngine(engine)
    if (safeEngine) {
      return this._toPublicState(this._getBucket(safeEngine))
    }
    return Object.fromEntries(
      PORTAL_POLICY_ENGINES.map((name) => [name.toLowerCase(), this._toPublicState(this._getBucket(name))])
    )
  }

  getSelectedPolicy(engine) {
    const bucket = this._getBucket(engine)
    return cloneValue(bucket.selectedPolicy) || null
  }

  getSelectedRulepack(engine) {
    const bucket = this._getBucket(engine)
    return cloneValue(bucket.selectedRulepack) || null
  }

  getRulepackSelection(engine, fallback = {}) {
    const bucket = this._getBucket(engine)
    if (bucket.selectedPolicy) {
      return {
        source: "portal",
        preferPortal: true,
        policyId: bucket.selectedPolicy.id || null,
        policyName: bucket.selectedPolicy.name || null,
        label: bucket.selectedPolicy.label || buildSelectionLabel(bucket.selectedPolicy)
      }
    }
    return {
      source: fallback.source || "local",
      preferPortal: false,
      policyId: null,
      policyName: null,
      label: fallback.label || "Built-in rulepack"
    }
  }

  async loadMetadata({ apiKey, engine = null } = {}) {
    await this.ensureLoaded()
    const safeEngine = normalizeEngine(engine)
    const metadata = await this.fetchMetadataFn({
      apiKey,
      engine: safeEngine || undefined
    })
    const now = new Date().toISOString()
    if (!metadata || typeof metadata !== "object") {
      throw new Error("portal_policy_metadata_unavailable")
    }

    const enginesToUpdate = safeEngine ? [safeEngine] : PORTAL_POLICY_ENGINES
    enginesToUpdate.forEach((engineName) => {
      const bucket = this._getBucket(engineName)
      const rawEntries = Array.isArray(metadata[engineName.toLowerCase()]) ? metadata[engineName.toLowerCase()] : []
      bucket.metadata = dedupeMetadata(
        rawEntries
          .map((entry) => normalizeMetadataEntry(engineName, entry))
          .filter(Boolean)
      )
      bucket.loadedAt = now
      if (!bucket.selectedRulepack && !bucket.packStatus) {
        bucket.packStatus = null
        bucket.lastError = null
      }
      if (bucket.selectedPolicy?.id) {
        const matching = bucket.metadata.find((entry) => entry.id === bucket.selectedPolicy.id)
        if (matching) {
          bucket.selectedPolicy = { ...matching }
        } else {
          bucket.selectedPolicy = null
          bucket.selectedRulepack = null
          bucket.packStatus = null
        }
      }
    })

    return this.getState(safeEngine)
  }

  async selectPolicy({ engine, policyId, policyName = null, apiKey = null } = {}) {
    await this.ensureLoaded()
    const bucket = this._getBucket(engine)
    const normalizedId = normalizePolicyId(policyId)
    if (!normalizedId) {
      throw new Error("invalid_policy_id")
    }
    const normalizedSelection = normalizeMetadataEntry(bucket.engine, {
      id: normalizedId,
      name: policyName
    }) || {
      engine: bucket.engine,
      id: normalizedId,
      name: normalizeText(policyName),
      label: buildSelectionLabel({ id: normalizedId, name: normalizeText(policyName) }),
      description: null,
      updatedAt: null
    }

    if (bucket.selectedPolicy?.id !== normalizedSelection.id) {
      bucket.selectedRulepack = null
      bucket.packStatus = null
    }
    bucket.selectedPolicy = normalizedSelection
    bucket.lastError = null
    if (normalizedSelection.id && !bucket.metadata.some((entry) => entry.id === normalizedSelection.id)) {
      bucket.metadata = dedupeMetadata(bucket.metadata.concat([{ ...normalizedSelection }]))
    }
    if (normalizeText(apiKey)) {
      try {
        await this.resolveRulepackForRun({
          apiKey,
          engine: bucket.engine,
          policyId: normalizedSelection.id,
          policyName: normalizedSelection.name || null
        })
        return this.getState(bucket.engine)
      } catch (err) {
        await this._persistSelections()
        throw err
      }
    }
    await this._persistSelections()
    return this.getState(bucket.engine)
  }

  async resolveRulepackForRun({ apiKey, engine, policyId = null, policyName = null } = {}) {
    await this.ensureLoaded()
    const bucket = this._getBucket(engine)
    const effectivePolicyId = normalizePolicyId(policyId || bucket.selectedPolicy?.id || null)
    if (!effectivePolicyId) {
      return {
        rulepack: null,
        selection: this.getRulepackSelection(bucket.engine)
      }
    }
    const rulepack = await this.loadRulepackFn(bucket.engine, {
      apiKey,
      policyId: effectivePolicyId
    }).catch((err) => {
      bucket.selectedRulepack = null
      bucket.packStatus = classifyPackStatus(err)
      bucket.lastError = serializeRuntimeError(err)
      throw err
    })
    if (!rulepack || typeof rulepack !== "object") {
      const err = new Error("portal_policy_rulepack_unavailable")
      err.code = "portal_policy_rulepack_unavailable"
      bucket.selectedRulepack = null
      bucket.packStatus = classifyPackStatus(err)
      bucket.lastError = serializeRuntimeError(err)
      throw err
    }
    const policyMeta = rulepack.policy && typeof rulepack.policy === "object" ? rulepack.policy : {}
    const normalizedSelection = normalizeMetadataEntry(bucket.engine, {
      id: policyMeta.id || effectivePolicyId,
      name: policyMeta.name || policyName || bucket.selectedPolicy?.name || null
    }) || {
      engine: bucket.engine,
      id: effectivePolicyId,
      name: normalizeText(policyName || bucket.selectedPolicy?.name),
      label: buildSelectionLabel({
        id: effectivePolicyId,
        name: normalizeText(policyName || bucket.selectedPolicy?.name)
      }),
      description: null,
      updatedAt: null
    }
    bucket.selectedPolicy = normalizedSelection
    bucket.selectedRulepack = cloneValue(rulepack)
    bucket.packStatus = "active"
    bucket.lastError = null
    if (normalizedSelection.id && !bucket.metadata.some((entry) => entry.id === normalizedSelection.id)) {
      bucket.metadata = dedupeMetadata(bucket.metadata.concat([{ ...normalizedSelection }]))
    }
    await this._persistSelections()
    return {
      rulepack: cloneValue(rulepack),
      selection: this.getRulepackSelection(bucket.engine)
    }
  }

  clearPolicy(engine) {
    const bucket = this._getBucket(engine)
    bucket.selectedPolicy = null
    bucket.selectedRulepack = null
    bucket.packStatus = null
    bucket.lastError = null
    void this._persistSelections()
    return this.getState(bucket.engine)
  }

  clearAll() {
    PORTAL_POLICY_ENGINES.forEach((engine) => {
      this.clearPolicy(engine)
    })
    return this.getState()
  }
}

export const portalPolicyRuntimeStore = new PortalPolicyRuntimeStore()

export function normalizePortalPolicyEngine(engine) {
  return normalizeEngine(engine)
}
