import { loadCanonicalDastRulepack } from "../dast/contract/index.js"
import { loadCanonicalSastRulepack } from "../sast/contract/index.js"
import { loadCanonicalIastRulepack } from "../iast/contract/index.js"
import {
  buildPortalUrl,
  getPortalBaseUrl,
  initializePortalRuntimeConfig
} from "../../common/portalConfig.js"

const runtimeAPI =
  typeof browser !== "undefined"
    ? browser
    : typeof chrome !== "undefined"
      ? chrome
      : null

const LOCAL_RULEPACK_PATHS = {
  DAST: "ptk/background/dast/modules/modules.json",
  SAST: "ptk/background/sast/modules/modules.json",
  IAST: "ptk/background/iast/modules/modules.json"
}

const LOCAL_RULEPACK_VARIANTS = {
  DAST: {
    cve: "ptk/background/dast/modules/modules_cve.json"
  },
  IAST: {
    // The shipped extension baseline for IAST already lives in modules.json.
    // Keep "free" as an explicit alias so callers can request it without
    // depending on a separate on-disk modules_free.json artifact.
    free: "ptk/background/iast/modules/modules.json"
  }
}

const ACCEPTED_RULEPACK_SCHEMAS = {
  DAST: new Set(["ptk-dast-rulepack/v1"]),
  SAST: new Set(["ptk-modules-v1", "ptk-sast-rulepack/v1"]),
  IAST: new Set(["ptk-modules-v1", "ptk-iast-rulepack/v1"])
}

const SUPPORTED_SHARED_SCHEMA_FEATURES = new Set()

function isAcceptedRulepackSchema(engine, schema) {
  if (!schema) return true
  const accepted = ACCEPTED_RULEPACK_SCHEMAS[String(engine || "").toUpperCase()]
  return accepted ? accepted.has(schema) : true
}

function normalizeSharedText(value) {
  if (value === undefined || value === null) return ""
  return String(value).trim()
}

function normalizeSharedFeatureList(values) {
  if (!Array.isArray(values)) return []
  const seen = new Set()
  return values
    .map((value) => normalizeSharedText(value))
    .filter((value) => {
      if (!value || seen.has(value)) return false
      seen.add(value)
      return true
    })
}

function parseVersionSegments(value) {
  const text = normalizeSharedText(value)
  if (!text) return []
  return text.split(".").map((segment) => {
    const match = String(segment).match(/^(\d+)/)
    return match ? Number(match[1]) : 0
  })
}

function compareExtensionVersions(left, right) {
  const leftParts = parseVersionSegments(left)
  const rightParts = parseVersionSegments(right)
  const maxLength = Math.max(leftParts.length, rightParts.length)
  for (let index = 0; index < maxLength; index += 1) {
    const a = Number(leftParts[index] || 0)
    const b = Number(rightParts[index] || 0)
    if (a > b) return 1
    if (a < b) return -1
  }
  return 0
}

function getCurrentExtensionVersion(opts = {}) {
  const explicit = normalizeSharedText(opts.extensionVersion)
  if (explicit) return explicit
  try {
    return normalizeSharedText(runtimeAPI?.runtime?.getManifest?.()?.version)
  } catch (_) {
    return ""
  }
}

function getSupportedSharedSchemaFeatures(opts = {}) {
  if (Array.isArray(opts.supportedSchemaFeatures)) {
    return normalizeSharedFeatureList(opts.supportedSchemaFeatures)
  }
  return Array.from(SUPPORTED_SHARED_SCHEMA_FEATURES)
}

function buildRulepackCompatibilityError(code, message, extras = {}) {
  const err = new Error(normalizeSharedText(message) || normalizeSharedText(code) || "rulepack_compatibility_error")
  err.code = normalizeSharedText(code) || "rulepack_compatibility_error"
  Object.assign(err, extras)
  return err
}

function assertSharedRulepackCompatibility(rulepack, opts = {}) {
  if (!rulepack || typeof rulepack !== "object" || Array.isArray(rulepack)) return

  const minExtensionVersion = normalizeSharedText(rulepack.minExtensionVersion)
  const currentExtensionVersion = getCurrentExtensionVersion(opts)
  if (minExtensionVersion) {
    if (!currentExtensionVersion || compareExtensionVersions(currentExtensionVersion, minExtensionVersion) < 0) {
      throw buildRulepackCompatibilityError(
        "quarantined_extension_version",
        `[PTK] Rulepack requires extension version ${minExtensionVersion} or newer`,
        {
          minExtensionVersion,
          currentExtensionVersion: currentExtensionVersion || null
        }
      )
    }
  }

  const requiredSchemaFeatures = normalizeSharedFeatureList(rulepack.requiresSchemaFeatures)
  if (requiredSchemaFeatures.length) {
    const supportedFeatures = new Set(getSupportedSharedSchemaFeatures(opts))
    const missingSchemaFeatures = requiredSchemaFeatures.filter((feature) => !supportedFeatures.has(feature))
    if (missingSchemaFeatures.length) {
      throw buildRulepackCompatibilityError(
        "quarantined_schema_features",
        `[PTK] Rulepack requires unsupported schema features: ${missingSchemaFeatures.join(", ")}`,
        {
          requiredSchemaFeatures,
          missingSchemaFeatures,
          supportedSchemaFeatures: Array.from(supportedFeatures)
        }
      )
    }
  }
}

async function fetchRulepackFromPath(path, expectedEngine, opts = {}) {
  if (!path) {
    throw new Error(`[PTK] Missing rulepack path for ${expectedEngine || 'unknown'} engine`)
  }
  if (!runtimeAPI?.runtime?.getURL) {
    throw new Error("[PTK] runtime.getURL unavailable to load rulepack")
  }

  const url = runtimeAPI.runtime.getURL(path)
  const resp = await fetch(url)
  if (!resp.ok) {
    throw new Error(
      `[PTK] Failed to load local rulepack for ${expectedEngine || 'engine'} from ${path}: ${resp.status}`
    )
  }

  const rulepack = await resp.json()
  if (!rulepack || typeof rulepack !== "object") {
    throw new Error(`[PTK] Local rulepack for ${expectedEngine || 'engine'} is not an object`)
  }

  if (expectedEngine && rulepack.engine && rulepack.engine !== expectedEngine) {
    console.warn("[PTK] Local rulepack engine mismatch", {
      expected: expectedEngine,
      actual: rulepack.engine
    })
  }

  if (!isAcceptedRulepackSchema(expectedEngine, rulepack.schema)) {
    console.warn("[PTK] Local rulepack schema mismatch", {
      expected: Array.from(ACCEPTED_RULEPACK_SCHEMAS[String(expectedEngine || "").toUpperCase()] || ["ptk-modules-v1"]),
      actual: rulepack.schema
    })
  }

  if (!Array.isArray(rulepack.modules)) {
    console.warn("[PTK] Local rulepack modules is not an array for", expectedEngine)
  }

  assertSharedRulepackCompatibility(rulepack, opts)

  return rulepack
}

/**
 * Load a rulepack from the packaged extension files.
 * @param {"DAST"|"SAST"|"IAST"} engine
 * @returns {Promise<object>}
 */
export async function loadLocalRulepack(engine) {
  const path = LOCAL_RULEPACK_PATHS[engine]
  if (!path) {
    throw new Error(`[PTK] Unsupported engine for local rulepack: ${engine}`)
  }
  return fetchRulepackFromPath(path, engine)
}

async function loadLocalRulepackVariant(engine, variant) {
  const variants = LOCAL_RULEPACK_VARIANTS[engine]
  const path = variants?.[variant]
  if (!path) {
    throw new Error(`[PTK] Unsupported rulepack variant "${variant}" for engine ${engine}`)
  }
  return fetchRulepackFromPath(path, engine)
}

function getFetchImplementation(fetchFn) {
  if (typeof fetchFn === "function") return fetchFn
  if (typeof fetch === "function") return fetch
  return null
}

function normalizePathFragment(value, fallback = "") {
  const trimmed = String(value || "").trim()
  if (!trimmed) return fallback
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`
}

function normalizePortalEngine(engine) {
  const normalized = String(engine || "").trim().toUpperCase()
  if (normalized === "DAST" || normalized === "SAST" || normalized === "IAST") {
    return normalized
  }
  return null
}

function buildPortalPoliciesUrl(opts = {}) {
  const baseUrl = String(opts.baseUrl || "").trim() || getPortalBaseUrl()
  return buildPortalUrl(
    normalizePathFragment(opts.policiesEndpoint, "/policies"),
    {
      baseUrl,
      apiBase: normalizePathFragment(opts.apiBase, "/api/v1")
    }
  )
}

function normalizePortalPolicyId(value) {
  if (value === undefined || value === null) return ""
  const trimmed = String(value).trim()
  if (!trimmed) return ""
  try {
    return BigInt(trimmed) > 0n ? trimmed : ""
  } catch (_) {
    return ""
  }
}

function buildPortalPolicyDownloadUrl(opts = {}) {
  const basePoliciesUrl = buildPortalPoliciesUrl(opts)
  if (!basePoliciesUrl) return null
  const policyId = normalizePortalPolicyId(opts.policyId)
  if (!policyId) return null
  return new URL(`${basePoliciesUrl.replace(/\/+$/, "")}/${encodeURIComponent(policyId)}`).toString()
}

function normalizePortalMetadataResponse(payload) {
  const data = payload && typeof payload === "object" && payload.data && typeof payload.data === "object"
    ? payload.data
    : payload
  return {
    dast: Array.isArray(data?.dast) ? data.dast : [],
    sast: Array.isArray(data?.sast) ? data.sast : [],
    iast: Array.isArray(data?.iast) ? data.iast : []
  }
}

async function parsePortalResponseBody(response) {
  if (!response) return null
  if (typeof response.text === "function") {
    const text = await response.text().catch(() => "")
    if (!text) return null
    try {
      return JSON.parse(text)
    } catch (_) {
      return { message: text }
    }
  }
  if (typeof response.json === "function") {
    return response.json().catch(() => null)
  }
  return null
}

function buildPortalRequestError(defaultCode, response, payload = null) {
  const errorCode = String(payload?.error || defaultCode || "portal_request_failed").trim()
  const errorMessage = String(payload?.message || errorCode).trim() || errorCode
  const err = new Error(errorMessage)
  err.code = errorCode
  err.status = Number(response?.status || 0) || null
  err.portalMessage = errorMessage
  return err
}

function buildPortalRulepackError(defaultCode, err, extras = {}) {
  const code = String(err?.code || defaultCode || "portal_rulepack_invalid").trim() || "portal_rulepack_invalid"
  const message = String(err?.portalMessage || err?.message || code).trim() || code
  const wrapped = new Error(message)
  wrapped.code = code
  wrapped.portalMessage = message
  if (Number.isFinite(Number(extras?.status || err?.status))) {
    wrapped.status = Number(extras?.status || err?.status)
  } else {
    wrapped.status = null
  }
  return wrapped
}

function normalizePortalRulepack(engine, rulepack, policyId = null) {
  const engineName = String(engine || "").toUpperCase()
  if (!rulepack || typeof rulepack !== "object" || Array.isArray(rulepack)) {
    throw buildPortalRulepackError("portal_rulepack_invalid_payload", new Error("Portal rulepack payload must be an object"))
  }
  try {
    if (engineName === "DAST") {
      return loadCanonicalDastRulepack(rulepack, {
        label: `portal-policy:${policyId || "selected"}`
      })
    }
    if (engineName === "IAST") {
      return loadCanonicalIastRulepack(rulepack, {
        label: `portal-policy:${policyId || "selected"}`
      })
    }
    if (engineName === "SAST") {
      return loadCanonicalSastRulepack(rulepack, {
        label: `portal-policy:${policyId || "selected"}`
      })
    }
  } catch (err) {
    throw buildPortalRulepackError("portal_rulepack_invalid_schema", err)
  }
  return rulepack
}

/**
 * Fetch portal policy metadata for one engine or all engines.
 * When `opts.engine` is provided, the response contains only that engine bucket.
 * @param {object} [opts]
 * @returns {Promise<object|null>}
 */
export async function fetchPortalPolicyMetadata(opts = {}) {
  await initializePortalRuntimeConfig()
  const apiKey = String(opts.apiKey || opts.token || "").trim()
  if (!apiKey) return null

  const fetchImpl = getFetchImplementation(opts.fetchFn)
  if (!fetchImpl) return null

  const url = buildPortalPoliciesUrl(opts)
  if (!url) return null

  const safeEngine = normalizePortalEngine(opts.engine)
  const headers = {
    Authorization: `Bearer ${apiKey}`,
    Accept: "application/json"
  }
  const init = {
    method: "POST",
    headers,
    cache: "no-cache",
    credentials: "omit"
  }
  if (safeEngine) {
    headers["Content-Type"] = "application/json"
    init.body = JSON.stringify({ engine: safeEngine })
  }

  try {
    const response = await fetchImpl(url, init)
    if (!response?.ok) {
      const payload = await parsePortalResponseBody(response)
      throw buildPortalRequestError("portal_policy_metadata_fetch_failed", response, payload)
    }
    const payload = await parsePortalResponseBody(response)
    const metadata = normalizePortalMetadataResponse(payload)
    if (!safeEngine) return metadata
    const engineBucket = String(safeEngine).toLowerCase()
    return { [engineBucket]: metadata[engineBucket] }
  } catch (err) {
    console.warn("[PTK] Failed to fetch portal policy metadata", {
      engine: safeEngine || null,
      error: err?.portalMessage || err?.message || String(err),
      code: err?.code || null,
      status: err?.status || null
    })
    throw err
  }
}

/**
 * Download a rulepack snapshot from PTK Portal policy download API.
 * @param {"DAST"|"SAST"|"IAST"} engine
 * @param {object} [opts]
 * @returns {Promise<object|null>}
 */
export async function loadPortalRulepack(engine, opts = {}) {
  await initializePortalRuntimeConfig()
  const apiKey = String(opts.apiKey || opts.token || "").trim()
  if (!apiKey) return null

  const fetchImpl = getFetchImplementation(opts.fetchFn)
  if (!fetchImpl) return null

  const policyId = normalizePortalPolicyId(opts.policyId)
  if (!policyId) return null

  const url = buildPortalPolicyDownloadUrl({ ...opts, policyId })
  if (!url) return null

  const extensionVersion = getCurrentExtensionVersion(opts)
  const supportedSchemaFeatures = getSupportedSharedSchemaFeatures(opts)
  const headers = {
    Authorization: `Bearer ${apiKey}`,
    Accept: "application/json"
  }
  if (extensionVersion) {
    headers["X-PTK-Extension-Version"] = extensionVersion
  }
  if (supportedSchemaFeatures.length) {
    headers["X-PTK-Schema-Features"] = supportedSchemaFeatures.join(",")
  }

  try {
    const response = await fetchImpl(url, {
      method: "GET",
      headers,
      cache: "no-cache",
      credentials: "omit"
    })
    if (!response?.ok) {
      const payload = await parsePortalResponseBody(response)
      throw buildPortalRequestError("portal_rulepack_fetch_failed", response, payload)
    }
    const payload = await parsePortalResponseBody(response)
    assertSharedRulepackCompatibility(payload, opts)

    let rulepack = null
    try {
      rulepack = normalizePortalRulepack(engine, payload, policyId)
    } catch (err) {
      throw buildPortalRulepackError("quarantined_schema", err)
    }
    if (!rulepack) {
      return null
    }
    return rulepack
  } catch (err) {
    console.warn("[PTK] Failed to load portal rulepack", {
      engine,
      policyId,
      error: err?.portalMessage || err?.message || String(err),
      code: err?.code || null,
      status: err?.status || null
    })
    throw err
  }
}

/**
 * Unified rulepack loader that can later prefer Portal rulepacks.
 * @param {"DAST"|"SAST"|"IAST"} engine
 * @param {object} [opts]
 * @returns {Promise<object>}
 */
export async function loadRulepack(engine, opts = {}) {
  if (opts?.preferPortal && normalizePortalPolicyId(opts.policyId)) {
    const portalRulepack = await loadPortalRulepack(engine, opts)
    if (portalRulepack) {
      return portalRulepack
    }
  }
  if (opts?.variant) {
    return loadLocalRulepackVariant(engine, opts.variant)
  }
  return loadLocalRulepack(engine)
}

export async function loadCanonicalRulepack(engine, opts = {}) {
  const rulepack = await loadRulepack(engine, opts)
  if (String(engine || "").toUpperCase() === "DAST") {
    return loadCanonicalDastRulepack(rulepack, {
      label: opts?.variant ? `DAST:${opts.variant}` : "DAST"
    })
  }
  if (String(engine || "").toUpperCase() === "SAST") {
    return loadCanonicalSastRulepack(rulepack, {
      label: opts?.variant ? `SAST:${opts.variant}` : "SAST"
    })
  }
  if (String(engine || "").toUpperCase() === "IAST") {
    return loadCanonicalIastRulepack(rulepack, {
      label: opts?.variant ? `IAST:${opts.variant}` : "IAST"
    })
  }
  return rulepack
}
