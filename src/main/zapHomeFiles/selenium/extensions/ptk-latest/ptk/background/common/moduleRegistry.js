import { loadCanonicalDastRulepack } from "../dast/contract/index.js"
import { loadCanonicalSastRulepack } from "../sast/contract/index.js"
import { loadCanonicalIastRulepack } from "../iast/contract/index.js"

const runtimeAPI =
  typeof browser !== "undefined"
    ? browser
    : typeof chrome !== "undefined"
      ? chrome
      : null

const RULEPACK_CHILD_KEY = {
  DAST: "attacks",
  SAST: "rules",
  IAST: "rules"
}

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

function isAcceptedRulepackSchema(engine, schema) {
  if (!schema) return true
  const accepted = ACCEPTED_RULEPACK_SCHEMAS[String(engine || "").toUpperCase()]
  return accepted ? accepted.has(schema) : true
}

async function fetchRulepackFromPath(path, expectedEngine) {
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

function buildPortalPoliciesUrl(engine, opts = {}) {
  const baseUrl = String(opts.baseUrl || "").trim().replace(/\/+$/, "")
  if (!baseUrl) return null
  let apiBase = normalizePathFragment(opts.apiBase, "/api/v1").replace(/\/+$/, "")
  const endpoint = normalizePathFragment(opts.policiesEndpoint, "/policies")
  const url = new URL(`${baseUrl}${apiBase}${endpoint}`)
  url.searchParams.set("engine", String(engine || "").trim().toUpperCase())
  url.searchParams.set("includeSelections", "true")
  if (opts.policyId !== undefined && opts.policyId !== null && opts.policyId !== "") {
    url.searchParams.set("policyId", String(opts.policyId).trim())
  }
  return url.toString()
}

function extractPoliciesFromPortalResponse(engine, payload) {
  if (!payload || typeof payload !== "object") return []
  const data = payload.data && typeof payload.data === "object" ? payload.data : payload
  const bucket = data?.[String(engine || "").toLowerCase()]
  return Array.isArray(bucket) ? bucket : []
}

function clonePortalModules(modules, childKey) {
  if (!Array.isArray(modules)) return []
  return modules
    .filter((moduleDef) => moduleDef && typeof moduleDef === "object")
    .map((moduleDef) => {
      const next = JSON.parse(JSON.stringify(moduleDef))
      const children = Array.isArray(next?.[childKey]) ? next[childKey] : []
      next[childKey] = children
      return next
    })
}

function clonePortalValue(value, fallback = null) {
  if (value === undefined) return fallback
  try {
    return JSON.parse(JSON.stringify(value))
  } catch (_) {
    return fallback
  }
}

function filterActiveIastRules(modules) {
  return clonePortalModules(modules, "rules")
    .map((moduleDef) => {
      const rules = Array.isArray(moduleDef?.rules) ? moduleDef.rules : []
      moduleDef.rules = rules
        .filter((ruleDef) => {
          const status = String(ruleDef?.status || "").trim().toLowerCase()
          return !status || status === "active"
        })
        .map((ruleDef) => {
          const next = JSON.parse(JSON.stringify(ruleDef))
          if (next && typeof next === "object" && !Array.isArray(next)) {
            delete next.status
          }
          return next
        })
      return moduleDef
    })
    .filter((moduleDef) => Array.isArray(moduleDef?.rules) && moduleDef.rules.length > 0)
}

function selectPortalPolicy(policies, opts = {}) {
  if (!Array.isArray(policies) || !policies.length) return null

  const requestedId = opts.policyId !== undefined && opts.policyId !== null && opts.policyId !== ""
    ? String(opts.policyId).trim()
    : ""
  if (requestedId) {
    return policies.find((policy) => String(policy?.id || "").trim() === requestedId) || null
  }

  const requestedName = String(opts.policyName || "").trim().toLowerCase()
  if (requestedName) {
    return policies.find((policy) => String(policy?.name || "").trim().toLowerCase() === requestedName) || null
  }

  if (policies.length === 1) return policies[0]
  return null
}

function buildPortalRulepack(engine, policy) {
  const childKey = RULEPACK_CHILD_KEY[engine] || "rules"
  const engineName = String(engine || "").toUpperCase()
  const modules = engineName === "IAST"
    ? filterActiveIastRules(policy?.modules)
    : clonePortalModules(policy?.modules, childKey)
  const customModules = engineName === "SAST"
    ? clonePortalModules(policy?.custom_modules, childKey)
    : []
  const effectiveModules = engineName === "SAST"
    ? (modules.length ? modules : customModules)
    : modules
  if (!effectiveModules.length) return null
  const baseRulepack = {
    schema: engineName === "SAST" ? "ptk-sast-rulepack/v1" : "ptk-modules-v1",
    engine,
    version: 1,
    policy: {
      id: policy?.id ? String(policy.id) : null,
      name: policy?.name || null,
      description: policy?.description || null,
      updated_at: policy?.updated_at || null
    },
    modules: effectiveModules
  }
  if (engineName === "DAST") {
    return loadCanonicalDastRulepack(baseRulepack, {
      label: `portal-policy:${policy?.id || policy?.name || "single"}`
    })
  }
  if (engineName === "IAST") {
    return loadCanonicalIastRulepack(baseRulepack, {
      label: `portal-policy:${policy?.id || policy?.name || "single"}`
    })
  }
  if (engineName === "SAST") {
    if (policy?.policy_model) {
      baseRulepack.policy_model = String(policy.policy_model)
    }
    if (policy?.contract && typeof policy.contract === "object" && !Array.isArray(policy.contract)) {
      baseRulepack.contract = clonePortalValue(policy.contract, {})
    }
    if (policy?.builtin_selection && typeof policy.builtin_selection === "object" && !Array.isArray(policy.builtin_selection)) {
      baseRulepack.builtin_selection = clonePortalValue(policy.builtin_selection, {})
    }
    if (customModules.length) {
      baseRulepack.custom_modules = customModules
    }
    return loadCanonicalSastRulepack(baseRulepack, {
      label: `portal-policy:${policy?.id || policy?.name || "single"}`
    })
  }
  return baseRulepack
}

/**
 * Load a rulepack from PTK Portal policies API.
 * @param {"DAST"|"SAST"|"IAST"} engine
 * @param {object} [opts]
 * @returns {Promise<object|null>}
 */
export async function loadPortalRulepack(engine, opts = {}) {
  const apiKey = String(opts.apiKey || opts.token || "").trim()
  if (!apiKey) return null

  const fetchImpl = getFetchImplementation(opts.fetchFn)
  if (!fetchImpl) return null

  const url = buildPortalPoliciesUrl(engine, opts)
  if (!url) return null

  try {
    const response = await fetchImpl(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: "application/json"
      },
      cache: "no-cache"
    })
    if (!response?.ok) {
      throw new Error(`portal_rulepack_fetch_failed:${response?.status || "unknown"}`)
    }
    const payload = await response.json().catch(() => null)
    const policies = extractPoliciesFromPortalResponse(engine, payload)
    const selected = selectPortalPolicy(policies, opts)
    if (!selected) {
      return null
    }
    const rulepack = buildPortalRulepack(engine, selected)
    if (!rulepack) {
      return null
    }
    return rulepack
  } catch (err) {
    console.warn("[PTK] Failed to load portal rulepack", {
      engine,
      error: err?.message || String(err)
    })
    return null
  }
}

/**
 * Unified rulepack loader that can later prefer Portal rulepacks.
 * @param {"DAST"|"SAST"|"IAST"} engine
 * @param {object} [opts]
 * @returns {Promise<object>}
 */
export async function loadRulepack(engine, opts = {}) {
  if (opts?.preferPortal) {
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
