function normalizeCatalogRefId(ref) {
  if (typeof ref === "string") return ref.trim()
  if (ref && typeof ref === "object") return String(ref.id || "").trim()
  return ""
}

function collectCatalogRefErrors(rulepack = {}, catalog = {}) {
  const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
  const errors = []

  const catalogBuckets = {
    sources: catalog?.sources || {},
    sinks: catalog?.sinks || {},
    sanitizers: catalog?.sanitizers || {},
    propagators: catalog?.propagators || {}
  }

  function validateRefs(refs, bucketName, ctx) {
    const bucket = catalogBuckets[bucketName] || {}
    const ids = Array.isArray(refs) ? refs : []
    ids.forEach((ref) => {
      const id = normalizeCatalogRefId(ref)
      if (!id) return
      if (bucket[id]) return
      errors.push({
        bucket: bucketName,
        id,
        moduleId: ctx.moduleId || null,
        ruleId: ctx.ruleId || null
      })
    })
  }

  modules.forEach((moduleDef) => {
    const rules = Array.isArray(moduleDef?.rules) ? moduleDef.rules : []
    rules.forEach((ruleDef) => {
      const ctx = {
        moduleId: moduleDef?.id || null,
        ruleId: ruleDef?.id || null
      }
      const detector = ruleDef?.detector && typeof ruleDef.detector === "object" ? ruleDef.detector : {}
      validateRefs(ruleDef?.sources || detector.sources, "sources", ctx)
      validateRefs(ruleDef?.sinks || detector.sinks, "sinks", ctx)
      validateRefs(ruleDef?.sanitizers || detector.sanitizers, "sanitizers", ctx)
      validateRefs(
        ruleDef?.propagate || ruleDef?.propagators || detector.propagators,
        "propagators",
        ctx
      )
    })
  })

  return errors
}

export function validateRulepackCatalogCompatibility(rulepack = {}, catalog = {}) {
  const errors = collectCatalogRefErrors(rulepack, catalog)
  return {
    valid: errors.length === 0,
    errors
  }
}

export function assertRulepackCatalogCompatibility(rulepack = {}, catalog = {}, opts = {}) {
  const result = validateRulepackCatalogCompatibility(rulepack, catalog)
  if (result.valid) return rulepack

  const summary = result.errors
    .map((entry) => `${entry.bucket}:${entry.id} (${entry.moduleId || "module"} / ${entry.ruleId || "rule"})`)
    .join(", ")

  const err = new Error(`[PTK SAST] Unknown catalog references${opts.label ? ` for ${opts.label}` : ""}: ${summary}`)
  err.code = "sast_catalog_refs_invalid"
  err.details = result.errors
  return (() => {
    throw err
  })()
}

export default assertRulepackCatalogCompatibility
