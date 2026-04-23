import {
  formatValidationFailure,
  isNonEmptyString,
  isPlainObject,
  pushRequiredError,
  pushTypeError
} from "../../common/simpleRulepackValidation.js"

function contextFor(moduleId = null, ruleId = null) {
  return {
    moduleId: moduleId || null,
    ruleId: ruleId || null
  }
}

function validateModule(moduleDef, index, errors) {
  const path = `/modules/${index}`
  const ctx = contextFor(moduleDef?.id || null, null)
  if (!isPlainObject(moduleDef)) {
    pushTypeError(errors, path, "object", ctx)
    return
  }
  if (!isNonEmptyString(moduleDef.id)) pushRequiredError(errors, path, "id", ctx)
  if (!isNonEmptyString(moduleDef.type)) pushRequiredError(errors, path, "type", ctx)
  if (typeof moduleDef.async !== "boolean") pushRequiredError(errors, path, "async", ctx)
  if (!isNonEmptyString(moduleDef.name)) pushRequiredError(errors, path, "name", ctx)
  if (!isPlainObject(moduleDef.metadata)) pushRequiredError(errors, path, "metadata", ctx)
  if (!Array.isArray(moduleDef.rules)) {
    pushRequiredError(errors, path, "rules", ctx)
    return
  }
  moduleDef.rules.forEach((ruleDef, ruleIndex) => {
    const rulePath = `${path}/rules/${ruleIndex}`
    const ruleCtx = contextFor(moduleDef.id, ruleDef?.id || null)
    if (!isPlainObject(ruleDef)) {
      pushTypeError(errors, rulePath, "object", ruleCtx)
      return
    }
    if (!isNonEmptyString(ruleDef.id)) pushRequiredError(errors, rulePath, "id", ruleCtx)
    if (!isNonEmptyString(ruleDef.name)) pushRequiredError(errors, rulePath, "name", ruleCtx)
    if (!isNonEmptyString(ruleDef.mode)) pushRequiredError(errors, rulePath, "mode", ruleCtx)
    if (!isPlainObject(ruleDef.metadata)) pushRequiredError(errors, rulePath, "metadata", ruleCtx)
    if (!isPlainObject(ruleDef.detector)) pushRequiredError(errors, rulePath, "detector", ruleCtx)
  })
}

export function validateSastRulepack(rulepack) {
  const errors = []
  if (!isPlainObject(rulepack)) {
    pushTypeError(errors, "/", "object")
    return { valid: false, errors }
  }
  if (rulepack.schema !== "ptk-sast-rulepack/v1") pushRequiredError(errors, "/", "schema")
  if (rulepack.engine !== "SAST") pushRequiredError(errors, "/", "engine")
  if (rulepack.version !== 1) pushRequiredError(errors, "/", "version")
  if (!Array.isArray(rulepack.modules)) {
    pushRequiredError(errors, "/", "modules")
  } else {
    rulepack.modules.forEach((moduleDef, index) => validateModule(moduleDef, index, errors))
  }
  return {
    valid: errors.length === 0,
    errors
  }
}

export function assertValidSastRulepack(rulepack, opts = {}) {
  const result = validateSastRulepack(rulepack)
  if (result.valid) return rulepack
  throw new Error(formatValidationFailure(result, {
    label: opts.label,
    prefix: "[PTK SAST] Invalid canonical rulepack",
    scopeKeys: ["moduleId", "ruleId"]
  }))
}

export default validateSastRulepack
