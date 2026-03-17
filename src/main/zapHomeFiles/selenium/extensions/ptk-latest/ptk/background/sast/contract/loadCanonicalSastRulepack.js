import normalizeLegacySastRulepack, { isCanonicalSastRulepack } from "./normalizeLegacySastRulepack.js"
import { assertValidSastRulepack } from "./validateSastRulepack.js"

export function loadCanonicalSastRulepack(rulepack, opts = {}) {
  const canonical = isCanonicalSastRulepack(rulepack)
    ? normalizeLegacySastRulepack(rulepack)
    : normalizeLegacySastRulepack(rulepack)
  assertValidSastRulepack(canonical, opts)
  return canonical
}

export default loadCanonicalSastRulepack
