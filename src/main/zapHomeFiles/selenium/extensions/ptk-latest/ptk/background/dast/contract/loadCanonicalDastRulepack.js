import normalizeLegacyDastRulepack, {
    isCanonicalDastRulepack
} from "./normalizeLegacyDastRulepack.js"
import {
    assertValidDastRulepack
} from "./validateDastRulepack.js"

export function loadCanonicalDastRulepack(rulepack, opts = {}) {
    const canonical = isCanonicalDastRulepack(rulepack)
        ? rulepack
        : normalizeLegacyDastRulepack(rulepack)
    assertValidDastRulepack(canonical, opts)
    return canonical
}

export default loadCanonicalDastRulepack
