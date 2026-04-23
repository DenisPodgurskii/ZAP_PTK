import normalizeLegacyIastRulepack from "./normalizeLegacyIastRulepack.js"
import {
    assertValidIastRulepack
} from "./validateIastRulepack.js"

export function loadCanonicalIastRulepack(rulepack, opts = {}) {
    const canonical = normalizeLegacyIastRulepack(rulepack)
    assertValidIastRulepack(canonical, opts)
    return canonical
}

export default loadCanonicalIastRulepack

