/* Author: PTK Team
 *
 * Builds a compact header-matching plan from technologies.json so we
 * can evaluate HTTP response headers outside of the main Wappalyzer engine.
 */

import { Wappalyzer } from "./wappalyzer.js"

const isPlainObject = (value) =>
    Object.prototype.toString.call(value) === "[object Object]"

function normalizePatterns(patterns = []) {
    return (patterns || [])
        .map((pattern) => {
            if (!pattern) return null
            return {
                raw: pattern.value || "",
                regex: pattern.regex || null,
            }
        })
        .filter(Boolean)
}

export function buildHeaderPlan(technologies = {}) {
    if (!technologies || typeof technologies !== "object") {
        return []
    }

    const plan = []

    Object.entries(technologies || {}).forEach(([name, definition]) => {
        if (!isPlainObject(definition) || !definition.headers) {
            return
        }

        const transformed = Wappalyzer.transformPatterns(definition.headers)
        if (!isPlainObject(transformed)) {
            return
        }

        const rules = Object.entries(transformed)
            .map(([headerName, patterns]) => {
                const normalized = normalizePatterns(patterns)
                if (!normalized.length) {
                    return null
                }

                return {
                    header: String(headerName || "").toLowerCase(),
                    patterns: normalized,
                }
            })
            .filter(Boolean)

        if (!rules.length) {
            return
        }

        plan.push({
            techId: name,
            techName: definition.name || name,
            rules,
        })
    })

    return plan
}
export default buildHeaderPlan
