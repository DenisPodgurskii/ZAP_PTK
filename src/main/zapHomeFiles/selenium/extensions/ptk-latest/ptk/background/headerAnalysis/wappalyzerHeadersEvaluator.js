import { buildHeaderPlan } from "../../packages/wappalyzer/headerRules.js"

let cachedPlan = []

export function setWappalyzerTechnologiesForHeaders(technologies = {}) {
    try {
        cachedPlan = buildHeaderPlan(technologies) || []
    } catch (err) {
        cachedPlan = []
        console.warn("[PTK][HeaderAnalysis] Failed to build Wappalyzer header plan", err)
    }
}

function headerArrayToMap(headers = []) {
    const map = {}
    headers.forEach((header) => {
        if (!header?.name) return
        const key = header.name.toLowerCase()
        if (!map[key]) {
            map[key] = []
        }
        map[key].push(header.value || "")
    })
    return map
}

function matchesPattern(value, pattern) {
    if (!value || !pattern) {
        return false
    }
    if (pattern.regex instanceof RegExp) {
        try {
            return pattern.regex.test(value)
        } catch (_) {
            return false
        }
    }
    const raw = String(pattern.raw || pattern.value || "").toLowerCase()
    if (!raw) return false
    return String(value).toLowerCase().includes(raw)
}

export function evaluateWappalyzerHeaders(responses = []) {
    if (!Array.isArray(cachedPlan) || !cachedPlan.length || !Array.isArray(responses) || !responses.length) {
        return { matches: [], evaluatedResponses: 0 }
    }

    const dedupe = new Set()
    const techMatchMap = new Map()

    responses.forEach((response) => {
        const headerMap = headerArrayToMap(response?.responseHeaders || [])
        cachedPlan.forEach((tech) => {
            let entry = techMatchMap.get(tech.techId)
            if (!entry) {
                entry = { techId: tech.techId, techName: tech.techName, matches: [] }
                techMatchMap.set(tech.techId, entry)
            }

            tech.rules.forEach((rule) => {
                const headerValues = headerMap[rule.header]
                if (!headerValues || !headerValues.length) {
                    return
                }
                headerValues.forEach((value) => {
                    rule.patterns.forEach((pattern) => {
                        if (!matchesPattern(value, pattern)) {
                            return
                        }
                        const key = `${tech.techId}|${rule.header}|${pattern.raw || pattern.value || ""}`
                        if (dedupe.has(key)) {
                            return
                        }
                        dedupe.add(key)
                        entry.matches.push({
                            header: rule.header,
                            value,
                            pattern: pattern.raw || pattern.value || "",
                        })
                    })
                })
            })
        })
    })

    const matches = Array.from(techMatchMap.values()).filter((item) => item.matches.length)

    return {
        matches,
        evaluatedResponses: responses.length,
    }
}
