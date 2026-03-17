import { ptk_module } from "../dast/modules/module.js"
import { loadCanonicalRulepack } from "../common/moduleRegistry.js"
import { resolveEffectiveSeverity } from "../common/severity_utils.js"
import { buildPassiveOriginal } from "./representativeResponseSelector.js"

let headerModulesPromise = null

function getCanonicalCategory(module) {
    return String(
        module?.metadata?.taxonomy?.category
        || module?.metadata?.category
        || ""
    ).toLowerCase()
}

function buildAttackMetadataView(module, attack) {
    const moduleMeta = module?.metadata && typeof module.metadata === "object" ? module.metadata : {}
    const attackMeta = attack?.metadata && typeof attack.metadata === "object" ? attack.metadata : {}
    const constants = Object.assign({}, moduleMeta.constants || {}, attackMeta.constants || {})
    const view = Object.assign({}, moduleMeta, attack, attackMeta, { constants })

    Object.keys(constants).forEach((key) => {
        if (view[key] === undefined) {
            view[key] = constants[key]
        }
    })

    if (view.condition === undefined && attack?.condition !== undefined) view.condition = attack.condition
    if (view.validation === undefined && attack?.validation !== undefined) view.validation = attack.validation
    if (view.target === undefined && attack?.target !== undefined) view.target = attack.target
    if (view.action === undefined && attack?.action !== undefined) view.action = attack.action

    return view
}

async function ensureHeaderModules() {
    if (headerModulesPromise) {
        return headerModulesPromise
    }

    headerModulesPromise = loadCanonicalRulepack("DAST")
        .then((rulepack) => {
            const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
            return modules
                .filter(
                    (module) =>
                        module &&
                        module.type === "passive" &&
                        (module.id === "headers" ||
                            getCanonicalCategory(module) === "security_headers")
                )
                .map((module) => new ptk_module(module))
        })
        .catch((err) => {
            console.warn("[PTK][HeaderAnalysis] Failed to load DAST header modules", err)
            return []
        })

    return headerModulesPromise
}

function describeFinding(finding) {
    const descriptionParts = []
    if (finding.description) {
        descriptionParts.push(finding.description)
    }
    if (finding.proof) {
        descriptionParts.push(`<strong>Evidence:</strong> ${finding.proof}`)
    }
    if (finding.recommendation) {
        descriptionParts.push(finding.recommendation)
    }
    if (finding.urls?.length) {
        const urlLines = finding.urls.slice(0, 3).map((url) => `<div>${url}</div>`).join("")
        descriptionParts.push(`<div><strong>URLs:</strong>${urlLines}</div>`)
    }
    return descriptionParts.join("<br/>")
}

export async function evaluatePassiveHeaders(responses = []) {
    const modules = await ensureHeaderModules()
    if (!modules.length || !Array.isArray(responses) || !responses.length) {
        return { tableRows: [], rawFindings: [] }
    }

    const findings = []
    const dedupe = new Set()

    for (const response of responses) {
        const original = buildPassiveOriginal(response)
        if (!original) continue
        const originKey = (() => {
            try {
                return new URL(response.url || "").origin
            } catch (_) {
                return response.url || ""
            }
        })()

        for (const module of modules) {
            if (!Array.isArray(module.attacks)) continue

            for (const attackDef of module.attacks) {
                const attack = module.prepareAttack(attackDef)
                const attackMeta = { metadata: buildAttackMetadataView(module, attack) }

                if (attack.condition && !module.validateAttackConditions(attackMeta, original)) {
                    continue
                }

                const result = module.validateAttack(attackMeta, original)
                if (!result?.success) {
                    continue
                }

                const key = `${module.id || module.name}|${attack.id || attack.name}|${originKey}`
                if (dedupe.has(key)) {
                    continue
                }
                dedupe.add(key)

                const severity = resolveEffectiveSeverity({
                    moduleMeta: module.metadata || {},
                    attackMeta: attack.metadata || {},
                })
                const moduleDocs = module.metadata?.docs || {}
                const attackDocs = attack.metadata?.docs || {}

                const finding = {
                    moduleId: module.id || module.name || "headers",
                    attackId: attack.id || attack.name || "passive-check",
                    title: attack.name || attack.id || "Header finding",
                    severity,
                    description: attackDocs.description || moduleDocs.description || "",
                    recommendation: attackDocs.recommendation || moduleDocs.recommendation || "",
                    links: attackDocs.links || moduleDocs.links || {},
                    proof: result.proof || "",
                    urls: [response.url].filter(Boolean),
                }

                findings.push(finding)
            }
        }
    }

    const rowMap = new Map()

    findings.forEach((finding) => {
        const key = `${finding.moduleId || finding.title}|${finding.attackId || finding.title}`
        const entry = rowMap.get(key)
        const description = describeFinding(finding)
        if (entry) {
            entry.descriptions.push(description)
            return
        }
        rowMap.set(key, {
            title: finding.title,
            descriptions: [description],
        })
    })

    const tableRows = Array.from(rowMap.values()).map((entry) => [
        entry.title,
        entry.descriptions.join('<hr/>'),
    ])

    return { tableRows, rawFindings: findings }
}
