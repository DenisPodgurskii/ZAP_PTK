function cloneValue(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value || null
    }
}

export class DastFindingPresentationService {
    constructor({
        getModules = () => [],
        sanitizeUiValue = (value) => value,
        uiLimits = null
    } = {}) {
        this.getModules = getModules
        this.sanitizeUiValue = sanitizeUiValue
        this.uiLimits = uiLimits
    }

    findRequestRecordById(scanResult, requestId) {
        if (!requestId) return null
        const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
        let record = requests.find((item) => String(item?.id) === String(requestId)) || null
        if (!record && typeof requestId === "string") {
            const match = requestId.match(/^req-(\d+)$/i)
            if (match) {
                const idx = Number(match[1]) - 1
                if (idx >= 0 && idx < requests.length) {
                    record = requests[idx] || null
                }
            }
        }
        return record
    }

    findAttackById(scanResult, attackId, moduleId = null) {
        if (!attackId) return { attack: null, request: null }
        const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
        const attackKey = String(attackId)
        const moduleKey = moduleId ? String(moduleId) : null
        for (const record of requests) {
            const attacks = Array.isArray(record?.attacks) ? record.attacks : []
            const found = attacks.find((item) => {
                if (String(item?.id) !== attackKey) return false
                if (!moduleKey) return true
                const candidateModuleId = item?.moduleId || item?.metadata?.moduleId || item?.metadata?.id || null
                return String(candidateModuleId) === moduleKey
            })
            if (found) return { attack: found, request: record }
        }
        return { attack: null, request: null }
    }

    _resolveDastCatalogMeta({ attack = null, moduleId = null } = {}) {
        const modules = Array.isArray(this.getModules?.()) ? this.getModules() : []
        if (!modules.length) return { moduleMeta: null, attackMeta: null, moduleDef: null, attackDef: null }
        const attackObj = attack && typeof attack === "object" ? attack : {}
        const attackMeta = attackObj.metadata && typeof attackObj.metadata === "object" ? attackObj.metadata : {}
        const resolvedModuleId = moduleId || attackObj.moduleId || attackMeta.moduleId || attackMeta.id || null
        const resolvedRuleId = attackObj.ruleId || attackMeta.id || attackMeta.ruleId || attackObj.id || null

        let moduleDef = null
        if (resolvedModuleId) {
            moduleDef = modules.find((item) => String(item?.id || item?.metadata?.id || "") === String(resolvedModuleId)) || null
        }
        if (!moduleDef && attackObj.moduleName) {
            const normalizedName = String(attackObj.moduleName || "").trim().toLowerCase()
            moduleDef = modules.find((item) => String(item?.name || item?.metadata?.name || "").trim().toLowerCase() === normalizedName) || null
        }
        if (!moduleDef) return { moduleMeta: null, attackMeta: null, moduleDef: null, attackDef: null }

        const moduleMeta = moduleDef.metadata && typeof moduleDef.metadata === "object" ? moduleDef.metadata : null
        const attackDefs = Array.isArray(moduleDef.attacks) ? moduleDef.attacks : []
        let attackDef = null
        if (resolvedRuleId) {
            attackDef = attackDefs.find((item) => String(item?.id || item?.ruleId || "") === String(resolvedRuleId)) || null
        }
        const attackRuleMeta = attackDef?.metadata && typeof attackDef.metadata === "object" ? attackDef.metadata : null
        return { moduleMeta, attackMeta: attackRuleMeta, moduleDef, attackDef }
    }

    _enrichAttackMetadata(attack, catalogMeta) {
        if (!attack || typeof attack !== "object") return attack
        const existing = attack.metadata && typeof attack.metadata === "object" ? attack.metadata : {}
        const moduleMeta = catalogMeta?.moduleMeta && typeof catalogMeta.moduleMeta === "object" ? catalogMeta.moduleMeta : {}
        const attackMeta = catalogMeta?.attackMeta && typeof catalogMeta.attackMeta === "object" ? catalogMeta.attackMeta : {}
        return Object.assign({}, attack, {
            metadata: Object.assign({}, moduleMeta, attackMeta, existing)
        })
    }

    _buildFindingDetailsFallback({ attack, requestId = null }) {
        if (!attack || typeof attack !== "object") return null
        const meta = attack.metadata && typeof attack.metadata === "object" ? attack.metadata : {}
        const fallback = {
            id: attack.findingId || `live:${requestId || "request"}:${attack.id || "attack"}`,
            moduleId: attack.moduleId || meta.moduleId || meta.id || null,
            moduleName: attack.moduleName || meta.moduleName || meta.module || null,
            ruleId: attack.ruleId || meta.id || meta.ruleId || null,
            ruleName: attack.ruleName || meta.name || null,
            vulnId: attack.vulnId || meta.vulnId || meta.category || null,
            category: attack.category || meta.category || null,
            severity: attack.severity || meta.severity || null,
            description: attack.description || meta.description || null,
            recommendation: attack.recommendation || meta.recommendation || null,
            links: attack.links || meta.links || null
        }
        Object.keys(fallback).forEach((key) => {
            if (fallback[key] === null || fallback[key] === undefined || fallback[key] === "") delete fallback[key]
        })
        return Object.keys(fallback).length ? fallback : null
    }

    _compactFindingForUi(finding) {
        if (!finding || typeof finding !== "object") return null
        const allowedKeys = [
            "id", "engine", "scanId", "moduleId", "moduleName", "ruleId", "ruleName",
            "vulnId", "category", "severity", "name", "title", "description", "recommendation",
            "links", "owasp", "cwe", "tags", "confidence", "location"
        ]
        const summary = {}
        allowedKeys.forEach((key) => {
            if (finding[key] !== undefined && finding[key] !== null) {
                summary[key] = this.sanitizeUiValue(finding[key], 0, this.uiLimits)
            }
        })
        return summary
    }

    _buildFindingPresentation({ finding = null, attack = null, requestId = null, catalogMeta = null } = {}) {
        const compactExisting = this._compactFindingForUi(finding)
        const fallback = compactExisting || this._buildFindingDetailsFallback({ attack, requestId }) || {}
        const attackObj = attack && typeof attack === "object" ? attack : {}
        const attackMeta = attackObj.metadata && typeof attackObj.metadata === "object" ? attackObj.metadata : {}
        const moduleMeta = catalogMeta?.moduleMeta && typeof catalogMeta.moduleMeta === "object" ? catalogMeta.moduleMeta : {}
        const attackRuleMeta = catalogMeta?.attackMeta && typeof catalogMeta.attackMeta === "object" ? catalogMeta.attackMeta : {}
        const merged = Object.assign({}, fallback)
        if (!merged.moduleId) merged.moduleId = attackObj.moduleId || attackMeta.moduleId || attackMeta.id || null
        if (!merged.moduleName) merged.moduleName = attackObj.moduleName || attackMeta.moduleName || moduleMeta.name || null
        if (!merged.ruleId) merged.ruleId = attackObj.ruleId || attackMeta.id || attackMeta.ruleId || attackObj.id || null
        if (!merged.ruleName) merged.ruleName = attackObj.ruleName || attackMeta.name || attackRuleMeta.name || null
        if (!merged.category) merged.category = attackObj.category || attackMeta.category || attackRuleMeta.category || moduleMeta.category || null
        if (!merged.vulnId) merged.vulnId = attackObj.vulnId || attackMeta.vulnId || moduleMeta.vulnId || null
        if (!merged.severity) merged.severity = attackObj.severity || attackMeta.severity || attackRuleMeta.severity || moduleMeta.severity || null
        if (!merged.description) merged.description = attackObj.description || attackMeta.description || attackRuleMeta.description || moduleMeta.description || null
        if (!merged.recommendation) merged.recommendation = attackObj.recommendation || attackMeta.recommendation || attackRuleMeta.recommendation || moduleMeta.recommendation || null
        if (!merged.links || typeof merged.links !== "object" || Array.isArray(merged.links) || Object.keys(merged.links).length === 0) {
            merged.links = attackObj.links || attackMeta.links || attackRuleMeta.links || moduleMeta.links || null
        }
        Object.keys(merged).forEach((key) => {
            if (merged[key] === null || merged[key] === undefined || merged[key] === "") delete merged[key]
        })
        return Object.keys(merged).length ? merged : null
    }

    getRequestSnapshot(scanResult, { requestId = null, attackId = null } = {}) {
        if (!requestId) return { requestId: null, original: null, attack: null }
        const record = this.findRequestRecordById(scanResult, requestId)
        if (!record) return { requestId, original: null, attack: null }
        let attack = null
        if (attackId && Array.isArray(record.attacks)) {
            attack = record.attacks.find((item) => String(item?.id) === String(attackId)) || null
        }
        return {
            requestId,
            original: cloneValue(record.original || null),
            attack: cloneValue(attack)
        }
    }

    getFindingDetails(scanResult, { findingId = null, requestId = null, attackId = null, moduleId = null } = {}) {
        const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
        let finding = null
        if (findingId) {
            finding = findings.find((item) => String(item?.id) === String(findingId)) || null
        }
        let requestRecord = null
        let attackRecord = null
        if (attackId && requestId) {
            requestRecord = this.findRequestRecordById(scanResult, requestId)
            if (requestRecord && Array.isArray(requestRecord.attacks)) {
                attackRecord = requestRecord.attacks.find((item) => String(item?.id) === String(attackId)) || null
            }
        }
        if (!attackRecord && attackId) {
            const found = this.findAttackById(scanResult, attackId, moduleId)
            attackRecord = found.attack
            requestRecord = requestRecord || found.request
        }
        if (!finding && attackRecord?.findingId) {
            finding = findings.find((item) => String(item?.id) === String(attackRecord.findingId)) || null
        }
        const catalogMeta = this._resolveDastCatalogMeta({ attack: attackRecord, moduleId })
        attackRecord = this._enrichAttackMetadata(attackRecord, catalogMeta)
        const compactFinding = this._buildFindingPresentation({
            finding,
            attack: attackRecord,
            requestId,
            catalogMeta
        })
        return {
            finding: cloneValue(compactFinding),
            attack: cloneValue(attackRecord),
            requestId: requestId || requestRecord?.id || null
        }
    }
}

export default DastFindingPresentationService
