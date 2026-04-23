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

    _metaDocs(meta) {
        return meta?.docs && typeof meta.docs === "object" ? meta.docs : {}
    }

    _metaTaxonomy(meta) {
        return meta?.taxonomy && typeof meta.taxonomy === "object" ? meta.taxonomy : {}
    }

    _resolveMetaDescription(meta) {
        return meta?.description || this._metaDocs(meta).description || null
    }

    _resolveMetaRecommendation(meta) {
        return meta?.recommendation || this._metaDocs(meta).recommendation || null
    }

    _resolveMetaLinks(meta) {
        return meta?.links || this._metaDocs(meta).links || null
    }

    _resolveMetaSeverity(meta) {
        return meta?.severity || this._metaTaxonomy(meta).severity || null
    }

    _resolveMetaCategory(meta) {
        return meta?.category || this._metaTaxonomy(meta).category || null
    }

    _resolveMetaVulnId(meta) {
        return meta?.vulnId || this._metaTaxonomy(meta).vulnId || null
    }

    _enrichAttackMetadata(attack, catalogMeta) {
        if (!attack || typeof attack !== "object") return attack
        const existing = attack.metadata && typeof attack.metadata === "object" ? attack.metadata : {}
        const moduleMeta = catalogMeta?.moduleMeta && typeof catalogMeta.moduleMeta === "object" ? catalogMeta.moduleMeta : {}
        const attackMeta = catalogMeta?.attackMeta && typeof catalogMeta.attackMeta === "object" ? catalogMeta.attackMeta : {}
        const mergedMeta = Object.assign({}, moduleMeta, attackMeta, existing, {
            taxonomy: Object.assign({}, moduleMeta.taxonomy || {}, attackMeta.taxonomy || {}, existing.taxonomy || {}),
            docs: Object.assign({}, moduleMeta.docs || {}, attackMeta.docs || {}, existing.docs || {}),
            constants: Object.assign({}, moduleMeta.constants || {}, attackMeta.constants || {}, existing.constants || {}),
            extensions: Object.assign({}, moduleMeta.extensions || {}, attackMeta.extensions || {}, existing.extensions || {})
        })
        const docs = this._metaDocs(mergedMeta)
        const taxonomy = this._metaTaxonomy(mergedMeta)
        return Object.assign({}, attack, {
            category: attack.category || taxonomy.category || null,
            vulnId: attack.vulnId || taxonomy.vulnId || null,
            severity: attack.severity || taxonomy.severity || null,
            description: attack.description || docs.description || null,
            recommendation: attack.recommendation || docs.recommendation || null,
            links: attack.links || docs.links || null,
            metadata: mergedMeta
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
            vulnId: attack.vulnId || this._resolveMetaVulnId(meta) || this._resolveMetaCategory(meta) || null,
            category: attack.category || this._resolveMetaCategory(meta) || null,
            severity: attack.severity || this._resolveMetaSeverity(meta) || null,
            description: attack.description || this._resolveMetaDescription(meta) || null,
            recommendation: attack.recommendation || this._resolveMetaRecommendation(meta) || null,
            links: attack.links || this._resolveMetaLinks(meta) || null
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
            "links", "owasp", "cwe", "tags", "confidence", "location",
            "outputKind", "reconKind", "presentationAggregate", "uiSurface", "findingKind",
            "evidence"
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
        const moduleDef = catalogMeta?.moduleDef && typeof catalogMeta.moduleDef === "object" ? catalogMeta.moduleDef : {}
        const attackDef = catalogMeta?.attackDef && typeof catalogMeta.attackDef === "object" ? catalogMeta.attackDef : {}
        const merged = Object.assign({}, fallback)
        if (!merged.moduleId) merged.moduleId = attackObj.moduleId || attackMeta.moduleId || attackMeta.id || null
        if (!merged.moduleName) merged.moduleName = attackObj.moduleName || attackMeta.moduleName || moduleMeta.moduleName || moduleDef.name || null
        if (!merged.ruleId) merged.ruleId = attackObj.ruleId || attackMeta.id || attackMeta.ruleId || attackObj.id || attackDef.id || null
        if (!merged.ruleName) merged.ruleName = attackObj.ruleName || attackMeta.name || attackDef.name || null
        if (!merged.category) merged.category = attackObj.category || this._resolveMetaCategory(attackMeta) || this._resolveMetaCategory(attackRuleMeta) || this._resolveMetaCategory(moduleMeta) || null
        if (!merged.vulnId) merged.vulnId = attackObj.vulnId || this._resolveMetaVulnId(attackMeta) || this._resolveMetaVulnId(attackRuleMeta) || this._resolveMetaVulnId(moduleMeta) || null
        if (!merged.severity) merged.severity = attackObj.severity || this._resolveMetaSeverity(attackMeta) || this._resolveMetaSeverity(attackRuleMeta) || this._resolveMetaSeverity(moduleMeta) || null
        if (!merged.description) merged.description = attackObj.description || this._resolveMetaDescription(attackMeta) || this._resolveMetaDescription(attackRuleMeta) || this._resolveMetaDescription(moduleMeta) || null
        if (!merged.recommendation) merged.recommendation = attackObj.recommendation || this._resolveMetaRecommendation(attackMeta) || this._resolveMetaRecommendation(attackRuleMeta) || this._resolveMetaRecommendation(moduleMeta) || null
        if (!merged.links || typeof merged.links !== "object" || Array.isArray(merged.links) || Object.keys(merged.links).length === 0) {
            merged.links = attackObj.links || this._resolveMetaLinks(attackMeta) || this._resolveMetaLinks(attackRuleMeta) || this._resolveMetaLinks(moduleMeta) || null
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
