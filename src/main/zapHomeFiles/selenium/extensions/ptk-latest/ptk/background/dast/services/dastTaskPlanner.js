import { ptk_request } from "../../rbuilder.js"
import { ptk_utils } from "../../utils.js"

export class DastTaskPlanner {
    constructor({
        awaitModulesLoaded = async () => {},
        refreshOastProbeDomains = () => {},
        ensureOastCallbackProbe = () => {},
        resolveOriginal = async () => null,
        getModules = () => [],
        shouldPlanModule = () => true,
        moduleRuntimeMode = () => "standard",
        buildSpaTasks = () => [],
        shouldUseBulkAttack = () => false,
        enrichAttackPayload = (payload) => payload,
        createTask = (task) => task,
        attackMetadataView = () => ({}),
        appendSelectorDiagnostics = () => {},
        registerPlannedTask = () => {},
        appendRuntimeEvent = () => {},
        fingerprintFromSchema = () => null,
        fingerprintFromPayload = () => null
    } = {}) {
        this.awaitModulesLoaded = awaitModulesLoaded
        this.refreshOastProbeDomains = refreshOastProbeDomains
        this.ensureOastCallbackProbe = ensureOastCallbackProbe
        this.resolveOriginal = resolveOriginal
        this.getModules = getModules
        this.shouldPlanModule = shouldPlanModule
        this.moduleRuntimeMode = moduleRuntimeMode
        this.buildSpaTasks = buildSpaTasks
        this.shouldUseBulkAttack = shouldUseBulkAttack
        this.enrichAttackPayload = enrichAttackPayload
        this.createTask = createTask
        this.attackMetadataView = attackMetadataView
        this.appendSelectorDiagnostics = appendSelectorDiagnostics
        this.registerPlannedTask = registerPlannedTask
        this.appendRuntimeEvent = appendRuntimeEvent
        this.fingerprintFromSchema = fingerprintFromSchema
        this.fingerprintFromPayload = fingerprintFromPayload
    }

    _selectorPriority(requestSchema, attack) {
        const selection = requestSchema?.metadata?.selectorSelection && typeof requestSchema.metadata.selectorSelection === "object"
            ? requestSchema.metadata.selectorSelection
            : null
        const selectorRank = Number(selection?.rankScore)
        const attackPriorityBoost = Number(attack?.metadata?.extensions?.selectorPriorityBoost)
        return Math.trunc(
            (Number.isFinite(selectorRank) ? selectorRank : 0)
            + (Number.isFinite(attackPriorityBoost) ? attackPriorityBoost : 0)
        )
    }

    _conditionNeedsRequestMetadata(condition) {
        if (!condition || typeof condition !== "object") return false
        try {
            const serialized = JSON.stringify(condition)
            return serialized.includes("attack.metadata.selectorSelection")
                || serialized.includes("attack.metadata.attacked")
        } catch {
            return false
        }
    }

    _sortModuleAttackRequests(entries = []) {
        return [...entries].sort((a, b) => {
            if (b.priority !== a.priority) return b.priority - a.priority
            const aLocation = String(a?.requestSchema?.metadata?.attacked?.location || "")
            const bLocation = String(b?.requestSchema?.metadata?.attacked?.location || "")
            if (aLocation !== bLocation) return aLocation.localeCompare(bLocation)
            const aName = String(a?.requestSchema?.metadata?.attacked?.name || "")
            const bName = String(b?.requestSchema?.metadata?.attacked?.name || "")
            if (aName !== bName) return aName.localeCompare(bName)
            return Number(a?.orderHint || 0) - Number(b?.orderHint || 0)
        })
    }

    _shouldPlanAttackRequest() {
        return true
    }

    async buildAttackPlan(raw) {
        const rawStr = typeof raw === "object" ? raw.raw : raw
        const rawMeta = typeof raw === "object" ? raw : {}
        const uiUrl = rawMeta.ui_url || rawMeta.uiUrl || null
        const baseSchemaCache = new Map()
        await this.awaitModulesLoaded()
        this.refreshOastProbeDomains()
        this.ensureOastCallbackProbe()
        const parseOpts = uiUrl ? { ui_url: uiUrl } : undefined
        const schema = ptk_request.parseRawRequest(rawStr, parseOpts)
        const modules = Array.isArray(this.getModules()) ? this.getModules() : []
        const planFingerprint = this.fingerprintFromSchema(schema)
        const original = await this.resolveOriginal(schema, rawMeta, {
            modules,
            planFingerprint
        })
        if (!original) return null

        const plan = {
            id: ptk_utils.attackId(),
            raw,
            schema,
            original,
            tasks: [],
            fingerprint: planFingerprint
        }

        for (const module of modules) {
            if (!Array.isArray(module?.attacks)) continue
            const modulePlanDecision = this.shouldPlanModule(module, schema, original)
            if (modulePlanDecision === false || modulePlanDecision?.allowed === false) {
                continue
            }
            const moduleAllowsStrategyBulk = this.shouldUseBulkAttack(module, { resolveOnly: true })
            const bufferedModuleTasks = []
            for (const attackDef of module.attacks) {
                let attack = null
                try {
                    attack = module.prepareAttack(attackDef)
                    const conditionNeedsRequestMetadata = this._conditionNeedsRequestMetadata(attack?.condition)
                    if (attack.condition && module.async !== false && !conditionNeedsRequestMetadata) {
                        const _a = { metadata: this.attackMetadataView(module, attack) }
                        if (!module.validateAttackConditions(_a, original)) continue
                    }

                    if (this.moduleRuntimeMode(module) === "spa") {
                        const spaTasks = this.buildSpaTasks(original, module, attack, rawMeta, planFingerprint)
                        for (const task of spaTasks) {
                            task.order = plan.tasks.length
                            plan.tasks.push(task)
                            this.registerPlannedTask()
                        }
                        continue
                    }

                    if (module.type === "active") {
                        const attackOptions = attack.action?.options
                        const baseSchemaKey = JSON.stringify(attackOptions || null)
                        let baseSchema = baseSchemaCache.get(baseSchemaKey)
                        if (!baseSchema) {
                            baseSchema = ptk_request.parseRawRequest(original.request.raw, attackOptions)
                            baseSchemaCache.set(baseSchemaKey, baseSchema)
                        }
                        const attackMode = this.shouldUseBulkAttack(module, { moduleAllowsStrategyBulk })
                            ? { mode: "bulk", prepared: true }
                            : { prepared: true }
                        const attackRequests = module.buildAttacks(baseSchema, attack, attackMode)
                        this.appendSelectorDiagnostics(module, attack, original)
                        for (const req of attackRequests) {
                            if (attack.condition && module.async !== false && conditionNeedsRequestMetadata) {
                                const conditionPayload = { metadata: this.attackMetadataView(module, attack, req?.metadata || {}) }
                                if (!module.validateAttackConditions(conditionPayload, original)) continue
                            }
                            const enriched = this.enrichAttackPayload(
                                ptk_request.updateRawRequest(req, null, attack.action?.options),
                                module,
                                attack
                            )
                            const fingerprint = this.fingerprintFromPayload(enriched) || planFingerprint
                            const task = this.createTask({
                                module,
                                attack,
                                payload: enriched,
                                type: "active",
                                fingerprint
                            })
                            bufferedModuleTasks.push({
                                module,
                                attack,
                                requestSchema: req,
                                task,
                                priority: this._selectorPriority(req, attack),
                                orderHint: bufferedModuleTasks.length
                            })
                        }
                    } else if (module.type === "passive") {
                        const passivePayload = { metadata: this.attackMetadataView(module, attack) }
                        const task = this.createTask({
                            module,
                            attack,
                            payload: passivePayload,
                            type: "passive",
                            fingerprint: planFingerprint
                        })
                        task.order = plan.tasks.length
                        plan.tasks.push(task)
                        this.registerPlannedTask()
                        this.appendSelectorDiagnostics(module, attack, original)
                    }
                } catch (err) {
                    this.appendRuntimeEvent({
                        type: "dast_plan_error",
                        phase: "plan_build",
                        moduleId: module?.id || null,
                        moduleName: module?.name || null,
                        attackId: attack?.id || attackDef?.id || null,
                        attackName: attack?.name || attackDef?.name || null,
                        url: original?.request?.url || null,
                        method: original?.request?.method || null,
                        error: err?.message || String(err)
                    })
                }
            }
            for (const entry of this._sortModuleAttackRequests(bufferedModuleTasks)) {
                if (!this._shouldPlanAttackRequest()) continue
                entry.task.order = plan.tasks.length
                plan.tasks.push(entry.task)
                this.registerPlannedTask()
            }
        }

        return plan
    }

    createTaskContext(original, options = {}) {
        return {
            original,
            rateLimited: options.rateLimited !== false,
            respectEngineState: options.respectEngineState !== false,
            notified: new Set(),
            executedByModule: Object.create(null),
            stopState: {}
        }
    }
}

export default DastTaskPlanner
