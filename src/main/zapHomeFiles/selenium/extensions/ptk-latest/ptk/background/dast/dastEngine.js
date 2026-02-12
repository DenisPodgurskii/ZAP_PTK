// dastEngine.js
import { ptk_module } from "./modules/module.js"
import { ptk_request } from "../rbuilder.js"
import { ptk_utils, ptk_queue, ptk_ruleManager } from "../utils.js"
import { getSearchParamsFromUrlOrHash } from "./urlUtils.js"
import { loadRulepack } from "../common/moduleRegistry.js"
import {
    createScanResultEnvelope,
    addFinding,
    addFindingToGroup
} from "../common/scanResults.js"
import {
    normalizeRulepack,
    resolveEffectiveSeverity
} from "../common/severity_utils.js"
import { resolveFindingTaxonomy } from "../common/resolveFindingTaxonomy.js"
import normalizeFinding from "../common/findingNormalizer.js"

const DEFAULT_SCAN_STRATEGY = 'SMART'
const SCAN_STRATEGY_CONFIGS = {
    FAST: {
        strategy: 'FAST',
        atomic: true,
        stopOnFirstFinding: true,
        dedupeScope: 'url-module'
    },
    SMART: {
        strategy: 'SMART',
        atomic: false,
        stopOnFirstFinding: true,
        dedupeScope: 'url-param-module'
    },
    COMPREHENSIVE: {
        strategy: 'COMPREHENSIVE',
        atomic: false,
        stopOnFirstFinding: false,
        dedupeScope: null
    }
}

function mergeModuleDefinitions(base = [], extra = []) {
    const merged = Array.isArray(base) ? base.slice() : []
    const idIndex = new Map()
    merged.forEach((mod, idx) => {
        if (mod?.id) {
            idIndex.set(mod.id, idx)
        }
    })
    extra.forEach(mod => {
        if (!mod) return
        if (mod.id && idIndex.has(mod.id)) {
            merged[idIndex.get(mod.id)] = mod
        } else {
            if (mod?.id) {
                idIndex.set(mod.id, merged.length)
            }
            merged.push(mod)
        }
    })
    return merged
}


export class dastEngine {
    /**
     * settings: { maxRequestsPerSecond, concurrency, modulesUrl, ... }
     */
    constructor(settings = {}) {
        this.settings = settings
        this.maxRequestsPerSecond = settings.maxRequestsPerSecond
        this.concurrency = settings.concurrency
        const requestedStrategy = settings.scanStrategy || settings.dastScanStrategy || DEFAULT_SCAN_STRATEGY
        this.strategyConfig = this._resolveStrategyConfig(requestedStrategy)
        this.scanStats = this._createStrategyStats(this.strategyConfig.strategy)
        this._strategyFindingKeys = new Set()
        this._baseRulepackPromise = null
        this._cveRulepackPromise = null
        this._rawBaseModules = null
        this._rawCveModules = null
        this.reset()
        this.automationHooks = null

        this._moduleLoadPromise = this.loadModules({
            runCve: !!settings?.runCve,
            policy: settings?.dastScanPolicy || settings?.scanPolicy
        })
        this._proModuleLoadPromise = this.loadProModules()
        this._debuggerDialogTabs = new Set()
        this._debuggerDialogListener = null
    }

    reset() {
        this.isRunning = false
        this.inProgress = false
        this.tokens = this.maxRequestsPerSecond
        this.lastRefill = Date.now()
        this.tokenRefillInterval = 1000
        this.activeCount = 0
        this._requestQueue = new ptk_queue()
        this.scanResult = this.getEmptyScanResult()
        this._taskQueue = []
        this._activePlans = new Map()
        this._taskWorkers = new Set()
        this._moduleLocks = new Set()
        this._planLocks = new Set()
        this._uniqueAttackSuccess = new Set()
        this._passiveUniqueFindingKeys = new Set()
        this._spaSeenSinks = new Set()
        this._fingerprintSet = new Set()
        this._idleResolvers = new Set()
        this._initializeStrategyState(this.strategyConfig)
        this._requestSeq = 0
        this._attackSeq = 0
        ptk_request.clearStoredHeaders()
    }

    async loadModules(options = {}) {
        const runCve = !!options.runCve
        const policyRaw = options.policy || this.settings?.dastScanPolicy || this.settings?.scanPolicy || 'ACTIVE'
        const policy = String(policyRaw || 'ACTIVE').toUpperCase()
        const baseModules = await this._ensureBaseModules()
        let moduleDefs = Array.isArray(baseModules) ? baseModules : []
        if (runCve) {
            const cveModules = await this._ensureCveModules()
            if (cveModules && cveModules.length) {
                moduleDefs = mergeModuleDefinitions(baseModules, cveModules)
            }
        }
        if (policy === 'RECON' || policy === 'RECONNAISSANCE' || policy === 'PASSIVE') {
            moduleDefs = moduleDefs.filter(m => (m?.type || '').toLowerCase() === 'passive')
        }
        this.modules = moduleDefs.map(m => new ptk_module(m))
        return this.modules
    }

    async _ensureBaseModules() {
        if (Array.isArray(this._rawBaseModules)) {
            return this._rawBaseModules
        }
        if (!this._baseRulepackPromise) {
            this._baseRulepackPromise = loadRulepack('DAST')
        }
        const rulepack = await this._baseRulepackPromise
        normalizeRulepack(rulepack, { engine: 'DAST', childKey: 'attacks' })
        const modules = Array.isArray(rulepack?.modules) ? rulepack.modules : []
        this._rawBaseModules = modules
        return modules
    }

    async _ensureCveModules() {
        if (Array.isArray(this._rawCveModules)) {
            return this._rawCveModules
        }
        if (!this._cveRulepackPromise) {
            this._cveRulepackPromise = loadRulepack('DAST', { variant: 'cve' })
                .then(rulepack => {
                    normalizeRulepack(rulepack, { engine: 'DAST', childKey: 'attacks' })
                    return Array.isArray(rulepack?.modules) ? rulepack.modules : []
                })
                .catch(err => {
                    console.warn('[PTK DAST] Failed to load CVE modules', err)
                    return []
                })
        }
        const modules = await this._cveRulepackPromise
        this._rawCveModules = modules
        return modules
    }


    async loadProModules() {
        // let self = this
        // this.pro_modules = []
        // let apiKey = worker.ptk_app?.settings?.profile?.api_key
        // let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.attacks_endpoint
        // if (apiKey) {
        //     return await fetch(url, { headers: { 'Authorization': apiKey }, cache: "no-cache" })
        //         .then(response => response.json())
        //         .then(json => {
        //             let modules = JSON.parse(json.rules.modules.json).modules
        //             Object.values(modules).forEach(module => {
        //                 self.pro_modules.push(new ptk_module(module))
        //             })
        //         }).catch(e => {
        //             console.log(e)
        //             return { "success": false, "json": { "message": e.message } }
        //         })
        // }
    }

    getEmptyScanResult() {
        const strategyName = this.strategyConfig?.strategy || DEFAULT_SCAN_STRATEGY
        const envelope = createScanResultEnvelope({
            engine: "DAST",
            scanId: null,
            host: null,
            tabId: null,
            startedAt: new Date().toISOString(),
            settings: {
                scanStrategy: strategyName
            }
        })
        envelope.version = envelope.version || "1.0"
        delete envelope.items
        delete envelope.type
        delete envelope.tabId
        envelope.requests = []
        envelope.pages = []
        envelope.runtimeEvents = []
        envelope.stats = Object.assign({}, envelope.stats, {
            high: 0,
            medium: 0,
            low: 0,
            attacksCount: 0
        })
        envelope.scanStats = this._createStrategyStats(strategyName)
        return envelope
    }

    canSendRequest() {
        const now = Date.now()
        if (now - this.lastRefill > this.tokenRefillInterval) {
            this.tokens = this.maxRequestsPerSecond
            this.lastRefill = now
        }
        if (this.tokens > 0) {
            this.tokens--
            return true
        }
        return false
    }

    enqueue(rawRequest, response) {
        if (!this.isAllowed(response)) return

        const raw = typeof rawRequest === 'object' ? rawRequest.raw : rawRequest
        const fpHint = typeof rawRequest === 'object' ? rawRequest.fingerprint : null
        const canonicalFingerprint = this._simpleFingerprint(rawRequest, response)
        const secondaryFingerprint = canonicalFingerprint ? null : ptk_request.fingerprintRawRequest(raw)
        const prefersHint = fpHint && fpHint.startsWith('spa:')
        const dedupeKey = prefersHint ? fpHint : (canonicalFingerprint || secondaryFingerprint)

        if (!dedupeKey) return
        if (this._fingerprintSet.has(dedupeKey)) {
            // console.log('[PTK][DAST] skip duplicate request', {
            //     dedupeKey,
            //     rawPreview: raw.slice(0, 80),
            //     hint: fpHint,
            //     canonical: canonicalFingerprint,
            //     secondary: secondaryFingerprint
            // })
            return
        }

        this._fingerprintSet.add(dedupeKey)

        this._requestQueue.enqueue(rawRequest)
    }



    isAllowed(response) {
        let allowed = true
        const rawUrl = response?.ui_url || response?.url || ''
        const url = new URL(response.url)
        const params = getSearchParamsFromUrlOrHash(rawUrl)
        const hasParams = [...params.keys()].length > 0
        if (this.settings.blacklist.includes(response.type) && !hasParams) {
            allowed = false
        } else {
            if (!url.host.includes(this.host) &&
                this.domains.findIndex(i => url.host.includes(i)) < 0) {
                allowed = false
            }
        }
        return allowed
    }

    updateScanResult(result, data) {
        if (!this.scanResult.stats) {
            this.scanResult.stats = {
                high: 0,
                medium: 0,
                low: 0,
                attacksCount: 0,
                findingsCount: 0
            }
        }
        const stats = this.scanResult.stats

        if (result) {
            const attacks = Array.isArray(result.attacks) ? result.attacks : []
            stats.attacksCount = (stats.attacksCount || 0) + attacks.length
            attacks.forEach((attack, index) => {
                if (attack?.success) {
                    this._addUnifiedFinding(result.requestRecord || { original: result.original }, attack, index)
                }
            })
        }

        if (data) {
            this._confirmAttackFromContent(data)
        }

        stats.findingsCount = stats.findingsCount || 0
        this.scanResult.stats = stats
        this._syncScanStats()

        if (result) {
            const delta = this._buildPlanDelta(result)
            if (delta) {
                browser.runtime.sendMessage({
                    channel: "ptk_background2popup_rattacker",
                    type: "dast_plan_completed",
                    delta
                }).catch(e => e)
            }
        }
    }

    _buildPlanDelta(result) {
        if (!result) return null
        const requestRecord = result.requestRecord || null
        const requestId = requestRecord?.id || null
        const original = requestRecord?.original || result.original || null
        const attacks = Array.isArray(requestRecord?.attacks)
            ? requestRecord.attacks
            : (Array.isArray(result.attacks) ? result.attacks : [])
        return {
            requestId,
            original,
            attacks
        }
    }

    async start(tabId, host, domains, settings = {}) {
        this.reset()
        this.tabId = tabId
        this.scanResult.host = this.host = host
        const started = new Date().toISOString()
        this.scanResult.startedAt = started
        this.scanResult.finishedAt = null
        this.domains = domains
        this.isRunning = true
        this.scanResult.scanId = this.scanId = ptk_utils.UUID()
        const runCveEnabled = !!(settings && settings.runCve)
        const dastScanPolicy = settings?.dastScanPolicy || settings?.scanPolicy || this.settings?.dastScanPolicy || this.settings?.scanPolicy || 'ACTIVE'
        this._moduleLoadPromise = this.loadModules({ runCve: runCveEnabled, policy: dastScanPolicy })

        this.maxRequestsPerSecond = settings.maxRequestsPerSecond || this.settings.maxRequestsPerSecond
        this.concurrency = settings.concurrency || this.settings.concurrency
        const requestedStrategy = settings.scanStrategy || settings.dastScanStrategy || this.settings?.scanStrategy || this.settings?.dastScanStrategy
        this._applyScanStrategy(requestedStrategy)
        this.scanResult.settings = Object.assign({}, this.scanResult.settings, {
            scanStrategy: this.strategyConfig.strategy,
            runCve: runCveEnabled,
            dastScanPolicy
        })

        this.inProgress = false
        this.run()
    }

    stop() {
        this.isRunning = false
        this.inProgress = false
        const pendingPlans = this._activePlans ? Array.from(this._activePlans.values()) : []
        for (const plan of pendingPlans) {
            plan.pending = 0
            this._finalizePlan(plan)
        }
        if (this._activePlans) this._activePlans.clear()
        if (this._taskWorkers) this._taskWorkers.clear()
        this._taskQueue = []
        if (this._moduleLocks) this._moduleLocks.clear()
        this._resolveIdleResolvers()
        if (this.scanResult) {
            const finished = new Date().toISOString()
            this.scanResult.finishedAt = finished
        }
        ptk_request.clearStoredHeaders()
    }

    async run() {
        if (!this.isRunning) return

        if (this.inProgress) return
        this.inProgress = true
        try {
            if (this.concurrency === 1) {
                await this.runSequential()
            } else {
                await this.runParallel()
            }
        } finally {
            this.inProgress = false
            this._notifyIdleResolvers()
        }

        if (this.isRunning) {
            setTimeout(() => this.run(), 200)
        }
    }

    async runSequential() {
        await this._drainRequestQueue()
        this._ensureTaskWorkers()
    }

    async runParallel() {
        await this.runSequential()
    }

    async onetimeScanRequest(raw) {
        let result = await this.scanRequest(raw, true)
        let stats = { findingsCount: 0, high: 0, medium: 0, low: 0, attacksCount: 0 }
        for (let i in result.attacks) {
            stats.attacksCount++
            if (result.attacks[i].success) {
                stats.findingsCount++
                if (result.attacks[i].metadata.severity == 'High') stats.high++
                if (result.attacks[i].metadata.severity == 'Medium') stats.medium++
                if (result.attacks[i].metadata.severity == 'Low') stats.low++
            }
        }
        return Object.assign({}, result, { stats: stats })
    }

    async buildAttackPlan(raw) {
        const rawStr = typeof raw === 'object' ? raw.raw : raw
        const rawMeta = typeof raw === 'object' ? raw : {}
        const uiUrl = rawMeta.ui_url || rawMeta.uiUrl || null
        if (this._moduleLoadPromise) {
            await this._moduleLoadPromise
        }
        const parseOpts = uiUrl ? { ui_url: uiUrl } : undefined
        const schema = ptk_request.parseRawRequest(rawStr, parseOpts)
        const original = await this.executeOriginal(schema)
        if (!original) return null

        const planFingerprint = this._fingerprintFromSchema(schema)
        const plan = {
            id: ptk_utils.attackId(),
            raw,
            schema,
            original,
            tasks: [],
            fingerprint: planFingerprint
        }

        const modules = Array.isArray(this.modules) ? this.modules : []
        for (const module of modules) {
            if (!Array.isArray(module.attacks)) continue
            const moduleSupportsAtomic = this._moduleSupportsAtomic(module)
            for (const attackDef of module.attacks) {
                const attack = module.prepareAttack(attackDef)
                if (attack.condition && module.async !== false) {
                    const _a = { metadata: Object.assign({}, attack, module.metadata) }
                    if (!module.validateAttackConditions(_a, original)) continue
                }

                if (module.metadata?.spa) {
                    const spaTasks = this._buildSpaTasks(original, module, attack, rawMeta, planFingerprint)
                    for (const task of spaTasks) {
                        task.order = plan.tasks.length
                        plan.tasks.push(task)
                        this._registerPlannedTask()
                    }
                    continue
                }

                if (module.type === 'active') {
                    const baseSchema = ptk_request.parseRawRequest(original.request.raw, attack.action?.options)
                    const attackMode = this._shouldUseBulkAttack(moduleSupportsAtomic) ? { mode: 'bulk' } : undefined
                    const attackRequests = module.buildAttacks(baseSchema, attack, attackMode)
                    for (const req of attackRequests) {
                        const enriched = this._enrichAttackPayload(ptk_request.updateRawRequest(req, null, attack.action?.options), module, attack)
                        const fingerprint = this._fingerprintFromPayload(enriched) || planFingerprint
                        const task = this._createTask({
                            module,
                            attack,
                            payload: enriched,
                            type: 'active',
                            fingerprint
                        })
                        task.order = plan.tasks.length
                        plan.tasks.push(task)
                        this._registerPlannedTask()
                    }
                } else if (module.type === 'passive') {
                    const passivePayload = { metadata: Object.assign({}, attack, module.metadata) }
                    const task = this._createTask({
                        module,
                        attack,
                        payload: passivePayload,
                        type: 'passive',
                        fingerprint: planFingerprint
                    })
                    task.order = plan.tasks.length
                    plan.tasks.push(task)
                    this._registerPlannedTask()
                }
            }
        }

        return plan
    }

    _enrichAttackPayload(schema, module, attack) {
        if (!schema) return schema
        const payload = JSON.parse(JSON.stringify(schema))
        payload.metadata = Object.assign({}, payload.metadata, module.metadata, attack)
        return payload
    }

    _createTask({ module, attack, payload, type, fingerprint }) {
        return {
            id: ptk_utils.attackId(),
            type,
            module,
            moduleId: module?.id,
            moduleName: module?.name,
            moduleAsync: module?.async !== false,
            attack,
            attackKey: attack?.id || attack?.name || `${module?.id || 'module'}:${ptk_utils.attackId()}`,
            payload,
            target: payload?.metadata?.attacked || null,
            urlFingerprint: fingerprint || null,
            deferCondition: module?.async === false && !!attack?.condition
        }
    }

    _createRequestRecord(original, persist = true) {
        const requests = Array.isArray(this.scanResult.requests) ? this.scanResult.requests : []
        if (!this.scanResult.requests) this.scanResult.requests = requests
        this._requestSeq = (this._requestSeq || 0) + 1
        const requestId = `req-${this._requestSeq}`
        const record = {
            id: requestId,
            original: original ? JSON.parse(JSON.stringify(original)) : null,
            attacks: []
        }
        if (persist) {
            requests.push(record)
        }
        return record
    }

    _attachAttackToRecord(record, attackResult) {
        if (!record || !attackResult) return null
        this._attackSeq = (this._attackSeq || 0) + 1
        const attackId = `atk-${this._attackSeq}`
        const mutation = Array.isArray(attackResult?.metadata?.mutations) ? attackResult.metadata.mutations[0] : null
        const classification = this._buildAttackClassification(attackResult, attackId)
        const payloadValue = attackResult?.metadata?.payload || attackResult?.payload || mutation?.after || null
        const attackedParam = attackResult?.metadata?.attacked?.name || (Array.isArray(attackResult?.metadata?.mutations) && attackResult.metadata.mutations[0]?.name) || null
        const actionToken = attackResult?.metadata?.action?.random || null
        const responseBody = attackResult?.response?.body
        const responseLength = typeof responseBody === 'string'
            ? responseBody.length
            : (typeof attackResult?.length === 'number' ? attackResult.length : null)
        const responseTime = typeof attackResult?.response?.timeMs === 'number'
            ? attackResult.response.timeMs
            : (typeof attackResult?.timeMs === 'number' ? attackResult.timeMs : null)
        const attackMeta = {
            id: attackId,
            findingId: attackResult?.findingId || null,
            success: !!attackResult?.success,
            payload: payloadValue,
            proof: attackResult?.proof || null,
            request: attackResult?.request || null,
            response: attackResult?.response || null,
            statusCode: attackResult?.response?.statusCode || attackResult?.statusCode || null,
            timeMs: responseTime,
            length: responseLength,
            name: attackResult?.metadata?.name || attackResult?.name || classification.ruleName || null,
            param: attackedParam,
            moduleId: classification.moduleId,
            moduleName: classification.moduleName,
            ruleId: classification.ruleId,
            ruleName: classification.ruleName,
            category: classification.category,
            severity: classification.severity || null,
            vulnId: classification.vulnId || null
        }
        attackMeta.description = classification.description || null
        attackMeta.recommendation = classification.recommendation || null
        attackMeta.links = classification.links || null
        attackMeta.owasp = classification.owasp || null
        attackMeta.cwe = classification.cwe || null
        attackMeta.tags = classification.tags || null
        attackMeta.metadata = {
            description: classification.description || null,
            recommendation: classification.recommendation || null,
            links: classification.links || null,
            owasp: classification.owasp || null,
            cwe: classification.cwe || null,
            tags: classification.tags || null,
            severity: classification.severity || null,
            moduleId: classification.moduleId,
            moduleName: classification.moduleName,
            ruleId: classification.ruleId,
            ruleName: classification.ruleName,
            vulnId: classification.vulnId,
            category: classification.category
        }
        if (actionToken) {
            attackMeta.actionToken = actionToken
        }
        record.attacks.push(attackMeta)
        if (attackResult && typeof attackResult === 'object') {
            attackResult.__requestRecordEntry = attackMeta
        }
        return attackMeta
    }

    _attachAttacksToRequestRecord(attacks = [], record) {
        if (!record || !Array.isArray(attacks)) return
        attacks.forEach(attack => this._attachAttackToRecord(record, attack))
    }

    async scanRequest(raw, ontime = false) {
        const plan = await this.buildAttackPlan(raw)
        if (!plan) return null
        const context = {
            original: plan.original,
            rateLimited: !ontime,
            respectEngineState: true,
            notified: new Set(),
            executedByModule: Object.create(null)
        }
        const attacks = []
        for (const task of plan.tasks) {
            const result = await this._runTask(task, context)
            if (result) attacks.push(result)
        }
        this._normalizeResultOrder(attacks)
        const requestRecord = this._createRequestRecord(plan.original, false)
        this._attachAttacksToRequestRecord(attacks, requestRecord)
        return { original: plan.original, attacks, requestRecord }
    }

    async scanRequestWithTasks(raw, options = {}) {
        const plan = await this.buildAttackPlan(raw)
        if (!plan) return null
        const attacks = await this._executeTaskPlan(plan, options)
        return { original: plan.original, attacks }
    }

    async _executeTaskPlan(plan, options = {}) {
        const tasks = Array.isArray(plan.tasks) ? [...plan.tasks] : []
        if (!tasks.length) {
            return []
        }
        const concurrency = Math.max(1, options.concurrency || this.concurrency || 1)
        const results = []
        const workers = new Set()
        const context = {
            original: plan.original,
            rateLimited: options.rateLimited !== false,
            respectEngineState: options.respectEngineState ?? false,
            notified: new Set(),
            executedByModule: Object.create(null)
        }

        const launch = () => {
            const task = tasks.shift()
            if (!task) return null
            const runner = (async () => {
                try {
                    const res = await this._runTask(task, context)
                    if (res) results.push(res)
                } catch (err) {
                    console.error('DAST attack task failed', err)
                }
            })()
            workers.add(runner)
            runner.finally(() => workers.delete(runner))
            return runner
        }

        while (tasks.length || workers.size) {
            while (workers.size < concurrency && tasks.length) {
                launch()
            }
            if (workers.size) {
                await Promise.race(workers)
            }
        }
        await Promise.all(workers)
        this._normalizeResultOrder(results)
        return results
    }

    async _runTask(task, context) {
        if (!task || !task.module) return null

        const automationToken = this._automationTaskStarted()
        let taskError = null
        try {
            if (this._isUniqueAttackAlreadySuccessful(task)) {
                return null
            }

            if (this._shouldSkipTaskDueToStrategy(task)) {
                return null
            }

            const moduleId = task.moduleId || task.module?.id || null
            const executedByModule = context?.executedByModule || null
            const requestKey = (() => {
                const req = context?.original?.request || {}
                const method = (req.method || '').toUpperCase()
                const url = req.url || ''
                return `${moduleId || 'module'}|${method}|${url}`
            })()
            const executedHistory = !task.moduleAsync && moduleId && executedByModule
                ? (executedByModule[requestKey] ||= [])
                : null
            const recordExecuted = (entry) => {
                if (!executedHistory || !entry) return
                executedHistory.unshift(entry)
                if (executedHistory.length > 5) executedHistory.pop()
            }
            if (executedHistory) {
                task.module.executed = executedHistory
            }
            if (task.deferCondition && task.attack?.condition) {
                const conditionPayload = { metadata: Object.assign({}, task.attack, task.module.metadata) }
                const shouldRun = task.module.validateAttackConditions(conditionPayload, context.original)
                if (!shouldRun) {
                    this._notifyAttackCompleted(task, context)
                    return null
                }
            }

            const shouldThrottle = task.type !== 'passive' && context?.rateLimited !== false
            if (shouldThrottle) {
                while (true) {
                    if (this.canSendRequest()) break
                    if (context?.respectEngineState !== false && !this.isRunning) break
                    await this._sleep(20)
                }
            }
            this._incrementStrategyStat('totalJobsExecuted')

            if (task.type === 'spa') {
                const res = await this._runSpaAttack(task)
                this._notifyAttackCompleted(task, context)
                if (res) {
                    this._decorateAttackResult(res, task)
                }
                if (res?.success) {
                    this._recordStrategyFinding(task, res)
                }
                if (res?.success && !this._shouldRecordSuccess(task)) {
                    return null
                }
                if (res) this._tagResultOrder(res, task)
                return res
            } else if (task.type === 'active') {
                const executed = await this.activeAttack(task.payload)
                if (executed) {
                    const trackingResult = await this._runTracking(task, executed)
                    if (trackingResult?.success) {
                        const combined = Object.assign(executed, trackingResult)
                        this._decorateAttackResult(combined, task)
                        if (combined?.success) {
                            this._recordStrategyFinding(task, combined)
                        }
                        if (combined?.success && !this._shouldRecordSuccess(task)) {
                            recordExecuted(combined)
                            this._notifyAttackCompleted(task, context)
                            return null
                        }
                        this._tagResultOrder(combined, task)
                        recordExecuted(combined)
                        this._notifyAttackCompleted(task, context)
                        return combined
                    }
                }
                if (executed && task.attack?.validation) {
                    const res = task.module.validateAttack(executed, context.original)
                    const combined = Object.assign(executed, res)
                    if (task.attack?.id === 'jwt_1') {
                        combined.__jwt1 = true
                    }
                    this._decorateAttackResult(combined, task)
                    if (combined?.success) {
                        this._recordStrategyFinding(task, combined)
                    }
                    if (combined?.success && !this._shouldRecordSuccess(task)) {
                        recordExecuted(combined)
                        this._notifyAttackCompleted(task, context)
                        return null
                    }
                    this._tagResultOrder(combined, task)
                    recordExecuted(combined)
                    this._notifyAttackCompleted(task, context)
                    return combined
                }
                recordExecuted(executed)
                this._notifyAttackCompleted(task, context)
                return null
            } else if (task.type === 'passive') {
                const res = task.module.validateAttack(task.payload, context.original)
                this._notifyAttackCompleted(task, context)
                if (res.success) {
                    const combined = Object.assign({}, task.payload, res)
                    combined.request =
                        combined.request ||
                        context.original?.request ||
                        context.original ||
                        null
                    combined.response =
                        combined.response ||
                        context.original?.response ||
                        null
                    if (!this._shouldRecordSuccess(task)) {
                        return null
                    }
                    if (!this._shouldRecordPassiveUnique(combined, task, context.original)) {
                        return null
                    }
                    this._recordStrategyFinding(task, combined)
                    this._decorateAttackResult(combined, task)
                    this._tagResultOrder(combined, task)
                    return combined
                }
            }
            return null
        } catch (err) {
            taskError = err
            throw err
        } finally {
            this._automationTaskFinished(automationToken, taskError)
        }
    }

    _notifyAttackCompleted(task, context) {
        if (!task) return
        const key = task.attackKey || task.id
        if (context?.notified?.has(key)) return
        context?.notified?.add(key)
        const attack = task.attack
        browser.runtime.sendMessage({
            channel: "ptk_background2popup_rattacker",
            type: "attack completed",
            // Avoid cloning full scanResult for progress updates.
            info: { name: attack?.name || task?.attack?.name || "Attack completed" }
        }).catch(e => e)
    }

    _tagResultOrder(result, task) {
        if (!result || !task) return
        result.__taskOrder = task.order ?? 0
    }

    _normalizeResultOrder(attacks = []) {
        attacks.sort((a, b) => {
            const ao = typeof a === 'object' && a !== null ? (a.__taskOrder ?? 0) : 0
            const bo = typeof b === 'object' && b !== null ? (b.__taskOrder ?? 0) : 0
            return ao - bo
        })
        for (const item of attacks) {
            if (item && typeof item === 'object' && Object.prototype.hasOwnProperty.call(item, '__taskOrder')) {
                delete item.__taskOrder
            }
        }
        return attacks
    }

    _shouldRecordSuccess(task) {
        if (!task || !task.module) return true
        const meta = task.module.metadata || {}
        if (meta.unique === false) {
            if (!this._uniqueAttackSuccess) this._uniqueAttackSuccess = new Set()
            const key = `${task.moduleId || task.moduleName || 'module'}|${task.attackKey || task.id}`
            if (this._uniqueAttackSuccess.has(key)) {
                return false
            }
            this._uniqueAttackSuccess.add(key)
        }
        return true
    }

    _shouldRecordPassiveUnique(result, task, original) {
        if (!task || !result) return true
        const meta = task.module?.metadata || {}
        if (meta.unique !== true) return true
        if (task.type !== 'passive') return true
        if (!this._passiveUniqueFindingKeys) this._passiveUniqueFindingKeys = new Set()

        const moduleId = task.moduleId || task.module?.id || task.moduleName || 'module'
        const ruleId = result.ruleId || task.attack?.id || task.attack?.name || 'rule'
        const req = result.request || original?.request || original || {}
        const url = req?.url || req?.ui_url || req?.uiUrl || null
        const param =
            result.param ||
            result.metadata?.attacked?.name ||
            (Array.isArray(result.metadata?.mutations) && result.metadata.mutations[0]?.name) ||
            null
        const key = `${moduleId}|${ruleId}|${url || ''}|${param || ''}`
        if (this._passiveUniqueFindingKeys.has(key)) {
            return false
        }
        this._passiveUniqueFindingKeys.add(key)
        return true
    }

    _isUniqueAttackAlreadySuccessful(task) {
        if (!task || !task.module) return false
        const meta = task.module.metadata || {}
        if (meta.unique === false) {
            if (!this._uniqueAttackSuccess) this._uniqueAttackSuccess = new Set()
            const key = `${task.moduleId || task.moduleName || 'module'}|${task.attackKey || task.id}`
            return this._uniqueAttackSuccess.has(key)
        }
        return false
    }

    _enqueuePlan(plan) {
        if (!plan) return
        plan.pending = plan.tasks?.length || 0
        plan.attacks = []
        plan.requestRecord = this._createRequestRecord(plan.original)
        plan.context = {
            original: plan.original,
            rateLimited: true,
            respectEngineState: true,
            notified: new Set(),
            executedByModule: Object.create(null)
        }
        this._activePlans.set(plan.id, plan)

        if (plan.pending === 0) {
            this._finalizePlan(plan)
            return
        }

        plan.tasks.forEach((task, index) => {
            task.planId = plan.id
            if (typeof task.order !== 'number') {
                task.order = index
            }
            this._taskQueue.push(task)
        })
        plan.tasks = []
        this._ensureTaskWorkers()
    }

    _finalizePlan(plan) {
        if (!plan || !this._activePlans?.has(plan.id)) return
        this._normalizeResultOrder(plan.attacks)
        if (plan.requestRecord) {
            this._attachAttacksToRequestRecord(plan.attacks, plan.requestRecord)
        }
        const result = {
            original: plan.original,
            attacks: plan.attacks,
            requestRecord: plan.requestRecord
        }
        this.updateScanResult(result)
        this._activePlans.delete(plan.id)
        plan.context = null
        this._notifyIdleResolvers()
    }

    _ensureTaskWorkers() {
        if (!this.isRunning) return
        if (!this._taskWorkers) this._taskWorkers = new Set()
        const target = Math.max(1, this.concurrency || 1)
        while (this._taskWorkers.size < target) {
            const worker = this._taskWorkerLoop()
            this._taskWorkers.add(worker)
            worker.finally(() => {
                this._taskWorkers.delete(worker)
                if (this.isRunning) {
                    this._ensureTaskWorkers()
                }
            })
        }
    }

    async _taskWorkerLoop() {
        while (this.isRunning) {
            const task = this._dequeueRunnableTask()
            if (!task) {
                await this._sleep(50)
                continue
            }

            const plan = this._activePlans.get(task.planId)
            if (!plan) {
                this._releaseModuleLock(task)
                this._releasePlanLock(task)
                continue
            }

            try {
                this.activeCount = Math.max(0, this.activeCount)
                this.activeCount++
                const res = await this._runTask(task, plan.context)
                if (res) {
                    plan.attacks.push(res)
                }
            } catch (err) {
                console.error('DAST worker error', {
                    module: task?.moduleId || task?.moduleName,
                    attack: task?.attackKey || task?.attack?.id,
                    url: task?.payload?.request?.url,
                    name: err?.name,
                    message: err?.message,
                    cause: err?.cause?.message || err?.cause || null
                }, err)
            } finally {
                this.activeCount = Math.max(0, this.activeCount - 1)
                this._releaseModuleLock(task)
                this._releasePlanLock(task)
                plan.pending = Math.max(0, (plan.pending || 0) - 1)
                if (plan.pending === 0) {
                    this._finalizePlan(plan)
                }
                this._notifyIdleResolvers()
            }
        }
    }

    _dequeueRunnableTask() {
        if (!this._taskQueue?.length) return null
        for (let i = 0; i < this._taskQueue.length; i++) {
            const task = this._taskQueue[i]
            if (!task) {
                this._taskQueue.splice(i, 1)
                i--
                continue
            }
            if (!task.moduleAsync && task.moduleId && this._moduleLocks.has(task.moduleId)) {
                continue
            }
            if (task.planId && this._planLocks.has(task.planId)) {
                continue
            }
            const planExists = this._activePlans.has(task.planId)
            if (!planExists) {
                this._taskQueue.splice(i, 1)
                i--
                continue
            }
            this._taskQueue.splice(i, 1)
            if (!task.moduleAsync && task.moduleId) {
                this._moduleLocks.add(task.moduleId)
                task._lockedModule = task.moduleId
            }
            if (task.planId) {
                this._planLocks.add(task.planId)
                task._planLocked = true
            }
            return task
        }
        return null
    }

    _releaseModuleLock(task) {
        if (task && !task.moduleAsync && task._lockedModule) {
            this._moduleLocks.delete(task._lockedModule)
            delete task._lockedModule
        }
    }

    _releasePlanLock(task) {
        if (task && task._planLocked && task.planId) {
            this._planLocks.delete(task.planId)
            delete task._planLocked
        }
    }

    _simpleFingerprint(rawRequest, response) {
        const raw = typeof rawRequest === 'object' ? rawRequest.raw : rawRequest
        const line = raw ? raw.split(/\r?\n/)[0] : ''
        const parts = line.trim().split(/\s+/)
        const method = (parts[0] || 'GET').toUpperCase()
        const urlPart = (typeof rawRequest === 'object' ? (rawRequest.ui_url || rawRequest.uiUrl) : null) || parts[1] || response?.ui_url || response?.url || '/'
        const base = response?.url || urlPart
        try {
            const urlObj = new URL(urlPart, urlPart && urlPart.startsWith('http') ? undefined : base || 'http://localhost')
            const host = (urlObj.host || '').toLowerCase()
            let pathname = urlObj.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            pathname = pathname.replace(/\/+/g, '/')
            const queryNames = new Set()
            urlObj.searchParams.forEach((_, key) => queryNames.add(key.toLowerCase()))
            const querySig = Array.from(queryNames).sort().join('&')
            const partsOut = ['http', host, pathname, method]
            if (querySig) partsOut.push(`q:${querySig}`)
            return partsOut.join('|')
        } catch (e) {
            return ''
        }
    }

    _buildSpaTasks(original, module, attack, rawMeta = {}, defaultFingerprint = null) {
        const tasks = []
        const uiUrl = rawMeta.ui_url || rawMeta.uiUrl || original?.request?.ui_url || original?.request?.url
        if (!uiUrl) return tasks
        try {
            const parsed = new URL(uiUrl)
            const hasHashQuery = parsed.hash && parsed.hash.includes('?')
            if (!hasHashQuery) return tasks
        } catch (_) {
            return tasks
        }

        const params = getSearchParamsFromUrlOrHash(uiUrl)
        const names = Array.from(new Set(Array.from(params.keys())))
        if (!names.length) {
            // still run once for checks that do not need params (token scans, sensitive data)
            names.push('')
        }

        const spaCfg = attack.spa || {}
        const payloads = Array.isArray(spaCfg.payloads) && spaCfg.payloads.length ? spaCfg.payloads : [spaCfg.markerToken || ptk_utils.attackParamId()]
        const checks = Array.isArray(spaCfg.checks) && spaCfg.checks.length ? spaCfg.checks : ['dom_xss']

        for (const name of names) {
            for (const payload of payloads) {
                const fingerprint = this._fingerprintFromUrl(uiUrl) || defaultFingerprint
                const task = this._createTask({
                    module,
                    attack,
                    payload: {
                        param: name,
                        payload,
                        checks,
                        markerDomain: spaCfg.markerDomain,
                        markerToken: spaCfg.markerToken || payload,
                        ui_url: uiUrl,
                        metadata: Object.assign({}, attack, module.metadata)
                    },
                    type: 'spa',
                    fingerprint
                })
                task.attackKey = `${task.attackKey}|${name}`
                tasks.push(task)
                this._registerPlannedTask()
            }
        }
        return tasks
    }

    _moduleSupportsAtomic(module) {
        if (!module) return false
        if (typeof module.supportsAtomic === 'boolean') return module.supportsAtomic
        if (typeof module.atomic === 'boolean') return module.atomic
        if (typeof module.metadata?.supportsAtomic === 'boolean') return module.metadata.supportsAtomic
        return true
    }

    _shouldUseBulkAttack(moduleSupportsAtomic) {
        return Boolean(this.strategyConfig?.atomic && moduleSupportsAtomic)
    }

    _resolveStrategyConfig(value) {
        const key = typeof value === 'string'
            ? value.toUpperCase()
            : (value?.strategy ? String(value.strategy).toUpperCase() : DEFAULT_SCAN_STRATEGY)
        const base = SCAN_STRATEGY_CONFIGS[key] || SCAN_STRATEGY_CONFIGS[DEFAULT_SCAN_STRATEGY]
        return Object.assign({}, base)
    }

    _createStrategyStats(strategy) {
        return {
            strategy: strategy || DEFAULT_SCAN_STRATEGY,
            totalJobsPlanned: 0,
            totalJobsExecuted: 0,
            skippedDueToStrategy: 0
        }
    }

    _initializeStrategyState(strategyConfig = this.strategyConfig) {
        const cfg = strategyConfig && strategyConfig.strategy ? Object.assign({}, strategyConfig) : this._resolveStrategyConfig(strategyConfig)
        this.strategyConfig = cfg
        this.scanStats = this._createStrategyStats(cfg.strategy)
        this._strategyFindingKeys = new Set()
        if (this.scanResult) {
            this.scanResult.settings = Object.assign({}, this.scanResult.settings, { scanStrategy: cfg.strategy })
            this._syncScanStats()
        }
    }

    _applyScanStrategy(strategyValue) {
        const cfg = this._resolveStrategyConfig(strategyValue || this.strategyConfig?.strategy)
        this._initializeStrategyState(cfg)
    }

    _syncScanStats() {
        if (this.scanResult) {
            this.scanResult.scanStats = Object.assign({}, this.scanStats)
        }
    }

    _incrementStrategyStat(field, delta = 1) {
        if (!this.scanStats || typeof this.scanStats[field] === 'undefined') return
        this.scanStats[field] += delta
        if (this.scanStats[field] < 0) {
            this.scanStats[field] = 0
        }
        this._syncScanStats()
    }

    _registerPlannedTask() {
        this._incrementStrategyStat('totalJobsPlanned', 1)
    }

    _fingerprintFromSchema(schema) {
        if (!schema) return null
        if (schema.request) {
            return this._fingerprintFromRequest(schema.request)
        }
        return null
    }

    _fingerprintFromPayload(payload) {
        if (!payload) return null
        if (payload.request) {
            return this._fingerprintFromRequest(payload.request)
        }
        const uiUrl = payload.ui_url || payload.uiUrl
        if (uiUrl) {
            return this._fingerprintFromUrl(uiUrl)
        }
        return null
    }

    _fingerprintFromRequest(req) {
        if (!req) return null
        const method = (req.method || 'GET').toUpperCase()
        const targetUrl = req.url || req.path || '/'
        const base = this._guessRequestBase(req)
        try {
            const resolved = new URL(targetUrl, targetUrl && targetUrl.startsWith('http') ? undefined : base || 'http://localhost')
            const host = (resolved.host || '').toLowerCase()
            let pathname = resolved.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            const names = new Set()
            resolved.searchParams.forEach((_, key) => names.add(key.toLowerCase()))
            if (Array.isArray(req.queryParams)) {
                for (const param of req.queryParams) {
                    if (param?.name) {
                        names.add(String(param.name).toLowerCase())
                    }
                }
            }
            const querySig = Array.from(names).sort().join('&')
            const parts = [method, host, pathname]
            if (querySig) parts.push(`q:${querySig}`)
            return parts.join('|')
        } catch (_) {
            return `${method}|${targetUrl || ''}`
        }
    }

    _guessRequestBase(req) {
        if (req?.baseUrl) return req.baseUrl
        const headers = Array.isArray(req?.headers) ? req.headers : []
        const hostHeader = headers.find(h => (h.name || '').toLowerCase() === 'host')
        if (hostHeader?.value) {
            const trimmed = hostHeader.value.trim()
            if (/^https?:\/\//i.test(trimmed)) {
                return trimmed
            }
            return `http://${trimmed}`
        }
        return 'http://localhost'
    }

    _fingerprintFromUrl(rawUrl) {
        if (!rawUrl) return null
        try {
            const resolved = new URL(rawUrl, rawUrl && rawUrl.startsWith('http') ? undefined : 'http://localhost')
            const host = (resolved.host || '').toLowerCase()
            let pathname = resolved.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            const names = new Set()
            resolved.searchParams.forEach((_, key) => names.add(key.toLowerCase()))
            const querySig = Array.from(names).sort().join('&')
            const parts = ['SPA', host, pathname]
            if (querySig) parts.push(`q:${querySig}`)
            return parts.join('|')
        } catch (_) {
            return rawUrl
        }
    }

    _extractParamName(task, result) {
        const meta = result?.metadata || task?.payload?.metadata || {}
        const attacked = meta.attacked || task?.target
        if (attacked) {
            if (typeof attacked === 'string') return attacked
            if (typeof attacked?.name === 'string') return attacked.name
        }
        if (typeof task?.target === 'string') return task.target
        return null
    }

    _taskFindingKey(task, result) {
        const scope = this.strategyConfig?.dedupeScope
        if (!scope) return null
        const fingerprint = task?.urlFingerprint || this._fingerprintFromPayload(task?.payload)
        const moduleId = task?.moduleId || task?.module?.id || task?.moduleName
        if (!fingerprint || !moduleId) return null
        if (scope === 'url-module') {
            return `${fingerprint}|${moduleId}`
        }
        const paramName = this._extractParamName(task, result) || '__all__'
        return `${fingerprint}|${moduleId}|${paramName}`
    }

    _shouldSkipTaskDueToStrategy(task) {
        if (!this.strategyConfig?.stopOnFirstFinding) return false
        const key = this._taskFindingKey(task)
        if (!key) return false
        if (this._strategyFindingKeys?.has(key)) {
            this._incrementStrategyStat('skippedDueToStrategy', 1)
            return true
        }
        return false
    }

    _recordStrategyFinding(task, result) {
        if (!this.strategyConfig?.stopOnFirstFinding) return
        const key = this._taskFindingKey(task, result)
        if (!key) return
        if (!this._strategyFindingKeys) {
            this._strategyFindingKeys = new Set()
        }
        this._strategyFindingKeys.add(key)
    }

    async _runSpaAttack(task) {
        const payload = task?.payload || {}
        const uiUrl = payload.ui_url
        if (!uiUrl || !payload.param) return null

        const runChecks = async () => {
            return this._withSpaAttackTab(uiUrl, async (tabId) => {
                try {
                    return await browser.tabs.sendMessage(tabId, {
                        type: 'spaParamTest',
                        param: payload.param,
                        payload: payload.payload,
                        checks: payload.checks || [],
                        markerDomain: payload.markerDomain,
                        markerToken: payload.markerToken
                    })
                } catch (err) {
                    if (browser?.scripting?.executeScript) {
                        try {
                            await browser.scripting.executeScript({
                                target: { tabId },
                            files: ['ptk/content/spa_hash_harness.js']
                        })
                        } catch (_) { }
                    }
                    return browser.tabs.sendMessage(tabId, {
                        type: 'spaParamTest',
                        param: payload.param,
                        payload: payload.payload,
                        checks: payload.checks || [],
                        markerDomain: payload.markerDomain,
                        markerToken: payload.markerToken
                    })
                }
            })
        }

        try {
            const res = await runChecks()
            const checks = payload.checks || []

            const pickDomXss = () => {
                const dx = res?.dom_xss
                if (!dx || !dx.vulnerable) return null
                if (dx.sinkKey && this._spaSeenSinks?.has(dx.sinkKey)) {
                    return null
                }
                if (dx.sinkKey && this._spaSeenSinks) {
                    this._spaSeenSinks.add(dx.sinkKey)
                }
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks,
                    sinkKey: dx.sinkKey || null,
                    executed: !!dx.executed,
                    reflected: !!dx.reflected,
                    context: dx.context || null
                })
                const proof = JSON.stringify({
                    executed: !!dx.executed,
                    reflected: !!dx.reflected,
                    sinkKey: dx.sinkKey || null,
                    context: dx.context || null
                })
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickDomRedirect = () => {
                const dr = res?.dom_redirect
                if (!dr || !dr.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(dr.evidence || dr)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickJsInjection = () => {
                const ji = res?.js_injection
                if (!ji || !ji.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(ji.evidence || ji)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickTokenInFragment = () => {
                const t = res?.token_in_fragment
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.tokens || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickTokenLeak = () => {
                const t = res?.token_leak_third_party
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.evidence || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickClientStorage = () => {
                const t = res?.client_storage_leak
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.entries || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickPostMessage = () => {
                const t = res?.postmessage
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.evidence || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            const pickSensitiveData = () => {
                const t = res?.spa_sensitive_data
                if (!t || !t.vulnerable) return null
                const metadata = Object.assign({}, payload.metadata, {
                    attacked: { location: 'hash', name: payload.param },
                    payload: payload.payload,
                    checks: payload.checks
                })
                const proof = JSON.stringify(t.matches || t)
                return {
                    success: true,
                    metadata,
                    request: { url: uiUrl, ui_url: uiUrl, method: 'GET' },
                    response: {},
                    proof
                }
            }

            for (const chk of checks) {
                if (chk === 'dom_xss') {
                    const r = pickDomXss()
                    if (r) return r
                } else if (chk === 'dom_redirect') {
                    const r = pickDomRedirect()
                    if (r) return r
                } else if (chk === 'js_injection') {
                    const r = pickJsInjection()
                    if (r) return r
                } else if (chk === 'token_in_fragment') {
                    const r = pickTokenInFragment()
                    if (r) return r
                } else if (chk === 'token_leak_third_party') {
                    const r = pickTokenLeak()
                    if (r) return r
                } else if (chk === 'client_storage_leak') {
                    const r = pickClientStorage()
                    if (r) return r
                } else if (chk === 'postmessage') {
                    const r = pickPostMessage()
                    if (r) return r
                } else if (chk === 'spa_sensitive_data') {
                    const r = pickSensitiveData()
                    if (r) return r
                }
            }

            return null
        } catch (err) {
            console.error('SPA attack failed', {
                url: uiUrl,
                param: payload.param,
                message: err?.message
            }, err)
            return null
        }
    }

    async _withSpaAttackTab(url, fn) {
        let tabId = null
        try {
            const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
            if (isFirefox) {
                const markedUrl = this._addSpaDialogMarker(url)
                const tab = await browser.tabs.create({ url: markedUrl, active: false })
                tabId = tab.id
                await this._markSpaAttackTab(tabId, { runAt: "document_start" })
            } else {
                const tab = await browser.tabs.create({ url: "about:blank", active: false })
                tabId = tab.id
                await this._markSpaAttackTab(tabId)
                await browser.tabs.update(tabId, { url })
            }
            await this._waitForTabReady(tabId)
            const res = await fn(tabId, url)
            return res
        } finally {
            if (tabId !== null) {
                await this._detachDialogAutoDismiss(tabId)
                try { await browser.tabs.remove(tabId) } catch (_) { }
            }
        }
    }

    _addSpaDialogMarker(url) {
        const marker = "ptk_dast=1"
        if (!url || url.includes(marker)) return url
        const hashIndex = url.indexOf("#")
        if (hashIndex >= 0) {
            const base = url.slice(0, hashIndex)
            const hash = url.slice(hashIndex + 1)
            const joiner = hash.includes("?") ? "&" : "?"
            return `${base}#${hash}${joiner}${marker}`
        }
        const joiner = url.includes("?") ? "&" : "?"
        return `${url}${joiner}${marker}`
    }

    async _attachDialogAutoDismiss(tabId) {
        const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
        if (isFirefox) return false
        if (!browser?.debugger || !tabId) return false
        const target = { tabId }
        try {
            await browser.debugger.attach(target, "1.3")
        } catch (_) {
            return false
        }
        try {
            await browser.debugger.sendCommand(target, "Page.enable")
            await browser.debugger.sendCommand(target, "Runtime.enable")
        } catch (_) { }
        this._ensureDebuggerDialogListener()
        this._debuggerDialogTabs.add(tabId)
        return true
    }

    async _detachDialogAutoDismiss(tabId) {
        if (!browser?.debugger || !tabId) return
        this._debuggerDialogTabs.delete(tabId)
        try {
            await browser.debugger.detach({ tabId })
        } catch (_) { }
    }

    _ensureDebuggerDialogListener() {
        if (this._debuggerDialogListener || !browser?.debugger?.onEvent) return
        this._debuggerDialogListener = (source, method, params) => {
            if (!source?.tabId || !this._debuggerDialogTabs.has(source.tabId)) return
            if (method !== "Page.javascriptDialogOpening" && method !== "Runtime.javascriptDialogOpening") return
            try {
                browser.debugger.sendCommand(source, "Page.handleJavaScriptDialog", { accept: true })
            } catch (_) { }
        }
        browser.debugger.onEvent.addListener(this._debuggerDialogListener)
    }

    async _markSpaAttackTab(tabId, opts = {}) {
        if (!tabId) return
        const marker = 'ptk_spa_attack_tab'
        const runAt = opts.runAt || "document_start"
        const code = (name) => {
            try {
                if (!window.name || !window.name.includes(name)) {
                    window.name = (window.name ? window.name + " " : "") + name
                }
            } catch (_) { }
        }
        if (browser?.scripting?.executeScript) {
            try {
                await browser.scripting.executeScript({
                    target: { tabId, allFrames: true },
                    func: code,
                    args: [marker]
                })
                return
            } catch (_) { }
        }
        if (browser?.tabs?.executeScript) {
            try {
                await browser.tabs.executeScript(tabId, {
                    code: `try{var n=${JSON.stringify(marker)};if(!window.name||window.name.indexOf(n)===-1){window.name=(window.name?window.name+' ':'')+n;}}catch(_){}`,
                    allFrames: true,
                    runAt
                })
            } catch (_) { }
        }
    }

    async _waitForTabReady(tabId, timeoutMs = 8000) {
        return new Promise((resolve) => {
            let done = false
            const finish = () => {
                if (done) return
                done = true
                try { browser.tabs.onUpdated.removeListener(listener) } catch (_) { }
                resolve()
            }
            const timer = setTimeout(() => {
                clearTimeout(timer)
                finish()
            }, timeoutMs)
            const listener = (updatedTabId, info) => {
                if (updatedTabId === tabId && info.status === 'complete') {
                    clearTimeout(timer)
                    finish()
                }
            }
            browser.tabs.onUpdated.addListener(listener)
        })
    }

    async _drainRequestQueue() {
        while (this.isRunning && this._requestQueue.size()) {
            const raw = this._requestQueue.dequeue()
            try {
                const plan = await this.buildAttackPlan(raw)
                if (!this.isRunning) break
                if (plan) {
                    this._enqueuePlan(plan)
                }
            } catch (err) {
                console.warn('Failed to build attack plan', err)
            }
        }
    }


    async activeAttack(schema) {
        try {
            let request = new ptk_request()
            if (!schema.opts) schema.opts = {}
            schema.opts.ptk_source = 'dast'
            const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
            if (isFirefox) {
                request.useListeners = true
                schema.opts.use_dnr = false
            }
            if (typeof schema.opts.override_headers === 'undefined') {
                schema.opts.override_headers = true
            }
            schema.opts.force_dnr = true
            schema.opts.log_fingerprint = true
            if (typeof schema.opts.requestTimeoutMs === 'undefined' || schema.opts.requestTimeoutMs === null) {
                const defaultTimeout = this.settings?.requestTimeoutMs
                if (Number.isFinite(defaultTimeout) && defaultTimeout > 0) {
                    schema.opts.requestTimeoutMs = defaultTimeout
                }
            }
            return request.sendRequest(schema)
        } catch (e) {
            // optionally: log or handle
        }
    }

    async executeOriginal(schema) {
        let _schema = JSON.parse(JSON.stringify(schema))
        let request = new ptk_request()
        _schema.opts = _schema.opts || {}
        _schema.opts.ptk_source = 'dast'
        const isFirefox = typeof browser !== 'undefined' && !!browser?.runtime?.getBrowserInfo
        if (isFirefox) {
            request.useListeners = true
            _schema.opts.use_dnr = false
        }
        _schema.opts.override_headers = true
        _schema.opts.follow_redirect = true
        return Promise.resolve(request.sendRequest(_schema))
    }

    async _runTracking(task, executed) {
        const tracking = task?.attack?.tracking
        if (!tracking || tracking.enabled !== true) return null
        const mode = tracking.mode || 'followup_get'
        if (mode !== 'followup_get') return null

        const marker = tracking.marker || 'PTK_UPLOAD_TEST'
        const trackingConfidence = typeof tracking.confidence === 'number' ? tracking.confidence : 95
        const responseBody = executed?.response?.body || ''
        if (marker && responseBody.includes(marker)) {
            return {
                success: true,
                proof: `Upload marker detected in response body.`,
                confidence: trackingConfidence,
                trackingConfirmed: true
            }
        }

        const candidates = this._extractTrackingUrls(task, executed)
        if (!candidates.length) return null

        for (const url of candidates) {
            const followup = this._buildFollowupRequest(executed, url)
            if (!followup) continue
            const res = await this.activeAttack(followup)
            const body = res?.response?.body || ''
            if (marker && body.includes(marker)) {
                return {
                    success: true,
                    proof: `Upload marker retrieved from ${url}.`,
                    tracking: { url },
                    confidence: trackingConfidence,
                    trackingConfirmed: true
                }
            }
        }

        return null
    }

    _extractTrackingUrls(task, executed) {
        const tracking = task?.attack?.tracking || {}
        const filename =
            tracking.filename ||
            task?.attack?.action?.files?.[0]?.filename ||
            task?.attack?.metadata?.action?.files?.[0]?.filename ||
            null
        const urls = new Set()
        const headers = executed?.response?.headers || []
        const locationHeader = headers.find(
            (h) => (h?.name || '').toLowerCase() === 'location'
        )
        if (locationHeader?.value) {
            if (!filename || locationHeader.value.includes(filename)) {
                urls.add(locationHeader.value)
            }
        }

        const body = executed?.response?.body || ''
        if (filename && body.includes(filename)) {
            const escaped = filename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            const absRe = new RegExp(`https?:\\/\\/[^\"'\\s<>]*${escaped}[^\"'\\s<>]*`, 'ig')
            const relRe = new RegExp(`\\/[^\"'\\s<>]*${escaped}[^\"'\\s<>]*`, 'ig')
            let match
            while ((match = absRe.exec(body))) urls.add(match[0])
            while ((match = relRe.exec(body))) urls.add(match[0])
        }

        return Array.from(urls).slice(0, 3)
    }

    _buildFollowupRequest(executed, url) {
        if (!executed?.request?.url || !url) return null
        let resolved = url
        try {
            resolved = new URL(url, executed.request.url).toString()
        } catch {
            return null
        }

        const schema = JSON.parse(JSON.stringify(executed))
        schema.request = schema.request || {}
        schema.response = {}
        schema.request.method = 'GET'
        schema.request.url = resolved
        schema.request.body = null
        schema.request.raw = null
        schema.opts = schema.opts || {}
        schema.opts.override_headers = true
        schema.opts.follow_redirect = true
        return schema
    }

    _sleep(ms) {
        return new Promise(r => setTimeout(r, ms))
    }

    _confirmAttackFromContent(data) {
        if (!data?.attackValue?.ptk) return
        const token = data.attackValue.ptk
        const requests = Array.isArray(this.scanResult?.requests) ? this.scanResult.requests : []
        for (const request of requests) {
            const attacks = Array.isArray(request?.attacks) ? request.attacks : []
            for (let idx = 0; idx < attacks.length; idx++) {
                const attack = attacks[idx]
                if (!attack || attack.success) continue
                if (attack.actionToken && attack.actionToken === token) {
                    attack.success = true
                    attack.proof = 'Confirmed by code execution on ' + data.location + '. Attack parameter value is: ' + token
                    this._addUnifiedFinding(request, attack, idx)
                    return
                }
            }
        }
    }

    _addUnifiedFinding(requestRecord, attack, index = 0) {
        if (!requestRecord || !attack || !attack.success || attack.__findingRecorded) return
        const classification = this._buildAttackClassification(attack, `attack-${index}`)
        const moduleId = classification.moduleId
        const moduleName = classification.moduleName
        const vulnId = classification.vulnId
        const ruleId = classification.ruleId
        const ruleName = classification.ruleName
        const severity = classification.severity
        const reqSchema = attack.request && attack.request.request ? attack.request.request : attack.request
        const originalReq = requestRecord?.original?.request || requestRecord?.original || {}
        const attackRecord = attack.__requestRecordEntry || attack
        const mutation = Array.isArray(attack?.metadata?.mutations) ? attack.metadata.mutations[0] : null
        const payloadValue = attack?.metadata?.payload || attack?.payload || mutation?.after || attackRecord?.payload || null
        const responseBody = attack?.response?.body || attackRecord?.response?.body
        const responseLength = typeof responseBody === 'string'
            ? responseBody.length
            : (typeof attack?.length === 'number' ? attack.length : (typeof attackRecord?.length === 'number' ? attackRecord.length : null))
        const responseTime = typeof attack?.response?.timeMs === 'number'
            ? attack.response.timeMs
            : (typeof attack?.timeMs === 'number'
                ? attack.timeMs
                : (typeof attackRecord?.response?.timeMs === 'number' ? attackRecord.response.timeMs : (typeof attackRecord?.timeMs === 'number' ? attackRecord.timeMs : null)))
        const location = {
            url: reqSchema?.url || attack.request?.url || attack.request?.ui_url || originalReq?.url || null,
            method: reqSchema?.method || attack.request?.method || originalReq?.method || null,
            param: attack.param || attack.metadata?.attacked?.name || (Array.isArray(attack.metadata?.mutations) && attack.metadata.mutations[0]?.name) || null
        }
        const logAttackId = attack.id || attack.__requestRecordEntry?.id || attack.__attackKey || null
        const originalResponse = requestRecord?.original?.response || null
        const originalRequest = requestRecord?.original?.request || requestRecord?.original || null
        const attackedParam = attack.param
            || attack.metadata?.attacked?.name
            || (Array.isArray(attack.metadata?.mutations) && attack.metadata.mutations[0]?.name)
            || null
        const attackEvidence = {
            id: logAttackId,
            param: attackedParam || null,
            payload: payloadValue || null,
            proof: attackRecord?.proof || null,
            request: attackRecord?.request || null,
            response: attackRecord?.response || null,
            statusCode: attackRecord?.response?.statusCode || attackRecord?.statusCode || null,
            timeMs: responseTime,
            length: responseLength
        }
        const confidenceDetails = this._resolveAttackConfidenceDetails(attack, classification)
        const confidence = confidenceDetails.confidence
        const attackMeta = attack?.metadata || {}
        const attackMetaEvidence = {
            attacked: attackMeta.attacked || null,
            checks: attackMeta.checks || null,
            sinkKey: attackMeta.sinkKey || null,
            executed: typeof attackMeta.executed === 'boolean' ? attackMeta.executed : null,
            reflected: typeof attackMeta.reflected === 'boolean' ? attackMeta.reflected : null,
            context: attackMeta.context || null,
            detector: attack?.detector || attackMeta.validation?.type || null,
            match: attack?.match || null,
            confidence: Number.isFinite(confidence) ? confidence : null
        }
        Object.keys(attackMetaEvidence).forEach((key) => {
            if (attackMetaEvidence[key] === null) delete attackMetaEvidence[key]
        })
        if (Object.keys(attackMetaEvidence).length) {
            attackEvidence.meta = attackMetaEvidence
        }
        const dastEvidence = {
            attackId: logAttackId,
            requestId: requestRecord?.id || null,
            param: location.param || attackedParam || null,
            payload: payloadValue || null,
            proof: attackRecord?.proof || null,
            request: attackRecord?.request || reqSchema || null,
            response: attackRecord?.response || null,
            original: {
                request: originalRequest || null,
                response: originalResponse || null
            },
            confidenceSignals: Array.isArray(confidenceDetails.signals) ? confidenceDetails.signals : [],
            attack: attackEvidence
        }
        const tags = Array.isArray(classification.tags) ? classification.tags : []
        const unifiedFinding = {
            id: `${this.scanResult.scanId || 'scan'}::DAST::${moduleId}::${ruleId}::${index}`,
            engine: "DAST",
            scanId: this.scanResult.scanId || null,
            moduleId,
            moduleName,
            ruleId,
            ruleName,
            vulnId: vulnId || moduleId,
            category: classification.category || 'dast',
            severity,
            confidence: Number.isFinite(confidence) ? confidence : null,
            owasp: classification.owasp || null,
            cwe: classification.cwe || null,
            tags: classification.tags || [],
            description: classification.description || null,
            recommendation: classification.recommendation || null,
            links: classification.links || null,
            location,
            createdAt: new Date().toISOString(),
            evidence: {
                dast: dastEvidence
            }
        }
        resolveFindingTaxonomy({
            finding: unifiedFinding,
            ruleMeta: classification.ruleMeta,
            moduleMeta: classification.moduleMeta
        })
        const normalizedFinding = normalizeFinding({
            engine: "DAST",
            moduleMeta: classification.moduleMeta || {},
            ruleMeta: classification.ruleMeta || {},
            scanId: this.scanResult?.scanId || null,
            finding: unifiedFinding
        })
        addFinding(this.scanResult, normalizedFinding)
        const groupKey = [
            "DAST",
            normalizedFinding.vulnId,
            moduleId,
            ruleId,
            normalizedFinding?.location?.url || location.url || "",
            normalizedFinding?.location?.param || location.param || ""
        ].join('@@')
        addFindingToGroup(this.scanResult, normalizedFinding, groupKey, {
            url: normalizedFinding?.location?.url || location.url,
            param: normalizedFinding?.location?.param || location.param || null
        })
        if (attack && typeof attack === 'object') {
            attack.findingId = normalizedFinding.id
            attack.__findingRecorded = true
            if (attack.__requestRecordEntry && attack.__requestRecordEntry !== attack) {
                attack.__requestRecordEntry.findingId = normalizedFinding.id
            }
        }
    }

    _decorateAttackResult(result, task) {
        if (!result || !task) return
        const moduleMeta = task.module?.metadata || {}
        const attackMeta = Object.assign({}, moduleMeta, task.attack || {}, result.metadata || {})
        result.metadata = attackMeta
        result.__moduleId = task.moduleId || task.module?.id || moduleMeta.id || attackMeta.moduleId || null
        result.__moduleName = task.moduleName || task.module?.name || moduleMeta.name || attackMeta.moduleName || result.__moduleId
        result.__moduleMetadata = moduleMeta
        result.__moduleVulnId = task.module?.vulnId || moduleMeta.vulnId || attackMeta.vulnId || null
        result.__attackKey = task.attackKey || attackMeta.id || null
    }

    _resolveAttackConfidenceDetails(attack, classification = {}) {
        const clamp = (value) => {
            if (!Number.isFinite(value)) return null
            return Math.min(100, Math.max(0, Math.round(value)))
        }
        if (attack?.trackingConfirmed) {
            return { confidence: 95, signals: ["tracking:confirmed"] }
        }
        if (attack?.metadata?.executed === true || attack?.executed === true) {
            return { confidence: 95, signals: ["execution:confirmed"] }
        }
        if (Number.isFinite(attack?.confidence)) {
            const value = clamp(attack.confidence)
            return { confidence: value, signals: [`override:attack:${value}`] }
        }
        if (Number.isFinite(attack?.metadata?.confidence)) {
            const value = clamp(attack.metadata.confidence)
            return { confidence: value, signals: [`override:rule:${value}`] }
        }
        if (Number.isFinite(attack?.metadata?.confidenceDefault)) {
            const value = clamp(attack.metadata.confidenceDefault)
            return { confidence: value, signals: [`override:module:${value}`] }
        }
        if (attack?.metadata?.validation?.rule) {
            return { confidence: 80, signals: ["validation:rule"] }
        }
        return { confidence: 30, signals: ["validation:none"] }
    }

    setAutomationHooks(hooks) {
        if (hooks && typeof hooks === 'object') {
            this.automationHooks = {
                sessionId: hooks.sessionId,
                onTaskStarted: hooks.onTaskStarted,
                onTaskFinished: hooks.onTaskFinished
            }
        } else {
            this.automationHooks = null
        }
    }

    _automationTaskStarted() {
        const hooks = this.automationHooks
        if (!hooks || typeof hooks.onTaskStarted !== 'function') {
            return null
        }
        try {
            hooks.onTaskStarted()
        } catch (_) { }
        return hooks
    }

    _automationTaskFinished(token, error) {
        if (!token || typeof token.onTaskFinished !== 'function') {
            return
        }
        try {
            token.onTaskFinished(error)
        } catch (_) { }
    }

    waitForIdle(timeoutMs) {
        if (!this.isRunning) {
            return Promise.resolve()
        }
        if (this._isIdle()) {
            return Promise.resolve()
        }
        return new Promise((resolve) => {
            const waiter = { resolve }
            if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
                waiter.timer = setTimeout(() => {
                    if (waiter.timer) {
                        clearTimeout(waiter.timer)
                        waiter.timer = null
                    }
                    this._idleResolvers.delete(waiter)
                    resolve()
                }, timeoutMs)
            }
            this._idleResolvers.add(waiter)
        })
    }

    _buildAttackClassification(attack, fallbackRuleId = null) {
        const moduleMeta = attack?.__moduleMetadata || attack?.metadata || {}
        const attackMeta = attack?.metadata || {}
        const moduleId = attack?.__moduleId || moduleMeta.id || moduleMeta.moduleId || attackMeta.moduleId || 'module'
        const moduleName = attack?.__moduleName || moduleMeta.name || moduleId
        const vulnId = attack?.__moduleVulnId || moduleMeta.vulnId || moduleMeta.category || moduleId
        const ruleId = attackMeta.id || attackMeta.ruleId || attackMeta.attackId || fallbackRuleId || attack?.__attackKey || 'attack'
        const ruleName = attackMeta.name || ruleId
        const severity = resolveEffectiveSeverity({
            moduleMeta,
            attackMeta
        })
        const category = attackMeta.category || moduleMeta.category || 'dast'
        const description = attackMeta.description || moduleMeta.description || null
        const recommendation = attackMeta.recommendation || moduleMeta.recommendation || null
        const links = attackMeta.links || moduleMeta.links || null
        const tags = Array.isArray(moduleMeta.tags) ? moduleMeta.tags : []
        return {
            moduleId,
            moduleName,
            vulnId,
            ruleId,
            ruleName,
            severity,
            category,
            owasp: moduleMeta.owasp || null,
            cwe: moduleMeta.cwe || null,
            tags,
            description,
            recommendation,
            links,
            moduleMeta,
            ruleMeta: attackMeta
        }
    }

    _isIdle() {
        const queueEmpty = !this._requestQueue?.size || this._requestQueue.size() === 0
        const noTaskQueue = !this._taskQueue?.length
        const noPlans = !this._activePlans?.size
        const noActiveTasks = (this.activeCount || 0) === 0
        const notBuilding = this.inProgress === false
        return queueEmpty && noTaskQueue && noPlans && noActiveTasks && this.isRunning
    }

    _notifyIdleResolvers() {
        if (!this._idleResolvers?.size) {
            return
        }
        if (!this._isIdle()) {
            return
        }
        this._resolveIdleResolvers()
    }

    _resolveIdleResolvers() {
        if (!this._idleResolvers?.size) {
            return
        }
        for (const waiter of this._idleResolvers) {
            if (waiter?.timer) {
                clearTimeout(waiter.timer)
            }
            try {
                waiter.resolve()
            } catch (_) {
                // ignore individual resolver errors
            }
        }
        this._idleResolvers.clear()
    }
}
