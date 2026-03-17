export class DastTaskScheduler {
    constructor({
        sleep = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms)),
        runTask = async () => null,
        normalizeResultOrder = () => {}
    } = {}) {
        this.sleep = sleep
        this.runTask = runTask
        this.normalizeResultOrder = normalizeResultOrder
    }

    createStrategyStats(strategy) {
        return {
            strategy,
            totalJobsPlanned: 0,
            totalJobsExecuted: 0,
            skippedDueToStrategy: 0
        }
    }

    _taskFindingKey(task, result, {
        strategyConfig = {},
        fingerprintFromPayload = () => null,
        extractParamName = () => null
    } = {}) {
        const scope = strategyConfig?.findingScope || null
        if (!scope) return null
        const fingerprint = task?.urlFingerprint || fingerprintFromPayload(task?.payload)
        const moduleId = task?.moduleId || task?.module?.id || task?.moduleName
        if (!fingerprint || !moduleId) return null
        if (scope === "url-module") {
            return `${fingerprint}|${moduleId}`
        }
        const paramName = extractParamName(task, result) || "__all__"
        return `${fingerprint}|${moduleId}|${paramName}`
    }

    shouldSkipTaskDueToStrategy(task, {
        strategyConfig = {},
        strategyFindingKeys = new Set(),
        fingerprintFromPayload = () => null,
        extractParamName = () => null,
        onSkip = () => {}
    } = {}) {
        if (!strategyConfig?.findingScope) return false
        const key = this._taskFindingKey(task, null, {
            strategyConfig,
            fingerprintFromPayload,
            extractParamName
        })
        if (!key) return false
        if (strategyFindingKeys.has(key)) {
            onSkip()
            return true
        }
        return false
    }

    recordStrategyFinding(task, result, {
        strategyConfig = {},
        strategyFindingKeys = new Set(),
        fingerprintFromPayload = () => null,
        extractParamName = () => null
    } = {}) {
        if (!strategyConfig?.findingScope) return
        const key = this._taskFindingKey(task, result, {
            strategyConfig,
            fingerprintFromPayload,
            extractParamName
        })
        if (!key) return
        strategyFindingKeys.add(key)
    }

    shouldSkipTaskDueToScanControls(task, context, scanControls = null) {
        const rules = scanControls?.stopRules || {}
        const state = context?.stopState
        const moduleId = task?.moduleId || task?.module?.id || "module"
        if (rules.stopOnFirstFindingPerRequest && state?.requestHasFinding) {
            return { reason: "scan_stop_on_first_per_request" }
        }
        if (rules.stopOnFirstFindingPerModule && state?.moduleHasFinding?.[moduleId]) {
            return { reason: "scan_stop_on_first_per_module" }
        }
        return null
    }

    recordScanControlFinding(task, context, result) {
        if (!result?.success) return
        const state = context?.stopState
        if (!state) return
        const moduleId = task?.moduleId || task?.module?.id || "module"
        state.requestHasFinding = true
        if (!state.moduleHasFinding) state.moduleHasFinding = Object.create(null)
        state.moduleHasFinding[moduleId] = true
    }

    async executeTaskPlan(plan, options = {}) {
        const tasks = Array.isArray(plan?.tasks) ? [...plan.tasks] : []
        if (!tasks.length) return []
        const concurrency = Math.max(1, options.concurrency || 1)
        const results = []
        const workers = new Set()
        const context = options.context

        const launch = () => {
            const task = tasks.shift()
            if (!task) return null
            const runner = (async () => {
                try {
                    const res = await this.runTask(task, context)
                    if (res) results.push(res)
                } catch (err) {
                    console.error("DAST attack task failed", err)
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
        this.normalizeResultOrder(results)
        return results
    }
}

export default DastTaskScheduler
