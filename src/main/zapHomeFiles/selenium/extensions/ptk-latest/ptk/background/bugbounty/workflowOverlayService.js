function clone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function asArray(value) {
    return Array.isArray(value) ? value : []
}

function humanizeEventType(value = "") {
    return String(value || "")
        .replace(/([a-z])([A-Z])/g, "$1 $2")
        .replace(/_/g, " ")
        .trim()
}

function deepClone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function replaceAllInString(value = "", from = "", to = "") {
    const raw = String(value ?? "")
    const target = String(from ?? "")
    if (!raw || !target || raw.includes(target) === false) {
        return {
            changed: false,
            value: raw
        }
    }
    return {
        changed: true,
        value: raw.split(target).join(String(to ?? ""))
    }
}

function mutateObjectStrings(target, from = "", to = "") {
    let changed = false
    const walk = (value) => {
        if (typeof value === "string") {
            const result = replaceAllInString(value, from, to)
            if (result.changed) changed = true
            return result.value
        }
        if (Array.isArray(value)) {
            return value.map((entry) => walk(entry))
        }
        if (value && typeof value === "object") {
            return Object.fromEntries(
                Object.entries(value).map(([key, entry]) => [key, walk(entry)])
            )
        }
        return value
    }
    return {
        changed,
        value: walk(target)
    }
}

function classifyStep(item = {}) {
    const typeName = String(item?.EventTypeName || item?.eventTypeName || item?.EventType || "").trim()
    const props = item?.props && typeof item.props === "object" ? item.props : {}
    const href = String(props?.href || "").toLowerCase()
    const action = String(props?.action || "").toLowerCase()
    const elementType = String(props?.elementType || "").toLowerCase()
    const method = String(props?.method || "").toLowerCase()
    const raw = `${typeName} ${href} ${action} ${method} ${elementType}`.toLowerCase()
    let semantic = "interaction"
    if (/navigate|waitforurl/.test(raw)) semantic = "navigation"
    else if (/submit|post|form/.test(raw)) semantic = "form_submit"
    else if (/upload|file/.test(raw)) semantic = "upload"
    else if (/delete|remove|destroy/.test(raw)) semantic = "destructive_action"
    else if (/admin|role|tenant|account|profile|login|signin|auth/.test(raw)) semantic = "role_sensitive_action"
    return {
        id: String(item?.id || item?.xpath || item?.csspath || `${typeName}-${Math.random().toString(36).slice(2, 8)}`),
        label: humanizeEventType(typeName || "Interaction"),
        semantic,
        target: String(item?.target || item?.xpath || item?.csspath || item?.fullcsspath || "").trim() || null,
        urlBefore: String(item?.urlBefore || "").trim() || null
    }
}

export class WorkflowOverlayService {
    constructor({
        storage = null,
        browserApi = typeof browser !== "undefined" ? browser : null
    } = {}) {
        this.storage = storage
        this.browserApi = browserApi
    }

    async _getStorageValue(key) {
        if (this.storage?.getItem) {
            return this.storage.getItem(key)
        }
        if (this.browserApi?.storage?.local?.get) {
            const result = await this.browserApi.storage.local.get(key)
            return result?.[key]
        }
        return null
    }

    async _loadRecordingSource() {
        const recorderEnvelope = await this._getStorageValue("ptk_recorder")
        const liveRecorderState = await this._getStorageValue("ptk_recording")
        const liveItems = await this._getStorageValue("ptk_recording_items")
        const recording = recorderEnvelope?.recording && typeof recorderEnvelope.recording === "object"
            ? recorderEnvelope.recording
            : null
        const items = Array.isArray(recording?.items) && recording.items.length
            ? recording.items
            : (Array.isArray(liveItems) ? liveItems : [])
        const startUrl = String(recording?.startUrl || liveRecorderState?.startUrl || items?.[0]?.Data || "").trim() || null
        return {
            recording,
            items: asArray(items),
            startUrl,
            source: recording ? "saved_recording" : (asArray(items).length ? "live_recording" : "none")
        }
    }

    _buildObjectSwapMutation(item = {}, objectSwap = null) {
        const swap = objectSwap && typeof objectSwap === "object" ? objectSwap : null
        if (!swap?.applied || !swap?.originalValue || !swap?.swappedValue) {
            return {
                changed: false,
                item: deepClone(item)
            }
        }
        const cloned = deepClone(item)
        let changed = false
        const fieldNames = ["Data", "data", "target", "ElementPath", "_cssPath", "urlBefore"]
        fieldNames.forEach((fieldName) => {
            if (typeof cloned?.[fieldName] !== "string") return
            const result = replaceAllInString(cloned[fieldName], swap.originalValue, swap.swappedValue)
            if (result.changed) {
                changed = true
                cloned[fieldName] = result.value
            }
        })
        if (Array.isArray(cloned?.targetOptions)) {
            const result = mutateObjectStrings(cloned.targetOptions, swap.originalValue, swap.swappedValue)
            if (result.changed) {
                changed = true
                cloned.targetOptions = result.value
            }
        }
        if (cloned?.props && typeof cloned.props === "object") {
            const result = mutateObjectStrings(cloned.props, swap.originalValue, swap.swappedValue)
            if (result.changed) {
                changed = true
                cloned.props = result.value
            }
        }
        return {
            changed,
            item: cloned
        }
    }

    async getSummary({ candidate = null, objectSwap = null, baselineSession = null, comparisonSession = null } = {}) {
        const recordingSource = await this._loadRecordingSource()
        const liveLog = await this._getStorageValue("ptk_recording_log")
        const replayEnvelope = await this._getStorageValue("ptk_replay")
        const rawItems = recordingSource.items
        const steps = asArray(rawItems).map((item) => classifyStep(item))
        const counts = steps.reduce((acc, step) => {
            acc[step.semantic] = Number(acc[step.semantic] || 0) + 1
            return acc
        }, {})
        const suggestedOverlays = []
        if (objectSwap?.applied === true) {
            suggestedOverlays.push(`Replace object identifier ${objectSwap.targetParam || "identifier"} during replay to validate object-level access control.`)
        }
        if (baselineSession?.label && comparisonSession?.label) {
            suggestedOverlays.push(`Replay the same workflow as ${baselineSession.label} and ${comparisonSession.label} to compare state transitions.`)
        }
        if (counts.role_sensitive_action) {
            suggestedOverlays.push("Focus overlay validation on role-sensitive actions in the recorded workflow.")
        }
        if (counts.destructive_action) {
            suggestedOverlays.push("Keep destructive steps opt-in before replaying the workflow with mutations.")
        }
        return {
            recordingPresent: steps.length > 0,
            replayActive: !!(replayEnvelope && typeof replayEnvelope === "object" && replayEnvelope.mode === "replay"),
            source: recordingSource.source,
            stepCount: steps.length,
            semanticCounts: counts,
            steps: steps.slice(0, 12),
            suggestedOverlays,
            logTail: String(liveLog || "").split("<br/>").filter(Boolean).slice(-5),
            candidateId: candidate?.id || null,
            routeKey: candidate?.routeKey || null
        }
    }

    async buildReplayPlan({
        candidate = null,
        objectSwap = null,
        baselineSession = null,
        comparisonSession = null,
        activeSession = null,
        activeSessionProfile = null,
        sessionRelation = "comparison",
        includeDestructive = false
    } = {}) {
        const recordingSource = await this._loadRecordingSource()
        const rawItems = recordingSource.items
        const steps = asArray(rawItems).map((item, index) => ({
            stepIndex: index,
            ...classifyStep(item)
        }))
        const summary = {
            recordingPresent: steps.length > 0,
            source: recordingSource.source,
            stepCount: steps.length,
            overlayedStepCount: 0,
            skippedStepCount: 0,
            activeSessionLabel: String(activeSession?.label || "").trim() || null
        }
        if (!steps.length) {
            return {
                ...summary,
                startUrl: recordingSource.startUrl,
                items: [],
                overlayPlan: {
                    source: "bugbounty_authz_diff",
                    candidateId: candidate?.id || null,
                    routeKey: candidate?.routeKey || null,
                    baselineSession: baselineSession || null,
                    comparisonSession: comparisonSession || null,
                    activeSession: activeSession || null,
                    objectSwap: objectSwap || null,
                    workflowSummary: {
                        source: recordingSource.source,
                        stepCount: 0,
                        steps: []
                    },
                    stepOverlays: [],
                    behavior: {
                        confirmDestructive: !includeDestructive,
                        keepDefaultTiming: true,
                        dryRun: false
                    }
                }
            }
        }
        const stepOverlays = []
        steps.forEach((step) => {
            const overlayEntry = {
                stepIndex: step.stepIndex,
                semantic: step.semantic,
                mutations: {}
            }
            if (!includeDestructive && step.semantic === "destructive_action") {
                overlayEntry.skip = true
                overlayEntry.reason = "destructive_action"
                summary.skippedStepCount += 1
            }
            const mutation = this._buildObjectSwapMutation(rawItems[step.stepIndex], objectSwap)
            if (mutation.changed) {
                overlayEntry.mutatedItem = mutation.item
                overlayEntry.reason = overlayEntry.reason || "object_swap"
                summary.overlayedStepCount += 1
            }
            if (overlayEntry.skip || overlayEntry.mutatedItem) {
                stepOverlays.push(overlayEntry)
            }
        })
        const startUrlMutation = this._buildObjectSwapMutation({
            Data: recordingSource.startUrl || ""
        }, objectSwap)
        const overlayPlan = {
            source: "bugbounty_authz_diff",
            candidateId: candidate?.id || null,
            routeKey: candidate?.routeKey || null,
            baselineSession: baselineSession || null,
            comparisonSession: comparisonSession || null,
            activeSession: activeSession || null,
            activeSessionProfile: activeSessionProfile
                ? {
                    id: activeSessionProfile.id || null,
                    label: activeSessionProfile.label || null,
                    host: activeSessionProfile.host || null
                }
                : null,
            sessionRelation: String(sessionRelation || "comparison").trim().toLowerCase() || "comparison",
            objectSwap: objectSwap || null,
            workflowSummary: {
                source: recordingSource.source,
                stepCount: steps.length,
                steps: steps.slice(0, 20)
            },
            stepOverlays,
            behavior: {
                confirmDestructive: !includeDestructive,
                keepDefaultTiming: true,
                dryRun: false
            }
        }
        return {
            ...summary,
            startUrl: String(startUrlMutation?.item?.Data || recordingSource.startUrl || "").trim() || recordingSource.startUrl || null,
            items: rawItems,
            overlayPlan
        }
    }
}

export default WorkflowOverlayService
