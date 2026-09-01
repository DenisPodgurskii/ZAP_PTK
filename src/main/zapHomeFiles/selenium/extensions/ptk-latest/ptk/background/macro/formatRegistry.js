/* Author: Denis Podgurskii */

import { PtkFlowError, normalizeFlow } from './flow.js'
import { chromeRecorderAdapter } from './chromeRecorderAdapter.js'
import { codeGenerators } from './codeGenerators.js'
import { ptkFlowAdapter } from './ptkFlowAdapter.js'
import { sideAdapter } from './sideAdapter.js'
import { xmlAdapter } from './xmlAdapter.js'
import { zestAdapter } from './zestAdapter.js'

const formats = Object.freeze([
    ptkFlowAdapter,
    xmlAdapter,
    zestAdapter,
    sideAdapter,
    chromeRecorderAdapter,
    ...codeGenerators
])

const byId = new Map(formats.map((format) => [format.id, format]))
const diagnosticLevelOrder = Object.freeze({ error: 0, warning: 1, info: 2 })

function exportDiagnosticLevel(entry, step) {
    if (!step) return entry?.level === 'error' ? 'error' : entry?.level === 'warning' ? 'warning' : 'info'
    if (!step.enabled) return 'info'
    if (step.optional) return entry?.level === 'info' ? 'info' : 'warning'
    return entry?.level === 'warning' || entry?.level === 'info' ? entry.level : 'error'
}

function enrichExportDiagnostics(flow, diagnostics = []) {
    const byStepId = new Map(flow.steps.map((step) => [step.id, step]))
    return diagnostics.map((entry) => {
        const stepId = entry?.stepId ? String(entry.stepId) : null
        const step = stepId ? byStepId.get(stepId) : null
        return {
            ...entry,
            level: exportDiagnosticLevel(entry, step),
            code: String(entry?.code || 'export_note'),
            message: String(entry?.message || 'Export note'),
            stepId,
            stepType: String(entry?.stepType || step?.type || 'workflow'),
            enabled: step ? step.enabled : null,
            optional: step ? step.optional : null,
            impact: entry?.impact || (step ? 'omitted' : 'note')
        }
    })
}

export function groupMacroDiagnostics(diagnostics = [], { visibleStepLimit = 3 } = {}) {
    const limit = Math.max(1, Math.min(20, Number(visibleStepLimit) || 3))
    const groups = new Map()
    diagnostics.forEach((entry, index) => {
        const level = entry?.level === 'error' ? 'error' : entry?.level === 'warning' ? 'warning' : 'info'
        const code = String(entry?.code || 'export_note')
        const stepType = String(entry?.stepType || 'workflow')
        const key = `${level}\u0000${code}\u0000${stepType}`
        if (!groups.has(key)) {
            groups.set(key, {
                level,
                code,
                stepType,
                message: String(entry?.message || 'Export note'),
                count: 0,
                stepIds: [],
                stepIdSet: new Set(),
                firstIndex: index
            })
        }
        const group = groups.get(key)
        group.count += 1
        const stepId = entry?.stepId ? String(entry.stepId) : ''
        if (stepId && !group.stepIdSet.has(stepId)) {
            group.stepIdSet.add(stepId)
            group.stepIds.push(stepId)
        }
    })
    return [...groups.values()]
        .sort((left, right) => diagnosticLevelOrder[left.level] - diagnosticLevelOrder[right.level] || left.firstIndex - right.firstIndex)
        .map((group) => {
            const { stepIdSet, ...publicGroup } = group
            return {
                ...publicGroup,
                visibleStepIds: group.stepIds.slice(0, limit),
                hiddenStepIds: group.stepIds.slice(limit)
            }
        })
}

export function summarizeMacroExport(flow, diagnostics = []) {
    const normalized = normalizeFlow(flow)
    const byStepId = new Map(normalized.steps.map((step) => [step.id, step]))
    const omitted = new Set()
    diagnostics.forEach((entry) => {
        if (entry?.impact === 'omitted' && entry?.stepId && byStepId.has(entry.stepId)) omitted.add(entry.stepId)
    })
    let requiredOmitted = 0
    let optionalOmitted = 0
    let disabledOmitted = 0
    let informationalOmitted = 0
    omitted.forEach((stepId) => {
        const step = byStepId.get(stepId)
        if (!step.enabled) disabledOmitted += 1
        else if (step.type === 'comment') informationalOmitted += 1
        else if (step.optional) optionalOmitted += 1
        else requiredOmitted += 1
    })
    return {
        sourceSteps: normalized.steps.length,
        preservedSteps: normalized.steps.length - omitted.size,
        requiredOmitted,
        optionalOmitted,
        disabledOmitted,
        informationalOmitted,
        errors: diagnostics.filter((entry) => entry.level === 'error').length,
        warnings: diagnostics.filter((entry) => entry.level === 'warning').length,
        info: diagnostics.filter((entry) => entry.level === 'info').length
    }
}

export function getMacroFormat(id) {
    const normalized = id === 'json' ? 'ptk-flow' : id
    const format = byId.get(normalized)
    if (!format) throw new PtkFlowError('unsupported_format', `Macro format ${String(id || 'unknown')} is not supported`)
    return format
}

export function listMacroFormats({ importOnly = false, exportOnly = false } = {}) {
    return formats
        .filter((format) => !importOnly || format.canImport)
        .filter((format) => !exportOnly || format.canExport)
        .map((format) => ({
            id: format.id,
            label: format.label,
            extensions: [...format.extensions],
            mimeType: format.mimeType,
            editorMode: format.editorMode,
            canImport: format.canImport,
            canExport: format.canExport,
            readOnly: format.readOnly === true
        }))
}

export function detectMacroFormat(input, fileName = '') {
    const candidates = formats
        .filter((format) => format.canImport && typeof format.detect === 'function')
        .map((format) => ({ ...format.detect(input, fileName), id: format.id, label: format.label }))
        .filter((candidate) => Number(candidate.confidence) > 0)
        .sort((left, right) => right.confidence - left.confidence || left.id.localeCompare(right.id))
    if (!candidates.length || candidates[0].confidence < 0.5) {
        throw new PtkFlowError('format_not_detected', 'Could not detect a supported macro format')
    }
    if (candidates.length > 1 && candidates[0].confidence === candidates[1].confidence) {
        throw new PtkFlowError('format_ambiguous', 'Macro format is ambiguous; select the format manually')
    }
    return candidates[0]
}

export function parseMacroDocument(input, { format = 'auto', fileName = '' } = {}) {
    const selected = format && format !== 'auto'
        ? getMacroFormat(format)
        : getMacroFormat(detectMacroFormat(input, fileName).id)
    if (!selected.canImport || typeof selected.parse !== 'function') {
        throw new PtkFlowError('format_not_importable', `${selected.label} cannot be imported`)
    }
    const result = selected.parse(input, { fileName })
    const diagnostics = Array.isArray(result.diagnostics) ? [...result.diagnostics] : []
    if (result.flow?.steps?.length && !result.flow?.startUrl) {
        diagnostics.push({
            level: 'error',
            code: 'missing_start_url',
            message: 'The imported workflow has executable steps but no HTTP or HTTPS start URL.',
            stepId: null,
            sourceIndex: null
        })
    }
    return {
        ...result,
        diagnostics,
        acceptable: result.acceptable !== false && !diagnostics.some((entry) => entry.level === 'error'),
        format: selected.id,
        formatLabel: selected.label,
        sourceFileName: String(fileName || '').slice(0, 512)
    }
}

export function serializeMacroDocument(flow, formatId = 'xml', options = {}) {
    const selected = getMacroFormat(formatId)
    if (!selected.canExport) throw new PtkFlowError('format_not_exportable', `${selected.label} cannot be exported`)
    const normalized = normalizeFlow(flow)
    const result = selected.readOnly
        ? selected.generate(normalized, options)
        : selected.serialize(normalized, options)
    const diagnostics = enrichExportDiagnostics(
        normalized,
        Array.isArray(result?.diagnostics) ? result.diagnostics : []
    )
    return {
        text: String(result?.text || ''),
        diagnostics,
        diagnosticGroups: groupMacroDiagnostics(diagnostics),
        summary: summarizeMacroExport(normalized, diagnostics),
        format: selected.id,
        formatLabel: selected.label,
        mimeType: selected.mimeType,
        editorMode: selected.editorMode,
        readOnly: selected.readOnly === true,
        extension: selected.extensions[0]
    }
}

export function macroDownloadName(flow, formatId = 'xml') {
    const normalized = normalizeFlow(flow)
    const format = getMacroFormat(formatId)
    let base = normalized.metadata.name || ''
    if (!base && normalized.startUrl) {
        try { base = new URL(normalized.startUrl).hostname } catch (_) { }
    }
    base = String(base || 'macro')
        .normalize('NFKD')
        .replace(/[^A-Za-z0-9._-]+/g, '_')
        .replace(/^[_\.]+|[_\.]+$/g, '')
        .slice(0, 100) || 'macro'
    return `PTK_${base}${format.extensions[0]}`
}
