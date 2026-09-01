/* Author: Denis Podgurskii */

import {
    PTK_FLOW_SCHEMA,
    PtkFlowError,
    diagnosticsResult,
    locatorToLegacy,
    normalizeFlow,
    normalizeLocatorType,
    normalizeImportedValue,
    safeParseMacroJson,
    selectFlowLocator,
    variablesFromSteps
} from './flow.js'

function windowIndexFor(handle, handles) {
    const existingDefault = handles.keys().next().value
    const key = String(handle || existingDefault || 'windowHandle1')
    if (!handles.has(key)) handles.set(key, handles.size)
    return handles.get(key)
}

function zestLocator(statement) {
    const type = normalizeLocatorType(statement?.type)
    const value = typeof statement?.element === 'string' ? statement.element : ''
    return type && value ? [{ type, value }] : []
}

function zestStep(statement, sourceIndex, handles, secretValues, diagnostics) {
    const stepId = `step-${String(sourceIndex + 1).padStart(4, '0')}`
    const type = String(statement?.elementType || '')
    const locators = zestLocator(statement)
    const common = {
        id: stepId,
        enabled: statement?.enabled !== false,
        optional: statement?.ptkOptional === true,
        durationMs: 0,
        timeoutMs: Math.max(0, Number(statement?.waitForMsec || 0) || 0),
        window: {
            index: windowIndexFor(statement?.windowHandle, handles),
            handle: String(statement?.windowHandle || '')
        },
        frameChain: [],
        locators,
        data: null,
        source: { format: 'zest', version: '0.3', command: type, index: sourceIndex }
    }
    if (type === 'ZestComment') return { ...common, type: 'comment', comment: String(statement.comment || '') }
    if (type === 'ZestClientLaunch') return { ...common, type: 'navigate', url: String(statement.url || '') }
    // Zest records viewport assistance as explicit statements. A stale scroll
    // locator must not abort an otherwise replayable business journey; the
    // following click/fill remains authoritative and will still fail normally
    // if its required target cannot be resolved.
    if (type === 'ZestClientElementScrollTo') {
        return { ...common, type: 'scroll', optional: true, scrollMode: 'intoView' }
    }
    if (type === 'ZestClientElementScroll') {
        return {
            ...common,
            type: 'scroll',
            scrollMode: 'by',
            x: Number(statement.x || 0),
            y: Number(statement.y || 0)
        }
    }
    if (type === 'ZestClientElementMouseOver') return { ...common, type: 'hover' }
    if (type === 'ZestClientElementClick') return { ...common, type: 'click' }
    if (type === 'ZestClientElementSubmit') return { ...common, type: 'submit' }
    if (type === 'ZestClientElementClear') return { ...common, type: 'fill', data: { kind: 'literal', value: '' } }
    if (type === 'ZestClientElementSendKeys') {
        return {
            ...common,
            type: 'fill',
            data: normalizeImportedValue(statement.value)
        }
    }
    if (type === 'ZestClientElementSelect') {
        return {
            ...common,
            type: 'select',
            data: normalizeImportedValue(statement.value)
        }
    }
    if (type === 'ZestActionSleep') {
        return { ...common, type: 'delay', durationMs: Math.max(0, Number(statement.milliseconds || statement.timeInMsec || 0) || 0) }
    }
    if (type === 'ZestClientWindowResize') {
        return {
            ...common,
            type: 'setWindowSize',
            width: Number(statement.width),
            height: Number(statement.height)
        }
    }
    diagnostics.push({
        level: statement?.enabled === false ? 'warning' : 'error',
        code: 'unsupported_zest_statement',
        message: `Zest statement ${type || 'unknown'} is not supported.`,
        stepId,
        sourceIndex
    })
    return null
}

function samePrimaryLocator(left, right) {
    const a = left?.locators?.[0]
    const b = right?.locators?.[0]
    return Boolean(a && b && a.type === b.type && a.value === b.value)
}

function markPreparatoryZestClicksOptional(steps) {
    for (let index = 0; index < steps.length; index++) {
        const click = steps[index]
        if (click?.type !== 'click') continue

        let nextIndex = index + 1
        while (steps[nextIndex]?.type === 'scroll' && samePrimaryLocator(click, steps[nextIndex])) {
            nextIndex++
        }
        const next = steps[nextIndex]
        if (next?.type === 'fill' && samePrimaryLocator(click, next)) {
            // Recorder-generated Zest commonly emits click/focus assistance
            // immediately before SendKeys. PTK sets the value and dispatches
            // the input/change events itself, so failure of that redundant
            // focus click must not abort an otherwise valid imported journey.
            click.optional = true
            click.source = { ...click.source, preparatory: true }
        }
    }
}

function firstLocator(step, options = {}) {
    return selectFlowLocator(step, options.element_path || options.elementPath || 'css')
}

function zestData(data) {
    if (!data) return ''
    if (data.kind === 'literal') return data.value
    if (data.kind === 'secret') return `\${PTK_SECRET:${data.name}}`
    if (data.kind === 'variable') return `\${${data.name}}`
    return ''
}

function baseStatement(step, index, options = {}) {
    const locator = firstLocator(step, options)
    return {
        windowHandle: step.window.handle || `windowHandle${step.window.index + 1}`,
        type: locator ? ({ css: 'cssSelector' }[locator.type] || locator.type) : undefined,
        element: locator?.value,
        waitForMsec: step.timeoutMs || 0,
        index,
        enabled: step.enabled,
        ...(step.optional ? { ptkOptional: true } : {})
    }
}

function serializeStep(step, index, diagnostics, options = {}) {
    const base = baseStatement(step, index, options)
    if (step.frameChain.length) {
        diagnostics.push({
            level: 'error',
            code: 'zest_frame_export_unsupported',
            message: 'Zest export does not yet have a lossless frame-chain mapping.',
            stepId: step.id
        })
        return null
    }
    if (step.type === 'comment') return { comment: step.comment || '', index, enabled: step.enabled, elementType: 'ZestComment' }
    if (step.type === 'navigate') {
        return {
            browserType: 'chrome-headless',
            capabilities: '',
            headless: true,
            url: step.url,
            windowHandle: step.window.handle || `windowHandle${step.window.index + 1}`,
            index,
            enabled: step.enabled,
            elementType: 'ZestClientLaunch'
        }
    }
    if (step.type === 'scroll' && step.scrollMode === 'intoView') {
        return { ...base, elementType: 'ZestClientElementScrollTo' }
    }
    if (step.type === 'scroll' && step.scrollMode === 'by') {
        return { ...base, x: step.x || 0, y: step.y || 0, elementType: 'ZestClientElementScroll' }
    }
    if (step.type === 'scroll') {
        diagnostics.push({
            level: step.enabled ? 'error' : 'warning',
            code: 'zest_absolute_scroll_unsupported',
            message: 'Zest cannot losslessly represent an absolute PTK or Chrome Recorder scroll position.',
            stepId: step.id,
            stepType: step.type,
            impact: 'omitted'
        })
        return null
    }
    if (step.type === 'hover') return { ...base, elementType: 'ZestClientElementMouseOver' }
    if (step.type === 'click') return { ...base, elementType: 'ZestClientElementClick' }
    if (step.type === 'submit') return { ...base, elementType: 'ZestClientElementSubmit' }
    if (step.type === 'fill' || step.type === 'keyPress') return { ...base, value: zestData(step.data), elementType: 'ZestClientElementSendKeys' }
    if (step.type === 'select') return { ...base, value: zestData(step.data), elementType: 'ZestClientElementSelect' }
    if (step.type === 'delay') return { milliseconds: step.durationMs, index, enabled: step.enabled, elementType: 'ZestActionSleep' }
    if (step.type === 'setWindowSize') {
        return { ...base, width: step.width, height: step.height, elementType: 'ZestClientWindowResize' }
    }
    diagnostics.push({
        level: step.enabled ? 'error' : 'warning',
        code: 'unsupported_zest_export_step',
        message: `PTK Flow step ${step.type} cannot be represented in Zest.`,
        stepId: step.id
    })
    return null
}

export const zestAdapter = Object.freeze({
    id: 'zest',
    label: 'ZAP Zest (.zst)',
    extensions: ['.zst'],
    mimeType: 'application/json',
    editorMode: { name: 'javascript', json: true },
    canImport: true,
    canExport: true,
    detect(input, fileName = '') {
        let confidence = String(fileName).toLowerCase().endsWith('.zst') ? 0.7 : 0
        if (typeof input === 'string' && input.includes('"zestVersion"') && input.includes('"ZestScript"')) confidence = 1
        return { confidence, format: 'zest', version: '0.3' }
    },
    parse(input) {
        const value = safeParseMacroJson(input)
        if (!value || value.elementType !== 'ZestScript' || !Array.isArray(value.statements)) {
            throw new PtkFlowError('invalid_zest', 'Expected a ZAP Zest script with a statements array')
        }
        const diagnostics = []
        const secretValues = Object.create(null)
        const handles = new Map()
        const steps = []
        value.statements.forEach((statement, index) => {
            const step = zestStep(statement, index, handles, secretValues, diagnostics)
            if (step) steps.push(step)
        })
        markPreparatoryZestClicksOptional(steps)
        if (handles.size > 1) {
            diagnostics.push({
                level: 'error',
                code: 'zest_multiple_windows_unsupported',
                message: 'This Zest workflow uses multiple browser window handles, which cannot yet be replayed losslessly.'
            })
        }
        const startUrl = steps.find((step) => step.type === 'navigate')?.url || ''
        const flow = {
            schema: PTK_FLOW_SCHEMA,
            metadata: {
                name: String(value.title || 'Imported Zest macro'),
                description: String(value.description || ''),
                sourceFormat: 'zest',
                sourceVersion: String(value.zestVersion || '')
            },
            startUrl,
            variables: variablesFromSteps(steps),
            steps
        }
        return { ...diagnosticsResult(flow, diagnostics), secretValues }
    },
    serialize(flow, options = {}) {
        const normalized = normalizeFlow(flow)
        const diagnostics = []
        const statements = []
        normalized.steps.forEach((step) => {
            const statement = serializeStep(step, statements.length + 1, diagnostics, options)
            if (statement) statements.push(statement)
        })
        const document = {
            about: 'This is a Zest script. For more details about Zest visit https://github.com/zaproxy/zest/',
            zestVersion: '0.3',
            title: normalized.metadata.name || 'PTK Flow',
            description: normalized.metadata.description || 'Exported by OWASP PTK',
            prefix: '',
            type: 'StandAlone',
            parameters: { tokenStart: '{{', tokenEnd: '}}', tokens: {}, elementType: 'ZestVariables' },
            statements,
            authentication: [],
            index: 0,
            enabled: true,
            elementType: 'ZestScript',
            options: { statementDelay: 0 }
        }
        return { text: `${JSON.stringify(document, null, 2)}\n`, diagnostics }
    }
})
