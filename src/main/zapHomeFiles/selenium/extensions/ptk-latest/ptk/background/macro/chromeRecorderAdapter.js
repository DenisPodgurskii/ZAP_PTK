/* Author: Denis Podgurskii */

import {
    PTK_FLOW_SCHEMA,
    PtkFlowError,
    diagnosticsResult,
    locatorFromString,
    normalizeFlow,
    normalizeImportedValue,
    safeParseMacroJson,
    selectFlowLocator,
    variablesFromSteps
} from './flow.js'

function chromeSelectors(step) {
    const locators = []
    const selectors = Array.isArray(step?.selectors) ? step.selectors : []
    for (const group of selectors) {
        const candidates = Array.isArray(group) ? group : [group]
        for (const candidate of candidates) {
            const locator = locatorFromString(String(candidate || ''))
            if (locator && !locators.some((entry) => entry.type === locator.type && entry.value === locator.value)) locators.push(locator)
        }
    }
    return locators
}

function chromeKeyValue(rawKey) {
    const key = String(rawKey || '')
    const aliases = {
        Enter: 'KEY_ENTER',
        Tab: 'KEY_TAB',
        Backspace: 'KEY_BACKSPACE',
        Delete: 'KEY_DELETE',
        Escape: 'KEY_ESCAPE',
        ArrowLeft: 'KEY_ARROW_LEFT',
        ArrowRight: 'KEY_ARROW_RIGHT',
        ArrowUp: 'KEY_ARROW_UP',
        ArrowDown: 'KEY_ARROW_DOWN'
    }
    return aliases[key] ? `\${${aliases[key]}}` : key
}

function chromeStep(source, index, secretValues, diagnostics, context) {
    const stepId = `step-${String(index + 1).padStart(4, '0')}`
    const command = String(source?.type || '')
    const recordedLocators = chromeSelectors(source)
    const target = String(source?.target || 'main')
    const locators = command === 'keyDown' && !recordedLocators.length
        ? (context.lastLocatorsByTarget.get(target) || []).map((locator) => ({ ...locator }))
        : recordedLocators
    const common = {
        id: stepId,
        enabled: true,
        optional: source?.ptkOptional === true,
        durationMs: 0,
        timeoutMs: Math.max(0, Number(source?.timeout || (source?.ptkOptional === true ? 1500 : 30000)) || 0),
        window: { index: 0, handle: target },
        frameChain: [],
        locators,
        data: null,
        source: { format: 'chrome-recorder', command, index }
    }
    if (source?.target && source.target !== 'main') {
        diagnostics.push({ level: 'error', code: 'chrome_target_unsupported', message: 'Chrome Recorder non-main targets require an explicit portable frame mapping.', stepId, sourceIndex: index })
        return null
    }
    if (command === 'setViewport') {
        return { ...common, type: 'setWindowSize', width: Number(source.width), height: Number(source.height) }
    }
    if (command === 'navigate') {
        context.lastLocatorsByTarget.delete(target)
        return { ...common, type: 'navigate', url: String(source.url || '') }
    }
    if (command === 'click') return { ...common, type: Number(source.clickCount || 1) > 1 ? 'doubleClick' : 'click' }
    if (command === 'doubleClick') return { ...common, type: 'doubleClick' }
    if (command === 'hover') return { ...common, type: 'hover' }
    if (command === 'change') {
        return {
            ...common,
            type: 'fill',
            data: normalizeImportedValue(source.value)
        }
    }
    if (command === 'keyDown') {
        if (!locators.length) {
            diagnostics.push({
                level: 'error',
                code: 'chrome_key_target_missing',
                message: 'Chrome Recorder keyDown has no selector and no preceding focused element in the same target.',
                stepId,
                sourceIndex: index
            })
            return null
        }
        return { ...common, type: 'keyPress', data: { kind: 'literal', value: chromeKeyValue(source.key) } }
    }
    if (command === 'keyUp') {
        diagnostics.push({ level: 'info', code: 'chrome_keyup_collapsed', message: 'Chrome Recorder keyUp is represented by the preceding PTK keyPress step.', stepId, sourceIndex: index })
        return null
    }
    if (command === 'scroll') {
        return { ...common, type: 'scroll', scrollMode: 'to', x: Number(source.x || 0), y: Number(source.y || 0) }
    }
    if (command === 'waitForElement') return { ...common, type: 'waitForElement' }
    if (command === 'waitForExpression') {
        const expression = String(source.expression || '').trim()
        const delayMatch = expression.match(/^new Promise\(resolve => setTimeout\(\(\) => resolve\(true\), (\d+)\)\)$/)
        if (delayMatch) return { ...common, type: 'delay', durationMs: Number(delayMatch[1]) }
        diagnostics.push({
            level: 'error',
            code: 'chrome_expression_unsupported',
            message: 'Chrome Recorder waitForExpression cannot be imported unless it is a PTK-generated static delay.',
            stepId,
            sourceIndex: index
        })
        return null
    }
    if (command === 'close') {
        diagnostics.push({
            level: 'error',
            code: 'chrome_close_unsupported',
            message: 'Chrome Recorder close cannot be represented as a PTK replay step.',
            stepId,
            sourceIndex: index
        })
        return null
    }
    diagnostics.push({
        level: 'error',
        code: 'unsupported_chrome_recorder_step',
        message: `Chrome Recorder step ${command || 'unknown'} is not supported.`,
        stepId,
        sourceIndex: index
    })
    return null
}

function selectorValue(locator) {
    if (locator.type === 'css') return locator.value
    if (locator.type === 'xpath') return `xpath/${locator.value}`
    if (locator.type === 'aria') return `aria/${locator.value}`
    if (locator.type === 'pierce') return `pierce/${locator.value}`
    if (locator.type === 'text') return `text/${locator.value}`
    if (locator.type === 'id') return `#${locator.value.replaceAll('"', '\\"')}`
    if (locator.type === 'name') return `[name="${locator.value.replaceAll('"', '\\"')}"]`
    if (locator.type === 'className') return `.${locator.value.trim().split(/\s+/).join('.')}`
    if (locator.type === 'linkText') return `aria/${locator.value}`
    return locator.value
}

function chromeData(data) {
    if (!data) return ''
    if (data.kind === 'literal') return data.value
    if (data.kind === 'secret') return `\${PTK_SECRET:${data.name}}`
    return `\${${data.name}}`
}

function chromeStepFromFlow(step, diagnostics, options = {}) {
    if (step.frameChain.length || step.window.index !== 0) {
        diagnostics.push({ level: 'error', code: 'chrome_frame_export_unsupported', message: 'Chrome Recorder export does not have a lossless PTK frame/window mapping.', stepId: step.id })
        return null
    }
    const preferred = selectFlowLocator(step, options.element_path || options.elementPath || 'css')
    const ordered = preferred
        ? [preferred, ...step.locators.filter((locator) => locator.type !== preferred.type || locator.value !== preferred.value)]
        : step.locators
    const selectors = ordered.map((locator) => [selectorValue(locator)])
    const base = {
        target: 'main',
        selectors,
        timeout: step.timeoutMs || 30000,
        ...(step.optional ? { ptkOptional: true } : {})
    }
    if (step.type === 'setWindowSize') {
        return { type: 'setViewport', width: step.width, height: step.height, deviceScaleFactor: 1, isMobile: false, hasTouch: false, isLandscape: false }
    }
    if (step.type === 'navigate') return { type: 'navigate', url: step.url, assertedEvents: [{ type: 'navigation', url: step.url, title: '' }] }
    if (step.type === 'click') return { type: 'click', ...base, offsetX: 1, offsetY: 1 }
    if (step.type === 'doubleClick') return { type: 'click', ...base, offsetX: 1, offsetY: 1, clickCount: 2 }
    if (step.type === 'hover') return { type: 'hover', ...base }
    if (step.type === 'fill' || step.type === 'select') return { type: 'change', ...base, value: chromeData(step.data) }
    if (step.type === 'keyPress') return { type: 'keyDown', ...base, key: chromeData(step.data) }
    if (step.type === 'scroll' && step.scrollMode === 'to') {
        return { type: 'scroll', ...base, x: step.x || 0, y: step.y || 0 }
    }
    if (step.type === 'scroll') {
        diagnostics.push({
            level: step.enabled ? 'error' : 'warning',
            code: 'chrome_scroll_mode_unsupported',
            message: `Chrome Recorder cannot losslessly represent PTK ${step.scrollMode} scrolling.`,
            stepId: step.id,
            stepType: step.type,
            impact: 'omitted'
        })
        return null
    }
    if (step.type === 'waitForElement') return { type: 'waitForElement', ...base, operator: '>=', count: 1, visible: true }
    if (step.type === 'delay') {
        const duration = Math.max(0, Number(step.durationMs) || 0)
        return {
            type: 'waitForExpression',
            expression: `new Promise(resolve => setTimeout(() => resolve(true), ${duration}))`,
            timeout: Math.max(duration + 1000, step.timeoutMs || 0)
        }
    }
    if (step.type === 'comment') {
        diagnostics.push({
            level: 'info',
            code: 'chrome_comment_omitted',
            message: 'Chrome Recorder has no portable comment step; the comment was intentionally omitted.',
            stepId: step.id,
            stepType: step.type,
            impact: 'omitted'
        })
        return null
    }
    diagnostics.push({ level: step.enabled ? 'error' : 'warning', code: 'unsupported_chrome_export_step', message: `PTK Flow step ${step.type} cannot be represented in Chrome Recorder.`, stepId: step.id })
    return null
}

export const chromeRecorderAdapter = Object.freeze({
    id: 'chrome-recorder',
    label: 'Chrome Recorder JSON',
    extensions: ['.chrome-recorder.json', '.json'],
    mimeType: 'application/json',
    editorMode: { name: 'javascript', json: true },
    canImport: true,
    canExport: true,
    detect(input, fileName = '') {
        let confidence = String(fileName).toLowerCase().endsWith('.chrome-recorder.json') ? 0.8 : 0
        if (typeof input === 'string' && input.includes('"title"') && input.includes('"steps"') && /"type"\s*:\s*"(setViewport|navigate|click|change)"/.test(input)) confidence = 0.9
        return { confidence, format: 'chrome-recorder', version: '1' }
    },
    parse(input) {
        const value = safeParseMacroJson(input)
        if (!value || typeof value.title !== 'string' || !Array.isArray(value.steps)) throw new PtkFlowError('invalid_chrome_recorder', 'Expected a Chrome Recorder JSON document')
        const diagnostics = []
        const secretValues = Object.create(null)
        const steps = []
        const context = { lastLocatorsByTarget: new Map() }
        value.steps.forEach((source, index) => {
            const step = chromeStep(source, index, secretValues, diagnostics, context)
            if (step) steps.push(step)
            if (step?.locators?.length && !['scroll', 'waitForElement'].includes(step.type)) {
                context.lastLocatorsByTarget.set(step.window.handle || 'main', step.locators.map((locator) => ({ ...locator })))
            }
        })
        const startUrl = steps.find((step) => step.type === 'navigate')?.url || ''
        const flow = {
            schema: PTK_FLOW_SCHEMA,
            metadata: { name: value.title, sourceFormat: 'chrome-recorder', sourceVersion: '1' },
            startUrl,
            variables: variablesFromSteps(steps),
            steps
        }
        return { ...diagnosticsResult(flow, diagnostics), secretValues }
    },
    serialize(flow, options = {}) {
        const normalized = normalizeFlow(flow)
        const diagnostics = []
        const steps = []
        normalized.steps.forEach((step) => {
            if (!step.enabled) {
                diagnostics.push({
                    level: 'info',
                    code: 'disabled_step_omitted',
                    message: `Disabled ${step.type} step was intentionally omitted.`,
                    stepId: step.id,
                    stepType: step.type,
                    impact: 'omitted'
                })
                return
            }
            const mapped = chromeStepFromFlow(step, diagnostics, options)
            if (mapped) steps.push(mapped)
        })
        return {
            text: `${JSON.stringify({ title: normalized.metadata.name || 'PTK Flow', steps }, null, 2)}\n`,
            diagnostics
        }
    }
})
