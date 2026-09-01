/* Author: Denis Podgurskii */

import {
    PTK_FLOW_SCHEMA,
    PtkFlowError,
    diagnosticsResult,
    locatorFromString,
    locatorToLegacy,
    normalizeFlow,
    normalizeImportedValue,
    safeParseMacroJson,
    selectFlowLocator,
    variablesFromSteps
} from './flow.js'

function resolveOpenUrl(baseUrl, target) {
    try {
        return new URL(String(target || ''), String(baseUrl || '')).toString()
    } catch (_) {
        throw new PtkFlowError('invalid_side_url', 'Selenium IDE open command contains an invalid URL')
    }
}

function sideLocators(command) {
    const locators = []
    const add = (value) => {
        const locator = locatorFromString(value)
        if (!locator) return
        if (!locators.some((entry) => entry.type === locator.type && entry.value === locator.value)) locators.push(locator)
    }
    add(command?.target)
    for (const target of Array.isArray(command?.targets) ? command.targets : []) add(Array.isArray(target) ? target[0] : target)
    return locators
}

function cloneFrameChain(frameChain) {
    return frameChain.map((frame) => ({ locators: frame.locators.map((locator) => ({ ...locator })) }))
}

function isFocusStateLocator(locator) {
    return locator?.type === 'css' && /\.(?:cdk|mat-mdc)-(?:program-)?focused\b/.test(String(locator.value || ''))
}

function preferPointerTargetForFocusClick(step, previousStep) {
    if (step?.type !== 'click' || previousStep?.type !== 'hover') return
    if (!step.locators.some(isFocusStateLocator)) return
    if (step.window?.index !== previousStep.window?.index) return
    if (JSON.stringify(step.frameChain) !== JSON.stringify(previousStep.frameChain)) return

    const locators = []
    for (const locator of [...previousStep.locators, ...step.locators]) {
        if (!locators.some((entry) => entry.type === locator.type && entry.value === locator.value)) {
            locators.push({ ...locator })
        }
    }
    step.locators = locators
}

function sideStep(command, sourceIndex, baseUrl, secretValues, diagnostics, context) {
    const stepId = `step-${String(sourceIndex + 1).padStart(4, '0')}`
    const name = String(command?.command || '')
    // Selenium IDE records mouseOver commands for transient visual targets
    // (for example Material touch/ripple spans) even when the following click
    // is the actual required interaction. Replay the hover when its target is
    // available, but let the subsequent required action decide whether the
    // journey can continue if that helper target has changed.
    const optional = command?.ptkOptional === true || name === 'mouseOver'
    const locators = sideLocators(command)
    const common = {
        id: stepId,
        enabled: command?.enabled !== false,
        optional,
        durationMs: 0,
        timeoutMs: optional ? 1500 : 30000,
        window: { ...context.window },
        frameChain: cloneFrameChain(context.frameChain),
        locators,
        data: null,
        source: { format: 'side', command: name, id: String(command?.id || ''), index: sourceIndex }
    }
    if (name === 'open') return { ...common, type: 'navigate', url: resolveOpenUrl(baseUrl, command.target) }
    if (name === 'click' || name === 'clickAndWait') return { ...common, type: 'click' }
    if (name === 'doubleClick') return { ...common, type: 'doubleClick' }
    if (name === 'type' || name === 'editContent') {
        return {
            ...common,
            type: 'fill',
            data: normalizeImportedValue(command.value)
        }
    }
    if (name === 'sendKeys') {
        return {
            ...common,
            type: 'keyPress',
            data: normalizeImportedValue(command.value)
        }
    }
    if (name === 'select') {
        return {
            ...common,
            type: 'select',
            data: normalizeImportedValue(command.value)
        }
    }
    if (name === 'submit') return { ...common, type: 'submit' }
    if (name === 'mouseOver') return { ...common, type: 'hover' }
    if (name === 'mouseOut') {
        diagnostics.push({
            level: 'info',
            code: 'side_mouseout_collapsed',
            message: 'A redundant Selenium IDE mouseOut helper was intentionally omitted.',
            stepId,
            sourceIndex
        })
        return null
    }
    if (name === 'pause') return { ...common, type: 'delay', durationMs: Math.max(0, Number(command.target || command.value || 0) || 0) }
    if (name === 'waitForElementPresent' || name === 'waitForElementVisible') return { ...common, type: 'waitForElement' }
    if (name === 'setWindowSize') {
        const [width, height] = String(command.target || command.value || '').split('x').map(Number)
        return { ...common, type: 'setWindowSize', width, height }
    }
    if (name === 'selectWindow') {
        return { ...common, type: 'selectWindow', locators: [], target: String(command.target || ''), data: { kind: 'literal', value: String(command.target || '') } }
    }
    if (name === 'assertText' || name === 'verifyText') return { ...common, type: 'assertText', expected: String(command.value || '') }
    if (name === 'assertElementPresent' || name === 'verifyElementPresent') return { ...common, type: 'assertElement', expected: 'present' }
    if (name === 'assertLocation' || name === 'verifyLocation') return { ...common, type: 'assertUrl', expected: String(command.target || command.value || '') }
    if (name === 'echo') return { ...common, type: 'comment', comment: String(command.target || command.value || '') }
    diagnostics.push({
        level: command?.enabled === false ? 'warning' : 'error',
        code: 'unsupported_side_command',
        message: `Selenium IDE command ${name || 'unknown'} is not supported.`,
        stepId,
        sourceIndex
    })
    return null
}

function applyFrameSelection(command, context, diagnostics, sourceIndex) {
    const target = String(command?.target || '')
    if (target === 'relative=top') {
        context.frameChain = []
        return
    }
    if (target === 'relative=parent') {
        context.frameChain.pop()
        return
    }
    let locator = null
    const indexMatch = target.match(/^index=(\d+)$/)
    if (indexMatch) {
        locator = { type: 'css', value: `iframe:nth-of-type(${Number(indexMatch[1]) + 1})` }
        diagnostics.push({
            level: 'warning',
            code: 'side_frame_index_normalized',
            message: 'A Selenium IDE frame index was converted to a positional iframe selector.',
            sourceIndex
        })
    } else {
        locator = locatorFromString(target)
    }
    if (!locator) {
        diagnostics.push({
            level: 'error',
            code: 'side_frame_target_unsupported',
            message: `Selenium IDE frame target ${target || 'unknown'} is not supported.`,
            sourceIndex
        })
        return
    }
    context.frameChain.push({ locators: [locator] })
}

function selectWindowContext(command, context) {
    const raw = String(command?.target || command?.value || '')
    const handle = raw.replace(/^(?:handle|name)=/, '') || `window-${context.windowHandles.size}`
    if (!context.windowHandles.has(handle)) context.windowHandles.set(handle, context.windowHandles.size)
    context.window = { index: context.windowHandles.get(handle), handle }
}

function sideTarget(step, options = {}) {
    const locator = selectFlowLocator(step, options.element_path || options.elementPath || 'css')
    return locator ? locatorToLegacy(locator) : ''
}

function sideTargets(step) {
    return step.locators.map((locator) => {
        const target = locatorToLegacy(locator)
        const strategy = ({ css: 'css:finder', xpath: 'xpath:attributes', id: 'id', name: 'name', linkText: 'linkText' })[locator.type] || 'auto'
        return [target, strategy]
    })
}

function sideValue(step) {
    if (!step.data) return ''
    if (step.data.kind === 'literal') return step.data.value
    if (step.data.kind === 'secret') return `\${PTK_SECRET:${step.data.name}}`
    return `\${${step.data.name}}`
}

function commandFromStep(step, index, diagnostics, options = {}) {
    const base = {
        id: `ptk-command-${String(index + 1).padStart(4, '0')}`,
        comment: '',
        command: '',
        target: sideTarget(step, options),
        targets: sideTargets(step),
        value: '',
        ...(step.optional ? { ptkOptional: true } : {})
    }
    if (step.type === 'navigate') return { ...base, command: 'open', target: step.url, targets: [] }
    if (step.type === 'click') return { ...base, command: 'click' }
    if (step.type === 'doubleClick') return { ...base, command: 'doubleClick' }
    if (step.type === 'fill') return { ...base, command: 'type', value: sideValue(step) }
    if (step.type === 'keyPress') return { ...base, command: 'sendKeys', value: sideValue(step) }
    if (step.type === 'select') return { ...base, command: 'select', value: sideValue(step) }
    if (step.type === 'submit') return { ...base, command: 'submit' }
    if (step.type === 'hover') return { ...base, command: 'mouseOver' }
    if (step.type === 'delay') return { ...base, command: 'pause', target: String(step.durationMs), targets: [] }
    if (step.type === 'waitForElement') return { ...base, command: 'waitForElementPresent' }
    if (step.type === 'setWindowSize') return { ...base, command: 'setWindowSize', target: `${step.width}x${step.height}`, targets: [] }
    if (step.type === 'selectWindow') return { ...base, command: 'selectWindow', target: step.target || sideValue(step), targets: [] }
    if (step.type === 'assertText') return { ...base, command: 'assertText', value: step.expected || '' }
    if (step.type === 'assertElement') return { ...base, command: 'assertElementPresent' }
    if (step.type === 'assertUrl') return { ...base, command: 'assertLocation', target: step.expected || '', targets: [] }
    if (step.type === 'comment') return { ...base, command: 'echo', target: step.comment || '', targets: [] }
    diagnostics.push({ level: step.enabled ? 'error' : 'warning', code: 'unsupported_side_export_step', message: `PTK Flow step ${step.type} cannot be represented in Selenium IDE.`, stepId: step.id })
    return null
}

function sideFrameTarget(frame) {
    const locator = frame?.locators?.[0]
    return locator ? locatorToLegacy(locator) : ''
}

function contextCommand(command, target, index) {
    return {
        id: `ptk-command-${String(index + 1).padStart(4, '0')}`,
        comment: '',
        command,
        target,
        targets: [],
        value: ''
    }
}

export const sideAdapter = Object.freeze({
    id: 'side',
    label: 'Selenium IDE (.side)',
    extensions: ['.side'],
    mimeType: 'application/json',
    editorMode: { name: 'javascript', json: true },
    canImport: true,
    canExport: true,
    detect(input, fileName = '') {
        let confidence = String(fileName).toLowerCase().endsWith('.side') ? 0.7 : 0
        if (typeof input === 'string' && input.includes('"tests"') && input.includes('"commands"') && input.includes('"url"')) confidence = 0.95
        return { confidence, format: 'side', version: '3' }
    },
    parse(input) {
        const value = safeParseMacroJson(input)
        if (!value || !Array.isArray(value.tests)) throw new PtkFlowError('invalid_side', 'Expected a Selenium IDE project with tests')
        const diagnostics = []
        const secretValues = Object.create(null)
        const steps = []
        let sourceIndex = 0
        const context = {
            window: { index: 0, handle: 'main' },
            windowHandles: new Map([['main', 0]]),
            frameChain: []
        }
        value.tests.forEach((test, testIndex) => {
            context.window = { index: 0, handle: 'main' }
            context.frameChain = []
            if (!Array.isArray(test?.commands)) {
                diagnostics.push({ level: 'error', code: 'invalid_side_test', message: `Selenium IDE test ${testIndex + 1} has no command array.` })
                return
            }
            if (value.tests.length > 1) {
                steps.push({
                    id: `step-${String(sourceIndex + 1).padStart(4, '0')}`,
                    type: 'comment', enabled: true, optional: false, durationMs: 0, timeoutMs: 0,
                    window: { index: 0, handle: '' }, frameChain: [], locators: [], data: null,
                    comment: `Selenium IDE test: ${String(test.name || testIndex + 1)}`,
                    source: { format: 'side', command: 'test', index: testIndex }
                })
                sourceIndex += 1
            }
            test.commands.forEach((command) => {
                const name = String(command?.command || '')
                if (name === 'selectFrame') {
                    applyFrameSelection(command, context, diagnostics, sourceIndex)
                    sourceIndex += 1
                    return
                }
                const step = sideStep(command, sourceIndex, value.url, secretValues, diagnostics, context)
                if (step) {
                    // Material-based applications often cause Selenium IDE to
                    // record the eventual click using the ephemeral
                    // `.cdk-focused` state. The immediately preceding hover is
                    // the pointer's actual structural target, so prefer its
                    // locator alternatives while keeping the recorded focus
                    // selector as a fallback.
                    preferPointerTargetForFocusClick(step, steps.at(-1))
                    steps.push(step)
                }
                if (name === 'selectWindow') {
                    selectWindowContext(command, context)
                    context.frameChain = []
                }
                sourceIndex += 1
            })
        })
        const startUrl = steps.find((step) => step.type === 'navigate')?.url || (value.url ? new URL(value.url).toString() : '')
        const flow = {
            schema: PTK_FLOW_SCHEMA,
            metadata: { name: String(value.name || 'Imported Selenium IDE macro'), sourceFormat: 'side', sourceVersion: String(value.version || '') },
            startUrl,
            variables: variablesFromSteps(steps),
            steps
        }
        return { ...diagnosticsResult(flow, diagnostics), secretValues }
    },
    serialize(flow, options = {}) {
        const normalized = normalizeFlow(flow)
        const diagnostics = []
        const commands = []
        let activeWindow = { index: 0, handle: 'main' }
        let activeFrameKey = '[]'
        let pendingWindowHandle = ''
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
            if (pendingWindowHandle && step.window.handle === pendingWindowHandle) {
                activeWindow = { ...step.window }
                activeFrameKey = '[]'
                pendingWindowHandle = ''
            }
            if (step.window.index !== activeWindow.index || (step.window.handle && step.window.handle !== activeWindow.handle)) {
                const target = `handle=${step.window.handle || `window-${step.window.index}`}`
                commands.push(contextCommand('selectWindow', target, commands.length))
                activeWindow = { ...step.window }
                activeFrameKey = '[]'
            }
            const frameKey = JSON.stringify(step.frameChain)
            if (frameKey !== activeFrameKey) {
                if (activeFrameKey !== '[]') commands.push(contextCommand('selectFrame', 'relative=top', commands.length))
                for (const frame of step.frameChain) {
                    const target = sideFrameTarget(frame)
                    if (!target) {
                        diagnostics.push({ level: 'error', code: 'side_frame_locator_missing', message: 'A frame has no Selenium IDE-compatible locator.', stepId: step.id })
                        break
                    }
                    commands.push(contextCommand('selectFrame', target, commands.length))
                }
                activeFrameKey = frameKey
            }
            const command = commandFromStep(step, commands.length, diagnostics, options)
            if (command) {
                commands.push(command)
                if (step.type === 'selectWindow') {
                    pendingWindowHandle = String(step.target || sideValue(step)).replace(/^(?:handle|name)=/, '')
                }
            }
        })
        const project = {
            id: 'ptk-flow-project',
            version: '3.17.0',
            name: normalized.metadata.name || 'PTK Flow',
            url: normalized.startUrl,
            tests: [{ id: 'ptk-flow-test', name: normalized.metadata.name || 'PTK Flow', commands }],
            suites: [{ id: 'ptk-flow-suite', name: 'Default Suite', persistSession: false, parallel: false, timeout: 300, tests: ['ptk-flow-test'] }],
            urls: normalized.startUrl ? [new URL(normalized.startUrl).origin] : [],
            plugins: []
        }
        return { text: `${JSON.stringify(project, null, 2)}\n`, diagnostics }
    }
})
