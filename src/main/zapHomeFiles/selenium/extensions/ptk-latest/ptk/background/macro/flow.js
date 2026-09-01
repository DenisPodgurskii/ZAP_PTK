/* Author: Denis Podgurskii */

export const PTK_FLOW_SCHEMA = 'ptk-flow/v1'

export const PTK_FLOW_LIMITS = Object.freeze({
    maxInputBytes: 10 * 1024 * 1024,
    maxSteps: 10000,
    maxDepth: 64,
    maxStringLength: 1024 * 1024,
    maxDiagnostics: 200
})

const STEP_TYPES = new Set([
    'navigate',
    'click',
    'doubleClick',
    'fill',
    'select',
    'submit',
    'keyPress',
    'scroll',
    'hover',
    'waitForElement',
    'waitForNavigation',
    'delay',
    'setWindowSize',
    'selectWindow',
    'assertText',
    'assertUrl',
    'assertElement',
    'comment'
])

const LOCATOR_TYPES = new Set([
    'css',
    'xpath',
    'id',
    'name',
    'className',
    'linkText',
    'aria',
    'text',
    'pierce'
])

const SCROLL_MODES = new Set(['intoView', 'to', 'by'])

const POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor'])

export class PtkFlowError extends Error {
    constructor(code, message, details = {}) {
        super(message)
        this.name = 'PtkFlowError'
        this.code = code
        this.details = details
    }
}

function hasOwn(value, key) {
    return Object.prototype.hasOwnProperty.call(value, key)
}

function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function boundedString(value, field, limits = PTK_FLOW_LIMITS, { allowEmpty = true } = {}) {
    if (value === undefined || value === null) return ''
    if (typeof value !== 'string') {
        throw new PtkFlowError('invalid_string', `${field} must be a string`, { field })
    }
    if (value.length > limits.maxStringLength) {
        throw new PtkFlowError('string_too_large', `${field} exceeds the supported size`, { field })
    }
    if (!allowEmpty && value.length === 0) {
        throw new PtkFlowError('empty_string', `${field} is required`, { field })
    }
    return value
}

function boundedInteger(value, field, { min = 0, max = Number.MAX_SAFE_INTEGER, fallback = 0 } = {}) {
    if (value === undefined || value === null || value === '') return fallback
    const number = Number(value)
    if (!Number.isSafeInteger(number) || number < min || number > max) {
        throw new PtkFlowError('invalid_integer', `${field} is outside the supported range`, { field })
    }
    return number
}

function inspectJsonValue(value, limits = PTK_FLOW_LIMITS) {
    const stack = [{ value, depth: 1, ancestors: new Set() }]
    while (stack.length) {
        const current = stack.pop()
        if (current.depth > limits.maxDepth) {
            throw new PtkFlowError('document_too_deep', 'The workflow exceeds the supported nesting depth')
        }
        if (typeof current.value === 'string' && current.value.length > limits.maxStringLength) {
            throw new PtkFlowError('string_too_large', 'The workflow contains an oversized string')
        }
        if (!current.value || typeof current.value !== 'object') continue
        if (current.ancestors.has(current.value)) {
            throw new PtkFlowError('cyclic_document', 'The workflow must not contain cycles')
        }
        const ancestors = new Set(current.ancestors)
        ancestors.add(current.value)
        for (const key of Object.keys(current.value)) {
            if (POLLUTION_KEYS.has(key)) {
                throw new PtkFlowError('pollution_key', 'The workflow contains a forbidden object key')
            }
            stack.push({ value: current.value[key], depth: current.depth + 1, ancestors })
        }
    }
}

export function safeParseMacroJson(text, limits = PTK_FLOW_LIMITS) {
    if (typeof text !== 'string') {
        throw new PtkFlowError('invalid_input', 'Macro input must be text')
    }
    if (new TextEncoder().encode(text).length > limits.maxInputBytes) {
        throw new PtkFlowError('file_too_large', 'The selected file exceeds the 10 MiB import limit')
    }
    let parsed
    try {
        parsed = JSON.parse(text, (key, value) => {
            if (POLLUTION_KEYS.has(key)) {
                throw new PtkFlowError('pollution_key', 'The workflow contains a forbidden object key')
            }
            return value
        })
    } catch (error) {
        if (error instanceof PtkFlowError) throw error
        throw new PtkFlowError('invalid_json', 'The selected file is not valid JSON')
    }
    inspectJsonValue(parsed, limits)
    return parsed
}

export function normalizeHttpUrl(value, field = 'URL', { allowEmpty = true } = {}) {
    const text = boundedString(value, field, PTK_FLOW_LIMITS, { allowEmpty })
    if (!text && allowEmpty) return ''
    let parsed
    try {
        parsed = new URL(text)
    } catch (_) {
        throw new PtkFlowError('invalid_url', `${field} must be an absolute HTTP or HTTPS URL`, { field })
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new PtkFlowError('unsupported_url_scheme', `${field} must use HTTP or HTTPS`, { field })
    }
    return parsed.toString()
}

export function normalizeLocatorType(value) {
    const raw = String(value || '').trim()
    const aliases = {
        cssSelector: 'css',
        css: 'css',
        xpath: 'xpath',
        id: 'id',
        name: 'name',
        class: 'className',
        className: 'className',
        link: 'linkText',
        linkText: 'linkText',
        aria: 'aria',
        text: 'text',
        pierce: 'pierce'
    }
    return aliases[raw] || null
}

export function locatorFromString(value) {
    if (typeof value !== 'string') return null
    const text = value.trim()
    if (!text) return null
    const prefixes = [
        ['css=', 'css'],
        ['xpath=', 'xpath'],
        ['id=', 'id'],
        ['name=', 'name'],
        ['class=', 'className'],
        ['className=', 'className'],
        ['link=', 'linkText'],
        ['linkText=', 'linkText'],
        ['aria/', 'aria'],
        ['xpath/', 'xpath'],
        ['pierce/', 'pierce'],
        ['text/', 'text']
    ]
    for (const [prefix, type] of prefixes) {
        if (text.startsWith(prefix)) {
            const locatorValue = text.slice(prefix.length)
            return locatorValue ? { type, value: locatorValue } : null
        }
    }
    if (text.startsWith('//') || text.startsWith('(//')) return { type: 'xpath', value: text }
    return { type: 'css', value: text }
}

export function locatorToLegacy(locator) {
    if (!locator) return ''
    const prefixes = {
        css: 'css=',
        xpath: 'xpath=',
        id: 'id=',
        name: 'name=',
        className: 'class=',
        linkText: 'linkText=',
        aria: 'aria/',
        text: 'text/',
        pierce: 'pierce/'
    }
    return `${prefixes[locator.type] || 'css='}${locator.value}`
}

function normalizeLocator(value, field, limits = PTK_FLOW_LIMITS) {
    if (typeof value === 'string') {
        const parsed = locatorFromString(value)
        if (!parsed) throw new PtkFlowError('invalid_locator', `${field} is not a valid locator`, { field })
        return parsed
    }
    if (!isObject(value)) {
        throw new PtkFlowError('invalid_locator', `${field} must be a locator object`, { field })
    }
    const type = normalizeLocatorType(value.type)
    if (!type || !LOCATOR_TYPES.has(type)) {
        throw new PtkFlowError('unsupported_locator', `${field} uses an unsupported locator type`, { field })
    }
    const locatorValue = boundedString(value.value, `${field}.value`, limits, { allowEmpty: false })
    return { type, value: locatorValue }
}

function normalizeLocators(value, field, limits = PTK_FLOW_LIMITS) {
    if (value === undefined || value === null) return []
    if (!Array.isArray(value)) {
        throw new PtkFlowError('invalid_locators', `${field} must be an array`, { field })
    }
    const seen = new Set()
    const locators = []
    value.forEach((entry, index) => {
        const locator = normalizeLocator(entry, `${field}[${index}]`, limits)
        const key = `${locator.type}\u0000${locator.value}`
        if (!seen.has(key)) {
            seen.add(key)
            locators.push(locator)
        }
    })
    // Angular Material/CDK dialog IDs and overlay container indexes are
    // generated at runtime. Preserve the producer locator, but append a
    // structural dialog fallback so the same external recording can replay
    // after a scanner or another overlay changes that creation order.
    for (const locator of [...locators]) {
        if (locator.type !== 'xpath') continue
        const candidates = []
        const withoutGeneratedDialogId = locator.value.replace(
            /mat-dialog-container\[@id=(['"])mat-mdc-dialog-\d+\1\]/ig,
            'mat-dialog-container'
        )
        if (withoutGeneratedDialogId !== locator.value) candidates.push(withoutGeneratedDialogId)
        const dialogSegment = locator.value.match(/\/mat-dialog-container(?:\[[^\]]+\])?\/.*$/i)?.[0]
        if (dialogSegment) candidates.push(`/${dialogSegment}`)
        for (const candidate of candidates) {
            const key = `xpath\u0000${candidate}`
            if (!seen.has(key)) {
                seen.add(key)
                locators.push({ type: 'xpath', value: candidate })
            }
        }
    }
    return locators
}

function normalizeData(value, field, limits = PTK_FLOW_LIMITS) {
    if (value === undefined || value === null) return null
    if (typeof value === 'string') {
        const secretMatch = value.match(/^\$\{PTK_SECRET:([A-Z0-9_]{1,80})\}$/)
        if (secretMatch) return { kind: 'secret', name: secretMatch[1] }
        return { kind: 'literal', value: boundedString(value, field, limits) }
    }
    if (!isObject(value)) {
        throw new PtkFlowError('invalid_data', `${field} must be text or a data reference`, { field })
    }
    if (value.kind === 'literal') {
        return { kind: 'literal', value: boundedString(value.value, `${field}.value`, limits) }
    }
    if (value.kind === 'secret' || value.kind === 'variable') {
        const name = boundedString(value.name, `${field}.name`, limits, { allowEmpty: false })
        if (!/^[A-Z][A-Z0-9_]{0,79}$/.test(name)) {
            throw new PtkFlowError('invalid_reference', `${field}.name must use an uppercase PTK reference name`, { field })
        }
        return { kind: value.kind, name }
    }
    throw new PtkFlowError('invalid_data_kind', `${field} uses an unsupported data reference`, { field })
}

function normalizeSource(value, limits = PTK_FLOW_LIMITS) {
    if (!isObject(value)) return null
    const source = {}
    for (const key of ['format', 'version', 'command', 'id']) {
        if (typeof value[key] === 'string' && value[key].length <= limits.maxStringLength) {
            source[key] = value[key]
        }
    }
    if (Number.isSafeInteger(Number(value.index)) && Number(value.index) >= 0) {
        source.index = Number(value.index)
    }
    if (value.preparatory === true) source.preparatory = true
    return Object.keys(source).length ? source : null
}

function normalizeFrameChain(value, field, limits = PTK_FLOW_LIMITS) {
    if (value === undefined || value === null) return []
    if (!Array.isArray(value)) {
        throw new PtkFlowError('invalid_frame_chain', `${field} must be an array`, { field })
    }
    return value.map((entry, index) => {
        if (!isObject(entry)) {
            throw new PtkFlowError('invalid_frame', `${field}[${index}] must be an object`, { field })
        }
        const locators = normalizeLocators(entry.locators, `${field}[${index}].locators`, limits)
        if (!locators.length) {
            throw new PtkFlowError('missing_frame_locator', `${field}[${index}] requires a locator`, { field })
        }
        return { locators }
    })
}

function normalizeStep(value, index, limits = PTK_FLOW_LIMITS) {
    if (!isObject(value)) {
        throw new PtkFlowError('invalid_step', `steps[${index}] must be an object`, { index })
    }
    const type = boundedString(value.type, `steps[${index}].type`, limits, { allowEmpty: false })
    if (!STEP_TYPES.has(type)) {
        throw new PtkFlowError('unsupported_step', `steps[${index}] uses unsupported step type ${type}`, { index, type })
    }
    const id = boundedString(value.id || `step-${String(index + 1).padStart(4, '0')}`, `steps[${index}].id`, limits, { allowEmpty: false })
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id)) {
        throw new PtkFlowError('invalid_step_id', `steps[${index}].id is invalid`, { index })
    }
    const step = {
        id,
        type,
        enabled: value.enabled !== false,
        optional: value.optional === true,
        durationMs: boundedInteger(value.durationMs, `steps[${index}].durationMs`, { min: 0, max: 24 * 60 * 60 * 1000 }),
        timeoutMs: boundedInteger(value.timeoutMs, `steps[${index}].timeoutMs`, { min: 0, max: 24 * 60 * 60 * 1000 }),
        window: {
            index: boundedInteger(value.window?.index, `steps[${index}].window.index`, { min: 0, max: 1024 }),
            handle: typeof value.window?.handle === 'string'
                ? boundedString(value.window.handle, `steps[${index}].window.handle`, limits)
                : ''
        },
        frameChain: normalizeFrameChain(value.frameChain, `steps[${index}].frameChain`, limits),
        locators: normalizeLocators(value.locators, `steps[${index}].locators`, limits),
        data: normalizeData(value.data, `steps[${index}].data`, limits),
        source: normalizeSource(value.source, limits)
    }

    if (value.url !== undefined) step.url = normalizeHttpUrl(value.url, `steps[${index}].url`, { allowEmpty: false })
    for (const key of ['key', 'operator', 'expected', 'comment', 'target']) {
        if (value[key] !== undefined) step[key] = boundedString(value[key], `steps[${index}].${key}`, limits)
    }
    if (value.targetOptions !== undefined) {
        if (!Array.isArray(value.targetOptions) || value.targetOptions.length > 32) {
            throw new PtkFlowError('invalid_window_targets', `steps[${index}].targetOptions must be an array with at most 32 entries`, { index })
        }
        step.targetOptions = [...new Set(value.targetOptions.map((entry, targetIndex) => {
            if (Array.isArray(entry)) entry = entry[0]
            return boundedString(entry, `steps[${index}].targetOptions[${targetIndex}]`, limits, { allowEmpty: false })
        }))]
    }
    for (const key of ['x', 'y']) {
        if (value[key] !== undefined) step[key] = boundedInteger(value[key], `steps[${index}].${key}`, { min: -1000000, max: 1000000 })
    }
    for (const key of ['width', 'height']) {
        if (value[key] !== undefined) step[key] = boundedInteger(value[key], `steps[${index}].${key}`, { min: 1, max: 100000 })
    }

    if (type === 'navigate' && !step.url) {
        throw new PtkFlowError('missing_url', `steps[${index}] navigation requires a URL`, { index })
    }

    if (type === 'scroll') {
        const explicitMode = value.scrollMode === undefined
            ? ''
            : boundedString(value.scrollMode, `steps[${index}].scrollMode`, limits, { allowEmpty: false })
        // Legacy PTK/XML scroll steps were locator-driven even when recorder
        // coordinates happened to be present. Preserve that behavior unless a
        // modern importer/recorder has declared an explicit scroll mode.
        const scrollMode = explicitMode || (step.locators.length ? 'intoView' : 'to')
        if (!SCROLL_MODES.has(scrollMode)) {
            throw new PtkFlowError('unsupported_scroll_mode', `steps[${index}] uses unsupported scroll mode ${scrollMode}`, { index, scrollMode })
        }
        if ((scrollMode === 'intoView' || scrollMode === 'by') && !step.locators.length) {
            throw new PtkFlowError('missing_scroll_locator', `steps[${index}] ${scrollMode} scrolling requires an element locator`, { index, scrollMode })
        }
        step.scrollMode = scrollMode
        if (scrollMode !== 'intoView') {
            step.x = Number.isSafeInteger(step.x) ? step.x : 0
            step.y = Number.isSafeInteger(step.y) ? step.y : 0
        }
    }
    const locatorTypes = new Set(['click', 'doubleClick', 'fill', 'select', 'submit', 'keyPress', 'scroll', 'hover', 'waitForElement', 'assertText', 'assertElement'])
    if (locatorTypes.has(type) && !step.locators.length && type !== 'scroll') {
        throw new PtkFlowError('missing_locator', `steps[${index}] requires an element locator`, { index })
    }
    if ((type === 'fill' || type === 'select' || type === 'keyPress') && !step.data) {
        throw new PtkFlowError('missing_data', `steps[${index}] requires input data`, { index })
    }
    if (type === 'setWindowSize' && (!step.width || !step.height)) {
        throw new PtkFlowError('missing_viewport', `steps[${index}] requires width and height`, { index })
    }
    if (type === 'selectWindow' && !step.target && !step.targetOptions?.length) {
        throw new PtkFlowError('missing_window_target', `steps[${index}] requires a window target`, { index })
    }
    return step
}

export function normalizeFlow(value, { limits = PTK_FLOW_LIMITS } = {}) {
    inspectJsonValue(value, limits)
    if (!isObject(value)) throw new PtkFlowError('invalid_flow', 'PTK Flow must be an object')
    if (value.schema !== PTK_FLOW_SCHEMA) {
        throw new PtkFlowError('unsupported_schema', `Expected ${PTK_FLOW_SCHEMA}`)
    }
    if (!Array.isArray(value.steps)) throw new PtkFlowError('missing_steps', 'PTK Flow requires a steps array')
    if (value.steps.length > limits.maxSteps) {
        throw new PtkFlowError('too_many_steps', `PTK Flow exceeds the ${limits.maxSteps} step limit`)
    }

    const metadata = {}
    if (isObject(value.metadata)) {
        for (const key of ['name', 'description', 'sourceFormat', 'sourceVersion']) {
            if (value.metadata[key] !== undefined) metadata[key] = boundedString(value.metadata[key], `metadata.${key}`, limits)
        }
    }
    const variables = []
    const variableNames = new Set()
    const variableKinds = new Map()
    if (value.variables !== undefined) {
        if (!Array.isArray(value.variables)) throw new PtkFlowError('invalid_variables', 'variables must be an array')
        for (const entry of value.variables) {
            if (!isObject(entry)) throw new PtkFlowError('invalid_variable', 'Each variable must be an object')
            const name = boundedString(entry.name, 'variables.name', limits, { allowEmpty: false })
            if (!/^[A-Z][A-Z0-9_]{0,79}$/.test(name)) throw new PtkFlowError('invalid_variable_name', 'Variable names must be uppercase')
            if (variableNames.has(name)) throw new PtkFlowError('duplicate_variable_name', `Duplicate variable name ${name}`)
            variableNames.add(name)
            const secret = entry.secret === true
            variableKinds.set(name, secret)
            variables.push({ name, secret })
        }
    }
    const steps = value.steps.map((step, index) => normalizeStep(step, index, limits))
    const ids = new Set()
    for (const step of steps) {
        if (ids.has(step.id)) throw new PtkFlowError('duplicate_step_id', `Duplicate step ID ${step.id}`)
        ids.add(step.id)
        if (step.data?.kind === 'secret' || step.data?.kind === 'variable') {
            if (!variableKinds.has(step.data.name)) throw new PtkFlowError('undeclared_variable', `Step ${step.id} references undeclared variable ${step.data.name}`)
            if (step.data.kind === 'secret' && variableKinds.get(step.data.name) !== true) {
                throw new PtkFlowError('variable_kind_mismatch', `Step ${step.id} requires ${step.data.name} to be declared as secret`)
            }
            if (step.data.kind === 'variable' && variableKinds.get(step.data.name) === true) {
                throw new PtkFlowError('variable_kind_mismatch', `Step ${step.id} requires ${step.data.name} to be declared as a non-secret variable`)
            }
        }
    }
    const startUrl = normalizeHttpUrl(value.startUrl || steps.find((step) => step.type === 'navigate')?.url || '', 'startUrl', { allowEmpty: true })
    return {
        schema: PTK_FLOW_SCHEMA,
        metadata,
        startUrl,
        variables,
        steps
    }
}

export function serializeFlowJson(flow) {
    return `${JSON.stringify(normalizeFlow(flow), null, 2)}\n`
}

export function diagnosticsResult(flow, diagnostics = []) {
    const bounded = diagnostics.slice(0, PTK_FLOW_LIMITS.maxDiagnostics).map((entry) => ({
        level: entry?.level === 'error' ? 'error' : entry?.level === 'warning' ? 'warning' : 'info',
        code: String(entry?.code || 'conversion_note').slice(0, 100),
        message: String(entry?.message || 'Conversion note').slice(0, 1000),
        stepId: entry?.stepId ? String(entry.stepId).slice(0, 128) : null,
        sourceIndex: Number.isSafeInteger(Number(entry?.sourceIndex)) ? Number(entry.sourceIndex) : null
    }))
    return {
        flow: normalizeFlow(flow),
        diagnostics: bounded,
        acceptable: !bounded.some((entry) => entry.level === 'error')
    }
}

export function normalizeImportedValue(value) {
    const literal = typeof value === 'string' ? value : String(value ?? '')
    const existing = literal.match(/^\$\{PTK_SECRET:([A-Z0-9_]{1,80})\}$/)
    if (existing) return { kind: 'secret', name: existing[1] }
    return { kind: 'literal', value: literal }
}

export function variablesFromSteps(steps = []) {
    const variables = new Map()
    for (const step of steps) {
        if (step?.data?.kind === 'secret') variables.set(step.data.name, true)
        if (step?.data?.kind === 'variable' && !variables.has(step.data.name)) variables.set(step.data.name, false)
    }
    return [...variables.entries()].map(([name, secret]) => ({ name, secret }))
}

export function resolveFlowData(data, { secrets = {}, variables = {}, preserveReferences = false } = {}) {
    if (!data) return ''
    if (data.kind === 'literal') return data.value
    if (data.kind === 'secret') {
        if (preserveReferences) return `\${PTK_SECRET:${data.name}}`
        if (!hasOwn(secrets, data.name)) throw new PtkFlowError('missing_secret', `Runtime secret ${data.name} is required`)
        return String(secrets[data.name])
    }
    if (data.kind === 'variable') {
        if (preserveReferences) return `\${${data.name}}`
        if (!hasOwn(variables, data.name)) throw new PtkFlowError('missing_variable', `Runtime variable ${data.name} is required`)
        return String(variables[data.name])
    }
    return ''
}

function frameInfoLocators(info) {
    if (!info || typeof info !== 'object') return []
    if (info.id) return [{ type: 'xpath', value: `//IFRAME[@id="${String(info.id).replaceAll('"', '&quot;')}"]` }]
    if (info.name) return [{ type: 'xpath', value: `//IFRAME[@name="${String(info.name).replaceAll('"', '&quot;')}"]` }]
    if (info.title) return [{ type: 'xpath', value: `//IFRAME[@title="${String(info.title).replaceAll('"', '&quot;')}"]` }]
    if (info.src) return [{ type: 'xpath', value: `//IFRAME[@src="${String(info.src).replaceAll('"', '&quot;')}"]` }]
    return []
}

function recordedLocators(item) {
    const values = []
    const append = (value) => {
        const locator = locatorFromString(value)
        if (!locator) return
        if (!values.some((entry) => entry.type === locator.type && entry.value === locator.value)) values.push(locator)
    }
    const recordedId = String(item?.props?.id || '')
    if (recordedId
        && !(/\d+$/.test(recordedId) && /[-_]/.test(recordedId))
        && !/^(mat|cdk|mdc)-/i.test(recordedId)
        && !/^mat-mdc-/i.test(recordedId)) {
        append(`id=${recordedId}`)
    }
    if (item?.props?.name) append(`name=${String(item.props.name)}`)
    for (const target of Array.isArray(item?.targetOptions) ? item.targetOptions : []) {
        append(Array.isArray(target) ? target[0] : target)
    }
    append(item?.target)
    if (item?.csspath) append(`css=${item.csspath}`)
    if (item?.xpath) append(`xpath=${item.xpath}`)
    if (item?.fullcsspath) append(`css=${item.fullcsspath}`)
    if (item?.fullxpath) append(`xpath=${item.fullxpath}`)
    return values
}

function mapRecordedType(eventTypeName) {
    return ({
        Navigate: 'navigate',
        WaitForUrl: 'waitForNavigation',
        Click: 'click',
        DblClick: 'doubleClick',
        SetValue: 'fill',
        Change: 'fill',
        SendKeys: 'keyPress',
        Delay: 'delay',
        SetWindowSize: 'setWindowSize',
        SelectWindow: 'selectWindow',
        Hover: 'hover',
        Scroll: 'scroll',
        Submit: 'submit'
    })[eventTypeName] || null
}

function recordedStep(item, index, secretValues, diagnostics) {
    const type = mapRecordedType(item?.eventTypeName)
    if (!type) {
        diagnostics.push({
            level: 'error',
            code: 'unsupported_recorded_step',
            message: `Recorded event ${String(item?.eventTypeName || 'unknown')} is not supported.`,
            sourceIndex: index
        })
        return null
    }
    const id = `step-${String(index + 1).padStart(4, '0')}`
    const locators = type === 'selectWindow' || (type === 'scroll' && item?.scrollTarget === 'window')
        ? []
        : recordedLocators(item)
    const stack = Array.isArray(item?.frameStack) && item.frameStack.length
        ? item.frameStack
        : item?.frameInfo ? [item.frameInfo] : []
    const step = {
        id,
        type,
        enabled: item?.Enable === undefined ? true : Number(item.Enable) !== 0,
        optional: Number(item?.Optional || 0) === 1,
        durationMs: Math.max(0, Number(item?.eventDuration || item?.Duration || 0) || 0),
        timeoutMs: Math.max(0, Number(item?.timeoutMs || item?.TimeoutMs || 0) || 0),
        window: {
            index: Math.max(0, Number(item?.windowIndex || item?.WindowIndex || 0) || 0),
            handle: String(item?.windowHandle || '')
        },
        frameChain: stack.map((info) => ({ locators: frameInfoLocators(info) })).filter((entry) => entry.locators.length),
        locators,
        data: null,
        source: { format: 'recording', index, command: String(item?.eventTypeName || '') }
    }
    const rawData = String(item?.data ?? item?.Data ?? '')
    if (type === 'navigate') step.url = normalizeHttpUrl(rawData, `recording[${index}].url`, { allowEmpty: false })
    if (type === 'waitForNavigation') step.url = normalizeHttpUrl(rawData, `recording[${index}].url`, { allowEmpty: false })
    if (type === 'fill' || type === 'keyPress' || type === 'select') {
        const locatorText = locators.map((locator) => locator.value).join(' ')
        step.data = normalizeImportedValue(rawData)
    }
    if (type === 'setWindowSize') {
        const [width, height] = rawData.split(',').map((entry) => Number(entry.trim()))
        step.width = width
        step.height = height
    }
    if (type === 'scroll') {
        const requestedMode = String(item?.scrollMode || item?.ScrollMode || item?.PtkScrollMode || '')
        step.scrollMode = SCROLL_MODES.has(requestedMode)
            ? requestedMode
            : locators.length ? 'intoView' : 'to'
        if (step.scrollMode !== 'intoView') {
            step.x = Number.isSafeInteger(Number(item?.x ?? item?.X)) ? Number(item?.x ?? item?.X) : 0
            step.y = Number.isSafeInteger(Number(item?.y ?? item?.Y)) ? Number(item?.y ?? item?.Y) : 0
        }
    }
    if (type === 'selectWindow') {
        const targets = [...new Set((Array.isArray(item?.targetOptions) ? item.targetOptions : [])
            .map((entry) => Array.isArray(entry) ? entry[0] : entry)
            .concat(rawData)
            .filter((entry) => typeof entry === 'string' && entry))]
        const temporaryTitle = targets.some((entry) => /^(title=)?(new tab|about:blank)$/i.test(entry))
        const preferred = temporaryTitle
            ? targets.find((entry) => entry.startsWith('index=')) || rawData
            : rawData || targets[0]
        step.target = preferred
        step.targetOptions = [...new Set([preferred, ...targets])]
        step.data = { kind: 'literal', value: preferred }
    }
    return step
}

export function flowFromRecording(recording, settings = {}) {
    const items = Array.isArray(recording?.items) ? recording.items : []
    const diagnostics = []
    const secretValues = Object.create(null)
    const steps = []
    let lastItem = null
    let sequence = 0
    for (const item of items) {
        if (settings.enable_extra_delay && lastItem
            && lastItem.eventTypeName !== 'Delay'
            && item?.eventTypeName !== 'Delay'
            && item?.csspath !== lastItem?.csspath) {
            sequence += 1
            steps.push({
                id: `step-${String(sequence).padStart(4, '0')}`,
                type: 'delay',
                enabled: true,
                optional: false,
                durationMs: Math.max(0, Number(settings.min_duration || 0) || 0),
                timeoutMs: 0,
                window: { index: 0, handle: '' },
                frameChain: [],
                locators: [],
                data: null,
                source: { format: 'recording', command: 'generated-delay' }
            })
        }
        sequence += 1
        const step = recordedStep(item, sequence - 1, secretValues, diagnostics)
        if (step) {
            step.id = `step-${String(sequence).padStart(4, '0')}`
            steps.push(step)
        }
        lastItem = item
    }
    if (steps.length && steps[steps.length - 1].type !== 'delay') {
        sequence += 1
        steps.push({
            id: `step-${String(sequence).padStart(4, '0')}`,
            type: 'delay',
            enabled: true,
            optional: false,
            durationMs: Math.max(0, Number(settings.min_duration || 0) || 0),
            timeoutMs: 0,
            window: { index: 0, handle: '' },
            frameChain: [],
            locators: [],
            data: null,
            source: { format: 'recording', command: 'generated-final-delay' }
        })
    }
    const startUrl = steps.find((step) => step.type === 'navigate')?.url || ''
    const flow = normalizeFlow({
        schema: PTK_FLOW_SCHEMA,
        metadata: { name: startUrl ? `PTK ${new URL(startUrl).hostname}` : 'PTK macro', sourceFormat: 'recording' },
        startUrl,
        variables: variablesFromSteps(steps),
        steps
    })
    return { ...diagnosticsResult(flow, diagnostics), secretValues }
}

export function selectFlowLocator(step, elementPath = 'css') {
    if (!step.locators.length) return null
    if (elementPath === 'source') return step.locators[0]
    if (elementPath === 'id') {
        const direct = step.locators.find((locator) => locator.type === 'id')
        if (direct) return direct
        const xpath = step.locators.find((locator) => locator.type === 'xpath' && /@id\s*=/.test(locator.value))
        const xpathId = xpath?.value?.match(/@id\s*=\s*(["'])(.*?)\1/)?.[2]
        if (xpathId) return { type: 'id', value: xpathId }
        const cssId = step.locators
            .filter((locator) => locator.type === 'css')
            .map((locator) => locator.value.match(/^(?:[A-Za-z][\w-]*)?(?:#([\w:.-]+)|\[id=["']([^"']+)["']\])$/))
            .find(Boolean)
        if (cssId) return { type: 'id', value: cssId[1] || cssId[2] }
        // Element ID is a preference, not permission to invent a locator.
        // Prefer another portable selector before falling back to XPath.
        return step.locators.find((locator) => locator.type === 'css')
            || step.locators.find((locator) => locator.type === 'name')
            || step.locators.find((locator) => locator.type === 'className')
            || step.locators[0]
    }
    if (elementPath === 'fullpath') {
        return [...step.locators].reverse().find((locator) => locator.type === 'xpath')
            || [...step.locators].reverse()[0]
    }
    return step.locators.find((locator) => locator.type === 'css') || step.locators[0]
}

function legacyElementPath(step, elementPath) {
    const framePath = step.frameChain.map((frame) => {
        const locator = frame.locators[0]
        if (!locator) return ''
        const quoted = String(locator.value).replaceAll('\\', '\\\\').replaceAll('"', '\\"')
        if (locator.type === 'id') return `css=iframe[id="${quoted}"]`
        if (locator.type === 'name') return `css=iframe[name="${quoted}"]`
        return locatorToLegacy(locator)
    }).filter(Boolean)
    const element = selectFlowLocator(step, elementPath)
    if (element) framePath.push(locatorToLegacy(element))
    return framePath.join('|||>')
}

function legacyEventType(type) {
    return ({
        navigate: 'Navigate',
        click: 'DriverClick',
        doubleClick: 'DoubleClick',
        fill: 'DriverSetControlValue',
        select: 'Select',
        submit: 'Submit',
        keyPress: 'SendKeys',
        scroll: 'Scroll',
        hover: 'Hover',
        waitForElement: 'WaitForElement',
        waitForNavigation: 'WaitForUrl',
        delay: 'Delay',
        setWindowSize: 'SetWindowSize',
        selectWindow: 'SelectWindow',
        assertText: 'AssertText',
        assertUrl: 'AssertUrl',
        assertElement: 'AssertElement',
        comment: 'Comment'
    })[type]
}

export function compileFlow(flow, options = {}) {
    const normalized = normalizeFlow(flow)
    const events = []
    for (const step of normalized.steps) {
        if ((!step.enabled && options.includeDisabled !== true) || (step.type === 'comment' && options.includeComments !== true)) continue
        const data = step.type === 'navigate' || step.type === 'waitForNavigation'
            ? step.url
            : step.type === 'setWindowSize'
                ? `${step.width},${step.height}`
                : step.type === 'scroll' && (Number.isSafeInteger(step.x) || Number.isSafeInteger(step.y))
                    ? `${Number.isSafeInteger(step.x) ? step.x : 0},${Number.isSafeInteger(step.y) ? step.y : 0}`
                : step.type === 'selectWindow'
                    ? step.target || resolveFlowData(step.data, options)
                    : step.type.startsWith('assert')
                        ? step.expected || ''
                        : resolveFlowData(step.data, options)
        const selected = selectFlowLocator(step, options.elementPath || 'css')
        const event = {
            WindowIndex: step.window.index,
            EventType: legacyEventType(step.type),
            EventTypeName: legacyEventType(step.type),
            UseEncryptedData: 0,
            Data: data,
            EncryptedData: '',
            ElementPath: legacyElementPath(step, options.elementPath || 'css'),
            Duration: step.durationMs,
            TimeoutMs: step.timeoutMs,
            Enable: step.enabled ? 1 : 0,
            Optional: step.optional ? 1 : 0,
            Step: events.length + 1,
            target: selected ? locatorToLegacy(selected) : step.target || '',
            targetOptions: step.type === 'selectWindow'
                ? [...(step.targetOptions || []), step.target].filter((entry, index, values) => entry && values.indexOf(entry) === index)
                : step.locators.map(locatorToLegacy),
            windowHandle: step.window.handle,
            PtkStepId: step.id,
            PtkStepType: step.type,
            PtkScrollMode: step.type === 'scroll' ? step.scrollMode : '',
            PtkPreparatory: step.source?.preparatory === true ? 1 : 0,
            Expected: step.expected || '',
            X: Number.isSafeInteger(step.x) ? step.x : null,
            Y: Number.isSafeInteger(step.y) ? step.y : null,
            // PTK's historical recorder stores zero-based XPath predicates and
            // its legacy replayer increments them. External workflow formats
            // use normal one-based XPath predicates and must be evaluated as-is.
            PtkXPathIndexBase: ['recording', 'xml'].includes(step.source?.format) ? 0 : 1
        }
        if (!event.EventType) {
            throw new PtkFlowError('unsupported_runtime_step', `Step ${step.id} cannot be compiled for replay`)
        }
        events.push(event)
    }
    const startUrl = normalized.startUrl || events.find((event) => event.EventType === 'Navigate')?.Data || ''
    return { startUrl, events }
}
