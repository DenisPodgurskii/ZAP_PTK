/* Author: Denis Podgurskii */

import {
    PTK_FLOW_LIMITS,
    PTK_FLOW_SCHEMA,
    PtkFlowError,
    compileFlow,
    diagnosticsResult,
    locatorFromString,
    normalizeFlow,
    normalizeImportedValue,
    safeParseMacroJson,
    variablesFromSteps
} from './flow.js'
import { sideAdapter } from './sideAdapter.js'

const FIELDS = [
    'WindowIndex',
    'EventType',
    'EventTypeName',
    'UseEncryptedData',
    'Data',
    'EncryptedData',
    'ElementPath',
    'Duration',
    'TimeoutMs',
    'Enable',
    'Optional',
    'PtkScrollMode',
    'Step',
    'TargetOptions'
]

function byteLength(text) {
    return new TextEncoder().encode(text).length
}

function decodeXmlText(value) {
    return value
        .replaceAll('&lt;', '<')
        .replaceAll('&gt;', '>')
        .replaceAll('&quot;', '"')
        .replaceAll('&apos;', "'")
        .replaceAll('&amp;', '&')
}

function encodeXmlText(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&apos;')
}

function cdata(value) {
    return `<![CDATA[${String(value ?? '').replaceAll(']]>', ']]]]><![CDATA[>')}]]>`
}

function readField(block, field) {
    const open = `<${field}>`
    const close = `</${field}>`
    const start = block.indexOf(open)
    if (start < 0) return ''
    const valueStart = start + open.length
    const end = block.indexOf(close, valueStart)
    if (end < 0) throw new PtkFlowError('invalid_xml', `XML field ${field} is not closed`)
    const raw = block.slice(valueStart, end).trim()
    if (raw.startsWith('<![CDATA[') && raw.endsWith(']]>')) {
        return raw.slice(9, -3).replaceAll(']]]]><![CDATA[>', ']]>')
    }
    return decodeXmlText(raw)
}

function readMacroEvents(text) {
    const events = []
    const open = '<MacroEvent>'
    const close = '</MacroEvent>'
    let cursor = 0
    while (cursor < text.length) {
        const start = text.indexOf(open, cursor)
        if (start < 0) break
        const end = text.indexOf(close, start + open.length)
        if (end < 0) throw new PtkFlowError('invalid_xml', 'A MacroEvent element is not closed')
        events.push(text.slice(start + open.length, end))
        if (events.length > PTK_FLOW_LIMITS.maxSteps) {
            throw new PtkFlowError('too_many_steps', `XML exceeds the ${PTK_FLOW_LIMITS.maxSteps} step limit`)
        }
        cursor = end + close.length
    }
    return events
}

function readSeleneseCommands(text) {
    const commands = []
    const open = '<selenese>'
    const close = '</selenese>'
    let cursor = 0
    while (cursor < text.length) {
        const start = text.indexOf(open, cursor)
        if (start < 0) break
        const end = text.indexOf(close, start + open.length)
        if (end < 0) throw new PtkFlowError('invalid_xml', 'A selenese element is not closed')
        const block = text.slice(start + open.length, end)
        commands.push({
            id: `selenese-${commands.length + 1}`,
            command: readField(block, 'command'),
            target: readField(block, 'target'),
            targets: [],
            value: readField(block, 'value'),
            ptkOptional: /^(?:true|1)$/i.test(readField(block, 'ptkOptional'))
        })
        if (commands.length > PTK_FLOW_LIMITS.maxSteps) {
            throw new PtkFlowError('too_many_steps', `XML exceeds the ${PTK_FLOW_LIMITS.maxSteps} step limit`)
        }
        cursor = end + close.length
    }
    return commands
}

function testCaseBaseUrl(text) {
    const start = text.indexOf('<TestCase')
    if (start < 0) return ''
    const end = text.indexOf('>', start)
    if (end < 0) throw new PtkFlowError('invalid_xml', 'The TestCase element is not closed')
    const tag = text.slice(start, end + 1)
    const match = tag.match(/\bbaseURL\s*=\s*(["'])([^"']*)\1/i)
    return match ? decodeXmlText(match[2]) : ''
}

function seleniumXmlStartUrl(commands, input) {
    const declared = testCaseBaseUrl(input)
    const open = commands.find((command) => command.command === 'open')?.target || ''
    try {
        return new URL(open, declared || undefined).toString()
    } catch (_) {
        if (declared) {
            try { return new URL(declared).toString() } catch (_) { }
        }
        return ''
    }
}

function parseSeleniumXml(input) {
    const commands = readSeleneseCommands(input)
    if (!commands.length) throw new PtkFlowError('invalid_xml', 'Expected a TestCase XML document with selenese commands')
    const startUrl = seleniumXmlStartUrl(commands, input)
    const project = {
        id: 'selenium-xml-project',
        version: 'xml',
        name: 'Imported Selenium/Katalon XML macro',
        url: startUrl,
        tests: [{ id: 'selenium-xml-test', name: 'Imported XML test', commands }],
        suites: [],
        urls: startUrl ? [new URL(startUrl).origin] : [],
        plugins: []
    }
    const imported = sideAdapter.parse(JSON.stringify(project))
    const flow = normalizeFlow({
        ...imported.flow,
        metadata: {
            ...imported.flow.metadata,
            name: 'Imported Selenium/Katalon XML macro',
            sourceFormat: 'selenium-xml',
            sourceVersion: '1'
        },
        steps: imported.flow.steps.map((step) => ({
            ...step,
            source: step.source ? { ...step.source, format: 'selenium-xml', version: '1' } : null
        }))
    })
    return {
        ...imported,
        flow,
        diagnostics: [{
            level: 'info',
            code: 'selenium_xml_detected',
            message: 'Detected Selenium/Katalon Recorder TestCase XML.',
            stepId: null,
            sourceIndex: null
        }, ...imported.diagnostics]
    }
}

function parseLegacyJavascript(data, eventTypeName) {
    const match = String(data || '').match(/\}\)\('([^']*)'(?:,\s*`([\s\S]*?)`)?\)\s*$/)
    if (!match) return null
    const path = match[1]
    const value = typeof match[2] === 'string'
        ? match[2].replace(/\\`/g, '`').replace(/\\\\/g, '\\')
        : null
    if (value !== null || eventTypeName === 'SetValue') return { type: 'fill', path, value: value ?? '' }
    const clickCount = (String(data).match(/item\.click\(\)/g) || []).length
    return { type: clickCount > 1 || eventTypeName === 'DblClick' ? 'doubleClick' : 'click', path, value: '' }
}

function parseElementPath(value) {
    const frameChain = []
    const locators = []
    for (const part of String(value || '').split('|||>').filter(Boolean)) {
        const locator = locatorFromString(part)
        if (!locator) continue
        if (locator.type === 'xpath' && /\/\/IFRAME\b/i.test(locator.value)) {
            frameChain.push({ locators: [locator] })
        } else {
            locators.push(locator)
        }
    }
    return { frameChain, locators }
}

function xmlType(eventType, eventTypeName, data) {
    const raw = String(eventType || eventTypeName || '').trim()
    const normalized = raw.toLowerCase()
    const mapped = ({
        navigate: 'navigate',
        waitforurl: 'waitForNavigation',
        driverclick: 'click',
        onclick: 'click',
        click: 'click',
        doubleclick: 'doubleClick',
        dblclick: 'doubleClick',
        driversetcontrolvalue: 'fill',
        setcontroldata: 'fill',
        setvalue: 'fill',
        change: 'fill',
        sendkeys: 'keyPress',
        scroll: 'scroll',
        hover: 'hover',
        submit: 'submit',
        select: 'select',
        waitforelement: 'waitForElement',
        delay: 'delay',
        setwindowsize: 'setWindowSize',
        selectwindow: 'selectWindow',
        asserttext: 'assertText',
        asserturl: 'assertUrl',
        assertelement: 'assertElement',
        comment: 'comment'
    })[normalized]
    if (mapped) return { type: mapped }
    if (normalized === 'javascript') {
        const parsed = parseLegacyJavascript(data, eventTypeName)
        if (parsed) return parsed
    }
    return null
}

export const xmlAdapter = Object.freeze({
    id: 'xml',
    label: 'XML (.rec)',
    extensions: ['.rec', '.xml'],
    mimeType: 'application/xml',
    editorMode: 'application/xml',
    canImport: true,
    canExport: true,
    detect(input, fileName = '') {
        const text = typeof input === 'string' ? input.trimStart() : ''
        const extension = String(fileName).toLowerCase()
        let confidence = 0
        if (text.startsWith('<?xml') || text.startsWith('<MacroEventList')) confidence = 0.9
        if (text.includes('<MacroEventList') && text.includes('<MacroEvent>')) confidence = 1
        if (text.includes('<TestCase') && text.includes('<selenese>')) confidence = 1
        if (extension.endsWith('.rec')) confidence = Math.max(confidence, 0.8)
        return { confidence, format: 'xml', version: '1' }
    },
    parse(input) {
        if (typeof input !== 'string') throw new PtkFlowError('invalid_input', 'XML input must be text')
        if (byteLength(input) > PTK_FLOW_LIMITS.maxInputBytes) throw new PtkFlowError('file_too_large', 'The selected file exceeds the 10 MiB import limit')
        if (/<!DOCTYPE|<!ENTITY/i.test(input)) throw new PtkFlowError('unsafe_xml', 'DTD and entity declarations are not supported')
        if (input.includes('<TestCase') && input.includes('<selenese>')) return parseSeleniumXml(input)
        if (!input.includes('<MacroEventList') || !input.includes('</MacroEventList>')) {
            throw new PtkFlowError('invalid_xml', 'Expected a MacroEventList XML document')
        }
        const blocks = readMacroEvents(input)
        const diagnostics = []
        const secretValues = Object.create(null)
        const steps = []
        blocks.forEach((block, index) => {
            const item = Object.fromEntries(FIELDS.map((field) => [field, readField(block, field)]))
            const mapping = xmlType(item.EventType, item.EventTypeName, item.Data)
            const stepId = `step-${String(index + 1).padStart(4, '0')}`
            if (!mapping) {
                diagnostics.push({
                    level: Number(item.Enable || 1) === 0 ? 'warning' : 'error',
                    code: 'unsupported_xml_event',
                    message: `XML event ${item.EventType || item.EventTypeName || 'unknown'} is not supported.`,
                    stepId,
                    sourceIndex: index
                })
                return
            }
            const path = parseElementPath(item.ElementPath)
            if (mapping.path && !path.locators.length) {
                const locator = locatorFromString(`css=${mapping.path}`)
                if (locator) path.locators.push(locator)
            }
            let targetOptions = []
            if (item.TargetOptions) {
                try {
                    targetOptions = safeParseMacroJson(item.TargetOptions)
                    if (!Array.isArray(targetOptions) || targetOptions.some((entry) => typeof entry !== 'string')) {
                        throw new PtkFlowError('invalid_targets', 'XML TargetOptions must be an array of strings')
                    }
                    if (mapping.type !== 'selectWindow') {
                        for (const value of targetOptions) {
                            const locator = locatorFromString(value)
                            if (locator && !path.locators.some((entry) => entry.type === locator.type && entry.value === locator.value)) {
                                path.locators.push(locator)
                            }
                        }
                    }
                } catch (error) {
                    diagnostics.push({
                        level: 'error',
                        code: mapping.type === 'selectWindow' ? 'invalid_xml_window_targets' : 'invalid_xml_locator_options',
                        message: error?.message || 'XML target options are invalid.',
                        stepId,
                        sourceIndex: index
                    })
                    targetOptions = []
                }
            }
            const step = {
                id: stepId,
                type: mapping.type,
                enabled: Number(item.Enable || 1) !== 0,
                optional: Number(item.Optional || 0) === 1,
                durationMs: Math.max(0, Number(item.Duration || 0) || 0),
                timeoutMs: Math.max(0, Number(item.TimeoutMs || 0) || 0),
                window: { index: Math.max(0, Number(item.WindowIndex || 0) || 0), handle: '' },
                frameChain: path.frameChain,
                locators: path.locators,
                data: null,
                source: { format: 'xml', version: '1', command: item.EventType, index }
            }
            const rawData = mapping.value !== undefined ? mapping.value : item.Data
            if (mapping.type === 'navigate' || mapping.type === 'waitForNavigation') step.url = rawData
            if (mapping.type === 'fill' || mapping.type === 'keyPress' || mapping.type === 'select') {
                step.data = normalizeImportedValue(rawData)
            }
            if (mapping.type === 'setWindowSize') {
                const [width, height] = String(rawData).split(',').map((entry) => Number(entry.trim()))
                step.width = width
                step.height = height
            }
            if (mapping.type === 'scroll') {
                const requestedMode = String(item.PtkScrollMode || '')
                step.scrollMode = ['intoView', 'to', 'by'].includes(requestedMode)
                    ? requestedMode
                    : path.locators.length ? 'intoView' : 'to'
                if (step.scrollMode !== 'intoView') {
                    const [x, y] = String(rawData || '0,0').split(',').map((entry) => Number(entry.trim()))
                    step.x = Number.isSafeInteger(x) ? x : 0
                    step.y = Number.isSafeInteger(y) ? y : 0
                }
            }
            if (mapping.type === 'selectWindow') {
                step.target = rawData
                step.data = { kind: 'literal', value: rawData }
                if (targetOptions.length) step.targetOptions = targetOptions
            }
            if (mapping.type.startsWith('assert')) step.expected = rawData
            if (mapping.type === 'comment') step.comment = rawData
            steps.push(step)
        })
        const startUrl = steps.find((step) => step.type === 'navigate')?.url || ''
        const flow = {
            schema: PTK_FLOW_SCHEMA,
            metadata: { name: startUrl ? `PTK ${new URL(startUrl).hostname}` : 'Imported XML macro', sourceFormat: 'xml', sourceVersion: '1' },
            startUrl,
            variables: variablesFromSteps(steps),
            steps
        }
        return { ...diagnosticsResult(flow, diagnostics), secretValues }
    },
    serialize(flow, options = {}) {
        const normalized = normalizeFlow(flow)
        const { events } = compileFlow(normalized, {
            ...options,
            includeDisabled: true,
            includeComments: true,
            preserveReferences: true
        })
        const lines = ['<?xml version="1.0"?>', '<MacroEventList>']
        for (const event of events) {
            lines.push('  <MacroEvent>')
            lines.push(`    <WindowIndex>${encodeXmlText(event.WindowIndex)}</WindowIndex>`)
            lines.push(`    <EventType>${encodeXmlText(event.EventType)}</EventType>`)
            lines.push(`    <EventTypeName>${encodeXmlText(event.EventTypeName)}</EventTypeName>`)
            lines.push('    <UseEncryptedData>0</UseEncryptedData>')
            lines.push(`    <Data>${cdata(event.Data)}</Data>`)
            lines.push('    <EncryptedData></EncryptedData>')
            lines.push(`    <ElementPath>${cdata(event.ElementPath)}</ElementPath>`)
            lines.push(`    <Duration>${encodeXmlText(event.Duration)}</Duration>`)
            lines.push(`    <TimeoutMs>${encodeXmlText(event.TimeoutMs)}</TimeoutMs>`)
            lines.push(`    <Enable>${encodeXmlText(event.Enable)}</Enable>`)
            lines.push(`    <Optional>${encodeXmlText(event.Optional)}</Optional>`)
            if (event.EventType === 'Scroll') {
                lines.push(`    <PtkScrollMode>${encodeXmlText(event.PtkScrollMode)}</PtkScrollMode>`)
            }
            lines.push(`    <Step>${encodeXmlText(event.Step)}</Step>`)
            if (event.targetOptions?.length) {
                lines.push(`    <TargetOptions>${cdata(JSON.stringify(event.targetOptions))}</TargetOptions>`)
            }
            lines.push('  </MacroEvent>')
        }
        lines.push('</MacroEventList>')
        return { text: `${lines.join('\r\n')}\r\n`, diagnostics: [] }
    }
})
