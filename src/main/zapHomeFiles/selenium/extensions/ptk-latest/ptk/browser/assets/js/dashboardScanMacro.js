/* Author: Denis Podgurskii */

import { compileFlow, normalizeFlow } from '../../../background/macro/flow.js'
import { parseMacroDocument } from '../../../background/macro/formatRegistry.js'

function httpOrigin(value, field) {
    let parsed
    try {
        parsed = new URL(String(value || ''))
    } catch (_) {
        throw new Error(`${field} must be an absolute HTTP or HTTPS URL.`)
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`${field} must use HTTP or HTTPS.`)
    }
    return parsed.origin
}

export function assertDashboardMacroScope(flow, targetUrl) {
    const normalized = normalizeFlow(flow)
    const targetOrigin = httpOrigin(targetUrl, 'The active scan target')
    const urls = []
    if (normalized.startUrl) urls.push({ label: 'Macro start URL', value: normalized.startUrl })
    for (const step of normalized.steps) {
        if ((step.type === 'navigate' || step.type === 'waitForNavigation') && step.url) {
            urls.push({ label: `Step ${step.id}`, value: step.url })
        }
    }
    for (const entry of urls) {
        if (httpOrigin(entry.value, entry.label) !== targetOrigin) {
            throw new Error(`${entry.label} is outside the active scan origin ${targetOrigin}.`)
        }
    }
    return { flow: normalized, targetOrigin }
}

export function prepareDashboardScanMacro(text, { fileName = '', format = 'auto', targetUrl = '' } = {}) {
    const imported = parseMacroDocument(text, { fileName, format })
    if (!imported.acceptable) {
        const blocking = imported.diagnostics.find((entry) => entry.level === 'error')
        throw new Error(blocking?.message || 'The macro contains blocking conversion errors.')
    }
    const scoped = assertDashboardMacroScope(imported.flow, targetUrl)
    return {
        ...imported,
        flow: scoped.flow,
        targetOrigin: scoped.targetOrigin,
        runtimeFields: scoped.flow.variables.map((entry) => ({
            name: entry.name,
            secret: entry.secret === true,
            suppliedByImport: entry.secret === true
                && Object.prototype.hasOwnProperty.call(imported.secretValues || {}, entry.name)
        }))
    }
}

export function compileDashboardScanMacro(prepared, { secrets = {}, variables = {}, elementPath = 'css' } = {}) {
    if (!prepared?.acceptable || !prepared?.flow) {
        throw new Error('Select a valid macro before starting scans.')
    }
    return compileFlow(prepared.flow, {
        secrets: { ...(prepared.secretValues || {}), ...secrets },
        variables,
        elementPath
    })
}

