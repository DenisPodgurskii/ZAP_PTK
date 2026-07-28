/* Author: Denis Podgurskii */
'use strict'

export const PTK_AUTOMATION_CONTROL_PATH = '/ptk/automation/control.html'

function parseAutomationControlUrl(value = '') {
    try {
        const parsed = new URL(String(value || ''))
        if (parsed.protocol !== 'chrome-extension:' && parsed.protocol !== 'moz-extension:') return null
        if (parsed.pathname !== PTK_AUTOMATION_CONTROL_PATH || parsed.search || parsed.hash) return null
        return parsed
    } catch (_) {
        return null
    }
}

export function isTrustedAutomationControlSender(sender = {}) {
    if (!browser?.runtime?.id || sender?.id !== browser.runtime.id) return false
    if (!Number.isInteger(sender?.frameId) || !Number.isInteger(sender?.tab?.id)) return false
    const senderUrl = parseAutomationControlUrl(sender?.url)
    if (!senderUrl) return false
    if (senderUrl.protocol === 'chrome-extension:' && senderUrl.hostname !== browser.runtime.id) return false

    if (sender.frameId === 0) {
        const tabUrl = parseAutomationControlUrl(sender?.tab?.url)
        if (!tabUrl) return false
        return senderUrl.protocol === tabUrl.protocol && senderUrl.hostname === tabUrl.hostname
    }

    // Firefox WebDriver deliberately blocks top-level moz-extension navigation.
    // The automation SDK therefore loads this inert extension page in an iframe
    // owned by a fresh about:blank tab and switches WebDriver into that frame.
    // A normal website cannot invoke the frame's extension-owned API because of
    // the same-origin boundary, and the control page never acts automatically.
    return senderUrl.protocol === 'moz-extension:' && sender?.tab?.url === 'about:blank'
}

export function buildIastPreNavigationOptions(message = {}) {
    const scanOptions = message?.scanOptions && typeof message.scanOptions === 'object'
        ? message.scanOptions
        : {}
    const engineConfigs = scanOptions?.engineConfigs && typeof scanOptions.engineConfigs === 'object'
        ? scanOptions.engineConfigs
        : {}
    const iastConfig = engineConfigs.IAST && typeof engineConfigs.IAST === 'object'
        ? engineConfigs.IAST
        : message?.iastOptions && typeof message.iastOptions === 'object'
            ? message.iastOptions
            : {}
    const scanStrategy = iastConfig.scanStrategy || scanOptions.policyCode || message?.scanStrategy || 'SMART'
    const opts = {}
    for (const key of ['rulepack', 'preferPortal', 'policyId', 'policyName', 'variant', 'portal']) {
        if (Object.prototype.hasOwnProperty.call(iastConfig, key)) opts[key] = iastConfig[key]
    }
    if (message?.ttlMs != null) opts.armTtlMs = message.ttlMs
    return { scanStrategy, opts }
}
