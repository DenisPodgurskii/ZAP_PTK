// Upgrade cleanup only. The retired source provider must never tag new traffic.
const CAPTURE_HEADER = 'x-ptk-sast-capture'
const RULE_BASE = 1900000000

export async function removeLegacySastCaptureRules(browserApi = globalThis.browser) {
    const dnr = browserApi?.declarativeNetRequest
    if (!dnr?.getSessionRules) return
    const rules = await dnr.getSessionRules()
    const owned = rules.filter(rule => Number.isInteger(rule.id) && rule.id >= RULE_BASE
        && rule.action?.type === 'modifyHeaders' && rule.action.requestHeaders?.length === 1
        && rule.action.requestHeaders[0].header?.toLowerCase() === CAPTURE_HEADER
        && rule.action.requestHeaders[0].operation === 'set'
        && /^[a-f0-9]{32}$/.test(rule.action.requestHeaders[0].value || '')
        && rule.condition?.tabIds?.length === 1 && Number.isInteger(rule.condition.tabIds[0])
        && rule.condition.requestMethods?.length === 1 && rule.condition.requestMethods[0] === 'get'
        && (JSON.stringify(rule.condition.resourceTypes) === '["main_frame","sub_frame"]'
            || JSON.stringify(rule.condition.resourceTypes) === '["script"]'))
    if (owned.length) await dnr.updateSessionRules({ removeRuleIds: owned.map(rule => rule.id) })
}
