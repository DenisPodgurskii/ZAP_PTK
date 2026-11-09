import { installPtkZapMainBootstrap } from '../../../zapAutomationMainBootstrap.js'

const OWNER_FIELDS = Object.freeze([
    'captureId', 'zapid', 'browserid', 'tabId', 'frameId',
    'documentId', 'sessionGeneration', 'streamGeneration', 'url'
])
const ID = /^[A-Za-z0-9_-]{1,128}$/u

function sameOwner(a, b) {
    return !!a && !!b && OWNER_FIELDS.every(key => a[key] === b[key])
}

async function currentFrame(browserApi, tabId) {
    try { return await browserApi.webNavigation.getFrame({ tabId, frameId: 0 }) }
    catch (_) { return null }
}

/**
 * Install the generated bridge/Agent function in the exact currently owned
 * Chromium document. This is an admission primitive, not a visit-completion
 * receipt. The caller must supply the ZAP capture owner's native recheck.
 */
export async function installZapOwnedMainBootstrap({
    browserApi = globalThis.browser, sender, zapid, browserid, getOwnedRoot,
    version, extensionOrigin, nonce
} = {}) {
    const tabId = sender?.tab?.id
    const documentId = sender?.documentId
    const url = sender?.url
    if (!Number.isInteger(tabId) || tabId < 0 || sender?.frameId !== 0
        || typeof documentId !== 'string' || !documentId || documentId.length > 128
        || typeof url !== 'string' || url.length > 2048 || !/^https?:\/\//u.test(url)
        || !ID.test(zapid || '') || !ID.test(browserid || '')
        || typeof version !== 'string' || !version || version.length > 64
        || typeof extensionOrigin !== 'string'
        || !/^chrome-extension:\/\/[a-z]{32}$/u.test(extensionOrigin)
        || typeof nonce !== 'string' || !/^ptk-[A-Za-z0-9._-]{1,124}$/u.test(nonce)
        || typeof getOwnedRoot !== 'function'
        || typeof browserApi?.webNavigation?.getFrame !== 'function'
        || typeof browserApi?.scripting?.executeScript !== 'function') {
        return { ok: false, reason: 'main_bootstrap_admission_unavailable' }
    }
    let before
    try { before = await getOwnedRoot({ zapid, browserid }) }
    catch (_) { return { ok: false, reason: 'main_bootstrap_owner_unavailable' } }
    if (!before || before.tabId !== tabId || before.zapid !== zapid || before.browserid !== browserid
        || before.url !== url
        || !Number.isSafeInteger(before.streamGeneration) || before.streamGeneration < 0) {
        return { ok: false, reason: 'main_bootstrap_owner_unavailable' }
    }
    const frameBefore = await currentFrame(browserApi, tabId)
    if (frameBefore?.documentId !== documentId || frameBefore?.url !== url) {
        return { ok: false, reason: 'main_bootstrap_document_changed' }
    }
    const config = { schema: 'ptk-zap-main-bootstrap-v1', enabled: true, version, extensionOrigin, nonce }
    let results
    try {
        results = await browserApi.scripting.executeScript({
            target: { tabId, documentIds: [documentId] },
            world: 'MAIN', injectImmediately: true,
            func: installPtkZapMainBootstrap, args: [config]
        })
    } catch (_) {
        return { ok: false, reason: 'main_bootstrap_injection_failed' }
    }
    const frameAfter = await currentFrame(browserApi, tabId)
    let after
    try { after = await getOwnedRoot({ zapid, browserid }) }
    catch (_) { return { ok: false, reason: 'main_bootstrap_result_unverified' } }
    if (!sameOwner(before, after) || frameAfter?.documentId !== documentId
        || frameAfter?.url !== url || !Array.isArray(results) || results.length !== 1
        || results[0]?.documentId !== documentId || results[0]?.frameId !== 0
        || results[0]?.result?.ok !== true || results[0]?.result?.nonce !== nonce
        || results[0]?.result?.bridgeId !== 'ptk-automation-bridge') {
        return { ok: false, reason: 'main_bootstrap_result_unverified' }
    }
    return { ok: true, nonce, documentId, streamGeneration: after.streamGeneration }
}
