export const AUTOMATION_POPUP_PATH = 'ptk/automation/popup.html'

export function isTrustedAutomationPopupSender(sender = {}, runtime = globalThis.browser?.runtime) {
    if (!runtime || typeof runtime.getURL !== 'function') return false
    if (sender?.tab) return false
    if (runtime.id && sender?.id !== runtime.id) return false

    const senderUrl = typeof sender?.url === 'string' ? sender.url : ''
    return senderUrl === runtime.getURL(AUTOMATION_POPUP_PATH)
}
