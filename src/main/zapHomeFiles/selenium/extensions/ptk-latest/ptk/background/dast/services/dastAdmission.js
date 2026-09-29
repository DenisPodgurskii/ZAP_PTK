import { getSearchParamsFromUrlOrHash } from "../urlUtils.js"

export function isDastResponseAllowed(response = {}, state = {}) {
    const rawUrl = response?.ui_url || response?.url || ""
    const sourceUrl = response?.url || rawUrl
    if (!sourceUrl) return false
    let url
    try { url = new URL(sourceUrl) } catch (_) { return false }
    const hasParams = Array.from(getSearchParamsFromUrlOrHash(rawUrl).keys()).length > 0
    const method = String(response?.method || "GET").toUpperCase()
    const stateChanging = ["POST", "PUT", "PATCH", "DELETE"].includes(method)
    const blacklist = Array.isArray(state?.settings?.blacklist) ? state.settings.blacklist : []
    if (blacklist.includes(response.type) && !hasParams && !stateChanging) return false
    const host = String(state?.host || "")
    const domains = Array.isArray(state?.domains) ? state.domains : []
    return url.host.includes(host) || domains.some(domain => url.host.includes(domain))
}
