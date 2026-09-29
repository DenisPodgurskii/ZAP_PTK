export class LocalDastBrowserOperations {
    constructor({ browserApi = globalThis.browser } = {}) {
        this.browserApi = browserApi
        this.remote = false
    }

    sendRuntimeMessage(message) {
        return this.browserApi?.runtime?.sendMessage?.(message) || Promise.resolve(undefined)
    }

    call(method, args = []) {
        const [namespace, name] = String(method || "").split(".")
        const fn = this.browserApi?.[namespace]?.[name]
        if (typeof fn !== "function") throw new Error("dast_browser_operation_unavailable")
        return fn.apply(this.browserApi[namespace], args)
    }

    async subscribe(event, listener, options = {}) {
        const [namespace, name] = String(event || "").split(".")
        const target = this.browserApi?.[namespace]?.[name]
        if (!target?.addListener || !target?.removeListener) throw new Error("dast_browser_event_unavailable")
        if (options.filter && options.extraInfoSpec) target.addListener(listener, options.filter, options.extraInfoSpec)
        else if (options.filter) target.addListener(listener, options.filter)
        else target.addListener(listener)
        return () => target.removeListener(listener)
    }
}

export function applyDastRequestTransportFlags(request, flags = {}) {
    request.useListeners = flags.useListeners === true
    request.trackWithListeners = flags.trackWithListeners === true
    request.isolatedRedirectSession = flags.isolatedRedirectSession === true
    request.isolatedPreserveRawHeaders = flags.isolatedPreserveRawHeaders === true
    return request
}

export default LocalDastBrowserOperations
