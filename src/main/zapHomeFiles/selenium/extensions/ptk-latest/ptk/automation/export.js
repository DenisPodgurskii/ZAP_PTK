/* PTK privileged replayable export transport.
 *
 * This extension page is intentionally inert:
 * - no export on load
 * - no query/hash parsing
 * - no postMessage API
 * - no opener communication
 * - no localStorage/window.name command state
 */
;(function () {
    'use strict'

    const runtime = (typeof browser !== 'undefined' && browser.runtime)
        ? browser.runtime
        : (typeof chrome !== 'undefined' && chrome.runtime ? chrome.runtime : null)

    function send(type, request) {
        if (!runtime || typeof runtime.sendMessage !== 'function') {
            return Promise.resolve({ ok: false, error: 'privileged_export_transport_unavailable' })
        }
        return Promise.resolve(runtime.sendMessage({
            channel: 'ptk_privileged_replayable_export',
            type,
            transport: 'extension-page',
            request: {
                ...(request || {}),
                transport: 'extension-page',
                exportMode: 'replayable',
                includeSecrets: true,
                sensitive: true
            }
        })).then(result => result || { ok: false, error: 'null_response' })
            .catch(err => ({ ok: false, error: err?.message || String(err) }))
    }

    Object.defineProperty(window, 'PTK_REPLAYABLE_EXPORT_TRANSPORT', {
        configurable: false,
        enumerable: false,
        writable: false,
        value: Object.freeze({
            handshake() {
                return {
                    ok: true,
                    transport: 'extension-page',
                    extensionOrigin: window.location.origin,
                    pathname: window.location.pathname,
                    runtimeId: runtime?.id || null
                }
            },
            export(request = {}) {
                return send('ptk-privileged-replayable-export', request)
            },
            chunk(request = {}) {
                return send('ptk-privileged-replayable-export-chunk', request)
            },
            release(request = {}) {
                return send('ptk-privileged-replayable-export-release', request)
            }
        })
    })
})()
