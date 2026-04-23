/* Author: PTK */

if (!window.__ptkBrowserWorkflowHarnessLoaded) {
    window.__ptkBrowserWorkflowHarnessLoaded = true

    const ATTACK_TAB_MARKER = 'ptk_browser_workflow_attack_tab'
    const DEFAULT_PROTECTED_PATHS = [
        '/my-account',
        '/account',
        '/profile',
        '/dashboard',
        '/settings',
        '/me',
        '/user'
    ]
    const DEFAULT_CHALLENGE_REGEX = /(mfa|2fa|otp|totp|one[-_ ]?time|verification\s*code|security\s*code|authenticator|challenge|verify)/i
    const DEFAULT_LOGGED_OUT_REGEX = /(log\s*in|sign\s*in|forgot\s*password|reset\s*password|authentication\s*required|please\s*sign\s*in)/i
    const DEFAULT_LOGGED_IN_REGEX = /(log\s*out|sign\s*out|my\s*account|account\s*settings|profile|dashboard|settings)/i

    function isAttackTab() {
        try {
            return String(window.name || '').includes(ATTACK_TAB_MARKER)
        } catch (_) {
            return false
        }
    }

    function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms))
    }

    async function waitForPageSettled(waitMs) {
        const bounded = Math.max(0, Math.min(5000, Number(waitMs) || 0))
        if (document.readyState === 'complete') {
            if (bounded > 0) await sleep(bounded)
            return
        }
        await new Promise((resolve) => {
            let done = false
            const finish = async () => {
                if (done) return
                done = true
                if (bounded > 0) await sleep(bounded)
                resolve()
            }
            window.addEventListener('load', () => { finish() }, { once: true })
            setTimeout(() => { finish() }, Math.max(1500, bounded + 250))
        })
    }

    function uniqueStrings(values = []) {
        const seen = new Set()
        const out = []
        for (const value of Array.isArray(values) ? values : [values]) {
            const text = String(value || '').trim()
            if (!text || seen.has(text)) continue
            seen.add(text)
            out.push(text)
        }
        return out
    }

    function buildRegex(value, fallback) {
        if (value instanceof RegExp) return value
        const text = String(value || '').trim()
        if (!text) return fallback
        try {
            return new RegExp(text, 'i')
        } catch (_) {
            return fallback
        }
    }

    function normalizeHeaders(input = {}) {
        const headers = new Headers()
        if (!input || typeof input !== 'object' || Array.isArray(input)) return headers
        Object.entries(input).forEach(([name, value]) => {
            const headerName = String(name || '').trim()
            if (!headerName) return
            try {
                headers.set(headerName, String(value ?? ''))
            } catch (_) { }
        })
        return headers
    }

    function normalizeProtectedPaths(paths = []) {
        const normalized = uniqueStrings(paths)
        return normalized.length ? normalized : DEFAULT_PROTECTED_PATHS.slice()
    }

    async function summarizeFetch(url, opts = {}, classifiers = {}) {
        const response = await fetch(url, opts)
        let text = ''
        try {
            text = await response.text()
        } catch (_) { }
        const sampledText = String(text || '').slice(0, 20000)
        const loginLike = classifiers.loggedOutRegex.test(response.url || '') || classifiers.loggedOutRegex.test(sampledText)
        const challengeLike = classifiers.challengeRegex.test(response.url || '') || classifiers.challengeRegex.test(sampledText)
        const loggedInLike = classifiers.loggedInRegex.test(response.url || '') || classifiers.loggedInRegex.test(sampledText)
        const denied = [401, 403].includes(Number(response.status || 0)) || loginLike || challengeLike
        const accessible = response.ok && !loginLike && !challengeLike
        return {
            url: response.url || url,
            status: Number(response.status || 0) || null,
            redirected: !!response.redirected,
            denied,
            loginLike,
            challengeLike,
            loggedInLike,
            accessible
        }
    }

    async function runAuth2faBypass({
        request = {},
        settleMs = 0,
        protectedPaths = [],
        challengeRegex = null,
        loggedOutRegex = null,
        loggedInRegex = null
    } = {}) {
        const requestUrl = String(request?.url || '').trim()
        if (!requestUrl) return { error: 'missing_request_url' }
        let origin
        try {
            origin = new URL(requestUrl).origin
        } catch (_) {
            return { error: 'invalid_request_url' }
        }

        const classifiers = {
            challengeRegex: buildRegex(challengeRegex, DEFAULT_CHALLENGE_REGEX),
            loggedOutRegex: buildRegex(loggedOutRegex, DEFAULT_LOGGED_OUT_REGEX),
            loggedInRegex: buildRegex(loggedInRegex, DEFAULT_LOGGED_IN_REGEX)
        }
        const candidatePaths = normalizeProtectedPaths(protectedPaths)
        const requestHeaders = normalizeHeaders(request.headers)

        const baseline = []
        for (const path of candidatePaths) {
            const targetUrl = new URL(path, origin).toString()
            baseline.push({
                path,
                ...(await summarizeFetch(targetUrl, {
                    method: 'GET',
                    credentials: 'include',
                    redirect: 'follow'
                }, classifiers))
            })
        }

        const baselineDenied = baseline.filter((entry) => entry.denied)
        if (!baselineDenied.length) {
            return {
                challengeDetected: false,
                reason: 'no_protected_baseline',
                baseline
            }
        }

        const requestMethod = String(request?.method || 'POST').toUpperCase()
        const loginResponse = await summarizeFetch(requestUrl, {
            method: requestMethod,
            headers: requestHeaders,
            body: ['GET', 'HEAD'].includes(requestMethod) ? undefined : (request?.body ?? ''),
            credentials: 'include',
            redirect: 'follow'
        }, classifiers)

        const challengeDetected = !!loginResponse.challengeLike
        if (!challengeDetected) {
            return {
                challengeDetected: false,
                reason: 'no_challenge_signal',
                baseline,
                loginResponse
            }
        }

        if (settleMs > 0) {
            await sleep(Math.max(0, Math.min(5000, Number(settleMs) || 0)))
        }

        const protectedChecks = []
        for (const entry of baseline) {
            protectedChecks.push({
                path: entry.path,
                baseline: entry,
                ...(await summarizeFetch(new URL(entry.path, origin).toString(), {
                    method: 'GET',
                    credentials: 'include',
                    redirect: 'follow'
                }, classifiers))
            })
        }

        const finding = protectedChecks.find((entry) => entry.baseline?.denied && entry.accessible)
        return {
            challengeDetected,
            reason: finding ? 'bypass_detected' : 'no_bypass_evidence',
            baseline,
            loginResponse,
            protectedChecks,
            finding: finding || null
        }
    }

    async function runBrowserWorkflowTest({
        flow = 'auth_2fa_bypass',
        request = {},
        settleMs = 0,
        protectedPaths = [],
        challengeRegex = null,
        loggedOutRegex = null,
        loggedInRegex = null
    } = {}) {
        if (!isAttackTab()) {
            return { error: 'not_attack_tab' }
        }

        await waitForPageSettled(settleMs)

        if (String(flow || '').trim().toLowerCase() !== 'auth_2fa_bypass') {
            return { error: 'unsupported_flow' }
        }

        return runAuth2faBypass({
            request,
            settleMs,
            protectedPaths,
            challengeRegex,
            loggedOutRegex,
            loggedInRegex
        })
    }

    const workflowRuntime = (typeof browser !== 'undefined' && browser.runtime)
        ? browser.runtime
        : ((typeof chrome !== 'undefined' && chrome.runtime) ? chrome.runtime : null)

    if (workflowRuntime?.onMessage?.addListener) {
        workflowRuntime.onMessage.addListener((msg, sender, sendResponse) => {
            if (msg?.type === 'browserWorkflowPing') {
                if (sendResponse) sendResponse({ ok: true, active: isAttackTab() })
                return false
            }
            if (msg?.type === 'browserWorkflowRun') {
                Promise.resolve()
                    .then(() => runBrowserWorkflowTest(msg))
                    .then((result) => {
                        if (sendResponse) sendResponse(result)
                    })
                    .catch((err) => {
                        const message = err && err.message ? err.message : String(err || 'unknown error')
                        if (sendResponse) sendResponse({ error: message })
                    })
                return true
            }
        })
    }
}
