const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])
const MAX_COOKIE_COUNT = 64
const MAX_COOKIE_LINE_LENGTH = 4096

function normalizeHostname(value) {
    return String(value || '').trim().replace(/^\.+/u, '').toLowerCase()
}

function defaultCookiePath(pathname) {
    const value = String(pathname || '')
    if (!value.startsWith('/') || value === '/') return '/'
    const lastSlash = value.lastIndexOf('/')
    return lastSlash <= 0 ? '/' : value.slice(0, lastSlash)
}

function cookiePathMatches(requestPath, cookiePath) {
    const target = String(requestPath || '/') || '/'
    const scope = String(cookiePath || '/') || '/'
    if (target === scope) return true
    if (!target.startsWith(scope)) return false
    return scope.endsWith('/') || target.charAt(scope.length) === '/'
}

function parseCookiePair(value) {
    const raw = String(value || '').trim()
    const separator = raw.indexOf('=')
    if (separator <= 0) return null
    const name = raw.slice(0, separator).trim()
    const cookieValue = raw.slice(separator + 1).trim()
    if (!name || /[\u0000-\u0020\u007f(),/:;<=>?@[\]{}]/u.test(name)) return null
    if (/[\r\n\u0000]/u.test(cookieValue)) return null
    return { name, value: cookieValue }
}

export function isRedirectStatus(status) {
    return REDIRECT_STATUSES.has(Number(status))
}

export function redirectRequestTransition(status, method, body) {
    const normalizedMethod = String(method || 'GET').toUpperCase()
    const code = Number(status)
    const rewriteToGet = (
        ((code === 301 || code === 302) && normalizedMethod === 'POST')
        || (code === 303 && normalizedMethod !== 'GET' && normalizedMethod !== 'HEAD')
    )
    return rewriteToGet
        ? { method: 'GET', body: null, bodyWasDropped: true }
        : { method: normalizedMethod, body, bodyWasDropped: false }
}

export class IsolatedRedirectCookieJar {
    constructor({ maxCookies = MAX_COOKIE_COUNT } = {}) {
        this.maxCookies = Math.max(1, Number(maxCookies) || MAX_COOKIE_COUNT)
        this.cookies = []
        this.sequence = 0
    }

    seedRequestCookieHeader(url, headerValue) {
        const parsedUrl = new URL(url)
        String(headerValue || '').split(';').forEach((part) => {
            const pair = parseCookiePair(part)
            if (!pair) return
            this._store({
                ...pair,
                domain: normalizeHostname(parsedUrl.hostname),
                path: '/',
                secure: parsedUrl.protocol === 'https:',
                expiresAt: null,
                exactOrigin: parsedUrl.origin
            })
        })
    }

    absorbResponseHeaders(url, headers, now = Date.now()) {
        const parsedUrl = new URL(url)
        const setCookieValues = (Array.isArray(headers) ? headers : [])
            .filter((header) => String(header?.name || '').toLowerCase() === 'set-cookie')
            .map((header) => String(header?.value || ''))
        setCookieValues.forEach((value) => this._absorbSetCookie(parsedUrl, value, now))
    }

    cookieHeaderFor(url, now = Date.now()) {
        const parsedUrl = new URL(url)
        const hostname = normalizeHostname(parsedUrl.hostname)
        const pathname = parsedUrl.pathname || '/'
        this.cookies = this.cookies.filter((cookie) => cookie.expiresAt === null || cookie.expiresAt > now)
        return this.cookies
            .filter((cookie) => {
                if (cookie.exactOrigin && cookie.exactOrigin !== parsedUrl.origin) return false
                if (cookie.domain !== hostname) return false
                if (cookie.secure && parsedUrl.protocol !== 'https:') return false
                return cookiePathMatches(pathname, cookie.path)
            })
            .sort((left, right) => right.path.length - left.path.length || left.sequence - right.sequence)
            .map((cookie) => `${cookie.name}=${cookie.value}`)
            .join('; ')
    }

    _absorbSetCookie(parsedUrl, value, now) {
        if (!value || value.length > MAX_COOKIE_LINE_LENGTH || /[\r\n]/u.test(value)) return
        const segments = value.split(';')
        const pair = parseCookiePair(segments.shift())
        if (!pair) return

        const attributes = new Map()
        segments.forEach((segment) => {
            const raw = segment.trim()
            if (!raw) return
            const separator = raw.indexOf('=')
            const name = (separator >= 0 ? raw.slice(0, separator) : raw).trim().toLowerCase()
            const attributeValue = separator >= 0 ? raw.slice(separator + 1).trim() : ''
            if (name && !attributes.has(name)) attributes.set(name, attributeValue)
        })

        const responseHostname = normalizeHostname(parsedUrl.hostname)
        const requestedDomain = normalizeHostname(attributes.get('domain'))
        // Fail closed without a public-suffix implementation: response cookies
        // may not expand beyond the exact host which issued them.
        if (requestedDomain && requestedDomain !== responseHostname) return

        const requestedPath = attributes.get('path')
        const path = requestedPath?.startsWith('/')
            ? requestedPath
            : defaultCookiePath(parsedUrl.pathname)
        let expiresAt = null
        if (attributes.has('max-age')) {
            const rawMaxAge = attributes.get('max-age')
            const maxAge = /^-?\d+$/u.test(rawMaxAge)
                ? Number.parseInt(rawMaxAge, 10)
                : Number.NaN
            if (Number.isFinite(maxAge)) expiresAt = maxAge <= 0 ? 0 : now + (maxAge * 1000)
        } else if (attributes.has('expires')) {
            const parsedExpiry = Date.parse(attributes.get('expires'))
            if (Number.isFinite(parsedExpiry)) expiresAt = parsedExpiry
        }

        const record = {
            ...pair,
            domain: responseHostname,
            path,
            secure: attributes.has('secure'),
            expiresAt,
            exactOrigin: null
        }
        if (expiresAt !== null && expiresAt <= now) {
            this._delete(record)
            return
        }
        this._store(record)
    }

    _delete(record) {
        this.cookies = this.cookies.filter((cookie) => !(
            cookie.name === record.name
            && cookie.domain === record.domain
            && cookie.path === record.path
            && cookie.exactOrigin === record.exactOrigin
        ))
    }

    _store(record) {
        this._delete(record)
        this.cookies.push({ ...record, sequence: this.sequence++ })
        if (this.cookies.length > this.maxCookies) {
            this.cookies.splice(0, this.cookies.length - this.maxCookies)
        }
    }
}
