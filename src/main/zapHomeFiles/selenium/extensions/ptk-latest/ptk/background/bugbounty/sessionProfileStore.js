function cloneValue(value) {
    if (typeof globalThis.structuredClone === "function") {
        try {
            return globalThis.structuredClone(value)
        } catch (_) {
            // fall back to JSON clone
        }
    }
    return JSON.parse(JSON.stringify(value ?? null))
}

function normalizeHostValue(host) {
    if (host === null || host === undefined) return ""
    const raw = String(host).trim()
    if (!raw) return ""
    try {
        if (/^https?:\/\//i.test(raw)) {
            return new URL(raw).host.toLowerCase()
        }
    } catch (_) {
        // fall through to string normalization
    }
    return raw
        .replace(/^https?:\/\//i, "")
        .replace(/\/+.*$/, "")
        .toLowerCase()
}

function cookieDomainFromHost(host) {
    return normalizeHostValue(host).split(":")[0] || ""
}

function normalizeLabel(label) {
    return String(label || "").trim()
}

function buildProfileSummary(profile = {}) {
    return {
        id: profile.id || null,
        label: profile.label || "",
        host: profile.host || "",
        notes: profile.notes || "",
        createdAt: profile.createdAt || null,
        updatedAt: profile.updatedAt || null,
        cookieCount: Number(profile.cookieCount || 0)
    }
}

function normalizeCookie(cookie = {}) {
    return {
        domain: cookie.domain || "",
        expirationDate: cookie.expirationDate,
        hostOnly: cookie.hostOnly === true,
        httpOnly: cookie.httpOnly === true,
        name: cookie.name || "",
        path: cookie.path || "/",
        sameSite: cookie.sameSite || "no_restriction",
        secure: cookie.secure === true,
        session: cookie.session !== false,
        storeId: cookie.storeId || "0",
        value: cookie.value || ""
    }
}

function cookieKey(cookie = {}) {
    return [
        cookie.domain || "",
        cookie.path || "/",
        cookie.name || "",
        cookie.value || ""
    ].join("|")
}

function dedupeCookies(cookies = []) {
    const seen = new Set()
    return (Array.isArray(cookies) ? cookies : [])
        .filter((cookie) => {
            const key = cookieKey(cookie)
            if (!key || seen.has(key)) return false
            seen.add(key)
            return true
        })
}

export class SessionProfileStore {
    constructor({
        storage = null,
        browserApi = typeof browser !== "undefined" ? browser : null,
        storageKey = "ptk_bugbounty_session_profiles_v1",
        now = () => new Date().toISOString()
    } = {}) {
        this.storage = storage
        this.browserApi = browserApi
        this.storageKey = storageKey
        this.now = now
        this._loaded = false
        this._profiles = []
    }

    normalizeHost(host) {
        return normalizeHostValue(host)
    }

    async load() {
        if (this._loaded) return this._profiles
        const stored = await this.storage?.getItem?.(this.storageKey)
        if (Array.isArray(stored?.profiles)) {
            this._profiles = stored.profiles
        } else if (Array.isArray(stored)) {
            this._profiles = stored
        } else {
            this._profiles = []
        }
        this._loaded = true
        return this._profiles
    }

    async _persist() {
        await this.storage?.setItem?.(this.storageKey, {
            profiles: this._profiles
        })
    }

    async _captureCookiesForHost(host) {
        const domain = cookieDomainFromHost(host)
        if (!domain || !this.browserApi?.cookies?.getAll) {
            return []
        }
        const collected = []
        const errors = []
        const attempts = [
            { domain },
            { url: `https://${domain}/` },
            { url: `http://${domain}/` }
        ]
        for (const query of attempts) {
            try {
                const cookies = await this.browserApi.cookies.getAll(query)
                if (Array.isArray(cookies) && cookies.length) {
                    collected.push(...cookies)
                }
            } catch (err) {
                errors.push(err?.message || String(err))
            }
        }
        if (!collected.length && errors.length === attempts.length) {
            throw new Error(`Session cookies could not be read for ${domain}: ${errors[0] || "cookie_access_failed"}`)
        }
        return dedupeCookies(collected)
            .map(normalizeCookie)
            .sort((left, right) => `${left.domain}|${left.name}|${left.path}`.localeCompare(`${right.domain}|${right.name}|${right.path}`))
    }

    async listProfiles({ host = null, includeSnapshot = false } = {}) {
        await this.load()
        const hostKey = this.normalizeHost(host)
        return this._profiles
            .filter((profile) => !hostKey || this.normalizeHost(profile?.host) === hostKey)
            .map((profile) => {
                if (includeSnapshot) {
                    return cloneValue(profile)
                }
                return buildProfileSummary(profile)
            })
            .sort((left, right) => String(left?.label || "").localeCompare(String(right?.label || "")))
    }

    async getProfile(id, { includeSnapshot = true } = {}) {
        await this.load()
        const key = String(id || "").trim()
        if (!key) return null
        const profile = this._profiles.find((entry) => String(entry?.id || "") === key) || null
        if (!profile) return null
        return includeSnapshot ? cloneValue(profile) : buildProfileSummary(profile)
    }

    async createProfile({ label = "", host = null, notes = "", cookies = null } = {}) {
        await this.load()
        const normalizedLabel = normalizeLabel(label)
        const normalizedHost = this.normalizeHost(host)
        if (!normalizedLabel) {
            throw new Error("Session profile label is required.")
        }
        if (!normalizedHost) {
            throw new Error("Session profile host is required.")
        }
        const capturedCookies = Array.isArray(cookies)
            ? cookies.map(normalizeCookie)
            : await this._captureCookiesForHost(normalizedHost)
        if (!capturedCookies.length) {
            throw new Error(`No cookies were captured for ${normalizedHost}. Session profiles currently support cookie-backed auth only.`)
        }
        const timestamp = this.now()
        const profile = {
            id: `session_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`,
            label: normalizedLabel,
            host: normalizedHost,
            notes: String(notes || "").trim(),
            createdAt: timestamp,
            updatedAt: timestamp,
            cookieCount: capturedCookies.length,
            snapshot: {
                cookies: capturedCookies
            }
        }
        this._profiles.push(profile)
        await this._persist()
        return buildProfileSummary(profile)
    }

    async deleteProfile(id) {
        await this.load()
        const key = String(id || "").trim()
        if (!key) return false
        const before = this._profiles.length
        this._profiles = this._profiles.filter((profile) => String(profile?.id || "") !== key)
        const deleted = this._profiles.length !== before
        if (deleted) {
            await this._persist()
        }
        return deleted
    }
}

export default SessionProfileStore
