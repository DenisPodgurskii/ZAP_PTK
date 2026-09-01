const DEFAULT_MAX_RELATED_TABS = 16
const DEFAULT_MAX_DEPTH = 4

function normalizeTabId(value) {
    const numeric = Number(value)
    return Number.isInteger(numeric) && numeric >= 0 ? numeric : null
}

function normalizeEngineId(value) {
    return String(value || '').trim().toUpperCase()
}

function normalizeHttpUrl(value) {
    try {
        const parsed = new URL(String(value || '').trim())
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
        if (parsed.username || parsed.password) return null
        return parsed
    } catch (_) {
        return null
    }
}

function normalizeScopeMode(value) {
    return String(value || '').trim().toLowerCase() === 'path' ? 'path' : 'origin'
}

function buildScope(rawUrl, mode = 'origin') {
    const parsed = normalizeHttpUrl(rawUrl)
    if (!parsed) return null
    const pathname = parsed.pathname || '/'
    const pathPrefix = pathname === '/'
        ? '/'
        : pathname.endsWith('/')
            ? pathname
            : `${pathname}/`
    return {
        mode: normalizeScopeMode(mode),
        origin: parsed.origin,
        pathname,
        pathPrefix
    }
}

function isUrlInScope(rawUrl, scope) {
    const parsed = normalizeHttpUrl(rawUrl)
    if (!parsed || !scope?.origin || parsed.origin !== scope.origin) return false
    if (scope.mode !== 'path' || scope.pathname === '/') return true
    return parsed.pathname === scope.pathname || parsed.pathname.startsWith(scope.pathPrefix)
}

function isPendingNavigationUrl(rawUrl) {
    const value = String(rawUrl || '').trim().toLowerCase()
    return !value || value === 'about:blank' || value.startsWith('about:srcdoc')
}

function cloneMeta(meta = {}) {
    return {
        tabId: meta.tabId,
        parentTabId: meta.parentTabId,
        rootTabId: meta.rootTabId,
        depth: meta.depth,
        role: meta.role,
        source: meta.source,
        url: meta.url || null,
        state: meta.state,
        createdAt: meta.createdAt,
        updatedAt: meta.updatedAt,
        reason: meta.reason || null
    }
}

export class ScopedTabSessionCoordinator {
    constructor({
        browserApi = globalThis.browser,
        maxRelatedTabs = DEFAULT_MAX_RELATED_TABS,
        maxDepth = DEFAULT_MAX_DEPTH
    } = {}) {
        this.browserApi = browserApi || null
        this.maxRelatedTabs = Math.max(1, Number(maxRelatedTabs) || DEFAULT_MAX_RELATED_TABS)
        this.maxDepth = Math.max(1, Number(maxDepth) || DEFAULT_MAX_DEPTH)
        this.sessions = new Map()
        this.started = false

        this._onCreated = (tab) => {
            this.observeCreatedTab(tab).catch(() => { })
        }
        this._onUpdated = (tabId, changeInfo, tab) => {
            this.observeTabUpdated(tabId, changeInfo, tab).catch(() => { })
        }
        this._onRemoved = (tabId) => {
            this.observeTabRemoved(tabId)
        }
        this._onCreatedNavigationTarget = (details) => {
            this.observeCreatedNavigationTarget(details).catch(() => { })
        }
    }

    start() {
        if (this.started) return false
        this.started = true
        this.browserApi?.tabs?.onCreated?.addListener?.(this._onCreated)
        this.browserApi?.tabs?.onUpdated?.addListener?.(this._onUpdated)
        this.browserApi?.tabs?.onRemoved?.addListener?.(this._onRemoved)
        this.browserApi?.webNavigation?.onCreatedNavigationTarget?.addListener?.(
            this._onCreatedNavigationTarget
        )
        return true
    }

    stop() {
        if (!this.started) return false
        this.started = false
        this.browserApi?.tabs?.onCreated?.removeListener?.(this._onCreated)
        this.browserApi?.tabs?.onUpdated?.removeListener?.(this._onUpdated)
        this.browserApi?.tabs?.onRemoved?.removeListener?.(this._onRemoved)
        this.browserApi?.webNavigation?.onCreatedNavigationTarget?.removeListener?.(
            this._onCreatedNavigationTarget
        )
        return true
    }

    async registerSession(engineId, options = {}) {
        const key = normalizeEngineId(engineId)
        const primaryTabId = normalizeTabId(options?.primaryTabId)
        if (!key || primaryTabId === null) return false

        this.unregisterSession(key, 'session_replaced')
        const now = Date.now()
        const session = {
            engineId: key,
            primaryTabId,
            scopeMode: normalizeScopeMode(options?.scopeMode),
            scope: buildScope(options?.targetUrl, options?.scopeMode),
            tabs: new Map(),
            onEnroll: typeof options?.onEnroll === 'function' ? options.onEnroll : null,
            onRelease: typeof options?.onRelease === 'function' ? options.onRelease : null,
            createdAt: now,
            updatedAt: now
        }
        session.tabs.set(primaryTabId, {
            tabId: primaryTabId,
            parentTabId: null,
            rootTabId: primaryTabId,
            depth: 0,
            role: 'primary_scan_tab',
            source: 'scan_start',
            url: typeof options?.targetUrl === 'string' ? options.targetUrl : null,
            state: 'active',
            createdAt: now,
            updatedAt: now
        })
        this.sessions.set(key, session)

        if (!session.scope && this.browserApi?.tabs?.get) {
            try {
                const tab = await this.browserApi.tabs.get(primaryTabId)
                const url = tab?.url || null
                session.scope = buildScope(url, session.scopeMode)
                const primary = session.tabs.get(primaryTabId)
                if (primary && url) {
                    primary.url = url
                    primary.updatedAt = Date.now()
                }
            } catch (_) { }
        }
        return !!session.scope
    }

    unregisterSession(engineId, reason = 'session_stopped') {
        const key = normalizeEngineId(engineId)
        const session = this.sessions.get(key)
        if (!session) return false
        const related = [...session.tabs.values()]
            .filter((meta) => meta.tabId !== session.primaryTabId && meta.state === 'active')
            .sort((left, right) => right.depth - left.depth)
        for (const meta of related) {
            this._notifyRelease(session, meta, reason)
        }
        this.sessions.delete(key)
        return true
    }

    hasSession(engineId) {
        return this.sessions.has(normalizeEngineId(engineId))
    }

    isTrackedTab(engineId, tabId) {
        const session = this.sessions.get(normalizeEngineId(engineId))
        const normalized = normalizeTabId(tabId)
        if (!session || normalized === null) return false
        return session.tabs.get(normalized)?.state === 'active'
    }

    getTabMeta(engineId, tabId, { includePending = false } = {}) {
        const session = this.sessions.get(normalizeEngineId(engineId))
        const normalized = normalizeTabId(tabId)
        if (!session || normalized === null) return null
        const meta = session.tabs.get(normalized)
        if (!meta || (!includePending && meta.state !== 'active')) return null
        return cloneMeta(meta)
    }

    isUrlInScope(engineId, rawUrl) {
        const session = this.sessions.get(normalizeEngineId(engineId))
        return !!session?.scope && isUrlInScope(rawUrl, session.scope)
    }

    async observeCreatedTab(tab = {}) {
        return this._observeChildCandidate({
            tabId: tab?.id,
            parentTabId: tab?.openerTabId,
            url: tab?.pendingUrl || tab?.url || null,
            source: 'tabs.onCreated'
        })
    }

    async observeCreatedNavigationTarget(details = {}) {
        return this._observeChildCandidate({
            tabId: details?.tabId,
            parentTabId: details?.sourceTabId,
            url: details?.url || null,
            source: 'webNavigation.onCreatedNavigationTarget'
        })
    }

    async _observeChildCandidate({ tabId, parentTabId, url, source }) {
        const childId = normalizeTabId(tabId)
        const parentId = normalizeTabId(parentTabId)
        if (childId === null || parentId === null || childId === parentId) return false

        let admitted = false
        for (const session of this.sessions.values()) {
            const parent = session.tabs.get(parentId)
            if (!parent || parent.state !== 'active') continue

            const existing = session.tabs.get(childId)
            if (existing?.state === 'active') {
                if (url && isUrlInScope(url, session.scope)) {
                    existing.url = url
                    existing.updatedAt = Date.now()
                }
                admitted = true
                continue
            }

            const depth = Number(parent.depth || 0) + 1
            if (depth > this.maxDepth) continue
            const relatedCount = [...session.tabs.values()]
                .filter((meta) => meta.tabId !== session.primaryTabId).length
            if (!existing && relatedCount >= this.maxRelatedTabs) continue

            const now = Date.now()
            const meta = existing || {
                tabId: childId,
                parentTabId: parentId,
                rootTabId: session.primaryTabId,
                depth,
                role: 'application_child_tab',
                source,
                url: null,
                state: 'pending',
                createdAt: now,
                updatedAt: now
            }
            meta.parentTabId = parentId
            meta.rootTabId = session.primaryTabId
            meta.depth = depth
            meta.source = source || meta.source
            meta.updatedAt = now
            if (url) meta.url = url
            session.tabs.set(childId, meta)

            if (isPendingNavigationUrl(url) || !session.scope) continue
            if (!isUrlInScope(url, session.scope)) {
                session.tabs.delete(childId)
                continue
            }
            admitted = (await this._activateRelatedTab(session, meta, url)) || admitted
        }
        return admitted
    }

    async observeTabUpdated(tabId, changeInfo = {}, tab = {}) {
        const normalized = normalizeTabId(tabId)
        if (normalized === null) return false
        const url = changeInfo?.url || tab?.url || null
        if (!url || isPendingNavigationUrl(url)) return false

        let tracked = false
        for (const session of this.sessions.values()) {
            const meta = session.tabs.get(normalized)
            if (!meta || normalized === session.primaryTabId) continue
            meta.url = url
            meta.updatedAt = Date.now()

            if (!isUrlInScope(url, session.scope)) {
                if (meta.state === 'active') {
                    this._releaseTabAndDescendants(session, meta, 'out_of_scope_navigation')
                } else {
                    session.tabs.delete(normalized)
                }
                continue
            }
            if (meta.state === 'pending') {
                tracked = (await this._activateRelatedTab(session, meta, url)) || tracked
            } else {
                tracked = true
            }
        }
        return tracked
    }

    observeTabRemoved(tabId) {
        const normalized = normalizeTabId(tabId)
        if (normalized === null) return false
        let removed = false
        for (const [engineId, session] of [...this.sessions.entries()]) {
            if (session.primaryTabId === normalized) {
                this.unregisterSession(engineId, 'primary_tab_closed')
                removed = true
                continue
            }
            const meta = session.tabs.get(normalized)
            if (!meta) continue
            const descendants = [...session.tabs.values()]
                .filter((candidate) => candidate.tabId !== normalized && this._isDescendantOf(session, candidate, normalized))
                .sort((left, right) => right.depth - left.depth)
            for (const descendant of descendants) {
                this._releaseRelatedTab(session, descendant, 'ancestor_tab_closed')
            }
            this._releaseRelatedTab(session, meta, 'tab_closed')
            removed = true
        }
        return removed
    }

    _isDescendantOf(session, meta, ancestorTabId) {
        let parentId = normalizeTabId(meta?.parentTabId)
        const seen = new Set()
        while (parentId !== null && !seen.has(parentId)) {
            if (parentId === ancestorTabId) return true
            seen.add(parentId)
            parentId = normalizeTabId(session.tabs.get(parentId)?.parentTabId)
        }
        return false
    }

    async _activateRelatedTab(session, meta, url) {
        if (!session || !meta || meta.state === 'active') return meta?.state === 'active'
        meta.state = 'active'
        meta.url = url || meta.url || null
        meta.updatedAt = Date.now()
        session.updatedAt = meta.updatedAt
        try {
            await session.onEnroll?.(cloneMeta(meta))
            return true
        } catch (_) {
            session.tabs.delete(meta.tabId)
            return false
        }
    }

    _releaseRelatedTab(session, meta, reason) {
        if (!session || !meta) return false
        session.tabs.delete(meta.tabId)
        if (meta.state === 'active') this._notifyRelease(session, meta, reason)
        return true
    }

    _releaseTabAndDescendants(session, meta, reason) {
        const descendants = [...session.tabs.values()]
            .filter((candidate) => candidate.tabId !== meta.tabId && this._isDescendantOf(session, candidate, meta.tabId))
            .sort((left, right) => right.depth - left.depth)
        for (const descendant of descendants) {
            this._releaseRelatedTab(session, descendant, 'ancestor_out_of_scope')
        }
        return this._releaseRelatedTab(session, meta, reason)
    }

    _notifyRelease(session, meta, reason) {
        const payload = cloneMeta({
            ...meta,
            state: 'released',
            reason,
            updatedAt: Date.now()
        })
        try {
            Promise.resolve(session.onRelease?.(payload)).catch(() => { })
        } catch (_) { }
    }
}

export const __scopedTabSessionTestHooks = {
    buildScope,
    isUrlInScope,
    normalizeHttpUrl,
    isPendingNavigationUrl,
    DEFAULT_MAX_RELATED_TABS,
    DEFAULT_MAX_DEPTH
}

export default ScopedTabSessionCoordinator
