/* Author: Denis Podgurskii */
import { ptk_utils, ptk_storage } from "../background/utils.js"

const worker = self

export class ptk_session {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_cookies"
        this._changingCookie = false
        this._updateTimers = new Map()
        this._storageCacheTime = 0
        this.addMessageListeners()
        this.addListiners()
        this.init()
    }

    async init() {
        this.storage = await ptk_storage.getItem(this.storageKey)
        if (!this.storage.blocked) {
            this.storage.blocked = []
        }
        if (!this.storage.readonly) {
            this.storage.readonly = []
        }
        await ptk_storage.setItem(this.storageKey, this.storage)
        this._storageCacheTime = Date.now()
        return this.storage
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }


    onMessage(message, sender, sendResponse) {
        if (message?.channel !== "ptk_popup2background_session") return undefined
        if (!ptk_utils.isTrustedExtensionPageSender(sender)) {
            return Promise.resolve({ result: false, error: 'untrusted_extension_sender' })
        }
        if (this["msg_" + message.type]) return this["msg_" + message.type](message)
        return Promise.resolve({ result: false })
    }

    addListiners() {

        this.onChanged = this.onChanged.bind(this)
        browser.cookies.onChanged.addListener(this.onChanged)

        this.onUpdated = this.onUpdated.bind(this)
        browser.tabs.onUpdated.addListener(this.onUpdated)
    }

    /* Fix 4: Debounce per-tab so rapid 'complete' events collapse into one call */
    onUpdated(tabId, info, tab) {
        if (info.status == 'complete') {
            clearTimeout(this._updateTimers.get(tabId))
            this._updateTimers.set(tabId, setTimeout(() => {
                this._updateTimers.delete(tabId)
                this.manageCookies(tabId, tab.url)
            }, 250))
        }
    }

    /* Fix 5: Cache storage reads — only refresh every 2 s for high-frequency callers */
    async _getStorageCached() {
        const now = Date.now()
        if (!this._storageCacheTime || now - this._storageCacheTime > 2000) {
            this.storage = await ptk_storage.getItem(this.storageKey)
            this._storageCacheTime = now
        }
        return this.storage
    }

    /* Invalidate cache so next _getStorageCached() does a fresh read */
    _invalidateStorageCache() {
        this._storageCacheTime = 0
    }

    /* Fix 3: Build O(1) lookup structures for blocked/readonly lists */
    _buildLookups(storage) {
        const blockedSet = new Set()
        for (const x of (storage.blocked || [])) {
            blockedSet.add(x.domain + '|' + x.name)
        }
        const readonlyMap = new Map()
        for (const r of (storage.readonly || [])) {
            readonlyMap.set(r.domain + '|' + r.name, r)
        }
        return { blockedSet, readonlyMap }
    }

    /* Fix 2: Re-entrancy guard prevents onChanged → removeCookie/set → onChanged loop */
    async onChanged(changeInfo) {
        if (this._changingCookie) return

        this.storage = await this._getStorageCached()
        const key = changeInfo.cookie.domain + '|' + changeInfo.cookie.name
        const { blockedSet, readonlyMap } = this._buildLookups(this.storage)

        this._changingCookie = true
        try {
            if (!changeInfo.removed && blockedSet.has(key)) {
                await this.removeCookie(changeInfo.cookie)
            }

            const locked = readonlyMap.get(key)
            if (locked && !changeInfo.removed) {
                if (!this.matchCookie(changeInfo.cookie, locked)) {
                    await this.removeCookie(changeInfo.cookie)
                    let cookie = this.buildCookie(locked)
                    await browser.cookies.set(cookie)
                }
            }
        } finally {
            this._changingCookie = false
        }
    }

    async manageCookies(tabId, url) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        this._storageCacheTime = Date.now()

        let cookies = await this.getAllCookiesByTab(tabId)
        if (!cookies){
            cookies = await this.getAllCookies(url)
        }

        const { blockedSet, readonlyMap } = this._buildLookups(this.storage)

        this._changingCookie = true
        try {
            for (const cookie of cookies) {
                const key = cookie.domain + '|' + cookie.name

                if (blockedSet.has(key)) {
                    this.removeCookie(cookie)
                    continue
                }

                const locked = readonlyMap.get(key)
                if (locked) {
                    let readonlyCookie = this.buildCookie(locked)
                    this.removeCookie(cookie).then(() => browser.cookies.set(readonlyCookie))
                }
            }
        } finally {
            this._changingCookie = false
        }
    }

    async removeCookie(cookie) {
        let url = this.buildCookieUrl(cookie)
        return browser.cookies.remove({
            'url': url,
            'name': cookie.name,
            'storeId': cookie.storeId
        })
    }

    matchCookie(s, t) {
        if (s.value != t.value) return false
        if (s.httpOnly != t.httpOnly) return false
        if (s.path != t.path) return false
        if (s.sameSite != t.sameSite) return false
        if (s.secure != t.secure) return false
        return true
    }

    buildCookie(values) {
        let cookie = {
            httpOnly: values.httpOnly,
            name: values.name,
            path: values.path,
            sameSite: values.sameSite,
            secure: values.secure,
            storeId: values.storeId,
            url: this.buildCookieUrl(Object.assign({}, values)),
            value: values.value
        }
        if (!values.hostOnly)
            cookie['domain'] = values.domain
        if (!values.session)
            cookie['expirationDate'] = values.expirationDate
        return cookie
    }

    buildCookieUrl(cookie) {
        if (!cookie.secure && worker.ptk_app.proxy?.getDashboardTab())
            cookie.secure = worker.ptk_app.proxy.getDashboardTab().url.indexOf("https://") === 0
        if (cookie.domain.substr(0, 1) === '.')
            cookie.domain = cookie.domain.substring(1)
        return "http" + ((cookie.secure) ? "s" : "") + "://" + cookie.domain + cookie.path
    }

    /* Fix 1: O(n) Set-based dedup instead of O(n^3) JSON.stringify dedup */
    _dedupCookies(cookies) {
        const seen = new Set()
        const result = []
        for (const c of cookies) {
            const key = c.domain + '|' + c.name + '|' + c.path + '|' + c.value
            if (!seen.has(key)) {
                seen.add(key)
                result.push(c)
            }
        }
        return result.sort((a, b) => a.name.localeCompare(b.name))
    }

    async getAllCookies(url) {
        let promises = []
        promises.push(browser.cookies.getAll({ 'url': url }))

        return Promise.all(promises).then((cookie) => {
            let merged = [].concat.apply([], cookie)
            return this._dedupCookies(merged)
        })
    }

    async getAllCookiesByTab(tabId) {
        let promises = []
        let tab = worker.ptk_app.proxy.getTab(tabId)
        return tab?.analyze().then((result) => {
            for (let i = 0; i < result.urls.length; i++) {
                promises.push(browser.cookies.getAll({ 'url': result.urls[i] }))
            }
            return Promise.all(promises).then((cookie) => {
                let merged = [].concat.apply([], cookie)
                return this._dedupCookies(merged)
            })
        })

    }


    async msg_init(message) {
        let activeTab = worker.ptk_app.proxy.getDashboardTab()
        let cookies = await this.getAllCookiesByTab(activeTab.tabId)
        this.storage = await this.init()
        return Promise.resolve(Object.assign({}, activeTab, { cookies: cookies, storage: this.storage }))
    }


    async msg_remove_all(message) {
        let activeTab = worker.ptk_app.proxy.getDashboardTab()
        let cookies = await this.getAllCookiesByTab(activeTab.tabId)
        for (var i = 0; i < cookies.length; i++) {
            let cookie = cookies[i]
            this.removeCookie(cookie)
        }
        return Promise.resolve(Object.assign({}, activeTab, { cookies: cookies }))

    }

    async msg_remove_one(message) {
        let activeTab = worker.ptk_app.proxy.getDashboardTab()
        let cookies = await this.getAllCookiesByTab(activeTab.tabId)
        let cookie = cookies[message.index]

        this.removeCookie(cookie)

        return Promise.resolve(Object.assign({}, activeTab, { cookies: cookies }))
    }

    //Export Import
    async msg_export(message) {
        let activeTab = worker.ptk_app.proxy.getDashboardTab()
        let cookies = await this.getAllCookiesByTab(activeTab.tabId)
        return Promise.resolve(Object.assign({}, { cookie: cookies }))
    }

    async msg_import(message) {
        let cookies = message.cookies
        cookies.forEach(cookie => {
            let c = this.buildCookie(cookie)
            browser.cookies.set(c)
        })
        return Promise.resolve(Object.assign({}, { cookie: cookies }))
    }

    //Block
    async msg_block_one(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        this._storageCacheTime = Date.now()
        let activeTab = worker.ptk_app.proxy.getDashboardTab()
        let cookies = await this.getAllCookiesByTab(activeTab.tabId)
        let cookie = cookies[message.index]

        if (!this.storage.blocked) this.storage.blocked = []

        this.storage.blocked.push(cookie)
        ptk_storage.setItem(this.storageKey, this.storage)
        this._invalidateStorageCache()
        this.removeCookie(cookie)

        return Promise.resolve(Object.assign({}, activeTab, { cookies: cookies }))

    }

    async msg_get_blocked_cookies(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        return Promise.resolve(Object.assign({}, { blockedCookies: this.storage }))
    }

    async msg_remove_blocked_rule(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        if (!this.storage.blocked) this.storage.blocked = []
        this.storage.blocked.splice(message.index, 1)
        ptk_storage.setItem(this.storageKey, this.storage)
        this._invalidateStorageCache()
        return Promise.resolve(Object.assign({}, activeTab, { blockedCookies: this.storage }))
    }

    async msg_remove_all_blocked_rules(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        this.storage.blocked = []
        ptk_storage.setItem(this.storageKey, this.storage)
        this._invalidateStorageCache()
        return Promise.resolve(Object.assign({}, activeTab, { blockedCookies: this.storage }))
    }

    //Readonly

    async msg_readonly_one(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        this._storageCacheTime = Date.now()
        let activeTab = worker.ptk_app.proxy.getDashboardTab()
        let cookies = await this.getAllCookiesByTab(activeTab.tabId)
        let cookie = cookies[message.index]

        if (!this.storage.readonly) this.storage.readonly = []

        this.storage.readonly.push(cookie)
        ptk_storage.setItem(this.storageKey, this.storage)
        this._invalidateStorageCache()

        return Promise.resolve(Object.assign({}, activeTab, { cookies: cookies }))
    }

    async msg_remove_readonly_rule(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        if (!this.storage.readonly) this.storage.readonly = []
        this.storage.readonly.splice(message.index, 1)
        ptk_storage.setItem(this.storageKey, this.storage)
        this._invalidateStorageCache()
        return Promise.resolve(Object.assign({}, activeTab, { readonlyCookies: this.storage }))
    }

    async msg_remove_all_readonly_rules(message) {
        this.storage = await ptk_storage.getItem(this.storageKey)
        this.storage.readonly = []
        ptk_storage.setItem(this.storageKey, this.storage)
        this._invalidateStorageCache()
        return Promise.resolve(Object.assign({}, activeTab, { readonlyCookies: this.storage }))
    }

    //Save/update

    async msg_save_one(message) {
        let activeTab = worker.ptk_app.proxy.getDashboardTab()
        let cookies = await this.getAllCookiesByTab(activeTab.tabId)
        let cookie = this.buildCookie(message.values)
        await this.removeCookie(message.values)
        browser.cookies.set(cookie)

        return Promise.resolve(Object.assign({}, activeTab, { cookies: cookies }))
    }


}
