/* Author: Denis Podgurskii */

import { ptk_utils } from "./utils.js"

export class ptk_settings {
    constructor(settings) {
        this.default = settings
        this._secretProvider = null
        this.reset()
        this._ready = false
        this._readyPromise = null
        this._readyResolve = null
        this.addMessageListeners()
    }

    reset() {
        for (const key of Object.keys(this)) {
            if (key === 'default' || key.startsWith('_')) continue
            delete this[key]
        }
        Object.assign(this, JSON.parse(JSON.stringify(this.default || {})))
        this._attachSecretAccessor()
    }

    attachSecretProvider(provider) {
        this._secretProvider = provider || null
        this._attachSecretAccessor()
    }

    _attachSecretAccessor() {
        if (!this.profile || typeof this.profile !== 'object') this.profile = {}
        if (!this._secretProvider) return
        Object.defineProperty(this.profile, 'api_key', {
            configurable: true,
            enumerable: false,
            get: () => this._secretProvider?.getTokenSync?.() || ''
        })
    }

    _isSecretPath(path) {
        return String(path || '').trim().toLowerCase() === 'profile.api_key'
    }

    // Get a clean copy of settings for storage (excludes internal properties)
    toStorageObject() {
        const result = {}
        for (const key in this) {
            // Skip internal properties and methods
            if (key === 'default' || key.startsWith('_') || typeof this[key] === 'function') continue
            result[key] = JSON.parse(JSON.stringify(this[key]))
        }
        return result
    }

    // Call this after mergeSettings to mark settings as ready
    markReady() {
        this._ready = true
        if (this._readyResolve) {
            this._readyResolve()
        }
    }

    // Wait for settings to be fully loaded from storage
    waitForReady() {
        if (this._ready) return Promise.resolve()
        if (!this._readyPromise) {
            this._readyPromise = new Promise(resolve => {
                this._readyResolve = resolve
            })
        }
        return this._readyPromise
    }

    /* Listeners */
    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    onMessage(message, sender, sendResponse) {
        if (message?.channel !== "ptk_popup2background_settings") return undefined
        if (!ptk_utils.isTrustedExtensionPageSender(sender)) {
            return Promise.resolve({ result: false, error: 'untrusted_extension_sender' })
        }
        if (this["msg_" + message.type]) return this["msg_" + message.type](message)
        return Promise.resolve({ result: false })
    }

    msg_update_settings(message) {
        if (this._isSecretPath(message?.path)) {
            return Promise.resolve({ success: false, error: 'secret_path_not_allowed' })
        }
        return this.updateSettings(message.path, message.value).then(function () {
            return Promise.resolve({ settings: this.toStorageObject() })
        }.bind(this))
    }

    msg_reset_settings(message) {
        return this.resetSettings().then(function () {
            return Promise.resolve({ settings: this.toStorageObject() })
        }.bind(this))
    }

    msg_get_settings(message) {
        return this.getSettings(message.path)
    }

    /* End Listeners */


    async updateSettings(path, value) {
        if (this._isSecretPath(path)) throw new Error('secret_path_not_allowed')
        ptk_utils.jsonSetValueByPath(this, path, value)
        return browser.storage.local.set({ "pentestkit8_settings": this.toStorageObject() })
    }

    async getSettings(path) {
        // Wait for settings to be loaded from storage before returning
        await this.waitForReady()
        if (this._isSecretPath(path)) return undefined
        let result = this.toStorageObject()
        if (path) result = ptk_utils.jsonGetValueByPath(this, path)
        if (result && typeof result === 'object') return JSON.parse(JSON.stringify(result))
        return result
    }

    async resetSettings() {
        this.reset()
        return browser.storage.local.set({ "pentestkit8_settings": this.toStorageObject() })
    }

    mergeSettings(source) {
        if (!source) return this
        const legacyMacroFormat = source?.macro?.format
        const hasExportFormat = Object.prototype.hasOwnProperty.call(source?.macro || {}, 'export_format')
        const supportedMacroFormats = new Set([
            'ptk-flow', 'xml', 'zest', 'side', 'chrome-recorder',
            'playwright', 'puppeteer', 'selenium-webdriver', 'cypress'
        ])
        if (!hasExportFormat && supportedMacroFormats.has(legacyMacroFormat) && this.macro) {
            this.macro.export_format = legacyMacroFormat
        }
        const result = this.deepMerge(this, source)
        this._attachSecretAccessor()
        return result
    }

    deepMerge(target, source) {
        if (!source) return target
        for (const key in source) {
            // Skip 'default' key - it contains saved defaults and would cause reference issues
            // Skip keys starting with '_' - they are internal state
            if (key === 'default' || key.startsWith('_')) continue

            if (target.hasOwnProperty(key)) {
                if (typeof (source[key]) === 'object' && source[key] !== null) {
                    this.deepMerge(target[key], source[key])
                } else {
                    Object.assign(target, { [key]: source[key] })
                }
            }
        }
        return target
    }

}
