/* Author: Denis Podgurskii */

import { ptk_utils } from "./utils.js"

export class ptk_settings {
    constructor(settings) {
        this.default = settings
        this.reset()
        this._ready = false
        this._readyPromise = null
        this._readyResolve = null
        this.addMessageListeners()
    }

    reset() {
        Object.assign(this, this.default)
    }

    // Get a clean copy of settings for storage (excludes internal properties)
    toStorageObject() {
        const result = {}
        for (const key in this) {
            // Skip internal properties and methods
            if (key === 'default' || key.startsWith('_') || typeof this[key] === 'function') continue
            result[key] = this[key]
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

        if (!ptk_utils.isTrustedOrigin(sender))
            return Promise.reject({ success: false, error: 'Error origin value' })

        if (message.channel == "ptk_popup2background_settings") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }
    }

    msg_update_settings(message) {
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
        ptk_utils.jsonSetValueByPath(this, path, value)
        return browser.storage.local.set({ "pentestkit8_settings": this.toStorageObject() })
    }

    async getSettings(path) {
        // Wait for settings to be loaded from storage before returning
        await this.waitForReady()
        let result = this
        if (path) result = ptk_utils.jsonGetValueByPath(this, path)
        return result
    }

    async resetSettings() {
        this.reset()
        return browser.storage.local.set({ "pentestkit8_settings": this.toStorageObject() })
    }

    mergeSettings(source) {
        if (!source) return this
        const result = this.deepMerge(this, source)
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
