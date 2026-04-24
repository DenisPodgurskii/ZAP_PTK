/* Author: Denis Podgurskii */
'use strict'

import "./ptk/packages/browser-polyfill/browser-polyfill.min.js"

import defaultSettings from "./ptk/settings.default.js"
import { ptk_settings } from "./ptk/background/settings.js"
import { ptk_proxy } from "./ptk/background/proxy.js"
import { ptk_dashboard } from "./ptk/background/dashboard.js"
import { ptk_dast } from "./ptk/background/dast.js"
import { ptk_request_manager } from "./ptk/background/rbuilder.js"
import { ptk_decoder_manager } from "./ptk/background/decoder.js"
import { ptk_sca } from "./ptk/background/sca.js"
import { ptk_session } from "./ptk/background/session.js"
import { ptk_recorder } from "./ptk/background/recorder.js"
import { ptk_ruleManager } from "./ptk/background/utils.js"
import { ptk_portscanner } from "./ptk/background/portscanner.js"
import { ptk_jwt } from "./ptk/background/jwt.js"
import { ptk_iast } from "./ptk/background/iast.js"
import { ptk_sast } from "./ptk/background/sast.js"
import { ptk_automation } from "./ptk/background/automation.js"
import { loadDevLocalConfig } from "./ptk/common/devLocalConfig.js"
import { initializePortalRuntimeConfig } from "./ptk/common/portalConfig.js"
import {
    armZapStartupPending,
    ensureZapStartupState,
    getZapStartupSnapshot,
    logZapLifecycle
} from "./ptk/common/zapLifecycle.js"

const worker = self
worker.isFirefox = browser.runtime.getBrowserInfo ? true : false
ensureZapStartupState(worker)
logZapLifecycle('background.module.evaluated', {
    isFirefox: worker.isFirefox,
    manifestVersion: browser?.runtime?.getManifest?.()?.manifest_version || null
})

browser.runtime.onStartup.addListener(() => {
    const snapshot = armZapStartupPending(worker, { reason: 'runtime.onStartup' })

    logZapLifecycle('runtime.onStartup', {
        isFirefox: worker.isFirefox,
        ...snapshot
    })

    worker.ptk_app?.automation?.zap?.transport?.handleStartupGateOpened?.('runtime.onStartup')
})

export class ptk_app {
    constructor(settings) {
        this.settings = new ptk_settings(settings)
        this.updated = false
        this._pendingUpdate = false
        this._bootstrapped = false

        this.proxy = new ptk_proxy(this.settings.proxy)
        this.request_manager = new ptk_request_manager(this.settings.rbuilder)
        ptk_ruleManager.resetSession()
        this.dast = new ptk_dast(this.settings.rattacker)
        this.rattacker = this.dast
        this.decoder_manager = new ptk_decoder_manager()
        this.sca = new ptk_sca()
        this.session = new ptk_session()
        this.dashboard = new ptk_dashboard()
        this.portscanner = new ptk_portscanner()
        this.jwt = new ptk_jwt()
        this.iast = new ptk_iast()
        this.sast = new ptk_sast()
        this.automation = new ptk_automation()
        this.automation.init(this)
        this.recorder = new ptk_recorder(this.settings.recorder)
        this.recorder.addMessageListeners()

        this.onMessage = this.onMessage.bind(this)
        this.addMessageListeners()
        this.ready = this.bootstrap()
    }

    async markUpdated() {
        this.updated = true
        this._pendingUpdate = true
        if (this._bootstrapped) {
            await this.applyPendingLifecycleFlags()
        }
        return true
    }

    async applyPendingLifecycleFlags() {
        if (!this._pendingUpdate) return false
        this.settings.release_note.show = true
        this._pendingUpdate = false
        await browser.storage.local.set({ "pentestkit8_settings": this.settings.toStorageObject() })
        return true
    }

    async bootstrap() {
        const bootstrapStartedAt = Date.now()
        logZapLifecycle('app.bootstrap.start', {
            isFirefox: worker.isFirefox,
            startup: getZapStartupSnapshot(worker)
        })
        await initializePortalRuntimeConfig()
        const devLocal = await loadDevLocalConfig()
        const devAutomationDefaults = devLocal?.automationEnabled === true
            ? {
                automation: {
                    enable: true
                }
            }
            : null
        if (devAutomationDefaults) {
            this.settings.mergeSettings(devAutomationDefaults)
        }

        const result = await browser.storage.local.get('pentestkit8_settings')
        if (result.pentestkit8_settings) {
            this.settings.mergeSettings(result.pentestkit8_settings)
        } else {
            await this.settings.resetSettings()
            if (devAutomationDefaults) {
                this.settings.mergeSettings(devAutomationDefaults)
                await browser.storage.local.set({ "pentestkit8_settings": this.settings.toStorageObject() })
            }
        }

        await this.applyPendingLifecycleFlags()
        this.settings.markReady()
        this._bootstrapped = true

        if (this.proxy) {
            this.proxy.maxTabsCount = this.settings.proxy.max_tabs
            this.proxy.maxRequestsPerTab = this.settings.proxy.max_requests_per_tab
        }
        const startupAfterBootstrap = getZapStartupSnapshot(worker)
        logZapLifecycle('app.bootstrap.end', {
            isFirefox: worker.isFirefox,
            startup: startupAfterBootstrap,
            elapsedMs: Date.now() - bootstrapStartedAt
        })
        if (startupAfterBootstrap.pending === true) {
            this.automation?.zap?.transport?.handleStartupGateOpened?.('app.bootstrap.end')
        }
        return this
    }

    addMessageListeners() {
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    async ensureEngine(name) {
        await this.ready
        return this[name] || null
    }

    async ensureEngines(names = []) {
        await this.ready
        return (Array.isArray(names) ? names : [names]).map((name) => this[name] || null)
    }

    onMessage(message, sender, sendResponse) {
        if (message?.channel === "ptk_content2background_zap" && message?.type === "zap_callback_url") {
            return this.ready.then(() => {
                const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
                const frameId = Number.isInteger(sender?.frameId) ? sender.frameId : 0
                const url = typeof message.url === 'string'
                    ? message.url
                    : (typeof sender?.url === 'string' ? sender.url : '')
                const processed = this.automation?.zap?.transport?.processContentObservedZapUrl?.({
                    tabId,
                    frameId,
                    url
                })
                return { ok: processed === true }
            })
        }

        if (message?.channel === "ptk_content2background_runtime" && message?.type === "content_bootstrap_hello") {
            return Promise.resolve(
                this.automation?.handleContentBootstrapHello?.(message, sender)
            ).then((response) => response || { mode: 'pending', script: 'none' })
        }

        if (message?.channel != "ptk_popup2background_app") {
            return undefined
        }

        return this.ready.then(() => {
            if (message.type == "on_updated_settings") {
                if (this.proxy) {
                    this.proxy.maxTabsCount = this.settings.proxy.max_tabs
                    this.proxy.maxRequestsPerTab = this.settings.proxy.max_requests_per_tab
                }
                if (this.dast) {
                    this.dast.loadProModules()
                }
                return true
            }

            if (message.type == "reloadptk") {
                browser.runtime.reload()
                return true
            }

            if (message.type == "history") {
                const route = message.route === "rattacker" ? "dast" : message.route
                this.settings.updateSettings("history", { route, hash: message.hash })
                return true
            }

            if (message.type == "release_note") {
                return { show: this.settings.release_note.show }
            }

            if (message.type == "release_note_read") {
                this.settings.updateSettings("release_note", { show: false })
                return { ok: true }
            }

            if (message.type == "ping") {
                return "pong"
            }

            return undefined
        })
    }
}

browser.runtime.onInstalled.addListener(async (details) => {
    const startupSnapshot = armZapStartupPending(worker, { reason: 'runtime.onInstalled' })
    logZapLifecycle('runtime.onInstalled', {
        isFirefox: worker.isFirefox,
        reason: details?.reason || null,
        previousVersion: details?.previousVersion || null,
        startup: startupSnapshot
    })
    worker.ptk_app?.automation?.zap?.transport?.handleStartupGateOpened?.('runtime.onInstalled')
    if (details.reason == 'update') {
        if (worker.ptk_app) {
            return worker.ptk_app.markUpdated()
        } else {
            worker.__PTK_APP_UPDATED__ = true
        }
    }
})

worker.ptk_app = new ptk_app(JSON.parse(JSON.stringify(defaultSettings)))
if (worker.__PTK_APP_UPDATED__) {
    worker.ptk_app.markUpdated().catch(() => {})
    delete worker.__PTK_APP_UPDATED__
}
