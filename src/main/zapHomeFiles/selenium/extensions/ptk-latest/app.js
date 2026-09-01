/* Author: Denis Podgurskii */
'use strict'

import "./ptk/packages/browser-polyfill/browser-polyfill.min.js"

import defaultSettings from "./ptk/settings.default.js"
import { ptk_settings } from "./ptk/background/settings.js"
import { SecretStore } from "./ptk/background/secretStore.js"
import { sensitiveArtifactStorage } from "./ptk/background/sensitiveArtifactStore.js"
import { ptk_proxy } from "./ptk/background/proxy.js"
import { ptk_dashboard } from "./ptk/background/dashboard.js"
import { ptk_dast } from "./ptk/background/dast.js"
import { ptk_request_manager } from "./ptk/background/rbuilder.js"
import { ptk_decoder_manager } from "./ptk/background/decoder.js"
import { ptk_sca } from "./ptk/background/sca.js"
import { ptk_session } from "./ptk/background/session.js"
import { ptk_recorder } from "./ptk/background/recorder.js"
import { ptk_ruleManager, ptk_utils } from "./ptk/background/utils.js"
import { ptk_portscanner } from "./ptk/background/portscanner.js"
import { ptk_jwt } from "./ptk/background/jwt.js"
import { ptk_iast } from "./ptk/background/iast.js"
import { ptk_sast } from "./ptk/background/sast.js"
import { ptk_automation } from "./ptk/background/automation.js"
import { zapBridge } from "./ptk/background/integration/zap/index.js"
import { ScopedTabSessionCoordinator } from "./ptk/background/common/scopedTabSessionCoordinator.js"
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

const ZAP_RUNNER_PATH = '/ptk/internal/zap-runner.html'

function parseExtensionUrl(value) {
    if (typeof value !== 'string' || !value) return null
    try {
        const parsed = new URL(value)
        if (parsed.protocol !== 'chrome-extension:' && parsed.protocol !== 'moz-extension:') {
            return null
        }
        if (parsed.pathname !== ZAP_RUNNER_PATH || parsed.search || parsed.hash) {
            return null
        }
        return parsed
    } catch (_) {
        return null
    }
}

function zapRunnerSenderMetadata(sender = {}) {
    const senderUrl = parseExtensionUrl(sender?.url)
    const tabUrl = parseExtensionUrl(sender?.tab?.url)
    return {
        senderIdMatches: Boolean(browser?.runtime?.id && sender?.id === browser.runtime.id),
        frameId: Number.isInteger(sender?.frameId) ? sender.frameId : null,
        senderProtocol: senderUrl?.protocol || null,
        senderPath: senderUrl?.pathname || null,
        hasTab: Boolean(sender?.tab),
        tabId: Number.isInteger(sender?.tab?.id) ? sender.tab.id : null,
        tabProtocol: tabUrl?.protocol || null,
        tabPath: tabUrl?.pathname || null,
        tabUrlAvailable: typeof sender?.tab?.url === 'string'
    }
}

function isTrustedZapRunnerSender(sender = {}) {
    if (!browser?.runtime?.id || sender?.id !== browser.runtime.id) return false
    if (sender?.frameId !== 0) return false

    const parsed = parseExtensionUrl(sender?.url)
    if (!parsed) return false
    if (parsed.protocol === 'chrome-extension:' && parsed.hostname !== browser.runtime.id) {
        return false
    }

    if (typeof sender?.tab?.url === 'string' && sender.tab.url) {
        const tabUrl = parseExtensionUrl(sender.tab.url)
        if (!tabUrl) return false
        if (tabUrl.protocol !== parsed.protocol || tabUrl.hostname !== parsed.hostname) {
            return false
        }
    }

    return true
}

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
        this.secretStore = new SecretStore()
        this.scopedTabSessions = new ScopedTabSessionCoordinator({ browserApi: browser })
        this.updated = false
        this._pendingUpdate = false
        this._bootstrapped = false
        this.devLocalConfig = {}

        this.proxy = new ptk_proxy(this.settings.proxy)
        worker.ptk_app = this
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
        this.dast.setScopedTabCoordinator?.(this.scopedTabSessions)
        this.sca.setScopedTabCoordinator?.(this.scopedTabSessions)
        this.iast.setScopedTabCoordinator?.(this.scopedTabSessions)
        this.sast.setScopedTabCoordinator?.(this.scopedTabSessions)
        this.scopedTabSessions.start()
        this.automation = new ptk_automation()
        this.automation.init(this, { zapBridge })
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
        await sensitiveArtifactStorage.clearExpired().catch(() => {})
        const bootstrapStartedAt = Date.now()
        logZapLifecycle('app.bootstrap.start', {
            isFirefox: worker.isFirefox,
            startup: getZapStartupSnapshot(worker)
        })
        await initializePortalRuntimeConfig()
        const devLocal = await loadDevLocalConfig()
        this.devLocalConfig = devLocal && typeof devLocal === "object" ? devLocal : {}
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
            const persistedSettings = JSON.parse(JSON.stringify(result.pentestkit8_settings))
            const legacyToken = typeof persistedSettings?.profile?.api_key === 'string'
                ? persistedSettings.profile.api_key
                : ''
            if (persistedSettings?.profile) delete persistedSettings.profile.api_key
            this.settings.mergeSettings(persistedSettings)
            await this.secretStore.initialize({ legacyToken })
            this.settings.attachSecretProvider(this.secretStore)
            if (legacyToken) {
                await browser.storage.local.set({ "pentestkit8_settings": this.settings.toStorageObject() })
            }
        } else {
            await this.secretStore.initialize()
            this.settings.attachSecretProvider(this.secretStore)
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

    async broadcastRuntimeProfileRefresh() {
        if (!browser?.tabs?.query || !browser?.tabs?.sendMessage) return false
        const tabs = await browser.tabs.query({})
        await Promise.allSettled((tabs || [])
            .filter((tab) => Number.isInteger(tab?.id))
            .map((tab) => browser.tabs.sendMessage(tab.id, {
                channel: 'ptk_background2content_runtime',
                type: 'refresh_profile'
            })))
        return true
    }

    onMessage(message, sender, sendResponse) {
        if (message?.channel === "ptk_extension_zap_runner") {
            if (!isTrustedZapRunnerSender(sender)) {
                const metadata = zapRunnerSenderMetadata(sender)
                console.warn(
                    '[PTK ZAP] PTK_CONTRACT phase=runner_message_rejected reason=not_top_level_extension_page',
                    metadata
                )
                logZapLifecycle('runner_message_rejected', {
                    reason: 'not_top_level_extension_page',
                    ...metadata
                })
                return Promise.resolve({
                    ok: false,
                    observed: false,
                    reason: 'untrusted_runner_sender',
                    requestId: message.requestId
                })
            }

            if (message?.type === "close_session_status") {
                return this.ready.then(() => {
                    const snapshot = this.automation?.getZapSessionControlSnapshot?.(
                        message.sessionId,
                        message.zapid
                    )
                    return {
                        ...(snapshot || { ok: false, error: 'zap_session_not_found' }),
                        trustedRunner: 'ptk-zap-control-v1',
                        requestId: message.requestId
                    }
                }).catch((error) => ({
                    ok: false,
                    reason: error?.message || String(error),
                    requestId: message.requestId
                }))
            }

            if (message?.type === "close_session_if_idle") {
                return this.ready.then(async () => {
                    const result = await this.automation?.requestZapSessionCloseIfIdle?.(
                        message.sessionId,
                        message.zapid,
                        {
                            closeRequestId: message.closeRequestId,
                            timeoutMs: message.timeoutMs
                        }
                    )
                    return {
                        ...(result || { ok: false, error: 'zap_session_close_unavailable' }),
                        trustedRunner: 'ptk-zap-control-v1',
                        requestId: message.requestId
                    }
                }).catch((error) => ({
                    ok: false,
                    reason: error?.message || String(error),
                    trustedRunner: 'ptk-zap-control-v1',
                    requestId: message.requestId
                }))
            }

            if (message?.type !== "scan_callback_tabs") {
                return Promise.resolve({
                    ok: false,
                    observed: false,
                    reason: 'unknown_runner_message',
                    requestId: message.requestId
                })
            }

            return this.ready.then(async () => {
                const transport = this.automation?.zap?.transport
                const observed = await transport?.scanOpenTabsForDirectCallbackUrls?.('zap.runner')
                return {
                    ok: true,
                    observed: observed === true,
                    requestId: message.requestId
                }
            }).catch((error) => ({
                ok: false,
                observed: false,
                reason: error?.message || String(error),
                requestId: message.requestId
            }))
        }

        if (message?.channel === "ptk_content2background_zap" && message?.type === "zap_callback_url") {
            const tabId = Number.isInteger(sender?.tab?.id) ? sender.tab.id : null
            const frameId = Number.isInteger(sender?.frameId) ? sender.frameId : 0
            const url = typeof message.url === 'string'
                ? message.url
                : (typeof sender?.url === 'string' ? sender.url : '')
            let processed = false
            let callbackError = null
            try {
                processed = this.automation?.zap?.transport?.processContentObservedZapUrl?.({
                    tabId,
                    frameId,
                    url
                }) === true
            } catch (error) {
                callbackError = error?.message || String(error)
            }

            const isBootstrapUrl = this.automation?.zap?.transport?.isBootstrapUrl?.(url) === true
            if (!callbackError && isBootstrapUrl) {
                void this.ready.then(async () => {
                    try {
                        await this.automation?.handleContentBootstrapHello?.({
                            channel: 'ptk_content2background_runtime',
                            type: 'content_bootstrap_hello',
                            url,
                            zapHintUrl: url,
                            reason: 'zap_callback_url'
                        }, sender)
                    } catch (error) {
                        console.warn('[PTK] ZAP callback runtime bootstrap failed:', error?.message || String(error))
                    }
                }).catch((error) => {
                    console.warn('[PTK] ZAP callback readiness wait failed:', error?.message || String(error))
                })
            }

            return Promise.resolve({
                ok: callbackError ? false : (processed === true || isBootstrapUrl),
                callbackProcessed: processed,
                ...(callbackError ? { error: callbackError } : {})
            })
        }

        if (message?.channel === "ptk_content2background_runtime" && message?.type === "content_bootstrap_hello") {
            return Promise.resolve(
                this.automation?.handleContentBootstrapHello?.(message, sender)
            ).then((response) => response || { mode: 'pending', script: 'none' })
        }

        if (message?.channel === "ptk_content2background_runtime" && message?.type === "manual_automation_authorization") {
            return this.ready.then(() => {
                return this.automation?.handleManualAutomationAuthorization?.(message, sender)
                    || { ok: true, allowed: false, reason: 'automation_unavailable' }
            })
        }

        if (message?.channel === "ptk_content2background_runtime" && message?.type === "manual_automation_activation_request") {
            return this.ready.then(() => {
                return this.automation?.handleManualAutomationActivationRequest?.(message, sender)
                    || { ok: true, allowed: false, reason: 'automation_unavailable' }
            })
        }

        if (message?.channel != "ptk_popup2background_app") {
            return undefined
        }

        if (!ptk_utils.isTrustedExtensionPageSender(sender)) {
            return Promise.resolve({ success: false, error: 'untrusted_extension_sender' })
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
                return this.broadcastRuntimeProfileRefresh().then(() => true)
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

            if (message.type == "clear_sensitive_artifacts") {
                if (this.recorder?.mode) {
                    return { success: false, error: 'recording_or_replay_active' }
                }
                return sensitiveArtifactStorage.clearAll().then(async () => {
                    await browser.storage.local.remove([
                        'ptk_jwt',
                        'ptk_rbuilder',
                        'ptk_recorder',
                        'ptk_bugbounty_session_profiles_v1',
                        'ptk_bugbounty_evidence_packages_v1',
                        'ptk_recording',
                        'ptk_recording_items',
                        'ptk_recording_timing',
                        'ptk_recording_log',
                        'ptk_replay',
                        'ptk_replay_items',
                        'ptk_replay_step',
                        'ptk_replay_regex'
                    ])
                    this.jwt.storage = {}
                    this.request_manager.storage = []
                    this.recorder.storage = { savedMacro: '', recording: {} }
                    await this.dast?.sessionProfileStore?.clearAll?.()
                    await this.dast?.evidencePackageStore?.clearAll?.()
                    return { success: true }
                })
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
