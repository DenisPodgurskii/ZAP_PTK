/* Author: Denis Podgurskii */

import { ptk_logger, ptk_notifications, ptk_utils } from "./utils.js"
import { sensitiveArtifactStorage as ptk_storage } from "./sensitiveArtifactStore.js"
import { ptk_exporter } from "./exporter.js"
import { normalizeFlow } from './macro/flow.js'

const worker = self

function createRecorderSessionId() {
    if (globalThis.crypto?.randomUUID) {
        return globalThis.crypto.randomUUID()
    }
    const bytes = new Uint8Array(24)
    globalThis.crypto.getRandomValues(bytes)
    return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
}

function replayItemSummary(item, index) {
    return {
        WindowIndex: Number.isInteger(Number(item?.WindowIndex)) ? Number(item.WindowIndex) : 0,
        EventType: String(item?.EventType || ''),
        EventTypeName: String(item?.EventTypeName || item?.EventType || ''),
        PtkStepId: String(item?.PtkStepId || ''),
        PtkStepType: String(item?.PtkStepType || ''),
        Step: Number.isSafeInteger(Number(item?.Step)) ? Number(item.Step) : index + 1,
        Enable: item?.Enable === 0 ? 0 : 1,
        Optional: item?.Optional === 1 ? 1 : 0
    }
}

const REPLAY_RESULT_STATUSES = new Set(['running', 'completed', 'failed', 'stopped'])
const REPLAY_TERMINAL_STATUSES = new Set(['completed', 'failed', 'stopped'])

function boundedReplayText(value, maxLength = 300) {
    return String(value || '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, maxLength)
}

function normalizeReplayResult(value, sessionId, fallbackTotal = 0) {
    const status = REPLAY_RESULT_STATUSES.has(value?.status) ? value.status : 'failed'
    const totalSteps = Math.max(0, Math.min(10000, Number(value?.totalSteps || fallbackTotal) || 0))
    const completedSteps = Math.max(0, Math.min(totalSteps, Number(value?.completedSteps || 0) || 0))
    const currentStep = Math.max(0, Math.min(totalSteps, Number(value?.currentStep || 0) || 0))
    const error = status === 'failed' ? {
        code: boundedReplayText(value?.error?.code || 'replay_failed', 100),
        message: boundedReplayText(value?.error?.message || 'Replay failed.', 300),
        stepType: boundedReplayText(value?.error?.stepType || '', 80)
    } : null
    return {
        status,
        sessionId,
        currentStepId: boundedReplayText(value?.currentStepId || '', 128),
        currentStep,
        completedSteps,
        totalSteps,
        warnings: Array.isArray(value?.warnings)
            ? value.warnings.slice(0, 50).map((entry) => boundedReplayText(entry, 300))
            : [],
        error,
        updatedAt: Date.now()
    }
}

export class ptk_recorder {
    constructor(settings) {
        this.recorderJS = settings.recorderFile
        this.trackerJS = settings.trackerFile
        this.popupJS = settings.popupFile
        this.replayerJS = settings.replayerFile
        this.setWindowSize = settings.set_window_size
        this.windowHeight = settings.window_height
        this.windowWidth = settings.window_width
        this.pathToIcons = settings.icons
        this.doubleClick = settings.double_click

        this.cleanCookieOnStart = false

        this.storageKey = 'ptk_recorder'
        this.storage = { 'savedMacro': '', 'savedFlow': null, 'savedFormat': 'xml', 'recording': {} }
        this.debuggerTargets = new Set()
        this.lastActiveTabId = null
        this.activeReplayTabId = null
        this.pendingReplayTabs = new Set()
        this.scanOwnedReplay = null
        this.replayResult = null

        this.reset()
    }

    /* Listeners */

    addListiners() {
        this.onCreated = this.onCreated.bind(this)
        browser.tabs.onCreated.addListener(this.onCreated)

        this.onActivated = this.onActivated.bind(this)
        browser.tabs.onActivated.addListener(this.onActivated)

        this.onUpdated = this.onUpdated.bind(this)
        browser.tabs.onUpdated.addListener(this.onUpdated)

        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onBeforeRequest = this.onBeforeRequest.bind(this)
        browser.webRequest.onBeforeRequest.addListener(this.onBeforeRequest, { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["requestBody"].concat(ptk_utils.extraInfoSpec)
        )

        this.onSendHeaders = this.onSendHeaders.bind(this)
        browser.webRequest.onSendHeaders.addListener(this.onSendHeaders, { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["requestHeaders"].concat(ptk_utils.extraInfoSpec)
        )

        this.onHeadersReceived = this.onHeadersReceived.bind(this)
        browser.webRequest.onHeadersReceived.addListener(this.onHeadersReceived, { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )

        this.onBeforeRedirect = this.onBeforeRedirect.bind(this)
        browser.webRequest.onBeforeRedirect.addListener(this.onBeforeRedirect, { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(this.onCompleted, { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )

    }

    removeListiners() {
        browser.tabs.onCreated.removeListener(this.onCreated)
        browser.tabs.onActivated.removeListener(this.onActivated)
        browser.tabs.onUpdated.removeListener(this.onUpdated)
        browser.tabs.onRemoved.removeListener(this.onRemoved)

        browser.webRequest.onBeforeRequest.removeListener(this.onBeforeRequest)
        browser.webRequest.onSendHeaders.removeListener(this.onSendHeaders)
        browser.webRequest.onHeadersReceived.removeListener(this.onHeadersReceived)
        browser.webRequest.onBeforeRedirect.removeListener(this.onBeforeRedirect)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
    }

    onCreated(tab) {
        if (this.mode == null) return
        if (this.mode === 'replay' && this.scanOwnedReplay) {
            if (Number.isInteger(tab?.id) && this.isTracking(tab?.openerTabId)) {
                this.pendingReplayTabs.add(tab.id)
            }
            return
        }
        this.tabs.push(tab.id)
    }

    onActivated(info) {
        if (this.mode !== "recording") return
        if (this.openerWinId && info.windowId !== this.openerWinId) return
        if (!this.isTracking(info.tabId)) return
        if (this.lastActiveTabId === info.tabId) return

        this.lastActiveTabId = info.tabId

        browser.tabs.get(info.tabId).then((tab) => {
            if (!tab) return
            this.recordSelectWindow(tab)
        }).catch(() => {})
    }

    onUpdated(tabId, info, tab) {

        if (info.status != "complete") return
        if (this.mode === 'replay' && this.scanOwnedReplay && this.pendingReplayTabs.has(tabId)) {
            if (!tab?.url || tab.url === 'about:blank') return
            this.pendingReplayTabs.delete(tabId)
            if (!this.isReplayUrlInScope(tab.url)) return
            if (!this.tabs.includes(tabId)) this.tabs.push(tabId)
        }
        if (!this.isTracking(tabId)) return
        if (this.mode === 'replay' && this.scanOwnedReplay && tab?.url && !this.isReplayUrlInScope(tab.url)) return
        this.injectScriptsForTab(tabId, tab?.url).catch(e => console.warn(e))
    }

    async injectScriptsForTab(tabId, tabUrl) {
        let file = null
        if (this.mode == "recording") file = this.recorderJS
        if (this.mode == "replay") file = this.replayerJS
        if (!file) return

        if (tabUrl != 'about:blank' && this.trackerJS) {
            if (this.cleanCookieOnStart) {
                await this.executeRecorderCode(tabId, `try { localStorage.clear(); sessionStorage.clear(); } catch (e) { }`, true).catch(() => {})
                this.cleanCookieOnStart = false
            }
            const popuJSPath = this.popupJS
            await this.executeRecorderFiles(tabId, [this.trackerJS], false)
            await this.executeRecorderFiles(tabId, [popuJSPath], false).catch(e => e)
            await this.executeRecorderFiles(tabId, [file], true)
            return
        }

        await this.executeRecorderFiles(tabId, [file], true).catch(e => e)
    }

    async executeRecorderFiles(tabId, files, allFrames) {
        const normalizedFiles = (Array.isArray(files) ? files : []).filter(Boolean)
        if (!normalizedFiles.length) return false
        const manifestVersion = Number(browser?.runtime?.getManifest?.()?.manifest_version || 2)
        if (!worker.isFirefox && manifestVersion >= 3 && browser?.scripting?.executeScript) {
            await browser.scripting.executeScript({
                files: normalizedFiles,
                target: { tabId, allFrames: allFrames === true }
            })
            return true
        }
        if (browser?.tabs?.executeScript) {
            const frameIds = await this.recorderFrameIds(tabId, allFrames)
            for (const file of normalizedFiles) {
                for (const frameId of frameIds) {
                    try {
                        await browser.tabs.executeScript(tabId, {
                            file,
                            frameId,
                            matchAboutBlank: true,
                            runAt: 'document_idle'
                        })
                    } catch (error) {
                        if (frameId === 0) throw error
                    }
                }
            }
            return true
        }
        throw new Error('recorder_script_injection_unavailable')
    }

    async executeRecorderCode(tabId, code, allFrames) {
        const manifestVersion = Number(browser?.runtime?.getManifest?.()?.manifest_version || 2)
        if (!worker.isFirefox && manifestVersion >= 3 && browser?.scripting?.executeScript) {
            await browser.scripting.executeScript({
                func: () => { try { localStorage.clear(); sessionStorage.clear(); } catch (e) { } },
                target: { tabId, allFrames: allFrames === true }
            })
            return true
        }
        if (browser?.tabs?.executeScript) {
            const frameIds = await this.recorderFrameIds(tabId, allFrames)
            for (const frameId of frameIds) {
                try {
                    await browser.tabs.executeScript(tabId, {
                        code,
                        frameId,
                        matchAboutBlank: true,
                        runAt: 'document_idle'
                    })
                } catch (error) {
                    if (frameId === 0) throw error
                }
            }
            return true
        }
        throw new Error('recorder_code_injection_unavailable')
    }

    async recorderFrameIds(tabId, allFrames) {
        if (allFrames !== true || !browser?.webNavigation?.getAllFrames) return [0]
        try {
            const frames = await browser.webNavigation.getAllFrames({ tabId })
            const ids = (Array.isArray(frames) ? frames : [])
                .map((frame) => Number(frame?.frameId))
                .filter((frameId) => Number.isInteger(frameId) && frameId >= 0)
            return [...new Set([0, ...ids])]
        } catch (_) {
            return [0]
        }
    }

    onRemoved(tabId, info) {
        if (tabId == this.openerTabId) {
            if (this.mode == "recording") this.stopRecording(info).catch(() => {})
            else if (this.mode == "replay") this.stopReplay(info).catch(() => {})
        }
    }

    onBeforeRequest(request) {
        if (ptk_utils.exclude(request.url) || request.type.match(/(ping)/) || !this.isTracking(request.tabId)) return

        if (this.mode == "recording") {
            try {
                let item = {
                    requestId: request.requestId, type: request.type, request: request, response: {}
                }

                this.recording.recordingRequests.push(item)

                if (worker.isFirefox) {
                    let filter = browser.webRequest.filterResponseData(item.requestId)
                    let decoder = new TextDecoder("utf-8")

                    filter.ondata = (event => {
                        let str = decoder.decode(event.data, { stream: true })
                        filter.write(event.data)
                        filter.disconnect()
                        let r = this.recording.recordingRequests[this.findLastIndex(this.recording.recordingRequests, item.requestId)]
                        r.response.body = str
                        r.response.base64Encoded = false
                    }).bind(this)
                }
            }
            catch (e) { e => ptk_logger(e, "Could not update recording request", "warning") }
        }
    }

    onSendHeaders(request) {
        if (this.isTracking(request.tabId) && this.mode == "recording") {
            let r = this.recording.recordingRequests[this.findLastIndex(this.recording.recordingRequests, request.requestId)]
            if (r) r.requestHeaders = request.requestHeaders
        }
    }

    onHeadersReceived(response) {
        if (!this.isTracking(response.tabId)) return
        if (this.mode == "recording") {
            let r = this.recording.recordingRequests[this.findLastIndex(this.recording.recordingRequests, response.requestId)]
            if (r) {
                r.responseHeaders = response.responseHeaders
                r.response.statusCode = response.statusCode
                r.response.statusLine = response.statusLine
            }
        }
    }

    onBeforeRedirect(response) {
        if (!this.isTracking(response.tabId)) return
        if (this.mode == "recording") {
            let r = this.recording.recordingRequests[this.findLastIndex(this.recording.recordingRequests, response.requestId)]
            if (r) {
                r.redirectUrl = response.redirectUrl
            }
        }
    }

    onCompleted(response) {
        if (!this.isTracking(response.tabId)) return
        if (this.mode == "recording") {
            let r = this.recording.recordingRequests[this.findLastIndex(this.recording.recordingRequests, response.requestId)]
            if (r) {
                r.serverIPAddress = response.ip
            }
        }
    }

    onStart(win, startUrl) {

        this.openerWinId = win.id
        this.openerTabId = win.tabs[0].id
        this.lastActiveTabId = this.openerTabId
        if (this.mode == 'replay') {
            this.activeReplayTabId = this.openerTabId
        }

        browser.windows.update(win.id, { "focused": true })

        if (this.setWindowSize) {
            browser.windows.update(win.id, { "height": parseInt(this.windowHeight), "width": parseInt(this.windowWidth) })
        }

        setTimeout(function () {
            if (!worker.isFirefox && this.mode == 'recording') {
                // Attach debugger for Network only during recording
                this.ensureDebugger(this.openerTabId).then((attached) => {
                    if (attached) {
                        const debugTarget = { tabId: this.openerTabId }
                        chrome.debugger.sendCommand(debugTarget, "Network.setCacheDisabled", { cacheDisabled: true }, () => {
                            if (chrome.runtime.lastError) {
                                // ignore missing tab
                            }
                        })
                        chrome.debugger.sendCommand(debugTarget, "Network.enable", {}, () => {
                            if (chrome.runtime.lastError) {
                                // ignore missing tab
                            }
                        })
                    }
                })
            }

            browser.tabs.update(this.openerTabId, { url: startUrl })

        }.bind(this), 300)
    }

    async startInActiveTab(startUrl) {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true })
        const activeTab = tabs && tabs[0]
        if (!activeTab) {
            throw new Error('No active tab found')
        }
        this.openerWinId = activeTab.windowId
        this.openerTabId = activeTab.id
        this.lastActiveTabId = this.openerTabId
        if (this.mode == 'replay') {
            this.activeReplayTabId = this.openerTabId
        }

        if (!worker.isFirefox && this.mode == 'recording') {
            this.ensureDebugger(this.openerTabId).then((attached) => {
                if (attached) {
                    const debugTarget = { tabId: this.openerTabId }
                    chrome.debugger.sendCommand(debugTarget, "Network.setCacheDisabled", { cacheDisabled: true }, () => {
                        if (chrome.runtime.lastError) {
                            // ignore missing tab
                        }
                    })
                    chrome.debugger.sendCommand(debugTarget, "Network.enable", {}, () => {
                        if (chrome.runtime.lastError) {
                            // ignore missing tab
                        }
                    })
                }
            })
        }

        const skipNavigation = this.mode === 'recording' && this.bootstrap?.skipNavigation === true
        if (skipNavigation) {
            await this.injectScriptsForTab(this.openerTabId, activeTab?.url)
            return
        }

        await browser.tabs.update(this.openerTabId, { url: startUrl })
    }

    async startInTab(tab, startUrl) {
        if (!tab || !Number.isInteger(tab.id)) throw new Error('Invalid replay target tab')
        this.openerWinId = tab.windowId
        this.openerTabId = tab.id
        this.lastActiveTabId = tab.id
        this.activeReplayTabId = tab.id
        await browser.tabs.update(tab.id, { active: true, url: startUrl })
    }

    isReplayUrlInScope(value) {
        if (!this.scanOwnedReplay?.scopeOrigin) return true
        try {
            return new URL(String(value || '')).origin === this.scanOwnedReplay.scopeOrigin
        } catch (_) {
            return false
        }
    }

    async prepareScanOwnedReplay(options, startUrl, items) {
        const requested = options?.scanOwned === true
            || options?.suppressConfirmation === true
            || Number.isInteger(options?.targetTabId)
            || !!options?.scopeOrigin
        if (!requested) return null
        if (options?.scanOwned !== true
            || options?.suppressConfirmation !== true
            || options?.source !== 'dashboard_manage_scans'
            || !Number.isInteger(options?.targetTabId)) {
            throw new Error('invalid_scan_owned_replay_request')
        }
        let scopeUrl
        try {
            scopeUrl = new URL(String(options.scopeOrigin || ''))
        } catch (_) {
            throw new Error('invalid_scan_owned_replay_scope')
        }
        if (!['http:', 'https:'].includes(scopeUrl.protocol) || scopeUrl.origin !== String(options.scopeOrigin || '')) {
            throw new Error('invalid_scan_owned_replay_scope')
        }
        const tab = await browser.tabs.get(options.targetTabId)
        let tabOrigin
        try {
            tabOrigin = new URL(String(tab?.url || '')).origin
        } catch (_) {
            throw new Error('scan_owned_replay_target_out_of_scope')
        }
        if (tabOrigin !== scopeUrl.origin) throw new Error('scan_owned_replay_target_out_of_scope')
        const replayUrls = [startUrl]
        for (const item of Array.isArray(items) ? items : []) {
            const type = String(item?.PtkStepType || item?.EventTypeName || item?.EventType || '').toLowerCase()
            if ((type === 'navigate' || type === 'waitfornavigation' || type === 'waitforurl') && item?.Data) {
                replayUrls.push(item.Data)
            }
        }
        for (const value of replayUrls) {
            let parsed
            try {
                parsed = new URL(String(value || ''))
            } catch (_) {
                throw new Error('scan_owned_replay_invalid_url')
            }
            if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== scopeUrl.origin) {
                throw new Error('scan_owned_replay_url_out_of_scope')
            }
        }
        return { tab, scopeOrigin: scopeUrl.origin, source: options.source }
    }

    async recordSelectWindow(tab) {
        if (!tab) return
        const targetOptions = []
        if (tab.title) {
            targetOptions.push(`title=${tab.title}`)
        }
        if (typeof tab.index === 'number') {
            targetOptions.push(`index=${tab.index}`)
        }
        if (!targetOptions.length) return

        const eventStart = Date.now()
        const item = {
            windowIndex: 0,
            frameInfo: {},
            frameStack: [],
            eventType: 12,
            eventTypeName: "SelectWindow",
            data: targetOptions[0],
            target: targetOptions[0],
            targetOptions: targetOptions,
            eventStart: eventStart,
            props: { title: tab.title, index: tab.index }
        }

        const result = await browser.storage.local.get(["ptk_recording_items", "ptk_recording_log"])
        const items = result.ptk_recording_items || []
        if (items.length > 0) {
            const last = items[items.length - 1]
            if (!last.eventDuration && last.eventStart) {
                last.eventDuration = eventStart - last.eventStart
            }
        }
        items.push(item)

        const log = (result.ptk_recording_log || '') + `Step #${items.length}: SelectWindow<br/>`
        await browser.storage.local.set({
            "ptk_recording_items": items,
            "ptk_recording_log": log
        })
    }

    findLastIndex(obj, requestId) {
        let l = obj.length
        while (l--) {
            if (obj[l].requestId == requestId) return l
        }
        return -1
    }

    onAttach(tabId) {
        this.onEvent = this.onEvent.bind(this)
        chrome.debugger.onEvent.addListener(this.onEvent)
        this.onDetach = this.onDetach.bind(this)
        chrome.debugger.onDetach.addListener(this.onDetach)
    }

    onDetach(source, reason) {
        if (source?.tabId) this.debuggerTargets.delete(source.tabId)
        chrome.debugger.onEvent.removeListener(this.onEvent)
        chrome.debugger.onDetach.removeListener(this.onDetach)
    }

    onEvent(debuggeeId, message, params) {
        let err = browser.runtime.lastError
        if (!this.isTracking(debuggeeId.tabId)) return
        if (!this.recording || !this.recording.requests) return

        if (params?.request?.url?.includes("-extension://")) return
        if (params?.response?.url?.includes("-extension://")) return

        let item = {
            requestId: params.requestId,
            parentId: params.loaderId,
            type: params.type,
            response: {},
            timing: {}
        }
        let reverseIndex = this.findLastIndex(this.recording.requests, item.requestId)

        if (message == "Network.requestWillBeSent") {
            if (params.redirectResponse ||
                !this.recording.requests.some(e => e.requestId === params.requestId)) {
                item.request = params.request
                this.recording.requests.push(item)
            }
        }
        if (message == "Network.loadingFinished" && reverseIndex > -1) {
            chrome.debugger.sendCommand(debuggeeId, "Network.getResponseBody", { "requestId": params.requestId },
                function (response) {
                    if (response?.body) {
                        this.recording.requests[reverseIndex].response.body = response.body
                        this.recording.requests[reverseIndex].response.base64Encoded = response.base64Encoded
                    }
                }.bind(this))
        }
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    onMessage(message, sender) {
        if (message.channel == "ptk_popup2background_recorder") {
            const trustedExtensionPage = ptk_utils.isTrustedExtensionPageSender(sender)
            const trustedContentControl = ptk_utils.isTrustedContentSender(sender)
                && (message.type === 'stop_recording' || message.type === 'stop_replay')
            if (!trustedExtensionPage && !trustedContentControl) {
                return Promise.resolve({ success: false, error: 'untrusted_extension_sender' })
            }
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ success: false })
        }

        if (message.channel == "ptk_content2background_recorder") {
            if (!ptk_utils.isTrustedContentSender(sender)) {
                return Promise.resolve({ success: false, error: 'untrusted_content_sender' })
            }
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message, sender)
            }
            return Promise.resolve({ success: false })
        }
    }

    async msg_init(message) {
        if (this.stopRecordingPromise) await this.stopRecordingPromise
        const storage = await ptk_storage.getItem(this.storageKey) || {}
        this.storage = storage
        if (this.mode !== 'recording') this.recording = storage['recording']
        return Promise.resolve({
            savedMacro: storage['savedMacro'],
            savedFlow: storage['savedFlow'],
            savedFormat: storage['savedFormat'],
            recording: storage['recording']
        })
    }

    msg_save_macro(message) {
        try {
            const nextStorage = {
                ...(this.storage || {}),
                savedMacro: typeof message.macro === 'string' ? message.macro : '',
                savedFlow: message.flow ? normalizeFlow(message.flow) : null,
                savedFormat: typeof message.format === 'string' ? message.format : 'xml'
            }
            return ptk_storage.setItem(this.storageKey, nextStorage).then(() => {
                this.storage = nextStorage
                return { success: true }
            })
        } catch (error) {
            return Promise.resolve({ success: false, error: error?.code || 'invalid_macro_flow' })
        }
    }

    msg_analyse(message) {
        return Promise.resolve(this.analyse())
    }

    msg_cancel_recording(message) {
        this.cancelled = true
        let a = this.tabs.reverse()
        for (let i = 0; i < a.length; i++) {
            browser.tabs.get(a[i]).then(function (tab) {
                if (tab && tab.id) {
                    browser.tabs.remove(tab.id).catch(e => e)
                }
            })
        }
        return Promise.resolve({ success: true })
    }

    async msg_stop_replay(message) {
        if (message?.sessionId && message.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, error: 'stale_replay_session' })
        }
        await this.stopReplay(message)
        return Promise.resolve({ success: true })
    }

    //External access
    async msg_start_recording(message) {
        if (this.mode != null) {
            ptk_notifications.notify("Recording/playback already started", "Stop recording before start a new one");
            return Promise.resolve({ success: false, error: 'recording_or_replay_already_started' })
        }
        await ptk_storage.setItem(this.storageKey, {})
        this.startRecording(message.clean_cookie, message.url, message.bootstrap)
        return Promise.resolve({ success: true })
    }

    //External access
    async msg_stop_recording(message) {
        const bootstrap = this.bootstrap
        await this.stopRecording(message)
        return Promise.resolve({ success: true, bootstrap })
    }

    //External access
    msg_export_recording(message) {
        let exporter = new ptk_exporter(this.recording, message.settings)
        let result = exporter.render()
        return Promise.resolve({ success: true, result: result, bootstrap: this.bootstrap })
    }

    //External access
    msg_reset_recording(message) {
        this.reset()
        ptk_storage.setItem(this.storageKey, {})
        return Promise.resolve({ success: true })
    }

    async msg_replay(message) {
        try {
            return await this.startReplay(
                message.clean_cookie,
                message.url,
                message.events,
                message.validate_regex,
                {
                    overlay: message?.overlay || null,
                    sessionProfile: message?.session_profile || null,
                    targetTabId: Number.isInteger(message?.target_tab_id) ? message.target_tab_id : null,
                    scopeOrigin: message?.scope_origin || '',
                    suppressConfirmation: message?.suppress_confirmation === true,
                    scanOwned: message?.scan_owned === true,
                    source: message?.source || ''
                }
            )
        } catch (error) {
            return { success: false, error: error?.message || 'replay_start_failed' }
        }
    }

    async msg_select_window(message) {
        if (this.mode !== 'replay') return Promise.resolve({ success: false })
        const targets = []
        if (message?.targetOptions && Array.isArray(message.targetOptions)) {
            message.targetOptions.forEach((entry) => {
                if (Array.isArray(entry)) {
                    targets.push(entry[0])
                } else {
                    targets.push(entry)
                }
            })
        }
        if (message?.target) targets.unshift(message.target)
        const uniqTargets = [...new Set(targets.filter(Boolean))]

        const allTabs = await browser.tabs.query({ windowId: this.openerWinId })
        const tabs = this.scanOwnedReplay
            ? allTabs.filter((tab) => this.isReplayUrlInScope(tab?.url))
            : allTabs
        const matchTab = (target) => {
            if (target.startsWith('title=')) {
                const title = target.slice(6)
                return tabs.find(t => t.title === title)
            }
            if (target.startsWith('index=')) {
                const index = Number(target.slice(6))
                return tabs.find(t => t.index === index)
            }
            return null
        }

        for (const target of uniqTargets) {
            const tab = matchTab(target)
            if (tab) {
                await browser.tabs.update(tab.id, { active: true })
                this.activeReplayTabId = tab.id
                return Promise.resolve({ success: true })
            }
        }

        return Promise.resolve({ success: false })
    }

    async msg_get_tab_id(message, sender) {
        return Promise.resolve({
            tabId: sender?.tab?.id ?? null,
            activeReplayTabId: this.activeReplayTabId
        })
    }

    async msg_get_active_replay_tab(message, sender) {
        const tabId = sender?.tab?.id
        if (this.mode !== 'replay' || !this.sessionId || message?.sessionId !== this.sessionId
            || !Number.isInteger(tabId) || !this.isTracking(tabId)) {
            return Promise.resolve({ success: false, error: 'invalid_replay_sender' })
        }
        return Promise.resolve({
            success: true,
            activeReplayTabId: this.activeReplayTabId
        })
    }

    async msg_replay_outcome(message, sender) {
        const tabId = sender?.tab?.id
        const frameId = Number(sender?.frameId)
        if (this.mode !== 'replay' || !this.sessionId || message?.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, error: 'invalid_session' })
        }
        if (!Number.isInteger(tabId) || frameId !== 0 || tabId !== this.openerTabId || !this.isTracking(tabId)) {
            return Promise.resolve({ success: false, error: 'invalid_replay_outcome_sender' })
        }
        if (REPLAY_TERMINAL_STATUSES.has(this.replayResult?.status)) {
            return Promise.resolve({ success: false, error: 'replay_already_terminal', result: this.replayResult })
        }
        const result = normalizeReplayResult(message?.outcome, this.sessionId, this.replay?.replayEvents?.length || 0)
        this.replayResult = result
        await browser.storage.local.set({
            ptk_replay_result: result,
            ptk_replay_last_result: result,
            ...(REPLAY_TERMINAL_STATUSES.has(result.status) ? { ptk_replay_step: -1 } : {})
        })
        if (REPLAY_TERMINAL_STATUSES.has(result.status) && this.scanOwnedReplay) {
            const completedSessionId = this.sessionId
            setTimeout(() => {
                if (this.mode === 'replay' && this.sessionId === completedSessionId) {
                    this.stopReplay({ reason: result.status, preserveResult: true }).catch(() => {})
                }
            }, 250)
        }
        return Promise.resolve({ success: true, result })
    }

    async msg_claim_confirmation(message, sender) {
        const tabId = sender?.tab?.id
        const frameId = Number(sender?.frameId)
        if ((this.mode !== 'recording' && this.mode !== 'replay')
            || !this.sessionId
            || message?.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, show: false, error: 'invalid_session' })
        }
        if (!Number.isInteger(tabId) || frameId !== 0 || !this.isTracking(tabId)) {
            return Promise.resolve({ success: false, show: false, error: 'invalid_confirmation_sender' })
        }
        if (this.confirmationClaimed) {
            return Promise.resolve({ success: true, show: false, mode: this.mode })
        }
        this.confirmationClaimed = true
        await browser.storage.local.remove(['ptk_recording_confirm_required']).catch(() => {})
        return Promise.resolve({ success: true, show: true, mode: this.mode })
    }

    async msg_get_replay_context(message, sender) {
        const tabId = sender?.tab?.id
        if (this.mode !== 'replay' || !this.sessionId || message?.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, error: 'invalid_session' })
        }
        if (!Number.isInteger(tabId) || Number(sender?.frameId) !== 0 || !this.isTracking(tabId)) {
            return Promise.resolve({ success: false, error: 'invalid_replay_tab' })
        }
        return Promise.resolve({
            success: true,
            tabId,
            isOpener: tabId === this.openerTabId,
            activeReplayTabId: this.activeReplayTabId
        })
    }

    async msg_get_replay_payload(message, sender) {
        const tabId = sender?.tab?.id
        const frameId = Number(sender?.frameId)
        if (this.mode !== 'replay' || !this.sessionId || message?.sessionId !== this.sessionId
            || !this.scanOwnedReplay || !Array.isArray(this.replay?.replayEvents)) {
            return Promise.resolve({ success: false, error: 'invalid_scan_owned_replay_session' })
        }
        if (!Number.isInteger(tabId) || !Number.isInteger(frameId) || frameId < 0 || !this.isTracking(tabId)) {
            return Promise.resolve({ success: false, error: 'invalid_replay_sender' })
        }
        const tab = await browser.tabs.get(tabId).catch(() => null)
        if (!tab || !this.isReplayUrlInScope(tab.url)) {
            return Promise.resolve({ success: false, error: 'replay_sender_out_of_scope' })
        }
        return Promise.resolve({
            success: true,
            items: this.replay.replayEvents,
            regex: this.replay.validateRegex || ''
        })
    }

    async msg_get_recording_context(message, sender) {
        const tabId = sender?.tab?.id
        if (this.mode !== 'recording' || !this.sessionId || message?.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, error: 'invalid_session' })
        }
        if (!Number.isInteger(tabId) || Number(sender?.frameId) !== 0 || !this.isTracking(tabId)) {
            return Promise.resolve({ success: false, error: 'invalid_recording_tab' })
        }
        return Promise.resolve({
            success: true,
            tabId,
            windowIndex: tabId === this.openerTabId ? 0 : 1
        })
    }

    async msg_get_frame_identity(message, sender) {
        if (!this.sessionId || message?.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, error: 'invalid_session' })
        }
        if (this.mode !== 'recording' && this.mode !== 'replay') {
            return Promise.resolve({ success: false, error: 'inactive_session' })
        }
        const tabId = sender?.tab?.id
        const frameId = Number(sender?.frameId)
        if (!Number.isInteger(tabId) || !Number.isInteger(frameId) || frameId < 1 || !this.isTracking(tabId)) {
            return Promise.resolve({ success: false, error: 'invalid_frame_sender' })
        }
        return Promise.resolve({
            success: true,
            tabId,
            frameId,
            windowIndex: tabId === this.openerTabId ? 0 : 1
        })
    }

    async msg_register_replay_child(message, sender) {
        const tabId = sender?.tab?.id
        if (this.mode !== 'replay' || !this.sessionId || message?.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, error: 'invalid_session' })
        }
        if (!Number.isInteger(tabId) || Number(sender?.frameId) !== 0 || tabId === this.openerTabId || !this.isTracking(tabId)) {
            return Promise.resolve({ success: false, error: 'invalid_child_tab' })
        }
        return Promise.resolve({ success: true, tabId })
    }

    async _isDirectChildFrame(sender, targetFrameId) {
        const tabId = sender?.tab?.id
        const senderFrameId = Number(sender?.frameId)
        if (!Number.isInteger(tabId) || !Number.isInteger(senderFrameId)) return false
        if (!Number.isInteger(targetFrameId) || targetFrameId < 1) return false
        try {
            const targetFrame = await browser.webNavigation.getFrame({ tabId, frameId: targetFrameId })
            return !!targetFrame && Number(targetFrame.parentFrameId) === senderFrameId
        } catch (_) {
            return false
        }
    }

    _normalizeFrameInfo(value) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) return null
        const normalizeEntry = (entry) => {
            if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
            const result = {
                index: Number.isInteger(entry.index) && entry.index >= 0 ? entry.index : 0
            }
            for (const key of ['name', 'id', 'title', 'src']) {
                result[key] = typeof entry[key] === 'string' ? entry[key].slice(0, 2048) : ''
            }
            return result
        }
        const result = normalizeEntry(value)
        if (!result) return null
        const stack = Array.isArray(value.stack) ? value.stack.slice(0, 16) : [value]
        result.stack = stack.map(normalizeEntry).filter(Boolean)
        return result
    }

    async msg_relay_frame_info(message, sender) {
        if (this.mode !== 'recording' || !this.sessionId || message?.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, error: 'invalid_session' })
        }
        const tabId = sender?.tab?.id
        const targetFrameId = Number(message?.targetFrameId)
        if (!Number.isInteger(tabId) || !this.isTracking(tabId) || !(await this._isDirectChildFrame(sender, targetFrameId))) {
            return Promise.resolve({ success: false, error: 'unrelated_frame' })
        }
        const frameInfo = this._normalizeFrameInfo(message?.frameInfo)
        if (!frameInfo) {
            return Promise.resolve({ success: false, error: 'invalid_frame_info' })
        }
        const response = await browser.tabs.sendMessage(tabId, {
            channel: 'ptk_background2content_recorder',
            type: 'frame_info',
            sessionId: this.sessionId,
            frameInfo
        }, { frameId: targetFrameId }).catch(() => null)
        return Promise.resolve({ success: response !== null })
    }

    async msg_relay_replay_step(message, sender) {
        if (this.mode !== 'replay' || !this.sessionId || message?.sessionId !== this.sessionId) {
            return Promise.resolve({ success: false, error: 'invalid_session' })
        }
        const step = Number(message?.step)
        const routeDepth = Number(message?.routeDepth || 0)
        if (!Number.isSafeInteger(step) || step < 1 || !Number.isSafeInteger(routeDepth) || routeDepth < 0 || routeDepth > 16) {
            return Promise.resolve({ success: false, error: 'invalid_step' })
        }
        const replayState = await browser.storage.local.get(['ptk_replay', 'ptk_replay_step'])
        if (replayState.ptk_replay?.sessionId !== this.sessionId || replayState.ptk_replay_step !== step) {
            return Promise.resolve({ success: false, error: 'stale_step' })
        }

        const senderTabId = sender?.tab?.id
        const targetTabId = Number(message?.targetTabId)
        const targetFrameId = Number(message?.targetFrameId || 0)
        if (!Number.isInteger(senderTabId) || !this.isTracking(senderTabId) || !Number.isInteger(targetTabId) || !this.isTracking(targetTabId)) {
            return Promise.resolve({ success: false, error: 'untracked_tab' })
        }

        let allowed = false
        if (targetTabId === senderTabId && targetFrameId > 0) {
            allowed = await this._isDirectChildFrame(sender, targetFrameId)
        } else if (Number(sender?.frameId) === 0 && senderTabId === this.openerTabId && targetFrameId === 0) {
            allowed = targetTabId === this.activeReplayTabId && targetTabId !== this.openerTabId
        }
        if (!allowed) {
            return Promise.resolve({ success: false, error: 'unrelated_replay_target' })
        }

        const response = await browser.tabs.sendMessage(targetTabId, {
            channel: 'ptk_background2content_recorder',
            type: 'replay_step',
            sessionId: this.sessionId,
            step,
            routeDepth
        }, { frameId: targetFrameId }).catch(() => null)
        return Promise.resolve({
            success: response?.success === true,
            errorCode: boundedReplayText(response?.errorCode || (response ? 'replay_step_failed' : 'replay_target_unavailable'), 100)
        })
    }

    async msg_set_window_size(message, sender) {
        if (this.mode !== 'replay') return Promise.resolve({ success: false })
        const windowId = sender?.tab?.windowId
        if (!windowId) return Promise.resolve({ success: false })
        const width = Number(message?.width)
        const height = Number(message?.height)
        if (!width || !height) return Promise.resolve({ success: false })
        return browser.windows.update(windowId, { width, height })
            .then(() => ({ success: true }))
            .catch(() => ({ success: false }))
    }

    /* End Listeners */

    isTracking(tabId) {
        return (tabId == this.openerTabId || this.tabs.includes(tabId))
    }

    cleanCookie(startUrl) {
        this.cleanCookieOnStart = true
        this.clearCookiesForUrl(startUrl).catch(() => {})
    }

    _buildReplayCookieUrl(startUrl, cookie = {}) {
        const baseUrl = new URL(startUrl)
        const rawDomain = String(cookie?.domain || baseUrl.hostname || "").trim().replace(/^\./, "")
        const path = String(cookie?.path || "/").trim() || "/"
        const secure = cookie?.secure === true || baseUrl.protocol === "https:"
        return `${secure ? "https" : "http"}://${rawDomain}${path}`
    }

    async clearCookiesForUrl(startUrl) {
        const baseUrl = new URL(startUrl)
        const cookies = await browser.cookies.getAll({ domain: baseUrl.hostname })
        await Promise.all((Array.isArray(cookies) ? cookies : []).map((cookie) => {
            return browser.cookies.remove({
                url: this._buildReplayCookieUrl(startUrl, cookie),
                name: cookie.name,
                storeId: cookie.storeId
            }).catch(() => null)
        }))
    }

    async applySessionProfileSnapshot(startUrl, sessionProfile = null) {
        const cookies = Array.isArray(sessionProfile?.snapshot?.cookies)
            ? sessionProfile.snapshot.cookies
            : []
        if (!cookies.length) {
            return 0
        }
        await this.clearCookiesForUrl(startUrl)
        let appliedCount = 0
        for (const cookie of cookies) {
            const payload = {
                url: this._buildReplayCookieUrl(startUrl, cookie),
                name: cookie?.name,
                value: cookie?.value || "",
                path: cookie?.path || "/",
                secure: cookie?.secure === true,
                httpOnly: cookie?.httpOnly === true,
                sameSite: cookie?.sameSite,
                storeId: cookie?.storeId || "0"
            }
            if (!cookie?.hostOnly && cookie?.domain) {
                payload.domain = cookie.domain
            }
            if (cookie?.session === false && Number.isFinite(cookie?.expirationDate)) {
                payload.expirationDate = cookie.expirationDate
            }
            try {
                await browser.cookies.set(payload)
                appliedCount += 1
            } catch (err) {
                console.warn("Failed to apply replay session cookie", cookie?.name, err)
            }
        }
        return appliedCount
    }

    startRecording(cleanCookie, startUrl, bootstrap) {
        if (this.mode == null) {
            this.reset()

            worker.ptk_recorder_active = true
            this.mode = 'recording'
            this.bootstrap = bootstrap
            this.cleanCookieOnStart = cleanCookie
            this.sessionId = createRecorderSessionId()
            this.confirmationClaimed = false
            this.captureSensitiveInputs = cleanCookie === true || bootstrap?.captureSensitiveInputs === true

            this.recording = {
                startUrl: startUrl, frames: [], items: [], requests: [], recordingRequests: []
            }

            if (cleanCookie) this.cleanCookie(startUrl)

            this.addListiners()
            let self = this
            browser.webRequest.handlerBehaviorChanged() //FF caching
            browser.storage.local.set({
                "ptk_recording_items": [],
                "ptk_recording_timing": [],
                "ptk_recording": {
                    mode: "recording",
                    startUrl: startUrl,
                    sessionId: this.sessionId,
                    captureSensitiveInputs: this.captureSensitiveInputs
                },
                "ptk_recording_log": "",
                "ptk_recording_confirm_required": true,
                "ptk_path_to_icons": this.pathToIcons,
                "ptk_double_click": this.doubleClick
            }).then(function () {
                self.startInActiveTab(startUrl).catch((e) => {
                    console.warn('Failed to start recording in active tab', e)
                })
            })
        } else {
            ptk_notifications.notify("Recording/playback already started", "Stop recording before start a new one");
        }
    }

    async stopRecording(params) {
        if (this.stopRecordingPromise) return this.stopRecordingPromise
        const recording = this.recording
        worker.ptk_recorder_active = false
        this.mode = null
        this.openerWinId = -1
        this.openerTabId = -1
        this.tabs = []
        this.detachAllDebuggers()
        this.removeListiners()

        if (this.cancelled) {
            this.reset()
            return
        }

        this.stopRecordingPromise = (async () => {
            const result = await browser.storage.local.get(["ptk_recording_items", "ptk_recording_timing"])
            if (!result) return
            if (!recording) throw new Error('recording_state_missing')

            let a = recording.requests
            let b = result.ptk_recording_timing || []

            for (let l = 0; l < recording.recordingRequests.length; l++) {

                for (let k = 0; k < a.length; k++) {
                    let r = a[k].request
                    let u = r.urlFragment ? r.url + r.urlFragment : r.url
                    if (recording.recordingRequests[l].request.url == u) {
                        recording.recordingRequests[l].response.body = a[k].response.body
                        recording.recordingRequests[l].response.base64Encoded = a[k].response.base64Encoded
                        if (r.postData) {
                            if (recording.recordingRequests[l]?.request?.requestBody) {
                                recording.recordingRequests[l].request.requestBody.postData = r.postData
                                recording.recordingRequests[l].request.requestBody.postDataEntries = r.postDataEntries
                            } else {
                                console.warn('No request body for postData', recording.recordingRequests[l]?.request)
                            }
                        }
                        a.splice(k, 1)
                        break
                    }
                }

                for (let k = 0; k < b.length; k++) {
                    if (recording.recordingRequests[l].request.url == b[k].name) {
                        recording.recordingRequests[l].timing = b[k]
                        b.splice(k, 1)
                        break
                    }
                }
            }
            recording.requests = []
            recording.items = result.ptk_recording_items || []

            await browser.storage.local.remove([
                "ptk_recording",
                "ptk_recording_items",
                "ptk_recording_timing",
                "ptk_recording_log",
                "ptk_recording_confirm_required",
                "ptk_path_to_icons",
                "ptk_double_click"
            ])
            this.recording = recording
            this.storage['recording'] = JSON.parse(JSON.stringify(recording))
            this.storage['savedMacro'] = ''
            this.storage['savedFlow'] = null
            this.storage['savedFormat'] = 'xml'
            await ptk_storage.setItem(this.storageKey, this.storage)
            await browser.runtime.sendMessage({
                channel: "ptk_background2popup_recorder",
                type: "recording_completed",
                recording: JSON.parse(JSON.stringify(recording))
            }).catch(e => ptk_logger.log(e, "Could send recording completed", "warning"))
        })()
        try {
            await this.stopRecordingPromise
        } finally {
            this.stopRecordingPromise = null
        }
    }

    async startReplay(cleanCookie, startUrl, items, validateRegex, options = {}) {
        if (this.mode == null) {

            const scanOwned = await this.prepareScanOwnedReplay(options, startUrl, items)

            worker.ptk_recorder_active = true
            this.mode = 'replay'
            const overlay = options?.overlay && typeof options.overlay === "object"
                ? options.overlay
                : null
            const sessionProfile = options?.sessionProfile && typeof options.sessionProfile === "object"
                ? options.sessionProfile
                : null
            this.cleanCookieOnStart = cleanCookie || !!sessionProfile
            this.sessionId = createRecorderSessionId()
            this.confirmationClaimed = false
            this.scanOwnedReplay = scanOwned

            this.replay = {
                startUrl: startUrl, replayStep: 0, replayEvents: items, validateRegex: validateRegex
            }
            this.replayResult = normalizeReplayResult({
                status: 'running',
                currentStep: 0,
                completedSteps: 0,
                totalSteps: items.length
            }, this.sessionId, items.length)

            if (sessionProfile?.snapshot) {
                await this.applySessionProfileSnapshot(startUrl, sessionProfile)
            } else if (cleanCookie) {
                await this.clearCookiesForUrl(startUrl)
            }
            this.addListiners()
            let self = this
            const persistedReplayItems = scanOwned
                ? items.map(replayItemSummary)
                : items
            await browser.storage.local.set({
                "ptk_replay_items": persistedReplayItems,
                "ptk_replay_step": 0,
                "ptk_replay_regex": validateRegex,
                "ptk_replay": {
                    mode: "replay",
                    startUrl: startUrl,
                    sessionId: this.sessionId,
                    scanOwned: !!scanOwned,
                    source: scanOwned?.source || null,
                    overlayPlan: overlay,
                    session: sessionProfile
                        ? {
                            id: sessionProfile?.id || null,
                            label: sessionProfile?.label || null,
                            host: sessionProfile?.host || null
                        }
                        : null
                },
                "ptk_replay_result": this.replayResult,
                "ptk_replay_last_result": this.replayResult,
                "ptk_recording_log": "",
                "ptk_recording_confirm_required": !scanOwned,
                "ptk_path_to_icons": this.pathToIcons
            })
            try {
                if (scanOwned) await self.startInTab(scanOwned.tab, startUrl)
                else await self.startInActiveTab(startUrl)
            } catch (error) {
                await self.stopReplay({ reason: 'replay_start_failed' })
                throw error
            }
            return { success: true, sessionId: this.sessionId, targetTabId: this.openerTabId }
        } else {
            ptk_notifications.notify("Recording/playback already started", "Stop recording before start a new one");
            return { success: false, error: 'recording_or_replay_already_started' }
        }
    }

    async cancelReplayInTabs(tabIds, sessionId) {
        if (!sessionId) return
        await Promise.all(tabIds.map(async (tabId) => {
            let frameIds = [0]
            try {
                const frames = await browser.webNavigation.getAllFrames({ tabId })
                frameIds = [...new Set((Array.isArray(frames) ? frames : [])
                    .map((frame) => Number(frame?.frameId))
                    .filter((frameId) => Number.isInteger(frameId) && frameId >= 0))]
                if (!frameIds.includes(0)) frameIds.unshift(0)
            } catch (_) { }
            await Promise.all(frameIds.map((frameId) => browser.tabs.sendMessage(tabId, {
                channel: 'ptk_background2content_recorder',
                type: 'replay_cancel',
                sessionId
            }, { frameId }).catch(() => null)))
        }))
    }

    async stopReplay(params = {}) {
        const sessionId = this.sessionId
        if (sessionId && !REPLAY_TERMINAL_STATUSES.has(this.replayResult?.status)) {
            this.replayResult = normalizeReplayResult({
                status: 'stopped',
                currentStep: this.replayResult?.currentStep || 0,
                completedSteps: this.replayResult?.completedSteps || 0,
                totalSteps: this.replayResult?.totalSteps || this.replay?.replayEvents?.length || 0
            }, sessionId, this.replay?.replayEvents?.length || 0)
            await browser.storage.local.set({ ptk_replay_last_result: this.replayResult }).catch(() => {})
        }
        const replayTabIds = [...new Set([this.openerTabId, ...this.tabs]
            .filter((tabId) => Number.isInteger(tabId) && tabId >= 0))]
        worker.ptk_recorder_active = false
        this.mode = null
        this.openerWinId = -1
        this.openerTabId = -1
        this.tabs = []
        this.replay = null
        this.sessionId = null
        this.activeReplayTabId = null
        this.pendingReplayTabs.clear()
        this.scanOwnedReplay = null
        this.replayResult = null
        this.detachAllDebuggers()
        this.removeListiners()
        await browser.storage.local.set({
            "ptk_replay_step": -1,
            "ptk_replay": null
        }).catch(() => {})
        await this.cancelReplayInTabs(replayTabIds, sessionId)
        await browser.storage.local.remove([
            "ptk_replay_items",
            "ptk_replay_step",
            "ptk_replay_regex",
            "ptk_replay",
            "ptk_replay_result",
            "ptk_recording_log",
            "ptk_recording_confirm_required",
            "ptk_path_to_icons",
            "ptk_double_click"
        ]).catch(() => {})
    }

    reset() {
        this.mode = null
        this.openerWinId = -1
        this.openerTabId = -1
        this.tabs = []
        this.replay = null
        this.recording = null
        this.sessionId = null
        this.activeReplayTabId = null
        this.pendingReplayTabs = new Set()
        this.scanOwnedReplay = null
        this.replayResult = null
        this.captureSensitiveInputs = false
        this.bootstrap = null
        this.stopRecordingPromise = null
        this.confirmationClaimed = false
        this.savedMacro = ""
        this.cancelled = false
        this.detachAllDebuggers()
        delete worker.ptk_recorder_active
        browser.storage.local.remove(
            [
                "ptk_recording",
                "ptk_recording_items",
                "ptk_recording_timing",
                "ptk_replay_items",
                "ptk_replay_step",
                "ptk_replay_regex",
                "ptk_replay",
                "ptk_replay_result",
                "ptk_replay_last_result",
                "ptk_recording_log"
            ])
        this.removeListiners()
    }

    ensureDebugger(tabId) {
        return new Promise((resolve) => {
            if (typeof chrome === "undefined" || !chrome.debugger || worker.isFirefox) {
                resolve(false)
                return
            }

            if (this.debuggerTargets.has(tabId)) {
                resolve(true)
                return
            }

            browser.tabs.get(tabId).then(() => {
                const debugTarget = { tabId: tabId }
                chrome.debugger.attach(debugTarget, "1.3", () => {
                    if (chrome.runtime.lastError) {
                        resolve(false)
                        return
                    }
                    this.debuggerTargets.add(tabId)
                    this.onAttach()
                    resolve(true)
                })
            }).catch(() => resolve(false))
        })
    }

    detachAllDebuggers() {
        if (typeof chrome === "undefined" || !chrome.debugger || worker.isFirefox) return
        for (const tabId of this.debuggerTargets) {
            const debugTarget = { tabId: tabId }
            chrome.debugger.detach(debugTarget, () => {
                if (chrome.runtime.lastError) {
                    // ignore missing tab
                }
            })
        }
        this.debuggerTargets.clear()
    }

    msg_debugger_click(message, sender) {
        if (this.mode !== 'recording') return Promise.resolve({ success: false })
        const tabId = sender?.tab?.id
        if (!tabId) return Promise.resolve({ success: false })
        return this.ensureDebugger(tabId).then((attached) => {
            if (!attached) return { success: false }
            const debugTarget = { tabId: tabId }
            const x = Math.max(0, Math.floor(message.x || 0))
            const y = Math.max(0, Math.floor(message.y || 0))
            const clickCount = message.clickCount || 1
            return new Promise((resolve) => {
                chrome.debugger.sendCommand(debugTarget, "Input.dispatchMouseEvent", {
                    type: "mouseMoved",
                    x: x,
                    y: y
                }, () => {
                    if (chrome.runtime.lastError) {
                        resolve({ success: false })
                        return
                    }
                    chrome.debugger.sendCommand(debugTarget, "Input.dispatchMouseEvent", {
                        type: "mousePressed",
                        x: x,
                        y: y,
                        button: "left",
                        clickCount: clickCount
                    }, () => {
                        if (chrome.runtime.lastError) {
                            resolve({ success: false })
                            return
                        }
                        chrome.debugger.sendCommand(debugTarget, "Input.dispatchMouseEvent", {
                            type: "mouseReleased",
                            x: x,
                            y: y,
                            button: "left",
                            clickCount: clickCount
                        }, () => {
                            if (chrome.runtime.lastError) {
                                resolve({ success: false })
                                return
                            }
                            resolve({ success: true })
                        })
                    })
                })
            })
        })
    }

    analyse() {
        let result = []
        let previousValue = []
        this.recording.recordingRequests.forEach(function (item) {

            let requestHeaders = item.requestHeaders ? item.requestHeaders : []
            let responseHeaders = item.responseHeaders ? item.responseHeaders : []
            let hostname = new URL(item.request.url).hostname

            if (!previousValue[hostname]) previousValue[hostname] = {}

            var resultitem = { hostname: hostname }
            requestHeaders.find(function (item) {
                if (item.name.toLowerCase() == 'cookie' && previousValue[hostname].cookie != item.value) {
                    resultitem.browser = { cookie: { item: {} } }
                    resultitem.browser.cookie = { item: item, request: item }
                    previousValue[hostname].cookie = item.value
                }
                if (item.name.toLowerCase() == 'authorization' && previousValue[hostname].authorization != item.value) {
                    resultitem.browser = { authorization: { item: {} } }
                    resultitem.browser.authorization = { item: item, request: item }
                    previousValue[hostname].authorization = item.value
                }
            })

            responseHeaders.find(function (item) {
                if (item.name.toLowerCase() == 'set-cookie') {
                    resultitem.server = { cookie: { item: {} } }
                    resultitem.server.cookie = { item: item, request: item }
                }
            })

            if (item.response?.body) {
                var body = item.response.base64Encoded ? atob(item.response.body) : item.response.body,
                    token = body.match(new RegExp('(?:"[^"]*token"\s?:\s?){1}"([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)"{1}'))
                if (token) {
                    resultitem.server = { token: { item: {} } }
                    resultitem.server.token = { item: token[token.length - 1], request: item }
                }
            }
            if (resultitem.browser || resultitem.server) {
                result.push(resultitem)
            }
        })
        return result
    }

}


