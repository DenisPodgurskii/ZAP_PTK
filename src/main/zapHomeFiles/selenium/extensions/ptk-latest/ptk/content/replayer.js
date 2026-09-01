/* Author: Denis Podgurskii */

(function () {
    if (typeof browser === typeof undefined) return
    if (window.__ptkReplayerRuntime?.create) {
        const current = window.ptk_replayer
        if (!current || current.cancelled || current.step < 0) {
            window.ptk_replayer = window.__ptkReplayerRuntime.create()
        }
        return
    }
    if (window.ptk_replayer) return

    function cloneReplayValue(value) {
        if (typeof globalThis.structuredClone === 'function') {
            try {
                return globalThis.structuredClone(value)
            } catch (e) {
                // fall back to JSON clone
            }
        }
        return JSON.parse(JSON.stringify(value ?? null))
    }

    let isIframe = false
    try {
        isIframe = window.self !== window.top
    } catch (e) {
        isIframe = true
    }

    let windowIndex = 0

    function isExpectedParentMessage(event) {
        if (!event || event.source !== window.parent) return false
        if (!document.referrer) return true
        try {
            const expectedOrigin = new URL(document.referrer).origin
            return expectedOrigin === 'null' || event.origin === expectedOrigin
        } catch (e) {
            return false
        }
    }

    class ReplayCancelledError extends Error {
        constructor() {
            super('Replay stopped')
            this.name = 'ReplayCancelledError'
        }
    }

    class ReplayStepError extends Error {
        constructor(code, message, stepType = '') {
            super(message)
            this.name = 'ReplayStepError'
            this.code = String(code || 'replay_step_failed').slice(0, 100)
            this.userMessage = String(message || 'Replay could not complete the required step.').slice(0, 300)
            this.stepType = String(stepType || '').slice(0, 80)
        }
    }

    function isReplayCancelledError(error) {
        return error?.name === 'ReplayCancelledError'
    }

    function initialReplayDestinationMatchesCurrent(rawUrl) {
        try {
            const expected = new URL(String(rawUrl || ''), window.location.href)
            const current = new URL(window.location.href)
            if (expected.href === current.href) return true
            const rootHashes = new Set(['', '#', '#/', '#/?'])
            return expected.origin === current.origin
                && expected.pathname === current.pathname
                && expected.search === current.search
                && rootHashes.has(expected.hash)
                && rootHashes.has(current.hash)
        } catch (_) {
            return false
        }
    }

    class ptk_replayer {
        constructor() {
            browser.storage.local.get([
                'ptk_replay',
                'ptk_replay_items',
                'ptk_replay_step',
                'ptk_replay_regex',
                'ptk_recording_log',
                'ptk_replay_debug_enabled']).then(async function (result) {
                    let replayItems = result.ptk_replay_items
                    let replayRegex = result.ptk_replay_regex
                    if (result.ptk_replay?.scanOwned === true) {
                        const payload = await browser.runtime.sendMessage({
                            channel: 'ptk_content2background_recorder',
                            type: 'get_replay_payload',
                            sessionId: result.ptk_replay.sessionId
                        }).catch(() => null)
                        if (!payload?.success || !Array.isArray(payload.items)) return
                        replayItems = payload.items
                        replayRegex = payload.regex
                    }
                    if (result.ptk_replay?.mode !== 'replay'
                        || !Array.isArray(replayItems)
                        || !Number.isSafeInteger(result.ptk_replay_step)
                        || result.ptk_replay_step < 0) return
                    this.items = replayItems
                    this.step = result.ptk_replay_step
                    this.regex = replayRegex
                    this.replayEnvelope = result.ptk_replay || null
                    this.sessionId = typeof result.ptk_replay?.sessionId === 'string'
                        ? result.ptk_replay.sessionId
                        : null
                    this.overlayPlan = result.ptk_replay?.overlayPlan || null
                    this.paused = false
                    this.forward = false
                    this.log = result.ptk_recording_log || ''
                    this._networkPending = 0
                    this._lastNetworkActivity = 0
                    this._networkWrapped = false
                    this.tabId = null
                    this.activeReplayTabId = null
                    this.frameRoutes = new Map()
                    this.frameLoadListeners = new WeakSet()
                    this.pendingFrameAcks = new Map()
                    this.frameReadyAttempts = 0
                    this.frameReadyTimer = null
                    this.hasInitialNavigate = false
                    this.cancelled = false
                    this.warnings = []
                    this.replayAbortController = new AbortController()
                    this.onReplayStorageChanged = this.handleReplayStorageChanged.bind(this)
                    browser.storage.onChanged.addListener(this.onReplayStorageChanged)
                    this.debugEnabled = typeof result.ptk_replay_debug_enabled === 'boolean'
                        ? result.ptk_replay_debug_enabled
                        : true


                    if (!isIframe) {
                        this.bootstrapReplayContext()
                    } else {
                        this.announceFrameReady()
                    }
                }.bind(this))
        }

        logEvent(item, msg) {
            if (item) {
                let eventName = (item.EventType == 'Javascript') ? item.EventType + '(' + item.EventTypeName + ')' : item.EventType
                this.log += 'Step #' + (this.step + 1) + ': ' + eventName + '<br/>'
            }
            if (msg) {
                this.log += msg + '<br/>'
            }
            browser.storage.local.set({
                'ptk_recording_log': this.log
            })
        }

        replayStepType(item) {
            return String(item?.PtkStepType || item?.EventTypeName || item?.EventType || '').slice(0, 80)
        }

        replayStepId(item) {
            return String(item?.PtkStepId || (Number.isSafeInteger(Number(item?.Step)) ? `step-${item.Step}` : '')).slice(0, 128)
        }

        async reportReplayOutcome(status, item = null, error = null, completedSteps = null) {
            if (!this.sessionId || isIframe) return null
            const currentStep = Number.isSafeInteger(Number(item?.Step))
                ? Number(item.Step)
                : Math.max(0, Math.min(this.items?.length || 0, Number(this.step) || 0))
            const safeError = error ? {
                code: error instanceof ReplayStepError ? error.code : 'replay_step_failed',
                message: error instanceof ReplayStepError
                    ? error.userMessage
                    : 'Replay stopped because a required step could not be completed.',
                stepType: this.replayStepType(item)
            } : null
            return browser.runtime.sendMessage({
                channel: 'ptk_content2background_recorder',
                type: 'replay_outcome',
                sessionId: this.sessionId,
                outcome: {
                    status,
                    currentStepId: this.replayStepId(item),
                    currentStep,
                    completedSteps: completedSteps === null
                        ? Math.max(0, Math.min(this.items?.length || 0, currentStep))
                        : completedSteps,
                    totalSteps: this.items?.length || 0,
                    warnings: this.warnings.slice(-50),
                    error: safeError
                }
            }).catch(() => null)
        }

        replayFailure(code, message, item = null) {
            return new ReplayStepError(code, message, this.replayStepType(item))
        }

        isRequiredStep(item) {
            return item?.Optional !== 1
        }

        recordOptionalWarning(code, message) {
            const warning = `${String(code || 'optional_step_failed').slice(0, 100)}: ${String(message || 'Optional replay step was skipped.').slice(0, 240)}`
            this.warnings.push(warning)
            if (this.warnings.length > 50) this.warnings.shift()
            this.logEvent(null, warning)
            return null
        }

        wait(ms, opts = {}) {
            return new Promise((resolve, reject) => {
                if (this.cancelled || this.replayAbortController?.signal?.aborted) {
                    reject(new ReplayCancelledError())
                    return
                }
                const signals = [opts.signal, this.replayAbortController?.signal].filter(Boolean)
                const cleanup = () => signals.forEach((signal) => signal.removeEventListener('abort', onAbort))
                const onAbort = () => {
                    clearTimeout(timerId)
                    cleanup()
                    reject(this.cancelled ? new ReplayCancelledError() : new DOMException('Aborted', 'AbortError'))
                }
                const timerId = setTimeout(() => {
                    cleanup()
                    resolve()
                }, Math.max(0, Number(ms) || 0))
                signals.forEach((signal) => signal.addEventListener('abort', onAbort, { once: true }))
            })
        }

        handleReplayStorageChanged(changes, namespace) {
            if (namespace !== 'local' || this.cancelled || !this.sessionId) return
            const replayChange = changes?.ptk_replay
            const stepChange = changes?.ptk_replay_step
            const replayStopped = replayChange
                && (replayChange.newValue?.mode !== 'replay'
                    || replayChange.newValue?.sessionId !== this.sessionId)
            const stepStopped = stepChange
                && (!Number.isSafeInteger(stepChange.newValue) || stepChange.newValue < 0)
            if (replayStopped || stepStopped) this.cancelReplay()
        }

        cancelReplay() {
            if (this.cancelled) return
            this.cancelled = true
            this.step = -1
            clearTimeout(this.frameReadyTimer)
            this.frameReadyTimer = null
            try { this.abortController?.abort() } catch (_) { }
            try { this.replayAbortController?.abort() } catch (_) { }
            for (const pending of this.pendingFrameAcks?.values?.() || []) {
                clearTimeout(pending.timer)
                pending.resolve({ success: false, errorCode: 'replay_cancelled' })
            }
            this.pendingFrameAcks?.clear?.()
            if (this.onReplayStorageChanged) {
                browser.storage.onChanged.removeListener(this.onReplayStorageChanged)
                this.onReplayStorageChanged = null
            }
        }

        async announceReplayChild() {
            if (!this.sessionId) return
            browser.runtime.sendMessage({
                channel: 'ptk_content2background_recorder',
                type: 'register_replay_child',
                sessionId: this.sessionId
            }).then((response) => {
                if (response?.success) this.tabId = response.tabId
            }).catch(() => {})
        }

        async bootstrapReplayContext() {
            try {
                const context = await browser.runtime.sendMessage({
                    channel: 'ptk_content2background_recorder',
                    type: 'get_replay_context',
                    sessionId: this.sessionId
                })
                if (!context?.success) return
                this.tabId = context.tabId
                this.activeReplayTabId = context.activeReplayTabId
                windowIndex = context.isOpener ? 0 : 1
                if (context.isOpener) {
                    try {
                        this._initNetworkTracking()
                    } catch (error) {
                        // Network-idle tracking is advisory. Firefox can reject
                        // wrapping page APIs from the extension isolated world;
                        // replay must still execute the recorded workflow.
                        this.debugLog('network_tracking_unavailable', {
                            error: error?.message || String(error)
                        })
                    }
                    this.start().catch((error) => {
                        this.debugLog('replay_start_failed', {
                            errorType: error?.name || 'Error'
                        })
                        this.reportReplayOutcome('failed', null, error).catch(() => null)
                    })
                } else {
                    await this.announceReplayChild()
                }
            } catch (_) { }
        }

        async announceFrameReady() {
            if (!isIframe || !this.sessionId || this.frameReadyAttempts >= 20) return
            try {
                const identity = await browser.runtime.sendMessage({
                    channel: 'ptk_content2background_recorder',
                    type: 'get_frame_identity',
                    sessionId: this.sessionId
                })
                if (!identity?.success || !Number.isInteger(identity.frameId) || identity.frameId < 1) return
                this.tabId = identity.tabId
                windowIndex = Number(identity.windowIndex) === 1 ? 1 : 0
                // Readiness is deliberately non-sensitive. Session and replay
                // state stay in extension runtime/storage.
                window.parent.postMessage({
                    channel: 'ptk_replayer_ready',
                    message: 'frame_ready',
                    frameId: identity.frameId
                }, '*')
            } catch (_) { }
            this.frameReadyAttempts += 1
            if (this.frameReadyAttempts < 20) {
                clearTimeout(this.frameReadyTimer)
                this.frameReadyTimer = setTimeout(() => this.announceFrameReady(), 250)
            }
        }

        findDirectFrame(source) {
            const frames = Array.from(document.getElementsByTagName('iframe'))
            const index = frames.findIndex((frame) => frame.contentWindow === source)
            if (index < 0) return null
            return { frame: frames[index], index }
        }

        registerFrameRoute(event) {
            const direct = this.findDirectFrame(event?.source)
            const frameId = Number(event?.data?.frameId)
            if (!direct || !Number.isInteger(frameId) || frameId < 1) return
            const origin = typeof event.origin === 'string' && event.origin !== 'null'
                ? event.origin
                : null
            this.frameRoutes.set(event.source, { frameId, origin })
            if (!this.frameLoadListeners.has(direct.frame)) {
                this.frameLoadListeners.add(direct.frame)
                const source = event.source
                direct.frame.addEventListener('load', () => this.frameRoutes.delete(source))
            }
        }

        async waitForFrameRoute(frameWindow, timeoutMs = 5000) {
            const deadline = Date.now() + timeoutMs
            while (Date.now() < deadline) {
                const route = this.frameRoutes.get(frameWindow)
                if (route) return route
                await this.wait(100)
            }
            return null
        }

        frameAckKey(step, routeDepth) {
            return [step, routeDepth].join(':')
        }

        waitForFrameAck(frameWindow, origin, step, routeDepth, timeoutMs = 10000) {
            const key = this.frameAckKey(step, routeDepth)
            const previous = this.pendingFrameAcks.get(key)
            if (previous) {
                clearTimeout(previous.timer)
                previous.resolve({ success: false, errorCode: 'frame_ack_replaced' })
            }
            return new Promise((resolve) => {
                const timer = setTimeout(() => {
                    this.pendingFrameAcks.delete(key)
                    resolve({ success: false, errorCode: 'frame_ack_timeout' })
                }, timeoutMs)
                this.pendingFrameAcks.set(key, {
                    source: frameWindow,
                    origin,
                    resolve,
                    timer
                })
            })
        }

        resolveFrameAck(event, data) {
            if (!data || data.sessionId !== this.sessionId) return false
            if (!Number.isSafeInteger(data.step) || !Number.isSafeInteger(data.routeDepth)) return false
            const key = this.frameAckKey(data.step, data.routeDepth)
            const pending = this.pendingFrameAcks.get(key)
            if (!pending || event.source !== pending.source || event.origin !== pending.origin) return false
            clearTimeout(pending.timer)
            this.pendingFrameAcks.delete(key)
            pending.resolve({
                success: data.success !== false,
                errorCode: String(data.errorCode || '').slice(0, 100)
            })
            return true
        }

        sendFrameAck(event, data, outcome = { success: true }) {
            if (!event?.source || typeof event.origin !== 'string' || event.origin === 'null') return
            event.source.postMessage({
                channel: 'ptk_replayer_ack',
                message: 'step_complete',
                sessionId: this.sessionId,
                step: data.step,
                routeDepth: data.routeDepth,
                success: outcome?.success !== false,
                errorCode: String(outcome?.errorCode || '').slice(0, 100)
            }, event.origin)
        }

        validate() {
            if (this.regex && this.step > 0) {
                let regex
                try {
                    regex = new RegExp(this.regex, 'i')
                } catch (_) {
                    throw this.replayFailure('validation_pattern_invalid', 'Replay validation pattern is invalid.')
                }
                if (!regex.test(document.body.innerHTML)) {
                    throw this.replayFailure('validation_failed', 'Replay validation did not match the page.')
                }
                this.logEvent(null, 'Replay validation passed')
            }
        }

        async execute(item) {
            const resolution = this.resolveOverlayItem(this.step, item)
            if (resolution.skip) {
                this.debugLog('step_skipped_overlay', {
                    step: this.step,
                    reason: resolution.overlay?.reason || 'overlay'
                })
                this.logEvent(item, `Skipped by workflow overlay (${resolution.overlay?.reason || 'overlay'})`)
                return
            }
            const effectiveItem = resolution.item
            if (!isIframe && effectiveItem.WindowIndex == windowIndex) {
                if (this.framePath(effectiveItem).frameLocators.length) {
                    await this.executeFrame(effectiveItem, 0)
                } else {
                    await this.doStep(this.step, effectiveItem)
                }
            } else if (!isIframe) {
                await this.sendChildStep(effectiveItem)
            }
        }

        async sendChildStep(item) {
            const response = await browser.runtime.sendMessage({
                channel: 'ptk_content2background_recorder',
                type: 'get_active_replay_tab',
                sessionId: this.sessionId
            }).catch(() => null)
            const targetTabId = response?.activeReplayTabId
            this.activeReplayTabId = targetTabId || this.activeReplayTabId
            if (!targetTabId || targetTabId === this.tabId) {
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('child_window_not_found', 'Could not locate the required child window.', item)
                }
                return this.recordOptionalWarning('child_window_not_found', 'Optional child-window step was skipped because the window was unavailable.')
            }
            const result = await browser.runtime.sendMessage({
                channel: 'ptk_content2background_recorder',
                type: 'relay_replay_step',
                sessionId: this.sessionId,
                step: this.step,
                routeDepth: 0,
                targetTabId,
                targetFrameId: 0
            }).catch(() => null)
            if (!result?.success) {
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure(result?.errorCode || 'child_window_step_failed', 'Could not complete the required step in the child window.', item)
                }
                return this.recordOptionalWarning(result?.errorCode || 'child_window_step_failed', 'Optional child-window step could not be completed.')
            }
        }

        framePath(item) {
            const rawParts = String(item.ElementPath || '').split('|||>').filter(Boolean)
            const parts = rawParts.filter(part => part !== 'xpath=' && part !== 'css=')
            const isIframeLocator = (part) => /IFRAME/i.test(part)
            let elementPathIndex = -1
            for (let i = parts.length - 1; i >= 0; i--) {
                if (/^(css|xpath)=/.test(parts[i]) && !isIframeLocator(parts[i])) {
                    elementPathIndex = i
                    break
                }
            }
            if (elementPathIndex === -1) elementPathIndex = parts.length - 1
            const frameLocators = parts.slice(0, elementPathIndex).filter(isIframeLocator)
            const elementPath = parts[elementPathIndex] || ''

            return { frameLocators, elementPath }
        }

        async executeFrame(item, routeDepth = 0){
            const { frameLocators, elementPath } = this.framePath(item)
            if (!Number.isSafeInteger(routeDepth) || routeDepth < 0 || routeDepth > frameLocators.length) {
                throw this.replayFailure('frame_route_invalid', 'The recorded frame route is invalid.', item)
            }
            if (routeDepth >= frameLocators.length) {
                const localItem = cloneReplayValue(item)
                localItem.ElementPath = elementPath
                await this.doStep(this.step, localItem)
                return
            }

            const locator = frameLocators[routeDepth]
            const frameElement = this.getFrameElement(locator, document)
            if (!frameElement || !frameElement.contentWindow) {
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('frame_not_found', 'Could not locate the required frame.', item)
                }
                return this.recordOptionalWarning('frame_not_found', 'Optional frame step was skipped because the frame was not available.')
            }
            const route = await this.waitForFrameRoute(frameElement.contentWindow)
            if (!route) {
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('frame_route_unavailable', 'Could not establish a trusted route to the required frame.', item)
                }
                return this.recordOptionalWarning('frame_route_unavailable', 'Optional frame step was skipped because its trusted route was unavailable.')
            }
            const payload = {
                channel: "2frame",
                message: 'doStep',
                sessionId: this.sessionId,
                step: this.step,
                routeDepth: routeDepth + 1
            }
            if (route.origin) {
                const ack = this.waitForFrameAck(
                    frameElement.contentWindow,
                    route.origin,
                    payload.step,
                    payload.routeDepth
                )
                frameElement.contentWindow.postMessage(payload, route.origin)
                const result = await ack
                if (!result?.success) {
                    this.debugLog('frame_step_ack_timeout', {
                        step: payload.step,
                        routeDepth: payload.routeDepth,
                        errorCode: result?.errorCode || 'frame_step_failed'
                    })
                    if (this.isRequiredStep(item)) {
                        throw this.replayFailure(result?.errorCode || 'frame_step_failed', 'Could not complete the required step inside the frame.', item)
                    }
                    this.recordOptionalWarning(result?.errorCode || 'frame_step_failed', 'Optional frame step could not be completed.')
                }
                return
            }
            const result = await browser.runtime.sendMessage({
                channel: 'ptk_content2background_recorder',
                type: 'relay_replay_step',
                sessionId: this.sessionId,
                step: this.step,
                routeDepth: routeDepth + 1,
                targetTabId: this.tabId,
                targetFrameId: route.frameId
            }).catch(() => null)
            if (!result?.success) {
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure(result?.errorCode || result?.error || 'frame_step_failed', 'Could not complete the required step inside the frame.', item)
                }
                this.recordOptionalWarning(result?.errorCode || result?.error || 'frame_step_failed', 'Optional frame step could not be completed.')
            }
        }

        getFrameElement(locator, doc) {
            if (!locator || !doc) return null
            const value = locator.startsWith('xpath=') ? locator.slice(6) : locator
            if (locator.startsWith('css=')) {
                return doc.querySelector(locator.slice(4))
            }
            if (value.includes('IFRAME')) {
                const xpath = value.startsWith('//') ? value : ('//' + value)
                return doc.evaluate(xpath, doc, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue
            }
            return null
        }

        async start() {
            let activeItem = null
            let completedSteps = Math.max(0, Number(this.step) || 0)
            let terminal = false
            try {
                if (this.step > -1) {
                    while (!this.cancelled) {
                        if (this.paused) break

                        const storedStep = await this.getCurrentStep()
                        if (storedStep === -1 || this.cancelled) break
                        if (storedStep >= this.items.length) {
                            this.step = storedStep
                            this.validate()
                            completedSteps = this.items.length
                            await this.reportReplayOutcome('completed', null, null, completedSteps)
                            terminal = true
                            break
                        }
                        this.step = storedStep
                        let item = this.items[this.step]
                        activeItem = item
                        await this.reportReplayOutcome('running', item, null, completedSteps)
                        this.debugLog('step_start', {
                            step: this.step,
                            eventType: item.EventType || item.EventTypeName
                        })

                        this.logEvent(item)
                        await browser.storage.local.set({ 'ptk_replay_step': (this.step + 1) })

                        this.abortController = new AbortController()
                        this.awaitTimeout = this.wait(item.Duration, { signal: this.abortController.signal })
                        try {
                            await this.awaitTimeout
                        } catch (error) {
                            if (this.cancelled || isReplayCancelledError(error)) break
                        }

                        if (this.paused || this.cancelled) break

                        this.step++

                        if (this.forward) {
                            this.forward = false
                            continue
                        }

                        await this.execute(item)
                        if (this.cancelled) break
                        completedSteps = storedStep + 1
                        this.debugLog('step_done', { step: this.step })
                    }
                }
            } catch (error) {
                if (!this.cancelled && !isReplayCancelledError(error)) {
                    this.logEvent(null, error instanceof ReplayStepError
                        ? error.userMessage
                        : 'Replay stopped because a required step could not be completed.')
                    await this.reportReplayOutcome('failed', activeItem, error, completedSteps)
                    terminal = true
                }
            } finally {
                if (terminal && !this.cancelled) this.stop()
            }
        }

        stop() {
            this.step = -1
            browser.storage.local.set({ "ptk_replay_step": this.step })
        }

        pause() {
            this.paused = true
            this.logEvent(null, 'Paused...')
        }

        run() {
            if (this.cancelled) return
            this.paused = false
            this.logEvent(null, 'Resumed...')
            this.start()
        }

        stepForward() {
            if (this.step > -1) {
                this.forward = true
                this.logEvent(null, 'Skip step #' + (this.step + 1))
                this.abortController.abort()
            }
        }

        async doStep(step, item) {
            if (!item || this.paused) return

            this.step = step
            const rawType = item.EventType || item.EventTypeName || item.eventTypeName || ''
            let eventType = String(rawType).toLowerCase()
            this.handler = this[eventType]
            if (this.handler) {
                await this.handler(item)
            } else {
                this.debugLog('missing_handler', { step: this.step, eventType })
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('unsupported_step', 'The macro contains a required step that PTK cannot replay.', item)
                }
                this.recordOptionalWarning('unsupported_step', 'An optional unsupported macro step was skipped.')
            }
        }

        async getApprovedMessageItem(data) {
            if (!data || typeof data !== 'object' || Array.isArray(data)) return null
            if (!this.sessionId || data.sessionId !== this.sessionId) return null
            if (!Number.isSafeInteger(data.step) || data.step < 1) return null

            const result = await browser.storage.local.get([
                'ptk_replay',
                'ptk_replay_items',
                'ptk_replay_step'
            ])
            if (result.ptk_replay?.mode !== 'replay') return null
            if (result.ptk_replay.sessionId !== this.sessionId) return null
            if (result.ptk_replay_step !== data.step) return null
            const replayItems = result.ptk_replay?.scanOwned === true
                ? this.items
                : result.ptk_replay_items
            if (!Array.isArray(replayItems)) return null

            const itemIndex = data.step - 1
            if (itemIndex < 0 || itemIndex >= replayItems.length) return null
            const resolution = this.resolveOverlayItem(data.step, replayItems[itemIndex])
            return resolution.skip ? null : resolution.item
        }

        getOverlayEntry(step) {
            const overlays = Array.isArray(this.overlayPlan?.stepOverlays)
                ? this.overlayPlan.stepOverlays
                : []
            return overlays.find((entry) => Number(entry?.stepIndex) === Number(step)) || null
        }

        resolveOverlayItem(step, item) {
            const overlay = this.getOverlayEntry(step)
            const effectiveItem = cloneReplayValue(item)
            if (!overlay) {
                return {
                    overlay: null,
                    skip: false,
                    item: effectiveItem
                }
            }
            if (overlay.skip) {
                return {
                    overlay,
                    skip: true,
                    item: effectiveItem
                }
            }
            if (overlay.mutatedItem && typeof overlay.mutatedItem === 'object') {
                return {
                    overlay,
                    skip: false,
                    item: cloneReplayValue(overlay.mutatedItem)
                }
            }
            return {
                overlay,
                skip: false,
                item: effectiveItem
            }
        }

        async bootstrapControl() {
            try {
                const resp = await browser.runtime.sendMessage({
                    channel: "ptk_content2background_recorder",
                    type: "get_tab_id"
                })
                this.tabId = resp?.tabId ?? null
                this.activeReplayTabId = resp?.activeReplayTabId ?? null
            } catch (e) {
                this.tabId = null
            }
            this.start()
        }

        async waitForActiveTab(timeoutMs = 60000, intervalMs = 250) {
            if (!this.tabId) return
            const endAt = Date.now() + timeoutMs
            while (Date.now() < endAt) {
                if (this.paused) return
                try {
                    const resp = await browser.runtime.sendMessage({
                        channel: "ptk_content2background_recorder",
                        type: "get_active_replay_tab",
                        sessionId: this.sessionId
                    })
                    this.activeReplayTabId = resp?.activeReplayTabId ?? this.activeReplayTabId
                    if (!this.activeReplayTabId || this.activeReplayTabId === this.tabId) {
                        return
                    }
                } catch (e) {
                    return
                }
                await this.wait(intervalMs)
            }
        }

        async getCurrentStep() {
            try {
                const result = await browser.storage.local.get(['ptk_replay_step', 'ptk_replay'])
                if (!result.ptk_replay) {
                    return -1
                }
                if (typeof result.ptk_replay_step === 'number') {
                    return result.ptk_replay_step
                }
            } catch (e) {
                // ignore
            }
            return this.step
        }

        async navigate(item) {
            if (item?.Data) {
                this.debugLog('navigate', { step: this.step })
                const destinationMatches = initialReplayDestinationMatchesCurrent(item.Data)
                if (!this.hasInitialNavigate) {
                    this.hasInitialNavigate = true
                    // Starting a recorded journey normally happens after the
                    // scanner has opened the target. Reloading the identical
                    // destination can destroy transient onboarding controls
                    // before the recorder's first click. Preserve the current
                    // document when it is already at that exact URL, including
                    // the common empty-hash / #/ alias for an SPA root.
                    if (!destinationMatches) {
                        window.location.href = item.Data
                    }
                } else if (!destinationMatches) {
                    // Navigate is an action. Imported formats use WaitForUrl
                    // for an observed navigation assertion, so a later open /
                    // navigate command must actually move the browser when its
                    // destination is not already loaded. The stored replay
                    // index lets the tracker resume after the document unload.
                    window.location.href = item.Data
                } else {
                    await this.waitForAppIdle({ timeoutMs: this.getStepTimeout(item) })
                }
            }
        }

        async waitforurl(item) {
            if (!item?.Data) return
            this.debugLog('wait_for_url', { step: this.step })
            await this.waitForUrl(item.Data, this.getStepTimeout(item))
            await this.waitForAppIdle({ timeoutMs: this.getStepTimeout(item) })
        }

        delay(item) { }

        driverclick(item) { return this.click(item) }
        onclick(item) { return this.click(item) }
        async click(item) {
            this.debugLog('click', { step: this.step })
            let element = await this.waitForElement(item, this.getStepTimeout(item))
            if (element) {
                // Some recorder formats emit an assistive focus click directly
                // before setting the same control value. The following fill
                // owns the real action; replaying this redundant click can
                // toggle animated SPA controls closed between the two steps.
                if (item?.PtkPreparatory === 1) return
                const beforeUrl = window.location.href
                const control = element.closest?.('button,a,input,textarea,select,[role="button"]') || element
                const isMenuTrigger = control.getAttribute?.('aria-haspopup') === 'menu'
                await this.performClick(element)
                // A synthetic bubbling resize reaches window and can make
                // Angular/CDK close a newly opened menu before the following
                // recorded menu-item step. A menu trigger has a direct ARIA
                // postcondition, so keep it open and advance once it settles.
                if (isMenuTrigger && control.getAttribute?.('aria-expanded') === 'true') {
                    await this.wait(150)
                    return
                }
                element.dispatchEvent(new Event('resize', {bubbles: true}))
                await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
            } else {
                return this.handleMissingElement(item, 'click')
            }
        }

        async doubleclick(item) {
            this.debugLog('double_click', { step: this.step })
            const element = await this.waitForElement(item, this.getStepTimeout(item))
            if (!element) return this.handleMissingElement(item, 'double click')
            const beforeUrl = window.location.href
            await this.performClick(element, 2)
            await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
        }

        driversetcontrolvalue(item) { return this.type(item) }
        setcontroldata(item) { return this.type(item) }
        setvalue(item) { return this.type(item) }
        setElementValue(element, value) {
            const nextValue = String(value ?? '')
            const lastValue = element.value
            let prototype = null
            if (typeof HTMLInputElement !== 'undefined' && element instanceof HTMLInputElement) {
                prototype = HTMLInputElement.prototype
            } else if (typeof HTMLTextAreaElement !== 'undefined' && element instanceof HTMLTextAreaElement) {
                prototype = HTMLTextAreaElement.prototype
            } else if (typeof HTMLSelectElement !== 'undefined' && element instanceof HTMLSelectElement) {
                prototype = HTMLSelectElement.prototype
            }
            const setter = prototype && Object.getOwnPropertyDescriptor(prototype, 'value')?.set
            if (setter) setter.call(element, nextValue)
            else element.value = nextValue
            if ('defaultValue' in element) element.defaultValue = nextValue
            const tracker = element._valueTracker
            if (tracker) tracker.setValue(lastValue)
            const inputEvent = typeof InputEvent === 'function'
                ? new InputEvent('input', {
                    bubbles: true,
                    cancelable: false,
                    composed: true,
                    data: nextValue,
                    inputType: 'insertText'
                })
                : new Event('input', { bubbles: true, composed: true })
            inputEvent.simulated = true
            element.dispatchEvent(inputEvent)
            element.dispatchEvent(new Event('change', { bubbles: true, composed: true }))
        }
        async type(item) {
            this.debugLog('type', { step: this.step })
            if ((item?.Data || item?.data) === '${PTK_SECRET}') {
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('missing_recorded_value', 'A required recorded value is not available.', item)
                }
                return this.recordOptionalWarning('missing_recorded_value', 'An optional step was skipped because its recorded value is not available.')
            }
            // DriverSetControlValue writes through the native value setter and
            // dispatches input/change itself, so an SPA control may be filled
            // while its expand/focus animation is still non-interactable.
            let element = await this.waitForElement(item, this.getStepTimeout(item), 250, { interactable: false })
            if (element) {
                const beforeUrl = window.location.href
                await this.ensureElementInView(element)
                this.setElementValue(element, item.Data)
                element.dispatchEvent(new Event('blur', {bubbles: true}))
                element.dispatchEvent(new Event('resize', {bubbles: true}))
                await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
            } else {
                return this.handleMissingElement(item, 'set value on')
            }
        }

        async sendkeys(item) {
            this.debugLog('sendkeys', { step: this.step })
            let element = await this.waitForElement(item, this.getStepTimeout(item))
            if (!element) {
                return this.handleMissingElement(item, 'send keys to')
            }

            const beforeUrl = window.location.href
            await this.ensureElementInView(element)
            const raw = item.Data || item.data || ''
            const tokens = this.parseKeyTokens(String(raw))
            const hasEnter = tokens.some(token => token.type === 'key' && String(token.key).toUpperCase() === 'KEY_ENTER')
            for (const token of tokens) {
                if (token.type === 'text') {
                    this.insertText(element, token.value)
                } else {
                    this.dispatchKey(element, token.key)
                }
            }
            if (hasEnter) {
                await this.waitForUrlChange(this.getStepTimeout(item))
            }
            element.dispatchEvent(new Event('change', { bubbles: true }))
            element.dispatchEvent(new Event('blur', { bubbles: true }))
            await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
        }

        async select(item) {
            this.debugLog('select', { step: this.step })
            const element = await this.waitForElement(item, this.getStepTimeout(item))
            if (!element) return this.handleMissingElement(item, 'select')
            const raw = String(item?.Data ?? item?.data ?? '')
            await this.ensureElementInView(element)
            let value = raw
            let option = null
            if (element instanceof HTMLSelectElement) {
                if (raw.startsWith('label=')) {
                    const label = raw.slice(6)
                    option = Array.from(element.options).find((entry) => entry.text === label)
                } else if (raw.startsWith('index=')) {
                    option = element.options[Number(raw.slice(6))] || null
                } else {
                    value = raw.startsWith('value=') ? raw.slice(6) : raw
                    option = Array.from(element.options).find((entry) => entry.value === value)
                }
                if (!option && this.isRequiredStep(item)) {
                    throw this.replayFailure('select_option_not_found', 'Could not select the required option.', item)
                }
                if (!option) return this.recordOptionalWarning('select_option_not_found', 'Optional selection was skipped because the option was not available.')
                if (option) element.value = option.value
            } else {
                element.value = raw.startsWith('value=') ? raw.slice(6) : raw
            }
            element.dispatchEvent(new Event('input', { bubbles: true }))
            element.dispatchEvent(new Event('change', { bubbles: true }))
            await this.waitForAppIdle({ timeoutMs: this.getStepTimeout(item) })
        }

        async submit(item) {
            this.debugLog('submit', { step: this.step })
            const element = await this.waitForElement(item, this.getStepTimeout(item), 250, { interactable: false })
            if (!element) return this.handleMissingElement(item, 'submit')
            const beforeUrl = window.location.href
            await this.ensureElementInView(element)
            const form = element instanceof HTMLFormElement ? element : element.closest?.('form')
            if (form?.requestSubmit) form.requestSubmit()
            else if (form?.submit) form.submit()
            else {
                // Zest can record submit against a control that is not nested
                // in a native form (for example an SPA search field). Enter is
                // the closest browser-level equivalent; clicking the field
                // merely focuses it and does not submit the recorded action.
                element.focus?.({ preventScroll: true })
                this.dispatchKey(element, 'KEY_ENTER')
            }
            await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
        }

        async scroll(item) {
            this.debugLog('scroll', { step: this.step })
            const hasLocator = this.getLocatorCandidates(item).length > 0
            const rawMode = String(item?.PtkScrollMode || '')
            const mode = ['intoView', 'to', 'by'].includes(rawMode)
                ? rawMode
                : hasLocator ? 'intoView' : 'to'
            const values = String(item?.Data || '0,0').split(',')
            const boundedCoordinate = (value) => Math.max(-1000000, Math.min(1000000, Math.round(Number(value) || 0)))
            const x = boundedCoordinate(Number.isFinite(Number(item?.X)) ? item.X : values[0])
            const y = boundedCoordinate(Number.isFinite(Number(item?.Y)) ? item.Y : values[1])
            if (mode === 'intoView') {
                this.debugLog('scroll_element_wait_start', { step: this.step, mode })
                const element = await this.waitForElement(item, this.getStepTimeout(item), 250, { interactable: false })
                this.debugLog('scroll_element_wait_done', { step: this.step, mode, found: Boolean(element) })
                if (!element) return this.handleMissingElement(item, 'scroll to')
                await this.ensureElementInView(element)
            } else if (mode === 'by') {
                const element = await this.waitForElement(item, this.getStepTimeout(item), 250, { interactable: false })
                if (!element) return this.handleMissingElement(item, 'scroll')
                if (typeof element.scrollBy === 'function') element.scrollBy(x, y)
                else {
                    element.scrollLeft += x
                    element.scrollTop += y
                }
            } else if (hasLocator) {
                const element = await this.waitForElement(item, this.getStepTimeout(item), 250, { interactable: false })
                if (!element) return this.handleMissingElement(item, 'scroll')
                if (typeof element.scrollTo === 'function') element.scrollTo(x, y)
                else {
                    element.scrollLeft = x
                    element.scrollTop = y
                }
            } else {
                window.scrollTo(x, y)
            }
            this.debugLog('scroll_action_done', { step: this.step, mode })
            await this.wait(100)
            const settleTimeout = Math.min(3000, this.getStepTimeout(item))
            this.debugLog('scroll_settle_start', { step: this.step, mode, settleTimeout })
            await Promise.all([
                this.waitForNetworkIdle(250, settleTimeout),
                this.waitForDomIdle(250, settleTimeout)
            ])
            this.debugLog('scroll_settle_done', { step: this.step, mode })
        }

        async waitforelement(item) {
            const element = await this.waitForElement(item, this.getStepTimeout(item), 250, { interactable: false })
            if (!element) this.handleMissingElement(item, 'wait for')
        }

        async asserttext(item) {
            const element = await this.waitForElement(item, this.getStepTimeout(item), 250, { interactable: false })
            if (!element) return this.handleAssertion(item, false, 'The expected element was not found.')
            const actual = String(element.textContent || element.value || '')
            const expected = String(item?.Expected ?? item?.Data ?? '')
            this.handleAssertion(item, this.matchesExpected(actual, expected), 'The expected text was not found.')
        }

        async asserturl(item) {
            const expected = String(item?.Expected ?? item?.Data ?? '')
            this.handleAssertion(item, this.matchesExpected(window.location.href, expected), 'The expected URL was not reached.')
        }

        async assertelement(item) {
            const expected = String(item?.Expected ?? item?.Data ?? 'present').toLowerCase()
            const shouldExist = !['absent', 'not present', 'false'].includes(expected)
            const element = await this.waitForElement(item, shouldExist ? this.getStepTimeout(item) : 250, 50, { interactable: false })
            this.handleAssertion(item, shouldExist ? Boolean(element) : !element, `Expected element to be ${shouldExist ? 'present' : 'absent'}`)
        }

        handleMissingElement(item, operation) {
            const message = `Could not ${operation} the required element.`
            this.debugLog('element_missing', { operation, step: this.step })
            if (this.isRequiredStep(item)) {
                throw this.replayFailure('element_not_found', message, item)
            }
            return this.recordOptionalWarning('element_not_found', `Optional ${operation} step was skipped because its element was not available.`)
        }

        handleAssertion(item, passed, message) {
            if (passed) {
                this.logEvent(null, 'Assertion passed')
                return true
            }
            this.debugLog('assertion_failed', { step: this.step })
            if (this.isRequiredStep(item)) throw this.replayFailure('assertion_failed', message, item)
            this.recordOptionalWarning('assertion_failed', `Optional assertion failed: ${message}`)
            return false
        }

        matchesExpected(actual, expected) {
            const value = String(actual || '')
            const pattern = String(expected || '')
            if (!pattern.includes('*') && !pattern.includes('?')) return value.includes(pattern)
            let expression = '^'
            for (const char of pattern) {
                if (char === '*') expression += '.*'
                else if (char === '?') expression += '.'
                else expression += char.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&')
            }
            return new RegExp(`${expression}$`, 's').test(value)
        }

        async selectwindow(item) {
            const target = item?.data || item?.Data || item?.target || (Array.isArray(item?.targetOptions) ? item.targetOptions[0] : null)
            const targetOptions = item?.targetOptions || item?.targets || []
            this.debugLog('select_window', { step: this.step })
            try {
                const response = await browser.runtime.sendMessage({
                    channel: "ptk_content2background_recorder",
                    type: "select_window",
                    target: target,
                    targetOptions: targetOptions
                })
                if (!response?.success) throw new Error('window_not_found')
                await this.forceViewportRefresh()
            } catch (e) {
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('window_not_found', 'Could not switch to the required browser window.', item)
                }
                return this.recordOptionalWarning('window_not_found', 'Optional window switch was skipped because the window was not available.')
            }
        }

        async hover(item) {
            this.debugLog('hover', { step: this.step })
            const element = await this.waitForElement(item, this.getStepTimeout(item))
            if (!element) {
                return this.handleMissingElement(item, 'hover over')
            }
            try {
                const rect = element.getBoundingClientRect()
                const init = {
                    bubbles: true,
                    cancelable: true,
                    view: window,
                    clientX: rect.left + rect.width / 2,
                    clientY: rect.top + rect.height / 2
                }
                element.dispatchEvent(new MouseEvent('mouseover', init))
                element.dispatchEvent(new MouseEvent('mouseenter', init))
                element.dispatchEvent(new MouseEvent('mousemove', init))
            } catch (e) {
                // ignore
            }
            await this.wait(150)
        }

        async setwindowsize(item) {
            const parsed = this.parseWindowSize(item?.Data || item?.data)
            if (!parsed) {
                this.debugLog('set_window_size_failed', { step: this.step })
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('window_size_invalid', 'The recorded browser window size is invalid.', item)
                }
                return this.recordOptionalWarning('window_size_invalid', 'Optional browser resize was skipped because its dimensions are invalid.')
            }
            this.debugLog('set_window_size', parsed)
            try {
                await browser.runtime.sendMessage({
                    channel: "ptk_content2background_recorder",
                    type: "set_window_size",
                    width: parsed.width,
                    height: parsed.height
                })
                await this.wait(250)
                await this.forceViewportRefresh()
            } catch (e) {
                this.debugLog('set_window_size_error', { step: this.step })
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('window_resize_failed', 'Could not resize the browser window for the required step.', item)
                }
                return this.recordOptionalWarning('window_resize_failed', 'Optional browser resize could not be completed.')
            }
        }

        async javascript(item) {
            if (!item || !item.Data) return
            try {
                const beforeUrl = window.location.href
                const data = item.Data
                const match = data.match(/\}\)\('([^']*)'(?:,\s*`([\s\S]*?)`)?\)/)
                if (!match) {
                    if (this.isRequiredStep(item)) {
                        throw this.replayFailure('legacy_javascript_unreadable', 'Could not interpret the required legacy macro step.', item)
                    }
                    return this.recordOptionalWarning('legacy_javascript_unreadable', 'An optional legacy macro step could not be interpreted.')
                }

                const path = match[1]
                const rawValue = match[2]
                const value = typeof rawValue === 'string'
                    ? rawValue.replace(/\\`/g, '`').replace(/\\\\/g, '\\')
                    : null

                if (value !== null) {
                    await this.type({ ElementPath: 'xpath=', Data: value, Optional: item.Optional, _cssPath: path })
                    return
                }

                const element = await this.waitForElement({ ElementPath: 'xpath=', Optional: item.Optional, _cssPath: path }, this.getStepTimeout(item))
                if (element) {
                    await this.performClick(element)
                    const clickCount = (data.match(/item\.click\(\)/g) || []).length
                    if (clickCount > 1) {
                        await this.performClick(element)
                    }
                    element.dispatchEvent(new Event('resize', { bubbles: true }))
                    await this.waitForAppIdle({ beforeUrl, timeoutMs: this.getStepTimeout(item) })
                } else {
                    return this.handleMissingElement(item, 'click')
                }
            } catch (e) {
                if (e instanceof ReplayStepError) throw e
                if (this.isRequiredStep(item)) {
                    throw this.replayFailure('legacy_javascript_failed', 'Could not complete the required legacy macro step.', item)
                }
                return this.recordOptionalWarning('legacy_javascript_failed', 'An optional legacy macro step could not be completed.')
            }
        }

        getStepTimeout(item) {
            const explicit = Number(item?.TimeoutMs || item?.timeoutMs || 0)
            if (Number.isFinite(explicit) && explicit > 0) return Math.min(explicit, 24 * 60 * 60 * 1000)
            if (!this.isRequiredStep(item)) return 1500
            const base = Math.max(30000, (item?.Duration || 0) * 5)
            return base
        }

        parseWindowSize(raw) {
            if (!raw) return null
            if (typeof raw === 'string') {
                const parts = raw.split(',').map(p => Number(p.trim()))
                if (parts.length >= 2 && parts[0] && parts[1]) {
                    return { width: parts[0], height: parts[1] }
                }
            }
            if (typeof raw === 'object') {
                const width = Number(raw.width)
                const height = Number(raw.height)
                if (width && height) {
                    return { width, height }
                }
            }
            return null
        }

        parseKeyTokens(raw) {
            const tokens = []
            const regex = /\$\{([^}]+)\}/g
            let lastIndex = 0
            let match
            while ((match = regex.exec(raw))) {
                if (match.index > lastIndex) {
                    tokens.push({ type: 'text', value: raw.slice(lastIndex, match.index) })
                }
                tokens.push({ type: 'key', key: match[1] })
                lastIndex = regex.lastIndex
            }
            if (lastIndex < raw.length) {
                tokens.push({ type: 'text', value: raw.slice(lastIndex) })
            }
            return tokens
        }

        insertText(element, text) {
            if (!text) return
            const lastValue = element.value
            const event = new Event('input', { bubbles: true })
            event.simulated = true
            element.value = (element.value || '') + text
            element.defaultValue = element.value
            const tracker = element._valueTracker
            if (tracker) { tracker.setValue(lastValue) }
            element.dispatchEvent(event)
        }

        dispatchKey(element, keyToken) {
            const keyMap = {
                KEY_ENTER: { key: 'Enter', code: 'Enter', keyCode: 13, which: 13 },
                KEY_TAB: { key: 'Tab', code: 'Tab', keyCode: 9, which: 9 },
                KEY_BACKSPACE: { key: 'Backspace', code: 'Backspace', keyCode: 8, which: 8 },
                KEY_DELETE: { key: 'Delete', code: 'Delete', keyCode: 46, which: 46 },
                KEY_ESCAPE: { key: 'Escape', code: 'Escape', keyCode: 27, which: 27 },
                KEY_ESC: { key: 'Escape', code: 'Escape', keyCode: 27, which: 27 },
                KEY_ARROW_LEFT: { key: 'ArrowLeft', code: 'ArrowLeft', keyCode: 37, which: 37 },
                KEY_ARROW_RIGHT: { key: 'ArrowRight', code: 'ArrowRight', keyCode: 39, which: 39 },
                KEY_ARROW_UP: { key: 'ArrowUp', code: 'ArrowUp', keyCode: 38, which: 38 },
                KEY_ARROW_DOWN: { key: 'ArrowDown', code: 'ArrowDown', keyCode: 40, which: 40 }
            }
            const normalized = String(keyToken || '').toUpperCase()
            const def = keyMap[keyToken] || keyMap[normalized] || null
            if (!def) {
                this.insertText(element, `\${${keyToken}}`)
                return
            }
            const payload = { bubbles: true, cancelable: true, ...def }
            element.dispatchEvent(new KeyboardEvent('keydown', payload))
            element.dispatchEvent(new KeyboardEvent('keypress', payload))
            element.dispatchEvent(new KeyboardEvent('keyup', payload))
        }

        _initNetworkTracking() {
            if (this._networkWrapped) return
            this._networkWrapped = true
            this._lastNetworkActivity = Date.now()
            const self = this
            const origFetch = window.fetch
            if (origFetch) {
                window.fetch = function (...args) {
                    self._networkPending++
                    self._lastNetworkActivity = Date.now()
                    return origFetch.apply(this, args)
                        .catch((err) => {
                            throw err
                        })
                        .finally(() => {
                            self._networkPending = Math.max(0, self._networkPending - 1)
                            self._lastNetworkActivity = Date.now()
                        })
                }
            }
            const origOpen = XMLHttpRequest.prototype.open
            const origSend = XMLHttpRequest.prototype.send
            XMLHttpRequest.prototype.open = function (...args) {
                this.__ptk_tracking = true
                return origOpen.apply(this, args)
            }
            XMLHttpRequest.prototype.send = function (...args) {
                if (this.__ptk_tracking) {
                    self._networkPending++
                    self._lastNetworkActivity = Date.now()
                    this.addEventListener('loadend', () => {
                        self._networkPending = Math.max(0, self._networkPending - 1)
                        self._lastNetworkActivity = Date.now()
                    }, { once: true })
                }
                return origSend.apply(this, args)
            }
        }

        async waitForUrl(expected, timeoutMs = 10000) {
            if (!expected) return
            const endAt = Date.now() + timeoutMs
            const normalizedExpected = String(expected)
            while (Date.now() < endAt) {
                if (window.location.href === normalizedExpected) return
                await this.wait(150)
            }
        }

        async waitForNetworkIdle(idleMs = 400, timeoutMs = 10000) {
            const endAt = Date.now() + timeoutMs
            while (Date.now() < endAt) {
                const pending = this._networkPending || 0
                const since = Date.now() - (this._lastNetworkActivity || 0)
                if (pending === 0 && since >= idleMs) return
                await this.wait(100)
            }
        }

        async waitForDomIdle(idleMs = 400, timeoutMs = 10000) {
            const endAt = Date.now() + timeoutMs
            let lastChange = Date.now()
            return new Promise((resolve) => {
                const observer = new MutationObserver(() => {
                    lastChange = Date.now()
                })
                observer.observe(document, { subtree: true, childList: true, attributes: true })
                const timer = setInterval(() => {
                    if (this.cancelled || Date.now() - lastChange >= idleMs || Date.now() > endAt) {
                        clearInterval(timer)
                        observer.disconnect()
                        resolve()
                    }
                }, 100)
            })
        }

        async waitForAppIdle({ beforeUrl = null, timeoutMs = 10000 } = {}) {
            const startUrl = beforeUrl || window.location.href
            let urlChanged = false
            const urlEndAt = Date.now() + Math.min(1500, timeoutMs)
            while (Date.now() < urlEndAt) {
                if (window.location.href !== startUrl) {
                    urlChanged = true
                    break
                }
                await this.wait(100)
            }
            if (urlChanged) {
                await this.waitForUrl(window.location.href, timeoutMs)
            }
            await Promise.all([
                this.waitForNetworkIdle(400, timeoutMs),
                this.waitForDomIdle(400, timeoutMs)
            ])
        }

        getElementByXpath(item) {
            let xpath = item.ElementPath
            xpath = xpath.replace('xpath=', '')
            const externalXpath = Number(item?.PtkXPathIndexBase) === 1
            if (!externalXpath) {
                xpath = xpath.replace(/\[(\d+)\]/g, function (fullMatch, n) { return "[" + (Number(n) + 1) + "]"; })
            }
            if (!xpath.startsWith('/') && !xpath.startsWith('(')) xpath = '/' + xpath
            const exact = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue
            if (exact || !externalXpath) return exact

            // Angular CDK appends transient dialog/menu panes beneath one
            // overlay container. Their generated IDs and body/container
            // indexes depend on which overlays have already opened, so an
            // external recorder's XPath can become stale even though its
            // structural dialog suffix remains valid. Relax only those CDK
            // details and accept a fallback only when all candidates resolve
            // to one interactable control.
            const relaxedXpaths = []
            const appendRelaxed = (candidate) => {
                if (candidate && candidate !== xpath && !relaxedXpaths.includes(candidate)) {
                    relaxedXpaths.push(candidate)
                }
            }
            appendRelaxed(xpath.replace(
                /mat-dialog-container\[@id=(['"])mat-mdc-dialog-\d+\1\]/ig,
                'mat-dialog-container'
            ))
            const dialogSegment = xpath.match(/\/mat-dialog-container(?:\[[^\]]+\])?\/.*$/i)?.[0]
            if (dialogSegment) appendRelaxed(`/${dialogSegment}`)
            appendRelaxed(xpath.replace(
                /^\/html\/body\/div\[\d+\]\/div\[\d+\]\//i,
                '/html/body/div/div/'
            ))
            if (!relaxedXpaths.length) return null
            const candidates = []
            for (const relaxed of relaxedXpaths) {
                const result = document.evaluate(relaxed, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null)
                for (let index = 0; index < result.snapshotLength; index++) {
                    const candidate = this.resolveInteractableElement(this.normalizeElement(result.snapshotItem(index)))
                    if (candidate && !candidates.includes(candidate)) {
                        candidates.push(candidate)
                    }
                }
            }
            return candidates.length === 1 ? candidates[0] : null
        }

        getElementByCss(item) {
            let selector = item.ElementPath.replace('css=', '')
            return this.findElementByCss(selector)
        }

        async waitForElement(item, timeoutMs = 15000, intervalMs = 250, { interactable = true } = {}) {
            const endAt = Date.now() + timeoutMs
            let lastError = null
            let lastSeen = null
            while (Date.now() < endAt) {
                try {
                    const locators = this.getLocatorCandidates(item)
                    for (const locator of locators) {
                        try {
                            item._lastLocator = locator
                            const located = this.normalizeElement(this.getElementByLocator(locator, item))
                            const el = interactable ? this.resolveInteractableElement(located) : located
                            if (el && (!interactable || this.isInteractable(el))) return el
                            if (located) lastSeen = located
                        } catch (error) {
                            // One producer locator can be syntactically invalid
                            // in another engine (for example Katalon's legacy
                            // `link=` selector encoded as CSS). Continue through
                            // the remaining recorded alternatives.
                            lastError = error
                        }
                    }
                } catch (e) {
                    lastError = e
                }
                await this.wait(intervalMs)
            }
            if (item && item._lastLocator) {
                const lastLocator = String(item._lastLocator)
                const exactId = lastLocator.startsWith('id=')
                    ? document.getElementById(lastLocator.slice(3))
                    : null
                this.debugLog('wait_for_element_failed', {
                    step: this.step,
                    locatorType: lastLocator.split('=')[0].slice(0, 20),
                    exactIdPresent: Boolean(exactId),
                    exactIdInteractable: Boolean(this.resolveInteractableElement(exactId))
                })
            }
            if (lastSeen && (!interactable || this.isInteractable(lastSeen))) return lastSeen
            return null
        }

        async waitForUrlChange(timeoutMs = 10000) {
            const startUrl = window.location.href
            const endAt = Date.now() + timeoutMs
            while (Date.now() < endAt) {
                if (window.location.href !== startUrl) {
                    this.debugLog('url_changed', { step: this.step })
                    return true
                }
                await this.wait(150)
            }
            return false
        }

        getLocatorCandidates(item) {
            const candidates = []
            const pushUnique = (value) => {
                if (value && !candidates.includes(value)) {
                    candidates.push(value)
                }
            }
            const normalizeLocator = (value) => {
                if (!value) return null
                const trimmed = String(value).trim()
                if (!trimmed) return null
                if (/^(css|xpath|id|name|class|className|linkText)=/i.test(trimmed)) return trimmed
                if (/^(aria|text|pierce)\//i.test(trimmed)) return trimmed
                if (/^\/|^\.\//.test(trimmed)) return `xpath=${trimmed}`
                return `css=${trimmed}`
            }
            const addFromTargets = (targets) => {
                if (!Array.isArray(targets)) return
                targets.forEach((entry) => {
                    if (Array.isArray(entry)) {
                        pushUnique(normalizeLocator(entry[0]))
                    } else {
                        pushUnique(normalizeLocator(entry))
                    }
                })
            }

            addFromTargets(item?.targetOptions)
            addFromTargets(item?.targets)
            pushUnique(normalizeLocator(item?.target))
            pushUnique(normalizeLocator(item?.ElementPath))
            if (item?._cssPath) {
                pushUnique(normalizeLocator(`css=${item._cssPath}`))
            }
            if (item?.csspath) {
                pushUnique(normalizeLocator(`css=${item.csspath}`))
            }
            if (item?.xpath) {
                pushUnique(normalizeLocator(`xpath=${item.xpath}`))
            }
            if (item?.fullxpath) {
                pushUnique(normalizeLocator(`xpath=${item.fullxpath}`))
            }

            return candidates.filter(Boolean)
        }

        getElementByLocator(locator, replayItem = null) {
            if (!locator) return null
            const value = String(locator)
            if (value.startsWith('id=')) {
                const id = value.slice(3)
                const exact = document.getElementById(id)
                if (exact) return exact
                // Angular Material generates mat-input-N IDs from runtime
                // creation order, which can differ between browsers. Only
                // recover when the current document has one unambiguous,
                // visible Material input candidate.
                if (/^mat-input-\d+$/.test(id)) {
                    const candidates = Array.from(document.querySelectorAll(
                        'input[id^="mat-input-"],textarea[id^="mat-input-"],input.mat-mdc-input-element,textarea.mat-mdc-input-element,input.mat-input-element,textarea.mat-input-element'
                    )).filter((element) => this.isInteractable(element))
                    const unique = [...new Set(candidates)]
                    if (unique.length === 1) return unique[0]
                }
                return null
            }
            if (value.startsWith('name=')) {
                return document.getElementsByName(value.slice(5))[0] || null
            }
            if (value.startsWith('class=') || value.startsWith('className=')) {
                const name = value.startsWith('className=') ? value.slice(10) : value.slice(6)
                return document.getElementsByClassName(name)[0] || null
            }
            if (value.startsWith('linkText=')) {
                const raw = value.slice(9)
                const [text, posPart] = raw.split('@POS=')
                const links = Array.from(document.querySelectorAll('a')).filter(a => (a.innerText || a.textContent || '').trim() === text)
                if (posPart) {
                    const index = Number(posPart) - 1
                    return links[index] || null
                }
                return links[0] || null
            }
            if (value.startsWith('css=')) {
                return this.findElementByCss(value.slice(4))
            }
            if (value.startsWith('pierce/')) {
                return this.findElementByCss(value.slice(7))
            }
            if (value.startsWith('aria/')) {
                const name = value.slice(5)
                return Array.from(document.querySelectorAll('[aria-label],button,a,input,select,textarea'))
                    .find((element) => (element.getAttribute('aria-label') || element.innerText || element.value || '').trim() === name) || null
            }
            if (value.startsWith('text/')) {
                const text = value.slice(5)
                return Array.from(document.querySelectorAll('button,a,label,input,option,[role]'))
                    .find((element) => (element.innerText || element.textContent || element.value || '').trim() === text) || null
            }
            if (value.startsWith('xpath=')) {
                const item = {
                    ElementPath: value,
                    PtkXPathIndexBase: replayItem?.PtkXPathIndexBase
                }
                return this.getElementByXpath(item)
            }
            return this.findElementByCss(value)
        }

        async forceViewportRefresh() {
            try {
                window.dispatchEvent(new Event('resize'))
                window.dispatchEvent(new Event('orientationchange'))
                await new Promise(resolve => requestAnimationFrame(resolve))
                await new Promise(resolve => requestAnimationFrame(resolve))
            } catch (e) {
                // ignore
            }
        }

        debugLog(label, data = {}) {
            if (!this.debugEnabled) return
            const entry = {
                ts: new Date().toISOString(),
                label: label,
                data: data
            }
            try {
                console.debug('[PTK Replay]', entry)
                browser.storage.local.get(['ptk_replay_debug']).then((result) => {
                    const prev = result.ptk_replay_debug || ''
                    const line = JSON.stringify(entry)
                    const next = (prev + line + '\n').slice(-20000)
                    browser.storage.local.set({ ptk_replay_debug: next })
                }).catch(() => {})
            } catch (e) {
                // ignore
            }
        }

        normalizeElement(node) {
            if (!node) return null
            if (node.nodeType === Node.ELEMENT_NODE) return node
            if (node.nodeType === Node.TEXT_NODE) return node.parentElement
            if (node.nodeType === Node.ATTRIBUTE_NODE) return node.ownerElement
            return null
        }

        isElementInViewport(element) {
            if (!element?.getBoundingClientRect) return false
            const rect = element.getBoundingClientRect()
            const doc = element.ownerDocument || document
            const view = doc.defaultView || window
            const height = view.innerHeight || doc.documentElement?.clientHeight || 0
            const width = view.innerWidth || doc.documentElement?.clientWidth || 0
            return rect.top <= height
                && rect.bottom > 0
                && rect.left <= width
                && rect.right > 0
        }

        async ensureElementInView(element) {
            if (!element || this.isElementInViewport(element)) return
            element.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
            await this.wait(50)
        }

        resolveInteractableElement(element) {
            if (!element) return null
            if (this.isInteractable(element)) return element
            const control = element.closest?.('button,a,input,textarea,select,[role="button"]') || null
            return control && this.isInteractable(control) ? control : null
        }

        async performClick(element, clickCount = 1) {
            const target = element.closest?.('button,a,input,textarea,select,[role="button"]') || element
            const owningDialog = target.closest?.('mat-dialog-container,[role="dialog"],dialog') || null
            const isDialogClose = Boolean(owningDialog) && (
                target.classList?.contains('close-dialog')
                || /\b(close|dismiss)\b/i.test(target.getAttribute?.('aria-label') || '')
                || /^\s*(close|dismiss)\s*$/i.test(target.textContent || '')
            )
            const expandedBefore = target.getAttribute?.('aria-expanded')
            const menuToggleWasClosed = target.getAttribute?.('aria-haspopup') === 'menu'
                && expandedBefore === 'false'
            try {
                if (target.scrollIntoView) {
                    target.scrollIntoView({ block: "center", inline: "center", behavior: "instant" })
                }
                target.focus?.({ preventScroll: true })
            } catch (e) {
                // ignore
            }
            const point = this.getClickPoint(target)
            const targetAtPoint = this.isTargetAtClickPoint(target)
            if (point && targetAtPoint) {
                try {
                    const res = await browser.runtime.sendMessage({
                        channel: "ptk_content2background_recorder",
                        type: "debugger_click",
                        x: point.x,
                        y: point.y,
                        clickCount
                    })
                    if (res?.success) {
                        // Treat the browser-visible dialog lifecycle as the
                        // result of a close action. Coordinate drift after a
                        // recorded viewport resize can make CDP acknowledge a
                        // click without activating the intended button.
                        if (isDialogClose && owningDialog?.isConnected && target.isConnected) {
                            await this.wait(150)
                            if (owningDialog.isConnected && target.isConnected) {
                                target.click?.()
                                await this.wait(250)
                            }
                        }
                        // A debugger command can be acknowledged before an SPA
                        // has applied the menu-trigger state change. Confirm a
                        // closed ARIA menu actually opened and retry through the
                        // DOM only when the first click had no observable effect.
                        // This avoids double-toggling controls that did open.
                        if (menuToggleWasClosed) {
                            await this.wait(150)
                            if (target.isConnected && target.getAttribute?.('aria-expanded') === 'false') {
                                target.click?.()
                                await this.wait(150)
                            }
                        }
                        return
                    }
                } catch (e) {
                    // fall back to DOM click
                }
            } else if (point) {
                this.debugLog('click_dom_fallback_obscured', { step: this.step })
            }
            if (typeof target.click === 'function') {
                target.click()
                if (clickCount > 1) {
                    target.click()
                    target.dispatchEvent(new MouseEvent('dblclick', { bubbles: true, cancelable: true, view: window, detail: 2 }))
                }
                return
            }
            if (target.dispatchEvent) {
                target.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, cancelable: true, view: window, pointerType: 'mouse' }))
                target.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, view: window }))
                target.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, cancelable: true, view: window, pointerType: 'mouse' }))
                target.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true, view: window }))
                target.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }))
            }
        }

        isInteractable(element) {
            if (!element || !element.getBoundingClientRect) return false
            const rect = element.getBoundingClientRect()
            if (rect.width <= 0 || rect.height <= 0) return false
            const style = element.ownerDocument?.defaultView?.getComputedStyle?.(element)
            if (style) {
                if (style.visibility === "hidden" || style.display === "none") return false
                if (style.pointerEvents === "none") return false
            }
            return true
        }

        isTargetAtClickPoint(element) {
            if (!element?.getBoundingClientRect) return false
            const rect = element.getBoundingClientRect()
            const x = rect.left + rect.width / 2
            const y = rect.top + rect.height / 2
            const root = element.getRootNode?.()
            const hit = typeof root?.elementFromPoint === 'function'
                ? root.elementFromPoint(x, y)
                : element.ownerDocument?.elementFromPoint?.(x, y)
            if (!hit) return false
            return hit === element
                || element.contains?.(hit)
                || hit.contains?.(element)
                || root?.host === hit
        }

        getClickPoint(element) {
            if (!element?.getBoundingClientRect) return null
            const rect = element.getBoundingClientRect()
            let x = rect.left + rect.width / 2
            let y = rect.top + rect.height / 2
            try {
                let win = element.ownerDocument?.defaultView
                while (win && win.frameElement) {
                    const frameRect = win.frameElement.getBoundingClientRect()
                    x += frameRect.left
                    y += frameRect.top
                    win = win.parent
                }
            } catch (e) {
                return null
            }
            if (x < 0 || y < 0 || x > window.innerWidth || y > window.innerHeight) {
                return null
            }
            if (!Number.isFinite(x) || !Number.isFinite(y)) return null
            return { x, y }
        }

        findElementByCss(selector) {
            let el = this.querySelectorDeep(selector, document)
            if (el) return el
            const frames = document.querySelectorAll('iframe')
            for (const frame of frames) {
                try {
                    const doc = frame.contentDocument
                    if (!doc) continue
                    el = this.querySelectorDeep(selector, doc)
                    if (el) return el
                } catch (e) {
                    // ignore cross-origin frames
                }
            }
            return null
        }

        querySelectorDeep(selector, root) {
            if (!root || !root.querySelector) return null
            let el = this.findBySelectorFallback(selector, root)
            if (el) return el
            const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT)
            let node = walker.currentNode
            while (node) {
                if (node.shadowRoot) {
                    el = this.findBySelectorFallback(selector, node.shadowRoot)
                    if (el) return el
                }
                node = walker.nextNode()
            }
            return null
        }

        findBySelectorFallback(selector, root) {
            let el = root.querySelector(selector)
            if (el) return el
            const normalized = this.normalizeCssSelector(selector)
            if (normalized !== selector) {
                el = root.querySelector(normalized)
                if (el) return el
            }
            const stripped = this.stripNthOfType(selector)
            if (stripped !== selector) {
                el = root.querySelector(stripped)
                if (el) return el
            }
            const normalizedStripped = this.stripNthOfType(normalized)
            if (normalizedStripped !== normalized) {
                el = root.querySelector(normalizedStripped)
                if (el) return el
            }
            const noIds = this.stripIdSelectors(selector)
            if (noIds !== selector) {
                el = root.querySelector(noIds)
                if (el) return el
            }
            const normalizedNoIds = this.stripIdSelectors(normalized)
            if (normalizedNoIds !== normalized) {
                el = root.querySelector(normalizedNoIds)
                if (el) return el
            }

            const parts = selector.split('>').map(part => part.trim()).filter(Boolean)
            if (parts.length < 2) return null

            for (let i = 1; i < parts.length; i++) {
                const candidate = parts.slice(i).join(' > ')
                el = root.querySelector(candidate)
                if (el) return el
                const normalizedCandidate = this.normalizeCssSelector(candidate)
                if (normalizedCandidate !== candidate) {
                    el = root.querySelector(normalizedCandidate)
                    if (el) return el
                }
                const strippedCandidate = this.stripNthOfType(candidate)
                if (strippedCandidate !== candidate) {
                    el = root.querySelector(strippedCandidate)
                    if (el) return el
                }
                const normalizedStrippedCandidate = this.stripNthOfType(normalizedCandidate)
                if (normalizedStrippedCandidate !== normalizedCandidate) {
                    el = root.querySelector(normalizedStrippedCandidate)
                    if (el) return el
                }
                const noIdsCandidate = this.stripIdSelectors(candidate)
                if (noIdsCandidate !== candidate) {
                    el = root.querySelector(noIdsCandidate)
                    if (el) return el
                }
                const normalizedNoIdsCandidate = this.stripIdSelectors(normalizedCandidate)
                if (normalizedNoIdsCandidate !== normalizedCandidate) {
                    el = root.querySelector(normalizedNoIdsCandidate)
                    if (el) return el
                }
            }

            return null
        }

        normalizeCssSelector(selector) {
            return selector.replace(/(^|[\s>+~])([A-Z][A-Z0-9-]*)/g, (match, prefix, tag) => {
                return prefix + tag.toLowerCase()
            })
        }

        stripNthOfType(selector) {
            return selector.replace(/:nth-of-type\(\d+\)/g, '')
        }

        stripIdSelectors(selector) {
            return selector
                .replace(/\[id="[^"]*"\]/g, '')
                .replace(/#[A-Za-z0-9_-]+/g, '')
        }

    }

    window.__ptkReplayerRuntime = Object.freeze({
        create: () => new ptk_replayer()
    })
    window.ptk_replayer = window.__ptkReplayerRuntime.create()


    window.addEventListener("message", async (event) => {
        const data = event?.data
        const replayer = window.ptk_replayer
        if (!data || typeof data !== 'object' || Array.isArray(data) || !replayer?.sessionId) return

        if (data.channel === 'ptk_replayer_ready' && data.message === 'frame_ready') {
            replayer.registerFrameRoute(event)
            return
        }

        if (data.channel === 'ptk_replayer_ack' && data.message === 'step_complete') {
            replayer.resolveFrameAck(event, data)
            return
        }

        if (isIframe && data.channel === '2frame' && data.message === 'doStep') {
            if (!isExpectedParentMessage(event)) return
            const item = await replayer.getApprovedMessageItem(data)
            if (item) {
                try {
                    replayer.step = data.step
                    await replayer.executeFrame(item, Number(data.routeDepth || 0))
                    replayer.sendFrameAck(event, data)
                } catch (error) {
                    replayer.sendFrameAck(event, data, {
                        success: false,
                        errorCode: error instanceof ReplayStepError ? error.code : 'frame_step_failed'
                    })
                }
            }
            return
        }

    })

    browser.runtime.onMessage.addListener(async (message) => {
        const replayer = window.ptk_replayer
        if (message?.channel !== 'ptk_background2content_recorder' || !replayer?.sessionId) return
        if (message.type === 'replay_cancel') {
            if (message.sessionId !== replayer.sessionId) return Promise.resolve({ success: false })
            replayer.cancelReplay()
            return Promise.resolve({ success: true })
        }
        if (message.type !== 'replay_step' || replayer.cancelled) return
        try {
            const item = await replayer.getApprovedMessageItem(message)
            if (!item) return Promise.resolve({ success: false })
            replayer.step = message.step
            if (String(item.ElementPath || '').includes('//IFRAME')) {
                await replayer.executeFrame(item, Number(message.routeDepth || 0))
            } else {
                await replayer.doStep(message.step, item)
            }
            return Promise.resolve({ success: !replayer.cancelled })
        } catch (error) {
            if (replayer.cancelled || isReplayCancelledError(error)) {
                return Promise.resolve({ success: false, stopped: true })
            }
            return Promise.resolve({
                success: false,
                errorCode: error instanceof ReplayStepError ? error.code : 'replay_step_failed'
            })
        }
    })

})()
