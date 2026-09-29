/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger } from "./utils.js"
import { sensitiveArtifactStorage as ptk_storage } from "./sensitiveArtifactStore.js"
import { RequestBuilderModel } from "./requestBuilder/model.js"
import { RequestBuilderTransport } from "./requestBuilder/transport.js"

const worker = globalThis.self || globalThis

export class ptk_request_manager {

    constructor(settings) {
        this.storageKey = 'ptk_rbuilder'
        this.storage = {}
        this.settings = settings
        this.storageEpoch = 0
        this.storageMutation = Promise.resolve()
        this.initPromise = this.init()
        this.addMessageListeners()
    }

    async init() {
        this.storage = await ptk_storage.getItem(this.storageKey)
        return this.storage
    }

    _queueStorageMutation(callback) {
        const run = async () => {
            await this.initPromise
            return callback()
        }
        const result = this.storageMutation.then(run, run)
        this.storageMutation = result.catch(() => {})
        return result
    }

    async _captureStorageEpoch() {
        await this.initPromise
        await this.storageMutation
        return this.storageEpoch
    }

    _mutateStorageIfCurrent(epoch, callback) {
        return this._queueStorageMutation(async () => {
            if (epoch !== this.storageEpoch) return false
            await callback()
            return true
        })
    }

    _storeScanResult(formId, scanResult, epoch) {
        return this._mutateStorageIfCurrent(epoch, async () => {
            if (!this.storage?.[formId]) return
            this.storage[formId].scanResult = scanResult
            await ptk_storage.setItem(this.storageKey, this.storage)
        })
    }

    async clear(index) {
        return this._queueStorageMutation(async () => {
            if (index !== undefined && index !== null) {
                delete this.storage[index]
                await ptk_storage.setItem(this.storageKey, this.storage)
            } else {
                this.storageEpoch += 1
                this.storage = {}
                await ptk_storage.removeItem(this.storageKey)
            }
            return JSON.parse(JSON.stringify(this.storage))
        })
    }

    findLastIndex(obj, requestId) {
        let l = obj.length
        while (l--) {
            if (obj[l].requestId == requestId) return l
        }
        return -1
    }

    /* Listeners */

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    onMessage(message, sender, sendResponse) {
        if (message?.channel !== "ptk_popup2background_request") return undefined
        if (!ptk_utils.isTrustedExtensionPageSender(sender)) {
            return Promise.resolve({ result: false, error: 'untrusted_extension_sender' })
        }
        if (this["msg_" + message.type]) return this["msg_" + message.type](message)
        return Promise.resolve({ result: false })
    }

    resort(storage) {
        let i = 0
        Object.keys(storage).sort(function (a, b) { return storage[a].sort - storage[b].sort }).forEach(function (key) {
            storage[key].sort = i
            i++
        })
        return storage
    }

    async msg_init(message) {
        return this._queueStorageMutation(async () => {
            this.storage = await ptk_storage.getItem(this.storageKey)
            this.storage = this.storage ? this.resort(this.storage) : []
            return JSON.parse(JSON.stringify(this.storage))
        })
    }

    async msg_clear(message) {
        await this.clear(message.index)
    }

    async msg_reset_all(message) {
        await this.clear()
        return { success: true }
    }

    async msg_parse_request(message) {
        let rbObj = ptk_request.parseRawRequest(message.raw, message.opts)
        const admittedEpoch = message.formId ? await this._captureStorageEpoch() : null
        if (message.formId) {
            await this._mutateStorageIfCurrent(admittedEpoch, async () => {
                if (!this.storage[message.formId]) {
                    this.storage[message.formId] = rbObj
                    this.storage[message.formId].sort = Object.keys(this.storage).length
                } else {
                    this.storage[message.formId].opts = message.opts
                    this.storage[message.formId].request = rbObj.request
                }
                await ptk_storage.setItem(this.storageKey, this.storage)
            })
        }
        return Promise.resolve(rbObj)
    }

    async msg_update_request(message) {
        let rbObj = ptk_request.updateRawRequest(message.schema, message.params, message.opts)
        const admittedEpoch = await this._captureStorageEpoch()
        if (message.formId) {
            await this._mutateStorageIfCurrent(admittedEpoch, async () => {
                if (!this.storage[message.formId]) {
                    this.storage[message.formId] = rbObj
                    this.storage[message.formId].sort = Object.keys(this.storage).length
                } else {
                    this.storage[message.formId].opts = message.opts
                    this.storage[message.formId].request = rbObj.request
                }
                await ptk_storage.setItem(this.storageKey, this.storage)
            })
        }
        return Promise.resolve(rbObj)
    }

    async msg_delete_request(message) {
        await this._queueStorageMutation(async () => {
            if (!this.storage[message.formId]) return
            delete this.storage[message.formId]
            await ptk_storage.setItem(this.storageKey, this.resort(this.storage))
        })
        return Promise.resolve(JSON.parse(JSON.stringify(this.storage)))
    }

    async msg_send_request(message) {
        let request = new ptk_request()
        request.isolatedRedirectSession = true
        request.isolatedPreserveRawHeaders = true
        if (message.useListeners) request.useListeners = true
        const admittedEpoch = message.formId ? await this._captureStorageEpoch() : null
        return request.sendRequest(message.schema).then(async response => {
            if (message.formId) {
                await this._mutateStorageIfCurrent(admittedEpoch, async () => {
                    if (!this.storage[message.formId]) {
                        this.storage[message.formId] = { sort: Object.keys(this.storage).length }
                    }
                    const sort = typeof this.storage[message.formId].sort === "number"
                        ? this.storage[message.formId].sort
                        : Object.keys(this.storage).length
                    this.storage[message.formId] = response
                    this.storage[message.formId].sort = sort
                    delete this.storage[message.formId].scanResult
                    await ptk_storage.setItem(this.storageKey, this.storage)
                })
            }
            return Promise.resolve(response)
        })
    }

    async msg_scan_request(message) {
        try {
            let rawRequest = message?.schema?.request?.raw || message?.raw || null
            const dastApp = worker.ptk_app?.rattacker || worker.ptk_app?.dast || null
            const scanFn = dastApp?.engine?.onetimeScanRequest
            if (typeof scanFn !== 'function') throw new Error('dast_engine_not_available')
            if (!rawRequest) throw new Error('scan_request_raw_missing')
            const requestManager = worker.ptk_app?.request_manager || null
            const admittedEpoch = typeof requestManager?._captureStorageEpoch === 'function'
                ? await requestManager._captureStorageEpoch()
                : null
            const requestUrl = String(message?.schema?.request?.url || '').trim()
            if (requestUrl && !/^[a-z][a-z0-9+.-]*:\/\//iu.test(requestUrl)) {
                const requestHeaders = Array.isArray(message?.schema?.request?.headers)
                    ? message.schema.request.headers
                    : []
                const host = String(
                    message?.schema?.request?.host
                    || requestHeaders.find((header) => String(header?.name || '').toLowerCase() === 'host')?.value
                    || ''
                ).trim()
                if (!host || host === 'unspecified-host') throw new Error('scan_request_host_missing')
                const scheme = String(message?.schema?.request?.scheme || 'http').replace(/:$/u, '')
                const scanSchema = JSON.parse(JSON.stringify(message.schema))
                scanSchema.request.url = new URL(requestUrl, `${scheme}://${host}`).toString()
                rawRequest = ptk_request.updateRawRequest(scanSchema, null, scanSchema.opts).request.raw
            }
            const scanResult = await scanFn.call(dastApp.engine, rawRequest, true)
            const cloned = JSON.parse(JSON.stringify(scanResult))
            if (typeof requestManager?._storeScanResult === 'function') {
                await requestManager._storeScanResult(message.formId, cloned, admittedEpoch)
            } else if (requestManager?.storage?.[message.formId]) {
                requestManager.storage[message.formId].scanResult = cloned
                await ptk_storage.setItem(requestManager.storageKey, requestManager.storage)
            }
            await browser.runtime.sendMessage({
                channel: "ptk_background2popup_rbuilder",
                type: "scan completed",
                scanResult: cloned
            }).catch(e => ptk_logger.log(e, "Could not send a message", "info"))
            return Promise.resolve({ success: true, scanResult: cloned })
        } catch (error) {
            const detail = error?.message || String(error)
            await browser.runtime.sendMessage({
                channel: "ptk_background2popup_rbuilder",
                type: "scan_failed",
                error: detail
            }).catch(e => ptk_logger.log(e, "Could not send a failure message", "info"))
            throw error
        }
    }

    async msg_sync_storage(message) {
        const admittedEpoch = await this._captureStorageEpoch()
        if (message.storage) {
            await this._mutateStorageIfCurrent(admittedEpoch, async () => {
                this.storage = this.resort(message.storage)
                await ptk_storage.setItem(this.storageKey, this.storage)
            })
        }
        return Promise.resolve(JSON.parse(JSON.stringify(this.storage)))
    }

    /* End Listeners */

}

export class ptk_request extends RequestBuilderTransport {
    static get _dnrLock() {
        return RequestBuilderTransport._dnrLock
    }

    static set _dnrLock(value) {
        RequestBuilderTransport._dnrLock = value
    }

    static get _storedHeaderMap() {
        return RequestBuilderTransport._storedHeaderMap
    }

    static set _storedHeaderMap(value) {
        RequestBuilderTransport._storedHeaderMap = value
    }

    static get _storedHeaderTtlMs() {
        return RequestBuilderTransport._storedHeaderTtlMs
    }

    static set _storedHeaderTtlMs(value) {
        RequestBuilderTransport._storedHeaderTtlMs = value
    }

    static clearStoredHeaders() {
        return RequestBuilderTransport.clearStoredHeaders()
    }

    static _purgeStoredHeaders(now = Date.now()) {
        return RequestBuilderTransport._purgeStoredHeaders(now)
    }

    static _cloneHeader(header = {}) {
        return RequestBuilderTransport._cloneHeader(header)
    }

    static _parseCookieHeader(value) {
        return RequestBuilderTransport._parseCookieHeader(value)
    }

    static _mergeCookieHeaderValues(liveValue, storedValue) {
        return RequestBuilderTransport._mergeCookieHeaderValues(liveValue, storedValue)
    }

    static _mergeFirefoxListenerHeaders(liveHeaders, storedHeaders, opts = {}) {
        return RequestBuilderTransport._mergeFirefoxListenerHeaders(liveHeaders, storedHeaders, opts)
    }

    static _withDnrLock(fn) {
        return RequestBuilderTransport._withDnrLock(fn)
    }

    static rbuilderScheme() {
        return RequestBuilderModel.rbuilderScheme()
    }

    static getParsedRaw(request) {
        return RequestBuilderModel.getParsedRaw(request)
    }

    static _hasRawUrlencodedParams(params) {
        return RequestBuilderModel._hasRawUrlencodedParams(params)
    }

    static _serializeUrlencodedParam(param) {
        return RequestBuilderModel._serializeUrlencodedParam(param)
    }

    static serializeUrlencodedParams(params) {
        return RequestBuilderModel.serializeUrlencodedParams(params)
    }

    static _isMultipartBody(body = null) {
        return RequestBuilderModel._isMultipartBody(body)
    }

    static serializeMultipartParams(params, boundary) {
        return RequestBuilderModel.serializeMultipartParams(params, boundary)
    }

    static updateRawRequest(schema, params, opts) {
        return RequestBuilderModel.updateRawRequest(schema, params, opts)
    }

    static fingerprintRawRequest(raw) {
        return RequestBuilderModel.fingerprintRawRequest(raw)
    }

    static _fallbackFingerprint(raw) {
        return RequestBuilderModel._fallbackFingerprint(raw)
    }

    static _bodyFingerprint(body) {
        return RequestBuilderModel._bodyFingerprint(body)
    }

    static _collectJsonPaths(value, prefix, acc) {
        return RequestBuilderModel._collectJsonPaths(value, prefix, acc)
    }

    static parseRawRequest(raw, opts) {
        return RequestBuilderModel.parseRawRequest(raw, opts)
    }

    static normalizeHeaders(schema, opts) {
        return RequestBuilderModel.normalizeHeaders(schema, opts)
    }
}
