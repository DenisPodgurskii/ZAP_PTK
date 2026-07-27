/* Author: Denis Podgurskii */
import { getSearchParamsFromUrlOrHash } from "../dast/urlUtils.js"
import { requestBuilderRawHttpCodec } from "./httpZRawHttpCodec.js"
import {
    encodeMultipartHeaderParameter,
    normalizeMultipartBoundary,
    normalizeMultipartContentType,
    normalizeMultipartDispositionType
} from "./multipartEncoding.js"

export class RequestBuilderModel {
    static codec = requestBuilderRawHttpCodec

    static rbuilderScheme() {
        return {
            sort: 0,
            opts: {
                "title": "",
                "override_headers": true,
                "follow_redirect": true,
                "update_content_length": true,
                "use_content_type": true
            },
            request: {

            },
            response: {
                headers: [],
                statusLine: '',
                statusCode: '',
                body: ''
            }
        }
    }

    static getParsedRaw(request) {
        let raw = ""
        if (request.split(/\r?\n\r?\n/).length > 1)
            raw = request.split(/\r?\n/).join('\r\n')
        else
            raw = request.split(/\r?\n/).concat(['\r\n']).join('\r\n')

        return raw
    }

    static _hasRawUrlencodedParams(params) {
        return Array.isArray(params) && params.some(
            (param) => param?.__ptkRawMode === 'append_suffix'
        )
    }

    static _serializeUrlencodedParam(param) {
        const name = String(param?.name ?? '')
        if (param?.__ptkRawMode === 'append_suffix') {
            const base = typeof param.__ptkRawBase === 'undefined'
                ? String(param?.value ?? '')
                : String(param.__ptkRawBase)
            const pair = new URLSearchParams([[name, base]]).toString()
            return `${pair}${String(param.__ptkRawSuffix ?? '')}`
        }
        return new URLSearchParams([[name, String(param?.value ?? '')]]).toString()
    }

    static serializeUrlencodedParams(params) {
        if (!Array.isArray(params)) return ''
        return params.map((param) => RequestBuilderModel._serializeUrlencodedParam(param)).join('&')
    }

    static _isMultipartBody(body = null) {
        const contentType = String(body?.contentType || body?.mimeType || '').toLowerCase()
        return contentType.includes('multipart/form-data')
            || (
                Array.isArray(body?.params)
                && typeof body?.boundary === 'string'
                && body.boundary.length > 0
            )
    }

    static serializeMultipartParams(params, boundary) {
        const safeBoundary = normalizeMultipartBoundary(boundary)
        if (!Array.isArray(params) || !params.length || !safeBoundary) return ''
        return params.map((param) => {
            let part = `--${safeBoundary}\r\n`
            part += `Content-Disposition: ${normalizeMultipartDispositionType(param?.type)}`
            if (param?.name) {
                part += `; name="${encodeMultipartHeaderParameter(param.name)}"`
            }
            if (param?.fileName) {
                part += `; filename="${encodeMultipartHeaderParameter(param.fileName)}"`
            }
            part += `\r\n`
            const contentType = normalizeMultipartContentType(param?.contentType)
            if (contentType) {
                part += `Content-Type: ${contentType}\r\n`
            }
            part += `\r\n`
            part += String(param?.value ?? '')
            part += `\r\n`
            return part
        }).join('') + `--${safeBoundary}--`
    }

    static updateRawRequest(schema, params, opts) {
        if (!opts) opts = schema.opts
        else schema.opts = opts

        if (params) {
            let url = params.request_protocol + '://' + params.request_url.replace(/^https?:\/\//, '')
            schema.request.scheme = params.request_protocol
            schema.request.method = params.request_method
            schema.request.url = url
        }

        RequestBuilderModel.normalizeHeaders(schema, opts)
        let requestForRaw = schema.request
        if (RequestBuilderModel._hasRawUrlencodedParams(schema?.request?.body?.params)) {
            const rawBody = schema.request.body?.text || RequestBuilderModel.serializeUrlencodedParams(schema.request.body.params)
            requestForRaw = Object.assign({}, schema.request, {
                body: Object.assign({}, schema.request.body, {
                    text: rawBody,
                    contentType: 'text/plain'
                })
            })
        }
        schema.request.raw = RequestBuilderModel.codec.buildRequest(requestForRaw, opts)
        return schema
    }

    static fingerprintRawRequest(raw) {
        if (!raw) return ''
        try {
            const schema = RequestBuilderModel.parseRawRequest(raw)
            const req = schema.request || {}
            const method = (req.method || 'GET').toUpperCase()
            const scheme = req.scheme || (req.request?.scheme) || 'http'
            const baseHost = req.host || req.headers?.find(h => (h.name || '').toLowerCase() === 'host')?.value || 'localhost'
            const needsBase = !(req.url || '').startsWith('http')
            const base = `${scheme}://${baseHost}`
            const urlObj = new URL(req.url || '/', needsBase ? base : undefined)
            const protocol = (urlObj.protocol || 'http:').replace(':', '').toLowerCase()
            const host = (urlObj.host || '').toLowerCase()
            let pathname = urlObj.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            pathname = pathname.replace(/\/+/g, '/')

            const queryNames = new Set()
            if (Array.isArray(req.queryParams)) {
                req.queryParams.forEach(param => {
                    const name = param?.name
                    if (name) queryNames.add(name.toLowerCase())
                })
            } else {
                urlObj.searchParams.forEach((_, key) => queryNames.add(key.toLowerCase()))
            }
            const querySig = Array.from(queryNames).sort().join('&')
            const bodySig = RequestBuilderModel._bodyFingerprint(req.body)

            const parts = [
                protocol,
                host,
                pathname,
                method
            ]
            if (querySig) parts.push(`q:${querySig}`)
            if (bodySig) parts.push(`b:${bodySig}`)
            return parts.join('|')
        } catch (err) {
            return RequestBuilderModel._fallbackFingerprint(raw)
        }
    }

    static _fallbackFingerprint(raw) {
        try {
            const firstLine = raw.split(/\r?\n/)[0] || ''
            const parts = firstLine.trim().split(/\s+/)
            const method = (parts[0] || 'GET').toUpperCase()
            const urlStr = parts[1] || '/'
            const urlObj = new URL(urlStr, urlStr.startsWith('http') ? undefined : 'http://localhost')
            const host = (urlObj.host || '').toLowerCase()
            let pathname = urlObj.pathname || '/'
            if (!pathname.startsWith('/')) pathname = '/' + pathname
            pathname = pathname.replace(/\/+/g, '/')
            const queryNames = new Set()
            urlObj.searchParams.forEach((_, key) => queryNames.add(key.toLowerCase()))
            const querySig = Array.from(queryNames).sort().join('&')
            const partsOut = ['http', host, pathname, method]
            if (querySig) partsOut.push(`q:${querySig}`)
            return partsOut.join('|')
        } catch (_) {
            try {
                return raw.split(/\r?\n/)[0]?.trim() || raw
            } catch {
                return raw || ''
            }
        }
    }

    static _bodyFingerprint(body) {
        if (!body) return ''

        if (Array.isArray(body.params) && body.params.length) {
            return body.params
                .map(p => (p?.name || '').toLowerCase())
                .filter(Boolean)
                .sort()
                .join('&')
        }

        if (body.json && typeof body.json === 'object') {
            const jsonPaths = []
            RequestBuilderModel._collectJsonPaths(body.json, '', jsonPaths)
            if (jsonPaths.length) {
                return jsonPaths.sort().join('&')
            }
        }

        if (typeof body.text === 'string' && body.text.length) {
            const mime = (body.mimeType || '').toLowerCase()
            const looksForm = mime.includes('application/x-www-form-urlencoded') || /[=&]/.test(body.text)
            if (looksForm) {
                try {
                    const usp = new URLSearchParams(body.text)
                    const keys = Array.from(usp.keys()).map(key => key.toLowerCase())
                    if (keys.length) return keys.sort().join('&')
                } catch { /* ignore malformed urlencoded bodies */ }
            }

            try {
                const json = JSON.parse(body.text)
                const jsonPaths = []
                RequestBuilderModel._collectJsonPaths(json, '', jsonPaths)
                if (jsonPaths.length) {
                    return jsonPaths.sort().join('&')
                }
            } catch { /* not json */ }
        }

        return ''
    }

    static _collectJsonPaths(value, prefix, acc) {
        if (value === null || value === undefined) {
            if (prefix) acc.push(prefix)
            return
        }
        if (Array.isArray(value)) {
            value.forEach((item, index) => {
                const next = prefix ? `${prefix}[${index}]` : `[${index}]`
                if (item !== null && typeof item === 'object') {
                    RequestBuilderModel._collectJsonPaths(item, next, acc)
                } else {
                    acc.push(next)
                }
            })
            return
        }
        if (typeof value === 'object') {
            const keys = Object.keys(value)
            if (!keys.length) {
                if (prefix) acc.push(prefix)
                return
            }
            keys.forEach(key => {
                const next = prefix ? `${prefix}.${key}` : key
                const item = value[key]
                if (item !== null && typeof item === 'object') {
                    RequestBuilderModel._collectJsonPaths(item, next, acc)
                } else {
                    acc.push(next)
                }
            })
            return
        }
        if (prefix) acc.push(prefix)
    }

    static parseRawRequest(raw, opts) {
        let schema = RequestBuilderModel.rbuilderScheme()
        if (!opts) opts = schema.opts
        else schema.opts = opts

        schema.request = RequestBuilderModel.codec.parseRequest(RequestBuilderModel.getParsedRaw(raw), opts)
        schema.request.scheme = schema.request.url.startsWith('https://') ? 'https' : 'http'

        try {
            const parsedUrl = new URL(schema.request.url)
            const pathname = parsedUrl.pathname || '/'
            const target = `${pathname}${parsedUrl.search || ''}`
            if (!schema.request.path) {
                schema.request.path = pathname
            }
            if (!schema.request.target) {
                schema.request.target = target
            }
        } catch (_) {
            if (!schema.request.path && typeof schema.request.target === 'string') {
                schema.request.path = schema.request.target.split('?')[0] || '/'
            }
            if (!schema.request.target && typeof schema.request.path === 'string') {
                schema.request.target = schema.request.path
            }
        }

        RequestBuilderModel.normalizeHeaders(schema, opts)
        schema.request.raw = RequestBuilderModel.codec.buildRequest(schema.request, opts)
        const urlForParams = opts?.ui_url || schema.request.url
        const params = getSearchParamsFromUrlOrHash(urlForParams)
        schema.request.queryParams = []
        params.forEach((value, name) => {
            schema.request.queryParams.push({ name, value })
        })
        schema.request.ui_url = urlForParams
        return schema
    }

    static normalizeHeaders(schema, opts) {
        let cacheControl = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "cache-control" });
        if (cacheControl == -1) {
            schema.request.headers.push({
                "name": "Cache-Control",
                "value": "no-cache"
            })
        } else {
            schema.request.headers[cacheControl].value = "no-cache"
        }

        let pragmaControl = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "pragma" });
        if (pragmaControl == -1) {
            schema.request.headers.push({
                "name": "Pragma",
                "value": "no-cache"
            })
        } else {
            schema.request.headers[pragmaControl].value = "no-cache"
        }

        if (schema.request.host == 'unspecified-host') {
            try {
                let url = new URL(schema.request.url)
                schema.request.host = url.host
            } catch (e) {
                throw new Error('Host header not defined. Use an absolute URL or add "Host" header.')
            }
        }
        if (schema.request.headers.findIndex(x => x.name.toLowerCase() == 'host') < 0) {
            schema.request.headers.push({ name: 'Host', value: schema.request.host })
        }

        const transportMode = String(opts?.transport_mode || '').toLowerCase()
        if (transportMode !== 'smuggling_h1' && opts?.update_content_length != false) {
            if (["POST", "PUT", "DELETE", "PATCH"].includes(schema.request.method)) {
                let contentLengthIndex = schema.request.headers.findIndex(obj => { return obj.name.toLowerCase() == "content-length" })
                let contentLengthVal = 0
                if (schema.request.body?.params) {
                    const encodedBody = RequestBuilderModel._isMultipartBody(schema.request.body)
                        ? RequestBuilderModel.serializeMultipartParams(schema.request.body.params, schema.request.body.boundary)
                        : (
                            RequestBuilderModel._hasRawUrlencodedParams(schema.request.body.params)
                                ? RequestBuilderModel.serializeUrlencodedParams(schema.request.body.params)
                                : (new URLSearchParams(schema.request.body.params.map(x => `${x.name}=${x.value}`).join('&'))).toString()
                        )
                    schema.request.bodySize = encodedBody.length
                    contentLengthVal = encodedBody.length
                } else if (schema.request.body?.text) {
                    contentLengthVal = schema.request.body.text.toString().length
                }
                schema.request.bodySize = contentLengthVal
                if (contentLengthIndex < 0) {
                    schema.request.headers.push({
                        "name": "Content-Length",
                        "value": contentLengthVal.toString()
                    })
                } else {
                    schema.request.headers[contentLengthIndex].value = contentLengthVal.toString()
                }
            }
        }
    }
}
