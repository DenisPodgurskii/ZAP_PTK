/* Author: Denis Podgurskii */
import { ptk_utils } from "../../utils.js"
import { jsonLogic } from '../../lib/json-logic-js.js'
import { getBundledDastWordlist } from "../bundledWordlists.js"

const MAX_ACTION_VALUE_LIST_VARIANTS = 32
const ACTION_VALUE_FROM_TRANSFORMS = Object.freeze(new Set(["trim", "lowercase", "uppercase"]))

export function normalizeRequestContextPath(rawPath) {
    const originalPath = typeof rawPath === 'string' && rawPath.length ? rawPath : '/'
    const normalizedRaw = originalPath.startsWith('/') ? originalPath : `/${originalPath}`
    const clean = normalizedRaw.replace(/\/+/g, '/')
    const parts = clean.split('/')
    let uncertain = false
    const normalizedParts = parts.map((part, index) => {
        if (index === 0 || !part) return part
        if (/^\d+$/.test(part)) return '{int}'
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(part)) return '{uuid}'
        if (/^[0-9a-f]{32,}$/i.test(part)) return '{hex}'
        if (/^[A-Za-z0-9_-]{12,}$/.test(part) && /[A-Za-z]/.test(part) && /\d/.test(part)) {
            uncertain = true
        }
        return part
    })
    const normalizedPath = uncertain ? clean : (normalizedParts.join('/') || '/')
    return { normalizedPath, uncertain }
}

export function deriveRequestContextSurface(attacked) {
    if (typeof attacked === 'string') {
        return { sourceType: 'unknown', targetName: attacked }
    }
    const location = String(attacked?.location || '').toLowerCase()
    const name = String(attacked?.name || '')
    if (location === 'query') return { sourceType: 'param:query', targetName: name || '*' }
    if (location === 'form' || location === 'body') return { sourceType: 'param:form', targetName: name || '*' }
    if (location === 'cookie') return { sourceType: 'cookie', targetName: name || '*' }
    if (location === 'header') return { sourceType: 'header', targetName: name || '*' }
    if (location === 'json') return { sourceType: 'json', targetName: name || '*' }
    if (location === 'xml') return { sourceType: 'xml', targetName: name || '*' }
    return { sourceType: 'unknown', targetName: name || '*' }
}

export function buildRequestContextKey({ method, normalizedPath, sourceType, targetName }) {
    const m = String(method || 'GET').toUpperCase()
    const p = String(normalizedPath || '/')
    const s = String(sourceType || 'unknown')
    const t = String(targetName || '*')
    return `${m}|${p}|${s}|${t}`
}

export class ptk_module {
    constructor(module) {
        Object.assign(this, module)

        // You can keep strings and/or RegExp here
        this.nonAttackParams = ['csrf', '_csrf', /^x-.*-token$/i, /^ptk_/i]
        this.scanControls = null
        this._selectorSkipStats = Object.create(null)
        this._selectorSelectionDiagnostics = []
        this._requestSurfaceCache = new WeakMap()
        this._candidateEvaluationCache = new WeakMap()
        this._attackOriginalRequirementsCache = new Map()

        jsonLogic.add_operation("regex", this.op_regex)
        jsonLogic.add_operation("proof", this.op_proof)
    }

    _moduleExecutionConfig() {
        return this?.metadata?.execution && typeof this.metadata.execution === 'object'
            ? this.metadata.execution
            : {}
    }

    _moduleTaxonomyConfig() {
        return this?.metadata?.taxonomy && typeof this.metadata.taxonomy === 'object'
            ? this.metadata.taxonomy
            : {}
    }

    _moduleRuntimeConfig() {
        return this?.runtime && typeof this.runtime === 'object'
            ? this.runtime
            : {}
    }

    _attackRuntimeConfig(attack, key) {
        const runtime = attack?.runtime
        if (runtime?.config && typeof runtime.config === 'object' && runtime.config[key] && typeof runtime.config[key] === 'object') {
            return runtime.config[key]
        }
        return null
    }

    _attackRequestGrouping(attack) {
        const grouping = String(attack?.requestGrouping || '').toLowerCase()
        if (grouping === 'bulk' || grouping === 'per_target') {
            return grouping
        }
        return 'inherit'
    }

    _applyAttackOptions(schema, attack) {
        if (!schema || typeof schema !== 'object') return schema
        const optionMap = attack?.action?.options
        if (!optionMap || typeof optionMap !== 'object') return schema
        schema.opts = schema.opts || {}
        Object.assign(schema.opts, this._clone(optionMap))
        return schema
    }

    _shouldUseStrictCookieOverride(attack, mutations = []) {
        if (String(this?.id || '').toLowerCase() !== 'jwt_injection') {
            return false
        }
        return Array.isArray(mutations) && mutations.some((mutation) => mutation?.location === 'cookie')
    }

    /* ---------------- json-logic helpers ---------------- */

    op_regex(obj, pattern) {
        let success = false
        pattern = new RegExp(pattern, "gmi")
        if (Array.isArray(obj)) {
            Object.entries(obj).forEach(([_key, _value]) => {
                if (pattern.test(JSON.stringify(_value))) {
                    success = true
                }
            })
        } else {
            success = pattern.test(obj)
        }
        return success
    }

    op_proof(obj, pattern) {
        let proof = ""
        pattern = new RegExp(pattern, "gmi")
        if (Array.isArray(obj)) {
            Object.entries(obj).forEach(([_key, _value]) => {
                if (pattern.test(JSON.stringify(_value))) {
                    proof = JSON.stringify(_value).match(pattern)[0]
                }
            })
        } else {
            if (pattern.test(obj))
                proof = obj.match(pattern)[0]
        }
        return proof
    }

    /* ---------------- internal helpers ---------------- */

    // case-insensitive + regex-aware denylist
    isAttackableName(name) {
        const deny = this.nonAttackParams || []
        const n = String(name ?? '').toLowerCase()
        return !deny.some(d => {
            if (d instanceof RegExp) return d.test(name)
            return String(d).toLowerCase() === n
        })
    }

    // robust URL constructor (supports relative URLs)
    _toURL(u, baseFallback) {
        try {
            return new URL(u)
        } catch {
            const base = baseFallback || (typeof location !== 'undefined' ? location.origin : 'http://localhost')
            return new URL(u, base)
        }
    }

    // Deep clone
    _clone(obj) {
        return JSON.parse(JSON.stringify(obj))
    }

    // Header helpers
    _headersArray(schema) {
        return schema?.request?.headers || (schema.request.headers = [])
    }

    _findHeaderIndex(schema, name) {
        const headers = this._headersArray(schema)
        const lname = name.toLowerCase()
        return headers.findIndex(h => (h.name || '').toLowerCase() === lname)
    }

    _getHeader(schema, name) {
        const i = this._findHeaderIndex(schema, name)
        return i >= 0 ? this._headersArray(schema)[i].value : undefined
    }

    _setHeader(schema, name, value) {
        const headers = this._headersArray(schema)
        const i = this._findHeaderIndex(schema, name)
        if (i >= 0) headers[i].value = value
        else headers.push({ name, value })
    }

    _contentType(schema) {
        return (this._getHeader(schema, 'Content-Type') || schema?.request?.body?.mimeType || '').toLowerCase()
    }

    _getHeaderFromRaw(raw, name) {
        if (!raw) return null
        const target = String(name || '').toLowerCase()
        const lines = String(raw).split(/\r?\n/)
        for (const line of lines) {
            const idx = line.indexOf(':')
            if (idx === -1) continue
            const hname = line.slice(0, idx).trim().toLowerCase()
            if (hname === target) {
                return line.slice(idx + 1).trim()
            }
        }
        return null
    }

    _extractJwtFromString(value) {
        if (!value) return null
        const match = String(value).match(/ey[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_-]*/)
        return match ? match[0] : null
    }

    _decodeJwtPayload(token) {
        if (!token) return null
        const parts = String(token).split('.')
        if (parts.length < 2) return null
        let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
        while (b64.length % 4) b64 += '='
        try {
            if (typeof atob === 'function') {
                return atob(b64)
            }
            if (typeof Buffer !== 'undefined') {
                return Buffer.from(b64, 'base64').toString('utf8')
            }
        } catch (_) {
            return null
        }
        return null
    }

    _looksJsonCt(ct) {
        return ct.includes('application/json') || ct.includes('text/json') || ct.includes('+json')
    }

    _looksXmlCt(ct) {
        return ct.includes('/xml') || ct.includes('+xml')
    }

    _looksXmlText(text) {
        if (typeof text !== 'string') return false
        const trimmed = text.trim()
        if (!trimmed.startsWith('<')) return false
        return /<[\w:.-]+[\s>]/.test(trimmed) && /<\/[\w:.-]+>/.test(trimmed)
    }

    // Ensure body exists; return a mutable reference
    _ensureBody(schema) {
        if (!schema.request.body) schema.request.body = {}
        return schema.request.body
    }

    _resolveMultipartBoundary(schema) {
        const body = this._ensureBody(schema)
        if (typeof body.boundary === 'string' && body.boundary.trim()) {
            return body.boundary.trim()
        }
        const contentType = this._getHeader(schema, 'Content-Type') || body.mimeType || ''
        const match = String(contentType).match(/boundary=([^;]+)/i)
        if (match?.[1]) {
            return String(match[1]).trim().replace(/^"|"$/g, '')
        }
        return `----PTKFormBoundary${String(ptk_utils.attackParamId()).replace(/[^A-Za-z0-9]/g, '')}`
    }

    _normalizeMultipartParam(param) {
        if (!param || typeof param !== 'object') return null
        return {
            type: param.type ? String(param.type) : undefined,
            name: param.name != null ? String(param.name) : undefined,
            value: String(param.value ?? ''),
            fileName: param.fileName != null ? String(param.fileName) : undefined,
            contentType: param.contentType != null ? String(param.contentType) : undefined
        }
    }

    _findMultipartFileFieldCandidate(params = []) {
        if (!Array.isArray(params) || !params.length) return null
        const normalized = params
            .map((param) => this._normalizeMultipartParam(param))
            .filter(Boolean)
        const existingFilePart = normalized.find((param) => !!param?.fileName && !!param?.name)
        if (existingFilePart?.name) return existingFilePart.name

        const scored = normalized
            .filter((param) => !!param?.name)
            .map((param, index) => {
                const name = String(param.name || '')
                const value = String(param.value ?? '')
                let score = 0
                if (/(?:^|_|-)(?:file|upload|avatar|image|photo|picture|icon|attachment|document|logo|resume|cv)(?:$|_|-)/i.test(name)) {
                    score += 50
                }
                if (value === '') score += 20
                if (/^(?:csrf|token|user|username|email|name|id|submit)$/i.test(name)) score -= 40
                return { name, score, index }
            })
            .sort((a, b) => {
                if (b.score !== a.score) return b.score - a.score
                return a.index - b.index
            })
        return scored[0]?.score > 0 ? scored[0].name : null
    }

    modifyMultipartFiles(schema, action, mutations = []) {
        const files = Array.isArray(action?.files) ? action.files : []
        if (!files.length) return schema

        const body = this._ensureBody(schema)
        const boundary = this._resolveMultipartBoundary(schema)
        const contentType = `multipart/form-data; boundary=${boundary}`
        const existingParams = Array.isArray(body.params)
            ? body.params
                .map((param) => this._normalizeMultipartParam(param))
                .filter(Boolean)
            : []
        const inheritedFieldName = this._findMultipartFileFieldCandidate(existingParams)
        const targetNames = new Set(
            files
                .map((file) => {
                    const explicitName = String(file?.name || '').trim()
                    if (!explicitName || explicitName === 'file') {
                        return inheritedFieldName || explicitName || 'file'
                    }
                    return explicitName
                })
                .filter(Boolean)
        )
        const preservedParams = existingParams.filter((param) => {
            if (!param?.name || !targetNames.has(param.name)) return true
            if (inheritedFieldName && param.name === inheritedFieldName) return false
            return !param.fileName
        })
        const multipartFiles = files.map((file) => {
            const explicitName = String(file?.name || '').trim()
            const name = (!explicitName || explicitName === 'file')
                ? (inheritedFieldName || explicitName || 'file')
                : explicitName
            const fileName = String(file?.filename || file?.fileName || 'ptk-upload.bin')
            const value = String(file?.content ?? '')
            const part = {
                name,
                value,
                fileName,
                contentType: String(file?.contentType || 'application/octet-stream')
            }
            this._recordMutation(mutations, 'body', name, '', fileName)
            return part
        })

        body.contentType = 'multipart/form-data'
        body.mimeType = contentType
        body.boundary = boundary
        body.params = preservedParams.concat(multipartFiles)
        delete body.text
        this._setHeader(schema, 'Content-Type', contentType)
        return schema
    }

    // Try to obtain JSON object for body; also indicate source
    _getJsonBody(schema) {
        const body = this._ensureBody(schema)
        const ct = this._contentType(schema)

        // Prefer explicit json field
        if (body.json && typeof body.json === 'object') {
            return { obj: body.json, source: 'json' }
        }

        // If content type suggests JSON, try to parse text/raw
        if (this._looksJsonCt(ct) && typeof body.text === 'string') {
            try {
                const obj = JSON.parse(body.text)
                body.json = obj
                return { obj, source: 'text' }
            } catch (_) { /* ignore */ }
        }

        // If no CT but text is parseable JSON, treat as JSON
        if (!this._looksJsonCt(ct) && typeof body.text === 'string') {
            try {
                const obj = JSON.parse(body.text)
                body.json = obj
                // also set header to json for clarity
                this._setHeader(schema, 'Content-Type', 'application/json')
                return { obj, source: 'text' }
            } catch (_) { /* ignore */ }
        }

        // If body has no text and no json but CT is JSON, initialize empty object
        if (this._looksJsonCt(ct) && !body.text && !body.json) {
            body.json = {}
            return { obj: body.json, source: 'json' }
        }

        return { obj: null, source: null }
    }

    _getXmlBody(schema) {
        const body = this._ensureBody(schema)
        const ct = this._contentType(schema)
        const text = (typeof body.text === 'string') ? body.text : null
        if (!text) return { text: null, source: null }
        if (this._looksXmlCt(ct) || this._looksXmlText(text)) {
            return { text, source: 'text' }
        }
        return { text: null, source: null }
    }

    _hasXmlBody(schema) {
        return Boolean(this._getXmlBody(schema).text)
    }

    _buildRequestSurfaceAnalysis(schema) {
        const originalResponseBodyText = this._extractOriginalResponseBodyText(schema)
        const queryParams = []
        for (const p of (schema?.request?.queryParams || [])) {
            if (!this.isAttackableName(p?.name)) continue
            if (this._isAuthLikeHardBlocked('params', { name: p?.name, value: p?.value, location: 'query' })) {
                this._noteSelectorSkip('params', 'auth_like_hard_deny', p?.name)
                continue
            }
            queryParams.push({
                location: 'query',
                name: p.name,
                path: p.name,
                value: p.value,
                typeHint: this._inferScalarTypeHint(p.value)
            })
        }

        const bodyParams = []
        for (const p of (schema?.request?.body?.params || [])) {
            if (!this.isAttackableName(p?.name)) continue
            if (this._isAuthLikeHardBlocked('params', { name: p?.name, value: p?.value, location: 'form' })) {
                this._noteSelectorSkip('params', 'auth_like_hard_deny', p?.name)
                continue
            }
            bodyParams.push({
                location: 'form',
                name: p.name,
                path: p.name,
                value: p.value,
                typeHint: this._inferScalarTypeHint(p.value)
            })
        }

        const headers = []
        for (const h of (schema?.request?.headers || [])) {
            const name = String(h?.name || '')
            const lowerName = name.toLowerCase()
            if (!name || !this.isAttackableName(name)) continue
            if (lowerName === 'cookie') continue
            if (this._isHardDeniedName('headers', name)) {
                this._noteSelectorSkip('headers', 'hard_deny', name)
                continue
            }
            if (this._isAuthLikeHardBlocked('headers', { name, value: h?.value, location: 'header' })) {
                this._noteSelectorSkip('headers', 'auth_like_hard_deny', name)
                continue
            }
            if (this._isSoftGloballyExcluded('headers', name)) {
                this._noteSelectorSkip('headers', 'global_exclude', name)
                continue
            }
            headers.push({
                location: 'header',
                name,
                path: name,
                value: h?.value
            })
        }

        const cookies = []
        for (const c of this._getCookiesArray(schema)) {
            if (!this.isAttackableName(c?.name)) continue
            if (this._isHardDeniedName('cookies', c?.name)) {
                this._noteSelectorSkip('cookies', 'hard_deny', c?.name)
                continue
            }
            if (this._isAuthLikeHardBlocked('cookies', { name: c?.name, value: c?.value, location: 'cookie' })) {
                this._noteSelectorSkip('cookies', 'auth_like_hard_deny', c?.name)
                continue
            }
            if (this._isSoftGloballyExcluded('cookies', c?.name)) {
                this._noteSelectorSkip('cookies', 'global_exclude', c?.name)
                continue
            }
            cookies.push({
                location: 'cookie',
                name: c.name,
                path: c.name,
                value: c.value
            })
        }

        const { obj: jsonObj } = this._getJsonBody(schema)
        const jsonLeaves = jsonObj
            ? this._enumerateJsonLeaves(jsonObj)
                .map((leaf) => ({
                    location: 'json',
                    name: String(leaf?.path || ''),
                    path: String(leaf?.path || ''),
                    value: leaf?.value,
                    jsonPath: String(leaf?.path || ''),
                    typeHint: this._inferScalarTypeHint(leaf?.value)
                }))
                .filter((leaf) => Boolean(leaf.name))
            : []

        const { text: xmlText } = this._getXmlBody(schema)
        const xmlLeaves = xmlText
            ? this._enumerateXmlLeaves(xmlText).map((leaf) => ({
                location: 'xml',
                path: leaf?.path,
                name: leaf?.name,
                value: leaf?.value
            }))
            : []

        return {
            queryParams,
            bodyParams,
            paramPool: queryParams.concat(bodyParams),
            headers,
            cookies,
            jsonObj,
            jsonLeaves,
            xmlText,
            xmlLeaves,
            originalResponseBodyText
        }
    }

    _getRequestSurfaceAnalysis(schema) {
        if (!schema || typeof schema !== 'object') {
            return {
                queryParams: [],
                bodyParams: [],
                paramPool: [],
                headers: [],
                cookies: [],
                jsonObj: null,
                jsonLeaves: [],
                xmlText: null,
                xmlLeaves: [],
                originalResponseBodyText: ''
            }
        }
        const cached = this._requestSurfaceCache.get(schema)
        if (cached) return cached
        const analysis = this._buildRequestSurfaceAnalysis(schema)
        this._requestSurfaceCache.set(schema, analysis)
        return analysis
    }

    // Sync json -> text (and ensure CT)
    _persistJsonBody(schema, obj) {
        const body = this._ensureBody(schema)
        body.json = obj
        try {
            body.text = JSON.stringify(obj)
        } catch {
            // Fallback, but shouldn't happen
            body.text = '' + obj
        }
        // Ensure Content-Type
        if (!this._looksJsonCt(this._contentType(schema))) {
            this._setHeader(schema, 'Content-Type', 'application/json')
        }
    }

    // JSON path parsing: supports dot and [index] notation
    _parseJsonPath(path) {
        const segs = []
        const re = /([^.\[\]]+)|\[(\d+)\]/g
        let m
        while ((m = re.exec(path)) !== null) {
            if (m[1] !== undefined) segs.push(m[1])
            else segs.push(Number(m[2]))
        }
        return segs
    }

    _getByJsonPath(obj, path) {
        const segs = Array.isArray(path) ? path : this._parseJsonPath(path)
        let cur = obj
        for (let i = 0; i < segs.length; i++) {
            if (cur == null) return { exists: false, parent: null, key: null, value: undefined }
            const k = segs[i]
            if (i === segs.length - 1) {
                return { exists: Object.prototype.hasOwnProperty.call(cur, k), parent: cur, key: k, value: cur?.[k] }
            } else {
                cur = cur?.[k]
            }
        }
        return { exists: false, parent: null, key: null, value: undefined }
    }

    _setByJsonPath(obj, path, value) {
        const segs = Array.isArray(path) ? path : this._parseJsonPath(path)
        if (!segs.length) return obj

        // JSON bodies can be primitives (e.g. `40`). Promote to a container so
        // path-based writes do not throw and attacks can still be built.
        let root = obj
        if (!root || typeof root !== 'object') {
            root = (typeof segs[0] === 'number') ? [] : {}
        }

        let cur = root
        for (let i = 0; i < segs.length - 1; i++) {
            const k = segs[i]
            const next = segs[i + 1]
            if (cur[k] == null || typeof cur[k] !== 'object') {
                // create object or array segment depending on next segment
                cur[k] = (typeof next === 'number') ? [] : {}
            }
            cur = cur[k]
        }
        const last = segs[segs.length - 1]
        cur[last] = value
        return root
    }

    _isPrimitive(v) {
        const t = typeof v
        return v == null || t === 'string' || t === 'number' || t === 'boolean'
    }

    // Enumerate JSON leaf paths (primitives only)
    _enumerateJsonLeaves(obj, basePath = '') {
        const out = []
        const addPath = (p) => (basePath ? `${basePath}.${p}` : p)

        if (Array.isArray(obj)) {
            for (let i = 0; i < obj.length; i++) {
                const val = obj[i]
                const path = `${basePath}[${i}]`
                if (this._isPrimitive(val)) {
                    out.push({ path, value: val })
                } else if (val && typeof val === 'object') {
                    out.push(...this._enumerateJsonLeaves(val, `${basePath}[${i}]`))
                }
            }
        } else if (obj && typeof obj === 'object') {
            for (const k of Object.keys(obj)) {
                const val = obj[k]
                const path = addPath(k)
                if (this._isPrimitive(val)) {
                    out.push({ path, value: val })
                } else if (val && typeof val === 'object') {
                    out.push(...this._enumerateJsonLeaves(val, path))
                }
            }
        }
        return out
    }

    _parseXmlDocument(xmlText) {
        if (typeof DOMParser !== 'function') return null
        try {
            const doc = new DOMParser().parseFromString(String(xmlText || ''), 'application/xml')
            if (!doc) return null
            if (doc.getElementsByTagName('parsererror').length > 0) return null
            return doc
        } catch (_) {
            return null
        }
    }

    _xmlSegmentName(segment) {
        const match = String(segment || '').match(/^([^[]+)(?:\[(\d+)\])?$/)
        if (!match) return { name: String(segment || ''), index: 1 }
        return {
            name: match[1],
            index: Number.parseInt(match[2] || '1', 10) || 1
        }
    }

    _enumerateXmlLeaves(xmlText) {
        const leaves = []
        const xmlDoc = this._parseXmlDocument(xmlText)

        if (xmlDoc?.documentElement) {
            const walk = (node, path) => {
                const childElements = Array.from(node.childNodes || []).filter(child => child?.nodeType === 1)
                if (!childElements.length) {
                    leaves.push({
                        path,
                        name: node.localName || node.nodeName,
                        value: node.textContent ?? ''
                    })
                    return
                }
                const counters = Object.create(null)
                for (const child of childElements) {
                    const key = child.nodeName
                    counters[key] = (counters[key] || 0) + 1
                    const childPath = `${path}/${key}[${counters[key]}]`
                    walk(child, childPath)
                }
            }

            const root = xmlDoc.documentElement
            const rootPath = `${root.nodeName}[1]`
            walk(root, rootPath)
            return leaves
        }

        // Fallback parser for non-DOM environments: flat tag matching.
        const counters = Object.create(null)
        const regex = /<([A-Za-z_][\w:.-]*)\b[^>]*>([^<>]*)<\/\1>/g
        let match
        while ((match = regex.exec(String(xmlText || ''))) !== null) {
            const tag = match[1]
            counters[tag] = (counters[tag] || 0) + 1
            leaves.push({
                path: `${tag}[${counters[tag]}]`,
                name: tag,
                value: match[2] ?? ''
            })
        }
        return leaves
    }

    _findXmlNodeByPath(rootNode, xmlPath) {
        if (!rootNode || !xmlPath) return null
        const parts = String(xmlPath).split('/').filter(Boolean)
        if (!parts.length) return null

        let current = rootNode
        let startIndex = 0
        const first = this._xmlSegmentName(parts[0])
        if (first.name === current.nodeName || first.name === current.localName) {
            if (first.index !== 1) return null
            startIndex = 1
        }

        for (let i = startIndex; i < parts.length; i++) {
            const { name, index } = this._xmlSegmentName(parts[i])
            const children = Array.from(current.childNodes || []).filter(child => {
                if (child?.nodeType !== 1) return false
                return child.nodeName === name || child.localName === name
            })
            current = children[index - 1]
            if (!current) return null
        }

        return current
    }

    _setXmlLeafByPath(xmlText, xmlPath, value) {
        const doc = this._parseXmlDocument(xmlText)
        if (doc?.documentElement && typeof XMLSerializer === 'function') {
            const node = this._findXmlNodeByPath(doc.documentElement, xmlPath)
            if (!node) return xmlText
            node.textContent = String(value ?? '')
            const serialized = new XMLSerializer().serializeToString(doc)
            if (/^\s*<\?xml/i.test(String(xmlText || '')) && !/^\s*<\?xml/i.test(serialized)) {
                return `<?xml version="1.0"?>${serialized}`
            }
            return serialized
        }

        // Fallback replacement by tag name when DOM parser is unavailable.
        const tail = String(xmlPath || '').split('/').pop() || ''
        const { name } = this._xmlSegmentName(tail)
        if (!name) return xmlText
        const reg = new RegExp(`(<${name}\\b[^>]*>)([\\s\\S]*?)(<\\/${name}>)`)
        return String(xmlText || '').replace(reg, (_m, p1, _p2, p3) => `${p1}${String(value ?? '')}${p3}`)
    }

    /* ---------------- cookie helpers ---------------- */

    _parseCookieHeader(cookieStr) {
        const list = []
        if (!cookieStr) return list
        cookieStr.split(';').forEach(part => {
            const eq = part.indexOf('=')
            if (eq === -1) return
            const name = part.slice(0, eq).trim()
            const value = part.slice(eq + 1).trim()
            if (name) list.push({ name, value })
        })
        return list
    }

    _stringifyCookies(arr) {
        return (arr || []).map(c => `${c.name}=${c.value}`).join('; ')
    }

    _getCookiesArray(schema) {
        // Prefer structured cookies array if present; else parse header
        if (Array.isArray(schema?.request?.cookies)) {
            return schema.request.cookies
        }
        const cookieHeader = this._getHeader(schema, 'Cookie') || ''
        const parsed = this._parseCookieHeader(cookieHeader)
        schema.request.cookies = parsed // keep in schema for later
        return schema.request.cookies
    }

    _ensureCookiesArray(schema) {
        if (!Array.isArray(schema?.request?.cookies)) {
            schema.request.cookies = []
        }
        return schema.request.cookies
    }

    /* ---------------- target enumeration ---------------- */

    // Enumerate attack targets according to action filters (query, form-body, headers, json-body, cookies)
    _getParamTargets(schema, action, target = null) {
        const targets = []
        const analysis = this._getRequestSurfaceAnalysis(schema)
        const qp = analysis.queryParams
        const bp = analysis.bodyParams
        const hh = analysis.headers
        const hasExplicitTargetConfig = target && typeof target === 'object'
            ? Object.values(target).some(value => Array.isArray(value) && value.length > 0)
            : false

        const targetParamSelectors = this._getTargetSelectors(target, 'params')
        const paramSelectors = targetParamSelectors || (action.params || [])
        const jsonSelectors = this._getTargetSelectors(target, 'json') || (hasExplicitTargetConfig ? [] : (action.params || []))
        const hasXmlBody = this._hasXmlBody(schema)
        const xmlSelectors = this._getTargetSelectors(target, 'xml') || (hasExplicitTargetConfig ? [] : (hasXmlBody ? (action.params || []) : []))
        const headerSelectors = this._getTargetSelectors(target, 'headers') || (action.headers || [])
        const cookieSelectors = this._getTargetSelectors(target, 'cookies') || (action.cookies || [])

        const actionHasWildcardQuery = (!targetParamSelectors) && paramSelectors.some(a => !a.name && !a.nameRegex && this._matchesSelectorLocation(a, 'query'))
        const actionHasWildcardForm = (!targetParamSelectors) && paramSelectors.some(a => !a.name && !a.nameRegex && this._matchesSelectorLocation(a, 'form'))
        const actionHasWildcardHeader = headerSelectors.some(a => !a.name)

        if (targetParamSelectors?.length) {
            const seenTargets = new Set()
            for (const selector of targetParamSelectors) {
                const family = this._selectorFamily(selector)
                const matches = []
                matches.push(...this._selectParamCandidates(schema, analysis.paramPool, selector))
                if (this._matchesSelectorLocation(selector, 'json') && Array.isArray(analysis.jsonLeaves) && analysis.jsonLeaves.length) {
                    matches.push(...this._selectParamCandidates(schema, analysis.jsonLeaves, selector))
                }
                if (this._matchesSelectorLocation(selector, 'xml') && Array.isArray(analysis.xmlLeaves) && analysis.xmlLeaves.length) {
                    matches.push(...this._selectXmlCandidates(schema, analysis.xmlLeaves, selector))
                }
                for (const match of matches) {
                    const key = `${String(match.location || '')}:${String(match.name || '').toLowerCase()}`
                    if (!match?.name || seenTargets.has(key)) continue
                    seenTargets.add(key)
                    const selectorRank = this._selectorRankSummary(
                        this._rankParamCandidate(match, selector, { family })
                    )
                    targets.push({
                        location: match.location,
                        name: match.name,
                        typeHint: match.typeHint,
                        selectorRank
                    })
                }
            }
        } else {
            // Query params
            for (const p of qp) {
                const matchingAction = paramSelectors.find(a => this._matchesParamSelector(p.name, a, null, 'query', p.value, schema))
                if (matchingAction || actionHasWildcardQuery) {
                    const rankingSelector = matchingAction
                        || paramSelectors.find(a => this._matchesSelectorLocation(a, 'query'))
                        || { family: this._selectorFamily(null) }
                    targets.push({
                        location: 'query',
                        name: p.name,
                        selectorRank: this._selectorRankSummary(
                            this._rankParamCandidate({
                                location: 'query',
                                name: p.name,
                                value: p.value,
                                typeHint: p.typeHint
                            }, rankingSelector, { family: this._selectorFamily(rankingSelector) })
                        )
                    })
                }
            }

            // Body params (form-encoded style)
            for (const p of bp) {
                const matchingAction = paramSelectors.find(a => this._matchesParamSelector(p.name, a, null, 'form', p.value, schema))
                if (matchingAction || actionHasWildcardForm) {
                    const rankingSelector = matchingAction
                        || paramSelectors.find(a => this._matchesSelectorLocation(a, 'form'))
                        || { family: this._selectorFamily(null) }
                    targets.push({
                        location: 'form',
                        name: p.name,
                        selectorRank: this._selectorRankSummary(
                            this._rankParamCandidate({
                                location: 'form',
                                name: p.name,
                                value: p.value,
                                typeHint: p.typeHint
                            }, rankingSelector, { family: this._selectorFamily(rankingSelector) })
                        )
                    })
                }
            }
        }

        // Headers (exclude Cookie; handled as cookie-level targets below).
        // Explicit header selectors are allowed even when the baseline request does not
        // contain that header, so host/header attacks are not silently dropped.
        const seenHeaderTargets = new Set()
        const pushHeaderTarget = (name, value = '', selector = null) => {
            const headerName = String(name || '')
            const lowerName = headerName.toLowerCase()
            if (!headerName || seenHeaderTargets.has(lowerName)) return
            if (!this.isAttackableName(headerName)) return
            if (lowerName === 'cookie') return
            if (this._isHardDeniedName('headers', headerName)) {
                this._noteSelectorSkip('headers', 'hard_deny', headerName)
                return
            }
            if (this._isAuthLikeHardBlocked('headers', { name: headerName, value, location: 'header' })) {
                this._noteSelectorSkip('headers', 'auth_like_hard_deny', headerName)
                return
            }
            if (this._isSoftGloballyExcluded('headers', headerName)) {
                this._noteSelectorSkip('headers', 'global_exclude', headerName)
                return
            }
            seenHeaderTargets.add(lowerName)
            targets.push({
                location: 'header',
                name: headerName,
                selectorRank: selector
                    ? this._selectorRankSummary(
                        this._rankParamCandidate({
                            location: 'header',
                            name: headerName,
                            value
                        }, selector, { family: this._selectorFamily(selector) })
                    )
                    : null
            })
        }
        for (const h of hh) {
            const explicitSelector = headerSelectors.find(a => a.name && a.name.toLowerCase() === String(h?.name || '').toLowerCase())
            const explicit = Boolean(explicitSelector)
            if (explicit || actionHasWildcardHeader) {
                pushHeaderTarget(h?.name, h?.value, explicitSelector || headerSelectors.find(a => !a.name) || null)
            }
        }
        for (const selector of headerSelectors) {
            if (!selector?.name) continue
            pushHeaderTarget(selector.name, selector.value, selector)
        }

        // Cookies (only if the action intends to touch cookies)
        const hasCookieIntent =
            (cookieSelectors && cookieSelectors.length > 0) ||
            (action.cookies && action.cookies.length > 0) ||
            (action.headers || []).some(h => (h.name || '').toLowerCase() === 'cookie')

        if (hasCookieIntent) {
            const cookies = analysis.cookies
            if (!cookieSelectors.length) {
                for (const c of cookies) {
                    targets.push({
                        location: 'cookie',
                        name: c.name,
                        selectorRank: null
                    })
                }
            } else {
                const seenCookies = new Set()
                for (const act of cookieSelectors) {
                    const matches = this._selectCookieCandidates(cookies, act)
                    for (const c of matches) {
                        const name = String(c?.name ?? '')
                        const key = name.toLowerCase()
                        if (!name || seenCookies.has(key)) continue
                        seenCookies.add(key)
                        targets.push({
                            location: 'cookie',
                            name,
                            selectorRank: this._selectorRankSummary(
                                this._rankParamCandidate({
                                    location: 'cookie',
                                    name,
                                    value: c?.value
                                }, act, { family: this._selectorFamily(act) })
                            )
                        })
                    }
                }
            }
        }

        // JSON body
        const { jsonObj, jsonLeaves } = analysis
        if (jsonObj && Array.isArray(jsonSelectors) && jsonSelectors.length) {
            const seenJsonTargets = new Set()
            const pushJsonTarget = (path, value, typeHint = null, selector = null) => {
                const targetPath = String(path || '')
                if (!targetPath || seenJsonTargets.has(targetPath)) return
                if (this._isAuthLikeHardBlocked('json', { name: targetPath, value, location: 'json' })) {
                    this._noteSelectorSkip('json', 'auth_like_hard_deny', targetPath)
                    return
                }
                seenJsonTargets.add(targetPath)
                const targetEntry = { location: 'json', name: targetPath }
                if (typeHint) targetEntry.typeHint = typeHint
                if (selector) {
                    targetEntry.selectorRank = this._selectorRankSummary(
                        this._rankParamCandidate({
                            location: 'json',
                            name: targetPath,
                            value,
                            jsonPath: targetPath,
                            path: targetPath,
                            typeHint
                        }, selector, { family: this._selectorFamily(selector) })
                    )
                }
                targets.push(targetEntry)
            }

            // Preserve explicit path behavior (can target paths even if missing in baseline body).
            const explicitJsonSelectors = jsonSelectors.filter(selector => selector?.name && typeof selector.name === 'string')
            for (const selector of explicitJsonSelectors) {
                if (!this._matchesSelectorLocation(selector, 'json')) continue
                const path = String(selector.name)
                const { value } = this._getByJsonPath(jsonObj, path)
                pushJsonTarget(path, value, this._inferScalarTypeHint(value), selector)
            }

            // For wildcard/regex selectors, apply the same candidate selection pipeline used for params.
            const dynamicJsonSelectors = jsonSelectors.filter(selector => !selector?.name)
            if (dynamicJsonSelectors.length) {
                for (const selector of dynamicJsonSelectors) {
                    if (!this._matchesSelectorLocation(selector, 'json')) continue
                    const matches = this._selectParamCandidates(schema, jsonLeaves, selector)
                    for (const match of matches) {
                        pushJsonTarget(match?.name, match?.value, match?.typeHint, selector)
                    }
                }
            }
        }

        // XML body
        const { xmlText, xmlLeaves } = analysis
        if (xmlText && (xmlSelectors.length || 0) >= 0) {
            const seenXmlTargets = new Set()
            for (const selector of (xmlSelectors || [])) {
                const matches = this._selectXmlCandidates(schema, xmlLeaves, selector)
                for (const match of matches) {
                    const path = String(match?.path || '')
                    if (!path || seenXmlTargets.has(path)) continue
                    seenXmlTargets.add(path)
                    const selectorRank = this._selectorRankSummary(
                        this._rankParamCandidate({
                            location: 'xml',
                            name: match?.name,
                            value: match?.value,
                            path,
                            jsonPath: path
                        }, selector, { family: this._selectorFamily(selector) })
                    )
                    targets.push({
                        location: 'xml',
                        name: path,
                        typeHint: this._inferScalarTypeHint(match?.value),
                        selectorRank
                    })
                }
            }
        }

        return targets
    }

    _recordMutation(list, location, name, before, after, meta = null, force = false) {
        if (!list) return
        // Only record if an actual change occurred (prevents noisy entries)
        if (before !== after || force) {
            list.push(Object.assign({ location, name, before, after }, meta && typeof meta === 'object' ? meta : null))
        }
    }

    _normalizeReportedMutation(schema, mutation) {
        if (!mutation || typeof mutation !== 'object') return mutation
        if (mutation.location !== 'body') return Object.assign({}, mutation)
        if (!Array.isArray(schema?.request?.body?.params)) return Object.assign({}, mutation)
        return Object.assign({}, mutation, { location: 'form' })
    }

    _compileParamNameRegex(action) {
        return this._compileSelectorRegex(action?.nameRegex, action?.flags)
    }

    _compileParamExcludeRegex(action) {
        return this._compileSelectorRegex(action?.excludeNameRegex, action?.excludeFlags || action?.flags)
    }

    _compileParamValueRegex(action) {
        return this._compileSelectorRegex(action?.valueRegex, action?.valueFlags || action?.flags)
    }

    _compileSelectorRegex(pattern, flags = null) {
        if (!pattern || typeof pattern !== 'string') return null
        try {
            const safeFlags = typeof flags === 'string'
                ? flags.replace(/g/g, '')
                : 'i'
            return new RegExp(pattern, safeFlags || undefined)
        } catch {
            return null
        }
    }

    setScanControls(scanControls) {
        this.scanControls = (scanControls && typeof scanControls === 'object') ? scanControls : null
        this._requestSurfaceCache = new WeakMap()
        this._candidateEvaluationCache = new WeakMap()
    }

    _clearSelectorDiagnostics() {
        this._selectorSkipStats = Object.create(null)
        this._selectorSelectionDiagnostics = []
    }

    _noteSelectorSkip(surface, reason, name = null) {
        const s = String(surface || 'unknown')
        const r = String(reason || 'unknown')
        const key = `${s}:${r}`
        const stats = this._selectorSkipStats || (this._selectorSkipStats = Object.create(null))
        if (!stats[key]) {
            stats[key] = { surface: s, reason: r, count: 0, samples: [] }
        }
        const entry = stats[key]
        entry.count += 1
        if (name && entry.samples.length < 3) {
            entry.samples.push(String(name))
        }
    }

    consumeSelectorDiagnostics() {
        const stats = this._selectorSkipStats || {}
        const out = Object.keys(stats).map((key) => Object.assign({ kind: 'skip' }, stats[key]))
        const selected = Array.isArray(this._selectorSelectionDiagnostics) ? this._selectorSelectionDiagnostics : []
        for (const item of selected) {
            out.push(Object.assign({ kind: 'selection' }, item))
        }
        const maxEntries = 10
        if (out.length > maxEntries) {
            const dropped = out.length - maxEntries + 1
            const trimmed = out.slice(0, Math.max(0, maxEntries - 1))
            trimmed.push({
                kind: 'truncation',
                reason: 'selector_diagnostics_payload_cap',
                dropped
            })
            this._clearSelectorDiagnostics()
            return trimmed
        }
        this._clearSelectorDiagnostics()
        return out
    }

    _truncateReason(value) {
        const text = String(value ?? '').trim()
        if (!text) return ''
        if (text.length <= 160) return text
        return `${text.slice(0, 157)}...`
    }

    _rankReasons(rank) {
        const reasons = []
        if (Number(rank?.explicitOverrideScore || 0) > 0) {
            reasons.push(`explicitOverride:+${rank.explicitOverrideScore}`)
        }
        reasons.push(`family:${rank?.family || 'unknown'} score=${Number(rank?.familyScore || 0)}`)
        reasons.push(`type:${rank?.classification?.type || 'unknown'} conf=${Number(rank?.classification?.typeConfidence || 0).toFixed(2)}`)
        reasons.push(`sensitivity:${rank?.classification?.sensitivity || 'unknown'} conf=${Number(rank?.classification?.sensitivityConfidence || 0).toFixed(2)}`)
        if (rank?.selectorMode === 'score') reasons.push('selectorMode:score')
        if (Number(rank?.selectorSignalScore || 0) > 0) reasons.push(`selectorSignals:+${rank.selectorSignalScore}`)
        if (Number(rank?.nameMatchBonus || 0) > 0) reasons.push(`nameMatch:+${rank.nameMatchBonus}`)
        if (Number(rank?.valueMatchBonus || 0) > 0) reasons.push(`valueMatch:+${rank.valueMatchBonus}`)
        if (Number(rank?.typeBonus || 0) > 0) reasons.push(`typeBonus:+${rank.typeBonus}`)
        if (Number(rank?.locationBonus || 0) > 0) reasons.push(`locationBonus:+${rank.locationBonus}`)
        if (Number(rank?.selectorWeightBonus || 0) !== 0) reasons.push(`selectorWeight:${rank.selectorWeightBonus >= 0 ? '+' : ''}${rank.selectorWeightBonus}`)
        if (Number(rank?.pathBonus || 0) > 0) reasons.push(`pathBonus:+${rank.pathBonus}`)
        if (Number(rank?.valueTypeBonus || 0) > 0) reasons.push(`valueTypeBonus:+${rank.valueTypeBonus}`)
        if (Number(rank?.semanticTagBonus || 0) > 0) reasons.push(`semanticTagBonus:+${rank.semanticTagBonus}`)
        if (Number(rank?.sensitivitySoftPenalty || 0) > 0) reasons.push(`sensitivityPenalty:-${rank.sensitivitySoftPenalty}`)
        if (Number(rank?.typePenalty || 0) > 0) reasons.push(`typePenalty:-${rank.typePenalty}`)
        if (Number(rank?.namePrior || 0) > 0) reasons.push(`namePrior:+${rank.namePrior}`)
        if (Array.isArray(rank?.matchedSemanticTags) && rank.matchedSemanticTags.length) {
            reasons.push(`semanticTags:${rank.matchedSemanticTags.join(',')}`)
        }
        return reasons.map((item) => this._truncateReason(item)).filter(Boolean)
    }

    _appendSelectorSelectionDiagnostics(surface, family, rankedEntries, selectedEntries) {
        const ranked = Array.isArray(rankedEntries) ? rankedEntries : []
        const selected = Array.isArray(selectedEntries) ? selectedEntries : []
        if (!selected.length || !ranked.length) return
        if (!Array.isArray(this._selectorSelectionDiagnostics)) {
            this._selectorSelectionDiagnostics = []
        }
        const maxEntries = 10
        for (const picked of selected) {
            if (this._selectorSelectionDiagnostics.length >= maxEntries) break
            const selectedKey = String(picked?.rank?.key || '')
            const alternatives = []
            for (const alt of ranked) {
                if (!alt?.rank) continue
                if (String(alt.rank.key || '') === selectedKey) continue
                alternatives.push({
                    key: String(alt.rank.key || ''),
                    rankScore: Number(alt.rank.rankScore || 0),
                    classification: {
                        type: alt.rank.classification?.type || 'unknown',
                        sensitivity: alt.rank.classification?.sensitivity || 'unknown',
                        semanticTags: Array.isArray(alt.rank.classification?.semanticTags) ? alt.rank.classification.semanticTags : [],
                        familyScore: Number(alt.rank.familyScore || 0),
                        familyConfidence: Number(alt.rank.confidence || 0)
                    }
                })
                if (alternatives.length >= 3) break
            }
            this._selectorSelectionDiagnostics.push({
                surface: String(surface || 'unknown'),
                family: String(family || 'unknown'),
                selected: {
                    key: selectedKey,
                    rankScore: Number(picked.rank.rankScore || 0),
                    impactScore: Number(picked.rank.selectorSignalScore || 0),
                    classification: {
                        type: picked.rank.classification?.type || 'unknown',
                        sensitivity: picked.rank.classification?.sensitivity || 'unknown',
                        semanticTags: Array.isArray(picked.rank.classification?.semanticTags) ? picked.rank.classification.semanticTags : [],
                        familyScore: Number(picked.rank.familyScore || 0),
                        familyConfidence: Number(picked.rank.confidence || 0)
                    },
                    selectorSignals: {
                        mode: picked.rank.selectorMode || 'filter',
                        matched: picked.rank.selectorMatched === true,
                        nameMatched: picked.rank.selectorNameMatched === true,
                        valueMatched: picked.rank.selectorValueMatched === true,
                        pathMatched: picked.rank.selectorPathMatched === true,
                        valueTypeMatched: picked.rank.selectorValueTypeMatched === true,
                        matchedSemanticTags: Array.isArray(picked.rank.matchedSemanticTags) ? picked.rank.matchedSemanticTags : []
                    },
                    reasons: this._rankReasons(picked.rank),
                    topAlternatives: alternatives
                }
            })
        }
    }

    _resolveGlobalExcludesConfig() {
        return this.scanControls?.globalExcludes && typeof this.scanControls.globalExcludes === 'object'
            ? this.scanControls.globalExcludes
            : {}
    }

    _matchesGlobalRegex(regexValue, name) {
        const matcher = this._compileSelectorRegex(regexValue)
        if (!matcher) return false
        return matcher.test(String(name ?? ''))
    }

    _isHardDeniedName(surface, name) {
        const lowerSurface = String(surface || '').toLowerCase()
        const candidate = String(name ?? '')
        const lname = candidate.toLowerCase()
        // Always-on micro hard deny for header transport invariants.
        if (lowerSurface === 'headers' && (lname === 'cookie' || lname === 'set-cookie')) {
            return true
        }
        if (this._moduleAllowsHardDeniedName(lowerSurface, candidate)) {
            return false
        }
        const cfg = this._resolveGlobalExcludesConfig()
        if (cfg.allowDangerousInputs === true) {
            return false
        }
        if (lowerSurface === 'params') {
            return this._matchesGlobalRegex(cfg.hardDenyParamNameRegex, candidate)
        }
        if (lowerSurface === 'cookies') {
            return this._matchesGlobalRegex(cfg.hardDenyCookieNameRegex, candidate)
        }
        if (lowerSurface === 'headers') {
            return this._matchesGlobalRegex(cfg.hardDenyHeaderNameRegex, candidate)
        }
        return false
    }

    _moduleAllowsHardDeniedName(surface, name) {
        const cfg = this._moduleExecutionConfig().allowHardDeniedTargets || this?.metadata?.allowHardDeniedTargets
        if (!cfg || typeof cfg !== 'object') return false
        const lowerSurface = String(surface || '').toLowerCase()
        const selector = cfg[lowerSurface]
        if (!selector) return false
        if (selector === true) return true
        const candidate = String(name ?? '')
        if (typeof selector === 'string') {
            return this._matchesGlobalRegex(selector, candidate)
        }
        if (Array.isArray(selector)) {
            const lname = candidate.toLowerCase()
            return selector.some(item => String(item || '').toLowerCase() === lname)
        }
        if (selector && typeof selector === 'object') {
            if (typeof selector.regex === 'string' && this._matchesGlobalRegex(selector.regex, candidate)) {
                return true
            }
            if (Array.isArray(selector.names)) {
                const lname = candidate.toLowerCase()
                return selector.names.some(item => String(item || '').toLowerCase() === lname)
            }
        }
        return false
    }

    _isSoftGloballyExcluded(surface, name) {
        const lowerSurface = String(surface || '').toLowerCase()
        const candidate = String(name ?? '')
        const cfg = this._resolveGlobalExcludesConfig()
        if (lowerSurface === 'params') {
            return this._matchesGlobalRegex(cfg.excludeParamNameRegex, candidate)
        }
        if (lowerSurface === 'cookies') {
            return this._matchesGlobalRegex(cfg.excludeCookieNameRegex, candidate)
        }
        if (lowerSurface === 'headers') {
            return this._matchesGlobalRegex(cfg.excludeHeaderNameRegex, candidate)
        }
        return false
    }

    _escapeRegexLiteral(value) {
        return String(value ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    }

    _extractOriginalResponseBodyText(schema) {
        const originalBody = schema?.original?.response?.body
        if (typeof originalBody === 'string') return originalBody
        if (originalBody && typeof originalBody?.text === 'string') return originalBody.text
        const responseBody = schema?.response?.body
        if (typeof responseBody === 'string') return responseBody
        if (responseBody && typeof responseBody?.text === 'string') return responseBody.text
        return ''
    }

    _isReflectedLocaleParamException(name, value, originalResponseBodyText) {
        const candidateName = String(name ?? '').trim()
        if (!/^(lang|locale)$/i.test(candidateName)) return false

        const rawValue = value === undefined || value === null ? '' : String(value).trim()
        if (!rawValue) return false

        const bodyText = typeof originalResponseBodyText === 'string' ? originalResponseBodyText : ''
        if (!bodyText) return false

        const escapedName = this._escapeRegexLiteral(candidateName)
        const escapedValue = this._escapeRegexLiteral(rawValue)
        const escapedEncodedValue = this._escapeRegexLiteral(encodeURIComponent(rawValue))
        const patterns = [
            new RegExp(`[?&]${escapedName}=${escapedEncodedValue}(?:[&#"'\\s<]|$)`, 'i'),
            new RegExp(`[?&]${escapedName}=${escapedValue}(?:[&#"'\\s<]|$)`, 'i'),
            new RegExp(`\\b${escapedName}\\b[^\\n\\r<]{0,48}[=:]\\s*${escapedValue}(?:[\\s<]|$)`, 'i'),
            new RegExp(`\\b(?:language|locale)\\b[^\\n\\r<]{0,48}[=:]\\s*${escapedValue}(?:[\\s<]|$)`, 'i'),
            new RegExp(`\\bname=["']${escapedName}["'][^>]{0,120}\\bvalue=["']${escapedValue}["']`, 'i'),
            new RegExp(`\\bvalue=["']${escapedValue}["'][^>]{0,120}\\bname=["']${escapedName}["']`, 'i')
        ]
        return patterns.some((pattern) => pattern.test(bodyText))
    }

    _shouldSkipSoftGloballyExcludedTarget(schema, surface, name, value = null) {
        if (!this._isSoftGloballyExcluded(surface, name)) return false
        if (String(surface || '').toLowerCase() !== 'params') return true
        const analysis = schema ? this._getRequestSurfaceAnalysis(schema) : null
        if (this._isReflectedLocaleParamException(name, value, analysis?.originalResponseBodyText)) {
            return false
        }
        return true
    }

    _surfaceFromLocation(location) {
        const value = String(location || '').toLowerCase()
        if (value === 'query' || value === 'body' || value === 'form') return 'params'
        if (value === 'cookie') return 'cookies'
        if (value === 'header') return 'headers'
        if (value === 'json') return 'json'
        if (value === 'xml') return 'xml'
        return 'unknown'
    }

    _compileCookieExcludeRegex(action) {
        return this._compileSelectorRegex(action?.excludeNameRegex, action?.excludeFlags || action?.flags)
    }

    _normalizeParamLocation(location) {
        const value = String(location ?? '').toLowerCase()
        if (!value) return null
        if (value === 'query') return 'query'
        if (value === 'form' || value === 'body') return 'form'
        if (value === 'json') return 'json'
        if (value === 'header') return 'header'
        if (value === 'cookie') return 'cookie'
        if (value === 'xml') return 'xml'
        return null
    }

    _matchesSelectorLocation(action, currentLocation = null) {
        if (!currentLocation) return true
        const current = this._normalizeParamLocation(currentLocation)
        if (!current) return true
        const selectorLoc = action?.location
        if (!selectorLoc) return true

        if (Array.isArray(selectorLoc)) {
            return selectorLoc
                .map(value => this._normalizeParamLocation(value))
                .filter(Boolean)
                .includes(current)
        }

        const normalized = this._normalizeParamLocation(selectorLoc)
        if (!normalized) return true
        return normalized === current
    }

    _matchesSelectorValue(action, candidateValue = null) {
        const matcher = this._compileParamValueRegex(action)
        if (!matcher) return true
        return matcher.test(String(candidateValue ?? ''))
    }

    _compileSelectorPathRegex(action) {
        return this._compileSelectorRegex(action?.pathRegex, action?.pathFlags || action?.flags)
    }

    _compileSelectorJsonPathRegex(action) {
        return this._compileSelectorRegex(action?.jsonPathRegex, action?.jsonPathFlags || action?.pathFlags || action?.flags)
    }

    _candidatePathText(candidate) {
        if (!candidate || typeof candidate !== 'object') return ''
        return String(candidate?.path ?? candidate?.jsonPath ?? candidate?.meta?.jsonPath ?? '')
    }

    _matchesSelectorPath(action, candidate = null) {
        const pathMatcher = this._compileSelectorPathRegex(action)
        const jsonPathMatcher = this._compileSelectorJsonPathRegex(action)
        if (!pathMatcher && !jsonPathMatcher) return true
        const pathText = this._candidatePathText(candidate)
        if (pathMatcher?.test(pathText)) return true
        if (jsonPathMatcher?.test(pathText)) return true
        return false
    }

    _normalizeSelectorValueTypes(raw) {
        const list = Array.isArray(raw) ? raw : (raw == null ? [] : [raw])
        return list
            .map((value) => String(value ?? '').trim().toLowerCase())
            .filter(Boolean)
    }

    _matchesSelectorValueType(action, candidate = null, classification = null) {
        const allowed = this._normalizeSelectorValueTypes(action?.valueTypeIn)
        if (!allowed.length) return true
        const type = String(classification?.type || this._classifyParam(candidate, this._selectorFamily(action))?.type || '').toLowerCase()
        return allowed.some((entry) => {
            if (entry === type) return true
            if (entry === 'numeric') return type === 'int' || type === 'float'
            if (entry === 'text') return type === 'string' || type === 'unknown' || type === 'opaque'
            if (entry === 'id_like') return type === 'int' || type === 'uuid' || type === 'objectid'
            return false
        })
    }

    _matchesSelectorSemanticTags(action, candidate = null, classification = null) {
        const required = Array.isArray(action?.semanticTagsAny)
            ? action.semanticTagsAny.map((value) => String(value ?? '').trim()).filter(Boolean)
            : []
        if (!required.length) return true
        const tagSet = new Set(Array.isArray(classification?.semanticTags) ? classification.semanticTags : [])
        return required.some((tag) => tagSet.has(tag))
    }

    _selectorSignalMatched(action, candidate = null, classification = null) {
        const nameRegexMatcher = this._compileParamNameRegex(action)
        const valueRegexMatcher = this._compileParamValueRegex(action)
        const nameText = String(candidate?.name ?? '')
        const pathText = this._candidatePathText(candidate)
        const valueText = String(candidate?.value ?? '')
        const nameMatched = Boolean(nameRegexMatcher && (nameRegexMatcher.test(nameText) || nameRegexMatcher.test(pathText)))
        const valueMatched = Boolean(valueRegexMatcher && valueRegexMatcher.test(valueText))
        const pathMatched = Boolean((action?.pathRegex || action?.jsonPathRegex) && this._matchesSelectorPath(action, candidate))
        const valueTypeMatched = Boolean(this._normalizeSelectorValueTypes(action?.valueTypeIn).length && this._matchesSelectorValueType(action, candidate, classification))
        const semanticMatched = Boolean(Array.isArray(action?.semanticTagsAny) && action.semanticTagsAny.length && this._matchesSelectorSemanticTags(action, candidate, classification))
        const hasExplicitRegexOrPathSignal = Boolean(nameRegexMatcher || valueRegexMatcher || action?.pathRegex || action?.jsonPathRegex)
        if (hasExplicitRegexOrPathSignal) {
            // In score mode, type/tag hints refine ranked candidates, but regex/path signals
            // still define the primary candidate source unless the selector opted into fallback.
            return nameMatched || valueMatched || pathMatched
        }
        return valueTypeMatched || semanticMatched
    }

    _selectorFilterMatched(action, candidate = null, classification = null) {
        return this._matchesSelectorValue(action, candidate?.value)
            && this._matchesSelectorPath(action, candidate)
            && this._matchesSelectorValueType(action, candidate, classification)
            && this._matchesSelectorSemanticTags(action, candidate, classification)
    }

    _isParamExcluded(paramName, action) {
        const candidate = String(paramName ?? '')
        const excludeMatcher = this._compileParamExcludeRegex(action)
        if (!excludeMatcher) return false
        return excludeMatcher.test(candidate)
    }

    _isNumericLike(value) {
        const candidate = String(value ?? '').trim()
        if (!candidate) return false
        return /^-?\d+(?:\.\d+)?$/.test(candidate)
    }

    _inferScalarTypeHint(value) {
        return this._isNumericLike(value) ? 'numeric' : 'string'
    }

    _normalizeCandidateLocation(location) {
        const value = String(location ?? '').toLowerCase()
        if (value === 'body') return 'form'
        if (!value) return 'query'
        return value
    }

    _normalizeJsonPathForKey(path) {
        const raw = String(path ?? '')
        if (!raw) return ''
        return raw.replace(/\[(\d+)\]/g, '[]')
    }

    _candidateKey(candidate) {
        const location = this._normalizeCandidateLocation(candidate?.location)
        const name = String(candidate?.name ?? '')
        const jsonPath = this._normalizeJsonPathForKey(candidate?.meta?.jsonPath || candidate?.jsonPath || '')
        return `${location}:${name}:${jsonPath}`
    }

    _candidateEvaluationEntry(candidate) {
        if (!candidate || typeof candidate !== 'object') return null
        let entry = this._candidateEvaluationCache.get(candidate)
        if (!entry) {
            entry = {
                classification: null,
                rankByKey: new Map()
            }
            this._candidateEvaluationCache.set(candidate, entry)
        }
        return entry
    }

    _rankCacheKey(action, family) {
        return [
            family || '',
            String(action?.name || ''),
            String(action?.nameRegex || ''),
            String(action?.flags || ''),
            String(action?.pathRegex || ''),
            String(action?.pathFlags || ''),
            String(action?.jsonPathRegex || ''),
            String(action?.jsonPathFlags || ''),
            String(action?.valueRegex || ''),
            String(action?.valueFlags || ''),
            JSON.stringify(this._normalizeSelectorValueTypes(action?.valueTypeIn)),
            JSON.stringify(Array.isArray(action?.semanticTagsAny) ? action.semanticTagsAny : []),
            String(action?.weight ?? ''),
            action?.scoredFallback === true ? '1' : '0'
        ].join('|')
    }

    _collectJsonLogicVars(node, out = []) {
        if (Array.isArray(node)) {
            for (const value of node) {
                this._collectJsonLogicVars(value, out)
            }
            return out
        }
        if (!node || typeof node !== 'object') return out
        for (const [key, value] of Object.entries(node)) {
            if (key === 'var' && typeof value === 'string') {
                out.push(value)
            }
            this._collectJsonLogicVars(value, out)
        }
        return out
    }

    _attackOriginalRequirementsCacheKey(attack) {
        return String(attack?.id || attack?.name || '')
    }

    getAttackOriginalRequirements(attack) {
        const cacheKey = this._attackOriginalRequirementsCacheKey(attack)
        if (cacheKey && this._attackOriginalRequirementsCache.has(cacheKey)) {
            return this._attackOriginalRequirementsCache.get(cacheKey)
        }

        const requirements = {
            needsStatus: false,
            needsHeaders: false,
            needsBody: false,
            needsOtherResponseData: false
        }
        const vars = this._collectJsonLogicVars([
            attack?.condition || null,
            attack?.validation?.rule || null,
            attack?.validation?.proof || null
        ])
        for (const path of vars) {
            if (typeof path !== 'string' || !path.startsWith('original.response.')) continue
            if (path.startsWith('original.response.body')) {
                requirements.needsBody = true
                continue
            }
            if (path.startsWith('original.response.headers')) {
                requirements.needsHeaders = true
                continue
            }
            if (path.startsWith('original.response.statusCode') || path.startsWith('original.response.status')) {
                requirements.needsStatus = true
                continue
            }
            requirements.needsOtherResponseData = true
        }

        if (this._isDeserializationTechniqueModule()) {
            requirements.needsStatus = true
            requirements.needsHeaders = true
            requirements.needsBody = true
        }

        const result = Object.freeze(requirements)
        if (cacheKey) {
            this._attackOriginalRequirementsCache.set(cacheKey, result)
        }
        return result
    }

    _selectorFamily(action) {
        const explicit = String(action?.family || '').trim().toLowerCase()
        if (explicit === 'sqli' || explicit === 'ssrf' || explicit === 'xss' || explicit === 'deserialization' || explicit === 'redirect' || explicit === 'traversal' || explicit === 'idor' || explicit === 'auth') return explicit
        const vulnId = String(this?.vulnId || '').toLowerCase()
        const moduleId = String(this?.id || '').toLowerCase()
        if (/redirect/.test(vulnId) || /redirect/.test(moduleId)) return 'redirect'
        if (/traversal|lfi|rfi|path_traversal/.test(vulnId) || /traversal|lfi|rfi|path_traversal/.test(moduleId)) return 'traversal'
        if (/idor|bola|access_control/.test(vulnId) || /idor|bola|access_control/.test(moduleId)) return 'idor'
        if (/auth|oauth|saml|sso/.test(vulnId) || /auth|oauth|saml|sso/.test(moduleId)) return 'auth'
        if (/\bsql|sqli|bsql\b/.test(vulnId) || /\bsql|sqli|bsql\b/.test(moduleId)) return 'sqli'
        if (/ssrf/.test(vulnId) || /ssrf/.test(moduleId)) return 'ssrf'
        if (/xss/.test(vulnId) || /xss/.test(moduleId)) return 'xss'
        if (/deserializ/.test(vulnId) || /deserializ/.test(moduleId)) return 'deserialization'
        return 'sqli'
    }

    _selectorMode(action) {
        return String(action?.selectorMode || '').trim().toLowerCase() === 'score' ? 'score' : 'filter'
    }

    _selectorHasScoringSignals(action) {
        return Boolean(
            action?.nameRegex
            || action?.valueRegex
            || action?.pathRegex
            || action?.jsonPathRegex
            || this._normalizeSelectorValueTypes(action?.valueTypeIn).length
            || (Array.isArray(action?.semanticTagsAny) && action.semanticTagsAny.length)
        )
    }

    _shannonEntropyEstimate(value) {
        const text = String(value ?? '')
        if (!text.length) return 0
        const map = Object.create(null)
        for (const ch of text) {
            map[ch] = (map[ch] || 0) + 1
        }
        let entropy = 0
        const len = text.length
        for (const count of Object.values(map)) {
            const p = count / len
            entropy -= p * Math.log2(p)
        }
        return entropy
    }

    _looksUuid(value) {
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value ?? '').trim())
    }

    _looksDate(value) {
        const text = String(value ?? '').trim()
        if (!text) return false
        return /^\d{4}-\d{2}-\d{2}(?:[tT ][0-9:.+-Zz]+)?$/.test(text)
    }

    _looksEmail(value) {
        return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(value ?? '').trim())
    }

    _looksUrl(value) {
        const text = String(value ?? '').trim()
        if (!text) return false
        if (/^(?:https?|ftp):\/\//i.test(text)) return true
        if (/^[a-z0-9.-]+\.[a-z]{2,}(?:[:/].*)?$/i.test(text)) return true
        return false
    }

    _looksRelativeUrlLike(value) {
        const text = String(value ?? '').trim()
        if (!text) return false
        return /^(?:\/{1,2}|\.{1,2}\/|\?|#)/.test(text)
    }

    _looksRedirectLikeValue(value) {
        return this._looksUrl(value) || this._looksRelativeUrlLike(value)
    }

    _looksPathLikeValue(value) {
        const text = String(value ?? '').trim()
        if (!text) return false
        if (/[\\/]/.test(text)) return true
        if (/\.\./.test(text)) return true
        if (/\.(?:php|jsp|asp|aspx|html?|json|xml|txt|log|env|ini|ya?ml|twig|mustache|hbs|tmpl|conf|cfg|bak|old|tmp)$/i.test(text)) return true
        if (/(?:template|include|view|layout|partial|fragment|asset|static)/i.test(text) && /\./.test(text)) return true
        return false
    }

    _looksHtmlLikeValue(value) {
        const text = String(value ?? '').trim()
        if (text.length < 3) return false
        return /<\/?[a-z][\w:-]*(?:\s[^<>]*)?>/i.test(text)
    }

    _looksMarkdownLikeValue(value) {
        const text = String(value ?? '').trim()
        if (text.length < 3) return false
        if (/^#{1,6}\s+\S/m.test(text)) return true
        if (/\[[^\]]+\]\([^)]+\)/.test(text)) return true
        if (/```[\s\S]*```/.test(text)) return true
        if (/(?:^|\n)\s*[-*+]\s+\S/.test(text)) return true
        if (/(?:^|\n)\s*\d+\.\s+\S/.test(text)) return true
        if (/`[^`\n]+`/.test(text)) return true
        if (/(?:^|[\s(])(?:\*\*|__|\*|_)\S.*?(?:\*\*|__|\*|_)(?=$|[\s).,;:!?])/.test(text)) return true
        return false
    }

    _looksObjectIdLike(value) {
        return /^[0-9a-f]{24}$/i.test(String(value ?? '').trim())
    }

    _looksBase64Like(value) {
        const text = String(value ?? '').trim()
        if (text.length < 16 || text.length % 4 !== 0) return false
        return /^[A-Za-z0-9+/=]+$/.test(text)
    }

    _looksJwtLike(value) {
        return Boolean(this._extractJwtFromString(String(value ?? '').trim()))
    }

    _looksTokenLike(value) {
        const text = String(value ?? '').trim()
        if (!text) return false
        if (this._looksJwtLike(text)) return true
        if (this._looksBase64Like(text) && this._shannonEntropyEstimate(text) >= 3.5) return true
        if (/^[A-Fa-f0-9]{32,}$/.test(text)) return true
        if (text.length >= 24 && /^[A-Za-z0-9_-]+$/.test(text) && this._shannonEntropyEstimate(text) >= 3.6) return true
        return false
    }

    _stringToUtf8Bytes(value) {
        const text = String(value ?? '')
        try {
            if (typeof TextEncoder !== 'undefined') {
                return new TextEncoder().encode(text)
            }
        } catch (_) {
            // fall through
        }
        if (typeof Buffer !== 'undefined') {
            return Uint8Array.from(Buffer.from(text, 'utf8'))
        }
        const arr = []
        for (let i = 0; i < text.length; i++) {
            arr.push(text.charCodeAt(i) & 0xff)
        }
        return Uint8Array.from(arr)
    }

    _utf8BytesToString(bytes) {
        if (!(bytes instanceof Uint8Array)) return String(bytes ?? '')
        try {
            if (typeof TextDecoder !== 'undefined') {
                return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
            }
        } catch (_) {
            // fall through
        }
        if (typeof Buffer !== 'undefined') {
            return Buffer.from(bytes).toString('utf8')
        }
        return Array.from(bytes).map(ch => String.fromCharCode(ch)).join('')
    }

    _isFormUrlEncoded(schema) {
        const ct = this._contentType(schema)
        return ct.includes('application/x-www-form-urlencoded')
    }

    _safeSingleUrlDecode(value, plusAsSpace = false) {
        const raw = String(value ?? '')
        try {
            const candidate = plusAsSpace ? raw.replace(/\+/g, ' ') : raw
            return decodeURIComponent(candidate)
        } catch (_) {
            return null
        }
    }

    _looksBase64Candidate(value) {
        const text = String(value ?? '').trim()
        if (text.length < 12) return false
        if (/\s/.test(text)) return false
        if (!/^[A-Za-z0-9+/_=-]+$/.test(text)) return false
        return true
    }

    _decodeBase64ToBytes(value, variant = 'std') {
        let input = String(value ?? '').trim()
        if (!input) return null
        if (variant === 'url') {
            input = input.replace(/-/g, '+').replace(/_/g, '/')
        }
        const mod = input.length % 4
        if (mod) input = input + '='.repeat(4 - mod)
        try {
            if (typeof Buffer !== 'undefined') {
                const buf = Buffer.from(input, 'base64')
                if (!buf.length) return null
                return Uint8Array.from(buf)
            }
            if (typeof atob === 'function') {
                const decoded = atob(input)
                const out = new Uint8Array(decoded.length)
                for (let i = 0; i < decoded.length; i++) out[i] = decoded.charCodeAt(i)
                return out
            }
        } catch (_) {
            return null
        }
        return null
    }

    _encodeBytesToBase64(bytes, variant = 'std', padding = 'keep') {
        if (!(bytes instanceof Uint8Array)) return null
        let encoded = null
        try {
            if (typeof Buffer !== 'undefined') {
                encoded = Buffer.from(bytes).toString('base64')
            } else if (typeof btoa === 'function') {
                let binary = ''
                bytes.forEach((b) => { binary += String.fromCharCode(b) })
                encoded = btoa(binary)
            }
        } catch (_) {
            return null
        }
        if (!encoded) return null
        if (variant === 'url') {
            encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_')
        }
        if (padding === 'strip') {
            encoded = encoded.replace(/=+$/g, '')
        } else if (padding === 'add') {
            while (encoded.length % 4) encoded += '='
        }
        return encoded
    }

    _looksLikelyTypeToken(value) {
        const token = String(value ?? '').trim()
        if (!token || token.length < 3) return false
        if (/^[A-Za-z_][\w.\\$]+(?:,\s*[A-Za-z0-9_.]+)?$/.test(token)) return true
        return false
    }

    _detectDeserializationFamily(decodedText, decodedBytes, candidateName = '') {
        const markers = []
        let formatFamily = 'unknown'
        let confidence = 0
        const name = String(candidateName || '')
        const lname = name.toLowerCase()
        const text = String(decodedText ?? '')

        if (decodedBytes instanceof Uint8Array && decodedBytes.length >= 4) {
            if (decodedBytes[0] === 0xac && decodedBytes[1] === 0xed && decodedBytes[2] === 0x00 && decodedBytes[3] === 0x05) {
                formatFamily = 'java_serialized'
                confidence = 0.95
                markers.push('java:aced0005')
            }
        }

        if (formatFamily === 'unknown' && decodedBytes instanceof Uint8Array && decodedBytes.length >= 2) {
            if (decodedBytes[0] === 0x04 && decodedBytes[1] === 0x08) {
                formatFamily = 'ruby_marshaled'
                confidence = 0.82
                markers.push('ruby:marshal0408')
            }
        }

        if (formatFamily === 'unknown') {
            if (/^([aObisNdRrC]):/i.test(text) && /(?:;|\{)/.test(text)) {
                formatFamily = 'php_serialized'
                confidence = 0.88
                markers.push('php:serialize-marker')
            } else if (/s:\d+:"[^"]*";/.test(text) || /O:\d+:"[^"]+":\d+:\{/.test(text)) {
                formatFamily = 'php_serialized'
                confidence = 0.82
                markers.push('php:length-marker')
            }
        }

        if (formatFamily === 'unknown') {
            const hasViewStateName = lname === '__viewstate'
            const hasViewStateMarker = text.startsWith('/wEP') || text.startsWith('dDw')
            if (hasViewStateName || hasViewStateMarker) {
                formatFamily = 'dotnet_viewstate'
                confidence = hasViewStateName && hasViewStateMarker ? 0.85 : 0.72
                markers.push(hasViewStateName ? 'viewstate:name' : 'viewstate:marker')
            }
        }

        if (formatFamily === 'unknown') {
            try {
                const parsed = JSON.parse(text)
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                    const keys = Object.keys(parsed)
                    const typeKey = keys.find(k => ['$type', '@class', '__type'].includes(k))
                    if (typeKey && this._looksLikelyTypeToken(parsed[typeKey])) {
                        formatFamily = 'json_type_metadata'
                        confidence = 0.84
                        markers.push(`json:${typeKey}`)
                    }
                }
            } catch (_) {
                // ignore
            }
        }

        return { formatFamily, confidence, markers }
    }

    _buildDeserCandidate(rawEntry, schema, minConfidence = 0.55) {
        const surface = String(rawEntry?.surface || '')
        const location = this._normalizeCandidateLocation(rawEntry?.location)
        const name = String(rawEntry?.name || '')
        const rawValue = String(rawEntry?.rawValue ?? '')
        if (!rawValue) return null

        const codecChain = []
        const codecNotes = []
        let workingText = rawValue
        let decodedBytes = null

        const plusAsSpace = this._isFormUrlEncoded(schema) && (location === 'query' || location === 'form')
        const shouldTryUrl = /%[0-9a-fA-F]{2}/.test(rawValue) || (plusAsSpace && rawValue.includes('+'))
        if (shouldTryUrl) {
            const once = this._safeSingleUrlDecode(rawValue, plusAsSpace)
            if (typeof once === 'string' && once !== rawValue) {
                workingText = once
                codecChain.push({ type: 'url', mode: 'percent' })
                codecNotes.push('url:single-pass')
            }
        }

        const tryBase64 = this._looksBase64Candidate(workingText)
        if (tryBase64) {
            const variant = /[-_]/.test(workingText) ? 'url' : 'std'
            const padding = /=+$/.test(workingText) ? 'keep' : 'add'
            const bytes = this._decodeBase64ToBytes(workingText, variant)
            if (bytes && bytes.length) {
                decodedBytes = bytes
                workingText = this._utf8BytesToString(bytes)
                codecChain.push({ type: 'base64', variant, padding })
                codecNotes.push(`base64:${variant}`)
            }
        }

        const detection = this._detectDeserializationFamily(workingText, decodedBytes, name)
        if (detection.formatFamily === 'unknown' || Number(detection.confidence || 0) < Number(minConfidence || 0)) {
            return null
        }

        const classification = this._classifyParam({
            name,
            value: rawValue,
            location
        }, 'deserialization')
        const sensitivityClass = classification.sensitivity === 'auth_like'
            ? 'auth_like'
            : (classification.type === 'token_like' ? 'token_like' : 'unknown')

        const key = this._candidateKey({
            location,
            name: surface === 'json' ? String(rawEntry?.jsonPath || name) : name,
            jsonPath: rawEntry?.jsonPath || ''
        })

        return {
            key,
            surface,
            name,
            rawValue,
            codecChain,
            decodedValue: decodedBytes instanceof Uint8Array ? decodedBytes : workingText,
            decodedText: workingText,
            formatFamily: detection.formatFamily,
            confidence: Number(detection.confidence || 0),
            deserConfidence: Number(detection.confidence || 0),
            sensitivityClass,
            evidence: {
                markers: detection.markers || [],
                codecNotes
            },
            location,
            jsonPath: rawEntry?.jsonPath || null
        }
    }

    _collectDeserRawCandidates(schema) {
        const out = []
        const query = Array.isArray(schema?.request?.queryParams) ? schema.request.queryParams : []
        const form = Array.isArray(schema?.request?.body?.params) ? schema.request.body.params : []
        const cookies = this._getCookiesArray(schema)
        const { obj: jsonObj } = this._getJsonBody(schema)

        query.forEach((item) => {
            if (!item?.name) return
            out.push({
                surface: 'param',
                location: 'query',
                name: String(item.name),
                rawValue: String(item.value ?? '')
            })
        })
        form.forEach((item) => {
            if (!item?.name) return
            out.push({
                surface: 'param',
                location: 'form',
                name: String(item.name),
                rawValue: String(item.value ?? '')
            })
        })
        cookies.forEach((item) => {
            if (!item?.name) return
            out.push({
                surface: 'cookie',
                location: 'cookie',
                name: String(item.name),
                rawValue: String(item.value ?? '')
            })
        })
        if (jsonObj && typeof jsonObj === 'object') {
            const leaves = this._enumerateJsonLeaves(jsonObj)
            for (const leaf of leaves) {
                if (!leaf?.path) continue
                out.push({
                    surface: 'json',
                    location: 'json',
                    name: String(leaf.path),
                    jsonPath: String(leaf.path),
                    rawValue: String(leaf.value ?? '')
                })
            }
        }
        return out
    }

    _detectDeserCandidates(schema, options = {}) {
        const minConfidence = Number.isFinite(options?.minConfidence) ? options.minConfidence : 0.55
        const allowedSurfaces = Array.isArray(options?.surfaces)
            ? options.surfaces.map(v => String(v || '').toLowerCase())
            : null
        const candidates = []
        const seen = new Set()
        const rawCandidates = this._collectDeserRawCandidates(schema)
        for (const rawEntry of rawCandidates) {
            const surface = String(rawEntry?.surface || '').toLowerCase()
            if (allowedSurfaces && !allowedSurfaces.includes(surface)) continue
            const candidate = this._buildDeserCandidate(rawEntry, schema, minConfidence)
            if (!candidate) continue
            const dedupeKey = `${candidate.key}|${candidate.formatFamily}|${candidate.codecChain.map(s => s.type).join('.')}`
            if (seen.has(dedupeKey)) continue
            seen.add(dedupeKey)
            candidates.push(candidate)
        }
        return candidates
    }

    _rewritePhpSerializedStringLengths(text) {
        return String(text ?? '').replace(/s:(\d+):"([^"]*)";/g, (_m, _len, content) => {
            return `s:${content.length}:"${content}";`
        })
    }

    _mutatePhpSerializedText(source, mutationKind) {
        let text = String(source ?? '')
        if (!text) return null
        if (mutationKind === 'control') {
            if (/s:(\d+):"/.test(text)) {
                return text.replace(/s:(\d+):"/, (_m, len) => `s:${Number(len) + 1}:"`)
            }
            return `${text};}`
        }

        let mutated = text
        if (/b:0;/.test(mutated)) {
            mutated = mutated.replace(/b:0;/, 'b:1;')
        } else if (/s:\d+:"role";s:\d+:"user";/i.test(mutated)) {
            mutated = mutated.replace(/s:\d+:"role";s:\d+:"user";/i, 's:4:"role";s:5:"admin";')
        } else if (/s:\d+:"isAdmin";b:0;/i.test(mutated)) {
            mutated = mutated.replace(/s:\d+:"isAdmin";b:0;/i, 's:7:"isAdmin";b:1;')
        } else {
            mutated = mutated.replace(/;$/, '') + ';b:1;'
        }
        return this._rewritePhpSerializedStringLengths(mutated)
    }

    _mutateJsonTypeText(source, mutationKind) {
        let parsed = null
        try {
            parsed = JSON.parse(String(source ?? ''))
        } catch (_) {
            return null
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
        const keys = Object.keys(parsed)
        const typeKey = keys.find(k => ['$type', '@class', '__type'].includes(k)) || '$type'
        if (mutationKind === 'control') {
            parsed[typeKey] = 'Invalid.Type, MissingAssembly'
        } else {
            parsed[typeKey] = 'System.Windows.Data.ObjectDataProvider, PresentationFramework'
        }
        try {
            return JSON.stringify(parsed)
        } catch (_) {
            return null
        }
    }

    _mutateSerializedBytes(sourceBytes, mutationKind) {
        if (!(sourceBytes instanceof Uint8Array) || sourceBytes.length < 6) return null
        const out = Uint8Array.from(sourceBytes)
        if (mutationKind === 'control') {
            return out.slice(0, Math.max(4, out.length - 2))
        }
        const idx = Math.max(4, out.length - 1)
        out[idx] = out[idx] ^ 0x01
        return out
    }

    _normalizeToBytes(value) {
        if (value instanceof Uint8Array) return value
        return this._stringToUtf8Bytes(String(value ?? ''))
    }

    _reencodeDeserValue(decodedValue, codecChain) {
        let currentBytes = this._normalizeToBytes(decodedValue)
        let currentText = this._utf8BytesToString(currentBytes)
        const steps = Array.isArray(codecChain) ? [...codecChain].reverse() : []
        for (const step of steps) {
            if (step?.type === 'base64') {
                const encoded = this._encodeBytesToBase64(
                    currentBytes,
                    String(step.variant || 'std'),
                    String(step.padding || 'keep')
                )
                if (typeof encoded !== 'string') return null
                currentText = encoded
                currentBytes = this._stringToUtf8Bytes(currentText)
                continue
            }
            if (step?.type === 'url') {
                currentText = encodeURIComponent(currentText)
                currentBytes = this._stringToUtf8Bytes(currentText)
                continue
            }
            // gzip/deflate are reserved in contract; skip mutation if chain contains unsupported step.
            return null
        }
        return currentText
    }

    _mutateDeserCandidate(candidate, mutationKind = 'semantic') {
        const kind = String(mutationKind || 'semantic').toLowerCase()
        const family = String(candidate?.formatFamily || 'unknown')
        const decoded = candidate?.decodedValue
        let mutatedDecoded = null
        let mutationLabel = kind

        if (family === 'php_serialized') {
            const source = (decoded instanceof Uint8Array) ? this._utf8BytesToString(decoded) : String(decoded ?? '')
            mutatedDecoded = this._mutatePhpSerializedText(source, kind === 'control' ? 'control' : 'semantic')
        } else if (family === 'json_type_metadata') {
            const source = (decoded instanceof Uint8Array) ? this._utf8BytesToString(decoded) : String(decoded ?? '')
            mutatedDecoded = this._mutateJsonTypeText(source, kind === 'control' ? 'control' : 'semantic')
        } else if (family === 'java_serialized' || family === 'dotnet_viewstate' || family === 'ruby_marshaled') {
            const bytes = this._normalizeToBytes(decoded)
            mutatedDecoded = this._mutateSerializedBytes(bytes, kind === 'control' ? 'control' : 'semantic')
            mutationLabel = kind === 'control' ? 'control' : 'parser_probe'
        } else {
            const source = (decoded instanceof Uint8Array) ? this._utf8BytesToString(decoded) : String(decoded ?? '')
            mutatedDecoded = kind === 'control' ? `${source}.invalid` : `${source}.tampered`
        }

        if (mutatedDecoded == null) return null
        const mutatedRaw = this._reencodeDeserValue(mutatedDecoded, candidate?.codecChain || [])
        if (typeof mutatedRaw !== 'string' || !mutatedRaw.length) return null
        return {
            rawValue: mutatedRaw,
            decodedValue: mutatedDecoded,
            mutationLabel
        }
    }

    _applyDeserRawMutation(schema, candidate, mutatedRaw, mutations = null) {
        const surface = String(candidate?.surface || '')
        const name = String(candidate?.name || '')
        if (!name) return schema

        if (surface === 'cookie') {
            const cookieAction = { cookies: [{ name, value: mutatedRaw, operation: 'replace' }] }
            return this.modifyCookies(schema, cookieAction, name, mutations)
        }

        if (surface === 'json') {
            const jsonAction = { params: [{ name, value: mutatedRaw, operation: 'replace' }] }
            return this.modifyJsonParams(schema, jsonAction, name, mutations)
        }

        const location = this._normalizeCandidateLocation(candidate?.location)
        const paramAction = { params: [{ name, value: mutatedRaw, operation: 'replace', location }] }
        if (location === 'query') {
            return this.modifyGetParams(schema, paramAction, name, mutations)
        }
        return this.modifyPostParams(schema, paramAction, name, mutations)
    }

    _isDeserializationCoverageAttack(attack) {
        const runtimeProfile = this._attackRuntimeConfig(attack, 'deserialization')
        const hasDeserProfile = !!(runtimeProfile && typeof runtimeProfile === 'object')
        if (hasDeserProfile && this._isDeserializationTechniqueModule()) return true
        // Legacy fallback for older module catalogs that relied on module id + attack id.
        if (this.id !== 'insecure_deserialization_coverage' && this.id !== 'deserialization_active_tamper') return false
        const attackId = String(attack?.id || '').toLowerCase()
        return attackId.startsWith('deser_')
    }

    _isDeserializationTechniqueModule() {
        if (String(this?._moduleRuntimeConfig()?.mode || '').toLowerCase() === 'deserialization') return true
        const taxonomy = this._moduleTaxonomyConfig()
        const category = String(taxonomy.category || this?.metadata?.category || '').toLowerCase()
        const vulnId = String(taxonomy.vulnId || this?.metadata?.vulnId || '').toLowerCase()
        if (category === 'deserialization' || vulnId === 'deserialization') return true
        // Legacy fallback for built-in ids.
        return this.id === 'insecure_deserialization'
            || this.id === 'insecure_deserialization_coverage'
            || this.id === 'deserialization_active_tamper'
    }

    _resolveDeserializationAttackProfile(attack) {
        const id = String(attack?.id || '').toLowerCase()
        const defaults = {
            mutationKind: 'semantic',
            familyAllow: null,
            minCandidateConfidence: 0.7,
            maxCandidates: 2
        }

        const fromRuntime = this._attackRuntimeConfig(attack, 'deserialization')
        if (fromRuntime && typeof fromRuntime === 'object') {
            const merged = Object.assign({}, defaults, fromRuntime)
            const normalizedMutation = String(merged.mutationKind || defaults.mutationKind).toLowerCase()
            const familyAllow = Array.isArray(merged.familyAllow)
                ? merged.familyAllow.map(v => String(v || '').toLowerCase()).filter(Boolean)
                : null
            return {
                mutationKind: normalizedMutation,
                familyAllow: familyAllow && familyAllow.length ? familyAllow : null,
                minCandidateConfidence: Number.isFinite(merged.minCandidateConfidence)
                    ? Number(merged.minCandidateConfidence)
                    : defaults.minCandidateConfidence,
                maxCandidates: this._clampInt(
                    Number.isFinite(merged.maxCandidates) ? Number(merged.maxCandidates) : defaults.maxCandidates,
                    1,
                    10
                )
            }
        }

        // Legacy fallback for backward compatibility with older catalogs.
        if (id.includes('php_signature_control')) {
            return Object.assign({}, defaults, {
                mutationKind: 'control',
                familyAllow: ['php_serialized'],
                maxCandidates: 2
            })
        }
        if (id.includes('php_semantic')) {
            return Object.assign({}, defaults, {
                mutationKind: 'semantic',
                familyAllow: ['php_serialized'],
                maxCandidates: 2
            })
        }
        if (id.includes('java_dotnet_parser')) {
            return Object.assign({}, defaults, {
                mutationKind: 'parser_probe',
                familyAllow: ['java_serialized', 'dotnet_viewstate'],
                maxCandidates: 1
            })
        }
        if (id.includes('json_type_semantic')) {
            return Object.assign({}, defaults, {
                mutationKind: 'semantic',
                familyAllow: ['json_type_metadata'],
                maxCandidates: 2
            })
        }
        return defaults
    }

    _buildDeserializationAttacks(schema, prepared) {
        const attacks = []
        const cfg = this._resolveDeserializationAttackProfile(prepared)
        const minConfidence = Number.isFinite(cfg?.minCandidateConfidence) ? Number(cfg.minCandidateConfidence) : 0.55
        const candidates = this._detectDeserCandidates(schema, { minConfidence })

        const familyAllow = Array.isArray(cfg?.familyAllow)
            ? new Set(cfg.familyAllow.map(v => String(v || '').toLowerCase()))
            : null
        const selectorAction = {
            family: 'deserialization',
            scoredFallback: true
        }

        const rankedEntries = this._sortRankedCandidates(
            candidates
                .filter((candidate) => {
                    if (familyAllow && !familyAllow.has(String(candidate?.formatFamily || '').toLowerCase())) return false
                    return true
                })
                .map((candidate) => ({
                    candidate,
                    rank: this._rankParamCandidate({
                        location: candidate.location,
                        name: candidate.name,
                        value: candidate.rawValue,
                        jsonPath: candidate.jsonPath || '',
                        deserConfidence: candidate.confidence
                    }, selectorAction, { family: 'deserialization' })
                }))
        )
        const selected = rankedEntries
        const mutationKind = String(cfg?.mutationKind || 'semantic').toLowerCase()

        for (const entry of selected) {
            const candidate = entry?.candidate
            if (!candidate) continue

            const hardDenySurface = candidate.surface === 'cookie'
                ? 'cookies'
                : (candidate.surface === 'json' ? 'json' : 'params')
            if (this._isAuthLikeHardBlocked(hardDenySurface, {
                name: candidate.name,
                value: candidate.rawValue,
                location: candidate.location
            })) {
                this._noteSelectorSkip(hardDenySurface, 'auth_like_hard_deny', candidate.name)
                continue
            }

            const mutated = this._mutateDeserCandidate(candidate, mutationKind)
            if (!mutated?.rawValue) continue

            const _schema = this._clone(schema)
            const mutations = []
            this._applyDeserRawMutation(_schema, candidate, mutated.rawValue, mutations)
            if (!mutations.length) continue
            this._applyAttackOptions(_schema, prepared)

            _schema.metadata = _schema.metadata || {}
            _schema.metadata.mutations = mutations
            _schema.metadata.attacked = this._normalizeReportedMutation(_schema, mutations[0])
            _schema.metadata.deserializationProbe = true
            _schema.metadata.deserFamily = candidate.formatFamily
            _schema.metadata.deserMutationKind = mutationKind
            _schema.metadata.codecChain = candidate.codecChain
            _schema.metadata.formatFamily = candidate.formatFamily
            _schema.metadata.mutationsRun = ['baseline', mutationKind]
            _schema.metadata.deserialization = {
                candidate: {
                    surface: candidate.surface,
                    name: candidate.name,
                    rawValue: candidate.rawValue,
                    codecChain: candidate.codecChain,
                    formatFamily: candidate.formatFamily,
                    confidence: candidate.confidence,
                    sensitivityClass: candidate.sensitivityClass,
                    evidence: candidate.evidence
                },
                mutationKind,
                mutationLabel: mutated.mutationLabel,
                mutatedRawValue: mutated.rawValue
            }

            attacks.push(_schema)
        }

        return attacks
    }

    _parseJsonValue(value) {
        const text = String(value ?? '').trim()
        if (!text) return null
        if (!((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']')))) {
            return null
        }
        try {
            const parsed = JSON.parse(text)
            if (parsed && typeof parsed === 'object') return parsed
        } catch (_) {
            return null
        }
        return null
    }

    _clampInt(value, min, max) {
        const num = Number.isFinite(value) ? value : 0
        return Math.max(min, Math.min(max, Math.trunc(num)))
    }

    _reconSeenCount(_candidate) {
        return 0
    }

    _classifyParamUncached(candidate, family = 'sqli') {
        const name = String(candidate?.name ?? '')
        const lname = name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()
        const value = String(candidate?.value ?? '')
        const location = this._normalizeCandidateLocation(candidate?.location)
        const valueTrimmed = value.trim()
        const valueWordCount = valueTrimmed ? valueTrimmed.split(/\s+/).filter(Boolean).length : 0
        const hasLineBreak = /[\r\n]/.test(value)
        const reasons = []
        const nameHints = []
        const valueHints = []

        let type = 'unknown'
        let typeConfidence = 0.4
        if (/^-?\d+$/.test(valueTrimmed)) {
            type = 'int'
            typeConfidence = 0.95
            valueHints.push('value:int')
        } else if (this._isNumericLike(valueTrimmed)) {
            type = 'float'
            typeConfidence = 0.9
            valueHints.push('value:float')
        } else if (/^(true|false|0|1)$/i.test(valueTrimmed)) {
            type = 'bool'
            typeConfidence = 0.82
            valueHints.push('value:bool')
        } else if (this._looksUuid(valueTrimmed)) {
            type = 'uuid'
            typeConfidence = 0.95
            valueHints.push('value:uuid')
        } else if (this._looksObjectIdLike(valueTrimmed)) {
            type = 'objectid'
            typeConfidence = 0.93
            valueHints.push('value:objectid')
        } else if (this._looksDate(valueTrimmed)) {
            type = 'date'
            typeConfidence = 0.82
            valueHints.push('value:date')
        } else if (this._looksEmail(valueTrimmed)) {
            type = 'email'
            typeConfidence = 0.9
            valueHints.push('value:email')
        } else if (this._looksUrl(valueTrimmed)) {
            type = 'url'
            typeConfidence = 0.9
            valueHints.push('value:url')
        } else if (this._parseJsonValue(valueTrimmed)) {
            type = 'json'
            typeConfidence = 0.9
            valueHints.push('value:json')
        } else if (this._looksTokenLike(valueTrimmed)) {
            type = 'token_like'
            typeConfidence = 0.92
            valueHints.push('value:token_like')
        } else if (valueTrimmed.length > 0) {
            type = 'string'
            typeConfidence = 0.6
            valueHints.push('value:string')
        } else {
            type = 'opaque'
            typeConfidence = 0.5
            valueHints.push('value:empty')
        }

        let sensitivity = 'low_risk'
        let sensitivityConfidence = 0.6
        const authLikeByName = /(?:^|[_-])(auth|token|jwt|bearer|csrf|xsrf|session|sessionid|sid|pass|password|pwd)(?:$|[_-])/.test(lname)
        const authLikeByValue = type === 'token_like' || this._looksJwtLike(valueTrimmed)
        if (authLikeByName || authLikeByValue) {
            sensitivity = 'auth_like'
            sensitivityConfidence = authLikeByValue ? 0.95 : 0.85
            reasons.push(authLikeByValue ? 'auth_like:value' : 'auth_like:name')
        } else if (/(email|phone|mobile|address|ssn|dob|firstname|lastname|fullname|user(name)?)/.test(lname) || type === 'email' || type === 'date') {
            sensitivity = 'pii_like'
            sensitivityConfidence = 0.78
            reasons.push('pii_like')
        } else {
            reasons.push('low_risk')
        }

        if (/(url|uri|endpoint|callback|redirect|return|next|dest|target|webhook|src|image|img|link)/.test(lname)) {
            nameHints.push('name:url_like')
        }
        if (/(path|file|filename|template|include|view|asset|layout|fragment|dir)/.test(lname)) {
            nameHints.push('name:path_like')
        }
        if (/(?:^|[_-])(id|userid|user_id|accountid|account_id|ownerid|owner_id)(?:$|[_-])/.test(lname) || /^(id|userId|accountId|ownerId)$/i.test(name)) {
            nameHints.push('name:id_like')
        }
        if (/(?:^|[._-]|\[)(username|user|email|login|account|identifier|userid|user_id|phone)(?:$|[._-]|\[)/.test(lname) || /^(username|user|email|login|account|identifier|userId|user_id|phone)$/i.test(name)) {
            nameHints.push('name:auth_identity')
        }
        if (/(?:^|[._-]|\[)(otp|mfa|2fa|totp|one[-_ ]?time|verification|verify|challenge)(?:$|[._-]|\[)/.test(lname) || /^(otp|mfa|totp|code)$/i.test(name)) {
            nameHints.push('name:auth_challenge')
        }
        if (/(?:^|[._-]|\[)(pass(word)?|passwd|pwd|current[_-]?password|new[_-]?password|confirm[_-]?password|currentpassword|newpassword|confirmpassword)(?:$|[._-]|\[)/.test(lname) || /^(pass|password|passwd|pwd|currentPassword|newPassword|confirmPassword)$/i.test(name)) {
            nameHints.push('name:auth_secret')
        }
        if (/(?:^|[._-]|\[)(state|csrf|nonce)(?:$|[._-]|\[)/.test(lname) || /^(state|csrf|nonce)$/i.test(name)) {
            nameHints.push('name:oauth_state')
        }
        if (/(?:^|[._-]|\[)(code[_-]?challenge|code[_-]?verifier|pkce|challenge[_-]?method|codechallenge|codeverifier|challengemethod)(?:$|[._-]|\[)/.test(lname)) {
            nameHints.push('name:oauth_pkce')
        }
        if (/(?:^|[._-]|\[)(response[_-]?mode|response[_-]?type|grant[_-]?type|responsemode|responsetype|granttype)(?:$|[._-]|\[)/.test(lname)) {
            nameHints.push('name:oauth_response')
        }
        if (/(?:^|[._-]|\[)(redirect[_-]?uri|redirecturi|callback[_-]?url|callback[_-]?uri|callbackurl|callbackuri|return[_-]?url|return[_-]?uri|returnurl|returnuri)(?:$|[._-]|\[)/.test(lname)) {
            nameHints.push('name:oauth_redirect')
        }
        if (/(?:^|[._-]|\[)(relaystate)(?:$|[._-]|\[)/.test(lname) || /^relaystate$/i.test(name)) {
            nameHints.push('name:saml_relay')
        }
        if (/(?:^|[._-]|\[)(post[_-]?logout[_-]?redirect[_-]?uri|postlogoutredirecturi)(?:$|[._-]|\[)/.test(lname)) {
            nameHints.push('name:saml_post_logout')
        }

        const textLikeType = type === 'string' || type === 'unknown' || type === 'opaque'
        const htmlLikeValue = textLikeType && this._looksHtmlLikeValue(valueTrimmed)
        const markdownLikeValue = textLikeType && !htmlLikeValue && this._looksMarkdownLikeValue(valueTrimmed)
        const urlLikeValue = type === 'url' || this._looksRelativeUrlLike(valueTrimmed)
        const shortTextValue = textLikeType
            && valueTrimmed.length > 0
            && valueTrimmed.length <= 80
            && valueWordCount <= 12
            && !urlLikeValue
            && !htmlLikeValue
            && !markdownLikeValue
        const longTextValue = textLikeType
            && (valueTrimmed.length >= 120 || valueWordCount >= 20 || hasLineBreak)
            && !urlLikeValue
        const sentenceTextValue = textLikeType
            && valueTrimmed.length >= 20
            && valueWordCount >= 3
            && !urlLikeValue
            && !htmlLikeValue
            && !markdownLikeValue

        const semanticTags = []
        if (location === 'json') semanticTags.push('json_leaf')
        if (location === 'query') semanticTags.push('query_param')
        if (location === 'form') semanticTags.push('form_param')
        if (location === 'cookie') semanticTags.push('cookie_value')
        if (location === 'header') semanticTags.push('header_value')
        if (textLikeType) semanticTags.push('text_like_value')
        if (urlLikeValue) semanticTags.push('url_like_value')
        if (this._looksRedirectLikeValue(valueTrimmed)) semanticTags.push('redirect_like_value')
        if (this._looksPathLikeValue(valueTrimmed)) semanticTags.push('path_like_value')
        if (type === 'int' || type === 'uuid' || type === 'objectid') semanticTags.push('id_like_value')
        if (textLikeType && sensitivity !== 'auth_like') semanticTags.push('writable_text')
        if (shortTextValue) semanticTags.push('short_text_value')
        if (longTextValue) semanticTags.push('long_text_value')
        if (hasLineBreak && textLikeType) semanticTags.push('multiline_text_value')
        if (sentenceTextValue) semanticTags.push('sentence_text_value')
        if (htmlLikeValue) semanticTags.push('html_like_value', 'rich_text_value')
        if (markdownLikeValue) semanticTags.push('markdown_like_value', 'rich_text_value')
        if (nameHints.includes('name:url_like')) semanticTags.push('url_field')
        if (nameHints.includes('name:path_like')) semanticTags.push('path_field')
        if (nameHints.includes('name:id_like')) semanticTags.push('id_field')
        if (nameHints.includes('name:auth_identity')) semanticTags.push('auth_identity_field')
        if (nameHints.includes('name:auth_challenge')) semanticTags.push('auth_challenge_field')
        if (nameHints.includes('name:auth_secret')) semanticTags.push('auth_secret_field')
        if (nameHints.includes('name:oauth_state')) semanticTags.push('oauth_state_field')
        if (nameHints.includes('name:oauth_pkce')) semanticTags.push('oauth_pkce_field')
        if (nameHints.includes('name:oauth_response')) semanticTags.push('oauth_response_field')
        if (nameHints.includes('name:oauth_redirect')) semanticTags.push('oauth_redirect_field')
        if (nameHints.includes('name:saml_relay')) semanticTags.push('saml_relay_field')
        if (nameHints.includes('name:saml_post_logout')) semanticTags.push('saml_post_logout_field')

        const byFamily = {
            sqli: { score: 0, confidence: 0.5, reasons: [] },
            ssrf: { score: 0, confidence: 0.5, reasons: [] },
            xss: { score: 0, confidence: 0.5, reasons: [] },
            deserialization: { score: 0, confidence: 0.5, reasons: [] },
            redirect: { score: 0, confidence: 0.5, reasons: [] },
            traversal: { score: 0, confidence: 0.5, reasons: [] },
            idor: { score: 0, confidence: 0.5, reasons: [] },
            auth: { score: 0, confidence: 0.5, reasons: [] }
        }

        const sqliScoreBase = (() => {
            if (type === 'token_like') return -90
            if (type === 'int' || type === 'float' || type === 'uuid' || type === 'objectid') return 120
            if (type === 'string' || type === 'unknown' || type === 'opaque') return 90
            if (type === 'url' || type === 'json') return 45
            return 35
        })()
        let sqliScore = sqliScoreBase
        if (location === 'query' || location === 'form') sqliScore += 20
        if (location === 'cookie') sqliScore += 10
        byFamily.sqli.score = this._clampInt(sqliScore, -100, 200)
        byFamily.sqli.confidence = Math.min(1, Math.max(0, Number(typeConfidence || 0.5)))
        byFamily.sqli.reasons = [`type:${type}`, `location:${location}`]

        let ssrfScore = -20
        if (type === 'url') ssrfScore = 180
        else if (type === 'string') ssrfScore = 70
        else if (type === 'unknown' || type === 'opaque') ssrfScore = 50
        else if (type === 'token_like') ssrfScore = -90
        if (location === 'query' || location === 'form' || location === 'json') ssrfScore += 10
        byFamily.ssrf.score = this._clampInt(ssrfScore, -100, 200)
        byFamily.ssrf.confidence = Math.min(1, Math.max(0, Number(typeConfidence || 0.5)))
        byFamily.ssrf.reasons = [`type:${type}`, `location:${location}`]

        let xssScore = 10
        if (type === 'string' || type === 'unknown' || type === 'opaque') xssScore = 130
        if (type === 'json') xssScore = 60
        if (type === 'int' || type === 'float' || type === 'bool' || type === 'objectid') xssScore = -40
        if (type === 'token_like') xssScore = -90
        if (location === 'query' || location === 'form' || location === 'json') xssScore += 10
        if (semanticTags.includes('html_like_value')) xssScore += 22
        if (semanticTags.includes('markdown_like_value')) xssScore += 18
        if (semanticTags.includes('long_text_value')) xssScore += 14
        if (semanticTags.includes('multiline_text_value')) xssScore += 12
        if (semanticTags.includes('sentence_text_value')) xssScore += 10
        if (semanticTags.includes('short_text_value')) xssScore += 6
        byFamily.xss.score = this._clampInt(xssScore, -100, 200)
        byFamily.xss.confidence = Math.min(1, Math.max(0, Number(typeConfidence || 0.5)))
        byFamily.xss.reasons = [`type:${type}`, `location:${location}`]

        let deserScore = -20
        if (type === 'token_like') deserScore = 160
        else if (type === 'string' || type === 'unknown' || type === 'opaque') deserScore = 95
        else if (type === 'json') deserScore = 120
        else if (type === 'url') deserScore = 40
        else deserScore = 30
        if (location === 'cookie') deserScore += 25
        if (location === 'query' || location === 'form' || location === 'json') deserScore += 10
        byFamily.deserialization.score = this._clampInt(deserScore, -100, 200)
        byFamily.deserialization.confidence = Math.min(1, Math.max(0, Number(typeConfidence || 0.5)))
        byFamily.deserialization.reasons = [`type:${type}`, `location:${location}`]

        let redirectScore = -30
        if (type === 'url' || type === 'relative_url') redirectScore = 185
        else if (type === 'string' || type === 'unknown' || type === 'opaque') redirectScore = 70
        else if (type === 'token_like') redirectScore = -90
        if (semanticTags.includes('redirect_like_value')) redirectScore += 25
        if (semanticTags.includes('url_field')) redirectScore += 12
        if (location === 'query' || location === 'form' || location === 'json') redirectScore += 10
        byFamily.redirect.score = this._clampInt(redirectScore, -100, 200)
        byFamily.redirect.confidence = Math.min(1, Math.max(0, Number(typeConfidence || 0.5)))
        byFamily.redirect.reasons = [`type:${type}`, `location:${location}`]

        let traversalScore = -25
        if (type === 'path') traversalScore = 190
        else if (type === 'string' || type === 'unknown' || type === 'opaque') traversalScore = 75
        else if (type === 'url' || type === 'relative_url') traversalScore = 40
        else if (type === 'token_like') traversalScore = -90
        if (semanticTags.includes('path_like_value')) traversalScore += 25
        if (semanticTags.includes('path_field')) traversalScore += 12
        if (location === 'query' || location === 'form' || location === 'json') traversalScore += 10
        byFamily.traversal.score = this._clampInt(traversalScore, -100, 200)
        byFamily.traversal.confidence = Math.min(1, Math.max(0, Number(typeConfidence || 0.5)))
        byFamily.traversal.reasons = [`type:${type}`, `location:${location}`]

        let idorScore = -30
        if (type === 'int' || type === 'uuid' || type === 'objectid') idorScore = 185
        else if (type === 'string' || type === 'unknown' || type === 'opaque') idorScore = 65
        else if (type === 'token_like') idorScore = -90
        if (semanticTags.includes('id_like_value')) idorScore += 25
        if (semanticTags.includes('id_field')) idorScore += 18
        if (location === 'query' || location === 'form' || location === 'json') idorScore += 10
        byFamily.idor.score = this._clampInt(idorScore, -100, 200)
        byFamily.idor.confidence = Math.min(1, Math.max(0, Number(typeConfidence || 0.5)))
        byFamily.idor.reasons = [`type:${type}`, `location:${location}`]

        let authScore = -10
        if (type === 'email') authScore = 185
        else if (type === 'token_like') authScore = 160
        else if (type === 'int' || type === 'float') authScore = 125
        else if (type === 'string' || type === 'unknown' || type === 'opaque') authScore = 140
        else if (type === 'url' || type === 'relative_url') authScore = 95
        else if (type === 'json') authScore = 60
        const authSemanticBoostTags = [
            'auth_identity_field',
            'auth_challenge_field',
            'auth_secret_field',
            'oauth_state_field',
            'oauth_pkce_field',
            'oauth_response_field',
            'oauth_redirect_field',
            'saml_relay_field',
            'saml_post_logout_field'
        ]
        if (authSemanticBoostTags.some((tag) => semanticTags.includes(tag))) authScore += 30
        if (location === 'query' || location === 'form' || location === 'json') authScore += 10
        byFamily.auth.score = this._clampInt(authScore, -100, 200)
        byFamily.auth.confidence = Math.min(1, Math.max(0, Number(typeConfidence || 0.5)))
        byFamily.auth.reasons = [`type:${type}`, `location:${location}`]

        const selectedFamily = byFamily[family] || byFamily.sqli
        selectedFamily.score = this._clampInt(selectedFamily.score, -100, 200)

        return {
            type,
            typeConfidence,
            sensitivity,
            sensitivityConfidence,
            semanticTags: Array.from(new Set(semanticTags)),
            attackabilityByFamily: byFamily,
            reasons,
            nameHints,
            valueHints
        }
    }

    _classifyParam(candidate, family = 'sqli') {
        const cacheEntry = this._candidateEvaluationEntry(candidate)
        if (cacheEntry?.classification) {
            return cacheEntry.classification
        }
        const classification = this._classifyParamUncached(candidate, family)
        if (cacheEntry) {
            cacheEntry.classification = classification
        }
        return classification
    }

    _isAuthLikeHardBlocked(surface, candidate) {
        const location = this._normalizeCandidateLocation(candidate?.location || (surface === 'params' ? 'form' : surface))
        const classification = this._classifyParam({
            name: candidate?.name,
            value: candidate?.value,
            location
        }, this._selectorFamily(null))
        if (classification.sensitivity !== 'auth_like') return false
        if (Number(classification.sensitivityConfidence || 0) < 0.8) return false
        const execution = this._moduleExecutionConfig()
        const moduleAllows = execution.allowAuthLikeTargets === true
            || execution.requiresAuthLike === true
            || this?.metadata?.allowAuthLikeTargets === true
            || this?.metadata?.requiresAuthLike === true
        return !moduleAllows
    }

    _namePriorFromPolicy(candidate, action) {
        let prior = 0
        const name = String(candidate?.name ?? '')
        if (action?.scoredFallback === true && action?.nameRegex) {
            const matcher = this._compileParamNameRegex(action)
            if (matcher?.test(name)) prior += 4
        }
        return this._clampInt(prior, 0, 10)
    }

    _rankParamCandidate(candidate, action, opts = {}) {
        const family = opts.family || this._selectorFamily(action)
        const cacheEntry = this._candidateEvaluationEntry(candidate)
        const rankCacheKey = this._rankCacheKey(action, family)
        if (cacheEntry?.rankByKey?.has(rankCacheKey)) {
            return cacheEntry.rankByKey.get(rankCacheKey)
        }
        const classification = this._classifyParam(candidate, family)
        const familyEntry = classification.attackabilityByFamily?.[family] || { score: 0, confidence: 0.5, reasons: [] }
        const familyScore = this._clampInt(familyEntry.score, -100, 200)
        const candidateName = String(candidate?.name ?? '')
        const candidatePath = String(candidate?.path ?? candidate?.jsonPath ?? '')
        const explicitName = String(action?.name ?? '')
        const explicitOverrideScore = (explicitName && (
            candidateName.toLowerCase() === explicitName.toLowerCase()
            || candidatePath.toLowerCase() === explicitName.toLowerCase()
        )) ? 300 : 0
        const selectorMode = this._selectorMode(action)

        const typeBonus = 0
        const locationBonus = 0
        const deserConfidenceBonus = (family === 'deserialization')
            ? this._clampInt(Math.round(Number(candidate?.deserConfidence || 0) * 80), 0, 80)
            : 0

        const nameRegexMatcher = this._compileParamNameRegex(action)
        const valueRegexMatcher = this._compileParamValueRegex(action)
        const selectorNameMatched = Boolean(nameRegexMatcher?.test(candidateName) || nameRegexMatcher?.test(candidatePath))
        const selectorValueMatched = Boolean(valueRegexMatcher?.test(String(candidate?.value ?? '')))
        const selectorPathMatched = this._matchesSelectorPath(action, candidate)
        const selectorValueTypeMatched = this._matchesSelectorValueType(action, candidate, classification)
        const semanticTags = Array.isArray(classification?.semanticTags) ? classification.semanticTags : []
        const requiredSemanticTags = Array.isArray(action?.semanticTagsAny)
            ? action.semanticTagsAny.map((value) => String(value ?? '').trim()).filter(Boolean)
            : []
        const matchedSemanticTags = requiredSemanticTags.filter((tag) => semanticTags.includes(tag))
        const selectorSemanticMatched = !requiredSemanticTags.length || matchedSemanticTags.length > 0
        const selectorHasSignals = this._selectorHasScoringSignals(action)
        const selectorWeight = Number.isFinite(Number(action?.weight)) ? Number(action.weight) : 0
        const selectorWeightBonus = this._clampInt(Math.round(selectorWeight), -200, 200)
        const nameMatchBonus = selectorNameMatched && action?.nameRegex ? 26 : 0
        const valueMatchBonus = selectorValueMatched && action?.valueRegex ? 28 : 0
        const pathBonus = selectorPathMatched && (action?.pathRegex || action?.jsonPathRegex) ? 18 : 0
        const valueTypeBonus = selectorValueTypeMatched && this._normalizeSelectorValueTypes(action?.valueTypeIn).length ? 16 : 0
        const semanticTagBonus = selectorSemanticMatched && matchedSemanticTags.length ? this._clampInt(matchedSemanticTags.length * 10, 0, 40) : 0
        const selectorSignalScore = this._clampInt(
            nameMatchBonus + valueMatchBonus + pathBonus + valueTypeBonus + semanticTagBonus + (selectorHasSignals ? selectorWeightBonus : 0),
            -300,
            300
        )
        const selectorMatched = selectorNameMatched || selectorValueMatched || selectorPathMatched || selectorValueTypeMatched || matchedSemanticTags.length > 0

        let sensitivitySoftPenalty = 0
        if (classification.sensitivity === 'auth_like') sensitivitySoftPenalty = family === 'auth' ? 40 : 250
        else if (classification.sensitivity === 'pii_like') sensitivitySoftPenalty = family === 'auth' ? 20 : 80
        const typePenalty = 0

        const namePrior = this._namePriorFromPolicy(candidate, action)

        const rankScore = this._clampInt(
            explicitOverrideScore
            + familyScore
            + typeBonus
            + locationBonus
            + deserConfidenceBonus
            + selectorSignalScore
            - sensitivitySoftPenalty
            - typePenalty
            + namePrior,
            -1000,
            1000
        )

        const result = {
            rankScore,
            confidence: Number(familyEntry?.confidence || 0),
            seenCount: this._reconSeenCount(candidate),
            key: this._candidateKey(candidate),
            classification,
            family,
            explicitOverrideScore,
            familyScore,
            typeBonus,
            locationBonus,
            deserConfidenceBonus,
            selectorMode,
            selectorHasSignals,
            selectorSignalScore,
            selectorWeightBonus,
            nameMatchBonus,
            valueMatchBonus,
            pathBonus,
            valueTypeBonus,
            semanticTagBonus,
            sensitivitySoftPenalty,
            typePenalty,
            namePrior,
            semanticTags,
            matchedSemanticTags,
            selectorMatched,
            selectorNameMatched,
            selectorValueMatched,
            selectorPathMatched,
            selectorValueTypeMatched
        }
        if (cacheEntry) {
            cacheEntry.rankByKey.set(rankCacheKey, result)
        }
        return result
    }

    _sortRankedCandidates(entries) {
        return (entries || []).sort((a, b) => {
            if (b.rank.rankScore !== a.rank.rankScore) return b.rank.rankScore - a.rank.rankScore
            if (b.rank.confidence !== a.rank.confidence) return b.rank.confidence - a.rank.confidence
            if (b.rank.seenCount !== a.rank.seenCount) return b.rank.seenCount - a.rank.seenCount
            return String(a.rank.key || '').localeCompare(String(b.rank.key || ''))
        })
    }

    _selectorRankSummary(rank) {
        if (!rank || typeof rank !== 'object') return null
        return {
            rankScore: Number(rank.rankScore || 0),
            selectorSignalScore: Number(rank.selectorSignalScore || 0),
            confidence: Number(rank.confidence || 0),
            family: String(rank.family || 'unknown'),
            classification: {
                type: rank.classification?.type || 'unknown',
                sensitivity: rank.classification?.sensitivity || 'unknown',
                semanticTags: Array.isArray(rank.classification?.semanticTags) ? rank.classification.semanticTags : []
            },
            selectorSignals: {
                mode: rank.selectorMode || 'filter',
                matched: rank.selectorMatched === true,
                nameMatched: rank.selectorNameMatched === true,
                valueMatched: rank.selectorValueMatched === true,
                pathMatched: rank.selectorPathMatched === true,
                valueTypeMatched: rank.selectorValueTypeMatched === true,
                matchedSemanticTags: Array.isArray(rank.matchedSemanticTags) ? rank.matchedSemanticTags : []
            },
            reasons: this._rankReasons(rank)
        }
    }

    _targetSelectorMetadata(candidate, action, overrides = {}) {
        const selectorCandidate = Object.assign({}, candidate || {}, overrides)
        const rank = this._rankParamCandidate(selectorCandidate, action, { family: this._selectorFamily(action) })
        return this._selectorRankSummary(rank)
    }

    _scoreParamCandidate(candidate, action) {
        return this._rankParamCandidate(candidate, action, { family: this._selectorFamily(action) }).rankScore
    }

    _scoreXmlCandidate(candidate, action) {
        return this._rankParamCandidate(candidate, action, { family: this._selectorFamily(action) }).rankScore
    }

    _selectXmlCandidates(schema, leaves, action, onlyPath = null) {
        const list = Array.isArray(leaves) ? leaves : []
        const hasExplicitName = Boolean(action?.name)
        const hasNameRegex = Boolean(action?.nameRegex)
        const hasValueRegex = Boolean(action?.valueRegex)
        const selectorMode = this._selectorMode(action)
        const regexHardInclude = this._selectorHasScoringSignals(action) && action?.scoredFallback !== true
        const pool = list.filter(candidate => {
            const name = candidate?.name
            if (!this.isAttackableName(name)) return false
            if (onlyPath && String(candidate?.path || '') !== String(onlyPath)) return false
            if (this._isHardDeniedName('params', name)) {
                this._noteSelectorSkip('params', 'hard_deny', name)
                return false
            }
            if (this._isAuthLikeHardBlocked('params', {
                name,
                value: candidate?.value,
                location: 'xml'
            })) {
                this._noteSelectorSkip('params', 'auth_like_hard_deny', name)
                return false
            }
            if (this._shouldSkipSoftGloballyExcludedTarget(schema, 'params', name, candidate?.value)) {
                this._noteSelectorSkip('params', 'global_exclude', name)
                return false
            }
            return true
        })

        let directMatches = []
        if (hasExplicitName) {
            const expected = String(action.name).toLowerCase()
            const explicitPath = expected.includes('/')
            directMatches = pool.filter(candidate => {
                const byName = String(candidate?.name ?? '').toLowerCase() === expected
                const byPath = String(candidate?.path ?? '').toLowerCase() === expected
                return explicitPath ? (byPath || byName) : byName
            })
        } else if (selectorMode === 'score') {
            const signalMatches = pool.filter(candidate => {
                const selectorCandidate = {
                    location: 'xml',
                    name: candidate?.name,
                    value: candidate?.value,
                    jsonPath: candidate?.path || '',
                    path: candidate?.path || ''
                }
                const classification = this._classifyParam(selectorCandidate, this._selectorFamily(action))
                return this._selectorSignalMatched(action, selectorCandidate, classification)
            })
            directMatches = signalMatches.length ? signalMatches : (action?.scoredFallback ? pool.slice() : [])
        } else if (hasNameRegex) {
            const matcher = this._compileParamNameRegex(action)
            directMatches = matcher
                ? pool.filter(candidate => {
                    return matcher.test(String(candidate?.name ?? '')) || matcher.test(String(candidate?.path ?? ''))
                })
                : []
        } else if (hasValueRegex) {
            directMatches = pool.filter(candidate => this._matchesSelectorValue(action, candidate?.value))
        } else {
            directMatches = pool.slice()
        }

        directMatches = directMatches.filter(candidate => !this._isParamExcluded(candidate?.name, action))
        directMatches = directMatches.filter(candidate => this._matchesSelectorLocation(action, 'xml'))
        directMatches = directMatches.filter(candidate => {
            const selectorCandidate = {
                location: 'xml',
                name: candidate?.name,
                value: candidate?.value,
                jsonPath: candidate?.path || '',
                path: candidate?.path || ''
            }
            const classification = this._classifyParam(selectorCandidate, this._selectorFamily(action))
            if (selectorMode === 'score') return true
            return this._selectorFilterMatched(action, selectorCandidate, classification)
        })
        const family = this._selectorFamily(action)

        if (directMatches.length && (hasExplicitName || regexHardInclude || !action?.scoredFallback)) {
            const rankedDirectEntries = this._sortRankedCandidates(
                directMatches.map(candidate => ({
                    candidate,
                    rank: this._rankParamCandidate({
                        location: 'xml',
                        name: candidate?.name,
                        value: candidate?.value,
                        jsonPath: candidate?.path
                    }, action, { family })
                }))
            )
            this._appendSelectorSelectionDiagnostics('xml', family, rankedDirectEntries, rankedDirectEntries)
            return rankedDirectEntries.map(entry => entry.candidate)
        }

        if (!action?.scoredFallback) return []

        const rankedEntries = this._sortRankedCandidates(
            directMatches.map(candidate => ({
                candidate,
                rank: this._rankParamCandidate({
                    location: 'xml',
                    name: candidate?.name,
                    value: candidate?.value,
                    jsonPath: candidate?.path
                }, action, { family })
                }))
        )
        this._appendSelectorSelectionDiagnostics('xml', family, rankedEntries, rankedEntries)
        return rankedEntries.map(entry => entry.candidate)
    }

    _selectParamCandidates(schema, params, action, onlyName = null) {
        const list = Array.isArray(params) ? params : []
        const hasExplicitName = Boolean(action?.name)
        const hasNameRegex = Boolean(action?.nameRegex)
        const hasValueRegex = Boolean(action?.valueRegex)
        const selectorMode = this._selectorMode(action)
        const regexHardInclude = this._selectorHasScoringSignals(action) && action?.scoredFallback !== true
        const pool = list.filter(candidate => {
            const name = candidate?.name
            if (!this.isAttackableName(name)) return false
            if (onlyName && String(name).toLowerCase() !== String(onlyName).toLowerCase()) return false
            if (this._isHardDeniedName('params', name)) {
                this._noteSelectorSkip('params', 'hard_deny', name)
                return false
            }
            if (this._isAuthLikeHardBlocked('params', {
                name,
                value: candidate?.value,
                location: candidate?.location
            })) {
                this._noteSelectorSkip('params', 'auth_like_hard_deny', name)
                return false
            }
            if (this._shouldSkipSoftGloballyExcludedTarget(schema, 'params', name, candidate?.value)) {
                this._noteSelectorSkip('params', 'global_exclude', name)
                return false
            }
            return true
        })

        let directMatches = []
        if (hasExplicitName) {
            directMatches = pool.filter(candidate => String(candidate?.name).toLowerCase() === String(action.name).toLowerCase())
        } else if (selectorMode === 'score') {
            const signalMatches = pool.filter(candidate => {
                const classification = this._classifyParam(candidate, this._selectorFamily(action))
                return this._selectorSignalMatched(action, candidate, classification)
            })
            directMatches = signalMatches.length ? signalMatches : (action?.scoredFallback ? pool.slice() : [])
        } else if (hasNameRegex) {
            const matcher = this._compileParamNameRegex(action)
            directMatches = matcher ? pool.filter(candidate => matcher.test(String(candidate?.name ?? '')) || matcher.test(String(candidate?.path ?? ''))) : []
        } else if (hasValueRegex) {
            directMatches = pool.filter(candidate => this._matchesSelectorValue(action, candidate?.value))
        } else {
            directMatches = pool.slice()
        }
        directMatches = directMatches.filter(candidate => !this._isParamExcluded(candidate?.name, action))
        directMatches = directMatches.filter(candidate => this._matchesSelectorLocation(action, candidate?.location))
        directMatches = directMatches.filter(candidate => {
            const classification = this._classifyParam(candidate, this._selectorFamily(action))
            if (selectorMode === 'score') return true
            return this._selectorFilterMatched(action, candidate, classification)
        })
        const family = this._selectorFamily(action)

        if (directMatches.length && (hasExplicitName || regexHardInclude || !action?.scoredFallback)) {
            const rankedDirectEntries = this._sortRankedCandidates(
                directMatches.map(candidate => ({
                    candidate,
                    rank: this._rankParamCandidate(candidate, action, { family })
                }))
            )
            this._appendSelectorSelectionDiagnostics('params', family, rankedDirectEntries, rankedDirectEntries)
            return rankedDirectEntries.map(entry => entry.candidate)
        }

        if (!action?.scoredFallback) return []

        const rankedEntries = this._sortRankedCandidates(
            directMatches.map(candidate => ({
                candidate,
                rank: this._rankParamCandidate(candidate, action, { family })
            }))
        )
        this._appendSelectorSelectionDiagnostics('params', family, rankedEntries, rankedEntries)
        return rankedEntries.map(entry => entry.candidate)
    }

    _isCookieExcluded(cookieName, action) {
        const candidate = String(cookieName ?? '')
        const excludeMatcher = this._compileCookieExcludeRegex(action)
        if (!excludeMatcher) return false
        return excludeMatcher.test(candidate)
    }

    _scoreCookieCandidate(cookie, action) {
        return this._rankParamCandidate({
            location: 'cookie',
            name: cookie?.name,
            value: cookie?.value
        }, action, { family: this._selectorFamily(action) }).rankScore
    }

    _selectCookieCandidates(cookies, action, onlyName = null) {
        const list = Array.isArray(cookies) ? cookies : []
        const hasExplicitName = Boolean(action?.name)
        const hasNameRegex = Boolean(action?.nameRegex)
        const selectorMode = this._selectorMode(action)
        const regexHardInclude = this._selectorHasScoringSignals(action) && action?.scoredFallback !== true
        const pool = list.filter(cookie => {
            const name = cookie?.name
            if (!this.isAttackableName(name)) return false
            if (onlyName && String(name).toLowerCase() !== String(onlyName).toLowerCase()) return false
            if (this._isHardDeniedName('cookies', name)) {
                this._noteSelectorSkip('cookies', 'hard_deny', name)
                return false
            }
            if (this._isAuthLikeHardBlocked('cookies', {
                name,
                value: cookie?.value,
                location: 'cookie'
            })) {
                this._noteSelectorSkip('cookies', 'auth_like_hard_deny', name)
                return false
            }
            if (this._isSoftGloballyExcluded('cookies', name)) {
                this._noteSelectorSkip('cookies', 'global_exclude', name)
                return false
            }
            if (this._isCookieExcluded(name, action)) return false
            return true
        })

        let directMatches = []
        if (hasExplicitName) {
            directMatches = pool.filter(cookie => String(cookie?.name).toLowerCase() === String(action.name).toLowerCase())
        } else if (selectorMode === 'score') {
            const signalMatches = pool.filter(cookie => {
                const selectorCandidate = {
                    location: 'cookie',
                    name: cookie?.name,
                    value: cookie?.value
                }
                const classification = this._classifyParam(selectorCandidate, this._selectorFamily(action))
                return this._selectorSignalMatched(action, selectorCandidate, classification)
            })
            directMatches = signalMatches.length ? signalMatches : (action?.scoredFallback ? pool.slice() : [])
        } else if (hasNameRegex) {
            const matcher = this._compileParamNameRegex(action)
            directMatches = matcher ? pool.filter(cookie => matcher.test(String(cookie?.name ?? ''))) : []
        } else {
            directMatches = pool.slice()
        }
        directMatches = directMatches.filter(cookie => {
            const selectorCandidate = {
                location: 'cookie',
                name: cookie?.name,
                value: cookie?.value
            }
            const classification = this._classifyParam(selectorCandidate, this._selectorFamily(action))
            if (selectorMode === 'score') return true
            return this._selectorFilterMatched(action, selectorCandidate, classification)
        })

        if (directMatches.length && (hasExplicitName || regexHardInclude || !action?.scoredFallback)) {
            const family = this._selectorFamily(action)
            const rankedDirectEntries = this._sortRankedCandidates(
                directMatches.map(candidate => ({
                    candidate,
                    rank: this._rankParamCandidate({
                        location: 'cookie',
                        name: candidate?.name,
                        value: candidate?.value
                    }, action, { family })
                }))
            )
            this._appendSelectorSelectionDiagnostics('cookies', family, rankedDirectEntries, rankedDirectEntries)
            return rankedDirectEntries.map(entry => entry.candidate)
        }

        if (!action?.scoredFallback) return []

        const family = this._selectorFamily(action)
        const rankedEntries = this._sortRankedCandidates(
            directMatches.map(cookie => ({
                candidate: cookie,
                rank: this._rankParamCandidate({
                    location: 'cookie',
                    name: cookie?.name,
                    value: cookie?.value
                    }, action, { family })
            }))
        )
        this._appendSelectorSelectionDiagnostics('cookies', family, rankedEntries, rankedEntries)
        return rankedEntries.map(entry => entry.candidate)
    }

    _selectorFieldNames() {
        return [
            'name',
            'nameRegex',
            'flags',
            'pathRegex',
            'pathFlags',
            'jsonPathRegex',
            'jsonPathFlags',
            'valueRegex',
            'valueFlags',
            'valueTypeIn',
            'semanticTagsAny',
            'weight',
            'selectorMode',
            'excludeNameRegex',
            'excludeFlags',
            'scoredFallback',
            'location'
        ]
    }

    _getTargetSelectors(target, surface) {
        if (!target || typeof target !== 'object') return null
        const list = target?.[surface]
        return Array.isArray(list) ? list : null
    }

    _extractSelectorFields(selector) {
        const out = {}
        if (!selector || typeof selector !== 'object') return out
        for (const key of this._selectorFieldNames()) {
            if (Object.prototype.hasOwnProperty.call(selector, key)) {
                out[key] = selector[key]
            }
        }
        return out
    }

    _mergeSurfaceSelectors(actions, selectors) {
        const actList = Array.isArray(actions) ? actions : []
        const selList = Array.isArray(selectors) ? selectors.filter(Boolean) : []
        if (!actList.length || !selList.length) return actList

        const merged = []
        for (const selector of selList) {
            const selectorFields = this._extractSelectorFields(selector)
            for (const action of actList) {
                merged.push(Object.assign({}, action, selectorFields))
            }
        }
        return merged
    }

    _matchesParamSelector(paramName, action, onlyName = null, currentLocation = null, paramValue = null, schema = null) {
        const candidate = String(paramName ?? '')
        if (onlyName && candidate.toLowerCase() !== String(onlyName).toLowerCase()) return false
        if (this._isHardDeniedName('params', candidate)) {
            this._noteSelectorSkip('params', 'hard_deny', candidate)
            return false
        }
        if (this._isAuthLikeHardBlocked('params', { name: candidate, value: paramValue, location: currentLocation })) {
            this._noteSelectorSkip('params', 'auth_like_hard_deny', candidate)
            return false
        }
        if (this._shouldSkipSoftGloballyExcludedTarget(schema, 'params', candidate, paramValue)) {
            this._noteSelectorSkip('params', 'global_exclude', candidate)
            return false
        }
        if (!this._matchesSelectorLocation(action, currentLocation)) return false
        if (this._isParamExcluded(candidate, action)) return false

        let nameMatches = false
        if (action?.name) {
            nameMatches = candidate.toLowerCase() === String(action.name).toLowerCase()
        } else {
            const matcher = this._compileParamNameRegex(action)
            if (matcher) {
                nameMatches = matcher.test(candidate)
            } else {
                nameMatches = !action?.name && !action?.nameRegex
            }
        }

        if (!nameMatches) return false
        const selectorCandidate = {
            location: currentLocation,
            name: candidate,
            value: paramValue
        }
        const classification = this._classifyParam(selectorCandidate, this._selectorFamily(action))
        if (!this._matchesSelectorValue(action, paramValue)) return false
        if (!this._matchesSelectorPath(action, selectorCandidate)) return false
        if (!this._matchesSelectorValueType(action, selectorCandidate, classification)) return false
        if (!this._matchesSelectorSemanticTags(action, selectorCandidate, classification)) return false
        return true
    }

    _isRawSuffixMutation(action) {
        return Boolean(action?.rawSuffix && action?.operation === 'add' && action?.position === 'after')
    }

    _clearRawSuffixMutationMeta(target) {
        if (!target || typeof target !== 'object') return
        delete target.__ptkRawMode
        delete target.__ptkRawBase
        delete target.__ptkRawSuffix
    }

    _applyRawSuffixMutationMeta(target, before, action) {
        if (!target || typeof target !== 'object') return
        if (!this._isRawSuffixMutation(action)) {
            this._clearRawSuffixMutationMeta(target)
            return
        }
        target.__ptkRawMode = 'append_suffix'
        target.__ptkRawBase = String(before ?? '')
        target.__ptkRawSuffix = String(action.value ?? '')
    }

    _serializeParamPair(param) {
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

    _rebuildQueryFromParams(schema) {
        const params = Array.isArray(schema?.request?.queryParams) ? schema.request.queryParams : []
        const urlObj = this._toURL(schema.request.url, schema.request.baseUrl)
        const query = params.map(param => this._serializeParamPair(param)).join('&')
        const pathname = urlObj.pathname || '/'
        const hash = urlObj.hash || ''
        schema.request.url = `${urlObj.origin}${pathname}${query ? '?' + query : ''}${hash}`
        return schema
    }

    _rebuildBodyTextFromParams(schema) {
        const params = schema?.request?.body?.params
        if (!Array.isArray(params)) return schema
        schema.request.body.text = params.map(param => this._serializeParamPair(param)).join('&')
        return schema
    }

    /* ---------------- mutation primitives ---------------- */

    modifyProps(schema, action) {
        for (let i = 0; i < (action.props?.length || 0); i++) {
            const propName = action.props[i].name
            const currentValue = ptk_utils.jsonGetValueByPath(schema, propName)
            const resolved = this._resolveTypedActionValue(action.props[i], currentValue, {
                name: propName,
                value: currentValue,
                location: 'prop'
            })
            ptk_utils.jsonSetValueByPath(schema, propName, resolved?.value, true)
        }
        return schema
    }

    _resolveDynamicActionValue(action, context = {}) {
        const spec = action?.valueFrom
        if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
            return { resolved: false, source: null, transforms: [] }
        }
        const source = typeof spec.source === 'string' ? spec.source.trim() : ''
        let value
        if (source === 'attacked.value') {
            value = context?.value
        } else if (source === 'attacked.name') {
            value = context?.name
        } else {
            return { resolved: false, source, transforms: [] }
        }
        if (typeof value === 'undefined' || value === null) {
            return { resolved: false, source, transforms: [] }
        }

        const transforms = Array.isArray(spec.transforms) ? spec.transforms : []
        let nextValue = value
        for (const transform of transforms) {
            const key = String(transform || '').trim().toLowerCase()
            if (!ACTION_VALUE_FROM_TRANSFORMS.has(key)) continue
            if (key === 'trim') {
                nextValue = String(nextValue).trim()
            } else if (key === 'lowercase') {
                nextValue = String(nextValue).toLowerCase()
            } else if (key === 'uppercase') {
                nextValue = String(nextValue).toUpperCase()
            }
        }

        return {
            resolved: true,
            source,
            transforms: transforms.map((entry) => String(entry || '').trim()).filter(Boolean),
            value: nextValue
        }
    }

    _resolveTypedActionValue(action, param, context = {}) {
        const dynamic = this._resolveDynamicActionValue(action, {
            name: context?.name,
            value: Object.prototype.hasOwnProperty.call(context || {}, 'value') ? context.value : param,
            location: context?.location
        })
        if (dynamic.resolved) {
            return {
                value: dynamic.value,
                mutationMeta: {
                    actionValueFromSource: dynamic.source,
                    actionValueFromTransforms: dynamic.transforms
                },
                forceRecord: action?.operation === 'replace' && dynamic.value === param
            }
        }

        const hasTypedValues =
            Object.prototype.hasOwnProperty.call(action || {}, 'valueNumeric') ||
            Object.prototype.hasOwnProperty.call(action || {}, 'valueString')
        if (!hasTypedValues) {
            return {
                value: action?.value,
                mutationMeta: null,
                forceRecord: false
            }
        }

        if (this._isNumericLike(param) && typeof action?.valueNumeric !== 'undefined') {
            return {
                value: action.valueNumeric,
                mutationMeta: null,
                forceRecord: false
            }
        }
        if (!this._isNumericLike(param) && typeof action?.valueString !== 'undefined') {
            return {
                value: action.valueString,
                mutationMeta: null,
                forceRecord: false
            }
        }
        return {
            value: action?.value,
            mutationMeta: null,
            forceRecord: false
        }
    }

    modifyParam(name, param, action, context = {}) {
        if (!this.isAttackableName(name) && name !== undefined && name !== null) {
            return { value: param, mutationMeta: null, forceRecord: false }
        }
        const resolved = this._resolveTypedActionValue(action, param, {
            name,
            value: Object.prototype.hasOwnProperty.call(context || {}, 'value') ? context.value : param,
            location: context?.location
        })
        const resolvedValue = resolved?.value

        if (action.regex) {
            let r = new RegExp(action.regex)
            return {
                value: String(param ?? '').replace(r, resolvedValue),
                mutationMeta: resolved?.mutationMeta || null,
                forceRecord: !!resolved?.forceRecord
            }
        } else if (action.operation === 'remove') {
            return { value: '', mutationMeta: resolved?.mutationMeta || null, forceRecord: !!resolved?.forceRecord }
        } else if (action.operation === 'add') {
            return {
                value: (action.position === 'after') ? (String(param ?? '') + resolvedValue) : (resolvedValue + String(param ?? '')),
                mutationMeta: resolved?.mutationMeta || null,
                forceRecord: !!resolved?.forceRecord
            }
        } else if (action.operation === 'replace') {
            return { value: resolvedValue, mutationMeta: resolved?.mutationMeta || null, forceRecord: !!resolved?.forceRecord }
        }
        return { value: param, mutationMeta: resolved?.mutationMeta || null, forceRecord: !!resolved?.forceRecord }
    }

    _parseActionValueListLimit(value, fallback = null) {
        if (value === undefined || value === null || value === '') return fallback
        const parsed = Number(value)
        if (!Number.isFinite(parsed) || parsed < 1) return fallback
        return Math.floor(parsed)
    }

    _expandPreparedAttackVariants(attack) {
        const prepared = this._clone(attack)
        const action = prepared?.action && typeof prepared.action === 'object' ? prepared.action : {}
        const valueListSpecs = []

        for (const bucket of ['props', 'params', 'headers', 'cookies']) {
            const entries = Array.isArray(action?.[bucket]) ? action[bucket] : []
            for (let index = 0; index < entries.length; index += 1) {
                const entry = entries[index]
                const ref = typeof entry?.valueListRef === 'string' ? entry.valueListRef.trim() : ''
                if (!ref) continue
                const values = getBundledDastWordlist(ref, this.bundledWordlists)
                if (!Array.isArray(values) || !values.length) {
                    throw new Error(`[PTK DAST] Unknown or empty action valueListRef: ${ref}`)
                }
                const limit = this._parseActionValueListLimit(entry?.valueListLimit, values.length)
                valueListSpecs.push({
                    bucket,
                    index,
                    ref,
                    values: values.slice(0, limit)
                })
            }
        }

        if (!valueListSpecs.length) {
            return [prepared]
        }

        let variants = [{
            attack: prepared,
            applied: []
        }]

        for (const spec of valueListSpecs) {
            const next = []
            for (const variant of variants) {
                for (const candidate of spec.values) {
                    if (next.length >= MAX_ACTION_VALUE_LIST_VARIANTS) break
                    const clone = this._clone(variant.attack)
                    const entry = clone?.action?.[spec.bucket]?.[spec.index]
                    if (!entry) continue
                    delete entry.valueListRef
                    delete entry.valueListLimit
                    entry.value = String(candidate)
                    if (Object.prototype.hasOwnProperty.call(entry, 'valueString')) {
                        entry.valueString = String(candidate)
                    }
                    const applied = variant.applied.concat([{
                        ref: spec.ref,
                        value: String(candidate),
                        bucket: spec.bucket,
                        index: spec.index
                    }])
                    next.push({
                        attack: clone,
                        applied
                    })
                }
                if (next.length >= MAX_ACTION_VALUE_LIST_VARIANTS) break
            }
            variants = next
        }

        return variants.map((variant) => {
            const clone = variant.attack
            clone.metadata = clone.metadata || {}
            clone.metadata.constants = clone.metadata.constants || {}
            clone.metadata.extensions = clone.metadata.extensions || {}
            clone.metadata.extensions.actionValueLists = variant.applied.map((entry) => this._clone(entry))
            if (variant.applied.length === 1) {
                clone.metadata.constants.actionValueListRef = variant.applied[0].ref
                clone.metadata.constants.actionValueListValue = variant.applied[0].value
            }
            return clone
        })
    }

    _attachPreparedAttackMetadata(schema, attack) {
        if (!schema || !attack) return
        const metadata = schema.metadata = schema.metadata || {}
        const attackConstants = attack?.metadata?.constants && typeof attack.metadata.constants === 'object'
            ? attack.metadata.constants
            : null
        const attackExtensions = attack?.metadata?.extensions && typeof attack.metadata.extensions === 'object'
            ? attack.metadata.extensions
            : null
        if (attackConstants && (attackConstants.actionValueListRef || attackConstants.actionValueListValue !== undefined)) {
            metadata.constants = metadata.constants && typeof metadata.constants === 'object' ? metadata.constants : {}
            if (attackConstants.actionValueListRef) {
                metadata.constants.actionValueListRef = attackConstants.actionValueListRef
            }
            if (attackConstants.actionValueListValue !== undefined) {
                metadata.constants.actionValueListValue = attackConstants.actionValueListValue
            }
        }
        if (attackExtensions?.actionValueLists) {
            metadata.extensions = metadata.extensions && typeof metadata.extensions === 'object' ? metadata.extensions : {}
            metadata.extensions.actionValueLists = this._clone(attackExtensions.actionValueLists)
        }
    }

    // onlyName: mutate only this param name (atomic mode)
    // mutations: array to collect {location,name,before,after}
    modifyPostParams(schema, action, onlyName = null, mutations = null) {
        const params = schema?.request?.body?.params
        if (!params) return schema

        for (const a of (action.params || [])) {
            if (!this._matchesSelectorLocation(a, 'form')) continue
            if (a.name) {
                if (onlyName && a.name.toLowerCase() !== onlyName.toLowerCase()) continue
                if (this._isHardDeniedName('params', a.name)) {
                    this._noteSelectorSkip('params', 'hard_deny', a.name)
                    continue
                }
                if (this._isAuthLikeHardBlocked('params', {
                    name: a.name,
                    value: a.value,
                    location: 'form'
                })) {
                    this._noteSelectorSkip('params', 'auth_like_hard_deny', a.name)
                    continue
                }
                const existingParam = params.find(obj => obj.name?.toLowerCase() === a.name.toLowerCase())
                if (this._shouldSkipSoftGloballyExcludedTarget(schema, 'params', a.name, existingParam?.value)) {
                    this._noteSelectorSkip('params', 'global_exclude', a.name)
                    continue
                }

                const ind = params.findIndex(obj => obj.name?.toLowerCase() === a.name.toLowerCase())
                if (ind < 0) {
                    const created = {
                        name: a.name,
                        value: this.modifyParam(a.name, '', a, { name: a.name, value: '', location: 'form' }).value
                    }
                    this._applyRawSuffixMutationMeta(created, '', a)
                    this._recordMutation(mutations, 'body', a.name, undefined, created.value)
                    params.push(created)
                } else {
                    const before = params[ind].value
                    const result = this.modifyParam(params[ind].name, params[ind].value, a, {
                        name: params[ind].name,
                        value: before,
                        location: 'form'
                    })
                    const after = result.value
                    params[ind].value = after
                    this._applyRawSuffixMutationMeta(params[ind], before, a)
                    this._recordMutation(mutations, 'body', params[ind].name, before, after, result.mutationMeta, result.forceRecord)
                }
            } else {
                for (const p of params) {
                    if (!this._matchesParamSelector(p.name, a, onlyName, 'form', p.value, schema)) continue
                    const before = p.value
                    const result = this.modifyParam(p.name, p.value, a, {
                        name: p.name,
                        value: before,
                        location: 'form'
                    })
                    const after = result.value
                    p.value = after
                    this._applyRawSuffixMutationMeta(p, before, a)
                    this._recordMutation(mutations, 'body', p.name, before, after, result.mutationMeta, result.forceRecord)
                }
            }
        }

        // ensure uniqueness marker to defeat caching
        params.push({ name: 'ptk_rnd', value: ptk_utils.attackParamId() })
        if (params.some(param => param?.__ptkRawMode === 'append_suffix')) {
            this._rebuildBodyTextFromParams(schema)
        }
        return schema
    }

    modifyGetParams(schema, action, onlyName = null, mutations = null) {
        const params = schema.request.queryParams || (schema.request.queryParams = [])

        for (const a of (action.params || [])) {
            if (!this._matchesSelectorLocation(a, 'query')) continue
            if (a.name) {
                if (onlyName && a.name.toLowerCase() !== onlyName.toLowerCase()) continue
                if (this._isHardDeniedName('params', a.name)) {
                    this._noteSelectorSkip('params', 'hard_deny', a.name)
                    continue
                }
                if (this._isAuthLikeHardBlocked('params', {
                    name: a.name,
                    value: a.value,
                    location: 'query'
                })) {
                    this._noteSelectorSkip('params', 'auth_like_hard_deny', a.name)
                    continue
                }
                const existingParam = params.find(obj => obj.name?.toLowerCase() === a.name.toLowerCase())
                if (this._shouldSkipSoftGloballyExcludedTarget(schema, 'params', a.name, existingParam?.value)) {
                    this._noteSelectorSkip('params', 'global_exclude', a.name)
                    continue
                }

                const ind = params.findIndex(obj => obj.name?.toLowerCase() === a.name.toLowerCase())
                if (ind < 0) {
                    const created = {
                        name: a.name,
                        value: this.modifyParam(a.name, '', a, { name: a.name, value: '', location: 'query' }).value
                    }
                    this._applyRawSuffixMutationMeta(created, '', a)
                    this._recordMutation(mutations, 'query', a.name, undefined, created.value)
                    params.push(created)
                } else {
                    const before = params[ind].value
                    const result = this.modifyParam(params[ind].name, params[ind].value, a, {
                        name: params[ind].name,
                        value: before,
                        location: 'query'
                    })
                    const after = result.value
                    params[ind].value = after
                    this._applyRawSuffixMutationMeta(params[ind], before, a)
                    this._recordMutation(mutations, 'query', params[ind].name, before, after, result.mutationMeta, result.forceRecord)
                }
            } else {
                for (const p of params) {
                    if (!this._matchesParamSelector(p.name, a, onlyName, 'query', p.value, schema)) continue
                    const before = p.value
                    const result = this.modifyParam(p.name, p.value, a, {
                        name: p.name,
                        value: before,
                        location: 'query'
                    })
                    const after = result.value
                    p.value = after
                    this._applyRawSuffixMutationMeta(p, before, a)
                    this._recordMutation(mutations, 'query', p.name, before, after, result.mutationMeta, result.forceRecord)
                }
            }
        }

        return this._rebuildQueryFromParams(schema)
    }

    // JSON body mutation
    // onlyPath: mutate only this JSON path (atomic mode)
    modifyJsonParams(schema, action, onlyPath = null, mutations = null) {
        const { obj: jsonObj } = this._getJsonBody(schema)
        if (jsonObj === undefined || jsonObj === null) return schema
        let workingJson = jsonObj

        const applyToPath = (path, act) => {
            const { exists, value } = this._getByJsonPath(workingJson, path)
            const before = exists ? value : undefined
            const result = this.modifyParam(path, before, act, { name: path, value: before, location: 'json' })
            const after = result.value // use path as the "name"
            workingJson = this._setByJsonPath(workingJson, path, after)
            this._recordMutation(mutations, 'json', path, before, after, result.mutationMeta, result.forceRecord)
        }

        const hasExplicit = (action.params || []).some(a => a.name)

        if (hasExplicit) {
            for (const a of (action.params || [])) {
                if (!a.name) continue
                if (onlyPath && a.name !== onlyPath) continue
                applyToPath(a.name, a)
            }
        } else {
            const leaves = this._enumerateJsonLeaves(workingJson)
            for (const leaf of leaves) {
                if (onlyPath && leaf.path !== onlyPath) continue
                for (const a of (action.params || [])) {
                    applyToPath(leaf.path, a)
                }
            }
        }

        if (workingJson && typeof workingJson === 'object' && !Array.isArray(workingJson)) {
            if (!Object.prototype.hasOwnProperty.call(workingJson, 'ptk_rnd')) {
                workingJson['ptk_rnd'] = ptk_utils.attackParamId()
            }
        }

        this._persistJsonBody(schema, workingJson)
        return schema
    }

    // XML body mutation
    // onlyPath: mutate only this XML path (atomic mode)
    modifyXmlParams(schema, action, onlyPath = null, mutations = null) {
        const { text: xmlText } = this._getXmlBody(schema)
        if (!xmlText) return schema

        const actions = Array.isArray(action?.params) ? action.params : []
        if (!actions.length) return schema

        let workingXml = String(xmlText)
        let leaves = this._enumerateXmlLeaves(workingXml)

        for (const a of actions) {
            if (!this._matchesSelectorLocation(a, 'xml')) continue

            const matches = this._selectXmlCandidates(schema, leaves, a, onlyPath)
            for (const match of matches) {
                const path = String(match?.path || '')
                if (!path) continue
                const before = String(match?.value ?? '')
                const result = this.modifyParam(match?.name, before, a, {
                    name: match?.name || path,
                    value: before,
                    location: 'xml'
                })
                const after = result.value
                if (before === after && !result.forceRecord) continue
                workingXml = this._setXmlLeafByPath(workingXml, path, after)
                this._recordMutation(mutations, 'xml', path, before, after, result.mutationMeta, result.forceRecord)
                leaves = this._enumerateXmlLeaves(workingXml)
            }
        }

        const body = this._ensureBody(schema)
        body.text = workingXml
        if (body.mimeType && !this._looksXmlCt(String(body.mimeType).toLowerCase())) {
            body.mimeType = 'application/xml'
        }

        return schema
    }

    // Cookie mutation (atomic or bulk)
    // onlyName: mutate only this cookie (atomic mode)
    modifyCookies(schema, action, onlyName = null, mutations = null) {
        const cookies = this._getCookiesArray(schema)
        const beforeSnapshot = cookies.map(c => ({ name: c.name, value: c.value }))

        // Determine cookie actions
        let cookieActs = []
        const cookieHeaderActs = (action.headers || []).filter(h => (h.name || '').toLowerCase() === 'cookie')
        const cookieHeaderAct = cookieHeaderActs.length ? cookieHeaderActs[0] : null

        if (Array.isArray(action.cookies) && action.cookies.length) {
            cookieActs = action.cookies
        } else if (cookieHeaderAct) {
            // Use header act as a template
            cookieActs = [{ name: onlyName || null, operation: cookieHeaderAct.operation, regex: cookieHeaderAct.regex, position: cookieHeaderAct.position, value: cookieHeaderAct.value }]
        }
        if (!cookieActs.length && !cookieHeaderAct) return schema

        const removeCookie = (cname, reason, beforeValue) => {
            const idx = cookies.findIndex(c => (c.name || '').toLowerCase() === (cname || '').toLowerCase())
            if (idx !== -1) {
                const before = typeof beforeValue !== 'undefined' ? beforeValue : cookies[idx].value
                cookies.splice(idx, 1)
                this._recordMutation(mutations, 'cookie', cname, before, undefined)
            }
        }

        // Apply per-cookie actions
        const apply = (cname, act) => {
            const idx = cookies.findIndex(c => (c.name || '').toLowerCase() === (cname || '').toLowerCase())
            if (idx === -1) {
                if (act.name) {
                    const before = undefined
                    if (act.operation === 'remove') {
                        return
                    }
                    const after = this.modifyParam(act.name, '', act, {
                        name: act.name,
                        value: '',
                        location: 'cookie'
                    }).value
                    cookies.push({ name: act.name, value: after })
                    this._recordMutation(mutations, 'cookie', act.name, before, after)
                }
            } else {
                const before = cookies[idx].value
                if (act.operation === 'remove') {
                    const name = cookies[idx].name
                    cookies.splice(idx, 1)
                    this._recordMutation(mutations, 'cookie', name || cname, before, undefined)
                    return
                }
                const result = this.modifyParam(cookies[idx].name, cookies[idx].value, act, {
                    name: cookies[idx].name,
                    value: before,
                    location: 'cookie'
                })
                const after = result.value
                cookies[idx].value = after
                this._recordMutation(mutations, 'cookie', cookies[idx].name, before, after, result.mutationMeta, result.forceRecord)
            }
        }

        for (const act of cookieActs) {
            if (act.operation === 'remove' && act.regex && !act.name && !act.nameRegex && !act.excludeNameRegex && !act.scoredFallback) {
                const r = new RegExp(act.regex)
                const toRemove = this._selectCookieCandidates(cookies, act, onlyName)
                    .filter(c => r.test(String(c.value ?? '')))
                    .map(c => c.name)
                for (const cname of toRemove) removeCookie(cname, 'regex')
                continue
            }
            if (act.name) {
                if (onlyName && act.name.toLowerCase() !== onlyName.toLowerCase()) continue
                if (this._isHardDeniedName('cookies', act.name)) {
                    this._noteSelectorSkip('cookies', 'hard_deny', act.name)
                    continue
                }
                if (this._isAuthLikeHardBlocked('cookies', {
                    name: act.name,
                    value: act.value,
                    location: 'cookie'
                })) {
                    this._noteSelectorSkip('cookies', 'auth_like_hard_deny', act.name)
                    continue
                }
                if (this._isSoftGloballyExcluded('cookies', act.name)) {
                    this._noteSelectorSkip('cookies', 'global_exclude', act.name)
                    continue
                }
                apply(act.name, act)
                continue
            }

            const matchingCookies = this._selectCookieCandidates(cookies, act, onlyName)

            if (act.operation === 'remove' && act.regex) {
                const r = new RegExp(act.regex)
                const toRemove = matchingCookies
                    .filter(c => r.test(String(c.value ?? '')))
                    .map(c => c.name)
                for (const cname of toRemove) removeCookie(cname, 'regex')
                continue
            }

            if (matchingCookies.length) {
                for (const c of matchingCookies) {
                    apply(c.name, act)
                }
                continue
            }

            if (onlyName && !act.nameRegex && !act.excludeNameRegex && !act.scoredFallback) {
                apply(onlyName, act)
                continue
            }
        }

        // Rebuild Cookie header from array
        let headerAfter = this._stringifyCookies(cookies)
        this._setHeader(schema, 'Cookie', headerAfter)

        // ---- Fallback diff for header-level regex attacks ----
        // If no cookie-level mutation recorded BUT there's a Cookie header act,
        // apply the header regex to the whole header and diff to identify cookie name(s).
        const hasCookieMutations = (mutations || []).some(m => m.location === 'cookie')
        if (!hasCookieMutations && cookieHeaderAct) {
            const headerBefore = this._stringifyCookies(beforeSnapshot)
            const headerModified = this.modifyParam('Cookie', headerBefore, cookieHeaderAct, {
                name: 'Cookie',
                value: headerBefore,
                location: 'header'
            }).value
            if (headerModified !== headerBefore) {
                const afterArr = this._parseCookieHeader(headerModified)
                const mapBefore = new Map(beforeSnapshot.map(c => [c.name, c.value]))
                const mapAfter = new Map(afterArr.map(c => [c.name, c.value]))

                for (const [k, vAfter] of mapAfter.entries()) {
                    const vBefore = mapBefore.get(k)
                    if (vBefore !== vAfter) {
                        this._recordMutation(mutations, 'cookie', k, vBefore, vAfter)
                    }
                }
                // Optionally detect removals (not typical for JWT-none), uncomment if needed:
                // for (const [k, vBefore] of mapBefore.entries()) {
                //     if (!mapAfter.has(k)) this._recordMutation(mutations, 'cookie', k, vBefore, undefined)
                // }

                // Persist parsed cookies + header
                schema.request.cookies = afterArr
                this._setHeader(schema, 'Cookie', headerModified)
            }
        }

        return schema
    }

    modifyHeaders(schema, action, onlyName = null, mutations = null) {
        const headers = this._headersArray(schema)

        for (const a of (action.headers || [])) {
            // Skip 'Cookie' here; handled by modifyCookies to track per-cookie names
            if ((a.name || '').toLowerCase() === 'cookie') continue

            if (a.operation === 'remove') {
                if (a.name) {
                    for (let i = headers.length - 1; i >= 0; i--) {
                        if ((headers[i].name || '').toLowerCase() === a.name.toLowerCase()) {
                            const before = headers[i].value
                            const name = headers[i].name
                            headers.splice(i, 1)
                            this._recordMutation(mutations, 'header', name, before, undefined)
                        }
                    }
                    continue
                }
                if (a.regex) {
                    const r = new RegExp(a.regex)
                    for (let i = headers.length - 1; i >= 0; i--) {
                        if (r.test(String(headers[i].value ?? ''))) {
                            const before = headers[i].value
                            const name = headers[i].name
                            headers.splice(i, 1)
                            this._recordMutation(mutations, 'header', name, before, undefined)
                        }
                    }
                    continue
                }
            }

            if (a.name) {
                if (onlyName && a.name.toLowerCase() !== onlyName.toLowerCase()) continue
                if (this._isHardDeniedName('headers', a.name)) {
                    this._noteSelectorSkip('headers', 'hard_deny', a.name)
                    continue
                }
                if (this._isAuthLikeHardBlocked('headers', {
                    name: a.name,
                    value: a.value,
                    location: 'header'
                })) {
                    this._noteSelectorSkip('headers', 'auth_like_hard_deny', a.name)
                    continue
                }
                if (this._isSoftGloballyExcluded('headers', a.name)) {
                    this._noteSelectorSkip('headers', 'global_exclude', a.name)
                    continue
                }

                const ind = headers.findIndex(obj => obj.name?.toLowerCase() === a.name.toLowerCase())
                if (ind < 0) {
                    const result = this.modifyParam(a.name, '', a, {
                        name: a.name,
                        value: '',
                        location: 'header'
                    })
                    this._recordMutation(mutations, 'header', a.name, undefined, result.value, result.mutationMeta, result.forceRecord)
                    headers.push({ name: a.name, value: result.value })
                } else {
                    const before = headers[ind].value
                    const result = this.modifyParam(headers[ind].name, headers[ind].value, a, {
                        name: headers[ind].name,
                        value: before,
                        location: 'header'
                    })
                    const after = result.value
                    headers[ind].value = after
                    this._recordMutation(mutations, 'header', headers[ind].name, before, after, result.mutationMeta, result.forceRecord)
                }
            } else {
                for (const h of headers) {
                    if (onlyName && h.name?.toLowerCase() !== onlyName.toLowerCase()) continue
                    if (this._isHardDeniedName('headers', h.name)) {
                        this._noteSelectorSkip('headers', 'hard_deny', h.name)
                        continue
                    }
                    if (this._isAuthLikeHardBlocked('headers', {
                        name: h.name,
                        value: h.value,
                        location: 'header'
                    })) {
                        this._noteSelectorSkip('headers', 'auth_like_hard_deny', h.name)
                        continue
                    }
                    if (this._isSoftGloballyExcluded('headers', h.name)) {
                        this._noteSelectorSkip('headers', 'global_exclude', h.name)
                        continue
                    }
                    const before = h.value
                    const result = this.modifyParam(h.name, h.value, a, {
                        name: h.name,
                        value: before,
                        location: 'header'
                    })
                    const after = result.value
                    h.value = after
                    this._recordMutation(mutations, 'header', h.name, before, after, result.mutationMeta, result.forceRecord)
                }
            }
        }
        return schema
    }

    modifyUrl(schema, action) {
        const url = this._toURL(schema.request.url, schema.request.baseUrl)
        schema.request.url = url.origin + action.url.value
        return schema
    }

    /* ---------------- attack preparation ---------------- */

    prepareAttack(a) {
        const attack = this._clone(a)
        const rnd = ptk_utils.attackParamId()

        if (attack.action?.random)
            attack.action.random = rnd

        const rep = (s) => (typeof s === 'string' ? s.replaceAll('%%random%%', rnd) : s)

        for (const arr of ['props', 'params', 'headers', 'cookies']) {
            for (const item of (attack.action?.[arr] || [])) {
                for (const key of ['value', 'valueString', 'valueNumeric']) {
                    if (typeof item?.[key] === 'string') item[key] = rep(item[key])
                }
            }
        }

        if (attack?.metadata?.constants && typeof attack.metadata.constants === 'object') {
            const asString = JSON.stringify(attack.metadata.constants)
            attack.metadata.constants = JSON.parse(asString.replaceAll('%%random%%', rnd))
        }

        if (attack?.action?.options && typeof attack.action.options === 'object') {
            const asString = JSON.stringify(attack.action.options)
            attack.action.options = JSON.parse(asString.replaceAll('%%random%%', rnd))
        }

        for (const runtimeKey of ['spa', 'browserNav', 'browserWorkflow']) {
            const runtimeCfg = this._attackRuntimeConfig(attack, runtimeKey)
            if (!runtimeCfg) continue
            const asString = JSON.stringify(runtimeCfg)
            const nextCfg = JSON.parse(asString.replaceAll('%%random%%', rnd))
            attack.runtime = attack.runtime || {}
            attack.runtime.config = attack.runtime.config || {}
            attack.runtime.config[runtimeKey] = nextCfg
        }

        return attack
    }

    /* ---------------- build attacks ---------------- */

    // Build N per-target attacks (default) or 1 bulk attack; can be overridden via options.mode.
    buildAttacks(schema, attack, options = {}) {
        const prepared = options?.prepared === true ? attack : this.prepareAttack(attack)
        const preparedVariants = this._expandPreparedAttackVariants(prepared)
        if (this._isDeserializationCoverageAttack(prepared)) {
            return this._buildDeserializationAttacks(schema, prepared)
        }
        if (!prepared?.action) {
            console.warn('[PTK DAST] Skipping attack without action definition', {
                module: this.id || this.name || 'unknown-module',
                attack: attack?.id || attack?.name || 'unknown-attack'
            })
            return []
        }
        const forcedMode = options?.mode
        const forcedAtomic = (typeof options?.atomic === 'boolean') ? options.atomic : null
        const requestGrouping = this._attackRequestGrouping(prepared)
        let atomic = requestGrouping !== 'bulk'

        if (forcedMode === 'bulk') {
            atomic = false
        } else if (forcedMode === 'per-param' || forcedMode === 'per_target') {
            atomic = true
        } else if (forcedAtomic !== null) {
            atomic = forcedAtomic
        } else if (requestGrouping === 'per_target') {
            atomic = true
        }
        const attacks = []

        if (!atomic) {
            for (const preparedVariant of preparedVariants) {
                attacks.push(this.buildAttack(schema, preparedVariant)) // bulk mode
            }
            return attacks
        }
        for (const preparedVariant of preparedVariants) {
            // Atomic: one attack per target (query/body/header/json/cookie)
            const targets = this._getParamTargets(schema, preparedVariant.action, preparedVariant.target || null)

            // If no param/header/json targets (e.g., only props/url), fall back to single
            if (!targets.length && !preparedVariant.action.params && !preparedVariant.action.headers && !preparedVariant.action.cookies) {
                attacks.push(this.buildAttack(schema, preparedVariant))
                continue
            }

            for (const tgt of targets) {
                const _schema = this._clone(schema)
                const mutations = []

                // Apply URL and props first (shared per atomic attack)
                if (preparedVariant.action.url) this.modifyUrl(_schema, preparedVariant.action)
                if (preparedVariant.action.props) this.modifyProps(_schema, preparedVariant.action)

                // Apply only the selected target, while tracking before/after
                if (tgt.location === 'query') {
                    if (preparedVariant.action.params?.length) {
                        this.modifyGetParams(_schema, preparedVariant.action, tgt.name, mutations)
                    }
                } else if (tgt.location === 'body' || tgt.location === 'form') {
                    if (preparedVariant.action.params?.length) {
                        this.modifyPostParams(_schema, preparedVariant.action, tgt.name, mutations)
                    }
                } else if (tgt.location === 'json') {
                    if (preparedVariant.action.params?.length) {
                        this.modifyJsonParams(_schema, preparedVariant.action, tgt.name, mutations)
                    }
                } else if (tgt.location === 'xml') {
                    if (preparedVariant.action.params?.length) {
                        this.modifyXmlParams(_schema, preparedVariant.action, tgt.name, mutations)
                    }
                } else if (tgt.location === 'cookie') {
                    if ((preparedVariant.action.cookies && preparedVariant.action.cookies.length) ||
                        (preparedVariant.action.headers || []).some(h => (h.name || '').toLowerCase() === 'cookie')) {
                        this.modifyCookies(_schema, preparedVariant.action, tgt.name, mutations)
                    }
                } else if (tgt.location === 'header') {
                    if (preparedVariant.action.headers?.length) {
                        this.modifyHeaders(_schema, preparedVariant.action, tgt.name, mutations)
                    }
                }

                // Cookie sync (ensure schema.request.cookies aligned with header)
                const cookieIndex = (_schema.request.headers || []).findIndex(i => (i.name || '').toLowerCase() === 'cookie')
                if (cookieIndex > -1) {
                    const cookieStr = _schema.request.headers[cookieIndex].value || ''
                    const parsed = this._parseCookieHeader(cookieStr)
                    _schema.request.cookies = parsed
                }

                // Attach metadata for reporting
                _schema.metadata = _schema.metadata || {}
                _schema.metadata.mutations = mutations
                this._attachPreparedAttackMetadata(_schema, preparedVariant)
                if (!mutations.length) {
                    continue
                }
                this._applyAttackOptions(_schema, preparedVariant)
                _schema.opts = _schema.opts || {}
                if (this._shouldUseStrictCookieOverride(preparedVariant, mutations)) {
                    _schema.opts.strict_cookie_override = true
                }
                _schema.metadata.attacked = Object.assign(
                    this._normalizeReportedMutation(_schema, mutations[0]),
                    tgt?.typeHint ? { typeHint: tgt.typeHint } : null
                )
                if (tgt?.selectorRank) {
                    _schema.metadata.selectorSelection = this._clone(tgt.selectorRank)
                }

                attacks.push(_schema)
            }
        }

        return attacks
    }

    // Legacy single attack builder; used for bulk mode and for non-param/url/props-only cases
    buildAttack(schema, attack) {
        let _schema = this._clone(schema)
        const mutations = []
        const effectiveAction = this._clone(attack.action || {})
        const target = attack.target || null

        const cookieSelectors = this._getTargetSelectors(target, 'cookies')
        const headerSelectors = this._getTargetSelectors(target, 'headers')
        const xmlSelectors = this._getTargetSelectors(target, 'xml')
        if (cookieSelectors?.length && effectiveAction.cookies?.length) {
            effectiveAction.cookies = this._mergeSurfaceSelectors(effectiveAction.cookies, cookieSelectors)
        }
        if (headerSelectors?.length && effectiveAction.headers?.length) {
            effectiveAction.headers = this._mergeSurfaceSelectors(effectiveAction.headers, headerSelectors)
        }

        // modify url
        if (effectiveAction.url) {
            _schema = this.modifyUrl(_schema, effectiveAction)
        }

        // modify properties, eg method or scheme
        if (effectiveAction.props) {
            _schema = this.modifyProps(_schema, effectiveAction)
        }

        // modify params (JSON or form or query)
        if (effectiveAction.params) {
            const method = (_schema.request.method || 'GET').toUpperCase()
            const hasBodyMethod = ["POST", "PUT", "DELETE", "PATCH"].includes(method)
            const { obj: jsonObj } = this._getJsonBody(_schema)
            const hasXmlBody = this._hasXmlBody(_schema)
            const paramSelectors = this._getTargetSelectors(target, 'params')
            const jsonSelectors = this._getTargetSelectors(target, 'json')
            const paramAction = this._clone(effectiveAction)

            if (hasBodyMethod && jsonObj && jsonSelectors?.length) {
                paramAction.params = this._mergeSurfaceSelectors(paramAction.params, jsonSelectors)
            } else if (hasBodyMethod && hasXmlBody && xmlSelectors?.length) {
                paramAction.params = this._mergeSurfaceSelectors(paramAction.params, xmlSelectors)
            } else if (paramSelectors?.length) {
                paramAction.params = this._mergeSurfaceSelectors(paramAction.params, paramSelectors)
            }

            if (hasBodyMethod && jsonObj) {
                _schema = this.modifyJsonParams(_schema, paramAction, null, mutations)
            } else if (hasBodyMethod && hasXmlBody) {
                _schema = this.modifyXmlParams(_schema, paramAction, null, mutations)
            } else if (hasBodyMethod) {
                _schema = this.modifyPostParams(_schema, paramAction, null, mutations)
            } else {
                _schema = this.modifyGetParams(_schema, paramAction, null, mutations)
            }
        }

        // modify cookies first (from action.cookies or headers['Cookie'])
        if ((effectiveAction.cookies && effectiveAction.cookies.length) ||
            (effectiveAction.headers || []).some(h => (h.name || '').toLowerCase() === 'cookie')) {
            _schema = this.modifyCookies(_schema, effectiveAction, null, mutations)
        }

        // modify other headers (Cookie excluded inside)
        if (effectiveAction.headers) {
            _schema = this.modifyHeaders(_schema, effectiveAction, null, mutations)
        }

        // modify multipart file payloads after headers so the boundary/content-type stay authoritative.
        if (effectiveAction.files?.length) {
            _schema = this.modifyMultipartFiles(_schema, effectiveAction, mutations)
        }

        // Cookie sync (ensure schema.request.cookies matches header)
        const cookieIndex = (_schema.request.headers || []).findIndex((item) => (item.name || '').toLowerCase() === 'cookie')
        if (cookieIndex > -1) {
            const cookieStr = _schema.request.headers[cookieIndex].value || ''
            _schema.request.cookies = this._parseCookieHeader(cookieStr)
        }

        _schema.metadata = _schema.metadata || {}
        _schema.metadata.mutations = mutations
        this._attachPreparedAttackMetadata(_schema, attack)
        this._applyAttackOptions(_schema, attack)
        _schema.opts = _schema.opts || {}
        if (this._shouldUseStrictCookieOverride(attack, mutations)) {
            _schema.opts.strict_cookie_override = true
        }
        if (mutations.length) {
            _schema.metadata.attacked = this._normalizeReportedMutation(_schema, mutations[0])
        }


        // If exactly one cookie changed in bulk mode, set attacked to that cookie to aid reporting.
        const cookieMuts = mutations.filter(m => m.location === 'cookie' && m.before !== m.after)
        if (cookieMuts.length === 1) {
            _schema.metadata.attacked = cookieMuts[0]
        }
        // If no mutation was recorded (e.g., regex didn’t match), fall back to a generic target reference.
        if (!_schema.metadata.attacked) {
            _schema.metadata.attacked = {
                location: 'unknown',
                name: ''
            }
        }

        return _schema
    }

    /* ---------------- validation ---------------- */

    validateAttackConditions(attack, original) {
        return jsonLogic.apply(attack.metadata?.condition, { "original": original, "attack": attack, "module": this })
    }

    _extractHeaderValue(response, headerName) {
        const target = String(headerName || '').toLowerCase()
        const headers = Array.isArray(response?.headers) ? response.headers : []
        for (const header of headers) {
            if (String(header?.name || '').toLowerCase() === target) {
                return String(header?.value || '')
            }
        }
        return ''
    }

    _looksDeserErrorSignal(bodyText) {
        const body = String(bodyText || '')
        if (!body) return false
        return /(deserializ|unserialize|ObjectInputStream|InvalidClassException|serialization|invalid\s*signature|hmac|viewstate|type\s*name|unexpected\s*token)/i.test(body)
    }

    _computeDeserDiffSignals(attack, original) {
        const attackRes = attack?.response || {}
        const originalRes = original?.response || {}
        const signals = []
        let score = 0

        const aStatus = Number(attackRes?.statusCode)
        const oStatus = Number(originalRes?.statusCode)
        if (Number.isFinite(aStatus) && Number.isFinite(oStatus) && aStatus !== oStatus) {
            score += 50
            signals.push('status_changed')
        }

        const aLocation = this._extractHeaderValue(attackRes, 'location')
        const oLocation = this._extractHeaderValue(originalRes, 'location')
        if (aLocation && aLocation !== oLocation) {
            score += 40
            signals.push('redirect_changed')
        }

        const aSetCookie = this._extractHeaderValue(attackRes, 'set-cookie')
        const oSetCookie = this._extractHeaderValue(originalRes, 'set-cookie')
        if (aSetCookie !== oSetCookie) {
            score += 25
            signals.push('set_cookie_changed')
        }

        const aBody = String(attackRes?.body || '')
        const oBody = String(originalRes?.body || '')
        const baseLen = Math.max(1, oBody.length)
        const lenDelta = Math.abs(aBody.length - oBody.length)
        const lenDeltaPct = (lenDelta / baseLen) * 100
        if (lenDeltaPct >= 15) {
            score += 40
            signals.push('body_delta_15p')
        } else if (lenDeltaPct >= 5) {
            score += 20
            signals.push('body_delta_5p')
        }

        const errorSignal = this._looksDeserErrorSignal(aBody)
        if (errorSignal) {
            score += 30
            signals.push('deser_error_signal')
        }

        try {
            const aJson = JSON.parse(aBody)
            const oJson = JSON.parse(oBody)
            if (
                aJson && oJson
                && typeof aJson === 'object' && typeof oJson === 'object'
                && !Array.isArray(aJson) && !Array.isArray(oJson)
            ) {
                const aKeys = Object.keys(aJson).sort().join('|')
                const oKeys = Object.keys(oJson).sort().join('|')
                if (aKeys !== oKeys) {
                    score += 25
                    signals.push('json_top_keys_changed')
                }
            }
        } catch (_) {
            // non-JSON bodies
        }

        if (score > 200) score = 200
        return {
            score,
            signals,
            statusCode: Number.isFinite(aStatus) ? aStatus : null,
            errorSignal,
            lenDelta,
            lenDeltaPct: Number.isFinite(lenDeltaPct) ? Number(lenDeltaPct.toFixed(2)) : 0
        }
    }

    _validatePassiveDeserialization(executed, original) {
        const requestShape = original?.request ? { request: original.request } : original
        const candidates = this._detectDeserCandidates(requestShape, { minConfidence: 0.55 })
            .sort((a, b) => Number(b?.confidence || 0) - Number(a?.confidence || 0))
        if (!candidates.length) {
            return { success: false, proof: '' }
        }
        const selected = candidates[0]
        executed.metadata = executed.metadata || {}
        executed.metadata.deserializationProbe = true
        executed.metadata.deserFamily = selected.formatFamily
        executed.metadata.formatFamily = selected.formatFamily
        executed.metadata.codecChain = selected.codecChain || []
        executed.metadata.deserialization = {
            candidate: {
                surface: selected.surface,
                name: selected.name,
                rawValue: selected.rawValue,
                codecChain: selected.codecChain || [],
                formatFamily: selected.formatFamily,
                confidence: selected.confidence,
                sensitivityClass: selected.sensitivityClass || 'unknown',
                evidence: selected.evidence || { markers: [] }
            },
            mutationKind: 'passive'
        }
        const marker = Array.isArray(selected?.evidence?.markers) && selected.evidence.markers.length
            ? selected.evidence.markers[0]
            : selected.formatFamily
        return {
            success: true,
            proof: `Passive serialized-value indicator: ${selected.surface}:${selected.name} (${marker})`,
            detector: 'deserialization-passive',
            match: marker,
            confidence: 45
        }
    }

    _validateActiveDeserialization(executed, original) {
        const diff = this._computeDeserDiffSignals(executed, original)
        const mutationKind = String(executed?.metadata?.deserMutationKind || 'semantic').toLowerCase()
        let success = false
        let confidence = 0
        let severity = null
        const attackedName = String(executed?.metadata?.attacked?.name || '')
        const attackedFamily = String(executed?.metadata?.deserFamily || executed?.metadata?.formatFamily || '')
        const executedHistory = Array.isArray(this.executed) ? this.executed : []
        const pairedControl = executedHistory.find((entry) => {
            const entryKind = String(entry?.metadata?.deserMutationKind || '').toLowerCase()
            if (entryKind !== 'control') return false
            const entryName = String(entry?.metadata?.attacked?.name || '')
            const entryFamily = String(entry?.metadata?.deserFamily || entry?.metadata?.formatFamily || '')
            return entryName && entryName === attackedName && entryFamily === attackedFamily
        })

        const strongSignal = diff.signals.includes('status_changed')
            || diff.signals.includes('redirect_changed')
            || diff.signals.includes('set_cookie_changed')
            || diff.signals.includes('body_delta_15p')
        const isServerError = Number.isFinite(diff.statusCode) && diff.statusCode >= 500

        if (mutationKind === 'semantic') {
            success = diff.score >= 40 && strongSignal && !isServerError
            if (pairedControl) {
                const controlDiff = this._computeDeserDiffSignals(pairedControl, original)
                const controlStrong = controlDiff.errorSignal || controlDiff.score >= 20
                success = success && controlStrong
            }
            if (success) {
                confidence = 78
                severity = 'medium'
            }
        } else if (mutationKind === 'control') {
            success = diff.errorSignal && diff.score >= 20
            if (success) {
                confidence = 72
                severity = 'medium'
            }
        } else {
            success = diff.errorSignal && diff.score >= 20
            if (success) {
                confidence = 68
                severity = 'medium'
            }
        }

        const behavioralImpact = success && (
            diff.signals.includes('status_changed')
            || diff.signals.includes('redirect_changed')
            || diff.signals.includes('set_cookie_changed')
        )
        if (behavioralImpact) {
            confidence = 92
            severity = 'high'
        }

        executed.metadata = executed.metadata || {}
        executed.metadata.deserializationProbe = true
        executed.metadata.diffSignals = {
            score: diff.score,
            signals: diff.signals,
            lenDelta: diff.lenDelta,
            lenDeltaPct: diff.lenDeltaPct,
            statusCode: diff.statusCode
        }
        if (pairedControl) {
            executed.metadata.controlPair = {
                attackId: pairedControl?.metadata?.id || null,
                mutationKind: pairedControl?.metadata?.deserMutationKind || 'control'
            }
        }
        executed.metadata.confirmation = behavioralImpact
            ? { strategy: 'role_state_echo', success: true }
            : { strategy: 'differential', success: success }
        if (!Array.isArray(executed.metadata.mutationsRun)) {
            executed.metadata.mutationsRun = ['baseline', mutationKind]
        }

        const proofSignals = diff.signals.length ? diff.signals.join(', ') : 'no-signals'
        return {
            success,
            proof: success
                ? `Deserialization differential detected (${proofSignals}).`
                : '',
            detector: 'deserialization-active',
            match: success ? proofSignals : null,
            confidence: success ? confidence : null,
            severity: success ? severity : null
        }
    }

    validateAttack(executed, original) {
        const isDeserializationModule = this._isDeserializationTechniqueModule()
        const isDeserializationCoverageAttack = this._isDeserializationCoverageAttack(executed?.metadata || {})
        const hasExplicitValidationRule = !!(
            executed?.metadata?.validation?.rule
            && executed.metadata.validation.rule !== false
        )
        const shouldPreferCustomValidation = (
            this.type !== 'passive'
            && isDeserializationModule
            && !isDeserializationCoverageAttack
            && executed?.metadata?.deserializationProbe !== true
            && hasExplicitValidationRule
        )
        if (
            !shouldPreferCustomValidation &&
            isDeserializationModule &&
            (this.type === 'passive' || (!isDeserializationCoverageAttack && executed?.metadata?.deserializationProbe !== true))
        ) {
            return this._validatePassiveDeserialization(executed, original)
        }
        if (
            !shouldPreferCustomValidation &&
            isDeserializationModule &&
            (executed?.metadata?.deserializationProbe === true || isDeserializationCoverageAttack)
        ) {
            return this._validateActiveDeserialization(executed, original)
        }
        if (executed) {
            const success = jsonLogic.apply(executed.metadata?.validation?.rule, { "attack": executed, "original": original, "module": this })
            let proof = ""
            if (executed.metadata?.validation?.proof && success) {
                proof = jsonLogic.apply(executed.metadata.validation.proof, { "attack": executed, "original": original, "module": this })
            }
            if (success && !proof) {
                proof = this._buildBaselineProof(executed, original)
            }
            return {
                "success": !!success,
                "proof": proof,
                "detector": executed.metadata?.validation?.type || executed.metadata?.validation?.detector || null,
                "match": proof || null
            }
        }
        return { "success": false, "proof": "" }
    }

    _buildBaselineProof(attack, original) {
        const attackRes = attack?.response || {}
        const origRes = original?.response || {}
        const statusMatch = attackRes?.statusCode != null && origRes?.statusCode != null
            && Number(attackRes.statusCode) === Number(origRes.statusCode)
        const bodyMatch = typeof attackRes?.body === "string" && typeof origRes?.body === "string"
            && attackRes.body === origRes.body
        if (statusMatch && bodyMatch) {
            return "Attack response matches baseline (status and body)."
        }
        if (statusMatch) {
            return "Attack response status matches baseline."
        }
        if (bodyMatch) {
            return "Attack response body matches baseline."
        }
        return ""
    }
}
