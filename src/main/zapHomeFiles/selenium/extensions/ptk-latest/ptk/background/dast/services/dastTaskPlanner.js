import { ptk_request } from "../../rbuilder.js"
import { ptk_utils } from "../../utils.js"

export class DastTaskPlanner {
    constructor({
        awaitModulesLoaded = async () => {},
        refreshOastProbeDomains = () => {},
        ensureOastCallbackProbe = () => {},
        resolveOriginal = async () => null,
        getModules = () => [],
        shouldPlanModule = () => true,
        moduleRuntimeMode = () => "standard",
        buildSpaTasks = () => [],
        shouldUseBulkAttack = () => false,
        enrichAttackPayload = (payload) => payload,
        createTask = (task) => task,
        attackMetadataView = () => ({}),
        appendSelectorDiagnostics = () => {},
        registerPlannedTask = () => {},
        appendRuntimeEvent = () => {},
        fingerprintFromSchema = () => null,
        fingerprintFromPayload = () => null
    } = {}) {
        this.awaitModulesLoaded = awaitModulesLoaded
        this.refreshOastProbeDomains = refreshOastProbeDomains
        this.ensureOastCallbackProbe = ensureOastCallbackProbe
        this.resolveOriginal = resolveOriginal
        this.getModules = getModules
        this.shouldPlanModule = shouldPlanModule
        this.moduleRuntimeMode = moduleRuntimeMode
        this.buildSpaTasks = buildSpaTasks
        this.shouldUseBulkAttack = shouldUseBulkAttack
        this.enrichAttackPayload = enrichAttackPayload
        this.createTask = createTask
        this.attackMetadataView = attackMetadataView
        this.appendSelectorDiagnostics = appendSelectorDiagnostics
        this.registerPlannedTask = registerPlannedTask
        this.appendRuntimeEvent = appendRuntimeEvent
        this.fingerprintFromSchema = fingerprintFromSchema
        this.fingerprintFromPayload = fingerprintFromPayload
    }

    _selectorPriority(requestSchema, attack) {
        const selection = requestSchema?.metadata?.selectorSelection && typeof requestSchema.metadata.selectorSelection === "object"
            ? requestSchema.metadata.selectorSelection
            : null
        const selectorRank = Number(selection?.rankScore)
        const attackPriorityBoost = Number(attack?.metadata?.extensions?.selectorPriorityBoost)
        return Math.trunc(
            (Number.isFinite(selectorRank) ? selectorRank : 0)
            + (Number.isFinite(attackPriorityBoost) ? attackPriorityBoost : 0)
        )
    }

    _collectAttackProbeStrings(value, out = []) {
        if (value == null) return out
        if (typeof value === "string") {
            out.push(value)
            return out
        }
        if (Array.isArray(value)) {
            value.forEach(item => this._collectAttackProbeStrings(item, out))
            return out
        }
        if (typeof value === "object") {
            for (const [key, nested] of Object.entries(value)) {
                if (key === "value" || key === "marker" || key === "payload") {
                    this._collectAttackProbeStrings(nested, out)
                } else if (nested && typeof nested === "object") {
                    this._collectAttackProbeStrings(nested, out)
                }
            }
        }
        return out
    }

    _requestSurfaceText(requestSchema = null, original = null) {
        const fields = [
            requestSchema?.request?.url,
            requestSchema?.request?.path,
            requestSchema?.request?.ui_url,
            requestSchema?.request?.uiUrl,
            original?.request?.url,
            original?.request?.path,
            original?.request?.ui_url,
            original?.request?.uiUrl,
            requestSchema?.metadata?.attacked?.location,
            requestSchema?.metadata?.attacked?.name
        ]
        return fields
            .filter(value => value != null)
            .map(value => String(value).toLowerCase())
            .join(" ")
    }

    _attackExecutionPriority(attack, requestSchema = null, original = null) {
        const values = []
        this._collectAttackProbeStrings(attack?.action, values)
        this._collectAttackProbeStrings(attack?.runtime?.confirmation?.tracking?.marker, values)
        const text = values.join(" ").toLowerCase()
        if (!text) return 0

        const invokesScript = /\b(?:alert|confirm|prompt|postmessage)\s*\(/i.test(text)
        if (!invokesScript) return 0

        let priority = 0
        const hasEventHandler = /\bon[a-z][a-z0-9_-]*\s*=/i.test(text)
        const injectsWholeTag = /<\s*[a-z][\w:-]*/i.test(text)
        const hasScriptTag = /<\s*script\b/i.test(text)
        const hasSvgExecution = /<\s*svg\b|(?:^|\s)svg\s+on[a-z][a-z0-9_-]*\s*=/i.test(text)
        const hasJsStringBreakout = /["'`]\s*;\s*(?:alert|confirm|prompt)\s*\(/i.test(text)
            || /\/\s*;\s*(?:alert|confirm|prompt)\s*\(/i.test(text)
            || /\*\/\s*(?:alert|confirm|prompt)\s*\(/i.test(text)
        const surface = this._requestSurfaceText(requestSchema, original)
        const likelyAttributeContext = /(?:attr|attribute|tagname|href|srcdoc|src|style|css|link|event)/i.test(surface)
        const likelyCodeContext = /(?:eval|assignment|quoted|string|comment|expression|template|javascript)/i.test(surface)
        const likelyHtmlContext = /(?:html|body|content|render|preview|escape|encode|decode|text)/i.test(surface)

        const breaksAttributeContext = hasEventHandler && !injectsWholeTag
        if (breaksAttributeContext) priority += 720
        if (hasScriptTag) priority += 620
        if (hasJsStringBreakout) priority += 560
        if (hasSvgExecution && !injectsWholeTag) priority += 520
        if (hasEventHandler && injectsWholeTag) priority += 180
        if (hasSvgExecution && injectsWholeTag) priority += 140
        if (breaksAttributeContext && likelyAttributeContext) priority += 260
        if (hasJsStringBreakout && likelyCodeContext) priority += 320
        if (hasScriptTag && likelyHtmlContext && !likelyAttributeContext && !likelyCodeContext) priority += 320
        if (hasEventHandler && !likelyAttributeContext && (likelyHtmlContext || likelyCodeContext)) priority -= 260

        return priority
    }

    _attackRequestPriority(requestSchema, attack, original = null) {
        return this._selectorPriority(requestSchema, attack) + this._attackExecutionPriority(attack, requestSchema, original)
    }

    _conditionNeedsRequestMetadata(condition) {
        if (!condition || typeof condition !== "object") return false
        try {
            const serialized = JSON.stringify(condition)
            return serialized.includes("attack.metadata.selectorSelection")
                || serialized.includes("attack.metadata.attacked")
        } catch {
            return false
        }
    }

    _sortModuleAttackRequests(entries = []) {
        return [...entries].sort((a, b) => {
            if (b.priority !== a.priority) return b.priority - a.priority
            const aLocation = String(a?.requestSchema?.metadata?.attacked?.location || "")
            const bLocation = String(b?.requestSchema?.metadata?.attacked?.location || "")
            if (aLocation !== bLocation) return aLocation.localeCompare(bLocation)
            const aName = String(a?.requestSchema?.metadata?.attacked?.name || "")
            const bName = String(b?.requestSchema?.metadata?.attacked?.name || "")
            if (aName !== bName) return aName.localeCompare(bName)
            return Number(a?.orderHint || 0) - Number(b?.orderHint || 0)
        })
    }

    _shouldPlanAttackRequest() {
        return true
    }

    _browserNavSourceDrivers(attack = null) {
        const cfg = attack?.runtime?.config?.browserNav
            || attack?.runtime?.browserNav
            || {}
        const values = cfg.sourceDrivers || cfg.sources || []
        return Array.from(new Set(
            (Array.isArray(values) ? values : [values])
                .map(value => String(value || "").trim())
                .filter(Boolean)
        ))
    }

    _browserNavSourceDriverPolicy(attack = null) {
        const cfg = attack?.runtime?.config?.browserNav
            || attack?.runtime?.browserNav
            || {}
        const policy = cfg.sourceDriverPolicy
        return policy && typeof policy === "object" ? policy : null
    }

    _attackPayloadValue(attack = null) {
        const params = Array.isArray(attack?.action?.params) ? attack.action.params : []
        for (const param of params) {
            if (param?.value != null) return String(param.value)
        }
        const constantsPayload = attack?.metadata?.constants?.payload
        return constantsPayload != null ? String(constantsPayload) : ""
    }

    _responseLooksLikeAngularExpressionParser(original = null) {
        const body = String(original?.response?.body || "")
        return /(?:\$\s*parse|\$parse)\s*\(|['"]\$parse['"]|\.get\(\s*['"]\$parse['"]\s*\)/i.test(body)
    }

    _responseLooksLikeSubmittableForm(original = null) {
        const body = String(original?.response?.body || "")
        return /<form\b/i.test(body)
    }

    _responseLooksLikePostMessageSource(original = null) {
        const body = String(original?.response?.body || "")
        return /(?:addEventListener\s*\(\s*['"]message['"]|(?:window\s*\.\s*)?onmessage\s*=|(?:event|messageEvent)\s*\.\s*data)/i.test(body)
    }

    _decodeJsStringLiteral(value = "") {
        try {
            return JSON.parse(`"${String(value).replace(/"/g, '\\"')}"`)
        } catch {
            return String(value)
                .replace(/\\'/g, "'")
                .replace(/\\"/g, '"')
                .replace(/\\\\/g, "\\")
        }
    }

    _extractJsStringBindings(source = "") {
        const bindings = new Map()
        const re = /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(['"])((?:\\.|(?!\2).){1,160})\2/g
        let match
        while ((match = re.exec(source))) {
            bindings.set(match[1], this._decodeJsStringLiteral(match[3]))
        }
        return bindings
    }

    _resolveJsStringReference(expression = "", bindings = new Map()) {
        const value = String(expression || "").trim()
        if (!value) return null
        const literal = value.match(/^(['"])((?:\\.|(?!\1).){0,160})\1$/)
        if (literal) return this._decodeJsStringLiteral(literal[2])
        if (/^[A-Za-z_$][\w$]*$/.test(value) && bindings.has(value)) {
            return bindings.get(value)
        }
        const concatHead = value.match(/^([A-Za-z_$][\w$]*|(['"])((?:\\.|(?!\2).){1,160})\2)\s*\+/)
        if (concatHead) {
            return this._resolveJsStringReference(concatHead[1], bindings)
        }
        return null
    }

    _addBrowserSourceKeyHint(hints, driver, key) {
        const normalizedDriver = String(driver || "").trim()
        const normalizedKey = String(key || "").trim()
        if (!normalizedDriver || !normalizedKey) return
        if (!hints[normalizedDriver]) hints[normalizedDriver] = []
        if (!hints[normalizedDriver].includes(normalizedKey)) hints[normalizedDriver].push(normalizedKey)
    }

    _extractBrowserSourceKeyHints(original = null) {
        const body = String(original?.response?.body || "")
        if (!body) return {}
        const bindings = this._extractJsStringBindings(body)
        const hints = {}

        const storageRe = /\b(?:window\.)?(localStorage|sessionStorage)(?:\s*\.\s*getItem\(\s*([^)]+?)\s*\)|\s*\[\s*([^\]]+?)\s*\]|\s*\.\s*setItem\(\s*([^,\n\r]+?)\s*,)/g
        let match
        while ((match = storageRe.exec(body))) {
            const key = this._resolveJsStringReference(match[2] || match[3] || match[4], bindings)
            if (key) this._addBrowserSourceKeyHint(hints, match[1], key)
        }

        const cookieCallRe = /\b(?:lookupCookie|getCookie|readCookie|cookieValue)\s*\(\s*([^)]+?)\s*\)/g
        while ((match = cookieCallRe.exec(body))) {
            const key = this._resolveJsStringReference(match[1], bindings)
            if (key) this._addBrowserSourceKeyHint(hints, "cookie", key)
        }

        const cookieAssignRe = /\bdocument\s*\.\s*cookie\s*=\s*([^;\n\r]+)/g
        while ((match = cookieAssignRe.exec(body))) {
            const key = this._resolveJsStringReference(match[1], bindings)
            if (key) this._addBrowserSourceKeyHint(hints, "cookie", key)
        }

        return hints
    }

    _browserSourceEvidence(original = null, keyHints = {}) {
        const evidence = new Set()
        if (this._responseLooksLikeAngularExpressionParser(original)) evidence.add("angularExpressionParser")
        if (this._responseLooksLikeSubmittableForm(original)) evidence.add("submittableForm")
        if (this._responseLooksLikePostMessageSource(original)) evidence.add("postMessageSource")
        const hints = keyHints && typeof keyHints === "object" ? keyHints : {}
        for (const driver of ["cookie", "localStorage", "sessionStorage"]) {
            if (Array.isArray(hints[driver]) && hints[driver].length) {
                evidence.add(`${driver}KeyHint`)
            }
        }
        return evidence
    }

    _sourceEvidenceSatisfies(requirements = [], evidence = new Set()) {
        const values = Array.isArray(requirements) ? requirements : [requirements]
        return values
            .map(value => String(value || "").trim())
            .filter(Boolean)
            .every(value => evidence.has(value))
    }

    _applyBrowserSourceDriverPolicy(attack = null, sourceDrivers = [], original = null, keyHints = {}) {
        const policy = this._browserNavSourceDriverPolicy(attack)
        if (!policy || policy.mode !== "generic-source-evidence") {
            return {
                sourceDrivers,
                keyMode: null
            }
        }

        const evidence = this._browserSourceEvidence(original, keyHints)
        if (!this._sourceEvidenceSatisfies(policy.requires || [], evidence)) {
            return {
                sourceDrivers: [],
                keyMode: policy.keyMode && typeof policy.keyMode === "object" ? policy.keyMode : null
            }
        }

        const driverPolicy = policy.drivers && typeof policy.drivers === "object" ? policy.drivers : {}
        const filtered = sourceDrivers.filter(driver => {
            const spec = driverPolicy[driver]
            if (!spec || typeof spec !== "object") return false
            return this._sourceEvidenceSatisfies(spec.requires || [], evidence)
        })
        return {
            sourceDrivers: filtered,
            keyMode: policy.keyMode && typeof policy.keyMode === "object" ? policy.keyMode : null
        }
    }

    _cloneSchema(schema = null) {
        if (!schema || typeof schema !== "object") return null
        try {
            return JSON.parse(JSON.stringify(schema))
        } catch {
            return null
        }
    }

    _buildBrowserSourceAttackRequest(baseSchema = null, attack = null, original = null) {
        let sourceDrivers = this._browserNavSourceDrivers(attack)
        if (!sourceDrivers.length) return null
        const attackId = String(attack?.id || "")
        const attackContext = String(attack?.metadata?.constants?.context || "")
        if (attackId.startsWith("angularjs_csti_") && attackContext === "template_interpolation") {
            if (this._responseLooksLikeAngularExpressionParser(original) || !this._responseLooksLikeSubmittableForm(original)) {
                return null
            }
            sourceDrivers = sourceDrivers.filter(driver => driver === "form")
            if (!sourceDrivers.length) return null
        }
        const payloadValue = this._attackPayloadValue(attack)
        if (!payloadValue) return null
        const schema = this._cloneSchema(baseSchema)
        if (!schema?.request) return null
        const requestUrl = String(
            original?.request?.url
            || original?.request?.ui_url
            || original?.request?.uiUrl
            || schema.request.url
            || ""
        ).trim()
        const uiUrl = String(
            original?.request?.ui_url
            || original?.request?.uiUrl
            || requestUrl
        ).trim()
        if (!requestUrl && !uiUrl) return null
        schema.request.method = String(schema.request.method || original?.request?.method || "GET").toUpperCase()
        schema.request.url = requestUrl || uiUrl
        schema.request.ui_url = uiUrl || requestUrl
        schema.request.method = "GET"
        schema.request.body = undefined
        schema.request.bodySize = 0
        schema.request.headers = Array.isArray(schema.request.headers)
            ? schema.request.headers.filter(header => !/^(?:content-length|content-type)$/i.test(String(header?.name || "")))
            : []
        try {
            const parsed = new URL(schema.request.url)
            schema.request.path = parsed.pathname || "/"
            schema.request.target = `${parsed.pathname || "/"}${parsed.search || ""}`
        } catch {}
        const keyHints = this._extractBrowserSourceKeyHints(original)
        const sourcePolicy = this._applyBrowserSourceDriverPolicy(attack, sourceDrivers, original, keyHints)
        sourceDrivers = sourcePolicy.sourceDrivers
        if (!sourceDrivers.length) return null
        schema.metadata = Object.assign({}, schema.metadata || {}, {
            attacked: {
                location: "browser_source",
                name: "browser_source"
            },
            payload: payloadValue,
            browserSource: {
                enabled: true,
                context: attackContext || null,
                sourceDrivers,
                keyHints,
                keyMode: sourcePolicy.keyMode,
                cookieEncoding: attackId.startsWith("angularjs_csti_") && attackContext === "expression_context"
                    ? "raw-first"
                    : null
            }
        })
        return schema
    }

    _baselineResponseText(original = null) {
        const response = original?.response && typeof original.response === "object"
            ? original.response
            : null
        if (!response) return ""
        return [
            response.body,
            response.statusText,
            response.statusMessage,
            response.statusLine,
            response.errorMessage
        ]
            .filter(value => value != null)
            .map(value => String(value))
            .join(" ")
            .slice(0, 2000)
    }

    _activeAttackBaselineSkipReason(original = null) {
        const method = String(original?.request?.method || "").toUpperCase()
        if (!method || ["GET", "HEAD", "OPTIONS"].includes(method)) return null

        const response = original?.response && typeof original.response === "object"
            ? original.response
            : null
        if (!response) return null

        const statusCode = Number(response.statusCode ?? response.status)
        const text = this._baselineResponseText(original)

        if (/\b(?:wrong\s+answer|invalid\s+captcha|captcha\s+(?:failed|invalid|wrong))\b/i.test(text)) {
            return "baseline_captcha_failed"
        }
        if (/\b(?:constraint\s+failed|foreign\s+key\s+constraint|validation\s+(?:failed|error)|invalid\s+(?:input|request|value)|required)\b/i.test(text)) {
            return "baseline_validation_failed"
        }
        if (!Number.isFinite(statusCode)) return null
        if (statusCode === 401 || statusCode === 403) return "baseline_auth_failed"
        if (statusCode >= 500) return "baseline_5xx"
        if (statusCode >= 400) return "baseline_4xx"
        return null
    }

    _pathFromUrl(value) {
        if (value == null) return null
        const raw = String(value || "").trim()
        if (!raw) return null
        try {
            return new URL(raw, "http://ptk.local").pathname || "/"
        } catch {
            const withoutQuery = raw.split(/[?#]/, 1)[0]
            if (!withoutQuery) return null
            return withoutQuery.startsWith("/") ? withoutQuery : `/${withoutQuery}`
        }
    }

    _compileTargetRegex(pattern) {
        if (pattern == null || pattern === "") return null
        try {
            return new RegExp(String(pattern), "i")
        } catch {
            return null
        }
    }

    _attackTargetMatchesRequest(attack, schema = null, original = null) {
        const target = attack?.target
        if (!target || typeof target !== "object") return true

        const hasRouteTarget = target.method != null || target.path != null || target.urlRegex != null
        if (!hasRouteTarget) return true

        const methodTarget = String(target.method || "").trim().toUpperCase()
        if (methodTarget) {
            const method = String(
                original?.request?.method
                || schema?.request?.method
                || ""
            ).trim().toUpperCase()
            if (method !== methodTarget) return false
        }

        const rawCandidates = [
            original?.request?.url,
            original?.request?.ui_url,
            original?.request?.uiUrl,
            original?.request?.path,
            schema?.request?.url,
            schema?.request?.ui_url,
            schema?.request?.uiUrl,
            schema?.request?.path
        ]
            .filter(value => value != null)
            .map(value => String(value))
            .filter(Boolean)

        const pathCandidates = Array.from(new Set(
            rawCandidates
                .map(value => this._pathFromUrl(value))
                .filter(Boolean)
        ))

        const targetPath = this._pathFromUrl(target.path)
        if (targetPath && !pathCandidates.includes(targetPath)) {
            return false
        }

        const urlRegex = this._compileTargetRegex(target.urlRegex)
        if (urlRegex) {
            const candidates = [...rawCandidates, ...pathCandidates]
            if (!candidates.some(value => {
                urlRegex.lastIndex = 0
                return urlRegex.test(value)
            })) {
                return false
            }
        }

        return true
    }

    _escapeRegex(value) {
        return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    }

    _decodeCandidateValue(value) {
        const raw = String(value ?? "")
        const values = new Set([raw, raw.replace(/\+/g, " ")])
        for (const candidate of Array.from(values)) {
            try {
                values.add(decodeURIComponent(candidate))
                values.add(decodeURIComponent(candidate.replace(/\+/g, " ")))
            } catch {}
        }
        return Array.from(values).filter(item => item.length >= 2)
    }

    _attackedOriginalValue(requestSchema = null, original = null) {
        const attacked = requestSchema?.metadata?.attacked
        const name = String(attacked?.name || "").trim()
        const location = String(attacked?.location || "").trim().toLowerCase()
        if (!name) return null

        let query = Array.isArray(original?.request?.queryParams) ? original.request.queryParams : []
        let form = Array.isArray(original?.request?.body?.params) ? original.request.body.params : []
        if ((!query.length && !form.length) && original?.request?.raw) {
            try {
                const parsedOriginal = ptk_request.parseRawRequest(original.request.raw, original?.request?.url ? { ui_url: original.request.url } : undefined)
                query = Array.isArray(parsedOriginal?.request?.queryParams) ? parsedOriginal.request.queryParams : query
                form = Array.isArray(parsedOriginal?.request?.body?.params) ? parsedOriginal.request.body.params : form
            } catch {}
        }
        if (!query.length && original?.request?.url) {
            try {
                const parsedUrl = new URL(original.request.url)
                query = Array.from(parsedUrl.searchParams.entries()).map(([paramName, value]) => ({ name: paramName, value }))
            } catch {}
        }
        const pools = location === "form" || location === "body"
            ? [form]
            : (location === "query" ? [query] : [query, form])

        for (const pool of pools) {
            const hit = pool.find(param => String(param?.name || "") === name)
            if (hit && hit.value != null) return String(hit.value)
        }
        return null
    }

    _angularInterpolationPairs(responseText = "") {
        const pairs = [{ start: "{{", end: "}}" }, { start: "[[", end: "]]" }]
        const providerRegex = /startSymbol\s*\(\s*(['"`])([^'"`]{1,12})\1\s*\)[\s\S]{0,240}?endSymbol\s*\(\s*(['"`])([^'"`]{1,12})\3\s*\)/gi
        let match = null
        while ((match = providerRegex.exec(responseText)) !== null) {
            const start = match[2]
            const end = match[4]
            if (start && end && !pairs.some(pair => pair.start === start && pair.end === end)) {
                pairs.push({ start, end })
            }
        }
        return pairs
    }

    _valueIsInsideDelimitedExpression(text, index, valueLength, pair) {
        const start = text.lastIndexOf(pair.start, index)
        if (start < 0) return false
        const end = text.indexOf(pair.end, index + valueLength)
        if (end < 0) return false
        const priorEnd = text.lastIndexOf(pair.end, index)
        const nestedStart = text.indexOf(pair.start, index + valueLength)
        return priorEnd < start && (nestedStart < 0 || nestedStart > end)
    }

    _valueIsInsideAngularDirectiveAttribute(text, index, valueLength) {
        const windowStart = Math.max(0, index - 320)
        const windowEnd = Math.min(text.length, index + valueLength + 320)
        const before = text.slice(windowStart, index)
        const after = text.slice(index + valueLength, windowEnd)
        const attrStart = before.match(/(?:\bdata-)?\bng-[\w:-]+\s*=\s*(["'])[^"']*$/i)
        if (!attrStart) return false
        const quote = attrStart[1]
        return after.includes(quote)
    }

    _valueIsInsideHtmlAttribute(text, index, valueLength) {
        const tagStart = text.lastIndexOf("<", index)
        const tagEndBefore = text.lastIndexOf(">", index)
        if (tagStart < 0 || tagStart < tagEndBefore) return false
        const nextTagEnd = text.indexOf(">", index + valueLength)
        if (nextTagEnd < 0) return false
        const tagPrefix = text.slice(tagStart, index)
        const singleQuotes = (tagPrefix.match(/'/g) || []).length
        const doubleQuotes = (tagPrefix.match(/"/g) || []).length
        return singleQuotes % 2 === 1 || doubleQuotes % 2 === 1
    }

    _looksLikeStandaloneReflectedValue(text, index, valueLength) {
        const before = index > 0 ? text[index - 1] : ""
        const after = index + valueLength < text.length ? text[index + valueLength] : ""
        const embeddedToken = /[A-Za-z0-9_.:/-]/
        return !embeddedToken.test(before) && !embeddedToken.test(after)
    }

    _inferAngularSourceContext(requestSchema = null, original = null) {
        const value = this._attackedOriginalValue(requestSchema, original)
        if (!value) return "unknown"
        const responseText = String(original?.response?.body || "")
        if (!responseText) return "unknown"

        const values = this._decodeCandidateValue(value)
        if (!values.length) return "unknown"
        const interpolationPairs = this._angularInterpolationPairs(responseText)
        let expressionHits = 0
        let templateHits = 0

        for (const candidate of values) {
            let index = responseText.indexOf(candidate)
            while (index >= 0) {
                if (this._looksLikeStandaloneReflectedValue(responseText, index, candidate.length)) {
                    const inInterpolation = interpolationPairs.some(pair => this._valueIsInsideDelimitedExpression(responseText, index, candidate.length, pair))
                    const inDirectiveAttribute = this._valueIsInsideAngularDirectiveAttribute(responseText, index, candidate.length)
                    const inPlainAttribute = !inDirectiveAttribute && this._valueIsInsideHtmlAttribute(responseText, index, candidate.length)
                    if (inInterpolation || inDirectiveAttribute) expressionHits += 1
                    else if (!inPlainAttribute) templateHits += 1
                }
                index = responseText.indexOf(candidate, index + candidate.length)
            }
        }

        if (expressionHits > 0 && templateHits === 0) return "expression_context"
        if (templateHits > 0 && expressionHits === 0) return "template_interpolation"
        return "unknown"
    }

    _attackMatchesAngularSourceContext(attack, requestSchema = null, original = null) {
        const attackId = String(attack?.id || "")
        if (!attackId.startsWith("angularjs_csti_")) return true
        const attackContext = String(attack?.metadata?.constants?.context || "")
        if (attackContext !== "expression_context" && attackContext !== "template_interpolation") return true
        const inferredContext = this._inferAngularSourceContext(requestSchema, original)
        if (inferredContext === "unknown") return true
        return attackContext === inferredContext
    }

    _hasAngularCstiModule(modules = []) {
        return (Array.isArray(modules) ? modules : []).some(module => {
            const moduleId = String(module?.id || module?.name || "").trim().toLowerCase()
            return moduleId === "angularjs_client_template_injection"
        })
    }

    _hasAngularTechnologyEvidence(original = null) {
        const responseBody = String(original?.response?.body || "")
        const requestUrl = String(original?.request?.url || original?.request?.ui_url || original?.request?.uiUrl || "")
        const text = `${requestUrl}\n${responseBody}`
        return /(?:\bng-app\b|\bdata-ng-app\b|\bng-controller\b|\bdata-ng-controller\b|\bng-bind\b|\bdata-ng-bind\b|\bangular\.module\s*\(|angularjs\/|angular(?:\.min)?\.js)/i.test(text)
    }

    _shouldPreferAngularCstiForRequest(module = null, requestSchema = null, original = null, modules = []) {
        const moduleId = String(module?.id || module?.name || "").trim().toLowerCase()
        if (moduleId !== "dom_xss_url_params") return false
        if (!this._hasAngularCstiModule(modules)) return false
        if (!this._hasAngularTechnologyEvidence(original)) return false
        const inferredContext = this._inferAngularSourceContext(requestSchema, original)
        return inferredContext === "expression_context" || inferredContext === "template_interpolation"
    }

    async buildAttackPlan(raw) {
        const rawStr = typeof raw === "object" ? raw.raw : raw
        const rawMeta = typeof raw === "object" ? raw : {}
        const uiUrl = rawMeta.ui_url || rawMeta.uiUrl || null
        const baseSchemaCache = new Map()
        await this.awaitModulesLoaded()
        this.refreshOastProbeDomains()
        this.ensureOastCallbackProbe()
        const parseOpts = uiUrl ? { ui_url: uiUrl } : undefined
        const schema = ptk_request.parseRawRequest(rawStr, parseOpts)
        const modules = Array.isArray(this.getModules()) ? this.getModules() : []
        const planFingerprint = this.fingerprintFromSchema(schema)
        const original = await this.resolveOriginal(schema, rawMeta, {
            modules,
            planFingerprint
        })
        if (!original) return null

        const plan = {
            id: ptk_utils.attackId(),
            raw,
            schema,
            original,
            tasks: [],
            fingerprint: planFingerprint
        }
        const baselineActiveSkipReason = this._activeAttackBaselineSkipReason(original)
        let baselineActiveSkipEventRecorded = false

        for (const module of modules) {
            if (!Array.isArray(module?.attacks)) continue
            const modulePlanDecision = this.shouldPlanModule(module, schema, original)
            if (modulePlanDecision === false || modulePlanDecision?.allowed === false) {
                continue
            }
            if (module.type === "active" && baselineActiveSkipReason) {
                if (!baselineActiveSkipEventRecorded) {
                    baselineActiveSkipEventRecorded = true
                    this.appendRuntimeEvent({
                        type: "dast_plan_skipped",
                        phase: "plan_build",
                        reason: baselineActiveSkipReason,
                        url: original?.request?.url || null,
                        method: original?.request?.method || null,
                        statusCode: original?.response?.statusCode ?? original?.response?.status ?? null
                    })
                }
                continue
            }
            const moduleAllowsStrategyBulk = this.shouldUseBulkAttack(module, { resolveOnly: true })
            const bufferedModuleTasks = []
            let angularCstiContextSkipRecorded = false
            for (const attackDef of module.attacks) {
                let attack = null
                try {
                    attack = module.prepareAttack(attackDef)
                    if (!this._attackTargetMatchesRequest(attack, schema, original)) {
                        continue
                    }
                    const conditionNeedsRequestMetadata = this._conditionNeedsRequestMetadata(attack?.condition)
                    if (attack.condition && module.async !== false && !conditionNeedsRequestMetadata) {
                        const _a = { metadata: this.attackMetadataView(module, attack) }
                        if (!module.validateAttackConditions(_a, original)) continue
                    }

                    if (this.moduleRuntimeMode(module) === "spa") {
                        const spaTasks = this.buildSpaTasks(original, module, attack, rawMeta, planFingerprint)
                        for (const task of spaTasks) {
                            task.order = plan.tasks.length
                            plan.tasks.push(task)
                            this.registerPlannedTask()
                        }
                        continue
                    }

                    if (module.type === "active") {
                        const attackOptions = attack.action?.options
                        const baseSchemaKey = JSON.stringify(attackOptions || null)
                        let baseSchema = baseSchemaCache.get(baseSchemaKey)
                        if (!baseSchema) {
                            baseSchema = ptk_request.parseRawRequest(original.request.raw, attackOptions)
                            baseSchemaCache.set(baseSchemaKey, baseSchema)
                        }
                        const attackMode = this.shouldUseBulkAttack(module, { moduleAllowsStrategyBulk })
                            ? { mode: "bulk", prepared: true }
                            : { prepared: true }
                        const attackRequests = module.buildAttacks(baseSchema, attack, attackMode)
                        const effectiveAttackRequests = Array.isArray(attackRequests) ? attackRequests.slice() : []
                        const browserSourceRequest = this._buildBrowserSourceAttackRequest(baseSchema, attack, original)
                        if (browserSourceRequest) {
                            effectiveAttackRequests.push(browserSourceRequest)
                        }
                        this.appendSelectorDiagnostics(module, attack, original)
                        for (const req of effectiveAttackRequests) {
                            if (this._shouldPreferAngularCstiForRequest(module, req, original, modules)) {
                                if (!angularCstiContextSkipRecorded) {
                                    angularCstiContextSkipRecorded = true
                                    this.appendRuntimeEvent({
                                        type: "dast_plan_skipped",
                                        phase: "plan_build",
                                        moduleId: module?.id || null,
                                        moduleName: module?.name || null,
                                        reason: "angular_csti_context_covered_by_framework_module",
                                        url: original?.request?.url || null,
                                        method: original?.request?.method || null
                                    })
                                }
                                continue
                            }
                            if (!this._attackMatchesAngularSourceContext(attack, req, original)) {
                                continue
                            }
                            if (attack.condition && module.async !== false && conditionNeedsRequestMetadata) {
                                const conditionPayload = { metadata: this.attackMetadataView(module, attack, req?.metadata || {}) }
                                if (!module.validateAttackConditions(conditionPayload, original)) continue
                            }
                            const enriched = this.enrichAttackPayload(
                                ptk_request.updateRawRequest(req, null, attack.action?.options),
                                module,
                                attack
                            )
                            const fingerprint = this.fingerprintFromPayload(enriched) || planFingerprint
                            const priority = this._attackRequestPriority(req, attack, original)
                            const task = this.createTask({
                                module,
                                attack,
                                payload: enriched,
                                type: "active",
                                fingerprint
                            })
                            task.plannerPriority = priority
                            bufferedModuleTasks.push({
                                module,
                                attack,
                                requestSchema: req,
                                task,
                                priority,
                                orderHint: bufferedModuleTasks.length
                            })
                        }
                    } else if (module.type === "passive") {
                        const passivePayload = { metadata: this.attackMetadataView(module, attack) }
                        const task = this.createTask({
                            module,
                            attack,
                            payload: passivePayload,
                            type: "passive",
                            fingerprint: planFingerprint
                        })
                        task.order = plan.tasks.length
                        plan.tasks.push(task)
                        this.registerPlannedTask()
                        this.appendSelectorDiagnostics(module, attack, original)
                    }
                } catch (err) {
                    this.appendRuntimeEvent({
                        type: "dast_plan_error",
                        phase: "plan_build",
                        moduleId: module?.id || null,
                        moduleName: module?.name || null,
                        attackId: attack?.id || attackDef?.id || null,
                        attackName: attack?.name || attackDef?.name || null,
                        url: original?.request?.url || null,
                        method: original?.request?.method || null,
                        error: err?.message || String(err)
                    })
                }
            }
            for (const entry of this._sortModuleAttackRequests(bufferedModuleTasks)) {
                if (!this._shouldPlanAttackRequest()) continue
                entry.task.order = plan.tasks.length
                plan.tasks.push(entry.task)
                this.registerPlannedTask()
            }
        }

        return plan
    }

    createTaskContext(original, options = {}) {
        return {
            original,
            rateLimited: options.rateLimited !== false,
            respectEngineState: options.respectEngineState !== false,
            notified: new Set(),
            executedByModule: Object.create(null),
            stopState: {}
        }
    }
}

export default DastTaskPlanner
