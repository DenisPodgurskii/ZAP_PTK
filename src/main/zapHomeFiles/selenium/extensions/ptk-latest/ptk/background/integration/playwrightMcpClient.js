const DEFAULT_BASE_URL = "http://localhost:8787"
const DEFAULT_TIMEOUT_MS = 15000
const DEFAULT_MCP_PROTOCOL_VERSION = "2025-11-25"
const STANDARD_MCP_CLIENT_INFO = {
    name: "PTK Playwright Client",
    version: "1.0.0"
}
const LEGACY_JOB_PATH = "/v1/jobs"
const STANDARD_MCP_PATH = "/mcp"

function trimTrailingSlash(value) {
    return String(value || "").trim().replace(/\/+$/, "")
}

function trimLeadingSlash(value) {
    return String(value || "").trim().replace(/^\/+/, "")
}

function resolveBaseUrl(settings = {}) {
    const automation = settings?.automation && typeof settings.automation === "object"
        ? settings.automation
        : {}
    const base = automation.playwrightMcpBaseUrl
        || automation.mcpBaseUrl
        || DEFAULT_BASE_URL
    return trimTrailingSlash(base) || DEFAULT_BASE_URL
}

function cloneValue(value) {
    if (typeof globalThis.structuredClone === "function") {
        try {
            return globalThis.structuredClone(value)
        } catch (_) {
            // fall through
        }
    }
    return JSON.parse(JSON.stringify(value ?? null))
}

function resolveJsonValue(text = "") {
    try {
        return text ? JSON.parse(text) : null
    } catch (_) {
        return text
    }
}

function extractJsonFromMarkdownResult(text = "") {
    const value = String(text || "")
    if (!value.trim()) return null

    const resultSectionMatch = value.match(/(?:^|\n)### Result\s*\n([\s\S]*?)(?:\n### [^\n]+|\n```|$)/)
    if (resultSectionMatch?.[1]) {
        const parsed = resolveJsonValue(resultSectionMatch[1].trim())
        if (parsed && typeof parsed === "object") {
            return parsed
        }
    }

    const firstJsonObjectMatch = value.match(/\{[\s\S]*\}/)
    if (firstJsonObjectMatch?.[0]) {
        const parsed = resolveJsonValue(firstJsonObjectMatch[0].trim())
        if (parsed && typeof parsed === "object") {
            return parsed
        }
    }

    return null
}

function normalizeHeadersRecord(headersLike = {}) {
    if (!headersLike) return {}
    if (typeof Headers !== "undefined" && headersLike instanceof Headers) {
        return Object.fromEntries(headersLike.entries())
    }
    if (Array.isArray(headersLike)) {
        return headersLike.reduce((acc, item) => {
            const name = String(item?.name || item?.[0] || "").trim().toLowerCase()
            if (!name) return acc
            acc[name] = String(item?.value ?? item?.[1] ?? "")
            return acc
        }, {})
    }
    if (typeof headersLike === "object") {
        return Object.entries(headersLike).reduce((acc, [name, value]) => {
            const key = String(name || "").trim().toLowerCase()
            if (!key) return acc
            acc[key] = String(value ?? "")
            return acc
        }, {})
    }
    return {}
}

function buildUrl(baseUrl, path = "") {
    const base = trimTrailingSlash(baseUrl)
    const suffix = trimLeadingSlash(path)
    return suffix ? `${base}/${suffix}` : base
}

function buildLocalHostAliases(baseUrl) {
    try {
        const url = new URL(String(baseUrl || ""))
        const hostname = String(url.hostname || "").trim().toLowerCase()
        if (hostname !== "localhost" && hostname !== "127.0.0.1") {
            return []
        }
        const alternate = new URL(url.toString())
        alternate.hostname = hostname === "localhost" ? "127.0.0.1" : "localhost"
        return [trimTrailingSlash(alternate.toString())]
    } catch (_) {
        return []
    }
}

function isEventStreamResponse(response) {
    const headers = normalizeHeadersRecord(response?.headers || {})
    return String(headers["content-type"] || "").toLowerCase().includes("text/event-stream")
}

function coerceMcpContentValue(block = null) {
    if (!block || typeof block !== "object") return null
    if (block?.structuredContent && typeof block.structuredContent === "object") {
        return block.structuredContent
    }
    if (typeof block?.text === "string") {
        const direct = resolveJsonValue(block.text)
        if (direct && typeof direct === "object") {
            return direct
        }
        return extractJsonFromMarkdownResult(block.text)
    }
    if (typeof block?.data === "string") {
        return resolveJsonValue(block.data)
    }
    if (block?.json && typeof block.json === "object") {
        return block.json
    }
    return null
}

function extractToolResultPayload(result = null) {
    if (!result || typeof result !== "object") return null
    if (result?.structuredContent && typeof result.structuredContent === "object") {
        return result.structuredContent
    }
    const content = Array.isArray(result?.content) ? result.content : []
    for (const block of content) {
        const value = coerceMcpContentValue(block)
        if (value !== null && value !== undefined) return value
    }
    return null
}

function parseSseMessages(text = "") {
    const messages = []
    let dataLines = []
    const flush = () => {
        if (!dataLines.length) return
        const payload = dataLines.join("\n").trim()
        dataLines = []
        if (!payload) return
        const parsed = resolveJsonValue(payload)
        if (parsed !== null && parsed !== undefined) {
            messages.push(parsed)
        }
    }
    String(text || "").split(/\r?\n/).forEach((line) => {
        if (line === "") {
            flush()
            return
        }
        if (line.startsWith("data:")) {
            dataLines.push(line.slice(5).trimStart())
        }
    })
    flush()
    return messages
}

function parseSseBlock(block = "") {
    const dataLines = []
    String(block || "").split(/\r?\n/).forEach((line) => {
        if (line.startsWith("data:")) {
            dataLines.push(line.slice(5).trimStart())
        }
    })
    if (!dataLines.length) return null
    const payload = dataLines.join("\n").trim()
    if (!payload) return null
    const parsed = resolveJsonValue(payload)
    return parsed === undefined ? null : parsed
}

function drainSseMessages(buffer = "") {
    const messages = []
    let working = String(buffer || "")
    while (true) {
        const boundary = working.match(/\r?\n\r?\n/)
        if (!boundary || boundary.index === undefined) break
        const block = working.slice(0, boundary.index)
        working = working.slice(boundary.index + boundary[0].length)
        const parsed = parseSseBlock(block)
        if (parsed !== null) {
            messages.push(parsed)
        }
    }
    return {
        messages,
        remainder: working
    }
}

function findJsonRpcResponse(message, requestId) {
    const entries = Array.isArray(message) ? message : [message]
    for (const entry of entries) {
        if (!entry || typeof entry !== "object") continue
        if (requestId !== undefined && requestId !== null) {
            if (entry.id === requestId && (entry.result !== undefined || entry.error !== undefined)) {
                return entry
            }
            continue
        }
        if (entry.result !== undefined || entry.error !== undefined) {
            return entry
        }
    }
    return null
}

async function readResponseText(response) {
    const stream = response?.body
    if (stream && typeof stream.getReader === "function") {
        const reader = stream.getReader()
        const decoder = new TextDecoder()
        let text = ""
        while (true) {
            const { done, value } = await reader.read()
            if (done) break
            if (value) {
                text += decoder.decode(value, { stream: true })
            }
        }
        text += decoder.decode()
        return text
    }
    return await response.text()
}

async function fetchBody(response) {
    const text = await readResponseText(response)
    if (isEventStreamResponse(response)) {
        return parseSseMessages(text)
    }
    return resolveJsonValue(text)
}

async function readJsonRpcEventStreamResponse(response, requestId) {
    const stream = response?.body
    if (!stream || typeof stream.getReader !== "function") {
        const body = await fetchBody(response)
        return findJsonRpcResponse(body, requestId)
    }
    const reader = stream.getReader()
    const decoder = new TextDecoder()
    return await new Promise((resolve, reject) => {
        let buffer = ""
        let settled = false
        const resolveOnce = (value) => {
            if (settled) return
            settled = true
            resolve(value)
        }
        const rejectOnce = (error) => {
            if (settled) return
            settled = true
            reject(error)
        }
        ;(async () => {
            try {
                while (true) {
                    const { done, value } = await reader.read()
                    if (done) break
                    if (!value) continue
                    buffer += decoder.decode(value, { stream: true })
                    const drained = drainSseMessages(buffer)
                    buffer = drained.remainder
                    for (const message of drained.messages) {
                        const match = findJsonRpcResponse(message, requestId)
                        if (match) {
                            resolveOnce(match)
                        }
                    }
                }
                buffer += decoder.decode()
                const drained = drainSseMessages(buffer)
                for (const message of drained.messages) {
                    const match = findJsonRpcResponse(message, requestId)
                    if (match) {
                        resolveOnce(match)
                    }
                }
                const finalMatch = findJsonRpcResponse(parseSseBlock(drained.remainder), requestId)
                resolveOnce(finalMatch)
            } catch (error) {
                rejectOnce(error)
            } finally {
                reader.releaseLock?.()
            }
        })().catch(rejectOnce)
    })
}

async function fetchJsonRpc(url, opts = {}, {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    requestId = null,
    resolveEventStreamEarly = true,
    preferBufferedTextResponse = false,
    fetchImpl = (...args) => fetch(...args)
} = {}) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
        let response
        try {
            response = await fetchImpl(url, {
                ...opts,
                signal: controller.signal
            })
        } catch (err) {
            const message = err?.name === "AbortError"
                ? `Playwright MCP request timed out after ${timeoutMs}ms: ${url}`
                : `Playwright MCP is unreachable at ${url}. Start standard @playwright/mcp on ${buildUrl(resolveBaseUrl(), "mcp")} or a legacy PTK runner exposing ${LEGACY_JOB_PATH}.`
            const wrapped = new Error(message)
            wrapped.cause = err
            throw wrapped
        }
        const headers = normalizeHeadersRecord(response.headers || {})
        const eventStreamResponse = isEventStreamResponse(response)
        const body = eventStreamResponse && preferBufferedTextResponse
            ? parseSseMessages(await readResponseText(response))
            : (eventStreamResponse && resolveEventStreamEarly && requestId !== undefined && requestId !== null
                ? await readJsonRpcEventStreamResponse(response, requestId)
                : await fetchBody(response))
        if (!response.ok) {
            const message = Array.isArray(body)
                ? body.map((entry) => entry?.error?.message || entry?.message || "").filter(Boolean)[0]
                : (body?.error?.message || body?.error || body?.message || `HTTP ${response.status}`)
            const err = new Error(`Playwright MCP request failed: ${message}`)
            err.status = response.status
            err.body = body
            throw err
        }
        return {
            status: response.status,
            headers,
            body
        }
    } finally {
        clearTimeout(timer)
    }
}

async function fetchJson(url, opts = {}, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = (...args) => fetch(...args)) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
        let response
        try {
            response = await fetchImpl(url, {
                ...opts,
                signal: controller.signal
            })
        } catch (err) {
            const message = err?.name === "AbortError"
                ? `Playwright MCP request timed out after ${timeoutMs}ms: ${url}`
                : `Playwright MCP is unreachable at ${url}. Start standard @playwright/mcp on ${buildUrl(resolveBaseUrl(), "mcp")} or a legacy PTK runner exposing ${LEGACY_JOB_PATH}.`
            const wrapped = new Error(message)
            wrapped.cause = err
            throw wrapped
        }
        const body = await fetchBody(response)
        if (!response.ok) {
            const message = Array.isArray(body)
                ? body.map((entry) => entry?.error?.message || entry?.message || "").filter(Boolean)[0]
                : (body?.error?.message || body?.error || body?.message || `HTTP ${response.status}`)
            const err = new Error(`Playwright MCP request failed: ${message}`)
            err.status = response.status
            err.body = body
            throw err
        }
        return {
            status: response.status,
            headers: normalizeHeadersRecord(response.headers || {}),
            body
        }
    } finally {
        clearTimeout(timer)
    }
}

function normalizeCookieSameSite(value = "") {
    const normalized = String(value || "").trim().toLowerCase()
    if (normalized === "lax") return "Lax"
    if (normalized === "strict") return "Strict"
    return "None"
}

function normalizeJobState(jobId, payload = {}, existing = null) {
    const next = {
        jobId: String(jobId || "").trim(),
        status: String(payload?.status || existing?.status || "queued").trim().toLowerCase() || "queued",
        acceptedAt: payload?.acceptedAt || existing?.acceptedAt || null,
        startedAt: payload?.startedAt || existing?.startedAt || null,
        finishedAt: payload?.finishedAt || existing?.finishedAt || null,
        progress: payload?.progress || existing?.progress || null,
        summary: payload?.summary || existing?.summary || null,
        observations: Array.isArray(payload?.observations) ? payload.observations : (existing?.observations || []),
        artifacts: payload?.artifacts || existing?.artifacts || null,
        error: payload?.error || existing?.error || null,
        updatedAt: new Date().toISOString()
    }
    if (["completed", "failed", "canceled", "timed_out"].includes(next.status) && !next.finishedAt) {
        next.finishedAt = new Date().toISOString()
    }
    return next
}

function buildStandardPlaywrightRunCode(payload = {}) {
    const requestSeed = payload?.requestSeed && typeof payload.requestSeed === "object"
        ? payload.requestSeed
        : {}
    const authContext = payload?.playbook?.authContext && typeof payload.playbook.authContext === "object"
        ? payload.playbook.authContext
        : {}
    const mutations = Array.isArray(payload?.playbook?.mutations) ? payload.playbook.mutations : []
    const constraints = payload?.constraints && typeof payload.constraints === "object"
        ? payload.constraints
        : {}
    const input = {
        baseUrl: payload?.target?.baseUrl || null,
        requestSeed,
        authContext,
        mutations,
        constraints
    }
    return `
async (page) => {
  const input = ${JSON.stringify(input)};
  const maxBodyChars = 200000;
  const forbiddenHeaders = new Set([
    'accept-charset',
    'accept-encoding',
    'access-control-request-headers',
    'access-control-request-method',
    'connection',
    'content-length',
    'cookie',
    'date',
    'dnt',
    'expect',
    'host',
    'keep-alive',
    'origin',
    'permissions-policy',
    'proxy-',
    'sec-',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    'via'
  ]);
  const nowIso = () => new Date().toISOString();
  const normalizeHeaders = (headers) => {
    if (!headers || typeof headers !== 'object') return {};
    return Object.entries(headers).reduce((acc, [name, value]) => {
      const key = String(name || '').trim().toLowerCase();
      if (!key) return acc;
      acc[key] = String(value ?? '');
      return acc;
    }, {});
  };
  const cloneJson = (value) => JSON.parse(JSON.stringify(value ?? null));
  const bucketStatus = (status) => {
    const code = Number(status || 0);
    if (code >= 200 && code < 300) return '2xx';
    if (code >= 300 && code < 400) return '3xx';
    if (code >= 400 && code < 500) return '4xx';
    if (code >= 500 && code < 600) return '5xx';
    return 'other';
  };
  const routeKeyFromUrl = (url) => {
    try {
      return new URL(String(url || '')).pathname || '/';
    } catch (_) {
      return '/';
    }
  };
  const normalizeParamKey = (raw) => {
    const value = String(raw || '').trim();
    if (!value) return '';
    return value.replace(/^[a-z_]+:/i, '');
  };
  const safeBodyText = (text) => {
    const value = typeof text === 'string' ? text : String(text ?? '');
    return value.length > maxBodyChars ? value.slice(0, maxBodyChars) : value;
  };
  const normalizeCookie = (cookie) => {
    if (!cookie || typeof cookie !== 'object') return null;
    const name = String(cookie.name || '').trim();
    const domain = String(cookie.domain || '').trim();
    if (!name || !domain) return null;
    const normalized = {
      name,
      value: String(cookie.value || ''),
      domain,
      path: String(cookie.path || '/').trim() || '/',
      secure: cookie.secure === true,
      httpOnly: cookie.httpOnly === true,
      sameSite: ${JSON.stringify(normalizeCookieSameSite("none"))}
    };
    const sameSite = String(cookie.sameSite || '').trim().toLowerCase();
    if (sameSite === 'lax') normalized.sameSite = 'Lax';
    else if (sameSite === 'strict') normalized.sameSite = 'Strict';
    else normalized.sameSite = 'None';
    const expires = Number(cookie.expirationDate ?? cookie.expires);
    if (Number.isFinite(expires) && expires > 0) {
      normalized.expires = expires;
    }
    return normalized;
  };
  const observations = [];
  const addObservation = (code, detail, severity = 'info') => {
    const next = {
      code: String(code || 'INFO'),
      severity: String(severity || 'info'),
      detail: String(detail || '')
    };
    if (!next.detail) return;
    const fingerprint = next.code + '|' + next.detail;
    if (observations.some((entry) => entry.code + '|' + entry.detail === fingerprint)) return;
    observations.push(next);
  };
  const appendCookies = async (cookies) => {
    const normalized = (Array.isArray(cookies) ? cookies : [])
      .map(normalizeCookie)
      .filter(Boolean);
    if (!normalized.length) return;
    try {
      await page.context().addCookies(normalized);
    } catch (error) {
      addObservation('COOKIE_IMPORT_FAILED', error?.message || 'Failed to load cookie snapshot into Playwright context.', 'medium');
    }
  };
  const ensureOrigin = async (url) => {
    const target = String(url || input.baseUrl || '').trim();
    if (!target) return;
    try {
      const origin = new URL(target).origin;
      try {
        await page.goto(origin, { waitUntil: 'domcontentloaded' });
      } catch (_) {
        await page.goto(origin, { waitUntil: 'commit' });
      }
    } catch (_) {
      // ignore invalid URL
    }
  };
  const clearSession = async () => {
    try {
      await page.context().clearCookies();
    } catch (_) {}
    try {
      await page.evaluate(() => {
        try { window.localStorage.clear(); } catch (_) {}
        try { window.sessionStorage.clear(); } catch (_) {}
      });
    } catch (_) {}
  };
  const applyMutation = (request, mutation, value) => {
    const base = cloneJson(request);
    const location = String(mutation?.location || '').trim().toLowerCase();
    const key = normalizeParamKey(mutation?.paramKey);
    if (!location || !key) return null;
    if (location === 'header') {
      base.headers = normalizeHeaders(base.headers);
      base.headers[key.toLowerCase()] = String(value ?? '');
      return base;
    }
    if (location === 'param' || location === 'query') {
      try {
        const url = new URL(String(base.url || ''));
        url.searchParams.set(key, String(value ?? ''));
        base.url = url.toString();
        return base;
      } catch (_) {
        return null;
      }
    }
    const contentType = String(normalizeHeaders(base.headers)['content-type'] || '').toLowerCase();
    if (location === 'json' || location === 'body') {
      if (contentType.includes('application/json')) {
        try {
          const data = base.body ? JSON.parse(String(base.body)) : {};
          data[key] = String(value ?? '');
          base.body = JSON.stringify(data);
          return base;
        } catch (_) {
          addObservation('UNSUPPORTED_MUTATION', 'JSON mutation could not be applied to a non-JSON body.', 'low');
          return null;
        }
      }
      if (contentType.includes('application/x-www-form-urlencoded')) {
        try {
          const params = new URLSearchParams(String(base.body || ''));
          params.set(key, String(value ?? ''));
          base.body = params.toString();
          return base;
        } catch (_) {
          return null;
        }
      }
      addObservation('UNSUPPORTED_MUTATION', 'Body mutation is only supported for JSON and form-encoded requests when using standard Playwright MCP.', 'low');
      return null;
    }
    if (location === 'cookie') {
      addObservation('UNSUPPORTED_MUTATION', 'Cookie mutation is not yet supported through standard Playwright MCP replay.', 'low');
      return null;
    }
    addObservation('UNSUPPORTED_MUTATION', 'Mutation location ' + location + ' is not yet supported through standard Playwright MCP replay.', 'low');
    return null;
  };
  const executeRequest = async (request, meta = {}) => {
    const started = Date.now();
    const headers = normalizeHeaders(request?.headers);
    const droppedHeaders = [];
    const outgoingHeaders = {};
    Object.entries(headers).forEach(([name, value]) => {
      const blocked = Array.from(forbiddenHeaders).some((entry) => entry.endsWith('-')
        ? name.startsWith(entry)
        : name === entry);
      if (blocked) {
        droppedHeaders.push(name);
        return;
      }
      outgoingHeaders[name] = value;
    });
    if (droppedHeaders.length) {
      addObservation('FORBIDDEN_HEADER_SKIPPED', 'Standard Playwright MCP replay skipped browser-forbidden headers: ' + droppedHeaders.join(', '), 'low');
    }
    const fetchPayload = {
      url: String(request?.url || ''),
      method: String(request?.method || 'GET').toUpperCase(),
      headers: outgoingHeaders,
      body: request?.body === undefined || request?.body === null ? '' : String(request.body)
    };
    const requestContext = page.context?.().request;
    if (!requestContext || typeof requestContext.fetch !== 'function') {
      throw new Error('Playwright MCP browser context does not expose request.fetch().');
    }
    const requestInit = {
      method: fetchPayload.method,
      headers: fetchPayload.headers,
      failOnStatusCode: false,
      maxRedirects: 10
    };
    if (!['GET', 'HEAD'].includes(fetchPayload.method)) {
      requestInit.data = fetchPayload.body;
    }
    const res = await requestContext.fetch(fetchPayload.url, requestInit);
    const responseHeaders = typeof res.headersArray === 'function'
      ? res.headersArray().map(({ name, value }) => ({ name, value }))
      : Object.entries(typeof res.headers === 'function' ? (res.headers() || {}) : {}).map(([name, value]) => ({ name, value }));
    const response = {
      url: typeof res.url === 'function' ? res.url() : fetchPayload.url,
      redirected: false,
      status: typeof res.status === 'function' ? res.status() : null,
      statusCode: typeof res.status === 'function' ? res.status() : null,
      headers: responseHeaders,
      body: await res.text()
    };
    const durationMs = Math.max(0, Date.now() - started);
    return {
      executionId: String(meta.executionId || 'exec_' + Math.random().toString(36).slice(2, 10)),
      kind: String(meta.kind || 'baseline'),
      mutationId: meta.mutationId || null,
      mutationValue: meta.mutationValue === undefined ? null : String(meta.mutationValue),
      request: {
        method: fetchPayload.method,
        url: fetchPayload.url,
        headers: Object.entries(fetchPayload.headers).map(([name, value]) => ({ name, value })),
        body: fetchPayload.body
      },
      response: {
        url: response?.url || fetchPayload.url,
        redirected: response?.redirected === true,
        status: response?.status ?? null,
        statusCode: response?.statusCode ?? response?.status ?? null,
        headers: Array.isArray(response?.headers) ? response.headers : [],
        body: safeBodyText(response?.body || '')
      },
      durationMs
    };
  };

  const startedAt = nowIso();
  try {
    await appendCookies(input?.requestSeed?.cookies);
    await appendCookies(input?.authContext?.cookieSnapshot);
    await ensureOrigin(input?.requestSeed?.url || input?.baseUrl);
    if (String(input?.authContext?.mode || '').trim().toLowerCase() === 'anonymous') {
      await clearSession();
      await ensureOrigin(input?.requestSeed?.url || input?.baseUrl);
    }
    const executions = [];
    const baselineExecution = await executeRequest(input.requestSeed || {}, {
      executionId: 'exec_baseline',
      kind: 'baseline'
    });
    executions.push(baselineExecution);

    const mutationList = Array.isArray(input?.mutations) ? input.mutations : [];
    const maxMutations = Number(input?.constraints?.maxMutations || mutationList.length || 0);
    let mutationCounter = 0;
    for (const mutation of mutationList) {
      const values = Array.isArray(mutation?.values) ? mutation.values : [];
      for (const value of values) {
        if (maxMutations > 0 && mutationCounter >= maxMutations) break;
        const mutated = applyMutation(input.requestSeed || {}, mutation, value);
        mutationCounter += 1;
        if (!mutated) continue;
        const execution = await executeRequest(mutated, {
          executionId: 'exec_' + (mutation?.id || 'mutation') + '_' + mutationCounter,
          kind: 'mutation',
          mutationId: mutation?.id || null,
          mutationValue: value
        });
        executions.push(execution);
      }
      if (maxMutations > 0 && mutationCounter >= maxMutations) break;
    }

    const responses = executions.map((entry) => entry.response).filter(Boolean);
    const statusHistogram = responses.reduce((acc, response) => {
      const bucket = bucketStatus(response?.status || response?.statusCode || 0);
      acc[bucket] = Number(acc[bucket] || 0) + 1;
      return acc;
    }, {});
    const uniqueRoutes = new Set(executions.map((entry) => routeKeyFromUrl(entry?.request?.url))).size;
    const baselineStatus = baselineExecution?.response?.status ?? baselineExecution?.response?.statusCode ?? null;
    executions
      .filter((entry) => entry.kind === 'mutation' && (entry?.response?.status ?? entry?.response?.statusCode) !== baselineStatus)
      .slice(0, 3)
      .forEach((entry) => {
        addObservation(
          'STATUS_ANOMALY',
          entry.request.method + ' ' + routeKeyFromUrl(entry.request.url) + ' returned ' + String(entry.response.status) + ' for mutated value ' + String(entry.mutationValue ?? ''),
          'medium'
        );
      });

    return {
      startedAt,
      finishedAt: nowIso(),
      summary: {
        requestsExecuted: executions.length,
        uniqueRoutes,
        statusHistogram
      },
      observations,
      executions,
      artifacts: {
        response: baselineExecution?.response || null,
        lastResponse: executions.length ? executions[executions.length - 1].response : null,
        network: {
          entries: executions.map((execution) => ({
            request: execution.request,
            response: execution.response,
            durationMs: execution.durationMs,
            kind: execution.kind,
            mutationId: execution.mutationId,
            mutationValue: execution.mutationValue
          }))
        }
      }
    };
  } catch (error) {
    return {
      startedAt,
      finishedAt: nowIso(),
      error: {
        message: error?.message || String(error)
      }
    };
  }
}
`
}

function mapStandardToolPayloadToJob(jobId, payload = {}) {
    if (payload?.error?.message) {
        return normalizeJobState(jobId, {
            status: "failed",
            error: payload.error.message,
            startedAt: payload?.startedAt || null,
            finishedAt: payload?.finishedAt || null
        })
    }
    return normalizeJobState(jobId, {
        status: "completed",
        startedAt: payload?.startedAt || null,
        finishedAt: payload?.finishedAt || null,
        summary: payload?.summary || null,
        observations: Array.isArray(payload?.observations) ? payload.observations : [],
        artifacts: payload?.artifacts || null
    })
}

export class PlaywrightMcpClient {
    constructor({ settings = {}, fetchImpl = (...args) => fetch(...args) } = {}) {
        this.settings = settings
        this.fetchImpl = fetchImpl
        this.usesDefaultFetchImpl = arguments[0]?.fetchImpl === undefined
        this.runtimeMode = null
        this.standardEndpoint = null
        this.standardSession = null
        this.standardTools = null
        this.localJobs = new Map()
        this._standardInitPromise = null
        this._requestCounter = -1
    }

    getBaseUrl() {
        return resolveBaseUrl(this.settings)
    }

    _nextRequestId(_prefix = "req") {
        this._requestCounter += 1
        // The current Playwright MCP server is sensitive to the first request ids.
        // Matching the official client sequence (initialize=0, first tools/call=1) avoids
        // empty event-stream bodies on the first tools/call request.
        return this._requestCounter
    }

    _legacyJobBaseUrl() {
        const baseUrl = this.getBaseUrl()
        return baseUrl.endsWith(STANDARD_MCP_PATH)
            ? baseUrl.slice(0, -STANDARD_MCP_PATH.length) || DEFAULT_BASE_URL
            : baseUrl
    }

    _standardEndpointCandidates() {
        const baseUrl = this.getBaseUrl()
        const candidates = []
        const pushCandidate = (value) => {
            const normalized = trimTrailingSlash(value)
            if (!normalized || candidates.includes(normalized)) return
            candidates.push(normalized)
        }
        const baseCandidates = [baseUrl, ...buildLocalHostAliases(baseUrl)]
        baseCandidates.forEach((candidateBase) => {
            if (candidateBase.endsWith(STANDARD_MCP_PATH)) {
                pushCandidate(candidateBase)
            } else {
                pushCandidate(buildUrl(candidateBase, STANDARD_MCP_PATH))
                pushCandidate(candidateBase)
            }
        })
        return candidates
    }

    _strictStandardMcpEndpointCandidates() {
        return this._standardEndpointCandidates().filter((endpoint) => endpoint.endsWith(STANDARD_MCP_PATH))
    }

    _legacyJobBaseUrlCandidates() {
        const baseUrl = this._legacyJobBaseUrl()
        return [baseUrl, ...buildLocalHostAliases(baseUrl)]
    }

    _setLocalJob(jobId, payload = {}) {
        const key = String(jobId || "").trim()
        if (!key) return null
        const existing = this.localJobs.get(key) || null
        const next = normalizeJobState(key, payload, existing)
        this.localJobs.set(key, next)
        return cloneValue(next)
    }

    _getLocalJob(jobId) {
        const key = String(jobId || "").trim()
        if (!key) return null
        const job = this.localJobs.get(key)
        return job ? cloneValue(job) : null
    }

    async _postStandardJsonRpc(endpoint, body, {
        accept = "application/json, text/event-stream",
        timeoutMs = DEFAULT_TIMEOUT_MS,
        includeProtocolVersion = true,
        includeSessionId = true,
        requestId = body?.id ?? null,
        resolveEventStreamEarly = true,
        preferBufferedTextResponse = false
    } = {}) {
        const headers = {
            "Content-Type": "application/json",
            "Accept": accept
        }
        if (includeProtocolVersion && this.standardSession?.protocolVersion) {
            headers["MCP-Protocol-Version"] = this.standardSession.protocolVersion
        }
        if (includeSessionId && this.standardSession?.sessionId) {
            headers["MCP-Session-Id"] = this.standardSession.sessionId
        }
        return fetchJsonRpc(endpoint, {
            method: "POST",
            headers,
            body: JSON.stringify(body)
        }, {
            timeoutMs,
            requestId,
            resolveEventStreamEarly,
            preferBufferedTextResponse,
            fetchImpl: this.fetchImpl
        })
    }

    async _deleteStandardSession(endpoint) {
        const sessionId = String(this.standardSession?.sessionId || "").trim()
        if (!sessionId) return
        try {
            await fetchJson(endpoint, {
                method: "DELETE",
                headers: {
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": this.standardSession?.protocolVersion || DEFAULT_MCP_PROTOCOL_VERSION,
                    "MCP-Session-Id": sessionId
                }
            }, DEFAULT_TIMEOUT_MS, this.fetchImpl)
        } catch (_) {
            // ignore session teardown failures
        }
    }

    async _postStandardBufferedJsonRpc(endpoint, body, {
        protocolVersion = null,
        sessionId = null,
        timeoutMs = DEFAULT_TIMEOUT_MS,
        requestId = body?.id ?? null
    } = {}) {
        const headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"
        }
        if (protocolVersion) {
            headers["MCP-Protocol-Version"] = String(protocolVersion)
        }
        if (sessionId) {
            headers["MCP-Session-Id"] = String(sessionId)
        }
        return fetchJsonRpc(endpoint, {
            method: "POST",
            headers,
            body: JSON.stringify(body)
        }, {
            timeoutMs,
            requestId,
            resolveEventStreamEarly: false,
            preferBufferedTextResponse: true,
            fetchImpl: this.fetchImpl
        })
    }

    async _fetchRawWithTimeout(url, opts = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
        let timer = null
        try {
            return await Promise.race([
                this.fetchImpl(url, opts),
                new Promise((_, reject) => {
                    timer = setTimeout(() => {
                        reject(new Error(`Playwright MCP request timed out after ${timeoutMs}ms: ${url}`))
                    }, timeoutMs)
                })
            ])
        } catch (err) {
            if (err?.message?.includes("timed out after")) {
                throw err
            }
            const wrapped = new Error(`Playwright MCP is unreachable at ${url}. Start standard @playwright/mcp on ${buildUrl(resolveBaseUrl(), "mcp")} or a legacy PTK runner exposing ${LEGACY_JOB_PATH}.`)
            wrapped.cause = err
            throw wrapped
        } finally {
            if (timer) {
                clearTimeout(timer)
            }
        }
    }

    async _postStandardRawJsonRpc(endpoint, body, {
        protocolVersion = null,
        sessionId = null,
        timeoutMs = DEFAULT_TIMEOUT_MS
    } = {}) {
        const headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"
        }
        if (protocolVersion) {
            headers["MCP-Protocol-Version"] = String(protocolVersion)
        }
        if (sessionId) {
            headers["MCP-Session-Id"] = String(sessionId)
        }
        const response = await this._fetchRawWithTimeout(endpoint, {
            method: "POST",
            headers,
            body: JSON.stringify(body)
        }, timeoutMs)
        const normalizedHeaders = normalizeHeadersRecord(response?.headers || {})
        const text = await response.text()
        const parsedBody = String(normalizedHeaders["content-type"] || "").toLowerCase().includes("text/event-stream")
            ? parseSseMessages(text)
            : resolveJsonValue(text)
        if (!response.ok) {
            const message = Array.isArray(parsedBody)
                ? parsedBody.map((entry) => entry?.error?.message || entry?.message || "").filter(Boolean)[0]
                : (parsedBody?.error?.message || parsedBody?.error || parsedBody?.message || `HTTP ${response.status}`)
            const err = new Error(`Playwright MCP request failed: ${message}`)
            err.status = response.status
            err.body = parsedBody
            throw err
        }
        return {
            status: response.status,
            headers: normalizedHeaders,
            body: parsedBody,
            text
        }
    }

    async _openStandardRawEventStream(endpoint, session = {}, {
        onMessage = null,
        timeoutMs = DEFAULT_TIMEOUT_MS
    } = {}) {
        const response = await this._fetchRawWithTimeout(endpoint, {
            method: "GET",
            headers: {
                "Accept": "text/event-stream",
                "MCP-Protocol-Version": session?.protocolVersion || DEFAULT_MCP_PROTOCOL_VERSION,
                ...(session?.sessionId ? { "MCP-Session-Id": String(session.sessionId) } : {})
            }
        }, timeoutMs)
        const headers = normalizeHeadersRecord(response?.headers || {})
        if (!response?.ok) {
            throw new Error(`Playwright MCP event stream request failed with HTTP ${response?.status || "unknown"}.`)
        }
        if (!String(headers["content-type"] || "").toLowerCase().includes("text/event-stream")) {
            throw new Error("Playwright MCP event stream did not return text/event-stream.")
        }
        const stream = response?.body
        if (!stream || typeof stream.getReader !== "function") {
            throw new Error("Playwright MCP event stream did not expose a readable body.")
        }
        const reader = stream.getReader()
        const decoder = new TextDecoder()
        let closed = false
        const close = async () => {
            if (closed) return
            closed = true
            try {
                await reader.cancel()
            } catch (_) {
                // ignore reader cancellation errors
            }
            try {
                reader.releaseLock?.()
            } catch (_) {
                // ignore reader release errors
            }
        }
        const loopPromise = (async () => {
            let buffer = ""
            try {
                while (!closed) {
                    const { done, value } = await reader.read()
                    if (done) break
                    if (!value) continue
                    buffer += decoder.decode(value, { stream: true })
                    const drained = drainSseMessages(buffer)
                    buffer = drained.remainder
                    for (const message of drained.messages) {
                        if (typeof onMessage === "function") {
                            await onMessage(message)
                        }
                    }
                }
                buffer += decoder.decode()
                const drained = drainSseMessages(buffer)
                for (const message of drained.messages) {
                    if (typeof onMessage === "function") {
                        await onMessage(message)
                    }
                }
                const trailing = parseSseBlock(drained.remainder)
                if (trailing !== null && trailing !== undefined && typeof onMessage === "function") {
                    await onMessage(trailing)
                }
            } finally {
                closed = true
                try {
                    reader.releaseLock?.()
                } catch (_) {
                    // ignore reader release errors
                }
            }
        })()
        return {
            headers,
            close,
            loopPromise
        }
    }

    async _initializeRawStandardSession(endpoint) {
        const initRequestId = 0
        const initializeResponse = await this._postStandardRawJsonRpc(endpoint, {
            method: "initialize",
            params: {
                protocolVersion: DEFAULT_MCP_PROTOCOL_VERSION,
                capabilities: {},
                clientInfo: STANDARD_MCP_CLIENT_INFO
            },
            jsonrpc: "2.0",
            id: initRequestId
        })
        const initializeBody = this._resolveJsonRpcResponseBody(initializeResponse?.body, initRequestId)
        if (!initializeBody?.result) {
            throw new Error(`Playwright MCP at ${endpoint} did not return a valid initialize result.`)
        }
        const session = {
            sessionId: initializeResponse?.headers?.["mcp-session-id"] || null,
            protocolVersion: String(initializeBody.result?.protocolVersion || DEFAULT_MCP_PROTOCOL_VERSION),
            serverInfo: initializeBody.result?.serverInfo || null,
            capabilities: initializeBody.result?.capabilities || {}
        }
        await this._postStandardRawJsonRpc(endpoint, {
            method: "notifications/initialized",
            jsonrpc: "2.0"
        }, {
            protocolVersion: session.protocolVersion,
            sessionId: session.sessionId
        })
        return {
            endpoint,
            session
        }
    }

    async _callStandardRaw(method, params = {}, {
        endpoint,
        session,
        requestId = 1
    } = {}) {
        const hasParams = Array.isArray(params)
            ? params.length > 0
            : (params && typeof params === "object"
                ? Object.keys(params).length > 0
                : params !== undefined && params !== null)
        const response = await this._postStandardRawJsonRpc(endpoint, {
            method,
            ...(hasParams ? { params } : {}),
            jsonrpc: "2.0",
            id: requestId
        }, {
            protocolVersion: session?.protocolVersion || DEFAULT_MCP_PROTOCOL_VERSION,
            sessionId: session?.sessionId || null
        })
        const jsonrpcResponse = this._resolveJsonRpcResponseBody(response?.body, requestId)
        if (!jsonrpcResponse) {
            throw new Error(`Playwright MCP returned no JSON-RPC response for ${method}.`)
        }
        if (jsonrpcResponse?.error) {
            const message = jsonrpcResponse.error?.message || `JSON-RPC error on ${method}`
            const err = new Error(message)
            err.body = jsonrpcResponse
            throw err
        }
        return jsonrpcResponse?.result
    }

    async _runRawStandardBrowserRunCode(endpoint, payload = {}, {
        onToolCallStarted = null
    } = {}) {
        const initRequestId = 0
        const initializeResponse = await this._postStandardRawJsonRpc(endpoint, {
            method: "initialize",
            params: {
                protocolVersion: DEFAULT_MCP_PROTOCOL_VERSION,
                capabilities: {},
                clientInfo: STANDARD_MCP_CLIENT_INFO
            },
            jsonrpc: "2.0",
            id: initRequestId
        })
        const initializeBody = this._resolveJsonRpcResponseBody(initializeResponse?.body, initRequestId)
        if (!initializeBody?.result) {
            throw new Error(`Playwright MCP at ${endpoint} did not return a valid initialize result.`)
        }
        const session = {
            sessionId: initializeResponse?.headers?.["mcp-session-id"] || null,
            protocolVersion: String(initializeBody.result?.protocolVersion || DEFAULT_MCP_PROTOCOL_VERSION),
            serverInfo: initializeBody.result?.serverInfo || null,
            capabilities: initializeBody.result?.capabilities || {}
        }
        await this._postStandardRawJsonRpc(endpoint, {
            method: "notifications/initialized",
            jsonrpc: "2.0"
        }, {
            protocolVersion: session.protocolVersion,
            sessionId: session.sessionId
        })
        const toolRequestId = 1
        let resolveStreamToolBody = null
        let rejectStreamToolBody = null
        const streamToolBodyPromise = new Promise((resolve, reject) => {
            resolveStreamToolBody = resolve
            rejectStreamToolBody = reject
        })
        let rawEventStream = null
        try {
            rawEventStream = await this._openStandardRawEventStream(endpoint, session, {
                onMessage: async (message) => {
                    const entries = Array.isArray(message) ? message : [message]
                    for (const entry of entries) {
                        if (!entry || typeof entry !== "object") continue
                        if (entry.method === "ping" && entry.id !== undefined && entry.id !== null) {
                            await this._postStandardRawJsonRpc(endpoint, {
                                jsonrpc: "2.0",
                                id: entry.id,
                                result: {}
                            }, {
                                protocolVersion: session.protocolVersion,
                                sessionId: session.sessionId
                            })
                            continue
                        }
                        const match = findJsonRpcResponse(entry, toolRequestId)
                        if (match) {
                            resolveStreamToolBody(match)
                        }
                    }
                }
            })
            rawEventStream.loopPromise.catch((error) => {
                rejectStreamToolBody(error)
            })
        } catch (_) {
            rawEventStream = null
        }
        const toolResponsePromise = this._postStandardRawJsonRpc(endpoint, {
            method: "tools/call",
            params: {
                name: "browser_run_code",
                arguments: {
                    code: buildStandardPlaywrightRunCode(payload)
                }
            },
            jsonrpc: "2.0",
            id: toolRequestId
        }, {
            protocolVersion: session.protocolVersion,
            sessionId: session.sessionId
        })
        if (typeof onToolCallStarted === "function") {
            try {
                onToolCallStarted()
            } catch (_) {
                // ignore caller callback failures
            }
        }
        let toolBody = null
        try {
            const toolResponse = await toolResponsePromise
            toolBody = this._resolveJsonRpcResponseBody(toolResponse?.body, toolRequestId)
            if (!toolBody && rawEventStream) {
                toolBody = await Promise.race([
                    streamToolBodyPromise,
                    rawEventStream.loopPromise.then(() => null)
                ])
            }
        } finally {
            if (rawEventStream) {
                await rawEventStream.close()
                try {
                    await rawEventStream.loopPromise
                } catch (_) {
                    // ignore event stream shutdown errors after the tool call has finished
                }
            }
        }
        if (!toolBody) {
            throw new Error("Playwright MCP returned no JSON-RPC response for tools/call.")
        }
        if (toolBody?.error) {
            const message = toolBody.error?.message || "JSON-RPC error on tools/call"
            const err = new Error(message)
            err.body = toolBody
            throw err
        }
        return {
            endpoint,
            session,
            result: toolBody?.result
        }
    }

    async _initializeBufferedStandardSession(endpoint) {
        const initRequestId = 0
        const result = await this._postStandardBufferedJsonRpc(endpoint, {
            method: "initialize",
            params: {
                protocolVersion: DEFAULT_MCP_PROTOCOL_VERSION,
                capabilities: {},
                clientInfo: STANDARD_MCP_CLIENT_INFO
            },
            jsonrpc: "2.0",
            id: initRequestId
        }, {
            requestId: initRequestId
        })
        const response = this._resolveJsonRpcResponseBody(result?.body, initRequestId)
        if (!response?.result) {
            throw new Error(`Playwright MCP at ${endpoint} did not return a valid initialize result.`)
        }
        const session = {
            sessionId: result?.headers?.["mcp-session-id"] || null,
            protocolVersion: String(response.result?.protocolVersion || DEFAULT_MCP_PROTOCOL_VERSION),
            serverInfo: response.result?.serverInfo || null,
            capabilities: response.result?.capabilities || {}
        }
        await this._postStandardBufferedJsonRpc(endpoint, {
            method: "notifications/initialized",
            jsonrpc: "2.0"
        }, {
            protocolVersion: session.protocolVersion,
            sessionId: session.sessionId,
            requestId: null
        })
        return {
            endpoint,
            session
        }
    }

    async _callStandardBuffered(method, params = {}, {
        endpoint,
        session
    } = {}) {
        const hasParams = Array.isArray(params)
            ? params.length > 0
            : (params && typeof params === "object"
                ? Object.keys(params).length > 0
                : params !== undefined && params !== null)
        const id = 1
        const response = await this._postStandardBufferedJsonRpc(endpoint, {
            method,
            ...(hasParams ? { params } : {}),
            jsonrpc: "2.0",
            id
        }, {
            protocolVersion: session?.protocolVersion || DEFAULT_MCP_PROTOCOL_VERSION,
            sessionId: session?.sessionId || null,
            requestId: id
        })
        const jsonrpcResponse = this._resolveJsonRpcResponseBody(response?.body, id)
        if (!jsonrpcResponse) {
            throw new Error(`Playwright MCP returned no JSON-RPC response for ${method}.`)
        }
        if (jsonrpcResponse?.error) {
            const message = jsonrpcResponse.error?.message || `JSON-RPC error on ${method}`
            const err = new Error(message)
            err.body = jsonrpcResponse
            throw err
        }
        return jsonrpcResponse?.result
    }

    _resolveJsonRpcResponseBody(body, requestId) {
        if (Array.isArray(body)) {
            const response = body.find((entry) => entry && typeof entry === "object" && entry.id === requestId)
                || body.find((entry) => entry && typeof entry === "object" && (entry.result || entry.error))
                || null
            return response
        }
        if (body && typeof body === "object") return body
        return null
    }

    async _callStandard(method, params = {}, { notification = false } = {}) {
        const id = notification ? undefined : this._nextRequestId(method.replace(/[^\w]+/g, "_"))
        const hasParams = Array.isArray(params)
            ? params.length > 0
            : (params && typeof params === "object"
                ? Object.keys(params).length > 0
                : params !== undefined && params !== null)
        const payload = notification
            ? {
                method,
                ...(hasParams ? { params } : {}),
                jsonrpc: "2.0"
            }
            : {
                method,
                ...(hasParams ? { params } : {}),
                jsonrpc: "2.0",
                id
            }
        const useBufferedToolCallResponse = method === "tools/call" && this.usesDefaultFetchImpl
        const response = await this._postStandardJsonRpc(this.standardEndpoint, payload, {
            includeProtocolVersion: method !== "initialize",
            includeSessionId: method !== "initialize",
            resolveEventStreamEarly: method !== "tools/call" || !useBufferedToolCallResponse,
            preferBufferedTextResponse: useBufferedToolCallResponse
        })
        if (notification) {
            return null
        }
        const jsonrpcResponse = this._resolveJsonRpcResponseBody(response?.body, id)
        if (!jsonrpcResponse) {
            throw new Error(`Playwright MCP returned no JSON-RPC response for ${method}.`)
        }
        if (jsonrpcResponse?.error) {
            const message = jsonrpcResponse.error?.message || `JSON-RPC error on ${method}`
            const err = new Error(message)
            err.body = jsonrpcResponse
            throw err
        }
        return jsonrpcResponse?.result
    }

    async _probeStandardEndpoint(endpoint) {
        const result = await this._postStandardJsonRpc(endpoint, {
            method: "initialize",
            params: {
                protocolVersion: DEFAULT_MCP_PROTOCOL_VERSION,
                capabilities: {},
                clientInfo: STANDARD_MCP_CLIENT_INFO
            },
            jsonrpc: "2.0",
            id: this._nextRequestId("initialize")
        }, {
            includeProtocolVersion: false,
            includeSessionId: false,
            resolveEventStreamEarly: false
        })
        const response = this._resolveJsonRpcResponseBody(result?.body, null)
        if (!response?.result) {
            throw new Error(`Playwright MCP at ${endpoint} did not return a valid initialize result.`)
        }
        this.standardEndpoint = endpoint
        this.standardSession = {
            sessionId: result?.headers?.["mcp-session-id"] || null,
            protocolVersion: String(response.result?.protocolVersion || DEFAULT_MCP_PROTOCOL_VERSION),
            serverInfo: response.result?.serverInfo || null,
            capabilities: response.result?.capabilities || {}
        }
        await this._callStandard("notifications/initialized", {}, { notification: true })
        // Avoid a proactive tools/list probe here. The current local Playwright MCP server
        // can behave inconsistently across raw HTTP setup sequences, while direct browser_run_code
        // calls still work through the official client path. We treat browser_run_code as the
        // required capability and surface any method-level failure on the first real call.
        this.standardTools = ["browser_run_code"]
        return {
            endpoint,
            session: cloneValue(this.standardSession),
            tools: [...this.standardTools]
        }
    }

    async _ensureStandardSession() {
        if (this.standardEndpoint && this.standardSession && Array.isArray(this.standardTools) && this.standardTools.length) {
            return {
                endpoint: this.standardEndpoint,
                session: cloneValue(this.standardSession),
                tools: [...this.standardTools]
            }
        }
        if (this._standardInitPromise) {
            return this._standardInitPromise
        }
        this._standardInitPromise = (async () => {
            let lastError = null
            for (const endpoint of this._standardEndpointCandidates()) {
                try {
                    return await this._probeStandardEndpoint(endpoint)
                } catch (err) {
                    lastError = err
                    this.standardEndpoint = null
                    this.standardSession = null
                    this.standardTools = null
                }
            }
            throw lastError || new Error("Playwright MCP standard endpoint is unreachable.")
        })()
        try {
            const resolved = await this._standardInitPromise
            this.runtimeMode = "standard_mcp"
            return resolved
        } catch (err) {
            await this._deleteStandardSession(this.standardEndpoint || this._standardEndpointCandidates()[0])
            throw err
        } finally {
            this._standardInitPromise = null
        }
    }

    async _createLegacyJob(payload = {}) {
        let lastError = null
        for (const baseUrl of this._legacyJobBaseUrlCandidates()) {
            try {
                const response = await fetchJson(`${baseUrl}${LEGACY_JOB_PATH}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "X-PTK-Schema-Version": String(payload?.schemaVersion || "1.0.0")
                    },
                    body: JSON.stringify(payload || {})
                }, DEFAULT_TIMEOUT_MS, this.fetchImpl)
                this.runtimeMode = "legacy_job_api"
                return response.body
            } catch (err) {
                lastError = err
            }
        }
        throw lastError || new Error("Playwright MCP legacy runner is unreachable.")
    }

    async _getLegacyJob(jobId) {
        const id = String(jobId || "").trim()
        if (!id) {
            throw new Error("Playwright MCP jobId is required")
        }
        let lastError = null
        for (const baseUrl of this._legacyJobBaseUrlCandidates()) {
            try {
                const response = await fetchJson(`${baseUrl}${LEGACY_JOB_PATH}/${encodeURIComponent(id)}`, {
                    method: "GET",
                    headers: {
                        "Accept": "application/json",
                        "X-PTK-Schema-Version": "1.0.0"
                    }
                }, DEFAULT_TIMEOUT_MS, this.fetchImpl)
                return response.body
            } catch (err) {
                lastError = err
            }
        }
        throw lastError || new Error(`Playwright MCP job ${id} is unreachable via the legacy runner API.`)
    }

    async _runStandardJob(jobId, payload = {}, {
        onToolCallStarted = null
    } = {}) {
        this._setLocalJob(jobId, {
            status: "running",
            startedAt: new Date().toISOString(),
            progress: {
                stage: "initializing_mcp",
                current: 0,
                total: 1,
                message: "Initializing standard Playwright MCP session"
            }
        })
        try {
            let rawSession = null
            let rawCallResult = null
            this._setLocalJob(jobId, {
                status: "running",
                progress: {
                    stage: "executing_browser_run_code",
                    current: 1,
                    total: 1,
                    message: "Replaying candidate through standard Playwright MCP"
                }
            })
            if (this.usesDefaultFetchImpl) {
                let lastError = null
                for (const endpoint of this._strictStandardMcpEndpointCandidates()) {
                    try {
                        const rawRun = await this._runRawStandardBrowserRunCode(endpoint, payload, {
                            onToolCallStarted
                        })
                        rawSession = {
                            endpoint: rawRun.endpoint,
                            session: rawRun.session
                        }
                        rawCallResult = rawRun.result
                        this.standardEndpoint = rawRun.endpoint
                        this.standardSession = cloneValue(rawRun.session)
                        this.standardTools = ["browser_run_code"]
                        break
                    } catch (err) {
                        lastError = err
                    }
                }
                if (!rawSession) {
                    throw lastError || new Error("Playwright MCP standard endpoint is unreachable.")
                }
            } else {
                await this._ensureStandardSession()
                this._setLocalJob(jobId, {
                    status: "running",
                    progress: {
                        stage: "executing_browser_run_code",
                        current: 1,
                        total: 1,
                        message: "Replaying candidate through standard Playwright MCP"
                    }
                })
            }
            const callResult = rawSession
                ? rawCallResult
                : await this._callStandard("tools/call", {
                    name: "browser_run_code",
                    arguments: {
                        code: buildStandardPlaywrightRunCode(payload)
                    }
                })
            if (callResult?.isError) {
                const payloadValue = extractToolResultPayload(callResult)
                const message = payloadValue?.message
                    || (Array.isArray(callResult?.content)
                        ? callResult.content.map((entry) => String(entry?.text || "")).filter(Boolean).join(" | ")
                        : "")
                    || "browser_run_code returned an error."
                throw new Error(message)
            }
            const toolPayload = extractToolResultPayload(callResult)
            if (!toolPayload || typeof toolPayload !== "object") {
                throw new Error("Playwright MCP browser_run_code did not return a structured PTK result.")
            }
            return this._setLocalJob(jobId, mapStandardToolPayloadToJob(jobId, toolPayload))
        } catch (err) {
            return this._setLocalJob(jobId, {
                status: "failed",
                error: err?.message || "standard_playwright_mcp_run_failed"
            })
        }
    }

    async _createStandardJob(payload = {}) {
        if (!this.usesDefaultFetchImpl) {
            await this._ensureStandardSession()
        }
        const jobId = String(payload?.jobId || `mcpjob_local_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`)
        const accepted = this._setLocalJob(jobId, {
            status: "queued",
            acceptedAt: new Date().toISOString(),
            progress: {
                stage: "queued",
                current: 0,
                total: 1,
                message: "Queued local PTK wrapper job for standard Playwright MCP"
            }
        })
        let resolveToolCallStarted = null
        const toolCallStartedPromise = this.usesDefaultFetchImpl
            ? new Promise((resolve) => {
                resolveToolCallStarted = () => resolve()
            })
            : null
        Promise.resolve()
            .then(() => this._runStandardJob(jobId, {
                ...payload,
                jobId
            }, {
                onToolCallStarted: resolveToolCallStarted
            }))
            .catch((err) => {
                this._setLocalJob(jobId, {
                    status: "failed",
                    error: err?.message || "standard_playwright_mcp_run_failed"
                })
            })
        if (toolCallStartedPromise) {
            await Promise.race([
                toolCallStartedPromise,
                new Promise((resolve) => setTimeout(resolve, 1000))
            ])
        }
        return accepted
    }

    _composeCreateError(standardErr, legacyErr) {
        const standardMessage = standardErr?.message
            ? `Standard MCP: ${standardErr.message}`
            : ""
        const legacyMessage = legacyErr?.message
            ? `Legacy runner: ${legacyErr.message}`
            : ""
        const parts = [standardMessage, legacyMessage].filter(Boolean)
        const message = parts.length
            ? parts.join(" | ")
            : "Playwright MCP is unreachable."
        const error = new Error(message)
        error.standard = standardErr || null
        error.legacy = legacyErr || null
        return error
    }

    async createJob(payload = {}) {
        const localJobId = String(payload?.jobId || "").trim()
        if (this.usesDefaultFetchImpl) {
            this.runtimeMode = "standard_mcp"
            return this._createStandardJob(payload)
        }
        if (this.runtimeMode === "standard_mcp") {
            return this._createStandardJob(payload)
        }
        if (this.runtimeMode === "legacy_job_api") {
            return this._createLegacyJob(payload)
        }
        try {
            await this._ensureStandardSession()
            this.runtimeMode = "standard_mcp"
            return this._createStandardJob(payload)
        } catch (standardErr) {
            if (localJobId) {
                this.localJobs.delete(localJobId)
            }
            try {
                return await this._createLegacyJob(payload)
            } catch (legacyErr) {
                throw this._composeCreateError(standardErr, legacyErr)
            }
        }
    }

    async getJob(jobId) {
        const id = String(jobId || "").trim()
        if (!id) {
            throw new Error("Playwright MCP jobId is required")
        }
        const localJob = this._getLocalJob(id)
        if (localJob) return localJob
        if (this.runtimeMode === "standard_mcp") {
            throw new Error(`Playwright MCP job ${id} is not available in the local PTK standard-MCP run store.`)
        }
        return this._getLegacyJob(id)
    }
}

export default PlaywrightMcpClient
