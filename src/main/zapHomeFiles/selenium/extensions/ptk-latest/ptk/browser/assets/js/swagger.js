/* Author: Denis Podgurskii */

const ext = globalThis.browser ?? globalThis.chrome
const STORAGE_KEY = "swagger.lastUrl"
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
const DEFAULT_STATUS = "Load an OpenAPI spec from URL or a local file."

let swaggerInstance = null

function setStatus(message, kind = "info") {
    const statusNode = document.getElementById("swagger_status")
    if (!statusNode) return

    statusNode.textContent = message
    statusNode.classList.remove("is-info", "is-success", "is-error", "is-loading")
    statusNode.classList.add(`is-${kind}`)
}

function validateUrl(urlValue) {
    const trimmed = (urlValue || "").trim()
    if (!trimmed) {
        throw new Error("Please enter a spec URL.")
    }

    let parsed
    try {
        parsed = new URL(trimmed)
    } catch (_) {
        throw new Error("Invalid URL format.")
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Only http:// and https:// URLs are allowed.")
    }

    return parsed.toString()
}

async function fetchSpecText(url) {
    let response
    try {
        response = await fetch(url, { credentials: "omit" })
    } catch (error) {
        throw new Error(`Failed to fetch spec (network/CORS issue). ${error?.message || ""}`.trim())
    }

    if (!response.ok) {
        throw new Error(`Failed to fetch spec: HTTP ${response.status} ${response.statusText}`.trim())
    }

    const text = await response.text()
    if (!text || !text.trim()) {
        throw new Error("Fetched spec is empty.")
    }

    return {
        text,
        contentType: response.headers.get("content-type") || ""
    }
}

function getYamlParser() {
    const parser = globalThis.jsyaml
    if (!parser || typeof parser.load !== "function") {
        throw new Error("YAML parser is unavailable.")
    }
    return parser
}

function parseJson(text) {
    try {
        return JSON.parse(text)
    } catch (error) {
        throw new Error(`Invalid JSON: ${error.message}`)
    }
}

function parseYaml(text) {
    try {
        return getYamlParser().load(text)
    } catch (error) {
        throw new Error(`Invalid YAML: ${error.message}`)
    }
}

function parseSpec(text, sourceName = "", contentType = "") {
    const trimmed = (text || "").trim()
    if (!trimmed) {
        throw new Error("Spec content is empty.")
    }

    const source = sourceName.toLowerCase()
    const ct = contentType.toLowerCase()
    const looksLikeJson = trimmed.startsWith("{") || trimmed.startsWith("[")
    const preferJson = source.endsWith(".json") || ct.includes("json") || looksLikeJson

    let parsed
    let jsonError = null
    let yamlError = null

    if (preferJson) {
        try {
            parsed = parseJson(trimmed)
        } catch (error) {
            jsonError = error
        }
        if (parsed === undefined) {
            try {
                parsed = parseYaml(trimmed)
            } catch (error) {
                yamlError = error
            }
        }
    } else {
        try {
            parsed = parseYaml(trimmed)
        } catch (error) {
            yamlError = error
        }
        if (parsed === undefined) {
            try {
                parsed = parseJson(trimmed)
            } catch (error) {
                jsonError = error
            }
        }
    }

    if (parsed === undefined) {
        const parseHints = [jsonError?.message, yamlError?.message].filter(Boolean).join(" | ")
        throw new Error(parseHints || "Unable to parse spec as JSON or YAML.")
    }

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Spec root must be a JSON/YAML object.")
    }

    if (!parsed.openapi && !parsed.swagger) {
        throw new Error("Spec must include `openapi` or `swagger` at the root.")
    }

    return parsed
}

function clearSwaggerUi() {
    const container = document.getElementById("swagger-ui")
    if (container) {
        container.replaceChildren()
    }
    swaggerInstance = null
}

function renderSwagger(specObj) {
    clearSwaggerUi()

    if (typeof globalThis.SwaggerUIBundle !== "function") {
        throw new Error("Swagger UI library is not available.")
    }

    const presets = [globalThis.SwaggerUIBundle.presets.apis]
    if (globalThis.SwaggerUIStandalonePreset) {
        presets.push(globalThis.SwaggerUIStandalonePreset)
    }

    swaggerInstance = globalThis.SwaggerUIBundle({
        dom_id: "#swagger-ui",
        spec: specObj,
        deepLinking: true,
        presets,
        layout: globalThis.SwaggerUIStandalonePreset ? "StandaloneLayout" : "BaseLayout",
        docExpansion: "list",
        defaultModelsExpandDepth: -1,
        displayRequestDuration: true,
        tryItOutEnabled: true,
        validatorUrl: null
    })
}

function specSummary(specObj) {
    const title = specObj?.info?.title || "Untitled API"
    const version = specObj?.info?.version || specObj?.openapi || specObj?.swagger || "unknown"
    return { title, version }
}

function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "")
        reader.onerror = () => reject(new Error("Failed to read file."))
        reader.readAsText(file)
    })
}

async function saveLastUrl(url) {
    if (!ext?.storage?.local) return
    try {
        await ext.storage.local.set({ [STORAGE_KEY]: url })
    } catch (_) {
        // Storage is best effort for this page.
    }
}

async function restoreLastUrl() {
    if (!ext?.storage?.local) return ""
    try {
        const data = await ext.storage.local.get(STORAGE_KEY)
        return (data && data[STORAGE_KEY]) || ""
    } catch (_) {
        return ""
    }
}

async function clearLastUrl() {
    if (!ext?.storage?.local) return
    try {
        await ext.storage.local.remove(STORAGE_KEY)
    } catch (_) {
        // Storage is best effort for this page.
    }
}

async function loadSpecFromUrl(urlValue) {
    const url = validateUrl(urlValue)
    setStatus("Loading spec from URL...", "loading")

    const { text, contentType } = await fetchSpecText(url)
    const specObj = parseSpec(text, url, contentType)
    renderSwagger(specObj)
    await saveLastUrl(url)

    const summary = specSummary(specObj)
    setStatus(`Loaded ${summary.title} (v${summary.version}) from URL.`, "success")
}

async function loadSpecFromFile(file) {
    if (!file) {
        throw new Error("Please select a file first.")
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
        throw new Error("File is too large. Please use a file under 10MB.")
    }

    setStatus("Loading spec from file...", "loading")
    const text = await readFileAsText(file)
    const specObj = parseSpec(text, file.name, file.type || "")
    renderSwagger(specObj)

    const summary = specSummary(specObj)
    setStatus(`Loaded ${summary.title} (v${summary.version}) from file ${file.name}.`, "success")
}

async function resetViewer() {
    const urlInput = document.getElementById("swagger_url")
    const fileInput = document.getElementById("swagger_file")
    if (urlInput) {
        urlInput.value = ""
    }
    if (fileInput) {
        fileInput.value = ""
    }
    clearSwaggerUi()
    await clearLastUrl()
    setStatus(DEFAULT_STATUS, "info")
}

jQuery(async function () {
    const urlInput = document.getElementById("swagger_url")
    const fileInput = document.getElementById("swagger_file")
    const loadUrlBtn = document.getElementById("swagger_load_url")
    const loadFileBtn = document.getElementById("swagger_load_file")
    const resetBtn = document.getElementById("swagger_reset")

    const lastUrl = await restoreLastUrl()
    if (urlInput && lastUrl) {
        urlInput.value = lastUrl
    }
    setStatus(DEFAULT_STATUS, "info")

    if (loadUrlBtn) {
        loadUrlBtn.addEventListener("click", async () => {
            try {
                await loadSpecFromUrl(urlInput?.value || "")
            } catch (error) {
                setStatus(error?.message || "Failed to load spec from URL.", "error")
            }
        })
    }

    if (loadFileBtn) {
        loadFileBtn.addEventListener("click", async () => {
            try {
                await loadSpecFromFile(fileInput?.files?.[0])
            } catch (error) {
                setStatus(error?.message || "Failed to load spec from file.", "error")
            }
        })
    }

    if (resetBtn) {
        resetBtn.addEventListener("click", async () => {
            try {
                await resetViewer()
            } catch (error) {
                setStatus(error?.message || "Failed to reset Swagger viewer.", "error")
            }
        })
    }

    if (urlInput) {
        urlInput.addEventListener("keydown", async event => {
            if (event.key !== "Enter") return
            event.preventDefault()
            try {
                await loadSpecFromUrl(urlInput.value)
            } catch (error) {
                setStatus(error?.message || "Failed to load spec from URL.", "error")
            }
        })
    }

    document.addEventListener("submit", event => {
        event.preventDefault()
        return false
    })
})

