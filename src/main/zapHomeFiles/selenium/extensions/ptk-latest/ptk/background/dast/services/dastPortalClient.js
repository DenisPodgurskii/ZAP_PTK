import { compressScanPayload } from "../../export/compressScanPayload.js"
import { parseDownloadedScanPayload } from "../../export/parseDownloadedScanPayload.js"
import {
    buildStoredCredentialPortalUrl,
    initializePortalRuntimeConfig
} from "../../../common/portalConfig.js"

export class DastPortalClient {
    constructor({
        lifecycleService = null,
        fetchImpl = (...args) => fetch(...args),
        compressPayload = compressScanPayload,
        parseDownloaded = parseDownloadedScanPayload
    } = {}) {
        this.lifecycleService = lifecycleService
        this.fetchImpl = fetchImpl
        this.compressPayload = compressPayload
        this.parseDownloaded = parseDownloaded
    }

    buildPortalUrl(endpoint, profile = {}) {
        return buildStoredCredentialPortalUrl(endpoint)
    }

    async saveScan(profile = {}, scanResult, { projectId = null } = {}) {
        await initializePortalRuntimeConfig()
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        if (!scanResult || typeof scanResult !== "object") {
            return { success: false, json: { message: "Scan result is empty" } }
        }
        const url = this.buildPortalUrl("/scans", profile)
        if (!url) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const payload = this.lifecycleService?.buildExportPayload?.(scanResult, { target: "portal" })
        if (!payload) {
            return { success: false, json: { message: "Scan result is empty" } }
        }
        if (projectId) payload.projectId = projectId
        let compressed
        try {
            compressed = await this.compressPayload(payload)
        } catch (err) {
            return {
                success: false,
                json: { message: "Unable to compress scan payload: " + (err?.message || "compression_failed") }
            }
        }
        return this.fetchImpl(url, {
            method: "POST",
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/json",
                "Content-Type": compressed.contentType,
                "X-PTK-Compression": compressed.compression
            },
            credentials: "omit",
            redirect: "error",
            cache: "no-cache",
            body: compressed.body
        })
            .then(async (response) => {
                if (response.status === 201) return { success: true }
                const json = await response.json().catch(() => ({ message: response.statusText || "Error while saving report" }))
                return { success: false, json }
            })
            .catch((e) => ({ success: false, json: { message: "Error while saving report: " + e.message } }))
    }

    async getProjects(profile = {}) {
        await initializePortalRuntimeConfig()
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        const url = this.buildPortalUrl("/projects", profile)
        if (!url) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        return this.fetchImpl(url, {
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/json"
            },
            credentials: "omit",
            redirect: "error",
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) return { success: true, json }
                return { success: false, json: json || { message: "Unable to load projects" } }
            })
            .catch((e) => ({ success: false, json: { message: "Error while loading projects: " + e.message } }))
    }

    async downloadScans(profile = {}, { projectId = null, engine = "dast" } = {}) {
        await initializePortalRuntimeConfig()
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        const baseUrl = this.buildPortalUrl("/scans", profile)
        if (!baseUrl) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        let requestUrl = baseUrl
        try {
            const url = new URL(baseUrl)
            if (projectId) url.searchParams.set("projectId", projectId)
            if (engine) url.searchParams.set("engine", engine)
            requestUrl = url.toString()
        } catch (_) {
            return { success: false, json: { message: "Invalid scans endpoint." } }
        }
        return this.fetchImpl(requestUrl, {
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/json"
            },
            credentials: "omit",
            redirect: "error",
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                const json = await httpResponse.json().catch(() => null)
                if (httpResponse.ok) return { success: true, json }
                return { success: false, json: json || { message: "Unable to load scans" } }
            })
            .catch((e) => ({ success: false, json: { message: "Error while loading scans: " + e.message } }))
    }

    async downloadScanById(profile = {}, scanId) {
        await initializePortalRuntimeConfig()
        const apiKey = profile?.api_key
        if (!apiKey) {
            return { success: false, json: { message: "No API key found" } }
        }
        if (!scanId) {
            return { success: false, json: { message: "Scan identifier is required." } }
        }
        const baseUrl = this.buildPortalUrl("/scans", profile)
        if (!baseUrl) {
            return { success: false, json: { message: "Portal endpoint is not configured." } }
        }
        const normalizedBase = baseUrl.replace(/\/+$/, "")
        const downloadUrl = `${normalizedBase}/${encodeURIComponent(scanId)}/download`
        return this.fetchImpl(downloadUrl, {
            headers: {
                Authorization: "Bearer " + apiKey,
                Accept: "application/gzip, application/x-gzip"
            },
            credentials: "omit",
            redirect: "error",
            cache: "no-cache"
        })
            .then(async (httpResponse) => {
                if (!httpResponse.ok) {
                    const json = await httpResponse.json().catch(() => null)
                    return { success: false, json: json || { message: "Unable to download scan" } }
                }
                const parsed = await this.parseDownloaded(httpResponse)
                if (!parsed?.ok || !parsed?.json) {
                    return { success: false, json: { message: "Downloaded scan payload is invalid JSON." } }
                }
                return {
                    success: true,
                    scanResult: this.lifecycleService?.hydrateImportedScan?.(parsed.json) || parsed.json
                }
            })
            .catch((e) => ({ success: false, json: { message: "Error while downloading scan: " + e.message } }))
    }

}

export default DastPortalClient
