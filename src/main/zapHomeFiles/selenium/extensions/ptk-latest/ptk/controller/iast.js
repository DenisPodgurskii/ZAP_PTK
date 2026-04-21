/* Author: Denis Podgurskii */
export class ptk_controller_iast {
    constructor() {
        this.importChunkBytes = 512 * 1024
    }

    async _readFileBuffer(file) {
        if (!file) {
            throw new Error("Invalid file payload")
        }
        if (typeof file.arrayBuffer === "function") {
            return file.arrayBuffer()
        }
        if (typeof FileReader === "function") {
            return new Promise((resolve, reject) => {
                const reader = new FileReader()
                reader.onerror = () => reject(reader.error || new Error("Invalid file payload"))
                reader.onload = () => resolve(reader.result instanceof ArrayBuffer ? reader.result : new ArrayBuffer(0))
                reader.readAsArrayBuffer(file)
            })
        }
        throw new Error("Invalid file payload")
    }

    async runBackgroundScan(tabId, host, scanStrategy, opts = null){
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "run_bg_scan",
            tabId: tabId,
            host: host,
            scanStrategy: scanStrategy,
            opts: opts || undefined
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async stopBackgroundScan(){
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "stop_bg_scan"
        }).then(response => {
            return response
        }).catch(e => e)
    }


    async init() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "init"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async getDefaultModules() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "get_default_modules"
        }).then(response => response)
            .catch(e => e)
    }

    async saveReport() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "save_report"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async saveScan(projectId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "save_scan",
            projectId: projectId
        }).then(response => response)
            .catch(e => e)
    }

    async getProjects() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "get_projects"
        }).then(response => response)
            .catch(e => e)
    }

    async downloadScans(projectId, engine = 'iast') {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "download_scans",
            projectId: projectId,
            engine: engine
        }).then(response => {
            return response
        }).catch(e => e)
    }


    async downloadScanById(scanId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "download_scan_by_id",
            scanId: scanId
        }).then(response => {
            return response
        }).catch(e => e)
    }
    

    async reset() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "reset"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async loadfile(file, options = {}) {
        const onProgress = typeof options?.onProgress === "function" ? options.onProgress : null
        const emitProgress = (event = {}) => {
            if (onProgress) onProgress(event)
        }
        emitProgress({ phase: "read_start", completed: 0, total: 1 })
        const buffer = await this._readFileBuffer(file)
        emitProgress({ phase: "read_complete", completed: 1, total: 1 })
        const size = Number(file.size || buffer.byteLength || 0)
        const chunkSize = this.importChunkBytes
        const chunkCount = Math.max(1, Math.ceil(size / chunkSize))
        let importId = null
        try {
            emitProgress({ phase: "upload_start", completed: 0, total: chunkCount })
            const started = await browser.runtime.sendMessage({
                channel: "ptk_popup2background_iast",
                type: "loadfile_init",
                fileMeta: {
                    name: String(file.name || ""),
                    type: String(file.type || ""),
                    size,
                    chunkCount,
                    chunkSize
                }
            }).then(response => response).catch(e => e)
            if (started instanceof Error || started?.success === false || !started?.importId) {
                throw new Error(started?.message || started?.error || "Invalid file payload.")
            }
            importId = started.importId
            for (let index = 0; index < chunkCount; index += 1) {
                const start = index * chunkSize
                const end = Math.min(buffer.byteLength, start + chunkSize)
                const chunk = Array.from(new Uint8Array(buffer.slice(start, end)))
                const chunkResult = await browser.runtime.sendMessage({
                    channel: "ptk_popup2background_iast",
                    type: "loadfile_chunk",
                    importId,
                    index,
                    chunk
                }).then(response => response).catch(e => e)
                if (chunkResult instanceof Error || chunkResult?.success === false) {
                    throw new Error(chunkResult?.message || chunkResult?.error || "Invalid file payload.")
                }
                emitProgress({ phase: "upload_chunk", completed: index + 1, total: chunkCount })
            }
            emitProgress({ phase: "finalize_start", completed: chunkCount, total: chunkCount })
            const result = await browser.runtime.sendMessage({
                channel: "ptk_popup2background_iast",
                type: "loadfile_finish",
                importId
            }).then(response => response).catch(e => e)
            emitProgress({ phase: "done", completed: chunkCount, total: chunkCount })
            return result
        } catch (e) {
            if (importId) {
                try {
                    await browser.runtime.sendMessage({
                        channel: "ptk_popup2background_iast",
                        type: "release_import",
                        importId
                    })
                } catch (_) { }
            }
            throw e
        }
    }

    async save(json) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "save",
            json: json
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async exportScanResult(target = "download") {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "export_scan_result",
            target
        }).then(response => response)
            .catch(e => e)
    }

    async getExportScanChunk(exportId, index) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "export_scan_chunk",
            exportId,
            index
        }).then(response => response)
            .catch(e => e)
    }

    async releaseExportScan(exportId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "release_export_scan",
            exportId
        }).then(response => response)
            .catch(e => e)
    }

    async getPolicyState() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "get_policy_state"
        }).then(response => response)
            .catch(e => e)
    }

    async loadPolicyMetadata() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "load_policy_metadata"
        }).then(response => response)
            .catch(e => e)
    }

    async selectPolicy(policyId, policyName = null) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "select_policy",
            policyId,
            policyName
        }).then(response => response)
            .catch(e => e)
    }

    async clearPolicy() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "clear_policy"
        }).then(response => response)
            .catch(e => e)
    }

}
