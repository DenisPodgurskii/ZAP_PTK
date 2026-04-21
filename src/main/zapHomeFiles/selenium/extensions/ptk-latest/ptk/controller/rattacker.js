/* Author: Denis Podgurskii */
export class ptk_controller_rattacker {
    constructor() {
        this.importChunkBytes = 512 * 1024
    }

    async _readFileBuffer(file) {
        if (!file) {
            throw new Error("Invalid file payload.")
        }
        if (typeof file.arrayBuffer === "function") {
            return file.arrayBuffer()
        }
        if (typeof FileReader === "function") {
            return new Promise((resolve, reject) => {
                const reader = new FileReader()
                reader.onerror = () => reject(reader.error || new Error("Invalid file payload."))
                reader.onload = () => resolve(reader.result instanceof ArrayBuffer ? reader.result : new ArrayBuffer(0))
                reader.readAsArrayBuffer(file)
            })
        }
        throw new Error("Invalid file payload.")
    }


    // async runScan(schema) {
    //     return browser.runtime.sendMessage({
    //         channel: "ptk_popup2background_rattacker",
    //         type: "run_scan",
    //         schema: schema
    //     }).then(response => {
    //         return response
    //     }).catch(e => e)
    // }

    async runBackgroundScan(tabId, host, domains, settings){
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "run_bg_scan",
            tabId: tabId,
            host: host,
            domains: domains,
            settings: settings
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async stopBackgroundScan(){
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "stop_bg_scan"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async checkApiKey(key){
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "check_apikey",
            key: key
        }).then(response => {
            return response
        }).catch(e => e)
    }
    

    async init() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "init"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async saveScan(projectId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "save_scan",
            projectId: projectId
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async getProjects() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_projects"
        }).then(response => response)
            .catch(e => e)
    }

    async downloadScans(projectId, engine = 'dast') {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "download_scans",
            projectId: projectId,
            engine: engine
        }).then(response => {
            return response
        }).catch(e => e)
    }


    async downloadScanById(scanId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "download_scan_by_id",
            scanId: scanId
        }).then(response => {
            return response
        }).catch(e => e)
    }
    

    async reset() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "reset"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async loadfile(file) {
        const buffer = await this._readFileBuffer(file)
        const size = Number(file.size || buffer.byteLength || 0)
        const chunkSize = this.importChunkBytes
        const chunkCount = Math.max(1, Math.ceil(size / chunkSize))
        let importId = null
        try {
            const started = await browser.runtime.sendMessage({
                channel: "ptk_popup2background_rattacker",
                type: "loadfile_init",
                fileMeta: {
                    name: String(file.name || ""),
                    type: String(file.type || ""),
                    size,
                    chunkCount,
                    chunkSize
                }
            })
            if (started instanceof Error || started?.success === false || !started?.importId) {
                throw new Error(started?.message || started?.error || "Invalid file payload.")
            }
            importId = started.importId
            for (let index = 0; index < chunkCount; index += 1) {
                const start = index * chunkSize
                const end = Math.min(buffer.byteLength, start + chunkSize)
                const chunk = Array.from(new Uint8Array(buffer.slice(start, end)))
                const chunkResult = await browser.runtime.sendMessage({
                    channel: "ptk_popup2background_rattacker",
                    type: "loadfile_chunk",
                    importId,
                    index,
                    chunk
                })
                if (chunkResult instanceof Error || chunkResult?.success === false) {
                    throw new Error(chunkResult?.message || chunkResult?.error || "Invalid file payload.")
                }
            }
            return await browser.runtime.sendMessage({
                channel: "ptk_popup2background_rattacker",
                type: "loadfile_finish",
                importId
            })
        } catch (e) {
            if (importId) {
                try {
                    await browser.runtime.sendMessage({
                        channel: "ptk_popup2background_rattacker",
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
            channel: "ptk_popup2background_rattacker",
            type: "save",
            json: json
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async exportScanResult(target = "download") {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "export_scan_result",
            target
        }).then(response => response)
            .catch(e => e)
    }

    async getExportScanChunk(exportId, index) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "export_scan_chunk",
            exportId,
            index
        }).then(response => response)
            .catch(e => e)
    }

    async releaseExportScan(exportId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "release_export_scan",
            exportId
        }).then(response => response)
            .catch(e => e)
    }

    async getRequestSnapshot(requestId, attackId = null) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_request_snapshot",
            requestId,
            attackId
        }).then(response => response)
            .catch(e => e)
    }

    async getFindingDetails({ findingId = null, requestId = null, attackId = null, moduleId = null } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_finding_details",
            findingId,
            requestId,
            attackId,
            moduleId
        }).then(response => response)
            .catch(e => e)
    }

    async getAnalysisSuppressions(host = null) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_analysis_suppressions",
            host
        }).then(response => response)
            .catch(e => e)
    }

    async toggleAnalysisSuppression({ host = null, suppressKey = null, suppressed = true } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "toggle_analysis_suppression",
            host,
            suppressKey,
            suppressed
        }).then(response => response)
            .catch(e => e)
    }

    async clearAnalysisSuppressions(host = null) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "clear_analysis_suppressions",
            host
        }).then(response => response)
            .catch(e => e)
    }

    async runCandidateInPlaywright({ candidateId = null, profile = "smoke", authMode = "reuse_storage_state", constraints = null, sessionProfileId = null } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "run_candidate_in_playwright",
            candidateId,
            profile,
            authMode,
            constraints,
            sessionProfileId
        }).then(response => response)
            .catch(e => e)
    }

    async getCandidatePlaywrightRun({ candidateId = null } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_candidate_playwright_run",
            candidateId
        }).then(response => response)
            .catch(e => e)
    }

    async getCandidatePlaywrightReadiness({ candidateId = null, skipNetwork = true } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_candidate_playwright_readiness",
            candidateId,
            skipNetwork
        }).then(response => response)
            .catch(e => e)
    }

    async compareCandidateAuthzDiff({
        candidateId = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        baselineResponse = null,
        comparisonResponse = null,
        objectSwap = null
    } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "compare_candidate_authz_diff",
            candidateId,
            baselineSessionProfileId,
            comparisonSessionProfileId,
            baselineResponse,
            comparisonResponse,
            objectSwap
        }).then(response => response)
            .catch(e => e)
    }

    async suggestCandidateObjectSwap({
        candidateId = null,
        objectSwap = null
    } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "suggest_candidate_object_swap",
            candidateId,
            objectSwap
        }).then(response => response)
            .catch(e => e)
    }

    async runCandidateAuthzDiff({
        candidateId = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        profile = "smoke",
        constraints = null,
        objectSwap = null
    } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "run_candidate_authz_diff",
            candidateId,
            baselineSessionProfileId,
            comparisonSessionProfileId,
            profile,
            constraints,
            objectSwap
        }).then(response => response)
            .catch(e => e)
    }

    async getCandidateAuthzDiffRun({ runId = null } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_candidate_authz_diff_run",
            runId
        }).then(response => response)
            .catch(e => e)
    }

    async createEvidencePackageFromAuthzDiff(payload = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "create_evidence_package_from_authz_diff",
            ...payload
        }).then(response => response)
            .catch(e => e)
    }

    async listEvidencePackages(payload = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "list_evidence_packages",
            ...payload
        }).then(response => response)
            .catch(e => e)
    }

    async getEvidencePackage(payload = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_evidence_package",
            ...payload
        }).then(response => response)
            .catch(e => e)
    }

    async exportEvidencePackage(payload = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "export_evidence_package",
            ...payload
        }).then(response => response)
            .catch(e => e)
    }

    async buildCandidateReportDraft(payload = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "build_candidate_report_draft",
            ...payload
        }).then(response => response)
            .catch(e => e)
    }

    async getWorkflowOverlaySummary(payload = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "get_workflow_overlay_summary",
            ...payload
        }).then(response => response)
            .catch(e => e)
    }

    async startWorkflowOverlayReplay(payload = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "start_workflow_overlay_replay",
            ...payload
        }).then(response => response)
            .catch(e => e)
    }

}
