/* Author: Denis Podgurskii */
export class ptk_controller_dast {
    constructor(channel = "ptk_popup2background_dast") {
        this.channel = channel
        this.importChunkBytes = 512 * 1024
    }

    async _send(type, payload = {}) {
        return browser.runtime.sendMessage({
            channel: this.channel,
            type,
            ...payload
        }).then(response => response)
            .catch(e => e)
    }

    async runBackgroundScan(tabId, host, domains, settings) {
        return this._send("run_bg_scan", { tabId, host, domains, settings })
    }

    async stopBackgroundScan(options = {}) {
        return this._send("stop_bg_scan", options)
    }

    async checkApiKey(key) {
        return this._send("check_apikey", { key })
    }

    async init() {
        return this._send("init")
    }

    async getDefaultModules() {
        return this._send("get_default_modules")
    }

    async saveScan(projectId) {
        return this._send("save_scan", { projectId })
    }

    async getProjects() {
        return this._send("get_projects")
    }

    async downloadScans(projectId, engine = "dast") {
        return this._send("download_scans", { projectId, engine })
    }

    async downloadScanById(scanId) {
        return this._send("download_scan_by_id", { scanId })
    }

    async reset() {
        return this._send("reset")
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
            const started = await this._send("loadfile_init", {
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
                const chunkResult = await this._send("loadfile_chunk", {
                    importId,
                    index,
                    chunk
                })
                if (chunkResult instanceof Error || chunkResult?.success === false) {
                    throw new Error(chunkResult?.message || chunkResult?.error || "Invalid file payload.")
                }
                emitProgress({ phase: "upload_chunk", completed: index + 1, total: chunkCount })
            }
            emitProgress({ phase: "finalize_start", completed: chunkCount, total: chunkCount })
            const result = await this._send("loadfile_finish", { importId })
            emitProgress({ phase: "done", completed: chunkCount, total: chunkCount })
            return result
        } catch (err) {
            if (importId) {
                try {
                    await this._send("release_import", { importId })
                } catch (_) { }
            }
            throw err
        }
    }

    async save(json) {
        return this._send("save", { json })
    }

    async exportScanResult(target = "download") {
        return this._send("export_scan_result", { target })
    }

    async getExportScanChunk(exportId, index) {
        return this._send("export_scan_chunk", { exportId, index })
    }

    async releaseExportScan(exportId) {
        return this._send("release_export_scan", { exportId })
    }

    async getRequestSnapshot(requestId, attackId = null, scanId = null) {
        return this._send("get_request_snapshot", { requestId, attackId, scanId })
    }

    async getFindingDetails({ findingId = null, requestId = null, attackId = null, moduleId = null } = {}) {
        return this._send("get_finding_details", { findingId, requestId, attackId, moduleId })
    }

    async getRelatedFindingSummaries() {
        return this._send("get_related_finding_summaries")
    }

    async recomputeAnalysis() {
        return this._send("recompute_analysis")
    }

    async getAnalysisSuppressions(host = null) {
        return this._send("get_analysis_suppressions", { host })
    }

    async toggleAnalysisSuppression({ host = null, suppressKey = null, suppressed = true } = {}) {
        return this._send("toggle_analysis_suppression", { host, suppressKey, suppressed })
    }

    async clearAnalysisSuppressions(host = null) {
        return this._send("clear_analysis_suppressions", { host })
    }

    async listSessionProfiles(host = null) {
        return this._send("list_session_profiles", { host })
    }

    async createSessionProfile({ label = "", host = null, notes = "" } = {}) {
        return this._send("create_session_profile", { label, host, notes })
    }

    async deleteSessionProfile(id, host = null) {
        return this._send("delete_session_profile", { id, host })
    }

    async runCandidateInPlaywright({ candidateId = null, profile = "smoke", authMode = "reuse_storage_state", constraints = null, sessionProfileId = null } = {}) {
        return this._send("run_candidate_in_playwright", { candidateId, profile, authMode, constraints, sessionProfileId })
    }

    async getCandidatePlaywrightRun({ candidateId = null } = {}) {
        return this._send("get_candidate_playwright_run", { candidateId })
    }

    async compareCandidateAuthzDiff({
        candidateId = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        baselineResponse = null,
        comparisonResponse = null,
        objectSwap = null
    } = {}) {
        return this._send("compare_candidate_authz_diff", {
            candidateId,
            baselineSessionProfileId,
            comparisonSessionProfileId,
            baselineResponse,
            comparisonResponse,
            objectSwap
        })
    }

    async suggestCandidateObjectSwap({
        candidateId = null,
        objectSwap = null
    } = {}) {
        return this._send("suggest_candidate_object_swap", {
            candidateId,
            objectSwap
        })
    }

    async runCandidateAuthzDiff({
        candidateId = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        profile = "smoke",
        constraints = null,
        objectSwap = null
    } = {}) {
        return this._send("run_candidate_authz_diff", {
            candidateId,
            baselineSessionProfileId,
            comparisonSessionProfileId,
            profile,
            constraints,
            objectSwap
        })
    }

    async getCandidateAuthzDiffRun({ runId = null } = {}) {
        return this._send("get_candidate_authz_diff_run", { runId })
    }

    async createEvidencePackageFromAuthzDiff(payload = {}) {
        return this._send("create_evidence_package_from_authz_diff", payload)
    }

    async listEvidencePackages(payload = {}) {
        return this._send("list_evidence_packages", payload)
    }

    async getEvidencePackage(payload = {}) {
        return this._send("get_evidence_package", payload)
    }

    async exportEvidencePackage(payload = {}) {
        return this._send("export_evidence_package", payload)
    }

    async buildCandidateReportDraft(payload = {}) {
        return this._send("build_candidate_report_draft", payload)
    }

    async getWorkflowOverlaySummary(payload = {}) {
        return this._send("get_workflow_overlay_summary", payload)
    }

    async startWorkflowOverlayReplay(payload = {}) {
        return this._send("start_workflow_overlay_replay", payload)
    }

    async getCandidatePlaywrightReadiness({ candidateId = null, skipNetwork = true } = {}) {
        return this._send("get_candidate_playwright_readiness", { candidateId, skipNetwork })
    }

    async getPolicyState() {
        return this._send("get_policy_state")
    }

    async loadPolicyMetadata() {
        return this._send("load_policy_metadata")
    }

    async selectPolicy(policyId, policyName = null) {
        return this._send("select_policy", { policyId, policyName })
    }

    async clearPolicy() {
        return this._send("clear_policy")
    }
}

export default ptk_controller_dast
