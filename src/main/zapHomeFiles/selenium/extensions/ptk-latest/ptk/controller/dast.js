/* Author: Denis Podgurskii */
export class ptk_controller_dast {
    constructor(channel = "ptk_popup2background_dast") {
        this.channel = channel
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

    async stopBackgroundScan() {
        return this._send("stop_bg_scan")
    }

    async checkApiKey(key) {
        return this._send("check_apikey", { key })
    }

    async init() {
        return this._send("init")
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

    async deleteScanById(scanId) {
        return this._send("delete_scan_by_id", { scanId })
    }

    async reset() {
        return this._send("reset")
    }

    async loadfile(file) {
        return this._send("loadfile", { file })
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

    async getRequestSnapshot(requestId, attackId = null) {
        return this._send("get_request_snapshot", { requestId, attackId })
    }

    async getFindingDetails({ findingId = null, requestId = null, attackId = null, moduleId = null } = {}) {
        return this._send("get_finding_details", { findingId, requestId, attackId, moduleId })
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

    async runCandidateInPlaywright({ candidateId = null, profile = "smoke", authMode = "reuse_storage_state", constraints = null } = {}) {
        return this._send("run_candidate_in_playwright", { candidateId, profile, authMode, constraints })
    }

    async getCandidatePlaywrightRun({ candidateId = null } = {}) {
        return this._send("get_candidate_playwright_run", { candidateId })
    }

    async getCandidatePlaywrightReadiness({ candidateId = null, skipNetwork = true } = {}) {
        return this._send("get_candidate_playwright_readiness", { candidateId, skipNetwork })
    }
}

export default ptk_controller_dast
