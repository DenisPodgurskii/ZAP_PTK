/* Author: Denis Podgurskii */
export class ptk_controller_rattacker {


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

    async deleteScanById(scanId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "delete_scan_by_id",
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
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "loadfile",
            file: file
        }).then(response => {
            return response
        }).catch(e => e)
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

    async runCandidateInPlaywright({ candidateId = null, profile = "smoke", authMode = "reuse_storage_state", constraints = null } = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_rattacker",
            type: "run_candidate_in_playwright",
            candidateId,
            profile,
            authMode,
            constraints
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

}
