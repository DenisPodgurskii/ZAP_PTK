/* Author: Denis Podgurskii */
export class ptk_controller_sast {

    async runBackgroundScan(tabId, host, scanStrategy, pages = null){
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "run_bg_scan",
            tabId: tabId,
            host: host,
            scanStrategy: scanStrategy,
            pages: pages
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async stopBackgroundScan(){
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "stop_bg_scan"
        }).then(response => {
            return response
        }).catch(e => e)
    }


    async init() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "init"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async saveReport() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "save_report"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async saveScan(projectId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "save_scan",
            projectId: projectId
        }).then(response => response)
            .catch(e => e)
    }

    async getProjects() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "get_projects"
        }).then(response => response)
            .catch(e => e)
    }

    async downloadScans(projectId, engine = 'sast') {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "download_scans",
            projectId: projectId,
            engine: engine
        }).then(response => {
            return response
        }).catch(e => e)
    }


    async downloadScanById(scanId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "download_scan_by_id",
            scanId: scanId
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async deleteScanById(scanId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "delete_scan_by_id",
            scanId: scanId
        }).then(response => {
            return response
        }).catch(e => e)
    }
    

    async reset() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "reset"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async loadfile(file) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "loadfile",
            file: file
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async save(json) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "save",
            json: json
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async exportScanResult(target = "download") {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_sast",
            type: "export_scan_result",
            target
        }).then(response => response)
            .catch(e => e)
    }

}
