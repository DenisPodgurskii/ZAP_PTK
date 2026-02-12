/* Author: Denis Podgurskii */
export class ptk_controller_iast {

    async runBackgroundScan(tabId, host, scanStrategy){
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "run_bg_scan",
            tabId: tabId,
            host: host,
            scanStrategy: scanStrategy
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

    async saveReport() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "save_report"
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async downloadScans() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "download_scans"
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

    async deleteScanById(scanId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "delete_scan_by_id",
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

    async loadfile(file) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_iast",
            type: "loadfile",
            file: file
        }).then(response => {
            return response
        }).catch(e => e)
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

}
