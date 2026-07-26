/* Author: Denis Podgurskii */

export class ptk_controller_index {

    init(options = {}) {
        let self = this
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "init",
            ...options
        })
            .then(function (result) {
                const previous = Object.assign({}, self)
                Object.assign(self, result)
                if (options?.tabId) {
                    self.tabId = options.tabId
                    if (options.url) self.url = options.url
                    if (result?.activeTab) {
                        result.activeTab = Object.assign({}, result.activeTab, {
                            tabId: options.tabId,
                            url: options.url || result.activeTab.url
                        })
                    }
                }
                if (result?.lite) {
                    if (!result.tab && previous.tab) self.tab = previous.tab
                    if (!result.storage && previous.storage) self.storage = previous.storage
                    if (!result.cookies && previous.cookies) self.cookies = previous.cookies
                }
                return self
            }).catch(e => e)
    }

    async complete(wappalyzer) {
        let self = this
        browser.runtime.sendMessage({ channel: "ptk_popup2background_dashboard", type: "analyze", info: wappalyzer }).catch(e => e)
        return Promise.resolve()
    }

    async get() {
        let self = this
        return browser.runtime.sendMessage({ channel: "ptk_popup2background_dashboard", type: "get" })
            .then(function (result) {
                Object.assign(self, result)
                return self
            }).catch(e => e)
    }

    async getScans(options = {}) {
        let self = this
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "get_scans",
            ...options
        }).then(function (result) {
            if (result && typeof result === "object") {
                if (result.activeTab) self.activeTab = result.activeTab
                if (result.scans) self.scans = result.scans
                if (result.policyState) self.policyState = result.policyState
                if (options?.tabId) {
                    self.tabId = options.tabId
                    if (options?.url) self.url = options.url
                }
            }
            return result
        }).catch(e => e)
    }

    async save(items) {
        return browser.runtime.sendMessage({ channel: "ptk_popup2background_dashboard", type: "save", items: items }).catch(e => e)
    }

    async getFullDashboard() {
        let self = this
        return browser.runtime.sendMessage({ channel: "ptk_popup2background_dashboard", type: "get_full_dashboard" })
            .then(function (result) {
                Object.assign(self, result)
                return self
            }).catch(e => e)
    }

    async runBackgroundScan(tabId, host, domains, scans, settings) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "run_bg_scan",
            tabId: tabId,
            host: host,
            domains: domains,
            scans: scans,
            settings: settings
        }).then(response => {
            return response
        }).catch(e => e)
    }

    async stopBackgroundScan(scans) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "stop_bg_scan",
            scans: scans
        }).then(response => {
            return response
        }).catch(e => e)
    }

    // Request fresh tab analysis when cached data is missing
    async requestTabAnalysis(tabId, url) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "request_tab_analysis",
            tabId,
            url
        }).catch(e => e)
    }

    async getPolicyState() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "get_policy_state"
        }).catch(e => e)
    }

    async loadPolicyMetadata(engine = null) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "load_policy_metadata",
            engine
        }).catch(e => e)
    }

    async selectPolicy(engine, policyId, policyName = null) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "select_policy",
            engine,
            policyId,
            policyName
        }).catch(e => e)
    }

    async clearPolicy(engine) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "clear_policy",
            engine
        }).catch(e => e)
    }

    async getProjects() {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "get_projects"
        }).catch(e => e)
    }

    async createReportSnapshot(snapshot) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "create_report_snapshot",
            snapshot
        }).catch(e => e)
    }

    async consumeReportSnapshot(snapshotId) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_dashboard",
            type: "consume_report_snapshot",
            snapshotId
        }).catch(e => e)
    }

}
