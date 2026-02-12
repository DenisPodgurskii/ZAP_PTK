/* Author: Denis Podgurskii */
'use strict'


import "./ptk/packages/browser-polyfill/browser-polyfill.min.js"

import { ptk_settings } from "./ptk/background/settings.js"
import { ptk_proxy } from "./ptk/background/proxy.js"
import { ptk_dashboard } from "./ptk/background/dashboard.js"
import { ptk_rattacker } from "./ptk/background/rattacker.js"
import { ptk_request_manager } from "./ptk/background/rbuilder.js"
import { ptk_decoder_manager } from "./ptk/background/decoder.js"
import { ptk_sca } from "./ptk/background/sca.js"
import { ptk_session } from "./ptk/background/session.js"
import { ptk_recorder } from "./ptk/background/recorder.js"
import { ptk_ruleManager } from "./ptk/background/utils.js"

import { ptk_portscanner } from "./ptk/background/portscanner.js"
import { ptk_jwt } from "./ptk/background/jwt.js"

import { ptk_iast } from "./ptk/background/iast.js"
import { ptk_sast } from "./ptk/background/sast.js"
import { ptk_automation } from "./ptk/background/automation.js"


const worker = self
worker.isFirefox = browser.runtime.getBrowserInfo ? true : false
 

export class ptk_app {
    constructor(settings) {

        this.settings = new ptk_settings(settings)

        browser.storage.local.get('pentestkit8_settings').then(function (result) {
            if (result.pentestkit8_settings) {
                this.settings.mergeSettings(result.pentestkit8_settings)
                if (this.updated) this.settings.release_note.show = true
            } else {
                this.settings.resetSettings()
            }

            // Mark settings as ready so getSettings() can return
            this.settings.markReady()

            this.proxy = new ptk_proxy(this.settings.proxy)

            this.request_manager = new ptk_request_manager(this.settings.rbuilder)
            ptk_ruleManager.resetSession()

            this.rattacker = new ptk_rattacker(this.settings.rattacker)

            this.decoder_manager = new ptk_decoder_manager()

            this.sca = new ptk_sca()

            this.session = new ptk_session()

            this.dashboard = new ptk_dashboard()

            this.portscanner = new ptk_portscanner()

            this.jwt = new ptk_jwt()

            this.iast = new ptk_iast()

            this.sast = new ptk_sast()

            this.automation = new ptk_automation()
            this.automation.init(this)

            this.recorder = new ptk_recorder(settings.recorder)
            this.recorder.addMessageListeners()

            this.addMessageListeners()

        }.bind(this))
    }


    addMessageListeners() {
        browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
            if (message.channel == "ptk_popup2background_app") {
                if (message.type == "on_updated_settings") {
                    if (this.proxy) {
                        this.proxy.maxTabsCount = this.settings.proxy.max_tabs
                        this.proxy.maxRequestsPerTab = this.settings.proxy.max_requests_per_tab
                    }
                    if (this.rattacker) {
                        this.rattacker.loadProModules()
                    }
                }

                if (message.type == "reloadptk") {
                    browser.runtime.reload()
                }

                if (message.type == "history") {
                    this.settings.updateSettings("history", { route: message.route, hash: message.hash })
                }

                if (message.type == "release_note") {
                    sendResponse && sendResponse({ show: this.settings.release_note.show })
                    return true
                }
                if (message.type == "release_note_read") {
                    this.settings.updateSettings("release_note", { show: false })
                    sendResponse && sendResponse({ ok: true })
                    return true
                }

                if (message.type == "ping") {
                    sendResponse && sendResponse("pong")
                    return true
                }
            }
        }.bind(this))
    }
}



browser.runtime.onInstalled.addListener(async (details) => {
    if (details.reason == 'update') {
        worker.ptk_app.updated = true
    }
})




// Start PTK app
fetch(browser.runtime.getURL('ptk/settings.json'))
    .then(response => response.json())
    .then(settings => {
        worker.ptk_app = new ptk_app(settings)
        
    })
    .catch(err => {
        
    })
