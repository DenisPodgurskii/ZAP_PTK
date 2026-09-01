/* Author: Denis Podgurskii */

import { ptk_exporter } from "../background/exporter.js"
import { ptk_importer } from "../background/importer.js"
import { compileFlow, flowFromRecording, normalizeFlow } from '../background/macro/flow.js'
import {
    listMacroFormats,
    macroDownloadName,
    parseMacroDocument,
    serializeMacroDocument
} from '../background/macro/formatRegistry.js'

export class ptk_controller_macro {
    constructor() {
        this.settings = {}
        this.recording = null
        this.flow = null
        this.secrets = Object.create(null)
        this.pendingImport = null
        this.savedMacro = ''
        this.flowOrigin = 'empty'
    }

    getSettings() {
        let self = this
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_settings",
            type: "get_settings",
            path: "macro"
        }).then(function (response) {
            Object.assign(self.settings, response)
            return self.settings
        })
    }

    updateSettings() {
        let self = this
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_settings",
            type: "update_settings",
            path: "macro",
            value: this.settings
        }).then(function (response) {
            return response.settings
        })
    }


    init() {
        let self = this
        return browser.runtime.sendMessage({ channel: "ptk_popup2background_recorder", type: "init" })
            .then(response => {
                Object.assign(self, response)
                return response
            })
    }

    save(macro = '') {
        const compatibilityXml = this.flow
            ? serializeMacroDocument(this.flow, 'xml', this.exportOptions()).text
            : macro
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_recorder",
            type: "save_macro",
            macro: compatibilityXml,
            flow: this.flow,
            format: this.settings.export_format || this.settings.format || 'xml'
        })
            .then(response => {
                return response
            })
    }

    reset() {
        return browser.runtime.sendMessage({ channel: "ptk_popup2background_recorder", type: "reset_recording" })
            .then(response => {
                return response
            })
    }

    start(clean_cookie, url, bootstrap = null) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_recorder",
            type: "start_recording",
            clean_cookie: clean_cookie,
            url: url,
            bootstrap
        }).then(response => {
            return response
        })
    }

    stop(params = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_recorder",
            type: "stop_recording",
            ...params
        }).then(response => {
            return response
        })
    }

    stopReplay(params = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_recorder",
            type: "stop_replay",
            ...params
        }).then(response => {
            return response
        })
    }

    export() {
        if (!this.flow && this.recording) this.setRecording(this.recording)
        if (!this.flow) return null
        return serializeMacroDocument(this.flow, this.settings.export_format || this.settings.format || 'xml', this.exportOptions())
    }

    import(macro, options = {}) {
        const document = parseMacroDocument(macro, {
            format: options.format || this.settings.export_format || this.settings.format || 'xml',
            fileName: options.fileName || ''
        })
        const compiled = compileFlow(document.flow, {
            secrets: { ...document.secretValues, ...this.secrets, ...(options.secrets || {}) },
            elementPath: 'source'
        })
        return [compiled.startUrl, compiled.events]
    }

    replay(clean_cookie, url, events, validate_regex, options = {}) {
        return browser.runtime.sendMessage({
            channel: "ptk_popup2background_recorder",
            type: "replay",
            clean_cookie: clean_cookie,
            url: url,
            events: events,
            validate_regex: validate_regex,
            target_tab_id: options.targetTabId,
            scope_origin: options.scopeOrigin,
            suppress_confirmation: options.suppressConfirmation === true,
            scan_owned: options.scanOwned === true,
            source: options.source || ''
        }).then(response => {
            return response
        })
    }

    side2macro(macro) {
        let importer = new ptk_importer({ format: 'side' })
        return importer.parse_side(macro)
    }

    formats() {
        return listMacroFormats()
    }

    usesImportedLocators() {
        if (!this.flow) return false
        if (this.flowOrigin === 'imported') return true
        if (this.flowOrigin === 'recording') return false
        return String(this.flow.metadata?.sourceFormat || '') !== 'recording'
    }

    exportOptions() {
        const elementPath = this.usesImportedLocators() ? 'source' : this.settings.element_path || 'css'
        return { ...this.settings, element_path: elementPath, elementPath }
    }

    normalizedImportedFlow(flow, format = '') {
        const normalized = normalizeFlow(flow)
        const sourceFormat = String(normalized.metadata?.sourceFormat || '')
        if (sourceFormat && sourceFormat !== 'recording') return normalized
        return normalizeFlow({
            ...normalized,
            metadata: {
                ...normalized.metadata,
                sourceFormat: String(format || 'ptk-flow')
            }
        })
    }

    setRecording(recording) {
        this.recording = recording
        const result = flowFromRecording(recording, this.settings)
        this.flow = result.flow
        this.flowOrigin = 'recording'
        this.secrets = { ...this.secrets, ...result.secretValues }
        return result
    }

    restore(result = {}) {
        this.recording = result.recording || null
        this.savedMacro = typeof result.savedMacro === 'string' ? result.savedMacro : ''
        if (result.savedFlow) {
            try {
                this.flow = normalizeFlow(result.savedFlow)
                this.flowOrigin = this.flow.metadata?.sourceFormat === 'recording' ? 'recording' : 'imported'
                return { source: 'flow', flow: this.flow, diagnostics: [] }
            } catch (_) {
                this.flow = null
            }
        }
        if (this.savedMacro) {
            const imported = parseMacroDocument(this.savedMacro, { format: 'xml', fileName: 'stored.rec' })
            this.flow = imported.flow
            this.flowOrigin = 'imported'
            this.secrets = { ...this.secrets, ...imported.secretValues }
            return { source: 'xml', ...imported }
        }
        if (this.recording?.items) {
            const recorded = this.setRecording(this.recording)
            return { source: 'recording', ...recorded }
        }
        return { source: 'empty', flow: null, diagnostics: [] }
    }

    prepareImport(text, options = {}) {
        const result = parseMacroDocument(text, options)
        this.pendingImport = result
        return result
    }

    acceptImport(secretValues = {}) {
        if (!this.pendingImport) throw new Error('No macro import is pending')
        if (!this.pendingImport.acceptable) throw new Error('The imported macro contains blocking conversion errors')
        this.flow = this.normalizedImportedFlow(this.pendingImport.flow, this.pendingImport.format)
        this.flowOrigin = 'imported'
        this.secrets = { ...this.pendingImport.secretValues, ...secretValues }
        const accepted = this.pendingImport
        this.pendingImport = null
        return accepted
    }

    cancelImport() {
        this.pendingImport = null
    }

    updateFromText(text, format) {
        const result = parseMacroDocument(text, { format })
        if (!result.acceptable) throw new Error('The macro contains blocking conversion errors')
        this.flow = this.normalizedImportedFlow(result.flow, result.format || format)
        this.flowOrigin = 'imported'
        this.secrets = { ...this.secrets, ...result.secretValues }
        return result
    }

    compile(options = {}) {
        if (!this.flow) return { startUrl: '', events: [] }
        return compileFlow(this.flow, {
            secrets: { ...this.secrets, ...(options.secrets || {}) },
            variables: options.variables || {},
            elementPath: this.usesImportedLocators() ? 'source' : this.settings.element_path || 'css'
        })
    }

    downloadName(format) {
        return macroDownloadName(this.flow, format || this.settings.export_format || this.settings.format || 'xml')
    }

}
