/* Author: Denis Podgurskii */

import { compileFlow } from './macro/flow.js'
import { parseMacroDocument, serializeMacroDocument } from './macro/formatRegistry.js'

export class ptk_importer {
    constructor(settings = {}) {
        this.settings = settings
    }

    parseDocument(text, options = {}) {
        const format = options.format || this.settings.import_format || this.settings.export_format || this.settings.format || 'xml'
        return parseMacroDocument(text, {
            format,
            fileName: options.fileName || ''
        })
    }

    parse(text, options = {}) {
        const document = this.parseDocument(text, options)
        const compiled = compileFlow(document.flow, {
            secrets: options.secrets || document.secretValues || {},
            variables: options.variables || {},
            elementPath: this.settings.element_path || 'css'
        })
        return [compiled.startUrl, compiled.events]
    }

    parse_xml(text, options = {}) {
        return this.parse(text, { ...options, format: 'xml' })
    }

    parse_side(value, options = {}) {
        const text = typeof value === 'string' ? value : JSON.stringify(value)
        const document = this.parseDocument(text, { ...options, format: 'side' })
        return serializeMacroDocument(document.flow, 'xml', this.settings).text
    }

    parse_zest(value, options = {}) {
        const text = typeof value === 'string' ? value : JSON.stringify(value)
        return this.parse(text, { ...options, format: 'zest' })
    }

    parse_chrome_recorder(value, options = {}) {
        const text = typeof value === 'string' ? value : JSON.stringify(value)
        return this.parse(text, { ...options, format: 'chrome-recorder' })
    }
}
