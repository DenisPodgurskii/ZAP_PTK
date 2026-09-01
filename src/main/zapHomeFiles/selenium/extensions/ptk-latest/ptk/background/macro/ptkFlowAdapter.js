/* Author: Denis Podgurskii */

import { PTK_FLOW_SCHEMA, diagnosticsResult, normalizeFlow, safeParseMacroJson, serializeFlowJson } from './flow.js'

export const ptkFlowAdapter = Object.freeze({
    id: 'ptk-flow',
    label: 'PTK Flow JSON',
    extensions: ['.ptk-flow.json', '.json'],
    mimeType: 'application/json',
    editorMode: { name: 'javascript', json: true },
    canImport: true,
    canExport: true,
    detect(input, fileName = '') {
        let confidence = String(fileName).toLowerCase().endsWith('.ptk-flow.json') ? 0.8 : 0
        if (typeof input === 'string' && input.includes(`"schema"`) && input.includes(PTK_FLOW_SCHEMA)) confidence = 1
        return { confidence, format: 'ptk-flow', version: '1' }
    },
    parse(input) {
        return { ...diagnosticsResult(normalizeFlow(safeParseMacroJson(input))), secretValues: Object.create(null) }
    },
    serialize(flow) {
        return { text: serializeFlowJson(flow), diagnostics: [] }
    }
})

