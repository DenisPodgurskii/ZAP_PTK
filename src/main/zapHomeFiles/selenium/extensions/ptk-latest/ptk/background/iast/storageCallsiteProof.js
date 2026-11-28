import { parse } from '../sast/acorn/acorn.mjs'

const MAX_BODY_CHARS = 1024 * 1024
const MAX_SCRIPT_CHARS = 256 * 1024
const SCRIPT_TAG = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi

function lineColumn(body, offset) {
    const before = body.slice(0, offset)
    const lastNewline = before.lastIndexOf('\n')
    return { line: before.split('\n').length, column: offset - lastNewline - 1 }
}

function sameHttpUrl(left, right) {
    try {
        const a = new URL(left), b = new URL(right)
        a.hash = ''; b.hash = ''
        return ['http:', 'https:'].includes(a.protocol) && a.href === b.href && !a.username && !a.password
    } catch (_) { return false }
}

function classicExternalReference(documentRecord, scriptUrl) {
    if (!documentRecord || documentRecord.complete !== true || documentRecord.base64Encoded
        || typeof documentRecord.body !== 'string' || documentRecord.body.length > MAX_BODY_CHARS
        || !['Document', 'main_frame', 'sub_frame'].includes(documentRecord.resourceType)
        || /<!--|<(?:template|textarea|noscript)\b/i.test(documentRecord.body)) return false
    const attribute = (attrs, name) => attrs.match(new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'))
    let matches = 0
    for (const tag of documentRecord.body.matchAll(/<script\b([^>]*)>/gi)) {
        const attrs = tag[1] || ''
        const src = attribute(attrs, 'src')
        if (!src) continue
        let resolved
        try { resolved = new URL(src[1] ?? src[2] ?? src[3], documentRecord.url).href }
        catch (_) { return false }
        if (!sameHttpUrl(resolved, scriptUrl)) continue
        if (/(?:^|\s)nomodule(?:\s|=|$)/i.test(attrs)) return false
        const type = attribute(attrs, 'type')
        if (type && !/^(?:text|application)\/(?:java|ecma)script(?:;.*)?$/i.test((type[1] ?? type[2] ?? type[3]).trim())) return false
        matches++
    }
    return matches === 1
}

function scriptCandidates(record, site, documentRecord) {
    if (!record || record.complete !== true || record.base64Encoded || typeof record.body !== 'string'
        || !record.body || record.body.length > MAX_BODY_CHARS) return []
    if (['Script', 'script'].includes(record.resourceType)) {
        return sameHttpUrl(record.url, site.scriptUrl)
            && classicExternalReference(documentRecord, site.scriptUrl)
            ? [{ code: record.body, start: { line: 1, column: 0 } }] : []
    }
    if (!['Document', 'main_frame', 'sub_frame'].includes(record.resourceType)
        || !sameHttpUrl(record.url, site.scriptUrl)
        || /<!--|<(?:template|textarea|noscript)\b/i.test(record.body)) return []
    const result = []
    for (const match of record.body.matchAll(SCRIPT_TAG)) {
        const attrs = match[1] || ''
        if (/\bsrc\s*=|\bnomodule\b/i.test(attrs)) continue
        const type = attrs.match(/\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i)
        if (type && !/^(?:text|application)\/(?:java|ecma)script(?:;.*)?$/i.test((type[1] ?? type[2] ?? type[3]).trim())) continue
        const codeStart = match.index + match[0].indexOf('>') + 1
        result.push({ code: match[2], start: lineColumn(record.body, codeStart) })
    }
    return result
}

function absoluteLocation(start, local) {
    return { line: start.line + local.line - 1,
        column: local.line === 1 ? start.column + local.column : local.column }
}

function bracketRead(node, kind, key) {
    return node?.type === 'MemberExpression' && node.computed === true && node.optional !== true
        && node.object?.type === 'Identifier' && node.object.name === kind
        && node.property?.type === 'Literal' && node.property.value === key
}

function candidateProof(code, start, observation) {
    if (!code || code.length > MAX_SCRIPT_CHARS) return null
    let program
    try { program = parse(code, { ecmaVersion: 'latest', sourceType: 'script', locations: true }) }
    catch (_) { return null }
    const source = observation.sourceBinding
    const key = `${source.kind}:`
    if (!['localStorage', 'sessionStorage'].includes(source.kind)
        || !source.key.startsWith(key) || source.key.length <= key.length) return null
    const storageKey = source.key.slice(key.length)
    const site = observation.site
    const matches = []
    for (let index = 0; index < program.body.length; index++) {
        const statement = program.body[index]
        if (statement.type !== 'ExpressionStatement'
            || statement.expression?.type !== 'CallExpression'
            || statement.expression.callee?.type !== 'Identifier'
            || statement.expression.callee.name !== 'eval'
            || statement.expression.arguments?.length !== 1
            || statement.expression.arguments[0]?.type !== 'Identifier') continue
        const sink = absoluteLocation(start, statement.expression.loc.start)
        if (site.line !== sink.line || site.column !== sink.column + 1) continue
        const variable = statement.expression.arguments[0].name
        const reads = []
        for (let before = 0; before < index; before++) {
            const declaration = program.body[before]
            if (declaration.type !== 'VariableDeclaration' || declaration.declarations.length !== 1) continue
            const item = declaration.declarations[0]
            if (item.id?.type === 'Identifier' && item.id.name === variable
                && bracketRead(item.init, source.kind, storageKey)) {
                reads.push(absoluteLocation(start, item.init.loc.start))
            }
        }
        if (reads.length === 1) matches.push({ read: reads[0], sink })
    }
    return matches.length === 1 ? matches[0] : null
}

/** Proves only that an unconditional classic-script bracket read ran before the observed sync eval. */
export async function proveStorageBracketRead({ record, observation, documentRecord } = {}) {
    if (observation?.kind !== 'source_relationship'
        || observation.acquisition !== 'sink_storage_snapshot'
        || observation.site?.kind !== 'code'
        || observation.site.operation !== 'code.eval'
        || observation.attackerControl !== 'unknown'
        || !globalThis.crypto?.subtle) return null
    const scripts = scriptCandidates(record, observation.site, documentRecord)
    const matches = scripts.map(script => candidateProof(script.code, script.start, observation)).filter(Boolean)
    if (matches.length !== 1) return null
    const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(record.body))
    const bodySha256 = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
    return { kind: 'straight_line_classic', bodySha256,
        readLine: matches[0].read.line, readColumn: matches[0].read.column + 1,
        sinkLine: matches[0].sink.line, sinkColumn: matches[0].sink.column + 1 }
}
