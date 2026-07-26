const MARKDOWN_ESCAPE_REGEX = /[\\&<>`*_{}\[\]()#+.!|\-]/g

const HTML_ENTITY_BY_CHARACTER = Object.freeze({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;'
})

export function stripHtmlTags(value, DOMParserCtor = globalThis.DOMParser) {
    if (!value) return ''
    const text = String(value)
    if (typeof DOMParserCtor !== 'function') return text

    try {
        const doc = new DOMParserCtor().parseFromString(text, 'text/html')
        return doc?.body?.textContent || ''
    } catch (_) {
        // The report encoders treat this as text, so retaining the source is safe.
        return text
    }
}

export function escapeMarkdownText(value) {
    if (value === null || value === undefined) return ''
    return String(value).replace(MARKDOWN_ESCAPE_REGEX, (character) => {
        return HTML_ENTITY_BY_CHARACTER[character] || `\\${character}`
    })
}

export function escapeMarkdownCell(value) {
    if (value === null || value === undefined) return ''
    const normalized = String(value).replace(/[\r\n]+/g, ' ')
    return escapeMarkdownText(normalized)
}
