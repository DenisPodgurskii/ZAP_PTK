/* Author: Denis Podgurskii */

function toUiText(value) {
    return value === null || value === undefined ? '' : String(value)
}

/**
 * Encode untrusted plain text before it is placed in an HTML-backed UI sink.
 */
export function escapeUiText(value) {
    return toUiText(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
}

/**
 * DataTables inserts display strings with innerHTML. Keep the original value
 * for sorting and searching, but encode the value used to create the cell.
 */
export function renderDataTableText(value, type) {
    const text = toUiText(value)
    return type === 'display' || type === undefined ? escapeUiText(text) : text
}

/**
 * Keep the trusted formatting wrapper while treating decoded JSON as text.
 */
export function renderPreformattedJson(value) {
    let json
    try {
        json = JSON.stringify(value, null, 2)
    } catch (e) {
        json = toUiText(value)
    }
    return `<pre>${escapeUiText(json)}</pre>`
}
