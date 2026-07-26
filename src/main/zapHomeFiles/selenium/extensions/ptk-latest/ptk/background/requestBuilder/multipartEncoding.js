const MULTIPART_PARAMETER_ESCAPE_REGEX = /[\r\n"]/g
const MULTIPART_TOKEN_REGEX = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/

const MULTIPART_PARAMETER_ESCAPES = Object.freeze({
    '\r': '%0D',
    '\n': '%0A',
    '"': '%22'
})

export function encodeMultipartHeaderParameter(value) {
    return String(value ?? '').replace(
        MULTIPART_PARAMETER_ESCAPE_REGEX,
        (character) => MULTIPART_PARAMETER_ESCAPES[character]
    )
}

export function normalizeMultipartDispositionType(value) {
    const type = String(value || 'form-data').trim()
    return MULTIPART_TOKEN_REGEX.test(type) ? type : 'form-data'
}

export function normalizeMultipartContentType(value) {
    const contentType = String(value || '').trim()
    if (!contentType || /[\r\n]/.test(contentType)) return ''
    return contentType
}

export function normalizeMultipartBoundary(value) {
    const boundary = String(value || '')
    if (!boundary || /[\r\n]/.test(boundary)) return ''
    return boundary
}
