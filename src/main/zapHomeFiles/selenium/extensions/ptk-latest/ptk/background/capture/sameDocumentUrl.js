// A fragment navigation does not replace the document. Preserve the entire
// origin/path/query string; only the fragment may differ across browser APIs.
export function documentUrlWithoutFragment(value) {
    return typeof value === 'string' && value ? value.split('#', 1)[0] : null
}

export function sameDocumentUrl(left, right) {
    const first = documentUrlWithoutFragment(left)
    return first !== null && first === documentUrlWithoutFragment(right)
}
