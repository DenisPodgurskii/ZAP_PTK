/* Author: PTK */

/**
 * Return URLSearchParams for a URL string, considering both:
 *  - normal query string: http://host/path?foo=bar
 *  - SPA hash routes:     http://host/#/search?foo=bar&baz=qux
 *
 * For SPA hashes, treat everything after the first '?' in the hash as a query part.
 */
export function getSearchParamsFromUrlOrHash(urlString) {
    try {
        let u
        try {
            u = new URL(urlString)
        } catch (_) {
            u = new URL(urlString, 'http://localhost')
        }

        // 1) Normal query string
        if (u.search && u.search.length > 1) {
            return u.searchParams
        }

        // 2) SPA-style routes in hash: #/search?foo=bar&baz=qux
        if (u.hash && u.hash.includes('?')) {
            const hash = u.hash.substring(1) // remove leading '#'
            const qIdx = hash.indexOf('?')
            if (qIdx !== -1 && qIdx < hash.length - 1) {
                const queryPart = hash.substring(qIdx + 1)
                return new URLSearchParams(queryPart)
            }
        }
    } catch (e) {
        // Fall through to return an empty params instance
    }

    // 3) Nothing useful
    return new URLSearchParams()
}
