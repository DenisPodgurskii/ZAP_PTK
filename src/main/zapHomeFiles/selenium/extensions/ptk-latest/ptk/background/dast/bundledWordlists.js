const AUTH_USERNAMES_LIST_RUNTIME_PATH = "ptk/background/auth.usernames.list.txt"

let bundledWordlistsCache = null
let bundledWordlistsPromise = null

export function parseBundledWordlistText(raw = "") {
    const seen = new Set()
    const values = []
    for (const line of String(raw || "").split(/\r?\n/g)) {
        const value = line.trim()
        if (!value || value.startsWith("#") || seen.has(value)) {
            continue
        }
        seen.add(value)
        values.push(value)
    }
    return values
}

async function readAuthUsernameSource() {
    const runtimeGetUrl = globalThis.browser?.runtime?.getURL || globalThis.chrome?.runtime?.getURL
    if (typeof runtimeGetUrl === "function" && typeof fetch === "function") {
        const response = await fetch(runtimeGetUrl(AUTH_USERNAMES_LIST_RUNTIME_PATH))
        if (!response.ok) {
            throw new Error(`[PTK DAST] Failed to load bundled auth usernames: ${response.status}`)
        }
        return response.text()
    }

    const { readFile } = await import("node:fs/promises")
    return readFile(new URL("../auth.usernames.list.txt", import.meta.url), "utf8")
}

async function buildBundledDastWordlists() {
    const authUsernames = parseBundledWordlistText(await readAuthUsernameSource())
    return Object.freeze({
        auth_enum_usernames_common: Object.freeze(authUsernames)
    })
}

export async function loadBundledDastWordlists(options = {}) {
    const forceReload = !!options?.forceReload
    if (!bundledWordlistsPromise || forceReload) {
        bundledWordlistsPromise = buildBundledDastWordlists()
            .then((wordlists) => {
                bundledWordlistsCache = wordlists
                return wordlists
            })
            .catch((error) => {
                bundledWordlistsPromise = null
                throw error
            })
    }
    return bundledWordlistsPromise
}

export function getBundledDastWordlist(ref = "", wordlists = bundledWordlistsCache) {
    const key = typeof ref === "string" ? ref.trim() : ""
    const list = key && wordlists ? wordlists[key] : null
    return Array.isArray(list) ? list.slice() : null
}
