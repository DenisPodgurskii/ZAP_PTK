/* Author: Denis Podgurskii */
import * as jose from "../packages/jose/browser/index.js"
import CryptoES from "../packages/crypto-es/index.js"

/* Utils */
const worker = self

function base64url_encode(source) {
    let encodedSource = CryptoES.enc.Base64.stringify(CryptoES.enc.Utf8.parse(source))
    encodedSource = encodedSource.replace(/=+$/, '')
    encodedSource = encodedSource.replace(/\+/g, '-')
    encodedSource = encodedSource.replace(/\//g, '_')
    return encodedSource
}


export class ptk_utils {
    constructor() { }

    static _originOf(value) {
        if (typeof value !== 'string' || !value) return null
        const extensionMatch = value.match(/^(chrome-extension|moz-extension):\/\/([^/]+)/i)
        if (extensionMatch) return `${extensionMatch[1].toLowerCase()}://${extensionMatch[2]}`
        try {
            return new URL(value).origin
        } catch (_) {
            return null
        }
    }

    static _extensionOrigin() {
        try {
            return this._originOf(browser.runtime.getURL(''))
        } catch (_) {
            return null
        }
    }

    static getOrigin(sender) {
        if (!sender || typeof sender.url !== 'string') return null
        if (this.isTrustedExtensionPageSender(sender)) return browser.runtime.id
        try {
            const parsed = new URL(sender.url)
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return parsed.origin
            if (parsed.protocol === 'file:') return sender.url
        } catch (_) { }
        return null
    }

    static isTrustedExtensionPageSender(sender) {
        if (!sender || sender.id !== browser.runtime.id || typeof sender.url !== 'string') return false
        const extensionOrigin = this._extensionOrigin()
        if (!extensionOrigin) return false

        try {
            if (this._originOf(sender.url) !== extensionOrigin) return false
            if (sender.origin && sender.origin !== 'null' && this._originOf(sender.origin) !== extensionOrigin) return false

            // An extension page embedded by a website inherits that web tab and
            // must not gain privileged UI access. PTK's own popup shell, however,
            // deliberately hosts dashboard/JWT pages in an extension-owned iframe.
            if (sender.tab) {
                const tabUrl = sender.tab.url || sender.tab.pendingUrl || ''
                if (!tabUrl || this._originOf(tabUrl) !== extensionOrigin) return false
            }
            return true
        } catch (_) {
            return false
        }
    }

    static isTrustedContentSender(sender) {
        if (!sender || sender.id !== browser.runtime.id || !Number.isInteger(sender?.tab?.id)) return false
        if (typeof sender.url !== 'string' || !sender.url) return false
        const extensionOrigin = this._extensionOrigin()

        try {
            const parsed = new URL(sender.url)
            if (extensionOrigin && this._originOf(sender.url) === extensionOrigin) return false
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:' || parsed.protocol === 'file:') {
                return true
            }
            if ((parsed.protocol === 'about:' || parsed.protocol === 'blob:') && Number(sender.frameId) > 0) {
                const tabUrl = sender.tab.url || sender.tab.pendingUrl || ''
                const tabProtocol = new URL(tabUrl).protocol
                return tabProtocol === 'http:' || tabProtocol === 'https:' || tabProtocol === 'file:'
            }
        } catch (_) { }
        return false
    }

    static isTrustedOrigin(sender) {
        return this.isTrustedExtensionPageSender(sender)
    }

    static jsonSetValueByPath(jsonData, path, value, add = false) {
        if (!(jsonData instanceof Object) || typeof (path) === "undefined") {
            throw "Not valid argument:jsonData:" + jsonData + ", path:" + path
        }
        let origData = jsonData
        path = path.replace(/\[(\w+)\]/g, '.$1') // convert indexes to properties
        path = path.replace(/^\./, '');// strip a leading dot
        let pathArray = path.split('.')
        let i = 0
        do {
            let key = pathArray[i]
            if (key in jsonData) {
                if (i < (pathArray.length - 1)) jsonData = jsonData[key]
                else jsonData[key] = value
            } else if (add) {
                if (i < (pathArray.length - 1)) {
                    jsonData[key] = {}
                    jsonData = jsonData[key]
                }
                else jsonData[key] = value
            }
            i++
        } while (i < pathArray.length)
        return origData
    }

    static jsonGetValueByPath(jsonData, path) {
        if (!(jsonData instanceof Object) || typeof (path) === "undefined") {
            throw "Not valid argument:jsonData:" + jsonData + ", path:" + path
        }
        let origData = jsonData
        path = path.replace(/\[(\w+)\]/g, '.$1') // convert indexes to properties
        path = path.replace(/^\./, '');// strip a leading dot
        let pathArray = path.split('.')
        let i = 0
        do {
            let key = pathArray[i]
            if (key in jsonData) {
                if (i < (pathArray.length - 1)) jsonData = jsonData[key]
                else return jsonData[key]
            }
            i++
        } while (i < pathArray.length)
        return origData
    }

    static get requestFilters() {
        return ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other"]
    }

    static get extraInfoSpec() {
        return browser.runtime.getBrowserInfo ? [] : ["extraHeaders"]
    }

    static UUID() {
        if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID()
        const bytes = new Uint8Array(16)
        globalThis.crypto.getRandomValues(bytes)
        bytes[6] = (bytes[6] & 0x0f) | 0x40
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
    }

    static attackId() {
        return this.UUID().replaceAll('-', '')
    }

    static attackParamId(l = 12) {
        const length = Math.max(1, Math.min(128, Number(l) || 12))
        const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
        const bytes = new Uint8Array(length)
        globalThis.crypto.getRandomValues(bytes)
        return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join('')
    }

    static isURL(url) {
        let regex = new RegExp(/^((http|https):\/\/){1}(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])?(:+[0-9]+)?([\/\?]{1}.*)?$/i)
        return regex.test(url)
    }

    static exclude(url) {
        if (url == 'chrome://newtab/' || url == 'about:newtab') return false
        let regex = new RegExp(/^(chrome:|about:|moz-extension:|chrome-extension:)/i)
        return regex.test(url)
    }

    static escapeHtml(unsafe) {
        if (unsafe === null || typeof unsafe === "undefined") {
            return ""
        }
        unsafe = String(unsafe)
        unsafe = unsafe.replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;")
        return unsafe
    }

    static unescapeHtml(unsafe) {
        if (unsafe === null || typeof unsafe === "undefined") {
            return ""
        }
        unsafe = String(unsafe)
        unsafe = unsafe
            .replaceAll("&lt;", /</)
            .replaceAll("&gt;", />/)
            .replaceAll("&quot;", /"/)
            .replaceAll("&#039;", /'/)
            .replaceAll("&amp;", /&/)
        return unsafe
    }
}

/* Logger */
export class ptk_logger {
    constructor() { }

    static log(event, msg, level) {
        // if (window.ptk_debug || level == "error") {
        //     console.log(event)
        //     if (msg instanceof Array) {
        //         for (m in msg) {
        //             console.log(m + ": " + msg[m])
        //         }
        //     } else console.log(msg)
        //     console.log("Logged at: " + Date.now())
        // }
    }

}

/* Notifications -- manage browser notifications */
export class ptk_notifications {
    constructor() { }

    static clearAll() {
        browser.notifications.getAll().then(function (notifications) {
            if (notifications) {
                for (let key in notifications) {
                    browser.notifications.clear(key)
                }
            }
        })
    }

    static notify(title, message, clearAll = true) {
        if (clearAll) this.clearAll()
        browser.notifications.create(
            'PTK_notification', {
            type: 'basic',
            iconUrl: browser.runtime.getURL('ptk/browser/assets/images/icon.png'),
            title: title,
            message: message
        })
    }
}

/* Queue for R-Attacker */
export class ptk_queue {
    constructor(items = []) {
        const normalized = Array.isArray(items) ? items.slice() : []
        this._buffer = normalized
        this._head = 0
        this._size = normalized.length
    }

    isEmpty() {
        return this._size === 0
    }

    enqueue(item) {
        this._buffer.push(item)
        this._size += 1
    }

    dequeue() {
        if (!this._size) {
            return undefined
        }
        const item = this._buffer[this._head]
        this._buffer[this._head] = undefined
        this._head += 1
        this._size -= 1
        if (this._size === 0) {
            this.clear()
        } else if (this._head > 1024 && this._head * 2 > this._buffer.length) {
            this._buffer = this._buffer.slice(this._head)
            this._head = 0
        }
        return item
    }

    size() {
        return this._size
    }

    clear() {
        this._buffer = []
        this._head = 0
        this._size = 0
    }

    has(item) {
        for (let i = this._head; i < this._buffer.length; i++) {
            if (this._buffer[i] === item) {
                return true
            }
        }
        return false
    }

    // Compatibility getter for any legacy direct reads.
    get items() {
        return this._buffer.slice(this._head)
    }

    // Compatibility setter for any legacy direct writes.
    set items(value) {
        const normalized = Array.isArray(value) ? value.slice() : []
        this._buffer = normalized
        this._head = 0
        this._size = normalized.length
    }

}

/* JWT Helper class */
export class ptk_jwtHelper {
    static SPKI = "SPKI"
    static PKCS8 = "PKCS8"
    static JWK = "JWK"
    constructor() {
        this.jwtRegex = /(ey[a-zA-Z0-9_=]+)\.(ey[a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)/
        this.sessionRegex = '(?:[^"]*token\s?\s?){1}","?(ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+]*)"?'
        this.headersRegex = '(?:"authorization"),"(?:.+\s?)?(ey[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_.]*)"'
        this.storageRegex = '(?:"*token"\s?):\s?"?(ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+]*)"?'

        this.cookiesRawRegex = /(?:[^"]*tokens?){1}\s?=\s?(ey[A-Za-z0-9-_]+.[A-Za-z0-9-_=]+.?[A-Za-z0-9-_.+]*)"?/
        this.headersRawRegex = /(?:authorization\:)(?:.+\s)?(ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.]*)/
    }

    checkToken(token) {
        let r = new RegExp(this.jwtRegex, "g")
        //let jwtToken = token.match(new RegExp(this.jwtRegex, "g"))
        let jwtToken = r.exec(token)
        let decodedToken = ''
        if (jwtToken) {
            try {
                decodedToken = JSON.stringify(this.parseJwt(jwtToken[0]), null, 4)

            } catch (e) { }
        }
        return { jwtToken: jwtToken, decodedToken: decodedToken }
    }

    detectCertFormat(cert) {
        if (typeof cert == 'string') {
            if (cert.startsWith("-----BEGIN PUBLIC KEY-----")) return ptk_jwtHelper.SPKI
            if (cert.startsWith("-----BEGIN PRIVATE KEY-----")) return ptk_jwtHelper.PKCS8
            try {
                JSON.parse(cert)
                return ptk_jwtHelper.JWK
            } catch (e) {
                return null
            }
        }
        return null
        // else {

        // }
    }

    checkJWT(item, regex) {
        let jwtToken = item.match(new RegExp(regex, "i", "g"))
        let decodedToken = ''
        if (jwtToken) {
            try {
                decodedToken = JSON.stringify(this.parseJwt(jwtToken[1]), null, 4)
            } catch (e) { }
        }
        return { jwtToken: jwtToken, decodedToken: decodedToken }
    }

    parseJwt(token) {
        let base64Url = token.split('.');
        if (base64Url.length >= 2) {
            let header = decodeURIComponent(atob(base64Url[0].replace(/-/g, '+').replace(/_/g, '/')).split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''))
            let jsonPayload = ''
            try {
                jsonPayload = decodeURIComponent(atob(base64Url[1].replace(/-/g, '+').replace(/_/g, '/')).split('').map(function (c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                }).join(''));
            } catch (e) {
            }

            if (base64Url.length == 3)
                return { "header": JSON.parse(header), "payload": JSON.parse(jsonPayload), "signature": base64Url[2] }
            else
                return { "header": JSON.parse(header), "payload": JSON.parse(jsonPayload), "signature": "" }
        }

        return null;
    }

    async generateConfusionAttacks(header, payload, secret) {
        let tokens = []
        let hObj = header
        let pObj = payload


        //ORIGINAL
        let m = secret
        let a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m))
        tokens.push(["", "ORIGINAL", a])

        if (m.length > 32) {
            a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m.substring(32)))
            tokens.push(["", "ORIGINAL_PKCS1", a])
        }


        //ADDITIONAL_LF
        m = secret + "\n"
        a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m))
        tokens.push(["", "ADDITIONAL_LF", a])

        if (m.length > 32) {
            a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m.substring(32)))
            tokens.push(["", "ADDITIONAL_LF_PKCS1", a])
        }

        //NO_HEADER_FOOTER
        m = secret.replace("-----BEGIN PUBLIC KEY-----\n", "").replaceAll("-----END PUBLIC KEY-----\\n?", "")
            .replace("-----BEGIN RSA PUBLIC KEY-----\n", "").replaceAll("-----END RSA PUBLIC KEY-----\\n?", "")
        a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m))
        tokens.push(["", "NO_HEADER_FOOTER", a])
        if (m.length > 32) {
            a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m.substring(32)))
            tokens.push(["", "NO_HEADER_FOOTER_PKCS1", a])
        }

        //NO_LF
        m = secret.replaceAll("\\r\\n|\\r|\\n", "")
        a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m))
        tokens.push(["", "NO_LF", a])
        if (m.length > 32) {
            a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m.substring(32)))
            tokens.push(["", "NO_LF_PKCS1", a])
        }

        //NO_HEADER_FOOTER_LF
        m = secret.replace("-----BEGIN PUBLIC KEY-----\n", "").replaceAll("-----END PUBLIC KEY-----\\n?", "")
            .replace("-----BEGIN RSA PUBLIC KEY-----\n", "").replaceAll("-----END RSA PUBLIC KEY-----\\n?", "")
            .replaceAll("\\r\\n|\\r|\\n", "")
        a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m))
        tokens.push(["", "NO_HEADER_FOOTER_LF", a])
        if (m.length > 32) {
            a = await new jose.SignJWT(pObj).setProtectedHeader(hObj).sign(new TextEncoder().encode(m.substring(32)))
            tokens.push(["", "NO_HEADER_FOOTER_LF_PKCS1", a])
        }



        return Promise.resolve(tokens)
    }

    async signToken(header, payload, secret, keys) {
        let hObj = JSON.parse(header)
        let pObj = JSON.parse(payload)

        if (hObj.alg.toLowerCase() == 'none') {
            return base64url_encode(header.replace(/\n/g, '')) + "." + base64url_encode(payload.replace(/\n/g, '')) + "."
        }
        else if (['HS256', 'HS384', 'HS512'].includes(hObj.alg)) {
            if (secret == "") {
                if (hObj.alg == 'HS256') {
                    let tH = CryptoES.enc.Base64.stringify(CryptoES.enc.Utf8.parse(JSON.stringify(hObj)))
                        .replace(/=/g, '')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                    let tP = CryptoES.enc.Base64.stringify(CryptoES.enc.Utf8.parse(JSON.stringify(pObj)))
                        .replace(/=/g, '')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                    let t = jose.base64url.encode(JSON.stringify(hObj)) + "." + jose.base64url.encode(JSON.stringify(pObj))

                    let hash = CryptoES.HmacSHA256(tH + "." + tP, '')
                    return (tH + "." + tP + "." + CryptoES.enc.Base64.stringify(hash))
                        .replace(/=/g, '')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                }
            } else {
                secret = new TextEncoder().encode(secret)
                return await new jose.SignJWT(pObj)
                    .setProtectedHeader(hObj)
                    .sign(secret)
            }
        } else {

            let format = this.detectCertFormat(keys['private'])
            let privateKey = null
            if (format == ptk_jwtHelper.PKCS8) {
                privateKey = await jose.importPKCS8(keys['private'], hObj.alg).catch(() => undefined)
            } else if (format == ptk_jwtHelper.JWK) {
                privateKey = await jose.importJWK(JSON.parse(keys['private']), hObj.alg).catch(() => undefined)
            }


            return await new jose.SignJWT(pObj)
                .setProtectedHeader(hObj)
                .sign(privateKey)

        }
    }
}

export class ptk_storage {

    static async setItem(key, value) {
        let obj = {}
        obj[key] = value
        return browser.storage.local.set(obj)
    }

    static async getItem(key) {
        return browser.storage.local.get(key).then(function (result) {
            let obj = {}
            if (result[key] && Object.keys(result[key]).length > 0)
                obj = result[key]
            return obj
        })
    }
}

// Mange manifest V3 declarativeNetRules
export class ptk_ruleManager {
    static declarativeNetRulesCounter = 0

    static resetSession() {
        if (!worker.isFirefox) {
            this.deleteSessionRules()
            this.declarativeNetRulesCounter = 0
        }
    }

    static getDynamicRules() {
        if (!worker.isFirefox) {
            return chrome.declarativeNetRequest.getDynamicRules(() => { })
        }
        return []
    }

    static getSessionRules() {
        if (!worker.isFirefox) {
            return chrome.declarativeNetRequest.getSessionRules(() => { })
        }
        return []
    }

    static async deleteSessionRules() {
        if (!worker.isFirefox) {
            await chrome.declarativeNetRequest.getSessionRules((rules) => {
                let ids = []
                rules.forEach(x => { ids.push(x.id) })
                chrome.declarativeNetRequest.updateSessionRules({
                    removeRuleIds: ids
                })
            })
        }
    }

    static async deleteDynamicRules(ids) {
        if (!worker.isFirefox) {
            if (!ids) {
                await chrome.declarativeNetRequest.getDynamicRules((rules) => {
                    ids = []
                    rules.forEach(x => { ids.push(x.id) })
                })
            }
            await chrome.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: ids
            })
        }
    }

    static async addSessionRule(schema, ruleId) {
        if (!worker.isFirefox) {
            let headers = []
            schema.request.headers.forEach((h) => {
                headers.push({ "header": h.name, "operation": "set", "value": h.value })
            })
            let requestDomain = null
            try {
                requestDomain = new URL(schema.request.url).hostname
            } catch (_) {
                requestDomain = null
            }
            let condition = {
                "urlFilter": schema.request.url,
                "resourceTypes": ["xmlhttprequest", "other"]
            }
            if (requestDomain) condition.requestDomains = [requestDomain]
            if (chrome?.runtime?.id) condition.initiatorDomains = [chrome.runtime.id]

            const rule = {
                "id": parseInt(ruleId),
                "priority": 1,
                "action": {
                    "type": "modifyHeaders",
                    "requestHeaders": headers
                },
                "condition": condition
            }

            await chrome.declarativeNetRequest.updateSessionRules({
                addRules: [rule]
            })

        }
    }

    static async removeSessionRule(id) {
        if (!worker.isFirefox) {
            try {
                //console.log('remove rule ' + id)
                await chrome.declarativeNetRequest.updateSessionRules({
                    removeRuleIds: [id]
                })
            } catch (e) {
            }
        }
    }

}
