const HTTP_PROTOCOLS = new Set(['http:', 'https:']);
const RESPONSE_META_POLICIES = new Set([
    'content-security-policy',
    'content-security-policy-report-only',
    'x-content-security-policy',
    'x-webkit-csp'
]);

export const HTML_PREVIEW_LIMITS = Object.freeze({
    maxStylesheets: 16,
    maxStylesheetBytes: 256 * 1024,
    maxAggregateCssBytes: 512 * 1024,
    fetchTimeoutMs: 2500,
    maxRedirects: 4
});

function parseHttpUrl(value, baseUrl) {
    try {
        const url = baseUrl ? new URL(String(value || ''), baseUrl) : new URL(String(value || ''));
        if (!HTTP_PROTOCOLS.has(url.protocol)) return null;
        if (url.username || url.password) return null;
        return url;
    } catch (_) {
        return null;
    }
}

export function normalizePreviewDocumentUrl(value) {
    const url = parseHttpUrl(value);
    if (!url) return null;
    url.hash = '';
    return url;
}

export function resolvePreviewStylesheetUrl(value, documentUrl) {
    if (!String(value || '').trim()) return null;
    const base = normalizePreviewDocumentUrl(documentUrl);
    if (!base) return null;
    const stylesheet = parseHttpUrl(value, base);
    if (!stylesheet || stylesheet.origin !== base.origin) return null;
    stylesheet.hash = '';
    return stylesheet;
}

function isStylesheetContentType(value) {
    if (!value) return true;
    return String(value).split(';', 1)[0].trim().toLowerCase() === 'text/css';
}

async function readBoundedText(response, maxBytes) {
    const declaredLength = Number(response.headers?.get?.('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
        return null;
    }

    if (!response.body || typeof response.body.getReader !== 'function') {
        const text = await response.text();
        return new TextEncoder().encode(text).byteLength <= maxBytes ? text : null;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let bytes = 0;
    let text = '';
    try {
        while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
            if (bytes > maxBytes) {
                await reader.cancel('ptk_html_preview_stylesheet_limit');
                return null;
            }
            text += decoder.decode(chunk.value, { stream: true });
        }
        text += decoder.decode();
        return text;
    } finally {
        reader.releaseLock();
    }
}

function isRedirectStatus(status) {
    return status >= 300 && status <= 399;
}

export async function fetchPreviewStylesheet(
    stylesheetUrl,
    documentUrl,
    fetchImpl = globalThis.fetch,
    limits = HTML_PREVIEW_LIMITS
) {
    const base = normalizePreviewDocumentUrl(documentUrl);
    let current = resolvePreviewStylesheetUrl(stylesheetUrl, base);
    if (!base || !current || typeof fetchImpl !== 'function') return null;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort('ptk_html_preview_stylesheet_timeout'), limits.fetchTimeoutMs);
    try {
        for (let redirectCount = 0; redirectCount <= limits.maxRedirects; redirectCount += 1) {
            let response;
            try {
                response = await fetchImpl(current.href, {
                    method: 'GET',
                    credentials: 'include',
                    redirect: 'manual',
                    referrerPolicy: 'no-referrer',
                    signal: controller.signal,
                    headers: { Accept: 'text/css,*/*;q=0.1' }
                });
            } catch (_) {
                return null;
            }

            if (isRedirectStatus(response.status)) {
                if (redirectCount === limits.maxRedirects) return null;
                const location = response.headers?.get?.('location');
                const next = resolvePreviewStylesheetUrl(location, current);
                if (!next || next.origin !== base.origin) return null;
                current = next;
                continue;
            }

            const finalUrl = parseHttpUrl(response.url || current.href);
            if (!response.ok || !finalUrl || finalUrl.origin !== base.origin) return null;
            if (!isStylesheetContentType(response.headers?.get?.('content-type'))) return null;

            const cssText = await readBoundedText(response, limits.maxStylesheetBytes);
            if (cssText === null) return null;
            return { cssText, url: finalUrl.href };
        }
    } catch (_) {
        return null;
    } finally {
        clearTimeout(timeoutId);
    }
    return null;
}

function serializeHtmlDocument(documentNode) {
    const doctype = documentNode.doctype?.name
        ? `<!DOCTYPE ${documentNode.doctype.name}>`
        : '<!DOCTYPE html>';
    return `${doctype}\n${documentNode.documentElement.outerHTML}`;
}

function buildPreviewContentSecurityPolicy(documentUrl) {
    return [
        "default-src 'none'",
        "script-src 'none'",
        "style-src 'unsafe-inline'",
        "img-src data: blob:",
        "font-src data: blob:",
        "media-src data: blob:",
        "object-src 'none'",
        "frame-src 'none'",
        "worker-src 'none'",
        "connect-src 'none'",
        "form-action 'none'",
        `base-uri ${documentUrl.origin}`
    ].join('; ');
}

export function escapeCssForStyleElement(value) {
    let css = String(value || '');
    const needle = '</style';
    let searchFrom = 0;
    while (searchFrom < css.length) {
        const index = css.toLowerCase().indexOf(needle, searchFrom);
        if (index < 0) break;
        css = `${css.slice(0, index)}\\3C ${css.slice(index + 1)}`;
        searchFrom = index + 4;
    }
    return css;
}

export async function prepareHtmlPreview({
    html,
    requestUrl,
    fetchImpl = globalThis.fetch,
    parserFactory = () => new DOMParser(),
    limits = HTML_PREVIEW_LIMITS
} = {}) {
    const documentUrl = normalizePreviewDocumentUrl(requestUrl);
    const source = String(html || '');
    if (!documentUrl) {
        return { html: source, stylesheets: { discovered: 0, inlined: 0, skipped: 0 } };
    }

    const parser = parserFactory();
    const documentNode = parser.parseFromString(source, 'text/html');
    if (!documentNode?.documentElement || !documentNode?.head) {
        return { html: source, stylesheets: { discovered: 0, inlined: 0, skipped: 0 } };
    }

    documentNode.querySelectorAll('base').forEach((node) => node.remove());
    documentNode.querySelectorAll('meta[http-equiv]').forEach((node) => {
        const directive = String(node.getAttribute('http-equiv') || '').trim().toLowerCase();
        if (directive === 'refresh' || RESPONSE_META_POLICIES.has(directive)) {
            node.remove();
        }
    });
    const contentSecurityPolicy = documentNode.createElement('meta');
    contentSecurityPolicy.setAttribute('http-equiv', 'Content-Security-Policy');
    contentSecurityPolicy.setAttribute('content', buildPreviewContentSecurityPolicy(documentUrl));
    const baseElement = documentNode.createElement('base');
    baseElement.href = documentUrl.href;
    documentNode.head.prepend(baseElement);
    documentNode.head.prepend(contentSecurityPolicy);

    const stylesheetLinks = Array.from(documentNode.querySelectorAll('link[rel]'))
        .filter((link) => link.relList?.contains('stylesheet') && !link.relList?.contains('alternate'));
    const selectedLinks = stylesheetLinks.slice(0, limits.maxStylesheets);
    const fetched = await Promise.all(selectedLinks.map(async (link) => {
        const resolved = resolvePreviewStylesheetUrl(link.getAttribute('href'), documentUrl);
        if (!resolved) return null;
        return fetchPreviewStylesheet(resolved, documentUrl, fetchImpl, limits).catch(() => null);
    }));

    let aggregateBytes = 0;
    let inlined = 0;
    selectedLinks.forEach((link, index) => {
        const result = fetched[index];
        if (!result) {
            link.remove();
            return;
        }
        const cssBytes = new TextEncoder().encode(result.cssText).byteLength;
        if (aggregateBytes + cssBytes > limits.maxAggregateCssBytes) {
            link.remove();
            return;
        }
        aggregateBytes += cssBytes;
        const style = documentNode.createElement('style');
        style.textContent = escapeCssForStyleElement(result.cssText);
        if (link.media) style.media = link.media;
        style.setAttribute('data-ptk-preview-stylesheet', result.url);
        link.replaceWith(style);
        inlined += 1;
    });

    stylesheetLinks.slice(limits.maxStylesheets).forEach((link) => link.remove());
    documentNode.querySelectorAll('link').forEach((link) => link.remove());

    return {
        html: serializeHtmlDocument(documentNode),
        stylesheets: {
            discovered: stylesheetLinks.length,
            inlined,
            skipped: stylesheetLinks.length - inlined
        }
    };
}
