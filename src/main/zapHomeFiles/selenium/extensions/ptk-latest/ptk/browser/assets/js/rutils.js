import { ptk_utils } from "../../../background/utils.js";
import { ptk_decoder } from "../../../background/decoder.js";
import { default as dompurify } from "../../../packages/dompurify/purify.es.mjs";
const decoder = new ptk_decoder();
const INLINE_FILE_SPLIT_RE = /\s+::\s+/;
const INLINE_FILE_PREFIX_RE = /^inline/i;
const RICH_TEXT_SANITIZE_CONFIG = {
    ALLOWED_TAGS: ['p', 'ul', 'ol', 'li', 'code', 'strong', 'em', 'a', 'br', 'pre', 'b', 'i'],
    ALLOWED_ATTR: ['href', 'target', 'rel']
};
const MODAL_TITLE_SANITIZE_CONFIG = {
    ALLOWED_TAGS: ['div', 'span', 'b', 'i'],
    ALLOWED_ATTR: ['class']
};

let iastDisplayRegistry = null;
let iastDisplayRegistryPromise = null;

function loadIastDisplayRegistry() {
    if (iastDisplayRegistryPromise) return iastDisplayRegistryPromise;
    try {
        const url = browser.runtime.getURL("/ptk/background/iast/modules/display_registry.json");
        iastDisplayRegistryPromise = fetch(url)
            .then((res) => (res && res.ok ? res.json() : null))
            .then((data) => {
                iastDisplayRegistry = data && typeof data === 'object' ? data : null;
                return iastDisplayRegistry;
            })
            .catch(() => {
                iastDisplayRegistry = null;
                return null;
            });
    } catch (_) {
        iastDisplayRegistry = null;
        iastDisplayRegistryPromise = Promise.resolve(null);
    }
    return iastDisplayRegistryPromise;
}

function getIastDisplayEntry(group, code) {
    if (!code) return null;
    const registry = iastDisplayRegistry;
    if (!registry || !registry[group]) return null;
    return registry[group][code] || null;
}

function formatIastDisplayLabel(group, code, fallback = '') {
    const entry = getIastDisplayEntry(group, code);
    if (entry && entry.label) return entry.label;
    return fallback || code || '';
}

loadIastDisplayRegistry();

const SEVERITY_VISUALS = {
    critical: { color: "ptk-sev-critical", icon: "fire", order: 0 },
    high: { color: "ptk-sev-high", icon: "exclamation triangle", order: 1 },
    medium: { color: "ptk-sev-medium", icon: "exclamation triangle", order: 2 },
    low: { color: "ptk-sev-low", icon: "exclamation triangle", order: 3 },
    info: { color: "ptk-sev-info", icon: "info circle", order: 4 }
};

const STAT_SELECTOR_MAP = {
    default: {
        attacks: "#attacks_count",
        findings: "#vulns_count",
        critical: "#critical_count",
        high: "#high_count",
        medium: "#medium_count",
        low: "#low_count",
        info: "#info_count"
    },
    dast: {
        attacks: "#dast_attacks_count",
        findings: "#dast_vulns_count",
        critical: "#dast_critical_count",
        high: "#dast_high_count",
        medium: "#dast_medium_count",
        low: "#dast_low_count",
        info: "#dast_info_count"
    },
    sast: {
        attacks: "#sast_attacks_count",
        findings: "#sast_vulns_count",
        critical: "#sast_critical_count",
        high: "#sast_high_count",
        medium: "#sast_medium_count",
        low: "#sast_low_count",
        info: "#sast_info_count"
    },
    iast: {
        findings: "#iast_vulns_count",
        critical: "#iast_critical_count",
        high: "#iast_high_count",
        medium: "#iast_medium_count",
        low: "#iast_low_count",
        info: "#iast_info_count"
    },
    sca: {
        findings: "#sca_vulns_count",
        critical: "#sca_critical_count",
        high: "#sca_high_count",
        medium: "#sca_medium_count",
        low: "#sca_low_count",
        info: "#sca_info_count"
    },
    rbuilder: {
        attacks: "#rbuilder_attacks_count",
        findings: "#rbuilder_vulns_count",
        critical: "#rbuilder_critical_count",
        high: "#rbuilder_high_count",
        medium: "#rbuilder_medium_count",
        low: "#rbuilder_low_count",
        info: "#rbuilder_info_count"
    }
};

let mf = browser.runtime.getManifest().manifest_version;
const isFirefox = mf == 2;

export async function pingContentScript(tabId, { timeoutMs = 500 } = {}) {
    if (typeof tabId !== 'number') return false;
    let timeoutId = null;
    const timeoutPromise = new Promise((resolve) => {
        timeoutId = setTimeout(() => resolve(false), timeoutMs);
    });
    const pingPromise = browser.tabs.sendMessage(tabId, {
        channel: "ptk_popup2content",
        type: "ping"
    }).then((res) => !!res?.ok).catch(() => false);
    const ok = await Promise.race([pingPromise, timeoutPromise]);
    if (timeoutId) clearTimeout(timeoutId);
    return !!ok;
}

export function updateDashboardTab(tabId, url) {
    if (typeof tabId !== 'number') return Promise.resolve(false);
    return browser.runtime.sendMessage({
        channel: "ptk_popup2background_dashboard",
        type: "init",
        tabId,
        url
    }).then(() => true).catch(() => false);
}

export function registerDashboardTabListener({ onTabChange, debounceMs = 200 } = {}) {
    const base = browser.runtime.getURL('');
    const isExtensionUrl = (url) => !!url && url.startsWith(base);
    let lastTabId = null;
    let lastUrl = null;
    let timerId = null;

    const emit = (tab) => {
        if (!tab?.tabId || !tab?.url || isExtensionUrl(tab.url)) return;
        if (tab.tabId === lastTabId && tab.url === lastUrl) return;
        lastTabId = tab.tabId;
        lastUrl = tab.url;
        if (timerId) clearTimeout(timerId);
        if (!debounceMs) {
            onTabChange && onTabChange(tab);
            return;
        }
        timerId = setTimeout(() => {
            onTabChange && onTabChange(tab);
        }, debounceMs);
    };

    const onActivated = async (info) => {
        const tab = await browser.tabs.get(info.tabId).catch(() => null);
        if (!tab?.url || isExtensionUrl(tab.url)) return;
        emit({ tabId: tab.id, url: tab.url });
    };

    const emitFromWindow = async (windowId) => {
        if (!windowId || windowId === browser.windows.WINDOW_ID_NONE) return;
        const tabs = await browser.tabs.query({ windowId }).catch(() => null);
        const active = tabs && tabs.length ? tabs.find((t) => t.active) : null;
        if (active?.url && !isExtensionUrl(active.url)) {
            emit({ tabId: active.id, url: active.url });
        }
    };

    const onFocusChanged = async (windowId) => {
        await emitFromWindow(windowId);
    };

    const onUpdated = (tabId, info, tab) => {
        if (!info?.url) return;
        if (!tab?.url || isExtensionUrl(tab.url)) return;
        emit({ tabId, url: tab.url });
    };

    browser.tabs.onActivated.addListener(onActivated);
    browser.tabs.onUpdated.addListener(onUpdated);
    browser.windows.onFocusChanged.addListener(onFocusChanged);

    browser.windows.getLastFocused({ populate: true }).then((win) => {
        const tabs = win?.tabs || [];
        const active = tabs.find((t) => t.active);
        if (active?.url && !isExtensionUrl(active.url)) {
            emit({ tabId: active.id, url: active.url });
            return;
        }
        const fallback = tabs.find((t) => t?.url && !isExtensionUrl(t.url));
        if (fallback?.url) emit({ tabId: fallback.id, url: fallback.url });
    }).catch(() => {});

    return () => {
        browser.tabs.onActivated.removeListener(onActivated);
        browser.tabs.onUpdated.removeListener(onUpdated);
        browser.windows.onFocusChanged.removeListener(onFocusChanged);
        if (timerId) clearTimeout(timerId);
    };
}

$("#attack_details_dialog_wrapper").prepend(
    `
    <div id="attack_details" class="ui fullscreen modal coupled" style="display: none; height: 83%">
        <i class="close icon"></i>
        <div class="ui header" id="attack_name"></div>
        <div class="content" style="min-height: 400px;  height: calc(100% - 30px); padding: 2px 7px 2px 2px; scrollbar-width: none;">
            <form class="ui tiny form controls" id="attack_details_form">
                <input type="hidden" id="attack_target" name="request_url">
                <div class="fields" id="finding_http_section" style="min-height: 65%; margin-bottom: 4px; display: none;">
                    <div class="eight wide field" id="finding_request_column" style="padding-right: 1px; overflow:auto">
                        <div class="ui large label"
                            style="position: sticky;width:100%; top: 0; z-index: 1; height: 34px; padding-top: 10px; margin-top: -2px;">
                            Request
                            <div class="ui mini icon secondary button send_rbuilder" style="position: absolute;top: 0px;right: -8px;z-index: 1;">
                                <i class="wrench large icon" title="Send to R-Builder"></i>
                            </div>
                        </div>
                        <textarea readonly id="raw_request" class="ui large input" rows="5" placeholder="Request"
                            style="scrollbar-width: none;height:calc(100% - 32px);"></textarea>
                    </div>
                    <div class="eight wide field response_view" id="finding_response_column" style="padding-right: 1px; overflow:auto">
                        <div class="ta-wrap" style="height:50%">
                            <textarea readonly id="raw_response_headers" class="ui large input" rows="8"
                            placeholder="Response Headers" style="height: 100%; scrollbar-width: none;"></textarea>
                            <div class="ui large label ta-btn">Response Headers</div>
                        </div>

                        <div class="ta-wrap" style="height:50%">
                            <textarea readonly id="raw_response" name="response_body" class="ui large input" rows="20"
                                placeholder="Response Body" style="height: calc(100% - 3px); padding-top: 35px; scrollbar-width: none; margin-top: 2px;"
                                autofocus></textarea>
                            <div class="ui small secondary buttons ta-btn">
                                <div class="ui button showHtml">HTML</div>
                                <div class="ui floating dropdown icon button">
                                    <i class="dropdown icon"></i>
                                    <div class="menu">
                                        <div class="item showHtmlNew"><i class="external square alternate icon"></i>
                                            Open in new window
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div id="iast_context_header" class="ui mini message" style="display:none; margin-bottom: 6px;"></div>
                <div class="fields" id="finding_source_sink_section" style="min-height: 65%; margin-bottom: 4px; display: none;">
                    <div class="eight wide field" id="finding_source_column" style="padding-right: 1px; overflow:auto">
                        <div class="ui message message-code" style="height:100%;">
                            <div class="meta">
                                <div class="header">Source: <span id="source_name"></span></div>
                                <div class="description">Link: <span id="source_link"></span></div>
                                <ul class="list">
                                    <li>Start: <span id="source_start"></span></li>
                                    <li>End: <span id="source_end"></span></li>
                                </ul>
                            </div>
                            <div class="iast-details-meta" id="source_extra_meta" style="display:none;"></div>
                            <pre id="source_details" class="ui input code-block iast-code-block" aria-readonly="true">
                                <code id="source_details_code"></code>
                            </pre>
                        </div>
                    </div>
                    <div class="eight wide field response_view" id="finding_sink_column" style="padding-right: 1px; overflow:auto">
                        <div class="ui message message-code" style="height: 100%;">
                            <div class="header">Sink - <span id="sink_name"></span></div>
                            <div class="description">Link: <span id="sink_link"></span></div>
                            <ul class="list">
                                <li>Start: <span id="sink_start"></span></li>
                                <li>End: <span id="sink_end"></span></li>
                            </ul>
                            <div class="iast-details-meta" id="sink_extra_meta" style="display:none;"></div>
                            <pre id="sink_details" class="ui input code-block iast-code-block" aria-readonly="true"><code id="sink_details_code"></code></pre>
                        </div>
                    </div>
                </div>

                <div class="ui top attached tabular menu small metadata finding-metadata" style="background-color: #e8e8e8;margin:0px">
                        <a class="item active" data-tab="finding-description">Description</a>
                        <a class="item" data-tab="finding-recommendation">Recommendation</a>
                        <a class="item" data-tab="finding-links">Links</a>
                </div>

                <div class="ui segment" style="padding: 0px;margin-right: -4px;margin-top: 0px;height: 29%; overflow:scroll;">

                    <div class="ui bottom attached tab segment small active" data-tab="finding-description" style="min-height: 100%;">
                        <div id="attack_description"></div>
                    </div>
                    <div class="ui bottom attached tab segment small" data-tab="finding-recommendation" style="min-height: 100%;">
                        <div id="attack_recommendation"></div>
                    </div>
                    <div class="ui bottom attached tab segment small" data-tab="finding-links" style="min-height: 100%;">
                        <div class="ui middle aligned divided list" id="attack_links">
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>
    <div id="dialogResponseHtml" class="ui fullscreen modal coupled" style="display: none;height: 83%">
        <i class="close icon"></i>
        <div class="header">HTML response</div>

        <div class="content" id="dialogResponseHtmlContent" style="min-height: 400px;height: 90%;padding:0px">
            <object id="dialogResponseHtmlContentObj" type="text/html" data="" style="overflow:hidden;height:100%;width:100%; min-height: 400px;" height="100%">
            </object>
            <iframe id="dialogResponseHtmlContentFrame" src="" style="overflow:hidden;height:100%;width:100%; min-height: 400px;" height="100%"></iframe>
        </div>
    </div>
    `
);

const findingModal = $("#attack_details");
const findingMetadataTabs = $("#attack_details .finding-metadata .item");
if (findingMetadataTabs.length) {
    findingMetadataTabs.tab();
}
if (findingModal.length && typeof findingModal.modal === 'function') {
    findingModal.modal({
        observeChanges: true,
        autofocus: false,
        onHidden: () => {
            destroyRequestEditor();
        }
    });
}

function toggleSection(selector, visible) {
    const node = $(selector);
    if (!node.length) return;
    node.toggle(!!visible);
}

function clearElementText(id) {
    const el = document.getElementById(id);
    if (el) el.textContent = '';
}

function resetFindingModal() {
    toggleSection("#finding_http_section", false);
    toggleSection("#finding_source_sink_section", false);
    toggleSection("#finding_trace_segment", false);
    clearElementText("attack_name");
    clearElementText("source_name");
    clearElementText("sink_name");
    clearElementText("source_start");
    clearElementText("source_end");
    clearElementText("sink_start");
    clearElementText("sink_end");
    clearElementText("finding_trace_title");
    $("#source_link").empty();
    $("#sink_link").empty();
    $("#source_extra_meta").empty().hide();
    $("#sink_extra_meta").empty().hide();
    $("#source_details_code").text("");
    $("#sink_details_code").text("");
    $("#raw_request").val("");
    $("#raw_response").val("");
    $("#raw_response_headers").val("");
    $("#attack_target").val("");
    $("#taint_trace").empty();
    destroyRequestEditor();
    setFindingMetadata("", "", {}, {});
}

function setFindingModalTitle(contentHtml) {
    const el = document.getElementById("attack_name");
    if (el) {
        el.innerHTML = contentHtml || "Finding details";
    }
}

function setFindingMetadata(description, recommendation, links, extras = {}) {
    $("#attack_description").html(dompurify.sanitize(description || "", RICH_TEXT_SANITIZE_CONFIG));
    $("#attack_recommendation").html(dompurify.sanitize(recommendation || "", RICH_TEXT_SANITIZE_CONFIG));
    const linksContainer = document.getElementById("attack_links");
    if (!linksContainer) return;
    linksContainer.innerHTML = "";
    const map = links && typeof links === "object" ? links : {};
    const entries = Object.entries(map);
    const extrasMarkup = []
    const owaspList = Array.isArray(extras?.owasp) ? extras.owasp : []
    const cweList = Array.isArray(extras?.cwe) ? extras.cwe : []
    const owaspHtml = renderOwaspChips(owaspList)
    if (owaspHtml) {
        extrasMarkup.push(`<div class="item"><strong>OWASP:</strong> ${owaspHtml}</div>`)
    }
    const cweHtml = renderCweChips(cweList)
    if (cweHtml) {
        extrasMarkup.push(`<div class="item"><strong>CWE:</strong> ${cweHtml}</div>`)
    }
    extrasMarkup.forEach(html => linksContainer.insertAdjacentHTML("beforeend", sanitize(html)))
    if (!entries.length) {
        if (!extrasMarkup.length) {
            const empty = document.createElement("div");
            empty.className = "item";
            empty.textContent = "No references provided.";
            linksContainer.appendChild(empty);
        }
        return;
    }
    entries.forEach(([title, href]) => {
        try {
            linksContainer.appendChild(makeLinkItem(title, href));
        } catch (err) {
            console.warn("Skipping invalid link entry", title, href);
        }
    });
}

function showFindingModal(tab = "finding-description") {
    if (findingMetadataTabs.length) {
        findingMetadataTabs.tab("change tab", tab);
    }
    if (findingModal.length) {
        findingModal.modal("show");
    }
}

let requestEditor;

function destroyRequestEditor() {
    if (requestEditor) {
        requestEditor.toTextArea();
        requestEditor = null;
    }
}

function mountRequestEditor(value) {
    destroyRequestEditor();
    const textarea = document.getElementById("raw_request");
    if (!textarea) return;
    textarea.value = value || "";
    requestEditor = CodeMirror.fromTextArea(textarea, {
        lineNumbers: false,
        lineWrapping: true,
        indentUnit: 4,
        mode: "message/http"
    });
    requestEditor.getDoc().setValue(value || "");
    requestEditor.setSize("101.5%", "100%");
    requestEditor.setCursor({ line: 1, ch: 1 });
}

export function sortAttacks() {
    // Expensive for large lists; call once after the scan completes.
    const $container = $("#attacks_info");
    if (!$container.length) return;

    // jQuery collections are array-like and do not always expose Array#sort.
    const nodes = $(".attack_info").get();
    nodes.sort((a, b) => {
        const aOrder = Number($(a).data("order")) || 0;
        const bOrder = Number($(b).data("order")) || 0;
        return aOrder - bOrder;
    });

    $container.append(nodes);
}

function canonicalizeSastUrl(raw, base) {
    if (!raw) return "";
    try {
        const u = new URL(String(raw), base || (typeof document !== "undefined" ? document.baseURI : undefined));
        u.hostname = (u.hostname || "").toLowerCase();
        u.search = "";
        u.hash = "";
        const isHttp = u.protocol === "http:";
        const isHttps = u.protocol === "https:";
        if ((isHttp && u.port === "80") || (isHttps && u.port === "443")) {
            u.port = "";
        }
        let p = u.pathname || "/";
        p = p.replace(/\/{2,}/g, "/");
        if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
        u.pathname = p;
        return u.toString();
    } catch (_) {
        const s = String(raw);
        const noHash = s.split("#")[0];
        const noQuery = noHash.split("?")[0];
        return noQuery.length > 1 && noQuery.endsWith("/") ? noQuery.slice(0, -1) : noQuery;
    }
}

export function canonicalizeSastFileId(raw, base) {
    if (!raw) return "";
    const trimmed = String(raw).trim();
    if (!trimmed) return "";
    if (INLINE_FILE_SPLIT_RE.test(trimmed)) {
        const [page, inlinePart] = trimmed.split(INLINE_FILE_SPLIT_RE);
        const canonPage = canonicalizeSastUrl(page, base);
        return `${canonPage} :: ${inlinePart}`;
    }
    return canonicalizeSastUrl(trimmed, base);
}

function canonicalizeSastEndpoint(raw, pageRaw) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) {
        return canonicalizeSastFileId(pageRaw || "");
    }
    if (INLINE_FILE_SPLIT_RE.test(trimmed)) {
        return canonicalizeSastFileId(trimmed);
    }
    const isInlineLabel = INLINE_FILE_PREFIX_RE.test(trimmed);
    if (isInlineLabel && pageRaw) {
        const pageCanon = canonicalizeSastFileId(pageRaw);
        if (pageCanon) {
            return `${pageCanon} :: ${trimmed}`;
        }
    }
    return canonicalizeSastFileId(trimmed);
}

function extractCanonBase(canon) {
    if (!canon) return "";
    const idx = canon.indexOf(" :: ");
    if (idx === -1) return canon;
    return canon.slice(0, idx).trim();
}

function buildMiscMeta(info) {
    const finding = info?.finding || null
    const meta = info?.metadata || {}
    let icon = ""
    let attackClass = "nonvuln"
    let order = 3
    let severityValue = ""
    const isVuln = info?.type === 'sast' || info?.type === 'iast' || !!info?.success

    if (isVuln) {
        let severity = info.severity || finding?.severity || meta?.severity || 'medium'
        severityValue = ("" + severity).toLowerCase()
        if (severityValue === 'informational') {
            severityValue = 'info'
        }
        const severityLabel = severityValue.charAt(0).toUpperCase() + severityValue.slice(1)
        const visualMeta = SEVERITY_VISUALS[severityValue] || { color: "grey", order: 5 }
        attackClass = "vuln success visible " + ptk_utils.escapeHtml(severityLabel) + " severity-" + ptk_utils.escapeHtml(severityValue)
        order = visualMeta.order
        let name = finding?.ruleName || info.name || meta?.name || info.identifiers?.summary || info.category
        const iconColor = visualMeta.color || "grey"
        const iconShape = visualMeta.icon || "exclamation triangle"
        icon = `<div ><i class="${iconShape} ${iconColor} icon" ></i><b>${ptk_utils.escapeHtml(name)}</b></div>`
    } else {
        let name = finding?.ruleName || info.name || meta?.name || info.identifiers?.summary || info.category
        icon = `<div><b>${ptk_utils.escapeHtml(name)}</b></div>`
    }

    const rawStatusCode = info?.response?.statusCode
    const statusString = rawStatusCode ? String(rawStatusCode) : ''
    const statusCode = Number.isFinite(Number(rawStatusCode)) ? Number(rawStatusCode) : null
    const is5xx = statusString.startsWith('5')
    const is4xx = !is5xx && statusString.startsWith('4')
    if (is5xx) {
        attackClass += " 5xx_status"
    } else if (is4xx) {
        attackClass += " 4xx_status"
    }

    return {
        icon,
        order,
        attackClass,
        severity: severityValue,
        isVuln,
        statusCode,
        is4xx,
        is5xx
    }
}

export function getMisc(info) {
    const meta = buildMiscMeta(info)
    return {
        icon: meta.icon,
        order: meta.order,
        attackClass: meta.attackClass,
        severity: meta.severity
    }
}

// Structured helper for counters to prevent drift from UI classification.
export function getMiscMeta(info) {
    return buildMiscMeta(info)
}

function getIconBySeverity(severity) {
    let normalized = String(severity || '').toLowerCase()
    if (normalized === 'informational') {
        normalized = 'info'
    }
    const visualMeta = SEVERITY_VISUALS[normalized] || { color: "grey", icon: "exclamation triangle", order: 5 }
    let icon = `<i class="${visualMeta.icon} ${visualMeta.color} icon"></i>`;
    return { icon: icon, order: visualMeta.order };
}

function sanitize(p) {
    return dompurify.sanitize(p, {
        ALLOWED_TAGS: ['p', 'ul', 'li', 'code', 'strong', 'em', 'a', 'br', 'pre', 'div', 'span'],
        ALLOWED_ATTR: ['href', 'target', 'rel', 'class', 'data-expanded', 'aria-expanded']
    });
}

function formatOwaspBadge(entry) {
    if (!entry || typeof entry !== "object") return ""
    const rawId = entry.id || ""
    if (!rawId || rawId === "unknown") return ""
    const id = rawId.toUpperCase()
    const version = entry.version && entry.version !== "unknown" ? `:${entry.version}` : ""
    const name = entry.name && entry.name !== "Unknown" ? ` - ${entry.name}` : ""
    return `${id}${version}${name}`
}

function renderOwaspChips(list) {
    if (!Array.isArray(list) || !list.length) return ""
    const chips = list
        .map(formatOwaspBadge)
        .filter(Boolean)
        .map(label => `<span class="ui tiny label">${ptk_utils.escapeHtml(label)}</span>`)
    if (!chips.length) return ""
    return sanitize(chips.join(" "))
}

function renderOwaspChip(entry) {
    return renderOwaspChips(entry ? [entry] : [])
}

function renderCweChips(list) {
    if (!Array.isArray(list) || !list.length) return ""
    const chips = list
        .map(code => String(code || "").trim())
        .filter(Boolean)
        .map(code => `<span class="ui tiny label">${ptk_utils.escapeHtml(code)}</span>`)
    if (!chips.length) return ""
    return sanitize(chips.join(" "))
}

function getPrimaryOwaspEntry(data = {}) {
    if (data?.owaspPrimary) return data.owaspPrimary
    if (Array.isArray(data?.owasp) && data.owasp.length) return data.owasp[0]
    return null
}

// Ensure highlight styles are present once
function ensureHighlightStyles() {
    if (document.getElementById('ptk-sast-highlight-styles')) return;
    const css = `
    .sast-highlight-source{ background: rgba(255,215,0,0.25); padding: 0 2px; border-radius:2px; }
    .sast-highlight-sink{ background: rgba(255,99,71,0.18); padding: 0 2px; border-radius:2px; }
    #source_details_code pre, #sink_details_code pre { white-space: pre-wrap; word-break: break-word; }
    .sast-trace-list { margin: 0; padding-left: 1.2em; }
    .sast-trace-list li { margin-bottom: 0.35em; }
    .sast-trace { margin: 0; }
    .sast-trace-view.full { display: none; }
    .sast-trace[data-expanded="true"] .sast-trace-view.full { display: block; }
    .sast-trace[data-expanded="true"] .sast-trace-view.collapsed { display: none; }
    .sast-trace-toggle { display: inline-block; margin-top: 4px; font-size: 12px; }
    .sast-trace-ellipsis { margin: 4px 0; font-style: italic; color: #555; }
    .iast-flow-list { display: flex; flex-direction: column; gap: 6px; margin-top: 6px; }
    .iast-flow-node { border: 1px solid #d4d4d5; padding: 6px 8px; border-radius: 4px; background: #fafafa; }
    .iast-flow-stage { font-size: 11px; font-weight: 600; color: #555; margin-bottom: 2px; }
    .iast-flow-label { font-size: 13px; }
    .iast-flow-op, .iast-flow-dom, .iast-flow-location { font-size: 12px; color: #666; }
    .iast-trace-separator { margin: 8px 0; border-top: 1px dashed #d4d4d5; }
    .iast-details-snippet { background:#f7f7f7; border:1px solid #ddd; padding:8px; border-radius:4px; min-height:80px; white-space:pre-wrap; }
    .iast-details-meta div { font-size:13px; color:#444; }
    `;
    const s = document.createElement('style');
    s.id = 'ptk-sast-highlight-styles';
    s.appendChild(document.createTextNode(css));
    document.head.appendChild(s);
}

// Render a snippet as sanitized HTML and optionally highlight the first occurrence
// of `needle` (already-trimmed raw text). Uses ptk_utils.escapeHtml to escape
// raw text before injecting highlight markup, then sanitizes the result.
const SNIPPET_CONTEXT_LINES = 2;

function renderSnippetWithHighlight(snippetRaw, needle, highlightClass, loc = null, options = {}) {
    const wrap = options.wrap !== false;
    const raw = String(snippetRaw || "");
    const needleStr = needle != null ? String(needle) : "";
    const escaped = ptk_utils.escapeHtml(raw);
    const BASE_SANITIZE = wrap
        ? { ALLOWED_TAGS: ['pre', 'code', 'span'], ALLOWED_ATTR: ['class'] }
        : { ALLOWED_TAGS: ['span'], ALLOWED_ATTR: ['class'] };
    if (!needleStr) {
        const html = wrap ? `<pre><code>${escaped}</code></pre>` : escaped;
        const cfg = wrap
            ? { ALLOWED_TAGS: ['pre', 'code'], ALLOWED_ATTR: [] }
            : { ALLOWED_TAGS: [], ALLOWED_ATTR: [] };
        return dompurify.sanitize(html, cfg);
    }
    const targetIdx = findNeedleIndexForLocation(raw, needleStr, loc);
    if (targetIdx === -1) {
        const escNeedle = ptk_utils.escapeHtml(needleStr);
        let highlighted = escaped;
        const idx = highlighted.indexOf(escNeedle);
        if (idx !== -1) {
            highlighted = highlighted.slice(0, idx)
                + `<span class="${highlightClass}">`
                + escNeedle
                + `</span>`
                + highlighted.slice(idx + escNeedle.length);
        }
        const html = wrap ? `<pre><code>${highlighted}</code></pre>` : highlighted;
        return dompurify.sanitize(html, BASE_SANITIZE);
    }
    const before = raw.slice(0, targetIdx);
    const target = raw.slice(targetIdx, targetIdx + needleStr.length);
    const after = raw.slice(targetIdx + needleStr.length);
    const highlighted = `${ptk_utils.escapeHtml(before)}<span class="${highlightClass}">${ptk_utils.escapeHtml(target)}</span>${ptk_utils.escapeHtml(after)}`;
    const html = wrap ? `<pre><code>${highlighted}</code></pre>` : highlighted;
    return dompurify.sanitize(html, BASE_SANITIZE);
}

function findNeedleIndexForLocation(raw, needle, loc) {
    if (!needle) return -1;
    const lines = raw.split('\n');
    const occurrences = [];
    let offset = 0;
    for (let i = 0; i < lines.length; i++) {
        let searchIdx = -1;
        while ((searchIdx = lines[i].indexOf(needle, searchIdx + 1)) !== -1) {
            occurrences.push({ offset: offset + searchIdx, line: i });
        }
        offset += lines[i].length + 1;
    }
    if (!occurrences.length) {
        return raw.indexOf(needle);
    }
    const startLine = Number(loc?.start?.line);
    if (!Number.isFinite(startLine)) {
        return occurrences[0].offset;
    }
    const contextUsed = Math.min(SNIPPET_CONTEXT_LINES, Math.max(0, startLine - 1));
    let targetLine = contextUsed;
    if (targetLine >= lines.length) {
        targetLine = lines.length - 1;
    }
    let best = occurrences[0];
    let bestDiff = Math.abs(best.line - targetLine);
    for (const occ of occurrences) {
        const diff = Math.abs(occ.line - targetLine);
        if (diff < bestDiff) {
            best = occ;
            bestDiff = diff;
        }
    }
    return best.offset;
}

function formatLocation(loc) {
    if (!loc) return '';
    const start = loc.start || loc;
    const line = typeof start?.line === 'number' ? `L${start.line}` : '';
    const column = typeof start?.column === 'number' ? `C${start.column}` : '';
    const parts = [line, column].filter(Boolean);
    return parts.join(':');
}

function formatPoint(point) {
    if (!point || typeof point.line !== 'number') return '—';
    const line = `L${point.line}`;
    const column = typeof point.column === 'number' ? `C${point.column}` : '';
    return column ? `${line}:${column}` : line;
}

function normalizeSnippet(snippet) {
    if (!snippet) return '';
    const unified = String(snippet).replace(/\r\n?/g, '\n');
    const lines = unified.split('\n');
    while (lines.length && !lines[0].trim()) lines.shift();
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
    return lines.join('\n');
}

function formatTaintTrace(trace) {
    if (!Array.isArray(trace) || !trace.length) return '';
    ensureHighlightStyles();

    const displayKind = (kind, idx, total) => {
        if (kind) return kind;
        if (idx === 0) return 'source';
        if (idx === total - 1) return 'sink';
        return 'step';
    };

    const renderList = (steps, insertEllipsis = false) => {
        const items = steps.map((step, idx) => {
            const total = steps.length;
            const kind = displayKind(step?.kind, idx, total);
            const parts = [];
            parts.push(`<strong>${ptk_utils.escapeHtml(kind)}</strong>`);
            if (step?.label) parts.push(`<code>${ptk_utils.escapeHtml(step.label)}</code>`);
            const file = step?.file;
            const locText = formatLocation(step?.loc);
            if (file || locText) {
                const combined = [file ? ptk_utils.escapeHtml(file) : '', locText ? ptk_utils.escapeHtml(locText) : '']
                    .filter(Boolean)
                    .join(' ');
                if (combined) parts.push(`<span>${combined}</span>`);
            }
            return `<li>${parts.join(' — ')}</li>`;
        });
        if (insertEllipsis && steps.length >= 2) {
            items.splice(1, 0, '<li class="sast-trace-ellipsis">…</li>');
        }
        return `<ul class="sast-trace-list">${items.join('')}</ul>`;
    };

    const total = trace.length;
    if (total <= 2) {
        return `<div class="sast-trace" data-expanded="true">${renderList(trace)}</div>`;
    }

    const collapsedSteps = [trace[0], trace[trace.length - 1]];
    const collapsedList = renderList(collapsedSteps, true);
    const fullList = renderList(trace);
    return `
        <a href="#" class="sast-trace-toggle" aria-expanded="false">Show full trace</a>
        <div class="sast-trace" data-expanded="false">
            
            <div class="sast-trace-view collapsed">
                ${collapsedList}
            </div>
            <div class="sast-trace-view full">${fullList}</div>
        </div>
    `;
}

function formatIastFlow(flow) {
    if (!Array.isArray(flow) || !flow.length) return '';
    const rows = flow.map((node, idx) => {
        const stage = sanitize(String(node?.stage || `step ${idx + 1}`)).toUpperCase();
        const label = sanitize(String(node?.label || node?.key || `Node ${idx + 1}`));
        const op = node?.op ? `<div class="iast-flow-op">Operation: ${sanitize(String(node.op))}</div>` : '';
        const dom = node?.domPath ? `<div class="iast-flow-dom">DOM: <code>${sanitize(String(node.domPath))}</code></div>` : '';
        const loc = node?.location ? `<div class="iast-flow-location">${sanitize(String(node.location))}</div>` : '';
        return `
            <div class="iast-flow-node">
                <div class="iast-flow-stage">${stage}</div>
                <div class="iast-flow-details">
                    <div class="iast-flow-label"><strong>${label}</strong></div>
                    ${op}
                    ${dom}
                    ${loc}
                </div>
            </div>
        `;
    }).join('');
    return `<div class="iast-flow-list">${rows}</div>`;
}

// helper to create safe anchor elements
const makeLinkItem = (title, url) => {
    const item = document.createElement('div');
    item.className = 'item';
    const content = document.createElement('div');
    content.className = 'content';
    const a = document.createElement('a');
    a.className = 'header';
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.href = url;
    a.textContent = title;
    const desc = document.createElement('div');
    desc.className = 'description';
    const a2 = document.createElement('a');
    a2.target = '_blank';
    a2.rel = 'noopener noreferrer';
    a2.href = url;
    a2.textContent = url;
    desc.appendChild(a2);
    content.appendChild(a);
    content.appendChild(desc);
    item.appendChild(content);
    return item;
};

function mergeLinkMap(...sources) {
    const map = {}
    sources.forEach(src => {
        if (!src || typeof src !== 'object') return
        Object.entries(src).forEach(([key, value]) => {
            if (!key || value === undefined || value === null) return
            map[key] = value
        })
    })
    return map
}

function makeSafeAnchor(url, label) {
    const a = document.createElement('a');
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.href = url;
    a.textContent = label || url;
    a.title = url; // full URL on hover
    return a;
}

function renderLocationInto(spanEl, { isInline, displayText, href }) {
    // Clear any previous content
    while (spanEl.firstChild) spanEl.removeChild(spanEl.firstChild);

    if (isInline || !href) {
        // Inline code location (e.g., "inline‐onclick[#0] in https://...")
        spanEl.textContent = displayText || 'inline';
    } else {
        // External file: clickable, safe anchor
        spanEl.appendChild(makeSafeAnchor(href, displayText || href));
    }
}

function resolveConfidence(info) {
    const candidates = [
        info?.confidence,
        info?.finding?.confidence,
        info?.metadata?.confidence,
        info?.module_metadata?.confidence,
        info?.meta?.confidence
    ];
    for (const value of candidates) {
        if (value === undefined || value === null || value === "") continue;
        const num = Number(value);
        if (Number.isFinite(num)) {
            return Math.max(0, Math.min(100, num));
        }
    }
    return null;
}

function formatConfidenceValue(confidence) {
    if (!Number.isFinite(confidence)) return null;
    return Math.round(confidence);
}

function renderConfidenceLine(confidence, { label = "Confidence" } = {}) {
    const value = formatConfidenceValue(confidence);
    if (value === null) return "";
    const safeLabel = ptk_utils.escapeHtml(label);
    return `<div class="description"><p>${safeLabel}: <b><i>${value}</i></b></p></div>`;
}

function renderConfidenceBadge(confidence) {
    const value = formatConfidenceValue(confidence);
    if (value === null) return "";
    return `<span class="ui tiny label" style="margin-left:6px;">Confidence: ${value}</span>`;
}

function appendConfidenceToTitle(titleHtml, confidence) {
    const badge = renderConfidenceBadge(confidence);
    if (!badge) return titleHtml;
    return `${titleHtml} ${badge}`;
}

export function bindAttack(info, original, index, requestId = -1) {
    if (!info) return ''
    const finding = info.finding || null
    info.metadata = info.metadata && typeof info.metadata === 'object' ? info.metadata : {}
    let proof = "";
    let param = "";

    let misc = getMisc(info);
    let icon = misc.icon,
        order = misc.order,
        attackClass = misc.attackClass;
    const severityAttr = misc.severity || ''

    if (info.proof)
        proof = `<div class="description"><p>Proof: <b><i name="proof">${ptk_utils.escapeHtml(
            info.proof
        )}</i></b></p></div>`;
    const attackedName = info.param || info.metadata?.attacked?.name || null
    if (attackedName) {
        param = `<div class="description"><p>Param: <b><i name="param">${ptk_utils.escapeHtml(
            attackedName
        )}</i></b></p></div>`;
    }
    let target = info.request?.url ? ptk_utils.escapeHtml(info.request.url) : original?.request?.url ? ptk_utils.escapeHtml(original.request.url) : "";
    const safeRequestId = requestId === null || requestId === undefined || requestId === ''
        ? '__ptk_unknown__'
        : String(requestId)
    let item = `
                <div class="ui message attack_info ${attackClass} ${ptk_utils.escapeHtml(safeRequestId)}"  data-order="${order}" data-severity="${ptk_utils.escapeHtml(severityAttr)}" data-request-id="${ptk_utils.escapeHtml(safeRequestId)}">
                ${icon}
                <div class="description">
                    <p>URL: <a href="${target}" target="_blank">${target}</a></p>
                </div>
                ${proof}
                ${param}
                <div class="ui left floated">
                    <a href="#" class="attack_details" data-requestId="${requestId}" data-index="${index}">Details</a>
                </div>
                </div>`;

    return item;
}

function getIASTContext(context, { includeElement = true } = {}) {
    if (!context || typeof context !== "object") return "";
    let res = "";
    let keys = Object.keys(context);
    if (keys.includes("element")) {
        res +=
            "<b>At element:</b> <i> " +
            ptk_utils.escapeHtml(context["element"].substring(0, 200)) +
            "</i>";
        if (keys.includes("position")) {
            res +=
                "<b>at position:</b> <i> " +
                ptk_utils.escapeHtml(context["position"]) +
                "</i>";
        }
        if (keys.includes("domPath")) {
            res +=
                " <b>path:</b> <i>" +
                ptk_utils.escapeHtml(context["domPath"].substring(0, 200)) +
                "</i>";
        }
    }
    if (includeElement) {
        if (keys.includes("tagName")) {
            res += " <b>tag:</b> <i>" + ptk_utils.escapeHtml(context["tagName"]) + "</i>";
        }
        if (keys.includes("elementId")) {
            res += " <b>id:</b> <i>" + ptk_utils.escapeHtml(context["elementId"]) + "</i>";
        }
        if (keys.includes("attribute")) {
            res += " <b>attr:</b> <i>" + ptk_utils.escapeHtml(context["attribute"]) + "</i>";
        }
    }
    if (keys.includes("requestUrl")) {
        res += " <b>request:</b> <i>" + ptk_utils.escapeHtml(context["requestUrl"]) + "</i>";
    }
    if (keys.includes("method")) {
        res += " <b>method:</b> <i>" + ptk_utils.escapeHtml(context["method"]) + "</i>";
    }
    if (keys.includes("headerName")) {
        res += " <b>header:</b> <i>" + ptk_utils.escapeHtml(context["headerName"]) + "</i>";
    }
    if (keys.includes("value")) {
        let raw = context["value"];
        if (Array.isArray(raw)) {
            raw = raw.length ? raw[0] : '';
        }
        if (raw !== undefined && raw !== null) {
            const v = typeof raw === 'string' ? raw : String(raw);
            res += " <b>with value:</b> <i>" + ptk_utils.escapeHtml(v) + "</i>";
        }
    }
    // Object.keys(context).forEach(item => {
    //     res += ptk_utils.escapeHtml(item) + ": " + ptk_utils.escapeHtml(context[item])
    // })
    return res;
}

function buildIastFlowSummary(flow) {
    if (!Array.isArray(flow) || !flow.length) return null;
    const parts = flow.map(node => {
        if (!node) return '';
        let label = node.label || node.key || '';
        if (node.elementId) {
            label += `#${node.elementId}`;
        }
        if (node.attribute) {
            label += `.${node.attribute}`;
        }
        return label;
    }).filter(Boolean);
    return parts.length ? parts.join(' -> ') : null;
}

function buildTraceSummary(trace) {
    if (!trace) return null;
    const lines = String(trace).split('\n').map(line => line.trim()).filter(Boolean);
    const frames = lines.slice(1).filter(line => {
        if (line.includes('chrome-extension://') || line.includes('moz-extension://')) return false;
        if (line.includes('ptk/content/iast.js')) return false;
        return true;
    });
    return frames[0] || null;
}

function buildSourceDisplay(evidence, info) {
    const rawSources = evidence?.raw?.sources || null;
    const entry =
        evidence?.primarySource ||
        (Array.isArray(evidence?.sources) ? evidence.sources[0] : null) ||
        (Array.isArray(rawSources) ? rawSources[0] : null);
    const key = entry?.key || evidence?.sourceKey || null;
    const kind = entry?.sourceKind || entry?.kind || evidence?.sourceKind || null;
    const labelFromKey = (() => {
        if (!key) return null;
        if (key.startsWith('localStorage:')) return `localStorage["${key.slice(13)}"]`;
        if (key.startsWith('sessionStorage:')) return `sessionStorage["${key.slice(15)}"]`;
        if (key.startsWith('cookie:')) return `Cookie "${key.slice(7)}"`;
        if (key.startsWith('inline:')) return `Inline value "${key.slice(7)}"`;
        if (key.startsWith('query:')) return `Query parameter "${key.slice(6)}"`;
        if (key.startsWith('hashQuery:')) return `Hash query parameter "${key.slice(10)}"`;
        if (key.startsWith('postMessage:')) return `postMessage from ${key.slice(12)}`;
        if (key === 'window.name') return 'window.name';
        return key;
    })();
    const rawLabel =
        entry?.label ||
        labelFromKey ||
        entry?.display ||
        evidence?.taintSource ||
        info?.source ||
        'n/a';
    const rawPreview =
        entry?.sourceValuePreview ||
        entry?.raw ||
        entry?.value ||
        evidence?.sourceValuePreview ||
        null;
    const preview = rawPreview ? String(rawPreview) : '';
    const trimmedPreview = preview.length > 80 ? `${preview.slice(0, 77)}...` : preview;
    const normalizedLabel = String(rawLabel);
    const normalizedKey = key ? String(key) : '';
    const safePreview =
        trimmedPreview && trimmedPreview !== normalizedLabel && trimmedPreview !== normalizedKey
            ? trimmedPreview
            : '';
    return {
        label: normalizedLabel,
        preview: safePreview,
        kind,
        key: normalizedKey
    };
}

function humanizeSourceLabel(label) {
    if (!label) return label;
    const str = String(label);
    if (str.startsWith('localStorage:')) return `localStorage["${str.slice(13)}"]`;
    if (str.startsWith('sessionStorage:')) return `sessionStorage["${str.slice(15)}"]`;
    if (str.startsWith('cookie:')) return `Cookie "${str.slice(7)}"`;
    if (str.startsWith('inline:')) return `Inline value "${str.slice(7)}"`;
    if (str.startsWith('query:')) return `Query parameter "${str.slice(6)}"`;
    if (str.startsWith('hashQuery:')) return `Hash query parameter "${str.slice(10)}"`;
    if (str.startsWith('postMessage:')) return `postMessage from ${str.slice(12)}`;
    return str;
}

export function bindIASTAttack(info, requestId = -1) {
    const evidence = getIASTEvidencePayload(info)
    const severity = (info?.severity || evidence?.raw?.severity || 'info').toString().toLowerCase()
    const meta = evidence?.raw?.meta || {}
    info.success = true; // to get proper misc
    info.name = meta.ruleName
    const { icon, order, attackClass } = getMisc( info )
    const title = meta.ruleName || info?.category || info?.type || evidence?.raw?.type || 'IAST finding'
    const sourceDisplay = buildSourceDisplay(evidence, info)
    const primaryClassCard =
        evidence?.primaryClass
        || evidence?.raw?.primaryClass
        || info?.primaryClass
        || null
    const observationCard = primaryClassCard === 'observation'
    const hybridCard = primaryClassCard === 'hybrid'
    const sourceKind = sourceDisplay.kind || null
    const sinkLabel = evidence?.sinkId || evidence?.raw?.sink || info?.sink || 'n/a'
    const contextPayload = evidence?.context || evidence?.raw?.context || info?.context || {}
    const sinkContext = Object.assign({}, evidence?.sinkContext || {}, {
        requestUrl: evidence?.sinkContext?.requestUrl || contextPayload?.requestUrl || null,
        method: evidence?.sinkContext?.method || contextPayload?.method || null,
        headerName: evidence?.sinkContext?.headerName || contextPayload?.headerName || null,
        destUrl: evidence?.sinkContext?.destUrl || contextPayload?.destUrl || evidence?.networkTarget?.url || null,
        destOrigin: evidence?.sinkContext?.destOrigin || contextPayload?.destOrigin || evidence?.networkTarget?.origin || null,
        isCrossOrigin: evidence?.sinkContext?.isCrossOrigin ?? contextPayload?.isCrossOrigin ?? evidence?.networkTarget?.isCrossOrigin ?? null,
        tagName: evidence?.sinkContext?.tagName || contextPayload?.tagName || null,
        domPath: evidence?.sinkContext?.domPath || contextPayload?.domPath || null,
        attribute: evidence?.sinkContext?.attribute || contextPayload?.attribute || null,
        elementId: evidence?.sinkContext?.elementId || contextPayload?.elementId || null
    })
    const context = getIASTContext(contextPayload, { includeElement: false })
    const trace = evidence?.trace || evidence?.raw?.trace || info?.trace || ''
    const traceSummary = evidence?.traceSummary || evidence?.raw?.traceSummary || buildTraceSummary(trace)
    const flowSummary = evidence?.flowSummary || evidence?.raw?.flowSummary || buildIastFlowSummary(contextPayload.flow)
    const targetUrl = resolveIASTLocation(info, evidence) || 'n/a'
    const safeTarget = ptk_utils.escapeHtml(targetUrl)
    const requestAttr = info?.requestKey ? ` data-request-key="${ptk_utils.escapeHtml(info.requestKey)}"` : ''
    const attr = (val) => ptk_utils.escapeHtml(String(val || ''))

    const traceMarkup = formatTaintTrace(trace)
    const traceHtmlRaw = traceMarkup ? sanitize(traceMarkup) : (trace ? sanitize(ptk_utils.escapeHtml(trace)) : '')
    const flowMarkup = Array.isArray(contextPayload.flow) ? formatIastFlow(contextPayload.flow) : ''
    const flowHtml = flowMarkup ? sanitize(flowMarkup) : ''
    const traceSections = []
    if (traceHtmlRaw) traceSections.push(`<pre>${traceHtmlRaw}</pre>`)

    const traceContent = traceSections.length ? traceSections.join('<div class="iast-trace-separator"></div>') : 'n/a'
    const owaspEntry = getPrimaryOwaspEntry(info)
    const owaspChip = renderOwaspChip(owaspEntry)
    const confidenceLine = ''
    const sinkDetails = []
    if (sinkContext?.requestUrl) {
        const method = sinkContext.method ? `${ptk_utils.escapeHtml(String(sinkContext.method))} ` : ''
        sinkDetails.push(`<div>Request: <b><i>${method}${ptk_utils.escapeHtml(String(sinkContext.requestUrl))}</i></b></div>`)
    }
    if (sinkContext?.destUrl) {
        sinkDetails.push(`<div>Destination: <b><i>${ptk_utils.escapeHtml(String(sinkContext.destUrl))}</i></b></div>`)
    }
    if (sinkContext?.destOrigin && typeof sinkContext.isCrossOrigin === 'boolean') {
        const crossLabel = sinkContext.isCrossOrigin ? 'cross-origin' : 'same-origin'
        sinkDetails.push(`<div>Origin: <b><i>${ptk_utils.escapeHtml(String(sinkContext.destOrigin))}</i></b> (${crossLabel})</div>`)
    }
    if (sinkContext?.headerName) {
        sinkDetails.push(`<div>Header: <b><i>${ptk_utils.escapeHtml(String(sinkContext.headerName))}</i></b></div>`)
    }
    // Element/tag details should appear in the Details modal, not the card.

    return `
        <div class="ui message attack_info ${attackClass} iast_attack_card ${requestId}" style="overflow:auto" data-order="${order}" data-severity="${attr(severity)}"${requestAttr}>
            ${icon}
            <div class="description">
                <div>Source: <b><i>${ptk_utils.escapeHtml(observationCard ? 'Observed' : sourceDisplay.label)}</i></b></div>
                ${''}
                <div>${ptk_utils.escapeHtml(observationCard || hybridCard ? 'Used In Operation' : 'Sink')}: <b><i>${ptk_utils.escapeHtml(sinkLabel)}</i></b></div>
                ${sinkDetails.join('')}
                ${confidenceLine}
                ${''}
                ${flowSummary ? `<div>Flow: <b><i>${ptk_utils.escapeHtml(String(flowSummary))}</i></b></div>` : ''}
                ${context ? `<div>${context}</div>` : ''}
                <div>URL: <a href="${safeTarget}" target="_blank" rel="noreferrer">${safeTarget}</a></div>
                ${''}
                <div class="iast-trace-row">
                    <a href="#" class="iast-trace-toggle" data-visible="false">Show trace</a>
                    <div class="iast-trace-content" style="display:none; margin-top: 8px;">${traceContent}</div>
                </div>
                <div class="iast-details-row">
                    <a href="#" class="iast-attack-details" data-index="${attr(info.__index ?? requestId)}">Details</a>
                </div>
            </div>
        </div>
    `
}

function buildIastDetailMeta(node, fallbackLabel = 'Not available', { context = null, role = null, sourcePreview = null, sinkPreview = null, sourceKind = null, ruleInfo = null, iastMeta = null } = {}) {
    const safeFallback = sanitize(ptk_utils.escapeHtml(String(fallbackLabel || 'Not available')))
    const rows = []
    if (!node) {
        if (role === 'sink' && context) {
            if (ruleInfo?.trust?.level || ruleInfo?.trust?.decision) {
                const trustLabel = formatIastDisplayLabel('trust', ruleInfo.trust.level, ruleInfo.trust.level)
                const trustLine = [trustLabel, ruleInfo.trust.decision].filter(Boolean).join(' / ')
                rows.push(`<div><strong>Trust:</strong> ${sanitize(ptk_utils.escapeHtml(String(trustLine)))}</div>`)
            }
            if (ruleInfo?.primaryClass) {
                const classLabel = formatIastDisplayLabel('primaryClass', ruleInfo.primaryClass, ruleInfo.primaryClass)
                rows.push(`<div><strong>Class:</strong> ${sanitize(ptk_utils.escapeHtml(String(classLabel)))}</div>`)
            }
            if (ruleInfo?.detection?.reason || ruleInfo?.detection?.dataKind) {
                const parts = []
                if (ruleInfo.detection.reason) {
                    const reasonLabel = formatIastDisplayLabel('reasons', ruleInfo.detection.reason, ruleInfo.detection.reason)
                    parts.push(`reason=${reasonLabel}`)
                }
                if (ruleInfo.detection.dataKind) parts.push(`kind=${ruleInfo.detection.dataKind}`)
                rows.push(`<div><strong>Detection:</strong> ${sanitize(ptk_utils.escapeHtml(parts.join(', ')))}</div>`)
            }
            if (context.destUrl) {
                rows.push(`<div><strong>Destination:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.destUrl)))}</div>`)
            }
            if (context.destOrigin && typeof context.isCrossOrigin === 'boolean') {
                rows.push(`<div><strong>Origin:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.destOrigin)))} (${context.isCrossOrigin ? 'cross-origin' : 'same-origin'})</div>`)
            }
            if (context.headerName) {
                rows.push(`<div><strong>Header:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.headerName)))}</div>`)
            }
            if (context.storageArea || context.storageKey) {
                const area = context.storageArea ? `${sanitize(ptk_utils.escapeHtml(String(context.storageArea)))} ` : ''
                rows.push(`<div><strong>Storage:</strong> ${area}${sanitize(ptk_utils.escapeHtml(String(context.storageKey || '')))}</div>`)
            }
            if (context.cookieName) {
                rows.push(`<div><strong>Cookie:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.cookieName)))}</div>`)
            }
            if (context.element) {
                rows.push(`<div><strong>Element:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.element)))}</div>`)
            }
            if (context.tagName) {
                rows.push(`<div><strong>Tag:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.tagName)))}</div>`)
            }
            if (context.elementId) {
                rows.push(`<div><strong>Element ID:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.elementId)))}</div>`)
            }
            if (context.attribute) {
                rows.push(`<div><strong>Attribute:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.attribute)))}</div>`)
            }
            if (context.domPath) {
                rows.push(`<div><strong>DOM Path:</strong> <div class="iast-dom-path"><code>${sanitize(ptk_utils.escapeHtml(String(context.domPath)))}</code></div></div>`)
            }
            if (sinkPreview) {
                rows.push(`<div><strong>Value:</strong> <code>${sanitize(ptk_utils.escapeHtml(String(sinkPreview)))}</code></div>`)
            }
            if (rows.length) return rows.join('')
        }
        return `<div>${safeFallback}</div>`
    }
    const label = node.label || node.key || fallbackLabel || 'Not available'
    const nodeKey = node.key ? String(node.key) : ''
    const nodeKind = node.sourceKind || node.kind || sourceKind || null
    if (role !== 'source' && role !== 'sink') {
        rows.push(`<div><strong>Label:</strong> ${sanitize(ptk_utils.escapeHtml(String(label)))}</div>`)
    }
    if (role === 'source') {
        if (nodeKind) {
            rows.push(`<div><strong>Kind:</strong> ${sanitize(ptk_utils.escapeHtml(String(nodeKind)))}</div>`)
        }
        if (nodeKey) {
            rows.push(`<div><strong>Key:</strong> ${sanitize(ptk_utils.escapeHtml(nodeKey))}</div>`)
        }
        if (iastMeta?.primaryClass) {
            const classLabel = formatIastDisplayLabel('primaryClass', iastMeta.primaryClass, iastMeta.primaryClass)
            rows.push(`<div><strong>Class:</strong> ${sanitize(ptk_utils.escapeHtml(String(classLabel)))}</div>`)
        }
        if (iastMeta?.origin) {
            const originText = iastMeta.origin.url || iastMeta.origin.detail || iastMeta.origin.kind || 'unknown'
            rows.push(`<div><strong>Origin:</strong> ${sanitize(ptk_utils.escapeHtml(String(originText)))}</div>`)
        } else if (nodeKind === 'inline' || nodeKey.startsWith('inline:')) {
            const elementId = nodeKey.startsWith('inline:') ? nodeKey.slice(7) : (node.elementId || 'unknown')
            rows.push(`<div><strong>Origin:</strong> ${sanitize(ptk_utils.escapeHtml(`DOM input (${elementId})`))}</div>`)
        }
        if (iastMeta?.observedAt?.kind) {
            const key = iastMeta.observedAt.key ? `["${iastMeta.observedAt.key}"]` : ''
            const cookie = iastMeta.observedAt.cookieName ? ` "${iastMeta.observedAt.cookieName}"` : ''
            rows.push(`<div><strong>Observed In:</strong> ${sanitize(ptk_utils.escapeHtml(`${iastMeta.observedAt.kind}${key}${cookie}`))}</div>`)
        }
        if (iastMeta?.detection?.reason || iastMeta?.detection?.dataKind) {
            const parts = []
            if (iastMeta?.detection?.reason) {
                const reasonLabel = formatIastDisplayLabel('reasons', iastMeta.detection.reason, iastMeta.detection.reason)
                parts.push(`reason=${reasonLabel}`)
            }
            if (iastMeta?.detection?.dataKind) {
                parts.push(`kind=${iastMeta.detection.dataKind}`)
            }
            rows.push(`<div><strong>Detection:</strong> ${sanitize(ptk_utils.escapeHtml(parts.join(', ')))}</div>`)
        }
    }
    const nodeDomPath = node.domPath ? String(node.domPath) : ''
    const nodeElementId = node.elementId ? String(node.elementId) : ''
    if (nodeDomPath && role !== 'sink') {
        rows.push(`<div><strong>DOM Path:</strong> <pre class="iast-dom-path"><code>${sanitize(ptk_utils.escapeHtml(nodeDomPath))}</code></pre></div>`)
    }
    if (nodeElementId && role !== 'sink') {
        rows.push(`<div><strong>Element ID:</strong> ${sanitize(ptk_utils.escapeHtml(nodeElementId))}</div>`)
    }
    if (node.location) {
        rows.push(`<div><strong>${role === 'source' ? 'Origin' : 'Location'}:</strong> ${sanitize(ptk_utils.escapeHtml(String(node.location)))}</div>`)
    }
    if (node.op) {
        rows.push(`<div><strong>Operation:</strong> ${sanitize(ptk_utils.escapeHtml(String(node.op)))}</div>`)
    }
    if (role === 'sink') {
        const sinkTag = context?.tagName || node?.tagName || node?.label || null
        const sinkLabel = label || null
        const sinkElementId = context?.elementId || nodeElementId || null
        const parts = []
        if (sinkTag) parts.push(`Tag: ${sinkTag}`)
        if (sinkLabel) parts.push(`Label: ${sinkLabel}`)
        if (sinkElementId) parts.push(`Element ID: ${sinkElementId}`)
        if (parts.length) {
            rows.push(`<div><strong>Element:</strong> ${sanitize(ptk_utils.escapeHtml(parts.join(' -> ')))}</div>`)
        }
        if (ruleInfo) {
            if (ruleInfo.moduleId) {
                rows.push(`<div><strong>Module ID:</strong> ${sanitize(ptk_utils.escapeHtml(String(ruleInfo.moduleId)))}</div>`)
            }
            if (Array.isArray(ruleInfo.allowedSources) && ruleInfo.allowedSources.length) {
                rows.push(`<div><strong>Allowed Sources:</strong> ${sanitize(ptk_utils.escapeHtml(ruleInfo.allowedSources.join(', ')))}</div>`)
            }
            // Related sinks are not shown in the Details view.
            if (ruleInfo.trust?.level || ruleInfo.trust?.decision) {
                const trustLabel = formatIastDisplayLabel('trust', ruleInfo.trust.level, ruleInfo.trust.level)
                const trustLine = [trustLabel, ruleInfo.trust.decision].filter(Boolean).join(' / ')
                rows.push(`<div><strong>Trust:</strong> ${sanitize(ptk_utils.escapeHtml(String(trustLine)))}</div>`)
            }
            if (ruleInfo.primaryClass) {
                const classLabel = formatIastDisplayLabel('primaryClass', ruleInfo.primaryClass, ruleInfo.primaryClass)
                rows.push(`<div><strong>Class:</strong> ${sanitize(ptk_utils.escapeHtml(String(classLabel)))}</div>`)
            }
            if (ruleInfo.detection?.reason || ruleInfo.detection?.dataKind) {
                const parts = []
                if (ruleInfo.detection.reason) {
                    const reasonLabel = formatIastDisplayLabel('reasons', ruleInfo.detection.reason, ruleInfo.detection.reason)
                    parts.push(`reason=${reasonLabel}`)
                }
                if (ruleInfo.detection.dataKind) parts.push(`kind=${ruleInfo.detection.dataKind}`)
                rows.push(`<div><strong>Detection:</strong> ${sanitize(ptk_utils.escapeHtml(parts.join(', ')))}</div>`)
            }
            if (ruleInfo.suppression?.suppressed) {
                const supParts = []
                if (ruleInfo.suppression.rule) supParts.push(`rule=${ruleInfo.suppression.rule}`)
                if (ruleInfo.suppression.reason) supParts.push(`reason=${ruleInfo.suppression.reason}`)
                rows.push(`<div><strong>Suppressed:</strong> ${sanitize(ptk_utils.escapeHtml(supParts.join(', ') || 'yes'))}</div>`)
            }
        }
        if (context?.headerName) {
            rows.push(`<div><strong>Header:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.headerName)))}</div>`)
        }
        if (context?.storageArea || context?.storageKey) {
            const area = context.storageArea ? `${sanitize(ptk_utils.escapeHtml(String(context.storageArea)))} ` : ''
            rows.push(`<div><strong>Storage:</strong> ${area}${sanitize(ptk_utils.escapeHtml(String(context.storageKey || '')))}</div>`)
        }
        if (context?.cookieName) {
            rows.push(`<div><strong>Cookie:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.cookieName)))}</div>`)
        }
        if (context?.cookieAttributes && typeof context.cookieAttributes === 'object') {
            const attrs = Object.entries(context.cookieAttributes)
                .map(([k, v]) => (v === true ? k : `${k}=${v}`))
                .join('; ');
            if (attrs) {
                rows.push(`<div><strong>Cookie Flags:</strong> ${sanitize(ptk_utils.escapeHtml(attrs))}</div>`)
            }
        }
        if (!ruleInfo?.observation && context?.element) {
            rows.push(`<div><strong>Element:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.element)))}</div>`)
        }
        // Element ID is included in the combined Element line above.
        if (context?.attribute) {
            rows.push(`<div><strong>Attribute:</strong> ${sanitize(ptk_utils.escapeHtml(String(context.attribute)))}</div>`)
        }
        if (!ruleInfo?.observation && context?.domPath) {
            const ctxDomPath = String(context.domPath)
            if (!nodeDomPath || nodeDomPath !== ctxDomPath) {
                rows.push(`<div><strong>DOM Path:</strong> <pre class="iast-dom-path"><code>${sanitize(ptk_utils.escapeHtml(ctxDomPath))}</code></pre></div>`)
            } else if (nodeDomPath) {
                rows.push(`<div><strong>DOM Path:</strong> <pre class="iast-dom-path"><code>${sanitize(ptk_utils.escapeHtml(nodeDomPath))}</code></pre></div>`)
            }
        } else if (!ruleInfo?.observation && nodeDomPath) {
            rows.push(`<div><strong>DOM Path:</strong> <pre class="iast-dom-path"><code>${sanitize(ptk_utils.escapeHtml(nodeDomPath))}</code></pre></div>`)
        }
    }
    return rows.join('')
}

function getIastDetailSnippet(node, context, fallback = '') {
    if (node && node.value) return String(node.value)
    if (context && context.value) return String(context.value)
    return fallback || ''
}

export function bindAttackDetails_IAST(info = {}) {
    resetFindingModal();
    toggleSection("#finding_source_sink_section", true);
    const evidence = getIASTEvidencePayload(info) || {}
    const debugUi = localStorage.getItem('ptk_iast_ui_debug') === '1'
        || sessionStorage.getItem('ptk_iast_ui_debug') === '1'
        || window.__PTK_IAST_UI_DEBUG__ === true
        || (typeof location !== 'undefined' && location.search.includes('iast_debug=1'))
    const context = evidence?.context || evidence?.raw?.context || info?.context || {}
    const flowSummary = evidence?.flowSummary || evidence?.raw?.flowSummary || buildIastFlowSummary(context?.flow)
    const sinkContextMerged = Object.assign({}, context, evidence?.sinkContext || {})
    const flow = Array.isArray(context?.flow) ? context.flow : []
    const category = info?.category || info?.type || evidence?.raw?.type || 'IAST finding'
    const ruleName = info?.ruleName
        || evidence?.raw?.meta?.ruleName
        || info?.metadata?.name
        || info?.module_metadata?.name
        || category
    const overrideInfo = {
        ...info,
        success: info.success ?? true,
        type: info.type || 'iast',
        name: ruleName,
        metadata: { ...(info.metadata || {}), name: ruleName }
    }
    if (info.finding) {
        overrideInfo.finding = { ...info.finding, ruleName }
    }
    const titleMeta = getMisc(overrideInfo)
    const modalTitle = titleMeta.icon || `<div><b>${ptk_utils.escapeHtml(ruleName)}</b></div>`
    setFindingModalTitle(dompurify.sanitize(modalTitle, MODAL_TITLE_SANITIZE_CONFIG))

    const description = info?.description || info?.metadata?.description || info?.meta?.description || evidence?.raw?.meta?.description || ''
    const recommendation = info?.recommendation || info?.metadata?.recommendation || info?.meta?.recommendation || evidence?.raw?.meta?.recommendation || ''
    const links = mergeLinkMap(
        info?.links,
        info?.metadata?.links,
        info?.meta?.links,
        evidence?.raw?.meta?.links,
        info?.module_metadata?.links
    )

    const fallbackPrimarySource = evidence?.primarySource || (Array.isArray(evidence?.sources) ? evidence.sources[0] : null)
    const sourceNode = flow.find(node => node?.stage === 'source')
        || flow[0]
        || (fallbackPrimarySource
            ? {
                stage: 'source',
                label: fallbackPrimarySource.label || fallbackPrimarySource.key || null,
                key: fallbackPrimarySource.key || null,
                location: fallbackPrimarySource.location || null,
                domPath: fallbackPrimarySource.domPath || null,
                elementId: fallbackPrimarySource.elementId || null,
                attribute: fallbackPrimarySource.attribute || null,
                value: fallbackPrimarySource.raw || fallbackPrimarySource.value || null,
                op: fallbackPrimarySource.op || null
            }
            : null)
    let sinkNode = flow.find(node => node?.stage === 'sink') || flow[flow.length - 1] || null
    if (!sinkNode && context && (context.tagName || context.elementId || context.domPath || context.attribute)) {
        sinkNode = {
            stage: 'sink',
            label: context.tagName || context.elementId || 'sink',
            domPath: context.domPath || null,
            elementId: context.elementId || null,
            attribute: context.attribute || null,
            location: context.location || null
        }
    }
    const sourceDisplay = buildSourceDisplay(evidence, info)
    const rawSourceLabel = sourceDisplay.label || sourceNode?.label || sourceNode?.key || evidence?.taintSource || info?.source || 'Source unavailable'
    const sourceKindLabel = sourceDisplay.kind ? String(sourceDisplay.kind) : ''
    const isInlineSource = sourceDisplay.kind === 'inline' || sourceDisplay.key?.startsWith('inline:')
    const sourceLabel = humanizeSourceLabel(rawSourceLabel)
    const sinkLabel = evidence?.sinkId || info?.sinkId || sinkNode?.label || sinkNode?.key || info?.sink || 'Sink unavailable'

    const sourceNameEl = document.getElementById('source_name')
    const sourceNameValue = sourceKindLabel && !sourceLabel.toLowerCase().startsWith(sourceKindLabel.toLowerCase())
        ? `${sourceKindLabel}: ${sourceLabel}`
        : sourceLabel
    if (isInlineSource && sourceDisplay.preview) {
        sourceNameEl.innerText = sourceDisplay.preview
    } else {
        sourceNameEl.innerText = sourceNameValue
    }
    if (sourceNameEl.innerText && !sourceNameEl.innerText.includes('["') && sourceNameEl.innerText.includes(':')) {
        sourceNameEl.innerText = humanizeSourceLabel(sourceNameEl.innerText)
    }
    document.getElementById('sink_name').innerText = sinkLabel
    document.getElementById('source_start').innerText = ''
    document.getElementById('source_end').innerText = ''
    document.getElementById('sink_start').innerText = ''
    document.getElementById('sink_end').innerText = ''
    const previewValue = sourceDisplay.preview ? String(sourceDisplay.preview) : ''
    const trimmedPreview = previewValue.length > 80 ? `${previewValue.slice(0, 77)}...` : previewValue
    const combinedSourceLabel = sourceKindLabel && !sourceLabel.toLowerCase().startsWith(sourceKindLabel.toLowerCase())
        ? `${sourceKindLabel}: ${sourceLabel}`
        : sourceLabel
    const primaryClassValue =
        evidence?.primaryClass
        || evidence?.raw?.primaryClass
        || info?.primaryClass
        || info?.evidence?.iast?.primaryClass
        || info?.evidence?.raw?.primaryClass
        || null
    const observation = primaryClassValue === 'observation'
    const hybrid = primaryClassValue === 'hybrid'
    if (observation || hybrid) {
        sourceNameEl.innerText = 'Observed'
    }
    const observedAt =
        evidence?.observedAt
        || evidence?.raw?.observedAt
        || info?.evidence?.iast?.observedAt
        || info?.evidence?.raw?.observedAt
        || null
    const detection =
        evidence?.detection
        || evidence?.raw?.detection
        || info?.evidence?.iast?.detection
        || info?.evidence?.raw?.detection
        || null
    const origin =
        evidence?.origin
        || evidence?.raw?.origin
        || info?.evidence?.iast?.origin
        || info?.evidence?.raw?.origin
        || null
    const sourceMetaHtml = buildIastDetailMeta(sourceNode, combinedSourceLabel, {
        context,
        role: 'source',
        sourcePreview: trimmedPreview,
        sourceKind: sourceKindLabel,
        iastMeta: {
            primaryClass: primaryClassValue,
            observedAt,
            detection,
            origin
        }
    })
    $("#source_extra_meta").html(sourceMetaHtml).show()
    if (debugUi) {
        const debugHtml = `
            <div class="ui tiny message">
                <div><strong>Debug sourceLabel:</strong> ${sanitize(ptk_utils.escapeHtml(String(sourceLabel || '')))}</div>
                <div><strong>Debug sourceDisplay.label:</strong> ${sanitize(ptk_utils.escapeHtml(String(sourceDisplay.label || '')))}</div>
                <div><strong>Debug sourceDisplay.preview:</strong> ${sanitize(ptk_utils.escapeHtml(String(sourceDisplay.preview || '')))}</div>
                <div><strong>Debug evidence.sources[0].label:</strong> ${sanitize(ptk_utils.escapeHtml(String(evidence?.sources?.[0]?.label || '')))}</div>
                <div><strong>Debug evidence.raw.sources[0].label:</strong> ${sanitize(ptk_utils.escapeHtml(String(evidence?.raw?.sources?.[0]?.label || '')))}</div>
                <div><strong>Debug primaryClass:</strong> ${sanitize(ptk_utils.escapeHtml(String(primaryClassValue || '')))}</div>
                <div><strong>Debug evidence keys:</strong> ${sanitize(ptk_utils.escapeHtml(String(Object.keys(evidence || {}).join(', '))))}</div>
                <div><strong>Debug evidence.raw keys:</strong> ${sanitize(ptk_utils.escapeHtml(String(Object.keys(evidence?.raw || {}).join(', '))))}</div>
            </div>
        `
        $("#source_extra_meta").append(debugHtml)
    }
    const sinkContextForRender = observation
        ? (() => {
            const sanitized = Object.assign({}, sinkContextMerged)
            delete sanitized.domPath
            delete sanitized.elementId
            delete sanitized.tagName
            delete sanitized.attribute
            delete sanitized.element
            return sanitized
        })()
        : sinkContextMerged
    let sinkSnippetRaw = getIastDetailSnippet(sinkNode, sinkContextForRender, evidence?.matched || '')
    const sinkPreview = sinkSnippetRaw ? '' : (evidence?.matched || context?.value || '')
    const trimmedSinkPreview = sinkPreview && String(sinkPreview).length > 80 ? `${String(sinkPreview).slice(0, 77)}...` : sinkPreview
    const ruleInfo = {
        ruleId: info?.ruleId || null,
        moduleId: info?.moduleId || null,
        sinkId: evidence?.sinkId || info?.sinkId || null,
        allowedSources: evidence?.allowedSources || info?.allowedSources || null,
        sinkSummary: evidence?.sinkSummary || info?.sinkSummary || null,
        observation,
        primaryClass: primaryClassValue || null,
        trust: evidence?.trust || evidence?.raw?.trust || info?.evidence?.iast?.trust || info?.evidence?.raw?.trust || null,
        detection: evidence?.detection || evidence?.raw?.detection || info?.evidence?.iast?.detection || info?.evidence?.raw?.detection || null,
        suppression: evidence?.suppression || evidence?.raw?.suppression || info?.evidence?.iast?.suppression || info?.evidence?.raw?.suppression || null
    }
    $("#sink_extra_meta").html(buildIastDetailMeta(sinkNode, sinkLabel, { context: sinkContextForRender, role: 'sink', sinkPreview: trimmedSinkPreview, ruleInfo })).show()
    $("#source_link").text('')
    $("#sink_link").text('')
    $("#source_link").closest('.description').hide()
    $("#source_start").closest('ul.list').hide()
    $("#sink_link").closest('.description').hide()
    $("#sink_start").closest('ul.list').hide()

    ensureHighlightStyles()
    const sourceCodeEl = document.getElementById('source_details_code')
    const sinkCodeEl = document.getElementById('sink_details_code')
    const applySnippet = (node, snippet, needle, cls) => {
        if (!node) return
        if (!snippet) {
            node.textContent = 'Snippet unavailable'
            return
        }
        try {
            node.innerHTML = renderSnippetWithHighlight(snippet, needle, cls, null, { wrap: false })
        } catch (_) {
            node.textContent = snippet
        }
    }

    let srcSnippetRaw = sourceDisplay.preview
        || sourceNode?.value
        || evidence?.sourceValuePreview
        || context?.value
        || ''
    if (!isInlineSource) {
        if (sourceLabel && srcSnippetRaw && String(sourceLabel) === String(srcSnippetRaw)) {
            srcSnippetRaw = ''
        }
        if (sourceDisplay?.preview && srcSnippetRaw && String(sourceDisplay.preview) === String(srcSnippetRaw)) {
            srcSnippetRaw = ''
        }
        if (sourceLabel && srcSnippetRaw && String(srcSnippetRaw).includes(String(sourceLabel))) {
            srcSnippetRaw = ''
        }
    }
    if (sinkLabel && sinkSnippetRaw && String(sinkLabel) === String(sinkSnippetRaw)) {
        sinkSnippetRaw = ''
    }
    const srcSnippet = normalizeSnippet(srcSnippetRaw) || 'n/a'
    const sinkSnippet = normalizeSnippet(sinkSnippetRaw)
    sourceCodeEl.textContent = srcSnippet
    $("#source_details").show()
    if (sinkSnippet) {
        applySnippet(sinkCodeEl, sinkSnippet, sinkLabel, 'sast-highlight-sink')
        $("#sink_details").show()
    } else {
        $("#sink_details").hide()
    }

    if (flow.length) {
        const flowHtml = formatIastFlow(flow)
        if (flowHtml) {
            $("#taint_trace").html(sanitize(flowHtml))
            $("#finding_trace_title").text("Flow");
            toggleSection("#finding_trace_segment", true);
        }
    }

    const locationInfo = info?.location || {}
    const headerRows = []
    const pageUrl = resolveIASTLocation(info, evidence) || ''
    if (locationInfo.route) {
        headerRows.push(`<div><strong>Route:</strong> ${sanitize(ptk_utils.escapeHtml(String(locationInfo.route)))}</div>`)
    }
    if (flowSummary) {
        headerRows.push(`<div><strong>Flow:</strong> ${sanitize(ptk_utils.escapeHtml(String(flowSummary)))}</div>`)
    }
    const timestamp = info?.createdAt || info?.updatedAt || null
    if (timestamp) {
        headerRows.push(`<div><strong>Time:</strong> ${sanitize(ptk_utils.escapeHtml(String(timestamp)))}</div>`)
    }
    const headerEl = document.getElementById('iast_context_header')
    if (headerEl) {
        if (headerRows.length) {
            headerEl.innerHTML = headerRows.join('')
            headerEl.style.display = 'block'
        } else {
            headerEl.style.display = 'none'
        }
    }

    setFindingMetadata(description || 'No description provided.', recommendation || 'No recommendation provided.', links || {}, {})
    showFindingModal()
}

export function resolveIASTLocation(info, evidence) {
    const location = info?.location || evidence?.raw?.location || null;
    if (!location) return "";
    if (typeof location === "string") return location;
    if (typeof location === "object") {
        return location.runtimeUrl || location.url || location.href || "";
    }
    return "";
}

function getIASTEvidencePayload(info) {
    if (!info) return null;
    const evidence = info.evidence;
    if (!evidence) return null;
    if (typeof evidence === "object" && !Array.isArray(evidence)) {
        if (evidence.iast && typeof evidence.iast === "object") return evidence.iast;
        if (evidence.IAST && typeof evidence.IAST === "object") return evidence.IAST;
        return evidence;
    }
    if (Array.isArray(evidence)) {
        return evidence.find(e => e?.source === "IAST") || evidence[0] || null;
    }
    return null;
}


export function bindSASTAttack(info, index = -1) {

    let { icon, order, attackClass } = getMisc(info);
    const traceMarkup = formatTaintTrace(info.trace);
    const traceHtml = traceMarkup ? sanitize(traceMarkup) : 'n/a';
    const sourceFileFull = info?.source?.sourceFileFull || info?.source?.sourceFile || '';
    const sinkFileFull = info?.sink?.sinkFileFull || info?.sink?.sinkFile || '';
    const pageContextRaw = info?.pageCanon || info?.pageUrl || '';
    const pageCanon = canonicalizeSastFileId(pageContextRaw);
    const sourceCanon = canonicalizeSastEndpoint(sourceFileFull, pageContextRaw || pageCanon);
    const sinkCanon = canonicalizeSastEndpoint(sinkFileFull, pageContextRaw || pageCanon);
    const sourceBase = extractCanonBase(sourceCanon);
    const sinkBase = extractCanonBase(sinkCanon);
    const ruleId = info?.metadata?.id || info?.module_metadata?.id || '';
    const ruleKey = ruleId ? encodeURIComponent(ruleId) : '';
    const severity = String(info?.metadata?.severity || info?.severity || '').toLowerCase();
    const attr = (val) => ptk_utils.escapeHtml(String(val || ""));
    let item = `
                <div class="ui message attack_info ${attackClass} ${index}" style="overflow:auto" data-order="${order}" data-source-file="${attr(sourceFileFull)}" data-sink-file="${attr(sinkFileFull)}" data-source-canon="${attr(sourceCanon)}" data-sink-canon="${attr(sinkCanon)}" data-source-base="${attr(sourceBase)}" data-sink-base="${attr(sinkBase)}" data-page-canon="${attr(pageCanon)}" data-page-url="${attr(pageContextRaw)}" data-rule-id="${attr(ruleId)}" data-rule-key="${attr(ruleKey)}" data-severity="${attr(severity)}">
                ${icon}
                    <div class="description">
                        <div>Source: <b><i>${sanitize(info.source.sourceName)}</i></b></div>
                        <div>Sink: <b><i>${sanitize(info.sink.sinkName)}</i></b> </div>
                        <div>Trace: ${traceHtml}</div>
                    </div>
                    <div class="ui left floated">
                        <a href="#" class="attack_details"  data-index="${index}">Details</a>
                    </div>
                </div>`;

    return item;
}


export function bindSCAAttack(info, requestId = -1) {
    let proof = "";

    // let misc = getMisc(info)
    // let icon = misc.icon, order = misc.order, attackClass = misc.attackClass

    let icon = "",
        order = "",
        attackClass = "vuln  visible";

    let item = `
      <div class="card" style="width:100%">
            <div class="content main">
                <div class="header">
                    Component: ${ptk_utils.escapeHtml(
        info.component
    )} <br/> Version: ${ptk_utils.escapeHtml(info.version)}
                </div>
                <div class="meta">
                    Found: ${ptk_utils.escapeHtml(info.file)}
                </div>
                
             
                ${prepareVulns(info.findings)}
            </div>
      </div>
    `;

    return item;
}

export function bindSCAComponentItem(component, index, options = {}) {
    const counts = calculateSCASeverityCounts(component?.findings)
    const componentName = ptk_utils.escapeHtml(component?.component || 'Unknown component')
    const version = ptk_utils.escapeHtml(component?.version || 'n/a')
    const source = buildSCAFileLink(component?.file)
    const componentKey = buildSCAComponentToken(component)
    const attrKey = encodeURIComponent(componentKey)
    const classes = [ 'sca-component-item']
    if (options.selected) {
        classes.push('active')
    }

    return `
        <div class="${classes.join(' ')}" data-component-id="${index}" data-component="${attrKey}" tabindex="0">
            <div class="title short_message_text" style="overflow:hidden;height:34px;background-color:#eeeeee;margin:1px 0 0 0;cursor:pointer; position: relative; padding: 6px 32px 6px 8px;">
                <span>${componentName} - ${version}</span>
                <i class="filter icon" style="float:right; position: absolute; top: 8px; right: 8px;" title="Filter by component"></i>
            </div>
            <div class="content" style="padding:8px 12px;">
                <div class="meta" style="word-break: break-word;">${source}</div>
                <div class="description" style="margin-top:6px;">
                    <div class="ui tiny labels">
                        <div class="ui basic label">Findings: ${counts.total}</div>
                        <div class="ui basic label ptk-sev-label ptk-sev-high">H: ${counts.high}</div>
                        <div class="ui basic label ptk-sev-label ptk-sev-medium">M: ${counts.medium}</div>
                        <div class="ui basic label ptk-sev-label ptk-sev-low">L: ${counts.low}</div>
                    </div>
                </div>
            </div>
        </div>`
}

export function bindSCAFinding(component, finding, index) {
    const severity = String(finding?.severity || '').toLowerCase()
    //const { icon } = getIconBySeverity(severity)
    finding.success = true; // force vuln styling
    let { icon, order, attackClass } = getMisc(finding);
    const componentName = ptk_utils.escapeHtml(component?.component || 'Unknown component')
    const version = ptk_utils.escapeHtml(component?.version || 'n/a')
    const summary = ptk_utils.escapeHtml(finding?.identifiers?.summary || 'No summary provided')
    const versionRange = buildSCAVersionRangeText(finding)
    const cweHtml = buildSCACweLabel(finding)
    const identifiers = buildSCAIdentifierSummary(finding)
    const references = buildSCAReferenceLinks(finding?.info)
    const source = buildSCAFileLink(component?.file)
    const componentKey = buildSCAComponentToken(component)
    const attrKey = encodeURIComponent(componentKey)
    return `
        <div class="ui message attack_info sca_finding ${attackClass}" data-index="${index}" data-component="${attrKey}">
            ${icon}
            <div class="description">
               
                <div>Component: <b>${componentName}</b> <span style="color:#666;">(Version: ${version})</span></div>
                ${source ? `<div>Source: ${source}</div>` : ''}
                ${versionRange ? `<div>Affected versions: <code>${ptk_utils.escapeHtml(versionRange)}</code></div>` : ''}
                ${cweHtml ? `<div>CWE: ${cweHtml}</div>` : ''}
                ${identifiers ? `<div class="sca-finding-identifiers">${identifiers}</div>` : ''}
                ${references}
            </div>
        </div>`
}

function calculateSCASeverityCounts(findings) {
    const counts = { total: 0, high: 0, medium: 0, low: 0 }
    if (!Array.isArray(findings)) return counts
    findings.forEach(finding => {
        counts.total += 1
        const key = String(finding?.severity || '').toLowerCase()
        if (counts[key] !== undefined) {
            counts[key] += 1
        }
    })
    return counts
}

function buildSCAComponentToken(component) {
    const name = String(component?.component || '').toLowerCase()
    const file = String(component?.file || '').toLowerCase()
    return `${name}::${file}`
}

function buildSCAVersionRangeText(finding) {
    if (!finding) return ''
    const segments = []
    if (finding.atOrAbove) segments.push(`>= ${finding.atOrAbove}`)
    if (finding.above) segments.push(`> ${finding.above}`)
    if (finding.atOrBelow) segments.push(`<= ${finding.atOrBelow}`)
    if (finding.below) segments.push(`< ${finding.below}`)
    return segments.join(' , ')
}

function buildSCACweLabel(finding) {
    const codes = normalizeSCAList(finding?.cwe)
    if (!codes.length) return ''
    return codes.map(code => {
        const raw = String(code || '')
        const numeric = raw.replace(/[^0-9]/g, '')
        const cweId = numeric || raw
        return `<a href="https://cwe.mitre.org/data/definitions/${encodeURIComponent(cweId)}.html" target="_blank" rel="noopener noreferrer">${ptk_utils.escapeHtml(raw)}</a>`
    }).join(', ')
}

function buildSCAIdentifierSummary(finding) {
    const identifiers = finding?.identifiers || {}
    const fragments = []
    const cves = normalizeSCAList(identifiers.CVE)
    if (cves.length) {
        const links = cves.map(cve => `<a href="https://www.cvedetails.com/cve/${encodeURIComponent(cve)}/" target="_blank" rel="noopener noreferrer">${ptk_utils.escapeHtml(cve)}</a>`).join(', ')
        fragments.push(`CVE: ${links}`)
    }
    const githubIds = normalizeSCAList(identifiers.githubID)
    if (githubIds.length) {
        fragments.push(`GitHub: ${githubIds.map(id => ptk_utils.escapeHtml(id)).join(', ')}`)
    }
    const issues = normalizeSCAList(identifiers.issue)
    if (issues.length) {
        fragments.push(`Issue: ${issues.map(id => ptk_utils.escapeHtml(id)).join(', ')}`)
    }
    const prs = normalizeSCAList(identifiers.PR)
    if (prs.length) {
        fragments.push(`PR: ${prs.map(id => ptk_utils.escapeHtml(id)).join(', ')}`)
    }
    const retid = identifiers.retid ? ptk_utils.escapeHtml(identifiers.retid) : ''
    if (retid) {
        fragments.push(`ID: ${retid}`)
    }
    return fragments.join(' | ')
}

function buildSCAReferenceLinks(links) {
    const list = normalizeSCAList(links).filter(link => typeof link === 'string' && link.trim())
    if (!list.length) return ''
    const html = list.map(link => {
        const safeUrl = ptk_utils.escapeHtml(link)
        return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer" title="${safeUrl}"><i class="external alternate icon"></i></a>`
    }).join(' ')
    return `<div class="sca-finding-links">References: ${html}</div>`
}

function buildSCAFileLink(file) {
    if (!file) return '<span>N/A</span>'
    const safe = ptk_utils.escapeHtml(file)
    if (typeof ptk_utils.isURL === 'function' && ptk_utils.isURL(file)) {
        return `<a href="${safe}" target="_blank" rel="noopener noreferrer">${safe}</a>`
    }
    return safe
}

function normalizeSCAList(value) {
    if (Array.isArray(value)) return value
    if (value === undefined || value === null || value === '') return []
    return [value]
}

function setStatValue(selector, value) {
    if (!selector) return
    const el = $(selector)
    if (el && el.length) {
        el.text(value)
    }
}

export function bindStats(stats = {}, type) {
    const findings = typeof stats.findingsCount === "number"
        ? stats.findingsCount
        : 0;
    const critical = typeof stats.critical === "number" ? stats.critical : 0;
    const high = typeof stats.high === "number" ? stats.high : 0;
    const medium = typeof stats.medium === "number" ? stats.medium : 0;
    const low = typeof stats.low === "number" ? stats.low : 0;
    const info = typeof stats.info === "number" ? stats.info : 0;

    const selectors = STAT_SELECTOR_MAP[type] || STAT_SELECTOR_MAP.default
    const primaryCount = (type === "dast" || type === "rbuilder")
        ? (typeof stats.attacksCount === "number" ? stats.attacksCount : 0)
        : (typeof stats.rulesCount === "number"
            ? stats.rulesCount
            : (typeof stats.attacksCount === "number" ? stats.attacksCount : 0));

    setStatValue(selectors.findings || STAT_SELECTOR_MAP.default.findings, findings)
    setStatValue(selectors.critical || STAT_SELECTOR_MAP.default.critical, critical)
    setStatValue(selectors.high || STAT_SELECTOR_MAP.default.high, high)
    setStatValue(selectors.medium || STAT_SELECTOR_MAP.default.medium, medium)
    setStatValue(selectors.low || STAT_SELECTOR_MAP.default.low, low)
    setStatValue(selectors.info || STAT_SELECTOR_MAP.default.info, info)
    if (selectors.attacks) {
        setStatValue(selectors.attacks, primaryCount)
    }
}

function prepareVulns(vulns) {
    let ret = '<div class="ui divided items">';
    Object.values(vulns).forEach((item) => {
        let icon = getIconBySeverity(item.severity);
        // ret += `<tr class="${(item.severity == 'high' ? 'ui red' : '')}">`
        // ret += `<td>${(item.severity.charAt(0).toUpperCase() + item.severity.slice(1))}</td>`
        // ret += `<td>${(item.identifiers.summary ? item.identifiers.summary : 'N/A')}</td>`
        let str = "";
        if (item.identifiers.CVE) {
            Object.values(item.identifiers.CVE).forEach((link) => {
                str += `<a target="_blank" href="https://www.cvedetails.com/cve/${link}/">${link}</a><br>`;
            });
        } else {
            Object.values(item.info).forEach((link) => {
                str += `<a target="_blank" href="${link}"><i class="external alternate icon"></i></a><br>`;
            });
        }
        // ret += "<td>" + str + "</td>"
        // ret += "</tr>"

        ret += `
        <div class="item">
            <div class="middle aligned content">
            ${icon.icon} ${item.identifiers.summary
                ? ptk_utils.escapeHtml(item.identifiers.summary)
                : "N/A"
            }
            <br/>
            ${str}
            </div>
        </div>`;
    });
    ret += "</div>";
    return ret;
}

export function bindAttackDetails_SAST(el, info) {

    resetFindingModal();
    toggleSection("#finding_source_sink_section", true);

    const description = info.metadata?.description || info.module_metadata?.description || '';
    const recommendation = info.metadata?.recommendation || info.module_metadata?.recommendation || '';
    const srcCodeEl = document.getElementById('source_details_code');
    const sinkCodeEl = document.getElementById('sink_details_code');

    ensureHighlightStyles();
    const sourceSnippet = normalizeSnippet(info.source?.sourceSnippet || info.codeSnippet || '');
    const sinkSnippet = normalizeSnippet(info.sink?.sinkSnippet || info.codeSnippet || '');

    // Highlight only the source and sink names inside the displayed snippets.
    // Prefer `info.sourceName` / `info.sinkName`, fall back to label fields.
    const srcNeedle = (info.source?.sourceName || info.source?.label || null) ? String(info.source?.sourceName || info.source?.label).trim() : null;
    const snkNeedle = (info.sink?.sinkName || info.sink?.label || null) ? String(info.sink?.sinkName || info.sink?.label).trim() : null;

    const applySnippet = (node, text, needle, cls, loc) => {
        if (!text) {
            node.textContent = 'Snippet unavailable';
            return;
        }
        try {
            node.innerHTML = renderSnippetWithHighlight(text, needle, cls, loc, { wrap: false });
        } catch (_) {
            node.textContent = text;
        }
    };

    applySnippet(srcCodeEl, sourceSnippet, srcNeedle, 'sast-highlight-source', info?.source?.sourceLoc);
    applySnippet(sinkCodeEl, sinkSnippet, snkNeedle, 'sast-highlight-sink', info?.sink?.sinkLoc);

    document.getElementById('source_name').innerText = info.source?.sourceName || info.source?.label || '—';
    document.getElementById('sink_name').innerText = info.sink?.sinkName || info.sink?.label || '—';

    document.getElementById('source_start').innerText = formatPoint(info?.source?.sourceLoc?.start);
    document.getElementById('source_end').innerText = formatPoint(info?.source?.sourceLoc?.end);
    document.getElementById('sink_start').innerText = formatPoint(info?.sink?.sinkLoc?.start);
    document.getElementById('sink_end').innerText = formatPoint(info?.sink?.sinkLoc?.end);

    // const traceWrapper = document.getElementById('taint_trace');
    // if (traceWrapper) {
    //     const container = traceWrapper.parentElement;
    //     const traceMarkup = formatTaintTrace(info.trace);
    //     if (traceMarkup) {
    //         traceWrapper.innerHTML = dompurify.sanitize(traceMarkup, { ALLOWED_TAGS: ['ul', 'li', 'strong', 'code', 'span'], ALLOWED_ATTR: ['class'] });
    //         container.style.display = '';
    //         toggleSection("#finding_trace_segment", true);
    //         document.getElementById("finding_trace_title").textContent = "Trace";
    //     } else {
    //         traceWrapper.innerHTML = '';
    //         container.style.display = 'none';
    //         toggleSection("#finding_trace_segment", false);
    //     }
    // }

    setFindingMetadata(description, recommendation, info.module_metadata?.links || {}, {});
    const modalTitle = getMisc(info).icon || `<div><b>${ptk_utils.escapeHtml(info.name || info.metadata?.name || 'SAST finding')}</b></div>`
    setFindingModalTitle(dompurify.sanitize(modalTitle, MODAL_TITLE_SANITIZE_CONFIG));

    const sourceLinkSpan = document.getElementById('source_link');
    const isInlineSource = String(info.source.sourceFile || '').startsWith('inline');

    renderLocationInto(sourceLinkSpan, {
        isInline: isInlineSource,
        displayText: isInlineSource
            ? (info.source?.sourceFileFull || info.source?.sourceFile || 'inline')
            : (info.source?.sourceFile || info.source?.sourceFileFull || ''),
        href: isInlineSource ? '' : (info.source?.sourceFile || info.source?.sourceFileFull || '')
    });


    const sinkLinkSpan = document.getElementById('sink_link');
    const isInlineSink = String(info.sink.sinkFile || '').startsWith('inline');
    renderLocationInto(sinkLinkSpan, {
        isInline: isInlineSink,
        displayText: isInlineSink
            ? (info.sink?.sinkFileFull || info.sink?.sinkFile || 'inline')
            : (info.sink?.sinkFile || info.sink?.sinkFileFull || ''),
        href: isInlineSink ? '' : (info.sink?.sinkFile || info.sink?.sinkFileFull || '')
    });

    showFindingModal();
    return false;
}

export function bindAttackDetails_DAST(el, attack, original) {
    attack = attack || {}
    const finding = attack.finding || null
    resetFindingModal();
    toggleSection("#finding_http_section", true);
    let proof = attack.proof;
    let response = attack.response?.body
        ? attack.response.body
        : original?.response?.body || "";
    let responseHeaders = attack.response?.headers
        ? attack.response.headers
        : original?.response?.headers || [];
    let baseRequestRaw = original?.request?.raw || "";
    let request = attack.request?.raw ? attack.request.raw : baseRequestRaw;
    let description = finding?.description || attack.metadata?.description || '';
    let recommendation = finding?.recommendation || attack.metadata?.recommendation || '';

    let misc = getMisc(attack);
    let icon = misc.icon;

    $("#raw_response").val(response || '');
    $("#raw_request").val(request || '');
    const headersText = Array.isArray(responseHeaders)
        ? responseHeaders.map(h => `${h.name}: ${h.value}`).join('\n')
        : ''
    const statusCode = attack.response?.statusCode || attack.response?.status || original?.response?.statusCode || original?.response?.status || null
    const statusMessage = attack.response?.statusMessage || attack.response?.statusText || original?.response?.statusMessage || original?.response?.statusText || ''
    const statusLine = statusCode ? `HTTP/1.1 ${statusCode}${statusMessage ? ` ${statusMessage}` : ''}` : ''
    const normalizedHeaders = headersText.trim()
    // Prepend status line for a raw-response look.
    const responseHeaderBlock = statusLine && !normalizedHeaders.startsWith('HTTP/')
        ? [statusLine, normalizedHeaders].filter(Boolean).join('\n')
        : headersText
    $("#raw_response_headers").val(responseHeaderBlock);
    const links = finding?.links || attack.metadata?.links || {};
    setFindingMetadata(description, recommendation, links, {});
    $("#attack_target").val(original?.request?.url || attack.request?.url || '');

    setFindingModalTitle(icon);

    toggleSection("#finding_response_column", true);
    toggleSection("#finding_request_column", true);
    toggleSection("#finding_source_sink_section", false);

    showFindingModal();
    setTimeout(function () {
        const ta = document.querySelector("#raw_response");
        const text = ta?.value || "";
        const idx = typeof proof === "string" ? text.indexOf(proof) : -1;
        if (ta && idx > -1 && proof) {
            scrollSelectionIntoView(ta, idx, idx + proof.length);
        }
    }, 100);

    return false;
}


function getCaretTopPx(textarea, index) {
    const div = document.createElement("div");
    const style = getComputedStyle(textarea);

    // Copy the critical text layout styles
    [
        "boxSizing", "width", "height", "overflowX", "overflowY",
        "borderTopWidth", "borderRightWidth", "borderBottomWidth", "borderLeftWidth",
        "paddingTop", "paddingRight", "paddingBottom", "paddingLeft",
        "fontFamily", "fontSize", "fontWeight", "fontStyle", "letterSpacing", "textTransform",
        "textIndent", "textAlign", "whiteSpace", "wordBreak", "wordWrap", "lineHeight",
        "tabSize"
    ].forEach(p => div.style[p] = style[p]);

    // Ensure wrapping matches textarea default
    div.style.whiteSpace = (textarea.wrap === "off") ? "pre" : "pre-wrap";
    div.style.position = "absolute";
    div.style.visibility = "hidden";
    div.style.top = "0";
    div.style.left = "-9999px";

    // Text before the caret
    const before = textarea.value.slice(0, index);
    const after = textarea.value.slice(index);

    // Use a span to measure caret position
    div.textContent = before;
    const span = document.createElement("span");
    span.textContent = after.length ? after[0] : "."; // placeholder if at end
    div.appendChild(span);

    document.body.appendChild(div);
    const top = span.offsetTop;     // caret top relative to content
    document.body.removeChild(div);
    return top;
}

function scrollSelectionIntoView(textarea, start, end) {
    textarea.focus();
    textarea.setSelectionRange(start, end);

    const caretTop = getCaretTopPx(textarea, start);
    const targetTop = Math.max(
        0,
        Math.min(
            caretTop - textarea.clientHeight / 2,
            textarea.scrollHeight - textarea.clientHeight
        )
    );
    textarea.scrollTop = targetTop;
}

export function showHtml(obj, newWin = false) {
    let formId = obj.closest(".ui.tab.active").attr("id"),
        target = "";
    if (formId) {
        let $form = $("#" + formId + " #request_form"),
            values = $form.form("get values");
        target = new URL(values["request_url"]).origin;
    } else {
        let $form = $("#attack_details_form"),
            values = $form.form("get values");
        target = new URL(values["request_url"]).origin;
    }
    let htmlString = obj
        .closest(".response_view")
        .find('[name="response_body"]')
        .val();
    htmlString = htmlString.replace(
        /<([^<])*(head)([^>])*>/,
        "<$1$2><base href='" + target + "' />"
    );
    //let dataBase64 = 'data:text/html;base64,' + decoder.base64_encode(htmlString)
    //let blob = new Blob([unescape(encodeURIComponent(htmlString))], { type: 'text/html' })
    let url = "showhtml.html?s=" + decoder.base64_encode(encodeURI(htmlString));

    if (newWin) {
        browser.windows.create({
            url: browser.runtime.getURL("/ptk/browser/" + url),
        });
    } else {
        $("#dialogResponseHtml").modal("show");
        if (isFirefox) {
            $("#dialogResponseHtmlContentFrame").prop("src", url);
            $("#dialogResponseHtmlContentObj").hide();
            $("#dialogResponseHtmlContentFrame").show();
        } else {
            $("#dialogResponseHtmlContentObj").prop("data", url);
            $("#dialogResponseHtmlContentFrame").hide();
            $("#dialogResponseHtmlContentObj").show();
        }
    }
    return false;
}

export class curl2object {
    static curlType = Object.freeze({
        PARAMS: "params",
        HEADERS: "headers",
        BODY: "body",
        URL: "url",
    });

    constructor() {
        this.backslashRegex = /\\/gi;
        this.newLineRegex = /\\n/gi;
    }

    // let us parse params

    parser(parse, command) {
        command = command.replace(this.backslashRegex, "");
        let object = {};
        let _command = command;
        let rx1, rx2, rx3;
        let _splitXXX, _each, _url;
        switch (parse) {
            case curl2object.curlType.PARAMS:
                rx1 = /-X/gi;
                rx2 = /-d/gi;
                rx3 = /-H/gi;
                _command = _command.replace(rx1, "XXX");
                _command = _command.replace(rx2, "XXX");
                _command = _command.replace(rx3, "XXX");
                // split by XXX
                _splitXXX = _command.split("XXX");
                _splitXXX.map((each) => {
                    _each = each.replace(this.newLineRegex, "");
                    if (_each.includes("-P")) {
                        let paramsArr = _each.split("-P").slice(1);
                        paramsArr.map((param) => {
                            _param = JSON.parse(param);
                            _param = _param.split(":");
                            object[_param[0]] = _param[1];
                        });
                    }
                });
                return object;
            case curl2object.curlType.HEADERS:
                rx1 = /-X/gi;
                rx2 = /-d/gi;
                rx3 = /-P/gi;
                _command = _command.replace(rx1, "XXX");
                _command = _command.replace(rx2, "XXX");
                _command = _command.replace(rx3, "XXX");
                // split by XXX
                _splitXXX = _command.split("XXX");
                _splitXXX.map((each) => {
                    _each = each.replace(this.newLineRegex, "");
                    if (_each.includes("-H")) {
                        let headersArr = _each.split("-H").slice(1);
                        headersArr.map((header) => {
                            _header = JSON.parse(header);
                            _header = _header.split(":");
                            object[_header[0]] = _header[1];
                        });
                    }
                });
                return object;
            case curl2object.curlType.BODY:
                rx1 = /-X/gi;
                rx2 = /-H/gi;
                rx3 = /-P/gi;
                _command = _command.replace(rx1, "XXX");
                _command = _command.replace(rx2, "XXX");
                _command = _command.replace(rx3, "XXX");
                // split by XXX
                _splitXXX = _command.split("XXX");
                _splitXXX.map((each) => {
                    _each = each.replace(this.newLineRegex, "");
                    if (_each.includes("-d")) {
                        let bodyArr = _each.split("-d").slice(1);
                        bodyArr.map((body) => {
                            object["body"] = body;
                        });
                    }
                });
                return object;
            case curl2object.curlType.URL:
                rx1 = /-d/gi;
                rx2 = /-H/gi;
                rx3 = /-P/gi;
                _command = _command.replace(rx1, "XXX");
                _command = _command.replace(rx2, "XXX");
                _command = _command.replace(rx3, "XXX");
                // split by XXX
                _splitXXX = _command.split("XXX");
                _splitXXX.map((each) => {
                    _each = each.replace(this.newLineRegex, "");
                    if (_each.includes("-X")) {
                        let urlArr = _each.split("-X").slice(1);
                        urlArr.map((url) => {
                            _url = url.trim().split(" ");
                            object["method"] = _url[0];
                            object["url"] = _url[1];
                        });
                    }
                });
                return object;
            default:
                return object;
        }
    }
}
