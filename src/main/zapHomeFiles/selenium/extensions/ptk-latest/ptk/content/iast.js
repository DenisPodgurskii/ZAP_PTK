/* Author: Denis Podgurskii */
;(() => {
if (globalThis.__PTK_IAST_AGENT_LOADED__) {
    try {
        globalThis.postMessage({ channel: 'ptk_iast_agent_ready' }, '*');
    } catch (_) { }
    return;
}
globalThis.__PTK_IAST_AGENT_LOADED__ = true;

const FREE_SAFE_HOOK_GROUPS = Object.freeze([
    'hook.code.exec',
    'hook.dom.documentWrite',
    'hook.dom.formAttributes',
    'hook.dom.htmlAssignments',
    'hook.dom.inlineEvents',
    'hook.dom.mutations',
    'hook.dom.urlAttributes',
    'hook.nav.redirects',
    'hook.net.responses',
    'hook.postMessage',
    'hook.runtime.integrity.fetchInit',
    'hook.script.loading',
]);

const POLICY_ONLY_HOOK_GROUPS = Object.freeze([
    'hook.client.json',
    'hook.console.leaks',
    'hook.dom.htmlParsers',
    'hook.net.exfil',
    'hook.runtime.integrity.prototypeWrites',
    'hook.storage',
]);

function createNullProtoObject() {
    return Object.create(null);
}

function ensureHookPlan(installPlanHookGroups, groupId, reason = 'derived-policy-support') {
    if (!installPlanHookGroups[groupId]) {
        installPlanHookGroups[groupId] = {
            enabled: true,
            reason,
            sinkIds: new Set(),
            ruleIds: new Set(),
            ruleCount: 0,
            tier: classifyHookGroupTier(groupId),
        };
    }
    return installPlanHookGroups[groupId];
}

function getDomAttributeHookGroupForSink(sinkId) {
    if (!sinkId) return null;
    if (sinkId === 'nav.iframe.srcdoc') return 'hook.dom.htmlAssignments';
    if (sinkId === 'dom.inline_event') return 'hook.dom.inlineEvents';
    if (sinkId === 'document.domain') return 'hook.dom.urlAttributes';
    if (
        sinkId === 'dom.attr.action'
        || sinkId === 'dom.attr.formaction'
        || sinkId.startsWith('dom.attr.action.')
        || sinkId.startsWith('dom.attr.formaction.')
    ) {
        return 'hook.dom.formAttributes';
    }
    return 'hook.dom.urlAttributes';
}

function getHookGroupsForSink(sinkId) {
    const groups = new Set();
    if (!sinkId) return groups;
    if (['dom.innerHTML', 'dom.outerHTML', 'dom.insertAdjacentHTML', 'nav.iframe.srcdoc'].includes(sinkId)) {
        groups.add('hook.dom.htmlAssignments');
    }
    if (sinkId === 'document.write') {
        groups.add('hook.dom.documentWrite');
    }
    if ([
        'dom.domParser.parseFromString',
        'dom.range.createContextualFragment',
        'dom.element.setHTMLUnsafe',
        'dom.shadowRoot.setHTMLUnsafe'
    ].includes(sinkId)) {
        groups.add('hook.dom.htmlParsers');
    }
    if (sinkId === 'dom.inline_event') {
        groups.add('hook.dom.inlineEvents');
    }
    if (sinkId === 'dom.mutation' || sinkId === 'dom.clobbering.named_property') {
        groups.add('hook.dom.mutations');
    }
    if (
        ['dom.attr.href', 'dom.attr.src', 'dom.attr.action', 'dom.attr.formaction', 'nav.iframe.src', 'nav.location.href', 'http.image.src', 'script.element.src'].includes(sinkId)
        || sinkId.startsWith('dom.attr.href.')
        || sinkId.startsWith('dom.attr.action.')
        || sinkId.startsWith('dom.attr.formaction.')
        || sinkId.startsWith('dom.attr.src.')
        || sinkId.startsWith('nav.iframe.src.')
        || sinkId.startsWith('script.element.src.')
    ) {
        const attrHookGroup = getDomAttributeHookGroupForSink(sinkId);
        if (attrHookGroup) groups.add(attrHookGroup);
    }
    if (sinkId.startsWith('code.')) {
        groups.add('hook.code.exec');
    }
    if (sinkId.startsWith('nav.location.') || sinkId.startsWith('nav.window.open') || sinkId.startsWith('nav.history.') || sinkId === 'nav.navigation.navigate') {
        groups.add('hook.nav.redirects');
    }
    if (sinkId.startsWith('http.') || sinkId.startsWith('csrf.')) {
        groups.add('hook.net.exfil');
    }
    if (sinkId === 'runtime.prototype.pollution.fetchInit') {
        groups.add('hook.runtime.integrity.fetchInit');
    }
    if (sinkId === 'runtime.prototype.pollution.write') {
        groups.add('hook.runtime.integrity.prototypeWrites');
    }
    if (sinkId.startsWith('realtime.')) {
        groups.add('hook.net.exfil');
    }
    if (sinkId.startsWith('clipboard.')) {
        groups.add('hook.net.exfil');
    }
    if (sinkId.startsWith('storage.')) {
        groups.add('hook.storage');
    }
    if (sinkId.startsWith('postmessage.') || sinkId.startsWith('channel.')) {
        groups.add('hook.postMessage');
    }
    if (sinkId.startsWith('log.console.')) {
        groups.add('hook.console.leaks');
    }
    if (sinkId.startsWith('worker.') || sinkId === 'script.element.src' || sinkId.startsWith('script.element.src.')) {
        groups.add('hook.script.loading');
    }
    if (
        sinkId === 'client.json.parse'
        || sinkId === 'dom.xpath.evaluate'
        || sinkId.startsWith('client.filereader.')
        || sinkId.startsWith('client.sql.')
    ) {
        groups.add('hook.client.json');
    }
    if (sinkId === 'document.domain') {
        groups.add('hook.dom.urlAttributes');
    }
    return groups;
}

function classifyHookGroupTier(groupId) {
    if (FREE_SAFE_HOOK_GROUPS.includes(groupId)) return 'free-safe';
    if (POLICY_ONLY_HOOK_GROUPS.includes(groupId)) return 'policy-only';
    return 'support';
}

const IAST_SECONDARY_SOURCE_KINDS = new Set(['cookie', 'localStorage', 'sessionStorage', 'windowName', 'referrer', 'hashRoute']);
const IAST_STORAGE_EXEC_SOURCE_KINDS = new Set(['cookie', 'localStorage', 'sessionStorage', 'windowName', 'referrer', 'hashRoute', 'postMessage']);
const IAST_RESPONSE_SOURCE_KINDS = new Set(['apiResponseField', 'graphqlResponseField']);
const IAST_SESSION_SOURCE_KINDS = new Set(['cookie', 'localStorage', 'sessionStorage', 'windowName', 'referrer']);
const IAST_STORAGE_REUSE_SOURCE_KINDS = new Set(['cookie', 'localStorage', 'sessionStorage', 'windowName']);
const IAST_REDIRECT_SOURCE_KINDS = new Set(['query', 'hashQuery', 'hashRoute', 'postMessage', 'referrer', 'windowName']);
const IAST_ROUTE_SOURCE_KINDS = new Set(['pathname', 'pathSegment', 'clientRoute', 'historyState', 'hashRoute', 'hashQuery', 'postMessage']);
const IAST_FORM_HIJACK_SOURCE_KINDS = new Set([
    'query', 'hashQuery', 'hashRoute', 'pathname', 'pathSegment', 'clientRoute',
    'historyState', 'bodyParam', 'jsonBodyField', 'formDataField', 'graphqlVariable',
    'postMessage', 'windowName', 'referrer'
]);

function hasAnyIastSourceKind(sourceKinds, expected) {
    return Array.isArray(sourceKinds) && sourceKinds.some((kind) => expected.has(kind));
}

function getIastRuleVariantByPrefix(sinkPlan, prefixes = []) {
    if (!sinkPlan?.variants?.length) return null;
    for (const prefix of prefixes) {
        const match = sinkPlan.variants.find((entry) => entry?.ruleId?.includes(prefix));
        if (match) return match;
    }
    return null;
}

function selectIastRuleVariant({ runtimePlan = null, sinkId = null, sourceKinds = [], isCrossOrigin = false } = {}) {
    const sinkPlan = sinkId && runtimePlan?.bySinkId ? runtimePlan.bySinkId[sinkId] || null : null;
    if (!sinkPlan?.variants?.length) return null;
    if (sinkPlan.uniqueRuleId) return sinkPlan.variants[0] || null;

    if ([
        'dom.innerHTML',
        'dom.outerHTML',
        'dom.insertAdjacentHTML',
        'document.write',
        'dom.mutation',
        'dom.domParser.parseFromString',
        'dom.range.createContextualFragment',
        'dom.element.setHTMLUnsafe',
        'dom.shadowRoot.setHTMLUnsafe'
    ].includes(sinkId)) {
        if (hasAnyIastSourceKind(sourceKinds, IAST_RESPONSE_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['response_']);
        }
        if (hasAnyIastSourceKind(sourceKinds, IAST_SECONDARY_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['secondary_sources']);
        }
        return getIastRuleVariantByPrefix(sinkPlan, ['dom_', 'document_write_', 'range_', 'element_', 'shadowroot_']) || sinkPlan.variants[0];
    }

    if (sinkId === 'dom.inline_event' || sinkId === 'nav.iframe.srcdoc') {
        if (hasAnyIastSourceKind(sourceKinds, IAST_SECONDARY_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['secondary_sources']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('secondary_sources')) || sinkPlan.variants[0];
    }

    if (['code.eval', 'code.function.constructor', 'code.function.apply', 'code.setTimeout', 'code.setInterval'].includes(sinkId)) {
        if (hasAnyIastSourceKind(sourceKinds, IAST_STORAGE_EXEC_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['storage_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('storage_')) || sinkPlan.variants[0];
    }

    if (sinkId === 'http.fetch.url' || sinkId === 'http.xhr.open') {
        if (hasAnyIastSourceKind(sourceKinds, IAST_STORAGE_REUSE_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['storage_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('storage_')) || sinkPlan.variants[0];
    }

    if (sinkId === 'http.fetch.headers') {
        if (isCrossOrigin && hasAnyIastSourceKind(sourceKinds, IAST_SESSION_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['session_']);
        }
        if (hasAnyIastSourceKind(sourceKinds, IAST_STORAGE_REUSE_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['storage_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('session_') && !entry.ruleId.includes('storage_')) || sinkPlan.variants[0];
    }

    if (['http.navigator.sendBeacon', 'http.image.src', 'realtime.websocket.send'].includes(sinkId)) {
        if (isCrossOrigin && hasAnyIastSourceKind(sourceKinds, IAST_SESSION_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['session_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('session_')) || sinkPlan.variants[0];
    }

    if (sinkId === 'realtime.webrtc.send') {
        if (hasAnyIastSourceKind(sourceKinds, IAST_SESSION_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['session_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('session_')) || sinkPlan.variants[0];
    }

    if (sinkId === 'postmessage.anyOrigin' || sinkId === 'postmessage.crossOrigin') {
        if (hasAnyIastSourceKind(sourceKinds, IAST_SESSION_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['session_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('session_')) || sinkPlan.variants[0];
    }

    if (['nav.location.href', 'nav.location.assign', 'nav.location.replace', 'nav.window.open'].includes(sinkId)) {
        if (isCrossOrigin && hasAnyIastSourceKind(sourceKinds, IAST_REDIRECT_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['_sources']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('_sources')) || sinkPlan.variants[0];
    }

    if (sinkId === 'nav.navigation.navigate') {
        if (isCrossOrigin && hasAnyIastSourceKind(sourceKinds, IAST_REDIRECT_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['_sources']);
        }
        if (hasAnyIastSourceKind(sourceKinds, IAST_ROUTE_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['route_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('_sources') && !entry.ruleId.includes('route_')) || sinkPlan.variants[0];
    }

    if (sinkId === 'nav.history.pushState' || sinkId === 'nav.history.replaceState') {
        if (hasAnyIastSourceKind(sourceKinds, IAST_ROUTE_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['route_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('route_')) || sinkPlan.variants[0];
    }

    if (sinkId === 'dom.attr.action' || sinkId === 'dom.attr.formaction') {
        if (hasAnyIastSourceKind(sourceKinds, IAST_RESPONSE_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['response_']);
        }
        if (sinkId === 'dom.attr.action' && isCrossOrigin && hasAnyIastSourceKind(sourceKinds, IAST_REDIRECT_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['_sources']);
        }
        if (hasAnyIastSourceKind(sourceKinds, IAST_FORM_HIJACK_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['hijack']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('response_') && !entry.ruleId.includes('_sources') && !entry.ruleId.includes('hijack')) || sinkPlan.variants[0];
    }

    return sinkPlan.variants[0] || null;
}

function buildRuleEntry(moduleDef, ruleDef) {
    return {
        moduleId: moduleDef.id,
        moduleName: moduleDef.name,
        moduleMeta: moduleDef.metadata || {},
        ruleId: ruleDef.id,
        ruleName: ruleDef.name,
        sinkId: ruleDef.sinkId || null,
        ruleMeta: ruleDef.metadata || {},
        hook: ruleDef.hook || null,
        conditions: ruleDef.conditions || {},
        sources: Array.isArray(ruleDef.sources)
            ? ruleDef.sources
            : (Array.isArray(ruleDef.metadata?.sources) ? ruleDef.metadata.sources : []),
        sanitizersAllowed: Array.isArray(ruleDef.sanitizersAllowed)
            ? ruleDef.sanitizersAllowed
            : (Array.isArray(ruleDef.metadata?.sanitizersAllowed) ? ruleDef.metadata.sanitizersAllowed : []),
        variantKey: ruleDef.id || null,
    };
}

function buildIastRuntimePlan(modulesJson) {
    const plan = {
        version: 1,
        activeModuleIds: [],
        activeRuleIds: [],
        activeHookGroups: [],
        freeSafeHookGroups: [],
        policyOnlyHookGroups: [],
        supportHookGroups: [],
        byRuleId: createNullProtoObject(),
        bySinkId: createNullProtoObject(),
        installPlan: { hookGroups: createNullProtoObject() },
    };

    if (!modulesJson || !Array.isArray(modulesJson.modules)) {
        return plan;
    }

    const activeHookGroups = new Set();
    const activeModuleIds = new Set();
    const activeRuleIds = new Set();
    const installPlanHookGroups = createNullProtoObject();

    for (const moduleDef of modulesJson.modules) {
        if (!moduleDef || typeof moduleDef !== 'object' || !Array.isArray(moduleDef.rules)) continue;
        if (moduleDef.id) activeModuleIds.add(moduleDef.id);

        for (const ruleDef of moduleDef.rules) {
            if (!ruleDef || typeof ruleDef !== 'object') continue;
            const entry = buildRuleEntry(moduleDef, ruleDef);
            if (entry.ruleId) {
                activeRuleIds.add(entry.ruleId);
                plan.byRuleId[entry.ruleId] = entry;
            }
            if (!entry.sinkId) continue;

            if (!plan.bySinkId[entry.sinkId]) {
                plan.bySinkId[entry.sinkId] = {
                    sinkId: entry.sinkId,
                    hookGroups: [],
                    variants: [],
                    uniqueRuleId: null,
                };
            }

            const sinkPlan = plan.bySinkId[entry.sinkId];
            sinkPlan.variants.push(entry);

            const sinkHookGroups = getHookGroupsForSink(entry.sinkId);
            sinkHookGroups.forEach((groupId) => {
                activeHookGroups.add(groupId);
                const hookPlan = ensureHookPlan(installPlanHookGroups, groupId, 'active-rules');
                hookPlan.sinkIds.add(entry.sinkId);
                hookPlan.ruleIds.add(entry.ruleId);
                sinkPlan.hookGroups = [...new Set([...sinkPlan.hookGroups, groupId])];
            });

            if (entry.sources.includes('postMessage')) {
                activeHookGroups.add('hook.postMessage');
            }
            if (entry.sources.includes('apiResponseField') || entry.sources.includes('graphqlResponseField')) {
                activeHookGroups.add('hook.net.responses');
            }
            if (entry.sanitizersAllowed.length) {
                activeHookGroups.add('hook.sanitizers');
            }
        }
    }

    for (const sinkPlan of Object.values(plan.bySinkId)) {
        if (sinkPlan.variants.length === 1) {
            sinkPlan.uniqueRuleId = sinkPlan.variants[0].ruleId;
        }
    }

    for (const groupId of activeHookGroups) {
        ensureHookPlan(installPlanHookGroups, groupId, 'derived-policy-support');
    }

    if (activeHookGroups.has('hook.runtime.integrity.fetchInit')) {
        ensureHookPlan(installPlanHookGroups, 'hook.runtime.integrity.prototypeWrites', 'supporting-dependency');
    }

    for (const hookPlan of Object.values(installPlanHookGroups)) {
        hookPlan.ruleCount = hookPlan.ruleIds.size;
        hookPlan.sinkIds = [...hookPlan.sinkIds].sort();
        hookPlan.ruleIds = [...hookPlan.ruleIds].sort();
    }

    plan.activeModuleIds = [...activeModuleIds].sort();
    plan.activeRuleIds = [...activeRuleIds].sort();
    plan.activeHookGroups = [...activeHookGroups].sort();
    plan.freeSafeHookGroups = plan.activeHookGroups.filter((groupId) => classifyHookGroupTier(groupId) === 'free-safe');
    plan.policyOnlyHookGroups = plan.activeHookGroups.filter((groupId) => classifyHookGroupTier(groupId) === 'policy-only');
    plan.supportHookGroups = Object.keys(installPlanHookGroups)
        .filter((groupId) => classifyHookGroupTier(groupId) === 'support')
        .sort();
    plan.installPlan.hookGroups = installPlanHookGroups;

    return plan;
}

function resolveIastRuntimeBinding({ runtimePlan = null, sinkId = null, ruleId = null, variant = null, fallbackType = null } = {}) {
    const sinkPlan = sinkId && runtimePlan?.bySinkId ? runtimePlan.bySinkId[sinkId] || null : null;
    let ruleEntry = null;

    if (sinkPlan && variant) {
        ruleEntry = sinkPlan.variants.find((entry) => entry.variantKey === variant || entry.ruleId === variant) || null;
    }
    if (!ruleEntry && sinkPlan?.uniqueRuleId) {
        ruleEntry = sinkPlan.variants[0] || null;
    }
    if (!ruleEntry && ruleId && runtimePlan?.byRuleId) {
        ruleEntry = runtimePlan.byRuleId[ruleId] || null;
    }
    if (!ruleEntry && sinkPlan?.variants?.length) {
        ruleEntry = sinkPlan.variants[0];
    }

    const ruleMeta = ruleEntry?.ruleMeta || {};
    return {
        ruleEntry,
        sinkPlan,
        binding: {
            sink: sinkId || ruleEntry?.sinkId || ruleMeta?.sink || fallbackType || 'iast_sink',
            sinkId: ruleEntry?.sinkId || sinkId || null,
            ruleId: ruleEntry?.ruleId || ruleId || null,
            type: ruleMeta?.message || ruleEntry?.ruleName || ruleMeta?.category || fallbackType || 'iast_sink'
        }
    };
}

function isIastSinkActive(sinkId) {
    if (!sinkId) return false;
    return Boolean(IAST_RUNTIME_PLAN?.bySinkId?.[sinkId]);
}

const __PTK_IAST_DBG__ = () => {};
let __IAST_DISABLE_HOOKS__ = false;
// Dynamic IAST modules + rule registry, populated from background at runtime.
let IAST_MODULES = null;
let IAST_RUNTIME_PLAN = null;
const IAST_RULE_INDEX = {
    bySinkId: Object.create(null),
    byRuleId: Object.create(null),
};
let __IAST_LAST_MODULES_REQUEST__ = 0;
const IAST_HOOK_GROUPS = {
    enabled: new Set(),
    installed: new Set()
};
window.__PTK_IAST_DEBUG_STATE__ = function () {
    return {
        activeModuleIds: Array.isArray(IAST_RUNTIME_PLAN?.activeModuleIds) ? IAST_RUNTIME_PLAN.activeModuleIds.slice() : [],
        activeRuleIds: Array.isArray(IAST_RUNTIME_PLAN?.activeRuleIds) ? IAST_RUNTIME_PLAN.activeRuleIds.slice() : [],
        activeHookGroups: Array.isArray(IAST_RUNTIME_PLAN?.activeHookGroups) ? IAST_RUNTIME_PLAN.activeHookGroups.slice() : [],
        enabledHookGroups: Array.from(IAST_HOOK_GROUPS.enabled || []),
        installedHookGroups: Array.from(IAST_HOOK_GROUPS.installed || []),
        protoEventsCount: IAST_PROTO_EVENTS.length,
        lastProtoEvent: IAST_PROTO_EVENTS.length ? Object.assign({}, IAST_PROTO_EVENTS[IAST_PROTO_EVENTS.length - 1]) : null,
        lastFetchInitDebug: window.__PTK_IAST_LAST_FETCHINIT_DEBUG__ || null
    };
};
const IAST_INTERNAL_HTML_PARSER_STATE = { depth: 0 };
const IAST_SANITIZED_VALUES = new Map();
const IAST_SANITIZED_TTL_MS = 30000;
const IAST_SANITIZED_MAX = 200;
const IAST_TAINT_TTL_MS = 60000;
const IAST_TAINT_MAX = 2000;
const IAST_TAINT_STORE = {
    nextSourceId: 1,
    nextTaintId: 1,
    stringMap: new Map(),
    objectMap: typeof WeakMap !== 'undefined' ? new WeakMap() : null
};
const IAST_MUTATION_QUEUE = [];
const IAST_MUTATION_BUDGET = {
    tokens: 2,
    max: 2,
    intervalMs: 1000,
    lastRefill: Date.now()
};
let IAST_MUTATION_FLUSH_SCHEDULED = false;
const IAST_MUTATION_BATCH_SIZE = 2;
const IAST_MUTATION_QUEUE_MAX = 50;
const IAST_TAINT_ACTIVITY_WINDOW_MS = 5000;
const IAST_AGENT_BOOT_AT = Date.now();
const IAST_SMART_STARTUP_SUPPRESS_MS = 2500;
const IAST_HEAVY_COOLDOWN_MS = 4000;
const IAST_HEAVY_MAX_PER_SEC = 8;
let IAST_HEAVY_COUNT = 0;
let IAST_HEAVY_RESET_AT = Date.now();
let IAST_HEAVY_PAUSED_UNTIL = 0;
const IAST_RUNTIME_SIGNAL_SOURCE_KINDS = new Set([
    'query',
    'hashQuery',
    'hashRoute',
    'clientRoute',
    'pathname',
    'pathSegment',
    'historyState',
    'cookie',
    'localStorage',
    'sessionStorage',
    'windowName',
    'postMessage',
    'apiResponseField',
    'graphqlResponseField',
    'form',
    'bodyParam',
    'jsonBodyField',
    'formDataField'
]);
const IAST_RUNTIME_SIGNAL_MAX_VALUE_LENGTH = 4096;
const IAST_RUNTIME_SIGNAL_SENT = new Map();
const IAST_INITIAL_SCAN_STRATEGY = (typeof window !== 'undefined'
    && String(window.__PTK_IAST_SCAN_STRATEGY__ || '').trim().toUpperCase() === 'COMPREHENSIVE')
    ? 'COMPREHENSIVE'
    : 'SMART';
let IAST_SCAN_STRATEGY = IAST_INITIAL_SCAN_STRATEGY;
const IAST_PROPAGATION_CONFIG = Object.freeze({
    SMART: Object.freeze({
        enabled: true,
        mode: 'bounded',
        maxLineage: 4,
        maxStringLength: 2048
    }),
    COMPREHENSIVE: Object.freeze({
        enabled: true,
        mode: 'full',
        maxLineage: 12,
        maxStringLength: 8192
    })
});
const IAST_SMART_DEDUP_TTL_MS = 60000;
const IAST_FINDING_DEDUP_MAX = 5000;
const IAST_FINDING_DEDUP = new Map();
const IAST_SINK_SEEN = new Map();
const IAST_NETWORK_HEADER_WINDOW_MS = 60000;
const IAST_NETWORK_HEADER_FREQUENCY_MAX = 12;
const IAST_NETWORK_HEADER_TRACKER = new Map();
const IAST_RESPONSE_SOURCE_MAX_CHARS = 32768;
const IAST_RESPONSE_SOURCE_MAX_ENTRIES = 24;
const IAST_PROTO_POLLUTION_TTL_MS = 120000;
const IAST_PROTO_IMPACT_FIELDS = Object.freeze([
    'method',
    'headers',
    'body',
    'credentials',
    'mode',
    'redirect',
    'referrer',
    'referrerPolicy',
    'integrity',
    'cache',
    'keepalive'
]);
const IAST_DANGEROUS_PROTO_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const IAST_PROTO_EVENTS = [];
const IAST_EXECUTABLE_BOOTSTRAP_SWEEP = {
    timer: null,
    scheduledAt: 0
};
let __IAST_MUTATION_TRAVERSE__ = null;
const IAST_EVIDENCE_SCHEMA_VERSION = 'iast-evidence@1';
const IAST_DETECTION_SCHEMA_VERSION = 'iast-detection@1';
const IAST_TRUST_SCHEMA_VERSION = 'iast-trust@1';
const IAST_PRIMARY_CLASSES = Object.freeze({
    TAINT_FLOW: 'taint_flow',
    OBSERVATION: 'observation',
    HYBRID: 'hybrid',
    POLICY_VIOLATION: 'policy_violation'
});
const IAST_SOURCE_ROLES = Object.freeze({
    ORIGIN: 'origin',
    OBSERVED: 'observed',
    DERIVED: 'derived',
    UNKNOWN: 'unknown'
});
const IAST_DATA_KINDS = Object.freeze({
    TOKEN: 'token',
    JWT: 'jwt',
    SESSION_ID: 'session_id',
    API_KEY: 'api_key',
    CREDENTIAL: 'credential',
    PII: 'pii',
    UNKNOWN: 'unknown'
});
const IAST_REASON_CODES = Object.freeze({
    JWT_HEURISTIC: 'jwt_heuristic',
    TOKEN_HEURISTIC: 'token_heuristic',
    AUTH_HEADER_SAME_ORIGIN: 'auth_header_same_origin',
    COOKIE_HEADER_ATTEMPT: 'forbidden_header_attempt_cookie',
    AUTH_HEADER_SAME_ORIGIN_RISKY: 'auth_header_same_origin_risky',
    WEBSOCKET_SAME_HOST: 'websocket_same_host',
    CLIENT_JSON_PARSE_OBSERVED: 'client_json_parse_observed',
    SAME_HOST_EXFIL: 'same_host_exfil_observation',
    CROSS_ORIGIN_POSTMESSAGE_RECEIVER: 'cross_origin_postmessage_receiver',
    POSTMESSAGE_RECEIVER_SAME_ORIGIN: 'same_origin_postmessage_receiver',
    RESPONSE_FIELD_CLIENT_PERSISTENCE: 'response_field_client_persistence',
    RESPONSE_FIELD_CROSS_BOUNDARY: 'response_field_cross_boundary',
    RESPONSE_AUTH_STATE_REUSE: 'response_auth_state_reuse',
    PROTOTYPE_POLLUTION_WRITE: 'prototype_pollution_write',
    PROTOTYPE_POLLUTION_FETCH_IMPACT: 'prototype_pollution_fetch_impact',
    SINK_POLICY_MATCH: 'sink_policy_match',
    FLOW_MATCH: 'flow_match',
    UNKNOWN: 'unknown'
});
const IAST_TRUST_LEVELS = Object.freeze({
    SAME_ORIGIN: 'same_origin',
    FIRST_PARTY: 'first_party',
    THIRD_PARTY: 'third_party',
    UNKNOWN: 'unknown'
});
const IAST_TRUST_DECISIONS = Object.freeze({
    ALLOW: 'allow',
    WARN: 'warn',
    BLOCK: 'block'
});

function resetIastRuleIndex() {
    IAST_MODULES = null;
    IAST_RUNTIME_PLAN = null;
    IAST_RULE_INDEX.bySinkId = Object.create(null);
    IAST_RULE_INDEX.byRuleId = Object.create(null);
}

function initIastRuleIndex(modulesJson) {
    resetIastRuleIndex();
    if (!modulesJson || !Array.isArray(modulesJson.modules)) {
        __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: invalid modulesJson', modulesJson);
        return;
    }

    IAST_MODULES = modulesJson;
    IAST_RUNTIME_PLAN = buildIastRuntimePlan(modulesJson);
    Object.keys(IAST_RUNTIME_PLAN.bySinkId).forEach((sinkId) => {
        IAST_RULE_INDEX.bySinkId[sinkId] = IAST_RUNTIME_PLAN.bySinkId[sinkId].variants.slice();
    });
    Object.keys(IAST_RUNTIME_PLAN.byRuleId).forEach((ruleId) => {
        IAST_RULE_INDEX.byRuleId[ruleId] = IAST_RUNTIME_PLAN.byRuleId[ruleId];
    });

    applyIastRuntimePlan(IAST_RUNTIME_PLAN);

    //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: rule index initialised', IAST_RULE_INDEX);
}

function mergeLinks(baseLinks, overrideLinks) {
    const result = Object.assign({}, baseLinks || {})
    if (overrideLinks && typeof overrideLinks === 'object') {
        Object.entries(overrideLinks).forEach(([key, value]) => {
            if (key) result[key] = value
        })
    }
    return Object.keys(result).length ? result : null
}

const IAST_SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info']

function normalizeIastSeverityValue(value, fallback = 'medium') {
    if (value === null || value === undefined) return fallback
    const normalized = String(value).trim().toLowerCase()
    if (IAST_SEVERITY_LEVELS.includes(normalized)) return normalized
    if (!Number.isNaN(Number(normalized))) {
        const numeric = Number(normalized)
        if (numeric >= 8) return 'high'
        if (numeric >= 5) return 'medium'
        if (numeric > 0) return 'low'
    }
    return fallback
}

function resolveIastEffectiveSeverity({ override, moduleMeta = {}, ruleMeta = {} } = {}) {
    if (override !== null && override !== undefined) {
        return normalizeIastSeverityValue(override)
    }
    if (ruleMeta?.severity != null) {
        return normalizeIastSeverityValue(ruleMeta.severity)
    }
    if (moduleMeta?.severity != null) {
        return normalizeIastSeverityValue(moduleMeta.severity)
    }
    return 'medium'
}

function getIastRuleBySinkId(sinkId) {
    return sinkId ? IAST_RULE_INDEX.bySinkId[sinkId]?.[0] || null : null;
}

function getIastRulesBySinkId(sinkId) {
    return sinkId ? IAST_RULE_INDEX.bySinkId[sinkId] || [] : [];
}

function getIastRuleByRuleId(ruleId) {
    return ruleId ? IAST_RULE_INDEX.byRuleId[ruleId] || null : null;
}

window.addEventListener('message', (event) => {
    const data = event.data || {}
    if (data.channel === 'ptk_background_iast2content_modules') {
        if (data.scanStrategy) setIastScanStrategy(data.scanStrategy);
        if (!data.iastModules) return;
        initIastRuleIndex(data.iastModules)
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: modules received from bridge')
    }
    if (data.channel === 'ptk_background_iast2content_token_origin') {
        if (Array.isArray(data.tokens)) {
            data.tokens.forEach(entry => {
                if (!entry || !entry.value) return;
                addTokenOrigin(entry.value, entry.origin || null);
            });
        }
    }
})

// On load, request the current IAST modules from background (helps after reloads)
try {
    requestModulesFromBackground(true)
} catch (_) {
    // ignore if not in extension context
}

function requestModulesFromBackground(force = false) {
    const now = Date.now();
    if (!force && now - __IAST_LAST_MODULES_REQUEST__ < 2000) {
        return;
    }
    __IAST_LAST_MODULES_REQUEST__ = now;
    try {
        window.postMessage({ channel: 'ptk_content_iast_request_modules' }, '*');
    } catch (e) {
        __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: modules request exception', e);
    }
}

function normalizeScanStrategy(value) {
    const normalized = String(value || '').trim().toUpperCase();
    return normalized === 'SMART' ? 'SMART' : 'COMPREHENSIVE';
}

function setIastScanStrategy(value) {
    const next = normalizeScanStrategy(value);
    if (next === IAST_SCAN_STRATEGY) return;
    IAST_SCAN_STRATEGY = next;
    IAST_FINDING_DEDUP.clear();
    IAST_SINK_SEEN.clear();
    refreshIastPropagationSettings();
}

function isSmartScanStrategy() {
    return IAST_SCAN_STRATEGY === 'SMART';
}

function isSmartMode() {
    return isSmartScanStrategy();
}

function getIastPropagationSettings(strategy = IAST_SCAN_STRATEGY) {
    return IAST_PROPAGATION_CONFIG[strategy] || IAST_PROPAGATION_CONFIG.SMART;
}

function refreshIastPropagationSettings() {
    const config = getIastPropagationSettings();
    const override = window.__PTK_IAST_PROPAGATION_OVERRIDE__;
    window.__PTK_IAST_PROPAGATION_MODE__ = config.mode;
    window.__PTK_IAST_PROPAGATION_MAX_LINEAGE__ = config.maxLineage;
    window.__PTK_IAST_PROPAGATION_MAX_STRING_LENGTH__ = config.maxStringLength;
    window.__PTK_IAST_PROPAGATION_ENABLED__ = typeof override === 'boolean'
        ? override
        : config.enabled;
}

function isHookGroupEnabled(groupId) {
    return IAST_HOOK_GROUPS.enabled.has(groupId);
}

function isAnyHookGroupEnabled(groupIds = []) {
    return groupIds.some((groupId) => isHookGroupEnabled(groupId));
}

function hasExecutableDomHookEnabled() {
    return isAnyHookGroupEnabled([
        'hook.dom.mutations',
        'hook.dom.htmlAssignments',
        'hook.dom.urlAttributes',
        'hook.dom.formAttributes',
        'hook.dom.inlineEvents'
    ]);
}

function refillMutationBudget() {
    const now = Date.now();
    const elapsed = now - IAST_MUTATION_BUDGET.lastRefill;
    if (elapsed < IAST_MUTATION_BUDGET.intervalMs) return;
    const refill = Math.floor(elapsed / IAST_MUTATION_BUDGET.intervalMs);
    if (refill <= 0) return;
    IAST_MUTATION_BUDGET.tokens = Math.min(
        IAST_MUTATION_BUDGET.max,
        IAST_MUTATION_BUDGET.tokens + refill
    );
    IAST_MUTATION_BUDGET.lastRefill = now;
}

function takeMutationToken() {
    refillMutationBudget();
    if (IAST_MUTATION_BUDGET.tokens <= 0) return false;
    IAST_MUTATION_BUDGET.tokens -= 1;
    return true;
}

function scheduleMutationFlush() {
    if (IAST_MUTATION_FLUSH_SCHEDULED) return;
    IAST_MUTATION_FLUSH_SCHEDULED = true;
    const flush = () => {
        IAST_MUTATION_FLUSH_SCHEDULED = false;
        if (!IAST_MUTATION_QUEUE.length) return;
        if (!takeMutationToken()) {
            setTimeout(scheduleMutationFlush, IAST_MUTATION_BUDGET.intervalMs);
            return;
        }
        const batch = IAST_MUTATION_QUEUE.splice(0, IAST_MUTATION_BATCH_SIZE);
        batch.forEach(({ node, trigger }) => {
            try {
                if (typeof __IAST_MUTATION_TRAVERSE__ === 'function') {
                    __IAST_MUTATION_TRAVERSE__(node, trigger);
                }
            } catch (_) { }
        });
        if (IAST_MUTATION_QUEUE.length) scheduleMutationFlush();
    };
    if (typeof window.requestIdleCallback === 'function') {
        window.requestIdleCallback(flush, { timeout: 200 });
    } else {
        setTimeout(flush, 0);
    }
}

function markTaintActivity() {
    window.__IAST_LAST_TAINT_AT__ = Date.now();
}

function hasRecentTaintActivity() {
    const last = window.__IAST_LAST_TAINT_AT__ || 0;
    return Date.now() - last <= IAST_TAINT_ACTIVITY_WINDOW_MS;
}

function isSmartStartupSuppressed() {
    return isSmartMode() && (Date.now() - IAST_AGENT_BOOT_AT) < IAST_SMART_STARTUP_SUPPRESS_MS;
}

function allowHeavyHook() {
    const now = Date.now();
    if (isSmartStartupSuppressed()) return false;
    if (now < IAST_HEAVY_PAUSED_UNTIL) return false;
    if (now - IAST_HEAVY_RESET_AT >= 1000) {
        IAST_HEAVY_RESET_AT = now;
        IAST_HEAVY_COUNT = 0;
    }
    IAST_HEAVY_COUNT += 1;
    if (IAST_HEAVY_COUNT > IAST_HEAVY_MAX_PER_SEC) {
        IAST_HEAVY_PAUSED_UNTIL = now + IAST_HEAVY_COOLDOWN_MS;
        return false;
    }
    return true;
}

function getExecutableMutationCandidate(node) {
    if (!node || node.nodeType !== Node.ELEMENT_NODE) return null;
    const tag = node.tagName ? String(node.tagName).toLowerCase() : null;

    if (tag === 'script') {
        const src = typeof node.getAttribute === 'function' ? node.getAttribute('src') : null;
        if (src && getDangerousUrlScheme(src)) {
            const match = matchesTaint(src);
            if (match) {
                return {
                    match,
                    value: src,
                    attribute: 'src',
                    tag,
                    candidateType: 'script-src'
                };
            }
        }
        const inlineScript = String(node.textContent || '').trim();
        if (inlineScript) {
            const match = matchesTaint(inlineScript);
            if (match) {
                return {
                    match,
                    value: inlineScript,
                    attribute: null,
                    tag,
                    candidateType: 'script-text'
                };
            }
        }
    }

    const attributes = Array.from(node.attributes || []);
    for (const attr of attributes) {
        const attrName = String(attr?.name || '').toLowerCase();
        const attrValue = attr?.value;
        if (!attrName || attrValue == null) continue;
        const dangerousUrlAttr = attrName === 'href' || attrName === 'src' || attrName === 'action' || attrName === 'formaction';
        const risky = attrName.startsWith('on')
            || attrName === 'srcdoc'
            || (dangerousUrlAttr && !!getDangerousUrlScheme(attrValue));
        if (!risky) continue;
        const match = matchesTaint(attrValue);
        if (!match) continue;
        return {
            match,
            value: attrValue,
            attribute: attr.name,
            tag,
            candidateType: attrName
        };
    }

    return null;
}

function walkElementSubtree(root, { maxElements = 24, maxMs = 2 } = {}, visit) {
    if (!root || typeof visit !== 'function') return;
    const start = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    let visited = 0;
    const shouldStop = () => {
        const now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
        return visited >= maxElements || (now - start) > maxMs;
    };
    const visitElement = (element) => {
        if (!element || element.nodeType !== Node.ELEMENT_NODE) return true;
        if (shouldStop()) return false;
        visited += 1;
        return visit(element) !== false;
    };

    if (root.nodeType === Node.ELEMENT_NODE && visitElement(root) === false) {
        return;
    }

    const walkerRoot = root.nodeType === Node.DOCUMENT_NODE
        ? (root.documentElement || root.body || root)
        : root;

    if (typeof document !== 'undefined'
        && typeof document.createTreeWalker === 'function'
        && walkerRoot
        && (walkerRoot.nodeType === Node.ELEMENT_NODE
            || walkerRoot.nodeType === Node.DOCUMENT_FRAGMENT_NODE
            || walkerRoot.nodeType === Node.DOCUMENT_NODE)) {
        const walker = document.createTreeWalker(walkerRoot, NodeFilter.SHOW_ELEMENT);
        let current = walker.nextNode();
        while (current) {
            if (visitElement(current) === false) return;
            current = walker.nextNode();
        }
        return;
    }

    if (walkerRoot && typeof walkerRoot.querySelectorAll === 'function') {
        const nodes = walkerRoot.querySelectorAll('*');
        for (let i = 0; i < nodes.length; i += 1) {
            if (visitElement(nodes[i]) === false) return;
        }
    }
}

function runExecutableBootstrapSweep(reason = 'bootstrap') {
    if (__IAST_DISABLE_HOOKS__) return;
    if (!window.__IAST_TAINTED__ || !Object.keys(window.__IAST_TAINTED__).length) return;
    if (!hasExecutableDomHookEnabled()) {
        return;
    }
    const root = document.documentElement || document.body;
    if (!root) return;
    const seen = new Set();
    walkElementSubtree(root, {
        maxElements: isSmartMode() ? 120 : 240,
        maxMs: isSmartMode() ? 5 : 8
    }, (node) => {
        const candidate = getExecutableMutationCandidate(node);
        if (!candidate || seen.has(node)) return true;
        seen.add(node);
        maybeReportTaintedValue(candidate.value, {
            type: 'xss-bootstrap-sweep',
            sink: reason,
            sinkId: 'dom.mutation'
        }, {
            element: node,
            nodeType: 'ELEMENT_NODE',
            tag: node.tagName,
            attribute: candidate.attribute,
            value: candidate.value,
            domPath: getDomPath(node),
            candidateType: candidate.candidateType,
            bootstrapReason: reason
        }, candidate.match);
        return seen.size < 3;
    });
}

function scheduleExecutableBootstrapSweep(reason = 'bootstrap') {
    if (!isSmartMode()) return;
    if (IAST_EXECUTABLE_BOOTSTRAP_SWEEP.timer) {
        clearTimeout(IAST_EXECUTABLE_BOOTSTRAP_SWEEP.timer);
        IAST_EXECUTABLE_BOOTSTRAP_SWEEP.timer = null;
    }
    const delay = Math.max(200, IAST_SMART_STARTUP_SUPPRESS_MS - (Date.now() - IAST_AGENT_BOOT_AT) + 200);
    IAST_EXECUTABLE_BOOTSTRAP_SWEEP.scheduledAt = Date.now();
    IAST_EXECUTABLE_BOOTSTRAP_SWEEP.timer = setTimeout(() => {
        IAST_EXECUTABLE_BOOTSTRAP_SWEEP.timer = null;
        try {
            runExecutableBootstrapSweep(reason);
        } catch (_) { }
    }, delay);
}

function withInternalHtmlParser(fn) {
    IAST_INTERNAL_HTML_PARSER_STATE.depth += 1;
    try {
        return typeof fn === 'function' ? fn() : undefined;
    } finally {
        IAST_INTERNAL_HTML_PARSER_STATE.depth = Math.max(0, IAST_INTERNAL_HTML_PARSER_STATE.depth - 1);
    }
}

function isInternalHtmlParserActive() {
    return IAST_INTERNAL_HTML_PARSER_STATE.depth > 0;
}

function installHookGroup(groupId) {
    if (IAST_HOOK_GROUPS.installed.has(groupId)) return;
    IAST_HOOK_GROUPS.installed.add(groupId);
    if (groupId === 'hook.sanitizers') {
        installSanitizerHooks();
    }
}

function installSanitizerHooks() {
    if (window.__IAST_SANITIZER_HOOKED__) return;
    window.__IAST_SANITIZER_HOOKED__ = true;
    const wrapDomPurify = () => {
        if (!window.DOMPurify || typeof window.DOMPurify.sanitize !== 'function') return false;
        if (window.DOMPurify.__ptk_wrapped__) return true;
        const orig = window.DOMPurify.sanitize.bind(window.DOMPurify);
        window.DOMPurify.sanitize = function (...args) {
            const result = orig(...args);
            recordSanitizedValue(result, 'san.domPurify');
            return result;
        };
        window.DOMPurify.__ptk_wrapped__ = true;
        return true;
    };
    if (wrapDomPurify()) return;
    let attempts = 0;
    const timer = setInterval(() => {
        attempts += 1;
        if (wrapDomPurify() || attempts > 40) {
            clearInterval(timer);
        }
    }, 500);
}

function applyIastRuntimePlan(runtimePlan) {
    const installGroups = runtimePlan?.installPlan?.hookGroups && typeof runtimePlan.installPlan.hookGroups === 'object'
        ? Object.keys(runtimePlan.installPlan.hookGroups)
        : [];
    const enabled = new Set(installGroups.length ? installGroups : (runtimePlan?.activeHookGroups || []));
    IAST_HOOK_GROUPS.enabled = enabled;
    enabled.forEach(groupId => installHookGroup(groupId));
    scheduleExecutableBootstrapSweep('modules_loaded');
}

// Deduplication set for mutation hooks
const __IAST_REPORTED_NODES__ = new Set();

// Encoding helpers
function withoutHooks(fn) {
    const prev = __IAST_DISABLE_HOOKS__;
    __IAST_DISABLE_HOOKS__ = true;
    try {
        return fn();
    } finally {
        __IAST_DISABLE_HOOKS__ = prev;
    }
}

// Re-write htmlDecode & htmlEncode

function htmlDecode(input) {
    if (input == null) return input;
    const str = String(input);
    if (!str.includes('&')) return str;
    try {
        return withoutHooks(() => {
            const ta = document.createElement('textarea');
            ta.innerHTML = str;
            return ta.value;
        });
    } catch (_) {
        return str;
    }
}

function htmlEncode(input) {
    return withoutHooks(() => {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    });
}

let __IAST_MATCH_COUNT__ = 0;

function getDomPath(node) {
    try {
        if (!node || node.nodeType !== 1) return null;
        const parts = [];
        let el = node;
        while (el && el.nodeType === 1 && parts.length < 10) {
            let part = el.tagName.toLowerCase();
            if (el.id) {
                part += `#${el.id}`;
                parts.unshift(part);
                break;
            }
            if (el.classList && el.classList.length) {
                part += '.' + Array.from(el.classList).slice(0, 3).join('.');
            }
            if (el.parentElement) {
                const siblings = Array.from(el.parentElement.children).filter(c => c.tagName === el.tagName);
                if (siblings.length > 1) {
                    const idx = siblings.indexOf(el);
                    part += `:nth-of-type(${idx + 1})`;
                }
            }
            parts.unshift(part);
            el = el.parentElement;
        }
        return parts.length ? parts.join(' > ') : null;
    } catch (_) {
        return null;
    }
}

function computeDomPath(el) {
    try {
        if (!el || el.nodeType !== 1) return null;
        const segments = [];
        let node = el;
        let safety = 0;
        while (node && node.nodeType === 1 && safety < 50) {
            safety++;
            const tag = (node.tagName || '').toLowerCase();
            if (!tag) break;
            let part = tag;
            if (node.id) {
                part += `#${node.id}`;
            } else if (node.classList && node.classList.length) {
                part += '.' + Array.from(node.classList).slice(0, 3).join('.');
            }
            if (!node.id && node.parentElement) {
                let idx = 1;
                let sib = node;
                while ((sib = sib.previousElementSibling)) {
                    if (sib.tagName === node.tagName) idx++;
                }
                if (idx > 1) part += `:nth-of-type(${idx})`;
            }
            segments.unshift(part);
            node = node.parentElement;
            if (node === document.documentElement) {
                segments.unshift('html');
                break;
            }
        }
        return segments.join(' > ');
    } catch (_) {
        return null;
    }
}

function enrichContext(ctx = {}) {
    const context = Object.assign({}, ctx);
    const el = context.element;
    if (el && el.nodeType === 1) {
        context.tagName = el.tagName ? el.tagName.toLowerCase() : context.tagName;
        context.elementId = el.id || context.elementId || null;
        if (el.classList && el.classList.length) {
            context.elementClasses = Array.from(el.classList);
        }
        if (!context.domPath) {
            context.domPath = computeDomPath(el);
        }
        if (el.outerHTML && !context.elementOuterHTML) {
            const html = String(el.outerHTML);
            context.elementOuterHTML = html.length > 1024 ? html.slice(0, 1024) : html;
        }
    } else if (context.element && typeof context.element === 'string' && !context.domPath) {
        try {
            const tmp = document.createElement('div');
            tmp.innerHTML = context.element;
            const first = tmp.firstElementChild;
            const path = computeDomPath(first);
            if (path) context.domPath = path;
        } catch (_) { }
    }
    if (!context.domPath && context.target && context.target.nodeType === 1) {
        const path = computeDomPath(context.target);
        if (path) context.domPath = path;
    }
    delete context.element;
    delete context.target;
    return context;
}

// Taint collection
window.__IAST_TAINT_META__ = window.__IAST_TAINT_META__ || {};
window.__PTK_IAST_HAS_TAINT__ = window.__PTK_IAST_HAS_TAINT__ || false;
window.__PTK_IAST_PROPAGATION_OVERRIDE__ = typeof window.__PTK_IAST_PROPAGATION_ENABLED__ === 'boolean'
    ? window.__PTK_IAST_PROPAGATION_ENABLED__
    : null;
window.__PTK_IAST_PROPAGATION_ENABLED__ = false;
refreshIastPropagationSettings();
const IAST_TOKEN_ORIGINS = new Map();
const IAST_TOKEN_ORIGIN_TTL_MS = 2 * 60 * 1000;
const IAST_TOKEN_ORIGIN_MAX = 200;
const IAST_ORIGIN_WAIT_MS = 200;

function getTaintMetaEntry(key) {
    if (!key) return null;
    return window.__IAST_TAINT_META__?.[key] || null;
}

function updateTaintMetaEntry(key, extras = {}) {
    if (!key) return null;
    const store = window.__IAST_TAINT_META__ = window.__IAST_TAINT_META__ || {};
    const current = store[key] || {};
    if (extras && typeof extras === 'object') {
        Object.entries(extras).forEach(([k, v]) => {
            if (v !== undefined && v !== null) {
                current[k] = v;
            }
        });
    }
    current.lastUpdated = Date.now();
    store[key] = current;
    return current;
}

function fnv1aHash(str) {
    let hash = 2166136261;
    for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        hash = (hash * 16777619) >>> 0;
    }
    return hash.toString(16);
}

function fingerprintValue(value) {
    const str = String(value);
    const prefix = str.slice(0, 12);
    const suffix = str.slice(-12);
    return `${str.length}:${fnv1aHash(str)}:${prefix}:${suffix}`;
}

function pruneTaintStore() {
    if (IAST_TAINT_STORE.stringMap.size <= IAST_TAINT_MAX) return;
    const now = Date.now();
    for (const [key, entry] of IAST_TAINT_STORE.stringMap.entries()) {
        if (!entry || now - entry.time > IAST_TAINT_TTL_MS) {
            IAST_TAINT_STORE.stringMap.delete(key);
        }
        if (IAST_TAINT_STORE.stringMap.size <= IAST_TAINT_MAX) break;
    }
}

function addTokenOrigin(value, origin) {
    if (!value) return;
    const str = String(value);
    const now = Date.now();
    IAST_TOKEN_ORIGINS.set(str, { origin: origin || null, time: now });
    if (IAST_TOKEN_ORIGINS.size > IAST_TOKEN_ORIGIN_MAX) {
        for (const [key, entry] of IAST_TOKEN_ORIGINS.entries()) {
            if (!entry || now - entry.time > IAST_TOKEN_ORIGIN_TTL_MS) {
                IAST_TOKEN_ORIGINS.delete(key);
            }
            if (IAST_TOKEN_ORIGINS.size <= IAST_TOKEN_ORIGIN_MAX) break;
        }
    }
}

function getTokenOrigin(value) {
    if (!value) return null;
    const str = String(value);
    const entry = IAST_TOKEN_ORIGINS.get(str);
    if (!entry) return null;
    if (Date.now() - entry.time > IAST_TOKEN_ORIGIN_TTL_MS) {
        IAST_TOKEN_ORIGINS.delete(str);
        return null;
    }
    return entry.origin || null;
}

function classifyTaintKind(sourceKind, value, meta = {}) {
    if (meta.taintKind) return meta.taintKind;
    if ((sourceKind === 'cookie' || sourceKind === 'localStorage' || sourceKind === 'sessionStorage') && isTokenLikeValue(value)) {
        return 'secret';
    }
    if ((sourceKind === 'apiResponseField' || sourceKind === 'graphqlResponseField') && isTokenLikeValue(value)) {
        return 'secret';
    }
    if (sourceKind === 'query' || sourceKind === 'hashQuery' || sourceKind === 'hashRoute'
        || sourceKind === 'inline' || sourceKind === 'postMessage'
        || sourceKind === 'pathname' || sourceKind === 'pathSegment'
        || sourceKind === 'clientRoute' || sourceKind === 'historyState'
        || sourceKind === 'bodyParam' || sourceKind === 'jsonBodyField'
        || sourceKind === 'formDataField' || sourceKind === 'graphqlVariable') {
        return 'user_input';
    }
    return 'unknown';
}

function guessLabel(value, meta = {}) {
    if (meta.label) return meta.label;
    if (isTokenLikeValue(value) && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(value))) {
        return 'jwt';
    }
    return null;
}

function createSource(value, sourceKind, meta = {}) {
    window.__PTK_IAST_HAS_TAINT__ = true;
    const sourceId = meta.sourceId || `s_${IAST_TAINT_STORE.nextSourceId++}`;
    const taintId = `t_${IAST_TAINT_STORE.nextTaintId++}`;
    const taint = {
        taintId,
        sourceId,
        sourceKind,
        taintKind: classifyTaintKind(sourceKind, value, meta),
        label: guessLabel(value, meta),
        createdAt: Date.now(),
        origin: { url: window.location.href },
        meta: Object.assign({}, meta),
        lineage: [{ op: 'source', at: Date.now(), meta: Object.assign({}, meta) }]
    };
    if (typeof value === 'object' && value !== null && IAST_TAINT_STORE.objectMap) {
        IAST_TAINT_STORE.objectMap.set(value, { taint, time: Date.now() });
    } else {
        const fp = fingerprintValue(value);
        IAST_TAINT_STORE.stringMap.set(fp, { taint, time: Date.now() });
        pruneTaintStore();
    }
    return taint;
}

function getTaintEntry(value) {
    if (!window.__PTK_IAST_HAS_TAINT__) return null;
    if (value === null || value === undefined) return null;
    if (typeof value === 'object' && value !== null && IAST_TAINT_STORE.objectMap) {
        const entry = IAST_TAINT_STORE.objectMap.get(value);
        return entry?.taint ? { taint: entry.taint, matchType: 'id' } : null;
    }
    const fp = fingerprintValue(value);
    const entry = IAST_TAINT_STORE.stringMap.get(fp);
    if (!entry) return null;
    if (Date.now() - entry.time > IAST_TAINT_TTL_MS) {
        IAST_TAINT_STORE.stringMap.delete(fp);
        return null;
    }
    return entry?.taint ? { taint: entry.taint, matchType: 'fingerprint' } : null;
}

function propagateTaint(outputValue, op, inputs = [], meta = {}) {
    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) return;
    const maxLineage = Number.isFinite(window.__PTK_IAST_PROPAGATION_MAX_LINEAGE__)
        ? window.__PTK_IAST_PROPAGATION_MAX_LINEAGE__
        : getIastPropagationSettings().maxLineage;
    const maxStringLength = Number.isFinite(window.__PTK_IAST_PROPAGATION_MAX_STRING_LENGTH__)
        ? window.__PTK_IAST_PROPAGATION_MAX_STRING_LENGTH__
        : getIastPropagationSettings().maxStringLength;
    if (typeof outputValue === 'string' && outputValue.length > maxStringLength) return;
    const inputTaints = inputs.map(getTaintEntry).filter(Boolean).map(entry => entry.taint);
    if (!inputTaints.length) return;
    const primary = inputTaints[0];
    const primaryLineage = Array.isArray(primary?.lineage) ? primary.lineage : [];
    if (Number.isFinite(maxLineage) && maxLineage > 0 && primaryLineage.length >= maxLineage) return;
    const taint = {
        taintId: `t_${IAST_TAINT_STORE.nextTaintId++}`,
        sourceId: primary.sourceId,
        sourceKind: primary.sourceKind,
        taintKind: primary.taintKind,
        label: primary.label,
        createdAt: Date.now(),
        origin: primary.origin,
        meta: Object.assign({}, primary.meta, meta, {
            propagationMode: window.__PTK_IAST_PROPAGATION_MODE__ || getIastPropagationSettings().mode
        }),
        lineage: primaryLineage.concat([{ op, at: Date.now(), meta }]).slice(-Math.max(maxLineage, 1))
    };
    if (typeof outputValue === 'object' && outputValue !== null && IAST_TAINT_STORE.objectMap) {
        IAST_TAINT_STORE.objectMap.set(outputValue, { taint, time: Date.now() });
    } else {
        const fp = fingerprintValue(outputValue);
        IAST_TAINT_STORE.stringMap.set(fp, { taint, time: Date.now() });
        pruneTaintStore();
    }
}

function isTokenLikeValue(value) {
    if (value === null || value === undefined) return false;
    const str = String(value).trim();
    if (str.length < 12) return false;
    // JWT-like: three base64url segments
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(str) && str.length >= 30) {
        return true;
    }
    // Long hex
    if (/^[A-Fa-f0-9]+$/.test(str) && str.length >= 32) {
        return true;
    }
    // Long base64 / base64url-ish
    if (/^[A-Za-z0-9+/_=-]+$/.test(str) && str.length >= 24) {
        return true;
    }
    // Mixed classes and long enough
    const hasLower = /[a-z]/.test(str);
    const hasUpper = /[A-Z]/.test(str);
    const hasDigit = /[0-9]/.test(str);
    if (str.length >= 20 && ((hasLower && hasUpper) || (hasUpper && hasDigit) || (hasLower && hasDigit))) {
        return true;
    }
    return false;
}

function isInternalStorageKey(key) {
    return typeof key === 'string' && key.startsWith('ptk_iast_');
}

function getTokenDataKind(value) {
    if (value == null) return 'unknown';
    const str = String(value).trim();
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(str) && str.length >= 30) {
        return 'jwt';
    }
    return isTokenLikeValue(value) ? 'token' : 'unknown';
}

function buildRoutingMeta() {
    const runtimeUrl = window.location.href;
    const pathname = getNormalizedPathname();
    const hashRoute = getHashRouteValue();
    const clientRoute = getClientRouteValue();
    const route = clientRoute || window.location.hash || pathname || null;
    let urlPattern = null;
    if (hashRoute) {
        urlPattern = `${runtimeUrl.split('#')[0] || runtimeUrl}#${hashRoute.split('?')[0] || ''}`;
    } else if (clientRoute) {
        urlPattern = `${window.location.origin}${String(clientRoute).split('?')[0] || clientRoute}`;
    }
    return {
        runtimeUrl,
        pathname,
        clientRoute,
        route,
        urlPattern
    };
}

// Best-effort propagation for common string operations
(function () {
    if (window.__PTK_IAST_PROPAGATION_INSTALLED__) return;
    window.__PTK_IAST_PROPAGATION_INSTALLED__ = true;
    if (!isSmartMode()) {
        const wrapStringMethod = (name) => {
            const orig = String.prototype[name];
            if (!orig || orig.__ptk_iast_wrapped__) return;
            const wrapped = function (...args) {
                const result = orig.apply(this, args);
                try {
                    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                        return result;
                    }
                    propagateTaint(result, `String.${name}`, [this, ...args]);
                } catch (_) { }
                return result;
            };
            wrapped.__ptk_iast_wrapped__ = true;
            String.prototype[name] = wrapped;
        };
        [
            'concat',
            'slice',
            'substring',
            'substr',
            'replace',
            'replaceAll',
            'toLowerCase',
            'toUpperCase',
            'trim',
            'padStart',
            'padEnd'
        ].forEach(wrapStringMethod);

        const origToString = String.prototype.toString;
        if (origToString && !origToString.__ptk_iast_wrapped__) {
            const wrapped = function (...args) {
                const result = origToString.apply(this, args);
                try {
                    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                        return result;
                    }
                    propagateTaint(result, 'String.toString', [this]);
                } catch (_) { }
                return result;
            };
            wrapped.__ptk_iast_wrapped__ = true;
            String.prototype.toString = wrapped;
        }
    }

    const origJsonParse = JSON.parse;
    if (origJsonParse && !origJsonParse.__ptk_iast_wrapped__) {
        const wrapped = function (text, ...rest) {
            const result = origJsonParse.call(this, text, ...rest);
            try {
                if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                    return result;
                }
                propagateTaint(result, 'JSON.parse', [text]);
            } catch (_) { }
            return result;
        };
        wrapped.__ptk_iast_wrapped__ = true;
        JSON.parse = wrapped;
    }

    if (typeof Headers !== 'undefined' && Headers.prototype && typeof Headers.prototype.set === 'function') {
        const origSet = Headers.prototype.set;
        if (!origSet.__ptk_iast_wrapped__) {
            const wrapped = function (name, value) {
                const result = origSet.call(this, name, value);
                try {
                    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                        return result;
                    }
                    propagateTaint(this, 'Headers.set', [value], { headerName: name });
                } catch (_) { }
                return result;
            };
            wrapped.__ptk_iast_wrapped__ = true;
            Headers.prototype.set = wrapped;
        }
    }

    if (typeof FormData !== 'undefined' && FormData.prototype && typeof FormData.prototype.append === 'function') {
        const origAppend = FormData.prototype.append;
        if (!origAppend.__ptk_iast_wrapped__) {
            const wrapped = function (name, value, filename) {
                const result = origAppend.call(this, name, value, filename);
                try {
                    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                        return result;
                    }
                    propagateTaint(this, 'FormData.append', [value], { fieldName: name });
                } catch (_) { }
                return result;
            };
            wrapped.__ptk_iast_wrapped__ = true;
            FormData.prototype.append = wrapped;
        }
    }
})();

function collectTaintedSources() {
    const raw = {};
    const add = (key, valRaw, metaOverride = null) => {
        if (!valRaw) return;
        let val = String(valRaw).trim().replace(/^#/, '');
        const hasAlnum = /[A-Za-z0-9]/.test(val);
        if (!hasAlnum && val !== '/') return;
        if ((key.startsWith('cookie:') || key.startsWith('localStorage:')) && !isTokenLikeValue(val)) {
            return;
        }
        const meta = Object.assign({}, metaOverride || describeSourceKey(key, val));
        const storedMeta = updateTaintMetaEntry(key, { taintKind: meta.taintKind, sourceKind: meta.sourceKind });
        const taint = createSource(val, meta.sourceKind || meta.type || 'unknown', Object.assign({}, meta, { sourceId: storedMeta?.sourceId || null }));
        updateTaintMetaEntry(key, { sourceId: taint.sourceId });
        raw[key] = val;
        registerTaintSource(key, val, Object.assign({}, meta, { sourceId: taint.sourceId }), { trackActivity: false });
    };
    for (const [k, v] of new URLSearchParams(location.search)) add(`query:${k}`, v);
    purgeHashTaintEntries();
    collectHashSources().forEach(src => add(src.key, src.value, src.meta));
    purgeRouteTaintEntries();
    collectRouteSources().forEach(src => add(src.key, src.value, src.meta));
    if (document.referrer) add('referrer', document.referrer);
    document.cookie.split(';').forEach(c => {
        const [k, v] = c.split('=').map(s => s.trim());
        const decodedVal = decodeURIComponent(v || '');
        add(`cookie:${k}`, decodedVal, createCookieSourceMeta(k, decodedVal));
    });
    ['localStorage', 'sessionStorage'].forEach(store => {
        try {
            for (let i = 0; i < window[store].length; i++) {
                const key = window[store].key(i), val = window[store].getItem(key);
                if (isInternalStorageKey(key)) continue;
                add(`${store}:${key}`, val);
            }
        } catch { };
    });
    if (window.name) add('window.name', window.name);
    //console.info('[IAST] Collected taints', raw);
    return raw;
}
window.__IAST_TAINT_GRAPH__ = window.__IAST_TAINT_GRAPH__ || {};
window.__IAST_TAINTED__ = collectTaintedSources();
scheduleExecutableBootstrapSweep('initial_seed');

function captureStackTrace(label = 'IAST flow') {
    try {
        return (new Error(label)).stack;
    } catch (_) {
        return null;
    }
}

function captureElementMeta(el) {
    if (!el || typeof el !== 'object') return {};
    return {
        domPath: getDomPath(el),
        elementId: el.id || null,
        elementTag: el.tagName ? el.tagName.toLowerCase() : null
    };
}

function describeSourceKey(key, rawValue) {
    if (!key) return {};
    const meta = {
        label: key,
        detail: key,
        location: window.location.href,
        value: rawValue
    };
    if (key.startsWith('query:')) {
        meta.type = 'query';
        meta.label = `Query parameter "${key.slice(6)}"`;
        meta.detail = key.slice(6) || key;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'query';
    } else if (key.startsWith('cookie:')) {
        meta.type = 'cookie';
        meta.label = `Cookie "${key.slice(7)}"`;
        meta.detail = key.slice(7) || key;
        meta.sourceKind = 'cookie';
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'user_input';
    } else if (key.startsWith('localStorage:')) {
        meta.type = 'localStorage';
        meta.label = `localStorage["${key.slice(13)}"]`;
        meta.sourceKind = 'localStorage';
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'unknown';
    } else if (key.startsWith('sessionStorage:')) {
        meta.type = 'sessionStorage';
        meta.label = `sessionStorage["${key.slice(15)}"]`;
        meta.sourceKind = 'sessionStorage';
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'unknown';
    } else if (key === 'window.name') {
        meta.type = 'windowName';
        meta.label = 'window.name';
        meta.sourceKind = 'windowName';
    } else if (key === 'referrer') {
        meta.type = 'referrer';
        meta.label = 'document.referrer';
        meta.sourceKind = 'referrer';
    } else if (key === 'hash:route') {
        meta.type = 'hashRoute';
        meta.label = 'Location hash route';
        meta.detail = rawValue || key;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'hashRoute';
    } else if (key.startsWith('hash:param:')) {
        const paramName = key.slice('hash:param:'.length) || 'param';
        meta.type = 'hashQuery';
        meta.label = `Location hash parameter "${paramName}"`;
        meta.detail = paramName;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'hashQuery';
    } else if (key === 'postMessage' || key.startsWith('postMessage:')) {
        meta.type = 'postMessage';
        meta.label = key === 'postMessage' ? 'postMessage message' : `postMessage from ${key.slice('postMessage:'.length)}`;
        meta.detail = key;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'postMessage';
    } else if (key === 'path:pathname') {
        meta.type = 'pathname';
        meta.label = 'Location pathname';
        meta.detail = rawValue || '/';
        meta.taintKind = 'user_input';
        meta.sourceKind = 'pathname';
    } else if (key.startsWith('path:segment:')) {
        const parts = key.split(':');
        const segment = parts.slice(3).join(':') || rawValue || 'segment';
        meta.type = 'pathSegment';
        meta.label = `Path segment "${segment}"`;
        meta.detail = segment;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'pathSegment';
    } else if (key === 'route:client') {
        meta.type = 'clientRoute';
        meta.label = 'Client route';
        meta.detail = rawValue || key;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'clientRoute';
    } else if (key === 'history:state') {
        meta.type = 'historyState';
        meta.label = 'history.state';
        meta.detail = rawValue || key;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'historyState';
    } else if (key.startsWith('body:param:')) {
        const paramName = key.slice('body:param:'.length) || 'param';
        meta.type = 'bodyParam';
        meta.label = `Request body parameter "${paramName}"`;
        meta.detail = paramName;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'bodyParam';
    } else if (key.startsWith('body:json:')) {
        const fieldPath = key.slice('body:json:'.length) || 'field';
        meta.type = 'jsonBodyField';
        meta.label = `JSON body field "${fieldPath}"`;
        meta.detail = fieldPath;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'jsonBodyField';
    } else if (key.startsWith('body:formdata:')) {
        const fieldName = key.slice('body:formdata:'.length) || 'field';
        meta.type = 'formDataField';
        meta.label = `FormData field "${fieldName}"`;
        meta.detail = fieldName;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'formDataField';
    } else if (key.startsWith('graphql:variables:')) {
        const fieldPath = key.slice('graphql:variables:'.length) || 'variable';
        meta.type = 'graphqlVariable';
        meta.label = `GraphQL variable "${fieldPath}"`;
        meta.detail = fieldPath;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'graphqlVariable';
    } else if (key.startsWith('response:json:')) {
        const fieldPath = key.slice('response:json:'.length) || 'field';
        meta.type = 'apiResponseField';
        meta.label = `API response field "${fieldPath}"`;
        meta.detail = fieldPath;
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'unknown';
        meta.sourceKind = 'apiResponseField';
    } else if (key.startsWith('graphql:response:')) {
        const fieldPath = key.slice('graphql:response:'.length) || 'field';
        meta.type = 'graphqlResponseField';
        meta.label = `GraphQL response field "${fieldPath}"`;
        meta.detail = fieldPath;
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'unknown';
        meta.sourceKind = 'graphqlResponseField';
    } else if (key.startsWith('inline:')) {
        meta.type = 'inline';
        meta.label = `Inline value "${key.slice(7)}"`;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'inline';
    }
    return meta;
}

function normalizeSourceEntry(entry, fallbackKey = null, fallbackRaw = null) {
    const provided = entry || {};
    const key = provided.key || provided.source || fallbackKey;
    if (!key) return null;
    const providedRaw = Object.prototype.hasOwnProperty.call(provided, 'raw')
        ? provided.raw
        : (Object.prototype.hasOwnProperty.call(provided, 'value') ? provided.value : undefined);
    const rawValue = providedRaw !== undefined ? providedRaw : fallbackRaw;
    const descriptor = describeSourceKey(key, rawValue);
    const storedMeta = getTaintMetaEntry(key) || {};
    const normalized = Object.assign({}, provided, {
        key,
        source: key,
        raw: rawValue,
        value: rawValue,
        label: provided.label || descriptor.label || key,
        detail: provided.detail || descriptor.detail || key,
        location: provided.location || descriptor.location || storedMeta.location || window.location.href,
        taintKind: provided.taintKind || storedMeta.taintKind || descriptor.taintKind || null,
        sourceKind: provided.sourceKind || storedMeta.sourceKind || descriptor.sourceKind || descriptor.type || null,
        sourceId: provided.sourceId || storedMeta.sourceId || null,
        origin: provided.origin || storedMeta.origin || null,
        isCrossOriginMessage: typeof provided.isCrossOriginMessage === 'boolean'
            ? provided.isCrossOriginMessage
            : (typeof storedMeta.isCrossOriginMessage === 'boolean' ? storedMeta.isCrossOriginMessage : null),
        responseUrl: provided.responseUrl || storedMeta.responseUrl || null,
        responseStatus: provided.responseStatus || storedMeta.responseStatus || null
    });
    normalized.__normalizedSource = true;
    return normalized;
}

function normalizeTaintedSources(sourceMatches, fallbackRaw = null) {
    if (!Array.isArray(sourceMatches)) return [];
    return sourceMatches
        .map(entry => normalizeSourceEntry(entry, entry?.key || entry?.source || null, entry?.raw ?? fallbackRaw))
        .filter(Boolean);
}

function formatSourceForReport(source) {
    if (!source) return 'Unknown source';
    const key = (source.key || source.source || '').toLowerCase();
    const detail = source.detail || source.label || key || 'source';
    const rawValue = source.value != null ? String(source.value) : (source.raw != null ? String(source.raw) : '');
    if (key.startsWith('hash:param:')) {
        return `location.hash parameter "${detail}" (value: "${rawValue}")`;
    }
    if (key === 'hash') {
        return `location.hash value "${rawValue || detail}"`;
    }
    if (key === 'hash:route') {
        return `location.hash route "${rawValue || detail}"`;
    }
    if (key === 'path:pathname') {
        return `location.pathname "${rawValue || detail}"`;
    }
    if (key.startsWith('path:segment:')) {
        return `location.pathname segment "${rawValue || detail}"`;
    }
    if (key === 'route:client') {
        return `client route "${rawValue || detail}"`;
    }
    if (key === 'history:state') {
        return `history.state (${rawValue || detail})`;
    }
    if (key.startsWith('query:param:') || key.startsWith('query:')) {
        return `location.search parameter "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('cookie:')) {
        return `document.cookie "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('body:param:')) {
        return `request body parameter "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('body:json:')) {
        return `JSON body field "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('body:formdata:')) {
        return `FormData field "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('graphql:variables:')) {
        return `GraphQL variable "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('response:json:')) {
        return `API response field "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('graphql:response:')) {
        return `GraphQL response field "${detail}" (value: "${rawValue}")`;
    }
    if (source.label && rawValue !== '') {
        return `${source.label} (${rawValue})`;
    }
    if (source.label) return source.label;
    if (source.source || source.key) return source.source || source.key;
    return 'Unknown source';
}

const DOM_XSS_SINK_IDS = new Set([
    'dom.inline_event',
    'dom.innerHTML',
    'dom.outerHTML',
    'dom.insertAdjacentHTML',
    'dom.mutation',
    'dom.domParser.parseFromString',
    'dom.range.createContextualFragment',
    'dom.element.setHTMLUnsafe',
    'dom.shadowRoot.setHTMLUnsafe',
    'document.write',
    'nav.iframe.srcdoc'
]);

function purgeHashTaintEntries() {
    const taints = window.__IAST_TAINTED__ || {};
    const meta = window.__IAST_TAINT_META__ || {};
    const graph = window.__IAST_TAINT_GRAPH__ || {};
    Object.keys(taints).forEach(key => {
        if (key === 'hash' || key.startsWith('hash:')) {
            delete taints[key];
            delete meta[key];
            delete graph[key];
        }
    });
}

function purgeQueryTaintEntries() {
    const taints = window.__IAST_TAINTED__ || {};
    const meta = window.__IAST_TAINT_META__ || {};
    const graph = window.__IAST_TAINT_GRAPH__ || {};
    Object.keys(taints).forEach(key => {
        if (key.startsWith('query:')) {
            delete taints[key];
            delete meta[key];
            delete graph[key];
        }
    });
}

function purgeRouteTaintEntries() {
    const taints = window.__IAST_TAINTED__ || {};
    const meta = window.__IAST_TAINT_META__ || {};
    const graph = window.__IAST_TAINT_GRAPH__ || {};
    Object.keys(taints).forEach(key => {
        if (key === 'path:pathname' || key === 'route:client' || key === 'history:state' || key.startsWith('path:segment:')) {
            delete taints[key];
            delete meta[key];
            delete graph[key];
        }
    });
}

function createHashSource({ key, label, op, detail, value, type }) {
    return {
        key,
        value,
        meta: {
            type: type || 'hash',
            label: label || key,
            detail: detail || key,
            op: op || 'hash',
            location: window.location.href,
            value,
            taintKind: 'user_input'
        }
    };
}

function createCookieSourceMeta(name, value, overrides = {}) {
    const detail = (name || '').trim() || 'cookie';
    return Object.assign({
        type: 'cookie',
        label: `Cookie "${detail}"`,
        detail,
        sourceKind: 'cookie',
        taintKind: 'user_input',
        op: 'document.cookie',
        location: window.location.href,
        value
    }, overrides);
}

function collectHashSources() {
    let raw = window.location.hash || '';
    if (raw.startsWith('#')) raw = raw.slice(1);
    try {
        raw = decodeURIComponent(raw);
    } catch (_) {
        raw = raw;
    }
    const normalized = (raw || '').trim();
    // Skip trivial hashes like "#" or "#/" to avoid tainting everything with base routes.
    if (!normalized || normalized === '/' || normalized === '#/' || normalized === '#') {
        return [];
    }
    const [routePartRaw, queryPartRaw] = normalized.split('?');
    const sources = [];
    const routePart = (routePartRaw || '').trim();
    if (routePart && routePart !== '/' && routePart !== '#/') {
        sources.push(createHashSource({
            key: 'hash:route',
            label: 'Location hash route',
            op: 'hashRoute',
            detail: routePart,
            value: routePart,
            type: 'hashRoute'
        }));
    }
    if (queryPartRaw && queryPartRaw.trim()) {
        const params = new URLSearchParams(queryPartRaw);
        for (const [name, value] of params.entries()) {
            const trimmedName = (name || '').trim();
            const trimmedVal = (value || '').trim();
            if (!trimmedName || !trimmedVal) continue;
            sources.push(createHashSource({
                key: `hash:param:${trimmedName}`,
                label: `Location hash parameter "${trimmedName}"`,
                op: 'hashParam',
                detail: trimmedName,
                value: trimmedVal,
                type: 'hashQuery'
            }));
        }
    }
    return sources;
}

function safeDecodeComponent(value) {
    if (value == null) return '';
    try {
        return decodeURIComponent(String(value));
    } catch (_) {
        return String(value);
    }
}

function getNormalizedPathname() {
    const pathname = safeDecodeComponent(window.location.pathname || '/').trim();
    if (!pathname) return '/';
    return pathname.startsWith('/') ? pathname : `/${pathname}`;
}

function getHashRouteValue() {
    let raw = window.location.hash || '';
    if (raw.startsWith('#')) raw = raw.slice(1);
    raw = safeDecodeComponent(raw).trim();
    if (!raw || raw === '/' || raw === '#/' || raw === '#') return '';
    const routePart = String(raw.split('?')[0] || '').trim();
    if (!routePart || routePart === '/' || routePart === '#/' || routePart === '#') return '';
    return routePart;
}

function getClientRouteValue() {
    const hashRoute = getHashRouteValue();
    if (hashRoute) return hashRoute;
    return getNormalizedPathname();
}

function collectRouteSources() {
    const sources = [];
    const pathname = getNormalizedPathname();
    if (pathname && pathname !== '/') {
        sources.push({
            key: 'path:pathname',
            value: pathname,
            meta: {
                type: 'pathname',
                sourceKind: 'pathname',
                label: 'Location pathname',
                detail: pathname,
                op: 'pathname',
                location: window.location.href,
                value: pathname,
                taintKind: 'user_input'
            }
        });

        pathname.split('/').filter(Boolean).forEach((segment, index) => {
            const normalizedSegment = safeDecodeComponent(segment).trim();
            if (!normalizedSegment) return;
            sources.push({
                key: `path:segment:${index}:${normalizedSegment}`,
                value: normalizedSegment,
                meta: {
                    type: 'pathSegment',
                    sourceKind: 'pathSegment',
                    label: `Path segment "${normalizedSegment}"`,
                    detail: normalizedSegment,
                    op: 'pathnameSegment',
                    location: window.location.href,
                    value: normalizedSegment,
                    taintKind: 'user_input'
                }
            });
        });
    }

    const clientRoute = getClientRouteValue();
    if (clientRoute && clientRoute !== '/') {
        sources.push({
            key: 'route:client',
            value: clientRoute,
            meta: {
                type: 'clientRoute',
                sourceKind: 'clientRoute',
                label: 'Client route',
                detail: clientRoute,
                op: 'clientRoute',
                location: window.location.href,
                value: clientRoute,
                taintKind: 'user_input'
            }
        });
    }

    const historyState = safeSerializeValue(window.history?.state);
    if (isMeaningfulSourceValue(historyState) && String(historyState).length <= 2000) {
        sources.push({
            key: 'history:state',
            value: historyState,
            meta: {
                type: 'historyState',
                sourceKind: 'historyState',
                label: 'history.state',
                detail: historyState,
                op: 'history.state',
                location: window.location.href,
                value: historyState,
                taintKind: 'user_input'
            }
        });
    }
    return sources;
}

function isMeaningfulSourceValue(value) {
    if (value == null) return false;
    const trimmed = String(value).trim();
    if (!trimmed) return false;
    if (trimmed.length < 3) return false;
    if (trimmed === '/' || trimmed === '#/' || trimmed === '#') return false;
    return true;
}

function isSourceMatchingValue(sourceValue, sinkValue) {
    if (!isMeaningfulSourceValue(sourceValue)) return false;
    const sinkStr = String(sinkValue || '');
    const sourceStr = String(sourceValue || '');
    if (!sinkStr || !sourceStr) return false;
    return sinkStr.indexOf(sourceStr) !== -1;
}

function resolveUrlRelative(url) {
    if (!url) return null;
    try {
        return new URL(url, window.location.href);
    } catch (_) {
        return null;
    }
}

function isCrossOriginUrl(url) {
    const resolved = resolveUrlRelative(url);
    if (!resolved) return false;
    return resolved.origin !== window.location.origin;
}

const DANGEROUS_URL_SCHEMES = new Set(['javascript', 'data']);
const DANGEROUS_URL_SINK_MAP = Object.freeze({
    'dom.attr.href': {
        javascript: 'dom.attr.href.javascriptUrl',
        data: 'dom.attr.href.dataUrl'
    },
    'dom.attr.action': {
        javascript: 'dom.attr.action.javascriptUrl',
        data: 'dom.attr.action.dataUrl'
    },
    'dom.attr.formaction': {
        javascript: 'dom.attr.formaction.javascriptUrl',
        data: 'dom.attr.formaction.dataUrl'
    },
    'dom.attr.src': {
        javascript: 'dom.attr.src.javascriptUrl',
        data: 'dom.attr.src.dataUrl'
    },
    'nav.iframe.src': {
        javascript: 'nav.iframe.src.javascriptUrl',
        data: 'nav.iframe.src.dataUrl'
    },
    'nav.location.href': {
        javascript: 'nav.location.href.javascriptUrl',
        data: 'nav.location.href.dataUrl'
    },
    'nav.location.assign': {
        javascript: 'nav.location.assign.javascriptUrl',
        data: 'nav.location.assign.dataUrl'
    },
    'nav.location.replace': {
        javascript: 'nav.location.replace.javascriptUrl',
        data: 'nav.location.replace.dataUrl'
    },
    'nav.window.open': {
        javascript: 'nav.window.open.javascriptUrl',
        data: 'nav.window.open.dataUrl'
    },
    'script.element.src': {
        data: 'script.element.src.dataUrl'
    }
});

function getUrlScheme(rawUrl) {
    if (rawUrl == null) return null;
    const value = String(rawUrl).trim();
    if (!value) return null;
    const explicit = value.match(/^([a-z][a-z0-9+.-]*):/i);
    if (explicit?.[1]) {
        return explicit[1].toLowerCase();
    }
    try {
        const parsed = new URL(value, window.location.href);
        return parsed.protocol ? parsed.protocol.replace(':', '').toLowerCase() : null;
    } catch (_) {
        return null;
    }
}

function getDangerousUrlScheme(rawUrl) {
    const scheme = getUrlScheme(rawUrl);
    return scheme && DANGEROUS_URL_SCHEMES.has(scheme) ? scheme : null;
}

function resolveDangerousUrlSinkId(baseSinkId, rawUrl) {
    if (!baseSinkId) return null;
    const scheme = getDangerousUrlScheme(rawUrl);
    if (!scheme) return null;
    return DANGEROUS_URL_SINK_MAP?.[baseSinkId]?.[scheme] || null;
}

function looksLikeInternalRoute(url) {
    if (!url) return false;
    const str = String(url).trim();
    if (!str) return false;
    if (str === '/' || str === '#/' || str === '#') return true;
    if (str.startsWith('#/')) return true;
    if (str.startsWith('/')) return true;
    return false;
}

function shouldReportNavigationSink(targetUrl) {
    if (!targetUrl) return false;
    if (getDangerousUrlScheme(targetUrl)) {
        return true;
    }
    if (looksLikeInternalRoute(targetUrl)) {
        // Ignore internal SPA routes like /login or #/search to reduce noise.
        return false;
    }
    return isCrossOriginUrl(targetUrl);
}

function shouldReportRouteControlledNavigationSink(targetUrl) {
    if (!targetUrl) return false;
    if (shouldReportNavigationSink(targetUrl)) return true;
    return looksLikeInternalRoute(targetUrl);
}

function looksLikeXssPayload(value) {
    if (value == null) return false;
    const str = String(value);
    const trimmed = str.trim();
    if (!trimmed) return false;
    const lower = trimmed.toLowerCase();
    const hasAngleBrackets = /[<>]/.test(trimmed);
    const hasJsScheme = lower.includes('javascript:');
    const hasOnEvent = lower.includes('onerror') || lower.includes('onload') || lower.includes('onclick') || lower.includes('onmouseover');
    const hasDangerousTags = lower.includes('<script') || lower.includes('<img') || lower.includes('<svg') || lower.includes('<iframe');
    if (hasJsScheme || hasOnEvent || hasDangerousTags) return true;
    if (hasAngleBrackets && (hasOnEvent || hasDangerousTags)) return true;
    return false;
}

function isUserControlledSource(source) {
    if (!source) return false;
    if (source.taintKind === 'user_input') return true;
    const key = (source.key || source.source || '').toLowerCase();
    if (!key) return false;
    if (key.startsWith('hash:param:')) return true;
    if (key === 'hash:route' || key === 'hash') return true;
    if (key === 'path:pathname' || key === 'route:client' || key === 'history:state' || key.startsWith('path:segment:')) return true;
    if (key.startsWith('query:param:') || key.startsWith('query:')) return true;
    if (key.startsWith('cookie:')) return true;
    if (key.startsWith('body:param:') || key.startsWith('body:json:') || key.startsWith('body:formdata:')) return true;
    if (key.startsWith('graphql:variables:')) return true;
    if (key.startsWith('inline:')) return true;
    return false;
}

function isCookieSource(source) {
    if (!source) return false;
    if (source.sourceKind === 'cookie') return true;
    const key = (source.key || source.source || '').toLowerCase();
    if (!key) return false;
    return key.startsWith('cookie:');
}

function shouldReportDomXss(attrName, newValue, taintedSources = []) {
    const sources = Array.isArray(taintedSources) ? taintedSources : [];
    const attr = (attrName || '').toLowerCase();
    if (attr === 'routerlink' || attr === 'routerlinkactive' || attr === 'ng-reflect-router-link') {
        // Router attributes pointing to internal routes are not interesting sinks.
        return false;
    }
    const hasUserInput = sources.some(isUserControlledSource);
    const cookieSources = sources.filter(isCookieSource);
    const hasCookieSources = cookieSources.length > 0;

    if (hasCookieSources && sources.length === cookieSources.length) {
        const cookieHasXssPayload = cookieSources.some(src => looksLikeXssPayload(src?.value ?? src?.raw));
        if (!cookieHasXssPayload) {
            return false;
        }
    }

    if (hasUserInput) {
        if (attr === 'innerhtml' || attr === 'outerhtml' || !attr) {
            return true;
        }
        if (attr === 'href' || attr === 'src' || attr.startsWith('on')) {
            return true;
        }
        return false;
    }
    const valueStr = newValue == null ? '' : String(newValue);
    if ((attr === 'href' || attr === 'src') && !looksLikeXssPayload(valueStr)) {
        return false;
    }
    return looksLikeXssPayload(valueStr);
}

function isSuspiciousExfilUrl(url) {
    if (!url) return false;
    const str = String(url);
    if (isCrossOriginUrl(str)) return true;
    const lower = str.toLowerCase();
    if (lower.includes('callback') || lower.includes('webhook') || lower.includes('tracking') || lower.includes('pixel')) {
        return true;
    }
    if (lower.includes('token=') || lower.includes('session=') || lower.includes('auth=')) {
        return true;
    }
    return false;
}

function evaluateSinkHeuristics(value, info = {}, context = {}, taintedSources = []) {
    const sinkId = info?.sinkId || info?.sink || null;
    if (!sinkId) return { skip: false, downgrade: null };
    if (DOM_XSS_SINK_IDS.has(sinkId)) {
        const attrName = context.attribute || context.attr || context.attrName || context.eventType || null;
        const sources = Array.isArray(taintedSources) && taintedSources.length ? taintedSources : (context.taintedSources || []);
        if (!shouldReportDomXss(attrName, value, sources)) {
            const attr = String(attrName || '').toLowerCase();
            const hasUserInput = sources.some(isUserControlledSource);
            return {
                skip: false,
                downgrade: {
                    primaryClass: hasUserInput ? IAST_PRIMARY_CLASSES.HYBRID : IAST_PRIMARY_CLASSES.OBSERVATION,
                    severity: (attr === 'innerhtml' || attr === 'outerhtml' || attr.startsWith('on')) ? 'low' : 'info',
                    reason: IAST_REASON_CODES.FLOW_MATCH,
                    confidence: hasUserInput ? 55 : 45,
                    confidencePenalty: hasUserInput ? 20 : 30,
                    details: {
                        heuristic: 'dom_xss_low_signal',
                        attribute: attr || null,
                        userControlledSource: hasUserInput
                    }
                }
            };
        }
    }
    return { skip: false, downgrade: null };
}

function applyHeuristicDowngrade(context = {}, downgrade = null) {
    if (!downgrade || typeof downgrade !== 'object') return;
    if (!context.primaryClass || context.primaryClass === IAST_PRIMARY_CLASSES.TAINT_FLOW) {
        context.primaryClass = downgrade.primaryClass || IAST_PRIMARY_CLASSES.HYBRID;
    }
    if (!context.severityOverride) {
        context.severityOverride = downgrade.severity || 'info';
    }
    const existingPenalty = Number.isFinite(context.confidencePenalty) ? context.confidencePenalty : 0;
    if (Number.isFinite(downgrade.confidencePenalty) && downgrade.confidencePenalty > existingPenalty) {
        context.confidencePenalty = downgrade.confidencePenalty;
    }
    context.detection = Object.assign({}, context.detection || {}, {
        reason: context.detection?.reason || downgrade.reason || IAST_REASON_CODES.FLOW_MATCH,
        confidence: context.detection?.confidence ?? downgrade.confidence ?? 55,
        details: Object.assign({}, context.detection?.details || {}, downgrade.details || {})
    });
}

function registerTaintSource(key, value, meta = {}, options = {}) {
    if (!key) return;
    if (options.trackActivity !== false) {
        markTaintActivity();
    }
    updateTaintMetaEntry(key, { taintKind: meta.taintKind });
    window.__IAST_TAINT_GRAPH__[key] = {
        node: {
            key,
            label: meta.label || key,
            type: meta.type || 'source',
            detail: meta.detail || key,
            domPath: meta.domPath || null,
            elementId: meta.elementId || null,
            attribute: meta.attribute || null,
            location: meta.location || window.location.href,
            value,
            op: meta.op || meta.type || 'source',
            stack: meta.stack || captureStackTrace('IAST source'),
            timestamp: Date.now()
        },
        parents: []
    };
}

function registerTaintPropagation(key, value, matchResult, meta = {}, options = {}) {
    if (!key) return;
    if (options.trackActivity !== false) {
        markTaintActivity();
    }
    updateTaintMetaEntry(key, { taintKind: meta.taintKind });
    const parents = Array.isArray(matchResult?.allSources)
        ? matchResult.allSources
            .filter(src => src && src.source)
            .map(src => ({ key: src.source }))
        : [];
    window.__IAST_TAINT_GRAPH__[key] = {
        node: {
            key,
            label: meta.label || key,
            type: meta.type || 'propagation',
            detail: meta.detail || '',
            domPath: meta.domPath || null,
            elementId: meta.elementId || null,
            attribute: meta.attribute || null,
            location: meta.location || window.location.href,
            value,
            op: meta.op || 'propagation',
            stack: meta.stack || captureStackTrace(meta.op || 'propagation'),
            timestamp: Date.now()
        },
        parents
    };
}

function ensureTaintGraphEntry(key, value, meta = {}, options = {}) {
    if (meta.parentsMatch) {
        registerTaintPropagation(key, value, meta.parentsMatch, meta, options);
    } else {
        registerTaintSource(key, value, meta, options);
    }
}

function buildTaintFlowChain(key, depth = 0, visited = new Set()) {
    if (!key || depth > 20 || visited.has(key)) return [];
    visited.add(key);
    const entry = window.__IAST_TAINT_GRAPH__?.[key];
    if (!entry) {
        return [{
            stage: depth === 0 ? 'source' : 'propagation',
            key,
            label: key,
            value: window.__IAST_TAINTED__?.[key] || null
        }];
    }
    const parents = entry.parents && entry.parents.length ? entry.parents : null;
    let parentChain = [];
    if (parents && parents.length) {
        parentChain = buildTaintFlowChain(parents[0].key, depth + 1, visited);
    }
    const node = Object.assign({
        stage: parents && parents.length ? 'propagation' : 'source',
        key: entry.node?.key || key,
        label: entry.node?.label || key,
        detail: entry.node?.detail || '',
        domPath: entry.node?.domPath || null,
        elementId: entry.node?.elementId || null,
        attribute: entry.node?.attribute || null,
        location: entry.node?.location || null,
        value: entry.node?.value || null,
        op: entry.node?.op || null,
        stack: entry.node?.stack || null,
        timestamp: entry.node?.timestamp || Date.now()
    });
    return parentChain.concat([node]);
}

function buildTaintFlow(match, sinkMeta = {}) {
    if (!match) return [];
    const chain = buildTaintFlowChain(match.source) || [];
    const sinkNode = {
        stage: 'sink',
        key: sinkMeta.sinkId || sinkMeta.sink || 'sink',
        label: sinkMeta.sink || sinkMeta.sinkId || 'sink',
        op: sinkMeta.ruleId || sinkMeta.type || 'sink',
        domPath: sinkMeta.domPath || null,
        elementId: sinkMeta.elementId || null,
        attribute: sinkMeta.attribute || null,
        location: sinkMeta.location || window.location.href,
        value: sinkMeta.value || null,
        detail: sinkMeta.detail || null
    };
    return chain.concat([sinkNode]);
}

function buildRuleBinding({ sinkId, ruleId, variant = null, fallbackType }) {
    return resolveIastRuntimeBinding({
        runtimePlan: IAST_RUNTIME_PLAN,
        sinkId,
        ruleId,
        variant,
        fallbackType,
    }).binding;
}

function buildObservedRuleBinding({ sinkId, value, match = null, context = {}, fallbackType }) {
    const resolvedMatch = match || matchesTaint(value);
    const normalizedSources = normalizeTaintedSources(resolvedMatch?.allSources || [], resolvedMatch?.raw || value);
    const sourceKinds = normalizedSources
        .map((entry) => entry?.sourceKind || entry?.kind || null)
        .filter(Boolean);
    const isCrossOrigin = typeof context.isCrossOrigin === 'boolean'
        ? context.isCrossOrigin
        : Boolean(context.networkTarget?.isCrossOrigin);
    const variantEntry = selectIastRuleVariant({
        runtimePlan: IAST_RUNTIME_PLAN,
        sinkId,
        sourceKinds,
        isCrossOrigin
    });
    return buildRuleBinding({
        sinkId,
        ruleId: variantEntry?.ruleId || null,
        fallbackType
    });
}

function applyPostMessageReceiverSignals(context = {}, primarySource = null) {
    if (!primarySource || primarySource.sourceKind !== 'postMessage') return;
    const sourceOrigin = primarySource.origin || null;
    if (sourceOrigin && !context.origin) {
        context.origin = sourceOrigin;
    }
    const isCrossOriginMessage = primarySource.isCrossOriginMessage === true
        || Boolean(sourceOrigin && sourceOrigin !== 'null' && sourceOrigin !== window.location.origin);
    context.sourceRole = context.sourceRole || IAST_SOURCE_ROLES.ORIGIN;
    context.trust = Object.assign({}, context.trust || {}, {
        level: isCrossOriginMessage ? IAST_TRUST_LEVELS.THIRD_PARTY : IAST_TRUST_LEVELS.SAME_ORIGIN,
        decision: isCrossOriginMessage ? IAST_TRUST_DECISIONS.WARN : IAST_TRUST_DECISIONS.ALLOW
    });
    context.detection = Object.assign({}, context.detection || {}, {
        reason: context.detection?.reason || (isCrossOriginMessage
            ? IAST_REASON_CODES.CROSS_ORIGIN_POSTMESSAGE_RECEIVER
            : IAST_REASON_CODES.POSTMESSAGE_RECEIVER_SAME_ORIGIN),
        dataKind: context.detection?.dataKind || IAST_DATA_KINDS.UNKNOWN,
        confidence: context.detection?.confidence || (isCrossOriginMessage ? 78 : 58),
        details: Object.assign({}, context.detection?.details || {}, {
            messageOrigin: sourceOrigin || 'unknown',
            crossOriginMessage: isCrossOriginMessage
        })
    });
}

function applyResponseSourceSignals(context = {}, primarySource = null, sinkId = null) {
    const sourceKind = String(primarySource?.sourceKind || '');
    if (sourceKind !== 'apiResponseField' && sourceKind !== 'graphqlResponseField') return;
    const sourcePath = String(primarySource?.detail || primarySource?.key || '').toLowerCase();
    const authLike = isAuthLikeResponseFieldPath(sourcePath);
    context.sourceRole = context.sourceRole || IAST_SOURCE_ROLES.DERIVED;
    if ((sinkId || '').startsWith('storage.')) {
        context.primaryClass = context.primaryClass || IAST_PRIMARY_CLASSES.HYBRID;
        context.detection = Object.assign({}, context.detection || {}, {
            reason: context.detection?.reason || (authLike
                ? IAST_REASON_CODES.RESPONSE_AUTH_STATE_REUSE
                : IAST_REASON_CODES.RESPONSE_FIELD_CLIENT_PERSISTENCE),
            dataKind: context.detection?.dataKind || (primarySource?.taintKind === 'secret' ? IAST_DATA_KINDS.TOKEN : IAST_DATA_KINDS.UNKNOWN),
            confidence: context.detection?.confidence || (authLike ? 76 : 68),
            details: Object.assign({}, context.detection?.details || {}, {
                responseField: primarySource?.detail || primarySource?.key || null,
                responseUrl: primarySource?.responseUrl || null,
                responseStatus: primarySource?.responseStatus || null
            })
        });
        return;
    }
    if (
        sinkId === 'http.fetch.headers'
        || sinkId === 'http.xhr.setRequestHeader'
        || sinkId === 'postmessage.anyOrigin'
        || sinkId === 'postmessage.crossOrigin'
        || sinkId === 'realtime.websocket.send'
        || sinkId === 'realtime.webrtc.send'
    ) {
        context.primaryClass = context.primaryClass || IAST_PRIMARY_CLASSES.HYBRID;
        context.detection = Object.assign({}, context.detection || {}, {
            reason: context.detection?.reason || (authLike
                ? IAST_REASON_CODES.RESPONSE_AUTH_STATE_REUSE
                : IAST_REASON_CODES.RESPONSE_FIELD_CROSS_BOUNDARY),
            dataKind: context.detection?.dataKind || (primarySource?.taintKind === 'secret' ? IAST_DATA_KINDS.TOKEN : IAST_DATA_KINDS.UNKNOWN),
            confidence: context.detection?.confidence || (authLike ? 80 : 72),
            details: Object.assign({}, context.detection?.details || {}, {
                responseField: primarySource?.detail || primarySource?.key || null,
                responseUrl: primarySource?.responseUrl || null,
                responseStatus: primarySource?.responseStatus || null
            })
        });
    }
}

function applySourceSpecificSignals(context = {}, primarySource = null, sinkId = null) {
    if (!primarySource) return;
    applyPostMessageReceiverSignals(context, primarySource);
    applyResponseSourceSignals(context, primarySource, sinkId);
}
// Dynamic monitoring (storage, cookie, window.name, hash)
(function () {
    const taints = window.__IAST_TAINTED__;
    const meta = window.__IAST_TAINT_META__;
    const record = (key, val, options = {}) => {
        if (!val) return;
        const s = String(val);
        const hasAlnum = /[A-Za-z0-9]/.test(s);
        if (!hasAlnum && s !== '/') return;
        taints[key] = s;
        const mergedMeta = Object.assign({}, describeSourceKey(key, s), options);
        const storedMeta = updateTaintMetaEntry(key, { taintKind: mergedMeta.taintKind, sourceKind: mergedMeta.sourceKind });
        const taint = createSource(s, mergedMeta.sourceKind || mergedMeta.type || 'unknown', Object.assign({}, mergedMeta, { sourceId: storedMeta?.sourceId || null }));
        updateTaintMetaEntry(key, { sourceId: taint.sourceId });
        ensureTaintGraphEntry(key, s, Object.assign({}, mergedMeta, { sourceId: taint.sourceId }), {
            trackActivity: options.trackActivity !== false
        });
        //console.info('[IAST] Updated source', key, s);
    };
    const refreshHashSources = () => {
        purgeHashTaintEntries();
        const sources = collectHashSources();
        sources.forEach(src => {
            record(src.key, src.value, Object.assign({}, src.meta, {
                trackActivity: !isSmartMode()
            }));
        });
        scheduleExecutableBootstrapSweep('hash_refresh');
    };
    const refreshQuerySources = () => {
        purgeQueryTaintEntries();
        for (const [key, value] of new URLSearchParams(location.search)) {
            record(`query:${key}`, value, {
                trackActivity: !isSmartMode()
            });
        }
        scheduleExecutableBootstrapSweep('query_refresh');
    };
    const refreshRouteSources = () => {
        purgeRouteTaintEntries();
        const sources = collectRouteSources();
        sources.forEach(src => {
            record(src.key, src.value, Object.assign({}, src.meta, {
                trackActivity: !isSmartMode()
            }));
        });
        scheduleExecutableBootstrapSweep('route_refresh');
    };
    const refreshLocationSources = () => {
        refreshQuerySources();
        refreshHashSources();
        refreshRouteSources();
    };
    window.__IAST_REFRESH_ROUTE_SOURCES__ = refreshLocationSources;
    // Storage wrappers
    const proto = Storage.prototype;
    ['setItem', 'removeItem', 'clear'].forEach(fn => {
        const orig = proto[fn];
        proto[fn] = function (k, v) {
            const area = this === localStorage ? 'localStorage' : 'sessionStorage';
            if (fn === 'setItem') {
                if (isInternalStorageKey(k)) {
                    return orig.apply(this, arguments);
                }
                if (!isTokenLikeValue(v)) {
                    return orig.apply(this, arguments);
                }
                const storageHooksEnabled = isHookGroupEnabled('hook.storage');
                const match = matchesTaint(v);
                const elMeta = captureElementMeta(document?.activeElement || null);
                const sinkId = area === 'localStorage' ? 'storage.localStorage.setItem' : 'storage.sessionStorage.setItem';
                const ruleId = area === 'localStorage' ? 'localstorage_token_persist' : 'sessionstorage_token_persist';
                const binding = buildRuleBinding({ sinkId, ruleId, fallbackType: 'storage-token-leak' });
                const dataKind = getTokenDataKind(v);
                const origin = getTokenOrigin(v);
                record(`${area}:${k}`, v, {
                    label: `${area}:${k}`,
                    type: area,
                    op: `${area}.setItem`,
                    domPath: elMeta.domPath,
                    elementId: elMeta.elementId,
                    parentsMatch: match
                });
                if (!storageHooksEnabled) {
                    emitStorageObservationSignal({ area, key: k, value: v, elMeta });
                    return orig.apply(this, arguments);
                }
                const reportObservation = (originValue) => {
                    maybeReportTaintedValue(v, binding, Object.assign({
                        storageKey: k,
                        storageArea: area,
                        value: v,
                        primaryClass: 'observation',
                        sourceRole: 'observed',
                        origin: originValue,
                        detection: {
                            reason: dataKind === 'jwt' ? 'jwt_heuristic' : 'token_heuristic',
                            dataKind,
                            confidence: 80,
                            details: {
                                matchedBy: dataKind === 'jwt' ? 'jwt_structure' : 'token_heuristic',
                                valuePreview: buildSourcePreview(v),
                                length: String(v || '').length
                            }
                        },
                        observedAt: { kind: area === 'localStorage' ? 'storage.localStorage' : 'storage.sessionStorage', key: k },
                        operation: { sinkId, sinkArgs: { key: k, area } }
                    }, elMeta), match);
                };
                if (origin) {
                    reportObservation(origin);
                } else {
                    setTimeout(() => {
                        reportObservation(getTokenOrigin(v));
                    }, IAST_ORIGIN_WAIT_MS);
                }
            }
            if (fn === 'removeItem') delete taints[`${this === localStorage ? 'localStorage' : 'sessionStorage'}:${k}`];
            if (fn === 'clear') Object.keys(taints)
                .filter(x => x.startsWith(this === localStorage ? 'localStorage:' : 'sessionStorage:'))
                .forEach(x => delete taints[x]);
            return orig.apply(this, arguments);
        };
    });
    // window.name
    if (typeof window.__defineSetter__ === 'function') {
        let cur = window.name;
        window.__defineSetter__('name', v => {
            cur = v;
            record('window.name', v, describeSourceKey('window.name', v));
        });
        window.__defineGetter__('name', () => cur);
    }
    // cookie
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (desc && desc.configurable) {
        Object.defineProperty(Document.prototype, 'cookie', {
            get() { return desc.get.call(document); },
            set(v) {
                const res = desc.set.call(document, v);
                const [p = ""] = v.split(';');
                const [k = "", rawVal = ""] = p.split('=');
                let decoded = '';
                try {
                    decoded = decodeURIComponent(rawVal || '');
                } catch (_) {
                    decoded = rawVal || '';
                }
                if (!isTokenLikeValue(decoded)) {
                    return res;
                }
                const storageHooksEnabled = isHookGroupEnabled('hook.storage');
                const match = matchesTaint(decoded);
                const elMeta = captureElementMeta(document?.activeElement || null);
                const binding = buildRuleBinding({
                    sinkId: 'storage.document.cookie',
                    fallbackType: 'storage-token-leak'
                });
                const dataKind = getTokenDataKind(decoded);
                const origin = getTokenOrigin(decoded);
                record(`cookie:${k}`, decoded, Object.assign(
                    createCookieSourceMeta(k, decoded, { value: decoded }),
                    {
                        domPath: elMeta.domPath,
                        elementId: elMeta.elementId,
                        parentsMatch: match
                    }
                ));
                if (!storageHooksEnabled) {
                    emitStorageObservationSignal({ area: 'cookie', key: k, value: decoded, rawCookie: v, elMeta });
                    return res;
                }
                const reportObservation = (originValue) => {
                    maybeReportTaintedValue(decoded, binding, Object.assign({
                        cookieName: k,
                        rawCookie: v,
                        value: decoded,
                        primaryClass: 'observation',
                        sourceRole: 'observed',
                        origin: originValue,
                        detection: {
                            reason: dataKind === 'jwt' ? 'jwt_heuristic' : 'token_heuristic',
                            dataKind,
                            confidence: 80,
                            details: {
                                matchedBy: dataKind === 'jwt' ? 'jwt_structure' : 'token_heuristic',
                                valuePreview: buildSourcePreview(decoded),
                                length: String(decoded || '').length
                            }
                        },
                        observedAt: { kind: 'storage.cookie', cookieName: k },
                        operation: { sinkId: 'storage.document.cookie', sinkArgs: { cookieName: k } }
                    }, elMeta), match);
                };
                if (origin) {
                    reportObservation(origin);
                } else {
                    setTimeout(() => {
                        reportObservation(getTokenOrigin(decoded));
                    }, IAST_ORIGIN_WAIT_MS);
                }
                return res;
            },
            configurable: true
        });
    }
    // hashchange
    window.addEventListener('hashchange', () => {
        refreshHashSources();
        refreshRouteSources();
    });

    window.addEventListener('popstate', () => {
        refreshRouteSources();
    });

    // postMessage source
    window.addEventListener('message', (event) => {
        if (!isHookGroupEnabled('hook.postMessage')) return;
        try {
            const data = event?.data;
            if (data && typeof data === 'object') {
                if (data.ptk_iast || data.ptk_ws || data.source === 'ptk-automation') return;
                if (typeof data.channel === 'string' && data.channel.startsWith('ptk_')) return;
            }
            const payload = safeSerializeValue(event?.data);
            if (!payload) return;
            const origin = event?.origin || 'unknown';
            const isCrossOriginMessage = Boolean(origin && origin !== 'null' && origin !== 'unknown' && origin !== window.location.origin);
            record(`postMessage:${origin}`, payload, {
                type: 'postMessage',
                label: `postMessage from ${origin}`,
                taintKind: 'user_input',
                sourceKind: 'postMessage',
                origin,
                isCrossOriginMessage,
                detail: origin
            });
        } catch (_) {
            // ignore postMessage source errors
        }
    });
})();

// Inline source capture: track user input events (input/change)
(function () {
    const isInputElement = (el) =>
        el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement;
    const lastInlineAt = new WeakMap();

    const recordInlineValue = (el) => {
        if (!el || !isInputElement(el)) return;
        const val = el.value;
        if (!val) return;
        if (String(val).length > 2000) return;
        const key = `inline:${el.id || el.name || el.tagName?.toLowerCase() || 'input'}`;
        const value = String(val);
        window.__IAST_TAINTED__[key] = value;
        updateTaintMetaEntry(key, { taintKind: 'user_input', sourceKind: 'inline' });
        const meta = Object.assign({
            type: 'inline',
            sourceKind: 'inline',
            label: `Inline value "${key.slice(7)}"`,
            taintKind: 'user_input'
        }, captureElementMeta(el));
        registerTaintSource(key, value, meta);
    };

    document.addEventListener('input', (event) => {
        if (event && event.isTrusted === false) return;
        const target = event?.target;
        if (!target) return;
        const now = Date.now();
        const last = lastInlineAt.get(target) || 0;
        if (now - last < 300) return;
        lastInlineAt.set(target, now);
        recordInlineValue(target);
    }, true);

    document.addEventListener('change', (event) => {
        recordInlineValue(event?.target);
    }, true);
})();


function matchesTaint(input) {
    if (__IAST_DISABLE_HOOKS__) return null;
    const taints = Object.entries(window.__IAST_TAINTED__ || {}).filter(([, v]) => v);
    if (!taints.length) return null;
    let rawStr = String(input || '');
    try { rawStr = htmlDecode(rawStr); } catch { }
    rawStr = rawStr.toLowerCase();
    if (!/[a-z0-9\/]/i.test(rawStr)) return null;

    // Fast path: skip if no taint token appears in the input
    let hasToken = false;
    for (const [key, val] of taints) {
        if (!val) continue;
        const token = String(val).trim().toLowerCase();
        if (!token) continue;
        if (rawStr.indexOf(token) !== -1) {
            hasToken = true;
            break;
        }
    }
    if (!hasToken) return null;

    const meta = window.__IAST_TAINT_META__ || {};
    const matches = [];

    const kindOf = (key) => {
        if (key.startsWith('query:')) return 'query';
        if (key === 'hash:route') return 'hashRoute';
        if (key.startsWith('hash:param:')) return 'hashQuery';
        if (key === 'path:pathname') return 'pathname';
        if (key.startsWith('path:segment:')) return 'pathSegment';
        if (key === 'route:client') return 'clientRoute';
        if (key === 'history:state') return 'historyState';
        if (key.startsWith('body:param:')) return 'bodyParam';
        if (key.startsWith('body:json:')) return 'jsonBodyField';
        if (key.startsWith('body:formdata:')) return 'formDataField';
        if (key.startsWith('graphql:variables:')) return 'graphqlVariable';
        if (key.startsWith('response:json:')) return 'apiResponseField';
        if (key.startsWith('graphql:response:')) return 'graphqlResponseField';
        if (key === 'referrer') return 'referrer';
        if (key.startsWith('cookie:')) return 'cookie';
        if (key.startsWith('localStorage:')) return 'localStorage';
        if (key.startsWith('sessionStorage:')) return 'sessionStorage';
        if (key === 'window.name') return 'windowName';
        if (key === 'postMessage' || key.startsWith('postMessage:')) return 'postMessage';
        if (key.startsWith('inline:')) return 'inline';
        return 'other';
    };

    const kindPriority = (kind) => {
        switch (kind) {
            case 'query': return 100;
            case 'hashQuery': return 90;
            case 'hashRoute': return 85;
            case 'clientRoute': return 82;
            case 'pathname': return 80;
            case 'pathSegment': return 78;
            case 'historyState': return 76;
            case 'formDataField': return 75;
            case 'bodyParam': return 74;
            case 'jsonBodyField': return 72;
            case 'graphqlVariable': return 71;
            case 'graphqlResponseField': return 69;
            case 'apiResponseField': return 68;
            case 'inline': return 80;
            case 'localStorage': return 70;
            case 'sessionStorage': return 60;
            case 'cookie': return 50;
            case 'referrer': return 40;
            case 'windowName': return 30;
            case 'postMessage': return 30;
            default: return 10;
        }
    };

    const matchTypePriority = (matchType) => {
        switch (matchType) {
            case 'url-eq': return 3;
            case 'exact': return 2;
            case 'token': return 1;
            case 'substring': return 0;
            default: return 0;
        }
    };

    const looksLikeUrl = (s) => /^[a-z][\w+.-]+:\/\//i.test(s);

    for (const [sourceKey, rawVal] of taints) {
        if (!rawVal) continue;
        if (!isMeaningfulSourceValue(rawVal)) continue;
        let tv = String(rawVal).trim().toLowerCase().replace(/^#/, '').replace(/;$/, '');
        if (!tv) continue;

        let rawToMatch = rawStr;
        let tvToMatch = tv;
        let matchType = null;

        if (looksLikeUrl(tv) && looksLikeUrl(rawStr)) {
            try {
                rawToMatch = new URL(rawStr, location.href).href.toLowerCase();
                tvToMatch = new URL(tv, location.href).href.toLowerCase();
                if (rawToMatch === tvToMatch) matchType = 'url-eq';
            } catch (e) {
                rawToMatch = rawStr;
                tvToMatch = tv;
            }
        }

        if (!matchType) {
            if (/^[a-z0-9]+$/i.test(tv)) {
                const esc = tv.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
                const re = new RegExp(`\\b${esc}\\b`, 'i');
                if (re.test(rawToMatch)) matchType = 'exact';
            } else if (isSourceMatchingValue(tvToMatch, rawToMatch)) {
                matchType = 'substring';
            }
        }

        if (!matchType) continue;

        const kind = kindOf(sourceKey);
        const sourceMeta = meta[sourceKey] || {};
        const baseScore = kindPriority(kind) * 100 + matchTypePriority(matchType);
        const lastUpdated = typeof meta[sourceKey]?.lastUpdated === 'number' ? meta[sourceKey].lastUpdated : 0;
        const recencyBoost = lastUpdated ? Math.min(Math.floor(lastUpdated / 1000), 1_000_000) : 0;
        const score = baseScore * 1_000_000 + recencyBoost;

        matches.push({
            source: sourceKey,
            raw: rawVal,
            kind,
            matchType,
            score,
            lastUpdated,
            taintKind: sourceMeta.taintKind || null
        });
    }

    if (!matches.length) return null;
    matches.sort((a, b) => b.score - a.score);
    const primary = matches[0];
    __IAST_MATCH_COUNT__++
    //if (__IAST_MATCH_COUNT__ <= 20) __PTK_IAST_DBG__('taint match', { primary, total: matches.length, raw: input });
    return {
        source: primary.source,
        raw: primary.raw,
        allSources: matches
    };
}

(function flushBufferedFindings() {
    const key = 'ptk_iast_buffer';
    const data = localStorage.getItem(key);
    if (!data) return;
    let arr;
    try { arr = JSON.parse(data); } catch { arr = null; }
    if (Array.isArray(arr)) {
        arr.forEach(msg => {
            try { window.postMessage(msg, '*'); }
            catch (e) {/*ignore*/ }
        });
    }
    localStorage.removeItem(key);
})();

function sanitizeIastPayloadValue(v) {
    if (v == null) return v;
    if (v instanceof Error) return v.toString();
    if (typeof Node !== 'undefined' && v instanceof Node) {
        return v.outerHTML || v.textContent || String(v);
    }
    if (typeof v === 'object') {
        try {
            return structuredClone(v);
        } catch (e) {
            try {
                return JSON.parse(JSON.stringify(v));
            } catch (_) {
                return String(v);
            }
        }
    }
    return v;
}

function postBufferedIastMessage(msg) {
    withoutHooks(() => {
        const key = 'ptk_iast_buffer';
        let buf;
        try {
            buf = JSON.parse(localStorage.getItem(key) || '[]');
        } catch (_) {
            buf = [];
        }
        buf.push(msg);
        localStorage.setItem(key, JSON.stringify(buf));
        window.postMessage(msg, '*');
    });
}

function postDirectIastMessage(msg) {
    withoutHooks(() => {
        window.postMessage(msg, '*');
    });
}

function sanitizeIastPayloadObject(details = {}) {
    const sanitized = {};
    Object.entries(details).forEach(([k, v]) => {
        sanitized[k] = sanitizeIastPayloadValue(v);
    });
    return sanitized;
}

function safeRuntimeSignalPart(value, fallback = 'none') {
    const raw = value == null ? '' : String(value).trim();
    if (!raw) return fallback;
    return raw.replace(/[^a-zA-Z0-9._:-]+/g, '_').slice(0, 120) || fallback;
}

function buildRuntimeSignalSourceMeta(value, fallback = {}) {
    if (value == null) {
        return {
            match: null,
            primarySource: null,
            sourceKind: fallback.sourceKind || null,
            sourceKey: fallback.sourceKey || null,
            sourceValuePreview: buildSourcePreview(value)
        };
    }
    const serialized = typeof value === 'string' ? value : safeSerializeValue(value);
    if (!serialized || typeof serialized !== 'string') {
        return {
            match: null,
            primarySource: null,
            sourceKind: fallback.sourceKind || null,
            sourceKey: fallback.sourceKey || null,
            sourceValuePreview: buildSourcePreview(value)
        };
    }
    if (serialized.length > IAST_RUNTIME_SIGNAL_MAX_VALUE_LENGTH) {
        return {
            match: null,
            primarySource: null,
            sourceKind: fallback.sourceKind || null,
            sourceKey: fallback.sourceKey || null,
            sourceValuePreview: buildSourcePreview(serialized.slice(0, IAST_RUNTIME_SIGNAL_MAX_VALUE_LENGTH))
        };
    }
    const match = matchesTaint(value);
    const normalizedSources = normalizeTaintedSources(match?.allSources || [], match?.raw || value);
    const primarySource = normalizedSources[0] || null;
    return {
        match,
        primarySource,
        sourceKind: primarySource?.sourceKind || primarySource?.kind || fallback.sourceKind || null,
        sourceKey: primarySource?.key || primarySource?.source || primarySource?.sourceId || fallback.sourceKey || null,
        sourceValuePreview: buildSourcePreview(primarySource?.raw ?? value)
    };
}

function shouldEmitRuntimeSignalForSource(sourceKind) {
    const normalized = String(sourceKind || '').trim();
    return !!normalized && IAST_RUNTIME_SIGNAL_SOURCE_KINDS.has(normalized);
}

function shouldSendRuntimeSignal(eventKey) {
    const key = String(eventKey || '').trim();
    if (!key) return false;
    if (IAST_RUNTIME_SIGNAL_SENT.has(key)) return false;
    IAST_RUNTIME_SIGNAL_SENT.set(key, Date.now());
    if (IAST_RUNTIME_SIGNAL_SENT.size > 512) {
        const oldestKey = IAST_RUNTIME_SIGNAL_SENT.keys().next().value;
        if (oldestKey) {
            IAST_RUNTIME_SIGNAL_SENT.delete(oldestKey);
        }
    }
    return true;
}

function reportRuntimeSignal({
    signalFamily = null,
    signalCode = 'iast_runtime_signal',
    sinkId = null,
    value = null,
    severity = 'info',
    confidence = null,
    context = {}
} = {}) {
    const routing = buildRoutingMeta();
    const url = window.location.href;
    const method = context?.method || 'GET';
    const normalizedSignalCode = signalCode || 'iast_runtime_signal';
    const sourceMeta = buildRuntimeSignalSourceMeta(value, {
        sourceKind: context?.sourceKind || null,
        sourceKey: context?.sourceKey || null
    });
    if (!sourceMeta.match || !shouldEmitRuntimeSignalForSource(sourceMeta.sourceKind)) {
        return;
    }
    const detection = context?.detection && typeof context.detection === 'object'
        ? Object.assign({}, context.detection)
        : null;
    const sinkContext = {
        requestUrl: context?.requestUrl || null,
        method,
        headerName: context?.headerName || null,
        destUrl: context?.destUrl || null,
        destHost: context?.destHost || null,
        destOrigin: context?.destOrigin || null,
        isCrossOrigin: typeof context?.isCrossOrigin === 'boolean' ? context.isCrossOrigin : null,
        cookieName: context?.cookieName || null,
        storageKey: context?.storageKey || context?.key || null,
        storageArea: context?.storageArea || null
    };
    const signalKey = [
        safeRuntimeSignalPart(sinkId, 'sink'),
        safeRuntimeSignalPart(normalizedSignalCode, 'signal'),
        safeRuntimeSignalPart(sourceMeta.sourceKind, 'unknown'),
        safeRuntimeSignalPart(sourceMeta.sourceKey, 'none'),
        safeRuntimeSignalPart(routing.route || url, 'route')
    ].join(':');
    const event = {
        id: `runtimeevent:${signalKey}`,
        eventKey: signalKey,
        engine: 'IAST',
        kind: 'iast_runtime_signal',
        signalFamily,
        signalCode: normalizedSignalCode,
        category: null,
        severity,
        confidence: Number.isFinite(Number(confidence)) ? Number(confidence) : (Number.isFinite(Number(detection?.confidence)) ? Number(detection.confidence) : null),
        findingId: null,
        findingFingerprint: null,
        requestId: null,
        requestKey: null,
        moduleId: null,
        ruleId: null,
        sinkId: sinkId || null,
        sourceKind: sourceMeta.sourceKind || null,
        sourceKey: sourceMeta.sourceKey || null,
        sourceRole: context?.sourceRole || IAST_SOURCE_ROLES.OBSERVED,
        primaryClass: context?.primaryClass || IAST_PRIMARY_CLASSES.OBSERVATION,
        detection,
        trust: context?.trust || null,
        suppression: null,
        sanitizers: Array.isArray(context?.sanitizerObserved) ? context.sanitizerObserved : [],
        confidenceSignals: [],
        url,
        route: routing.route || null,
        method,
        location: {
            url,
            method,
            route: routing.route || null
        },
        routing,
        headerName: context?.headerName || null,
        storageKey: context?.storageKey || context?.key || null,
        cookieName: context?.cookieName || null,
        attribute: context?.attribute || null,
        isCrossOrigin: typeof context?.isCrossOrigin === 'boolean' ? context.isCrossOrigin : null,
        observedAt: context?.observedAt || null,
        sinkContext,
        sourceValuePreview: sourceMeta.sourceValuePreview || null,
        time: Date.now(),
        evidenceRefs: []
    };
    if (!shouldSendRuntimeSignal(event.eventKey)) {
        return;
    }
    try {
        postDirectIastMessage({
            ptk_iast: 'runtime_signal',
            channel: 'ptk_content_iast2background_iast',
            signal: sanitizeIastPayloadObject(event)
        });
    } catch (e) {
        console.warn('IAST reportRuntimeSignal.postMessage failed:', e);
    }
}


function reportFinding({ type, sink, sinkId = null, ruleId = null, category = null, severity: severityOverride = null, matched, source, sources = null, context = {} }) {
    // Require rule catalog
    if (!IAST_MODULES) {
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: skip finding, modules not loaded yet', { sinkId, ruleId });
        requestModulesFromBackground();
        return;
    }
    let ruleEntry = null;
    if (ruleId) {
        ruleEntry = getIastRuleByRuleId(ruleId);
    }
    if (!ruleEntry && sinkId) {
        ruleEntry = getIastRuleBySinkId(sinkId);
    }
    if (!ruleEntry) {
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: skip finding, rule not found', { sinkId, ruleId });
        requestModulesFromBackground();
        return;
    }

    const loc = window.location.href;
    let trace = '';
    try {
        trace = (new Error(`Sink: ${type}`)).stack;
    } catch (e) { }
    const cleanedTrace = cleanTraceFrames(trace);
    const attackId = window.__PTK_CURRENT_ATTACK_ID__ || null;
    const moduleMeta = ruleEntry.moduleMeta || {};
    const ruleMeta = ruleEntry.ruleMeta || {};
    const resolvedSeverity = resolveIastEffectiveSeverity({
        override: severityOverride,
        moduleMeta,
        ruleMeta
    });
    const resolvedCategory = category || ruleMeta.category || moduleMeta.category || null;
    const description = ruleMeta.description || moduleMeta.description || null;
    const recommendation = ruleMeta.recommendation || moduleMeta.recommendation || null;
    const mergedLinks = mergeLinks(moduleMeta.links, ruleMeta.links);
    const findingMeta = {
        ruleId: ruleEntry.ruleId,
        ruleName: ruleEntry.ruleName,
        moduleId: ruleEntry.moduleId,
        moduleName: ruleEntry.moduleName,
        cwe: ruleMeta.cwe || moduleMeta.cwe || null,
        owasp: ruleMeta.owasp || moduleMeta.owasp || null,
        message: ruleMeta.message || null,
        tags: ruleMeta.tags || [],
        description,
        recommendation,
        links: mergedLinks
    };
    let normalizedSources = Array.isArray(sources) && sources.length ? normalizeTaintedSources(sources, matched) : [];
    const normalizedPrimarySource = (() => {
        if (!source) return null;
        if (typeof source === 'string') {
            return normalizeSourceEntry({ source, raw: matched });
        }
        if (source.__normalizedSource) return source;
        return normalizeSourceEntry(source, source?.source || source?.key || null, source?.raw ?? matched);
    })();
    if (!normalizedSources.length && normalizedPrimarySource) {
        normalizedSources = [normalizedPrimarySource];
    }
    const decoratedSources = normalizedSources.map(entry => Object.assign({}, entry, {
        display: formatSourceForReport(entry),
        sourceValuePreview: buildSourcePreview(entry?.raw ?? entry?.value ?? matched)
    }));
    const formattedSource = normalizedPrimarySource ? formatSourceForReport(normalizedPrimarySource) : 'Unknown source';
    const sourceKey = normalizedPrimarySource?.key || (typeof source === 'string' ? source : null);
    const sourceKind = normalizedPrimarySource?.sourceKind || normalizedPrimarySource?.kind || null;
    const sourceValuePreview = buildSourcePreview(normalizedPrimarySource?.raw ?? matched);
    const primarySource = normalizedPrimarySource || (decoratedSources.length ? decoratedSources[0] : null);
    const secondarySources = decoratedSources.filter(entry => entry !== primarySource).map(entry => ({
        display: entry.display,
        key: entry.key || entry.source || null,
        sourceKind: entry.sourceKind || entry.kind || null,
        score: entry.score || null,
        sourceValuePreview: entry.sourceValuePreview || null
    }));
    const cookieDetails = context.rawCookie ? parseCookieAssignment(context.rawCookie) : null;
    const resolvedNetworkTarget = context?.networkTarget
        || buildNetworkTarget(context?.destUrl || context?.requestUrl || context?.url || null);
    const sinkContext = {
        requestUrl: context.requestUrl || null,
        method: context.method || null,
        headerName: context.headerName || null,
        destUrl: context.destUrl || resolvedNetworkTarget?.url || null,
        destHost: context.destHost || resolvedNetworkTarget?.host || null,
        destOrigin: context.destOrigin || resolvedNetworkTarget?.origin || null,
        isCrossOrigin: typeof context.isCrossOrigin === 'boolean' ? context.isCrossOrigin : (resolvedNetworkTarget?.isCrossOrigin ?? null),
        tagName: context.tagName || context.element?.tagName || null,
        domPath: context.domPath || null,
        attribute: context.attribute || null,
        elementId: context.elementId || null,
        cookieName: context.cookieName || cookieDetails?.name || null,
        cookieAttributes: cookieDetails?.attributes || null,
        storageKey: context.storageKey || null,
        storageArea: context.storageArea || null
    };
    const flowSummary = buildFlowSummary(context.flow);

    const operationMeta = context?.operation || {
        sinkId: sinkId || sink || null,
        sinkArgs: context?.sinkArgs || null
    };
    const observedAt = context?.observedAt || (() => {
        if ((sinkId || '').startsWith('storage.localStorage')) {
            return { kind: 'storage.localStorage', key: context.storageKey || null };
        }
        if ((sinkId || '').startsWith('storage.sessionStorage')) {
            return { kind: 'storage.sessionStorage', key: context.storageKey || null };
        }
        if ((sinkId || '').startsWith('storage.document.cookie')) {
            return { kind: 'storage.cookie', cookieName: context.cookieName || null };
        }
        return null;
    })();
    const detection = context?.detection || null;
    const normalizedDetection = (detection && typeof detection === 'object')
        ? Object.assign({ schemaVersion: IAST_DETECTION_SCHEMA_VERSION }, detection)
        : detection;
    const trust = context?.trust || null;
    const normalizedTrust = (trust && typeof trust === 'object')
        ? Object.assign({ schemaVersion: IAST_TRUST_SCHEMA_VERSION }, trust)
        : trust;
    const suppression = context?.suppression || null;
    const primaryClass = context?.primaryClass || (normalizedDetection ? IAST_PRIMARY_CLASSES.OBSERVATION : IAST_PRIMARY_CLASSES.TAINT_FLOW);
    const sourceRole = context?.sourceRole || (primaryClass === IAST_PRIMARY_CLASSES.OBSERVATION ? IAST_SOURCE_ROLES.OBSERVED : IAST_SOURCE_ROLES.ORIGIN);
    const details = {
        type: type,
        sink,
        sinkId: sinkId || sink || null,
        ruleId: ruleEntry.ruleId,
        ruleName: findingMeta.ruleName,
        moduleId: findingMeta.moduleId,
        moduleName: findingMeta.moduleName,
        matched,
        source: formattedSource,
        sourceKey,
        sourceKind,
        sourceValuePreview,
        sources: decoratedSources,
        primarySource,
        secondarySources,
        schemaVersion: IAST_EVIDENCE_SCHEMA_VERSION,
        primaryClass,
        sourceRole,
        origin: context?.origin || null,
        observedAt,
        operation: operationMeta,
        detection: normalizedDetection,
        trust: normalizedTrust,
        suppression,
        networkTarget: resolvedNetworkTarget || null,
        routing: buildRoutingMeta(),
        category: resolvedCategory,
        severity: resolvedSeverity,
        meta: findingMeta,
        context: enrichContext(context),
        sinkContext,
        flowSummary,
        location: loc,
        trace: cleanedTrace.trace,
        traceSummary: cleanedTrace.traceSummary,
        attackId: attackId,
        timestamp: Date.now(),
        description,
        recommendation,
        links: mergedLinks
    };
    // __PTK_IAST_DBG__('reportFinding', {
    //     sink: sinkId || sink || null,
    //     type,
    //     severity: resolvedSeverity,
    //     category: resolvedCategory,
    //     source: formattedSource,
    //     matched: matched ? String(matched).slice(0, 120) : '',
    //     location: loc
    // });

    // 1) Console output
    // console.groupCollapsed(`%cIAST%c ${type}`,
    //     'color:#d9534f;font-weight:bold', '');
    // console.log('• location:', loc);
    // console.log('• sink:    ', sink);
    // console.log('• source:  ', source);
    // console.log('• matched: ', matched);
    // // log any extra context fields
    // Object.entries(context).forEach(([k, v]) =>
    //     console.log(`• ${k}:       `, v)
    // );
    // console.groupEnd();


    // 2) PostMessage to background (sanitize non-cloneable payloads)
    const sanitized = sanitizeIastPayloadObject(details);
    try {
        postBufferedIastMessage({
            ptk_iast: 'finding_report',
            channel: 'ptk_content_iast2background_iast',
            finding: sanitized
        })
    } catch (e) {
        console.warn('IAST reportFinding.postMessage failed:', e);
    }
}

function safeSerializeValue(value) {
    if (value == null) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    try {
        return JSON.stringify(value);
    } catch (_) {
        try {
            return String(value);
        } catch {
            return '';
        }
    }
}

function isTrackableDynamicSourceValue(value) {
    const serialized = safeSerializeValue(value).trim();
    if (!serialized) return false;
    if (serialized.length > 1024) return false;
    return isMeaningfulSourceValue(serialized);
}

function registerDynamicTaintSource(key, rawValue, meta = {}) {
    if (!key || !isTrackableDynamicSourceValue(rawValue)) return null;
    const value = safeSerializeValue(rawValue).trim();
    const sourceMeta = Object.assign({}, describeSourceKey(key, value), meta, {
        value,
        raw: value
    });
    window.__IAST_TAINTED__[key] = value;
    updateTaintMetaEntry(key, {
        taintKind: sourceMeta.taintKind,
        sourceKind: sourceMeta.sourceKind
    });
    const existing = getTaintEntry(value);
    let sourceId = sourceMeta.sourceId || existing?.taint?.sourceId || null;
    if (!existing) {
        const taint = createSource(value, sourceMeta.sourceKind || sourceMeta.type || 'unknown', sourceMeta);
        sourceId = taint?.sourceId || sourceId;
    }
    updateTaintMetaEntry(key, {
        sourceId,
        sourceKind: sourceMeta.sourceKind,
        taintKind: sourceMeta.taintKind
    });
    registerTaintSource(key, value, Object.assign({}, sourceMeta, { sourceId }));
    return value;
}

function collectJsonPrimitiveEntries(value, prefix = '', out = [], depth = 0, seen = null) {
    if (out.length >= 24 || depth > 4 || value == null) return out;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        out.push({
            path: prefix || 'value',
            value
        });
        return out;
    }
    if (typeof value !== 'object') return out;
    const nextSeen = seen || new Set();
    if (nextSeen.has(value)) return out;
    nextSeen.add(value);

    if (Array.isArray(value)) {
        value.slice(0, 10).forEach((entry, index) => {
            const nextPrefix = prefix ? `${prefix}[${index}]` : `[${index}]`;
            collectJsonPrimitiveEntries(entry, nextPrefix, out, depth + 1, nextSeen);
        });
        return out;
    }

    Object.entries(value).slice(0, 20).forEach(([key, entry]) => {
        const nextPrefix = prefix ? `${prefix}.${key}` : key;
        collectJsonPrimitiveEntries(entry, nextPrefix, out, depth + 1, nextSeen);
    });
    return out;
}

function looksLikeJsonString(value) {
    if (typeof value !== 'string') return false;
    const trimmed = value.trim();
    if (!trimmed) return false;
    return (trimmed.startsWith('{') && trimmed.endsWith('}'))
        || (trimmed.startsWith('[') && trimmed.endsWith(']'));
}

function registerJsonBodySources(jsonValue) {
    if (!jsonValue || typeof jsonValue !== 'object') return;
    const maybeGraphqlVariables = jsonValue && typeof jsonValue === 'object' && !Array.isArray(jsonValue)
        ? jsonValue.variables
        : null;
    if (maybeGraphqlVariables && typeof maybeGraphqlVariables === 'object') {
        collectJsonPrimitiveEntries(maybeGraphqlVariables).forEach((entry) => {
            registerDynamicTaintSource(`graphql:variables:${entry.path}`, entry.value, {
                type: 'graphqlVariable',
                sourceKind: 'graphqlVariable',
                label: `GraphQL variable "${entry.path}"`,
                detail: entry.path,
                taintKind: 'user_input'
            });
        });
    }

    collectJsonPrimitiveEntries(jsonValue).forEach((entry) => {
        registerDynamicTaintSource(`body:json:${entry.path}`, entry.value, {
            type: 'jsonBodyField',
            sourceKind: 'jsonBodyField',
            label: `JSON body field "${entry.path}"`,
            detail: entry.path,
            taintKind: 'user_input'
        });
    });
}

function registerUrlEncodedBodySources(rawBody) {
    const serialized = safeSerializeValue(rawBody);
    if (!serialized) return;
    try {
        const params = new URLSearchParams(serialized);
        let seen = 0;
        for (const [key, value] of params.entries()) {
            registerDynamicTaintSource(`body:param:${key}`, value, {
                type: 'bodyParam',
                sourceKind: 'bodyParam',
                label: `Request body parameter "${key}"`,
                detail: key,
                taintKind: 'user_input'
            });
            seen += 1;
            if (seen >= 24) break;
        }
    } catch (_) { }
}

function extractContentTypeFromHeaders(headerSets = []) {
    let contentType = '';
    headerSets.forEach((headerSet) => {
        if (contentType) return;
        if (!headerSet) return;
        if (typeof Headers !== 'undefined' && headerSet instanceof Headers) {
            const value = headerSet.get('content-type');
            if (value) contentType = String(value).toLowerCase();
            return;
        }
        if (Array.isArray(headerSet)) {
            headerSet.forEach((entry) => {
                if (contentType || !Array.isArray(entry)) return;
                if (String(entry[0] || '').toLowerCase() === 'content-type') {
                    contentType = String(entry[1] || '').toLowerCase();
                }
            });
            return;
        }
        if (typeof headerSet === 'object') {
            Object.entries(headerSet).forEach(([name, value]) => {
                if (contentType || !name) return;
                if (String(name).toLowerCase() === 'content-type') {
                    contentType = String(value || '').toLowerCase();
                }
            });
        }
    });
    return contentType;
}

function registerRequestBodySources(body, options = {}) {
    if (body == null) return;
    const contentType = String(options.contentType || '').toLowerCase();

    if (typeof FormData !== 'undefined' && body instanceof FormData) {
        let count = 0;
        body.forEach((value, key) => {
            if (count >= 24) return;
            if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
                registerDynamicTaintSource(`body:formdata:${key}`, value, {
                    type: 'formDataField',
                    sourceKind: 'formDataField',
                    label: `FormData field "${key}"`,
                    detail: key,
                    taintKind: 'user_input'
                });
                count += 1;
            }
        });
        return;
    }

    if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
        registerUrlEncodedBodySources(body.toString());
        return;
    }

    if (typeof body === 'string') {
        const trimmed = body.trim();
        if (!trimmed) return;
        if (contentType.includes('json') || looksLikeJsonString(trimmed)) {
            try {
                const parsed = JSON.parse(trimmed);
                registerJsonBodySources(parsed);
                return;
            } catch (_) { }
        }
        if (contentType.includes('x-www-form-urlencoded') || /^[^=&?#\s]+=[^&]*(&[^=&?#\s]+=[^&]*)*$/.test(trimmed)) {
            registerUrlEncodedBodySources(trimmed);
        }
        return;
    }

    if (typeof body === 'object') {
        registerJsonBodySources(body);
    }
}

function isNetworkActivityHookEnabled() {
    return isHookGroupEnabled('hook.net.exfil') || isHookGroupEnabled('hook.net.responses');
}

function isLikelyGraphqlBody(body) {
    if (!body) return false;
    if (typeof body === 'string') {
        const trimmed = body.trim();
        if (!trimmed) return false;
        try {
            const parsed = JSON.parse(trimmed);
            return isLikelyGraphqlBody(parsed);
        } catch (_) {
            return /\bquery\b|\bmutation\b|\bsubscription\b/.test(trimmed) && trimmed.includes('{');
        }
    }
    if (typeof body !== 'object') return false;
    if (Array.isArray(body)) return false;
    return typeof body.query === 'string'
        || typeof body.operationName === 'string'
        || (body.variables && typeof body.variables === 'object');
}

function isLikelyGraphqlRequest(url, body, contentType = '') {
    const lowerUrl = String(url || '').toLowerCase();
    if (lowerUrl.includes('/graphql') || lowerUrl.includes('graphql')) return true;
    if (String(contentType || '').toLowerCase().includes('application/graphql')) return true;
    return isLikelyGraphqlBody(body);
}

function trimResponsePayloadText(value, limit = IAST_RESPONSE_SOURCE_MAX_CHARS) {
    const text = safeSerializeValue(value);
    if (!text) return '';
    if (text.length <= limit) return text;
    return text.slice(0, limit);
}

function parseJsonTextSafely(text) {
    if (typeof text !== 'string') return null;
    const trimmed = text.trim();
    if (!trimmed) return null;
    if (trimmed.length > IAST_RESPONSE_SOURCE_MAX_CHARS) return null;
    if (!looksLikeJsonString(trimmed)) return null;
    try {
        return JSON.parse(trimmed);
    } catch (_) {
        return null;
    }
}

function inferResponseFieldTaintKind(path, value) {
    if (isTokenLikeValue(value)) return 'secret';
    const normalizedPath = String(path || '').toLowerCase();
    if (/(token|jwt|secret|apikey|api_key|session|cookie|password|authorization)/.test(normalizedPath)) {
        return 'secret';
    }
    return 'unknown';
}

function registerResponseFieldSources(jsonValue, options = {}) {
    if (!jsonValue || typeof jsonValue !== 'object') return;
    const isGraphql = options.isGraphql === true;
    const responseUrl = options.responseUrl || options.requestUrl || null;
    const responseStatus = Number.isFinite(Number(options.responseStatus)) ? Number(options.responseStatus) : null;
    const responseRoot = isGraphql && jsonValue && typeof jsonValue === 'object' && !Array.isArray(jsonValue) && jsonValue.data && typeof jsonValue.data === 'object'
        ? jsonValue.data
        : jsonValue;
    const entries = collectJsonPrimitiveEntries(responseRoot).slice(0, IAST_RESPONSE_SOURCE_MAX_ENTRIES);
    const basePrefix = isGraphql ? 'graphql:response:' : 'response:json:';
    const sourceKind = isGraphql ? 'graphqlResponseField' : 'apiResponseField';
    const sourceTitle = isGraphql ? 'GraphQL response field' : 'API response field';
    entries.forEach((entry) => {
        registerDynamicTaintSource(`${basePrefix}${entry.path}`, entry.value, {
            type: sourceKind,
            sourceKind,
            label: `${sourceTitle} "${entry.path}"`,
            detail: entry.path,
            taintKind: inferResponseFieldTaintKind(entry.path, entry.value),
            responseUrl,
            responseStatus
        });
    });
}

function captureFetchResponseSources(response, options = {}) {
    if (!response || !isNetworkActivityHookEnabled()) return;
    const contentType = String(response.headers?.get?.('content-type') || '').toLowerCase();
    const isJsonLike = contentType.includes('json')
        || contentType.includes('graphql')
        || options.isGraphql === true;
    if (!isJsonLike) return;
    if (String(response.type || '').toLowerCase() === 'opaque') return;
    let clone;
    try {
        clone = response.clone();
    } catch (_) {
        return;
    }
    Promise.resolve()
        .then(() => clone.text())
        .then((text) => {
            const payload = trimResponsePayloadText(text);
            const parsed = parseJsonTextSafely(payload);
            if (!parsed || typeof parsed !== 'object') return;
            registerResponseFieldSources(parsed, {
                isGraphql: options.isGraphql === true,
                requestUrl: options.requestUrl || null,
                responseUrl: response.url || options.requestUrl || null,
                responseStatus: response.status
            });
        })
        .catch(() => {});
}

function captureXhrResponseSources(xhr) {
    if (!xhr || !isNetworkActivityHookEnabled()) return;
    let contentType = '';
    try {
        contentType = String(xhr.getResponseHeader('content-type') || '').toLowerCase();
    } catch (_) { }
    const isJsonLike = contentType.includes('json')
        || contentType.includes('graphql')
        || xhr.__ptk_iast_is_graphql === true
        || xhr.responseType === 'json';
    if (!isJsonLike) return;
    let parsed = null;
    if (xhr.responseType === 'json' && xhr.response && typeof xhr.response === 'object') {
        parsed = xhr.response;
    } else {
        const rawText = trimResponsePayloadText(xhr.responseText || '');
        parsed = parseJsonTextSafely(rawText);
    }
    if (!parsed || typeof parsed !== 'object') return;
    registerResponseFieldSources(parsed, {
        isGraphql: xhr.__ptk_iast_is_graphql === true,
        requestUrl: xhr.__ptk_iast_url_resolved || xhr.__ptk_iast_url || null,
        responseUrl: xhr.responseURL || xhr.__ptk_iast_url_resolved || xhr.__ptk_iast_url || null,
        responseStatus: xhr.status
    });
}

function isAuthLikeResponseFieldPath(path = '') {
    return /(role|admin|tenant|permission|feature|flag|entitlement|scope|access|plan|privilege)/i.test(String(path || ''));
}

function prunePrototypePollutionEvents() {
    const now = Date.now();
    while (IAST_PROTO_EVENTS.length) {
        const head = IAST_PROTO_EVENTS[0];
        if (head && now - head.at <= IAST_PROTO_POLLUTION_TTL_MS) break;
        IAST_PROTO_EVENTS.shift();
    }
}

function rememberPrototypePollutionEvent(event) {
    if (!event || typeof event !== 'object') return;
    prunePrototypePollutionEvents();
    IAST_PROTO_EVENTS.push(event);
    if (IAST_PROTO_EVENTS.length > 20) {
        IAST_PROTO_EVENTS.splice(0, IAST_PROTO_EVENTS.length - 20);
    }
}

function getRecentPrototypePollutionEvent() {
    prunePrototypePollutionEvents();
    return IAST_PROTO_EVENTS.length ? IAST_PROTO_EVENTS[IAST_PROTO_EVENTS.length - 1] : null;
}

function buildMatchOverrideFromNormalizedSources(sources = [], fallbackRaw = null) {
    const normalized = normalizeTaintedSources(sources, fallbackRaw);
    if (!normalized.length) return null;
    const primary = normalized[0];
    return {
        source: primary.key || primary.source || null,
        raw: primary.raw ?? primary.value ?? fallbackRaw ?? null,
        allSources: normalized
    };
}

function pruneSanitizedValues() {
    if (IAST_SANITIZED_VALUES.size <= IAST_SANITIZED_MAX) return;
    const now = Date.now();
    for (const [key, entry] of IAST_SANITIZED_VALUES.entries()) {
        if (!entry || now - entry.time > IAST_SANITIZED_TTL_MS) {
            IAST_SANITIZED_VALUES.delete(key);
        }
        if (IAST_SANITIZED_VALUES.size <= IAST_SANITIZED_MAX) break;
    }
}

function recordSanitizedValue(value, sanitizerId) {
    const serialized = safeSerializeValue(value);
    if (!serialized) return;
    const now = Date.now();
    const entry = IAST_SANITIZED_VALUES.get(serialized) || { time: now, sanitizers: new Set() };
    entry.time = now;
    entry.sanitizers.add(sanitizerId);
    IAST_SANITIZED_VALUES.set(serialized, entry);
    pruneSanitizedValues();
}

function getSanitizersForValue(value) {
    const serialized = safeSerializeValue(value);
    if (!serialized) return [];
    const entry = IAST_SANITIZED_VALUES.get(serialized);
    if (!entry) return [];
    if (Date.now() - entry.time > IAST_SANITIZED_TTL_MS) {
        IAST_SANITIZED_VALUES.delete(serialized);
        return [];
    }
    return Array.from(entry.sanitizers || []);
}

function sanitizeSourcesForRule(ruleEntry, sources) {
    const ruleMeta = ruleEntry?.ruleMeta || {};
    const allowed = Array.isArray(ruleEntry.sources)
        ? ruleEntry.sources
        : (Array.isArray(ruleMeta.sources) ? ruleMeta.sources : null);
    if (!allowed || !allowed.length) return sources;
    return sources.filter(src => {
        const kind = src?.sourceKind || src?.type || '';
        return kind && allowed.includes(kind);
    });
}

function shouldSuppressForSanitizer(ruleEntry, value) {
    const ruleMeta = ruleEntry?.ruleMeta || {};
    const allowed = Array.isArray(ruleEntry.sanitizersAllowed)
        ? ruleEntry.sanitizersAllowed
        : (Array.isArray(ruleMeta.sanitizersAllowed) ? ruleMeta.sanitizersAllowed : []);
    if (!allowed.length) return { suppress: false, observed: [] };
    const observed = getSanitizersForValue(value).filter(id => allowed.includes(id));
    if (!observed.length) return { suppress: false, observed: [] };
    const onSanitized = ruleEntry.onSanitized || ruleMeta.onSanitized || 'lower_confidence';
    return { suppress: onSanitized === 'suppress', observed };
}

function buildSourcePreview(value) {
    const str = safeSerializeValue(value);
    if (!str) return '';
    if (str.length <= 80) return str;
    return `${str.slice(0, 77)}...`;
}

function formatFlowNodeLabel(node) {
    if (!node) return '';
    let label = node.label || node.key || '';
    if (node.elementId) {
        label += `#${node.elementId}`;
    }
    if (node.attribute) {
        label += `.${node.attribute}`;
    }
    return label || '';
}

function buildFlowSummary(flow) {
    if (!Array.isArray(flow) || !flow.length) return null;
    const parts = flow.map(node => formatFlowNodeLabel(node)).filter(Boolean);
    if (!parts.length) return null;
    return parts.join(' -> ');
}

function cleanTraceFrames(trace) {
    if (!trace) return { trace: '', traceSummary: null };
    const lines = String(trace).split('\n');
    const frames = lines.slice(1).map(line => line.trim()).filter(Boolean);
    const filtered = frames.filter(line => {
        if (line.includes('chrome-extension://') || line.includes('moz-extension://')) return false;
        if (line.includes('ptk/content/iast.js')) return false;
        return true;
    });
    const trimmed = filtered.slice(0, 5);
    return {
        trace: trimmed.length ? [lines[0], ...trimmed].join('\n') : lines[0] || '',
        traceSummary: trimmed[0] || null
    };
}

function parseCookieAssignment(rawCookie) {
    if (!rawCookie) return null;
    const parts = String(rawCookie).split(';').map(part => part.trim()).filter(Boolean);
    if (!parts.length) return null;
    const [nameValue, ...attrs] = parts;
    const eqIndex = nameValue.indexOf('=');
    const name = eqIndex >= 0 ? nameValue.slice(0, eqIndex).trim() : nameValue.trim();
    const attributes = {};
    attrs.forEach(attr => {
        if (!attr) return;
        const [k, ...rest] = attr.split('=');
        const key = String(k || '').trim().toLowerCase();
        if (!key) return;
        const value = rest.length ? rest.join('=').trim() : true;
        attributes[key] = value;
    });
    return {
        name: name || null,
        attributes: Object.keys(attributes).length ? attributes : null
    };
}

function pruneFindingCache(cache) {
    if (cache.size <= IAST_FINDING_DEDUP_MAX) return;
    const now = Date.now();
    for (const [key, ts] of cache.entries()) {
        if (now - ts > IAST_SMART_DEDUP_TTL_MS) {
            cache.delete(key);
        }
        if (cache.size <= IAST_FINDING_DEDUP_MAX) break;
    }
}

function isCacheHit(cache, key) {
    const ts = cache.get(key);
    if (!ts) return false;
    if (Date.now() - ts > IAST_SMART_DEDUP_TTL_MS) {
        cache.delete(key);
        return false;
    }
    return true;
}

function markCache(cache, key) {
    cache.set(key, Date.now());
    pruneFindingCache(cache);
}

function buildFindingDedupKey({ ruleId, sinkId, sourceKey, location, elementId, attribute }) {
    return [
        ruleId || '',
        sinkId || '',
        sourceKey || '',
        location || '',
        elementId || '',
        attribute || ''
    ].join('|');
}

function isCrossOriginRequest(requestUrl) {
    if (!requestUrl) return false;
    try {
        const target = new URL(requestUrl, window.location.href);
        return target.origin !== window.location.origin;
    } catch (_) {
        return false;
    }
}

function resolveAbsoluteUrl(rawUrl, baseUrl = window.location.href) {
    if (!rawUrl) return null;
    try {
        return new URL(rawUrl, baseUrl).href;
    } catch (_) {
        return null;
    }
}

function buildNetworkTarget(rawUrl) {
    const resolved = resolveAbsoluteUrl(rawUrl);
    if (!resolved) return null;
    try {
        const parsed = new URL(resolved);
        const scheme = parsed.protocol ? parsed.protocol.replace(':', '') : null;
        return {
            url: resolved,
            host: parsed.host || null,
            origin: parsed.origin || null,
            scheme,
            isCrossOrigin: parsed.origin !== window.location.origin
        };
    } catch (_) {
        return null;
    }
}

function buildNetworkContext(rawUrl) {
    const target = buildNetworkTarget(rawUrl);
    if (!target) return null;
    return {
        networkTarget: target,
        destUrl: target.url,
        destHost: target.host,
        destOrigin: target.origin,
        isCrossOrigin: target.isCrossOrigin,
        scheme: target.scheme
    };
}

function buildSinkArgs(context = {}) {
    const args = {};
    if (context.headerName) args.headerName = context.headerName;
    if (context.requestUrl) args.requestUrl = context.requestUrl;
    if (context.method) args.method = context.method;
    if (context.url) args.url = context.url;
    if (context.destUrl) args.destUrl = context.destUrl;
    if (context.destOrigin) args.destOrigin = context.destOrigin;
    if (context.destHost) args.destHost = context.destHost;
    if (typeof context.isCrossOrigin === 'boolean') args.isCrossOrigin = context.isCrossOrigin;
    if (context.scheme) args.scheme = context.scheme;
    if (context.storageKey) args.storageKey = context.storageKey;
    if (context.storageArea) args.storageArea = context.storageArea;
    if (context.cookieName) args.cookieName = context.cookieName;
    if (context.key) args.key = context.key;
    return Object.keys(args).length ? args : null;
}

function isAuthHeaderName(name) {
    if (!name) return false;
    const lower = String(name).trim().toLowerCase();
    if (!lower) return false;
    if (lower === 'authorization' || lower === 'proxy-authorization') return true;
    if (lower === 'x-api-key' || lower === 'x-auth-token' || lower === 'x-access-token') return true;
    if (lower === 'x-csrf-token' || lower === 'x-xsrf-token') return true;
    return false;
}

function isCookieHeaderName(name) {
    if (!name) return false;
    const lower = String(name).trim().toLowerCase();
    return lower === 'cookie' || lower === 'set-cookie';
}

function getAuthHeaderAllowlist() {
    const fallback = ['authorization', 'proxy-authorization', 'x-api-key', 'x-auth-token', 'x-access-token', 'x-csrf-token', 'x-xsrf-token'];
    const override = Array.isArray(window?.__PTK_IAST_AUTH_HEADERS__)
        ? window.__PTK_IAST_AUTH_HEADERS__.map(v => String(v).toLowerCase().trim()).filter(Boolean)
        : null;
    return override && override.length ? override : fallback;
}

function isExpectedAuthHeader(name) {
    if (!name) return false;
    const lower = String(name).trim().toLowerCase();
    return getAuthHeaderAllowlist().includes(lower);
}

function isLikelyNonApiPath(destUrl) {
    if (!destUrl) return false;
    try {
        const parsed = new URL(destUrl, window.location.href);
        const path = parsed.pathname.toLowerCase();
        const extMatch = path.match(/\.([a-z0-9]+)$/);
        if (!extMatch) return false;
        const ext = extMatch[1];
        return ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'map', 'json'].includes(ext);
    } catch (_) {
        return false;
    }
}

function isSameHostTarget(target) {
    if (!target || !target.host) return false;
    return target.host === window.location.host;
}

function shouldDowngradeSameHostExfil(sinkId) {
    if (!sinkId) return false;
    return [
        'http.xhr.open',
        'http.xhr.send',
        'http.fetch.url',
        'http.fetch.headers',
        'http.navigator.sendBeacon',
        'http.image.src'
    ].includes(sinkId);
}

function isStorageObservationRisky(context, sinkId) {
    if (!sinkId) return false;
    if (sinkId.startsWith('storage.localStorage')) return true;
    if (sinkId.startsWith('storage.sessionStorage')) return false;
    if (sinkId === 'storage.document.cookie') {
        const details = context?.rawCookie ? parseCookieAssignment(context.rawCookie) : null;
        const attrs = details?.attributes || {};
        const hasSecure = Object.prototype.hasOwnProperty.call(attrs, 'secure');
        const hasSameSite = Object.prototype.hasOwnProperty.call(attrs, 'samesite');
        return !(hasSecure && hasSameSite);
    }
    return false;
}

function emitStorageObservationSignal({ area, key, value, rawCookie = null, elMeta = null } = {}) {
    const sinkId = area === 'localStorage'
        ? 'storage.localStorage.setItem'
        : area === 'sessionStorage'
            ? 'storage.sessionStorage.setItem'
            : 'storage.document.cookie';
    const dataKind = getTokenDataKind(value);
    const detectionReason = dataKind === 'jwt' ? IAST_REASON_CODES.JWT_HEURISTIC : IAST_REASON_CODES.TOKEN_HEURISTIC;
    const severity = area === 'localStorage' || sinkId === 'storage.document.cookie' ? 'low' : 'info';
    reportRuntimeSignal({
        signalFamily: 'auth_signal',
        signalCode: detectionReason,
        sinkId,
        value,
        severity,
        confidence: 80,
        context: Object.assign({
            sourceKind: area === 'localStorage' ? 'localStorage' : area === 'sessionStorage' ? 'sessionStorage' : 'cookie',
            sourceKey: area === 'localStorage'
                ? `localStorage:${key}`
                : area === 'sessionStorage'
                    ? `sessionStorage:${key}`
                    : `cookie:${key}`,
            storageArea: area === 'cookie' ? null : area,
            storageKey: area === 'cookie' ? null : key,
            cookieName: area === 'cookie' ? key : null,
            rawCookie,
            primaryClass: IAST_PRIMARY_CLASSES.OBSERVATION,
            sourceRole: IAST_SOURCE_ROLES.OBSERVED,
            detection: {
                reason: detectionReason,
                dataKind,
                confidence: 80,
                details: {
                    matchedBy: dataKind === 'jwt' ? 'jwt_structure' : 'token_heuristic',
                    valuePreview: buildSourcePreview(value),
                    length: String(value || '').length
                }
            },
            observedAt: area === 'cookie'
                ? { kind: 'storage.cookie', cookieName: key }
                : { kind: area === 'localStorage' ? 'storage.localStorage' : 'storage.sessionStorage', key },
            trust: {
                level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                decision: IAST_TRUST_DECISIONS.ALLOW
            }
        }, elMeta || {})
    });
}

function emitAuthHeaderRuntimeSignal({ sinkId, headerName, value, requestUrl, method, networkTarget } = {}) {
    if (!isExpectedAuthHeader(headerName)) return;
    const sameOrigin = networkTarget && networkTarget.origin === window.location.origin && networkTarget.isCrossOrigin === false;
    if (!sameOrigin) return;
    const sourceMeta = buildRuntimeSignalSourceMeta(value);
    const riskySameOrigin = isLikelyNonApiPath(networkTarget?.url || requestUrl || null)
        || isHighFrequencyAuthHeader({
            sinkId,
            headerName,
            destOrigin: networkTarget?.origin || null,
            location
        });
    reportRuntimeSignal({
        signalFamily: 'auth_signal',
        signalCode: riskySameOrigin ? IAST_REASON_CODES.AUTH_HEADER_SAME_ORIGIN_RISKY : IAST_REASON_CODES.AUTH_HEADER_SAME_ORIGIN,
        sinkId,
        value,
        severity: riskySameOrigin ? 'low' : 'info',
        confidence: 60,
        context: {
            sourceKind: sourceMeta.sourceKind || null,
            sourceKey: sourceMeta.sourceKey || null,
            headerName,
            requestUrl: requestUrl || networkTarget?.url || null,
            method: method || 'GET',
            destUrl: networkTarget?.url || null,
            destHost: networkTarget?.host || null,
            destOrigin: networkTarget?.origin || null,
            isCrossOrigin: networkTarget?.isCrossOrigin ?? null,
            primaryClass: IAST_PRIMARY_CLASSES.OBSERVATION,
            sourceRole: IAST_SOURCE_ROLES.OBSERVED,
            trust: {
                level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                decision: IAST_TRUST_DECISIONS.ALLOW
            },
            detection: {
                reason: riskySameOrigin ? IAST_REASON_CODES.AUTH_HEADER_SAME_ORIGIN_RISKY : IAST_REASON_CODES.AUTH_HEADER_SAME_ORIGIN,
                dataKind: sourceMeta.primarySource?.taintKind === 'secret' ? IAST_DATA_KINDS.TOKEN : getTokenDataKind(value),
                confidence: 60,
                details: {
                    headerName,
                    valuePreview: buildSourcePreview(value),
                    destination: networkTarget?.url || requestUrl || null
                }
            }
        }
    });
}

function emitJsonParseRuntimeSignal(input) {
    const sourceMeta = buildRuntimeSignalSourceMeta(input);
    if (!sourceMeta.match) return;
    reportRuntimeSignal({
        signalFamily: 'client_runtime',
        signalCode: IAST_REASON_CODES.CLIENT_JSON_PARSE_OBSERVED,
        sinkId: 'client.json.parse',
        value: input,
        severity: 'info',
        confidence: 55,
        context: {
            sourceKind: sourceMeta.sourceKind || null,
            sourceKey: sourceMeta.sourceKey || null,
            primaryClass: IAST_PRIMARY_CLASSES.OBSERVATION,
            sourceRole: IAST_SOURCE_ROLES.OBSERVED,
            detection: {
                reason: IAST_REASON_CODES.CLIENT_JSON_PARSE_OBSERVED,
                dataKind: sourceMeta.primarySource?.taintKind === 'secret' ? IAST_DATA_KINDS.TOKEN : IAST_DATA_KINDS.UNKNOWN,
                confidence: 55,
                details: {
                    valuePreview: sourceMeta.sourceValuePreview || buildSourcePreview(input)
                }
            },
            trust: {
                level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                decision: IAST_TRUST_DECISIONS.ALLOW
            }
        }
    });
}

function emitWebSocketRuntimeSignal({ value, socketUrl = null, protocol = null } = {}) {
    const networkTarget = buildNetworkTarget(socketUrl);
    if (!networkTarget || !isSameHostTarget(networkTarget)) return;
    const sourceMeta = buildRuntimeSignalSourceMeta(value);
    if (!sourceMeta.match) return;
    reportRuntimeSignal({
        signalFamily: 'client_runtime',
        signalCode: IAST_REASON_CODES.WEBSOCKET_SAME_HOST,
        sinkId: 'realtime.websocket.send',
        value,
        severity: 'info',
        confidence: 50,
        context: {
            sourceKind: sourceMeta.sourceKind || null,
            sourceKey: sourceMeta.sourceKey || null,
            requestUrl: networkTarget.url,
            destUrl: networkTarget.url,
            destHost: networkTarget.host,
            destOrigin: networkTarget.origin,
            isCrossOrigin: networkTarget.isCrossOrigin,
            protocol: protocol || null,
            primaryClass: IAST_PRIMARY_CLASSES.OBSERVATION,
            sourceRole: IAST_SOURCE_ROLES.OBSERVED,
            detection: {
                reason: IAST_REASON_CODES.WEBSOCKET_SAME_HOST,
                dataKind: sourceMeta.primarySource?.taintKind === 'secret' ? IAST_DATA_KINDS.TOKEN : IAST_DATA_KINDS.UNKNOWN,
                confidence: 50,
                details: {
                    socketUrl: networkTarget.url
                }
            },
            trust: {
                level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                decision: IAST_TRUST_DECISIONS.ALLOW
            }
        }
    });
}

function emitPostMessageRuntimeSignal({ message, targetOrigin, sinkId } = {}) {
    const sourceMeta = buildRuntimeSignalSourceMeta(message);
    if (!sourceMeta.match) return;
    const primarySourceKind = String(sourceMeta.primarySource?.sourceKind || sourceMeta.primarySource?.kind || '').toLowerCase();
    const responseBoundary = primarySourceKind === 'apiresponsefield' || primarySourceKind === 'graphqlresponsefield';
    const signalCode = responseBoundary
        ? IAST_REASON_CODES.RESPONSE_FIELD_CROSS_BOUNDARY
        : IAST_REASON_CODES.CROSS_ORIGIN_POSTMESSAGE_RECEIVER;
    const primaryClass = responseBoundary ? IAST_PRIMARY_CLASSES.HYBRID : IAST_PRIMARY_CLASSES.OBSERVATION;
    reportRuntimeSignal({
        signalFamily: 'message_boundary',
        signalCode,
        sinkId,
        value: message,
        severity: responseBoundary ? 'medium' : 'info',
        confidence: responseBoundary ? 65 : 55,
        context: {
            sourceKind: sourceMeta.sourceKind || null,
            sourceKey: sourceMeta.sourceKey || null,
            targetOrigin: targetOrigin == null ? '*' : targetOrigin,
            isCrossOrigin: sinkId === 'postmessage.crossOrigin' ? true : null,
            primaryClass,
            sourceRole: responseBoundary ? IAST_SOURCE_ROLES.DERIVED : IAST_SOURCE_ROLES.OBSERVED,
            detection: {
                reason: signalCode,
                dataKind: sourceMeta.primarySource?.taintKind === 'secret' ? IAST_DATA_KINDS.TOKEN : IAST_DATA_KINDS.UNKNOWN,
                confidence: responseBoundary ? 65 : 55,
                details: {
                    targetOrigin: targetOrigin == null ? '*' : targetOrigin
                }
            },
            trust: {
                level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                decision: IAST_TRUST_DECISIONS.ALLOW
            }
        }
    });
}

function getIastSuppressionConfig() {
    if (window?.__PTK_IAST_SUPPRESSIONS__ && typeof window.__PTK_IAST_SUPPRESSIONS__ === 'object') {
        return window.__PTK_IAST_SUPPRESSIONS__;
    }
    try {
        const raw = localStorage.getItem('ptk_iast_suppressions');
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (_) {
        return null;
    }
}

function evaluateIastSuppression({ ruleId, sinkId, context, detection }) {
    const config = getIastSuppressionConfig();
    const rules = Array.isArray(config?.rules) ? config.rules : [];
    if (!rules.length) return null;
    const destOrigin = context?.destOrigin || context?.networkTarget?.origin || null;
    const destUrl = context?.destUrl || context?.networkTarget?.url || context?.requestUrl || null;
    const headerName = context?.headerName ? String(context.headerName).toLowerCase() : null;
    const storageKey = context?.storageKey || context?.key || null;
    const reasonCode = detection?.reason || null;
    for (const rule of rules) {
        if (!rule || typeof rule !== 'object') continue;
        if (rule.ruleId && rule.ruleId !== ruleId) continue;
        if (rule.sinkId && rule.sinkId !== sinkId) continue;
        if (rule.destOrigin && destOrigin && rule.destOrigin !== destOrigin) continue;
        if (rule.headerName && headerName && String(rule.headerName).toLowerCase() !== headerName) continue;
        if (rule.storageKey && storageKey && String(rule.storageKey) !== String(storageKey)) continue;
        if (rule.reasonCode && reasonCode && String(rule.reasonCode) !== String(reasonCode)) continue;
        if (rule.pathPattern && destUrl) {
            try {
                const re = new RegExp(rule.pathPattern);
                if (!re.test(destUrl)) continue;
            } catch (_) {
                continue;
            }
        }
        return {
            suppressed: true,
            rule: rule.ruleId || null,
            sinkId: sinkId || null,
            reason: rule.reasonCode || null
        };
    }
    return null;
}

function buildNetworkDedupKey({ sinkId, headerName, destOrigin, location }) {
    if (!sinkId || !headerName || !destOrigin || !location) return null;
    return [
        'net',
        sinkId,
        String(headerName).toLowerCase(),
        destOrigin,
        location
    ].join('|');
}

function isHighFrequencyAuthHeader({ sinkId, headerName, destOrigin, location }) {
    if (!sinkId || !headerName || !destOrigin || !location) return false;
    const now = Date.now();
    const key = [sinkId, String(headerName).toLowerCase(), destOrigin, location].join('|');
    const entry = IAST_NETWORK_HEADER_TRACKER.get(key);
    if (!entry || now - entry.since > IAST_NETWORK_HEADER_WINDOW_MS) {
        IAST_NETWORK_HEADER_TRACKER.set(key, { since: now, count: 1 });
        return false;
    }
    entry.count += 1;
    if (now - entry.since > IAST_NETWORK_HEADER_WINDOW_MS) {
        entry.since = now;
        entry.count = 1;
        return false;
    }
    if (entry.count >= IAST_NETWORK_HEADER_FREQUENCY_MAX) {
        IAST_NETWORK_HEADER_TRACKER.set(key, { since: now, count: 1 });
        return true;
    }
    return false;
}

function maybeReportTaintedValue(value, info = {}, contextExtras = {}, matchOverride = null) {
    if (__IAST_DISABLE_HOOKS__) return false;
    const context = Object.assign({ value }, contextExtras);
    const match = matchOverride || matchesTaint(value);
    const taintEntry = getTaintEntry(value);
    const taintedSources = match ? normalizeTaintedSources(match.allSources, match.raw) : [];
    const heuristicDecision = evaluateSinkHeuristics(value, info, context, taintedSources);
    if (heuristicDecision.skip) return false;
    if (!match && !taintEntry) return false;
    if (typeof context.element === 'undefined') {
        context.element = document?.activeElement || null;
    }
    const location = window.location.href;
    if (!context.location) {
        context.location = location;
    }
    const sinkMeta = {
        sinkId: info.sinkId || info.sink || null,
        sink: info.sink || info.sinkId || null,
        ruleId: info.ruleId || null,
        domPath: context.domPath || (context.element ? getDomPath(context.element) : null),
        elementId: context.elementId || (context.element && context.element.id ? context.element.id : null),
        attribute: context.attribute || null,
        location,
        value
    };
    const flow = buildTaintFlow(match, sinkMeta);
    if (flow.length) {
        context.flow = flow;
    }
    const sinkId = info.sinkId || info.sink || null;
    const explicitRule = info.ruleId ? getIastRuleByRuleId(info.ruleId) : null;
    const sinkCandidates = sinkId ? getIastRulesBySinkId(sinkId) : [];
    const candidates = explicitRule
        ? [explicitRule, ...sinkCandidates.filter((entry) => entry && entry.ruleId !== explicitRule.ruleId)]
        : sinkCandidates;
    window.__PTK_IAST_LAST_REPORT_DEBUG__ = {
        sinkId,
        requestedRuleId: info.ruleId || null,
        candidateRuleIds: candidates.map((entry) => entry?.ruleId || null),
        taintedSourceKinds: taintedSources.map((src) => src?.sourceKind || src?.kind || null)
    };
    if (!candidates.length) return false;
    const sinkArgs = buildSinkArgs(context);
    const sourceRefsFromSubstring = (sources) => sources.map(src => ({
        sourceId: src?.sourceId || null,
        taintId: src?.taintId || null,
        sourceKind: src?.sourceKind || null,
        taintKind: src?.taintKind || null,
        label: src?.label || null,
        matchType: 'substring',
        confidence: 60
    }));
    const sourceRefsFromTaint = (taintInfo) => [{
        sourceId: taintInfo?.sourceId || null,
        taintId: taintInfo?.taintId || null,
        sourceKind: taintInfo?.sourceKind || null,
        taintKind: taintInfo?.taintKind || null,
        label: taintInfo?.label || null,
        matchType: taintEntry?.matchType || 'id',
        confidence: taintEntry?.matchType === 'id' ? 95 : 80
    }];
    const isSmart = isSmartScanStrategy();
    const sinkPageKey = sinkId && location ? `${sinkId}|${location}` : null;
    if (isSmart && sinkPageKey && isCacheHit(IAST_SINK_SEEN, sinkPageKey)) {
        return false;
    }
    const networkDedupKey = buildNetworkDedupKey({
        sinkId,
        headerName: context.headerName || null,
        destOrigin: context.destOrigin || context?.networkTarget?.origin || null,
        location
    });
    if (isSmart && networkDedupKey && isCacheHit(IAST_FINDING_DEDUP, networkDedupKey)) {
        return false;
    }
    let reported = false;
    for (const ruleEntry of candidates) {
        const conditions = ruleEntry.conditions || {};
        if (conditions.requiresCrossOrigin) {
            const reqUrl = context.requestUrl || context.url || context.destUrl || null;
            if (!isCrossOriginRequest(reqUrl)) {
                continue;
            }
        }
        const filteredSources = sanitizeSourcesForRule(ruleEntry, taintedSources);
        if (!filteredSources.length) {
            window.__PTK_IAST_LAST_REPORT_DEBUG__ = Object.assign({}, window.__PTK_IAST_LAST_REPORT_DEBUG__ || {}, {
                ruleId: ruleEntry.ruleId,
                reason: 'filtered_sources_empty',
                allowedSources: Array.isArray(ruleEntry.sources) ? ruleEntry.sources.slice() : [],
                taintedSourceKinds: taintedSources.map((src) => src?.sourceKind || src?.kind || null)
            });
            continue;
        }
        const sanitizerCheck = shouldSuppressForSanitizer(ruleEntry, value);
        if (sanitizerCheck.suppress) continue;
        const primarySource = filteredSources.length
            ? filteredSources[0]
            : (match.source ? normalizeSourceEntry({ source: match.source, raw: match.raw }) : null);
        const sourceKey = primarySource?.key || null;
        if (isSmart) {
            const dedupKey = buildFindingDedupKey({
                ruleId: ruleEntry.ruleId,
                sinkId,
                sourceKey,
                location,
                elementId: context.elementId || null,
                attribute: context.attribute || null
            });
            if (isCacheHit(IAST_FINDING_DEDUP, dedupKey)) {
                continue;
            }
        }
        const nextContext = Object.assign({}, context, {
            taintedSources: filteredSources,
            sinkArgs
        });
        const matchInfo = taintEntry
            ? { matchType: taintEntry.matchType || 'id', confidence: taintEntry.matchType === 'id' ? 95 : 80 }
            : { matchType: 'substring', confidence: 60 };
        nextContext.match = matchInfo;
        nextContext.sourceRefs = taintEntry
            ? sourceRefsFromTaint(taintEntry.taint)
            : sourceRefsFromSubstring(filteredSources);
        applySourceSpecificSignals(nextContext, primarySource, sinkId);
        if (sanitizerCheck.observed.length) {
            nextContext.sanitizerObserved = sanitizerCheck.observed;
            nextContext.confidencePenalty = 25;
        }
        if (heuristicDecision.downgrade) {
            applyHeuristicDowngrade(nextContext, heuristicDecision.downgrade);
        }
        if (sinkId && (sinkId === 'http.xhr.setRequestHeader' || sinkId === 'http.fetch.headers')) {
            const target = nextContext?.networkTarget
                || buildNetworkTarget(nextContext.destUrl || nextContext.requestUrl || null)
                || (nextContext.destOrigin ? { origin: nextContext.destOrigin, isCrossOrigin: nextContext.isCrossOrigin } : null);
            const isSameOrigin = target && target.origin === window.location.origin && target.isCrossOrigin === false;
            const headerName = nextContext.headerName || null;
            if (isSameOrigin && headerName) {
                const hasKnownOrigin = Boolean(nextContext.origin) || nextContext.sourceRole === IAST_SOURCE_ROLES.ORIGIN;
                if (isCookieHeaderName(headerName)) {
                    nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
                    if (!hasKnownOrigin && !nextContext.sourceRole) {
                        nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
                    }
                    nextContext.severityOverride = 'low';
                    nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                        reason: IAST_REASON_CODES.COOKIE_HEADER_ATTEMPT,
                        dataKind: nextContext.detection?.dataKind || IAST_DATA_KINDS.TOKEN,
                        confidence: nextContext.detection?.confidence || 55
                    });
                } else if (isExpectedAuthHeader(headerName)) {
                    const destUrl = nextContext.destUrl || nextContext?.networkTarget?.url || nextContext.requestUrl || null;
                    const riskySameOrigin = isLikelyNonApiPath(destUrl) || isHighFrequencyAuthHeader({
                        sinkId,
                        headerName,
                        destOrigin: target.origin || nextContext.destOrigin || null,
                        location
                    });
                    nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
                    if (!hasKnownOrigin && !nextContext.sourceRole) {
                        nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
                    }
                    nextContext.severityOverride = riskySameOrigin ? 'low' : 'info';
                    nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                        reason: riskySameOrigin ? IAST_REASON_CODES.AUTH_HEADER_SAME_ORIGIN_RISKY : IAST_REASON_CODES.AUTH_HEADER_SAME_ORIGIN,
                        dataKind: nextContext.detection?.dataKind || IAST_DATA_KINDS.TOKEN,
                        confidence: nextContext.detection?.confidence || 60
                    });
                    nextContext.trust = Object.assign({}, nextContext.trust || {}, {
                        level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                        decision: IAST_TRUST_DECISIONS.ALLOW
                    });
                }
            }
        }
        if (sinkId === 'realtime.websocket.send') {
            const target = nextContext?.networkTarget
                || buildNetworkTarget(nextContext.destUrl || nextContext.requestUrl || nextContext.url || null);
            if (target && isSameHostTarget(target)) {
                const hasKnownOrigin = Boolean(nextContext.origin) || nextContext.sourceRole === IAST_SOURCE_ROLES.ORIGIN;
                nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
                if (!hasKnownOrigin && !nextContext.sourceRole) {
                    nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
                }
                nextContext.severityOverride = 'info';
                nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                    reason: IAST_REASON_CODES.WEBSOCKET_SAME_HOST,
                    dataKind: nextContext.detection?.dataKind || IAST_DATA_KINDS.UNKNOWN,
                    confidence: nextContext.detection?.confidence || 50
                });
                nextContext.trust = Object.assign({}, nextContext.trust || {}, {
                    level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                    decision: IAST_TRUST_DECISIONS.ALLOW
                });
            }
        }
        if (shouldDowngradeSameHostExfil(sinkId)) {
            const target = nextContext?.networkTarget
                || buildNetworkTarget(nextContext.destUrl || nextContext.requestUrl || nextContext.url || null);
            if (target && isSameHostTarget(target)) {
                const hasKnownOrigin = Boolean(nextContext.origin) || nextContext.sourceRole === IAST_SOURCE_ROLES.ORIGIN;
                nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
                if (!hasKnownOrigin && !nextContext.sourceRole) {
                    nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
                }
                nextContext.severityOverride = 'info';
                nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                    reason: IAST_REASON_CODES.SAME_HOST_EXFIL,
                    dataKind: nextContext.detection?.dataKind || IAST_DATA_KINDS.UNKNOWN,
                    confidence: nextContext.detection?.confidence || 50
                });
                nextContext.trust = Object.assign({}, nextContext.trust || {}, {
                    level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                    decision: IAST_TRUST_DECISIONS.ALLOW
                });
            }
        }
        if ((nextContext.primaryClass === IAST_PRIMARY_CLASSES.OBSERVATION)
            && (sinkId && sinkId.startsWith('storage.'))
            && !nextContext.severityOverride) {
            nextContext.severityOverride = isStorageObservationRisky(nextContext, sinkId) ? 'low' : 'info';
        }
        const suppressionMatch = evaluateIastSuppression({
            ruleId: ruleEntry.ruleId,
            sinkId,
            context: nextContext,
            detection: nextContext.detection
        });
        if (suppressionMatch) {
            nextContext.suppression = suppressionMatch;
        }
        reportFinding({
            type: info.type || ruleEntry.ruleId || info.sinkId || 'iast_sink',
            sink: info.sink || sinkId || 'iast_sink',
            sinkId,
            ruleId: ruleEntry.ruleId,
            matched: match.raw,
            source: primarySource || match.source,
            sources: filteredSources,
            severity: nextContext.severityOverride || info.severity || null,
            context: nextContext
        });
        window.__PTK_IAST_LAST_REPORT_DEBUG__ = Object.assign({}, window.__PTK_IAST_LAST_REPORT_DEBUG__ || {}, {
            ruleId: ruleEntry.ruleId,
            reason: 'reported',
            filteredSourceKinds: filteredSources.map((src) => src?.sourceKind || src?.kind || null)
        });
        reported = true;
        if (isSmart) {
            if (sinkPageKey) {
                markCache(IAST_SINK_SEEN, sinkPageKey);
            }
            const dedupKey = buildFindingDedupKey({
                ruleId: ruleEntry.ruleId,
                sinkId,
                sourceKey,
                location,
                elementId: context.elementId || null,
                attribute: context.attribute || null
            });
            markCache(IAST_FINDING_DEDUP, dedupKey);
            if (networkDedupKey) {
                markCache(IAST_FINDING_DEDUP, networkDedupKey);
            }
            break;
        }
    }
    return reported;
}


// Inline-event scanner helper
function scanInlineEvents(htmlFragment) {
    let m;
    try {
        const doc = withInternalHtmlParser(() => new DOMParser().parseFromString(htmlFragment, 'text/html'));
        doc.querySelectorAll('*').forEach(el => {
            Array.from(el.attributes).forEach(attr => {
                const name = attr.name.toLowerCase();
                if (!name.startsWith('on')) return;
                const val = attr.value;
                m = matchesTaint(val);
                if (!m) return;

                maybeReportTaintedValue(val, {
                    type: 'dom-inline-event-handler',
                    sink: name,
                    sinkId: 'dom.inline_event'
                }, {
                    element: el,
                    tag: el.tagName,
                    attribute: name,
                    eventType: name,
                    value: val
                }, m);
            });
        });
    } catch (e) {
        console.warn('[IAST] inline-event scan error', e);
    }
}


// Eval & Function hooks
; (function () {
    const originalEval = window.eval;
    window.eval = function (code) {
        if (!isHookGroupEnabled('hook.code.exec')) {
            return originalEval.call(this, code);
        }
        const m = matchesTaint(code);
        if (m) {
            maybeReportTaintedValue(code, {
                type: 'xss-via-eval',
                sink: 'eval',
                sinkId: 'code.eval'
            }, {
                element: document?.activeElement || null,
                code: code
            }, m);
        }
        return originalEval.call(this, code);
    };
})();

; (function () {
    const OriginalFunction = window.Function;
    window.Function = new Proxy(OriginalFunction, {
        construct(target, args, newTarget) {
            if (!isHookGroupEnabled('hook.code.exec')) {
                return Reflect.construct(target, args, newTarget);
            }
            const body = args.slice(-1)[0] + '';
            const m = matchesTaint(body);
            if (m) {
                maybeReportTaintedValue(body, {
                    type: 'xss-via-Function',
                    sink: 'Function.constructor',
                    sinkId: 'code.function.constructor'
                }, {
                    element: document?.activeElement || null,
                    code: body
                }, m);
            }
            return Reflect.construct(target, args, newTarget);
        },
        apply(target, thisArg, args) {
            if (!isHookGroupEnabled('hook.code.exec')) {
                return Reflect.apply(target, thisArg, args);
            }
            const body = args.slice(-1)[0] + '';
            const m = matchesTaint(body);
            if (m) {
                maybeReportTaintedValue(body, {
                    type: 'xss-via-Function',
                    sink: 'Function.apply',
                    sinkId: 'code.function.apply'
                }, { element: document?.activeElement || null, code: body }, m);
            }
            return Reflect.apply(target, thisArg, args);
        }
    });
})();

// JSON.parse sink
; (function () {
    const origParse = JSON.parse;
    JSON.parse = function (input, ...rest) {
        if (!isHookGroupEnabled('hook.client.json')) {
            emitJsonParseRuntimeSignal(input);
            return origParse.call(this, input, ...rest);
        }
        const m = matchesTaint(input);
        if (m) {
            const binding = buildRuleBinding({ sinkId: 'client.json.parse', fallbackType: 'json-parse' });
            maybeReportTaintedValue(input, binding, { value: input }, m);
        }
        return origParse.call(this, input, ...rest);
    };
})();

// DOM parser and unsafe HTML sinks
; (function () {
    const isHtmlParsingMimeType = (mimeType) => {
        const normalized = String(mimeType || '').trim().toLowerCase();
        return normalized === 'text/html' || normalized === 'application/xhtml+xml' || normalized === 'image/svg+xml';
    };

    if (typeof DOMParser !== 'undefined' && DOMParser.prototype && typeof DOMParser.prototype.parseFromString === 'function') {
        const origParseFromString = DOMParser.prototype.parseFromString;
        DOMParser.prototype.parseFromString = function (markup, mimeType, ...rest) {
            if (!isInternalHtmlParserActive() && isHookGroupEnabled('hook.dom.htmlParsers') && isHtmlParsingMimeType(mimeType)) {
                const payload = safeSerializeValue(markup);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'dom-parser-html',
                        sink: 'DOMParser.parseFromString',
                        sinkId: 'dom.domParser.parseFromString'
                    }, {
                        value: payload,
                        contentType: mimeType,
                        parser: 'DOMParser.parseFromString'
                    });
                }
            }
            return origParseFromString.call(this, markup, mimeType, ...rest);
        };
    }

    if (typeof Range !== 'undefined' && Range.prototype && typeof Range.prototype.createContextualFragment === 'function') {
        const origCreateContextualFragment = Range.prototype.createContextualFragment;
        Range.prototype.createContextualFragment = function (markup) {
            if (!isInternalHtmlParserActive() && isHookGroupEnabled('hook.dom.htmlParsers')) {
                const payload = safeSerializeValue(markup);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'range-contextual-fragment',
                        sink: 'Range.createContextualFragment',
                        sinkId: 'dom.range.createContextualFragment'
                    }, {
                        value: payload,
                        parser: 'Range.createContextualFragment'
                    });
                }
            }
            return origCreateContextualFragment.call(this, markup);
        };
    }

    if (typeof Element !== 'undefined' && Element.prototype && typeof Element.prototype.setHTMLUnsafe === 'function') {
        const origSetHTMLUnsafe = Element.prototype.setHTMLUnsafe;
        Element.prototype.setHTMLUnsafe = function (markup, ...rest) {
            if (isHookGroupEnabled('hook.dom.htmlParsers')) {
                const payload = safeSerializeValue(markup);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'sethtmlunsafe',
                        sink: 'Element.setHTMLUnsafe',
                        sinkId: 'dom.element.setHTMLUnsafe'
                    }, {
                        value: payload,
                        element: this,
                        domPath: getDomPath(this)
                    });
                }
            }
            return origSetHTMLUnsafe.call(this, markup, ...rest);
        };
    }

    if (typeof ShadowRoot !== 'undefined' && ShadowRoot.prototype && typeof ShadowRoot.prototype.setHTMLUnsafe === 'function') {
        const origShadowSetHTMLUnsafe = ShadowRoot.prototype.setHTMLUnsafe;
        ShadowRoot.prototype.setHTMLUnsafe = function (markup, ...rest) {
            if (isHookGroupEnabled('hook.dom.htmlParsers')) {
                const payload = safeSerializeValue(markup);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'shadowroot-sethtmlunsafe',
                        sink: 'ShadowRoot.setHTMLUnsafe',
                        sinkId: 'dom.shadowRoot.setHTMLUnsafe'
                    }, {
                        value: payload,
                        domPath: getDomPath(this.host || null),
                        hostTag: this.host?.tagName ? this.host.tagName.toLowerCase() : null
                    });
                }
            }
            return origShadowSetHTMLUnsafe.call(this, markup, ...rest);
        };
    }
})();

// FileReader sinks
; (function () {
    if (typeof FileReader === 'undefined' || !FileReader.prototype) return;
    const methodDefs = [
        ['readAsText', 'client.filereader.readAsText', 'filereader_readAsText_tainted'],
        ['readAsDataURL', 'client.filereader.readAsDataURL', 'filereader_readAsDataURL_tainted'],
        ['readAsArrayBuffer', 'client.filereader.readAsArrayBuffer', 'filereader_readAsArrayBuffer_tainted']
    ];

    const buildFileReaderPayload = (candidate) => {
        if (candidate == null) return '';
        if (typeof candidate === 'string') return candidate;
        const parts = [];
        if (typeof candidate?.name === 'string' && candidate.name) parts.push(candidate.name);
        if (typeof candidate?.fileName === 'string' && candidate.fileName) parts.push(candidate.fileName);
        if (typeof candidate?.path === 'string' && candidate.path) parts.push(candidate.path);
        if (typeof candidate?.type === 'string' && candidate.type) parts.push(candidate.type);
        if (parts.length) return parts.join('|');
        return safeSerializeValue(candidate);
    };

    methodDefs.forEach(([method, sinkId, ruleId]) => {
        const orig = FileReader.prototype[method];
        if (typeof orig !== 'function') return;
        FileReader.prototype[method] = function (...args) {
            if (!isHookGroupEnabled('hook.client.json')) {
                return orig.apply(this, args);
            }
            const candidate = args[0];
            const payload = buildFileReaderPayload(candidate);
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'filereader-sink',
                    sink: `FileReader.${method}`,
                    sinkId,
                    ruleId
                }, {
                    value: payload,
                    fileName: candidate?.name || candidate?.fileName || null,
                    fileType: candidate?.type || null,
                    api: `FileReader.${method}`
                });
            }
            return orig.apply(this, args);
        };
    });
})();

// XPath sink
; (function () {
    if (typeof Document === 'undefined' || !Document.prototype || typeof Document.prototype.evaluate !== 'function') return;
    const origEvaluate = Document.prototype.evaluate;
    Document.prototype.evaluate = function (expression, ...rest) {
        if (!isHookGroupEnabled('hook.client.json')) {
            return origEvaluate.call(this, expression, ...rest);
        }
        const payload = safeSerializeValue(expression);
        if (payload) {
            const binding = buildRuleBinding({ sinkId: 'dom.xpath.evaluate', fallbackType: 'xpath-injection' });
            maybeReportTaintedValue(payload, Object.assign({
                type: 'xpath-injection',
                sink: 'document.evaluate'
            }, binding), {
                value: payload,
                api: 'document.evaluate'
            });
        }
        return origEvaluate.call(this, expression, ...rest);
    };
})();

// WebSQL sinks
; (function () {
    if (typeof window.openDatabase !== 'function') return;
    const WRAP_MARK = '__ptk_iast_wrapped__';

    const wrapExecuteSql = (tx) => {
        if (!tx || typeof tx.executeSql !== 'function') return;
        if (tx.executeSql[WRAP_MARK]) return;
        const origExecuteSql = tx.executeSql;
        tx.executeSql = function (sqlStatement, ...rest) {
            if (isHookGroupEnabled('hook.client.json')) {
                const payload = safeSerializeValue(sqlStatement);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'client-sql',
                        sink: 'tx.executeSql',
                        sinkId: 'client.sql.executeSql'
                    }, {
                        value: payload,
                        api: 'tx.executeSql'
                    });
                }
            }
            return origExecuteSql.call(this, sqlStatement, ...rest);
        };
        tx.executeSql[WRAP_MARK] = true;
    };

    const wrapDb = (db) => {
        if (!db || typeof db !== 'object') return db;
        ['transaction', 'readTransaction'].forEach((method) => {
            const orig = db[method];
            if (typeof orig !== 'function' || orig[WRAP_MARK]) return;
            db[method] = function (txCallback, ...rest) {
                if (typeof txCallback !== 'function') {
                    return orig.call(this, txCallback, ...rest);
                }
                const wrappedCallback = function (tx, ...txRest) {
                    try {
                        wrapExecuteSql(tx);
                    } catch (_) { }
                    return txCallback.call(this, tx, ...txRest);
                };
                return orig.call(this, wrappedCallback, ...rest);
            };
            db[method][WRAP_MARK] = true;
        });
        return db;
    };

    const origOpenDatabase = window.openDatabase;
    if (origOpenDatabase[WRAP_MARK]) return;
    window.openDatabase = function (...args) {
        if (isHookGroupEnabled('hook.client.json')) {
            const namePayload = safeSerializeValue(args[0]);
            const displayNamePayload = safeSerializeValue(args[2]);
            const payload = [namePayload, displayNamePayload].filter(Boolean).join('|');
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'client-sql',
                    sink: 'openDatabase',
                    sinkId: 'client.sql.openDatabase'
                }, {
                    value: payload,
                    dbName: namePayload || null,
                    dbDisplayName: displayNamePayload || null,
                    api: 'openDatabase'
                });
            }
        }
        const db = origOpenDatabase.apply(this, args);
        return wrapDb(db);
    };
    window.openDatabase[WRAP_MARK] = true;
})();

// document.domain manipulation sink
; (function () {
    if (typeof Document === 'undefined' || !Document.prototype) return;
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'domain');
    if (desc && desc.set) {
        Object.defineProperty(Document.prototype, 'domain', {
            configurable: true,
            enumerable: desc.enumerable,
            get: desc.get,
            set(value) {
                if (!isHookGroupEnabled('hook.dom.urlAttributes')) {
                    return desc.set.call(this, value);
                }
                const m = matchesTaint(value);
                if (m) {
                    const binding = buildRuleBinding({ sinkId: 'document.domain', fallbackType: 'document-domain' });
                    maybeReportTaintedValue(value, binding, { value }, m);
                }
                return desc.set.call(this, value);
            }
        });
    }
})();


// document.write
; (function () {
    const origWrite = document.write;

    document.write = function (...args) {
        if (!isHookGroupEnabled('hook.dom.documentWrite')) {
            return origWrite.apply(document, args);
        }
        if (!allowHeavyHook()) {
            const html = args.join('');
            const m = matchesTaint(html);
            if (m) {
                maybeReportTaintedValue(html, {
                    type: 'xss-via-document.write',
                    sink: 'document.write',
                    sinkId: 'document.write'
                }, { value: html, element: document?.activeElement || null }, m);
            }
            return origWrite.apply(document, args);
        }
        const html = args.join('');
        let fragment;
        try {
            // Parse the HTML into a DocumentFragment
            const doc = withInternalHtmlParser(() => {
                const parser = new DOMParser();
                return parser.parseFromString(html, 'text/html');
            });
            fragment = doc.body;
            // Traverse and report any taint in attributes or text nodes
            traverseAndReport(fragment, 'document.write');
        } catch (e) {
            // Fallback to the old behavior if parsing fails
            const m = matchesTaint(html);
            if (m) {
                maybeReportTaintedValue(html, {
                    type: 'xss-via-document.write',
                    sink: 'document.write',
                    sinkId: 'document.write'
                }, { value: html, element: document?.activeElement || null }, m);
                scanInlineEvents(html);
            }
        }
        return origWrite.apply(document, args);
    };

    // Helper: walk a DOM subtree and report the first taint per node
    function traverseAndReport(root, sink) {
        const seen = new Set();  // avoid duplicates
        walkElementSubtree(root, {
            maxElements: IAST_SCAN_STRATEGY === 'SMART' ? 24 : 72,
            maxMs: IAST_SCAN_STRATEGY === 'SMART' ? 2 : 4
        }, (node) => {
            const candidate = getExecutableMutationCandidate(node);
            if (candidate && !seen.has(node)) {
                maybeReportTaintedValue(candidate.value, {
                    type: 'xss-via-document.write',
                    sink: sink,
                    sinkId: 'document.write'
                }, {
                    value: candidate.value,
                    element: node,
                    domPath: getDomPath(node),
                    tag: candidate.tag,
                    attribute: candidate.attribute,
                    candidateType: candidate.candidateType
                }, candidate.match);
                seen.add(node);
            }
            return seen.size < 3;
        });
    }
})();

// innerHTML/outerHTML
['innerHTML', 'outerHTML'].forEach(prop => {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
    Object.defineProperty(Element.prototype, prop, {
        get: desc.get,
        set(htmlString) {
            if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.htmlAssignments')) {
                return desc.set.call(this, htmlString);
            }
            if (!allowHeavyHook()) {
                const m = matchesTaint(htmlString);
                if (m) {
                    maybeReportTaintedValue(htmlString, {
                        type: `xss-via-${prop}`,
                        sink: prop,
                        sinkId: prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML'
                    }, { value: htmlString, element: this, domPath: getDomPath(this) }, m);
                }
                return desc.set.call(this, htmlString);
            }
            try {
                const frag = withInternalHtmlParser(() => document.createRange().createContextualFragment(htmlString));
                traverseAndReport(frag, `xss-via-${prop}`);
            } catch {
                const m = matchesTaint(htmlString);
                if (m) {
                    maybeReportTaintedValue(htmlString, {
                        type: `xss-via-${prop}`,
                        sink: prop,
                        sinkId: prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML'
                    }, { value: htmlString, element: this, domPath: getDomPath(this) }, m);
                    scanInlineEvents(htmlString);
                }
            }
            return desc.set.call(this, htmlString);
        },
        configurable: true,
        enumerable: desc.enumerable
    });
});


// insertAdjacentHTML
; (function () {
    const origInsert = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (pos, htmlString) {
        if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.htmlAssignments')) {
            return origInsert.call(this, pos, htmlString);
        }
        if (!allowHeavyHook()) {
            const m = matchesTaint(htmlString);
            if (m) {
                maybeReportTaintedValue(htmlString, {
                    type: 'xss-via-insertAdjacentHTML',
                    sink: 'insertAdjacentHTML',
                    sinkId: 'dom.insertAdjacentHTML'
                }, { value: htmlString, element: this, position: pos }, m);
            }
            return origInsert.call(this, pos, htmlString);
        }
        try {
            // parse HTML to a fragment for precise matching
            const frag = withInternalHtmlParser(() => document.createRange().createContextualFragment(htmlString));
            traverseAndReport(frag, `insertAdjacentHTML(${pos})`);
        } catch {
            // fallback to simple match
            const m = matchesTaint(htmlString);
            if (m) {
                maybeReportTaintedValue(htmlString, {
                    type: 'xss-via-insertAdjacentHTML',
                    sink: 'insertAdjacentHTML',
                    sinkId: 'dom.insertAdjacentHTML'
                }, { value: htmlString, element: this, position: pos }, m);
                scanInlineEvents(htmlString);
            }
        }
        return origInsert.call(this, pos, htmlString);
    };
})();

// Attribute/property sinks (href/src/action/formaction + inline events)
; (function () {
    const resolveAttrSinkId = (el, attrName, value) => {
        const name = (attrName || '').toLowerCase();
        const tag = el?.tagName ? el.tagName.toLowerCase() : '';
        if (name.startsWith('on')) return 'dom.inline_event';
        if (name === 'srcdoc') return 'nav.iframe.srcdoc';
        if (name === 'href') {
            return resolveDangerousUrlSinkId('dom.attr.href', value) || 'dom.attr.href';
        }
        if (name === 'action') return resolveDangerousUrlSinkId('dom.attr.action', value) || 'dom.attr.action';
        if (name === 'formaction') return resolveDangerousUrlSinkId('dom.attr.formaction', value) || 'dom.attr.formaction';
        if (name === 'src') {
            if (tag === 'img') return 'http.image.src';
            if (tag === 'script') {
                return resolveDangerousUrlSinkId('script.element.src', value) || 'script.element.src';
            }
            if (tag === 'iframe') {
                return resolveDangerousUrlSinkId('nav.iframe.src', value) || 'nav.iframe.src';
            }
            return resolveDangerousUrlSinkId('dom.attr.src', value) || 'dom.attr.src';
        }
        return null;
    };

    const reportAttrSink = (el, attrName, value) => {
        if (__IAST_DISABLE_HOOKS__) return;
        const sinkId = resolveAttrSinkId(el, attrName, value);
        if (!sinkId) {
            window.__PTK_IAST_LAST_ATTR_DEBUG__ = {
                attrName,
                sinkId: null,
                reason: 'no_sink_id',
                value: safeSerializeValue(value)
            };
            return;
        }
        const attrHookGroup = getDomAttributeHookGroupForSink(sinkId);
        if (!attrHookGroup || !isHookGroupEnabled(attrHookGroup)) {
            window.__PTK_IAST_LAST_ATTR_DEBUG__ = {
                attrName,
                sinkId,
                hookGroup: attrHookGroup || null,
                reason: 'hook_group_disabled',
                value: safeSerializeValue(value)
            };
            return;
        }
        if (!hasRecentTaintActivity()) {
            window.__PTK_IAST_LAST_ATTR_DEBUG__ = {
                attrName,
                sinkId,
                hookGroup: attrHookGroup,
                reason: 'no_recent_taint',
                value: safeSerializeValue(value)
            };
            return;
        }
        if (!allowHeavyHook()) {
            window.__PTK_IAST_LAST_ATTR_DEBUG__ = {
                attrName,
                sinkId,
                hookGroup: attrHookGroup,
                reason: 'heavy_hook_denied',
                value: safeSerializeValue(value)
            };
            return;
        }
        const m = matchesTaint(value);
        if (!m) {
            window.__PTK_IAST_LAST_ATTR_DEBUG__ = {
                attrName,
                sinkId,
                hookGroup: attrHookGroup,
                reason: 'no_taint_match',
                value: safeSerializeValue(value)
            };
            return;
        }
        const binding = buildRuleBinding({ sinkId, fallbackType: 'dom-attr' });
        window.__PTK_IAST_LAST_ATTR_DEBUG__ = {
            attrName,
            sinkId,
            hookGroup: attrHookGroup,
            reason: 'report_attempt',
            binding,
            matchedSource: m?.source || null,
            matchedRaw: safeSerializeValue(m?.raw ?? value),
            value: safeSerializeValue(value)
        };
        maybeReportTaintedValue(value, binding, {
            value,
            attribute: attrName,
            element: el,
            domPath: getDomPath(el)
        }, m);
    };

    const wrapPropertySetter = (proto, prop) => {
        if (!proto) return;
        const desc = Object.getOwnPropertyDescriptor(proto, prop);
        if (!desc || !desc.set) return;
        Object.defineProperty(proto, prop, {
            configurable: true,
            enumerable: desc.enumerable,
            get: desc.get,
            set(value) {
                reportAttrSink(this, prop, value);
                return desc.set.call(this, value);
            }
        });
    };

    const origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
        const res = origSetAttribute.apply(this, arguments);
        try {
            reportAttrSink(this, name, value);
        } catch (_) { }
        return res;
    };

    wrapPropertySetter(HTMLAnchorElement?.prototype, 'href');
    wrapPropertySetter(HTMLAreaElement?.prototype, 'href');
    wrapPropertySetter(HTMLLinkElement?.prototype, 'href');
    wrapPropertySetter(HTMLImageElement?.prototype, 'src');
    wrapPropertySetter(HTMLScriptElement?.prototype, 'src');
    wrapPropertySetter(HTMLIFrameElement?.prototype, 'src');
    wrapPropertySetter(HTMLIFrameElement?.prototype, 'srcdoc');
    wrapPropertySetter(HTMLFormElement?.prototype, 'action');
    wrapPropertySetter(HTMLButtonElement?.prototype, 'formAction');
    wrapPropertySetter(HTMLInputElement?.prototype, 'formAction');
})();

// createContextualFragment & appendChild/insertBefore
; (function () {
    if (isSmartMode()) return;

    // 1) Walk a subtree in post-order, checking text nodes and element attributes
    function traverseAndReport(root, trigger) {
        if (isSmartMode()) return;
        if (__IAST_DISABLE_HOOKS__) return;
        if (!window.__IAST_TAINTED__ || !Object.keys(window.__IAST_TAINTED__).length) return;
        if (!hasRecentTaintActivity()) return;
        if (!allowHeavyHook()) return;
        const seen = new Set();
        walkElementSubtree(root, {
            maxElements: IAST_SCAN_STRATEGY === 'SMART' ? 24 : 96,
            maxMs: IAST_SCAN_STRATEGY === 'SMART' ? 1.5 : 3
        }, (node) => {
            if (seen.has(node)) return true;
            const candidate = getExecutableMutationCandidate(node);
            if (!candidate) return true;
            seen.add(node);
            maybeReportTaintedValue(candidate.value, {
                type: 'xss-via-mutation',
                sink: trigger,
                sinkId: 'dom.mutation'
            }, {
                element: node,
                nodeType: 'ELEMENT_NODE',
                tag: node.tagName,
                attribute: candidate.attribute,
                value: candidate.value,
                domPath: getDomPath(node),
                candidateType: candidate.candidateType
            }, candidate.match);
            return seen.size < 3;
        });
    }

    __IAST_MUTATION_TRAVERSE__ = traverseAndReport;

    // 2) List of prototypes & methods to hook
    const hooks = [
        [Node.prototype, ['appendChild', 'insertBefore', 'replaceChild']],
        [Element.prototype, ['append', 'prepend', 'before', 'after', 'replaceWith']],
        [Document.prototype, ['adoptNode']]
    ];

    for (const [proto, methods] of hooks) {
        for (const name of methods) {
            const orig = proto[name];
            if (typeof orig !== 'function') continue;

            Object.defineProperty(proto, name, {
                configurable: true,
                writable: true,
                value: function (...args) {
                    if (isSmartMode()) {
                        return orig.apply(this, args);
                    }
                    if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.mutations')) {
                        return orig.apply(this, args);
                    }
                    if (!hasRecentTaintActivity()) {
                        return orig.apply(this, args);
                    }
                    if (!allowHeavyHook()) {
                        return orig.apply(this, args);
                    }
                    //console.debug(`[IAST] mutation hook: ${name}`, this, args);

                    // figure out which Nodes are being inserted/adopted
                    const nodes = [];
                    switch (name) {
                        case 'insertBefore':
                        case 'replaceChild':
                            nodes.push(args[0]);
                            break;
                        case 'appendChild':
                        case 'adoptNode':
                            nodes.push(args[0]);
                            break;
                        default:
                            // append/prepend/before/after/replaceWith take Node or strings
                            args.forEach(a => {
                                if (typeof a === 'string') {
                                    // strings become TextNodes at runtime; scan them too
                                    const txtNode = document.createTextNode(a);
                                    nodes.push(txtNode);
                                } else if (a instanceof Node) {
                                    nodes.push(a);
                                }
                            });
                    }

                    // run taint scan asynchronously (budgeted)
                    for (const n of nodes) {
                        if (IAST_MUTATION_QUEUE.length < IAST_MUTATION_QUEUE_MAX) {
                            IAST_MUTATION_QUEUE.push({ node: n, trigger: name });
                        }
                    }
                    scheduleMutationFlush();

                    // and finally perform the real mutation
                    return orig.apply(this, args);
                }
            });
        }
    }
})();

// DOM clobbering candidates
; (function () {
    if (isSmartMode()) return;

    const RISKY_NAMED_PROPERTIES = new Set([
        'action',
        'api',
        'callback',
        'config',
        'handler',
        'href',
        'location',
        'method',
        'next',
        'onerror',
        'onload',
        'redirect',
        'redirectto',
        'returnto',
        'src',
        'target',
        'url',
        'username'
    ]);

    const isCollectionLike = (value) => {
        if (!value) return false;
        if (typeof Element !== 'undefined' && value instanceof Element) return true;
        if (typeof HTMLCollection !== 'undefined' && value instanceof HTMLCollection) return true;
        if (typeof NodeList !== 'undefined' && value instanceof NodeList) return true;
        return false;
    };

    const getCandidateNames = (element) => {
        const names = [];
        const idVal = element?.id ? String(element.id).trim() : '';
        const nameVal = typeof element?.getAttribute === 'function'
            ? String(element.getAttribute('name') || '').trim()
            : '';
        if (idVal) names.push({ attr: 'id', value: idVal });
        if (nameVal) names.push({ attr: 'name', value: nameVal });
        return names;
    };

    const DOM_CLOBBERING_QUEUE = [];
    let domClobberingFlushScheduled = false;

    const reportDomClobbering = (element, attr, candidateName) => {
        const normalized = String(candidateName || '').trim();
        if (!normalized) return;
        const lower = normalized.toLowerCase();
        if (!RISKY_NAMED_PROPERTIES.has(lower)) return;
        let resolved = null;
        try {
            resolved = window[normalized];
        } catch (_) {
            resolved = null;
        }
        if (!resolved) {
            try {
                resolved = document[normalized];
            } catch (_) {
                resolved = null;
            }
        }
        if (!isCollectionLike(resolved)) return;

        const location = window.location.href;
        const dedupKey = `dom-clobbering|${lower}|${location}`;
        if (isCacheHit(IAST_FINDING_DEDUP, dedupKey)) return;
        markCache(IAST_FINDING_DEDUP, dedupKey);

        const context = {
            value: normalized,
            attribute: attr,
            element,
            domPath: getDomPath(element),
            primaryClass: IAST_PRIMARY_CLASSES.POLICY_VIOLATION,
            sourceRole: IAST_SOURCE_ROLES.UNKNOWN,
            detection: {
                reason: IAST_REASON_CODES.SINK_POLICY_MATCH,
                dataKind: IAST_DATA_KINDS.UNKNOWN,
                confidence: 55,
                details: {
                    candidate: normalized,
                    attribute: attr
                }
            },
            observedAt: {
                kind: 'dom.namedProperty',
                property: normalized
            },
            operation: {
                sinkId: 'dom.clobbering.named_property',
                sinkArgs: {
                    candidate: normalized,
                    attribute: attr
                }
            }
        };

        const match = matchesTaint(normalized) || matchesTaint(element?.outerHTML || '');
        if (match) {
            maybeReportTaintedValue(normalized, {
                type: 'dom-clobbering',
                sink: 'window/document named property',
                sinkId: 'dom.clobbering.named_property'
            }, context, match);
            return;
        }

        reportFinding({
            type: 'dom-clobbering',
            sink: 'window/document named property',
            sinkId: 'dom.clobbering.named_property',
            matched: normalized,
            source: {
                key: 'inline:dom-clobbering',
                source: 'inline:dom-clobbering',
                sourceKind: 'inline',
                raw: normalized,
                value: normalized
            },
            sources: [{
                key: 'inline:dom-clobbering',
                source: 'inline:dom-clobbering',
                sourceKind: 'inline',
                raw: normalized,
                value: normalized
            }],
            context
        });
    };

    const scanElement = (element) => {
        if (!element || element.nodeType !== Node.ELEMENT_NODE) return;
        getCandidateNames(element).forEach(({ attr, value }) => {
            reportDomClobbering(element, attr, value);
        });
    };

    const scanNodeSubtree = (root) => {
        if (!root || root.nodeType !== Node.ELEMENT_NODE) return;
        scanElement(root);
        if (typeof root.querySelectorAll !== 'function') return;
        const descendants = root.querySelectorAll('[id],[name]');
        for (let i = 0; i < descendants.length && i < 80; i += 1) {
            scanElement(descendants[i]);
        }
    };

    const flushDomClobberingQueue = () => {
        domClobberingFlushScheduled = false;
        let budget = 3;
        while (DOM_CLOBBERING_QUEUE.length && budget > 0) {
            const node = DOM_CLOBBERING_QUEUE.shift();
            try {
                scanNodeSubtree(node);
            } catch (_) { }
            budget -= 1;
        }
        if (DOM_CLOBBERING_QUEUE.length) {
            scheduleDomClobberingFlush();
        }
    };

    function scheduleDomClobberingFlush() {
        if (domClobberingFlushScheduled) return;
        domClobberingFlushScheduled = true;
        if (typeof window.requestIdleCallback === 'function') {
            window.requestIdleCallback(flushDomClobberingQueue, { timeout: 250 });
        } else {
            setTimeout(flushDomClobberingQueue, 16);
        }
    }

    const enqueueDomClobberingScan = (root) => {
        if (!root || root.nodeType !== Node.ELEMENT_NODE) return;
        if (DOM_CLOBBERING_QUEUE.length >= 24) return;
        DOM_CLOBBERING_QUEUE.push(root);
        scheduleDomClobberingFlush();
    };

    const runBootstrapScan = () => {
        if (isSmartMode()) return;
        if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.mutations')) return;
        if (IAST_SCAN_STRATEGY !== 'COMPREHENSIVE') return;
        const root = document.documentElement || document.body;
        if (!root) return;
        enqueueDomClobberingScan(root);
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', runBootstrapScan, { once: true });
    } else {
        setTimeout(runBootstrapScan, 0);
    }

    if (typeof MutationObserver === 'undefined') return;
    const observer = new MutationObserver((records) => {
        if (isSmartMode()) return;
        if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.mutations')) return;
        records.forEach((record) => {
            if (!record || !record.addedNodes) return;
            record.addedNodes.forEach((node) => {
                enqueueDomClobberingScan(node);
            });
        });
    });
    try {
        const root = document.documentElement || document;
        observer.observe(root, { childList: true, subtree: true });
    } catch (_) { }
})();

// DOM URL navigation sinks
; (function () {
    const NAV_SUPPRESS = { meta: null, time: 0 };
    const NAV_REPLAY_STATE = { active: false };
    function markLocationNavTrigger(meta) {
        NAV_SUPPRESS.meta = meta || null;
        NAV_SUPPRESS.time = Date.now();
    }
    function consumeLocationNavTrigger() {
        if (!NAV_SUPPRESS.meta) return null;
        if (Date.now() - NAV_SUPPRESS.time > 1500) {
            NAV_SUPPRESS.meta = null;
            return null;
        }
        const meta = NAV_SUPPRESS.meta;
        NAV_SUPPRESS.meta = null;
        return meta;
    }
    window.__IAST_CONSUME_NAV_TRIGGER__ = consumeLocationNavTrigger;
    function scheduleNavigationReplay(fn) {
        if (typeof fn !== 'function') return;
        setTimeout(() => {
            NAV_REPLAY_STATE.active = true;
            try {
                fn();
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: navigation replay failed', e);
            } finally {
                NAV_REPLAY_STATE.active = false;
            }
        }, 0);
    }

    const LocationProto = typeof Location !== 'undefined' ? Location.prototype : null;

    function wrapLocationSetter(prop, sinkId, label) {
        const targets = [];
        if (LocationProto) targets.push(LocationProto);
        try {
            if (window.location) targets.push(window.location);
        } catch (_) { }
        targets.forEach(target => {
            try {
                const desc = Object.getOwnPropertyDescriptor(target, prop);
                if (!desc || typeof desc.set !== 'function' || desc.configurable === false) return;
                Object.defineProperty(target, prop, {
                    configurable: true,
                    enumerable: desc.enumerable,
                    get: desc.get ? function () { return desc.get.call(this); } : undefined,
                    set(value) {
                        const ctx = this;
                        const runNative = () => desc.set.call(ctx, value);
                        if (NAV_REPLAY_STATE.active) {
                            return runNative();
                        }
                        if (!isHookGroupEnabled('hook.nav.redirects')) {
                            return runNative();
                        }
                        if (!shouldReportNavigationSink(value)) {
                            return runNative();
                        }
                        const resolvedSinkId = resolveDangerousUrlSinkId(sinkId, value) || sinkId;
                        const elMeta = captureElementMeta(document?.activeElement || null);
                        const observedBinding = buildObservedRuleBinding({
                            sinkId: resolvedSinkId,
                            value,
                            context: Object.assign({ value }, buildNetworkContext(value) || {}),
                            fallbackType: 'dom-url-navigation'
                        });
                        const reported = maybeReportTaintedValue(value, Object.assign({
                            type: 'dom-url-navigation',
                            sink: label
                        }, observedBinding), Object.assign({ property: prop, value }, elMeta, buildNetworkContext(value) || {}, {
                            scheme: getUrlScheme(value)
                        }));
                        if (reported) markLocationNavTrigger({ sinkId: resolvedSinkId, ruleId: observedBinding.ruleId || null, sinkLabel: label });
                        if (reported) {
                            scheduleNavigationReplay(runNative);
                            return;
                        }
                        return runNative();
                    }
                });
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: unable to wrap location property', prop);
            }
        });
    }

    function wrapLocationMethod(method, sinkId, label) {
        const targets = [];
        try {
            if (window.location && typeof window.location[method] === 'function') {
                targets.push({ target: window.location, useBound: true });
            }
        } catch (_) { }
        if (LocationProto && typeof LocationProto[method] === 'function') {
            targets.push({ target: LocationProto, useBound: false });
        }
        let wrapped = false;
        targets.forEach(({ target, useBound }) => {
            try {
                const orig = target[method];
                if (typeof orig !== 'function') return;
                if (useBound) {
                    const bound = orig.bind(window.location);
                    target[method] = function (...args) {
                        const callArgs = args.slice(0);
                        const invokeNative = () => bound(...callArgs);
                        if (NAV_REPLAY_STATE.active) {
                            return invokeNative();
                        }
                        if (!isHookGroupEnabled('hook.nav.redirects')) {
                            return invokeNative();
                        }
                        const url = args[0];
                        if (typeof url === 'string' && shouldReportNavigationSink(url)) {
                            const resolvedSinkId = resolveDangerousUrlSinkId(sinkId, url) || sinkId;
                            const elMeta = captureElementMeta(document?.activeElement || null);
                            const observedBinding = buildObservedRuleBinding({
                                sinkId: resolvedSinkId,
                                value: url,
                                context: Object.assign({ value: url }, buildNetworkContext(url) || {}),
                                fallbackType: 'dom-url-navigation'
                            });
                            const reported = maybeReportTaintedValue(url, Object.assign({
                                type: 'dom-url-navigation',
                                sink: label
                            }, observedBinding), Object.assign({ method: label, value: url }, elMeta, buildNetworkContext(url) || {}, {
                                scheme: getUrlScheme(url)
                            }));
                            if (reported) {
                                markLocationNavTrigger({ sinkId: resolvedSinkId, ruleId: observedBinding.ruleId || null, sinkLabel: label });
                                scheduleNavigationReplay(invokeNative);
                                return;
                            }
                        }
                        return invokeNative();
                    };
                } else {
                    target[method] = function (...args) {
                        const ctx = this;
                        const callArgs = args.slice(0);
                        const invokeNative = () => orig.apply(ctx, callArgs);
                        if (NAV_REPLAY_STATE.active) {
                            return invokeNative();
                        }
                        if (!isHookGroupEnabled('hook.nav.redirects')) {
                            return invokeNative();
                        }
                        const url = args[0];
                        if (typeof url === 'string' && shouldReportNavigationSink(url)) {
                            const resolvedSinkId = resolveDangerousUrlSinkId(sinkId, url) || sinkId;
                            const elMeta = captureElementMeta(document?.activeElement || null);
                            const observedBinding = buildObservedRuleBinding({
                                sinkId: resolvedSinkId,
                                value: url,
                                context: Object.assign({ value: url }, buildNetworkContext(url) || {}),
                                fallbackType: 'dom-url-navigation'
                            });
                            const reported = maybeReportTaintedValue(url, Object.assign({
                                type: 'dom-url-navigation',
                                sink: label
                            }, observedBinding), Object.assign({ method: label, value: url }, elMeta, buildNetworkContext(url) || {}, {
                                scheme: getUrlScheme(url)
                            }));
                            if (reported) {
                                markLocationNavTrigger({ sinkId: resolvedSinkId, ruleId: observedBinding.ruleId || null, sinkLabel: label });
                                scheduleNavigationReplay(invokeNative);
                                return;
                            }
                        }
                        return invokeNative();
                    };
                }
                wrapped = true;
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: failed to wrap location method', method, e);
            }
        });
        if (!wrapped) {
            __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: unable to patch location method', method);
        }
    }

    wrapLocationSetter('href', 'nav.location.href', 'location.href');
    wrapLocationMethod('assign', 'nav.location.assign', 'location.assign');
    wrapLocationMethod('replace', 'nav.location.replace', 'location.replace');

    const HistoryProto = typeof History !== 'undefined' ? History.prototype : null;
    const refreshRouteSourcesAsync = () => {
        if (typeof window.__IAST_REFRESH_ROUTE_SOURCES__ !== 'function') return;
        setTimeout(() => {
            try {
                window.__IAST_REFRESH_ROUTE_SOURCES__();
            } catch (_) { }
        }, 0);
    };
    const wrapHistoryMethod = (method, sinkId) => {
        if (!HistoryProto || typeof HistoryProto[method] !== 'function') return;
        const orig = HistoryProto[method];
        HistoryProto[method] = function (state, title, url) {
            if (isHookGroupEnabled('hook.nav.redirects') && typeof url === 'string' && url && shouldReportRouteControlledNavigationSink(url)) {
                const observedBinding = buildObservedRuleBinding({
                    sinkId,
                    value: url,
                    context: Object.assign({
                        value: url,
                        historyState: safeSerializeValue(state)
                    }, buildNetworkContext(url) || {}),
                    fallbackType: 'dom-url-navigation'
                });
                maybeReportTaintedValue(url, Object.assign({
                    type: 'dom-url-navigation',
                    sink: `history.${method}`
                }, observedBinding), Object.assign({
                    value: url,
                    method: `history.${method}`,
                    historyState: safeSerializeValue(state)
                }, buildNetworkContext(url) || {}));
            }
            const result = orig.apply(this, arguments);
            refreshRouteSourcesAsync();
            return result;
        };
    };
    if (HistoryProto) {
        wrapHistoryMethod('pushState', 'nav.history.pushState');
        wrapHistoryMethod('replaceState', 'nav.history.replaceState');
    }
})();

// Open-Redirect Detection

; (function () {
    function isExternalRedirect(url) {
        if (getDangerousUrlScheme(url)) return true;
        try {
            // resolve relative URLs against current location
            const resolved = new URL(url, window.location.href);
            // only consider http(s) URLs…
            if (!/^https?:$/i.test(resolved.protocol)) return false;
            // …and only if the origin really differs
            return resolved.origin !== window.location.origin;
        } catch (e) {
            // not a valid URL at all
            return false;
        }
    }

    function recordRedirect(url, method) {
        if (!isHookGroupEnabled('hook.nav.redirects')) return;
        // 1) skip anything that isn’t an external http(s) redirect
        if (!isExternalRedirect(url)) return;

        let resolvedSinkId = method === 'navigation.navigate' ? 'nav.navigation.navigate' : 'nav.window.open';
        let resolvedSinkLabel = method === 'navigation.navigate' ? 'navigation.navigate' : method;
        if (method === 'navigation.navigate') {
            if (typeof window.__IAST_CONSUME_NAV_TRIGGER__ === 'function') {
                const recent = window.__IAST_CONSUME_NAV_TRIGGER__();
                if (recent && recent.sinkId) {
                    resolvedSinkId = recent.sinkId;
                    resolvedSinkLabel = recent.sinkLabel || resolvedSinkLabel;
                } else {
                    resolvedSinkId = 'nav.location.href';
                    resolvedSinkLabel = 'location.href';
                }
            } else {
                resolvedSinkId = 'nav.location.href';
                resolvedSinkLabel = 'location.href';
            }
        }
        resolvedSinkId = resolveDangerousUrlSinkId(resolvedSinkId, url) || resolvedSinkId;

        const m = matchesTaint(url);
        const binding = buildObservedRuleBinding({
            sinkId: resolvedSinkId,
            value: url,
            context: Object.assign({ value: url }, buildNetworkContext(url) || {}),
            fallbackType: 'open-redirect'
        });
        if (m) {
            const meta = captureElementMeta(document?.activeElement || null);
            maybeReportTaintedValue(url, binding, Object.assign({ value: url }, meta, buildNetworkContext(url) || {}), m);
        }
    }

    //Wrap window.open()
    const origOpen = window.open;
    window.open = function (url, ...rest) {
        if (!isHookGroupEnabled('hook.nav.redirects')) {
            return origOpen.call(this, url, ...rest);
        }
        if (typeof url === 'string') {
            recordRedirect(url, 'window.open');
        }
        return origOpen.call(this, url, ...rest);
    };

    if ('navigation' in window && typeof navigation.addEventListener === 'function') {
        navigation.addEventListener('navigate', event => {
            if (!isHookGroupEnabled('hook.nav.redirects')) return;
            // event.destination.url is the URL we’re about to go to
            const url = event.destination.url;
            if (typeof url === 'string' && shouldReportRouteControlledNavigationSink(url)) {
                let resolvedSinkId = 'nav.navigation.navigate';
                let resolvedSinkLabel = 'navigation.navigate';
                if (typeof window.__IAST_CONSUME_NAV_TRIGGER__ === 'function') {
                    const recent = window.__IAST_CONSUME_NAV_TRIGGER__();
                    if (recent && recent.sinkId) {
                        resolvedSinkId = recent.sinkId;
                        resolvedSinkLabel = recent.sinkLabel || resolvedSinkLabel;
                    }
                }
                resolvedSinkId = resolveDangerousUrlSinkId(resolvedSinkId, url) || resolvedSinkId;
                const binding = buildObservedRuleBinding({
                    sinkId: resolvedSinkId,
                    value: url,
                    context: Object.assign({ value: url }, buildNetworkContext(url) || {}),
                    fallbackType: 'open-redirect'
                });
                const match = matchesTaint(url);
                if (match) {
                    const meta = captureElementMeta(document?.activeElement || null);
                    maybeReportTaintedValue(url, binding, Object.assign({ value: url }, meta, buildNetworkContext(url) || {}), match);
                }
            }
            // keep open-redirect classification for external redirects
            recordRedirect(url, 'navigation.navigate');
        });
    }

})();

// HTTP exfiltration sinks
; (function () {
    function coerceRequestUrl(input) {
        if (!input) return '';
        if (typeof input === 'string') return input;
        if (typeof URL !== 'undefined' && input instanceof URL) return input.href;
        if (typeof Request !== 'undefined' && input instanceof Request) return input.url;
        try {
            return String(input);
        } catch {
            return '';
        }
    }

    function coerceBodyString(body) {
        if (body == null) return '';
        if (typeof body === 'string') return body;
        if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
            return body.toString();
        }
        if (typeof FormData !== 'undefined' && body instanceof FormData) {
            const parts = [];
            body.forEach((val, key) => parts.push(`${key}=${val}`));
            return parts.join('&');
        }
        if (typeof Blob !== 'undefined' && body instanceof Blob) {
            // synchronous access not possible; fall back to placeholder
            return '[blob]';
        }
        return safeSerializeValue(body);
    }

    function scanHeaders(headers, cb) {
        if (!headers) return;
        if (typeof Headers !== 'undefined' && headers instanceof Headers) {
            headers.forEach((value, name) => cb(name, value));
            return;
        }
        if (Array.isArray(headers)) {
            headers.forEach(entry => {
                if (!entry) return;
                const [name, value] = entry;
                cb(name, value);
            });
            return;
        }
        if (typeof headers === 'object') {
            Object.entries(headers).forEach(([name, value]) => {
                if (Array.isArray(value)) {
                    value.forEach(v => cb(name, v));
                } else {
                    cb(name, value);
                }
            });
        }
    }

    const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

    function isCrossOriginUrl(url) {
        const target = buildNetworkTarget(url);
        if (!target) return false;
        return target.isCrossOrigin;
    }

    function requestIsInstance(resource) {
        return typeof Request !== 'undefined' && resource instanceof Request;
    }

    function resolveRequestMethod(resource, init) {
        if (init && init.method) return String(init.method).toUpperCase();
        if (requestIsInstance(resource) && resource.method) {
            return String(resource.method).toUpperCase();
        }
        return 'GET';
    }

    function resolveRequestCredentials(resource, init) {
        if (init && init.credentials) return String(init.credentials);
        if (requestIsInstance(resource) && resource.credentials) {
            return String(resource.credentials);
        }
        return 'same-origin';
    }

    function headersIndicateProtection(headerSet) {
        let protectedSignal = false;
        scanHeaders(headerSet, (name) => {
            if (protectedSignal || !name) return;
            const lower = String(name).toLowerCase();
            if (!lower) return;
            if (lower.includes('csrf') || lower.includes('xsrf') || lower.includes('token') || lower === 'x-requested-with'
                || lower === 'authorization' || lower === 'proxy-authorization' || lower.includes('api-key')) {
                protectedSignal = true;
            }
        });
        return protectedSignal;
    }

    function summarizeHeaders(headerSets, cap = 6) {
        const summary = [];
        headerSets.forEach(set => {
            scanHeaders(set, (name, value) => {
                if (summary.length >= cap) return;
                const serialized = safeSerializeValue(value || '');
                summary.push({
                    name,
                    value: serialized.length > 200 ? serialized.slice(0, 200) : serialized
                });
            });
        });
        return summary;
    }

    function documentHasAntiCsrfCookie() {
        if (typeof document === 'undefined' || !document.cookie) return false;
        try {
            return document.cookie.split(';').some(part => {
                const key = part.split('=')[0]?.trim().toLowerCase();
                if (!key) return false;
                return key.includes('csrf') || key.includes('xsrf');
            });
        } catch (_) {
            return false;
        }
    }

    function getDangerousPrototypeKeys(input) {
        if (!input || typeof input !== 'object') return [];
        try {
            return Reflect.ownKeys(input)
                .map((key) => typeof key === 'symbol' ? null : String(key))
                .filter((key) => key && IAST_DANGEROUS_PROTO_KEYS.has(key));
        } catch (_) {
            return [];
        }
    }

    function getOwnDangerousPropertyValue(input, key) {
        if (!input || typeof input !== 'object' || !key) return undefined;
        try {
            return Object.getOwnPropertyDescriptor(input, key)?.value;
        } catch (_) {
            return undefined;
        }
    }

    function normalizeStructuredMatchToken(value) {
        const serialized = safeSerializeValue(value).trim().toLowerCase();
        if (!serialized) return '';
        return serialized.replace(/\s+/g, '');
    }

    function resolveStructuredPrototypePollutionMatch(value) {
        const normalizedObserved = normalizeStructuredMatchToken(value);
        if (!normalizedObserved) return null;
        const taints = Object.entries(window.__IAST_TAINTED__ || {}).filter(([, v]) => v);
        if (!taints.length) return null;
        const meta = window.__IAST_TAINT_META__ || {};
        const matches = [];

        const kindOf = (key) => {
            if (key.startsWith('query:')) return 'query';
            if (key === 'hash:route') return 'hashRoute';
            if (key.startsWith('hash:param:')) return 'hashQuery';
            if (key === 'path:pathname') return 'pathname';
            if (key.startsWith('path:segment:')) return 'pathSegment';
            if (key === 'route:client') return 'clientRoute';
            if (key === 'history:state') return 'historyState';
            if (key.startsWith('body:param:')) return 'bodyParam';
            if (key.startsWith('body:json:')) return 'jsonBodyField';
            if (key.startsWith('body:formdata:')) return 'formDataField';
            if (key.startsWith('graphql:variables:')) return 'graphqlVariable';
            if (key.startsWith('response:json:')) return 'apiResponseField';
            if (key.startsWith('graphql:response:')) return 'graphqlResponseField';
            if (key === 'referrer') return 'referrer';
            if (key.startsWith('cookie:')) return 'cookie';
            if (key.startsWith('localStorage:')) return 'localStorage';
            if (key.startsWith('sessionStorage:')) return 'sessionStorage';
            if (key === 'window.name') return 'windowName';
            if (key === 'postMessage' || key.startsWith('postMessage:')) return 'postMessage';
            if (key.startsWith('inline:')) return 'inline';
            return 'other';
        };

        const kindPriority = (kind) => {
            switch (kind) {
                case 'query': return 100;
                case 'hashQuery': return 90;
                case 'hashRoute': return 85;
                case 'clientRoute': return 82;
                case 'pathname': return 80;
                case 'pathSegment': return 78;
                case 'historyState': return 76;
                case 'formDataField': return 75;
                case 'bodyParam': return 74;
                case 'jsonBodyField': return 72;
                case 'graphqlVariable': return 71;
                case 'graphqlResponseField': return 69;
                case 'apiResponseField': return 68;
                case 'inline': return 80;
                case 'localStorage': return 70;
                case 'sessionStorage': return 60;
                case 'cookie': return 50;
                case 'referrer': return 40;
                case 'windowName': return 30;
                case 'postMessage': return 30;
                default: return 10;
            }
        };

        for (const [sourceKey, rawVal] of taints) {
            if (!rawVal) continue;
            const normalizedTaint = normalizeStructuredMatchToken(rawVal);
            if (!normalizedTaint) continue;
            if (!normalizedObserved.includes(normalizedTaint)) continue;
            const kind = kindOf(sourceKey);
            const sourceMeta = meta[sourceKey] || {};
            const lastUpdated = typeof sourceMeta.lastUpdated === 'number' ? sourceMeta.lastUpdated : 0;
            const score = kindPriority(kind) * 1_000_000 + Math.min(Math.floor(lastUpdated / 1000), 1_000_000);
            matches.push({
                source: sourceKey,
                raw: rawVal,
                kind,
                matchType: 'structured',
                score,
                lastUpdated,
                taintKind: sourceMeta.taintKind || null
            });
        }

        if (!matches.length) return null;
        matches.sort((a, b) => b.score - a.score);
        const primary = matches[0];
        return {
            source: primary.source,
            raw: primary.raw,
            allSources: matches
        };
    }

    function resolvePrototypePollutionMatch(value, sourceObject = null, dangerousKey = null) {
        const candidates = [
            typeof value === 'string' ? value : null,
            trimResponsePayloadText(value),
            sourceObject ? trimResponsePayloadText(sourceObject) : null
        ].filter(Boolean);
        for (const candidate of candidates) {
            const match = matchesTaint(candidate);
            if (match) {
                return {
                    observedValue: candidate,
                    matchOverride: match,
                    sources: normalizeTaintedSources(match.allSources, match.raw)
                };
            }
        }
        const wrappedValue = dangerousKey && value && typeof value === 'object'
            ? { [dangerousKey]: value }
            : null;
        const structuredMatch = resolveStructuredPrototypePollutionMatch(value)
            || (sourceObject ? resolveStructuredPrototypePollutionMatch(sourceObject) : null)
            || (wrappedValue ? resolveStructuredPrototypePollutionMatch(wrappedValue) : null);
        if (structuredMatch) {
            return {
                observedValue: safeSerializeValue(sourceObject || value),
                matchOverride: structuredMatch,
                sources: normalizeTaintedSources(structuredMatch.allSources, structuredMatch.raw)
            };
        }
        return null;
    }

    function reportPrototypePollutionWrite(method, dangerousKey, dangerousValue, sourceObject = null) {
        if (!isHookGroupEnabled('hook.runtime.integrity.prototypeWrites')) return;
        const resolved = resolvePrototypePollutionMatch(dangerousValue, sourceObject, dangerousKey);
        if (!resolved || !resolved.matchOverride) return;
        rememberPrototypePollutionEvent({
            at: Date.now(),
            method,
            key: dangerousKey,
            observedValue: resolved.observedValue,
            matchOverride: resolved.matchOverride,
            sources: resolved.sources
        });
        window.__PTK_IAST_LAST_FETCHINIT_DEBUG__ = {
            phase: 'prototype_write_recorded',
            method,
            dangerousKey,
            observedValue: resolved.observedValue,
            sourceKinds: resolved.sources.map((source) => source?.sourceKind).filter(Boolean)
        };
        maybeReportTaintedValue(resolved.observedValue, {
            type: 'prototype-pollution-write',
            sink: `${method} prototype write`,
            sinkId: 'runtime.prototype.pollution.write'
        }, {
            attribute: dangerousKey,
            value: resolved.observedValue,
            primaryClass: IAST_PRIMARY_CLASSES.HYBRID,
            sourceRole: IAST_SOURCE_ROLES.ORIGIN,
            detection: {
                reason: IAST_REASON_CODES.PROTOTYPE_POLLUTION_WRITE,
                dataKind: IAST_DATA_KINDS.UNKNOWN,
                confidence: 84,
                details: {
                    method,
                    dangerousKey
                }
            }
        }, resolved.matchOverride);
    }

    function getInheritedPrototypeImpactFields(init) {
        if (!init || typeof init !== 'object' || Array.isArray(init)) return [];
        return IAST_PROTO_IMPACT_FIELDS.filter((field) => {
            if (!(field in init)) return false;
            return !Object.prototype.hasOwnProperty.call(init, field);
        });
    }

    function reportPrototypePollutionFetchImpact(url, init, inheritedFields = []) {
        if (!isHookGroupEnabled('hook.runtime.integrity.fetchInit')) return;
        window.__PTK_IAST_LAST_FETCHINIT_DEBUG__ = {
            phase: 'fetch_impact_enter',
            url: url || null,
            inheritedFields: Array.isArray(inheritedFields) ? inheritedFields.slice() : [],
            hasInit: !!init
        };
        if (!Array.isArray(inheritedFields) || !inheritedFields.length) return;
        const recent = getRecentPrototypePollutionEvent();
        if (!recent || !recent.matchOverride) {
            window.__PTK_IAST_LAST_FETCHINIT_DEBUG__ = {
                phase: 'fetch_impact_missing_recent',
                url: url || null,
                inheritedFields: Array.isArray(inheritedFields) ? inheritedFields.slice() : [],
                recent: recent
                    ? {
                        at: recent.at || null,
                        method: recent.method || null,
                        key: recent.key || null,
                        observedValue: recent.observedValue || null
                    }
                    : null
            };
            return;
        }
        window.__PTK_IAST_LAST_FETCHINIT_DEBUG__ = {
            phase: 'fetch_impact_reporting',
            url: url || null,
            inheritedFields: Array.isArray(inheritedFields) ? inheritedFields.slice() : [],
            recent: {
                at: recent.at || null,
                method: recent.method || null,
                key: recent.key || null,
                observedValue: recent.observedValue || null
            }
        };
        maybeReportTaintedValue(recent.observedValue, {
            type: 'prototype-pollution-impact',
            sink: 'fetch(init inherited prototype fields)',
            sinkId: 'runtime.prototype.pollution.fetchInit'
        }, Object.assign({
            value: recent.observedValue,
            requestUrl: url || null,
            url: url || null,
            inheritedFields,
            attribute: inheritedFields.join(','),
            primaryClass: IAST_PRIMARY_CLASSES.HYBRID,
            sourceRole: IAST_SOURCE_ROLES.ORIGIN,
            detection: {
                reason: IAST_REASON_CODES.PROTOTYPE_POLLUTION_FETCH_IMPACT,
                dataKind: IAST_DATA_KINDS.UNKNOWN,
                confidence: 88,
                details: {
                    inheritedFields,
                    pollutionKey: recent.key || null,
                    pollutionMethod: recent.method || null
                }
            }
        }, buildNetworkContext(url) || {}), recent.matchOverride);
    }

    if (typeof Object.assign === 'function' && !Object.assign.__ptk_iast_wrapped__) {
        const origAssign = Object.assign;
        const wrappedAssign = function (target, ...sources) {
            if (isHookGroupEnabled('hook.runtime.integrity.prototypeWrites')) {
                sources.slice(0, 3).forEach((source) => {
                    getDangerousPrototypeKeys(source).forEach((dangerousKey) => {
                        reportPrototypePollutionWrite('Object.assign', dangerousKey, getOwnDangerousPropertyValue(source, dangerousKey), source);
                    });
                });
            }
            return origAssign.call(Object, target, ...sources);
        };
        wrappedAssign.__ptk_iast_wrapped__ = true;
        Object.assign = wrappedAssign;
    }

    if (typeof Reflect !== 'undefined' && typeof Reflect.set === 'function' && !Reflect.set.__ptk_iast_wrapped__) {
        const origReflectSet = Reflect.set;
        const wrappedReflectSet = function (target, propertyKey, value, receiver) {
            if (isHookGroupEnabled('hook.runtime.integrity.prototypeWrites') && IAST_DANGEROUS_PROTO_KEYS.has(String(propertyKey || ''))) {
                reportPrototypePollutionWrite('Reflect.set', String(propertyKey), value, receiver || target);
            }
            return origReflectSet.call(Reflect, target, propertyKey, value, receiver);
        };
        wrappedReflectSet.__ptk_iast_wrapped__ = true;
        Reflect.set = wrappedReflectSet;
    }

    if (typeof Object.defineProperty === 'function' && !Object.defineProperty.__ptk_iast_wrapped__) {
        const origDefineProperty = Object.defineProperty;
        const wrappedDefineProperty = function (target, propertyKey, descriptor) {
            if (isHookGroupEnabled('hook.runtime.integrity.prototypeWrites') && IAST_DANGEROUS_PROTO_KEYS.has(String(propertyKey || ''))) {
                reportPrototypePollutionWrite('Object.defineProperty', String(propertyKey), descriptor?.value, descriptor);
            }
            return origDefineProperty.call(Object, target, propertyKey, descriptor);
        };
        wrappedDefineProperty.__ptk_iast_wrapped__ = true;
        Object.defineProperty = wrappedDefineProperty;
    }

    if (typeof window.WebSocket === 'function') {
        const OriginalWebSocket = window.WebSocket;
        if (!OriginalWebSocket.__ptk_iast_url_wrapped__) {
            const WrappedWebSocket = new Proxy(OriginalWebSocket, {
                construct(target, args, newTarget) {
                    if (isHookGroupEnabled('hook.net.exfil')) {
                        const url = coerceRequestUrl(args?.[0]);
                        if (url) {
                            const networkContext = buildNetworkContext(url);
                            maybeReportTaintedValue(url, {
                                type: 'websocket-url-poisoning',
                                sink: 'WebSocket(url)',
                                sinkId: 'realtime.websocket.url'
                            }, Object.assign({
                                value: url,
                                url,
                                requestUrl: url
                            }, networkContext || {}));
                        }
                    }
                    return Reflect.construct(target, args, newTarget);
                }
            });
            try {
                WrappedWebSocket.prototype = OriginalWebSocket.prototype;
                Object.setPrototypeOf(WrappedWebSocket, OriginalWebSocket);
                ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach((k) => {
                    WrappedWebSocket[k] = OriginalWebSocket[k];
                });
            } catch (_) { }
            WrappedWebSocket.__ptk_iast_url_wrapped__ = true;
            window.WebSocket = WrappedWebSocket;
        }
    }

    if (typeof window.fetch === 'function') {
        const origFetch = window.fetch;
        window.fetch = function (...args) {
            let isGraphqlRequest = false;
            try {
                const networkHooksEnabled = isNetworkActivityHookEnabled();
                const responseHooksEnabled = isHookGroupEnabled('hook.net.responses');
                const resource = args[0];
                const init = args[1];
                const url = coerceRequestUrl(resource);
                const inheritedImpactFields = getInheritedPrototypeImpactFields(init);
                if (inheritedImpactFields.length) {
                    reportPrototypePollutionFetchImpact(url, init, inheritedImpactFields);
                }
                const exfilHooksEnabled = isHookGroupEnabled('hook.net.exfil');
                const networkContext = buildNetworkContext(url);
                const suspiciousUrl = url && isSuspiciousExfilUrl(url);
                if (exfilHooksEnabled && url && suspiciousUrl) {
                    const observedBinding = buildObservedRuleBinding({
                        sinkId: 'http.fetch.url',
                        value: url,
                        context: Object.assign({ value: url, method: 'fetch', requestUrl: url }, networkContext || {}),
                        fallbackType: 'http-exfiltration'
                    });
                    maybeReportTaintedValue(url, Object.assign({
                        type: 'http-exfiltration',
                        sink: 'fetch(url)'
                    }, observedBinding), Object.assign({ value: url, method: 'fetch', requestUrl: url }, networkContext || {}));
                }
                const headerCandidates = [];
                if (requestIsInstance(resource)) {
                    headerCandidates.push(resource.headers);
                }
                if (init && init.headers) {
                    headerCandidates.push(init.headers);
                }
                const contentType = extractContentTypeFromHeaders(headerCandidates);
                const requestBody = init && Object.prototype.hasOwnProperty.call(init, 'body')
                    ? init.body
                    : null;
                isGraphqlRequest = isLikelyGraphqlRequest(url, requestBody, contentType);
                const method = resolveRequestMethod(resource, init);
                if (networkHooksEnabled && requestBody != null) {
                    registerRequestBodySources(requestBody, { contentType });
                }
                let hasProtectiveHeader = false;
                if (exfilHooksEnabled && suspiciousUrl) {
                    headerCandidates.forEach(candidate => {
                        if (!hasProtectiveHeader && headersIndicateProtection(candidate)) {
                            hasProtectiveHeader = true;
                        }
                        scanHeaders(candidate, (name, value) => {
                            const observedBinding = buildObservedRuleBinding({
                                sinkId: 'http.fetch.headers',
                                value,
                                context: Object.assign({ headerName: name, value, requestUrl: url, method: 'fetch' }, networkContext || {}),
                                fallbackType: 'http-exfiltration'
                            });
                            maybeReportTaintedValue(value, Object.assign({
                                type: 'http-exfiltration',
                                sink: 'fetch headers'
                            }, observedBinding), Object.assign({ headerName: name, value, requestUrl: url, method: 'fetch' }, networkContext || {}));
                        });
                    });
                } else {
                    headerCandidates.forEach(candidate => {
                        scanHeaders(candidate, (name, value) => {
                            emitAuthHeaderRuntimeSignal({
                                sinkId: 'http.fetch.headers',
                                headerName: name,
                                value,
                                requestUrl: url,
                                method: method || 'GET',
                                networkTarget: buildNetworkTarget(url)
                            });
                        });
                    });
                }

                const credentialsMode = resolveRequestCredentials(resource, init);
                const sendsCredentials = String(credentialsMode || '').toLowerCase() === 'include';
                const hasCsrfCookie = documentHasAntiCsrfCookie();
                if (exfilHooksEnabled && url && isCrossOriginUrl(url) && sendsCredentials && !SAFE_HTTP_METHODS.has(method)
                    && !hasProtectiveHeader && !hasCsrfCookie) {
                    reportFinding({
                        type: 'csrf-cross-site-fetch',
                        sink: 'fetch',
                        sinkId: 'csrf.fetch',
                        matched: null,
                        source: null,
                        sources: [],
                        context: {
                            method,
                            url,
                            credentials: credentialsMode,
                            headers: summarizeHeaders(headerCandidates),
                            value: url,
                            requestUrl: url,
                            ...(networkContext || {})
                        }
                    });
                }
                if (!networkHooksEnabled && !headerCandidates.length && !requestBody && !responseHooksEnabled) {
                    return origFetch.apply(this, args);
                }
            } catch (err) {
                __PTK_IAST_DBG__('fetch wrapper error', err);
            }
            const fetchPromise = origFetch.apply(this, args);
            return Promise.resolve(fetchPromise).then((response) => {
                try {
                    if (isHookGroupEnabled('hook.net.responses')) {
                        captureFetchResponseSources(response, {
                            requestUrl: coerceRequestUrl(args[0]),
                            isGraphql: isGraphqlRequest
                        });
                    }
                } catch (_) { }
                return response;
            });
        };
    }

    if (typeof XMLHttpRequest !== 'undefined') {
        const origOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url, ...rest) {
            this.__ptk_iast_method = method;
            this.__ptk_iast_url = url;
            this.__ptk_iast_headers = [];
            this.__ptk_iast_is_graphql = false;
            const networkTarget = buildNetworkTarget(url);
            this.__ptk_iast_networkTarget = networkTarget;
            this.__ptk_iast_url_resolved = networkTarget?.url || null;
            if (!isNetworkActivityHookEnabled()) {
                return origOpen.call(this, method, url, ...rest);
            }
            const suspicious = isSuspiciousExfilUrl(url);
            this.__ptk_iast_exfil_suspicious = suspicious;
            if (suspicious) {
                const networkContext = networkTarget ? {
                    networkTarget,
                    destUrl: networkTarget.url,
                    destHost: networkTarget.host,
                    destOrigin: networkTarget.origin,
                    isCrossOrigin: networkTarget.isCrossOrigin,
                    scheme: networkTarget.scheme
                } : null;
                const observedBinding = buildObservedRuleBinding({
                    sinkId: 'http.xhr.open',
                    value: url,
                    context: Object.assign({ method, value: url, requestUrl: url }, networkContext || {}),
                    fallbackType: 'http-exfiltration'
                });
                maybeReportTaintedValue(url, Object.assign({
                    type: 'http-exfiltration',
                    sink: 'XMLHttpRequest.open'
                }, observedBinding), Object.assign({ method, value: url, requestUrl: url }, networkContext || {}));
            }
            return origOpen.call(this, method, url, ...rest);
        };

        const origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
        if (origSetRequestHeader) {
            XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
                const exfilHooksEnabled = isHookGroupEnabled('hook.net.exfil');
                const m = exfilHooksEnabled ? matchesTaint(value) : null;
                if (exfilHooksEnabled && m) {
                    const networkTarget = this.__ptk_iast_networkTarget || buildNetworkTarget(this.__ptk_iast_url || null);
                    const networkContext = networkTarget ? {
                        networkTarget,
                        destUrl: networkTarget.url,
                        destHost: networkTarget.host,
                        destOrigin: networkTarget.origin,
                        isCrossOrigin: networkTarget.isCrossOrigin,
                        scheme: networkTarget.scheme
                    } : null;
                    const binding = buildRuleBinding({ sinkId: 'http.xhr.setRequestHeader', fallbackType: 'xhr-header' });
                    maybeReportTaintedValue(value, binding, {
                        headerName: name,
                        value,
                        requestUrl: this.__ptk_iast_url || null,
                        method: this.__ptk_iast_method || null,
                        ...(networkContext || {})
                    }, m);
                } else if (!exfilHooksEnabled) {
                    emitAuthHeaderRuntimeSignal({
                        sinkId: 'http.xhr.setRequestHeader',
                        headerName: name,
                        value,
                        requestUrl: this.__ptk_iast_url || null,
                        method: this.__ptk_iast_method || 'GET',
                        networkTarget: this.__ptk_iast_networkTarget || buildNetworkTarget(this.__ptk_iast_url || null)
                    });
                }
                this.__ptk_iast_headers = Array.isArray(this.__ptk_iast_headers) ? this.__ptk_iast_headers : [];
                this.__ptk_iast_headers.push([name, value]);
                return origSetRequestHeader.call(this, name, value);
            };
        }

        const origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function (body) {
            const networkHooksEnabled = isNetworkActivityHookEnabled();
            const exfilHooksEnabled = isHookGroupEnabled('hook.net.exfil');
            const responseHooksEnabled = isHookGroupEnabled('hook.net.responses');
            if (networkHooksEnabled && body !== undefined) {
                const contentType = extractContentTypeFromHeaders([this.__ptk_iast_headers]);
                this.__ptk_iast_is_graphql = isLikelyGraphqlRequest(
                    this.__ptk_iast_url_resolved || this.__ptk_iast_url || null,
                    body,
                    contentType
                );
                registerRequestBodySources(body, { contentType });
                const serialized = coerceBodyString(body);
                if (exfilHooksEnabled && serialized && this.__ptk_iast_exfil_suspicious) {
                    const networkTarget = this.__ptk_iast_networkTarget || buildNetworkTarget(this.__ptk_iast_url || null);
                    const networkContext = networkTarget ? {
                        networkTarget,
                        destUrl: networkTarget.url,
                        destHost: networkTarget.host,
                        destOrigin: networkTarget.origin,
                        isCrossOrigin: networkTarget.isCrossOrigin,
                        scheme: networkTarget.scheme
                    } : null;
                    maybeReportTaintedValue(serialized, {
                        type: 'http-exfiltration',
                        sink: 'XMLHttpRequest.send',
                        sinkId: 'http.xhr.send'
                    }, {
                        method: this.__ptk_iast_method || null,
                        requestUrl: this.__ptk_iast_url || null,
                        value: serialized,
                        ...(networkContext || {})
                    });
                }
            }
            if (responseHooksEnabled && !this.__ptk_iast_response_listener_added && typeof this.addEventListener === 'function') {
                this.__ptk_iast_response_listener_added = true;
                this.addEventListener('loadend', () => {
                    try {
                        captureXhrResponseSources(this);
                    } catch (_) { }
                    this.__ptk_iast_response_listener_added = false;
                }, { once: true });
            }
            return origSend.call(this, body);
        };
    }

    if (typeof navigator !== 'undefined' && navigator && typeof navigator.sendBeacon === 'function') {
        const origSendBeacon = navigator.sendBeacon;
        navigator.sendBeacon = function (url, data) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origSendBeacon.call(this, url, data);
            }
            if (isSuspiciousExfilUrl(url)) {
                const networkContext = buildNetworkContext(url);
                const observedBinding = buildObservedRuleBinding({
                    sinkId: 'http.navigator.sendBeacon',
                    value: data,
                    context: Object.assign({ value: coerceBodyString(data), url, requestUrl: url }, networkContext || {}),
                    fallbackType: 'http-exfiltration'
                });
                maybeReportTaintedValue(data, Object.assign({
                    type: 'http-exfiltration',
                    sink: 'navigator.sendBeacon'
                }, observedBinding), Object.assign({ value: coerceBodyString(data), url, requestUrl: url }, networkContext || {}));
            }
            return origSendBeacon.call(this, url, data);
        };
    }

    if (typeof HTMLImageElement !== 'undefined') {
        const desc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
        if (desc && desc.set) {
            Object.defineProperty(HTMLImageElement.prototype, 'src', {
                configurable: true,
                enumerable: desc.enumerable,
                get: desc.get,
                set(value) {
                    if (!isHookGroupEnabled('hook.net.exfil')) {
                        return desc.set.call(this, value);
                    }
                    if (isSuspiciousExfilUrl(value)) {
                        const networkContext = buildNetworkContext(value);
                        const observedBinding = buildObservedRuleBinding({
                            sinkId: 'http.image.src',
                            value,
                            context: Object.assign({ value, element: this, requestUrl: value }, networkContext || {}),
                            fallbackType: 'http-exfiltration'
                        });
                        maybeReportTaintedValue(value, Object.assign({
                            type: 'http-exfiltration',
                            sink: 'image.src'
                        }, observedBinding), Object.assign({ value, element: this, requestUrl: value }, networkContext || {}));
                    }
                    return desc.set.call(this, value);
                }
            });
        }
    }

    if (typeof WebSocket !== 'undefined' && WebSocket.prototype && typeof WebSocket.prototype.send === 'function') {
        const origSocketSend = WebSocket.prototype.send;
        WebSocket.prototype.send = function (data) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                emitWebSocketRuntimeSignal({
                    value: data,
                    socketUrl: this?.url || null,
                    protocol: this?.protocol || null
                });
                return origSocketSend.apply(this, arguments);
            }
            const payload = safeSerializeValue(data);
            if (payload) {
                const networkContext = buildNetworkContext(this?.url || null);
                const observedBinding = buildObservedRuleBinding({
                    sinkId: 'realtime.websocket.send',
                    value: payload,
                    context: Object.assign({
                        value: payload,
                        url: this?.url || null,
                        protocol: this?.protocol || null
                    }, networkContext || {}),
                    fallbackType: 'realtime-exfiltration'
                });
                maybeReportTaintedValue(payload, Object.assign({
                    type: 'realtime-exfiltration',
                    sink: 'WebSocket.send'
                }, observedBinding), {
                    value: payload,
                    url: this?.url || null,
                    protocol: this?.protocol || null,
                    ...(networkContext || {})
                });
            }
            return origSocketSend.apply(this, arguments);
        };
    }

    if (typeof RTCDataChannel !== 'undefined' && RTCDataChannel.prototype && typeof RTCDataChannel.prototype.send === 'function') {
        const origRtcSend = RTCDataChannel.prototype.send;
        RTCDataChannel.prototype.send = function (data) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origRtcSend.apply(this, arguments);
            }
            const payload = safeSerializeValue(data);
            if (payload) {
                const observedBinding = buildObservedRuleBinding({
                    sinkId: 'realtime.webrtc.send',
                    value: payload,
                    context: { value: payload, label: this?.label || null },
                    fallbackType: 'realtime-exfiltration'
                });
                maybeReportTaintedValue(payload, Object.assign({
                    type: 'realtime-exfiltration',
                    sink: 'RTCDataChannel.send'
                }, observedBinding), {
                    value: payload,
                    label: this?.label || null
                });
            }
            return origRtcSend.apply(this, arguments);
        };
    }
})();

// Dynamic script loading sinks
; (function () {
    if (typeof HTMLScriptElement === 'undefined') return;
    const desc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (!desc || !desc.set) return;
    Object.defineProperty(HTMLScriptElement.prototype, 'src', {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set(value) {
            if (!isHookGroupEnabled('hook.script.loading')) {
                return desc.set.call(this, value);
            }
            const networkContext = buildNetworkContext(value);
            maybeReportTaintedValue(value, {
                type: 'dynamic-script-loading',
                sink: 'script.src',
                sinkId: 'script.element.src'
            }, Object.assign({ value, element: this, requestUrl: value }, networkContext || {}));
            return desc.set.call(this, value);
        }
    });
})();

// Debug logging sinks
; (function () {
    if (typeof console === 'undefined') return;
    const sinks = [
        { method: 'log', sinkId: 'log.console.log' },
        { method: 'error', sinkId: 'log.console.error' }
    ];
    sinks.forEach(({ method, sinkId }) => {
        const orig = console[method];
        if (typeof orig !== 'function') return;
        console[method] = function (...args) {
            if (!isHookGroupEnabled('hook.console.leaks')) {
                return orig.apply(this, args);
            }
            args.forEach(arg => {
                const payload = safeSerializeValue(arg);
                if (!payload) return;
                const binding = buildRuleBinding({ sinkId, fallbackType: 'debug-logging' });
                maybeReportTaintedValue(payload, Object.assign({
                    type: 'debug-logging',
                    sink: `console.${method}`
                }, binding), { value: payload, method: `console.${method}` });
            });
            return orig.apply(this, args);
        };
    });
})();

// Clipboard exfiltration sink
; (function () {
    if (typeof navigator === 'undefined') return;
    const clip = navigator.clipboard;
    if (!clip || typeof clip.writeText !== 'function') return;
    const origWriteText = clip.writeText;
    clip.writeText = function (...args) {
        if (!isHookGroupEnabled('hook.net.exfil')) {
            return origWriteText.apply(this, args);
        }
        const payload = safeSerializeValue(args[0]);
        if (payload) {
            maybeReportTaintedValue(payload, {
                type: 'clipboard-exfiltration',
                sink: 'navigator.clipboard.writeText',
                sinkId: 'clipboard.writeText'
            }, { value: payload });
        }
        return origWriteText.apply(this, args);
    };
})();

// BroadcastChannel & MessagePort sinks
; (function () {
    if (typeof BroadcastChannel !== 'undefined' && BroadcastChannel.prototype) {
        const orig = BroadcastChannel.prototype.postMessage;
        if (typeof orig === 'function') {
            BroadcastChannel.prototype.postMessage = function (message) {
                if (!isHookGroupEnabled('hook.postMessage')) {
                    return orig.apply(this, arguments);
                }
                if (!isIastSinkActive('channel.broadcast.postMessage')) {
                    return orig.apply(this, arguments);
                }
                const payload = safeSerializeValue(message);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'web-messaging-channel',
                        sink: 'BroadcastChannel.postMessage',
                        sinkId: 'channel.broadcast.postMessage'
                    }, { value: payload, channelName: this?.name || null });
                }
                return orig.apply(this, arguments);
            };
        }
    }

    if (typeof MessagePort !== 'undefined' && MessagePort.prototype) {
        const origPortPost = MessagePort.prototype.postMessage;
        if (typeof origPortPost === 'function') {
            MessagePort.prototype.postMessage = function (message, transfer) {
                if (!isHookGroupEnabled('hook.postMessage')) {
                    return origPortPost.apply(this, arguments);
                }
                if (!isIastSinkActive('channel.messageport.postMessage')) {
                    return origPortPost.apply(this, arguments);
                }
                const payload = safeSerializeValue(message);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'web-messaging-channel',
                        sink: 'MessagePort.postMessage',
                        sinkId: 'channel.messageport.postMessage'
                    }, { value: payload });
                }
                return origPortPost.apply(this, arguments);
            };
        }
    }
})();

// Worker & ServiceWorker script loading sinks
; (function () {
    if (typeof navigator !== 'undefined' && navigator.serviceWorker && typeof navigator.serviceWorker.register === 'function') {
        const origRegister = navigator.serviceWorker.register;
        navigator.serviceWorker.register = function (...args) {
            if (!isHookGroupEnabled('hook.script.loading')) {
                return origRegister.apply(this, args);
            }
            const payload = safeSerializeValue(args[0]);
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'worker-script-loading',
                    sink: 'navigator.serviceWorker.register',
                    sinkId: 'worker.serviceWorker.register'
                }, { value: payload });
            }
            return origRegister.apply(this, args);
        };
    }

    if (typeof window.Worker === 'function') {
        const OriginalWorker = window.Worker;
        window.Worker = new Proxy(OriginalWorker, {
            construct(target, args, newTarget) {
                if (!isHookGroupEnabled('hook.script.loading')) {
                    return Reflect.construct(target, args, newTarget);
                }
                const payload = safeSerializeValue(args[0]);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'worker-script-loading',
                        sink: 'Worker',
                        sinkId: 'worker.webworker.constructor'
                    }, { value: payload });
                }
                return Reflect.construct(target, args, newTarget);
            }
        });
    }
})();

// window.postMessage misuse
; (function () {
    if (typeof window.postMessage !== 'function') return;
    const origPostMessage = window.postMessage;
    window.postMessage = function (message, targetOrigin, transfer) {
        if (!isHookGroupEnabled('hook.postMessage')) {
            const originValue = targetOrigin == null ? '*' : targetOrigin;
            if (originValue === '*' || originValue === '') {
                emitPostMessageRuntimeSignal({
                    message,
                    targetOrigin: originValue,
                    sinkId: 'postmessage.anyOrigin'
                });
            } else if (typeof originValue === 'string') {
                let destOrigin = null;
                try {
                    destOrigin = new URL(originValue, window.location.href).origin;
                } catch (_) {
                    destOrigin = null;
                }
                if (destOrigin && destOrigin !== window.location.origin) {
                    emitPostMessageRuntimeSignal({
                        message,
                        targetOrigin: originValue,
                        sinkId: 'postmessage.crossOrigin'
                    });
                }
            }
            return origPostMessage.apply(this, arguments);
        }
        const payload = safeSerializeValue(message);
        const originValue = targetOrigin == null ? '*' : targetOrigin;
        const defaultContext = { value: payload, targetOrigin: originValue };
        if (originValue === '*' || originValue === '') {
            if (!isIastSinkActive('postmessage.anyOrigin')) {
                return origPostMessage.apply(this, arguments);
            }
            const observedBinding = buildObservedRuleBinding({
                sinkId: 'postmessage.anyOrigin',
                value: payload,
                context: defaultContext,
                fallbackType: 'postmessage-leak'
            });
            maybeReportTaintedValue(payload, Object.assign({
                type: 'postMessage-leak',
                sink: 'window.postMessage'
            }, observedBinding), defaultContext);
        } else if (typeof originValue === 'string') {
            let destOrigin = null;
            try {
                destOrigin = new URL(originValue, window.location.href).origin;
            } catch (_) {
                destOrigin = null;
            }
            if (destOrigin && destOrigin !== window.location.origin) {
                if (!isIastSinkActive('postmessage.crossOrigin')) {
                    return origPostMessage.apply(this, arguments);
                }
                const observedBinding = buildObservedRuleBinding({
                    sinkId: 'postmessage.crossOrigin',
                    value: payload,
                    context: Object.assign({}, defaultContext, { destination: destOrigin, isCrossOrigin: true }),
                    fallbackType: 'postmessage-leak'
                });
                maybeReportTaintedValue(payload, Object.assign({
                    type: 'postMessage-leak',
                    sink: 'window.postMessage'
                }, observedBinding), Object.assign({}, defaultContext, { destination: destOrigin }));
            }
        }
        return origPostMessage.apply(this, arguments);
    };
})();

// IFrame navigation/content sinks
; (function () {
    if (typeof HTMLIFrameElement === 'undefined') return;
    const srcDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    if (srcDesc && srcDesc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
            configurable: true,
            enumerable: srcDesc.enumerable,
            get: srcDesc.get,
            set(value) {
                if (!isHookGroupEnabled('hook.dom.urlAttributes')) {
                    return srcDesc.set.call(this, value);
                }
                if (shouldReportNavigationSink(value)) {
                    maybeReportTaintedValue(value, {
                        type: 'iframe-navigation',
                        sink: 'iframe.src',
                        sinkId: 'nav.iframe.src'
                    }, { value, element: this });
                }
                return srcDesc.set.call(this, value);
            }
        });
    }
    const srcdocDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
    if (srcdocDesc && srcdocDesc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
            configurable: true,
            enumerable: srcdocDesc.enumerable,
            get: srcdocDesc.get,
            set(value) {
                if (!isHookGroupEnabled('hook.dom.htmlAssignments')) {
                    return srcdocDesc.set.call(this, value);
                }
                maybeReportTaintedValue(value, {
                    type: 'iframe-srcdoc',
                    sink: 'iframe.srcdoc',
                    sinkId: 'nav.iframe.srcdoc'
                }, { value, element: this });
                return srcdocDesc.set.call(this, value);
            }
        });
    }
})();

// Timer-based execution sinks
; (function () {
    function wrapTimer(fnName, sinkId) {
        if (typeof window[fnName] !== 'function') return;
        const orig = window[fnName];
        window[fnName] = function (handler, ...rest) {
            if (!isHookGroupEnabled('hook.code.exec')) {
                return orig.call(this, handler, ...rest);
            }
            if (typeof handler === 'string' && handler) {
                maybeReportTaintedValue(handler, {
                    type: 'timer-execution',
                    sink: fnName,
                    sinkId
                }, { value: handler, method: fnName });
            }
            return orig.call(this, handler, ...rest);
        };
    }
    wrapTimer('setTimeout', 'code.setTimeout');
    wrapTimer('setInterval', 'code.setInterval');
})();

try {
    window.postMessage({ channel: 'ptk_iast_agent_ready' }, '*');
} catch (_) { }
})();
