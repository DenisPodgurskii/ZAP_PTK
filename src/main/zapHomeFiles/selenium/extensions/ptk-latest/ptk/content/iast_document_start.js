/* Author: Denis Podgurskii */
;((IAST_OBSERVER_ENTRY) => {
// Only the generated native MAIN/document-start entry supplies early authority.
// This is lexical construction, never inferred from page state or a public flag.
const IAST_OBSERVER_CAPABILITIES = captureIastObserverCapabilities();
const PTK_IAST_PAGE_TO_CONTENT_EVENT = 'ptk:iast:page-to-content:v1';
const PTK_IAST_CONTENT_TO_PAGE_EVENT = 'ptk:iast:content-to-page:v1';

function parseIastBridgeEventDetail(detail) {
    if (!detail) return null;
    if (typeof detail === 'object') return detail;
    if (typeof detail !== 'string') return null;
    try {
        const parsed = JSON.parse(detail);
        return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (_) {
        return null;
    }
}

function emitIastPageBridgeMessage(payload) {
    if (!payload || typeof payload !== 'object') return false;
    try {
        const detail = JSON.stringify(payload);
        const event = new CustomEvent(PTK_IAST_PAGE_TO_CONTENT_EVENT, { detail });
        window.dispatchEvent(event);
        return true;
    } catch (_) {
        return false;
    }
}

if (globalThis.__PTK_IAST_AGENT_LOADED__ && globalThis.__PTK_IAST_INSTALLATION_STATE__ === 'ready') {
    try {
        globalThis.__PTK_IAST_REBIND_BRIDGE__?.();
        emitIastPageBridgeMessage({ channel: 'ptk_iast_agent_ready', installationState: 'ready' });
    } catch (_) { }
    return;
}

function isIastAgentAuthorizedForPageHooks() {
    try {
        return globalThis.__PTK_IAST_AGENT_AUTHORIZED__ === true
            || globalThis.__PTK_IAST_PROVISIONAL_HOOKS__ === true;
    } catch (_) {
        return false;
    }
}

if (!isIastAgentAuthorizedForPageHooks()) {
    try {
        emitIastPageBridgeMessage({
            channel: 'ptk_iast_agent_ignored',
            reason: 'missing_extension_authorization'
        });
    } catch (_) { }
    return;
}

if (globalThis.__PTK_IAST_INSTALLATION_STATE__ === 'installing'
    || globalThis.__PTK_IAST_INSTALLATION_STATE__ === 'failed') {
    globalThis.__PTK_IAST_INSTALLATION_STATE__ = 'failed';
    emitIastPageBridgeMessage({ channel: 'ptk_iast_agent_failed', error: 'incomplete_agent_installation' });
    return;
}
globalThis.__PTK_IAST_INSTALLATION_STATE__ = 'installing';

const FREE_SAFE_HOOK_GROUPS = Object.freeze([
    'hook.angularjs',
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
    'hook.sanitizers',
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
    if (sinkId.startsWith('angularjs.')) {
        groups.add('hook.angularjs');
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
    if (sinkId === 'form.submit.call' || sinkId === 'form.requestSubmit.call') {
        groups.add('hook.dom.formAttributes');
    }
    if (sinkId.startsWith('postmessage.') || sinkId.startsWith('channel.')) {
        groups.add('hook.postMessage');
    }
    if (sinkId.startsWith('log.console.')) {
        groups.add('hook.console.leaks');
    }
    if (sinkId.startsWith('trustedTypes.') || sinkId.startsWith('sanitizer.')) {
        groups.add('hook.sanitizers');
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
const IAST_CHANNEL_SOURCE_KINDS = new Set(['broadcastMessage', 'messagePort', 'workerMessage']);
const IAST_OBJECT_URL_SOURCE_KINDS = new Set(['objectUrl']);
const IAST_PERSISTENT_STORAGE_SOURCE_KINDS = new Set(['indexedDb', 'cacheStorage']);
const IAST_ANGULAR_EXECUTION_SERVICES = new Set(['$parse', '$compile', '$interpolate']);
const IAST_EXECUTION_CONTEXT_STACK = [];

function withIastExecutionContext(context, callback) {
    if (typeof callback !== 'function') return undefined;
    const normalized = context && typeof context === 'object'
        ? Object.assign({}, context)
        : null;
    if (!normalized) return callback();
    IAST_EXECUTION_CONTEXT_STACK.push(normalized);
    try {
        return callback();
    } finally {
        IAST_EXECUTION_CONTEXT_STACK.pop();
    }
}

function getActiveIastExecutionContext() {
    if (!IAST_EXECUTION_CONTEXT_STACK.length) return null;
    const context = IAST_EXECUTION_CONTEXT_STACK[IAST_EXECUTION_CONTEXT_STACK.length - 1];
    return context && typeof context === 'object' ? Object.assign({}, context) : null;
}

function getActiveAngularExecutionContext() {
    const context = getActiveIastExecutionContext();
    if (context?.framework !== 'AngularJS') return null;
    if (!IAST_ANGULAR_EXECUTION_SERVICES.has(context.angularService)) return null;
    return context;
}

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

function selectIastRuleVariant({ runtimePlan = null, sinkId = null, sourceKinds = [], isCrossOrigin = false, context = {} } = {}) {
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
        if (hasAnyIastSourceKind(sourceKinds, IAST_CHANNEL_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['channel_']);
        }
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
        if (sinkId === 'code.function.constructor' && context?.framework === 'AngularJS'
            && IAST_ANGULAR_EXECUTION_SERVICES.has(context?.angularService)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['angularjs_expression_']);
        }
        if (hasAnyIastSourceKind(sourceKinds, IAST_CHANNEL_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['channel_']);
        }
        if (hasAnyIastSourceKind(sourceKinds, IAST_PERSISTENT_STORAGE_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['persistent_']);
        }
        if (hasAnyIastSourceKind(sourceKinds, IAST_STORAGE_EXEC_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['storage_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('storage_') && !entry.ruleId.includes('angularjs_expression_')) || sinkPlan.variants[0];
    }

    if (sinkId === 'http.fetch.url' || sinkId === 'http.xhr.open') {
        if (hasAnyIastSourceKind(sourceKinds, IAST_PERSISTENT_STORAGE_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['persistent_']);
        }
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
        if (sinkId === 'nav.window.open' && hasAnyIastSourceKind(sourceKinds, IAST_OBJECT_URL_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['objecturl_']);
        }
        if (hasAnyIastSourceKind(sourceKinds, IAST_CHANNEL_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['channel_']);
        }
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
        if (hasAnyIastSourceKind(sourceKinds, IAST_CHANNEL_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['channel_']);
        }
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

    if (['script.element.src', 'nav.iframe.src', 'worker.webworker.constructor'].includes(sinkId)) {
        if (hasAnyIastSourceKind(sourceKinds, IAST_OBJECT_URL_SOURCE_KINDS)) {
            return getIastRuleVariantByPrefix(sinkPlan, ['objecturl_']);
        }
        return sinkPlan.variants.find((entry) => !entry.ruleId.includes('objecturl_')) || sinkPlan.variants[0];
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

            if (entry.sources.includes('postMessage') || entry.sources.some((sourceId) => IAST_CHANNEL_SOURCE_KINDS.has(sourceId))) {
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
let IAST_MODULES_SIGNATURE = null;
let IAST_RUNTIME_PLAN = null;
const IAST_RULE_INDEX = {
    bySinkId: Object.create(null),
    byRuleId: Object.create(null),
};
let __IAST_LAST_MODULES_REQUEST__ = 0;
const IAST_PENDING_FINDING_REPORTS = [];
const IAST_PENDING_FINDING_REPORTS_MAX = 100;
const IAST_DEFERRED_WRITE_REPORTS = [];
const IAST_DEFERRED_WRITE_REPORTS_MAX = 100;
const IAST_DEFERRED_WRITE_TIMER = IAST_OBSERVER_ENTRY === 'native-main-document-start'
    && typeof globalThis.setTimeout === 'function' ? globalThis.setTimeout : null;
let IAST_DEFERRED_WRITE_TIMER_ARMED = false;
let IAST_DEFERRED_WRITE_GENERATION = 0;
let IAST_FLUSHED_PENDING_FINDING_REPORTS_COUNT = 0;
const IAST_HOOK_FAILURE_THRESHOLD = 3;
const IAST_RUNTIME_DEGRADED_GROUP_THRESHOLD = 3;
const IAST_RUNTIME_DEGRADED_DISABLED_GROUPS = new Set([
    'hook.dom.documentWrite',
    'hook.dom.htmlAssignments',
    'hook.dom.htmlParsers',
    'hook.dom.mutations',
    'hook.net.exfil',
    'hook.runtime.integrity.fetchInit',
    'hook.runtime.integrity.prototypeWrites'
]);
function createIastHookRuntimeState() {
    return {
        enabled: new Set(),
        installed: new Set(),
        degraded: new Set(),
        failures: new Map(),
        globallyDisabled: new Set(),
        runtimeState: 'normal'
    };
}
const IAST_HOOK_GROUPS = createIastHookRuntimeState();
const IAST_PROVISIONAL_PRE_MODULE_HOOK_GROUPS = new Set(FREE_SAFE_HOOK_GROUPS);
const IAST_TRUSTED_HTML_RESTRICTION = {
    checked: false,
    enforced: false,
    message: null
};

function enableProvisionalPreModuleHooks() {
    try {
        if (globalThis.__PTK_IAST_PROVISIONAL_HOOKS__ !== true) return;
    } catch (_) {
        return;
    }
    if (IAST_MODULES || IAST_RUNTIME_PLAN) return;
    IAST_PROVISIONAL_PRE_MODULE_HOOK_GROUPS.forEach((groupId) => {
        IAST_HOOK_GROUPS.enabled.add(groupId);
    });
}

enableProvisionalPreModuleHooks();

function normalizeIastHookErrorMessage(error) {
    try {
        if (typeof error?.message === 'string' && error.message) {
            return error.message;
        }
    } catch (_) { }
    try {
        const serialized = String(error ?? '');
        return serialized || 'unknown hook error';
    } catch (_) {
        return 'unknown hook error';
    }
}
function updateIastHookRuntimeState() {
    const degradedCount = IAST_HOOK_GROUPS.degraded.size;
    if (degradedCount >= IAST_RUNTIME_DEGRADED_GROUP_THRESHOLD) {
        IAST_HOOK_GROUPS.globallyDisabled = new Set(
            Array.from(IAST_HOOK_GROUPS.enabled || []).filter((groupId) => (
                IAST_RUNTIME_DEGRADED_DISABLED_GROUPS.has(groupId)
                && !IAST_HOOK_GROUPS.degraded.has(groupId)
            ))
        );
    } else {
        IAST_HOOK_GROUPS.globallyDisabled = new Set();
    }
    IAST_HOOK_GROUPS.runtimeState = IAST_HOOK_GROUPS.globallyDisabled.size
        ? 'disabled_due_to_runtime_errors'
        : degradedCount
            ? 'degraded'
            : 'normal';
    emitIastRuntimeHealthUpdate();
}
function recordIastHookFailure(groupId, hookName, error) {
    if (!groupId) return;
    try {
        const now = Date.now();
        const existing = IAST_HOOK_GROUPS.failures.get(groupId) || {
            count: 0,
            firstAt: now,
            lastAt: null,
            lastHook: null,
            lastMessage: null
        };
        existing.count += 1;
        existing.lastAt = now;
        existing.lastHook = hookName || null;
        existing.lastMessage = normalizeIastHookErrorMessage(error);
        IAST_HOOK_GROUPS.failures.set(groupId, existing);
        if (existing.count >= IAST_HOOK_FAILURE_THRESHOLD) {
            IAST_HOOK_GROUPS.degraded.add(groupId);
        }
        updateIastHookRuntimeState();
        __PTK_IAST_DBG__('iast hook failure', {
            groupId,
            hookName: hookName || null,
            count: existing.count,
            runtimeState: IAST_HOOK_GROUPS.runtimeState,
            degraded: IAST_HOOK_GROUPS.degraded.has(groupId),
            message: existing.lastMessage
        });
    } catch (_) {
        // fail-open: never let hook-failure accounting break the app
    }
}
function buildIastRuntimeHealthPayload() {
    const hookGroupFailures = {};
    Array.from(IAST_HOOK_GROUPS.failures || []).forEach(([groupId, entry]) => {
        hookGroupFailures[groupId] = {
            count: Number(entry?.count || 0),
            firstAt: entry?.firstAt || null,
            lastAt: entry?.lastAt || null,
            lastHook: entry?.lastHook || null,
            lastMessage: entry?.lastMessage || null
        };
    });
    return {
        state: IAST_HOOK_GROUPS.runtimeState || 'normal',
        enabledHookGroups: Array.from(IAST_HOOK_GROUPS.enabled || []).sort(),
        degradedHookGroups: Array.from(IAST_HOOK_GROUPS.degraded || []).sort(),
        globallyDisabledHookGroups: Array.from(IAST_HOOK_GROUPS.globallyDisabled || []).sort(),
        hookGroupFailures,
        modulesLoaded: Boolean(IAST_MODULES),
        modulesSignature: IAST_MODULES_SIGNATURE || null,
        pendingFindingReports: IAST_PENDING_FINDING_REPORTS.length + IAST_DEFERRED_WRITE_REPORTS.length,
        flushedPendingFindingReports: IAST_FLUSHED_PENDING_FINDING_REPORTS_COUNT,
        url: (() => { try { return window.location.href || null; } catch (_) { return null; } })(),
        agentBootUrl: IAST_AGENT_BOOT_URL,
        documentReadyState: (() => { try { return document.readyState || null; } catch (_) { return null; } })(),
        agentBootReadyState: IAST_AGENT_BOOT_READY_STATE,
        agentBootAt: IAST_AGENT_BOOT_AT,
        navigationStart: IAST_AGENT_BOOT_NAVIGATION_START,
        agentBootDelayMs: IAST_AGENT_BOOT_NAVIGATION_START != null
            ? Math.max(0, Math.round(IAST_AGENT_BOOT_AT - IAST_AGENT_BOOT_NAVIGATION_START))
            : null,
        agentBootAfterLoad: IAST_AGENT_BOOT_READY_STATE === 'complete',
        updatedAt: Date.now()
    };
}
function emitIastRuntimeHealthUpdate({ force = false } = {}) {
    try {
        const payload = buildIastRuntimeHealthPayload();
        const signature = JSON.stringify({
            state: payload.state,
            enabledHookGroups: payload.enabledHookGroups,
            degradedHookGroups: payload.degradedHookGroups,
            globallyDisabledHookGroups: payload.globallyDisabledHookGroups,
            hookGroupFailures: payload.hookGroupFailures,
            modulesLoaded: payload.modulesLoaded,
            modulesSignature: payload.modulesSignature,
            pendingFindingReports: payload.pendingFindingReports,
            flushedPendingFindingReports: payload.flushedPendingFindingReports
        });
        if (!force && signature === IAST_LAST_RUNTIME_HEALTH_KEY) {
            return;
        }
        IAST_LAST_RUNTIME_HEALTH_KEY = signature;
        postDirectIastMessage({
            channel: 'ptk_iast_runtime_health',
            health: sanitizeIastPayloadObject(payload)
        });
    } catch (_) {
        // fail-open: runtime health reporting must never break the page
    }
}
function runIastHookGuard(groupId, hookName, fn, fallbackValue, options = {}) {
    const respectEnabled = options?.respectEnabled !== false;
    if (respectEnabled && groupId && !isHookGroupEnabled(groupId)) {
        return fallbackValue;
    }
    try {
        return fn();
    } catch (error) {
        if (groupId) {
            recordIastHookFailure(groupId, hookName, error);
        }
        return fallbackValue;
    }
}
window.__PTK_IAST_DEBUG_STATE__ = function () {
    const hookGroupFailures = {};
    Array.from(IAST_HOOK_GROUPS.failures || []).forEach(([groupId, entry]) => {
        hookGroupFailures[groupId] = Object.assign({}, entry);
    });
    return {
        activeModuleIds: Array.isArray(IAST_RUNTIME_PLAN?.activeModuleIds) ? IAST_RUNTIME_PLAN.activeModuleIds.slice() : [],
        activeRuleIds: Array.isArray(IAST_RUNTIME_PLAN?.activeRuleIds) ? IAST_RUNTIME_PLAN.activeRuleIds.slice() : [],
        activeHookGroups: Array.isArray(IAST_RUNTIME_PLAN?.activeHookGroups) ? IAST_RUNTIME_PLAN.activeHookGroups.slice() : [],
        enabledHookGroups: Array.from(IAST_HOOK_GROUPS.enabled || []),
        installedHookGroups: Array.from(IAST_HOOK_GROUPS.installed || []),
        degradedHookGroups: Array.from(IAST_HOOK_GROUPS.degraded || []),
        globallyDisabledHookGroups: Array.from(IAST_HOOK_GROUPS.globallyDisabled || []),
        runtimeHealthState: IAST_HOOK_GROUPS.runtimeState || 'normal',
        hookGroupFailures,
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
// Shadow-only evidence accounting. No source values or finding fields are retained.
const IAST_SHADOW_EVIDENCE_COUNTS = {
    total: 0,
    object_identity: 0,
    instrumented_propagation: 0,
    primitive_fingerprint_equality: 0,
    complete_value_equality: 0,
    canonical_url_equality: 0,
    lexical_word_boundary: 0,
    substring: 0,
    inconsistent_published_flow: 0,
    truncated_candidates: 0
};
let IAST_LAST_RUNTIME_HEALTH_KEY = '';
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
function readIastNavigationStartMs() {
    try {
        if (typeof performance !== 'undefined') {
            if (Number.isFinite(Number(performance.timeOrigin))) {
                return Number(performance.timeOrigin);
            }
            if (performance.timing && Number.isFinite(Number(performance.timing.navigationStart))) {
                return Number(performance.timing.navigationStart);
            }
        }
    } catch (_) { }
    return null;
}
const IAST_AGENT_BOOT_AT = Date.now();
const IAST_AGENT_BOOT_URL = (() => {
    try { return window.location.href || null; } catch (_) { return null; }
})();
const IAST_AGENT_BOOT_READY_STATE = (() => {
    try { return document.readyState || null; } catch (_) { return null; }
})();
const IAST_AGENT_BOOT_NAVIGATION_START = readIastNavigationStartMs();
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
    'broadcastMessage',
    'messagePort',
    'workerMessage',
    'objectUrl',
    'indexedDb',
    'cacheStorage',
    'apiResponseField',
    'graphqlResponseField',
    'form',
    'bodyParam',
    'jsonBodyField',
    'formDataField'
]);
const IAST_RUNTIME_SIGNAL_MAX_VALUE_LENGTH = 4096;
const IAST_RUNTIME_SIGNAL_SENT = new Map();
const IAST_OBJECT_URL_TAINT_KEYS = new Map();
const IAST_BLOB_TAINT = typeof WeakMap === 'function' ? new WeakMap() : null;
const IAST_CACHE_INSTANCES = typeof WeakMap === 'function' ? new WeakMap() : null;
const IAST_CACHE_RESPONSE_META = typeof WeakMap === 'function' ? new WeakMap() : null;
const IAST_FETCH_RESPONSE_META = typeof WeakMap === 'function' ? new WeakMap() : null;
const IAST_MESSAGE_HANDLER_WRAPS = typeof WeakMap === 'function' ? new WeakMap() : null;
const IAST_MESSAGE_TARGET_LABELS = typeof WeakMap === 'function' ? new WeakMap() : null;
let IAST_MESSAGE_TARGET_SEQ = 0;
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
    STORAGE_VALUE_EQUALITY_OBSERVED: 'storage_value_equality_observed',
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
const IAST_STORAGE_OBSERVATION_SINKS = new Set([
    'code.eval', 'code.function.constructor', 'code.function.apply',
    'dom.innerHTML', 'dom.outerHTML', 'dom.insertAdjacentHTML', 'document.write'
]);
const IAST_OBSERVATION_LIMITS = Object.freeze({ keys: 64, bytes: 65536, valueChars: 4096, relationships: 8 });
const IAST_OBSERVATION_DOCUMENT_ID = (() => {
    try { return globalThis.crypto.randomUUID(); } catch (_) {
        return `${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 14)}`;
    }
})();
const IAST_OBSERVATION_STATE = { operationHighWater: 0, emittedRelationships: 0, lossCount: 0, reasons: new Set(), revision: 0, terminal: false };
const IAST_BRIDGE_UNACKED = new Map();
const IAST_BRIDGE_UNACKED_LIMIT = 1024;
let IAST_OBSERVATION_STOPPED = false;
let IAST_OBSERVATION_SETTLING = false;
const IAST_OBSERVATION_NODE_IDS = typeof WeakMap === 'function' ? new WeakMap() : null;
const IAST_OBSERVATION_ERROR = typeof Error === 'function' ? Error : null;
let IAST_OBSERVATION_NEXT_NODE_ID = 1;
const IAST_STORAGE_OBSERVATION_CAPABILITIES = captureIastStorageObservationCapabilities();

function emitIastObservationState({ terminal = false } = {}) {
    if (terminal) IAST_OBSERVATION_STATE.terminal = true;
    IAST_OBSERVATION_STATE.revision += 1;
    try {
        emitIastPageBridgeMessage({ channel: 'ptk_iast_observation_state',
            installationState: globalThis.__PTK_IAST_INSTALLATION_STATE__ || 'installing',
            documentId: IAST_OBSERVATION_DOCUMENT_ID,
            operationHighWater: IAST_OBSERVATION_STATE.operationHighWater,
            emittedRelationships: IAST_OBSERVATION_STATE.emittedRelationships,
            // At terminal handoff the replay cache is not producer work: the
            // background verifies receivedRelationships against this document's
            // emittedRelationships. A lost page-side ACK must not strand an
            // otherwise accepted finding after the page is gone.
            pendingObservations: IAST_PENDING_FINDING_REPORTS.length + IAST_DEFERRED_WRITE_REPORTS.length
                + (IAST_OBSERVATION_STATE.terminal ? 0 : IAST_BRIDGE_UNACKED.size),
            lossCount: IAST_OBSERVATION_STATE.lossCount,
            reasons: Array.from(IAST_OBSERVATION_STATE.reasons).slice(0, 16),
            revision: IAST_OBSERVATION_STATE.revision,
            terminal: IAST_OBSERVATION_STATE.terminal });
    } catch (_) { }
}

function recordIastObservationGap(reason, loss = false) {
    if (IAST_OBSERVATION_STOPPED && !IAST_OBSERVATION_SETTLING) return;
    IAST_OBSERVATION_STATE.terminal = false;
    if (typeof reason === 'string' && reason.length <= 64 && IAST_OBSERVATION_STATE.reasons.size < 16) {
        IAST_OBSERVATION_STATE.reasons.add(reason);
    }
    if (loss) IAST_OBSERVATION_STATE.lossCount = Math.min(1000000, IAST_OBSERVATION_STATE.lossCount + 1);
    emitIastObservationState();
}

function captureIastStorageObservationCapabilities() {
    const result = { areas: [], reason: null, invoke: IAST_OBSERVER_CAPABILITIES.invoke };
    // Only a document-start acquisition may retain unpatched Storage capabilities.
    // A late agent must not invoke arbitrary page replacements while enumerating.
    if (IAST_OBSERVER_ENTRY !== 'native-main-document-start') {
        result.reason = 'storage_capability_late';
        return result;
    }
    try {
        if (typeof Storage === 'undefined' || !Storage.prototype) {
            result.reason = 'storage_capability_unavailable';
            return result;
        }
        const proto = Storage.prototype;
        const key = Object.getOwnPropertyDescriptor(proto, 'key')?.value;
        const getItem = Object.getOwnPropertyDescriptor(proto, 'getItem')?.value;
        const length = Object.getOwnPropertyDescriptor(proto, 'length')?.get;
        if (typeof key !== 'function' || typeof getItem !== 'function' || typeof length !== 'function'
            || getItem.__ptk_iast_wrapped__) {
            result.reason = 'storage_capability_unavailable';
            return result;
        }
        for (const name of ['localStorage', 'sessionStorage']) {
            let owner = window;
            let descriptor = null;
            for (let depth = 0; owner && depth < 5; depth += 1) {
                descriptor = Object.getOwnPropertyDescriptor(owner, name);
                if (descriptor) break;
                owner = Object.getPrototypeOf(owner);
            }
            // Data/accessor replacements are not a native window storage getter.
            // Early native window getters are invoked once and their receiver is retained.
            if (!descriptor || typeof descriptor.get !== 'function' || descriptor.set) {
                result.areas.push({ name, unavailable: true });
                continue;
            }
            try {
                const store = IAST_OBSERVER_CAPABILITIES.invoke(descriptor.get, window, []);
                IAST_OBSERVER_CAPABILITIES.invoke(length, store, []);
                result.areas.push({ name, store, key, getItem, length });
            } catch (_) { result.areas.push({ name, unavailable: true }); }
        }
    } catch (_) { result.reason = 'storage_capability_unavailable'; }
    return result;
}

function parseIastApplicationSite(trace, operationId, sinkId, context = {}) {
    if (!String(sinkId || '').startsWith('code.')) {
        if (/^(http\.|realtime\.)/.test(String(sinkId || '')) && sinkId !== 'http.image.src') {
            return { kind: 'dom', operation: sinkId };
        }
        const element = context.element;
        let observationId = null;
        if (element && typeof element === 'object' && IAST_OBSERVATION_NODE_IDS) {
            observationId = IAST_OBSERVATION_NODE_IDS.get(element);
            if (!observationId) {
                observationId = `n_${IAST_OBSERVATION_DOCUMENT_ID}_${IAST_OBSERVATION_NEXT_NODE_ID++}`;
                IAST_OBSERVATION_NODE_IDS.set(element, observationId);
            }
        }
        return { kind: 'dom', domPath: context.domPath || (element ? getDomPath(element) : null),
            attribute: context.attribute || null, operation: sinkId || null, observationId };
    }
    if (typeof trace === 'string') {
        const frames = trace.split('\n').slice(1, 17);
        for (const frame of frames) {
            if (/chrome-extension:\/\/|moz-extension:\/\/|\/ptk\/content\/iast\.js/.test(frame)) continue;
            const match = frame.match(/(?:\(|@|\s)((?:https?):\/\/[^\s)]+):(\d+):(\d+)\)?\s*$/);
            if (match && match[1].length <= 2048 && !/\beval at\b|(?:^|\s)eval code(?:\s|$)|blob:/.test(frame)) {
                return { kind: 'code', scriptUrl: match[1], line: Number(match[2]), column: Number(match[3]), operation: sinkId };
            }
        }
    }
    return { kind: 'unresolved', observationId: operationId, operation: sinkId || null };
}

function captureIastOperation(sinkId, context = {}) {
    if (IAST_OBSERVATION_STOPPED && !IAST_OBSERVATION_SETTLING) return null;
    IAST_OBSERVATION_STATE.terminal = false;
    const operationId = `o_${IAST_OBSERVATION_DOCUMENT_ID}_${++IAST_OBSERVATION_STATE.operationHighWater}`.slice(0, 128);
    let trace = typeof context.observationTrace === 'string' ? context.observationTrace : null;
    try {
        const formatter = IAST_OBSERVATION_ERROR && Object.getOwnPropertyDescriptor(IAST_OBSERVATION_ERROR, 'prepareStackTrace');
        if (!trace && IAST_OBSERVATION_ERROR && !formatter) {
            const stack = new IAST_OBSERVATION_ERROR('IAST observed operation').stack;
            if (typeof stack === 'string') trace = stack;
        }
    } catch (_) { }
    const operation = { operationId, site: parseIastApplicationSite(trace, operationId, sinkId, context),
        trace, completeness: { status: 'complete', reasons: [] } };
    return operation;
}

function collectIastOperationStorageCandidates(value, sinkId, operation) {
    const sources = [];
    if (!IAST_STORAGE_OBSERVATION_SINKS.has(sinkId) || typeof value !== 'string' || __IAST_DISABLE_HOOKS__) return sources;
    const limited = reason => {
        operation.completeness.status = 'limited';
        if (!operation.completeness.reasons.includes(reason)) operation.completeness.reasons.push(reason);
        recordIastObservationGap(reason);
    };
    if (!value) return sources;
    const oversizedSinkValue = value.length > IAST_OBSERVATION_LIMITS.valueChars;
    const rules = IAST_MODULES ? getIastRulesBySinkId(sinkId) : null;
    // An omitted/empty source list has always meant unrestricted eligibility.
    // Match that contract for custom rules instead of silently skipping stores.
    const allowed = rules && !rules.some(rule => !Array.isArray(rule.sources) || !rule.sources.length)
        ? new Set(rules.flatMap(rule => rule.sources)) : null;
    const capabilities = IAST_STORAGE_OBSERVATION_CAPABILITIES;
    if (capabilities.reason) { limited(capabilities.reason); return sources; }
    let reads = 0;
    let bytes = 0;
    for (const area of capabilities.areas) {
        if (allowed && !allowed.has(area.name)) continue;
        if (area.unavailable) { limited('storage_area_unavailable'); continue; }
        try {
            const count = capabilities.invoke(area.length, area.store, []);
            for (let index = 0; index < count; index += 1) {
                if (reads >= IAST_OBSERVATION_LIMITS.keys) { limited('storage_key_limit'); break; }
                reads += 1;
                const key = capabilities.invoke(area.key, area.store, [index]);
                if (typeof key !== 'string' || isInternalStorageKey(key)) continue;
                if (`${area.name}:${key}`.length > 512) { limited('storage_key_size_limit'); continue; }
                const stored = capabilities.invoke(area.getItem, area.store, [key]);
                if (typeof stored !== 'string') continue;
                const examined = (key.length + stored.length) * 2;
                if (bytes + examined > IAST_OBSERVATION_LIMITS.bytes) { limited('storage_byte_limit'); break; }
                bytes += examined;
                if (stored.length > IAST_OBSERVATION_LIMITS.valueChars) {
                    // The fresh-storage inference only admits complete value equality.
                    // A long unrelated Function/HTML argument cannot be a skipped
                    // storage match merely because it exceeds the observation bound.
                    if (!oversizedSinkValue || stored.length === value.length) limited('storage_value_limit');
                    continue;
                }
                if (oversizedSinkValue) continue;
                if (stored !== value) continue;
                sources.push({ __normalizedSource: true, __ptkOperationLocalSource: true,
                    key: `${area.name}:${key}`, source: `${area.name}:${key}`, sourceId: null, taintId: null,
                    raw: value, value, label: `${area.name}["${key}"]`, detail: key,
                    location: window.location.href, sourceKind: area.name, type: area.name, taintKind: 'unknown',
                    acquisition: 'sink_storage_snapshot', matchType: 'complete_value_equality' });
            }
            if (capabilities.invoke(area.length, area.store, []) !== count) limited('storage_changed_during_snapshot');
        } catch (_) { limited('storage_area_unavailable'); }
    }
    return sources;
}

function matchesIastSinkTaint(value, sinkId, context = {}) {
    // New acquisition never coerces target objects/TrustedHTML. Existing hook
    // branches retain their old handling and native argument/coercion order.
    if (typeof value !== 'string' || IAST_OBSERVATION_STOPPED) return null;
    try {
        const match = matchesTaint(value);
        if (!IAST_STORAGE_OBSERVATION_SINKS.has(sinkId)) return match;
        const operation = captureIastOperation(sinkId, context);
        const inferred = collectIastOperationStorageCandidates(value, sinkId, operation);
        const observed = match ? normalizeTaintedSources(match.allSources, match.raw) : [];
        // A stale same-key lexical match is not an observation of this stored
        // value. Preserve its weaker relationship separately from the fresh
        // equality; only an observed complete value replaces local inference.
        const completeKeys = new Set(observed.filter(source => source.raw === value).map(source => source.key));
        const allSources = observed.concat(inferred.filter(source => !completeKeys.has(source.key)));
        emitIastObservationState();
        if (!allSources.length) return null;
        const primary = observed[0] || allSources[0];
        return { source: primary.key, raw: primary.raw, allSources, observationOperation: operation };
    } catch (_) {
        // HTML entry points call this before their existing analysis guard.
        // Observer failure must never change the target operation's result.
        recordIastObservationGap('sink_observation_failed', true);
        return null;
    }
}

function buildIastRelationshipObservation(source, value, taintEntry, operation, sinkId) {
    const inferred = source?.acquisition === 'sink_storage_snapshot';
    const relatedTaint = source?.sourceId && source.sourceId === taintEntry?.taint?.sourceId ? taintEntry : null;
    const grade = classifyIastShadowSource(value, source, inferred ? null : relatedTaint);
    const propagation = relatedTaint?.taint?.shadowEvidence?.mechanism === 'instrumented_propagation'
        ? { operation: relatedTaint.taint.lineage?.slice(-1)[0]?.op || 'propagation', inheritedGrade: grade.inheritedGrade || grade.effectiveGrade }
        : null;
    return {
        schemaVersion: 2, identityVersion: 2, kind: 'source_relationship',
        operationId: operation.operationId, gradeAuthority: 'page_observed_untrusted',
        acquisition: source?.acquisition || 'existing_other',
        evidenceGrade: inferred ? 'complete_value_equality' : grade.effectiveGrade,
        inheritedGrade: inferred ? null : (grade.inheritedGrade || null),
        valueRelation: grade.valueRelation || 'unavailable', propagation,
        attackerControl: 'unknown', controlReason: inferred ? 'Application storage read not observed; equal stored value only.' : 'Source category and primitive equality do not establish attacker control.',
        site: Object.assign({}, operation.site),
        sourceBinding: { sourceId: inferred ? null : (source?.sourceId || null), key: source.key, kind: source.sourceKind || source.kind || 'unknown' },
        completeness: { status: operation.completeness.status, reasons: operation.completeness.reasons.slice(0, 16) }
    };
}

function buildIastSourceFlow(source, sinkMeta) {
    if (source?.acquisition !== 'sink_storage_snapshot') {
        const entry = window.__IAST_TAINT_GRAPH__?.[source.key];
        if (entry?.node?.value === source.raw) {
            return buildTaintFlow({ source: source.key, raw: source.raw, allSources: [source] }, sinkMeta);
        }
    }
    return [{ stage: 'source', key: source.key, label: source.label || source.key,
        op: source.acquisition === 'sink_storage_snapshot' ? 'storage_value_equality_observed' : (source.acquisition || 'source'),
        location: source.location || sinkMeta.location, value: source.raw },
    { stage: 'sink', key: sinkMeta.sinkId, label: sinkMeta.sink || sinkMeta.sinkId, op: 'sink',
        location: sinkMeta.location, domPath: sinkMeta.domPath || null, value: sinkMeta.value }];
}

function buildIastSourceBindingKey(source) {
    return JSON.stringify([source?.key || null, source?.sourceId || null, source?.acquisition || 'existing_other']);
}

function buildIastRelationshipDedupKey(ruleEntry, source, sinkId, location, context, severity, observation) {
    return JSON.stringify([2, location, ruleEntry.moduleId, ruleEntry.ruleId, source.key,
        source.sourceKind || source.kind || null, sinkId, context.transportCarrierKey || null,
        observation.site, observation.acquisition, observation.valueRelation, observation.evidenceGrade,
        observation.inheritedGrade, observation.attackerControl, context.primaryClass || 'taint_flow',
        severity || ruleEntry.ruleMeta?.severity || ruleEntry.moduleMeta?.severity || null,
        context.detection?.confidence ?? context.match?.confidence ?? null,
        context.confidencePenalty || 0, context.detection?.reason || null]);
}
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
    IAST_MODULES_SIGNATURE = null;
    IAST_RUNTIME_PLAN = null;
    IAST_RULE_INDEX.bySinkId = Object.create(null);
    IAST_RULE_INDEX.byRuleId = Object.create(null);
}

function buildIastModulesSignature(modulesJson, scanStrategy = null) {
    const normalizedStrategy = normalizeScanStrategy(scanStrategy || IAST_SCAN_STRATEGY);
    if (!modulesJson || !Array.isArray(modulesJson.modules)) {
        return `strategy:${normalizedStrategy}|modules:0`;
    }

    const policyId = String(modulesJson?.policy?.id || '').trim();
    const policyName = String(modulesJson?.policy?.name || '').trim();
    const version = String(modulesJson?.version || '').trim();
    const moduleSignature = modulesJson.modules.map((moduleDef, moduleIndex) => {
        const moduleId = String(moduleDef?.id || `module#${moduleIndex}`).trim();
        const ruleIds = Array.isArray(moduleDef?.rules)
            ? moduleDef.rules.map((ruleDef, ruleIndex) => String(ruleDef?.id || `rule#${ruleIndex}`).trim()).join(',')
            : '';
        return `${moduleId}:${ruleIds}`;
    }).join('|');

    return `strategy:${normalizedStrategy}|version:${version}|policy:${policyId}|name:${policyName}|modules:${moduleSignature}`;
}

function initIastRuleIndex(modulesJson, options = {}) {
    if (!modulesJson || !Array.isArray(modulesJson.modules)) {
        __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: invalid modulesJson', modulesJson);
        return false;
    }

    const nextSignature = String(options?.signature || '').trim()
        || buildIastModulesSignature(modulesJson, options?.scanStrategy || null);
    if (nextSignature && IAST_MODULES_SIGNATURE === nextSignature) {
        flushPendingIastFindingReports();
        emitIastRuntimeHealthUpdate({ force: true });
        return false;
    }

    resetIastRuleIndex();

    IAST_MODULES = modulesJson;
    IAST_MODULES_SIGNATURE = nextSignature || null;
    IAST_RUNTIME_PLAN = buildIastRuntimePlan(modulesJson);
    Object.keys(IAST_RUNTIME_PLAN.bySinkId).forEach((sinkId) => {
        IAST_RULE_INDEX.bySinkId[sinkId] = IAST_RUNTIME_PLAN.bySinkId[sinkId].variants.slice();
    });
    Object.keys(IAST_RUNTIME_PLAN.byRuleId).forEach((ruleId) => {
        IAST_RULE_INDEX.byRuleId[ruleId] = IAST_RUNTIME_PLAN.byRuleId[ruleId];
    });

    applyIastRuntimePlan(IAST_RUNTIME_PLAN);
    flushPendingIastFindingReports();
    emitIastRuntimeHealthUpdate({ force: true });

    //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: rule index initialised', IAST_RULE_INDEX);
    return true;
}

function queuePendingIastFindingReport(args) {
    if (!args || typeof args !== 'object') return;
    if (IAST_PENDING_FINDING_REPORTS.length >= IAST_PENDING_FINDING_REPORTS_MAX) {
        recordIastObservationGap('pending_observation_limit', true);
        return false;
    }
    IAST_PENDING_FINDING_REPORTS.push(args);
    emitIastObservationState();
    return true;
}

function publishDeferredIastWriteReports(entry) {
    if (entry.document !== document || __IAST_DISABLE_HOOKS__) {
        recordIastObservationGap('deferred_write_owner_unavailable', true);
        return;
    }
    for (const snapshot of entry.snapshots) {
        try {
            if (IAST_MODULES) qualifyIastSinkObservation(snapshot);
            else if (queuePendingIastFindingReport({ sinkObservation: snapshot, document })) {
                requestModulesFromBackground();
            }
        } catch (_) {
            recordIastObservationGap('deferred_write_qualification_failed', true);
        }
    }
}

function flushDeferredIastWriteReports() {
    if (IAST_OBSERVATION_STOPPED && !IAST_OBSERVATION_SETTLING) return;
    while (IAST_DEFERRED_WRITE_REPORTS[0]?.ready) {
        const entry = IAST_DEFERRED_WRITE_REPORTS.shift();
        publishDeferredIastWriteReports(entry);
    }
    emitIastObservationState();
}

function reserveDeferredIastWriteReports(snapshots) {
    if (!snapshots.length) return null;
    const entry = { document, snapshots, ready: false };
    if (IAST_DEFERRED_WRITE_REPORTS.length >= IAST_DEFERRED_WRITE_REPORTS_MAX) {
        // Never trade a finding for queue capacity. This one write qualifies
        // after native forwarding in its current task instead of yielding.
        recordIastObservationGap('deferred_write_capacity_fallback');
        entry.direct = true;
        return entry;
    }
    IAST_DEFERRED_WRITE_REPORTS.push(entry);
    emitIastObservationState();
    return entry;
}

function discardDeferredIastWriteReports(entry) {
    if (!entry || entry.direct) return;
    const index = IAST_DEFERRED_WRITE_REPORTS.indexOf(entry);
    if (index !== -1) IAST_DEFERRED_WRITE_REPORTS.splice(index, 1);
    emitIastObservationState();
}

function completeDeferredIastWriteReports(entry) {
    if (!entry) return;
    entry.ready = true;
    if (entry.direct || !IAST_DEFERRED_WRITE_TIMER) {
        if (entry.direct) publishDeferredIastWriteReports(entry);
        else flushDeferredIastWriteReports();
        return;
    }
    if (IAST_DEFERRED_WRITE_TIMER_ARMED) return;
    IAST_DEFERRED_WRITE_TIMER_ARMED = true;
    const generation = IAST_DEFERRED_WRITE_GENERATION;
    try {
        IAST_OBSERVER_CAPABILITIES.invoke(IAST_DEFERRED_WRITE_TIMER, window, [() => {
            if (generation !== IAST_DEFERRED_WRITE_GENERATION) return;
            IAST_DEFERRED_WRITE_TIMER_ARMED = false;
            flushDeferredIastWriteReports();
        }, 0]);
    } catch (_) {
        IAST_DEFERRED_WRITE_TIMER_ARMED = false;
        recordIastObservationGap('deferred_write_timer_unavailable');
        flushDeferredIastWriteReports();
    }
}

function flushPendingIastFindingReports() {
    if (IAST_OBSERVATION_STOPPED && !IAST_OBSERVATION_SETTLING) return;
    if (!IAST_MODULES || !IAST_PENDING_FINDING_REPORTS.length) return;
    const pending = IAST_PENDING_FINDING_REPORTS.splice(0, IAST_PENDING_FINDING_REPORTS.length);
    IAST_FLUSHED_PENDING_FINDING_REPORTS_COUNT += pending.length;
    pending.forEach((args) => {
        try {
            if (__IAST_DISABLE_HOOKS__) return;
            if (args.sinkObservation) {
                if (args.document !== document) return;
                qualifyIastSinkObservation(args.sinkObservation);
            } else {
                // Source-less policy observations keep their existing path.
                reportFinding(args);
            }
        } catch (_) { }
    });
    emitIastRuntimeHealthUpdate({ force: true });
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

function handleBackgroundIastBridgeMessage(data) {
    data = data || {}
    if (data.channel === 'ptk_iast_observation_stop') {
        IAST_OBSERVATION_STOPPED = true;
        IAST_OBSERVATION_SETTLING = true;
        try {
            flushDeferredIastWriteReports();
            if (IAST_DEFERRED_WRITE_REPORTS.length) recordIastObservationGap('pending_write_at_stop', true);
            flushPendingIastFindingReports();
            if (IAST_PENDING_FINDING_REPORTS.length) recordIastObservationGap('pending_rules_at_stop');
        } finally {
            IAST_OBSERVATION_SETTLING = false;
            emitIastObservationState({ terminal: true });
        }
        return;
    }
    if (data.channel === 'ptk_iast_observation_reset') {
        IAST_OBSERVATION_STOPPED = false;
        IAST_OBSERVATION_SETTLING = false;
        IAST_DEFERRED_WRITE_GENERATION += 1;
        IAST_DEFERRED_WRITE_TIMER_ARMED = false;
        IAST_DEFERRED_WRITE_REPORTS.length = 0;
        IAST_PENDING_FINDING_REPORTS.length = 0;
        IAST_BRIDGE_UNACKED.clear();
        IAST_OBSERVATION_STATE.operationHighWater = 0;
        IAST_OBSERVATION_STATE.emittedRelationships = 0;
        IAST_OBSERVATION_STATE.lossCount = 0;
        IAST_OBSERVATION_STATE.reasons.clear();
        IAST_OBSERVATION_STATE.terminal = false;
        IAST_FINDING_DEDUP.clear();
        emitIastObservationState();
        return;
    }
    if (data.channel === 'ptk_iast_observation_snapshot') {
        emitIastObservationState({ terminal: true });
        return;
    }
    if (data.channel === 'ptk_iast_finding_accepted') {
        if (typeof data.bufferId === 'string' && IAST_BRIDGE_UNACKED.delete(data.bufferId)) {
            emitIastObservationState();
        }
        return;
    }
    if (data.channel === 'ptk_content_iast_bridge_ready') {
        if (globalThis.__PTK_IAST_INSTALLATION_STATE__ === 'ready') {
            // The isolated bridge may attach after the initial receipt was emitted.
            // Replay the current bounded state before announcing agent readiness.
            emitIastObservationState();
            emitIastPageBridgeMessage({ channel: 'ptk_iast_agent_ready', installationState: 'ready' });
        }
        requestModulesFromBackground(true);
        return;
    }
    if (data.channel === 'ptk_background_iast2content_modules') {
        if (data.active === false) {
            disableIastRuntimeHooks(data.reason || 'inactive_scan_tab');
            return;
        }
        if (data.scanStrategy) setIastScanStrategy(data.scanStrategy);
        if (!data.iastModules) return;
        initIastRuleIndex(data.iastModules, {
            signature: data.iastModulesSignature || null,
            scanStrategy: data.scanStrategy || null
        })
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: modules received from bridge')
    }
}

function onIastContentBridgeEvent(event) {
    handleBackgroundIastBridgeMessage(parseIastBridgeEventDetail(event?.detail));
}

function onIastContentWindowMessage(event) {
    handleBackgroundIastBridgeMessage(event.data || {});
}

function rebindIastBridgeListeners() {
    // document.open() removes Window listeners while preserving this agent's
    // lexical state. Reinstall the same handlers, then replay only unaccepted
    // finding envelopes with their original buffer IDs.
    try {
        window.removeEventListener?.(PTK_IAST_CONTENT_TO_PAGE_EVENT, onIastContentBridgeEvent, false);
        window.removeEventListener?.('message', onIastContentWindowMessage, false);
        window.addEventListener(PTK_IAST_CONTENT_TO_PAGE_EVENT, onIastContentBridgeEvent, false);
        window.addEventListener('message', onIastContentWindowMessage, false);
        for (const [bufferId, message] of IAST_BRIDGE_UNACKED) {
            emitIastPageBridgeMessage({ channel: 'ptk_iast_buffer_append', bufferId, message });
            emitIastPageBridgeMessage(message);
        }
        emitIastObservationState();
        return true;
    } catch (_) {
        recordIastObservationGap('bridge_rebind_failed', true);
        return false;
    }
}

try {
    Object.defineProperty(globalThis, '__PTK_IAST_REBIND_BRIDGE__', {
        value: rebindIastBridgeListeners, configurable: false, writable: false
    });
} catch (_) {
    recordIastObservationGap('bridge_rebind_unavailable', true);
}
rebindIastBridgeListeners();

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
        emitIastPageBridgeMessage({ channel: 'ptk_content_iast_request_modules' });
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
    if (!groupId) return false;
    if (!IAST_HOOK_GROUPS.enabled.has(groupId)) return false;
    if (IAST_HOOK_GROUPS.degraded.has(groupId)) return false;
    if (IAST_HOOK_GROUPS.globallyDisabled.has(groupId)) return false;
    return true;
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

function getExecutableMutationCandidate(node, matchValue = matchesTaint) {
    if (!node || node.nodeType !== Node.ELEMENT_NODE) return null;
    const tag = node.tagName ? String(node.tagName).toLowerCase() : null;

    if (tag === 'script') {
        const src = typeof node.getAttribute === 'function' ? node.getAttribute('src') : null;
        if (src && getDangerousUrlScheme(src)) {
            const match = matchValue(src);
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
            const match = matchValue(inlineScript);
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
        const match = matchValue(attrValue);
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
    const delay = reason === 'modules_loaded'
        ? 50
        : Math.max(200, IAST_SMART_STARTUP_SUPPRESS_MS - (Date.now() - IAST_AGENT_BOOT_AT) + 200);
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

function isTrustedTypesHtmlRestrictionError(error) {
    const message = String(error?.message || error || '');
    if (!message) return false;
    return /trustedhtml/i.test(message)
        || /trusted types/i.test(message)
        || /requires\s+'?TrustedHTML'?/i.test(message)
        || /requires\s+"?TrustedHTML"?/i.test(message);
}

function isTrustedTypesHtmlRestricted() {
    if (IAST_TRUSTED_HTML_RESTRICTION.checked) {
        return IAST_TRUSTED_HTML_RESTRICTION.enforced;
    }
    IAST_TRUSTED_HTML_RESTRICTION.checked = true;
    return IAST_TRUSTED_HTML_RESTRICTION.enforced;
}

function markTrustedTypesHtmlRestricted(error) {
    if (!isTrustedTypesHtmlRestrictionError(error)) return false;
    IAST_TRUSTED_HTML_RESTRICTION.checked = true;
    IAST_TRUSTED_HTML_RESTRICTION.enforced = true;
    IAST_TRUSTED_HTML_RESTRICTION.message = String(error?.message || error || '');
    return true;
}

function disableIastRuntimeHooks(reason = 'inactive') {
    // An observation from a revoked admission must not survive reactivation.
    IAST_PENDING_FINDING_REPORTS.length = 0;
    IAST_DEFERRED_WRITE_GENERATION += 1;
    IAST_DEFERRED_WRITE_TIMER_ARMED = false;
    IAST_DEFERRED_WRITE_REPORTS.length = 0;
    IAST_HOOK_GROUPS.enabled = new Set();
    IAST_HOOK_GROUPS.globallyDisabled = new Set();
    IAST_HOOK_GROUPS.runtimeState = reason || 'inactive';
    emitIastRuntimeHealthUpdate({ force: true });
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
    const isDangerousDomPurifyConfig = (options = {}) => {
        if (!options || typeof options !== 'object') return false;
        const attrLists = [options.ADD_ATTR, options.ALLOWED_ATTR]
            .filter(Array.isArray)
            .flat()
            .map((entry) => String(entry || '').trim().toLowerCase());
        if (attrLists.some((entry) => entry.startsWith('on'))) {
            return true;
        }
        const tagLists = [options.ADD_TAGS, options.ALLOWED_TAGS]
            .filter(Array.isArray)
            .flat()
            .map((entry) => String(entry || '').trim().toLowerCase());
        if (tagLists.some((entry) => ['script', 'iframe', 'object', 'embed'].includes(entry))) {
            return true;
        }
        return false;
    };
    const wrapDomPurify = () => {
        if (!window.DOMPurify || typeof window.DOMPurify.sanitize !== 'function') return false;
        if (window.DOMPurify.__ptk_wrapped__) return true;
        const orig = window.DOMPurify.sanitize.bind(window.DOMPurify);
        window.DOMPurify.sanitize = function (...args) {
            const [value, options] = args;
            const result = orig(...args);
            recordSanitizedValue(result, 'san.domPurify');
            if (isDangerousDomPurifyConfig(options)) {
                const serializedValue = safeSerializeValue(value);
                const match = matchesTaint(serializedValue);
                if (match) {
                    maybeReportTaintedValue(serializedValue, {
                        type: 'sanitizer-misuse',
                        sink: 'DOMPurify.sanitize',
                        sinkId: 'sanitizer.dompurify.config'
                    }, {
                        value: serializedValue,
                        sanitizerOptions: safeSerializeValue(options),
                        sanitizerResult: safeSerializeValue(result)
                    }, match);
                }
            }
            return result;
        };
        window.DOMPurify.__ptk_wrapped__ = true;
        return true;
    };
    const wrapTrustedTypes = () => {
        if (!window.trustedTypes || typeof window.trustedTypes.createPolicy !== 'function') return false;
        if (window.trustedTypes.__ptk_wrapped__) return true;
        const origCreatePolicy = window.trustedTypes.createPolicy.bind(window.trustedTypes);
        window.trustedTypes.createPolicy = function (policyName, rules = {}) {
            const wrappedRules = Object.assign({}, rules || {});
            const sinkByMethod = {
                createHTML: 'trustedTypes.policy.createHTML',
                createScript: 'trustedTypes.policy.createScript',
                createScriptURL: 'trustedTypes.policy.createScriptURL'
            };
            Object.keys(sinkByMethod).forEach((method) => {
                const original = wrappedRules[method];
                if (typeof original !== 'function') return;
                wrappedRules[method] = function (...methodArgs) {
                    const result = original.apply(this, methodArgs);
                    const payload = safeSerializeValue(methodArgs[0]);
                    const match = matchesTaint(payload);
                    if (match) {
                        maybeReportTaintedValue(payload, {
                            type: 'trusted-types-policy',
                            sink: `trustedTypes.${method}`,
                            sinkId: sinkByMethod[method]
                        }, {
                            value: payload,
                            trustedTypesPolicy: policyName || null,
                            trustedTypesMethod: method,
                            trustedTypesResult: safeSerializeValue(result)
                        }, match);
                    }
                    return result;
                };
            });
            return origCreatePolicy(policyName, wrappedRules);
        };
        window.trustedTypes.__ptk_wrapped__ = true;
        return true;
    };
    if (wrapDomPurify() && wrapTrustedTypes()) return;
    let attempts = 0;
    const timer = setInterval(() => {
        attempts += 1;
        const domPurifyReady = wrapDomPurify();
        const trustedTypesReady = wrapTrustedTypes();
        if ((domPurifyReady && trustedTypesReady) || attempts > 40) {
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
    updateIastHookRuntimeState();
    emitIastRuntimeHealthUpdate({ force: true });
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
    const c = IAST_OBSERVER_CAPABILITIES;
    if (c.reason) return str;
    if (isTrustedTypesHtmlRestricted()) return str;
    try {
        return withoutHooks(() => {
            const ta = c.invoke(c.create, document, ['textarea']);
            c.invoke(c.set, ta, [str]);
            return c.invoke(c.textareaValue, ta, []);
        });
    } catch (error) {
        markTrustedTypesHtmlRestricted(error);
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
            if (isTrustedTypesHtmlRestricted()) {
                throw new Error('trusted_html_restricted');
            }
            const tmp = document.createElement('div');
            tmp.innerHTML = context.element;
            const first = tmp.firstElementChild;
            const path = computeDomPath(first);
            if (path) context.domPath = path;
        } catch (error) {
            markTrustedTypesHtmlRestricted(error);
        }
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

function classifyTaintKind(sourceKind, value, meta = {}) {
    if (meta.taintKind) return meta.taintKind;
    if ((sourceKind === 'cookie' || sourceKind === 'localStorage' || sourceKind === 'sessionStorage' || sourceKind === 'indexedDb' || sourceKind === 'cacheStorage') && isTokenLikeValue(value)) {
        return 'secret';
    }
    if ((sourceKind === 'apiResponseField' || sourceKind === 'graphqlResponseField') && isTokenLikeValue(value)) {
        return 'secret';
    }
    if (sourceKind === 'query' || sourceKind === 'hashQuery' || sourceKind === 'hashRoute'
        || sourceKind === 'inline' || sourceKind === 'postMessage'
        || sourceKind === 'broadcastMessage' || sourceKind === 'messagePort' || sourceKind === 'workerMessage'
        || sourceKind === 'pathname' || sourceKind === 'pathSegment'
        || sourceKind === 'clientRoute' || sourceKind === 'historyState'
        || sourceKind === 'objectUrl'
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
        lineage: [{ op: 'source', at: Date.now(), meta: Object.assign({}, meta) }],
        shadowEvidence: {
            mechanism: 'source_observation',
            inheritedGrade: typeof value === 'object' && value !== null
                ? 'object_identity'
                : 'primitive_fingerprint_equality'
        }
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

const IAST_SHADOW_MAX_CANDIDATES = 8;
const IAST_SHADOW_MAX_EQUALITY_LENGTH = 4096;
const IAST_SHADOW_GRADE_ORDER = {
    substring: 0,
    lexical_word_boundary: 1,
    canonical_url_equality: 2,
    primitive_fingerprint_equality: 3,
    complete_value_equality: 4,
    instrumented_propagation: 5,
    object_identity: 6
};

function weakerIastShadowGrade(first, second) {
    const a = Object.prototype.hasOwnProperty.call(IAST_SHADOW_GRADE_ORDER, first) ? first : 'substring';
    const b = Object.prototype.hasOwnProperty.call(IAST_SHADOW_GRADE_ORDER, second) ? second : 'substring';
    return IAST_SHADOW_GRADE_ORDER[a] <= IAST_SHADOW_GRADE_ORDER[b] ? a : b;
}

function classifyIastShadowSource(value, source, taintEntry, sharedValueString = null) {
    const sourceId = source?.sourceId || null;
    const matchedTaint = sourceId && taintEntry?.taint?.sourceId === sourceId ? taintEntry : null;
    const raw = source && Object.prototype.hasOwnProperty.call(source, 'raw') ? source.raw : source?.value;
    const valueType = typeof value;
    const rawType = typeof raw;
    const primitiveValue = valueType === 'string' || valueType === 'number' || valueType === 'boolean' || valueType === 'bigint';
    const primitiveRaw = rawType === 'string' || rawType === 'number' || rawType === 'boolean' || rawType === 'bigint';
    let valueRelation = source?.matchType === 'exact' ? 'lexical_word_boundary' : 'substring';
    if (source?.matchType === 'url-eq') valueRelation = 'canonical_url_equality';
    if (primitiveValue && primitiveRaw) {
        const valueString = sharedValueString === null ? String(value) : sharedValueString;
        const rawString = String(raw);
        if (valueString.length <= IAST_SHADOW_MAX_EQUALITY_LENGTH
            && rawString.length === valueString.length && rawString === valueString) {
            valueRelation = 'complete_value_equality';
        }
    }
    const lookupGrade = matchedTaint?.matchType === 'id'
        ? 'object_identity'
        : matchedTaint?.matchType === 'fingerprint'
            ? 'primitive_fingerprint_equality'
            : null;
    const inheritedGrade = matchedTaint?.taint?.shadowEvidence?.inheritedGrade || lookupGrade;
    const propagated = matchedTaint?.taint?.shadowEvidence?.mechanism === 'instrumented_propagation';
    const mechanism = propagated
        ? 'instrumented_propagation'
        : (lookupGrade || valueRelation);
    const effectiveGrade = propagated && inheritedGrade === 'object_identity' && lookupGrade === 'object_identity'
        ? 'instrumented_propagation'
        : (lookupGrade ? weakerIastShadowGrade(inheritedGrade, lookupGrade) : valueRelation);
    return {
        sourceKey: source?.key || source?.source || null,
        mechanism,
        valueRelation,
        inheritedGrade: inheritedGrade || null,
        effectiveGrade,
        // Source-category policy is not proof that the observed value was attacker-controlled.
        attackerControl: source?.taintKind === 'user_input' ? 'category_only_unverified' : 'unestablished'
    };
}

function classifyIastShadowFinding(value, eligibleSources, match, taintEntry, publishedFlow = null) {
    const eligible = Array.isArray(eligibleSources) ? eligibleSources : [];
    const count = Math.min(eligible.length, IAST_SHADOW_MAX_CANDIDATES);
    const valueType = typeof value;
    const valueString = valueType === 'string' || valueType === 'number' || valueType === 'boolean' || valueType === 'bigint'
        ? String(value)
        : null;
    let strongest = null;
    for (let i = 0; i < count; i += 1) {
        const candidate = classifyIastShadowSource(value, eligible[i], taintEntry, valueString);
        if (!strongest || IAST_SHADOW_GRADE_ORDER[candidate.effectiveGrade] > IAST_SHADOW_GRADE_ORDER[strongest.effectiveGrade]) {
            strongest = candidate;
        }
    }
    const publishedPrimaryKey = eligible[0]?.key || eligible[0]?.source || null;
    const flowNodes = Array.isArray(publishedFlow) ? publishedFlow : [];
    const publishedFlowSourceKey = flowNodes.find(node => node?.stage === 'source')?.key || match?.source || null;
    const publishedFlowConsistent = flowNodes.length
        ? flowNodes.some(node => node?.stage !== 'sink' && node?.key === publishedPrimaryKey)
        : publishedPrimaryKey === publishedFlowSourceKey;
    return {
        candidateCount: eligible.length,
        truncated: eligible.length > count,
        shadowPrimary: strongest,
        publishedPrimaryKey,
        publishedFlowSourceKey,
        publishedFlowConsistent,
        shadowFlowSourceKey: strongest?.sourceKey || null
    };
}

function recordIastShadowEvidence(shadow) {
    if (!shadow?.shadowPrimary) return;
    const counts = IAST_SHADOW_EVIDENCE_COUNTS;
    if (counts.total < 1000000) counts.total += 1;
    const grade = shadow.shadowPrimary.effectiveGrade;
    if (Object.prototype.hasOwnProperty.call(counts, grade) && counts[grade] < 1000000) counts[grade] += 1;
    if (!shadow.publishedFlowConsistent && counts.inconsistent_published_flow < 1000000) {
        counts.inconsistent_published_flow += 1;
    }
    if (shadow.truncated && counts.truncated_candidates < 1000000) counts.truncated_candidates += 1;
}

function isIastPrecisionWeakRelation(candidate) {
    return candidate?.valueRelation === 'lexical_word_boundary'
        || candidate?.valueRelation === 'substring';
}

function isIastDirectHtmlSink(sinkId) {
    return sinkId === 'dom.innerHTML' || sinkId === 'dom.outerHTML'
        || sinkId === 'dom.insertAdjacentHTML' || sinkId === 'document.write';
}

function isIastDirectHtmlExecutableCandidate(candidate, sinkId, node = null) {
    if (!candidate) return false;
    const attribute = String(candidate.attribute || '').toLowerCase();
    const tag = String(candidate.tag || '').toLowerCase();
    // HTML setters do not execute parsed script elements. Event handlers and
    // javascript navigation are executable candidates, not observed execution.
    return (tag === 'script' && sinkId === 'document.write')
        || (attribute.startsWith('on') && node && attribute in node && String(candidate.value).trim().length > 0)
        || ((attribute === 'href' || attribute === 'action' || attribute === 'formaction')
            && getDangerousUrlScheme(candidate.value) === 'javascript')
        || (attribute === 'src' && (tag === 'iframe' || tag === 'frame')
            && getDangerousUrlScheme(candidate.value) === 'javascript');
}

let IAST_DIRECT_HTML_PARSER = null;

function captureIastObserverCapabilities() {
    if (IAST_OBSERVER_ENTRY !== 'native-main-document-start') return { reason: 'observer_capability_unverified' };
    // Retain invocation and the complete observer-only WebIDL dependency chain.
    // Shared mutation/bootstrap traversal intentionally remains separate.
    const invoke = Reflect.apply;
    const result = { invoke, reason: 'html_capability_unavailable' };
    try {
        const getter = (proto, name) => {
            const fn = Object.getOwnPropertyDescriptor(proto, name)?.get;
            if (typeof fn !== 'function') throw new Error('missing observer getter');
            return fn;
        };
        result.create = Document.prototype.createElement;
        result.walker = Document.prototype.createTreeWalker;
        result.next = TreeWalker.prototype.nextNode;
        result.set = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')?.set;
        result.content = getter(HTMLTemplateElement.prototype, 'content');
        result.textareaValue = getter(HTMLTextAreaElement.prototype, 'value');
        result.nodeType = getter(Node.prototype, 'nodeType');
        result.text = getter(Node.prototype, 'textContent');
        result.parent = getter(Node.prototype, 'parentElement');
        result.tag = getter(Element.prototype, 'tagName');
        result.namespace = getter(Element.prototype, 'namespaceURI');
        result.attributes = getter(Element.prototype, 'attributes');
        result.attrName = getter(Attr.prototype, 'name');
        result.attrValue = getter(Attr.prototype, 'value');
        result.attrLength = getter(NamedNodeMap.prototype, 'length');
        result.attrItem = NamedNodeMap.prototype.item;
        result.getAttribute = Element.prototype.getAttribute;
        result.eventAttributes = Object.getOwnPropertyNames(HTMLElement.prototype).filter(name => name.startsWith('on'));
        result.lower = String.prototype.toLowerCase;
        result.trim = String.prototype.trim;
        result.starts = String.prototype.startsWith;
        result.includes = String.prototype.includes;
        result.url = URL;
        result.protocol = getter(URL.prototype, 'protocol');
        result.clockReceiver = performance;
        result.clock = performance.now;
        for (const name of ['create', 'walker', 'next', 'set', 'attrItem', 'getAttribute', 'clock', 'lower', 'trim', 'starts', 'includes', 'url']) {
            if (typeof result[name] !== 'function') throw new Error('missing observer method');
        }
        result.reason = null;
    } catch (_) { }
    return result;
}

function createIastDirectHtmlParser() {
    const c = IAST_OBSERVER_CAPABILITIES;
    if (c.reason) return null;
    return value => {
        const template = c.invoke(c.create, document, ['template']);
        if (c.invoke(c.tag, template, []) !== 'TEMPLATE') return null;
        c.invoke(c.set, template, [value]);
        return c.invoke(c.content, template, []);
    };
}

function inspectIastDirectHtmlImpact(value, sinkId, context = {}, parseHtml = null) {
    // Only primitive strings enter this observer. Native coercion and DOM
    // argument/return behavior remain owned by the original wrapper operation.
    if (typeof value !== 'string') return { status: 'unknown', reason: 'non_string_html' };
    if (sinkId === 'document.write') return { status: 'unknown', reason: 'document_write_stream_context_unknown' };
    const c = IAST_OBSERVER_CAPABILITIES;
    if (c.reason) {
        recordIastObservationGap(c.reason);
        return { status: 'unknown', reason: c.reason };
    }
    if (value.length > IAST_SHADOW_MAX_EQUALITY_LENGTH) {
        recordIastObservationGap('html_impact_value_limit');
        return { status: 'unknown', reason: 'html_impact_value_limit' };
    }
    try {
        if (sinkId === 'dom.insertAdjacentHTML' && typeof context.position !== 'string') {
            return { status: 'unknown', reason: 'html_target_context_unavailable' };
        }
        const position = sinkId === 'dom.insertAdjacentHTML' ? c.invoke(c.lower, context.position, []) : null;
        const outside = sinkId === 'dom.outerHTML' || position === 'beforebegin' || position === 'afterend';
        const target = outside && context.element ? c.invoke(c.parent, context.element, []) : context.element;
        if (!target) return { status: 'unknown', reason: 'html_target_context_unavailable' };
        const targetTag = c.invoke(c.lower, c.invoke(c.tag, target, []), []);
        if (c.invoke(c.namespace, target, []) !== 'http://www.w3.org/1999/xhtml') {
            return { status: 'unknown', reason: 'html_target_namespace_unresolved' };
        }
        if (targetTag === 'template' || targetTag === 'textarea' || targetTag === 'title' || targetTag === 'style'
            || targetTag === 'script' || targetTag === 'xmp' || targetTag === 'plaintext' || targetTag === 'noscript') {
            return { status: 'nonexecutable', reason: 'inert_html_target' };
        }
        if (!c.invoke(c.includes, value, ['<'])) return { status: 'nonexecutable', reason: 'plaintext_html_assignment' };
        if (typeof parseHtml !== 'function') return { status: 'unknown', reason: 'html_impact_parser_unavailable' };
        const root = withInternalHtmlParser(() => parseHtml(value));
        // Native parsed roots provide a walker. Do not use an unbounded
        // selector fallback or infer safety from a missing traversal capability.
        if (!root || c.invoke(c.nodeType, root, []) !== 11) {
            return { status: 'unknown', reason: 'html_impact_walker_unavailable' };
        }
        const now = () => c.invoke(c.clock, c.clockReceiver, []);
        const startedAt = now();
        let visited = 0, executable = false, unknownCandidate = false, limited = false;
        const reports = [];
        const walker = c.invoke(c.walker, document, [root, 1]);
        let node = c.invoke(c.next, walker, []);
        while (node) {
            if (visited >= 24 || now() - startedAt >= 2) { limited = true; break; }
            visited += 1;
            if (c.invoke(c.nodeType, node, []) !== 1) throw new Error('invalid walker result');
            const tag = c.invoke(c.lower, c.invoke(c.tag, node, []), []);
            const attrs = c.invoke(c.attributes, node, []);
            const count = c.invoke(c.attrLength, attrs, []);
            // Attribute iteration shares the bounded observer clock; never Array.from
            // or a page-replaceable iterator over an unbounded collection.
            for (let i = 0; i < count; i += 1) {
                if (now() - startedAt >= 2) { limited = true; break; }
                const attr = c.invoke(c.attrItem, attrs, [i]);
                const attribute = c.invoke(c.lower, c.invoke(c.attrName, attr, []), []);
                const raw = c.invoke(c.attrValue, attr, []);
                let scheme = null;
                try { scheme = c.invoke(c.protocol, new c.url(raw, 'https://ptk.invalid/'), []); } catch (_) { }
                let supportedEvent = false;
                for (let j = 0; j < c.eventAttributes.length; j += 1) {
                    if (c.eventAttributes[j] === attribute) { supportedEvent = true; break; }
                }
                const event = c.invoke(c.starts, attribute, ['on']) && c.invoke(c.trim, raw, []).length > 0;
                const navigation = attribute === 'href' || attribute === 'action' || attribute === 'formaction';
                const frameSrc = attribute === 'src' && (tag === 'iframe' || tag === 'frame');
                if (event && supportedEvent || (navigation || frameSrc) && scheme === 'javascript:') executable = true;
                else if (event || attribute === 'srcdoc' || (navigation || attribute === 'src')
                    && (scheme === 'javascript:' || scheme === 'data:')) unknownCandidate = true;
            }
            if (limited) break;
            node = c.invoke(c.next, walker, []);
        }
        if (executable) return { status: 'executable_candidate', reason: 'parsed_active_html_candidate', root, reports };
        if (limited || now() - startedAt >= 2) {
            recordIastObservationGap('html_impact_traversal_limit');
            return { status: 'unknown', reason: 'html_impact_traversal_limit' };
        }
        if (unknownCandidate) return { status: 'unknown', reason: 'nested_html_impact_unresolved', root, reports };
        return { status: 'nonexecutable', reason: 'parsed_inert_html', root, reports };
    } catch (_) {
        recordIastObservationGap('html_impact_parser_unavailable');
        return { status: 'unknown', reason: 'html_impact_parser_unavailable' };
    }
}

function getIastPrecisionSeverityOverride(sinkId, context, eligibleSources, shadow, taintEntry, sourceMetadata = null) {
    // Only these observed sinks can receive a Phase 2B severity decision.
    // Shadow accounting still runs independently for every reported finding.
    if (!isIastDirectHtmlSink(sinkId) && sinkId !== 'code.eval'
        && !isFunctionCodeExecutionSink(sinkId)
        && !(sinkId === 'dom.mutation' && isModulesLoadedBootstrapDomMutation(context))) return null;
    const sources = Array.isArray(eligibleSources) ? eligibleSources.slice(0, IAST_SHADOW_MAX_CANDIDATES) : [];
    if (!sources.length || !shadow?.shadowPrimary || shadow.truncated) return null;
    const grades = sources.map(source => classifyIastShadowSource(context.value, source, taintEntry));
    if (isIastDirectHtmlSink(sinkId)) {
        if (context.htmlImpact?.status === 'nonexecutable') return 'info';
        if (context.htmlImpact?.status !== 'executable_candidate') return 'low';
        // This function receives only the selected rule/source relationship.
        // Neither a stronger neighbour nor a category name upgrades lexical
        // coincidence to a causal High claim.
        const hasQualifiedSource = grades.some((grade, index) => !isIastPrecisionWeakRelation(grade)
            && (sources[index]?.taintKind === 'user_input'
                || sources[index]?.acquisition === 'instrumented_read'
                || IAST_RESPONSE_SOURCE_KINDS.has(sources[index]?.sourceKind)));
        return hasQualifiedSource ? null : 'low';
    }
    if (sinkId === 'dom.mutation' && isModulesLoadedBootstrapDomMutation(context)) {
        // The sweep discovers an existing executable-looking node; it did not
        // observe a mutation. Preserve High when an eligible, non-Boolean
        // browser-controlled value covers the executable candidate itself.
        const hasStrongCandidate = grades.some((grade, index) => {
            const source = sources[index];
            const observedType = sourceMetadata
                ? sourceMetadata[source?.key]?.observedValueType
                : getTaintMetaEntry(source?.key)?.observedValueType;
            return observedType !== 'boolean'
                && (source?.taintKind === 'user_input' || isUserControlledSource(source))
                && (grade.valueRelation === 'complete_value_equality'
                    || (grade.mechanism === 'instrumented_propagation'
                        && IAST_SHADOW_GRADE_ORDER[grade.inheritedGrade] >= IAST_SHADOW_GRADE_ORDER.complete_value_equality));
        });
        return hasStrongCandidate ? null : 'info';
    }
    if (sinkId === 'code.eval') {
        return grades.every(isIastPrecisionWeakRelation) ? 'low' : null;
    }
    if (isFunctionCodeExecutionSink(sinkId)) {
        const onlyBooleanOrConfigCoincidence = grades.every((grade, index) => {
            const source = sources[index];
            const observedType = sourceMetadata
                ? sourceMetadata[source?.key]?.observedValueType
                : getTaintMetaEntry(source?.key)?.observedValueType;
            const raw = String(source?.raw ?? source?.value ?? '').trim();
            return isIastPrecisionWeakRelation(grade)
                && (observedType === 'boolean'
                    || (isLowSignalPlainSourceValue(raw) && observedType !== 'string'));
        });
        return onlyBooleanOrConfigCoincidence ? 'low' : null;
    }
    return null;
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
    const inputTaints = inputs.map(getTaintEntry).filter(Boolean);
    if (!inputTaints.length) return;
    const primaryEntry = inputTaints[0];
    const primary = primaryEntry.taint;
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
        lineage: primaryLineage.concat([{ op, at: Date.now(), meta }]).slice(-Math.max(maxLineage, 1)),
        shadowEvidence: {
            mechanism: 'instrumented_propagation',
            inheritedGrade: weakerIastShadowGrade(
                primary?.shadowEvidence?.inheritedGrade || (primaryEntry.matchType === 'id'
                    ? 'object_identity' : 'primitive_fingerprint_equality'),
                primaryEntry.matchType === 'id' ? 'object_identity' : 'primitive_fingerprint_equality'
            )
        }
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
        if (!isTrackableDynamicSourceValue(val)) return;
        const hasAlnum = /[A-Za-z0-9]/.test(val);
        if (!hasAlnum && val !== '/') return;
        const meta = Object.assign({}, metaOverride || describeSourceKey(key, val));
        const storedMeta = updateTaintMetaEntry(key, { taintKind: meta.taintKind, sourceKind: meta.sourceKind });
        const taint = createSource(val, meta.sourceKind || meta.type || 'unknown', Object.assign({}, meta, { sourceId: storedMeta?.sourceId || null }));
        updateTaintMetaEntry(key, { sourceId: taint.sourceId });
        raw[key] = val;
        registerTaintSource(key, val, Object.assign({}, meta, { sourceId: taint.sourceId }), { trackActivity: false });
    };
    for (const [k, v] of new URLSearchParams(location.search)) add(`query:${k}`, v);
    const rawSearch = safeDecodeComponent(String(location.search || '').replace(/^\?/, '')).trim();
    if (rawSearch && !rawSearch.includes('=')) {
        add('query:raw', rawSearch, {
            type: 'query',
            label: 'Raw query string',
            detail: 'raw',
            taintKind: 'user_input',
            sourceKind: 'query',
            location: window.location.href,
            value: rawSearch
        });
    }
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
    // Initial/reseed enumeration has the same private authority and total
    // budgets as the sink snapshot; a loading document alone grants nothing.
    const storageCapabilities = IAST_STORAGE_OBSERVATION_CAPABILITIES;
    if (storageCapabilities.reason) recordIastObservationGap(storageCapabilities.reason);
    else {
        let reads = 0, bytes = 0;
        for (const area of storageCapabilities.areas) {
            if (area.unavailable) { recordIastObservationGap('storage_area_unavailable'); continue; }
            try {
                const count = storageCapabilities.invoke(area.length, area.store, []);
                for (let i = 0; i < count; i += 1) {
                    if (reads >= IAST_OBSERVATION_LIMITS.keys) { recordIastObservationGap('storage_key_limit', true); break; }
                    reads += 1;
                    const key = storageCapabilities.invoke(area.key, area.store, [i]);
                    if (typeof key !== 'string' || isInternalStorageKey(key)) continue;
                    if (`${area.name}:${key}`.length > 512) { recordIastObservationGap('storage_key_size_limit'); continue; }
                    const val = storageCapabilities.invoke(area.getItem, area.store, [key]);
                    if (typeof val !== 'string') continue;
                    bytes += (key.length + val.length) * 2;
                    if (bytes > IAST_OBSERVATION_LIMITS.bytes) { recordIastObservationGap('storage_byte_limit', true); break; }
                    if (val.length > IAST_OBSERVATION_LIMITS.valueChars) { recordIastObservationGap('storage_value_limit'); continue; }
                    add(`${area.name}:${key}`, val);
                }
                if (storageCapabilities.invoke(area.length, area.store, []) !== count) recordIastObservationGap('storage_changed_during_snapshot');
            } catch (_) { recordIastObservationGap('storage_area_unavailable'); }
            if (reads >= IAST_OBSERVATION_LIMITS.keys || bytes > IAST_OBSERVATION_LIMITS.bytes) break;
        }
    }
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
    } else if (key.startsWith('broadcast:')) {
        const channelName = key.slice('broadcast:'.length) || 'channel';
        meta.type = 'broadcastMessage';
        meta.label = `BroadcastChannel "${channelName}" message`;
        meta.detail = channelName;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'broadcastMessage';
    } else if (key.startsWith('messagePort:')) {
        const portLabel = key.slice('messagePort:'.length) || 'port';
        meta.type = 'messagePort';
        meta.label = `MessagePort "${portLabel}" message`;
        meta.detail = portLabel;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'messagePort';
    } else if (key.startsWith('workerMessage:')) {
        const workerLabel = key.slice('workerMessage:'.length) || 'worker';
        meta.type = 'workerMessage';
        meta.label = `Worker "${workerLabel}" message`;
        meta.detail = workerLabel;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'workerMessage';
    } else if (key.startsWith('objectUrl:')) {
        meta.type = 'objectUrl';
        meta.label = 'Object URL';
        meta.detail = rawValue || key.slice('objectUrl:'.length);
        meta.taintKind = 'user_input';
        meta.sourceKind = 'objectUrl';
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
    } else if (key.startsWith('indexedDb:')) {
        const detail = key.slice('indexedDb:'.length) || 'record';
        meta.type = 'indexedDb';
        meta.label = `IndexedDB "${detail}"`;
        meta.detail = detail;
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'unknown';
        meta.sourceKind = 'indexedDb';
    } else if (key.startsWith('cacheStorage:')) {
        const detail = key.slice('cacheStorage:'.length) || 'entry';
        meta.type = 'cacheStorage';
        meta.label = `CacheStorage "${detail}"`;
        meta.detail = detail;
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'unknown';
        meta.sourceKind = 'cacheStorage';
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
    // A sink-time storage equality is not an application read. In particular,
    // null must not fall through to a stale same-key source ID or taint kind.
    if (provided.__ptkOperationLocalSource === true) return Object.assign({}, provided);
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
        acquisition: provided.acquisition || (() => {
            const op = window.__IAST_TAINT_GRAPH__?.[key]?.node?.op || '';
            if (/\.getItem$/.test(op)) return 'instrumented_read';
            if (/\.setItem$/.test(op)) return 'instrumented_write';
            return /^localStorage:|^sessionStorage:|^cookie:|^window\.name$/.test(key) ? 'initial_snapshot' : 'existing_other';
        })(),
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

function buildUrlValidationEvidence(rawUrl) {
    const raw = safeSerializeValue(rawUrl).trim();
    const internalRoute = looksLikeInternalRoute(raw);
    const scheme = getUrlScheme(raw);
    const dangerousScheme = scheme && DANGEROUS_URL_SCHEMES.has(scheme) ? scheme : null;
    const evidence = {
        parsed: false,
        rawKind: internalRoute ? 'internal_route' : 'url',
        resolvedUrl: null,
        scheme: scheme || null,
        dangerousScheme,
        sameOrigin: null,
        crossOrigin: null,
        validationState: dangerousScheme ? 'dangerous_scheme' : 'unresolved'
    };
    if (!raw) {
        evidence.rawKind = 'empty';
        evidence.validationState = 'empty';
        return evidence;
    }
    try {
        const parsed = new URL(raw, window.location.href);
        evidence.parsed = true;
        evidence.resolvedUrl = parsed.href;
        evidence.scheme = parsed.protocol ? parsed.protocol.replace(':', '').toLowerCase() : evidence.scheme;
        evidence.sameOrigin = parsed.origin === window.location.origin;
        evidence.crossOrigin = parsed.origin !== window.location.origin;
        if (dangerousScheme) {
            evidence.validationState = 'dangerous_scheme';
        } else if (internalRoute || evidence.sameOrigin) {
            evidence.validationState = 'same_origin';
        } else {
            evidence.validationState = 'cross_origin';
        }
    } catch (_) {
        evidence.validationState = dangerousScheme ? 'dangerous_scheme' : 'invalid_url';
    }
    return evidence;
}

function shouldReportNavigationSink(targetUrl) {
    if (!targetUrl) return false;
    const validation = buildUrlValidationEvidence(targetUrl);
    if (validation.dangerousScheme) {
        return true;
    }
    if (validation.rawKind === 'internal_route' || validation.sameOrigin === true) {
        // Ignore internal SPA routes like /login or #/search to reduce noise.
        return false;
    }
    return validation.crossOrigin === true;
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
    // Direct HTML is qualified per eligible relationship, with the operation's
    // bounded parsed impact. The attribute heuristic cannot supply that proof
    // and must not lend a source-category High to another weak relationship.
    if (isIastDirectHtmlSink(sinkId)) return { skip: false, downgrade: null };
    if (DOM_XSS_SINK_IDS.has(sinkId)) {
        const attrName = context.attribute || context.attr || context.attrName || context.eventType
            || ({ 'dom.innerHTML': 'innerHTML', 'dom.outerHTML': 'outerHTML', 'dom.insertAdjacentHTML': 'innerHTML', 'document.write': 'innerHTML' })[sinkId] || null;
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
        isCrossOrigin,
        context
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
        const rawSearch = safeDecodeComponent(String(location.search || '').replace(/^\?/, '')).trim();
        if (rawSearch && !rawSearch.includes('=')) {
            record('query:raw', rawSearch, {
                type: 'query',
                label: 'Raw query string',
                detail: 'raw',
                sourceKind: 'query',
                taintKind: 'user_input',
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
    const storageAreaName = (store) => {
        try {
            return store === localStorage ? 'localStorage' : 'sessionStorage';
        } catch (_) {
            return 'storage';
        }
    };
    if (typeof proto.getItem === 'function' && !proto.getItem.__ptk_iast_wrapped__) {
        const originalGetItem = proto.getItem;
        const wrappedGetItem = function (k) {
            const value = originalGetItem.apply(this, arguments);
            try {
                if (isInternalStorageKey(k)) {
                    return value;
                }
                if (!isTrackableDynamicSourceValue(value)) {
                    return value;
                }
                const area = storageAreaName(this);
                record(`${area}:${k}`, value, {
                    label: `${area}["${k}"]`,
                    detail: k,
                    type: area,
                    sourceKind: area,
                    taintKind: isTokenLikeValue(value) ? 'secret' : 'user_input',
                    op: `${area}.getItem`,
                    storageArea: area,
                    storageKey: k,
                    trackActivity: true
                });
            } catch (_) {
                // preserve native storage behavior if source registration fails
            }
            return value;
        };
        wrappedGetItem.__ptk_iast_wrapped__ = true;
        proto.getItem = wrappedGetItem;
    }
    ['setItem', 'removeItem', 'clear'].forEach(fn => {
        const orig = proto[fn];
        proto[fn] = function (k, v) {
            const area = storageAreaName(this);
            if (fn === 'setItem') {
                if (isInternalStorageKey(k)) {
                    return orig.apply(this, arguments);
                }
                const value = v == null ? '' : String(v);
                const trackable = isTrackableDynamicSourceValue(value);
                const tokenLike = isTokenLikeValue(value);
                const elMeta = trackable || tokenLike ? captureElementMeta(document?.activeElement || null) : {};
                const match = trackable || tokenLike ? matchesTaint(value) : null;
                if (trackable) {
                    record(`${area}:${k}`, value, {
                        label: `${area}:${k}`,
                        type: area,
                        sourceKind: area,
                        taintKind: tokenLike ? 'secret' : 'user_input',
                        op: `${area}.setItem`,
                        storageArea: area,
                        storageKey: k,
                        domPath: elMeta.domPath,
                        elementId: elMeta.elementId,
                        parentsMatch: match
                    });
                }
                if (!tokenLike) {
                    return orig.apply(this, arguments);
                }
                const storageHooksEnabled = isHookGroupEnabled('hook.storage');
                const sinkId = area === 'localStorage' ? 'storage.localStorage.setItem' : 'storage.sessionStorage.setItem';
                const ruleId = area === 'localStorage' ? 'localstorage_token_persist' : 'sessionstorage_token_persist';
                const binding = buildRuleBinding({ sinkId, ruleId, fallbackType: 'storage-token-leak' });
                const dataKind = getTokenDataKind(value);
                if (!storageHooksEnabled) {
                    emitStorageObservationSignal({ area, key: k, value, elMeta });
                    return orig.apply(this, arguments);
                }
                const reportObservation = (originValue) => {
                    maybeReportTaintedValue(value, binding, Object.assign({
                        storageKey: k,
                        storageArea: area,
                        value,
                        primaryClass: 'observation',
                        sourceRole: 'observed',
                        origin: originValue,
                        detection: {
                            reason: dataKind === 'jwt' ? 'jwt_heuristic' : 'token_heuristic',
                            dataKind,
                            confidence: 80,
                            details: {
                                matchedBy: dataKind === 'jwt' ? 'jwt_structure' : 'token_heuristic',
                                valuePreview: buildSourcePreview(value),
                                length: String(value || '').length
                            }
                        },
                        observedAt: { kind: area === 'localStorage' ? 'storage.localStorage' : 'storage.sessionStorage', key: k },
                        operation: { sinkId, sinkArgs: { key: k, area } }
                    }, elMeta), match);
                };
                reportObservation(null);
            }
            if (fn === 'removeItem') delete taints[`${storageAreaName(this)}:${k}`];
            if (fn === 'clear') Object.keys(taints)
                .filter(x => x.startsWith(`${storageAreaName(this)}:`))
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
                const trackable = isTrackableDynamicSourceValue(decoded);
                const tokenLike = isTokenLikeValue(decoded);
                const match = trackable || tokenLike ? matchesTaint(decoded) : null;
                const elMeta = trackable || tokenLike ? captureElementMeta(document?.activeElement || null) : {};
                if (trackable) {
                    record(`cookie:${k}`, decoded, Object.assign(
                        createCookieSourceMeta(k, decoded, { value: decoded }),
                        {
                            domPath: elMeta.domPath,
                            elementId: elMeta.elementId,
                            parentsMatch: match
                        }
                    ));
                }
                if (!tokenLike) {
                    return res;
                }
                const storageHooksEnabled = isHookGroupEnabled('hook.storage');
                const binding = buildRuleBinding({
                    sinkId: 'storage.document.cookie',
                    fallbackType: 'storage-token-leak'
                });
                const dataKind = getTokenDataKind(decoded);
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
                reportObservation(null);
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
            if (isIastInternalMessagePayload(data)) return;
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

// IndexedDB and CacheStorage persistence sources
; (function () {
    const registerPersistentSource = (kind, detail, rawValue) => {
        if (rawValue == null) return null;
        const serialized = safeSerializeValue(rawValue).trim();
        if (!serialized || serialized.length > 4096) return null;
        const key = `${kind}:${detail || 'entry'}`;
        return registerDynamicTaintSource(key, serialized, {
            type: kind,
            label: kind === 'indexedDb' ? `IndexedDB "${detail}"` : `CacheStorage "${detail}"`,
            detail: detail || null,
            sourceKind: kind,
            taintKind: isTokenLikeValue(serialized) ? 'secret' : 'unknown'
        });
    };

    const inspectCachedResponse = async (cacheName, requestUrl, response) => {
        if (!response || typeof response.clone !== 'function') return;
        try {
            const clone = response.clone();
            const text = await clone.text();
            const trimmed = String(text || '').trim();
            if (!trimmed || trimmed.length > 4096) return;
            registerPersistentSource('cacheStorage', `${cacheName || 'cache'}:${requestUrl || 'entry'}`, trimmed);
        } catch (_) {
            // ignore cache response inspection failures
        }
    };

    if (typeof IDBObjectStore !== 'undefined' && IDBObjectStore.prototype) {
        const makeIndexedDbDetail = (store, key = null) => {
            const dbName = store?.transaction?.db?.name || 'db';
            const storeName = store?.name || 'store';
            const suffix = key == null || key === '' ? 'record' : safeSerializeValue(key);
            return `${dbName}/${storeName}/${suffix}`;
        };

        ['put', 'add'].forEach((method) => {
            const original = IDBObjectStore.prototype[method];
            if (typeof original !== 'function' || original.__ptk_iast_wrapped__) return;
            const wrapped = function (value, key) {
                if (isHookGroupEnabled('hook.storage')) {
                    try {
                        const serialized = safeSerializeValue(value).trim();
                        if (serialized) {
                            maybeReportTaintedValue(serialized, {
                                type: 'persistent-storage',
                                sink: `IDBObjectStore.${method}`,
                                sinkId: 'storage.indexeddb.put'
                            }, {
                                value: serialized,
                                storageArea: 'indexedDb',
                                storageKey: safeSerializeValue(key),
                                storeName: this?.name || null,
                                dbName: this?.transaction?.db?.name || null
                            });
                            if (matchesTaint(serialized) || isTokenLikeValue(serialized)) {
                                registerPersistentSource('indexedDb', makeIndexedDbDetail(this, key), serialized);
                            }
                        }
                    } catch (_) {
                        // ignore IndexedDB write tracking failures
                    }
                }
                return original.apply(this, arguments);
            };
            wrapped.__ptk_iast_wrapped__ = true;
            IDBObjectStore.prototype[method] = wrapped;
        });

        ['get', 'getAll'].forEach((method) => {
            const original = IDBObjectStore.prototype[method];
            if (typeof original !== 'function' || original.__ptk_iast_read_wrapped__) return;
            const wrapped = function (key) {
                const request = original.apply(this, arguments);
                if (!isHookGroupEnabled('hook.storage') || !request || typeof request.addEventListener !== 'function') {
                    return request;
                }
                const detail = makeIndexedDbDetail(this, key);
                request.addEventListener('success', () => {
                    try {
                        const result = request.result;
                        if (Array.isArray(result)) {
                            result.forEach((entry, index) => registerPersistentSource('indexedDb', `${detail}:${index}`, entry));
                        } else {
                            registerPersistentSource('indexedDb', detail, result);
                        }
                    } catch (_) {
                        // ignore IndexedDB read tracking failures
                    }
                }, { once: true });
                return request;
            };
            wrapped.__ptk_iast_read_wrapped__ = true;
            IDBObjectStore.prototype[method] = wrapped;
        });
    }

    if (typeof CacheStorage !== 'undefined' && CacheStorage.prototype && typeof CacheStorage.prototype.open === 'function' && IAST_CACHE_INSTANCES) {
        const originalOpen = CacheStorage.prototype.open;
        if (!originalOpen.__ptk_iast_wrapped__) {
            const wrappedOpen = function (cacheName) {
                return Promise.resolve(originalOpen.apply(this, arguments)).then((cache) => {
                    try {
                        if (cache) {
                            IAST_CACHE_INSTANCES.set(cache, safeSerializeValue(cacheName) || 'cache');
                        }
                    } catch (_) {
                        // ignore cache instance tracking failures
                    }
                    return cache;
                });
            };
            wrappedOpen.__ptk_iast_wrapped__ = true;
            CacheStorage.prototype.open = wrappedOpen;
        }
    }

    if (typeof Cache !== 'undefined' && Cache.prototype) {
        if (typeof Cache.prototype.put === 'function' && !Cache.prototype.put.__ptk_iast_wrapped__) {
            const originalPut = Cache.prototype.put;
            const wrappedPut = function (request, response) {
                const cacheName = IAST_CACHE_INSTANCES?.get(this) || 'cache';
                const requestUrl = safeSerializeValue(request?.url || request || '');
                if (isHookGroupEnabled('hook.storage')) {
                    try {
                        if (requestUrl) {
                            maybeReportTaintedValue(requestUrl, {
                                type: 'persistent-storage',
                                sink: 'Cache.put',
                                sinkId: 'storage.cache.put'
                            }, {
                                value: requestUrl,
                                storageArea: 'cacheStorage',
                                storageKey: requestUrl,
                                cacheName
                            });
                        }
                        void inspectCachedResponse(cacheName, requestUrl, response);
                    } catch (_) {
                        // ignore Cache.put tracking failures
                    }
                }
                return originalPut.apply(this, arguments);
            };
            wrappedPut.__ptk_iast_wrapped__ = true;
            Cache.prototype.put = wrappedPut;
        }

        if (typeof Cache.prototype.match === 'function' && !Cache.prototype.match.__ptk_iast_wrapped__) {
            const originalMatch = Cache.prototype.match;
            const wrappedMatch = function (request, options) {
                const cacheName = IAST_CACHE_INSTANCES?.get(this) || 'cache';
                const requestUrl = safeSerializeValue(request?.url || request || '');
                return Promise.resolve(originalMatch.call(this, request, options)).then((response) => {
                    if (response && IAST_CACHE_RESPONSE_META) {
                        IAST_CACHE_RESPONSE_META.set(response, {
                            cacheName,
                            requestUrl
                        });
                    }
                    return response;
                });
            };
            wrappedMatch.__ptk_iast_wrapped__ = true;
            Cache.prototype.match = wrappedMatch;
        }
    }

    if (typeof Response !== 'undefined' && Response.prototype && (IAST_CACHE_RESPONSE_META || IAST_FETCH_RESPONSE_META)) {
        ['text', 'json'].forEach((method) => {
            const original = Response.prototype[method];
            if (typeof original !== 'function' || original.__ptk_iast_wrapped__) return;
            const wrapped = function () {
                const cacheMeta = IAST_CACHE_RESPONSE_META?.get(this) || null;
                const fetchMeta = IAST_FETCH_RESPONSE_META?.get(this) || null;
                return Promise.resolve(original.apply(this, arguments)).then((result) => {
                    if (cacheMeta) {
                        try {
                            const value = method === 'json' ? safeSerializeValue(result) : result;
                            registerPersistentSource('cacheStorage', `${cacheMeta.cacheName || 'cache'}:${cacheMeta.requestUrl || 'entry'}`, value);
                        } catch (_) {
                            // ignore cache response source registration failures
                        }
                    }
                    if (fetchMeta && isHookGroupEnabled('hook.net.responses')) {
                        try {
                            const parsed = method === 'json' && result && typeof result === 'object'
                                ? result
                                : parseJsonTextSafely(trimResponsePayloadText(result));
                            if (parsed && typeof parsed === 'object') {
                                registerResponseFieldSources(parsed, fetchMeta);
                            }
                        } catch (_) {
                            // Response observation must preserve native response consumption.
                        }
                    }
                    return result;
                });
            };
            wrapped.__ptk_iast_wrapped__ = true;
            Response.prototype[method] = wrapped;
        });
    }
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
        if (key.startsWith('broadcast:')) return 'broadcastMessage';
        if (key.startsWith('messagePort:')) return 'messagePort';
        if (key.startsWith('workerMessage:')) return 'workerMessage';
        if (key.startsWith('objectUrl:')) return 'objectUrl';
        if (key.startsWith('indexedDb:')) return 'indexedDb';
        if (key.startsWith('cacheStorage:')) return 'cacheStorage';
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
            case 'broadcastMessage': return 32;
            case 'messagePort': return 31;
            case 'workerMessage': return 31;
            case 'objectUrl': return 35;
            case 'indexedDb': return 62;
            case 'cacheStorage': return 61;
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
    try {
        emitIastPageBridgeMessage({
            channel: 'ptk_iast_buffer_flush_request'
        });
    } catch (_) {/*ignore*/ }
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

function createIastBufferId() {
    try {
        if (crypto?.randomUUID) return crypto.randomUUID();
    } catch (_) { }
    return `iast-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function postBufferedIastMessage(msg) {
    let delivered = false;
    withoutHooks(() => {
        const bufferId = createIastBufferId();
        const bufferedMsg = msg && typeof msg === 'object'
            ? Object.assign({}, msg, { __ptkIastBufferId: bufferId })
            : { value: msg, __ptkIastBufferId: bufferId };
        if (IAST_BRIDGE_UNACKED.size >= IAST_BRIDGE_UNACKED_LIMIT) {
            recordIastObservationGap('bridge_unacked_limit', true);
        } else {
            IAST_BRIDGE_UNACKED.set(bufferId, bufferedMsg);
            emitIastObservationState();
        }
        try {
            emitIastPageBridgeMessage({
                channel: 'ptk_iast_buffer_append',
                bufferId,
                message: bufferedMsg
            });
        } catch (_) {/*ignore*/ }
        delivered = emitIastPageBridgeMessage(bufferedMsg);
    });
    if (!delivered) recordIastObservationGap('bridge_delivery_failed', true);
    return delivered;
}

function postDirectIastMessage(msg) {
    withoutHooks(() => {
        emitIastPageBridgeMessage(msg);
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


function reportFinding({ type, sink, sinkId = null, ruleId = null, category = null, severity: severityOverride = null, matched, source, sources = null, context = {} }, publication = null) {
    if (IAST_OBSERVATION_STOPPED && !IAST_OBSERVATION_SETTLING) return;
    if (!context.observation) {
        const operation = captureIastOperation(sinkId || sink, context);
        context = Object.assign({}, context, { observation: {
            schemaVersion: 2, identityVersion: 2, kind: 'policy_signal',
            operationId: operation.operationId, gradeAuthority: 'page_observed_untrusted',
            acquisition: 'existing_other', evidenceGrade: null, inheritedGrade: null,
            valueRelation: 'unavailable', propagation: null, attackerControl: 'not_applicable',
            controlReason: 'Source-less policy observation.', site: operation.site,
            sourceBinding: null, completeness: operation.completeness
        } });
    }
    // Require rule catalog
    if (!IAST_MODULES) {
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: skip finding, modules not loaded yet', { sinkId, ruleId });
        queuePendingIastFindingReport({ type, sink, sinkId, ruleId, category, severity: severityOverride, matched, source, sources, context });
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

    const loc = publication ? publication.location : window.location.href;
    let trace = publication ? publication.trace : '';
    if (!publication) {
        try {
            trace = (new Error(`Sink: ${type}`)).stack;
        } catch (e) { }
    }
    const cleanedTrace = cleanTraceFrames(trace);
    const attackId = publication ? publication.attackId : (window.__PTK_CURRENT_ATTACK_ID__ || null);
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
    // Replayed observations already contain their sink-time normalized fields;
    // do not fill original nulls from a newer same-key source registration.
    let normalizedSources = Array.isArray(sources) && sources.length
        ? (publication ? sources : normalizeTaintedSources(sources, matched))
        : [];
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
        tagName: context.tagName || (publication ? publication.elementTagName : context.element?.tagName) || null,
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
        schemaVersion: 2,
        observation: context.observation,
        primaryClass,
        sourceRole,
        origin: context?.origin || null,
        observedAt,
        operation: operationMeta,
        detection: normalizedDetection,
        trust: normalizedTrust,
        suppression,
        networkTarget: resolvedNetworkTarget || null,
        routing: publication ? publication.routing : buildRoutingMeta(),
        category: resolvedCategory,
        severity: resolvedSeverity,
        meta: findingMeta,
        context: enrichContext(publication ? Object.assign({}, context, publication.elementContext) : context),
        sinkContext,
        flowSummary,
        location: loc,
        trace: cleanedTrace.trace,
        traceSummary: cleanedTrace.traceSummary,
        attackId: attackId,
        timestamp: publication ? publication.timestamp : Date.now(),
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
    // Count one admitted relationship at its common publication boundary,
    // including source-less policy reports. Buffered redelivery does not enter
    // this function and cannot inflate this document high-water receipt.
    IAST_OBSERVATION_STATE.terminal = false;
    IAST_OBSERVATION_STATE.emittedRelationships += 1;
    emitIastObservationState();
    try {
        const navigationCorrelation = sanitized?.context?.navigationCorrelation;
        if (navigationCorrelation?.deferUntilObserved === true) {
            postDirectIastMessage({
                channel: 'ptk_iast_navigation_candidate',
                candidate: {
                    destination: navigationCorrelation.destination || sanitized?.context?.destUrl || null,
                    requestUrl: navigationCorrelation.requestUrl || sanitized?.context?.destUrl || null,
                    sourceOrigin: navigationCorrelation.sourceOrigin || window.location.origin,
                    sourceUrl: navigationCorrelation.sourceUrl || loc,
                    navigationType: navigationCorrelation.navigationType || null,
                    methodEvidence: navigationCorrelation.methodEvidence || null
                },
                finding: sanitized
            });
            return;
        }
        postBufferedIastMessage({
            ptk_iast: 'finding_report',
            channel: 'ptk_content_iast2background_iast',
            finding: sanitized
        })
    } catch (e) {
        recordIastObservationGap('finding_publication_failed', true);
        console.warn('IAST reportFinding.postMessage failed:', e);
    }
}

function safeSerializeValue(value) {
    if (value == null) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
    try {
        const serialized = JSON.stringify(value);
        if (typeof serialized === 'string') return serialized;
    } catch (_) {
        // fall through to String() fallback below
    }
    try {
        const fallback = String(value);
        return typeof fallback === 'string' ? fallback : '';
    } catch {
        return '';
    }
}

function coerceDomParserMarkup(value) {
    if (typeof value === 'string') return value;
    try {
        return String(value ?? '');
    } catch (_) {
        return '';
    }
}

function callNativeConsoleMethod(originalMethod, args = []) {
    if (typeof originalMethod !== 'function') return undefined;
    const normalizedArgs = Array.isArray(args) ? args : [args];
    try {
        return originalMethod.apply(console, normalizedArgs);
    } catch (_) {
        try {
            return Function.prototype.apply.call(originalMethod, console, normalizedArgs);
        } catch (_) {
            return undefined;
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
        sourceKind: sourceMeta.sourceKind,
        observedValueType: typeof rawValue
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

function unregisterDynamicTaintSource(key) {
    if (!key) return;
    delete window.__IAST_TAINTED__?.[key];
    delete window.__IAST_TAINT_META__?.[key];
    delete window.__IAST_TAINT_GRAPH__?.[key];
}

function collectPrimaryTaintMatch(values = []) {
    for (const candidate of values) {
        const serialized = safeSerializeValue(candidate).trim();
        if (!serialized) continue;
        const match = matchesTaint(serialized);
        if (!match) continue;
        const sources = normalizeTaintedSources(match.allSources || [], match.raw || serialized);
        if (!sources.length) continue;
        return {
            value: serialized,
            match,
            sources,
            primarySource: sources[0]
        };
    }
    return null;
}

function getWrappedMessageHandler(listener, wrapKey, wrapperFactory) {
    if (typeof listener !== 'function') return listener;
    if (!IAST_MESSAGE_HANDLER_WRAPS) return wrapperFactory(listener);
    let entry = IAST_MESSAGE_HANDLER_WRAPS.get(listener);
    if (!entry) {
        entry = Object.create(null);
        IAST_MESSAGE_HANDLER_WRAPS.set(listener, entry);
    }
    if (!entry[wrapKey]) {
        entry[wrapKey] = wrapperFactory(listener);
    }
    return entry[wrapKey];
}

function getIastMessageTargetLabel(target, prefix = 'target') {
    if (!target || typeof target !== 'object') return prefix;
    if (IAST_MESSAGE_TARGET_LABELS?.has(target)) {
        return IAST_MESSAGE_TARGET_LABELS.get(target);
    }
    const explicit = safeSerializeValue(
        target.name
        || target.label
        || target.id
        || target.scriptURL
        || target.url
        || target.__ptk_iast_worker_url__
        || ''
    ).trim();
    const label = explicit || `${prefix}-${++IAST_MESSAGE_TARGET_SEQ}`;
    IAST_MESSAGE_TARGET_LABELS?.set(target, label);
    return label;
}

function isIastInternalMessagePayload(data) {
    if (!data || typeof data !== 'object') return false;
    if (data.ptk_iast || data.ptk_ws || [
        'ptk-automation',
        'ptk-extension',
        'ptk-spa-net',
        'ptk-spa',
        'ptk-leak',
        'ptk-leak-set',
        'ptk-pmtest',
        'ptk-xss'
    ].includes(data.source)) return true;
    return typeof data.channel === 'string' && data.channel.startsWith('ptk_');
}

function isHiddenFrameTarget(targetName) {
    const name = safeSerializeValue(targetName).trim();
    if (!name || !document?.querySelectorAll) return false;
    const frames = Array.from(document.querySelectorAll('iframe, frame'));
    const frame = frames.find((entry) => entry?.name === name);
    if (!frame) return false;
    const style = window.getComputedStyle ? window.getComputedStyle(frame) : null;
    if (style && (style.display === 'none' || style.visibility === 'hidden')) {
        return true;
    }
    const width = Number(frame.offsetWidth || frame.clientWidth || 0);
    const height = Number(frame.offsetHeight || frame.clientHeight || 0);
    return width === 0 || height === 0;
}

function getFormSubmitTarget(form, submitter = null) {
    const submitterAction = safeSerializeValue(submitter?.formAction).trim();
    const formAction = safeSerializeValue(form?.action || form?.getAttribute?.('action')).trim();
    return submitterAction || formAction || null;
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

function isTopLevelPathSegmentSource(source) {
    const key = String(source?.key || source?.source || '');
    return /^path:segment:0(?::|$)/.test(key);
}

function isPathSegmentSource(source) {
    const key = String(source?.key || source?.source || '');
    return /^path:segment:\d+(?::|$)/.test(key);
}

function isDeeperPathSegmentSource(source) {
    const key = String(source?.key || source?.source || '');
    const match = key.match(/^path:segment:(\d+)(?::|$)/);
    return Boolean(match && Number(match[1]) > 0);
}

function isRouteNamespaceSource(source) {
    const key = String(source?.key || source?.source || '');
    return key === 'path:pathname'
        || key === 'route:client'
        || key === 'history:state'
        || isPathSegmentSource(source);
}

function shouldSuppressTopLevelPathSegmentDomMutation(sinkId, sources) {
    if (sinkId !== 'dom.mutation') return false;
    if (!Array.isArray(sources) || !sources.length) return false;
    const hasTopLevelSegment = sources.some((source) => isTopLevelPathSegmentSource(source));
    if (!hasTopLevelSegment) return false;
    const hasSpecificRouteSegment = sources.some((source) => isDeeperPathSegmentSource(source));
    if (hasSpecificRouteSegment) return false;
    return sources.every((source) => isRouteNamespaceSource(source));
}

function isModulesLoadedBootstrapDomMutation(context) {
    const reason = String(context?.bootstrapReason || context?.sink || '').toLowerCase();
    return reason === 'modules_loaded';
}

function shouldSuppressModulesLoadedRouteDomMutation(sinkId, context, sources) {
    if (sinkId !== 'dom.mutation') return false;
    if (!isModulesLoadedBootstrapDomMutation(context)) return false;
    if (!Array.isArray(sources) || !sources.length) return false;
    return sources.every((source) => isRouteNamespaceSource(source));
}

function isFunctionCodeExecutionSink(sinkId) {
    return sinkId === 'code.function.constructor' || sinkId === 'code.function.apply';
}

function isLowSignalPlainSourceValue(value) {
    if (value == null) return false;
    const trimmed = String(value).trim();
    if (!trimmed || trimmed.length > 24) return false;
    return /^[A-Za-z_$][\w$.-]*$/.test(trimmed);
}

function isLowSignalFunctionCodeSource(source) {
    if (!source || typeof source !== 'object') return false;
    const key = String(source.key || source.source || '');
    const rawValue = source.value != null ? source.value : source.raw;
    if (!isLowSignalPlainSourceValue(rawValue)) return false;
    if (isPathSegmentSource(source)) return true;
    return key.startsWith('query:')
        || key.startsWith('hash:param:')
        || key.startsWith('body:param:');
}

function shouldSuppressLowSignalFunctionCodeMatch(sinkId, sources) {
    if (!isFunctionCodeExecutionSink(sinkId)) return false;
    if (!Array.isArray(sources) || !sources.length) return false;
    return sources.every((source) => isLowSignalFunctionCodeSource(source));
}

function shouldSuppressForSanitizer(ruleEntry, value, observedSanitizers = null) {
    const ruleMeta = ruleEntry?.ruleMeta || {};
    const allowed = Array.isArray(ruleEntry.sanitizersAllowed)
        ? ruleEntry.sanitizersAllowed
        : (Array.isArray(ruleMeta.sanitizersAllowed) ? ruleMeta.sanitizersAllowed : []);
    if (!allowed.length) return { suppress: false, observed: [] };
    const observed = (observedSanitizers || getSanitizersForValue(value)).filter(id => allowed.includes(id));
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

function isPlaywrightUtilityScriptEvaluation(trace) {
    if (!trace) return false;
    const frames = String(trace).split('\n').slice(1).map(line => line.trim()).filter(Boolean).filter(line => {
        if (line.includes('chrome-extension://') || line.includes('moz-extension://')) return false;
        if (line.includes('ptk/content/iast.js')) return false;
        return true;
    });
    return frames.length > 0 && frames.every(line => /\bUtilityScript(?:\.|<)/.test(line));
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

function buildFindingDedupKey({ ruleId, sinkId, sourceKey, location, elementId, attribute, transportCarrierKey }) {
    return [
        ruleId || '',
        sinkId || '',
        sourceKey || '',
        location || '',
        elementId || '',
        attribute || '',
        transportCarrierKey || ''
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
        scheme: target.scheme,
        urlValidation: buildUrlValidationEvidence(rawUrl)
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

function isIgnorableWebSocketSendError(error) {
    const message = String(error?.message || error || '');
    const name = String(error?.name || '');
    return (
        name === 'InvalidStateError'
        || /CLOSING or CLOSED state/i.test(message)
        || /CONNECTING state/i.test(message)
        || /still in connecting state/i.test(message)
    );
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
    return null;
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

function isIastTransportSink(sinkId) {
    const normalizedSinkId = String(sinkId || '').trim();
    return normalizedSinkId.startsWith('http.') || normalizedSinkId.startsWith('realtime.');
}

function normalizeIastTransportPath(pathname) {
    const path = String(pathname || '/').split('/').map((segment) => {
        if (!segment) return '';
        if (/^\d+$/.test(segment)) return ':id';
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(segment)) return ':uuid';
        if (segment.length >= 24 && /^[a-z0-9_-]+$/i.test(segment) && /\d/.test(segment)) return ':token';
        return segment.slice(0, 96);
    }).join('/');
    return (path || '/').slice(0, 384);
}

function normalizeIastTransportQuery(searchParams) {
    const names = [];
    try {
        for (const name of searchParams.keys()) {
            const normalizedName = String(name || '').trim().slice(0, 64);
            if (normalizedName) names.push(normalizedName);
        }
    } catch (_) { }
    const boundedNames = Array.from(new Set(names)).sort().slice(0, 16);
    return boundedNames.length
        ? `?keys=${boundedNames.map((name) => encodeURIComponent(name)).join(',')}`
        : '';
}

function buildIastTransportCarrierKey(sinkId, context = {}, baseUrl = window.location.href) {
    if (!isIastTransportSink(sinkId)) return null;
    const method = String(context.method || '').trim().toUpperCase().slice(0, 16);
    const headerName = String(context.headerName || '').trim().toLowerCase().slice(0, 96);
    const rawUrl = context.destUrl
        || context?.networkTarget?.url
        || context.requestUrl
        || context.url
        || context.destOrigin
        || context?.networkTarget?.origin
        || '';
    let destination = '';
    if (rawUrl) {
        try {
            const parsed = new URL(String(rawUrl), baseUrl);
            const queryShape = normalizeIastTransportQuery(parsed.searchParams);
            destination = `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}${normalizeIastTransportPath(parsed.pathname)}${queryShape}`;
        } catch (_) {
            destination = String(rawUrl).split(/[?#]/, 1)[0].slice(0, 384);
        }
    }
    return ['carrier-v1', String(sinkId || '').trim(), method, destination, headerName].join('|').slice(0, 640);
}

function buildNetworkDedupKey({ transportCarrierKey, location }) {
    if (!transportCarrierKey || !location) return null;
    return ['net', transportCarrierKey, location].join('|');
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

function shouldUseActiveElementForIastSink(sinkId) {
    const normalizedSinkId = String(sinkId || '').trim();
    if (!normalizedSinkId) return true;
    return !normalizedSinkId.startsWith('http.')
        && !normalizedSinkId.startsWith('realtime.');
}

function resolveIastSinkElement(sinkId, contextElement, activeElement = null) {
    if (typeof contextElement !== 'undefined') return contextElement;
    return shouldUseActiveElementForIastSink(sinkId) ? (activeElement || null) : null;
}

function maybeReportTaintedValue(value, info = {}, contextExtras = {}, matchOverride = null, options = {}) {
    if (IAST_OBSERVATION_STOPPED && !IAST_OBSERVATION_SETTLING) return;
    if (__IAST_DISABLE_HOOKS__) return false;
    const context = Object.assign({ value }, contextExtras);
    const sinkId = info.sinkId || info.sink || null;
    const match = matchOverride || matchesTaint(value);
    const taintEntry = getTaintEntry(value);
    const taintedSources = match ? normalizeTaintedSources(match.allSources, match.raw) : [];
    const operation = match?.observationOperation || captureIastOperation(sinkId, context);
    const heuristicDecision = evaluateSinkHeuristics(value, info, context, taintedSources);
    if (heuristicDecision.skip) return false;
    if (!match && !taintEntry) return false;
    if (typeof context.element === 'undefined') {
        context.element = resolveIastSinkElement(sinkId, context.element, document?.activeElement || null);
    }
    const location = window.location.href;
    if (!context.location) {
        context.location = location;
    }
    const transportCarrierKey = buildIastTransportCarrierKey(sinkId, context, location);
    if (transportCarrierKey) {
        context.transportCarrierKey = transportCarrierKey;
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
    const sourceFlows = Object.create(null);
    taintedSources.forEach(source => { sourceFlows[buildIastSourceBindingKey(source)] = buildIastSourceFlow(source, sinkMeta); });
    if (flow.length) {
        context.flow = flow;
    }
    const observation = {
        value, info, context, sinkId, match, taintEntry, taintedSources,
        heuristicDecision, flow, sourceFlows, operation, location, transportCarrierKey
    };
    if (!IAST_MODULES || options.deferPublication === true) {
        // Freeze the original observation, not a partially classified report.
        // The same rule/source/precision path runs once rules become available.
        // No target code or source collector is replayed at flush time.
        try {
            const sourceMetadata = Object.create(null);
            taintedSources.forEach((source) => {
                if (source?.key) sourceMetadata[source.key] = {
                    observedValueType: getTaintMetaEntry(source.key)?.observedValueType
                };
            });
            const snapshot = withoutHooks(() => {
                // Enrichment belongs to publication, not qualification: adding
                // a node ID here must not change the existing SMART dedup key.
                const enriched = enrichContext(context);
                const elementContext = {};
                ['tagName', 'elementId', 'elementClasses', 'domPath', 'elementOuterHTML'].forEach((key) => {
                    if (Object.prototype.hasOwnProperty.call(enriched, key)) elementContext[key] = enriched[key];
                });
                const qualificationContext = Object.assign({}, context);
                delete qualificationContext.element;
                delete qualificationContext.target;
                const immutableOperation = Object.assign({}, operation);
                delete immutableOperation.htmlRelationshipAdmission;
                return structuredClone(Object.assign({}, observation, {
                    operation: immutableOperation,
                    context: qualificationContext,
                    sinkArgs: buildSinkArgs(context),
                    observedSanitizers: getSanitizersForValue(value),
                    sourceMetadata,
                    publication: {
                        location,
                        routing: buildRoutingMeta(),
                        attackId: window.__PTK_CURRENT_ATTACK_ID__ || null,
                        timestamp: Date.now(),
                        trace: captureStackTrace(`Sink: ${info.type || sinkId || 'iast_sink'}`),
                        elementTagName: context.element?.tagName || null,
                        elementContext
                    }
                }));
            });
            // Only admission accounting is shared between snapshots from one
            // native write. Source/value/site evidence remains detached.
            if (operation.htmlRelationshipAdmission) {
                snapshot.operation.htmlRelationshipAdmission = operation.htmlRelationshipAdmission;
            }
            if (options.deferPublication === true) return snapshot;
            if (!queuePendingIastFindingReport({ sinkObservation: snapshot, document })) {
                window.__PTK_IAST_LAST_REPORT_DEBUG__ = { sinkId, reason: 'pending_observation_limit' };
                return false;
            }
            window.__PTK_IAST_LAST_REPORT_DEBUG__ = {
                sinkId,
                requestedRuleId: info.ruleId || null,
                reason: 'queued_before_modules'
            };
            requestModulesFromBackground();
            return true;
        } catch (_) {
            recordIastObservationGap('pending_snapshot_unavailable', true);
            window.__PTK_IAST_LAST_REPORT_DEBUG__ = { sinkId, reason: 'pending_snapshot_unavailable' };
            return false;
        }
    }
    return qualifyIastSinkObservation(observation);
}

function qualifyIastSinkObservation(observation) {
    if (__IAST_DISABLE_HOOKS__ || !IAST_MODULES) return false;
    const {
        value, info, context, sinkId, match, taintEntry, taintedSources,
        heuristicDecision, flow, sourceFlows = null, operation = captureIastOperation(sinkId, context), location, transportCarrierKey, publication = null,
        sourceMetadata = null
    } = observation;
    const explicitRule = info.ruleId ? getIastRuleByRuleId(info.ruleId) : null;
    const sinkCandidates = sinkId ? getIastRulesBySinkId(sinkId) : [];
    // A browser-observed navigation has already been classified to one concrete
    // sink identity. Keep that identity exclusive so one completed navigation
    // cannot create competing assign/replace findings in comprehensive mode.
    const exclusiveObservedNavigation = explicitRule
        && context?.navigationCorrelation?.deferUntilObserved === true;
    const candidates = exclusiveObservedNavigation
        ? [explicitRule]
        : explicitRule
        ? [explicitRule, ...sinkCandidates.filter((entry) => entry && entry.ruleId !== explicitRule.ruleId)]
        : sinkCandidates;
    window.__PTK_IAST_LAST_REPORT_DEBUG__ = {
        sinkId,
        requestedRuleId: info.ruleId || null,
        candidateRuleIds: candidates.map((entry) => entry?.ruleId || null),
        taintedSourceKinds: taintedSources.map((src) => src?.sourceKind || src?.kind || null)
    };
    if (!candidates.length) return false;
    const sinkArgs = observation.sinkArgs || buildSinkArgs(context);
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
    const transportCarrierIsPrimary = Boolean(transportCarrierKey) && sinkId !== 'http.image.src';
    // Enumerate independently eligible relationships before SMART deduplication.
    // A weak generic path match must not consume a stronger secondary rule.
    const pairs = [];
    for (const ruleEntry of candidates) {
        for (const source of sanitizeSourcesForRule(ruleEntry, taintedSources)) {
            const relationTaint = source.sourceId && source.sourceId === taintEntry?.taint?.sourceId ? taintEntry : null;
            const grade = classifyIastShadowSource(value, source, relationTaint);
            pairs.push({ ruleEntry, source, strength: IAST_SHADOW_GRADE_ORDER[grade.effectiveGrade] || 0,
                relationStrength: IAST_SHADOW_GRADE_ORDER[grade.valueRelation] || 0 });
        }
    }
    pairs.sort((a, b) => b.strength - a.strength || b.relationStrength - a.relationStrength
        || String(a.ruleEntry.ruleId).localeCompare(String(b.ruleEntry.ruleId)) || String(a.source.key).localeCompare(String(b.source.key)));
    let reported = false;
    let admitted = 0;
    for (const pair of pairs) {
        const ruleEntry = pair.ruleEntry;
        const primarySource = pair.source;
        const filteredSources = [primarySource];
        if (typeof primarySource.key !== 'string' || primarySource.key.length > 512) {
            recordIastObservationGap('source_key_size_limit', true);
            continue;
        }
        const conditions = ruleEntry.conditions || {};
        if (conditions.requiresFramework && context.framework !== conditions.requiresFramework) {
            continue;
        }
        if (conditions.excludesFramework && context.framework === conditions.excludesFramework) {
            continue;
        }
        if (Array.isArray(conditions.requiresAngularServices)
            && !conditions.requiresAngularServices.includes(context.angularService)) {
            continue;
        }
        if (conditions.requiresCrossOrigin) {
            const reqUrl = context.requestUrl || context.url || context.destUrl || null;
            if (!isCrossOriginRequest(reqUrl)) {
                continue;
            }
        }
        if (!filteredSources.length) {
            window.__PTK_IAST_LAST_REPORT_DEBUG__ = Object.assign({}, window.__PTK_IAST_LAST_REPORT_DEBUG__ || {}, {
                ruleId: ruleEntry.ruleId,
                reason: 'filtered_sources_empty',
                allowedSources: Array.isArray(ruleEntry.sources) ? ruleEntry.sources.slice() : [],
                taintedSourceKinds: taintedSources.map((src) => src?.sourceKind || src?.kind || null)
            });
            continue;
        }
        if (shouldSuppressTopLevelPathSegmentDomMutation(sinkId, filteredSources)) {
            window.__PTK_IAST_LAST_REPORT_DEBUG__ = Object.assign({}, window.__PTK_IAST_LAST_REPORT_DEBUG__ || {}, {
                ruleId: ruleEntry.ruleId,
                reason: 'top_level_path_segment_dom_mutation_suppressed',
                taintedSourceKeys: filteredSources.map((src) => src?.key || src?.source || null)
            });
            continue;
        }
        if (shouldSuppressModulesLoadedRouteDomMutation(sinkId, context, filteredSources)) {
            window.__PTK_IAST_LAST_REPORT_DEBUG__ = Object.assign({}, window.__PTK_IAST_LAST_REPORT_DEBUG__ || {}, {
                ruleId: ruleEntry.ruleId,
                reason: 'modules_loaded_route_dom_mutation_suppressed',
                taintedSourceKeys: filteredSources.map((src) => src?.key || src?.source || null)
            });
            continue;
        }
        if (shouldSuppressLowSignalFunctionCodeMatch(sinkId, filteredSources)) {
            window.__PTK_IAST_LAST_REPORT_DEBUG__ = Object.assign({}, window.__PTK_IAST_LAST_REPORT_DEBUG__ || {}, {
                ruleId: ruleEntry.ruleId,
                reason: 'low_signal_function_code_match_suppressed',
                taintedSourceKeys: filteredSources.map((src) => src?.key || src?.source || null)
            });
            continue;
        }
        const sanitizerCheck = shouldSuppressForSanitizer(ruleEntry, value, observation.observedSanitizers);
        if (sanitizerCheck.suppress) continue;
        const sourceKey = primarySource?.key || null;
        const relationTaint = primarySource.sourceId && primarySource.sourceId === taintEntry?.taint?.sourceId ? taintEntry : null;
        const pairMatch = { source: sourceKey, raw: primarySource.raw, allSources: filteredSources };
        const pairFlow = sourceFlows?.[buildIastSourceBindingKey(primarySource)] || (publication ? [] : buildIastSourceFlow(primarySource, { sinkId, sink: info.sink || sinkId, location, value }));
        const nextContext = Object.assign({}, context, {
            taintedSources: filteredSources,
            sinkArgs,
            flow: pairFlow
        });
        const matchInfo = relationTaint
            ? { matchType: relationTaint.matchType || 'id', confidence: relationTaint.matchType === 'id' ? 95 : 80 }
            : { matchType: 'substring', confidence: 60 };
        nextContext.match = matchInfo;
        nextContext.sourceRefs = relationTaint
            ? sourceRefsFromTaint(relationTaint.taint)
            : sourceRefsFromSubstring(filteredSources);
        applySourceSpecificSignals(nextContext, primarySource, sinkId);
        if (sanitizerCheck.observed.length) {
            nextContext.sanitizerObserved = sanitizerCheck.observed;
            nextContext.confidencePenalty = 25;
        }
        const pairHeuristic = evaluateSinkHeuristics(value, info, nextContext, filteredSources);
        if (pairHeuristic.skip) continue;
        if (pairHeuristic.downgrade) {
            applyHeuristicDowngrade(nextContext, pairHeuristic.downgrade);
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
        // Evaluate the selected rule's eligible sources before publication;
        // leave the existing published source, flow and confidence untouched.
        let shadow = null;
        let precisionSeverity = null;
        try {
            shadow = classifyIastShadowFinding(value, filteredSources, pairMatch, relationTaint, pairFlow);
            precisionSeverity = getIastPrecisionSeverityOverride(sinkId, nextContext, filteredSources, shadow, relationTaint, sourceMetadata);
        } catch (_) { }
        const relationshipObservation = buildIastRelationshipObservation(primarySource, value, relationTaint, operation, sinkId);
        if (isIastDirectHtmlSink(sinkId) && precisionSeverity) {
            const existingSeverity = resolveIastEffectiveSeverity({
                override: nextContext.severityOverride || info.severity,
                moduleMeta: ruleEntry.moduleMeta || {}, ruleMeta: ruleEntry.ruleMeta || {}
            });
            const severityOrder = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
            nextContext.severityOverride = severityOrder[existingSeverity] < severityOrder[precisionSeverity]
                ? existingSeverity : precisionSeverity;
            nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
            nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
            nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                reason: IAST_REASON_CODES.FLOW_MATCH,
                confidence: Math.min(nextContext.detection?.confidence || 55, 55),
                details: Object.assign({}, nextContext.detection?.details || {}, {
                    heuristic: 'direct_html_relationship_precision',
                    htmlImpact: nextContext.htmlImpact?.status || 'unknown',
                    impactReason: nextContext.htmlImpact?.reason || 'html_impact_unavailable',
                    sourceReadObserved: primarySource.acquisition === 'instrumented_read',
                    evidenceGrade: relationshipObservation.evidenceGrade
                })
            });
        }
        if (primarySource.acquisition === 'sink_storage_snapshot') {
            nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
            nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
            nextContext.severityOverride = precisionSeverity === 'info' || nextContext.severityOverride === 'info' ? 'info' : 'low';
            nextContext.detection = { reason: IAST_REASON_CODES.STORAGE_VALUE_EQUALITY_OBSERVED,
                dataKind: IAST_DATA_KINDS.UNKNOWN, confidence: 55,
                details: { acquisition: 'sink_storage_snapshot', sourceReadObserved: false, attackerControlEstablished: false } };
        }
        nextContext.observation = relationshipObservation;
        const finalSeverity = nextContext.severityOverride || precisionSeverity || info.severity || null;
        const dedupKey = buildIastRelationshipDedupKey(ruleEntry, primarySource, sinkId, location, nextContext, finalSeverity, relationshipObservation);
        if (isSmart && isCacheHit(IAST_FINDING_DEDUP, dedupKey)) continue;
        if (admitted >= IAST_OBSERVATION_LIMITS.relationships
            || operation.htmlRelationshipAdmission?.admitted >= IAST_OBSERVATION_LIMITS.relationships) {
            recordIastObservationGap('qualified_relationship_limit', true);
            break;
        }
        reportFinding({
            type: info.type || ruleEntry.ruleId || info.sinkId || 'iast_sink',
            sink: info.sink || sinkId || 'iast_sink',
            sinkId,
            ruleId: ruleEntry.ruleId,
            matched: primarySource.raw,
            source: primarySource,
            sources: filteredSources,
            severity: finalSeverity,
            context: nextContext
        }, publication);
        admitted += 1;
        if (operation.htmlRelationshipAdmission) operation.htmlRelationshipAdmission.admitted += 1;
        try { recordIastShadowEvidence(shadow); } catch (_) { }
        window.__PTK_IAST_LAST_REPORT_DEBUG__ = Object.assign({}, window.__PTK_IAST_LAST_REPORT_DEBUG__ || {}, {
            ruleId: ruleEntry.ruleId,
            reason: 'reported',
            filteredSourceKinds: filteredSources.map((src) => src?.sourceKind || src?.kind || null)
        });
        reported = true;
        if (isSmart && nextContext?.navigationCorrelation?.deferUntilObserved !== true) {
            markCache(IAST_FINDING_DEDUP, dedupKey);
        }
    }
    emitIastObservationState();
    return reported;
}


// Inline-event scanner helper
function scanInlineEvents(htmlFragment) {
    let m;
    if (isTrustedTypesHtmlRestricted()) return;
    try {
        const normalizedMarkup = coerceDomParserMarkup(htmlFragment);
        const doc = withInternalHtmlParser(() => new DOMParser().parseFromString(normalizedMarkup, 'text/html'));
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
        // Playwright serializes its own page-evaluation helpers through
        // UtilityScript. Those helpers are scanner/test control code, not
        // target application execution. Suppress only stacks made entirely of
        // UtilityScript frames; an application frame keeps the sink visible.
        if (isPlaywrightUtilityScriptEvaluation((new Error('PTK eval caller')).stack)) {
            return originalEval.call(this, code);
        }
        runIastHookGuard('hook.code.exec', 'window.eval.pre', () => {
            const m = matchesIastSinkTaint(code, 'code.eval', { element: document?.activeElement || null });
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
        });
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
            runIastHookGuard('hook.code.exec', 'Function.construct.pre', () => {
                const body = args.slice(-1)[0] + '';
                const m = matchesIastSinkTaint(body, 'code.function.constructor', { element: document?.activeElement || null });
                if (m) {
                    const angularContext = getActiveAngularExecutionContext();
                    maybeReportTaintedValue(body, {
                        type: 'xss-via-Function',
                        sink: 'Function.constructor',
                        sinkId: 'code.function.constructor'
                    }, Object.assign({
                        element: document?.activeElement || null,
                        code: body
                    }, angularContext || {}), m);
                }
            });
            return Reflect.construct(target, args, newTarget);
        },
        apply(target, thisArg, args) {
            if (!isHookGroupEnabled('hook.code.exec')) {
                return Reflect.apply(target, thisArg, args);
            }
            runIastHookGuard('hook.code.exec', 'Function.apply.pre', () => {
                const body = args.slice(-1)[0] + '';
                const m = matchesIastSinkTaint(body, 'code.function.apply', { element: document?.activeElement || null });
                if (m) {
                    const angularContext = getActiveAngularExecutionContext();
                    maybeReportTaintedValue(body, {
                        type: 'xss-via-Function',
                        sink: 'Function.apply',
                        sinkId: 'code.function.apply'
                    }, Object.assign({ element: document?.activeElement || null, code: body }, angularContext || {}), m);
                }
            });
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
    if (isTrustedTypesHtmlRestricted()) return;
    const isHtmlParsingMimeType = (mimeType) => {
        const normalized = String(mimeType || '').trim().toLowerCase();
        return normalized === 'text/html' || normalized === 'application/xhtml+xml' || normalized === 'image/svg+xml';
    };

    if (typeof DOMParser !== 'undefined' && DOMParser.prototype && typeof DOMParser.prototype.parseFromString === 'function') {
        const origParseFromString = DOMParser.prototype.parseFromString;
        DOMParser.prototype.parseFromString = function (markup, mimeType, ...rest) {
            const normalizedMarkup = runIastHookGuard(
                'hook.dom.htmlParsers',
                'DOMParser.parseFromString.normalize',
                () => coerceDomParserMarkup(markup),
                String(markup ?? ''),
                { respectEnabled: false }
            );
            runIastHookGuard('hook.dom.htmlParsers', 'DOMParser.parseFromString.pre', () => {
                if (isInternalHtmlParserActive() || !isHtmlParsingMimeType(mimeType)) {
                    return;
                }
                const payload = normalizedMarkup;
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
            });
            return origParseFromString.call(this, normalizedMarkup, mimeType, ...rest);
        };
    }

    if (typeof Range !== 'undefined' && Range.prototype && typeof Range.prototype.createContextualFragment === 'function') {
        const origCreateContextualFragment = Range.prototype.createContextualFragment;
        Range.prototype.createContextualFragment = function (markup) {
            runIastHookGuard('hook.dom.htmlParsers', 'Range.createContextualFragment.pre', () => {
                if (isInternalHtmlParserActive()) {
                    return;
                }
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
            });
            return origCreateContextualFragment.call(this, markup);
        };
    }

    if (typeof Element !== 'undefined' && Element.prototype && typeof Element.prototype.setHTMLUnsafe === 'function') {
        const origSetHTMLUnsafe = Element.prototype.setHTMLUnsafe;
        Element.prototype.setHTMLUnsafe = function (markup, ...rest) {
            runIastHookGuard('hook.dom.htmlParsers', 'Element.setHTMLUnsafe.pre', () => {
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
            });
            return origSetHTMLUnsafe.call(this, markup, ...rest);
        };
    }

    if (typeof ShadowRoot !== 'undefined' && ShadowRoot.prototype && typeof ShadowRoot.prototype.setHTMLUnsafe === 'function') {
        const origShadowSetHTMLUnsafe = ShadowRoot.prototype.setHTMLUnsafe;
        ShadowRoot.prototype.setHTMLUnsafe = function (markup, ...rest) {
            runIastHookGuard('hook.dom.htmlParsers', 'ShadowRoot.setHTMLUnsafe.pre', () => {
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
            });
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
                runIastHookGuard('hook.dom.urlAttributes', 'Document.domain.setter', () => {
                    const m = matchesTaint(value);
                    if (m) {
                        const binding = buildRuleBinding({ sinkId: 'document.domain', fallbackType: 'document-domain' });
                        maybeReportTaintedValue(value, binding, { value }, m);
                    }
                });
                return desc.set.call(this, value);
            }
        });
    }
})();


// document.write
; (function () {
    const origWrite = document.write;
    const parseHtml = createIastDirectHtmlParser();
    IAST_DIRECT_HTML_PARSER = parseHtml;

    document.write = function (...args) {
        if (!isHookGroupEnabled('hook.dom.documentWrite') || args.some(value => typeof value !== 'string')) {
            return origWrite.apply(this, args);
        }
        const html = args.join('');
        const operationMatch = matchesIastSinkTaint(html, 'document.write', { element: document?.activeElement || null });
        const snapshots = [];
        const captureReport = (value, info, context, match) => {
            // A late/unverified entry has no private document-start timer.
            // Keep its original synchronous publication path unchanged.
            if (!IAST_DEFERRED_WRITE_TIMER) return maybeReportTaintedValue(value, info, context, match);
            const snapshot = maybeReportTaintedValue(value, info, context, match, { deferPublication: true });
            if (snapshot) snapshots.push(snapshot);
        };
        runIastHookGuard('hook.dom.documentWrite', 'document.write.analysis', () => {
            if (!operationMatch && !matchesTaint(html)) return;
            const operation = operationMatch?.observationOperation || captureIastOperation('document.write', {});
            operation.htmlRelationshipAdmission = { admitted: 0 };
            const analysis = inspectIastDirectHtmlImpact(html, 'document.write', {}, parseHtml);
            const htmlImpact = { status: analysis.status, reason: analysis.reason };
            if (!allowHeavyHook()) {
                const m = operationMatch || matchesTaint(html);
                if (m) {
                    captureReport(html, {
                        type: 'xss-via-document.write',
                        sink: 'document.write',
                        sinkId: 'document.write'
                    }, { value: html, element: document?.activeElement || null, htmlImpact }, m);
                }
                return;
            }
            try {
                const reported = traverseAndReport(analysis, 'document.write', operation, captureReport);
                const directMatch = operationMatch || matchesTaint(html);
                const reportedBindings = new Set((analysis.reports || []).flatMap(({ candidate }) =>
                    normalizeTaintedSources((candidate.match?.allSources || []).slice(0, IAST_OBSERVATION_LIMITS.relationships),
                        candidate.match?.raw).map(buildIastSourceBindingKey)));
                const remainingSources = reported ? (directMatch?.allSources || []).filter(source =>
                    !reportedBindings.has(buildIastSourceBindingKey(source))) : directMatch?.allSources;
                if (!reported || remainingSources?.length) {
                    const firstRemaining = remainingSources?.[0];
                    const m = reported && firstRemaining ? Object.assign({}, directMatch, {
                        source: firstRemaining.key || firstRemaining.source,
                        raw: firstRemaining.raw, allSources: remainingSources
                    }) : directMatch;
                    if (m) m.observationOperation = operation;
                    if (m) {
                        captureReport(html, {
                            type: 'xss-via-document.write',
                            sink: 'document.write',
                            sinkId: 'document.write'
                        }, { value: html, element: document?.activeElement || null, htmlImpact, fallbackReason: 'direct_tainted_html_sink' }, m);
                    }
                }
            } catch (_) {
                const m = operationMatch || matchesTaint(html);
                if (m) {
                    captureReport(html, {
                        type: 'xss-via-document.write',
                        sink: 'document.write',
                        sinkId: 'document.write'
                    }, { value: html, element: document?.activeElement || null, htmlImpact }, m);
                }
            }
        });
        const entry = reserveDeferredIastWriteReports(snapshots);
        try {
            const result = origWrite.apply(this, args);
            completeDeferredIastWriteReports(entry);
            return result;
        } catch (error) {
            discardDeferredIastWriteReports(entry);
            throw error;
        }
    };

    // Helper: walk a DOM subtree and report the first taint per node
    function traverseAndReport(analysis, sink, operation, captureReport) {
        const seen = new Set();  // avoid duplicates
        for (const { node, candidate, htmlImpact } of analysis.reports || []) {
            if (candidate && !seen.has(node)) {
                captureReport(candidate.value, {
                    type: 'xss-via-document.write',
                    sink: sink,
                    sinkId: 'document.write'
                }, {
                    value: candidate.value,
                    element: node,
                    domPath: getDomPath(node),
                    tag: candidate.tag,
                    attribute: candidate.attribute,
                    candidateType: candidate.candidateType,
                    htmlImpact
                }, Object.assign({}, candidate.match, { observationOperation: operation }));
                seen.add(node);
            }
        }
        return seen.size;
    }
})();

// innerHTML/outerHTML
if (!isTrustedTypesHtmlRestricted()) {
    const parseHtml = IAST_DIRECT_HTML_PARSER;
    ['innerHTML', 'outerHTML'].forEach(prop => {
        const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
        Object.defineProperty(Element.prototype, prop, {
            get: desc.get,
            set(htmlString) {
                if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.htmlAssignments') || typeof htmlString !== 'string') {
                    return desc.set.call(this, htmlString);
                }
                const operationMatch = matchesIastSinkTaint(htmlString, prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML', { element: this, domPath: getDomPath(this) });
                runIastHookGuard('hook.dom.htmlAssignments', `Element.${prop}.analysis`, () => {
                    if (typeof htmlString === 'string' && !operationMatch && !matchesTaint(htmlString)) return;
                    const analysis = inspectIastDirectHtmlImpact(htmlString, prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML', { element: this }, parseHtml);
                    const htmlImpact = { status: analysis.status, reason: analysis.reason };
                    if (!allowHeavyHook()) {
                        const m = operationMatch || matchesTaint(htmlString);
                        if (m) {
                            maybeReportTaintedValue(htmlString, {
                                type: `xss-via-${prop}`,
                                sink: prop,
                                sinkId: prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML'
                            }, { value: htmlString, element: this, domPath: getDomPath(this), htmlImpact }, m);
                        }
                        return;
                    }
                    try {
                        const frag = analysis.root;
                        const reported = typeof traverseAndReport === 'function'
                            ? traverseAndReport(frag, `xss-via-${prop}`)
                            : 0;
                        if (!reported) {
                            const m = operationMatch || matchesTaint(htmlString);
                            if (m) {
                                maybeReportTaintedValue(htmlString, {
                                    type: `xss-via-${prop}`,
                                    sink: prop,
                                    sinkId: prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML'
                                }, { value: htmlString, element: this, domPath: getDomPath(this), htmlImpact, fallbackReason: 'direct_tainted_html_sink' }, m);
                            }
                        }
                    } catch (_) {
                        const m = operationMatch || matchesTaint(htmlString);
                        if (m) {
                            maybeReportTaintedValue(htmlString, {
                                type: `xss-via-${prop}`,
                                sink: prop,
                                sinkId: prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML'
                            }, { value: htmlString, element: this, domPath: getDomPath(this), htmlImpact }, m);
                        }
                    }
                });
                return desc.set.call(this, htmlString);
            },
            configurable: true,
            enumerable: desc.enumerable
        });
    });
}


// insertAdjacentHTML
; (function () {
    if (isTrustedTypesHtmlRestricted()) return;
    const origInsert = Element.prototype.insertAdjacentHTML;
    const parseHtml = IAST_DIRECT_HTML_PARSER;
    Element.prototype.insertAdjacentHTML = function (pos, htmlString) {
        if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.htmlAssignments')
            || typeof htmlString !== 'string' || typeof pos !== 'string') {
            return origInsert.call(this, pos, htmlString);
        }
        const operationMatch = matchesIastSinkTaint(htmlString, 'dom.insertAdjacentHTML', { element: this, position: pos });
        runIastHookGuard('hook.dom.htmlAssignments', 'Element.insertAdjacentHTML.analysis', () => {
            if (typeof htmlString === 'string' && !operationMatch && !matchesTaint(htmlString)) return;
            const analysis = inspectIastDirectHtmlImpact(htmlString, 'dom.insertAdjacentHTML', { element: this, position: pos }, parseHtml);
            const htmlImpact = { status: analysis.status, reason: analysis.reason };
            if (!allowHeavyHook()) {
                const m = operationMatch || matchesTaint(htmlString);
                if (m) {
                    maybeReportTaintedValue(htmlString, {
                        type: 'xss-via-insertAdjacentHTML',
                        sink: 'insertAdjacentHTML',
                        sinkId: 'dom.insertAdjacentHTML'
                    }, { value: htmlString, element: this, position: pos, htmlImpact }, m);
                }
                return;
            }
            try {
                const frag = analysis.root;
                const reported = typeof traverseAndReport === 'function'
                    ? traverseAndReport(frag, `insertAdjacentHTML(${pos})`)
                    : 0;
                if (!reported) {
                    const m = operationMatch || matchesTaint(htmlString);
                    if (m) {
                        maybeReportTaintedValue(htmlString, {
                            type: 'xss-via-insertAdjacentHTML',
                            sink: 'insertAdjacentHTML',
                            sinkId: 'dom.insertAdjacentHTML'
                        }, { value: htmlString, element: this, position: pos, htmlImpact, fallbackReason: 'direct_tainted_html_sink' }, m);
                    }
                }
            } catch (_) {
                const m = operationMatch || matchesTaint(htmlString);
                if (m) {
                    maybeReportTaintedValue(htmlString, {
                        type: 'xss-via-insertAdjacentHTML',
                        sink: 'insertAdjacentHTML',
                        sinkId: 'dom.insertAdjacentHTML'
                    }, { value: htmlString, element: this, position: pos, htmlImpact }, m);
                }
            }
        });
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
        if (name === 'data' && tag === 'object') {
            return resolveDangerousUrlSinkId('dom.attr.src', value) || 'dom.attr.src';
        }
        if (name === 'value' && tag === 'param') {
            const paramName = String(el?.getAttribute?.('name') || el?.name || '').trim().toLowerCase();
            if (/^(?:code|movie|src|url|data)$/.test(paramName)) {
                return resolveDangerousUrlSinkId('dom.attr.src', value) || 'dom.attr.src';
            }
            return null;
        }
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
            if (tag === 'iframe' || tag === 'frame') {
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
        const m = matchesTaint(value);
        if (!m) {
            const reason = hasRecentTaintActivity() ? 'no_taint_match' : 'no_recent_taint';
            window.__PTK_IAST_LAST_ATTR_DEBUG__ = {
                attrName,
                sinkId,
                hookGroup: attrHookGroup,
                reason,
                value: safeSerializeValue(value)
            };
            return;
        }
        const networkContext = buildNetworkContext(value) || {};
        const binding = buildObservedRuleBinding({
            sinkId,
            value,
            match: m,
            context: Object.assign({ value }, networkContext),
            fallbackType: 'dom-attr'
        });
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
        maybeReportTaintedValue(value, binding, Object.assign({
            value,
            attribute: attrName,
            element: el,
            domPath: getDomPath(el)
        }, networkContext), m);
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
                runIastHookGuard(getDomAttributeHookGroupForSink(resolveAttrSinkId(this, prop, value)), `${prop}.setter`, () => {
                    reportAttrSink(this, prop, value);
                });
                return desc.set.call(this, value);
            }
        });
    };

    const origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
        const res = origSetAttribute.apply(this, arguments);
        runIastHookGuard(getDomAttributeHookGroupForSink(resolveAttrSinkId(this, name, value)), 'Element.setAttribute.post', () => {
            reportAttrSink(this, name, value);
        });
        return res;
    };

    if (Element.prototype.setAttributeNS) {
        const origSetAttributeNS = Element.prototype.setAttributeNS;
        Element.prototype.setAttributeNS = function (namespace, name, value) {
            const res = origSetAttributeNS.apply(this, arguments);
            const normalizedName = String(name || '').toLowerCase();
            const attrName = normalizedName === 'xlink:href' || normalizedName === 'href' ? 'href' : name;
            runIastHookGuard(getDomAttributeHookGroupForSink(resolveAttrSinkId(this, attrName, value)), 'Element.setAttributeNS.post', () => {
                reportAttrSink(this, attrName, value);
            });
            return res;
        };
    }

    wrapPropertySetter(HTMLAnchorElement?.prototype, 'href');
    wrapPropertySetter(HTMLAreaElement?.prototype, 'href');
    wrapPropertySetter(typeof HTMLBaseElement !== 'undefined' ? HTMLBaseElement.prototype : null, 'href');
    wrapPropertySetter(HTMLLinkElement?.prototype, 'href');
    wrapPropertySetter(HTMLImageElement?.prototype, 'src');
    wrapPropertySetter(HTMLScriptElement?.prototype, 'src');
    wrapPropertySetter(HTMLIFrameElement?.prototype, 'src');
    wrapPropertySetter(HTMLIFrameElement?.prototype, 'srcdoc');
    wrapPropertySetter(typeof HTMLFrameElement !== 'undefined' ? HTMLFrameElement.prototype : null, 'src');
    wrapPropertySetter(typeof HTMLEmbedElement !== 'undefined' ? HTMLEmbedElement.prototype : null, 'src');
    wrapPropertySetter(typeof HTMLObjectElement !== 'undefined' ? HTMLObjectElement.prototype : null, 'data');
    wrapPropertySetter(typeof HTMLParamElement !== 'undefined' ? HTMLParamElement.prototype : null, 'value');
    wrapPropertySetter(HTMLFormElement?.prototype, 'action');
    wrapPropertySetter(HTMLButtonElement?.prototype, 'formAction');
    wrapPropertySetter(HTMLInputElement?.prototype, 'formAction');
})();

// Form submission sinks
; (function () {
    if (typeof HTMLFormElement === 'undefined' || !HTMLFormElement.prototype) return;

    const reportFormSubmission = (form, submitter, sinkId, sinkLabel) => {
        if (!isHookGroupEnabled('hook.dom.formAttributes')) return;
        const targetValue = getFormSubmitTarget(form, submitter);
        if (!targetValue) return;
        const submitTarget = safeSerializeValue(submitter?.formTarget || form?.target || form?.getAttribute?.('target') || '').trim() || null;
        const hiddenFrameTarget = isHiddenFrameTarget(submitTarget);
        const observedBinding = buildObservedRuleBinding({
            sinkId,
            value: targetValue,
            context: {
                value: targetValue,
                submitterTag: submitter?.tagName || null,
                formTarget: submitTarget,
                hiddenFrameTarget
            },
            fallbackType: 'form-submit'
        });
        maybeReportTaintedValue(targetValue, Object.assign({
            type: 'form-submit',
            sink: sinkLabel
        }, observedBinding), {
            value: targetValue,
            element: form,
            submitterTag: submitter?.tagName?.toLowerCase?.() || null,
            formAction: safeSerializeValue(form?.action || form?.getAttribute?.('action') || '').trim() || null,
            submitterFormAction: safeSerializeValue(submitter?.formAction || '').trim() || null,
            formTarget: submitTarget,
            hiddenFrameTarget,
            method: safeSerializeValue(form?.method || form?.getAttribute?.('method') || null)
        });
    };

    if (typeof HTMLFormElement.prototype.submit === 'function' && !HTMLFormElement.prototype.submit.__ptk_iast_wrapped__) {
        const origSubmit = HTMLFormElement.prototype.submit;
        const wrappedSubmit = function () {
            try {
                reportFormSubmission(this, null, 'form.submit.call', 'HTMLFormElement.submit');
            } catch (_) {
                // ignore form submit instrumentation failures
            }
            return origSubmit.apply(this, arguments);
        };
        wrappedSubmit.__ptk_iast_wrapped__ = true;
        HTMLFormElement.prototype.submit = wrappedSubmit;
    }

    if (typeof HTMLFormElement.prototype.requestSubmit === 'function' && !HTMLFormElement.prototype.requestSubmit.__ptk_iast_wrapped__) {
        const origRequestSubmit = HTMLFormElement.prototype.requestSubmit;
        const wrappedRequestSubmit = function (submitter) {
            try {
                reportFormSubmission(this, submitter || null, 'form.requestSubmit.call', 'HTMLFormElement.requestSubmit');
            } catch (_) {
                // ignore requestSubmit instrumentation failures
            }
            return origRequestSubmit.apply(this, arguments);
        };
        wrappedRequestSubmit.__ptk_iast_wrapped__ = true;
        HTMLFormElement.prototype.requestSubmit = wrappedRequestSubmit;
    }
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
    const HAS_NAVIGATION_OBSERVER = Boolean(
        'navigation' in window && typeof window.navigation?.addEventListener === 'function'
    );
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
    window.__IAST_MARK_NAV_TRIGGER__ = markLocationNavTrigger;

    const LocationProto = typeof Location !== 'undefined' ? Location.prototype : null;

    function observeDirectLocationIntent(value, sinkId, label) {
        if (!isHookGroupEnabled('hook.nav.redirects')) return false;
        const url = safeSerializeValue(value);
        if (!url || !shouldReportNavigationSink(url)) return false;
        const match = matchesTaint(url);
        if (!match) return false;
        const resolvedSinkId = resolveDangerousUrlSinkId(sinkId, url) || sinkId;
        markLocationNavTrigger({
            sinkId: resolvedSinkId,
            sinkLabel: label,
            methodEvidence: 'direct_wrapper'
        });
        if (!HAS_NAVIGATION_OBSERVER) {
            const networkContext = buildNetworkContext(url) || {};
            const observedBinding = buildObservedRuleBinding({
                sinkId: resolvedSinkId,
                value: url,
                match,
                context: Object.assign({ value: url }, networkContext),
                fallbackType: 'dom-url-navigation'
            });
            maybeReportTaintedValue(url, Object.assign({
                type: 'dom-url-navigation',
                sink: label
            }, observedBinding), Object.assign({
                value: url,
                methodEvidence: 'direct_wrapper_without_navigation_api'
            }, captureElementMeta(document?.activeElement || null), networkContext), match);
        }
        return true;
    }

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
                        observeDirectLocationIntent(value, sinkId, label);
                        return desc.set.call(this, value);
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
                    const wrapper = function (...args) {
                        observeDirectLocationIntent(args[0], sinkId, label);
                        return bound(...args);
                    };
                    target[method] = wrapper;
                    if (target[method] !== wrapper) return;
                } else {
                    const wrapper = function (...args) {
                        observeDirectLocationIntent(args[0], sinkId, label);
                        return orig.apply(this, args);
                    };
                    target[method] = wrapper;
                    if (target[method] !== wrapper) return;
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

        let resolvedSinkId = 'nav.window.open';
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
        if (typeof navigation.navigate === 'function') {
            try {
                const originalNavigate = navigation.navigate.bind(navigation);
                const wrappedNavigate = function (url, options) {
                    const payload = safeSerializeValue(url);
                    if (payload && shouldReportRouteControlledNavigationSink(payload) && matchesTaint(payload)
                        && typeof window.__IAST_MARK_NAV_TRIGGER__ === 'function') {
                        window.__IAST_MARK_NAV_TRIGGER__({
                            sinkId: resolveDangerousUrlSinkId('nav.navigation.navigate', payload) || 'nav.navigation.navigate',
                            sinkLabel: 'navigation.navigate',
                            methodEvidence: 'direct_wrapper'
                        });
                    }
                    return originalNavigate(url, options);
                };
                navigation.navigate = wrappedNavigate;
            } catch (_) {
                // The navigate event remains the authoritative fallback.
            }
        }
        navigation.addEventListener('navigate', event => {
            if (!isHookGroupEnabled('hook.nav.redirects')) return;
            const url = safeSerializeValue(event?.destination?.url);
            const navigationType = String(event?.navigationType || '');
            if (!url || event?.downloadRequest != null || event?.formData != null
                || event?.sourceElement || event?.userInitiated === true
                || event?.hashChange === true || !['push', 'replace'].includes(navigationType)) {
                return;
            }
            const recent = typeof window.__IAST_CONSUME_NAV_TRIGGER__ === 'function'
                ? window.__IAST_CONSUME_NAV_TRIGGER__()
                : null;
            const explicitNavigationApi = recent?.sinkId === 'nav.navigation.navigate'
                || String(recent?.sinkId || '').startsWith('nav.navigation.navigate.');
            const reportable = explicitNavigationApi
                ? shouldReportRouteControlledNavigationSink(url)
                : shouldReportNavigationSink(url);
            if (!reportable) return;
            const match = matchesTaint(url);
            if (!match) return;

            const baseSinkId = recent?.sinkId
                || (navigationType === 'replace' ? 'nav.location.replace' : 'nav.location.assign');
            const resolvedSinkId = resolveDangerousUrlSinkId(baseSinkId, url) || baseSinkId;
            const sinkLabel = recent?.sinkLabel
                || (navigationType === 'replace' ? 'location.replace' : 'location.assign-equivalent');
            const networkContext = buildNetworkContext(url) || {};
            const requestUrl = (() => {
                try {
                    const parsed = new URL(url, window.location.href);
                    parsed.hash = '';
                    return parsed.href;
                } catch (_) {
                    return url;
                }
            })();
            const isHttpNavigation = /^https?:/i.test(requestUrl);
            const correlation = {
                deferUntilObserved: isHttpNavigation,
                destination: url,
                requestUrl,
                sourceOrigin: window.location.origin,
                sourceUrl: window.location.href,
                navigationType,
                methodEvidence: recent?.methodEvidence || (navigationType === 'replace'
                    ? 'navigation_api_replace'
                    : 'navigation_api_push_equivalent')
            };
            const binding = buildObservedRuleBinding({
                sinkId: resolvedSinkId,
                value: url,
                match,
                context: Object.assign({ value: url, navigationCorrelation: correlation }, networkContext),
                fallbackType: 'open-redirect'
            });
            const meta = captureElementMeta(document?.activeElement || null);
            maybeReportTaintedValue(url, Object.assign({
                type: 'open-redirect',
                sink: sinkLabel
            }, binding), Object.assign({
                value: url,
                navigationCorrelation: correlation
            }, meta, networkContext), match);
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
        const serialized = safeSerializeValue(value);
        if (!serialized) return '';
        const normalized = serialized.trim().toLowerCase();
        if (!normalized) return '';
        return normalized.replace(/\s+/g, '');
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
        try {
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
        } catch (_) {
            // IAST hooks must never break application runtime.
        }
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
            runIastHookGuard('hook.runtime.integrity.prototypeWrites', 'Object.assign.pre', () => {
                sources.slice(0, 3).forEach((source) => {
                    getDangerousPrototypeKeys(source).forEach((dangerousKey) => {
                        reportPrototypePollutionWrite('Object.assign', dangerousKey, getOwnDangerousPropertyValue(source, dangerousKey), source);
                    });
                });
            });
            return origAssign.call(Object, target, ...sources);
        };
        wrappedAssign.__ptk_iast_wrapped__ = true;
        Object.assign = wrappedAssign;
    }

    if (typeof Reflect !== 'undefined' && typeof Reflect.set === 'function' && !Reflect.set.__ptk_iast_wrapped__) {
        const origReflectSet = Reflect.set;
        const wrappedReflectSet = function (target, propertyKey, value, receiver) {
            runIastHookGuard('hook.runtime.integrity.prototypeWrites', 'Reflect.set.pre', () => {
                if (IAST_DANGEROUS_PROTO_KEYS.has(String(propertyKey || ''))) {
                    reportPrototypePollutionWrite('Reflect.set', String(propertyKey), value, receiver || target);
                }
            });
            return origReflectSet.call(Reflect, target, propertyKey, value, receiver);
        };
        wrappedReflectSet.__ptk_iast_wrapped__ = true;
        Reflect.set = wrappedReflectSet;
    }

    if (typeof Object.defineProperty === 'function' && !Object.defineProperty.__ptk_iast_wrapped__) {
        const origDefineProperty = Object.defineProperty;
        const wrappedDefineProperty = function (target, propertyKey, descriptor) {
            runIastHookGuard('hook.runtime.integrity.prototypeWrites', 'Object.defineProperty.pre', () => {
                if (IAST_DANGEROUS_PROTO_KEYS.has(String(propertyKey || ''))) {
                    reportPrototypePollutionWrite('Object.defineProperty', String(propertyKey), descriptor?.value, descriptor);
                }
            });
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
            runIastHookGuard('hook.net.exfil', 'window.fetch.pre', () => {
                const networkHooksEnabled = isNetworkActivityHookEnabled();
                const responseHooksEnabled = isHookGroupEnabled('hook.net.responses');
                const resource = args[0];
                const init = args[1];
                const url = coerceRequestUrl(resource);
                const inheritedImpactFields = getInheritedPrototypeImpactFields(init);
                runIastHookGuard('hook.runtime.integrity.fetchInit', 'window.fetch.fetchInitImpact', () => {
                    if (inheritedImpactFields.length) {
                        reportPrototypePollutionFetchImpact(url, init, inheritedImpactFields);
                    }
                }, undefined, { respectEnabled: false });
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
                // An outbound request body is a sink/carrier, not an independent
                // attacker-controlled source. Registering its fields here makes
                // the request match values that it introduced itself and creates
                // tautological exfiltration findings. Independently observed
                // sources (URL, user input, storage, messages, responses, etc.)
                // are already present in the taint registry and still match the
                // request body and headers below.
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
                    return;
                }
            });
            const fetchPromise = origFetch.apply(this, args);
            return Promise.resolve(fetchPromise).then((response) => {
                runIastHookGuard('hook.net.responses', 'window.fetch.responseCapture', () => {
                    if (isHookGroupEnabled('hook.net.responses')) {
                        const responseMeta = {
                            requestUrl: coerceRequestUrl(args[0]),
                            responseUrl: response?.url || coerceRequestUrl(args[0]),
                            responseStatus: response?.status,
                            isGraphql: isGraphqlRequest
                        };
                        if (response && IAST_FETCH_RESPONSE_META) {
                            IAST_FETCH_RESPONSE_META.set(response, responseMeta);
                        }
                        captureFetchResponseSources(response, responseMeta);
                    }
                });
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
            runIastHookGuard('hook.net.exfil', 'XMLHttpRequest.open.pre', () => {
                const suspicious = isSuspiciousExfilUrl(url);
                this.__ptk_iast_exfil_suspicious = suspicious;
                if (!suspicious) return;
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
            });
            return origOpen.call(this, method, url, ...rest);
        };

        const origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
        if (origSetRequestHeader) {
            XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
                runIastHookGuard('hook.net.exfil', 'XMLHttpRequest.setRequestHeader.pre', () => {
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
                });
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
            runIastHookGuard('hook.net.exfil', 'XMLHttpRequest.send.pre', () => {
                if (!networkHooksEnabled || body === undefined) return;
                const contentType = extractContentTypeFromHeaders([this.__ptk_iast_headers]);
                this.__ptk_iast_is_graphql = isLikelyGraphqlRequest(
                    this.__ptk_iast_url_resolved || this.__ptk_iast_url || null,
                    body,
                    contentType
                );
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
            });
            if (responseHooksEnabled && !this.__ptk_iast_response_listener_added && typeof this.addEventListener === 'function') {
                this.__ptk_iast_response_listener_added = true;
                this.addEventListener('loadend', () => {
                    runIastHookGuard('hook.net.responses', 'XMLHttpRequest.loadend.responseCapture', () => {
                        captureXhrResponseSources(this);
                    });
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
            runIastHookGuard('hook.net.exfil', 'navigator.sendBeacon.pre', () => {
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
            });
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
                    runIastHookGuard('hook.net.exfil', 'HTMLImageElement.src.setter', () => {
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
                    });
                    return desc.set.call(this, value);
                }
            });
        }
    }

    if (typeof WebSocket !== 'undefined' && WebSocket.prototype && typeof WebSocket.prototype.send === 'function') {
        const origSocketSend = WebSocket.prototype.send;
        WebSocket.prototype.send = function (data) {
            if (this?.readyState !== WebSocket.OPEN) {
                return undefined;
            }
            let sendResult;
            try {
                sendResult = origSocketSend.apply(this, arguments);
            } catch (error) {
                if (isIgnorableWebSocketSendError(error)) {
                    return undefined;
                }
                throw error;
            }
            if (!isHookGroupEnabled('hook.net.exfil')) {
                emitWebSocketRuntimeSignal({
                    value: data,
                    socketUrl: this?.url || null,
                    protocol: this?.protocol || null
                });
                return sendResult;
            }
            runIastHookGuard('hook.net.exfil', 'WebSocket.send.post', () => {
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
            });
            return sendResult;
        };
    }

    if (typeof RTCDataChannel !== 'undefined' && RTCDataChannel.prototype && typeof RTCDataChannel.prototype.send === 'function') {
        const origRtcSend = RTCDataChannel.prototype.send;
        RTCDataChannel.prototype.send = function (data) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origRtcSend.apply(this, arguments);
            }
            runIastHookGuard('hook.net.exfil', 'RTCDataChannel.send.pre', () => {
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
            });
            return origRtcSend.apply(this, arguments);
        };
    }
})();

// Dynamic script loading sinks
; (function () {
    if (typeof window !== 'undefined' && typeof window.Blob === 'function' && IAST_BLOB_TAINT) {
        const OriginalBlob = window.Blob;
        if (!OriginalBlob.__ptk_wrapped__) {
            window.Blob = new Proxy(OriginalBlob, {
                construct(target, args, newTarget) {
                    const instance = Reflect.construct(target, args, newTarget);
                    try {
                        const parts = Array.isArray(args?.[0]) ? args[0] : [];
                        const taintInfo = collectPrimaryTaintMatch(parts);
                        if (taintInfo) {
                            IAST_BLOB_TAINT.set(instance, {
                                taintKind: taintInfo.primarySource?.taintKind || 'user_input',
                                sourceKind: taintInfo.primarySource?.sourceKind || null
                            });
                        }
                    } catch (_) {
                        // ignore Blob taint capture failures
                    }
                    return instance;
                }
            });
            window.Blob.__ptk_wrapped__ = true;
        }
    }

    if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') return;
    if (URL.__ptk_objecturl_wrapped__) return;
    const origCreateObjectURL = URL.createObjectURL.bind(URL);
    URL.createObjectURL = function (object) {
        const url = origCreateObjectURL(object);
        try {
            const taintInfo = IAST_BLOB_TAINT && object ? IAST_BLOB_TAINT.get(object) : null;
            if (taintInfo) {
                const key = `objectUrl:${url}`;
                registerDynamicTaintSource(key, url, {
                    type: 'objectUrl',
                    label: 'Object URL',
                    detail: url,
                    sourceKind: 'objectUrl',
                    taintKind: taintInfo.taintKind || 'user_input'
                });
                IAST_OBJECT_URL_TAINT_KEYS.set(String(url), key);
            }
        } catch (_) {
            // ignore object URL taint capture failures
        }
        return url;
    };
    if (typeof URL.revokeObjectURL === 'function') {
        const origRevokeObjectURL = URL.revokeObjectURL.bind(URL);
        URL.revokeObjectURL = function (url) {
            try {
                const key = IAST_OBJECT_URL_TAINT_KEYS.get(String(url));
                if (key) {
                    unregisterDynamicTaintSource(key);
                    IAST_OBJECT_URL_TAINT_KEYS.delete(String(url));
                }
            } catch (_) {
                // ignore cleanup failures
            }
            return origRevokeObjectURL(url);
        };
    }
    URL.__ptk_objecturl_wrapped__ = true;
})();

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
            runIastHookGuard('hook.script.loading', 'HTMLScriptElement.src.setter', () => {
                const networkContext = buildNetworkContext(value);
                maybeReportTaintedValue(value, {
                    type: 'dynamic-script-loading',
                    sink: 'script.src',
                    sinkId: 'script.element.src'
                }, Object.assign({ value, element: this, requestUrl: value }, networkContext || {}));
            });
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
                return callNativeConsoleMethod(orig, args);
            }
            runIastHookGuard('hook.console.leaks', `console.${method}.pre`, () => {
                args.forEach(arg => {
                    const payload = safeSerializeValue(arg);
                    if (!payload) return;
                    const binding = buildRuleBinding({ sinkId, fallbackType: 'debug-logging' });
                    maybeReportTaintedValue(payload, Object.assign({
                        type: 'debug-logging',
                        sink: `console.${method}`
                    }, binding), { value: payload, method: `console.${method}` });
                });
            });
            return callNativeConsoleMethod(orig, args);
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
        runIastHookGuard('hook.net.exfil', 'navigator.clipboard.writeText.pre', () => {
            const payload = safeSerializeValue(args[0]);
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'clipboard-exfiltration',
                    sink: 'navigator.clipboard.writeText',
                    sinkId: 'clipboard.writeText'
                }, { value: payload });
            }
        });
        return origWriteText.apply(this, args);
    };
})();

// BroadcastChannel & MessagePort sinks
; (function () {
    const registerInboundMessage = (sourceKey, payload, meta = {}) => {
        if (!isHookGroupEnabled('hook.postMessage')) return;
        registerDynamicTaintSource(sourceKey, payload, Object.assign({
            taintKind: 'user_input'
        }, meta));
    };

    const wrapMessageEventListener = (listener, wrapKey, sourceKeyBuilder, metaBuilder) => {
        return getWrappedMessageHandler(listener, wrapKey, (original) => function (event) {
            try {
                if (isIastInternalMessagePayload(event?.data)) {
                    return undefined;
                }
                const payload = safeSerializeValue(event?.data);
                if (payload) {
                    registerInboundMessage(sourceKeyBuilder.call(this, event), payload, metaBuilder.call(this, event, payload));
                }
            } catch (_) {
                // ignore inbound message capture failures
            }
            return original.apply(this, arguments);
        });
    };

    const wrapEventTargetMessageHandlers = (proto, wrapKey, sourceKeyBuilder, metaBuilder) => {
        if (!proto) return;
        if (typeof proto.addEventListener === 'function' && !proto.addEventListener.__ptk_iast_message_wrapped__) {
            const originalAdd = proto.addEventListener;
            const wrappedAdd = function (type, listener, options) {
                if (type === 'message' && typeof listener === 'function') {
                    return originalAdd.call(this, type, wrapMessageEventListener(listener, wrapKey, sourceKeyBuilder, metaBuilder), options);
                }
                return originalAdd.apply(this, arguments);
            };
            wrappedAdd.__ptk_iast_message_wrapped__ = true;
            proto.addEventListener = wrappedAdd;
        }
        if (typeof proto.removeEventListener === 'function' && !proto.removeEventListener.__ptk_iast_message_wrapped__) {
            const originalRemove = proto.removeEventListener;
            const wrappedRemove = function (type, listener, options) {
                if (type === 'message' && typeof listener === 'function') {
                    return originalRemove.call(this, type, wrapMessageEventListener(listener, wrapKey, sourceKeyBuilder, metaBuilder), options);
                }
                return originalRemove.apply(this, arguments);
            };
            wrappedRemove.__ptk_iast_message_wrapped__ = true;
            proto.removeEventListener = wrappedRemove;
        }
        const desc = Object.getOwnPropertyDescriptor(proto, 'onmessage');
        if (desc?.set && !desc.set.__ptk_iast_message_wrapped__) {
            Object.defineProperty(proto, 'onmessage', {
                configurable: true,
                enumerable: desc.enumerable,
                get: desc.get,
                set(handler) {
                    if (typeof handler !== 'function') {
                        return desc.set.call(this, handler);
                    }
                    const wrapped = wrapMessageEventListener(handler, wrapKey, sourceKeyBuilder, metaBuilder);
                    return desc.set.call(this, wrapped);
                }
            });
            Object.getOwnPropertyDescriptor(proto, 'onmessage')?.set && (Object.getOwnPropertyDescriptor(proto, 'onmessage').set.__ptk_iast_message_wrapped__ = true);
        }
    };

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
                runIastHookGuard('hook.postMessage', 'BroadcastChannel.postMessage.pre', () => {
                    const payload = safeSerializeValue(message);
                    if (payload) {
                        maybeReportTaintedValue(payload, {
                            type: 'web-messaging-channel',
                            sink: 'BroadcastChannel.postMessage',
                            sinkId: 'channel.broadcast.postMessage'
                        }, { value: payload, channelName: this?.name || null });
                    }
                });
                return orig.apply(this, arguments);
            };
        }

        wrapEventTargetMessageHandlers(
            BroadcastChannel.prototype,
            'broadcast-message',
            function () {
                return `broadcast:${getIastMessageTargetLabel(this, 'broadcast')}`;
            },
            function (event, payload) {
                return {
                    type: 'broadcastMessage',
                    label: `BroadcastChannel "${getIastMessageTargetLabel(this, 'broadcast')}" message`,
                    detail: getIastMessageTargetLabel(this, 'broadcast'),
                    sourceKind: 'broadcastMessage',
                    value: payload
                };
            }
        );
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
                runIastHookGuard('hook.postMessage', 'MessagePort.postMessage.pre', () => {
                    const payload = safeSerializeValue(message);
                    if (payload) {
                        maybeReportTaintedValue(payload, {
                            type: 'web-messaging-channel',
                            sink: 'MessagePort.postMessage',
                            sinkId: 'channel.messageport.postMessage'
                        }, { value: payload });
                    }
                });
                return origPortPost.apply(this, arguments);
            };
        }

        wrapEventTargetMessageHandlers(
            MessagePort.prototype,
            'messageport-message',
            function () {
                return `messagePort:${getIastMessageTargetLabel(this, 'port')}`;
            },
            function (event, payload) {
                return {
                    type: 'messagePort',
                    label: `MessagePort "${getIastMessageTargetLabel(this, 'port')}" message`,
                    detail: getIastMessageTargetLabel(this, 'port'),
                    sourceKind: 'messagePort',
                    value: payload
                };
            }
        );
    }

    if (typeof Worker !== 'undefined' && Worker.prototype) {
        wrapEventTargetMessageHandlers(
            Worker.prototype,
            'worker-message',
            function () {
                return `workerMessage:${getIastMessageTargetLabel(this, 'worker')}`;
            },
            function (event, payload) {
                return {
                    type: 'workerMessage',
                    label: `Worker "${getIastMessageTargetLabel(this, 'worker')}" message`,
                    detail: getIastMessageTargetLabel(this, 'worker'),
                    sourceKind: 'workerMessage',
                    value: payload
                };
            }
        );
    }
})();

// Worker & ServiceWorker script loading sinks
; (function () {
    if (typeof globalThis.importScripts === 'function' && !globalThis.importScripts.__ptk_iast_wrapped__) {
        const origImportScripts = globalThis.importScripts;
        const wrappedImportScripts = function (...urls) {
            runIastHookGuard('hook.script.loading', 'importScripts.pre', () => {
                urls.forEach((url) => {
                    const payload = safeSerializeValue(url);
                    if (!payload) return;
                    maybeReportTaintedValue(payload, {
                        type: 'dynamic-import-loading',
                        sink: 'importScripts',
                        sinkId: 'worker.importScripts'
                    }, { value: payload });
                });
            });
            return origImportScripts.apply(this, urls);
        };
        wrappedImportScripts.__ptk_iast_wrapped__ = true;
        globalThis.importScripts = wrappedImportScripts;
    }

    if (typeof navigator !== 'undefined' && navigator.serviceWorker && typeof navigator.serviceWorker.register === 'function') {
        const origRegister = navigator.serviceWorker.register;
        navigator.serviceWorker.register = function (...args) {
            if (!isHookGroupEnabled('hook.script.loading')) {
                return origRegister.apply(this, args);
            }
            runIastHookGuard('hook.script.loading', 'navigator.serviceWorker.register.pre', () => {
                const payload = safeSerializeValue(args[0]);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'worker-script-loading',
                        sink: 'navigator.serviceWorker.register',
                        sinkId: 'worker.serviceWorker.register'
                    }, { value: payload });
                }
            });
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
                const payload = runIastHookGuard('hook.script.loading', 'Worker.construct.pre', () => {
                    const nextPayload = safeSerializeValue(args[0]);
                    if (nextPayload) {
                        maybeReportTaintedValue(nextPayload, {
                            type: 'worker-script-loading',
                            sink: 'Worker',
                            sinkId: 'worker.webworker.constructor'
                        }, { value: nextPayload });
                    }
                    return nextPayload;
                }, '');
                const worker = Reflect.construct(target, args, newTarget);
                try {
                    worker.__ptk_iast_label = payload || 'worker';
                } catch (_) {
                    // ignore worker label tracking failures
                }
                return worker;
            }
        });
    }
})();

// window.postMessage misuse
; (function () {
    if (typeof window.postMessage !== 'function') return;
    const origPostMessage = window.postMessage;
    window.postMessage = function (message, targetOrigin, transfer) {
        if (isIastInternalMessagePayload(message)) {
            return origPostMessage.apply(this, arguments);
        }
        if (!isHookGroupEnabled('hook.postMessage')) {
            runIastHookGuard('hook.postMessage', 'window.postMessage.runtimeSignal', () => {
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
            }, undefined, { respectEnabled: false });
            return origPostMessage.apply(this, arguments);
        }
        runIastHookGuard('hook.postMessage', 'window.postMessage.pre', () => {
            const payload = safeSerializeValue(message);
            const originValue = targetOrigin == null ? '*' : targetOrigin;
            const defaultContext = { value: payload, targetOrigin: originValue };
            if (originValue === '*' || originValue === '') {
                if (!isIastSinkActive('postmessage.anyOrigin')) {
                    return;
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
                        return;
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
        });
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
                runIastHookGuard('hook.dom.urlAttributes', 'HTMLIFrameElement.src.setter', () => {
                    if (shouldReportNavigationSink(value)) {
                        maybeReportTaintedValue(value, {
                            type: 'iframe-navigation',
                            sink: 'iframe.src',
                            sinkId: 'nav.iframe.src'
                        }, { value, element: this });
                    }
                });
                return srcDesc.set.call(this, value);
            }
        });
    }
    // srcdoc is intentionally handled only by the generic attribute/property
    // wrapper above. That path binds the rule from the observed source kind,
    // which is required to distinguish direct input from secondary sources.
})();

// AngularJS expression/template sinks
; (function () {
    const GROUP_ID = 'hook.angularjs';
    const WRAPPED_MARK = '__ptk_iast_angular_wrapped__';
    const DECORATED_MARK = '__ptk_iast_angular_decorated__';
    const serviceSinks = {
        '$parse': {
            sinkId: 'angularjs.parse.expression',
            type: 'angularjs-expression',
            sink: 'AngularJS $parse'
        },
        '$compile': {
            sinkId: 'angularjs.compile.template',
            type: 'angularjs-template-compile',
            sink: 'AngularJS $compile'
        },
        '$interpolate': {
            sinkId: 'angularjs.compile.template',
            type: 'angularjs-template-interpolate',
            sink: 'AngularJS $interpolate'
        }
    };
    const wrappedServices = new WeakMap();
    const wrappedServiceResults = new WeakMap();
    const patchedInjectors = new WeakSet();

    function buildAngularExecutionContext(serviceName, phase) {
        return {
            framework: 'AngularJS',
            angularService: serviceName,
            angularPhase: phase
        };
    }

    function wrapAngularServiceResult(serviceName, result) {
        if (typeof result !== 'function') return result;
        let byService = wrappedServiceResults.get(result);
        if (byService?.[serviceName]) return byService[serviceName];
        const wrappedResult = new Proxy(result, {
            apply(target, thisArg, args) {
                return withIastExecutionContext(
                    buildAngularExecutionContext(serviceName, 'evaluator'),
                    () => Reflect.apply(target, thisArg, args)
                );
            }
        });
        if (!byService) {
            byService = Object.create(null);
            wrappedServiceResults.set(result, byService);
        }
        byService[serviceName] = wrappedResult;
        return wrappedResult;
    }

    function reportAngularSink(value, serviceName, serviceMeta) {
        if (!isHookGroupEnabled(GROUP_ID)) return;
        const payload = safeSerializeValue(value);
        if (!payload) return;
        const binding = buildRuleBinding({
            sinkId: serviceMeta.sinkId,
            fallbackType: serviceMeta.type
        });
        maybeReportTaintedValue(payload, Object.assign({
            type: serviceMeta.type,
            sink: serviceMeta.sink,
            framework: 'AngularJS',
            service: serviceName
        }, binding), {
            value: payload,
            framework: 'AngularJS',
            angularService: serviceName
        });
    }

    function wrapAngularService(serviceName, service) {
        const serviceMeta = serviceSinks[serviceName];
        if (!serviceMeta || typeof service !== 'function') return service;
        if (service[WRAPPED_MARK]) return service;
        let byService = wrappedServices.get(service);
        if (byService?.[serviceName]) return byService[serviceName];
        const wrapped = function (...args) {
            const thisArg = this;
            return withIastExecutionContext(
                buildAngularExecutionContext(serviceName, 'service'),
                () => {
                    runIastHookGuard(GROUP_ID, `AngularJS.${serviceName}.pre`, () => {
                        reportAngularSink(args[0], serviceName, serviceMeta);
                    });
                    return wrapAngularServiceResult(serviceName, service.apply(thisArg, args));
                }
            );
        };
        try {
            Object.defineProperty(wrapped, WRAPPED_MARK, {
                value: true,
                configurable: false,
                enumerable: false
            });
        } catch (_) { }
        if (!byService) {
            byService = Object.create(null);
            wrappedServices.set(service, byService);
        }
        byService[serviceName] = wrapped;
        return wrapped;
    }

    function installAngularDecorators(moduleRef) {
        if (!moduleRef || typeof moduleRef.config !== 'function' || moduleRef[DECORATED_MARK]) return;
        try {
            Object.defineProperty(moduleRef, DECORATED_MARK, {
                value: true,
                configurable: false,
                enumerable: false
            });
        } catch (_) {
            try { moduleRef[DECORATED_MARK] = true; } catch (_) { }
        }
        try {
            moduleRef.config(['$provide', function ($provide) {
                if (!$provide || typeof $provide.decorator !== 'function') return;
                Object.keys(serviceSinks).forEach((serviceName) => {
                    try {
                        $provide.decorator(serviceName, ['$delegate', function ($delegate) {
                            return wrapAngularService(serviceName, $delegate);
                        }]);
                    } catch (_) { }
                });
            }]);
        } catch (_) { }
    }

    function patchAngularInjector(injector) {
        if (!injector || patchedInjectors.has(injector) || typeof injector.get !== 'function') return false;
        patchedInjectors.add(injector);
        const originalGet = injector.get;
        injector.get = function (name, ...rest) {
            const service = originalGet.call(this, name, ...rest);
            return wrapAngularService(name, service);
        };
        Object.keys(serviceSinks).forEach((serviceName) => {
            try {
                wrapAngularService(serviceName, originalGet.call(injector, serviceName));
            } catch (_) { }
        });
        return true;
    }

    function patchAngularElementInjector(angularRef) {
        if (!angularRef || typeof angularRef.element !== 'function') return false;
        let patched = false;
        try {
            const candidates = [document.documentElement, document.body].filter(Boolean);
            candidates.forEach((node) => {
                try {
                    const elementRef = angularRef.element(node);
                    if (elementRef && typeof elementRef.injector === 'function') {
                        patched = patchAngularInjector(elementRef.injector()) || patched;
                    }
                } catch (_) { }
            });
        } catch (_) { }
        return patched;
    }

    function patchAngular(angularRef) {
        if (!angularRef || typeof angularRef !== 'object') return false;
        let patched = false;
        if (typeof angularRef.module === 'function' && !angularRef.module[WRAPPED_MARK]) {
            const originalModule = angularRef.module;
            angularRef.module = function (...args) {
                const moduleRef = originalModule.apply(this, args);
                installAngularDecorators(moduleRef);
                return moduleRef;
            };
            try {
                Object.defineProperty(angularRef.module, WRAPPED_MARK, {
                    value: true,
                    configurable: false,
                    enumerable: false
                });
            } catch (_) { }
            patched = true;
        }
        if (typeof angularRef.injector === 'function' && !angularRef.injector[WRAPPED_MARK]) {
            const originalInjector = angularRef.injector;
            angularRef.injector = function (...args) {
                const injector = originalInjector.apply(this, args);
                patchAngularInjector(injector);
                return injector;
            };
            try {
                Object.defineProperty(angularRef.injector, WRAPPED_MARK, {
                    value: true,
                    configurable: false,
                    enumerable: false
                });
            } catch (_) { }
            patched = true;
        }
        try {
            ['ng'].forEach((moduleName) => {
                try {
                    installAngularDecorators(angularRef.module(moduleName));
                    patched = true;
                } catch (_) { }
            });
        } catch (_) { }
        patched = patchAngularElementInjector(angularRef) || patched;
        return patched;
    }

    function tryPatchAngular() {
        if (!isHookGroupEnabled(GROUP_ID)) return false;
        return runIastHookGuard(GROUP_ID, 'AngularJS.patch', () => patchAngular(window.angular), false);
    }

    if (tryPatchAngular()) return;
    let attempts = 0;
    const timer = setInterval(() => {
        attempts += 1;
        const patched = tryPatchAngular();
        if (patched || attempts > 80) {
            clearInterval(timer);
        }
    }, 250);
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
            runIastHookGuard('hook.code.exec', `${fnName}.pre`, () => {
                if (typeof handler === 'string' && handler) {
                    maybeReportTaintedValue(handler, {
                        type: 'timer-execution',
                        sink: fnName,
                        sinkId
                    }, { value: handler, method: fnName });
                }
            });
            return orig.call(this, handler, ...rest);
        };
    }
    wrapTimer('setTimeout', 'code.setTimeout');
    wrapTimer('setInterval', 'code.setInterval');
})();

try {
    globalThis.__PTK_IAST_INSTALLATION_STATE__ = 'ready';
    globalThis.__PTK_IAST_AGENT_LOADED__ = true;
    emitIastObservationState();
    emitIastPageBridgeMessage({ channel: 'ptk_iast_agent_ready', installationState: 'ready' });
    window.addEventListener('pagehide', () => {
        // A write completed in the current task may still be waiting for its
        // deferred timer. Admit that already-ready work before this realm is
        // discarded; the timer cannot be relied on after navigation.
        flushDeferredIastWriteReports();
        flushPendingIastFindingReports();
        if (IAST_DEFERRED_WRITE_REPORTS.length || IAST_PENDING_FINDING_REPORTS.length) {
            recordIastObservationGap('pending_observation_at_pagehide', true);
        }
        emitIastObservationState({ terminal: true });
    }, { once: true });
} catch (_) { }
})('native-main-document-start');
