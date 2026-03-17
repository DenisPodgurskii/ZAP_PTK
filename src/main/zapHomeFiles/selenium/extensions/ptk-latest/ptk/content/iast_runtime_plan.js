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
])

const POLICY_ONLY_HOOK_GROUPS = Object.freeze([
  'hook.client.json',
  'hook.console.leaks',
  'hook.dom.htmlParsers',
  'hook.net.exfil',
  'hook.runtime.integrity.prototypeWrites',
  'hook.storage',
])

function createNullProtoObject() {
  return Object.create(null)
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
    }
  }
  return installPlanHookGroups[groupId]
}

export function getDomAttributeHookGroupForSink(sinkId) {
  if (!sinkId) return null
  if (sinkId === 'nav.iframe.srcdoc') return 'hook.dom.htmlAssignments'
  if (sinkId === 'dom.inline_event') return 'hook.dom.inlineEvents'
  if (sinkId === 'document.domain') return 'hook.dom.urlAttributes'
  if (
    sinkId === 'dom.attr.action'
    || sinkId === 'dom.attr.formaction'
    || sinkId.startsWith('dom.attr.action.')
    || sinkId.startsWith('dom.attr.formaction.')
  ) {
    return 'hook.dom.formAttributes'
  }
  return 'hook.dom.urlAttributes'
}

export function getHookGroupsForSink(sinkId) {
  const groups = new Set()
  if (!sinkId) return groups
  if (['dom.innerHTML', 'dom.outerHTML', 'dom.insertAdjacentHTML', 'nav.iframe.srcdoc'].includes(sinkId)) {
    groups.add('hook.dom.htmlAssignments')
  }
  if (sinkId === 'document.write') {
    groups.add('hook.dom.documentWrite')
  }
  if ([
    'dom.domParser.parseFromString',
    'dom.range.createContextualFragment',
    'dom.element.setHTMLUnsafe',
    'dom.shadowRoot.setHTMLUnsafe'
  ].includes(sinkId)) {
    groups.add('hook.dom.htmlParsers')
  }
  if (sinkId === 'dom.inline_event') {
    groups.add('hook.dom.inlineEvents')
  }
  if (sinkId === 'dom.mutation' || sinkId === 'dom.clobbering.named_property') {
    groups.add('hook.dom.mutations')
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
    const attrHookGroup = getDomAttributeHookGroupForSink(sinkId)
    if (attrHookGroup) groups.add(attrHookGroup)
  }
  if (sinkId.startsWith('code.')) {
    groups.add('hook.code.exec')
  }
  if (sinkId.startsWith('nav.location.') || sinkId.startsWith('nav.window.open') || sinkId.startsWith('nav.history.') || sinkId === 'nav.navigation.navigate') {
    groups.add('hook.nav.redirects')
  }
  if (sinkId.startsWith('http.') || sinkId.startsWith('csrf.')) {
    groups.add('hook.net.exfil')
  }
  if (sinkId === 'runtime.prototype.pollution.fetchInit') {
    groups.add('hook.runtime.integrity.fetchInit')
  }
  if (sinkId === 'runtime.prototype.pollution.write') {
    groups.add('hook.runtime.integrity.prototypeWrites')
  }
  if (sinkId.startsWith('realtime.')) {
    groups.add('hook.net.exfil')
  }
  if (sinkId.startsWith('clipboard.')) {
    groups.add('hook.net.exfil')
  }
  if (sinkId.startsWith('storage.')) {
    groups.add('hook.storage')
  }
  if (sinkId.startsWith('postmessage.') || sinkId.startsWith('channel.')) {
    groups.add('hook.postMessage')
  }
  if (sinkId.startsWith('log.console.')) {
    groups.add('hook.console.leaks')
  }
  if (sinkId.startsWith('worker.') || sinkId === 'script.element.src' || sinkId.startsWith('script.element.src.')) {
    groups.add('hook.script.loading')
  }
  if (
    sinkId === 'client.json.parse'
    || sinkId === 'dom.xpath.evaluate'
    || sinkId.startsWith('client.filereader.')
    || sinkId.startsWith('client.sql.')
  ) {
    groups.add('hook.client.json')
  }
  if (sinkId === 'document.domain') {
    groups.add('hook.dom.urlAttributes')
  }
  return groups
}

export function classifyHookGroupTier(groupId) {
  if (FREE_SAFE_HOOK_GROUPS.includes(groupId)) return 'free-safe'
  if (POLICY_ONLY_HOOK_GROUPS.includes(groupId)) return 'policy-only'
  return 'support'
}

const SECONDARY_SOURCE_KINDS = new Set(['cookie', 'localStorage', 'sessionStorage', 'windowName', 'referrer', 'hashRoute'])
const STORAGE_EXEC_SOURCE_KINDS = new Set(['cookie', 'localStorage', 'sessionStorage', 'windowName', 'referrer', 'hashRoute', 'postMessage'])
const RESPONSE_SOURCE_KINDS = new Set(['apiResponseField', 'graphqlResponseField'])
const SESSION_SOURCE_KINDS = new Set(['cookie', 'localStorage', 'sessionStorage', 'windowName', 'referrer'])
const STORAGE_REUSE_SOURCE_KINDS = new Set(['cookie', 'localStorage', 'sessionStorage', 'windowName'])
const REDIRECT_SOURCE_KINDS = new Set(['query', 'hashQuery', 'hashRoute', 'postMessage', 'referrer', 'windowName'])
const ROUTE_SOURCE_KINDS = new Set(['pathname', 'pathSegment', 'clientRoute', 'historyState', 'hashRoute', 'hashQuery', 'postMessage'])
const FORM_HIJACK_SOURCE_KINDS = new Set([
  'query', 'hashQuery', 'hashRoute', 'pathname', 'pathSegment', 'clientRoute',
  'historyState', 'bodyParam', 'jsonBodyField', 'formDataField', 'graphqlVariable',
  'postMessage', 'windowName', 'referrer'
])

function hasAnySourceKind(sourceKinds, expected) {
  return Array.isArray(sourceKinds) && sourceKinds.some((kind) => expected.has(kind))
}

function getRuleVariantByPrefix(sinkPlan, prefixes = []) {
  if (!sinkPlan?.variants?.length) return null
  for (const prefix of prefixes) {
    const match = sinkPlan.variants.find((entry) => entry?.ruleId?.includes(prefix))
    if (match) return match
  }
  return null
}

export function selectIastRuleVariant({ runtimePlan = null, sinkId = null, sourceKinds = [], isCrossOrigin = false } = {}) {
  const sinkPlan = sinkId && runtimePlan?.bySinkId ? runtimePlan.bySinkId[sinkId] || null : null
  if (!sinkPlan?.variants?.length) return null
  if (sinkPlan.uniqueRuleId) return sinkPlan.variants[0] || null

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
    if (hasAnySourceKind(sourceKinds, RESPONSE_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['response_'])
    }
    if (hasAnySourceKind(sourceKinds, SECONDARY_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['secondary_sources'])
    }
    return getRuleVariantByPrefix(sinkPlan, ['dom_', 'document_write_', 'range_', 'element_', 'shadowroot_']) || sinkPlan.variants[0]
  }

  if (sinkId === 'dom.inline_event' || sinkId === 'nav.iframe.srcdoc') {
    if (hasAnySourceKind(sourceKinds, SECONDARY_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['secondary_sources'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('secondary_sources')) || sinkPlan.variants[0]
  }

  if (['code.eval', 'code.function.constructor', 'code.function.apply', 'code.setTimeout', 'code.setInterval'].includes(sinkId)) {
    if (hasAnySourceKind(sourceKinds, STORAGE_EXEC_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['storage_'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('storage_')) || sinkPlan.variants[0]
  }

  if (sinkId === 'http.fetch.url' || sinkId === 'http.xhr.open') {
    if (hasAnySourceKind(sourceKinds, STORAGE_REUSE_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['storage_'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('storage_')) || sinkPlan.variants[0]
  }

  if (sinkId === 'http.fetch.headers') {
    if (isCrossOrigin && hasAnySourceKind(sourceKinds, SESSION_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['session_'])
    }
    if (hasAnySourceKind(sourceKinds, STORAGE_REUSE_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['storage_'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('session_') && !entry.ruleId.includes('storage_')) || sinkPlan.variants[0]
  }

  if (['http.navigator.sendBeacon', 'http.image.src', 'realtime.websocket.send'].includes(sinkId)) {
    if (isCrossOrigin && hasAnySourceKind(sourceKinds, SESSION_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['session_'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('session_')) || sinkPlan.variants[0]
  }

  if (sinkId === 'realtime.webrtc.send') {
    if (hasAnySourceKind(sourceKinds, SESSION_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['session_'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('session_')) || sinkPlan.variants[0]
  }

  if (sinkId === 'postmessage.anyOrigin' || sinkId === 'postmessage.crossOrigin') {
    if (hasAnySourceKind(sourceKinds, SESSION_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['session_'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('session_')) || sinkPlan.variants[0]
  }

  if (['nav.location.href', 'nav.location.assign', 'nav.location.replace', 'nav.window.open'].includes(sinkId)) {
    if (isCrossOrigin && hasAnySourceKind(sourceKinds, REDIRECT_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['_sources'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('_sources')) || sinkPlan.variants[0]
  }

  if (sinkId === 'nav.navigation.navigate') {
    if (isCrossOrigin && hasAnySourceKind(sourceKinds, REDIRECT_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['_sources'])
    }
    if (hasAnySourceKind(sourceKinds, ROUTE_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['route_'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('_sources') && !entry.ruleId.includes('route_')) || sinkPlan.variants[0]
  }

  if (sinkId === 'nav.history.pushState' || sinkId === 'nav.history.replaceState') {
    if (hasAnySourceKind(sourceKinds, ROUTE_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['route_'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('route_')) || sinkPlan.variants[0]
  }

  if (sinkId === 'dom.attr.action' || sinkId === 'dom.attr.formaction') {
    if (hasAnySourceKind(sourceKinds, RESPONSE_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['response_'])
    }
    if (sinkId === 'dom.attr.action' && isCrossOrigin && hasAnySourceKind(sourceKinds, REDIRECT_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['_sources'])
    }
    if (hasAnySourceKind(sourceKinds, FORM_HIJACK_SOURCE_KINDS)) {
      return getRuleVariantByPrefix(sinkPlan, ['hijack'])
    }
    return sinkPlan.variants.find((entry) => !entry.ruleId.includes('response_') && !entry.ruleId.includes('_sources') && !entry.ruleId.includes('hijack')) || sinkPlan.variants[0]
  }

  return sinkPlan.variants[0] || null
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
  }
}

export function buildIastRuntimePlan(modulesJson) {
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
  }

  if (!modulesJson || !Array.isArray(modulesJson.modules)) {
    return plan
  }

  const activeHookGroups = new Set()
  const activeModuleIds = new Set()
  const activeRuleIds = new Set()
  const installPlanHookGroups = createNullProtoObject()

  for (const moduleDef of modulesJson.modules) {
    if (!moduleDef || typeof moduleDef !== 'object' || !Array.isArray(moduleDef.rules)) continue
    if (moduleDef.id) activeModuleIds.add(moduleDef.id)

    for (const ruleDef of moduleDef.rules) {
      if (!ruleDef || typeof ruleDef !== 'object') continue
      const entry = buildRuleEntry(moduleDef, ruleDef)
      if (entry.ruleId) {
        activeRuleIds.add(entry.ruleId)
        plan.byRuleId[entry.ruleId] = entry
      }
      if (!entry.sinkId) continue

      if (!plan.bySinkId[entry.sinkId]) {
        plan.bySinkId[entry.sinkId] = {
          sinkId: entry.sinkId,
          hookGroups: [],
          variants: [],
          uniqueRuleId: null,
        }
      }

      const sinkPlan = plan.bySinkId[entry.sinkId]
      sinkPlan.variants.push(entry)

      const sinkHookGroups = getHookGroupsForSink(entry.sinkId)
      sinkHookGroups.forEach((groupId) => {
        activeHookGroups.add(groupId)
        const hookPlan = ensureHookPlan(installPlanHookGroups, groupId, 'active-rules')
        hookPlan.sinkIds.add(entry.sinkId)
        hookPlan.ruleIds.add(entry.ruleId)
        sinkPlan.hookGroups = [...new Set([...sinkPlan.hookGroups, groupId])]
      })

      if (entry.sources.includes('postMessage')) {
        activeHookGroups.add('hook.postMessage')
      }
      if (entry.sources.includes('apiResponseField') || entry.sources.includes('graphqlResponseField')) {
        activeHookGroups.add('hook.net.responses')
      }
      if (entry.sanitizersAllowed.length) {
        activeHookGroups.add('hook.sanitizers')
      }
    }
  }

  for (const sinkPlan of Object.values(plan.bySinkId)) {
    if (sinkPlan.variants.length === 1) {
      sinkPlan.uniqueRuleId = sinkPlan.variants[0].ruleId
    }
  }

  for (const groupId of activeHookGroups) {
    ensureHookPlan(installPlanHookGroups, groupId, 'derived-policy-support')
  }

  if (activeHookGroups.has('hook.runtime.integrity.fetchInit')) {
    ensureHookPlan(installPlanHookGroups, 'hook.runtime.integrity.prototypeWrites', 'supporting-dependency')
  }

  for (const hookPlan of Object.values(installPlanHookGroups)) {
    hookPlan.ruleCount = hookPlan.ruleIds.size
    hookPlan.sinkIds = [...hookPlan.sinkIds].sort()
    hookPlan.ruleIds = [...hookPlan.ruleIds].sort()
  }

  plan.activeModuleIds = [...activeModuleIds].sort()
  plan.activeRuleIds = [...activeRuleIds].sort()
  plan.activeHookGroups = [...activeHookGroups].sort()
  plan.freeSafeHookGroups = plan.activeHookGroups.filter((groupId) => classifyHookGroupTier(groupId) === 'free-safe')
  plan.policyOnlyHookGroups = plan.activeHookGroups.filter((groupId) => classifyHookGroupTier(groupId) === 'policy-only')
  plan.supportHookGroups = Object.keys(installPlanHookGroups)
    .filter((groupId) => classifyHookGroupTier(groupId) === 'support')
    .sort()
  plan.installPlan.hookGroups = installPlanHookGroups

  return plan
}

export function resolveIastRuntimeBinding({ runtimePlan = null, sinkId = null, ruleId = null, variant = null, fallbackType = null } = {}) {
  const sinkPlan = sinkId && runtimePlan?.bySinkId ? runtimePlan.bySinkId[sinkId] || null : null
  let ruleEntry = null

  if (sinkPlan && variant) {
    ruleEntry = sinkPlan.variants.find((entry) => entry.variantKey === variant || entry.ruleId === variant) || null
  }
  if (!ruleEntry && sinkPlan?.uniqueRuleId) {
    ruleEntry = sinkPlan.variants[0] || null
  }
  if (!ruleEntry && ruleId && runtimePlan?.byRuleId) {
    ruleEntry = runtimePlan.byRuleId[ruleId] || null
  }
  if (!ruleEntry && sinkPlan?.variants?.length) {
    ruleEntry = sinkPlan.variants[0]
  }

  const ruleMeta = ruleEntry?.ruleMeta || {}
  return {
    ruleEntry,
    sinkPlan,
    binding: {
      sink: sinkId || ruleEntry?.sinkId || ruleMeta?.sink || fallbackType || 'iast_sink',
      sinkId: ruleEntry?.sinkId || sinkId || null,
      ruleId: ruleEntry?.ruleId || ruleId || null,
      type: ruleMeta?.message || ruleEntry?.ruleName || ruleMeta?.category || fallbackType || 'iast_sink'
    }
  }
}

export {
  FREE_SAFE_HOOK_GROUPS,
  POLICY_ONLY_HOOK_GROUPS,
}
