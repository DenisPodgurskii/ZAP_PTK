/* Author: Denis Podgurskii */

import { assertRulepackCatalogCompatibility } from "./catalog_validation.js";

export class SastConfigService {
  constructor({
    browserApi = browser,
    fetchFn = null,
    loadRulepackFn = async () => ({ modules: [] }),
    normalizeRulepackFn = () => {}
  } = {}) {
    this.browserApi = browserApi;
    const resolvedFetch = typeof fetchFn === "function"
      ? fetchFn
      : (typeof globalThis?.fetch === "function" ? globalThis.fetch.bind(globalThis) : null);
    this.fetchFn = resolvedFetch;
    this.loadRulepackFn = loadRulepackFn;
    this.normalizeRulepackFn = normalizeRulepackFn;
    this.defaultModulesCache = null;
  }

  async getDefaultModules(rulepack = null) {
    if (rulepack && Array.isArray(rulepack.modules)) {
      this.defaultModulesCache = rulepack.modules;
      return this.defaultModulesCache;
    }
    if (Array.isArray(this.defaultModulesCache) && this.defaultModulesCache.length) {
      return this.defaultModulesCache;
    }
    try {
      const localPack = await this.loadRulepackFn("SAST");
      this.normalizeRulepackFn(localPack, { engine: "SAST", childKey: "rules" });
      this.defaultModulesCache = localPack.modules || [];
    } catch (err) {
      console.warn("[PTK SAST] Failed to load default SAST modules", err);
      this.defaultModulesCache = [];
    }
    return this.defaultModulesCache;
  }

  async prepareOptions(scanStrategyRaw, opts = {}) {
    let rulepack = opts?.rulepack;
    let catalog = opts?.catalog;

    if (!rulepack || typeof rulepack !== "object") {
      rulepack = await this.loadRulepackFn("SAST", opts);
    }

    if (!catalog || typeof catalog !== "object") {
      if (typeof this.fetchFn !== "function") {
        throw new Error("sast_catalog_fetch_unavailable");
      }
      const catalogUrl = this.browserApi.runtime.getURL("ptk/background/sast/modules/catalog.json");
      catalog = await this.fetchFn(catalogUrl).then(res => res.json());
    }

    this.normalizeRulepackFn(rulepack, { engine: "SAST", childKey: "rules" });
    assertRulepackCatalogCompatibility(rulepack, catalog, { label: "SAST runtime rulepack" });
    if (rulepack && Array.isArray(rulepack.modules)) {
      this.defaultModulesCache = rulepack.modules;
    }

    const scanStrategySettings = (scanStrategyRaw && typeof scanStrategyRaw === "object") ? scanStrategyRaw : {};
    let scanStrategyCode = (typeof scanStrategyRaw === "number" || typeof scanStrategyRaw === "string")
      ? Number(scanStrategyRaw)
      : Number(
        scanStrategySettings.scanStrategyCode ??
        scanStrategySettings.scanStrategy ??
        scanStrategySettings.policyCode ??
        scanStrategySettings.policy ??
        0
      );
    if (!Number.isFinite(scanStrategyCode)) scanStrategyCode = 0;

    const scanStrategy = Object.assign({}, scanStrategySettings, { scanStrategyCode });
    const pages = Array.isArray(opts?.pages) ? opts.pages : null;
    const mergedOpts = Object.assign({}, opts, {
      rulepack,
      catalog,
      pages: pages || scanStrategy.pages || scanStrategy.routes || [],
      spaDelayMs: opts?.spaDelayMs || scanStrategy.spaDelayMs || scanStrategy.spaDelay || null,
      scanStrategyCode,
    });

    return { scanStrategy, opts: mergedOpts, scanStrategyCode };
  }
}

export default SastConfigService;
