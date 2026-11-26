package org.zaproxy.addon.ptk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.addon.ptk.options.EngineRunLocation;
import org.zaproxy.addon.ptk.options.PtkParam;

/**
 * Filters PTK module definitions to only include rules and attacks that are enabled according to
 * {@link PtkParam}. Each leaf (rule/attack) is included iff {@link PtkParam#isRuleEnabled} returns
 * {@code true}; inheritance is handled by {@code isRuleEnabled} itself, so no short-circuiting at
 * the engine or module level is needed here.
 */
public final class PtkConfigFilter {

    private PtkConfigFilter() {}

    /**
     * Returns definitions filtered by the enabled flags in {@code param}. If {@code param} is
     * {@code null} all definitions are returned unchanged. No run-location filtering is applied.
     *
     * @param resources loaded SAST, IAST, DAST definitions
     * @param param the param instance to query for enabled state
     * @return map with keys "sast", "iast", "dast"; keys with no enabled rules are omitted
     */
    public static Map<String, PtkModulesDefinition> filter(
            PtkResourcesLoader.LoadedPtkResources resources, PtkParam param) {
        return filter(resources, param, null);
    }

    /**
     * Returns definitions filtered by the enabled flags in {@code param} and by {@code
     * currentContext}. Engines whose configured run location does not match {@code currentContext}
     * are excluded entirely. A {@code null} context disables run-location filtering (all engines
     * pass). If {@code param} is {@code null} all definitions are returned unchanged.
     *
     * @param resources loaded SAST, IAST, DAST definitions
     * @param param the param instance to query for enabled state and run locations
     * @param currentContext the scan context in which this config is being served, or {@code null}
     *     to skip run-location filtering
     * @return map with keys "sast", "iast", "dast"; keys with no enabled rules are omitted
     */
    public static Map<String, PtkModulesDefinition> filter(
            PtkResourcesLoader.LoadedPtkResources resources,
            PtkParam param,
            EngineRunLocation currentContext) {
        Map<String, PtkModulesDefinition> out = new LinkedHashMap<>();
        if (param == null) {
            if (resources.getSastModules() != null) out.put("sast", resources.getSastModules());
            if (resources.getIastModules() != null) out.put("iast", resources.getIastModules());
            if (resources.getDastModules() != null) out.put("dast", resources.getDastModules());
            return out;
        }
        addFiltered(out, "sast", resources.getSastModules(), param, resources, currentContext);
        addFiltered(out, "iast", resources.getIastModules(), param, resources, currentContext);
        addFiltered(out, "dast", resources.getDastModules(), param, resources, currentContext);
        return out;
    }

    /**
     * Tells whether or not the given rule/attack is enabled: per "Use recommended defaults" if that
     * is selected, otherwise per {@link PtkParam#isRuleEnabled}.
     *
     * @param engine the engine name, e.g. "DAST"
     * @param moduleId the module id
     * @param ruleId the rule or attack id
     * @param param the param instance to query for enabled state
     * @param resources the loaded definitions, for the recommended defaults
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public static boolean isRuleEnabled(
            String engine,
            String moduleId,
            String ruleId,
            PtkParam param,
            PtkResourcesLoader.LoadedPtkResources resources) {
        return param.isUseRecommendedDefaults()
                ? resources.isRecommendedEnabled(engine, moduleId, ruleId)
                : param.isRuleEnabled(engine, moduleId, ruleId);
    }

    /**
     * Tells whether or not the given module is enabled, that is, whether at least one of its rules
     * or attacks is enabled (see {@link #isRuleEnabled}), and so would be included by {@link
     * #filter}.
     *
     * @param engine the engine name, e.g. "DAST"
     * @param module the module
     * @param param the param instance to query for enabled state
     * @param resources the loaded definitions, for the recommended defaults
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public static boolean isModuleEnabled(
            String engine,
            PtkModule module,
            PtkParam param,
            PtkResourcesLoader.LoadedPtkResources resources) {
        return Stream.concat(
                        module.getRules() == null
                                ? Stream.<String>empty()
                                : module.getRules().stream().map(PtkRule::getId),
                        module.getAttacks() == null
                                ? Stream.<String>empty()
                                : module.getAttacks().stream().map(PtkAttack::getId))
                .filter(Objects::nonNull)
                .anyMatch(id -> isRuleEnabled(engine, module.getId(), id, param, resources));
    }

    private static void addFiltered(
            Map<String, PtkModulesDefinition> out,
            String key,
            PtkModulesDefinition def,
            PtkParam param,
            PtkResourcesLoader.LoadedPtkResources resources,
            EngineRunLocation currentContext) {
        if (def == null) return;
        if (currentContext != null) {
            String engineName = def.getEngine();
            if (engineName != null && param.getEngineRunLocation(engineName) != currentContext) {
                return;
            }
        }
        PtkModulesDefinition filtered = filterDefinition(def, param, resources);
        if (filtered != null) out.put(key, filtered);
    }

    private static PtkModulesDefinition filterDefinition(
            PtkModulesDefinition def,
            PtkParam param,
            PtkResourcesLoader.LoadedPtkResources resources) {
        if (def == null || def.getModules() == null) return null;
        String engine = def.getEngine();
        List<PtkModule> filteredModules = new ArrayList<>();
        for (PtkModule mod : def.getModules()) {
            String moduleId = mod.getId();
            List<PtkRule> ruleList = null;
            if (mod.getRules() != null) {
                ruleList = new ArrayList<>();
                for (PtkRule r : mod.getRules()) {
                    boolean enabled = isRuleEnabled(engine, moduleId, r.getId(), param, resources);
                    if (r.getId() != null && enabled) {
                        ruleList.add(r);
                    }
                }
            }
            List<PtkAttack> attackList = null;
            if (mod.getAttacks() != null) {
                attackList = new ArrayList<>();
                for (PtkAttack a : mod.getAttacks()) {
                    boolean enabled = isRuleEnabled(engine, moduleId, a.getId(), param, resources);
                    if (a.getId() != null && enabled) {
                        attackList.add(a);
                    }
                }
            }
            if ((ruleList != null && !ruleList.isEmpty())
                    || (attackList != null && !attackList.isEmpty())) {
                PtkModule filteredMod = new PtkModule();
                filteredMod.setId(mod.getId());
                filteredMod.setType(mod.getType());
                filteredMod.setAsync(mod.isAsync());
                filteredMod.setName(mod.getName());
                filteredMod.setMetadata(mod.getMetadata());
                filteredMod.setRuntime(mod.getRuntime());
                filteredMod.setRules(ruleList);
                filteredMod.setAttacks(attackList);
                filteredModules.add(filteredMod);
            }
        }
        if (filteredModules.isEmpty()) return null;
        PtkModulesDefinition result = new PtkModulesDefinition();
        result.setSchema(def.getSchema());
        result.setEngine(def.getEngine());
        result.setVersion(def.getVersion());
        result.setModules(filteredModules);
        return result;
    }
}
