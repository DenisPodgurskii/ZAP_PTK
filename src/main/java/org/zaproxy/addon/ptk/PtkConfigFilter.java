package org.zaproxy.addon.ptk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
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
     * {@code null} all definitions are returned unchanged.
     *
     * @param resources loaded SAST, IAST, DAST definitions
     * @param param the param instance to query for enabled state
     * @return map with keys "sast", "iast", "dast"; keys with no enabled rules are omitted
     */
    public static Map<String, PtkModulesDefinition> filter(
            PtkResourcesLoader.LoadedPtkResources resources, PtkParam param) {
        Map<String, PtkModulesDefinition> out = new LinkedHashMap<>();
        if (param == null) {
            if (resources.getSastModules() != null) out.put("sast", resources.getSastModules());
            if (resources.getIastModules() != null) out.put("iast", resources.getIastModules());
            if (resources.getDastModules() != null) out.put("dast", resources.getDastModules());
            return out;
        }
        addFiltered(out, "sast", resources.getSastModules(), param);
        addFiltered(out, "iast", resources.getIastModules(), param);
        addFiltered(out, "dast", resources.getDastModules(), param);
        return out;
    }

    private static void addFiltered(
            Map<String, PtkModulesDefinition> out,
            String key,
            PtkModulesDefinition def,
            PtkParam param) {
        if (def == null) return;
        PtkModulesDefinition filtered = filterDefinition(def, param);
        if (filtered != null) out.put(key, filtered);
    }

    private static PtkModulesDefinition filterDefinition(PtkModulesDefinition def, PtkParam param) {
        if (def == null || def.getModules() == null) return null;
        String engine = def.getEngine();
        List<PtkModule> filteredModules = new ArrayList<>();
        for (PtkModule mod : def.getModules()) {
            String moduleId = mod.getId();
            List<PtkRule> ruleList = null;
            if (mod.getRules() != null) {
                ruleList = new ArrayList<>();
                for (PtkRule r : mod.getRules()) {
                    if (r.getId() != null && param.isRuleEnabled(engine, moduleId, r.getId())) {
                        ruleList.add(r);
                    }
                }
            }
            List<PtkAttack> attackList = null;
            if (mod.getAttacks() != null) {
                attackList = new ArrayList<>();
                for (PtkAttack a : mod.getAttacks()) {
                    if (a.getId() != null && param.isRuleEnabled(engine, moduleId, a.getId())) {
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
