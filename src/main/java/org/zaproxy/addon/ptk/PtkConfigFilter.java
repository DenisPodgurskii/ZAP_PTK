package org.zaproxy.addon.ptk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.addon.ptk.options.PtkParam;

/**
 * Filters PTK module definitions to only include engines, modules, and rules/attacks that are
 * enabled (checked) in the options panel. Only the exact path for a rule/attack is used: a rule or
 * attack is included only when its path (e.g. "engineIdx/moduleIdx/childIdx") is in the checked
 * set. Parent paths (engine or module) are ignored for inclusion, so selecting one rule does not
 * include the whole engine or module.
 */
public final class PtkConfigFilter {

    private PtkConfigFilter() {}

    /**
     * Returns definitions filtered by the checked path set. If {@code checkedPaths} is null or
     * empty, all definitions are returned (default-all behavior). Otherwise only
     * engines/modules/rules that correspond to checked paths are included.
     *
     * @param resources loaded SAST, IAST, DAST definitions
     * @param checkedPaths path strings from {@link PtkParam}
     * @return map with keys "sast", "iast", "dast" and filtered (or full) definitions; keys with
     *     null definitions are omitted
     */
    public static Map<String, PtkModulesDefinition> filterByCheckedPaths(
            PtkResourcesLoader.LoadedPtkResources resources, Set<String> checkedPaths) {
        Map<String, PtkModulesDefinition> out = new LinkedHashMap<>();
        boolean filter = checkedPaths != null && !checkedPaths.isEmpty();
        PtkModulesDefinition sast = resources.getSastModules();
        PtkModulesDefinition iast = resources.getIastModules();
        PtkModulesDefinition dast = resources.getDastModules();
        if (!filter) {
            if (sast != null) out.put("sast", sast);
            if (iast != null) out.put("iast", iast);
            if (dast != null) out.put("dast", dast);
            return out;
        }
        // Tree order: same as options panel (sast, iast, dast when non-null). Path "0"/"1"/"2"
        // refer to tree child index.
        List<String> keys = new ArrayList<>();
        List<PtkModulesDefinition> defs = new ArrayList<>();
        if (sast != null) {
            keys.add("sast");
            defs.add(sast);
        }
        if (iast != null) {
            keys.add("iast");
            defs.add(iast);
        }
        if (dast != null) {
            keys.add("dast");
            defs.add(dast);
        }
        for (int treeIndex = 0; treeIndex < defs.size(); treeIndex++) {
            PtkModulesDefinition filtered =
                    filterDefinition(defs.get(treeIndex), treeIndex, checkedPaths);
            if (filtered != null) {
                out.put(keys.get(treeIndex), filtered);
            }
        }
        return out;
    }

    /** Filters one engine definition by path set. Only rule/attack paths are used for inclusion. */
    private static PtkModulesDefinition filterDefinition(
            PtkModulesDefinition def, int engineIndex, Set<String> checked) {
        if (def == null || def.getModules() == null) return null;
        List<PtkModule> filteredModules = new ArrayList<>();
        for (int m = 0; m < def.getModules().size(); m++) {
            PtkModule mod = def.getModules().get(m);
            String modulePath = engineIndex + "/" + m;
            int childIdx = 0;
            List<PtkRule> ruleList = null;
            if (mod.getRules() != null) {
                ruleList = new ArrayList<>();
                for (PtkRule r : mod.getRules()) {
                    String nodePath = modulePath + "/" + childIdx;
                    if (checked.contains(nodePath)) ruleList.add(r);
                    childIdx++;
                }
            }
            List<PtkAttack> attackList = null;
            if (mod.getAttacks() != null) {
                attackList = new ArrayList<>();
                for (PtkAttack a : mod.getAttacks()) {
                    String nodePath = modulePath + "/" + childIdx;
                    if (checked.contains(nodePath)) attackList.add(a);
                    childIdx++;
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
