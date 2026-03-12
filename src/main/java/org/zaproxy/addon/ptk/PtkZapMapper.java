package org.zaproxy.addon.ptk;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.zaproxy.addon.ptk.model.EngineMapping;
import org.zaproxy.addon.ptk.model.ModuleRuleMapping;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.addon.ptk.model.ZapMappingDefinition;

/**
 * Maps between PTK module/rule IDs and ZAP alert references (baseAlertId-subId). Supports
 * validation that every rule has a unique alert reference.
 */
public class PtkZapMapper {

    private static final String RULE_KEY_SEP = ":";
    private static final String ALERT_REF_SEP = "-";

    /** (moduleId + ":" + ruleId) → alert reference (e.g. "220000-1"). */
    private final Map<String, String> ruleKeyToAlertRef = new HashMap<>();

    /** Alert reference → (moduleId, ruleId). */
    private final Map<String, ModuleAndRule> alertRefToRule = new HashMap<>();

    private final ZapMappingDefinition zapMapping;

    public PtkZapMapper(PtkResourcesLoader.LoadedPtkResources resources) {
        this.zapMapping = resources.getZapMapping();
        Objects.requireNonNull(zapMapping, "ZapMappingDefinition must not be null");
        for (EngineMapping em : zapMapping.getEngines()) {
            if (em.getModuleMappings() != null && !em.getModuleMappings().isEmpty()) {
                for (ModuleRuleMapping mrm : em.getModuleMappings()) {
                    if (mrm.getRules() == null) continue;
                    int base = mrm.getBaseAlertId();
                    for (Map.Entry<String, Integer> e : mrm.getRules().entrySet()) {
                        String ref = base + ALERT_REF_SEP + e.getValue();
                        String key = ruleKey(mrm.getModuleId(), e.getKey());
                        ruleKeyToAlertRef.put(key, ref);
                        alertRefToRule.put(ref, new ModuleAndRule(mrm.getModuleId(), e.getKey()));
                    }
                }
            } else if (em.getMappings() != null) {
                // v1 fallback: each module → baseAlertId-1
                for (Map.Entry<String, Integer> e : em.getMappings().entrySet()) {
                    String ref = e.getValue() + ALERT_REF_SEP + "1";
                    String key = ruleKey(e.getKey(), null);
                    ruleKeyToAlertRef.put(key, ref);
                    alertRefToRule.put(ref, new ModuleAndRule(e.getKey(), null));
                }
            }
        }
    }

    private static String ruleKey(String moduleId, String ruleId) {
        return ruleId != null ? moduleId + RULE_KEY_SEP + ruleId : moduleId + RULE_KEY_SEP;
    }

    /**
     * Returns the ZAP alert reference for the given module and rule/attack id (e.g. "220000-1"), or
     * null if not mapped. For v1-style mapping without rules, pass ruleId null to get
     * baseAlertId-1.
     */
    public String getZapAlertReference(String moduleId, String ruleId) {
        return ruleKeyToAlertRef.get(ruleKey(moduleId, ruleId));
    }

    /**
     * Returns the module id and rule id for the given ZAP alert reference, or null if not mapped.
     */
    public ModuleAndRule getModuleIdAndRuleId(String alertReference) {
        return alertRefToRule.get(alertReference);
    }

    public Map<String, String> getRuleKeyToAlertRefMap() {
        return Map.copyOf(ruleKeyToAlertRef);
    }

    public Map<String, ModuleAndRule> getAlertRefToRuleMap() {
        return Map.copyOf(alertRefToRule);
    }

    /**
     * Checks that every rule (and attack) in the module definitions has a unique ZAP alert
     * reference, and that no two rules share the same reference.
     *
     * @param resources loaded PTK resources
     * @return result describing whether all rules have unique alert references and any violations
     */
    public OneToOneCheckResult checkUniqueAlertReferences(
            PtkResourcesLoader.LoadedPtkResources resources) {
        List<String> errors = new ArrayList<>();

        // Collect all (engine, moduleId, ruleId) from definitions
        List<RuleRef> expectedRules = new ArrayList<>();
        if (resources != null) {
            for (PtkModulesDefinition def : resources.getAllModuleDefinitions()) {
                if (def.getModules() == null) continue;
                String engine = def.getEngine();
                for (PtkModule m : def.getModules()) {
                    if (m.getId() == null) continue;
                    if (m.getRules() != null) {
                        for (PtkRule r : m.getRules()) {
                            if (r.getId() != null) {
                                expectedRules.add(new RuleRef(engine, m.getId(), r.getId()));
                            }
                        }
                    }
                    if (m.getAttacks() != null) {
                        for (PtkAttack a : m.getAttacks()) {
                            if (a.getId() != null) {
                                expectedRules.add(new RuleRef(engine, m.getId(), a.getId()));
                            }
                        }
                    }
                }
            }
        }

        // Every rule has a reference
        for (RuleRef rr : expectedRules) {
            String ref = getZapAlertReference(rr.getModuleId(), rr.getRuleId());
            if (ref == null) {
                errors.add(
                        "No alert reference for rule "
                                + rr.getRuleId()
                                + " in module "
                                + rr.getModuleId()
                                + " ("
                                + rr.getEngine()
                                + ")");
            }
        }

        // All references are unique (our map construction already ensures ref → single
        // (module,rule); check no duplicate refs)
        Map<String, List<String>> refToKeys = new HashMap<>();
        for (Map.Entry<String, String> e : ruleKeyToAlertRef.entrySet()) {
            refToKeys.computeIfAbsent(e.getValue(), k -> new ArrayList<>()).add(e.getKey());
        }
        for (Map.Entry<String, List<String>> e : refToKeys.entrySet()) {
            if (e.getValue().size() > 1) {
                errors.add(
                        "Alert reference "
                                + e.getKey()
                                + " is mapped by more than one rule: "
                                + e.getValue());
            }
        }

        return new OneToOneCheckResult(errors.isEmpty(), List.copyOf(errors));
    }

    @Getter
    @AllArgsConstructor
    private static final class RuleRef {

        private final String engine;
        private final String moduleId;
        private final String ruleId;
    }

    private static final String MISSING_ALERT_ID = "??????";

    /**
     * Produces lines for ZAP scanners.md: "<base alert id> PTK - <engine> - <module name>", one per
     * module. Sorted by base alert id. Modules with no mapping use ??????.
     */
    public List<String> formatScannersMdLines(PtkResourcesLoader.LoadedPtkResources resources) {
        Objects.requireNonNull(resources, "resources");

        List<ScannersMdEntry> entries = new ArrayList<>();
        for (PtkModulesDefinition def : resources.getAllModuleDefinitions()) {
            if (def.getModules() == null) continue;
            String engine = def.getEngine();
            for (PtkModule m : def.getModules()) {
                if (m.getId() == null) continue;
                String moduleName = m.getName() != null ? m.getName() : m.getId();
                String ref = null;
                if (m.getRules() != null
                        && !m.getRules().isEmpty()
                        && m.getRules().get(0).getId() != null) {
                    ref = getZapAlertReference(m.getId(), m.getRules().get(0).getId());
                }
                if (ref == null
                        && m.getAttacks() != null
                        && !m.getAttacks().isEmpty()
                        && m.getAttacks().get(0).getId() != null) {
                    ref = getZapAlertReference(m.getId(), m.getAttacks().get(0).getId());
                }
                String idStr = MISSING_ALERT_ID;
                Integer baseId = null;
                if (ref != null) {
                    int idx = ref.indexOf(ALERT_REF_SEP);
                    if (idx > 0) {
                        try {
                            baseId = Integer.parseInt(ref.substring(0, idx));
                            idStr = String.valueOf(baseId);
                        } catch (NumberFormatException ignored) {
                            // keep ??????
                        }
                    } else {
                        idStr = ref;
                    }
                }
                entries.add(new ScannersMdEntry(idStr, baseId, engine, moduleName));
            }
        }

        Comparator<ScannersMdEntry> byId =
                Comparator.<ScannersMdEntry, Integer>comparing(
                                e ->
                                        e.getParsedBaseId() != null
                                                ? e.getParsedBaseId()
                                                : Integer.MAX_VALUE)
                        .thenComparing(ScannersMdEntry::getEngine)
                        .thenComparing(ScannersMdEntry::getModuleName);
        entries.sort(byId);

        return entries.stream()
                .map(e -> e.getIdStr() + "  PTK - " + e.getEngine() + " - " + e.getModuleName())
                .collect(Collectors.toList());
    }

    @Getter
    @AllArgsConstructor
    private static final class ScannersMdEntry {

        private final String idStr;
        private final Integer parsedBaseId;
        private final String engine;
        private final String moduleName;
    }

    /** (moduleId, ruleId) pair for reverse lookup. */
    @Getter
    @AllArgsConstructor
    public static final class ModuleAndRule {

        private final String moduleId;
        private final String ruleId;
    }

    /** Result of the unique alert reference check. */
    @Getter
    @AllArgsConstructor
    public static final class OneToOneCheckResult {

        private final boolean oneToOne;
        private final List<String> errors;
    }
}
