package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.ptk.model.EngineMapping;
import org.zaproxy.addon.ptk.model.ModuleRuleMapping;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.addon.ptk.model.ZapMappingDefinition;

/**
 * Unit tests for {@link ZapMappingUpdater} merge logic: preserve existing IDs, add new
 * rules/modules.
 */
class ZapMappingUpdaterTest {

    @Test
    void merge_preservesExistingBaseAlertIdAndRuleSubIds() {
        ZapMappingDefinition existing = new ZapMappingDefinition();
        existing.setEngines(List.of(engineWithModule("SAST", "m1", 220000, Map.of("r1", 1))));
        PtkModulesDefinition def = new PtkModulesDefinition();
        def.setEngine("SAST");
        def.setModules(List.of(moduleWithRules("m1", List.of(rule("r1")))));

        ZapMappingDefinition out = ZapMappingUpdater.merge(existing, def, null, null);

        EngineMapping em =
                out.getEngines().stream()
                        .filter(e -> "SAST".equals(e.getEngine()))
                        .findFirst()
                        .orElseThrow();
        ModuleRuleMapping mrm =
                em.getModuleMappings().stream()
                        .filter(m -> "m1".equals(m.getModuleId()))
                        .findFirst()
                        .orElseThrow();
        assertEquals(220000, mrm.getBaseAlertId());
        assertEquals(Map.of("r1", 1), mrm.getRules());
    }

    @Test
    void merge_addsNewRuleWithNextSubId() {
        ZapMappingDefinition existing = new ZapMappingDefinition();
        existing.setEngines(List.of(engineWithModule("SAST", "m1", 220000, Map.of("r1", 1))));
        PtkModulesDefinition def = new PtkModulesDefinition();
        def.setEngine("SAST");
        def.setModules(List.of(moduleWithRules("m1", List.of(rule("r1"), rule("r2")))));

        ZapMappingDefinition out = ZapMappingUpdater.merge(existing, def, null, null);

        ModuleRuleMapping mrm = findModule(out, "SAST", "m1");
        assertNotNull(mrm);
        assertEquals(220000, mrm.getBaseAlertId());
        assertEquals(1, mrm.getRules().get("r1"));
        assertEquals(2, mrm.getRules().get("r2"));
    }

    @Test
    void merge_addsNewModuleWithNextBaseId() {
        ZapMappingDefinition existing = new ZapMappingDefinition();
        existing.setEngines(List.of(engineWithModule("SAST", "m1", 220000, Map.of("r1", 1))));
        PtkModulesDefinition def = new PtkModulesDefinition();
        def.setEngine("SAST");
        def.setModules(
                List.of(
                        moduleWithRules("m1", List.of(rule("r1"))),
                        moduleWithRules("m2", List.of(rule("r1"), rule("r2")))));

        ZapMappingDefinition out = ZapMappingUpdater.merge(existing, def, null, null);

        ModuleRuleMapping m1 = findModule(out, "SAST", "m1");
        ModuleRuleMapping m2 = findModule(out, "SAST", "m2");
        assertNotNull(m1);
        assertNotNull(m2);
        assertEquals(220000, m1.getBaseAlertId());
        assertEquals(220001, m2.getBaseAlertId());
        assertEquals(Map.of("r1", 1, "r2", 2), m2.getRules());
    }

    @Test
    void merge_withNoExisting_createsFullMapping() {
        ZapMappingDefinition existing = null;
        PtkModulesDefinition def = new PtkModulesDefinition();
        def.setEngine("SAST");
        def.setModules(List.of(moduleWithRules("m1", List.of(rule("r1")))));

        ZapMappingDefinition out = ZapMappingUpdater.merge(existing, def, null, null);

        assertEquals("ptk-zap-mapping-v1", out.getSchema());
        assertEquals(1, out.getVersion());
        assertNotNull(out.getEngines());
        ModuleRuleMapping m1 = findModule(out, "SAST", "m1");
        assertNotNull(m1);
        assertEquals(220000, m1.getBaseAlertId());
        assertEquals(Map.of("r1", 1), m1.getRules());
    }

    private static EngineMapping engineWithModule(
            String engine, String moduleId, int baseAlertId, Map<String, Integer> rules) {
        EngineMapping em = new EngineMapping();
        em.setEngine(engine);
        ModuleRuleMapping mrm = new ModuleRuleMapping();
        mrm.setModuleId(moduleId);
        mrm.setBaseAlertId(baseAlertId);
        mrm.setRules(new LinkedHashMap<>(rules));
        em.setModuleMappings(List.of(mrm));
        return em;
    }

    private static PtkModule moduleWithRules(String moduleId, List<PtkRule> rules) {
        PtkModule m = new PtkModule();
        m.setId(moduleId);
        m.setName(moduleId);
        m.setRules(rules);
        return m;
    }

    private static PtkRule rule(String id) {
        PtkRule r = new PtkRule();
        r.setId(id);
        return r;
    }

    private static ModuleRuleMapping findModule(
            ZapMappingDefinition def, String engine, String moduleId) {
        return def.getEngines().stream()
                .filter(e -> engine.equals(e.getEngine()))
                .flatMap(e -> e.getModuleMappings().stream())
                .filter(m -> moduleId.equals(m.getModuleId()))
                .findFirst()
                .orElse(null);
    }
}
