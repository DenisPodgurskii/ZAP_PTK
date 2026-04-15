package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.addon.ptk.options.PtkParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link PtkConfigFilter}. */
class PtkConfigFilterTest {

    private PtkParam param;

    @BeforeEach
    void setUp() {
        param = new PtkParam();
        param.load(new ZapXmlConfiguration());
    }

    // --- default (no flags) ---

    @Test
    void filter_noFlags_returnsAllDefinitions() {
        PtkModulesDefinition sast = definition("SAST", module("m1", rule("r1"), rule("r2")));
        PtkModulesDefinition dast = definition("DAST", moduleWithAttacks("a1", "a2"));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, dast, null);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        assertEquals(2, result.size());
        assertEquals("SAST", result.get("sast").getEngine());
        assertEquals(1, result.get("sast").getModules().size());
        assertEquals("DAST", result.get("dast").getEngine());
        assertEquals(1, result.get("dast").getModules().size());
    }

    @Test
    void filter_nullParam_returnsAllDefinitions() {
        PtkModulesDefinition sast = definition("SAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, null);

        assertEquals(1, result.size());
        assertEquals("SAST", result.get("sast").getEngine());
    }

    // --- engine-level disabled ---

    @Test
    void filter_engineDisabled_excludesAllRulesInEngine() {
        PtkModulesDefinition sast = definition("SAST", module("m1", rule("r1")));
        PtkModulesDefinition iast = definition("IAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, iast, null, null);
        param.setEngineEnabled("SAST", false);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        assertEquals(1, result.size());
        assertNull(result.get("sast"));
        assertNotNull(result.get("iast"));
    }

    @Test
    void filter_allEnginesDisabled_returnsEmptyMap() {
        PtkModulesDefinition sast = definition("SAST", module("m1", rule("r1")));
        PtkModulesDefinition iast = definition("IAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, iast, null, null);
        param.setEngineEnabled("SAST", false);
        param.setEngineEnabled("IAST", false);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        assertTrue(result.isEmpty());
    }

    // --- module-level disabled ---

    @Test
    void filter_moduleDisabled_excludesAllRulesInModule() {
        PtkModule m1 = module("m1", rule("r1"));
        PtkModule m2 = module("m2", rule("r2"));
        PtkModulesDefinition sast = definition("SAST", m1, m2);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);
        param.setModuleEnabled("SAST", "m1", false);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        assertEquals(1, result.size());
        PtkModulesDefinition filtered = result.get("sast");
        assertNotNull(filtered);
        assertEquals(1, filtered.getModules().size());
        assertEquals("m2", filtered.getModules().get(0).getId());
    }

    @Test
    void filter_allModulesInEngineDisabled_engineOmittedFromResult() {
        PtkModulesDefinition sast = definition("SAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);
        param.setModuleEnabled("SAST", "m1", false);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        assertTrue(result.isEmpty());
    }

    // --- rule-level disabled ---

    @Test
    void filter_ruleDisabled_excludesOnlyThatRule() {
        PtkModule mod = module("m1", rule("r1"), rule("r2"), rule("r3"));
        PtkModulesDefinition sast = definition("SAST", mod);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);
        param.setRuleEnabled("SAST", "m1", "r2", false);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        PtkModulesDefinition filtered = result.get("sast");
        assertNotNull(filtered);
        assertEquals(1, filtered.getModules().size());
        List<PtkRule> rules = filtered.getModules().get(0).getRules();
        assertEquals(2, rules.size());
        assertEquals("r1", rules.get(0).getId());
        assertEquals("r3", rules.get(1).getId());
    }

    @Test
    void filter_attackDisabled_excludesOnlyThatAttack() {
        PtkModule mod = moduleWithAttacks("a1", "a2", "a3");
        PtkModulesDefinition dast = definition("DAST", mod);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(null, null, dast, null);
        param.setRuleEnabled("DAST", "dast-mod", "a2", false);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        PtkModulesDefinition filtered = result.get("dast");
        assertNotNull(filtered);
        List<PtkAttack> attacks = filtered.getModules().get(0).getAttacks();
        assertEquals(2, attacks.size());
        assertEquals("a1", attacks.get(0).getId());
        assertEquals("a3", attacks.get(1).getId());
    }

    // --- child overrides parent ---

    @Test
    void filter_ruleTrueOverridesEngineFalse_ruleIsIncluded() {
        PtkModule m1 = module("m1", rule("r1"), rule("r2"));
        PtkModulesDefinition sast = definition("SAST", m1);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);
        param.setEngineEnabled("SAST", false);
        param.setRuleEnabled("SAST", "m1", "r1", true); // override

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        PtkModulesDefinition filtered = result.get("sast");
        assertNotNull(filtered);
        assertEquals(1, filtered.getModules().get(0).getRules().size());
        assertEquals("r1", filtered.getModules().get(0).getRules().get(0).getId());
    }

    // --- null definition omitted ---

    @Test
    void filter_nullDefinition_omittedFromResult() {
        PtkModulesDefinition sast = definition("SAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        assertEquals(1, result.size());
        assertNull(result.get("iast"));
        assertNull(result.get("dast"));
    }

    // --- multiple engines independent ---

    @Test
    void filter_multipleEngines_eachIndependentlyConfigured() {
        PtkModulesDefinition sast = definition("SAST", module("s1", rule("r1")));
        PtkModulesDefinition iast = definition("IAST", module("i1", rule("r1")));
        PtkModulesDefinition dast = definition("DAST", moduleWithAttacks("a1"));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, iast, dast, null);
        param.setEngineEnabled("SAST", false);
        param.setEngineEnabled("DAST", false);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        assertEquals(1, result.size());
        assertNotNull(result.get("iast"));
        assertEquals("IAST", result.get("iast").getEngine());
    }

    @Test
    void filter_moduleWithRulesAndAttacks_eachFilteredIndependently() {
        PtkModule mod = module("m1", rule("r1"), rule("r2"));
        mod.setAttacks(List.of(attack("a1"), attack("a2")));
        PtkModulesDefinition dast = definition("DAST", mod);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(null, null, dast, null);
        param.setRuleEnabled("DAST", "m1", "r1", false);
        param.setRuleEnabled("DAST", "m1", "a2", false);

        Map<String, PtkModulesDefinition> result = PtkConfigFilter.filter(resources, param);

        PtkModule filtered = result.get("dast").getModules().get(0);
        assertEquals(1, filtered.getRules().size());
        assertEquals("r2", filtered.getRules().get(0).getId());
        assertEquals(1, filtered.getAttacks().size());
        assertEquals("a1", filtered.getAttacks().get(0).getId());
    }

    // --- helpers ---

    private static PtkModulesDefinition definition(String engineName, PtkModule... modules) {
        PtkModulesDefinition def = new PtkModulesDefinition();
        def.setEngine(engineName);
        def.setVersion(1);
        def.setModules(List.of(modules));
        return def;
    }

    private static PtkModule module(String moduleId, PtkRule... rules) {
        PtkModule mod = new PtkModule();
        mod.setId(moduleId);
        mod.setName(moduleId);
        mod.setRules(List.of(rules));
        return mod;
    }

    private static PtkModule moduleWithAttacks(String... attackIds) {
        PtkModule mod = new PtkModule();
        mod.setId("dast-mod");
        mod.setName("dast-mod");
        mod.setAttacks(Arrays.stream(attackIds).map(PtkConfigFilterTest::attack).toList());
        return mod;
    }

    private static PtkRule rule(String id) {
        PtkRule r = new PtkRule();
        r.setId(id);
        r.setName(id);
        return r;
    }

    private static PtkAttack attack(String id) {
        PtkAttack a = new PtkAttack();
        a.setId(id);
        a.setName(id);
        return a;
    }
}
