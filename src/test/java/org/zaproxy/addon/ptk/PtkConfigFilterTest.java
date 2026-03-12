package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;

/** Unit tests for {@link PtkConfigFilter}. */
class PtkConfigFilterTest {

    @Test
    void filterByCheckedPaths_nullCheckedPaths_returnsAllDefinitionsUnchanged() {
        PtkModulesDefinition sast =
                definition("sast", "SAST", module("m1", rule("r1"), rule("r2")));
        PtkModulesDefinition dast = definition("dast", "DAST", moduleWithAttack("a1", "a2"));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, dast, null);

        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, null);

        assertEquals(2, result.size());
        assertTrue(result.containsKey("sast"));
        assertTrue(result.containsKey("dast"));
        assertEquals(sast, result.get("sast"));
        assertEquals(dast, result.get("dast"));
    }

    @Test
    void filterByCheckedPaths_emptyCheckedPaths_returnsAllDefinitionsUnchanged() {
        PtkModulesDefinition sast = definition("sast", "SAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);

        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of());

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(sast, result.get("sast"));
    }

    @Test
    void filterByCheckedPaths_explicitRulePaths_includesOnlyThoseRules() {
        PtkModule mod1 = module("m1", rule("r1"));
        PtkModule mod2 = module("m2", rule("r2"));
        PtkModulesDefinition sast = definition("sast", "SAST", mod1, mod2);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);
        // Only rule paths are used; engine/module paths do not include all children
        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("0/0/0", "0/1/0"));

        assertEquals(1, result.size());
        PtkModulesDefinition filtered = result.get("sast");
        assertNotNull(filtered);
        assertEquals(2, filtered.getModules().size());
        assertEquals("m1", filtered.getModules().get(0).getId());
        assertEquals("m2", filtered.getModules().get(1).getId());
        assertEquals(1, filtered.getModules().get(0).getRules().size());
        assertEquals(1, filtered.getModules().get(1).getRules().size());
    }

    @Test
    void filterByCheckedPaths_onlyOneRulePath_includesOnlyThatModuleAndRule() {
        PtkModule mod1 = module("m1", rule("r1"));
        PtkModule mod2 = module("m2", rule("r2"));
        PtkModulesDefinition sast = definition("sast", "SAST", mod1, mod2);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);

        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("0/1/0"));

        assertEquals(1, result.size());
        PtkModulesDefinition filtered = result.get("sast");
        assertNotNull(filtered);
        assertEquals(1, filtered.getModules().size());
        assertEquals("m2", filtered.getModules().get(0).getId());
        assertEquals(1, filtered.getModules().get(0).getRules().size());
    }

    @Test
    void filterByCheckedPaths_onlyOneRulePathChecked_includesOnlyThatRule() {
        PtkModule mod = module("m1", rule("r1"), rule("r2"), rule("r3"));
        PtkModulesDefinition sast = definition("sast", "SAST", mod);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);

        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("0/0/1"));

        assertEquals(1, result.size());
        PtkModulesDefinition filtered = result.get("sast");
        assertNotNull(filtered);
        assertEquals(1, filtered.getModules().size());
        assertEquals(1, filtered.getModules().get(0).getRules().size());
        assertEquals("r2", filtered.getModules().get(0).getRules().get(0).getId());
    }

    @Test
    void filterByCheckedPaths_attackPathChecked_includesOnlyThatAttack() {
        PtkModule mod = moduleWithAttack("a1", "a2", "a3");
        PtkModulesDefinition dast = definition("dast", "DAST", mod);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(null, null, dast, null);

        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("0/0/1"));

        assertEquals(1, result.size());
        PtkModulesDefinition filtered = result.get("dast");
        assertNotNull(filtered);
        assertEquals(1, filtered.getModules().size());
        assertEquals(1, filtered.getModules().get(0).getAttacks().size());
        assertEquals("a2", filtered.getModules().get(0).getAttacks().get(0).getId());
    }

    @Test
    void filterByCheckedPaths_noMatchingPaths_returnsEmptyMap() {
        PtkModulesDefinition sast = definition("sast", "SAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);

        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("9/9/9", "1/0/0"));

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void filterByCheckedPaths_treeOrder_whenSastNull_path0RefersToIast() {
        PtkModulesDefinition iast = definition("iast", "IAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(null, iast, null, null);

        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("0/0/0"));

        assertEquals(1, result.size());
        assertTrue(result.containsKey("iast"));
        assertEquals(iast.getEngine(), result.get("iast").getEngine());
        assertEquals(1, result.get("iast").getModules().size());
    }

    @Test
    void filterByCheckedPaths_nullDefinition_omittedFromResult() {
        PtkModulesDefinition sast = definition("sast", "SAST", module("m1", rule("r1")));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, null, null, null);

        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("0/0/0"));

        assertEquals(1, result.size());
        assertNull(result.get("iast"));
        assertNull(result.get("dast"));
    }

    @Test
    void filterByCheckedPaths_moduleWithRulesAndAttacks_filtersByLeafPaths() {
        PtkModule mod = module("m1", rule("r1"), rule("r2"));
        mod.setAttacks(List.of(attack("a1"), attack("a2")));
        PtkModulesDefinition def = definition("mixed", "DAST", mod);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(null, null, def, null);
        // Child indices: 0=r1, 1=r2, 2=a1, 3=a2. Only leaf paths include content.
        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(
                        resources, Set.of("0/0/0", "0/0/1", "0/0/2", "0/0/3"));

        assertEquals(1, result.size());
        PtkModule filteredMod = result.get("dast").getModules().get(0);
        assertEquals(2, filteredMod.getRules().size());
        assertEquals(2, filteredMod.getAttacks().size());
    }

    @Test
    void filterByCheckedPaths_multipleEngines_respectsTreeIndices() {
        PtkModulesDefinition sast = definition("sast", "SAST", module("s1", rule("r1")));
        PtkModulesDefinition iast = definition("iast", "IAST", module("i1", rule("r1")));
        PtkModulesDefinition dast = definition("dast", "DAST", moduleWithAttack("a1"));
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(sast, iast, dast, null);
        // Only enable the one IAST rule (engine index 1, module 0, rule 0)
        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("1/0/0"));

        assertEquals(1, result.size());
        assertTrue(result.containsKey("iast"));
        assertEquals("IAST", result.get("iast").getEngine());
        assertEquals(1, result.get("iast").getModules().size());
    }

    @Test
    void filterByCheckedPaths_oneDastRuleWithParentPaths_returnsOnlyThatRule() {
        PtkModule mod = moduleWithAttack("a1", "a2", "a3");
        PtkModulesDefinition dast = definition("dast", "DAST", mod);
        PtkResourcesLoader.LoadedPtkResources resources =
                new PtkResourcesLoader.LoadedPtkResources(null, null, dast, null);
        // Simulate tree storing parent paths when one rule is checked (e.g. "0", "0/0", "0/0/1")
        Map<String, PtkModulesDefinition> result =
                PtkConfigFilter.filterByCheckedPaths(resources, Set.of("0", "0/0", "0/0/1"));

        assertEquals(1, result.size());
        PtkModulesDefinition filtered = result.get("dast");
        assertNotNull(filtered);
        assertEquals(1, filtered.getModules().size());
        assertEquals(1, filtered.getModules().get(0).getAttacks().size());
        assertEquals("a2", filtered.getModules().get(0).getAttacks().get(0).getId());
    }

    // --- helpers ---

    private static PtkModulesDefinition definition(
            String engine, String engineName, PtkModule... modules) {
        PtkModulesDefinition def = new PtkModulesDefinition();
        def.setSchema("ptk-" + engine.toLowerCase() + "-rulepack/v1");
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

    private static PtkModule moduleWithAttack(String... attackIds) {
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
