package org.zaproxy.addon.ptk.gspm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar.RuleOwner;
import org.zaproxy.addon.ptk.PtkAlertBuilder;
import org.zaproxy.addon.ptk.PtkResourcesLoader;
import org.zaproxy.addon.ptk.PtkResourcesLoader.LoadedPtkResources;
import org.zaproxy.addon.ptk.gspm.GspmPtkRegistrar.Engine;
import org.zaproxy.addon.ptk.model.ModuleRuleMapping;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.addon.ptk.options.PtkParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link GspmPtkRegistrar}, using the PTK definitions bundled with the add-on. */
class GspmPtkRegistrarTest {

    private static final UnaryOperator<String> MESSAGES = key -> "msg:" + key;

    private LoadedPtkResources resources;
    private PtkParam param;
    private GspmPtkRegistrar registrar;

    @BeforeEach
    void setUp() {
        resources = new PtkResourcesLoader().loadAll();
        param = new PtkParam();
        param.load(new ZapXmlConfiguration());
        param.setUseRecommendedDefaults(false);
        registrar =
                new GspmPtkRegistrar(
                        MESSAGES, () -> "Client Browser", () -> resources, () -> param, null);
    }

    @Test
    void shouldRegisterOneRuleForEachMappedModuleUsingItsBaseAlertId() {
        for (Engine engine : Engine.values()) {
            // Given
            Map<String, Integer> alertIds =
                    GspmPtkRegistrar.getModuleAlertIds(resources.getZapMapping(), engine);
            List<PtkModule> modules = engine.getModules(resources).getModules();

            // When
            List<GspmRule> rules = rules(engine);

            // Then
            assertEquals(modules.size(), rules.size(), engine.name());
            for (int i = 0; i < modules.size(); i++) {
                assertEquals(alertIds.get(modules.get(i).getId()), rules.get(i).getId());
            }
        }
    }

    @Test
    void shouldHaveUniqueIdsAcrossAllEngines() {
        // Given
        Set<Integer> ids = new HashSet<>();
        int count = 0;

        // When
        for (Engine engine : Engine.values()) {
            for (GspmRule rule : rules(engine)) {
                ids.add(rule.getId());
                count++;
            }
        }

        // Then
        assertEquals(count, ids.size());
    }

    @Test
    void shouldPlaceEachEngineUnderItsToolPhaseAndCategories() {
        assertEngine(Engine.DAST, "ptk-dast", GspmPhase.ACTIVE, "dast");
        assertEngine(Engine.IAST, "ptk-iast", GspmPhase.ACTIVE, "iast");
        assertEngine(Engine.SAST, "ptk-sast", GspmPhase.PASSIVE, "sast");
    }

    @Test
    void shouldUseModuleNameAndTags() {
        // Given
        PtkModule module = Engine.DAST.getModules(resources).getModules().get(0);

        // When
        GspmRule rule = rules(Engine.DAST).get(0);

        // Then
        assertEquals(module.getName(), rule.getName());
        assertEquals(PtkAlertBuilder.getModuleTags(module), rule.getAlertTags());
        assertEquals(
                List.copyOf(PtkAlertBuilder.getModuleTags(module).keySet()),
                List.copyOf(rule.getAlertTags().keySet()));
        assertTrue(rule.getAlertTags().containsKey(PtkAlertBuilder.TAG_TOOL_PTK));
        assertNull(rule.getAttackStrength());
    }

    @Test
    void shouldBeEnabledWhileAnyRuleOfTheModuleIsEnabled() {
        // Given
        PtkModule module = moduleWithRules(Engine.SAST);
        GspmRule rule = ruleFor(Engine.SAST, module);
        List<PtkRule> moduleRules = module.getRules();
        for (int i = 1; i < moduleRules.size(); i++) {
            param.setRuleEnabled("SAST", module.getId(), moduleRules.get(i).getId(), false);
        }

        // When / Then
        assertTrue(rule.isEnabled());
        assertEquals(AlertThreshold.MEDIUM, rule.getAlertThreshold());

        // When
        param.setRuleEnabled("SAST", module.getId(), moduleRules.get(0).getId(), false);

        // Then
        assertFalse(rule.isEnabled());
        assertEquals(AlertThreshold.OFF, rule.getAlertThreshold());
    }

    @Test
    void shouldBeDisabledWhenTheEngineIsDisabled() {
        // Given
        GspmRule rule = rules(Engine.IAST).get(0);

        // When
        param.setEngineEnabled("IAST", false);

        // Then
        assertFalse(rule.isEnabled());
    }

    @Test
    void shouldFollowRecommendedDefaultsWhenSelected() {
        // Given
        param.setUseRecommendedDefaults(true);
        ModuleRuleMapping notRecommended =
                resources.getZapMapping().getEngines().stream()
                        .filter(e -> "DAST".equalsIgnoreCase(e.getEngine()))
                        .flatMap(e -> e.getModuleMappings().stream())
                        .filter(
                                mm ->
                                        !mm.isRecommended()
                                                && mm.getRecommendedRuleOverrides() == null)
                        .findFirst()
                        .orElseThrow();

        // When
        GspmRule rule =
                rules(Engine.DAST).stream()
                        .filter(r -> r.getId() == notRecommended.getBaseAlertId())
                        .findFirst()
                        .orElseThrow();

        // Then
        assertFalse(rule.isEnabled());
    }

    @Test
    void shouldNotChangePtkConfigurationWhenChangedViaGspm() {
        // Given
        GspmRule rule = rules(Engine.DAST).get(0);

        // When
        rule.setEnabled(false);
        rule.setAlertThreshold(AlertThreshold.OFF);

        // Then
        assertTrue(rule.isEnabled());
    }

    @Test
    void shouldRegisterAndUnregisterAllEnginesWithGspm() {
        // Given
        GspmRegistry registry = new GspmRegistry();
        int expected = 0;
        for (Engine engine : Engine.values()) {
            expected += rules(engine).size();
        }

        // When
        registrar.getRuleSources().forEach(s -> s.registerRulesWithGspm(registry));

        // Then
        assertEquals(expected, registry.getAllRules().size());
        assertEquals(rules(Engine.SAST).size(), registry.getRulesByTool("ptk-sast").size());
        assertEquals("msg:ptk.gspm.tool.dast", registry.getToolDisplayName("ptk-dast"));

        // When
        registrar.getRuleSources().forEach(s -> s.unregisterRulesFromGspm(registry));

        // Then
        assertTrue(registry.getAllRules().isEmpty());
    }

    private void assertEngine(Engine engine, String tool, GspmPhase phase, String category) {
        for (GspmRule rule : rules(engine)) {
            assertEquals(tool, rule.getTool());
            assertEquals(phase, rule.getPhase());
            assertEquals(
                    List.of(
                            new GspmCategory("browser", "Client Browser"),
                            new GspmCategory(category, "msg:ptk.gspm.category." + category)),
                    rule.getCategories());
        }
    }

    private List<GspmRule> rules(Engine engine) {
        return registrar.getRules(engine).stream().map(RuleOwner::rule).toList();
    }

    private PtkModule moduleWithRules(Engine engine) {
        return engine.getModules(resources).getModules().stream()
                .filter(m -> m.getRules() != null && m.getRules().size() > 1)
                .findFirst()
                .orElseThrow();
    }

    private GspmRule ruleFor(Engine engine, PtkModule module) {
        int id =
                GspmPtkRegistrar.getModuleAlertIds(resources.getZapMapping(), engine)
                        .get(module.getId());
        return rules(engine).stream().filter(r -> r.getId() == id).findFirst().orElseThrow();
    }
}
