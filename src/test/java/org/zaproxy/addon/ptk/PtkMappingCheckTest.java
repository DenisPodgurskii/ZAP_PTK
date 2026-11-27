package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.ptk.model.EngineMapping;
import org.zaproxy.addon.ptk.model.ModuleRuleMapping;
import org.zaproxy.addon.ptk.model.ZapMappingDefinition;

/** Unit tests for {@link PtkMappingCheck}. */
class PtkMappingCheckTest {

    @Test
    void shouldHaveOnlyKnownPolicyTagsInBundledMapping() {
        ZapMappingDefinition mapping = new PtkResourcesLoader().loadZapMapping();

        assertEquals(List.of(), PtkMappingCheck.findInvalidPolicyTags(mapping));
    }

    @Test
    void shouldReportUnknownPolicyTags() {
        ZapMappingDefinition mapping =
                mapping(
                        "DAST",
                        "xss",
                        List.of(PolicyTag.QA_STD.getTag(), "POLICY_QA_STANDARD", "CUSTOM"));

        List<String> errors = PtkMappingCheck.findInvalidPolicyTags(mapping);

        assertEquals(List.of("DAST xss: POLICY_QA_STANDARD"), errors);
    }

    @Test
    void shouldReportPolicyTagsOfZapDups() {
        ZapMappingDefinition mapping =
                mapping(
                        "DAST",
                        "sql_injection",
                        List.of(PolicyTag.PENTEST.getTag(), PtkAlertBuilder.TAG_TOOL_PTK_ZAP_DUP));

        List<String> errors = PtkMappingCheck.findInvalidPolicyTags(mapping);

        assertEquals(
                List.of("DAST sql_injection: POLICY_PENTEST not allowed with TOOL_PTK_ZAP_DUP"),
                errors);
    }

    @Test
    void shouldAllowModulesWithoutTags() {
        ZapMappingDefinition mapping = mapping("SAST", "dom-xss", null);

        assertEquals(List.of(), PtkMappingCheck.findInvalidPolicyTags(mapping));
    }

    private static ZapMappingDefinition mapping(String engine, String moduleId, List<String> tags) {
        ModuleRuleMapping mm = new ModuleRuleMapping();
        mm.setModuleId(moduleId);
        mm.setTags(tags);
        EngineMapping em = new EngineMapping();
        em.setEngine(engine);
        em.setModuleMappings(List.of(mm));
        ZapMappingDefinition mapping = new ZapMappingDefinition();
        mapping.setEngines(List.of(em));
        return mapping;
    }
}
