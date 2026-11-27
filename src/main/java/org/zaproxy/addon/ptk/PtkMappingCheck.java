package org.zaproxy.addon.ptk;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.ptk.model.EngineMapping;
import org.zaproxy.addon.ptk.model.ModuleRuleMapping;
import org.zaproxy.addon.ptk.model.ZapMappingDefinition;

/**
 * Command-line entry point to load PTK/ZAP resources and verify every rule has a unique ZAP alert
 * reference (<alert-id>_<sub-id>) and only known ZAP policy tags. Prints result to stdout and exits
 * with 0 if valid, 1 if invalid.
 *
 * <p>Run with: ./gradlew runPtkMappingCheck
 */
public final class PtkMappingCheck {

    public static void main(String[] args) {
        PtkResourcesLoader loader = new PtkResourcesLoader();
        PtkResourcesLoader.LoadedPtkResources resources = loader.loadAll();

        if (resources.getZapMapping() == null) {
            System.err.println("ERROR: Could not load zap-mapping.json");
            System.exit(1);
        }

        PtkZapMapper mapper = new PtkZapMapper(resources);
        PtkZapMapper.OneToOneCheckResult result = mapper.checkUniqueAlertReferences(resources);

        List<String> tagErrors = findInvalidPolicyTags(resources.getZapMapping());

        if (result.isOneToOne() && tagErrors.isEmpty()) {
            System.out.println(
                    "OK: All rules have unique alert references ("
                            + mapper.getAlertRefToRuleMap().size()
                            + " rule ↔ alert refs) and all policy tags are valid.");
            System.exit(0);
        }

        if (!result.isOneToOne()) {
            System.err.println("ERROR: Not all rules have unique alert references:");
            for (String err : result.getErrors()) {
                System.err.println("  - " + err);
            }
        }
        if (!tagErrors.isEmpty()) {
            System.err.println("ERROR: Invalid policy tags:");
            for (String err : tagErrors) {
                System.err.println("  - " + err);
            }
        }
        System.exit(1);
    }

    /**
     * Finds the module tags that look like ZAP policy tags ({@code POLICY_*}) but are not one of
     * the {@link PolicyTag}s, e.g. misspelled, which would leave the module out of the policy, and
     * the policy tags of modules which duplicate ZAP scan rules ({@link
     * PtkAlertBuilder#TAG_TOOL_PTK_ZAP_DUP}), which should not be in the policies.
     *
     * @param mapping the ZAP mapping
     * @return the errors, one per unknown tag, empty if none
     */
    static List<String> findInvalidPolicyTags(ZapMappingDefinition mapping) {
        List<String> errors = new ArrayList<>();
        if (mapping == null || mapping.getEngines() == null) {
            return errors;
        }
        Set<String> policyTags =
                Stream.of(PolicyTag.values()).map(PolicyTag::getTag).collect(Collectors.toSet());
        for (EngineMapping em : mapping.getEngines()) {
            if (em.getModuleMappings() == null) continue;
            for (ModuleRuleMapping mm : em.getModuleMappings()) {
                if (mm.getTags() == null) continue;
                boolean zapDup = mm.getTags().contains(PtkAlertBuilder.TAG_TOOL_PTK_ZAP_DUP);
                for (String tag : mm.getTags()) {
                    if (tag == null || !tag.startsWith("POLICY_")) continue;
                    if (!policyTags.contains(tag)) {
                        errors.add(em.getEngine() + " " + mm.getModuleId() + ": " + tag);
                    } else if (zapDup) {
                        errors.add(
                                em.getEngine()
                                        + " "
                                        + mm.getModuleId()
                                        + ": "
                                        + tag
                                        + " not allowed with "
                                        + PtkAlertBuilder.TAG_TOOL_PTK_ZAP_DUP);
                    }
                }
            }
        }
        return errors;
    }
}
