package org.zaproxy.addon.ptk;

/**
 * Command-line entry point to load PTK/ZAP resources and verify every rule has a unique ZAP alert
 * reference (<alert-id>_<sub-id>). Prints result to stdout and exits with 0 if valid, 1 if invalid.
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

        if (result.isOneToOne()) {
            System.out.println(
                    "OK: All rules have unique alert references ("
                            + mapper.getAlertRefToRuleMap().size()
                            + " rule ↔ alert refs).");
            System.exit(0);
        }

        System.err.println("ERROR: Not all rules have unique alert references:");
        for (String err : result.getErrors()) {
            System.err.println("  - " + err);
        }
        System.exit(1);
    }
}
