package org.zaproxy.addon.ptk;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModuleMetadata;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;

/**
 * Builds example alerts from PTK module definitions for {@link ExampleAlertProvider}. Each rule or
 * attack defined in the config files (sast-modules.json, iast-modules.json, dast-modules.json) is
 * mapped to a ZAP alert with the relevant information from the module metadata.
 */
public final class PtkExampleAlerts {

    private PtkExampleAlerts() {}

    /**
     * Builds a list of example alerts from all PTK module definitions and the ZAP mapping.
     *
     * @param resources loaded PTK resources (modules + zap mapping)
     * @return list of example alerts, one per rule/attack
     */
    public static List<Alert> getExampleAlerts(PtkResourcesLoader.LoadedPtkResources resources) {
        if (resources == null) {
            return List.of();
        }
        PtkZapMapper mapper = new PtkZapMapper(resources);
        List<Alert> alerts = new ArrayList<>();

        for (PtkModulesDefinition def : resources.getAllModuleDefinitions()) {
            if (def.getModules() == null) continue;
            String engine = def.getEngine();
            for (PtkModule module : def.getModules()) {
                if (module.getId() == null) continue;

                PtkModuleMetadata meta = PtkAlertBuilder.parseModuleMetadata(module.getMetadata());
                String moduleName = module.getName() != null ? module.getName() : module.getId();

                if (module.getRules() != null) {
                    for (PtkRule rule : module.getRules()) {
                        if (rule.getId() == null) continue;
                        String alertRef = mapper.getZapAlertReference(module.getId(), rule.getId());
                        if (alertRef == null) continue;

                        ExampleAlert alert =
                                PtkAlertBuilder.buildExampleAlert(
                                        alertRef,
                                        engine,
                                        moduleName,
                                        rule.getName() != null ? rule.getName() : rule.getId(),
                                        meta,
                                        rule.getSeverity(),
                                        PtkAlertBuilder.parseRuleDescription(rule.getMetadata()));
                        if (alert != null) {
                            alerts.add(alert);
                        }
                    }
                }
                if (module.getAttacks() != null) {
                    for (PtkAttack attack : module.getAttacks()) {
                        if (attack.getId() == null) continue;
                        String alertRef =
                                mapper.getZapAlertReference(module.getId(), attack.getId());
                        if (alertRef == null) continue;

                        ExampleAlert alert =
                                PtkAlertBuilder.buildExampleAlert(
                                        alertRef,
                                        engine,
                                        moduleName,
                                        attack.getName() != null
                                                ? attack.getName()
                                                : attack.getId(),
                                        meta,
                                        null,
                                        null);
                        if (alert != null) {
                            alerts.add(alert);
                        }
                    }
                }
            }
        }
        return alerts;
    }
}
