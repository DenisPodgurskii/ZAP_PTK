package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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

    private static final String EXAMPLE_URI = "https://www.example.com/";
    private static final String CODE_LINK_BASE =
            "https://github.com/DenisPodgurskii/pentestkit/blob/master/src/ptk/background/";
    private static final String CODE_LINK_SUFFIX = "/modules/modules.json";
    private static final String CODE_LINK_TEXT_PREFIX = "src/ptk/background/";

    private static final Gson GSON = new Gson();

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

                PtkModuleMetadata meta = parseModuleMetadata(module.getMetadata());
                String moduleName = module.getName() != null ? module.getName() : module.getId();

                if (module.getRules() != null) {
                    for (PtkRule rule : module.getRules()) {
                        if (rule.getId() == null) continue;
                        String alertRef = mapper.getZapAlertReference(module.getId(), rule.getId());
                        if (alertRef == null) continue;

                        String ruleDescription = parseRuleDescription(rule.getMetadata());
                        ExampleAlert alert =
                                buildAlert(
                                        alertRef,
                                        engine,
                                        moduleName,
                                        rule.getName() != null ? rule.getName() : rule.getId(),
                                        meta,
                                        rule.getSeverity(),
                                        ruleDescription);
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
                                buildAlert(
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

    private static ExampleAlert buildAlert(
            String alertRef,
            String engine,
            String moduleName,
            String ruleOrAttackName,
            PtkModuleMetadata meta,
            String ruleSeverity,
            String ruleDescription) {
        int pluginId = PtkAlertBuilder.parseBaseAlertId(alertRef);
        if (pluginId < 0) {
            return null;
        }
        int risk =
                PtkAlertBuilder.parseSeverity(
                        ruleSeverity != null ? ruleSeverity : getSeverity(meta));
        String description =
                PtkAlertBuilder.htmlToPlainText(
                        ruleDescription != null ? ruleDescription : getDescription(meta));
        String solution = PtkAlertBuilder.htmlToPlainText(getRecommendation(meta));
        String reference = formatReferences(meta);
        int cweId = PtkAlertBuilder.parseFirstCwe(meta);
        Map<String, String> tags = PtkAlertBuilder.owaspToZapTags(meta);
        description += "\nGenerated by OWASP PTK " + engine + " Module";

        Alert.Builder builder =
                Alert.builder()
                        .setPluginId(pluginId)
                        .setName(ruleOrAttackName)
                        .setRisk(risk)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setDescription(description)
                        .setSolution(solution != null ? solution : "")
                        .setReference(reference != null ? reference : "")
                        .setCweId(cweId)
                        .setUri(EXAMPLE_URI)
                        .setAlertRef(alertRef);
        if (!tags.isEmpty()) {
            builder.setTags(tags);
        }
        Alert baseAlert = builder.build();
        String engineLower = engine.toLowerCase();
        String codeLink = CODE_LINK_BASE + engineLower + CODE_LINK_SUFFIX;
        String codeLinkText = CODE_LINK_TEXT_PREFIX + engineLower + CODE_LINK_SUFFIX;
        return new ExampleAlert(baseAlert, moduleName, codeLink, codeLinkText);
    }

    private static PtkModuleMetadata parseModuleMetadata(JsonElement metadata) {
        if (metadata == null || !metadata.isJsonObject()) {
            return null;
        }
        return GSON.fromJson(metadata, PtkModuleMetadata.class);
    }

    private static String parseRuleDescription(JsonElement metadata) {
        if (metadata == null
                || !metadata.isJsonObject()
                || metadata.getAsJsonObject().get("description") == null) {
            return null;
        }
        JsonElement desc = metadata.getAsJsonObject().get("description");
        return desc.isJsonNull() ? null : desc.getAsString();
    }

    private static String getSeverity(PtkModuleMetadata meta) {
        return meta != null && meta.getSeverity() != null ? meta.getSeverity() : "medium";
    }

    private static String getDescription(PtkModuleMetadata meta) {
        return meta != null ? meta.getDescription() : null;
    }

    private static String getRecommendation(PtkModuleMetadata meta) {
        return meta != null ? meta.getRecommendation() : null;
    }

    private static String formatReferences(PtkModuleMetadata meta) {
        if (meta == null || meta.getLinks() == null || meta.getLinks().isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (String url : meta.getLinks().values()) {
            if (url == null) continue;
            // ZAP expects just links; trim any label text before "http"
            int httpIdx = url.indexOf("http");
            if (httpIdx >= 0) {
                url = url.substring(httpIdx);
            }
            if (sb.length() > 0) sb.append("\n");
            sb.append(url);
        }
        return sb.toString();
    }
}
