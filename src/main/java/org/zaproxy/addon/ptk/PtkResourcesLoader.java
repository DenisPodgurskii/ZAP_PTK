package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.zaproxy.addon.ptk.model.EngineMapping;
import org.zaproxy.addon.ptk.model.ModuleRuleMapping;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.ZapMappingDefinition;

/**
 * Loads PTK module definitions and ZAP mapping from the add-on resources. Reads the four JSON
 * files: sast-modules.json, iast-modules.json, dast-modules.json, zap-mapping.json.
 */
public class PtkResourcesLoader {

    private static final String RESOURCE_BASE = "org/zaproxy/addon/ptk/";
    private static final String SAST_MODULES = RESOURCE_BASE + "sast-modules.json";
    private static final String IAST_MODULES = RESOURCE_BASE + "iast-modules.json";
    private static final String DAST_MODULES = RESOURCE_BASE + "dast-modules.json";
    private static final String ZAP_MAPPING = RESOURCE_BASE + "zap-mapping.json";

    private final Gson gson = new GsonBuilder().create();

    /**
     * Loads the SAST module definition from sast-modules.json.
     *
     * @return the parsed definition, or null if the resource is not found
     */
    public PtkModulesDefinition loadSastModules() {
        return loadModules(SAST_MODULES);
    }

    /**
     * Loads the IAST module definition from iast-modules.json.
     *
     * @return the parsed definition, or null if the resource is not found
     */
    public PtkModulesDefinition loadIastModules() {
        return loadModules(IAST_MODULES);
    }

    /**
     * Loads the DAST module definition from dast-modules.json.
     *
     * @return the parsed definition, or null if the resource is not found
     */
    public PtkModulesDefinition loadDastModules() {
        return loadModules(DAST_MODULES);
    }

    /**
     * Loads the ZAP mapping definition from zap-mapping.json.
     *
     * @return the parsed definition, or null if the resource is not found
     */
    public ZapMappingDefinition loadZapMapping() {
        try (InputStream in = getResourceStream(ZAP_MAPPING)) {
            if (in == null) {
                return null;
            }
            return gson.fromJson(
                    new InputStreamReader(in, StandardCharsets.UTF_8), ZapMappingDefinition.class);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load " + ZAP_MAPPING, e);
        }
    }

    /**
     * Loads all four resources into a single container.
     *
     * @return a {@link LoadedPtkResources} with the three module definitions and the ZAP mapping
     */
    public LoadedPtkResources loadAll() {
        PtkModulesDefinition sast = loadSastModules();
        PtkModulesDefinition iast = loadIastModules();
        PtkModulesDefinition dast = loadDastModules();
        ZapMappingDefinition zapMapping = loadZapMapping();
        return new LoadedPtkResources(sast, iast, dast, zapMapping);
    }

    private PtkModulesDefinition loadModules(String resourcePath) {
        try (InputStream in = getResourceStream(resourcePath)) {
            if (in == null) {
                return null;
            }
            return gson.fromJson(
                    new InputStreamReader(in, StandardCharsets.UTF_8), PtkModulesDefinition.class);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load " + resourcePath, e);
        }
    }

    private InputStream getResourceStream(String path) {
        ClassLoader cl = getClass().getClassLoader();
        if (cl == null) {
            cl = ClassLoader.getSystemClassLoader();
        }
        return cl.getResourceAsStream(path);
    }

    /** Container for the four loaded resources. */
    @Getter
    @AllArgsConstructor
    public static final class LoadedPtkResources {

        private final PtkModulesDefinition sastModules;
        private final PtkModulesDefinition iastModules;
        private final PtkModulesDefinition dastModules;
        private final ZapMappingDefinition zapMapping;

        /** All module definitions in order: SAST, IAST, DAST. */
        public List<PtkModulesDefinition> getAllModuleDefinitions() {
            List<PtkModulesDefinition> list = new ArrayList<>(3);
            if (sastModules != null) list.add(sastModules);
            if (iastModules != null) list.add(iastModules);
            if (dastModules != null) list.add(dastModules);
            return list;
        }

        /**
         * Returns whether a rule/attack is enabled under "Use recommended defaults" mode.
         *
         * <p>Lookup order:
         *
         * <ol>
         *   <li>Per-rule override in {@code recommendedRuleOverrides} for the matching module.
         *   <li>Module-level {@code recommended} flag.
         *   <li>Default {@code true} if the module is not present in the ZAP mapping.
         * </ol>
         *
         * @param engine the engine name (e.g. "DAST", "SAST", "IAST")
         * @param moduleId the module identifier
         * @param ruleId the rule or attack identifier
         * @return {@code true} if the rule should be active under recommended defaults
         */
        public boolean isRecommendedEnabled(String engine, String moduleId, String ruleId) {
            if (zapMapping == null || zapMapping.getEngines() == null) return true;
            for (EngineMapping em : zapMapping.getEngines()) {
                if (!engine.equalsIgnoreCase(em.getEngine()) || em.getModuleMappings() == null)
                    continue;
                for (ModuleRuleMapping mm : em.getModuleMappings()) {
                    if (!moduleId.equals(mm.getModuleId())) continue;
                    Map<String, Boolean> overrides = mm.getRecommendedRuleOverrides();
                    if (overrides != null && overrides.containsKey(ruleId)) {
                        return overrides.get(ruleId);
                    }
                    return mm.isRecommended();
                }
            }
            return true;
        }
    }
}
