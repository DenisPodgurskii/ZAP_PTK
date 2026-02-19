package org.zaproxy.addon.ptk.model;

import java.util.List;
import java.util.Map;

/**
 * Per-engine mapping. v1: module id → ZAP plugin id. v2: list of module rule mappings (module id,
 * base alert id, rule id → sub-id).
 */
public class EngineMapping {

    private String engine;

    /** v1: PTK module id → ZAP plugin id (e.g. 220000). */
    private Map<String, Integer> mappings;

    /** v2: per-module base alert id and rule id → sub-id. */
    private List<ModuleRuleMapping> moduleMappings;

    public String getEngine() {
        return engine;
    }

    public void setEngine(String engine) {
        this.engine = engine;
    }

    public Map<String, Integer> getMappings() {
        return mappings;
    }

    public void setMappings(Map<String, Integer> mappings) {
        this.mappings = mappings;
    }

    public List<ModuleRuleMapping> getModuleMappings() {
        return moduleMappings;
    }

    public void setModuleMappings(List<ModuleRuleMapping> moduleMappings) {
        this.moduleMappings = moduleMappings;
    }
}
