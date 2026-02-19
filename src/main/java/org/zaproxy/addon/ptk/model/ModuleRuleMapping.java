package org.zaproxy.addon.ptk.model;

import java.util.Map;

/**
 * Per-module mapping: base ZAP alert id and rule/attack id → sub-id (1, 2, 3…). The full ZAP alert
 * reference is {@code <baseAlertId>_<subId>}.
 */
public class ModuleRuleMapping {

    private String moduleId;
    private int baseAlertId;

    /** Rule or attack id → sub-id (1-based). */
    private Map<String, Integer> rules;

    public String getModuleId() {
        return moduleId;
    }

    public void setModuleId(String moduleId) {
        this.moduleId = moduleId;
    }

    public int getBaseAlertId() {
        return baseAlertId;
    }

    public void setBaseAlertId(int baseAlertId) {
        this.baseAlertId = baseAlertId;
    }

    public Map<String, Integer> getRules() {
        return rules;
    }

    public void setRules(Map<String, Integer> rules) {
        this.rules = rules;
    }
}
