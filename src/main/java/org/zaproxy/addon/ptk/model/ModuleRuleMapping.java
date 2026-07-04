package org.zaproxy.addon.ptk.model;

import java.util.Map;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Per-module mapping: base ZAP alert id and rule/attack id → sub-id (1, 2, 3…). The full ZAP alert
 * reference is {@code <baseAlertId>_<subId>}.
 */
@Getter
@Setter
@NoArgsConstructor
public class ModuleRuleMapping {

    private String moduleId;
    private int baseAlertId;

    /** Rule or attack id → sub-id (1-based). */
    private Map<String, Integer> rules;

    /**
     * Whether this module is included when "Use recommended defaults" is active. Omitting this
     * field (or setting it to {@code true}) means the module is on by default.
     */
    private boolean recommended = true;

    /**
     * Per-rule overrides for the recommended state. Only entries that differ from the module-level
     * {@link #recommended} value are needed. {@code null} means no overrides.
     */
    private Map<String, Boolean> recommendedRuleOverrides;
}
