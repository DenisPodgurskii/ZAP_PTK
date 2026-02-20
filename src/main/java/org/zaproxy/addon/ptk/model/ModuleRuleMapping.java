package org.zaproxy.addon.ptk.model;

import java.util.Map;
import lombok.AllArgsConstructor;
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
@AllArgsConstructor
public class ModuleRuleMapping {

    private String moduleId;
    private int baseAlertId;

    /** Rule or attack id → sub-id (1-based). */
    private Map<String, Integer> rules;
}
