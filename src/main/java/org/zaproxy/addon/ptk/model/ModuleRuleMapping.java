package org.zaproxy.addon.ptk.model;

import java.util.List;
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

    /**
     * The alert tags of the module, added to all of its alerts and used by the Global Scan Policy
     * Manager to select the module by tag, e.g. the ZAP policy tags ({@code POLICY_QA_STD}). Only
     * the tag names, their values are those of the corresponding ZAP tags, if any. {@code null}
     * means no tags.
     */
    private List<String> tags;
}
