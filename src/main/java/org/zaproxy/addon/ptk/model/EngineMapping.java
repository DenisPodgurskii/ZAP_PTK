package org.zaproxy.addon.ptk.model;

import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Per-engine mapping. v1: module id → ZAP plugin id. v2: list of module rule mappings (module id,
 * base alert id, rule id → sub-id).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EngineMapping {

    private String engine;

    /** v1: PTK module id → ZAP plugin id (e.g. 220000). */
    private Map<String, Integer> mappings;

    /** v2: per-module base alert id and rule id → sub-id. */
    private List<ModuleRuleMapping> moduleMappings;
}
