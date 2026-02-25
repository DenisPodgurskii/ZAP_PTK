package org.zaproxy.addon.ptk.model;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Root structure for PTK module definition files (sast-modules.json, iast-modules.json,
 * dast-modules.json). Schema: ptk-modules-v1.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkModulesDefinition {

    private String schema;
    private String engine;
    private int version;
    private List<PtkModule> modules;
}
