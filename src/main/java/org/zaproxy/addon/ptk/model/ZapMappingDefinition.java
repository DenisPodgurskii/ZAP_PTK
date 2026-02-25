package org.zaproxy.addon.ptk.model;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Root structure for the PTK-to-ZAP alert mapping file (zap-mapping.json). Schema:
 * ptk-zap-mapping-v1.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ZapMappingDefinition {

    private String schema;
    private int version;
    private List<EngineMapping> engines;
}
