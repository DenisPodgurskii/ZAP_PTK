package org.zaproxy.addon.ptk.model;

import java.util.List;

/**
 * Root structure for the PTK-to-ZAP alert mapping file (zap-mapping.json). Schema:
 * ptk-zap-mapping-v1.
 */
public class ZapMappingDefinition {

    private String schema;
    private int version;
    private List<EngineMapping> engines;

    public String getSchema() {
        return schema;
    }

    public void setSchema(String schema) {
        this.schema = schema;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public List<EngineMapping> getEngines() {
        return engines;
    }

    public void setEngines(List<EngineMapping> engines) {
        this.engines = engines;
    }
}
