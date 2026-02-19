package org.zaproxy.addon.ptk.model;

import java.util.List;

/**
 * Root structure for PTK module definition files (sast-modules.json, iast-modules.json,
 * dast-modules.json). Schema: ptk-modules-v1.
 */
public class PtkModulesDefinition {

    private String schema;

    private String engine;

    private int version;

    private List<PtkModule> modules;

    public String getSchema() {
        return schema;
    }

    public void setSchema(String schema) {
        this.schema = schema;
    }

    public String getEngine() {
        return engine;
    }

    public void setEngine(String engine) {
        this.engine = engine;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public List<PtkModule> getModules() {
        return modules;
    }

    public void setModules(List<PtkModule> modules) {
        this.modules = modules;
    }
}
