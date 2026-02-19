package org.zaproxy.addon.ptk.model;

import java.util.List;

/**
 * A single PTK module (e.g. dom-xss, sql_injection). Has metadata and either rules (SAST/IAST) or
 * attacks (DAST).
 */
public class PtkModule {

    private String id;
    private String type;
    private boolean async;
    private String name;
    private PtkModuleMetadata metadata;

    /** Present for SAST and IAST modules. */
    private List<PtkRule> rules;

    /** Present for DAST modules. */
    private List<PtkAttack> attacks;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public boolean isAsync() {
        return async;
    }

    public void setAsync(boolean async) {
        this.async = async;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public PtkModuleMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(PtkModuleMetadata metadata) {
        this.metadata = metadata;
    }

    public List<PtkRule> getRules() {
        return rules;
    }

    public void setRules(List<PtkRule> rules) {
        this.rules = rules;
    }

    public List<PtkAttack> getAttacks() {
        return attacks;
    }

    public void setAttacks(List<PtkAttack> attacks) {
        this.attacks = attacks;
    }
}
