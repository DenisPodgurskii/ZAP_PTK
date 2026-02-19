package org.zaproxy.addon.ptk.model;

/** Optional metadata on a PTK rule (e.g. description, maxFindings). */
public class PtkRuleMetadata {

    private String description;
    private Integer maxFindings;
    private Integer originLimit;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Integer getMaxFindings() {
        return maxFindings;
    }

    public void setMaxFindings(Integer maxFindings) {
        this.maxFindings = maxFindings;
    }

    public Integer getOriginLimit() {
        return originLimit;
    }

    public void setOriginLimit(Integer originLimit) {
        this.originLimit = originLimit;
    }
}
