package org.zaproxy.addon.ptk.model;

import java.util.List;
import java.util.Map;

/** Metadata attached to a PTK module (description, links, severity, CWE/OWASP, etc.). */
public class PtkModuleMetadata {

    private String description;
    private String recommendation;
    private Map<String, String> links;
    private Integer maxFindings;
    private String category;
    private List<String> owasp;
    private List<String> cwe;
    private List<String> tags;
    private String severity;
    private String vulnId;
    private String regex;
    private Boolean unique;
    private Integer originLimit;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public Map<String, String> getLinks() {
        return links;
    }

    public void setLinks(Map<String, String> links) {
        this.links = links;
    }

    public Integer getMaxFindings() {
        return maxFindings;
    }

    public void setMaxFindings(Integer maxFindings) {
        this.maxFindings = maxFindings;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public List<String> getOwasp() {
        return owasp;
    }

    public void setOwasp(List<String> owasp) {
        this.owasp = owasp;
    }

    public List<String> getCwe() {
        return cwe;
    }

    public void setCwe(List<String> cwe) {
        this.cwe = cwe;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getVulnId() {
        return vulnId;
    }

    public void setVulnId(String vulnId) {
        this.vulnId = vulnId;
    }

    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    public Boolean getUnique() {
        return unique;
    }

    public void setUnique(Boolean unique) {
        this.unique = unique;
    }

    public Integer getOriginLimit() {
        return originLimit;
    }

    public void setOriginLimit(Integer originLimit) {
        this.originLimit = originLimit;
    }
}
