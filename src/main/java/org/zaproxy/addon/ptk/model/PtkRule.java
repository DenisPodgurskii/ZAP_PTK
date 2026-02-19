package org.zaproxy.addon.ptk.model;

import com.google.gson.JsonElement;
import java.util.List;

/**
 * A single rule within a PTK module. Used for SAST (pattern/taint) and IAST. Fields are optional
 * depending on rule type (pattern, taint, or IAST runtime).
 */
public class PtkRule {

    private String mode;
    private String id;
    private String name;
    private String severity;
    private PtkRuleMetadata metadata;

    /** SAST pattern rules: list of match descriptors. */
    private List<JsonElement> matches;

    /** SAST taint / IAST: source identifiers. */
    private List<String> sources;

    /** SAST taint: sink identifiers. */
    private List<String> sinks;

    /** SAST taint: sanitizer identifiers. */
    private List<String> sanitizers;

    /** SAST taint: propagation kinds. */
    private List<String> propagate;

    /** SAST taint: taint kind tags. */
    private List<String> taint_kinds;

    /** IAST: sink identifier. */
    private String sinkId;

    /** IAST: allowed sanitizers. */
    private List<String> sanitizersAllowed;

    /** IAST: confidence when sanitized. */
    private String onSanitized;

    /** IAST: hook descriptor (kind, objectType/objectPath, property/method, etc.). */
    private JsonElement hook;

    /** IAST: conditions (e.g. requiresTaint). */
    private JsonElement conditions;

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public PtkRuleMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(PtkRuleMetadata metadata) {
        this.metadata = metadata;
    }

    public List<JsonElement> getMatches() {
        return matches;
    }

    public void setMatches(List<JsonElement> matches) {
        this.matches = matches;
    }

    public List<String> getSources() {
        return sources;
    }

    public void setSources(List<String> sources) {
        this.sources = sources;
    }

    public List<String> getSinks() {
        return sinks;
    }

    public void setSinks(List<String> sinks) {
        this.sinks = sinks;
    }

    public List<String> getSanitizers() {
        return sanitizers;
    }

    public void setSanitizers(List<String> sanitizers) {
        this.sanitizers = sanitizers;
    }

    public List<String> getPropagate() {
        return propagate;
    }

    public void setPropagate(List<String> propagate) {
        this.propagate = propagate;
    }

    public List<String> getTaint_kinds() {
        return taint_kinds;
    }

    public void setTaint_kinds(List<String> taint_kinds) {
        this.taint_kinds = taint_kinds;
    }

    public String getSinkId() {
        return sinkId;
    }

    public void setSinkId(String sinkId) {
        this.sinkId = sinkId;
    }

    public List<String> getSanitizersAllowed() {
        return sanitizersAllowed;
    }

    public void setSanitizersAllowed(List<String> sanitizersAllowed) {
        this.sanitizersAllowed = sanitizersAllowed;
    }

    public String getOnSanitized() {
        return onSanitized;
    }

    public void setOnSanitized(String onSanitized) {
        this.onSanitized = onSanitized;
    }

    public JsonElement getHook() {
        return hook;
    }

    public void setHook(JsonElement hook) {
        this.hook = hook;
    }

    public JsonElement getConditions() {
        return conditions;
    }

    public void setConditions(JsonElement conditions) {
        this.conditions = conditions;
    }
}
