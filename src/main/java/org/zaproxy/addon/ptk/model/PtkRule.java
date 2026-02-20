package org.zaproxy.addon.ptk.model;

import com.google.gson.JsonElement;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A single rule within a PTK module. Used for SAST (pattern/taint) and IAST. Fields are optional
 * depending on rule type (pattern, taint, or IAST runtime).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
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
}
