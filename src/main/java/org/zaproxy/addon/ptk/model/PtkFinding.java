package org.zaproxy.addon.ptk.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A single finding from PTK (SAST, IAST, or DAST). Common fields: id, fingerprint, moduleId,
 * ruleId, severity, confidence, summary, location, proof. Engine-specific fields (source, sink,
 * trace, request, response, etc.) are preserved for inclusion in alert details.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFinding {

    private String id;
    private String fingerprint;
    private String moduleId;
    private String ruleId;

    /** DAST: attack id (often same as ruleId). */
    private String attackId;

    private String severity;
    private Integer confidence;
    private String summary;

    private PtkFindingLocation location;
    private PtkFindingProof proof;

    /** SAST: source/sink/trace info. */
    private PtkFindingSourceSink source;

    private PtkFindingSourceSink sink;
    private Object trace;

    /** SAST: code snippet. */
    private String codeSnippet;

    /** IAST: context (domPath, elementId, tagName). */
    private PtkFindingContext context;

    /** DAST: request/response. */
    private PtkFindingRequest request;

    private PtkFindingResponse response;

    public String getUri() {
        return location != null ? location.getUrl() : null;
    }

    public String getMethod() {
        return location != null ? location.getMethod() : null;
    }

    public String getParam() {
        return location != null ? location.getParam() : null;
    }
}
