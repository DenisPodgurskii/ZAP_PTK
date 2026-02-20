package org.zaproxy.addon.ptk.model;

import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Metadata attached to a PTK module (description, links, severity, CWE/OWASP, etc.). */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
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
}
