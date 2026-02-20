package org.zaproxy.addon.ptk.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Optional metadata on a PTK rule (e.g. description, maxFindings). */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkRuleMetadata {

    private String description;
    private Integer maxFindings;
    private Integer originLimit;
}
