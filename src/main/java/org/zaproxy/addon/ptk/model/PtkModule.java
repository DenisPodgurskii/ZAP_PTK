package org.zaproxy.addon.ptk.model;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A single PTK module (e.g. dom-xss, sql_injection). Has metadata and either rules (SAST/IAST) or
 * attacks (DAST).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
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
}
