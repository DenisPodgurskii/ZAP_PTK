package org.zaproxy.addon.ptk.model;

import com.google.gson.JsonElement;
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

    /** Canonical or legacy module metadata block; preserved as-is for round-tripping. */
    private JsonElement metadata;

    /** Canonical runtime block used by v1 DAST modules. */
    private JsonElement runtime;

    /** Present for SAST and IAST modules. */
    private List<PtkRule> rules;

    /** Present for DAST modules. */
    private List<PtkAttack> attacks;
}
