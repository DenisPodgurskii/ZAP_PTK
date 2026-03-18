package org.zaproxy.addon.ptk.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** IAST context: domPath, elementId, tagName. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFindingContext {

    private String domPath;
    private String elementId;
    private String tagName;
}
