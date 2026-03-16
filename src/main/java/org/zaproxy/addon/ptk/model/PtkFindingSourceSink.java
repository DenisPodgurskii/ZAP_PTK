package org.zaproxy.addon.ptk.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Source or sink in a PTK finding (SAST/IAST). May have id, label, kind, file, line, column. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFindingSourceSink {

    private String id;
    private String label;
    private String kind;
    private String file;
    private Integer line;
    private Integer column;
}
