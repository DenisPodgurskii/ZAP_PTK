package org.zaproxy.addon.ptk.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Proof/evidence for a PTK finding: mode, payload, proof, summary. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFindingProof {

    private String mode;
    private String payload;
    private String proof;
    private String summary;
}
