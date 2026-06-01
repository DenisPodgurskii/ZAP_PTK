package org.zaproxy.addon.ptk.model;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Payload of a PTK finding batch: engine, scanId, truncated flag, and findings list. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFindingPayload {

    private String engine;
    private String scanId;
    private String sessionId;
    private Boolean truncated;
    private List<PtkFinding> findings;
}
