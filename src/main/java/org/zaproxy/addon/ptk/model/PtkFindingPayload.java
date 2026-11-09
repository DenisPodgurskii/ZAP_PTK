package org.zaproxy.addon.ptk.model;

import com.google.gson.JsonObject;
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

    private JsonObject scanCompleteness;

    public PtkFindingPayload(
            String engine,
            String scanId,
            String sessionId,
            Boolean truncated,
            List<PtkFinding> findings) {
        this.engine = engine;
        this.scanId = scanId;
        this.sessionId = sessionId;
        this.truncated = truncated;
        this.findings = findings;
    }
}
