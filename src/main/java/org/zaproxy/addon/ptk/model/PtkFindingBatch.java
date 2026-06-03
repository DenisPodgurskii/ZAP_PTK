package org.zaproxy.addon.ptk.model;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Root envelope for PTK alert batches sent to ZAP via PTK_ALERT_PATH. Contains source, type,
 * schema, and payload with engine-specific findings.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFindingBatch {

    private String source;
    private String type;
    private String schema;
    private Long ts;
    private String batchId;
    private Integer batchSeq;
    private String zapid;
    private String browserid;
    private PtkFindingPayload payload;

    public boolean isSastBatch() {
        return "sast_findings_batch".equals(type);
    }

    public boolean isIastBatch() {
        return "iast_findings_batch".equals(type);
    }

    public boolean isDastBatch() {
        return "dast_findings_batch".equals(type);
    }

    public List<PtkFinding> getFindings() {
        if (payload == null || payload.getFindings() == null) {
            return List.of();
        }
        return payload.getFindings();
    }
}
