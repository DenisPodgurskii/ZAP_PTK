package org.zaproxy.addon.ptk;

import java.util.LinkedHashMap;
import java.util.Map;

final class PtkBrowserTaskState {
    private final String zapid;
    private final String browserId;
    private final long loadedAtMs;
    private final String loadedUrl;
    private String closeDecision;
    private String closeReason;
    private long closedAtMs;

    private PtkBrowserTaskState(String zapid, String browserId, String loadedUrl, long loadedAtMs) {
        this.zapid = zapid;
        this.browserId = browserId;
        this.loadedUrl = loadedUrl;
        this.loadedAtMs = loadedAtMs;
    }

    static String key(String zapid, String browserId) {
        return (zapid != null ? zapid : "") + "|" + (browserId != null ? browserId : "");
    }

    static PtkBrowserTaskState loaded(
            String zapid, String browserId, String loadedUrl, long loadedAtMs) {
        return new PtkBrowserTaskState(zapid, browserId, loadedUrl, loadedAtMs);
    }

    synchronized void close(String decision, String reason, long closedAtMs) {
        this.closeDecision = decision;
        this.closeReason = reason;
        this.closedAtMs = closedAtMs;
    }

    synchronized Map<String, Object> toLogFields(long nowMs) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("loadedAgoMs", Math.max(0L, nowMs - loadedAtMs));
        if (closedAtMs > 0L) {
            fields.put("closedAgoMs", Math.max(0L, nowMs - closedAtMs));
        }
        if (closeDecision != null && !closeDecision.isBlank()) {
            fields.put("decision", closeDecision);
        }
        if (closeReason != null && !closeReason.isBlank()) {
            fields.put("reason", closeReason);
        }
        if (loadedUrl != null && !loadedUrl.isBlank()) {
            fields.put("loadedUrl", redactZapCallbackUrlForLog(loadedUrl));
        }
        fields.put("zapid", zapid);
        fields.put("browserid", browserId);
        return fields;
    }

    private static String redactZapCallbackUrlForLog(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String redacted =
                value.replaceAll(
                                "(https?://[^/?#\\s\"'<>]+/zapCallBackUrl/)[^/?#\\s\"'<>]+",
                                "$1<redacted>")
                        .replaceAll("(/zapCallBackUrl/)[^/?#\\s\"'<>]+", "$1<redacted>");
        if (redacted.contains("/zapCallBackUrl/")) {
            redacted =
                    redacted.replaceAll("([?&]zapid=)[^&#\\s\"'<>]+", "$1<redacted>")
                            .replaceAll("(\\|)[^\\s\"'<>]+", "$1<redacted>");
        }
        return redacted;
    }
}
