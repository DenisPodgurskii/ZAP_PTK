package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.ptk.model.PtkFinding;
import org.zaproxy.addon.ptk.model.PtkFindingBatch;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

/**
 * Handles PTK alert batches received via PTK_ALERT_PATH. Parses the JSON payload, maps findings to
 * ZAP alerts, and raises them via ExtensionAlert.
 */
public final class PtkAlertHandler {

    private static final Gson GSON = new Gson();
    private static final Logger LOGGER = LogManager.getLogger(PtkAlertHandler.class);

    private static final String HTTP_BOUNDARY = HttpHeader.CRLF + HttpHeader.CRLF;
    private static final int ACK_CACHE_MAX_ENTRIES = 2_000;
    private static final Map<String, AlertBatchAck> BATCH_ACK_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, Object> BATCH_ACK_LOCKS = new ConcurrentHashMap<>();
    private static final Map<String, Long> IMPORTED_FINDING_KEYS = new ConcurrentHashMap<>();
    private static final Map<String, Object> IMPORTED_FINDING_LOCKS = new ConcurrentHashMap<>();

    private PtkAlertHandler() {}

    /**
     * Processes a PTK alert batch from the request body. Parses JSON, builds ZAP alerts for each
     * mapped finding, and raises them.
     *
     * @param requestBody the raw JSON body (e.g. from msg.getRequestBody().toString())
     * @return number of alerts raised
     */
    public static int processAlertBatch(String requestBody) {
        return processAlertBatchWithAck(requestBody).alertsRaised;
    }

    public static AlertBatchAck processAlertBatchWithAck(String requestBody) {
        if (requestBody == null || requestBody.isBlank()) {
            return AlertBatchAck.empty(null, null);
        }
        PtkFindingBatch batch;
        try {
            batch = GSON.fromJson(requestBody, PtkFindingBatch.class);
        } catch (JsonSyntaxException e) {
            return AlertBatchAck.empty(null, null);
        }
        String batchId = batch != null ? batch.getBatchId() : null;
        Integer batchSeq = batch != null ? batch.getBatchSeq() : null;
        String ackKey = buildBatchAckKey(batch);
        if (ackKey != null) {
            AlertBatchAck cached = BATCH_ACK_CACHE.get(ackKey);
            if (cached != null) {
                return cached;
            }
            Object batchLock = BATCH_ACK_LOCKS.computeIfAbsent(ackKey, key -> new Object());
            synchronized (batchLock) {
                cached = BATCH_ACK_CACHE.get(ackKey);
                if (cached != null) {
                    return cached;
                }
                try {
                    return processParsedAlertBatch(batch, ackKey, batchId, batchSeq);
                } finally {
                    BATCH_ACK_LOCKS.remove(ackKey, batchLock);
                }
            }
        }
        return processParsedAlertBatch(batch, null, batchId, batchSeq);
    }

    private static AlertBatchAck processParsedAlertBatch(
            PtkFindingBatch batch, String ackKey, String batchId, Integer batchSeq) {
        if (batch == null || batch.getPayload() == null || batch.getFindings() == null) {
            return cacheAck(ackKey, AlertBatchAck.empty(batchId, batchSeq));
        }
        String engine = batch.getPayload().getEngine();
        if (engine == null || engine.isBlank()) {
            engine = inferEngine(batch.getType());
        }
        List<PtkFinding> findings = batch.getFindings();
        AlertBatchAck ack = new AlertBatchAck(batchId, batchSeq, findings.size());
        PtkResourcesLoader loader = new PtkResourcesLoader();
        PtkResourcesLoader.LoadedPtkResources resources = loader.loadAll();
        if (resources == null || resources.getZapMapping() == null) {
            for (PtkFinding finding : findings) {
                ack.add(
                        FindingAck.rejected(
                                findingIdentity(finding), finding, "rejected_missing_mapping"));
            }
            return cacheAck(ackKey, ack);
        }
        PtkZapMapper mapper = new PtkZapMapper(resources);
        ExtensionAlert extAlert = null;
        try {
            if (Control.getSingleton() != null
                    && Control.getSingleton().getExtensionLoader() != null) {
                extAlert =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionAlert.class);
            }
        } catch (RuntimeException e) {
            LOGGER.debug("PTK could not resolve ExtensionAlert: {}", e.getMessage());
        }
        LOGGER.debug("PTK alert batch: {} alerts reported", findings.size());

        for (PtkFinding finding : findings) {
            String findingId = findingIdentity(finding);
            if (finding.getModuleId() == null || finding.getRuleId() == null) {
                LOGGER.error(
                        "PTK module or rule not found for id={}, moduleId={}, ruleId={}",
                        finding.getId(),
                        finding.getModuleId(),
                        finding.getRuleId());
                ack.add(FindingAck.rejected(findingId, finding, "rejected_missing_mapping"));
                continue;
            }
            Alert alert = PtkAlertBuilder.buildFromFinding(finding, engine, mapper, resources);
            if (alert == null) {
                LOGGER.error(
                        "PTK mapping not found for moduleId={}, ruleId={}",
                        finding.getModuleId(),
                        finding.getRuleId());
                ack.add(FindingAck.rejected(findingId, finding, "rejected_missing_mapping"));
                continue;
            }
            if (extAlert == null) {
                ack.add(FindingAck.rejected(findingId, finding, "rejected_raise_failed"));
                continue;
            }
            String findingKey = buildImportedFindingKey(batch, finding, alert);
            String status;
            if (findingKey != null) {
                Object findingLock =
                        IMPORTED_FINDING_LOCKS.computeIfAbsent(findingKey, key -> new Object());
                synchronized (findingLock) {
                    if (IMPORTED_FINDING_KEYS.containsKey(findingKey)) {
                        status = "accepted_duplicate";
                    } else {
                        status = raiseAlert(alert, finding, extAlert);
                        if ("accepted_raised".equals(status)) {
                            ack.alertsRaised++;
                            IMPORTED_FINDING_KEYS.put(findingKey, System.currentTimeMillis());
                            evictOldImportedFindingKeys();
                        }
                    }
                }
                IMPORTED_FINDING_LOCKS.remove(findingKey, findingLock);
            } else {
                status = raiseAlert(alert, finding, extAlert);
                if ("accepted_raised".equals(status)) {
                    ack.alertsRaised++;
                }
            }
            ack.add(FindingAck.fromStatus(findingId, finding, status, alert));
        }

        LOGGER.debug("PTK alerts raised: {} of {} reported", ack.alertsRaised, findings.size());
        return cacheAck(ackKey, ack);
    }

    private static String inferEngine(String type) {
        if (type == null) return "PTK";
        if (type.contains("sast")) return "SAST";
        if (type.contains("iast")) return "IAST";
        if (type.contains("dast")) return "DAST";
        return "PTK";
    }

    private static String raiseAlert(Alert alert, PtkFinding finding, ExtensionAlert extAlert) {
        try {
            HttpMessage msg;
            String otherInfoNote;

            String requestRaw = finding.getRequest() != null ? finding.getRequest().getRaw() : null;
            String responseRaw =
                    finding.getResponse() != null ? finding.getResponse().getRaw() : null;

            if (requestRaw != null && responseRaw != null) {
                msg = new HttpMessage();
                String[] headBody = splitHeaderBody(requestRaw);
                msg.setRequestHeader(headBody[0]);
                msg.setRequestBody(headBody[1]);
                headBody = splitHeaderBody(responseRaw);
                msg.setResponseHeader(headBody[0]);
                msg.setResponseBody(headBody[1]);
                otherInfoNote = null;
            } else {
                String url = finding.getUri();
                if (url == null || url.isBlank()) {
                    LOGGER.error("PTK no URL in finding: {}", alert.getName());
                    return "rejected_invalid_url";
                }
                URI uri;
                try {
                    uri = new URI(url, true);
                    // Strip URL fragment - fragments are client-side only and absent from Sites
                    // Tree
                    uri.setFragment(null);
                } catch (Exception e) {
                    LOGGER.error("PTK could not parse URL '{}': {}", url, e.getMessage());
                    return "rejected_invalid_url";
                }
                msg = findInSitesTree(uri);
                if (msg != null) {
                    otherInfoNote = Constant.messages.getString("ptk.alert.otherinfo.similar");
                } else {
                    LOGGER.error(
                            "PTK no Sites Tree match for alert: name={} url={}",
                            alert.getName(),
                            uri);
                    return "rejected_missing_site_tree_match";
                }
            }

            if (otherInfoNote != null) {
                String existing = alert.getOtherInfo();
                alert.setOtherInfo(
                        existing != null && !existing.isEmpty()
                                ? existing + "\n" + otherInfoNote
                                : otherInfoNote);
            }

            HistoryReference ref =
                    new HistoryReference(
                            Model.getSingleton().getSession(), HistoryReference.TYPE_SCANNER, msg);
            alert.setMessage(msg);
            extAlert.alertFound(alert, ref);
            LOGGER.debug("PTK raised alert: {}", alert.getName());
            return "accepted_raised";
        } catch (Exception e) {
            LOGGER.error("PTK failed to raise alert: {}", alert.getName(), e);
            return "rejected_raise_failed";
        }
    }

    private static AlertBatchAck cacheAck(String ackKey, AlertBatchAck ack) {
        if (ackKey == null || ack == null) {
            return ack != null ? ack : AlertBatchAck.empty(null, null);
        }
        BATCH_ACK_CACHE.put(ackKey, ack);
        while (BATCH_ACK_CACHE.size() > ACK_CACHE_MAX_ENTRIES) {
            String firstKey = BATCH_ACK_CACHE.keySet().stream().findFirst().orElse(null);
            if (firstKey == null) break;
            BATCH_ACK_CACHE.remove(firstKey);
        }
        return ack;
    }

    private static String buildBatchAckKey(PtkFindingBatch batch) {
        if (batch == null || batch.getBatchId() == null || batch.getBatchId().isBlank()) {
            return null;
        }
        String sessionId =
                batch.getPayload() != null && batch.getPayload().getSessionId() != null
                        ? batch.getPayload().getSessionId()
                        : "";
        return String.join(
                "|",
                nullSafe(sessionId),
                nullSafe(batch.getZapid()),
                nullSafe(batch.getBatchId()),
                String.valueOf(batch.getBatchSeq()));
    }

    private static String buildImportedFindingKey(
            PtkFindingBatch batch, PtkFinding finding, Alert alert) {
        String sessionId =
                batch.getPayload() != null && batch.getPayload().getSessionId() != null
                        ? batch.getPayload().getSessionId()
                        : "";
        return String.join(
                "|",
                nullSafe(sessionId),
                nullSafe(batch.getZapid()),
                nullSafe(batch.getPayload() != null ? batch.getPayload().getEngine() : null),
                nullSafe(batch.getPayload() != null ? batch.getPayload().getScanId() : null),
                nullSafe(alert != null ? alert.getAlertRef() : null),
                nullSafe(findingIdentity(finding)),
                nullSafe(finding != null ? finding.getUri() : null),
                nullSafe(finding != null ? finding.getParam() : null));
    }

    private static String findingIdentity(PtkFinding finding) {
        if (finding == null) {
            return "";
        }
        if (finding.getId() != null && !finding.getId().isBlank()) {
            return finding.getId();
        }
        if (finding.getFingerprint() != null && !finding.getFingerprint().isBlank()) {
            return finding.getFingerprint();
        }
        return String.join(
                "|",
                nullSafe(finding.getModuleId()),
                nullSafe(finding.getRuleId()),
                nullSafe(finding.getUri()),
                nullSafe(finding.getMethod()),
                nullSafe(finding.getParam()));
    }

    private static String nullSafe(String value) {
        return value != null ? value : "";
    }

    private static void evictOldImportedFindingKeys() {
        while (IMPORTED_FINDING_KEYS.size() > ACK_CACHE_MAX_ENTRIES) {
            String oldest =
                    IMPORTED_FINDING_KEYS.entrySet().stream()
                            .min(Map.Entry.comparingByValue())
                            .map(Map.Entry::getKey)
                            .orElse(null);
            if (oldest == null) break;
            IMPORTED_FINDING_KEYS.remove(oldest);
        }
    }

    public static final class AlertBatchAck {
        public String result = "OK";
        public int contractVersion = 2;
        public boolean structuredAck = true;
        public boolean legacyAck = false;
        public String batchId;
        public Integer batchSeq;
        public int received;
        public int accepted;
        public int alertsRaised;
        public List<FindingAck> findingResults = new ArrayList<>();
        public Map<String, Integer> reasonCounts = new LinkedHashMap<>();

        AlertBatchAck(String batchId, Integer batchSeq, int received) {
            this.batchId = batchId;
            this.batchSeq = batchSeq;
            this.received = received;
        }

        static AlertBatchAck empty(String batchId, Integer batchSeq) {
            return new AlertBatchAck(batchId, batchSeq, 0);
        }

        void add(FindingAck findingAck) {
            findingResults.add(findingAck);
            reasonCounts.merge(findingAck.status, 1, Integer::sum);
            if (findingAck.status != null && findingAck.status.startsWith("accepted_")) {
                accepted++;
            }
        }
    }

    public static final class FindingAck {
        public String id;
        public String findingId;
        public String fingerprint;
        public String status;
        public String reason;
        public String alertRef;

        static FindingAck accepted(String id, PtkFinding finding, String status, Alert alert) {
            return fromStatus(id, finding, status, alert);
        }

        static FindingAck rejected(String id, PtkFinding finding, String status) {
            return fromStatus(id, finding, status, null);
        }

        static FindingAck fromStatus(String id, PtkFinding finding, String status, Alert alert) {
            FindingAck ack = new FindingAck();
            ack.id = id;
            ack.findingId = finding != null ? finding.getId() : null;
            ack.fingerprint = finding != null ? finding.getFingerprint() : null;
            ack.status = status;
            ack.reason = status;
            ack.alertRef = alert != null ? alert.getAlertRef() : null;
            return ack;
        }
    }

    private static HttpMessage findInSitesTree(URI uri) {
        try {
            var node = Model.getSingleton().getSession().getSiteTree().findNode(uri);
            if (node != null && node.getHistoryReference() != null) {
                return node.getHistoryReference().getHttpMessage();
            }
        } catch (Exception e) {
            LOGGER.debug("PTK could not find '{}' in Sites Tree: {}", uri, e.getMessage());
        }
        return null;
    }

    private static String[] splitHeaderBody(String full) {
        if (full.indexOf(HTTP_BOUNDARY) > 0) {
            return full.split(HTTP_BOUNDARY, 2);
        }
        return new String[] {full, ""};
    }
}
