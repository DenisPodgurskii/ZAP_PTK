package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
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
    private static final PtkAlertReceipts RECEIPTS = new PtkAlertReceipts();
    private static final Map<String, String> BATCH_DIGESTS = new ConcurrentHashMap<>();
    private static final Map<String, JsonObject> COMPLETENESS = new ConcurrentHashMap<>();
    private record RetiredAck(AlertBatchAck ack, String v3Digest) {}

    private static final LinkedHashMap<String, RetiredAck> RETIRED_ACKS = new LinkedHashMap<>();

    private PtkAlertHandler() {}

    public static synchronized void retireSession(String zapid, String sessionId) {
        String scope = receiptScope(zapid, sessionId);
        for (String key : RECEIPTS.retire(scope)) {
            if (key.startsWith("batch:")) {
                String batchKey = key.substring(6);
                AlertBatchAck ack = BATCH_ACK_CACHE.remove(batchKey);
                String digest = BATCH_DIGESTS.remove(batchKey);
                if (ack != null) RETIRED_ACKS.put(batchKey, new RetiredAck(ack,
                        PtkIastV3Contract.V3.equals(ack.schema) ? digest : null));
            } else if (key.startsWith("finding:")) IMPORTED_FINDING_KEYS.remove(key.substring(8));
        }
        COMPLETENESS.keySet().removeIf(key -> key.startsWith(scope + ":"));
        while (RETIRED_ACKS.size() > ACK_CACHE_MAX_ENTRIES
                || GSON.toJson(RETIRED_ACKS).getBytes(StandardCharsets.UTF_8).length
                        > 8 * 1024 * 1024)
            RETIRED_ACKS.remove(RETIRED_ACKS.keySet().iterator().next());
    }

    public static synchronized void clearAllReceipts() {
        RECEIPTS.clear();
        BATCH_ACK_CACHE.clear();
        BATCH_DIGESTS.clear();
        IMPORTED_FINDING_KEYS.clear();
        BATCH_ACK_LOCKS.clear();
        IMPORTED_FINDING_LOCKS.clear();
        COMPLETENESS.clear();
        RETIRED_ACKS.clear();
    }

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
        if (requestBody.getBytes(StandardCharsets.UTF_8).length > 16 * 1024 * 1024)
            return AlertBatchAck.failure(null, null, "invalid_payload");
        PtkFindingBatch batch;
        String wireSchema = null;
        try {
            JsonObject root = JsonParser.parseString(requestBody).getAsJsonObject();
            String schema = root.has("schema") ? root.get("schema").getAsString() : "";
            wireSchema = schema;
            if (PtkIastV2Contract.V2.equals(schema)
                    || PtkIastV3Contract.V3.equals(schema)
                    || "iast_findings_batch"
                            .equals(root.has("type") ? root.get("type").getAsString() : "")) {
                if (!PtkConfigFilter.supportedIastSchemas().contains(schema))
                    return AlertBatchAck.failure(null, null, "unsupported_schema");
                if (PtkIastV2Contract.V2.equals(schema)) PtkIastV2Contract.validate(root);
                if (PtkIastV3Contract.V3.equals(schema)) PtkIastV3Contract.validate(root);
            }
            batch = GSON.fromJson(requestBody, PtkFindingBatch.class);
            // Flow is a v3-only model field; legacy engines must not acquire a new export seam.
            if (!PtkIastV3Contract.V3.equals(schema) && batch != null && batch.getFindings() != null)
                for (PtkFinding finding : batch.getFindings()) finding.setFlow(null);
        } catch (RuntimeException e) {
            return versionAck(AlertBatchAck.failure(null, null, "invalid_payload"), wireSchema);
        }
        String batchId = batch != null ? batch.getBatchId() : null;
        Integer batchSeq = batch != null ? batch.getBatchSeq() : null;
        String ackKey = buildBatchAckKey(batch);
        if (ackKey != null) {
            String digest = digest(requestBody);
            String priorDigest = BATCH_DIGESTS.get(ackKey);
            RetiredAck retired;
            synchronized (PtkAlertHandler.class) {
                retired = RETIRED_ACKS.get(ackKey);
            }
            if (priorDigest == null && retired != null) priorDigest = retired.v3Digest();
            if (priorDigest != null && !priorDigest.equals(digest))
                return versionAck(AlertBatchAck.failure(batchId, batchSeq, "immutable_identity_conflict"), batch.getSchema());
            AlertBatchAck cached = BATCH_ACK_CACHE.get(ackKey);
            synchronized (PtkAlertHandler.class) {
                if (cached == null && retired != null) cached = retired.ack();
            }
            if (cached != null) {
                return cached;
            }
            Object batchLock = BATCH_ACK_LOCKS.computeIfAbsent(ackKey, key -> new Object());
            synchronized (batchLock) {
                cached = BATCH_ACK_CACHE.get(ackKey);
                if (cached != null) {
                    return cached;
                }
                AlertBatchAck estimated =
                        versionAck(new AlertBatchAck(batchId, batchSeq, batch.getFindings().size()), batch.getSchema());
                for (PtkFinding finding : batch.getFindings())
                    estimated.add(
                            FindingAck.rejected(
                                    findingIdentity(finding),
                                    finding,
                                    "rejected_immutable_identity_conflict"));
                long receiptBytes = utf8(ackKey) + utf8(GSON.toJson(estimated)) + 4096;
                PtkAlertReceipts.Admission admission =
                        RECEIPTS.admit(scope(batch), "batch:" + ackKey, digest, receiptBytes);
                if (admission != PtkAlertReceipts.Admission.NEW
                        && admission != PtkAlertReceipts.Admission.DUPLICATE)
                    return versionAck(AlertBatchAck.failure(batchId, batchSeq, receiptError(admission)), batch.getSchema());
                BATCH_DIGESTS.put(ackKey, digest);
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
        AlertBatchAck ack = versionAck(new AlertBatchAck(batchId, batchSeq, findings.size()), batch.getSchema());
        if (isStructuredIast(batch)) {
            JsonObject summary = batch.getPayload().getScanCompleteness();
            String summaryKey = scope(batch) + ":" + GSON.toJson(List.of(nullSafe(batch.getSchema()), batch.getPayload().getScanId()));
            synchronized (COMPLETENESS) {
                JsonObject prior = COMPLETENESS.get(summaryKey);
                long revision = summary.get("revision").getAsLong();
                if (prior != null
                        && (revision < prior.get("revision").getAsLong()
                                || prior.get("terminal").getAsBoolean()
                                        && !summary.get("terminal").getAsBoolean()
                                || summary.getAsJsonObject("counters").get("lossCount").getAsLong()
                                        < prior.getAsJsonObject("counters")
                                                .get("lossCount")
                                                .getAsLong()
                                || summary.getAsJsonObject("counters")
                                                .get("recordsRejected")
                                                .getAsLong()
                                        < prior.getAsJsonObject("counters")
                                                .get("recordsRejected")
                                                .getAsLong()))
                    return cacheAck(
                            ackKey,
                            versionAck(AlertBatchAck.failure(
                                    batchId, batchSeq, "invalid_completeness_revision"), batch.getSchema()));
                if (prior != null
                        && revision == prior.get("revision").getAsLong()
                        && !prior.equals(summary))
                    return cacheAck(
                            ackKey,
                            versionAck(AlertBatchAck.failure(
                                    batchId, batchSeq, "immutable_identity_conflict"), batch.getSchema()));
                if (prior == null || revision > prior.get("revision").getAsLong())
                    COMPLETENESS.put(summaryKey, summary.deepCopy());
                ack.scanCompletenessRevision = revision;
                ack.scanCompletenessAccepted = true;
            }
            if (findings.isEmpty()) return cacheAck(ackKey, ack);
        }
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
                    String contentDigest =
                            isStructuredIast(batch)
                                    ? digest(GSON.toJson(finding))
                                    : "legacy";
                    PtkAlertReceipts.Admission admission =
                            RECEIPTS.admit(
                                    scope(batch),
                                    "finding:" + findingKey,
                                    contentDigest,
                                    utf8(findingKey) + 128);
                    if (admission == PtkAlertReceipts.Admission.CONFLICT
                            || admission == PtkAlertReceipts.Admission.CAPACITY
                            || admission == PtkAlertReceipts.Admission.RETIRED) {
                        ack.permanentFailure = true;
                        ack.errorCode = receiptError(admission);
                        ack.add(
                                FindingAck.rejected(
                                        findingId, finding, "rejected_" + ack.errorCode));
                        IMPORTED_FINDING_LOCKS.remove(findingKey, findingLock);
                        continue;
                    }
                    if (IMPORTED_FINDING_KEYS.containsKey(findingKey)) {
                        status = "accepted_duplicate";
                    } else if (admission == PtkAlertReceipts.Admission.DUPLICATE) {
                        status = "rejected_raise_failed";
                    } else {
                        status = raiseAlert(alert, finding, extAlert);
                        if ("accepted_raised".equals(status)) {
                            ack.alertsRaised++;
                            IMPORTED_FINDING_KEYS.put(findingKey, System.currentTimeMillis());
                        } else {
                            RECEIPTS.release(scope(batch), "finding:" + findingKey);
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
            String uriStr = msg.getRequestHeader().getURI().toString();
            int fragmentOffset = uriStr.indexOf("%23");
            if (fragmentOffset > 0) {
                // Strip URL fragment - fragments are client-side only and absent from Sites
                // Tree
                msg.getRequestHeader().setURI(new URI(uriStr.substring(0, fragmentOffset), true));
            }

            HistoryReference ref =
                    new HistoryReference(
                            Model.getSingleton().getSession(), HistoryReference.TYPE_SCANNER, msg);
            alert.setMessage(msg);
            extAlert.alertFound(alert, ref);
            // ExtensionAlert can swallow a database-write exception and return.
            // Its supported ZAP implementations assign this ID only after
            // TableAlert.write returns; a bare method return is not a storage
            // acknowledgement for the publisher or a future visit checkpoint.
            if (!hasStoredAlertId(alert)) {
                LOGGER.error("PTK alert was not stored: {}", alert.getName());
                return "rejected_raise_failed";
            }
            LOGGER.debug("PTK raised alert: {}", alert.getName());
            return "accepted_raised";
        } catch (Exception e) {
            LOGGER.error("PTK failed to raise alert: {}", alert.getName(), e);
            return "rejected_raise_failed";
        }
    }

    // ZAP's first persisted alert can have ID 0. A fresh Alert starts at -1;
    // ExtensionAlert changes that ID only after TableAlert.write returns.
    static boolean hasStoredAlertId(Alert alert) {
        return alert != null && alert.getAlertId() >= 0;
    }

    private static AlertBatchAck cacheAck(String ackKey, AlertBatchAck ack) {
        if (ackKey == null || ack == null) {
            return ack != null ? ack : AlertBatchAck.empty(null, null);
        }
        BATCH_ACK_CACHE.put(ackKey, ack);
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
        return GSON.toJson(
                List.of(
                        nullSafe(sessionId),
                        nullSafe(batch.getZapid()),
                        nullSafe(batch.getSchema()),
                        nullSafe(batch.getBatchId()),
                        String.valueOf(batch.getBatchSeq())));
    }

    private static String buildImportedFindingKey(
            PtkFindingBatch batch, PtkFinding finding, Alert alert) {
        String sessionId =
                batch.getPayload() != null && batch.getPayload().getSessionId() != null
                        ? batch.getPayload().getSessionId()
                        : "";
        if (isStructuredIast(batch))
            return GSON.toJson(
                    List.of(
                            nullSafe(sessionId),
                            nullSafe(batch.getZapid()),
                            nullSafe(batch.getSchema()),
                            "IAST",
                            nullSafe(batch.getPayload().getScanId()),
                            findingIdentity(finding)));
        return GSON.toJson(
                List.of(
                        nullSafe(sessionId),
                        nullSafe(batch.getZapid()),
                        nullSafe(batch.getSchema()),
                        nullSafe(
                                batch.getPayload() != null ? batch.getPayload().getEngine() : null),
                        nullSafe(
                                batch.getPayload() != null ? batch.getPayload().getScanId() : null),
                        nullSafe(alert != null ? alert.getAlertRef() : null),
                        nullSafe(findingIdentity(finding)),
                        nullSafe(finding != null ? finding.getUri() : null),
                        nullSafe(finding != null ? finding.getParam() : null)));
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

    private static boolean isStructuredIast(PtkFindingBatch batch) {
        return PtkIastV2Contract.V2.equals(batch.getSchema()) || PtkIastV3Contract.V3.equals(batch.getSchema());
    }

    private static AlertBatchAck versionAck(AlertBatchAck ack, String schema) {
        if (PtkIastV3Contract.V3.equals(schema)) {
            ack.contractVersion = 3;
            ack.schema = PtkIastV3Contract.V3;
        }
        return ack;
    }

    private static String receiptScope(String zapid, String sessionId) {
        return GSON.toJson(List.of(nullSafe(zapid), nullSafe(sessionId)));
    }

    private static String scope(PtkFindingBatch batch) {
        return receiptScope(
                batch.getZapid(),
                batch.getPayload() != null ? batch.getPayload().getSessionId() : null);
    }

    private static int utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static String digest(String value) {
        try {
            return HexFormat.of()
                    .formatHex(
                            MessageDigest.getInstance("SHA-256")
                                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String receiptError(PtkAlertReceipts.Admission admission) {
        return admission == PtkAlertReceipts.Admission.CONFLICT
                ? "immutable_identity_conflict"
                : admission == PtkAlertReceipts.Admission.RETIRED
                        ? "retired_session"
                        : "receipt_capacity";
    }

    public static final class AlertBatchAck {
        public String result = "OK";
        public int contractVersion = 2;
        public String schema;
        public boolean structuredAck = true;
        public boolean legacyAck = false;
        public String batchId;
        public Integer batchSeq;
        public int received;
        public int accepted;
        public int alertsRaised;
        public List<FindingAck> findingResults = new ArrayList<>();
        public Map<String, Integer> reasonCounts = new LinkedHashMap<>();
        public boolean permanentFailure;
        public String errorCode;
        public boolean scanCompletenessAccepted;
        public Long scanCompletenessRevision;

        AlertBatchAck(String batchId, Integer batchSeq, int received) {
            this.batchId = batchId;
            this.batchSeq = batchSeq;
            this.received = received;
        }

        static AlertBatchAck empty(String batchId, Integer batchSeq) {
            return new AlertBatchAck(batchId, batchSeq, 0);
        }

        static AlertBatchAck failure(String batchId, Integer batchSeq, String reason) {
            AlertBatchAck ack = empty(batchId, batchSeq);
            ack.result = "ERROR";
            ack.permanentFailure = true;
            ack.errorCode = reason;
            return ack;
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
