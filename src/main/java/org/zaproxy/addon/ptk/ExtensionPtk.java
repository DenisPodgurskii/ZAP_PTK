package org.zaproxy.addon.ptk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONArray;
import net.sf.json.JSONNull;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.client.ClientCallBackImplementor;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class ExtensionPtk extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionPtk.class);
    private static final String PREFIX = "ptk";
    private static final int PLUGIN_ID_PTK = 500000;
    private static final int DEDUPE_CAP = 5000;
    private static final int MAX_FIELD_LEN = 4096;
    private static final String TYPE_ALERTS_BATCH = "alerts_batch";

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionClientIntegration.class);

    private final Map<String, Boolean> seenFingerprints =
            Collections.synchronizedMap(
                    new LinkedHashMap<>(128, 0.75f, true) {
                        @Override
                        protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                            return size() > DEDUPE_CAP;
                        }
                    });

    private ClientCallBackImplementor callBackImplementor;
    private ExtensionAlert extAlert;

    public ExtensionPtk() {
        super("ExtensionPtk");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        extAlert = Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            LOGGER.warn("ExtensionAlert not available, PTK alerts cannot be raised yet.");
        }

        callBackImplementor = new CallBackImplementor();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .registerClientCallBack(callBackImplementor);
    }

    @Override
    public void unload() {
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .unregisterClientCallBack(callBackImplementor);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    class CallBackImplementor implements ClientCallBackImplementor {

        @Override
        public String getImplementorName() {
            return PREFIX;
        }

        @Override
        public String handleCallBack(HttpMessage msg) {
            String body =
                    msg != null && msg.getRequestBody() != null
                            ? msg.getRequestBody().toString()
                            : "";

            String batchId = null;
            int received = 0;
            int created = 0;
            int skipped = 0;
            int errors = 0;

            try {
                JSONObject envelope = JSONObject.fromObject(body);
                batchId = trimToNull(getStringValue(envelope, "batchId"));
                String source = trimToNull(getStringValue(envelope, "source"));
                String type = trimToNull(getStringValue(envelope, "type"));

                if (source != null && !PREFIX.equalsIgnoreCase(source)) {
                    LOGGER.warn("Received callback with unexpected source '{}'", source);
                }
                if (!TYPE_ALERTS_BATCH.equals(type)) {
                    LOGGER.debug("Ignoring callback type '{}'", type);
                    return applyResponse(
                            msg, buildResponse(batchId, received, created, skipped, errors));
                }

                JSONObject payload = getObject(envelope, "payload");
                JSONArray alerts = payload != null ? getArray(payload, "alerts") : null;
                if (alerts == null) {
                    LOGGER.warn("PTK callback batch {} has no payload.alerts array", batchId);
                    errors++;
                    return applyResponse(
                            msg, buildResponse(batchId, received, created, skipped, errors));
                }

                String payloadEngine =
                        payload != null ? trimToNull(getStringValue(payload, "engine")) : null;
                String payloadScanId =
                        payload != null ? trimToNull(getStringValue(payload, "scanId")) : null;
                received = alerts.size();

                for (int i = 0; i < alerts.size(); i++) {
                    Object raw = alerts.get(i);
                    if (!(raw instanceof JSONObject alertJson)) {
                        errors++;
                        continue;
                    }

                    ProcessingResult result = processAlert(alertJson, payloadEngine, payloadScanId);
                    created += result.created;
                    skipped += result.skipped;
                    errors += result.errors;
                }
            } catch (Exception e) {
                errors++;
                LOGGER.warn("Failed to process PTK callback batch {}: {}", batchId, e.getMessage());
                LOGGER.debug("PTK callback processing exception", e);
            }

            LOGGER.info(
                    "Processed PTK batch {}: received={}, created={}, skipped={}, errors={}",
                    batchId,
                    received,
                    created,
                    skipped,
                    errors);

            return applyResponse(msg, buildResponse(batchId, received, created, skipped, errors));
        }
    }

    private ProcessingResult processAlert(
            JSONObject alertJson, String payloadEngine, String payloadScanId) {
        ProcessingResult result = new ProcessingResult();

        String url = trimToNull(getStringValue(alertJson, "url"));
        if (url == null) {
            result.errors++;
            return result;
        }

        String name = trimToNull(getStringValue(alertJson, "name"));
        if (name == null) {
            name = "PTK Finding";
        }

        int riskId =
                clamp(
                        getIntValue(alertJson, "riskId", Alert.RISK_INFO),
                        Alert.RISK_INFO,
                        Alert.RISK_HIGH);
        int confidenceId =
                clamp(
                        getIntValue(alertJson, "confidenceId", Alert.CONFIDENCE_MEDIUM),
                        Alert.CONFIDENCE_LOW,
                        Alert.CONFIDENCE_HIGH);

        String param = truncate(trimToNull(getStringValue(alertJson, "param")), MAX_FIELD_LEN);
        String attack = truncate(trimToNull(getStringValue(alertJson, "attack")), MAX_FIELD_LEN);
        String evidence =
                truncate(trimToNull(getStringValue(alertJson, "evidence")), MAX_FIELD_LEN);
        String description =
                truncate(trimToNull(getStringValue(alertJson, "description")), MAX_FIELD_LEN);
        String solution =
                truncate(trimToNull(getStringValue(alertJson, "solution")), MAX_FIELD_LEN);
        String references =
                truncate(trimToNull(getStringValue(alertJson, "references")), MAX_FIELD_LEN);
        String otherInfo =
                truncate(trimToNull(getStringValue(alertJson, "otherInfo")), MAX_FIELD_LEN);
        Integer cweId = getNullableInt(alertJson, "cweId");
        Integer wascId = getNullableInt(alertJson, "wascId");

        if (otherInfo == null) {
            StringBuilder sb = new StringBuilder();
            if (payloadEngine != null) {
                sb.append("engine=").append(payloadEngine);
            }
            if (payloadScanId != null) {
                if (sb.length() > 0) {
                    sb.append("; ");
                }
                sb.append("scanId=").append(payloadScanId);
            }
            otherInfo = sb.length() > 0 ? truncate(sb.toString(), MAX_FIELD_LEN) : null;
        }

        String fingerprint = trimToNull(getStringValue(alertJson, "fingerprint"));
        String dedupeKey =
                fingerprint != null
                        ? fingerprint
                        : fallbackFingerprint(url, name, riskId, param == null ? "" : param);
        if (hasSeenFingerprint(dedupeKey)) {
            result.skipped++;
            return result;
        }

        HistoryReference historyRef = resolveHistoryRef(url);
        if (historyRef == null) {
            result.errors++;
            return result;
        }

        ExtensionAlert extensionAlert = extAlert;
        if (extensionAlert == null) {
            extensionAlert =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
            extAlert = extensionAlert;
        }
        if (extensionAlert == null) {
            LOGGER.warn("ExtensionAlert unavailable, skipping PTK alert for URL {}", url);
            result.errors++;
            return result;
        }

        try {
            Alert.Builder builder =
                    Alert.builder()
                            .setPluginId(PLUGIN_ID_PTK)
                            .setSource(Alert.Source.TOOL)
                            .setUri(url)
                            .setRisk(riskId)
                            .setConfidence(confidenceId)
                            .setName(name)
                            .setHistoryRef(historyRef)
                            .setMessage(historyRef.getHttpMessage());

            if (description != null) {
                builder.setDescription(description);
            }
            if (param != null) {
                builder.setParam(param);
            }
            if (attack != null) {
                builder.setAttack(attack);
            }
            if (evidence != null) {
                builder.setEvidence(evidence);
            }
            if (solution != null) {
                builder.setSolution(solution);
            }
            if (references != null) {
                builder.setReference(references);
            }
            if (otherInfo != null) {
                builder.setOtherInfo(otherInfo);
            }
            if (cweId != null) {
                builder.setCweId(cweId);
            }
            if (wascId != null) {
                builder.setWascId(wascId);
            }

            Map<String, String> tags = toTagsMap(getArray(alertJson, "tags"));
            if (!tags.isEmpty()) {
                builder.setTags(tags);
            }

            Alert alert = builder.build();
            extensionAlert.alertFound(alert, historyRef);
            rememberFingerprint(dedupeKey);
            result.created++;
        } catch (Exception e) {
            result.errors++;
            LOGGER.warn("Failed to raise PTK alert for URL {}: {}", url, e.getMessage());
            LOGGER.debug("PTK alert raise exception", e);
        }

        return result;
    }

    private HistoryReference resolveHistoryRef(String url) {
        String normalizedUrl = trimToNull(url);
        if (normalizedUrl == null) {
            return null;
        }

        Session session = Model.getSingleton().getSession();
        if (session == null) {
            LOGGER.warn(
                    "No active ZAP session while resolving HistoryReference for {}", normalizedUrl);
            return null;
        }

        try {
            URI uri = new URI(stripFragment(normalizedUrl), true);
            SiteNode node = session.getSiteTree().findNode(uri);
            if (node != null) {
                HistoryReference historyReference = node.getHistoryReference();
                if (historyReference != null) {
                    return historyReference;
                }
            }

            HttpRequestHeader requestHeader =
                    new HttpRequestHeader(HttpRequestHeader.GET, uri, HttpHeader.HTTP11);
            HttpMessage syntheticMessage = new HttpMessage(requestHeader);
            return new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, syntheticMessage);
        } catch (URIException e) {
            LOGGER.warn("Invalid alert URL '{}': {}", normalizedUrl, e.getMessage());
            LOGGER.debug("PTK URI parse exception", e);
        } catch (Exception e) {
            LOGGER.warn(
                    "Failed to resolve HistoryReference for '{}': {}",
                    normalizedUrl,
                    e.getMessage());
            LOGGER.debug("PTK HistoryReference resolve exception", e);
        }
        return null;
    }

    private static String buildResponse(
            String batchId, int received, int created, int skipped, int errors) {
        JSONObject response = new JSONObject();
        response.put("result", "OK");
        response.put("batchId", batchId);
        response.put("received", received);
        response.put("created", created);
        response.put("skipped", skipped);
        response.put("errors", errors);
        return response.toString();
    }

    private static String applyResponse(HttpMessage msg, String responseBody) {
        if (msg != null) {
            msg.getResponseHeader().setStatusCode(200);
            msg.getResponseHeader().setReasonPhrase("OK");
            msg.getResponseBody().setBody(responseBody);
            msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/json");
            msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
        }
        return responseBody;
    }

    private static JSONObject getObject(JSONObject source, String key) {
        if (source == null || key == null || !source.containsKey(key)) {
            return null;
        }
        Object value = source.get(key);
        return value instanceof JSONObject ? (JSONObject) value : null;
    }

    private static JSONArray getArray(JSONObject source, String key) {
        if (source == null || key == null || !source.containsKey(key)) {
            return null;
        }
        Object value = source.get(key);
        return value instanceof JSONArray ? (JSONArray) value : null;
    }

    private static String getStringValue(JSONObject source, String key) {
        if (source == null || key == null || !source.containsKey(key)) {
            return null;
        }
        Object value = source.get(key);
        if (value == null || value instanceof JSONNull) {
            return null;
        }
        return String.valueOf(value);
    }

    private static int getIntValue(JSONObject source, String key, int defaultValue) {
        Integer value = getNullableInt(source, key);
        return value != null ? value : defaultValue;
    }

    private static Integer getNullableInt(JSONObject source, String key) {
        if (source == null || key == null || !source.containsKey(key)) {
            return null;
        }
        Object value = source.get(key);
        if (value == null || value instanceof JSONNull) {
            return null;
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (Exception e) {
            return null;
        }
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private static String stripFragment(String url) {
        int hashIndex = url.indexOf('#');
        return hashIndex >= 0 ? url.substring(0, hashIndex) : url;
    }

    private static String truncate(String value, int maxLen) {
        if (value == null) {
            return null;
        }
        return value.length() <= maxLen ? value : value.substring(0, maxLen);
    }

    private static Map<String, String> toTagsMap(JSONArray tagsArray) {
        if (tagsArray == null || tagsArray.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, String> tags = new LinkedHashMap<>();
        for (int i = 0; i < tagsArray.size(); i++) {
            Object value = tagsArray.get(i);
            if (value == null || value instanceof JSONNull) {
                continue;
            }
            String tag = trimToNull(String.valueOf(value));
            if (tag != null) {
                tags.put(tag, "");
            }
        }
        return tags;
    }

    private boolean hasSeenFingerprint(String dedupeKey) {
        if (dedupeKey == null) {
            return false;
        }
        synchronized (seenFingerprints) {
            return seenFingerprints.containsKey(dedupeKey);
        }
    }

    private void rememberFingerprint(String dedupeKey) {
        if (dedupeKey == null) {
            return;
        }
        synchronized (seenFingerprints) {
            seenFingerprints.put(dedupeKey, Boolean.TRUE);
        }
    }

    private static String fallbackFingerprint(String url, String name, int riskId, String param) {
        String payload = url + "|" + name + "|" + riskId + "|" + param;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(payload.hashCode());
        }
    }

    private static class ProcessingResult {
        int created;
        int skipped;
        int errors;
    }
}
