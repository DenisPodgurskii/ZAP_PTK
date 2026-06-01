package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import java.util.List;
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

    private PtkAlertHandler() {}

    /**
     * Processes a PTK alert batch from the request body. Parses JSON, builds ZAP alerts for each
     * mapped finding, and raises them.
     *
     * @param requestBody the raw JSON body (e.g. from msg.getRequestBody().toString())
     * @return number of alerts raised
     */
    public static int processAlertBatch(String requestBody) {
        if (requestBody == null || requestBody.isBlank()) {
            return 0;
        }
        PtkFindingBatch batch;
        try {
            batch = GSON.fromJson(requestBody, PtkFindingBatch.class);
        } catch (JsonSyntaxException e) {
            return 0;
        }
        if (batch == null || batch.getPayload() == null || batch.getFindings() == null) {
            return 0;
        }
        String engine = batch.getPayload().getEngine();
        if (engine == null || engine.isBlank()) {
            engine = inferEngine(batch.getType());
        }
        PtkResourcesLoader loader = new PtkResourcesLoader();
        PtkResourcesLoader.LoadedPtkResources resources = loader.loadAll();
        if (resources == null || resources.getZapMapping() == null) {
            return 0;
        }
        PtkZapMapper mapper = new PtkZapMapper(resources);
        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return 0;
        }
        List<PtkFinding> findings = batch.getFindings();
        LOGGER.debug("PTK alert batch: {} alerts reported", findings.size());

        int raised = 0;
        for (PtkFinding finding : findings) {
            if (finding.getModuleId() == null || finding.getRuleId() == null) {
                LOGGER.error(
                        "PTK module or rule not found for id={}, moduleId={}, ruleId={}",
                        finding.getId(),
                        finding.getModuleId(),
                        finding.getRuleId());
                continue;
            }
            Alert alert = PtkAlertBuilder.buildFromFinding(finding, engine, mapper, resources);
            if (alert == null) {
                LOGGER.error(
                        "PTK mapping not found for moduleId={}, ruleId={}",
                        finding.getModuleId(),
                        finding.getRuleId());
                continue;
            }
            if (raiseAlert(alert, finding, extAlert)) {
                raised++;
            }
        }

        LOGGER.debug("PTK alerts raised: {} of {} reported", raised, findings.size());
        return raised;
    }

    private static String inferEngine(String type) {
        if (type == null) return "PTK";
        if (type.contains("sast")) return "SAST";
        if (type.contains("iast")) return "IAST";
        if (type.contains("dast")) return "DAST";
        return "PTK";
    }

    private static boolean raiseAlert(Alert alert, PtkFinding finding, ExtensionAlert extAlert) {
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
                    return false;
                }
                URI uri;
                try {
                    uri = new URI(url, true);
                } catch (Exception e) {
                    LOGGER.error("PTK could not parse URL '{}': {}", url, e.getMessage());
                    return false;
                }
                msg = findInSitesTree(uri);
                if (msg != null) {
                    otherInfoNote = Constant.messages.getString("ptk.alert.otherinfo.similar");
                } else {
                    LOGGER.error(
                            "PTK no Sites Tree match for alert: name={} url={}",
                            alert.getName(),
                            uri);
                    return false;
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
            LOGGER.debug("PTK raised alert: {}", alert.getName());
            return true;
        } catch (Exception e) {
            LOGGER.error("PTK failed to raise alert: {}", alert.getName(), e);
            return false;
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
