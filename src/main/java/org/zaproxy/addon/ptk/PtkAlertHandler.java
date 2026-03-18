package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.httpclient.URI;
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
        int raised = 0;
        for (PtkFinding finding : batch.getFindings()) {
            if (finding.getModuleId() == null || finding.getRuleId() == null) {
                continue;
            }
            Alert alert = PtkAlertBuilder.buildFromFinding(finding, engine, mapper, resources);
            if (alert == null) {
                continue;
            }
            if (raiseAlert(alert, finding, extAlert)) {
                raised++;
            }
        }
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
            HttpMessage msg = createHttpMessageForFinding(finding);
            HistoryReference ref =
                    new HistoryReference(
                            Model.getSingleton().getSession(), HistoryReference.TYPE_SCANNER, msg);
            alert.setMessage(msg);
            extAlert.alertFound(alert, ref);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static HttpMessage createHttpMessageForFinding(PtkFinding finding) throws Exception {
        String requestRaw = null;
        String responseRaw = null;
        if (finding.getRequest() != null && finding.getRequest().getRaw() != null) {
            requestRaw = finding.getRequest().getRaw();
        }
        if (finding.getResponse() != null && finding.getResponse().getRaw() != null) {
            responseRaw = finding.getResponse().getRaw();
        }
        if (requestRaw != null && responseRaw != null) {
            HttpMessage msg = new HttpMessage();
            msg.getRequestHeader().setMessage(requestRaw);
            msg.getRequestBody().setLength(0);
            msg.getResponseHeader().setMessage(responseRaw);
            msg.getResponseBody().setLength(0);
            return msg;
        }
        String url =
                finding.getUri() != null && !finding.getUri().isBlank()
                        ? finding.getUri()
                        : "http://localhost/";
        String method = finding.getMethod() != null ? finding.getMethod() : "GET";
        URI uri;
        try {
            uri = new URI(url, true);
        } catch (Exception e) {
            uri = new URI("http://localhost/", true);
        }
        String path = uri.getPath();
        if (path == null || path.isEmpty()) path = "/";
        String query = uri.getQuery();
        if (query != null && !query.isEmpty()) path = path + "?" + query;
        String host = uri.getHost();
        if (host == null || host.isEmpty()) host = "localhost";
        String request =
                method + " " + path + " " + HttpHeader.HTTP11 + "\r\nHost: " + host + "\r\n\r\n";
        String response = HttpHeader.HTTP11 + " 200 OK\r\nContent-Type: text/html\r\n\r\n";
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setMessage(request);
        msg.getRequestBody().setLength(0);
        msg.getResponseHeader().setMessage(response);
        msg.getResponseBody().setLength(0);
        return msg;
    }
}
