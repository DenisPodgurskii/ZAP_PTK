package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
    private static final String CRLF = "\r\n";
    private static final Pattern REQUEST_LINE_PATTERN =
            Pattern.compile("^[A-Za-z!#$%&'*+.^_`|~-]+\\s+\\S+\\s+HTTP/\\d(?:\\.\\d)?$");
    private static final Pattern STATUS_LINE_PATTERN =
            Pattern.compile("^(HTTP/\\d(?:\\.\\d)?)\\s+(\\d{3})(?:\\s+(.*))?$");
    private static final Pattern STATUS_PROTOCOL_PATTERN =
            Pattern.compile("^(HTTP/\\d(?:\\.\\d)?)(?:\\s+.*)?$");
    private static final Pattern HEADER_LINE_PATTERN =
            Pattern.compile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+:.*$");

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
            HttpMessage msg = createHttpMessageForFinding(finding);
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

    static HttpMessage createHttpMessageForFinding(PtkFinding finding) throws Exception {
        String requestRaw = null;
        String responseRaw = null;
        if (finding.getRequest() != null && finding.getRequest().getRaw() != null) {
            requestRaw = finding.getRequest().getRaw();
        }
        if (finding.getResponse() != null && finding.getResponse().getRaw() != null) {
            responseRaw = finding.getResponse().getRaw();
        }
        ParsedHttpMessage normalizedRequest = normalizeRequestMessage(requestRaw, finding);
        ParsedHttpMessage normalizedResponse = normalizeResponseMessage(responseRaw, finding);
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setMessage(normalizedRequest.header());
        msg.getRequestBody().setBody(normalizedRequest.body());
        msg.getResponseHeader().setMessage(normalizedResponse.header());
        msg.getResponseBody().setBody(normalizedResponse.body());
        return msg;
    }

    private static ParsedHttpMessage normalizeRequestMessage(String raw, PtkFinding finding)
            throws Exception {
        RequestContext context = buildRequestContext(finding);
        RawHttpMessage split = splitRawHttpMessage(raw);
        List<String> lines = split != null ? getHeaderLines(split.header()) : List.of();
        String requestLine =
                !lines.isEmpty() && REQUEST_LINE_PATTERN.matcher(lines.get(0)).matches()
                        ? lines.get(0)
                        : context.method() + " " + context.pathAndQuery() + " " + HttpHeader.HTTP11;
        StringBuilder header = new StringBuilder();
        header.append(requestLine).append(CRLF);
        boolean hasHostHeader = false;
        for (int i = 1; i < lines.size(); i++) {
            String headerLine = sanitizeHeaderLine(lines.get(i));
            if (headerLine == null) {
                continue;
            }
            if (headerLine.regionMatches(true, 0, "Host:", 0, 5)) {
                hasHostHeader = true;
            }
            header.append(headerLine).append(CRLF);
        }
        if (!hasHostHeader) {
            header.append("Host: ").append(context.host()).append(CRLF);
        }
        header.append(CRLF);
        return new ParsedHttpMessage(header.toString(), split != null ? split.body() : "");
    }

    private static ParsedHttpMessage normalizeResponseMessage(String raw, PtkFinding finding) {
        RawHttpMessage split = splitRawHttpMessage(raw);
        List<String> lines = split != null ? getHeaderLines(split.header()) : List.of();
        StringBuilder header = new StringBuilder();
        header.append(normalizeStatusLine(!lines.isEmpty() ? lines.get(0) : null, finding))
                .append(CRLF);
        for (int i = 1; i < lines.size(); i++) {
            String headerLine = sanitizeHeaderLine(lines.get(i));
            if (headerLine != null) {
                header.append(headerLine).append(CRLF);
            }
        }
        header.append(CRLF);
        return new ParsedHttpMessage(header.toString(), split != null ? split.body() : "");
    }

    private static RawHttpMessage splitRawHttpMessage(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String normalized = raw.replace("\r\n", "\n").replace('\r', '\n');
        String[] parts = normalized.split("\n\n", 2);
        if (parts.length == 2) {
            return new RawHttpMessage(parts[0], parts[1]);
        }
        return new RawHttpMessage(normalized, "");
    }

    private static List<String> getHeaderLines(String header) {
        if (header == null || header.isBlank()) {
            return List.of();
        }
        String[] parts = header.split("\n");
        List<String> lines = new ArrayList<>(parts.length);
        for (String part : parts) {
            String line = part.trim();
            if (!line.isEmpty()) {
                lines.add(line);
            }
        }
        return lines;
    }

    private static String sanitizeHeaderLine(String line) {
        if (line == null) {
            return null;
        }
        String trimmed = line.trim();
        if (trimmed.isEmpty() || !HEADER_LINE_PATTERN.matcher(trimmed).matches()) {
            return null;
        }
        return trimmed;
    }

    private static String normalizeStatusLine(String rawStatusLine, PtkFinding finding) {
        String statusLine = rawStatusLine != null ? rawStatusLine.trim() : "";
        Matcher validStatusLine = STATUS_LINE_PATTERN.matcher(statusLine);
        if (validStatusLine.matches()) {
            return statusLine;
        }
        String protocol = HttpHeader.HTTP11;
        Matcher protocolMatcher = STATUS_PROTOCOL_PATTERN.matcher(statusLine);
        if (protocolMatcher.matches()) {
            protocol = protocolMatcher.group(1);
        }
        int statusCode = resolveStatusCode(finding);
        String reasonPhrase = extractReasonPhrase(statusLine);
        if (reasonPhrase == null || reasonPhrase.isBlank()) {
            reasonPhrase = defaultReasonPhrase(statusCode);
        }
        return protocol + " " + statusCode + " " + reasonPhrase;
    }

    private static String extractReasonPhrase(String statusLine) {
        if (statusLine == null || statusLine.isBlank()) {
            return null;
        }
        String trimmed = statusLine.trim();
        if (trimmed.matches("^HTTP/\\d(?:\\.\\d)?\\s+\\d{3}(?:\\s+.*)?$")) {
            String[] parts = trimmed.split("\\s+", 3);
            return parts.length >= 3 ? parts[2].trim() : null;
        }
        if (trimmed.matches("^HTTP/\\d(?:\\.\\d)?\\s+.+$")) {
            return trimmed.replaceFirst("^HTTP/\\d(?:\\.\\d)?\\s+", "").trim();
        }
        return null;
    }

    private static int resolveStatusCode(PtkFinding finding) {
        if (finding.getResponse() != null && finding.getResponse().getStatusCode() != null) {
            int code = finding.getResponse().getStatusCode();
            if (code >= 100 && code <= 599) {
                return code;
            }
        }
        return 200;
    }

    private static String defaultReasonPhrase(int statusCode) {
        return switch (statusCode) {
            case 201 -> "Created";
            case 202 -> "Accepted";
            case 204 -> "No Content";
            case 301 -> "Moved Permanently";
            case 302 -> "Found";
            case 304 -> "Not Modified";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 409 -> "Conflict";
            case 422 -> "Unprocessable Entity";
            case 429 -> "Too Many Requests";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            case 504 -> "Gateway Timeout";
            default -> statusCode >= 400 ? "Error" : "OK";
        };
    }

    private static RequestContext buildRequestContext(PtkFinding finding) throws Exception {
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
        int port = uri.getPort();
        if (port > 0) {
            host = host + ":" + port;
        }
        return new RequestContext(method, host, path);
    }

    private record RawHttpMessage(String header, String body) {}

    private record ParsedHttpMessage(String header, String body) {}

    private record RequestContext(String method, String host, String pathAndQuery) {}
}
