package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.client.ClientCallBackImplementor;
import org.zaproxy.addon.client.ClientCallBackUtils;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.options.PtkOptionsPanel;
import org.zaproxy.addon.ptk.options.PtkParam;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;

public class ExtensionPtk extends ExtensionAdaptor implements ExampleAlertProvider {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionPtk.class);
    private static final String PREFIX = "ptk";
    private static final Gson GSON = new Gson();
    private static final int BROWSER_CLOSE_MAX_ATTEMPTS = 20;
    private static final long BROWSER_CLOSE_WAIT_SLICE_MS = 1000;
    private static final Set<String> DEFAULT_INFO_TIMING_PHASES =
            Set.of("progress.terminal", "session.summary", "browser_close.end");

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionClientIntegration.class);

    private ClientCallBackImplementor callBackImplementor;
    private PtkOptionsPanel optionsPanel;
    private PtkParam ptkParam;
    private final Object configCacheLock = new Object();
    private volatile PtkResourcesLoader.LoadedPtkResources cachedResources;
    private volatile String cachedConfigKey;
    private volatile String cachedConfigJson;

    private final Map<String, Integer> scanProgress = new ConcurrentHashMap<>();
    private final Map<String, String> scanStatus = new ConcurrentHashMap<>();
    private final Map<String, Long> callbackFirstSeenAtMs = new ConcurrentHashMap<>();
    private final Map<String, String> browserIdByZapId = new ConcurrentHashMap<>();
    private final Map<String, Integer> alertsRaisedByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> firstAlertSeenAtMs = new ConcurrentHashMap<>();
    private final Set<String> firstProgressLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> firstAlertLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> terminalProgressLogged = ConcurrentHashMap.newKeySet();

    public ExtensionPtk() {
        super("ExtensionPtk");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        callBackImplementor = new CallBackImplementor();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .registerClientCallBack(callBackImplementor);
        extensionHook.addOptionsParamSet(getParam());
        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
        }
    }

    private PtkOptionsPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new PtkOptionsPanel();
        }
        return optionsPanel;
    }

    private PtkParam getParam() {
        if (ptkParam == null) {
            ptkParam = new PtkParam();
        }
        return ptkParam;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .unregisterClientCallBack(callBackImplementor);
        if (optionsPanel != null) {
            optionsPanel.unload();
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return PtkExampleAlerts.getExampleAlerts(getLoadedResources());
    }

    private PtkResourcesLoader.LoadedPtkResources getLoadedResources() {
        PtkResourcesLoader.LoadedPtkResources resources = cachedResources;
        if (resources != null) {
            return resources;
        }
        synchronized (configCacheLock) {
            resources = cachedResources;
            if (resources == null) {
                resources = new PtkResourcesLoader().loadAll();
                cachedResources = resources;
                LOGGER.debug("PTK resources cache populated");
            }
            return resources;
        }
    }

    private String getCachedConfigJson() {
        PtkParam param = getParam();
        PtkResourcesLoader.LoadedPtkResources resources = getLoadedResources();
        String configKey = param.buildConfigCacheKey(resources);
        String json = cachedConfigJson;
        if (json != null && configKey.equals(cachedConfigKey)) {
            LOGGER.debug("PTK /ptk/config cache hit");
            return json;
        }

        synchronized (configCacheLock) {
            if (cachedConfigJson != null && configKey.equals(cachedConfigKey)) {
                LOGGER.debug("PTK /ptk/config cache hit after lock");
                return cachedConfigJson;
            }

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("mode", param.isAutomatedScanningEnabled() ? "auto" : "manual");
            Map<String, PtkModulesDefinition> config = PtkConfigFilter.filter(resources, param);
            response.put("sast", config.get("sast") != null ? config.get("sast") : Map.of());
            response.put("iast", config.get("iast") != null ? config.get("iast") : Map.of());
            response.put("dast", config.get("dast") != null ? config.get("dast") : Map.of());

            json = GSON.toJson(response);
            cachedConfigKey = configKey;
            cachedConfigJson = json;
            LOGGER.debug("PTK /ptk/config cache miss; rebuilt response");
            return json;
        }
    }

    class CallBackImplementor implements ClientCallBackImplementor {

        private static final String PTK_ALERT_PATH = "/ptk/alert";
        private static final String PTK_CONFIG_PATH = "/ptk/config";
        private static final String PTK_PING_PATH = "/ptk/ping";
        private static final String PTK_PROGRESS_PATH = "/ptk/progress";

        @SuppressWarnings("unchecked")
        private Map<String, Object> parseRequestBody(String requestBody) {
            if (requestBody == null || requestBody.isBlank()) {
                return Map.of();
            }
            try {
                Map<String, Object> parsed = GSON.fromJson(requestBody, Map.class);
                return parsed != null ? parsed : Map.of();
            } catch (Exception e) {
                return Map.of();
            }
        }

        private String getStringField(Map<String, Object> body, String key) {
            Object value = body.get(key);
            return value instanceof String ? (String) value : null;
        }

        private Integer getIntegerField(Map<String, Object> body, String key) {
            Object value = body.get(key);
            return value instanceof Number ? ((Number) value).intValue() : null;
        }

        private void rememberBrowserId(String zapid, String browserid) {
            if (zapid == null || zapid.isBlank() || browserid == null || browserid.isBlank()) {
                return;
            }
            browserIdByZapId.put(zapid, browserid);
        }

        private long markCallbackStart(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return -1L;
            }
            return callbackFirstSeenAtMs.computeIfAbsent(zapid, key -> System.currentTimeMillis());
        }

        private Long getElapsedSinceFirst(String zapid, long nowMs) {
            if (zapid == null || zapid.isBlank()) {
                return null;
            }
            long startedAt = markCallbackStart(zapid);
            if (startedAt <= 0L) {
                return null;
            }
            return Math.max(0L, nowMs - startedAt);
        }

        private int rememberAlertsRaised(String zapid, int raised) {
            if (zapid == null || zapid.isBlank()) {
                return Math.max(0, raised);
            }
            return alertsRaisedByZapId.merge(zapid, Math.max(0, raised), Integer::sum);
        }

        private int getAlertsRaisedTotal(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return 0;
            }
            return alertsRaisedByZapId.getOrDefault(zapid, 0);
        }

        private void markFirstAlertSeen(String zapid, long seenAtMs) {
            if (zapid == null || zapid.isBlank()) {
                return;
            }
            firstAlertSeenAtMs.putIfAbsent(zapid, seenAtMs);
        }

        private Long getFirstAlertElapsed(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return null;
            }
            Long firstAlertAt = firstAlertSeenAtMs.get(zapid);
            if (firstAlertAt == null) {
                return null;
            }
            return getElapsedSinceFirst(zapid, firstAlertAt);
        }

        private Map<String, Object> buildSessionSummaryExtra(
                String zapid, boolean forced, long waitedMs, Integer progress, String status) {
            Map<String, Object> extra = new LinkedHashMap<>();
            extra.put("waitedMs", waitedMs);
            extra.put("forced", forced);
            extra.put("progress", progress != null ? progress : 0);
            if (status != null && !status.isBlank()) {
                extra.put("status", status);
            }
            extra.put("alertsTotal", getAlertsRaisedTotal(zapid));
            extra.put("terminalSeen", zapid != null && terminalProgressLogged.contains(zapid));
            Long firstAlertMs = getFirstAlertElapsed(zapid);
            if (firstAlertMs != null) {
                extra.put("firstAlertMs", firstAlertMs);
            }
            return extra;
        }

        private void clearTrackingState(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return;
            }
            scanProgress.remove(zapid);
            scanStatus.remove(zapid);
            callbackFirstSeenAtMs.remove(zapid);
            browserIdByZapId.remove(zapid);
            alertsRaisedByZapId.remove(zapid);
            firstAlertSeenAtMs.remove(zapid);
            firstProgressLogged.remove(zapid);
            firstAlertLogged.remove(zapid);
            terminalProgressLogged.remove(zapid);
        }

        private boolean isTerminalProgressValue(Integer progress, String status) {
            if (progress != null && progress.intValue() >= 100) {
                return true;
            }
            return "completed".equalsIgnoreCase(status)
                    || "error".equalsIgnoreCase(status)
                    || "cancelled".equalsIgnoreCase(status)
                    || "timeout".equalsIgnoreCase(status);
        }

        private void logCallbackSummary(
                HttpMessage msg,
                String type,
                String requestBody,
                String zapid,
                String browserid,
                Integer progress,
                Integer alertsRaised,
                String status,
                Long handlerMs,
                Long sinceFirstMs,
                Boolean firstEvent) {
            if (!LOGGER.isDebugEnabled()) {
                return;
            }
            StringBuilder summary = new StringBuilder();
            summary.append("PTK callback type=")
                    .append(type)
                    .append(" method=")
                    .append(msg.getRequestHeader().getMethod())
                    .append(" uri=")
                    .append(msg.getRequestHeader().getURI())
                    .append(" zapid=")
                    .append(zapid)
                    .append(" browserid=")
                    .append(browserid);
            if (progress != null) {
                summary.append(" progress=").append(progress);
            }
            if (status != null && !status.isBlank()) {
                summary.append(" status=").append(status);
            }
            summary.append(" bodyChars=").append(requestBody != null ? requestBody.length() : 0);
            if (alertsRaised != null) {
                summary.append(" alertsRaised=").append(alertsRaised);
            }
            if (handlerMs != null) {
                summary.append(" handlerMs=").append(handlerMs);
            }
            if (sinceFirstMs != null) {
                summary.append(" sinceFirstMs=").append(sinceFirstMs);
            }
            if (firstEvent != null) {
                summary.append(" first=").append(firstEvent);
            }
            LOGGER.info(summary.toString());
        }

        private void logTimingSummary(
                String zapid,
                String browserid,
                String phase,
                Long elapsedMs,
                Map<String, Object> extra) {
            if (phase == null || phase.isBlank()) {
                return;
            }
            if (!LOGGER.isDebugEnabled() && !DEFAULT_INFO_TIMING_PHASES.contains(phase)) {
                return;
            }
            StringBuilder summary = new StringBuilder();
            summary.append("PTK_TIMING");
            if (zapid != null && !zapid.isBlank()) {
                summary.append(" zapid=").append(zapid);
            }
            if (browserid != null && !browserid.isBlank()) {
                summary.append(" browserid=").append(browserid);
            }
            summary.append(" phase=").append(phase);
            if (elapsedMs != null) {
                summary.append(" elapsedMs=").append(elapsedMs);
            }
            if (extra != null) {
                extra.forEach(
                        (key, value) -> {
                            if (key == null || key.isBlank() || value == null) {
                                return;
                            }
                            summary.append(" ").append(key).append("=").append(value);
                        });
            }
            LOGGER.info(summary.toString());
        }

        @Override
        public String getImplementorName() {
            return PREFIX;
        }

        @Override
        public String handleCallBack(HttpMessage msg) {
            String uri =
                    msg.getRequestHeader().getURI() != null
                            ? msg.getRequestHeader().getURI().toString()
                            : "";
            if (uri.contains(PTK_CONFIG_PATH)) {
                long startedAt = System.currentTimeMillis();
                String requestBody = msg.getRequestBody().toString();
                Map<String, Object> requestData = parseRequestBody(requestBody);
                String zapid = getStringField(requestData, "zapid");
                String browserid = getStringField(requestData, "browserid");
                rememberBrowserId(zapid, browserid);
                markCallbackStart(zapid);
                msg.getResponseBody().setBody(getCachedConfigJson());
                long finishedAt = System.currentTimeMillis();
                Long sinceFirstMs = getElapsedSinceFirst(zapid, finishedAt);
                logCallbackSummary(
                        msg,
                        "config",
                        requestBody,
                        zapid,
                        browserid,
                        null,
                        null,
                        "ok",
                        finishedAt - startedAt,
                        sinceFirstMs,
                        false);
                logTimingSummary(
                        zapid,
                        browserid,
                        "config.end",
                        sinceFirstMs,
                        Map.of("durationMs", finishedAt - startedAt));
            } else if (uri.contains(PTK_ALERT_PATH)) {
                long startedAt = System.currentTimeMillis();
                String requestBody = msg.getRequestBody().toString();
                int raised = PtkAlertHandler.processAlertBatch(requestBody);
                Map<String, Object> requestData = parseRequestBody(requestBody);
                String zapid = getStringField(requestData, "zapid");
                String browserid = getStringField(requestData, "browserid");
                rememberBrowserId(zapid, browserid);
                boolean firstAlert = zapid != null && firstAlertLogged.add(zapid);
                markCallbackStart(zapid);
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("result", "OK");
                response.put("alertsRaised", raised);
                msg.getResponseBody().setBody(GSON.toJson(response));
                long finishedAt = System.currentTimeMillis();
                Long sinceFirstMs = getElapsedSinceFirst(zapid, finishedAt);
                int totalAlerts = rememberAlertsRaised(zapid, raised);
                if (firstAlert) {
                    markFirstAlertSeen(zapid, finishedAt);
                }
                if (firstAlert) {
                    logCallbackSummary(
                            msg,
                            "alert",
                            requestBody,
                            zapid,
                            browserid,
                            null,
                            raised,
                            "ok",
                            finishedAt - startedAt,
                            sinceFirstMs,
                            true);
                    logTimingSummary(
                            zapid,
                            browserid,
                            "alert.first",
                            sinceFirstMs,
                            Map.of("alertsRaised", raised, "alertsTotal", totalAlerts));
                }
            } else if (uri.contains(PTK_PING_PATH)) {
                // Will use in the future
                LOGGER.debug(
                        "PTK got ping: {} {} {}",
                        msg.getRequestHeader().getMethod(),
                        msg.getRequestHeader().getURI(),
                        msg.getRequestBody());
            } else if (uri.contains(PTK_PROGRESS_PATH)) {
                long startedAt = System.currentTimeMillis();
                String requestBody = msg.getRequestBody().toString();
                try {
                    Map<String, Object> progressData = parseRequestBody(requestBody);
                    String zapid = (String) progressData.get("zapid");
                    String browserid = (String) progressData.get("browserid");
                    Number progress = (Number) progressData.get("progress");
                    String status = getStringField(progressData, "status");
                    if (zapid != null && progress != null) {
                        rememberBrowserId(zapid, browserid);
                        scanProgress.put(zapid, progress.intValue());
                        if (status != null && !status.isBlank()) {
                            scanStatus.put(zapid, status);
                        }
                        boolean firstProgress = firstProgressLogged.add(zapid);
                        long finishedAt = System.currentTimeMillis();
                        markCallbackStart(zapid);
                        Long sinceFirstMs = getElapsedSinceFirst(zapid, finishedAt);
                        boolean terminalProgress =
                                isTerminalProgressValue(progress.intValue(), status);
                        if (terminalProgress && zapid != null && !zapid.isBlank()) {
                            terminalProgressLogged.add(zapid);
                        }
                        if (firstProgress || terminalProgress) {
                            logCallbackSummary(
                                    msg,
                                    "progress",
                                    requestBody,
                                    zapid,
                                    browserid,
                                    progress.intValue(),
                                    null,
                                    status,
                                    finishedAt - startedAt,
                                    sinceFirstMs,
                                    firstProgress);
                        }
                        if (firstProgress) {
                            logTimingSummary(
                                    zapid,
                                    browserid,
                                    "progress.first",
                                    sinceFirstMs,
                                    Map.of(
                                            "progress",
                                            progress.intValue(),
                                            "status",
                                            status != null ? status : ""));
                        }
                        if (terminalProgress) {
                            Map<String, Object> extra = new LinkedHashMap<>();
                            extra.put("progress", progress.intValue());
                            if (status != null && !status.isBlank()) {
                                extra.put("status", status);
                            }
                            extra.put("alertsTotal", getAlertsRaisedTotal(zapid));
                            logTimingSummary(
                                    zapid, browserid, "progress.terminal", sinceFirstMs, extra);
                        }
                    } else {
                        LOGGER.warn("PTK progress missing zapid or progress: {}", requestBody);
                    }
                } catch (Exception e) {
                    LOGGER.warn("PTK failed to parse progress body: {}", requestBody, e);
                }
                msg.getResponseBody().setBody("{\"result\": \"OK\"}");
            } else {
                LOGGER.warn(
                        "PTK unexpected request: {} {} {}",
                        msg.getRequestHeader().getMethod(),
                        msg.getRequestHeader().getURI(),
                        msg.getRequestBody());
                msg.getResponseBody().setBody("{\"result\": \"FAIL\"}");
            }
            msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/json");
            msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
            return "";
        }

        @Override
        public void browserClosing(ClientCallBackUtils ccbutils) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.info("PTK browserClosing uuid={}", ccbutils.getUuid());
            }
            if (ccbutils.getUuid() == null) {
                return;
            }
            String zapid = ccbutils.getUuid().toString();
            if (!scanProgress.containsKey(zapid)) {
                LOGGER.warn("PTK browserExiting: no progress for UUID {}", ccbutils.getUuid());
                return;
            }
            long start = System.currentTimeMillis();
            int count = 0;
            while (!isTerminalProgress(zapid)) {
                count++;
                if (count >= BROWSER_CLOSE_MAX_ATTEMPTS) {
                    String browserid = browserIdByZapId.get(zapid);
                    Map<String, Object> summaryExtra =
                            buildSessionSummaryExtra(
                                    zapid,
                                    true,
                                    (System.currentTimeMillis() - start),
                                    scanProgress.getOrDefault(zapid, 0),
                                    scanStatus.getOrDefault(zapid, ""));
                    LOGGER.warn(
                            "PTK browserClosing uuid={} forced=true waitedMs={} progress={} status={}",
                            ccbutils.getUuid(),
                            (System.currentTimeMillis() - start),
                            scanProgress.get(zapid),
                            scanStatus.getOrDefault(zapid, ""));
                    logTimingSummary(
                            zapid,
                            browserid,
                            "session.summary",
                            getElapsedSinceFirst(zapid, System.currentTimeMillis()),
                            summaryExtra);
                    logTimingSummary(
                            zapid,
                            browserid,
                            "browser_close.end",
                            getElapsedSinceFirst(zapid, System.currentTimeMillis()),
                            summaryExtra);
                    clearTrackingState(zapid);
                    return;
                }
                try {
                    Thread.sleep(BROWSER_CLOSE_WAIT_SLICE_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            scanProgress.remove(zapid);
            String status = scanStatus.remove(zapid);
            String browserid = browserIdByZapId.remove(zapid);
            Long elapsedSinceFirstMs = getElapsedSinceFirst(zapid, System.currentTimeMillis());
            Map<String, Object> summaryExtra =
                    buildSessionSummaryExtra(
                            zapid,
                            false,
                            (System.currentTimeMillis() - start),
                            100,
                            status != null ? status : "");
            logTimingSummary(
                    zapid, browserid, "session.summary", elapsedSinceFirstMs, summaryExtra);
            logTimingSummary(
                    zapid, browserid, "browser_close.end", elapsedSinceFirstMs, summaryExtra);
            clearTrackingState(zapid);
        }

        private boolean isTerminalProgress(String zapid) {
            return isTerminalProgressValue(
                    scanProgress.getOrDefault(zapid, 100), scanStatus.get(zapid));
        }
    }
}
