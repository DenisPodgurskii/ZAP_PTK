package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.client.ClientCallBackImplementor;
import org.zaproxy.addon.client.ClientCallBackUtils;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.options.PtkOptionsPanel;
import org.zaproxy.addon.ptk.options.PtkParam;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.BrowserExtension;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.SeleniumOptions;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.model.Context;

/*
 * Browser close timeout model:
 * - BROWSER_CLOSE_TOTAL_WAIT_MS is the Java polling budget after the first PTK
 *   close decision has returned. ZAP waits this long for progress callbacks to
 *   report terminal state or safeToClose before forcing the browser closed.
 * - BROWSER_CLOSE_SCRIPT_TIMEOUT_MS is the Selenium async-script budget for a
 *   single close-decision call.
 * - BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS is now the legacy close-decision bridge call
 *   timeout. The close-decision script must not stop PTK merely because this or any
 *   other close budget elapsed.
 * - Follow-up WebDriver decisions are attempted every
 *   BROWSER_CLOSE_FOLLOW_UP_DECISION_EVERY_ATTEMPTS slices while the Java polling
 *   budget remains open. The worst-case wall-clock bound is therefore
 *   BROWSER_CLOSE_MAX_WALL_CLOCK_MS.
 * - Browser sessions that reach close without any PTK progress get a bounded
 *   startup grace. This avoids closing a valid page too early when many
 *   WebDriver browsers are started concurrently and the PTK content/background
 *   handshake is delayed.
 * - Hard timeout means forced/incomplete. It is not clean close evidence.
 */
final class PtkCloseContract {
    static final int BROWSER_CLOSE_MAX_ATTEMPTS = 120;
    static final long BROWSER_CLOSE_WAIT_SLICE_MS = 1000;
    static final long BROWSER_CLOSE_NO_PROGRESS_GRACE_MS = 25000;
    static final long BROWSER_CLOSE_AUTOMATION_DISABLED_GRACE_MS = 2500;
    static final long CLOSED_ZAPID_RETENTION_MS = 60_000L;
    static final int CLOSED_ZAPID_MAX_ENTRIES = 1024;
    static final long BROWSER_CLOSE_TOTAL_WAIT_MS =
            BROWSER_CLOSE_MAX_ATTEMPTS * BROWSER_CLOSE_WAIT_SLICE_MS;
    static final long BROWSER_CLOSE_SCRIPT_TIMEOUT_MS = 30000;
    static final int BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS = 25000;
    static final long BROWSER_CLOSE_ACTIVITY_STALE_MS = 30_000L;
    static final int BROWSER_CLOSE_FOLLOW_UP_DECISION_EVERY_ATTEMPTS = 15;
    static final int BROWSER_CLOSE_MAX_FOLLOW_UP_DECISIONS =
            BROWSER_CLOSE_MAX_ATTEMPTS / BROWSER_CLOSE_FOLLOW_UP_DECISION_EVERY_ATTEMPTS;
    static final long BROWSER_CLOSE_MAX_WALL_CLOCK_MS =
            BROWSER_CLOSE_SCRIPT_TIMEOUT_MS
                    + BROWSER_CLOSE_NO_PROGRESS_GRACE_MS
                    + BROWSER_CLOSE_AUTOMATION_DISABLED_GRACE_MS
                    + BROWSER_CLOSE_TOTAL_WAIT_MS
                    + (BROWSER_CLOSE_MAX_FOLLOW_UP_DECISIONS * BROWSER_CLOSE_SCRIPT_TIMEOUT_MS);

    static {
        if (BROWSER_CLOSE_SCRIPT_TIMEOUT_MS < BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS) {
            throw new IllegalStateException(
                    "PTK browser close script timeout must cover PTK bridge timeout");
        }
    }

    private PtkCloseContract() {}

    static Long getCloseDecisionAttemptedAtMs(
            Map<String, Long> closeDecisionAttemptedByZapId, String zapid) {
        if (zapid == null || zapid.isBlank()) {
            return null;
        }
        return closeDecisionAttemptedByZapId.get(zapid);
    }

    static void markCloseDecisionAttempted(
            Map<String, Long> closeDecisionAttemptedByZapId, String zapid, long decidedAtMs) {
        if (zapid == null || zapid.isBlank()) {
            return;
        }
        closeDecisionAttemptedByZapId.putIfAbsent(zapid, decidedAtMs);
    }

    static boolean canAcceptSafeToClose(
            Map<String, Long> closeDecisionAttemptedByZapId, String zapid) {
        return getCloseDecisionAttemptedAtMs(closeDecisionAttemptedByZapId, zapid) != null;
    }

    static String normalizeHttpTargetUrl(String targetUrl) {
        return PtkUrlUtils.normalizeHttpTargetUrl(targetUrl);
    }

    static boolean rememberInitialTargetUrl(
            Map<String, String> targetUrlByZapId, String zapid, String targetUrl) {
        if (zapid == null || zapid.isBlank()) {
            return false;
        }
        String normalized = normalizeHttpTargetUrl(targetUrl);
        if (normalized == null) {
            return false;
        }
        String existing = targetUrlByZapId.putIfAbsent(zapid, normalized);
        return existing == null || existing.equals(normalized);
    }

    static boolean rememberBrowserCoverageTargetUrl(
            Map<String, String> browserCoverageTargetUrlByZapId, String zapid, String targetUrl) {
        if (browserCoverageTargetUrlByZapId == null || zapid == null || zapid.isBlank()) {
            return false;
        }
        String normalized = PtkUrlUtils.normalizeBrowserCoverageUrl(targetUrl);
        if (normalized == null) {
            return false;
        }
        String existing = browserCoverageTargetUrlByZapId.putIfAbsent(zapid, normalized);
        return existing == null || existing.equals(normalized);
    }

    static void rememberClosedZapId(Map<String, Long> closedZapIds, String zapid, long closedAtMs) {
        if (closedZapIds == null || zapid == null || zapid.isBlank()) {
            return;
        }
        pruneClosedZapIds(closedZapIds, closedAtMs);
        closedZapIds.put(zapid, closedAtMs);
        pruneClosedZapIds(closedZapIds, closedAtMs);
    }

    static boolean isRecentlyClosedZapId(Map<String, Long> closedZapIds, String zapid, long nowMs) {
        if (closedZapIds == null || zapid == null || zapid.isBlank()) {
            return false;
        }
        Long closedAtMs = closedZapIds.get(zapid);
        if (closedAtMs == null) {
            return false;
        }
        if (nowMs - closedAtMs > CLOSED_ZAPID_RETENTION_MS) {
            closedZapIds.remove(zapid, closedAtMs);
            return false;
        }
        return true;
    }

    static void pruneClosedZapIds(Map<String, Long> closedZapIds, long nowMs) {
        if (closedZapIds == null || closedZapIds.isEmpty()) {
            return;
        }
        closedZapIds
                .entrySet()
                .removeIf(entry -> nowMs - entry.getValue() > CLOSED_ZAPID_RETENTION_MS);
        while (closedZapIds.size() > CLOSED_ZAPID_MAX_ENTRIES) {
            String oldestKey = null;
            long oldestAt = Long.MAX_VALUE;
            for (Map.Entry<String, Long> entry : closedZapIds.entrySet()) {
                if (entry.getValue() < oldestAt) {
                    oldestKey = entry.getKey();
                    oldestAt = entry.getValue();
                }
            }
            if (oldestKey == null) {
                return;
            }
            closedZapIds.remove(oldestKey);
        }
    }

    static boolean isTerminalProgressValue(Integer progress, String status) {
        if ("completed".equalsIgnoreCase(status)
                || "error".equalsIgnoreCase(status)
                || "cancelled".equalsIgnoreCase(status)
                || "engine_incomplete".equalsIgnoreCase(status)
                || "timeout".equalsIgnoreCase(status)) {
            return true;
        }
        return (status == null || status.isBlank())
                && progress != null
                && progress.intValue() >= 100;
    }

    static boolean canAcceptCloseDecisionSafeToClose(
            String decision, Integer progress, String status) {
        return "safe_to_close".equals(decision) && isTerminalProgressValue(progress, status);
    }

    static boolean canAcceptCloseDecisionSafeToClose(
            Map<String, Object> closeDecision, Integer progress, String status) {
        String decision = getString(closeDecision, "decision");
        if (canAcceptCloseDecisionSafeToClose(decision, progress, status)) {
            return true;
        }
        if (!"safe_to_close".equals(decision)) {
            return false;
        }
        String scanState = getString(closeDecision, "scanState");
        if (!isTerminalProgressValue(null, scanState)) {
            return false;
        }
        if (Boolean.TRUE.equals(closeDecision.get("zapProgressTerminalPosted"))) {
            return true;
        }
        String reason = getString(closeDecision, "reason");
        if ("already_terminal".equals(reason)) {
            return true;
        }
        Object zapTerminalPost = closeDecision.get("zapTerminalPost");
        if (zapTerminalPost instanceof Map<?, ?> terminalPost) {
            if (Boolean.TRUE.equals(terminalPost.get("posted"))) {
                return true;
            }
        }
        return false;
    }

    static boolean isBrowserLocalNonParticipantCloseDecision(Map<String, Object> closeDecision) {
        String decision = getString(closeDecision, "decision");
        if (!"not_applicable".equals(decision)) {
            return false;
        }
        String reason = getString(closeDecision, "reason");
        String error = getString(closeDecision, "error");
        return isBrowserLocalNonParticipantReason(reason)
                || isBrowserLocalNonParticipantReason(error);
    }

    static boolean isBrowserLocalTabSafeToCloseDecision(Map<String, Object> closeDecision) {
        String decision = getString(closeDecision, "decision");
        if (!"browser_tab_safe_to_close".equals(decision)) {
            return false;
        }
        if (Boolean.TRUE.equals(closeDecision.get("stopRequested"))) {
            return false;
        }
        String reason = getString(closeDecision, "reason");
        return "no_active_browser_work".equals(reason) || "non_owner_active_work".equals(reason);
    }

    @SuppressWarnings("unchecked")
    static String canonicalProgressSummary(Map<String, Object> progressData) {
        if (progressData == null || progressData.isEmpty()) {
            return "";
        }
        StringBuilder summary = new StringBuilder();
        appendSummaryField(summary, "sid", getString(progressData, "sessionId"));
        appendSummaryField(summary, "aseq", getInteger(progressData, "activitySeq"));
        appendSummaryField(summary, "afp", getString(progressData, "activityFingerprint"));
        Object safeToClose = progressData.get("safeToClose");
        if (safeToClose instanceof Boolean) {
            appendSummaryField(summary, "safe", safeToClose);
        }
        String status = getString(progressData, "status");
        Integer progress = getInteger(progressData, "progress");
        if ((status != null && !status.isBlank()) || progress != null) {
            appendSummaryField(
                    summary,
                    "top",
                    (status != null ? status : "") + ":" + (progress != null ? progress : 0));
        }
        Object publisherValue = progressData.get("publisher");
        if (publisherValue instanceof Map<?, ?> rawPublisher) {
            Map<String, Object> publisher = (Map<String, Object>) rawPublisher;
            appendSummaryField(summary, "pf", getInteger(publisher, "pendingFindings"));
            appendSummaryField(summary, "ifb", getInteger(publisher, "inFlightBatches"));
            Object drained = publisher.get("drained");
            if (drained instanceof Boolean) {
                appendSummaryField(summary, "pdr", drained);
            }
            appendSummaryField(summary, "lab", getInteger(publisher, "lastAckedBatchSeq"));
        }
        Object enginesValue = progressData.get("engines");
        if (!(enginesValue instanceof Map<?, ?> engines) || engines.isEmpty()) {
            return summary.toString();
        }
        engines.forEach(
                (engineName, engineValue) -> {
                    if (!(engineName instanceof String) || !(engineValue instanceof Map<?, ?>)) {
                        return;
                    }
                    Map<String, Object> engine = (Map<String, Object>) engineValue;
                    if (!summary.isEmpty()) {
                        summary.append(',');
                    }
                    Integer engineProgress = getInteger(engine, "progress");
                    summary.append(engineName)
                            .append(':')
                            .append(getString(engine, "status"))
                            .append(':')
                            .append(engineProgress != null ? engineProgress : 0);
                    Object detailsValue = engine.get("details");
                    if (detailsValue instanceof Map<?, ?> rawDetails) {
                        Map<String, Object> details = (Map<String, Object>) rawDetails;
                        summary.append('[');
                        appendDetailField(summary, details, "planned", "p");
                        appendDetailField(summary, details, "executed", "e");
                        appendDetailField(summary, details, "remaining", "rem");
                        appendDetailField(summary, details, "requestQueue", "rq");
                        appendDetailField(summary, details, "taskQueue", "tq");
                        appendDetailField(summary, details, "activeTasks", "at");
                        appendDetailField(summary, details, "planning", "pl");
                        appendDetailField(summary, details, "pendingCaptures", "pcap");
                        appendDetailField(summary, details, "findingsCount", "f");
                        appendDetailField(summary, details, "seededRequests", "seed");
                        appendDetailField(summary, details, "agentReady", "iar");
                        appendDetailField(summary, details, "requestsCount", "ireq");
                        appendDetailField(summary, details, "runtimeEventsCount", "irt");
                        appendDetailField(summary, details, "findingReportsAccepted", "ifa");
                        appendDetailField(
                                summary, details, "findingReportsDroppedInactive", "ifdi");
                        appendDetailField(
                                summary, details, "findingReportsDroppedTabMismatch", "ifdt");
                        appendDetailField(summary, details, "runtimeSignalsAccepted", "irsa");
                        appendDetailField(summary, details, "modulesSentOk", "imok");
                        appendDetailField(summary, details, "modulesSentSkipped", "imsk");
                        appendDetailField(summary, details, "modulesSentError", "imerr");
                        appendDetailField(summary, details, "pendingFindings", "pf");
                        appendDetailField(summary, details, "inFlightBatches", "ifb");
                        summary.append(']');
                    }
                });
        return summary.toString();
    }

    static Long newestActivityAt(Long progressChangedAtMs, Long alertChangedAtMs) {
        if (progressChangedAtMs == null) {
            return alertChangedAtMs;
        }
        if (alertChangedAtMs == null) {
            return progressChangedAtMs;
        }
        return Math.max(progressChangedAtMs, alertChangedAtMs);
    }

    static boolean isActivityFresh(Long lastActivityAtMs, long nowMs) {
        return lastActivityAtMs != null
                && nowMs - lastActivityAtMs <= BROWSER_CLOSE_ACTIVITY_STALE_MS;
    }

    static long activityIdleMs(Long lastActivityAtMs, long nowMs) {
        if (lastActivityAtMs == null) {
            return -1L;
        }
        return Math.max(0L, nowMs - lastActivityAtMs);
    }

    private static boolean isBrowserLocalNonParticipantReason(String reason) {
        return "automation_disabled".equals(reason)
                || "manual_mode".equals(reason)
                || "ptk_automation_unavailable".equals(reason)
                || "ptk_agent_unavailable".equals(reason)
                || "ptk_automation_untrusted".equals(reason);
    }

    private static String getString(Map<String, Object> map, String key) {
        Object value = map != null ? map.get(key) : null;
        return value == null ? null : String.valueOf(value);
    }

    private static Integer getInteger(Map<String, Object> map, String key) {
        Object value = map != null ? map.get(key) : null;
        return value instanceof Number ? ((Number) value).intValue() : null;
    }

    private static void appendDetailField(
            StringBuilder summary, Map<String, Object> details, String key, String label) {
        Object value = details.get(key);
        if (!(value instanceof Number)) {
            return;
        }
        summary.append(';').append(label).append('=').append(((Number) value).intValue());
    }

    private static void appendSummaryField(StringBuilder summary, String label, Object value) {
        if (value == null) {
            return;
        }
        String text = String.valueOf(value);
        if (text.isBlank()) {
            return;
        }
        if (!summary.isEmpty()) {
            summary.append(',');
        }
        summary.append(label).append('=').append(text);
    }
}

public class ExtensionPtk extends ExtensionAdaptor implements ExampleAlertProvider {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionPtk.class);
    private static final String PREFIX = "ptk";
    private static final Gson GSON = new Gson();

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionClientIntegration.class, ExtensionSelenium.class);
    private static final List<Browser> PTK_CHROMIUM_BROWSERS =
            List.of(Browser.CHROME, Browser.EDGE);
    private static final List<String> PTK_CHROMIUM_BACKGROUND_ARGS =
            List.of(
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-domain-reliability",
                    "--disable-default-apps",
                    "--disable-features=AutofillServerCommunication,OptimizationHints,OptimizationHintsFetching,OptimizationTargetPrediction,msEdgeUpdateLaunchServicesPreferredVersion,msForceBrowserSignIn",
                    "--disable-sync",
                    "--no-default-browser-check",
                    "--no-first-run");
    private static final int ZAP_HISTORY_SEED_MAX_URLS = 500;
    private static final int ZAP_HISTORY_SEED_MAX_SITE_NODES = 10_000;
    private static final long ZAP_HISTORY_SEED_CACHE_TTL_MS = 2_000L;
    private static final long ZAP_HISTORY_SEED_FAILURE_LOG_INTERVAL_MS = 60_000L;

    private ClientCallBackImplementor callBackImplementor;
    private PtkOptionsPanel optionsPanel;
    private PtkParam ptkParam;
    private final List<PtkDiagnosticExtension> diagnosticExtensions = new ArrayList<>();
    private final Object configCacheLock = new Object();
    private volatile PtkResourcesLoader.LoadedPtkResources cachedResources;
    private volatile String cachedConfigKey;
    private volatile String cachedConfigJson;
    private final Map<String, ZapHistorySeedCacheEntry> zapHistorySeedCache =
            new ConcurrentHashMap<>();
    private final AtomicLong lastZapHistorySeedFailureLogAtMs = new AtomicLong(0L);

    private final Map<String, Integer> scanProgress = new ConcurrentHashMap<>();
    private final Map<String, String> scanStatus = new ConcurrentHashMap<>();
    private final Map<String, Long> callbackFirstSeenAtMs = new ConcurrentHashMap<>();
    private final Map<String, String> browserIdByZapId = new ConcurrentHashMap<>();
    private final Map<String, Integer> alertsRaisedByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> firstAlertSeenAtMs = new ConcurrentHashMap<>();
    private final Map<String, String> lastProgressSummaryByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> lastProgressChangedAtMsByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlertChangedAtMsByZapId = new ConcurrentHashMap<>();
    private final Set<String> staleCloseLogged = ConcurrentHashMap.newKeySet();
    /*
     * safeToClose is advisory state accepted only through the ZAP callback flow for
     * the current zapid/WebDriver-controlled browser. Page scripts can observe the
     * DOM nonce used by PTK automation messages, so the nonce is a correlation guard,
     * not a secret; PTK background/session state remains the source of truth for
     * whether work is terminal.
     */
    private final Map<String, Boolean> safeToCloseByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> lastCloseDecisionByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> closeDecisionAttemptedByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> sessionIdByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> targetUrlByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> browserCoverageTargetUrlByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> zapIdByWebDriverSessionId = new ConcurrentHashMap<>();
    private final Map<String, BrowserCoverageEvidence> browserCoverageByUrl =
            new ConcurrentHashMap<>();
    private final Set<String> firstProgressLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> firstAlertLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> terminalProgressLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> sessionEstablishedLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> manualModeConfigZapIds = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> closedZapIds = new ConcurrentHashMap<>();

    private static final class ZapHistorySeedCacheEntry {
        private final List<String> urls;
        private final long createdAtMs;

        private ZapHistorySeedCacheEntry(List<String> urls, long createdAtMs) {
            this.urls = List.copyOf(urls);
            this.createdAtMs = createdAtMs;
        }
    }

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
        ensurePtkSeleniumExtensionsConfigured(
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class));
        loadDiagnosticExtensions(extensionHook);
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
        unloadDiagnosticExtensions();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .unregisterClientCallBack(callBackImplementor);
        if (optionsPanel != null) {
            optionsPanel.unload();
        }
    }

    private void loadDiagnosticExtensions(ExtensionHook extensionHook) {
        ServiceLoader<PtkDiagnosticExtension> loader =
                ServiceLoader.load(PtkDiagnosticExtension.class, getClass().getClassLoader());
        for (PtkDiagnosticExtension diagnosticExtension : loader) {
            try {
                diagnosticExtension.hook(this, extensionHook);
                diagnosticExtensions.add(diagnosticExtension);
                LOGGER.warn(
                        "PTK diagnostic extension loaded: {}",
                        diagnosticExtension.getClass().getName());
            } catch (RuntimeException e) {
                LOGGER.warn(
                        "PTK diagnostic extension failed to load class={} reason={}",
                        diagnosticExtension.getClass().getName(),
                        e.getMessage());
            }
        }
    }

    private void unloadDiagnosticExtensions() {
        for (PtkDiagnosticExtension diagnosticExtension : diagnosticExtensions) {
            try {
                diagnosticExtension.unload(this);
            } catch (RuntimeException e) {
                LOGGER.warn(
                        "PTK diagnostic extension failed to unload class={} reason={}",
                        diagnosticExtension.getClass().getName(),
                        e.getMessage());
            }
        }
        diagnosticExtensions.clear();
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return PtkExampleAlerts.getExampleAlerts(getLoadedResources());
    }

    private static void ensurePtkSeleniumExtensionsConfigured(ExtensionSelenium extensionSelenium) {
        if (extensionSelenium == null) {
            return;
        }
        Path chromiumPath = Path.of(Constant.getZapHome(), "selenium", "extensions", "ptk-latest");
        Path xpiPath = Path.of(Constant.getZapHome(), "selenium", "extensions", "ptk-latest.xpi");

        try {
            SeleniumOptions options = getSeleniumOptions(extensionSelenium);
            if (options == null) {
                LOGGER.warn("PTK Selenium extension config skipped; Selenium options unavailable");
                return;
            }
            ensurePtkSeleniumBrowserArguments(options);
            List<BrowserExtension> extensions = new ArrayList<>(options.getBrowserExtensions());
            boolean changed = false;
            for (Browser browser : PTK_CHROMIUM_BROWSERS) {
                changed |=
                        ensureBrowserExtension(extensions, chromiumPath, browser, browser.getId());
            }
            changed |= ensureBrowserExtension(extensions, xpiPath, Browser.FIREFOX, "Firefox");
            if (changed) {
                options.setBrowserExtensions(extensions);
            }
            logConfiguredPtkExtensions(extensions);
        } catch (Exception e) {
            LOGGER.warn("PTK Selenium extension config failed: {}", e.getMessage());
        }
    }

    private static boolean ensurePtkSeleniumBrowserArguments(SeleniumOptions options) {
        boolean changed = false;
        for (Browser browser : PTK_CHROMIUM_BROWSERS) {
            try {
                changed |= ensurePtkSeleniumBrowserArguments(options, browser);
            } catch (ReflectiveOperationException | RuntimeException e) {
                LOGGER.warn(
                        "PTK Selenium browser argument config failed browser={} reason={}",
                        browser,
                        e.getMessage());
            }
        }
        return changed;
    }

    private static boolean ensurePtkSeleniumBrowserArguments(
            SeleniumOptions options, Browser browser) throws ReflectiveOperationException {
        String browserId = browser.getId();
        List<Object> arguments = getSeleniumBrowserArguments(options, browserId);
        Set<String> existing = ConcurrentHashMap.newKeySet();
        for (Object argument : arguments) {
            String value = getBrowserArgumentValue(argument);
            if (value != null && !value.isBlank()) {
                existing.add(value);
            }
        }
        boolean changed = false;
        for (String argument : PTK_CHROMIUM_BACKGROUND_ARGS) {
            if (existing.add(argument)) {
                arguments.add(newBrowserArgument(argument));
                changed = true;
            }
        }
        if (changed) {
            setSeleniumBrowserArguments(options, browserId, arguments);
            LOGGER.debug(
                    "PTK Selenium browser arguments configured browser={} added={}",
                    browser,
                    PTK_CHROMIUM_BACKGROUND_ARGS.size());
        }
        return changed;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> getSeleniumBrowserArguments(
            SeleniumOptions options, String browserId) throws ReflectiveOperationException {
        Method method =
                SeleniumOptions.class.getDeclaredMethod("getBrowserArguments", String.class);
        method.setAccessible(true);
        Object value = method.invoke(options, browserId);
        if (value instanceof List<?> arguments) {
            return new ArrayList<>((List<Object>) arguments);
        }
        return new ArrayList<>();
    }

    private static void setSeleniumBrowserArguments(
            SeleniumOptions options, String browserId, List<Object> arguments)
            throws ReflectiveOperationException {
        Method method =
                SeleniumOptions.class.getDeclaredMethod(
                        "setBrowserArguments", String.class, List.class);
        method.setAccessible(true);
        method.invoke(options, browserId, arguments);
    }

    private static Object newBrowserArgument(String argument) throws ReflectiveOperationException {
        Class<?> argumentClass =
                Class.forName("org.zaproxy.zap.extension.selenium.internal.BrowserArgument");
        return argumentClass
                .getConstructor(String.class, boolean.class)
                .newInstance(argument, true);
    }

    private static String getBrowserArgumentValue(Object argument)
            throws ReflectiveOperationException {
        if (argument == null) {
            return null;
        }
        Method method = argument.getClass().getMethod("getArgument");
        Object value = method.invoke(argument);
        return value == null ? null : String.valueOf(value);
    }

    private static boolean ensureBrowserExtension(
            List<BrowserExtension> extensions, Path path, Browser browser, String label) {
        boolean exists =
                browser == Browser.FIREFOX ? Files.isRegularFile(path) : Files.isDirectory(path);
        if (!exists) {
            LOGGER.warn("PTK {} extension config skipped; path not found path={}", label, path);
            return false;
        }
        Path normalizedPath = path.toAbsolutePath().normalize();
        boolean alreadyConfigured =
                extensions.stream()
                        .filter(extension -> extension != null && extension.getBrowser() == browser)
                        .map(BrowserExtension::getPath)
                        .filter(extensionPath -> extensionPath != null)
                        .map(extensionPath -> extensionPath.toAbsolutePath().normalize())
                        .anyMatch(normalizedPath::equals);
        if (alreadyConfigured) {
            LOGGER.debug(
                    "PTK {} extension available to Selenium browser={} path={}",
                    label,
                    browser,
                    normalizedPath);
            return false;
        }

        extensions.add(new BrowserExtension(path, true, browser));
        LOGGER.debug(
                "PTK {} extension registered with Selenium browser={} path={}",
                label,
                browser,
                normalizedPath);
        return true;
    }

    private static void logConfiguredPtkExtensions(List<BrowserExtension> extensions) {
        for (BrowserExtension extension : extensions) {
            if (extension == null || extension.getPath() == null) {
                continue;
            }
            Path path = extension.getPath().toAbsolutePath().normalize();
            String name = path.getFileName() != null ? path.getFileName().toString() : "";
            if (!"ptk-latest".equals(name) && !"ptk-latest.xpi".equals(name)) {
                continue;
            }
            LOGGER.debug(
                    "PTK Selenium extension configured browser={} enabled={} path={}",
                    extension.getBrowser(),
                    extension.isEnabled(),
                    path);
        }
    }

    private static SeleniumOptions getSeleniumOptions(ExtensionSelenium extensionSelenium) {
        try {
            Method getOptionsMethod = ExtensionSelenium.class.getDeclaredMethod("getOptions");
            getOptionsMethod.setAccessible(true);
            Object value = getOptionsMethod.invoke(extensionSelenium);
            return value instanceof SeleniumOptions ? (SeleniumOptions) value : null;
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.warn("PTK failed to access Selenium options: {}", e.getMessage());
            return null;
        }
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

    private String getConfigJsonForRequest(Map<String, Object> requestData) {
        String baseJson = getCachedConfigJson();
        Map<String, Object> seedConfig = buildZapHistorySeedConfig(requestData);
        if (seedConfig.isEmpty()) {
            return baseJson;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> response = GSON.fromJson(baseJson, Map.class);
        if (response == null) {
            response = new LinkedHashMap<>();
        }
        response.putAll(seedConfig);
        return GSON.toJson(response);
    }

    private Map<String, Object> buildZapHistorySeedConfig(Map<String, Object> requestData) {
        if (requestData == null || requestData.isEmpty()) {
            return Map.of();
        }
        String targetUrl = getStringField(requestData, "targetUrl");
        String zapid = getStringField(requestData, "zapid");
        if ((targetUrl == null || targetUrl.isBlank()) && zapid != null && !zapid.isBlank()) {
            targetUrl = targetUrlByZapId.get(zapid);
        }
        List<String> urls = getCachedZapHistorySeedUrls(targetUrl, ZAP_HISTORY_SEED_MAX_URLS);
        if (urls.isEmpty()) {
            return Map.of();
        }
        String scope = PtkUrlUtils.deriveSameDirectoryPathScope(targetUrl);
        if (scope == null || scope.isBlank()) {
            scope = "zap-context";
        }
        LOGGER.debug(
                "PTK /ptk/config returning {} ZAP history seed URLs scope={}", urls.size(), scope);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("zapHistorySeedUrls", urls);
        result.put("zapHistorySeedCount", urls.size());
        result.put("zapHistorySeedMaxUrls", ZAP_HISTORY_SEED_MAX_URLS);
        result.put("zapHistorySeedScope", scope);
        return result;
    }

    private static String getStringField(Map<String, Object> body, String key) {
        if (body == null || key == null) {
            return null;
        }
        Object value = body.get(key);
        return value instanceof String ? (String) value : null;
    }

    private List<String> getCachedZapHistorySeedUrls(String targetUrl, int maxUrls) {
        if (maxUrls <= 0) {
            return List.of();
        }
        String normalizedTarget = PtkUrlUtils.normalizeHttpUrlWithoutFragment(targetUrl);
        String cacheKey =
                (normalizedTarget != null ? normalizedTarget : "zap-context") + "#" + maxUrls;
        long now = System.currentTimeMillis();
        ZapHistorySeedCacheEntry cached = zapHistorySeedCache.get(cacheKey);
        if (cached != null && now - cached.createdAtMs <= ZAP_HISTORY_SEED_CACHE_TTL_MS) {
            return cached.urls;
        }
        List<String> urls = collectZapHistorySeedUrls(targetUrl, maxUrls);
        zapHistorySeedCache.put(cacheKey, new ZapHistorySeedCacheEntry(urls, now));
        zapHistorySeedCache
                .entrySet()
                .removeIf(
                        entry ->
                                now - entry.getValue().createdAtMs
                                        > ZAP_HISTORY_SEED_CACHE_TTL_MS * 4);
        return urls;
    }

    private List<String> collectZapHistorySeedUrls(String targetUrl, int maxUrls) {
        String normalizedTarget = PtkUrlUtils.normalizeHttpUrlWithoutFragment(targetUrl);
        if (maxUrls <= 0) {
            return List.of();
        }
        Set<String> urls = new LinkedHashSet<>();
        if (normalizedTarget != null) {
            addZapHistorySeedUrl(urls, normalizedTarget, normalizedTarget, maxUrls);
        }
        try {
            SiteNode root = Model.getSingleton().getSession().getSiteTree().getRoot();
            if (root == null) {
                return new ArrayList<>(urls);
            }
            List<Context> contexts = Model.getSingleton().getSession().getContexts();
            Enumeration<?> nodes = root.preorderEnumeration();
            int visitedNodes = 0;
            while (nodes.hasMoreElements()
                    && urls.size() < maxUrls
                    && visitedNodes < ZAP_HISTORY_SEED_MAX_SITE_NODES) {
                visitedNodes++;
                Object candidate = nodes.nextElement();
                if (!(candidate instanceof SiteNode siteNode)) {
                    continue;
                }
                HistoryReference historyReference = siteNode.getHistoryReference();
                String url = getHistoryReferenceUrl(historyReference);
                if (url == null) {
                    continue;
                }
                if (normalizedTarget != null) {
                    addZapHistorySeedUrl(urls, normalizedTarget, url, maxUrls);
                } else {
                    addZapContextHistorySeedUrl(urls, contexts, url, maxUrls);
                }
            }
            if (nodes.hasMoreElements() && visitedNodes >= ZAP_HISTORY_SEED_MAX_SITE_NODES) {
                LOGGER.debug(
                        "PTK ZAP history seed collection reached node cap target={} cap={}",
                        normalizedTarget != null ? normalizedTarget : "zap-context",
                        ZAP_HISTORY_SEED_MAX_SITE_NODES);
            }
        } catch (Exception e) {
            logZapHistorySeedCollectionFailure(
                    normalizedTarget != null ? normalizedTarget : "zap-context", e);
        }
        return new ArrayList<>(urls);
    }

    static List<String> collectZapHistorySeedUrlsFromCandidates(
            String targetUrl, int maxUrls, Iterable<String> candidateUrls, List<Context> contexts) {
        String normalizedTarget = PtkUrlUtils.normalizeHttpUrlWithoutFragment(targetUrl);
        if (maxUrls <= 0) {
            return List.of();
        }
        Set<String> urls = new LinkedHashSet<>();
        if (normalizedTarget != null) {
            addZapHistorySeedUrl(urls, normalizedTarget, normalizedTarget, maxUrls);
        }
        if (candidateUrls == null) {
            return new ArrayList<>(urls);
        }
        for (String candidateUrl : candidateUrls) {
            if (urls.size() >= maxUrls) {
                break;
            }
            if (normalizedTarget != null) {
                addZapHistorySeedUrl(urls, normalizedTarget, candidateUrl, maxUrls);
            } else {
                addZapContextHistorySeedUrl(urls, contexts, candidateUrl, maxUrls);
            }
        }
        return new ArrayList<>(urls);
    }

    private static String getHistoryReferenceUrl(HistoryReference historyReference) {
        if (historyReference == null) {
            return null;
        }
        try {
            org.apache.commons.httpclient.URI uri = historyReference.getURI();
            return uri != null ? uri.toString() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void logZapHistorySeedCollectionFailure(String scope, Exception error) {
        long now = System.currentTimeMillis();
        long last = lastZapHistorySeedFailureLogAtMs.get();
        if (now - last >= ZAP_HISTORY_SEED_FAILURE_LOG_INTERVAL_MS
                && lastZapHistorySeedFailureLogAtMs.compareAndSet(last, now)) {
            LOGGER.warn("PTK failed to collect ZAP history seed URLs for {}", scope, error);
        } else {
            LOGGER.debug("PTK failed to collect ZAP history seed URLs for {}", scope, error);
        }
    }

    private static void addZapHistorySeedUrl(
            Set<String> urls, String targetUrl, String candidateUrl, int maxUrls) {
        if (urls.size() >= maxUrls) {
            return;
        }
        if (!PtkUrlUtils.isSameOriginAndPathScoped(targetUrl, candidateUrl)) {
            return;
        }
        String normalized = PtkUrlUtils.normalizeHttpUrlWithoutFragment(candidateUrl);
        if (normalized != null) {
            urls.add(normalized);
        }
    }

    private static void addZapContextHistorySeedUrl(
            Set<String> urls, List<Context> contexts, String candidateUrl, int maxUrls) {
        if (urls.size() >= maxUrls || contexts == null || contexts.isEmpty()) {
            return;
        }
        String normalized = PtkUrlUtils.normalizeHttpUrlWithoutFragment(candidateUrl);
        if (normalized == null) {
            return;
        }
        boolean inContext = false;
        for (Context context : contexts) {
            if (context != null && context.isInContext(normalized)) {
                inContext = true;
                break;
            }
        }
        if (inContext) {
            urls.add(normalized);
        }
    }

    BrowserCoverageSnapshot getBrowserCoverageSnapshot(String url) {
        String key = normalizeBrowserCoverageUrl(url);
        if (key == null) {
            return BrowserCoverageSnapshot.empty(url);
        }
        BrowserCoverageEvidence evidence = browserCoverageByUrl.get(key);
        return evidence != null ? evidence.snapshot(key) : BrowserCoverageSnapshot.empty(key);
    }

    String getBrowserCoverageSessionId(String zapid) {
        if (zapid == null || zapid.isBlank()) {
            return null;
        }
        return sessionIdByZapId.get(zapid);
    }

    long browserCloseMaxWallClockMs() {
        return PtkCloseContract.BROWSER_CLOSE_MAX_WALL_CLOCK_MS;
    }

    void recordBrowserCoverageScheduled(String url, int attempt) {
        String key = normalizeBrowserCoverageUrl(url);
        if (key == null) {
            return;
        }
        BrowserCoverageEvidence evidence =
                browserCoverageByUrl.computeIfAbsent(key, ignored -> new BrowserCoverageEvidence());
        evidence.scheduled(attempt);
        LOGGER.info("PTK_BROWSER_COVERAGE url={} event=scheduled attempt={}", key, attempt);
    }

    void logBrowserCoverageResult(
            String url,
            int attempts,
            String finalState,
            BrowserCoverageSnapshot snapshot,
            boolean terminal) {
        String key = normalizeBrowserCoverageUrl(url);
        if (key == null) {
            key = url;
        }
        BrowserCoverageSnapshot effective =
                snapshot != null ? snapshot : BrowserCoverageSnapshot.empty(key);
        LOGGER.info(
                "PTK_BROWSER_COVERAGE url={} event=result attempts={} finalState={} terminal={} browserLoaded={} ptkSessionEstablished={} ptkAnalysisReady={} browserSessionInvalid={} webdriverScriptFailed={} forcedClose={} noPtkProgress={}",
                key,
                attempts,
                finalState,
                terminal,
                effective.browserLoaded(),
                effective.ptkSessionEstablished(),
                effective.ptkAnalysisReady(),
                effective.browserSessionInvalid(),
                effective.webdriverScriptFailed(),
                effective.forcedClose(),
                effective.noPtkProgress());
    }

    void recordBrowserCoverageNavigationDelivered(
            String zapid, String targetUrl, String previousUrl) {
        String key = normalizeBrowserCoverageUrl(targetUrl);
        if (key == null) {
            return;
        }
        if (zapid != null && !zapid.isBlank()) {
            rememberBrowserCoverageTarget(zapid, targetUrl);
        }
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("source", "browserCoverageNavigation");
        if (previousUrl != null && !previousUrl.isBlank()) {
            extra.put("previousUrl", previousUrl);
        }
        recordBrowserEvidenceState("browser_loaded", targetUrl, extra);
        StringBuilder summary = new StringBuilder();
        summary.append("PTK_BROWSER_EVIDENCE");
        if (zapid != null && !zapid.isBlank()) {
            summary.append(" zapid=").append(zapid);
        }
        summary.append(" event=browser_loaded url=").append(key);
        extra.forEach(
                (name, value) -> {
                    if (name != null && !name.isBlank() && value != null) {
                        summary.append(" ").append(name).append("=").append(value);
                    }
                });
        LOGGER.info(summary.toString());
    }

    void rememberBrowserCoverageTarget(String zapid, String targetUrl) {
        if (zapid == null || zapid.isBlank()) {
            return;
        }
        String key = normalizeBrowserCoverageUrl(targetUrl);
        if (key == null) {
            return;
        }
        PtkCloseContract.rememberBrowserCoverageTargetUrl(
                browserCoverageTargetUrlByZapId, zapid, targetUrl);
        recordBrowserCoveragePtkSessionIfKnown(zapid, key, null);
    }

    private String getBrowserCoverageTargetUrl(String zapid) {
        if (zapid == null || zapid.isBlank()) {
            return null;
        }
        return browserCoverageTargetUrlByZapId.get(zapid);
    }

    private String getEvidenceTargetUrl(String zapid, String observedTargetUrl) {
        String coverageTarget = getBrowserCoverageTargetUrl(zapid);
        if (coverageTarget != null && !coverageTarget.isBlank()) {
            return coverageTarget;
        }
        String closeTarget = zapid != null && !zapid.isBlank() ? targetUrlByZapId.get(zapid) : null;
        if (closeTarget != null && !closeTarget.isBlank()) {
            return closeTarget;
        }
        return observedTargetUrl;
    }

    void recordBrowserCoveragePtkSessionIfKnown(String zapid, String targetUrl) {
        recordBrowserCoveragePtkSessionIfKnown(zapid, targetUrl, null);
    }

    void recordBrowserCoveragePtkSessionIfKnown(
            String zapid, String targetUrl, String observedUrl) {
        if (zapid == null || zapid.isBlank()) {
            return;
        }
        String key = normalizeBrowserCoverageUrl(targetUrl);
        if (key == null) {
            return;
        }
        Integer progress = scanProgress.get(zapid);
        boolean observedUrlHasSession =
                observedUrl != null && getBrowserCoverageSnapshot(observedUrl).hasPtkSession();
        String sessionId = sessionIdByZapId.get(zapid);
        String status = scanStatus.get(zapid);
        boolean sessionEstablished =
                sessionId != null
                        && !sessionId.isBlank()
                        && status != null
                        && !status.isBlank()
                        && !"callback".equals(status);
        if (!sessionEstablished && !observedUrlHasSession) {
            return;
        }
        BrowserCoverageSnapshot snapshot = getBrowserCoverageSnapshot(targetUrl);
        if (snapshot.hasPtkSession()) {
            return;
        }
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("progress", progress != null ? progress : 0);
        extra.put("source", "browserCoverageTarget");
        if (sessionId != null && !sessionId.isBlank()) {
            extra.put("sessionId", sessionId);
        }
        if (observedUrl != null && !observedUrl.isBlank()) {
            extra.put("observedUrl", observedUrl);
        }
        if (status != null && !status.isBlank()) {
            extra.put("status", status);
        }
        recordBrowserEvidenceState("ptk_session_established", targetUrl, extra);
        StringBuilder summary = new StringBuilder();
        summary.append("PTK_BROWSER_EVIDENCE");
        summary.append(" zapid=").append(zapid);
        String browserId = browserIdByZapId.get(zapid);
        if (browserId != null && !browserId.isBlank()) {
            summary.append(" browserid=").append(browserId);
        }
        summary.append(" event=ptk_session_established url=").append(key);
        extra.forEach(
                (name, value) -> {
                    if (name != null && !name.isBlank() && value != null) {
                        summary.append(" ").append(name).append("=").append(value);
                    }
                });
        LOGGER.info(summary.toString());
    }

    void recordBrowserCoverageAnalysisReady(
            String zapid, String targetUrl, String observedUrl, String readinessState) {
        String key = normalizeBrowserCoverageUrl(targetUrl);
        if (key == null) {
            return;
        }
        BrowserCoverageSnapshot snapshot = getBrowserCoverageSnapshot(targetUrl);
        if (snapshot.hasPtkAnalysisReady()) {
            return;
        }
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("source", "browserCoverageTarget");
        if (observedUrl != null && !observedUrl.isBlank()) {
            extra.put("observedUrl", observedUrl);
        }
        if (readinessState != null && !readinessState.isBlank()) {
            extra.put("readiness", readinessState);
        }
        String sessionId = zapid != null ? sessionIdByZapId.get(zapid) : null;
        if (sessionId != null && !sessionId.isBlank()) {
            extra.put("sessionId", sessionId);
        }
        recordBrowserEvidenceState("ptk_analysis_ready", targetUrl, extra);
        StringBuilder summary = new StringBuilder();
        summary.append("PTK_BROWSER_EVIDENCE");
        if (zapid != null && !zapid.isBlank()) {
            summary.append(" zapid=").append(zapid);
        }
        String browserId = zapid != null ? browserIdByZapId.get(zapid) : null;
        if (browserId != null && !browserId.isBlank()) {
            summary.append(" browserid=").append(browserId);
        }
        summary.append(" event=ptk_analysis_ready url=").append(key);
        extra.forEach(
                (name, value) -> {
                    if (name != null && !name.isBlank() && value != null) {
                        summary.append(" ").append(name).append("=").append(value);
                    }
                });
        LOGGER.info(summary.toString());
    }

    void recordBrowserCoverageBrowserLoaded(
            String zapid, String targetUrl, String observedUrl, String source) {
        String key = normalizeBrowserCoverageUrl(targetUrl);
        if (key == null) {
            return;
        }
        if (zapid != null && !zapid.isBlank()) {
            rememberBrowserCoverageTarget(zapid, targetUrl);
        }
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("source", source != null && !source.isBlank() ? source : "browserCoverage");
        if (observedUrl != null && !observedUrl.isBlank()) {
            extra.put("observedUrl", observedUrl);
        }
        recordBrowserEvidenceState("browser_loaded", targetUrl, extra);
        StringBuilder summary = new StringBuilder();
        summary.append("PTK_BROWSER_EVIDENCE");
        if (zapid != null && !zapid.isBlank()) {
            summary.append(" zapid=").append(zapid);
        }
        summary.append(" event=browser_loaded url=").append(key);
        extra.forEach(
                (name, value) -> {
                    if (name != null && !name.isBlank() && value != null) {
                        summary.append(" ").append(name).append("=").append(value);
                    }
                });
        LOGGER.info(summary.toString());
    }

    void recordBrowserCoverageInvalid(String zapid, String targetUrl, String reason, String error) {
        String key = normalizeBrowserCoverageUrl(targetUrl);
        if (key == null) {
            return;
        }
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("reason", reason != null && !reason.isBlank() ? reason : "unknown");
        if (error != null && !error.isBlank()) {
            extra.put("error", error);
        }
        recordBrowserEvidenceState("browser_session_invalid", targetUrl, extra);
        StringBuilder summary = new StringBuilder();
        summary.append("PTK_BROWSER_EVIDENCE");
        if (zapid != null && !zapid.isBlank()) {
            summary.append(" zapid=").append(zapid);
        }
        summary.append(" event=browser_session_invalid url=").append(key);
        extra.forEach(
                (name, value) -> {
                    if (name != null && !name.isBlank() && value != null) {
                        summary.append(" ").append(name).append("=").append(value);
                    }
                });
        LOGGER.info(summary.toString());
    }

    void rememberWebDriverZapId(WebDriver driver, String zapid) {
        String sessionId = webDriverSessionId(driver);
        if (sessionId == null || zapid == null || zapid.isBlank()) {
            return;
        }
        zapIdByWebDriverSessionId.put(sessionId, zapid);
    }

    String getZapIdForWebDriver(WebDriver driver) {
        String sessionId = webDriverSessionId(driver);
        return sessionId != null ? zapIdByWebDriverSessionId.get(sessionId) : null;
    }

    private static String webDriverSessionId(WebDriver driver) {
        if (driver instanceof RemoteWebDriver remoteWebDriver
                && remoteWebDriver.getSessionId() != null) {
            return remoteWebDriver.getSessionId().toString();
        }
        return null;
    }

    private void recordBrowserEvidenceState(String event, String url, Map<String, Object> extra) {
        String key = normalizeBrowserCoverageUrl(url);
        if (key == null) {
            return;
        }
        BrowserCoverageEvidence evidence =
                browserCoverageByUrl.computeIfAbsent(key, ignored -> new BrowserCoverageEvidence());
        evidence.record(event, extra);
    }

    private static String normalizeBrowserCoverageUrl(String url) {
        return PtkUrlUtils.normalizeBrowserCoverageUrl(url);
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

        private boolean isCloseDecisionActionable(Map<String, Object> closeDecision) {
            if (closeDecision == null || closeDecision.isEmpty()) {
                return false;
            }
            String decision = getStringField(closeDecision, "decision");
            if ("safe_to_close".equals(decision)
                    || "wait".equals(decision)
                    || "browser_tab_safe_to_close".equals(decision)) {
                return true;
            }
            if ("failed".equals(decision) || "not_applicable".equals(decision)) {
                return false;
            }
            Object ok = closeDecision.get("ok");
            String scanState = getStringField(closeDecision, "scanState");
            return Boolean.TRUE.equals(ok) && scanState != null && !"unknown".equals(scanState);
        }

        private boolean isAutomationDisabledCloseDecision(Map<String, Object> closeDecision) {
            if (closeDecision == null || closeDecision.isEmpty()) {
                return false;
            }
            return "automation_disabled".equals(getStringField(closeDecision, "reason"))
                    || "automation_disabled".equals(getStringField(closeDecision, "error"));
        }

        private Boolean getBooleanField(Map<String, Object> body, String key) {
            Object value = body.get(key);
            return value instanceof Boolean ? (Boolean) value : null;
        }

        private String extractZapIdFromUrl(String rawUrl) {
            if (rawUrl == null || rawUrl.isBlank()) {
                return null;
            }
            try {
                int queryStart = rawUrl.indexOf('?');
                if (queryStart < 0 || queryStart + 1 >= rawUrl.length()) {
                    return null;
                }
                int fragmentStart = rawUrl.indexOf('#', queryStart + 1);
                String query =
                        fragmentStart >= 0
                                ? rawUrl.substring(queryStart + 1, fragmentStart)
                                : rawUrl.substring(queryStart + 1);
                for (String part : query.split("&")) {
                    int equalsIndex = part.indexOf('=');
                    String key = equalsIndex >= 0 ? part.substring(0, equalsIndex) : part;
                    if (!"zapid".equals(key)) {
                        continue;
                    }
                    String value = equalsIndex >= 0 ? part.substring(equalsIndex + 1) : "";
                    String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
                    return decoded.isBlank() ? null : decoded;
                }
            } catch (IllegalArgumentException e) {
                LOGGER.debug("PTK failed to parse zapid from URL {}", rawUrl, e);
            }
            return null;
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

        private void rememberConfigMode(String zapid, boolean automatedScanningEnabled) {
            if (zapid == null || zapid.isBlank()) {
                return;
            }
            if (automatedScanningEnabled) {
                manualModeConfigZapIds.remove(zapid);
            } else {
                manualModeConfigZapIds.add(zapid);
            }
        }

        private boolean isManualModeCallbackProgress(
                String zapid, Integer progress, String status, String sessionId) {
            if (zapid == null || zapid.isBlank() || !manualModeConfigZapIds.contains(zapid)) {
                return false;
            }
            if (sessionId != null && !sessionId.isBlank()) {
                return false;
            }
            if (progress != null && progress.intValue() > 0) {
                return false;
            }
            return status == null || status.isBlank() || "callback".equalsIgnoreCase(status);
        }

        private boolean isManualModeConfigOnlyClose(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return false;
            }
            return isManualModeCallbackProgress(
                    zapid,
                    scanProgress.get(zapid),
                    scanStatus.get(zapid),
                    sessionIdByZapId.get(zapid));
        }

        private Map<String, Object> buildManualModeCloseDecision() {
            Map<String, Object> closeDecision = new LinkedHashMap<>();
            closeDecision.put("participant", "ptk");
            closeDecision.put("decision", "not_applicable");
            closeDecision.put("scanState", "manual");
            closeDecision.put("reason", "manual_mode");
            closeDecision.put("stopRequested", false);
            return closeDecision;
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
            int previous = alertsRaisedByZapId.getOrDefault(zapid, 0);
            int total = alertsRaisedByZapId.merge(zapid, Math.max(0, raised), Integer::sum);
            if (total != previous) {
                lastAlertChangedAtMsByZapId.put(zapid, System.currentTimeMillis());
            }
            return total;
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

        private Long getLastMeaningfulActivityAtMs(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return null;
            }
            return PtkCloseContract.newestActivityAt(
                    lastProgressChangedAtMsByZapId.get(zapid),
                    lastAlertChangedAtMsByZapId.get(zapid));
        }

        private boolean hasRecentMeaningfulActivity(String zapid, long nowMs) {
            return PtkCloseContract.isActivityFresh(getLastMeaningfulActivityAtMs(zapid), nowMs);
        }

        private void putActivitySummaryFields(Map<String, Object> extra, String zapid, long nowMs) {
            if (extra == null) {
                return;
            }
            Long activityAt = getLastMeaningfulActivityAtMs(zapid);
            long idleMs = PtkCloseContract.activityIdleMs(activityAt, nowMs);
            if (idleMs >= 0L) {
                extra.put("activityIdleMs", idleMs);
                extra.put("activityFresh", PtkCloseContract.isActivityFresh(activityAt, nowMs));
            }
            Long progressChangedAt =
                    zapid != null ? lastProgressChangedAtMsByZapId.get(zapid) : null;
            if (progressChangedAt != null) {
                extra.put("progressIdleMs", Math.max(0L, nowMs - progressChangedAt));
            }
            Long alertChangedAt = zapid != null ? lastAlertChangedAtMsByZapId.get(zapid) : null;
            if (alertChangedAt != null) {
                extra.put("alertIdleMs", Math.max(0L, nowMs - alertChangedAt));
            }
        }

        private Map<String, Object> buildSessionSummaryExtra(
                String zapid, boolean forced, long waitedMs, Integer progress, String status) {
            Map<String, Object> extra = new LinkedHashMap<>();
            extra.put("waitedMs", waitedMs);
            extra.put("forced", forced);
            extra.put("decision", forced ? "forced_closed" : "safe_to_close");
            extra.put("progress", progress != null ? progress : 0);
            if (status != null && !status.isBlank()) {
                extra.put("status", status);
            }
            extra.put("alertsTotal", getAlertsRaisedTotal(zapid));
            extra.put("terminalSeen", zapid != null && terminalProgressLogged.contains(zapid));
            if (zapid != null && safeToCloseByZapId.containsKey(zapid)) {
                extra.put("safeToClose", safeToCloseByZapId.get(zapid));
            }
            String lastCloseDecision = zapid != null ? lastCloseDecisionByZapId.get(zapid) : null;
            if (lastCloseDecision != null && !lastCloseDecision.isBlank()) {
                extra.put("lastCloseDecision", lastCloseDecision);
            }
            Long firstAlertMs = getFirstAlertElapsed(zapid);
            if (firstAlertMs != null) {
                extra.put("firstAlertMs", firstAlertMs);
            }
            putActivitySummaryFields(extra, zapid, System.currentTimeMillis());
            return extra;
        }

        private void clearTrackingState(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return;
            }
            PtkCloseContract.rememberClosedZapId(closedZapIds, zapid, System.currentTimeMillis());
            scanProgress.remove(zapid);
            scanStatus.remove(zapid);
            callbackFirstSeenAtMs.remove(zapid);
            browserIdByZapId.remove(zapid);
            alertsRaisedByZapId.remove(zapid);
            firstAlertSeenAtMs.remove(zapid);
            lastProgressSummaryByZapId.remove(zapid);
            lastProgressChangedAtMsByZapId.remove(zapid);
            lastAlertChangedAtMsByZapId.remove(zapid);
            staleCloseLogged.remove(zapid);
            safeToCloseByZapId.remove(zapid);
            lastCloseDecisionByZapId.remove(zapid);
            closeDecisionAttemptedByZapId.remove(zapid);
            sessionIdByZapId.remove(zapid);
            targetUrlByZapId.remove(zapid);
            browserCoverageTargetUrlByZapId.remove(zapid);
            zapIdByWebDriverSessionId.entrySet().removeIf(entry -> zapid.equals(entry.getValue()));
            firstProgressLogged.remove(zapid);
            firstAlertLogged.remove(zapid);
            terminalProgressLogged.remove(zapid);
            manualModeConfigZapIds.remove(zapid);
        }

        private boolean isTerminalProgressValue(Integer progress, String status) {
            return PtkCloseContract.isTerminalProgressValue(progress, status);
        }

        private boolean isSafeToClose(String zapid) {
            if (zapid != null && Boolean.TRUE.equals(safeToCloseByZapId.get(zapid))) {
                return true;
            }
            return isTerminalProgress(zapid);
        }

        private boolean hasSessionId(String zapid) {
            return zapid != null
                    && !zapid.isBlank()
                    && sessionIdByZapId.get(zapid) != null
                    && !sessionIdByZapId.get(zapid).isBlank();
        }

        private boolean isWaitingForSessionStart(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return false;
            }
            if (hasSessionId(zapid)) {
                return false;
            }
            String status = scanStatus.get(zapid);
            return !scanProgress.containsKey(zapid)
                    || status == null
                    || status.isBlank()
                    || "callback".equalsIgnoreCase(status);
        }

        private void waitForSessionStartBeforeClose(String zapid, long closeDeadlineMs) {
            if (zapid == null || zapid.isBlank()) {
                return;
            }
            long deadline =
                    Math.min(
                            closeDeadlineMs,
                            System.currentTimeMillis()
                                    + PtkCloseContract.BROWSER_CLOSE_NO_PROGRESS_GRACE_MS);
            while (isWaitingForSessionStart(zapid) && System.currentTimeMillis() < deadline) {
                try {
                    Thread.sleep(Math.min(250, PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }

        Long getCloseDecisionAttemptedAtMs(String zapid) {
            return PtkCloseContract.getCloseDecisionAttemptedAtMs(
                    closeDecisionAttemptedByZapId, zapid);
        }

        void markCloseDecisionAttempted(String zapid, long decidedAtMs) {
            PtkCloseContract.markCloseDecisionAttempted(
                    closeDecisionAttemptedByZapId, zapid, decidedAtMs);
        }

        private long remainingCloseBudgetMs(long closeDeadlineMs) {
            return Math.max(0L, closeDeadlineMs - System.currentTimeMillis());
        }

        private boolean hasCloseBudget(long closeDeadlineMs, long minRequiredMs) {
            return remainingCloseBudgetMs(closeDeadlineMs) >= Math.max(0L, minRequiredMs);
        }

        private Map<String, Object> requestPtkCloseDecision(
                ClientCallBackUtils ccbutils, String zapid, long closeDeadlineMs) {
            Map<String, Object> fallback = new LinkedHashMap<>();
            fallback.put("participant", "ptk");
            fallback.put("decision", "not_applicable");
            fallback.put("scanState", "unknown");
            fallback.put("reason", "webdriver_unavailable");

            long remainingMs = remainingCloseBudgetMs(closeDeadlineMs);
            if (remainingMs < 2_500L) {
                fallback.put("reason", "close_budget_exhausted");
                fallback.put("remainingMs", remainingMs);
                return fallback;
            }
            long scriptTimeoutMs =
                    Math.min(PtkCloseContract.BROWSER_CLOSE_SCRIPT_TIMEOUT_MS, remainingMs);
            long ptkBridgeTimeoutMs =
                    Math.min(PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS, scriptTimeoutMs);

            if (ccbutils == null) {
                return fallback;
            }

            WebDriver driver;
            try {
                driver = ccbutils.getWebDriver();
            } catch (RuntimeException e) {
                fallback.put("reason", "webdriver_lookup_failed");
                fallback.put("error", e.getMessage());
                return fallback;
            }

            if (!(driver instanceof JavascriptExecutor js)) {
                fallback.put("reason", "javascript_executor_unavailable");
                return fallback;
            }

            try {
                driver.manage()
                        .timeouts()
                        .scriptTimeout(Duration.ofMillis(Math.max(2_500L, scriptTimeoutMs)));
            } catch (RuntimeException e) {
                LOGGER.debug("PTK closeContract could not set script timeout: {}", e.getMessage());
            }

            /*
             * The source value lets PTK distinguish ZAP's browser-close path from
             * user-driven automation calls. It is trusted only in combination with
             * the ZAP callback URL/zapid and the WebDriver-controlled tab; PTK
             * background/session lookup still decides whether the session is
             * terminal and safe to close.
             */
            String script =
                    """
                    const done = arguments[arguments.length - 1];
                    const bridgeTimeoutMs = arguments[0] || 10000;
                    const explicitSessionId = arguments[1] || null;
                    const explicitZapId = arguments[2] || null;
                    const callTimeoutMs = Math.max(2000, bridgeTimeoutMs);
                    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
                    const timeoutAfter = (label, ms) => new Promise((resolve) => setTimeout(() => {
                      resolve({ ok: false, code: label + '_timeout', status: 'unknown' });
                    }, Math.max(500, ms || 3000)));
                    const terminal = new Set(['none', 'completed', 'error', 'timeout', 'cancelled', 'engine_incomplete']);
                    const statusOf = (value) => {
                      const status = String(value && (value.status || value.completionStatus || value.summary && value.summary.status) || '').toLowerCase();
                      return status;
                    };
                    const currentCloseUrl = String(location && location.href || '');
                    const shouldStopForClose = (snapshot) => {
                      const context = snapshot && snapshot.zapCloseContext && typeof snapshot.zapCloseContext === 'object'
                        ? snapshot.zapCloseContext
                        : {};
                      return context.shouldStopSession === true;
                    };
                    const numberOf = (value) => {
                      const parsed = Number(value);
                      return Number.isFinite(parsed) ? parsed : 0;
                    };
                    const concreteEngineWork = (engine) => {
                      if (!engine || typeof engine !== 'object') return false;
                      const telemetry = engine.telemetry && typeof engine.telemetry === 'object'
                        ? engine.telemetry
                        : engine;
                      const progress = telemetry.progress && typeof telemetry.progress === 'object'
                        ? telemetry.progress
                        : (engine.progress && typeof engine.progress === 'object' ? engine.progress : {});
                      const state = String(engine.state || telemetry.status || '').toLowerCase();
                      return [
                        telemetry.activeTasks,
                        telemetry.taskQueue,
                        telemetry.requestQueue,
                        telemetry.pendingPlans,
                        telemetry.planning,
                        telemetry.pendingCaptures,
                        telemetry.pendingAutomationSeeds,
                        telemetry.pendingHtmlDiscovery,
                        telemetry.remaining,
                        progress.remaining
                      ].some((value) => numberOf(value) > 0)
                        || telemetry.isRunning === true
                        || telemetry.isScanRunning === true
                        || state === 'running'
                        || state === 'scanning';
                    };
                    const hasConcreteBrowserWork = (snapshot) => {
                      if (!snapshot || snapshot.ok !== true || !snapshot.engines || typeof snapshot.engines !== 'object') return true;
                      return Object.values(snapshot.engines).some(concreteEngineWork);
                    };
                    const withTimeout = (promise, label, ms) => Promise.race([
                      Promise.resolve(promise),
                      timeoutAfter(label, ms)
                    ]);
                    const refreshAutomationStatus = async () => {
                      try {
                        const nonce = document.getElementById('__ptk_automation_nonce__')?.dataset?.nonce || '';
                        if (!nonce) return false;
                        window.postMessage({
                          source: 'ptk-extension',
                          type: 'automation-status',
                          enabled: true,
                          nonce
                        }, '*');
                        await sleep(25);
                        return true;
                      } catch (_) {
                        return false;
                      }
                    };
                    const sendZapCloseMessage = (type, payload = {}, timeoutMs = 3000) => new Promise((resolve) => {
                      try {
                        const nonce = document.getElementById('__ptk_automation_nonce__')?.dataset?.nonce || '';
                        if (!nonce) {
                          resolve({ ok: false, error: 'zap_close_bridge_unavailable' });
                          return;
                        }
                        const requestId = 'ptk-zap-close-' + Date.now() + '-' + Math.random().toString(36).slice(2);
                        let settled = false;
                        let disabledFallback = null;
                        const finish = (value) => {
                          if (settled) return;
                          settled = true;
                          try { window.removeEventListener('message', onMessage); } catch (_) {}
                          resolve(value || null);
                        };
                        const onMessage = (event) => {
                          if (event.source !== window) return;
                          const data = event.data || {};
                          if (data.source !== 'ptk-extension') return;
                          if (data.requestId !== requestId) return;
                          if (data.nonce !== nonce) return;
                          if (data.error === 'automation_disabled') {
                            disabledFallback = data;
                            return;
                          }
                          finish(data);
                        };
                        window.addEventListener('message', onMessage);
                        window.postMessage({
                          source: 'ptk-automation',
                          nonce,
                          requestId,
                          type,
                          sessionId: explicitSessionId,
                          options: Object.assign({}, payload.options || {}, {
                            sessionId: explicitSessionId,
                            source: 'zap_browser_close',
                            zapid: explicitZapId,
                            currentUrl: currentCloseUrl
                          }),
                          wait: payload.wait,
                          includeFindings: payload.includeFindings === true,
                          limit: payload.limit
                        }, '*');
                        setTimeout(() => finish(disabledFallback || { ok: false, error: type + '_direct_timeout' }), Math.max(500, timeoutMs || 3000));
                      } catch (error) {
                        resolve({ ok: false, error: error && error.message || String(error) });
                      }
                    });
                    const readProgressDirect = () => sendZapCloseMessage(
                      'get-session-progress',
                      { options: { sessionId: explicitSessionId, source: 'zap_browser_close', currentUrl: currentCloseUrl } },
                      3000
                    );
                    (async () => {
                      try {
                        await refreshAutomationStatus();
                        const automation = window.PTK_AUTOMATION;
                        const trustedAutomation = automation && automation.bridgeId === 'ptk-automation-bridge'
                          ? automation
                          : null;
                        if (trustedAutomation && typeof trustedAutomation.getSessionProgress === 'function') {
                          const readProgress = () => typeof trustedAutomation.getSessionProgress === 'function'
                            ? withTimeout(trustedAutomation.getSessionProgress({
                                sessionId: explicitSessionId,
                                source: 'zap_browser_close',
                                zapid: explicitZapId,
                                currentUrl: currentCloseUrl
                              }), 'scan_status', 3000)
                            : Promise.resolve(null);
                          const waitForTerminal = async (maxMs) => {
                            const deadline = Date.now() + Math.max(0, maxMs || 0);
                            let latest = null;
                            while (Date.now() < deadline) {
                              latest = await readProgress();
                              const latestStatus = statusOf(latest);
                              if (latest && latest.ok === true && terminal.has(latestStatus)) {
                                return latest;
                              }
                              await sleep(500);
                            }
                            return latest;
                          };
                          const before = typeof automation.getSessionProgress === 'function'
                            ? await readProgress()
                            : null;
                          if (before && before.error === 'automation_disabled') {
                            await refreshAutomationStatus();
                            const directBefore = await readProgressDirect();
                            if (directBefore && directBefore.ok !== false) {
                              Object.assign(before, directBefore);
                            }
                          }
                          const statusBefore = statusOf(before);
                          if (before && before.ok === true && terminal.has(statusBefore)) {
                            done({
                              ok: true,
                              participant: 'ptk',
                              decision: 'safe_to_close',
                              scanState: statusBefore,
                              statusBefore,
                              sessionId: explicitSessionId,
                              reason: 'already_terminal',
                              stopVia: 'automation_bridge'
                            });
                            return;
                          }
                          if (before && before.ok === true) {
                            const ownerClose = shouldStopForClose(before);
                            const concreteWork = hasConcreteBrowserWork(before);
                            if (!ownerClose) {
                              done({
                                ok: true,
                                participant: 'ptk',
                                decision: 'browser_tab_safe_to_close',
                                scanState: statusBefore || 'running',
                                statusBefore,
                                sessionId: explicitSessionId,
                                stopRequested: false,
                                reason: concreteWork ? 'non_owner_active_work' : 'no_active_browser_work',
                                stopVia: 'automation_bridge'
                              });
                              return;
                            }
                          done({
                            ok: true,
                            participant: 'ptk',
                            decision: 'wait',
                            scanState: statusBefore || 'running',
                            statusBefore,
                            sessionId: explicitSessionId,
                            stopRequested: false,
                            stopVia: 'automation_bridge',
                            reason: concreteWork ? 'active_browser_work' : 'owner_waiting_for_terminal'
                          });
                          return;
                        }
                        }
                        {
                          const before = await readProgressDirect();
                          const statusBefore = statusOf(before);
                          if (before && before.ok === true && terminal.has(statusBefore)) {
                            done({
                              ok: true,
                              participant: 'ptk',
                              decision: 'safe_to_close',
                              scanState: statusBefore,
                              statusBefore,
                              sessionId: explicitSessionId,
                              reason: 'already_terminal',
                              stopVia: 'direct_zap_close'
                            });
                            return;
                          }
                          if (before && before.ok === true) {
                            if (!hasConcreteBrowserWork(before)) {
                              done({
                                ok: true,
                                participant: 'ptk',
                                decision: 'browser_tab_safe_to_close',
                                scanState: statusBefore || 'running',
                                statusBefore,
                                sessionId: explicitSessionId,
                                stopRequested: false,
                                stopVia: 'direct_zap_close',
                                reason: 'no_active_browser_work'
                              });
                              return;
                            }
                            if (!shouldStopForClose(before)) {
                              done({
                                ok: true,
                                participant: 'ptk',
                                decision: 'browser_tab_safe_to_close',
                                scanState: statusBefore || 'running',
                                statusBefore,
                                sessionId: explicitSessionId,
                                stopRequested: false,
                                stopVia: 'direct_zap_close',
                                reason: 'non_owner_active_work'
                              });
                              return;
                            }
                          }
                          if (before && before.ok === true) {
                            done({
                              ok: true,
                              participant: 'ptk',
                              decision: 'wait',
                              scanState: statusBefore || 'running',
                              statusBefore,
                              sessionId: explicitSessionId,
                              stopRequested: false,
                              stopVia: 'direct_zap_close',
                              reason: hasConcreteBrowserWork(before) ? 'active_browser_work' : 'owner_waiting_for_terminal'
                            });
                            return;
                          }
                        }
                        const agent = window.PTK_AGENT;
                        if (!agent || typeof agent.scanStatus !== 'function') {
                          done({
                            participant: 'ptk',
                            decision: 'not_applicable',
                            scanState: 'unknown',
                            reason: automation && !trustedAutomation ? 'ptk_automation_untrusted' : automation ? 'ptk_agent_unavailable' : 'ptk_automation_unavailable'
                          });
                          return;
                        }
                        const before = await Promise.race([
                          Promise.resolve(agent.scanStatus({})),
                          timeoutAfter('scan_status', 3000)
                        ]);
                        const statusBefore = String(before && before.status || '').toLowerCase();
                        if (before && before.ok === true && terminal.has(statusBefore)) {
                          done({
                            ok: true,
                            participant: 'ptk',
                            decision: 'safe_to_close',
                            scanState: statusBefore,
                            statusBefore,
                            sessionId: before.sessionId || null,
                            reason: 'already_terminal'
                          });
                          return;
                        }
                        done({
                          ok: before && before.ok !== false,
                          participant: 'ptk',
                          decision: 'wait',
                          scanState: statusBefore || 'running',
                          statusBefore,
                          sessionId: before && before.sessionId || null,
                          stopRequested: false,
                          reason: 'agent_running_without_terminal'
                        });
                      } catch (error) {
                        done({
                          ok: false,
                          participant: 'ptk',
                          decision: 'failed',
                          scanState: 'unknown',
                          reason: error && error.message || String(error)
                        });
                      }
                    })();
                    """;

            String originalWindow = null;
            List<String> windowHandles = new ArrayList<>();
            String sessionId = sessionIdByZapId.get(zapid);
            try {
                originalWindow = driver.getWindowHandle();
                windowHandles.addAll(driver.getWindowHandles());
            } catch (RuntimeException e) {
                LOGGER.debug("PTK closeContract could not enumerate windows: {}", e.getMessage());
            }
            if (windowHandles.isEmpty()) {
                try {
                    Object rawResult =
                            js.executeAsyncScript(script, ptkBridgeTimeoutMs, sessionId, zapid);
                    return normalizeCloseScriptResult(rawResult, fallback, 0, null);
                } catch (WebDriverException e) {
                    fallback.put("reason", "webdriver_script_failed");
                    fallback.put("error", e.getMessage());
                    return fallback;
                }
            }

            Map<String, Object> bestUnavailable = null;
            for (int i = 0; i < windowHandles.size(); i++) {
                String handle = windowHandles.get(i);
                String currentUrl = null;
                try {
                    driver.switchTo().window(handle);
                    currentUrl = driver.getCurrentUrl();
                    Object rawResult =
                            js.executeAsyncScript(script, ptkBridgeTimeoutMs, sessionId, zapid);
                    Map<String, Object> result =
                            normalizeCloseScriptResult(rawResult, fallback, i, currentUrl);
                    String decision = getStringField(result, "decision");
                    String reason = getStringField(result, "reason");
                    if (!"not_applicable".equals(decision)
                            || (!"ptk_agent_unavailable".equals(reason)
                                    && !"ptk_automation_unavailable".equals(reason))) {
                        return result;
                    }
                    bestUnavailable = result;
                } catch (WebDriverException e) {
                    Map<String, Object> failed = new LinkedHashMap<>(fallback);
                    failed.put("reason", "webdriver_script_failed");
                    failed.put("error", e.getMessage());
                    failed.put("windowIndex", i);
                    if (currentUrl != null) {
                        failed.put("windowUrl", currentUrl);
                    }
                    bestUnavailable = failed;
                }
            }
            String targetUrl = targetUrlByZapId.get(zapid);
            if (targetUrl != null) {
                try {
                    driver.switchTo().window(windowHandles.get(0));
                    driver.navigate().to(targetUrl);
                    Object rawResult =
                            js.executeAsyncScript(script, ptkBridgeTimeoutMs, sessionId, zapid);
                    Map<String, Object> result =
                            normalizeCloseScriptResult(
                                    rawResult, fallback, windowHandles.size(), targetUrl);
                    result.put("navigatedForClose", true);
                    String decision = getStringField(result, "decision");
                    String reason = getStringField(result, "reason");
                    if (!"not_applicable".equals(decision)
                            || (!"ptk_agent_unavailable".equals(reason)
                                    && !"ptk_automation_unavailable".equals(reason))) {
                        return result;
                    }
                    bestUnavailable = result;
                } catch (WebDriverException e) {
                    Map<String, Object> failed = new LinkedHashMap<>(fallback);
                    failed.put("reason", "webdriver_navigation_for_close_failed");
                    failed.put("error", e.getMessage());
                    failed.put("windowUrl", targetUrl);
                    bestUnavailable = failed;
                }
            }
            if (originalWindow != null) {
                try {
                    driver.switchTo().window(originalWindow);
                } catch (RuntimeException e) {
                    LOGGER.debug("PTK closeContract could not restore window: {}", e.getMessage());
                }
            }
            return bestUnavailable != null ? bestUnavailable : fallback;
        }

        private Map<String, Object> normalizeCloseScriptResult(
                Object rawResult, Map<String, Object> fallback, int windowIndex, String windowUrl) {
            if (rawResult instanceof Map<?, ?> rawMap) {
                Map<String, Object> result = new LinkedHashMap<>();
                rawMap.forEach(
                        (key, value) -> {
                            if (key != null) {
                                result.put(String.valueOf(key), value);
                            }
                        });
                result.put("windowIndex", windowIndex);
                if (windowUrl != null && !windowUrl.isBlank()) {
                    result.put("windowUrl", windowUrl);
                }
                if ("automation_disabled".equals(getStringField(result, "error"))
                        || "automation_disabled".equals(getStringField(result, "reason"))) {
                    result.put("ok", false);
                    result.put("decision", "not_applicable");
                    result.putIfAbsent("scanState", "callback");
                    result.putIfAbsent("reason", "automation_disabled");
                }
                return result;
            }
            Map<String, Object> result = new LinkedHashMap<>(fallback);
            result.put("reason", "unexpected_script_result");
            result.put("resultType", rawResult != null ? rawResult.getClass().getName() : "null");
            result.put("windowIndex", windowIndex);
            if (windowUrl != null && !windowUrl.isBlank()) {
                result.put("windowUrl", windowUrl);
            }
            return result;
        }

        private void logCloseContractDecision(
                String zapid,
                String browserid,
                String decision,
                String scanState,
                long waitedMs,
                Integer progress,
                String status,
                Map<String, Object> diagnostics) {
            if (zapid != null && !zapid.isBlank() && decision != null && !decision.isBlank()) {
                lastCloseDecisionByZapId.put(zapid, decision);
            }
            StringBuilder summary = new StringBuilder();
            summary.append("PTK closeContract");
            if (zapid != null && !zapid.isBlank()) {
                summary.append(" zapid=").append(zapid);
            }
            if (browserid != null && !browserid.isBlank()) {
                summary.append(" browserid=").append(browserid);
            }
            summary.append(" decision=").append(decision != null ? decision : "unknown");
            summary.append(" scanState=")
                    .append(scanState != null && !scanState.isBlank() ? scanState : "unknown");
            summary.append(" waitedMs=").append(waitedMs);
            summary.append(" progress=").append(progress != null ? progress : 0);
            if (status != null && !status.isBlank()) {
                summary.append(" status=").append(status);
            }
            summary.append(" alertsTotal=").append(getAlertsRaisedTotal(zapid));
            if (diagnostics != null) {
                Object reason = diagnostics.get("reason");
                if (reason != null) {
                    summary.append(" reason=").append(reason);
                }
                Object stopRequested = diagnostics.get("stopRequested");
                if (stopRequested != null) {
                    summary.append(" stopRequested=").append(stopRequested);
                }
                Object windowIndex = diagnostics.get("windowIndex");
                if (windowIndex != null) {
                    summary.append(" windowIndex=").append(windowIndex);
                }
                Object windowUrl = diagnostics.get("windowUrl");
                if (windowUrl != null) {
                    summary.append(" windowUrl=").append(windowUrl);
                }
            }

            Map<String, Object> evidenceExtra = new LinkedHashMap<>();
            evidenceExtra.put("decision", decision != null ? decision : "unknown");
            evidenceExtra.put(
                    "scanState", scanState != null && !scanState.isBlank() ? scanState : "unknown");
            evidenceExtra.put("progress", progress != null ? progress : 0);
            if (status != null && !status.isBlank()) {
                evidenceExtra.put("status", status);
            }
            if (diagnostics != null) {
                Object reason = diagnostics.get("reason");
                if (reason != null) {
                    evidenceExtra.put("reason", reason);
                }
                Object stopRequested = diagnostics.get("stopRequested");
                if (stopRequested != null) {
                    evidenceExtra.put("stopRequested", stopRequested);
                }
                Object windowIndex = diagnostics.get("windowIndex");
                if (windowIndex != null) {
                    evidenceExtra.put("windowIndex", windowIndex);
                }
            }
            String scheduledTarget =
                    zapid != null && !zapid.isBlank() ? getEvidenceTargetUrl(zapid, null) : null;
            Object evidenceUrl = diagnostics != null ? diagnostics.get("windowUrl") : null;
            if (scheduledTarget != null && !scheduledTarget.isBlank()) {
                evidenceExtra.put("scheduledTarget", scheduledTarget);
            }
            logBrowserEvidence(
                    zapid,
                    browserid,
                    "browser_close",
                    evidenceUrl != null ? String.valueOf(evidenceUrl) : null,
                    evidenceExtra);
            if ("forced_closed".equals(decision) || "failed".equals(decision)) {
                LOGGER.warn(summary.toString());
            } else {
                LOGGER.info(summary.toString());
            }
        }

        private String summarizeProgressPayload(Map<String, Object> progressData) {
            return PtkCloseContract.canonicalProgressSummary(progressData);
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
            LOGGER.debug(summary.toString());
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
            if (!LOGGER.isDebugEnabled()) {
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
            LOGGER.debug(summary.toString());
        }

        private void logBrowserEvidence(
                String zapid,
                String browserid,
                String event,
                String url,
                Map<String, Object> extra) {
            recordBrowserEvidenceState(event, url, extra);
            StringBuilder summary = new StringBuilder();
            summary.append("PTK_BROWSER_EVIDENCE");
            if (zapid != null && !zapid.isBlank()) {
                summary.append(" zapid=").append(zapid);
            }
            if (browserid != null && !browserid.isBlank()) {
                summary.append(" browserid=").append(browserid);
            }
            summary.append(" event=").append(event != null && !event.isBlank() ? event : "unknown");
            if (url != null && !url.isBlank()) {
                summary.append(" url=").append(url);
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
                rememberConfigMode(zapid, getParam().isAutomatedScanningEnabled());
                markCallbackStart(zapid);
                msg.getResponseBody().setBody(getConfigJsonForRequest(requestData));
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
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("result", "OK");
                try {
                    Map<String, Object> progressData = parseRequestBody(requestBody);
                    String zapid = (String) progressData.get("zapid");
                    String browserid = (String) progressData.get("browserid");
                    String sessionId = getStringField(progressData, "sessionId");
                    String targetUrl = getStringField(progressData, "targetUrl");
                    Number progress = (Number) progressData.get("progress");
                    String status = getStringField(progressData, "status");
                    Boolean safeToClose = getBooleanField(progressData, "safeToClose");
                    if (zapid != null && progress != null) {
                        if (PtkCloseContract.isRecentlyClosedZapId(
                                closedZapIds, zapid, System.currentTimeMillis())) {
                            LOGGER.debug("PTK ignored late progress for closed zapid={}", zapid);
                            msg.getResponseBody().setBody(GSON.toJson(response));
                            msg.getResponseHeader()
                                    .setHeader(HttpHeader.CONTENT_TYPE, "application/json");
                            msg.getResponseHeader()
                                    .setContentLength(msg.getResponseBody().length());
                            return "";
                        }
                        rememberBrowserId(zapid, browserid);
                        boolean sessionEstablished = false;
                        if (sessionId != null && !sessionId.isBlank()) {
                            sessionIdByZapId.put(zapid, sessionId);
                            sessionEstablished = sessionEstablishedLogged.add(zapid);
                        }
                        String evidenceTargetUrl = getEvidenceTargetUrl(zapid, targetUrl);
                        if (targetUrl != null && !targetUrl.isBlank()) {
                            boolean rememberedTarget =
                                    PtkCloseContract.rememberInitialTargetUrl(
                                            targetUrlByZapId, zapid, targetUrl);
                            if (!rememberedTarget) {
                                LOGGER.debug(
                                        "PTK ignored progress targetUrl update zapid={} value={}",
                                        zapid,
                                        targetUrl);
                            }
                        } else {
                            evidenceTargetUrl = getEvidenceTargetUrl(zapid, null);
                        }
                        scanProgress.put(zapid, progress.intValue());
                        if (status != null && !status.isBlank()) {
                            scanStatus.put(zapid, status);
                        }
                        // safeToClose is accepted only after ZAP has explicitly asked the
                        // WebDriver-controlled tab for a PTK close decision. This prevents
                        // ordinary page/progress callbacks from pre-setting close readiness.
                        boolean acceptedSafeToClose = false;
                        if (safeToClose != null) {
                            if (PtkCloseContract.canAcceptSafeToClose(
                                    closeDecisionAttemptedByZapId, zapid)) {
                                safeToCloseByZapId.put(zapid, safeToClose);
                                acceptedSafeToClose = Boolean.TRUE.equals(safeToClose);
                            } else {
                                LOGGER.debug(
                                        "PTK ignored safeToClose before close request zapid={} value={}",
                                        zapid,
                                        safeToClose);
                            }
                        }
                        boolean firstProgress = firstProgressLogged.add(zapid);
                        long finishedAt = System.currentTimeMillis();
                        markCallbackStart(zapid);
                        Long sinceFirstMs = getElapsedSinceFirst(zapid, finishedAt);
                        boolean terminalProgress =
                                acceptedSafeToClose
                                        || isTerminalProgressValue(progress.intValue(), status);
                        if (terminalProgress && zapid != null && !zapid.isBlank()) {
                            terminalProgressLogged.add(zapid);
                        }
                        boolean manualModeCallbackOnly =
                                isManualModeCallbackProgress(
                                        zapid, progress.intValue(), status, sessionId);
                        String progressSummary = summarizeProgressPayload(progressData);
                        String previousProgressSummary =
                                zapid != null && !zapid.isBlank() && !progressSummary.isBlank()
                                        ? lastProgressSummaryByZapId.put(zapid, progressSummary)
                                        : null;
                        boolean progressChanged =
                                zapid != null
                                        && !zapid.isBlank()
                                        && !progressSummary.isBlank()
                                        && !progressSummary.equals(previousProgressSummary);
                        if ((firstProgress || progressChanged)
                                && zapid != null
                                && !zapid.isBlank()
                                && !progressSummary.isBlank()) {
                            lastProgressChangedAtMsByZapId.put(zapid, finishedAt);
                        }
                        if ((firstProgress || sessionEstablished || terminalProgress)
                                && !manualModeCallbackOnly) {
                            Map<String, Object> evidenceExtra = new LinkedHashMap<>();
                            evidenceExtra.put("progress", progress.intValue());
                            if (status != null && !status.isBlank()) {
                                evidenceExtra.put("status", status);
                            }
                            if (sessionId != null && !sessionId.isBlank()) {
                                evidenceExtra.put("sessionId", sessionId);
                            }
                            if (firstProgress && !sessionEstablished && !terminalProgress) {
                                logBrowserEvidence(
                                        zapid,
                                        browserid,
                                        "ptk_progress_seen",
                                        evidenceTargetUrl,
                                        evidenceExtra);
                            }
                            if (sessionEstablished) {
                                logBrowserEvidence(
                                        zapid,
                                        browserid,
                                        "ptk_session_established",
                                        evidenceTargetUrl,
                                        evidenceExtra);
                            }
                            if (terminalProgress) {
                                logBrowserEvidence(
                                        zapid,
                                        browserid,
                                        "ptk_session_terminal",
                                        evidenceTargetUrl,
                                        evidenceExtra);
                            }
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
                        if (!firstProgress && !terminalProgress && progressChanged) {
                            Map<String, Object> extra = new LinkedHashMap<>();
                            extra.put("progress", progress.intValue());
                            if (status != null && !status.isBlank()) {
                                extra.put("status", status);
                            }
                            extra.put("engines", progressSummary);
                            logTimingSummary(
                                    zapid, browserid, "progress.update", sinceFirstMs, extra);
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
                msg.getResponseBody().setBody(GSON.toJson(response));
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
        @SuppressWarnings("deprecation")
        public void browserLaunched(SeleniumScriptUtils ssutils) {
            if (ssutils == null || ssutils.getWebDriver() == null) {
                return;
            }
            String currentUrl;
            try {
                currentUrl = ssutils.getWebDriver().getCurrentUrl();
            } catch (Exception e) {
                LOGGER.warn("PTK browserLaunched failed to read current URL: {}", e.getMessage());
                return;
            }
            String zapid = extractZapIdFromUrl(currentUrl);
            String browserid = ssutils.getBrowserId();
            if (zapid == null || zapid.isBlank()) {
                LOGGER.debug(
                        "PTK browserLaunched without zapid browserid={} url={}",
                        browserid,
                        currentUrl);
                return;
            }

            rememberWebDriverZapId(ssutils.getWebDriver(), zapid);
            rememberBrowserId(zapid, browserid);
            closedZapIds.remove(zapid);
            browserCoverageTargetUrlByZapId.remove(zapid);
            sessionEstablishedLogged.remove(zapid);
            logBrowserEvidence(
                    zapid,
                    browserid,
                    "browser_loaded",
                    currentUrl,
                    Map.of("source", "browserLaunched"));
            long start = System.currentTimeMillis();
            logTimingSummary(zapid, browserid, "browser_launch.begin", null, Map.of());
            long waitedMs = System.currentTimeMillis() - start;
            boolean callbackSeen =
                    callbackFirstSeenAtMs.containsKey(zapid) || scanProgress.containsKey(zapid);
            Map<String, Object> extra = new LinkedHashMap<>();
            extra.put("waitedMs", waitedMs);
            extra.put("callbackSeen", callbackSeen);
            logTimingSummary(zapid, browserid, "browser_launch.end", null, extra);
        }

        @Override
        public void browserClosing(ClientCallBackUtils ccbutils) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PTK browserClosing uuid={}", ccbutils.getUuid());
            }
            if (ccbutils.getUuid() == null) {
                return;
            }
            String zapid = ccbutils.getUuid().toString();
            long start = System.currentTimeMillis();
            long closeDeadlineMs = start + PtkCloseContract.BROWSER_CLOSE_MAX_WALL_CLOCK_MS;
            String browserid = browserIdByZapId.get(zapid);
            if (isManualModeConfigOnlyClose(zapid)) {
                Map<String, Object> closeDecision = buildManualModeCloseDecision();
                long waitedMs = System.currentTimeMillis() - start;
                logCloseContractDecision(
                        zapid,
                        browserid,
                        "not_applicable",
                        "manual",
                        waitedMs,
                        0,
                        "manual",
                        closeDecision);
                logTimingSummary(
                        zapid,
                        browserid,
                        "browser_close.end",
                        getElapsedSinceFirst(zapid, System.currentTimeMillis()),
                        Map.of(
                                "waitedMs",
                                waitedMs,
                                "forced",
                                false,
                                "decision",
                                "not_applicable",
                                "reason",
                                "manual_mode"));
                clearTrackingState(zapid);
                return;
            }
            waitForSessionStartBeforeClose(zapid, closeDeadlineMs);
            boolean hadProgressBeforeClose = scanProgress.containsKey(zapid);
            Map<String, Object> closeDecision =
                    requestPtkCloseDecision(ccbutils, zapid, closeDeadlineMs);
            markCloseDecisionAttempted(zapid, System.currentTimeMillis());
            String initialDecision = getStringField(closeDecision, "decision");
            String initialScanState = getStringField(closeDecision, "scanState");
            if (PtkCloseContract.canAcceptCloseDecisionSafeToClose(
                    closeDecision,
                    scanProgress.getOrDefault(zapid, 0),
                    scanStatus.getOrDefault(zapid, ""))) {
                safeToCloseByZapId.put(zapid, true);
            }
            if (isAutomationDisabledCloseDecision(closeDecision)
                    && isWaitingForSessionStart(zapid)) {
                long sessionStartDeadline =
                        System.currentTimeMillis()
                                + PtkCloseContract.BROWSER_CLOSE_NO_PROGRESS_GRACE_MS;
                int retry = 0;
                while (isWaitingForSessionStart(zapid)
                        && System.currentTimeMillis() < sessionStartDeadline
                        && hasCloseBudget(closeDeadlineMs, 2_500L)) {
                    try {
                        Thread.sleep(PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    retry++;
                }
                closeDecision = requestPtkCloseDecision(ccbutils, zapid, closeDeadlineMs);
                initialDecision = getStringField(closeDecision, "decision");
                initialScanState = getStringField(closeDecision, "scanState");
                if (PtkCloseContract.canAcceptCloseDecisionSafeToClose(
                        closeDecision,
                        scanProgress.getOrDefault(zapid, 0),
                        scanStatus.getOrDefault(zapid, ""))) {
                    safeToCloseByZapId.put(zapid, true);
                }
                if (!isAutomationDisabledCloseDecision(closeDecision)) {
                    LOGGER.info(
                            "PTK browserClosing uuid={} recovered after {} session-start close retries",
                            ccbutils.getUuid(),
                            retry);
                }
            }
            if (!hadProgressBeforeClose && isAutomationDisabledCloseDecision(closeDecision)) {
                long automationDisabledDeadline =
                        System.currentTimeMillis()
                                + PtkCloseContract.BROWSER_CLOSE_AUTOMATION_DISABLED_GRACE_MS;
                while (!scanProgress.containsKey(zapid)
                        && System.currentTimeMillis() < automationDisabledDeadline
                        && hasCloseBudget(closeDeadlineMs, 250L)) {
                    try {
                        Thread.sleep(Math.min(250, PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
            if (!hadProgressBeforeClose && !isCloseDecisionActionable(closeDecision)) {
                long noProgressDeadline =
                        System.currentTimeMillis()
                                + PtkCloseContract.BROWSER_CLOSE_NO_PROGRESS_GRACE_MS;
                int retry = 0;
                while (!scanProgress.containsKey(zapid)
                        && !isCloseDecisionActionable(closeDecision)
                        && System.currentTimeMillis() < noProgressDeadline
                        && hasCloseBudget(closeDeadlineMs, 250L)) {
                    try {
                        Thread.sleep(PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    retry++;
                }
                if (!scanProgress.containsKey(zapid)
                        && !isCloseDecisionActionable(closeDecision)
                        && hasCloseBudget(closeDeadlineMs, 2_500L)) {
                    closeDecision = requestPtkCloseDecision(ccbutils, zapid, closeDeadlineMs);
                    initialDecision = getStringField(closeDecision, "decision");
                    initialScanState = getStringField(closeDecision, "scanState");
                    if (PtkCloseContract.canAcceptCloseDecisionSafeToClose(
                            closeDecision,
                            scanProgress.getOrDefault(zapid, 0),
                            scanStatus.getOrDefault(zapid, ""))) {
                        safeToCloseByZapId.put(zapid, true);
                    }
                }
                if (scanProgress.containsKey(zapid)) {
                    LOGGER.info(
                            "PTK browserClosing uuid={} received delayed progress after {} no-progress close retries",
                            ccbutils.getUuid(),
                            retry);
                }
            }
            boolean hasProgressBeforeClose =
                    hadProgressBeforeClose || scanProgress.containsKey(zapid);
            if (!hasProgressBeforeClose
                    && (!isCloseDecisionActionable(closeDecision)
                            || isAutomationDisabledCloseDecision(closeDecision))) {
                String currentUrl = null;
                try {
                    currentUrl = ccbutils.getWebDriver().getCurrentUrl();
                } catch (RuntimeException e) {
                    LOGGER.debug(
                            "PTK browserExiting failed to read current URL for UUID {}: {}",
                            ccbutils.getUuid(),
                            e.getMessage());
                }
                logBrowserEvidence(
                        zapid,
                        null,
                        "browser_session_invalid",
                        currentUrl,
                        Map.of("reason", "no_ptk_progress"));
                LOGGER.warn(
                        "PTK browserExiting: no progress for UUID {} url={}",
                        ccbutils.getUuid(),
                        currentUrl);
                return;
            }
            if (!hasSessionId(zapid) && isWaitingForSessionStart(zapid)) {
                String currentUrl = null;
                try {
                    currentUrl = ccbutils.getWebDriver().getCurrentUrl();
                } catch (RuntimeException e) {
                    LOGGER.debug(
                            "PTK browserExiting failed to read current URL for UUID {}: {}",
                            ccbutils.getUuid(),
                            e.getMessage());
                }
                Map<String, Object> extra = new LinkedHashMap<>();
                extra.put("reason", "no_ptk_session_after_startup_grace");
                extra.put("progress", scanProgress.getOrDefault(zapid, 0));
                String status = scanStatus.get(zapid);
                if (status != null && !status.isBlank()) {
                    extra.put("status", status);
                }
                putActivitySummaryFields(extra, zapid, System.currentTimeMillis());
                logBrowserEvidence(zapid, browserid, "browser_session_invalid", currentUrl, extra);
                logCloseContractDecision(
                        zapid,
                        browserid,
                        "browser_session_invalid",
                        status,
                        System.currentTimeMillis() - start,
                        scanProgress.getOrDefault(zapid, 0),
                        status,
                        extra);
                return;
            }
            if (PtkCloseContract.isBrowserLocalNonParticipantCloseDecision(closeDecision)) {
                logCloseContractDecision(
                        zapid,
                        browserid,
                        initialDecision != null ? initialDecision : "not_applicable",
                        initialScanState,
                        (System.currentTimeMillis() - start),
                        scanProgress.getOrDefault(zapid, 0),
                        scanStatus.getOrDefault(zapid, ""),
                        closeDecision);
                return;
            }
            if (PtkCloseContract.isBrowserLocalTabSafeToCloseDecision(closeDecision)) {
                long waitedMs = System.currentTimeMillis() - start;
                int progress = scanProgress.getOrDefault(zapid, 0);
                String status = scanStatus.getOrDefault(zapid, "");
                logCloseContractDecision(
                        zapid,
                        browserid,
                        initialDecision != null ? initialDecision : "browser_tab_safe_to_close",
                        initialScanState,
                        waitedMs,
                        progress,
                        status,
                        closeDecision);
                Map<String, Object> closeExtra = new LinkedHashMap<>();
                closeExtra.put("waitedMs", waitedMs);
                closeExtra.put("forced", false);
                closeExtra.put("decision", "browser_tab_safe_to_close");
                closeExtra.put("progress", progress);
                if (status != null && !status.isBlank()) {
                    closeExtra.put("status", status);
                }
                closeExtra.put("alertsTotal", getAlertsRaisedTotal(zapid));
                closeExtra.put("terminalSeen", terminalProgressLogged.contains(zapid));
                closeExtra.put("reason", getStringField(closeDecision, "reason"));
                putActivitySummaryFields(closeExtra, zapid, System.currentTimeMillis());
                logTimingSummary(
                        zapid,
                        browserid,
                        "browser_close.end",
                        getElapsedSinceFirst(zapid, System.currentTimeMillis()),
                        closeExtra);
                // This is a browser-tab/local close decision, not a PTK/ZAP session-terminal
                // decision. Keep zapid tracking alive so sibling/owner browser work can still
                // publish progress and findings for the same ZAP session.
                return;
            }
            logCloseContractDecision(
                    zapid,
                    browserid,
                    initialDecision != null ? initialDecision : "wait",
                    initialScanState,
                    0,
                    scanProgress.getOrDefault(zapid, 0),
                    scanStatus.getOrDefault(zapid, ""),
                    closeDecision);

            int count = 0;
            while (!isSafeToClose(zapid)) {
                long nowMs = System.currentTimeMillis();
                if (!hasRecentMeaningfulActivity(zapid, nowMs) && staleCloseLogged.add(zapid)) {
                    Map<String, Object> staleExtra = new LinkedHashMap<>();
                    staleExtra.put("reason", "activity_stale_waiting_for_terminal");
                    staleExtra.put("stopRequested", false);
                    putActivitySummaryFields(staleExtra, zapid, nowMs);
                    logCloseContractDecision(
                            zapid,
                            browserid,
                            "wait",
                            scanStatus.getOrDefault(zapid, ""),
                            nowMs - start,
                            scanProgress.getOrDefault(zapid, 0),
                            scanStatus.getOrDefault(zapid, ""),
                            staleExtra);
                }
                if (count >= PtkCloseContract.BROWSER_CLOSE_MAX_ATTEMPTS
                        || !hasCloseBudget(closeDeadlineMs, 250L)) {
                    Map<String, Object> summaryExtra =
                            buildSessionSummaryExtra(
                                    zapid,
                                    true,
                                    (System.currentTimeMillis() - start),
                                    scanProgress.getOrDefault(zapid, 0),
                                    scanStatus.getOrDefault(zapid, ""));
                    if (!hasRecentMeaningfulActivity(zapid, System.currentTimeMillis())) {
                        summaryExtra.put("reason", "activity_stale_forced_close");
                    }
                    LOGGER.warn(
                            "PTK browserClosing uuid={} forced=true waitedMs={} progress={} status={}",
                            ccbutils.getUuid(),
                            (System.currentTimeMillis() - start),
                            scanProgress.get(zapid),
                            scanStatus.getOrDefault(zapid, ""));
                    logCloseContractDecision(
                            zapid,
                            browserid,
                            "forced_closed",
                            scanStatus.getOrDefault(zapid, ""),
                            (System.currentTimeMillis() - start),
                            scanProgress.getOrDefault(zapid, 0),
                            scanStatus.getOrDefault(zapid, ""),
                            closeDecision);
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
                    Thread.sleep(PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS);
                    count++;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (count % PtkCloseContract.BROWSER_CLOSE_FOLLOW_UP_DECISION_EVERY_ATTEMPTS == 0
                        && !isSafeToClose(zapid)
                        && hasCloseBudget(closeDeadlineMs, 2_500L)) {
                    closeDecision = requestPtkCloseDecision(ccbutils, zapid, closeDeadlineMs);
                    String followUpDecision = getStringField(closeDecision, "decision");
                    String followUpScanState = getStringField(closeDecision, "scanState");
                    if (PtkCloseContract.canAcceptCloseDecisionSafeToClose(
                            closeDecision,
                            scanProgress.getOrDefault(zapid, 0),
                            scanStatus.getOrDefault(zapid, ""))) {
                        safeToCloseByZapId.put(zapid, true);
                    }
                    logCloseContractDecision(
                            zapid,
                            browserid,
                            followUpDecision != null ? followUpDecision : "wait",
                            followUpScanState,
                            (System.currentTimeMillis() - start),
                            scanProgress.getOrDefault(zapid, 0),
                            scanStatus.getOrDefault(zapid, ""),
                            closeDecision);
                }
            }
            scanProgress.remove(zapid);
            String status = scanStatus.remove(zapid);
            String closeDecisionState = getStringField(closeDecision, "scanState");
            String effectiveFinalStatus = status != null ? status : "";
            if (!isTerminalProgressValue(100, effectiveFinalStatus)
                    && "safe_to_close".equals(getStringField(closeDecision, "decision"))
                    && closeDecisionState != null
                    && !closeDecisionState.isBlank()) {
                effectiveFinalStatus = closeDecisionState;
            }
            browserid = browserIdByZapId.remove(zapid);
            Long elapsedSinceFirstMs = getElapsedSinceFirst(zapid, System.currentTimeMillis());
            Map<String, Object> summaryExtra =
                    buildSessionSummaryExtra(
                            zapid,
                            false,
                            (System.currentTimeMillis() - start),
                            100,
                            effectiveFinalStatus);
            logCloseContractDecision(
                    zapid,
                    browserid,
                    "safe_to_close",
                    effectiveFinalStatus,
                    (System.currentTimeMillis() - start),
                    100,
                    effectiveFinalStatus,
                    closeDecision);
            logTimingSummary(
                    zapid, browserid, "session.summary", elapsedSinceFirstMs, summaryExtra);
            logTimingSummary(
                    zapid, browserid, "browser_close.end", elapsedSinceFirstMs, summaryExtra);
            clearTrackingState(zapid);
        }

        private boolean isTerminalProgress(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return false;
            }
            if (terminalProgressLogged.contains(zapid)) {
                return true;
            }
            return isTerminalProgressValue(scanProgress.get(zapid), scanStatus.get(zapid));
        }
    }
}
