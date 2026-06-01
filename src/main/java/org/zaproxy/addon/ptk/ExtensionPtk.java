package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import java.lang.reflect.Field;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.OverrideMessageProxyListener;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
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
 * - BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS is the close-decision bridge call timeout.
 *   The close-decision script must not stop PTK merely because this or any other
 *   close budget elapsed. Stale activity is logged as degraded waiting evidence,
 *   not as permission to stop a running PTK scan.
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
    static final long BROWSER_CALLBACK_BOOTSTRAP_HANDSHAKE_MS = 12000;
    static final long BROWSER_CALLBACK_BOOTSTRAP_RELOAD_AFTER_MS = 1250;
    static final long BROWSER_CALLBACK_BOOTSTRAP_POLL_MS = 100;
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

    @FunctionalInterface
    interface CallbackHandshakeSleeper {
        void sleep(long sleepMs) throws InterruptedException;
    }

    record CallbackBootstrapHandshakeResult(
            boolean handshakeSeen,
            long handshakeWaitedMs,
            int handshakePolls,
            String handshakeMode,
            boolean callbackReloadAttempted,
            String callbackReloadError,
            boolean interrupted) {

        Map<String, Object> toLogFields() {
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("handshakeSeen", handshakeSeen);
            fields.put("handshakeWaitedMs", handshakeWaitedMs);
            fields.put("handshakePolls", handshakePolls);
            fields.put("handshakeMode", handshakeMode);
            fields.put("callbackReloadAttempted", callbackReloadAttempted);
            if (callbackReloadError != null && !callbackReloadError.isBlank()) {
                fields.put("callbackReloadError", callbackReloadError);
            }
            if (interrupted) {
                fields.put("interrupted", true);
            }
            return fields;
        }
    }

    static CallbackBootstrapHandshakeResult awaitCallbackBootstrapHandshake(
            BooleanSupplier handshakeSeen,
            Runnable reloadCallback,
            LongSupplier nowMs,
            CallbackHandshakeSleeper sleeper) {
        return awaitCallbackBootstrapHandshake(
                handshakeSeen,
                reloadCallback,
                nowMs,
                sleeper,
                BROWSER_CALLBACK_BOOTSTRAP_HANDSHAKE_MS,
                BROWSER_CALLBACK_BOOTSTRAP_RELOAD_AFTER_MS,
                BROWSER_CALLBACK_BOOTSTRAP_POLL_MS);
    }

    static CallbackBootstrapHandshakeResult awaitCallbackBootstrapHandshake(
            BooleanSupplier handshakeSeen,
            Runnable reloadCallback,
            LongSupplier nowMs,
            CallbackHandshakeSleeper sleeper,
            long maxWaitMs,
            long reloadAfterMs,
            long pollMs) {
        long start = nowMs.getAsLong();
        long deadline = start + Math.max(0L, maxWaitMs);
        long reloadAt = start + Math.max(0L, reloadAfterMs);
        long effectivePollMs = Math.max(1L, pollMs);
        int polls = 0;
        boolean reloadAttempted = false;
        String reloadError = null;
        boolean interrupted = false;

        while (true) {
            if (handshakeSeen != null && handshakeSeen.getAsBoolean()) {
                return new CallbackBootstrapHandshakeResult(
                        true,
                        Math.max(0L, nowMs.getAsLong() - start),
                        polls,
                        "java_callback_wait",
                        reloadAttempted,
                        reloadError,
                        interrupted);
            }
            long now = nowMs.getAsLong();
            if (now >= deadline || interrupted) {
                return new CallbackBootstrapHandshakeResult(
                        false,
                        Math.max(0L, now - start),
                        polls,
                        "java_callback_wait",
                        reloadAttempted,
                        reloadError,
                        interrupted);
            }
            if (!reloadAttempted && reloadCallback != null && now >= reloadAt) {
                reloadAttempted = true;
                try {
                    reloadCallback.run();
                } catch (RuntimeException e) {
                    reloadError = e.getMessage() != null ? e.getMessage() : e.toString();
                }
                if (handshakeSeen != null && handshakeSeen.getAsBoolean()) {
                    return new CallbackBootstrapHandshakeResult(
                            true,
                            Math.max(0L, nowMs.getAsLong() - start),
                            polls,
                            "java_callback_wait",
                            reloadAttempted,
                            reloadError,
                            interrupted);
                }
            }
            long sleepMs = Math.min(effectivePollMs, Math.max(1L, deadline - now));
            polls++;
            try {
                sleeper.sleep(sleepMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                interrupted = true;
            }
        }
    }

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

    static boolean isActiveBrowserWorkCloseDecision(Map<String, Object> closeDecision) {
        String decision = getString(closeDecision, "decision");
        if (!"wait".equals(decision)) {
            return false;
        }
        if (Boolean.TRUE.equals(closeDecision.get("stopRequested"))) {
            return false;
        }
        return "active_browser_work".equals(getString(closeDecision, "reason"));
    }

    @SuppressWarnings("unchecked")
    static String canonicalProgressSummary(Map<String, Object> progressData) {
        if (progressData == null || progressData.isEmpty()) {
            return "";
        }
        StringBuilder summary = new StringBuilder();
        appendSummaryField(summary, "sid", getString(progressData, "sessionId"));
        // Build the close-readiness activity signal on the Java side. Extension-provided
        // activitySeq/activityFingerprint may include heartbeat or module-delivery counters,
        // which would keep browser close alive even when engines are no longer making
        // meaningful scan progress.
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
                        appendDetailField(summary, details, "findingReportsAccepted", "ifa");
                        appendDetailField(
                                summary, details, "findingReportsDroppedInactive", "ifdi");
                        appendDetailField(
                                summary, details, "findingReportsDroppedTabMismatch", "ifdt");
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

    static boolean shouldCreateAdaptiveStaleCloseRequest(
            PtkZapSessionSnapshot snapshot,
            String requestedSessionId,
            String requestedBrowserId,
            long nowMs) {
        if (snapshot == null || snapshot.closeRequest() != null) {
            return false;
        }
        if (snapshot.contractVersion() < 2 || snapshot.isV2PhysicallySafeToClose()) {
            return false;
        }
        String sessionId = snapshot.sessionId();
        if (sessionId == null || sessionId.isBlank()) {
            return false;
        }
        if (requestedSessionId != null
                && !requestedSessionId.isBlank()
                && !requestedSessionId.equals(sessionId)) {
            return false;
        }
        String browserId = snapshot.browserId();
        if (browserId != null
                && !browserId.isBlank()
                && requestedBrowserId != null
                && !requestedBrowserId.isBlank()
                && !requestedBrowserId.equals(browserId)) {
            return false;
        }
        Integer progress = snapshot.progress();
        if (progress == null || progress < 99) {
            return false;
        }
        String status = snapshot.status();
        if (status == null || isTerminalProgressValue(progress, status)) {
            return false;
        }
        return !isActivityFresh(snapshot.newestActivityAt(), nowMs);
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

public class ExtensionPtk extends ExtensionAdaptor
        implements ExampleAlertProvider, OptionsChangedListener {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionPtk.class);
    private static final String PREFIX = "ptk";
    private static final Gson GSON = new Gson();

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionClientIntegration.class, ExtensionSelenium.class);
    private static final List<Browser> PTK_CHROMIUM_BROWSERS =
            List.of(Browser.CHROME, Browser.CHROME_HEADLESS, Browser.EDGE, Browser.EDGE_HEADLESS);
    private static final List<Browser> PTK_FIREFOX_BROWSERS =
            List.of(Browser.FIREFOX, Browser.FIREFOX_HEADLESS);
    private static final List<String> PTK_CHROMIUM_BACKGROUND_ARGS =
            List.of(
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-domain-reliability",
                    "--disable-default-apps",
                    "--disable-features=AutofillServerCommunication,OptimizationHints,OptimizationHintsFetching,OptimizationTargetPrediction,msEdgeUpdateLaunchServicesPreferredVersion,msForceBrowserSignIn",
                    "--proxy-bypass-list=edge.microsoft.com;*.dl.delivery.mp.microsoft.com;update.googleapis.com;dl.google.com;*.gvt1.com",
                    "--disable-sync",
                    "--no-default-browser-check",
                    "--no-first-run");
    private static final int PTK_BROWSER_BACKGROUND_PROXY_LISTENER_ORDER = 0;
    private static final String PTK_BACKGROUND_TRAFFIC_EMPTY_RESPONSE =
            "HTTP/1.1 204 No Content\r\n"
                    + "Content-Length: 0\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "Connection: close\r\n\r\n";
    private static final int ZAP_HISTORY_SEED_MAX_URLS = 500;
    private static final int ZAP_HISTORY_SEED_MAX_SITE_NODES = 10_000;
    private static final long ZAP_HISTORY_SEED_CACHE_TTL_MS = 2_000L;
    private static final long ZAP_HISTORY_SEED_FAILURE_LOG_INTERVAL_MS = 60_000L;
    private static final long PTK_CLIENT_SPIDER_ACTIVITY_TOUCH_MIN_INTERVAL_MS = 500L;
    private static final int PTK_CLIENT_SPIDER_SEED_URL_CAP = 24;

    private ClientCallBackImplementor callBackImplementor;
    private final OverrideMessageProxyListener browserBackgroundTrafficProxyListener =
            new BrowserBackgroundTrafficProxyListener();
    private PtkOptionsPanel optionsPanel;
    private PtkParam ptkParam;
    private final List<PtkDiagnosticExtension> diagnosticExtensions = new ArrayList<>();
    private final Object configCacheLock = new Object();
    private volatile PtkResourcesLoader.LoadedPtkResources cachedResources;
    private volatile String cachedConfigKey;
    private volatile String cachedConfigJson;
    private volatile int cachedInitiator;
    private final Map<String, ZapHistorySeedCacheEntry> zapHistorySeedCache =
            new ConcurrentHashMap<>();
    private final AtomicLong lastZapHistorySeedFailureLogAtMs = new AtomicLong(0L);
    private final AtomicBoolean clientSpiderActivityTouchWarned = new AtomicBoolean(false);
    private final Map<String, Long> clientSpiderActivityTouchAtMsByZapId =
            new ConcurrentHashMap<>();
    private final Set<String> clientSpiderSeededScanKeys = ConcurrentHashMap.newKeySet();
    private volatile Field clientSpiderLastEventReceivedTimeField;
    private volatile Field clientSpiderOptionsField;
    private volatile Method clientSpiderAddOpenUrlTaskMethod;
    private volatile Method clientOptionsGetThreadCountMethod;
    private volatile Method clientOptionsGetPageLoadTimeMethod;

    private final Map<String, Integer> scanProgress = new ConcurrentHashMap<>();
    private final Map<String, String> scanStatus = new ConcurrentHashMap<>();
    private final Map<String, Long> callbackFirstSeenAtMs = new ConcurrentHashMap<>();
    private final Map<String, String> browserIdByZapId = new ConcurrentHashMap<>();
    private final Map<String, Integer> alertsRaisedByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> firstAlertSeenAtMs = new ConcurrentHashMap<>();
    private final Map<String, String> lastProgressSummaryByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> lastEngineEvidenceSummaryByZapIdAndEngine =
            new ConcurrentHashMap<>();
    private final Map<String, Long> lastProgressChangedAtMsByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlertChangedAtMsByZapId = new ConcurrentHashMap<>();
    private final Map<String, Integer> progressContractVersionByZapId = new ConcurrentHashMap<>();
    private final Map<String, Boolean> publisherDrainedByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> closeRequestIdByZapId = new ConcurrentHashMap<>();
    private final Map<String, Boolean> closeRequestAckByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> closeRequestCreatedAtMsByZapId = new ConcurrentHashMap<>();
    private final Set<String> staleCloseLogged = ConcurrentHashMap.newKeySet();
    private final Map<String, PtkZapSessionState> sessionStateByZapId = new ConcurrentHashMap<>();
    private final Map<String, PtkBrowserTaskState> browserTaskStateByZapIdAndBrowserId =
            new ConcurrentHashMap<>();
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
    private final Set<String> contractCallbackLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> configAppliedLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> targetResolvedLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> closeWaitActiveLogged = ConcurrentHashMap.newKeySet();
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

    private Field getClientSpiderLastEventReceivedTimeField() {
        Field existing = clientSpiderLastEventReceivedTimeField;
        if (existing != null) {
            return existing;
        }
        try {
            Class<?> clientSpiderClass =
                    Class.forName("org.zaproxy.addon.client.spider.ClientSpider");
            Field field = clientSpiderClass.getDeclaredField("lastEventReceivedtime");
            field.setAccessible(true);
            clientSpiderLastEventReceivedTimeField = field;
            return field;
        } catch (LinkageError | ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug(
                    "PTK could not access Client Spider activity timestamp field: {}",
                    e.getMessage());
            return null;
        }
    }

    private Field getClientSpiderOptionsField() {
        Field existing = clientSpiderOptionsField;
        if (existing != null) {
            return existing;
        }
        try {
            Class<?> clientSpiderClass =
                    Class.forName("org.zaproxy.addon.client.spider.ClientSpider");
            Field field = clientSpiderClass.getDeclaredField("options");
            field.setAccessible(true);
            clientSpiderOptionsField = field;
            return field;
        } catch (LinkageError | ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug("PTK could not access Client Spider options field: {}", e.getMessage());
            return null;
        }
    }

    private Method getClientSpiderAddOpenUrlTaskMethod() {
        Method existing = clientSpiderAddOpenUrlTaskMethod;
        if (existing != null) {
            return existing;
        }
        try {
            Class<?> clientSpiderClass =
                    Class.forName("org.zaproxy.addon.client.spider.ClientSpider");
            Method method =
                    clientSpiderClass.getDeclaredMethod("addOpenUrlTask", String.class, int.class);
            method.setAccessible(true);
            clientSpiderAddOpenUrlTaskMethod = method;
            return method;
        } catch (LinkageError | ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug(
                    "PTK could not access Client Spider addOpenUrlTask method: {}", e.getMessage());
            return null;
        }
    }

    private Method getClientOptionsGetThreadCountMethod(Object options) {
        if (options == null) {
            return null;
        }
        Method existing = clientOptionsGetThreadCountMethod;
        if (existing != null) {
            return existing;
        }
        try {
            Method method = options.getClass().getMethod("getThreadCount");
            clientOptionsGetThreadCountMethod = method;
            return method;
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug("PTK could not access ClientOptions.getThreadCount: {}", e.getMessage());
            return null;
        }
    }

    private Method getClientOptionsGetPageLoadTimeMethod(Object options) {
        if (options == null) {
            return null;
        }
        Method existing = clientOptionsGetPageLoadTimeMethod;
        if (existing != null) {
            return existing;
        }
        try {
            Method method = options.getClass().getMethod("getPageLoadTimeInSecs");
            clientOptionsGetPageLoadTimeMethod = method;
            return method;
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug(
                    "PTK could not access ClientOptions.getPageLoadTimeInSecs: {}", e.getMessage());
            return null;
        }
    }

    private void seedActiveClientSpiderTasksForPtkTarget(
            String zapid, String targetUrl, List<String> seedUrls) {
        if (!getParam().isAutomatedScanningEnabled()
                || targetUrl == null
                || targetUrl.isBlank()
                || seedUrls == null
                || seedUrls.isEmpty()) {
            return;
        }

        ExtensionClientIntegration clientExtension =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionClientIntegration.class);
        if (clientExtension == null) {
            return;
        }

        List<?> activeScans;
        try {
            activeScans = clientExtension.getActiveScans();
        } catch (RuntimeException e) {
            LOGGER.debug(
                    "PTK failed to read active Client Spider scans for seeding: {}",
                    e.getMessage());
            return;
        }
        if (activeScans == null || activeScans.isEmpty()) {
            return;
        }

        String normalizedTarget = PtkUrlUtils.normalizeHttpUrlWithoutFragment(targetUrl);
        for (Object scan : activeScans) {
            if (scan == null) {
                continue;
            }
            String scanTarget = getClientSpiderTargetUrl(scan);
            String normalizedScanTarget = PtkUrlUtils.normalizeHttpUrlWithoutFragment(scanTarget);
            if (normalizedTarget == null || !normalizedTarget.equals(normalizedScanTarget)) {
                continue;
            }
            String scanKey =
                    System.identityHashCode(scan)
                            + ":"
                            + (normalizedTarget != null ? normalizedTarget : targetUrl);
            if (!clientSpiderSeededScanKeys.add(scanKey)) {
                continue;
            }
            seedClientSpiderTasks(scan, zapid, targetUrl, seedUrls);
        }
    }

    private void seedClientSpiderTasks(
            Object scan, String zapid, String targetUrl, List<String> seedUrls) {
        Method addOpenUrlTask = getClientSpiderAddOpenUrlTaskMethod();
        Field optionsField = getClientSpiderOptionsField();
        if (addOpenUrlTask == null || optionsField == null) {
            return;
        }

        Object options;
        try {
            options = optionsField.get(scan);
        } catch (IllegalAccessException | RuntimeException e) {
            LOGGER.debug(
                    "PTK failed to read Client Spider options for seeding: {}", e.getMessage());
            return;
        }

        int threadCount = getClientSpiderThreadCount(options);
        if (threadCount <= 1) {
            return;
        }
        int pageLoadTime = getClientSpiderPageLoadTime(options);
        /*
         * Client Spider serialises WebDriver creation through its WebDriver pool. With fast pages,
         * a task can finish and return its browser to the pool before later queued tasks acquire
         * the creation lock, causing those tasks to reuse an existing browser instead of starting
         * the requested browser concurrency. Queue a bounded batch of real in-scope URLs so the
         * worker pool has enough work to keep creating browsers while the first tasks are active.
         */
        int seedLimit =
                Math.min(
                        Math.max(threadCount * 3, threadCount - 1), PTK_CLIENT_SPIDER_SEED_URL_CAP);
        if (seedLimit <= 0) {
            return;
        }

        int attempted = 0;
        int seeded = 0;
        Set<String> unique = new LinkedHashSet<>();
        String normalizedTarget = PtkUrlUtils.normalizeHttpUrlWithoutFragment(targetUrl);
        for (String seedUrl : seedUrls) {
            String normalized = PtkUrlUtils.normalizeHttpUrlWithoutFragment(seedUrl);
            if (normalized == null
                    || normalized.equals(normalizedTarget)
                    || !PtkUrlUtils.isSameOriginAndPathScoped(targetUrl, normalized)
                    || !unique.add(normalized)) {
                continue;
            }
            attempted++;
            try {
                Object task = addOpenUrlTask.invoke(scan, normalized, pageLoadTime);
                if (task != null) {
                    seeded++;
                }
            } catch (ReflectiveOperationException | RuntimeException e) {
                LOGGER.debug(
                        "PTK failed to seed Client Spider URL task url={} reason={}",
                        normalized,
                        e.getMessage());
            }
            if (seeded >= seedLimit) {
                break;
            }
        }

        if (seeded > 0) {
            LOGGER.info(
                    "PTK_CONTRACT phase=client_spider_seed_tasks zapid={} seeded={} attempted={} threadCount={} targetUrl={}",
                    zapid,
                    seeded,
                    attempted,
                    threadCount,
                    targetUrl);
        }
    }

    private int getClientSpiderThreadCount(Object options) {
        Method method = getClientOptionsGetThreadCountMethod(options);
        if (method == null) {
            return 1;
        }
        try {
            Object value = method.invoke(options);
            return value instanceof Number ? ((Number) value).intValue() : 1;
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug("PTK failed to read Client Spider thread count: {}", e.getMessage());
            return 1;
        }
    }

    private int getClientSpiderPageLoadTime(Object options) {
        Method method = getClientOptionsGetPageLoadTimeMethod(options);
        if (method == null) {
            return 5;
        }
        try {
            Object value = method.invoke(options);
            return value instanceof Number ? ((Number) value).intValue() : 5;
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug("PTK failed to read Client Spider page-load time: {}", e.getMessage());
            return 5;
        }
    }

    private void touchActiveClientSpidersForPtkActivity(
            String zapid, String targetUrl, String reason, long nowMs) {
        if (zapid == null || zapid.isBlank() || nowMs <= 0) {
            return;
        }
        Long previousTouch = clientSpiderActivityTouchAtMsByZapId.get(zapid);
        if (previousTouch != null
                && nowMs - previousTouch < PTK_CLIENT_SPIDER_ACTIVITY_TOUCH_MIN_INTERVAL_MS) {
            return;
        }

        String activityTarget = firstNonBlank(targetUrl, targetUrlByZapId.get(zapid));
        if (activityTarget == null || activityTarget.isBlank()) {
            activityTarget = browserCoverageTargetUrlByZapId.get(zapid);
        }
        if (activityTarget == null || activityTarget.isBlank()) {
            return;
        }

        ExtensionClientIntegration clientExtension =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionClientIntegration.class);
        if (clientExtension == null) {
            return;
        }

        List<?> activeScans;
        try {
            activeScans = clientExtension.getActiveScans();
        } catch (RuntimeException e) {
            LOGGER.debug("PTK failed to read active Client Spider scans: {}", e.getMessage());
            return;
        }
        if (activeScans == null || activeScans.isEmpty()) {
            return;
        }

        int touched = 0;
        for (Object scan : activeScans) {
            if (scan == null || !isPtkActivityInClientSpiderScope(scan, activityTarget)) {
                continue;
            }
            if (touchClientSpiderActivity(scan, nowMs)) {
                touched++;
            }
        }

        if (touched > 0) {
            clientSpiderActivityTouchAtMsByZapId.put(zapid, nowMs);
            LOGGER.debug(
                    "PTK touched Client Spider activity zapid={} touched={} reason={} target={}",
                    zapid,
                    touched,
                    reason,
                    activityTarget);
        }
    }

    private boolean isPtkActivityInClientSpiderScope(Object scan, String activityTarget) {
        String scanTarget = getClientSpiderTargetUrl(scan);
        if (scanTarget == null || scanTarget.isBlank()) {
            return false;
        }
        return PtkUrlUtils.isSameOriginAndPathScoped(scanTarget, activityTarget)
                || PtkUrlUtils.isSameOriginAndPathScoped(activityTarget, scanTarget);
    }

    private String getClientSpiderTargetUrl(Object scan) {
        if (scan == null) {
            return null;
        }
        try {
            Method getTargetUrl = scan.getClass().getMethod("getTargetUrl");
            Object value = getTargetUrl.invoke(scan);
            return value != null ? String.valueOf(value) : null;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    private boolean touchClientSpiderActivity(Object scan, long nowMs) {
        Field field = getClientSpiderLastEventReceivedTimeField();
        if (field == null) {
            if (clientSpiderActivityTouchWarned.compareAndSet(false, true)) {
                LOGGER.warn(
                        "PTK cannot extend Client Spider quiet-window activity; field unavailable");
            }
            return false;
        }
        try {
            field.setLong(scan, nowMs);
            return true;
        } catch (IllegalAccessException | RuntimeException e) {
            if (clientSpiderActivityTouchWarned.compareAndSet(false, true)) {
                LOGGER.warn(
                        "PTK failed to extend Client Spider quiet-window activity: {}",
                        e.getMessage());
            }
            return false;
        }
    }

    private static String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        if (second != null && !second.isBlank()) {
            return second;
        }
        return null;
    }

    static boolean isBrowserBackgroundRequestToSuppress(String host, String path) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String normalizedHost = host.toLowerCase().strip();
        while (normalizedHost.endsWith(".")) {
            normalizedHost = normalizedHost.substring(0, normalizedHost.length() - 1);
        }
        String normalizedPath = path == null || path.isBlank() ? "/" : path.toLowerCase();

        if ("edge.microsoft.com".equals(normalizedHost)
                && normalizedPath.startsWith("/componentupdater/")) {
            return true;
        }
        if ("firefox.settings.services.mozilla.com".equals(normalizedHost)
                && normalizedPath.startsWith("/v1/")) {
            return true;
        }
        return normalizedHost.endsWith(".dl.delivery.mp.microsoft.com")
                && normalizedPath.startsWith("/filestreamingservice/");
    }

    private static boolean isBrowserBackgroundRequestToSuppress(HttpMessage message) {
        if (message == null || message.getRequestHeader() == null) {
            return false;
        }
        try {
            org.apache.commons.httpclient.URI uri = message.getRequestHeader().getURI();
            if (uri == null) {
                return false;
            }
            return isBrowserBackgroundRequestToSuppress(uri.getHost(), uri.getPath());
        } catch (URIException | RuntimeException e) {
            return false;
        }
    }

    private static boolean applyBrowserBackgroundTrafficResponse(HttpMessage message) {
        if (!isBrowserBackgroundRequestToSuppress(message)) {
            return false;
        }
        try {
            message.setResponseHeader(PTK_BACKGROUND_TRAFFIC_EMPTY_RESPONSE);
            message.setResponseBody("");
            message.setResponseFromTargetHost(false);
            if (LOGGER.isDebugEnabled()) {
                org.apache.commons.httpclient.URI uri = message.getRequestHeader().getURI();
                LOGGER.debug(
                        "PTK_CONTRACT phase=browser_background_request_suppressed host={} path={}",
                        uri.getHost(),
                        uri.getPath());
            }
            return true;
        } catch (HttpMalformedHeaderException | URIException | RuntimeException e) {
            LOGGER.debug("PTK failed to suppress browser background request: {}", e.getMessage());
            return false;
        }
    }

    private static final class BrowserBackgroundTrafficProxyListener
            implements OverrideMessageProxyListener {
        @Override
        public int getArrangeableListenerOrder() {
            return PTK_BROWSER_BACKGROUND_PROXY_LISTENER_ORDER;
        }

        @Override
        public boolean onHttpRequestSend(HttpMessage message) {
            return applyBrowserBackgroundTrafficResponse(message);
        }

        @Override
        public boolean onHttpResponseReceived(HttpMessage message) {
            return isBrowserBackgroundRequestToSuppress(message);
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addOverrideMessageProxyListener(browserBackgroundTrafficProxyListener);
        callBackImplementor = new CallBackImplementor();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .registerClientCallBack(callBackImplementor);
        ensurePtkSeleniumExtensionsConfigured(
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class));
        loadDiagnosticExtensions(extensionHook);
        extensionHook.addOptionsChangedListener(this);
        extensionHook.addOptionsParamSet(getParam());
        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
        }
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        clearConfigCache();
    }

    private void clearConfigCache() {
        synchronized (configCacheLock) {
            cachedConfigKey = null;
            cachedConfigJson = null;
            cachedInitiator = 0;
        }
        LOGGER.debug("PTK /ptk/config cache cleared after options change");
    }

    private PtkOptionsPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new PtkOptionsPanel();
        }
        return optionsPanel;
    }

    public PtkParam getParam() {
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
            for (Browser browser : PTK_FIREFOX_BROWSERS) {
                changed |= ensureBrowserExtension(extensions, xpiPath, browser, browser.getId());
            }
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

    private String getCachedConfigJson(ClientCallBackImplementor.ClientCallBackContext cbContext) {
        PtkParam param = getParam();
        PtkResourcesLoader.LoadedPtkResources resources = getLoadedResources();
        String configKey = param.buildConfigCacheKey(resources);
        if (cbContext.initiator() != cachedInitiator) {
            clearConfigCache();
        }
        String json = cachedConfigJson;

        if (json != null
                && configKey.equals(cachedConfigKey)
                && cbContext.initiator() == cachedInitiator) {
            LOGGER.debug("PTK /ptk/config cache hit");
            return json;
        }

        synchronized (configCacheLock) {
            if (cachedConfigJson != null
                    && configKey.equals(cachedConfigKey)
                    && cbContext.initiator() == cachedInitiator) {
                LOGGER.debug("PTK /ptk/config cache hit after lock");
                return cachedConfigJson;
            }
            String mode = "manual";
            if (param.isAutomatedScanningEnabled()
                    || (cbContext.initiator() == HttpSender.ACTIVE_SCANNER_INITIATOR
                            && param.isActiveScanRuleEnabled())) {
                mode = "auto";
            }
            LOGGER.info(
                    "PTK mode {} auto={} active={}",
                    mode,
                    param.isAutomatedScanningEnabled(),
                    param.isActiveScanRuleEnabled());

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("mode", mode);
            response.put("contractVersion", 2);
            response.put("ptkControlSupported", true);
            response.put("controlPath", "/ptk/control");
            Map<String, PtkModulesDefinition> config = PtkConfigFilter.filter(resources, param);
            response.put("sast", config.get("sast") != null ? config.get("sast") : Map.of());
            response.put("iast", config.get("iast") != null ? config.get("iast") : Map.of());
            response.put("dast", config.get("dast") != null ? config.get("dast") : Map.of());

            json = GSON.toJson(response);
            cachedConfigKey = configKey;
            cachedConfigJson = json;
            cachedInitiator = cbContext.initiator();
            LOGGER.debug("PTK /ptk/config cache miss; rebuilt response");
            return json;
        }
    }

    private String getConfigJsonForRequest(
            Map<String, Object> requestData,
            ClientCallBackImplementor.ClientCallBackContext cbContext) {
        String baseJson = getCachedConfigJson(cbContext);
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
        seedActiveClientSpiderTasksForPtkTarget(zapid, targetUrl, urls);
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
        private static final String PTK_CONTROL_PATH = "/ptk/control";
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

        @SuppressWarnings("unchecked")
        private Map<String, Object> getMapField(Map<String, Object> body, String key) {
            Object value = body != null ? body.get(key) : null;
            return value instanceof Map<?, ?> ? (Map<String, Object>) value : Map.of();
        }

        private boolean isV2Progress(Map<String, Object> progressData) {
            Integer version = getIntegerField(progressData, "contractVersion");
            return version != null && version.intValue() >= 2;
        }

        private boolean isV2ProgressSafeToClose(String zapid, Map<String, Object> progressData) {
            if (!isV2ProgressPhysicallySafeToClose(zapid, progressData)) {
                return false;
            }
            Map<String, Object> publisher = getPublisherStateField(progressData);
            Boolean publisherDrained = getBooleanField(publisher, "drained");
            String completionStatus = getStringField(progressData, "completionStatus");
            String releaseStatus = getStringField(progressData, "releaseStatus");
            return Boolean.TRUE.equals(publisherDrained)
                    && "completed".equals(completionStatus)
                    && (releaseStatus == null
                            || releaseStatus.isBlank()
                            || "clean".equals(releaseStatus));
        }

        private boolean isV2ProgressPhysicallySafeToClose(
                String zapid, Map<String, Object> progressData) {
            if (!isV2ProgressTerminalEvidence(progressData)) {
                return false;
            }
            String activeCloseRequestId = activeCloseRequestId(zapid);
            if (activeCloseRequestId == null || activeCloseRequestId.isBlank()) {
                return true;
            }
            String progressCloseRequestId = getStringField(progressData, "closeRequestId");
            Boolean closeRequestAck = getBooleanField(progressData, "closeRequestAck");
            return activeCloseRequestId.equals(progressCloseRequestId)
                    && Boolean.TRUE.equals(closeRequestAck);
        }

        private boolean isV2ProgressTerminalEvidence(Map<String, Object> progressData) {
            Boolean terminalSeen = getBooleanField(progressData, "terminalSeen");
            if (Boolean.TRUE.equals(terminalSeen)) {
                return true;
            }
            return isTerminalProgressValue(
                    getIntegerField(progressData, "progress"),
                    getStringField(progressData, "status"));
        }

        private Map<String, Object> getPublisherStateField(Map<String, Object> body) {
            Map<String, Object> publisher = getMapField(body, "publisher");
            return publisher.isEmpty() ? getMapField(body, "zapPublisherDrain") : publisher;
        }

        private boolean canAcceptCloseDecisionSafeToClose(
                String zapid, Map<String, Object> closeDecision, Integer progress, String status) {
            if (!PtkCloseContract.canAcceptCloseDecisionSafeToClose(
                    closeDecision, progress, status)) {
                return false;
            }
            Integer closeDecisionContractVersion =
                    getIntegerField(closeDecision, "contractVersion");
            if (closeDecisionContractVersion != null
                    && closeDecisionContractVersion.intValue() >= 2) {
                return canAcceptObservedV2SafeToClose(zapid);
            }
            if (progressContractVersionByZapId.getOrDefault(zapid, 0) < 2) {
                return true;
            }
            PtkZapSessionSnapshot snapshot = sessionSnapshot(zapid);
            if (snapshot == null) {
                return false;
            }
            PtkCloseRequestState closeRequest = snapshot.closeRequest();
            if (closeRequest == null || closeRequest.id().isBlank()) {
                return snapshot.isV2PhysicallySafeToClose();
            }
            String closeDecisionRequestId = getStringField(closeDecision, "closeRequestId");
            Boolean closeDecisionAck = getBooleanField(closeDecision, "closeRequestAck");
            boolean explicitCloseRequestTerminalDecision =
                    isExplicitCloseRequestTerminalDecision(closeDecision);
            if (explicitCloseRequestTerminalDecision
                    && closeRequest.id().equals(closeDecisionRequestId)
                    && Boolean.TRUE.equals(closeDecisionAck)) {
                PtkZapSessionState state = sessionStateByZapId.get(zapid);
                if (state != null) {
                    state.acknowledgeCloseRequest(closeRequest.id());
                }
                closeRequestAckByZapId.put(zapid, true);
                PtkZapSessionSnapshot refreshedSnapshot = sessionSnapshot(zapid);
                if (refreshedSnapshot != null && refreshedSnapshot.closeRequest() != null) {
                    closeRequest = refreshedSnapshot.closeRequest();
                }
            }
            boolean closeRequestMatchedAndAcked =
                    (closeRequest.id().equals(closeDecisionRequestId)
                                    && Boolean.TRUE.equals(closeDecisionAck))
                            || closeRequest.acknowledged();
            if (!closeRequestMatchedAndAcked) {
                return false;
            }
            if (snapshot.isV2PhysicallySafeToClose()) {
                return true;
            }
            if (snapshot.contractVersion() >= 2) {
                return canAcceptObservedV2SafeToClose(zapid);
            }
            String scanState = getStringField(closeDecision, "scanState");
            boolean terminalDecision =
                    snapshot.publisherDrained() && isTerminalProgressValue(null, scanState);
            if (terminalDecision) {
                PtkZapSessionState state = sessionStateByZapId.get(zapid);
                if (state != null) {
                    state.setSafeToClose(true);
                    state.markTerminalProgressSeen();
                }
            }
            if (terminalDecision) {
                return true;
            }
            boolean inferredClean =
                    explicitCloseRequestTerminalDecision && hasStaleAlertActivity(zapid);
            if (inferredClean) {
                PtkZapSessionState state = sessionStateByZapId.get(zapid);
                if (state != null) {
                    state.setSafeToClose(true);
                    state.markTerminalProgressSeen();
                }
                LOGGER.info(
                        "PTK_CONTRACT phase=legacy_inferred_clean_close zapid={} closeRequestId={} alertIdleMs={}",
                        zapid,
                        closeRequest.id(),
                        alertIdleMs(zapid));
            }
            return inferredClean;
        }

        private boolean canAcceptObservedV2SafeToClose(String zapid) {
            PtkZapSessionSnapshot snapshot = sessionSnapshot(zapid);
            if (snapshot == null || !snapshot.isV2PhysicallySafeToClose()) {
                return false;
            }
            PtkCloseRequestState closeRequest = snapshot.closeRequest();
            return closeRequest == null
                    || closeRequest.id().isBlank()
                    || closeRequest.acknowledged()
                    || Boolean.TRUE.equals(closeRequestAckByZapId.get(zapid));
        }

        private boolean isExplicitCloseRequestTerminalDecision(Map<String, Object> closeDecision) {
            if (closeDecision == null || closeDecision.isEmpty()) {
                return false;
            }
            if (!"safe_to_close".equals(getStringField(closeDecision, "decision"))) {
                return false;
            }
            String reason = getStringField(closeDecision, "reason");
            if (!"close_requested".equals(reason) && !"already_terminal".equals(reason)) {
                return false;
            }
            return isTerminalProgressValue(null, getStringField(closeDecision, "scanState"));
        }

        private Long alertIdleMs(String zapid) {
            Long alertAt = zapid != null ? lastAlertChangedAtMsByZapId.get(zapid) : null;
            return alertAt != null ? Math.max(0L, System.currentTimeMillis() - alertAt) : null;
        }

        private boolean hasStaleAlertActivity(String zapid) {
            Long idleMs = alertIdleMs(zapid);
            return idleMs == null || idleMs >= PtkCloseContract.BROWSER_CLOSE_ACTIVITY_STALE_MS;
        }

        private String activeCloseRequestId(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return null;
            }
            PtkZapSessionSnapshot snapshot = sessionSnapshot(zapid);
            if (snapshot != null && snapshot.closeRequest() != null) {
                return snapshot.closeRequest().id();
            }
            return closeRequestIdByZapId.get(zapid);
        }

        private void rememberV2ProgressState(String zapid, Map<String, Object> progressData) {
            if (zapid == null || zapid.isBlank() || !isV2Progress(progressData)) {
                return;
            }
            Integer version = getIntegerField(progressData, "contractVersion");
            if (version != null) {
                progressContractVersionByZapId.put(zapid, version);
            }
            Map<String, Object> publisher = getPublisherStateField(progressData);
            Boolean publisherDrained = getBooleanField(publisher, "drained");
            if (publisherDrained != null) {
                publisherDrainedByZapId.put(zapid, publisherDrained);
            }
            PtkZapSessionState state = sessionState(zapid);
            if (state != null) {
                state.rememberReleaseState(
                        getStringField(progressData, "completionStatus"),
                        getStringField(progressData, "releaseStatus"));
            }
            acknowledgeCloseRequestFromBody(
                    zapid,
                    getStringField(progressData, "sessionId"),
                    getStringField(progressData, "browserid"),
                    progressData,
                    "progress");
        }

        private boolean acknowledgeCloseRequestFromBody(
                String zapid,
                String sessionId,
                String browserid,
                Map<String, Object> body,
                String source) {
            String bodyCloseRequestId = getStringField(body, "closeRequestId");
            Boolean closeRequestAck = getBooleanField(body, "closeRequestAck");
            if (zapid == null
                    || zapid.isBlank()
                    || bodyCloseRequestId == null
                    || bodyCloseRequestId.isBlank()
                    || !Boolean.TRUE.equals(closeRequestAck)) {
                return false;
            }
            PtkZapSessionState state = sessionStateByZapId.get(zapid);
            PtkZapSessionSnapshot snapshot = state != null ? state.snapshot() : null;
            PtkCloseRequestState closeRequest = snapshot != null ? snapshot.closeRequest() : null;
            String activeCloseRequestId =
                    closeRequest != null ? closeRequest.id() : closeRequestIdByZapId.get(zapid);
            if (!bodyCloseRequestId.equals(activeCloseRequestId)) {
                LOGGER.debug(
                        "PTK ignored closeRequestAck for non-active request zapid={} requestId={} activeRequestId={} source={}",
                        zapid,
                        bodyCloseRequestId,
                        activeCloseRequestId,
                        source);
                return false;
            }
            if (state != null
                    && !state.isCloseRequestForSession(closeRequest, sessionId, browserid)) {
                LOGGER.debug(
                        "PTK ignored closeRequestAck for mismatched session zapid={} requestId={} sessionId={} browserid={} source={}",
                        zapid,
                        bodyCloseRequestId,
                        sessionId,
                        browserid,
                        source);
                return false;
            }
            closeRequestAckByZapId.put(zapid, true);
            if (state != null) {
                state.acknowledgeCloseRequest(bodyCloseRequestId);
                PtkZapSessionSnapshot ackSnapshot = state.snapshot();
                if (ackSnapshot.hasV2CleanTerminalEvidence()) {
                    state.setSafeToClose(true);
                    safeToCloseByZapId.put(zapid, true);
                }
            }
            logContractPhase(
                    "control_close_request_acknowledged",
                    zapid,
                    browserid,
                    Map.of(
                            "sessionId",
                            sessionId != null ? sessionId : "",
                            "closeRequestId",
                            bodyCloseRequestId,
                            "source",
                            source != null ? source : ""));
            return true;
        }

        private String ensureCloseRequest(String zapid, String reason) {
            if (zapid == null || zapid.isBlank()) {
                return null;
            }
            PtkZapSessionState state = sessionState(zapid);
            String existingMapValue = closeRequestIdByZapId.get(zapid);
            long nowMs = System.currentTimeMillis();
            PtkCloseRequestState closeRequest =
                    existingMapValue != null && !existingMapValue.isBlank()
                            ? state.ensureCloseRequest(
                                    existingMapValue,
                                    reason,
                                    closeRequestCreatedAtMsByZapId.getOrDefault(zapid, nowMs))
                            : state.ensureCloseRequest(reason, nowMs);
            String closeRequestId = closeRequest.id();
            boolean newRequest = closeRequestIdByZapId.putIfAbsent(zapid, closeRequestId) == null;
            closeRequestAckByZapId.putIfAbsent(zapid, closeRequest.acknowledged());
            closeRequestCreatedAtMsByZapId.putIfAbsent(zapid, closeRequest.createdAtMs());
            if (newRequest) {
                LOGGER.info(
                        "PTK_CONTRACT phase=graceful_stop_requested zapid={} closeRequestId={} reason={}",
                        zapid,
                        closeRequestId,
                        reason);
            }
            return closeRequestId;
        }

        private void addCloseControlResponse(Map<String, Object> response, String zapid) {
            addCloseControlResponse(response, zapid, null, null);
        }

        private void addCloseControlResponse(
                Map<String, Object> response, String zapid, String sessionId, String browserid) {
            if (response == null || zapid == null || zapid.isBlank()) {
                return;
            }
            PtkZapSessionSnapshot snapshot = sessionSnapshot(zapid);
            PtkCloseRequestState closeRequest = snapshot != null ? snapshot.closeRequest() : null;
            String closeRequestId =
                    closeRequest != null ? closeRequest.id() : closeRequestIdByZapId.get(zapid);
            if (closeRequestId == null || closeRequestId.isBlank()) {
                return;
            }
            PtkZapSessionState state = sessionStateByZapId.get(zapid);
            if (state != null
                    && !state.isCloseRequestForSession(closeRequest, sessionId, browserid)) {
                LOGGER.debug(
                        "PTK ignored control poll for mismatched session zapid={} closeRequestId={} sessionId={} browserid={}",
                        zapid,
                        closeRequestId,
                        sessionId,
                        browserid);
                return;
            }
            boolean closeAcked =
                    closeRequest != null
                            ? closeRequest.acknowledged()
                            : Boolean.TRUE.equals(closeRequestAckByZapId.get(zapid));
            if (closeAcked) {
                return;
            }
            response.put("closeRequested", true);
            response.put("closeRequestId", closeRequestId);
            response.put("mode", "graceful_stop_and_drain");
            String reason = closeRequest != null ? closeRequest.reason() : null;
            response.put(
                    "reason",
                    reason != null && !reason.isBlank()
                            ? reason
                            : "activity_stale_after_close_request");
            response.put("stopTimeoutMs", PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS);
            response.put("drainTimeoutMs", PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS);
        }

        private Map<String, Object> buildControlPollResponse(Map<String, Object> controlData) {
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("result", "OK");
            response.put("closeRequested", false);
            String zapid = getStringField(controlData, "zapid");
            String browserid = getStringField(controlData, "browserid");
            String sessionId = getStringField(controlData, "sessionId");
            if (zapid == null || zapid.isBlank()) {
                return response;
            }
            PtkZapSessionState state = sessionStateByZapId.get(zapid);
            if (state != null && browserid != null && !browserid.isBlank()) {
                browserIdByZapId.put(zapid, browserid);
            }
            if (state != null && state.matchesActiveSession(sessionId, browserid)) {
                state.rememberSessionContext(browserid, sessionId);
            } else if (state != null) {
                LOGGER.debug(
                        "PTK ignored control poll session context for mismatched session zapid={} sessionId={} browserid={}",
                        zapid,
                        sessionId,
                        browserid);
            }
            Map<String, Object> pollFields = new LinkedHashMap<>();
            pollFields.put("sessionId", sessionId != null ? sessionId : "");
            Integer activitySeq = getIntegerField(controlData, "activitySeq");
            if (activitySeq != null) {
                pollFields.put("activitySeq", activitySeq);
            }
            logContractPhase("control_poll", zapid, browserid, pollFields);
            acknowledgeCloseRequestFromBody(zapid, sessionId, browserid, controlData, "control");
            if (state != null
                    && PtkCloseContract.shouldCreateAdaptiveStaleCloseRequest(
                            state.snapshot(), sessionId, browserid, System.currentTimeMillis())) {
                ensureCloseRequest(zapid, "activity_stale_before_browser_close");
            }
            addCloseControlResponse(response, zapid, sessionId, browserid);
            if (Boolean.TRUE.equals(response.get("closeRequested"))) {
                logContractPhase(
                        "control_close_request_returned",
                        zapid,
                        browserid,
                        Map.of(
                                "sessionId",
                                sessionId != null ? sessionId : "",
                                "closeRequestId",
                                String.valueOf(response.get("closeRequestId"))));
            }
            return response;
        }

        private boolean isCurrentBrowserWithinScheduledTargetScope(
                ClientCallBackUtils ccbutils, String zapid) {
            if (ccbutils == null || zapid == null || zapid.isBlank()) {
                return false;
            }
            String targetUrl = targetUrlByZapId.get(zapid);
            if (targetUrl == null || targetUrl.isBlank()) {
                return false;
            }
            try {
                WebDriver driver = ccbutils.getWebDriver();
                String currentUrl = driver != null ? driver.getCurrentUrl() : null;
                return PtkUrlUtils.isSameOriginAndPathScoped(targetUrl, currentUrl);
            } catch (RuntimeException e) {
                LOGGER.debug(
                        "PTK closeContract could not pre-classify close target for zapid {}: {}",
                        zapid,
                        e.getMessage());
                return false;
            }
        }

        private Map<String, Object> buildCallbackOwnerWaitDecision(String zapid) {
            Map<String, Object> decision = new LinkedHashMap<>();
            decision.put("ok", true);
            decision.put("participant", "ptk");
            decision.put("decision", "wait");
            decision.put("scanState", scanStatus.getOrDefault(zapid, "running"));
            decision.put("statusBefore", scanStatus.getOrDefault(zapid, "running"));
            decision.put("sessionId", sessionIdByZapId.get(zapid));
            decision.put("stopRequested", false);
            decision.put("source", "callback_progress");
            decision.put("reason", "active_browser_work");
            return decision;
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

        private PtkZapSessionState sessionState(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return null;
            }
            return sessionStateByZapId.computeIfAbsent(zapid, PtkZapSessionState::new);
        }

        private PtkZapSessionSnapshot sessionSnapshot(String zapid) {
            PtkZapSessionState state = sessionStateByZapId.get(zapid);
            return state != null ? state.snapshot() : null;
        }

        private void rememberBrowserId(String zapid, String browserid) {
            if (zapid == null || zapid.isBlank() || browserid == null || browserid.isBlank()) {
                return;
            }
            browserIdByZapId.put(zapid, browserid);
            PtkZapSessionState state = sessionState(zapid);
            if (state != null) {
                state.rememberBrowserId(browserid);
            }
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
            long nowMs = System.currentTimeMillis();
            PtkZapSessionState state = sessionState(zapid);
            if (state != null) {
                state.markCallbackStart(nowMs);
            }
            return callbackFirstSeenAtMs.computeIfAbsent(zapid, key -> nowMs);
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
            PtkZapSessionState state = sessionState(zapid);
            int stateTotal =
                    state != null ? state.addAlerts(raised, System.currentTimeMillis()) : 0;
            int previous = alertsRaisedByZapId.getOrDefault(zapid, 0);
            int total = alertsRaisedByZapId.merge(zapid, Math.max(0, raised), Integer::sum);
            if (total != previous) {
                lastAlertChangedAtMsByZapId.put(zapid, System.currentTimeMillis());
            }
            return Math.max(total, stateTotal);
        }

        private int getAlertsRaisedTotal(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return 0;
            }
            PtkZapSessionSnapshot snapshot = sessionSnapshot(zapid);
            if (snapshot != null) {
                return Math.max(
                        snapshot.alertsRaisedTotal(), alertsRaisedByZapId.getOrDefault(zapid, 0));
            }
            return alertsRaisedByZapId.getOrDefault(zapid, 0);
        }

        private void markFirstAlertSeen(String zapid, long seenAtMs) {
            if (zapid == null || zapid.isBlank()) {
                return;
            }
            firstAlertSeenAtMs.putIfAbsent(zapid, seenAtMs);
            PtkZapSessionState state = sessionState(zapid);
            if (state != null) {
                state.markFirstAlertSeen(seenAtMs);
            }
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
            PtkZapSessionSnapshot snapshot = sessionSnapshot(zapid);
            if (snapshot != null && snapshot.newestActivityAt() != null) {
                return snapshot.newestActivityAt();
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
            PtkZapSessionSnapshot snapshot = sessionSnapshot(zapid);
            if (snapshot != null) {
                if (snapshot.contractVersion() > 0) {
                    extra.put("contractVersion", snapshot.contractVersion());
                }
                if (snapshot.completionStatus() != null && !snapshot.completionStatus().isBlank()) {
                    extra.put("completionStatus", snapshot.completionStatus());
                }
                if (snapshot.releaseStatus() != null && !snapshot.releaseStatus().isBlank()) {
                    extra.put("releaseStatus", snapshot.releaseStatus());
                }
                if (snapshot.closeRequest() != null) {
                    extra.put("closeRequestId", snapshot.closeRequest().id());
                    extra.put("closeRequestAck", snapshot.closeRequest().acknowledged());
                }
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

        private void markBrowserTaskClosed(
                String zapid, String browserid, String decision, String reason, long closedAtMs) {
            if (zapid == null || zapid.isBlank() || browserid == null || browserid.isBlank()) {
                return;
            }
            PtkBrowserTaskState task =
                    browserTaskStateByZapIdAndBrowserId.get(
                            PtkBrowserTaskState.key(zapid, browserid));
            if (task != null) {
                task.close(decision, reason, closedAtMs);
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
            lastEngineEvidenceSummaryByZapIdAndEngine
                    .entrySet()
                    .removeIf(entry -> entry.getKey().startsWith(zapid + "|"));
            lastProgressChangedAtMsByZapId.remove(zapid);
            lastAlertChangedAtMsByZapId.remove(zapid);
            progressContractVersionByZapId.remove(zapid);
            publisherDrainedByZapId.remove(zapid);
            closeRequestIdByZapId.remove(zapid);
            closeRequestAckByZapId.remove(zapid);
            closeRequestCreatedAtMsByZapId.remove(zapid);
            clientSpiderActivityTouchAtMsByZapId.remove(zapid);
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
            sessionStateByZapId.remove(zapid);
            browserTaskStateByZapIdAndBrowserId
                    .entrySet()
                    .removeIf(entry -> entry.getKey().startsWith(zapid + "|"));
            contractCallbackLogged.remove(zapid + ":config");
            contractCallbackLogged.remove(zapid + ":progress");
            configAppliedLogged.remove(zapid);
            targetResolvedLogged.remove(zapid);
            closeWaitActiveLogged.remove(zapid);
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

        private Map<String, Object> buildCallbackProgressWaitDecision(String zapid, String reason) {
            Map<String, Object> decision = new LinkedHashMap<>();
            decision.put("participant", "ptk");
            decision.put("decision", "wait");
            decision.put("scanState", scanStatus.getOrDefault(zapid, "running"));
            decision.put("statusBefore", scanStatus.getOrDefault(zapid, "running"));
            decision.put("progress", scanProgress.getOrDefault(zapid, 0));
            decision.put("stopRequested", false);
            decision.put("reason", reason);
            decision.put("source", "callback_progress");
            String sessionId = sessionIdByZapId.get(zapid);
            if (sessionId != null && !sessionId.isBlank()) {
                decision.put("sessionId", sessionId);
            }
            return decision;
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
            PtkZapSessionSnapshot snapshot = sessionSnapshot(zapid);
            if (snapshot != null && snapshot.closeDecisionAttemptedAtMs() != null) {
                return snapshot.closeDecisionAttemptedAtMs();
            }
            return PtkCloseContract.getCloseDecisionAttemptedAtMs(
                    closeDecisionAttemptedByZapId, zapid);
        }

        void markCloseDecisionAttempted(String zapid, long decidedAtMs) {
            PtkZapSessionState state = sessionState(zapid);
            if (state != null) {
                state.markCloseDecisionAttempted(decidedAtMs);
            }
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
                    const explicitCloseRequestId = arguments[3] || null;
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
                    const withCloseProof = (result, snapshot, requestAck) => {
                      const proof = snapshot && typeof snapshot === 'object' ? snapshot : {};
                      const publisherProof = proof.publisher && typeof proof.publisher === 'object'
                        ? proof.publisher
                        : (proof.zapPublisherDrain && typeof proof.zapPublisherDrain === 'object' ? proof.zapPublisherDrain : null);
                      result.contractVersion = proof.contractVersion || null;
                      if (!result.contractVersion && publisherProof) {
                        result.contractVersion = 2;
                      }
                      const resultStatus = statusOf(result);
                      const proofStatus = statusOf(proof);
                      result.terminalSeen = proof.terminalSeen === true || terminal.has(resultStatus) || terminal.has(proofStatus);
                      if (publisherProof) {
                        result.publisher = publisherProof;
                      }
                      if (proof.closeReadiness && typeof proof.closeReadiness === 'object') {
                        result.closeReadiness = proof.closeReadiness;
                      } else if (publisherProof) {
                        const publisherDrained = publisherProof.drained === true;
                        result.closeReadiness = {
                          safeToClose: result.terminalSeen === true && publisherDrained,
                          reason: result.terminalSeen === true
                            ? (publisherDrained ? 'terminal_publisher_drained' : 'publisher_not_drained')
                            : 'not_terminal',
                          terminal: result.terminalSeen === true,
                          publisherDrained
                        };
                      }
                      if (proof.closeRequestId) {
                        result.closeRequestId = proof.closeRequestId;
                      } else if (explicitCloseRequestId) {
                        result.closeRequestId = explicitCloseRequestId;
                      }
                      result.closeRequestAck = proof.closeRequestAck === true || requestAck === true;
                      return result;
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
                      const state = String(telemetry.status || engine.state || '').toLowerCase();
                      const phase = String(telemetry.phase || progress.phase || '').toLowerCase();
                      const workCounters = [
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
                      ];
                      if (workCounters.some((value) => numberOf(value) > 0)) return true;
                      const hasExplicitWorkCounters = workCounters.some((value) => value !== undefined && value !== null);
                      const idle =
                        telemetry.idle === true
                        || telemetry.isIdle === true
                        || progress.idle === true
                        || progress.isIdle === true
                        || state === 'idle'
                        || phase === 'idle';
                      if (idle && hasExplicitWorkCounters) return false;
                      return telemetry.isRunning === true
                        || telemetry.isScanRunning === true
                        || state === 'running'
                        || state === 'scanning';
                    };
                    const requiresTargetWindow = (engine) => {
                      return engine
                        && typeof engine === 'object'
                        && engine.targetWindowRequired === true;
                    };
                    const hasConcreteBrowserWork = (snapshot) => {
                      if (!snapshot || snapshot.ok !== true || !snapshot.engines || typeof snapshot.engines !== 'object') return true;
                      return Object.values(snapshot.engines).some((engine) => {
                        if (!requiresTargetWindow(engine)) return false;
                        if (!concreteEngineWork(engine)) return false;
                        return true;
                      });
                    };
                    const hasAnyEngineWork = (snapshot) => {
                      if (!snapshot || snapshot.ok !== true || !snapshot.engines || typeof snapshot.engines !== 'object') return true;
                      return Object.values(snapshot.engines).some((engine) => concreteEngineWork(engine));
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
                    const requestGracefulStopDirect = () => {
                      if (!explicitCloseRequestId) {
                        return Promise.resolve(null);
                      }
                      return sendZapCloseMessage(
                        'session-end',
                        {
                          wait: false,
                          options: {
                            sessionId: explicitSessionId,
                            source: 'zap_browser_close',
                            zapid: explicitZapId,
                            currentUrl: currentCloseUrl,
                            closeRequestId: explicitCloseRequestId,
                            closeRequestMode: 'graceful_stop_and_drain',
                            closeRequestReason: 'browser_close_requested',
                            stopTimeoutMs: bridgeTimeoutMs
                          }
                        },
                        Math.max(3000, callTimeoutMs - 500)
                      );
                    };
                    const buildAgentZapCloseOptions = () => ({
                      sessionId: explicitSessionId,
                      source: 'zap_browser_close',
                      zapid: explicitZapId,
                      currentUrl: currentCloseUrl,
                      closeRequestId: explicitCloseRequestId,
                      closeRequestMode: 'graceful_stop_and_drain',
                      closeRequestReason: 'browser_close_requested',
                      stopTimeoutMs: bridgeTimeoutMs,
                      wait: false
                    });
                    const readAgentProgress = (agent) => Promise.race([
                      Promise.resolve(agent.scanStatus(buildAgentZapCloseOptions())),
                      timeoutAfter('agent_scan_status', 3000)
                    ]);
                    const requestAgentGracefulStop = (agent) => {
                      if (!explicitCloseRequestId || !agent || typeof agent.stopScan !== 'function') {
                        return Promise.resolve(null);
                      }
                      return Promise.race([
                        Promise.resolve(agent.stopScan(buildAgentZapCloseOptions())),
                        timeoutAfter('agent_session_end', Math.max(3000, callTimeoutMs - 500))
                      ]);
                    };
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
                          const requestGracefulStop = () => {
                            if (!explicitCloseRequestId || typeof trustedAutomation.endSession !== 'function') {
                              return Promise.resolve(null);
                            }
                            return withTimeout(trustedAutomation.endSession({
                              sessionId: explicitSessionId,
                              source: 'zap_browser_close',
                              zapid: explicitZapId,
                              currentUrl: currentCloseUrl,
                              closeRequestId: explicitCloseRequestId,
                              closeRequestMode: 'graceful_stop_and_drain',
                              closeRequestReason: 'browser_close_requested',
                              stopTimeoutMs: bridgeTimeoutMs,
                              wait: false
                            }), 'session_end', Math.max(3000, callTimeoutMs - 500));
                          };
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
                            done(withCloseProof({
                              ok: true,
                              participant: 'ptk',
                              decision: 'safe_to_close',
                              scanState: statusBefore,
                              statusBefore,
                              sessionId: explicitSessionId,
                              reason: 'already_terminal',
                              stopVia: 'automation_bridge'
                            }, before, false));
                            return;
                          }
                          if (before && before.ok === true) {
                            const ownerClose = shouldStopForClose(before);
                            const concreteWork = hasConcreteBrowserWork(before);
                            const anyEngineWork = hasAnyEngineWork(before);
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
                            if (anyEngineWork && !explicitCloseRequestId) {
                              done({
                                ok: true,
                                participant: 'ptk',
                                decision: 'wait',
                                scanState: statusBefore || 'running',
                                statusBefore,
                                sessionId: explicitSessionId,
                                stopRequested: false,
                                stopVia: 'automation_bridge',
                                reason: 'active_browser_work'
                              });
                              return;
                            }
                          }
                          if (explicitCloseRequestId) {
                            const stopResult = await requestGracefulStop();
                            const after = await readProgress();
                            const afterStatus = statusOf(after);
                            if (after && after.ok === true && terminal.has(afterStatus)) {
                              done(withCloseProof({
                                ok: true,
                                participant: 'ptk',
                                decision: 'safe_to_close',
                                scanState: afterStatus,
                                statusBefore,
                                statusAfter: afterStatus,
                                sessionId: explicitSessionId,
                                reason: 'close_requested',
                                stopRequested: true,
                                closeRequestId: explicitCloseRequestId,
                                closeRequestAck: true,
                                stopVia: 'automation_bridge',
                                stopResult
                              }, after, true));
                              return;
                            }
                            done({
                              ok: true,
                              participant: 'ptk',
                              decision: 'wait',
                              scanState: afterStatus || statusBefore || 'stopping',
                              statusBefore,
                              statusAfter: afterStatus || null,
                              sessionId: explicitSessionId,
                              stopRequested: true,
                              closeRequestId: explicitCloseRequestId,
                              closeRequestAck: true,
                              stopVia: 'automation_bridge',
                              reason: 'graceful_stop_requested',
                              stopResult
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
                            done(withCloseProof({
                              ok: true,
                              participant: 'ptk',
                              decision: 'safe_to_close',
                              scanState: statusBefore,
                              statusBefore,
                              sessionId: explicitSessionId,
                              reason: 'already_terminal',
                              stopVia: 'direct_zap_close'
                            }, before, false));
                            return;
                          }
                          if (before && before.ok === true) {
                            const ownerClose = shouldStopForClose(before);
                            const concreteWork = hasConcreteBrowserWork(before);
                            const anyEngineWork = hasAnyEngineWork(before);
                            if (!ownerClose && !concreteWork) {
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
                            if (!ownerClose) {
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
                            if (ownerClose && anyEngineWork && !explicitCloseRequestId) {
                              done({
                                ok: true,
                                participant: 'ptk',
                                decision: 'wait',
                                scanState: statusBefore || 'running',
                                statusBefore,
                                sessionId: explicitSessionId,
                                stopRequested: false,
                                stopVia: 'direct_zap_close',
                                reason: 'active_browser_work'
                              });
                              return;
                            }
                            if (explicitCloseRequestId) {
                              const stopResult = await requestGracefulStopDirect();
                              const after = await readProgressDirect();
                              const afterStatus = statusOf(after);
                              if (after && after.ok === true && terminal.has(afterStatus)) {
                                done(withCloseProof({
                                  ok: true,
                                  participant: 'ptk',
                                  decision: 'safe_to_close',
                                  scanState: afterStatus,
                                  statusBefore,
                                  statusAfter: afterStatus,
                                  sessionId: explicitSessionId,
                                  stopRequested: true,
                                  reason: 'close_requested',
                                  closeRequestId: explicitCloseRequestId,
                                  closeRequestAck: true,
                                  stopVia: 'direct_zap_close',
                                  stopResult
                                }, after, true));
                                return;
                              }
                              done({
                                ok: true,
                                participant: 'ptk',
                                decision: 'wait',
                                scanState: afterStatus || statusBefore || 'stopping',
                                statusBefore,
                                statusAfter: afterStatus || null,
                                sessionId: explicitSessionId,
                                stopRequested: true,
                                stopVia: 'direct_zap_close',
                                reason: 'graceful_stop_requested',
                                closeRequestId: explicitCloseRequestId,
                                closeRequestAck: true,
                                stopResult
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
                          readAgentProgress(agent),
                          timeoutAfter('scan_status', 3000)
                        ]);
                        const statusBefore = String(before && before.status || '').toLowerCase();
                        if (before && before.ok === true && terminal.has(statusBefore)) {
                          done(withCloseProof({
                            ok: true,
                            participant: 'ptk',
                            decision: 'safe_to_close',
                            scanState: statusBefore,
                            statusBefore,
                            sessionId: before.sessionId || null,
                            reason: 'already_terminal'
                          }, before, false));
                          return;
                        }
                        if (explicitCloseRequestId) {
                          const stopResult = await requestAgentGracefulStop(agent);
                          const after = await readAgentProgress(agent);
                          const afterStatus = String(after && after.status || '').toLowerCase();
                          if (after && after.ok === true && terminal.has(afterStatus)) {
                            done(withCloseProof({
                              ok: true,
                              participant: 'ptk',
                              decision: 'safe_to_close',
                              scanState: afterStatus,
                              statusBefore,
                              statusAfter: afterStatus,
                              sessionId: after.sessionId || before && before.sessionId || explicitSessionId,
                              reason: 'close_requested',
                              stopRequested: true,
                              closeRequestId: explicitCloseRequestId,
                              closeRequestAck: true,
                              stopVia: 'ptk_agent',
                              stopResult
                            }, after, true));
                            return;
                          }
                          done({
                            ok: after && after.ok !== false,
                            participant: 'ptk',
                            decision: 'wait',
                            scanState: afterStatus || statusBefore || 'stopping',
                            statusBefore,
                            statusAfter: afterStatus || null,
                            sessionId: after && after.sessionId || before && before.sessionId || explicitSessionId,
                            stopRequested: true,
                            reason: 'graceful_stop_requested',
                            closeRequestId: explicitCloseRequestId,
                            closeRequestAck: true,
                            stopVia: 'ptk_agent',
                            stopResult
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
                            js.executeAsyncScript(
                                    script,
                                    ptkBridgeTimeoutMs,
                                    sessionId,
                                    zapid,
                                    closeRequestIdByZapId.get(zapid));
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
                            js.executeAsyncScript(
                                    script,
                                    ptkBridgeTimeoutMs,
                                    sessionId,
                                    zapid,
                                    closeRequestIdByZapId.get(zapid));
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
                            js.executeAsyncScript(
                                    script,
                                    ptkBridgeTimeoutMs,
                                    sessionId,
                                    zapid,
                                    closeRequestIdByZapId.get(zapid));
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

        @SuppressWarnings("unchecked")
        private void logEngineEvidenceIfChanged(
                String zapid,
                String browserid,
                String sessionId,
                String url,
                Map<String, Object> progressData,
                boolean terminalProgress) {
            if (zapid == null || zapid.isBlank() || progressData == null) {
                return;
            }
            Object enginesValue = progressData.get("engines");
            if (!(enginesValue instanceof Map<?, ?> rawEngines) || rawEngines.isEmpty()) {
                return;
            }
            rawEngines.forEach(
                    (engineNameValue, engineValue) -> {
                        if (!(engineNameValue instanceof String engineName)
                                || !(engineValue instanceof Map<?, ?> rawEngine)) {
                            return;
                        }
                        String engine = engineName.trim().toUpperCase();
                        if (engine.isBlank()) {
                            return;
                        }
                        Map<String, Object> engineData = (Map<String, Object>) rawEngine;
                        String status = getStringField(engineData, "status");
                        if (status == null || status.isBlank()) {
                            status = "unknown";
                        }
                        Integer progress = getIntegerField(engineData, "progress");
                        if (progress == null) {
                            progress = 0;
                        }
                        String completionStatus = getStringField(engineData, "completionStatus");
                        Map<String, Object> details = getMapField(engineData, "details");
                        String engineError = getStringField(details, "error");
                        String engineMessage = getStringField(details, "message");
                        String summary =
                                status
                                        + ":"
                                        + progress
                                        + ":"
                                        + (completionStatus != null ? completionStatus : "")
                                        + ":"
                                        + terminalProgress
                                        + ":"
                                        + (engineError != null ? engineError : "")
                                        + ":"
                                        + (engineMessage != null ? engineMessage : "")
                                        + ":"
                                        + getOptionalIntegerField(details, "agentReady")
                                        + ":"
                                        + getOptionalIntegerField(details, "findingsCount");
                        String evidenceKey = zapid + "|" + engine;
                        String previous =
                                lastEngineEvidenceSummaryByZapIdAndEngine.put(evidenceKey, summary);
                        if (summary.equals(previous)) {
                            return;
                        }
                        Map<String, Object> extra = new LinkedHashMap<>();
                        if (sessionId != null && !sessionId.isBlank()) {
                            extra.put("sessionId", sessionId);
                        }
                        extra.put("engine", engine);
                        extra.put("status", status);
                        extra.put("progress", progress);
                        if (completionStatus != null && !completionStatus.isBlank()) {
                            extra.put("completionStatus", completionStatus);
                        }
                        extra.put("terminal", terminalProgress);
                        copyEngineDetail(extra, details, "agentReady");
                        copyEngineDetail(extra, details, "findingsCount");
                        copyEngineDetail(extra, details, "runtimeSignalsAccepted");
                        copyEngineDetail(extra, details, "findingReportsAccepted");
                        copyEngineDetail(extra, details, "totalFiles");
                        copyEngineDetail(extra, details, "completedFiles");
                        copyEngineDetail(extra, details, "error");
                        copyEngineDetail(extra, details, "message");
                        logEngineEvidence(zapid, browserid, url, extra);
                    });
        }

        private void logEngineEvidence(
                String zapid, String browserid, String url, Map<String, Object> extra) {
            StringBuilder summary = new StringBuilder();
            summary.append("PTK_ENGINE_EVIDENCE");
            if (zapid != null && !zapid.isBlank()) {
                summary.append(" zapid=").append(zapid);
            }
            if (browserid != null && !browserid.isBlank()) {
                summary.append(" browserid=").append(browserid);
            }
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

        private void copyEngineDetail(
                Map<String, Object> target, Map<String, Object> details, String key) {
            if (target == null || details == null || key == null || key.isBlank()) {
                return;
            }
            Object value = details.get(key);
            if (value instanceof Number || value instanceof Boolean) {
                target.put(key, value);
            } else if (value instanceof String text && !text.isBlank() && !text.contains(" ")) {
                target.put(key, text);
            }
        }

        private Integer getOptionalIntegerField(Map<String, Object> body, String key) {
            return body != null ? getIntegerField(body, key) : null;
        }

        private void logContractPhase(
                String phase, String zapid, String browserid, Map<String, Object> extra) {
            if (phase == null || phase.isBlank()) {
                return;
            }
            StringBuilder summary = new StringBuilder("PTK_CONTRACT phase=").append(phase);
            if (zapid != null && !zapid.isBlank()) {
                summary.append(" zapid=").append(zapid);
            }
            if (browserid != null && !browserid.isBlank()) {
                summary.append(" browserid=").append(browserid);
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
            // No longer used
            return null;
        }

        @Override
        public String handleCallBack(
                HttpMessage msg, ClientCallBackImplementor.ClientCallBackContext cbContext) {
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
                logBrowserEvidence(zapid, browserid, "config_callback", null, null);
                if (zapid != null && contractCallbackLogged.add(zapid + ":config")) {
                    logContractPhase(
                            "callback_detected",
                            zapid,
                            browserid,
                            Map.of(
                                    "path",
                                    "config",
                                    "mode",
                                    getParam().isAutomatedScanningEnabled()
                                            ? "automated"
                                            : "manual"));
                }
                String configJson = getConfigJsonForRequest(requestData, cbContext);
                msg.getResponseBody().setBody(configJson);
                long finishedAt = System.currentTimeMillis();
                Map<String, Object> configResponse = parseRequestBody(configJson);
                Map<String, Object> configServedFields = new LinkedHashMap<>();
                configServedFields.put("durationMs", finishedAt - startedAt);
                configServedFields.put("automated", getParam().isAutomatedScanningEnabled());
                String targetUrl = getStringField(requestData, "targetUrl");
                if (targetUrl != null && !targetUrl.isBlank()) {
                    configServedFields.put("targetUrl", targetUrl);
                }
                Integer seedCount = getIntegerField(configResponse, "zapHistorySeedCount");
                if (seedCount != null) {
                    configServedFields.put("zapHistorySeedCount", seedCount);
                }
                String seedScope = getStringField(configResponse, "zapHistorySeedScope");
                if (seedScope != null && !seedScope.isBlank()) {
                    configServedFields.put("zapHistorySeedScope", seedScope);
                }
                logContractPhase("config_served", zapid, browserid, configServedFields);
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
                Map<String, Object> requestData = parseRequestBody(requestBody);
                String zapid = getStringField(requestData, "zapid");
                String browserid = getStringField(requestData, "browserid");
                Map<String, Object> alertReceivedFields = new LinkedHashMap<>();
                alertReceivedFields.put("batchId", requestData.get("batchId"));
                alertReceivedFields.put("batchSeq", requestData.get("batchSeq"));
                logContractPhase("alert_batch_received", zapid, browserid, alertReceivedFields);
                PtkAlertHandler.AlertBatchAck ack =
                        PtkAlertHandler.processAlertBatchWithAck(requestBody);
                int raised = ack.alertsRaised;
                Map<String, Object> alertAckFields = new LinkedHashMap<>();
                alertAckFields.put("batchId", ack.batchId);
                alertAckFields.put("batchSeq", ack.batchSeq);
                alertAckFields.put("received", ack.received);
                alertAckFields.put("accepted", ack.accepted);
                alertAckFields.put("alertsRaised", ack.alertsRaised);
                alertAckFields.put("reasonCounts", ack.reasonCounts);
                logContractPhase("alert_batch_acknowledged", zapid, browserid, alertAckFields);
                rememberBrowserId(zapid, browserid);
                boolean firstAlert = zapid != null && firstAlertLogged.add(zapid);
                markCallbackStart(zapid);
                msg.getResponseBody().setBody(GSON.toJson(ack));
                long finishedAt = System.currentTimeMillis();
                Long sinceFirstMs = getElapsedSinceFirst(zapid, finishedAt);
                int totalAlerts = rememberAlertsRaised(zapid, raised);
                if (ack.accepted > 0) {
                    touchActiveClientSpidersForPtkActivity(
                            zapid,
                            getEvidenceTargetUrl(zapid, null),
                            "alert_batch_acknowledged",
                            finishedAt);
                }
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
            } else if (uri.contains(PTK_CONTROL_PATH)) {
                String requestBody = msg.getRequestBody().toString();
                try {
                    Map<String, Object> controlData = parseRequestBody(requestBody);
                    msg.getResponseBody()
                            .setBody(GSON.toJson(buildControlPollResponse(controlData)));
                } catch (Exception e) {
                    LOGGER.warn("PTK failed to parse control body: {}", requestBody, e);
                    msg.getResponseBody().setBody("{\"result\":\"FAIL\",\"closeRequested\":false}");
                }
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
                        if (contractCallbackLogged.add(zapid + ":progress")) {
                            logContractPhase(
                                    "callback_detected",
                                    zapid,
                                    browserid,
                                    Map.of("path", "progress"));
                        }
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
                        boolean v2Progress = isV2Progress(progressData);
                        rememberV2ProgressState(zapid, progressData);
                        rememberBrowserId(zapid, browserid);
                        boolean sessionEstablished = false;
                        if (sessionId != null && !sessionId.isBlank()) {
                            sessionIdByZapId.put(zapid, sessionId);
                            sessionEstablished = sessionEstablishedLogged.add(zapid);
                        }
                        if (configAppliedLogged.add(zapid)) {
                            logContractPhase(
                                    "config_applied",
                                    zapid,
                                    browserid,
                                    Map.of(
                                            "sessionId",
                                            sessionId != null ? sessionId : "",
                                            "progress",
                                            progress.intValue(),
                                            "status",
                                            status != null ? status : ""));
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
                            } else if (targetResolvedLogged.add(zapid)) {
                                logContractPhase(
                                        "target_resolved",
                                        zapid,
                                        browserid,
                                        Map.of("targetUrl", evidenceTargetUrl));
                            }
                        } else {
                            evidenceTargetUrl = getEvidenceTargetUrl(zapid, null);
                        }
                        // safeToClose is accepted only after ZAP has explicitly asked the
                        // WebDriver-controlled tab for a PTK close decision. This prevents
                        // ordinary page/progress callbacks from pre-setting close readiness.
                        boolean acceptedSafeToClose = false;
                        if (safeToClose != null) {
                            boolean v2PhysicalSafeToClose =
                                    v2Progress
                                            && isV2ProgressPhysicallySafeToClose(
                                                    zapid, progressData);
                            if (v2PhysicalSafeToClose
                                    || PtkCloseContract.canAcceptSafeToClose(
                                            closeDecisionAttemptedByZapId, zapid)) {
                                safeToCloseByZapId.put(zapid, safeToClose);
                                acceptedSafeToClose =
                                        v2Progress
                                                ? v2PhysicalSafeToClose
                                                : Boolean.TRUE.equals(safeToClose);
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
                                v2Progress
                                        ? isV2ProgressTerminalEvidence(progressData)
                                        : (acceptedSafeToClose
                                                || isTerminalProgressValue(
                                                        progress.intValue(), status));
                        boolean manualModeCallbackOnly =
                                isManualModeCallbackProgress(
                                        zapid, progress.intValue(), status, sessionId);
                        String progressSummary = summarizeProgressPayload(progressData);
                        Integer contractVersion = getIntegerField(progressData, "contractVersion");
                        Integer activitySeq = getIntegerField(progressData, "activitySeq");
                        Map<String, Object> publisher = getMapField(progressData, "publisher");
                        Boolean publisherDrained = getBooleanField(publisher, "drained");
                        PtkZapSessionState state = sessionState(zapid);
                        PtkZapSessionState.ProgressActivity stateProgress =
                                state != null
                                        ? state.recordProgress(
                                                browserid,
                                                sessionId,
                                                progress.intValue(),
                                                status,
                                                progressSummary,
                                                terminalProgress,
                                                contractVersion,
                                                publisherDrained,
                                                activitySeq,
                                                finishedAt)
                                        : null;
                        boolean outOfOrderProgress =
                                stateProgress != null && stateProgress.outOfOrder();
                        boolean ignoredAfterTerminal =
                                stateProgress != null && stateProgress.ignoredAfterTerminal();
                        if (outOfOrderProgress) {
                            terminalProgress = false;
                            if (v2Progress) {
                                safeToCloseByZapId.remove(zapid);
                            }
                            LOGGER.debug(
                                    "PTK ignored out-of-order progress zapid={} activitySeq={}",
                                    zapid,
                                    activitySeq);
                        } else if (ignoredAfterTerminal) {
                            LOGGER.debug(
                                    "PTK ignored non-terminal progress after terminal evidence zapid={} activitySeq={} progress={} status={}",
                                    zapid,
                                    activitySeq,
                                    progress.intValue(),
                                    status);
                        } else {
                            logEngineEvidenceIfChanged(
                                    zapid,
                                    browserid,
                                    sessionId,
                                    evidenceTargetUrl,
                                    progressData,
                                    terminalProgress);
                            scanProgress.put(zapid, progress.intValue());
                            if (status != null && !status.isBlank()) {
                                scanStatus.put(zapid, status);
                            }
                            if (terminalProgress && zapid != null && !zapid.isBlank()) {
                                terminalProgressLogged.add(zapid);
                                if (v2Progress && canAcceptObservedV2SafeToClose(zapid)) {
                                    safeToCloseByZapId.put(zapid, true);
                                } else if (!v2Progress) {
                                    safeToCloseByZapId.put(zapid, true);
                                }
                            }
                        }
                        String previousProgressSummary =
                                !outOfOrderProgress
                                                && !ignoredAfterTerminal
                                                && zapid != null
                                                && !zapid.isBlank()
                                                && !progressSummary.isBlank()
                                        ? lastProgressSummaryByZapId.put(zapid, progressSummary)
                                        : null;
                        boolean progressChanged =
                                !outOfOrderProgress
                                        && !ignoredAfterTerminal
                                        && zapid != null
                                        && !zapid.isBlank()
                                        && !progressSummary.isBlank()
                                        && !progressSummary.equals(previousProgressSummary);
                        if ((firstProgress || progressChanged)
                                && zapid != null
                                && !zapid.isBlank()
                                && !progressSummary.isBlank()) {
                            lastProgressChangedAtMsByZapId.put(zapid, finishedAt);
                            LOGGER.info(
                                    "PTK_CONTRACT phase=progress_activity_changed zapid={} browserid={} sessionId={} contractVersion={} activitySeq={} progress={} status={}",
                                    zapid,
                                    browserid,
                                    sessionId,
                                    getIntegerField(progressData, "contractVersion"),
                                    getIntegerField(progressData, "activitySeq"),
                                    progress.intValue(),
                                    status != null ? status : "");
                        }
                        if (!terminalProgress
                                && !manualModeCallbackOnly
                                && (progressChanged
                                        || sessionEstablished
                                        || hasRecentMeaningfulActivity(zapid, finishedAt))) {
                            touchActiveClientSpidersForPtkActivity(
                                    zapid,
                                    evidenceTargetUrl,
                                    "progress_activity_changed",
                                    finishedAt);
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
                                logContractPhase(
                                        "session_started",
                                        zapid,
                                        browserid,
                                        Map.of(
                                                "sessionId",
                                                sessionId,
                                                "progress",
                                                progress.intValue(),
                                                "status",
                                                status != null ? status : ""));
                                logBrowserEvidence(
                                        zapid,
                                        browserid,
                                        "ptk_session_established",
                                        evidenceTargetUrl,
                                        evidenceExtra);
                            }
                            if (terminalProgress) {
                                logContractPhase(
                                        "terminal_progress_seen",
                                        zapid,
                                        browserid,
                                        Map.of(
                                                "sessionId",
                                                sessionId != null ? sessionId : "",
                                                "progress",
                                                progress.intValue(),
                                                "status",
                                                status != null ? status : ""));
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
                        if (v2Progress
                                && terminalProgress
                                && Boolean.TRUE.equals(getBooleanField(publisher, "drained"))) {
                            Map<String, Object> publisherDrainedFields = new LinkedHashMap<>();
                            publisherDrainedFields.put(
                                    "sessionId", sessionId != null ? sessionId : "");
                            publisherDrainedFields.put(
                                    "contractVersion",
                                    getIntegerField(progressData, "contractVersion"));
                            publisherDrainedFields.put(
                                    "activitySeq", getIntegerField(progressData, "activitySeq"));
                            publisherDrainedFields.put(
                                    "closeRequestId",
                                    getStringField(progressData, "closeRequestId") != null
                                            ? getStringField(progressData, "closeRequestId")
                                            : "");
                            publisherDrainedFields.put(
                                    "closeRequestAck",
                                    Boolean.TRUE.equals(
                                            getBooleanField(progressData, "closeRequestAck")));
                            publisherDrainedFields.put("progress", progress.intValue());
                            publisherDrainedFields.put("status", status != null ? status : "");
                            logContractPhase(
                                    "publisher_drained", zapid, browserid, publisherDrainedFields);
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
                    addCloseControlResponse(
                            response,
                            getStringField(progressData, "zapid"),
                            getStringField(progressData, "sessionId"),
                            getStringField(progressData, "browserid"));
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
            if (browserid != null && !browserid.isBlank()) {
                browserTaskStateByZapIdAndBrowserId.put(
                        PtkBrowserTaskState.key(zapid, browserid),
                        PtkBrowserTaskState.loaded(
                                zapid, browserid, currentUrl, System.currentTimeMillis()));
            }
            closedZapIds.remove(zapid);
            browserCoverageTargetUrlByZapId.remove(zapid);
            sessionEstablishedLogged.remove(zapid);
            logContractPhase(
                    "browser_loaded",
                    zapid,
                    browserid,
                    Map.of("url", currentUrl, "source", "browserLaunched"));
            logBrowserEvidence(
                    zapid,
                    browserid,
                    "browser_loaded",
                    currentUrl,
                    Map.of("source", "browserLaunched"));
            long start = System.currentTimeMillis();
            logTimingSummary(zapid, browserid, "browser_launch.begin", null, Map.of());
            Map<String, Object> handshake =
                    awaitCallbackBootstrapHandshake(ssutils.getWebDriver(), zapid, currentUrl);
            long waitedMs = System.currentTimeMillis() - start;
            boolean callbackSeen = Boolean.TRUE.equals(handshake.get("handshakeSeen"));
            Map<String, Object> extra = new LinkedHashMap<>();
            extra.put("waitedMs", waitedMs);
            extra.put("callbackSeen", callbackSeen);
            extra.putAll(handshake);
            logContractPhase("browser_launch_callback_handshake", zapid, browserid, handshake);
            logTimingSummary(zapid, browserid, "browser_launch.end", null, extra);
        }

        private Map<String, Object> awaitCallbackBootstrapHandshake(
                WebDriver driver, String zapid, String callbackUrl) {
            if (!isZapCallbackBootstrapUrl(callbackUrl)) {
                return new PtkCloseContract.CallbackBootstrapHandshakeResult(
                                hasCallbackHandshake(zapid),
                                0L,
                                0,
                                "java_callback_not_applicable",
                                false,
                                null,
                                false)
                        .toLogFields();
            }
            return PtkCloseContract.awaitCallbackBootstrapHandshake(
                            () -> hasCallbackHandshake(zapid),
                            () -> reloadZapCallbackBootstrapPage(driver, callbackUrl),
                            System::currentTimeMillis,
                            Thread::sleep)
                    .toLogFields();
        }

        private boolean isZapCallbackBootstrapUrl(String url) {
            return url != null
                    && url.contains("zapCallBackUrl")
                    && extractZapIdFromUrl(url) != null;
        }

        private void reloadZapCallbackBootstrapPage(WebDriver driver, String callbackUrl) {
            if (driver == null || !isZapCallbackBootstrapUrl(callbackUrl)) {
                return;
            }
            driver.navigate().to(callbackUrl);
        }

        private boolean hasCallbackHandshake(String zapid) {
            return zapid != null
                    && !zapid.isBlank()
                    && (callbackFirstSeenAtMs.containsKey(zapid)
                            || scanProgress.containsKey(zapid));
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
            logContractPhase(
                    "browser_close_requested",
                    zapid,
                    browserid,
                    Map.of("maxWallClockMs", PtkCloseContract.BROWSER_CLOSE_MAX_WALL_CLOCK_MS));
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
            boolean ownerTargetClose = isCurrentBrowserWithinScheduledTargetScope(ccbutils, zapid);
            boolean hadProgressBeforeClose = scanProgress.containsKey(zapid);
            boolean callbackObservedOwnerSession =
                    ownerTargetClose && hadProgressBeforeClose && hasSessionId(zapid);
            Map<String, Object> closeDecision =
                    callbackObservedOwnerSession && !isSafeToClose(zapid)
                            ? buildCallbackOwnerWaitDecision(zapid)
                            : requestPtkCloseDecision(ccbutils, zapid, closeDeadlineMs);
            if (!"callback_progress".equals(getStringField(closeDecision, "source"))) {
                markCloseDecisionAttempted(zapid, System.currentTimeMillis());
            }
            String initialDecision = getStringField(closeDecision, "decision");
            String initialScanState = getStringField(closeDecision, "scanState");
            if (canAcceptCloseDecisionSafeToClose(
                    zapid,
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
                markCloseDecisionAttempted(zapid, System.currentTimeMillis());
                initialDecision = getStringField(closeDecision, "decision");
                initialScanState = getStringField(closeDecision, "scanState");
                if (canAcceptCloseDecisionSafeToClose(
                        zapid,
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
                    markCloseDecisionAttempted(zapid, System.currentTimeMillis());
                    initialDecision = getStringField(closeDecision, "decision");
                    initialScanState = getStringField(closeDecision, "scanState");
                    if (canAcceptCloseDecisionSafeToClose(
                            zapid,
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
                String reason = getStringField(closeDecision, "reason");
                markBrowserTaskClosed(
                        zapid,
                        browserid,
                        initialDecision != null ? initialDecision : "not_applicable",
                        reason,
                        System.currentTimeMillis());
                logContractPhase(
                        "local_tab_close",
                        zapid,
                        browserid,
                        Map.of(
                                "decision",
                                initialDecision != null ? initialDecision : "not_applicable",
                                "reason",
                                reason != null ? reason : ""));
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
                String reason = getStringField(closeDecision, "reason");
                markBrowserTaskClosed(
                        zapid,
                        browserid,
                        "browser_tab_safe_to_close",
                        reason,
                        System.currentTimeMillis());
                logContractPhase(
                        "local_tab_close",
                        zapid,
                        browserid,
                        Map.of(
                                "decision",
                                "browser_tab_safe_to_close",
                                "reason",
                                reason != null ? reason : "",
                                "waitedMs",
                                waitedMs));
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
                boolean recentActivity = hasRecentMeaningfulActivity(zapid, nowMs);
                if (recentActivity && closeWaitActiveLogged.add(zapid)) {
                    Map<String, Object> activeExtra = new LinkedHashMap<>();
                    activeExtra.put("waitedMs", nowMs - start);
                    activeExtra.put("progress", scanProgress.getOrDefault(zapid, 0));
                    activeExtra.put("status", scanStatus.getOrDefault(zapid, ""));
                    putActivitySummaryFields(activeExtra, zapid, nowMs);
                    logContractPhase("close_wait_active", zapid, browserid, activeExtra);
                }
                if (!recentActivity
                        && !ownerTargetClose
                        && activeCloseRequestId(zapid) == null
                        && hasCloseBudget(closeDeadlineMs, 2_500L)) {
                    closeDecision = requestPtkCloseDecision(ccbutils, zapid, closeDeadlineMs);
                    if (!"callback_progress".equals(getStringField(closeDecision, "source"))) {
                        markCloseDecisionAttempted(zapid, System.currentTimeMillis());
                    }
                    if (PtkCloseContract.isBrowserLocalTabSafeToCloseDecision(closeDecision)) {
                        long waitedMs = System.currentTimeMillis() - start;
                        String reason = getStringField(closeDecision, "reason");
                        markBrowserTaskClosed(
                                zapid,
                                browserid,
                                "browser_tab_safe_to_close",
                                reason,
                                System.currentTimeMillis());
                        logContractPhase(
                                "local_tab_close",
                                zapid,
                                browserid,
                                Map.of(
                                        "decision",
                                        "browser_tab_safe_to_close",
                                        "reason",
                                        reason != null ? reason : "",
                                        "waitedMs",
                                        waitedMs));
                        logCloseContractDecision(
                                zapid,
                                browserid,
                                getStringField(closeDecision, "decision"),
                                getStringField(closeDecision, "scanState"),
                                waitedMs,
                                scanProgress.getOrDefault(zapid, 0),
                                scanStatus.getOrDefault(zapid, ""),
                                closeDecision);
                        return;
                    }
                    if (PtkCloseContract.isActiveBrowserWorkCloseDecision(closeDecision)) {
                        recentActivity = true;
                        Map<String, Object> activeExtra = new LinkedHashMap<>();
                        activeExtra.put("waitedMs", System.currentTimeMillis() - start);
                        activeExtra.put("progress", scanProgress.getOrDefault(zapid, 0));
                        activeExtra.put("status", scanStatus.getOrDefault(zapid, ""));
                        activeExtra.put("reason", "active_browser_work");
                        putActivitySummaryFields(activeExtra, zapid, System.currentTimeMillis());
                        logContractPhase("close_wait_active", zapid, browserid, activeExtra);
                        logCloseContractDecision(
                                zapid,
                                browserid,
                                getStringField(closeDecision, "decision"),
                                getStringField(closeDecision, "scanState"),
                                System.currentTimeMillis() - start,
                                scanProgress.getOrDefault(zapid, 0),
                                scanStatus.getOrDefault(zapid, ""),
                                closeDecision);
                    } else if (canAcceptCloseDecisionSafeToClose(
                            zapid,
                            closeDecision,
                            scanProgress.getOrDefault(zapid, 0),
                            scanStatus.getOrDefault(zapid, ""))) {
                        safeToCloseByZapId.put(zapid, true);
                    }
                }
                if (!recentActivity && staleCloseLogged.add(zapid)) {
                    String closeRequestId =
                            ensureCloseRequest(zapid, "activity_stale_after_close_request");
                    Map<String, Object> staleExtra = new LinkedHashMap<>();
                    staleExtra.put("reason", "activity_stale_waiting_for_terminal");
                    staleExtra.put("stopRequested", true);
                    if (closeRequestId != null && !closeRequestId.isBlank()) {
                        staleExtra.put("closeRequestId", closeRequestId);
                    }
                    LOGGER.info(
                            "PTK_CONTRACT phase=close_wait_stale zapid={} browserid={} waitedMs={} progress={} status={}",
                            zapid,
                            browserid,
                            nowMs - start,
                            scanProgress.getOrDefault(zapid, 0),
                            scanStatus.getOrDefault(zapid, ""));
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
                    if (hasCloseBudget(closeDeadlineMs, 2_500L)) {
                        closeDecision = requestPtkCloseDecision(ccbutils, zapid, closeDeadlineMs);
                        if (!"callback_progress".equals(getStringField(closeDecision, "source"))) {
                            markCloseDecisionAttempted(zapid, System.currentTimeMillis());
                        }
                        if (PtkCloseContract.isBrowserLocalTabSafeToCloseDecision(closeDecision)) {
                            long waitedMs = System.currentTimeMillis() - start;
                            String reason = getStringField(closeDecision, "reason");
                            markBrowserTaskClosed(
                                    zapid,
                                    browserid,
                                    "browser_tab_safe_to_close",
                                    reason,
                                    System.currentTimeMillis());
                            logContractPhase(
                                    "local_tab_close",
                                    zapid,
                                    browserid,
                                    Map.of(
                                            "decision",
                                            "browser_tab_safe_to_close",
                                            "reason",
                                            reason != null ? reason : "",
                                            "waitedMs",
                                            waitedMs));
                            logCloseContractDecision(
                                    zapid,
                                    browserid,
                                    getStringField(closeDecision, "decision"),
                                    getStringField(closeDecision, "scanState"),
                                    waitedMs,
                                    scanProgress.getOrDefault(zapid, 0),
                                    scanStatus.getOrDefault(zapid, ""),
                                    closeDecision);
                            return;
                        }
                        if (canAcceptCloseDecisionSafeToClose(
                                zapid,
                                closeDecision,
                                scanProgress.getOrDefault(zapid, 0),
                                scanStatus.getOrDefault(zapid, ""))) {
                            safeToCloseByZapId.put(zapid, true);
                        }
                        logCloseContractDecision(
                                zapid,
                                browserid,
                                getStringField(closeDecision, "decision") != null
                                        ? getStringField(closeDecision, "decision")
                                        : "wait",
                                getStringField(closeDecision, "scanState"),
                                System.currentTimeMillis() - start,
                                scanProgress.getOrDefault(zapid, 0),
                                scanStatus.getOrDefault(zapid, ""),
                                closeDecision);
                    }
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
                    PtkZapSessionSnapshot forcedSnapshot = sessionSnapshot(zapid);
                    if (forcedSnapshot != null) {
                        summaryExtra.put("contractVersion", forcedSnapshot.contractVersion());
                        summaryExtra.put("publisherDrained", forcedSnapshot.publisherDrained());
                        summaryExtra.put(
                                "terminalProgressSeen", forcedSnapshot.terminalProgressSeen());
                        if (forcedSnapshot.closeRequest() != null) {
                            summaryExtra.put("closeRequestId", forcedSnapshot.closeRequest().id());
                            summaryExtra.put(
                                    "closeRequestAck",
                                    forcedSnapshot.closeRequest().acknowledged());
                        }
                    }
                    markBrowserTaskClosed(
                            zapid,
                            browserid,
                            "forced_closed",
                            String.valueOf(summaryExtra.get("reason")),
                            System.currentTimeMillis());
                    LOGGER.warn(
                            "PTK browserClosing uuid={} forced=true waitedMs={} progress={} status={}",
                            ccbutils.getUuid(),
                            (System.currentTimeMillis() - start),
                            scanProgress.get(zapid),
                            scanStatus.getOrDefault(zapid, ""));
                    logContractPhase("forced_close", zapid, browserid, summaryExtra);
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
                        && !hasRecentMeaningfulActivity(zapid, System.currentTimeMillis())
                        && hasCloseBudget(closeDeadlineMs, 2_500L)) {
                    closeDecision = requestPtkCloseDecision(ccbutils, zapid, closeDeadlineMs);
                    if (!"callback_progress".equals(getStringField(closeDecision, "source"))) {
                        markCloseDecisionAttempted(zapid, System.currentTimeMillis());
                    }
                    String followUpDecision = getStringField(closeDecision, "decision");
                    String followUpScanState = getStringField(closeDecision, "scanState");
                    if (PtkCloseContract.isBrowserLocalTabSafeToCloseDecision(closeDecision)) {
                        long waitedMs = System.currentTimeMillis() - start;
                        String reason = getStringField(closeDecision, "reason");
                        markBrowserTaskClosed(
                                zapid,
                                browserid,
                                "browser_tab_safe_to_close",
                                reason,
                                System.currentTimeMillis());
                        logContractPhase(
                                "local_tab_close",
                                zapid,
                                browserid,
                                Map.of(
                                        "decision",
                                        "browser_tab_safe_to_close",
                                        "reason",
                                        reason != null ? reason : "",
                                        "waitedMs",
                                        waitedMs));
                        logCloseContractDecision(
                                zapid,
                                browserid,
                                followUpDecision != null
                                        ? followUpDecision
                                        : "browser_tab_safe_to_close",
                                followUpScanState,
                                waitedMs,
                                scanProgress.getOrDefault(zapid, 0),
                                scanStatus.getOrDefault(zapid, ""),
                                closeDecision);
                        return;
                    }
                    if (canAcceptCloseDecisionSafeToClose(
                            zapid,
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
            PtkZapSessionSnapshot cleanSnapshot = sessionSnapshot(zapid);
            if (cleanSnapshot != null) {
                summaryExtra.put("contractVersion", cleanSnapshot.contractVersion());
                summaryExtra.put("publisherDrained", cleanSnapshot.publisherDrained());
                summaryExtra.put("terminalProgressSeen", cleanSnapshot.terminalProgressSeen());
                if (cleanSnapshot.completionStatus() != null
                        && !cleanSnapshot.completionStatus().isBlank()) {
                    summaryExtra.put("completionStatus", cleanSnapshot.completionStatus());
                }
                if (cleanSnapshot.releaseStatus() != null
                        && !cleanSnapshot.releaseStatus().isBlank()) {
                    summaryExtra.put("releaseStatus", cleanSnapshot.releaseStatus());
                }
                if (cleanSnapshot.contractVersion() >= 2) {
                    summaryExtra.put("releaseClean", cleanSnapshot.isV2ReleaseClean());
                }
                if (cleanSnapshot.closeRequest() != null) {
                    summaryExtra.put("closeRequestId", cleanSnapshot.closeRequest().id());
                    summaryExtra.put(
                            "closeRequestAck", cleanSnapshot.closeRequest().acknowledged());
                }
            }
            markBrowserTaskClosed(
                    zapid,
                    browserid,
                    "safe_to_close",
                    getStringField(closeDecision, "reason"),
                    System.currentTimeMillis());
            logCloseContractDecision(
                    zapid,
                    browserid,
                    "safe_to_close",
                    effectiveFinalStatus,
                    (System.currentTimeMillis() - start),
                    100,
                    effectiveFinalStatus,
                    closeDecision);
            String closePhase =
                    cleanSnapshot != null
                                    && cleanSnapshot.contractVersion() >= 2
                                    && !cleanSnapshot.isV2ReleaseClean()
                            ? "incomplete_close"
                            : "clean_close";
            logContractPhase(closePhase, zapid, browserid, summaryExtra);
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
            if (progressContractVersionByZapId.getOrDefault(zapid, 0) >= 2) {
                return canAcceptObservedV2SafeToClose(zapid);
            }
            if (terminalProgressLogged.contains(zapid)) {
                return true;
            }
            return isTerminalProgressValue(scanProgress.get(zapid), scanStatus.get(zapid));
        }
    }
}
