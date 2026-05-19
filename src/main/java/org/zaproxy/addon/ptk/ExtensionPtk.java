package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.ExtensionAutomation;
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

/*
 * Browser close timeout model:
 * - BROWSER_CLOSE_TOTAL_WAIT_MS is the Java polling budget after the first PTK
 *   close decision has returned. ZAP waits this long for progress callbacks to
 *   report terminal state or safeToClose before forcing the browser closed.
 * - BROWSER_CLOSE_SCRIPT_TIMEOUT_MS is the Selenium async-script budget for a
 *   single close-decision call. It must be greater than the PTK stop budget so
 *   WebDriver can receive PTK's callback rather than timing out first.
 * - BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS is the stopTimeoutMs value sent both to the
 *   ZAP progress callback response and the injected PTK close-decision script.
 * - The injected script derives its internal call timeout directly from that
 *   stopTimeoutMs value; there is no separate JavaScript cap to keep in sync.
 * - Follow-up WebDriver decisions are attempted every
 *   BROWSER_CLOSE_FOLLOW_UP_DECISION_EVERY_ATTEMPTS slices while the Java polling
 *   budget remains open. The worst-case wall-clock bound is therefore
 *   BROWSER_CLOSE_MAX_WALL_CLOCK_MS.
 * - Browser sessions that reach close without any PTK progress get a bounded
 *   startup grace. This avoids closing a valid page too early when many
 *   WebDriver browsers are started concurrently and the PTK content/background
 *   handshake is delayed.
 */
final class PtkCloseContract {
    static final int BROWSER_CLOSE_MAX_ATTEMPTS = 12;
    static final long BROWSER_CLOSE_WAIT_SLICE_MS = 1000;
    static final long BROWSER_CLOSE_NO_PROGRESS_GRACE_MS = 25000;
    static final long BROWSER_CLOSE_AUTOMATION_DISABLED_GRACE_MS = 2500;
    static final long BROWSER_CLOSE_TOTAL_WAIT_MS =
            BROWSER_CLOSE_MAX_ATTEMPTS * BROWSER_CLOSE_WAIT_SLICE_MS;
    static final long BROWSER_CLOSE_SCRIPT_TIMEOUT_MS = 30000;
    static final int BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS = 25000;
    static final int BROWSER_CLOSE_FOLLOW_UP_DECISION_EVERY_ATTEMPTS = 5;
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
                    "PTK browser close script timeout must cover PTK stop timeout");
        }
    }

    private PtkCloseContract() {}

    static Long getCloseRequestedAtMs(Map<String, Long> closeRequestedByZapId, String zapid) {
        if (zapid == null || zapid.isBlank()) {
            return null;
        }
        return closeRequestedByZapId.get(zapid);
    }

    static void markCloseDecisionAttempted(
            Map<String, Long> closeRequestedByZapId, String zapid, long decidedAtMs) {
        if (zapid == null || zapid.isBlank()) {
            return;
        }
        closeRequestedByZapId.putIfAbsent(zapid, decidedAtMs);
    }

    static boolean canAcceptSafeToClose(Map<String, Long> closeRequestedByZapId, String zapid) {
        return getCloseRequestedAtMs(closeRequestedByZapId, zapid) != null;
    }

    static String normalizeHttpTargetUrl(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return null;
        }
        try {
            URI uri = new URI(targetUrl.trim()).normalize();
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return null;
            }
            if (uri.getHost() == null || uri.getHost().isBlank()) {
                return null;
            }
            return uri.toString();
        } catch (Exception e) {
            return null;
        }
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
        String reason = getString(closeDecision, "reason");
        if ("already_terminal".equals(reason)) {
            return true;
        }
        if (Boolean.TRUE.equals(closeDecision.get("zapProgressTerminalPosted"))) {
            return true;
        }
        Object zapTerminalPost = closeDecision.get("zapTerminalPost");
        if (zapTerminalPost instanceof Map<?, ?> terminalPost) {
            if (Boolean.TRUE.equals(terminalPost.get("posted"))) {
                return true;
            }
        }
        return Boolean.TRUE.equals(closeDecision.get("stopRequested"));
    }

    private static String getString(Map<String, Object> map, String key) {
        Object value = map != null ? map.get(key) : null;
        return value == null ? null : String.valueOf(value);
    }
}

public class ExtensionPtk extends ExtensionAdaptor implements ExampleAlertProvider {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionPtk.class);
    private static final String PREFIX = "ptk";
    private static final Gson GSON = new Gson();
    private static final List<String> PTK_CHROMIUM_BACKGROUND_ARGS =
            List.of(
                    "--disable-component-update",
                    "--disable-domain-reliability",
                    "--disable-search-engine-choice-screen",
                    "--no-default-browser-check",
                    "--proxy-bypass-list=<-loopback>;*.delivery.mp.microsoft.com;edgeassetservice.azureedge.net;edge.microsoft.com",
                    "--disable-features=AutofillServerCommunication,CertificateTransparencyComponentUpdater,EdgeShoppingAssistant,MediaRouter,OptimizationHints,msEdgeAssetDeliveryService,msEdgeHubApps");

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(
                    ExtensionClientIntegration.class,
                    ExtensionSelenium.class,
                    ExtensionAutomation.class);

    private ClientCallBackImplementor callBackImplementor;
    private PtkBrowserCoverageJob browserCoverageJob;
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
    private final Map<String, String> lastProgressSummaryByZapId = new ConcurrentHashMap<>();
    /*
     * safeToClose is advisory state accepted only through the ZAP callback flow for
     * the current zapid/WebDriver-controlled browser. Page scripts can observe the
     * DOM nonce used by PTK automation messages, so the nonce is a correlation guard,
     * not a secret; PTK background/session state remains the source of truth for
     * whether work is terminal.
     */
    private final Map<String, Boolean> safeToCloseByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> lastCloseDecisionByZapId = new ConcurrentHashMap<>();
    private final Map<String, Long> closeRequestedByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> sessionIdByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> targetUrlByZapId = new ConcurrentHashMap<>();
    private final Map<String, String> zapIdByWebDriverSessionId = new ConcurrentHashMap<>();
    private final Map<String, BrowserCoverageEvidence> browserCoverageByUrl =
            new ConcurrentHashMap<>();
    private final Set<String> firstProgressLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> firstAlertLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> terminalProgressLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> sessionEstablishedLogged = ConcurrentHashMap.newKeySet();
    private final Set<String> closedZapIds = ConcurrentHashMap.newKeySet();

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
        ExtensionAutomation extensionAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        if (extensionAutomation != null) {
            browserCoverageJob = new PtkBrowserCoverageJob(this);
            extensionAutomation.registerAutomationJob(browserCoverageJob);
        }
        ensurePtkSeleniumExtensionsConfigured(
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class));
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
        ExtensionAutomation extensionAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        if (extensionAutomation != null && browserCoverageJob != null) {
            extensionAutomation.unregisterAutomationJob(browserCoverageJob);
        }
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
            List<BrowserExtension> extensions = new ArrayList<>(options.getBrowserExtensions());
            boolean changed = false;
            changed |= ensureBrowserExtension(extensions, chromiumPath, Browser.CHROME, "Chromium");
            changed |= ensureBrowserExtension(extensions, xpiPath, Browser.FIREFOX, "Firefox");
            if (changed) {
                options.setBrowserExtensions(extensions);
            }
            ensurePtkSeleniumBrowserArguments(options);
            logConfiguredPtkExtensions(extensions);
        } catch (Exception e) {
            LOGGER.warn("PTK Selenium extension config failed: {}", e.getMessage());
        }
    }

    private static void ensurePtkSeleniumBrowserArguments(SeleniumOptions options) {
        for (String browserId :
                Arrays.asList("chrome", "chrome-headless", "edge", "edge-headless")) {
            for (String argument : PTK_CHROMIUM_BACKGROUND_ARGS) {
                ensurePtkSeleniumBrowserArgument(options, browserId, argument);
            }
        }
    }

    private static void ensurePtkSeleniumBrowserArgument(
            SeleniumOptions options, String browserId, String argument) {
        try {
            Class<?> browserArgumentClass =
                    Class.forName("org.zaproxy.zap.extension.selenium.internal.BrowserArgument");
            Method getBrowserArguments =
                    SeleniumOptions.class.getDeclaredMethod("getBrowserArguments", String.class);
            Method addBrowserArgument =
                    SeleniumOptions.class.getDeclaredMethod(
                            "addBrowserArgument", String.class, browserArgumentClass);
            getBrowserArguments.setAccessible(true);
            addBrowserArgument.setAccessible(true);
            @SuppressWarnings("unchecked")
            List<Object> existing = (List<Object>) getBrowserArguments.invoke(options, browserId);
            if (existing != null) {
                for (Object candidate : existing) {
                    if (candidate == null) {
                        continue;
                    }
                    Method getArgument = candidate.getClass().getMethod("getArgument");
                    if (argument.equals(getArgument.invoke(candidate))) {
                        return;
                    }
                }
            }
            Object browserArgument =
                    browserArgumentClass
                            .getConstructor(String.class, boolean.class)
                            .newInstance(argument, true);
            addBrowserArgument.invoke(options, browserId, browserArgument);
            LOGGER.debug(
                    "PTK Selenium browser argument registered browser={} arg={}",
                    browserId,
                    argument);
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug(
                    "PTK Selenium browser argument config skipped browser={} arg={} reason={}",
                    browserId,
                    argument,
                    e.getMessage());
        }
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
        // Browser coverage targets are SDK/ZAP-owned inputs. They must override
        // early extension progress target URLs, which can be a redirected/current
        // page and would otherwise make the coverage job wait on the wrong key.
        targetUrlByZapId.put(zapid, targetUrl);
        recordBrowserCoveragePtkSessionIfKnown(zapid, targetUrl, null);
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
            if ("safe_to_close".equals(decision) || "wait".equals(decision)) {
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

        private void appendDetailField(
                StringBuilder summary, Map<String, Object> details, String key, String label) {
            Object value = details.get(key);
            if (!(value instanceof Number)) {
                return;
            }
            summary.append(';').append(label).append('=').append(((Number) value).intValue());
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
            return extra;
        }

        private void clearTrackingState(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return;
            }
            closedZapIds.add(zapid);
            scanProgress.remove(zapid);
            scanStatus.remove(zapid);
            callbackFirstSeenAtMs.remove(zapid);
            browserIdByZapId.remove(zapid);
            alertsRaisedByZapId.remove(zapid);
            firstAlertSeenAtMs.remove(zapid);
            lastProgressSummaryByZapId.remove(zapid);
            safeToCloseByZapId.remove(zapid);
            lastCloseDecisionByZapId.remove(zapid);
            closeRequestedByZapId.remove(zapid);
            sessionIdByZapId.remove(zapid);
            targetUrlByZapId.remove(zapid);
            zapIdByWebDriverSessionId.entrySet().removeIf(entry -> zapid.equals(entry.getValue()));
            firstProgressLogged.remove(zapid);
            firstAlertLogged.remove(zapid);
            terminalProgressLogged.remove(zapid);
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

        private void waitForSessionStartBeforeClose(String zapid) {
            if (zapid == null || zapid.isBlank()) {
                return;
            }
            long deadline =
                    System.currentTimeMillis()
                            + PtkCloseContract.BROWSER_CLOSE_NO_PROGRESS_GRACE_MS;
            while (isWaitingForSessionStart(zapid) && System.currentTimeMillis() < deadline) {
                try {
                    Thread.sleep(Math.min(250, PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }

        Long getCloseRequestedAtMs(String zapid) {
            return PtkCloseContract.getCloseRequestedAtMs(closeRequestedByZapId, zapid);
        }

        void markCloseDecisionAttempted(String zapid, long decidedAtMs) {
            PtkCloseContract.markCloseDecisionAttempted(closeRequestedByZapId, zapid, decidedAtMs);
        }

        private Map<String, Object> requestPtkCloseDecision(
                ClientCallBackUtils ccbutils, String zapid) {
            Map<String, Object> fallback = new LinkedHashMap<>();
            fallback.put("participant", "ptk");
            fallback.put("decision", "not_applicable");
            fallback.put("scanState", "unknown");
            fallback.put("reason", "webdriver_unavailable");

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
                        .scriptTimeout(
                                Duration.ofMillis(
                                        PtkCloseContract.BROWSER_CLOSE_SCRIPT_TIMEOUT_MS));
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
                    const stopTimeoutMs = arguments[0] || 10000;
                    const explicitSessionId = arguments[1] || null;
                    const explicitZapId = arguments[2] || null;
                    const callTimeoutMs = Math.max(2000, stopTimeoutMs);
                    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
                    const timeoutAfter = (label, ms) => new Promise((resolve) => setTimeout(() => {
                      resolve({ ok: false, code: label + '_timeout', status: 'unknown' });
                    }, Math.max(500, ms || 3000)));
                    const terminal = new Set(['none', 'completed', 'error', 'timeout', 'cancelled', 'engine_incomplete']);
                    const statusOf = (value) => {
                      const status = String(value && (value.status || value.completionStatus || value.summary && value.summary.status) || '').toLowerCase();
                      return status;
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
                            zapid: explicitZapId
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
                      { options: { sessionId: explicitSessionId, source: 'zap_browser_close' } },
                      3000
                    );
                    const stopDirect = () => sendZapCloseMessage(
                      'session-end',
                      {
                        wait: false,
                        options: {
                          sessionId: explicitSessionId,
                          source: 'zap_browser_close',
                          stopTimeoutMs
                        }
                      },
                      Math.min(5000, callTimeoutMs)
                    );
                    (async () => {
                      try {
                        await refreshAutomationStatus();
                        const automation = window.PTK_AUTOMATION;
                        const trustedAutomation = automation && automation.bridgeId === 'ptk-automation-bridge'
                          ? automation
                          : null;
                        if (trustedAutomation && typeof trustedAutomation.endSession === 'function') {
                          const readProgress = () => typeof trustedAutomation.getSessionProgress === 'function'
                            ? withTimeout(trustedAutomation.getSessionProgress({ sessionId: explicitSessionId, source: 'zap_browser_close', zapid: explicitZapId }), 'scan_status', 3000)
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
                          const stop = await withTimeout(
                            trustedAutomation.endSession({
                              sessionId: explicitSessionId,
                              wait: false,
                              source: 'zap_browser_close',
                              zapid: explicitZapId,
                              stopTimeoutMs
                            }),
                            'stop_scan',
                            Math.min(5000, callTimeoutMs)
                          );
                          if (stop && stop.error === 'automation_disabled') {
                            await refreshAutomationStatus();
                            const retryStop = await withTimeout(
                              trustedAutomation.endSession({
                                sessionId: explicitSessionId,
                                wait: false,
                                source: 'zap_browser_close',
                                zapid: explicitZapId,
                                stopTimeoutMs
                              }),
                              'stop_scan_retry',
                              Math.min(5000, callTimeoutMs)
                            );
                            if (retryStop && retryStop.ok !== false) {
                              Object.assign(stop, retryStop);
                            }
                            if (stop && stop.error === 'automation_disabled') {
                              const directStop = await stopDirect();
                              if (directStop && directStop.ok !== false) {
                                directStop.stopVia = 'direct_zap_close';
                                Object.assign(stop, directStop);
                              }
                            }
                          }
                          let after = await waitForTerminal(Math.max(1000, callTimeoutMs - 5000));
                          const directAfter = after && after.error === 'automation_disabled'
                            ? await readProgressDirect()
                            : null;
                          if (directAfter && directAfter.ok !== false) {
                            after = Object.assign(after || {}, directAfter);
                          }
                          const stopStatus = statusOf(stop);
                          const finalStatus = statusOf(after) || stopStatus || statusBefore || 'stopping';
                          const finalCompletionStatus = String(after && (after.completionStatus || after.summary && after.summary.status) || stop && (stop.completionStatus || stop.summary && stop.summary.status) || '').toLowerCase();
                          const terminalPosted = Boolean(after && after.zapProgressTerminalPosted === true || stop && stop.zapProgressTerminalPosted === true);
                          done({
                            ok: stop && stop.ok !== false,
                            participant: 'ptk',
                            decision: terminal.has(finalStatus) ? 'safe_to_close' : 'wait',
                            scanState: finalStatus,
                            completionStatus: finalCompletionStatus || null,
                            zapProgressTerminalPosted: terminalPosted,
                            zapTerminalPost: after && after.zapTerminalPost || stop && stop.zapTerminalPost || null,
                            statusBefore,
                            sessionId: explicitSessionId,
                            stopRequested: true,
                            stopVia: stop && stop.stopVia ? stop.stopVia : 'automation_bridge',
                            reason: terminal.has(finalStatus) ? 'terminal_after_stop' : stop && stop.error || 'close_requested'
                          });
                          return;
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
                          const stop = await stopDirect();
                          const after = await readProgressDirect();
                          const stopStatus = statusOf(stop);
                          const finalStatus = statusOf(after) || stopStatus || statusBefore || 'stopping';
                          const finalCompletionStatus = String(after && (after.completionStatus || after.summary && after.summary.status) || stop && (stop.completionStatus || stop.summary && stop.summary.status) || '').toLowerCase();
                          const terminalPosted = Boolean(after && after.zapProgressTerminalPosted === true || stop && stop.zapProgressTerminalPosted === true);
                          if (stop && stop.ok !== false) {
                            done({
                              ok: true,
                              participant: 'ptk',
                              decision: terminal.has(finalStatus) ? 'safe_to_close' : 'wait',
                              scanState: finalStatus,
                              completionStatus: finalCompletionStatus || null,
                              zapProgressTerminalPosted: terminalPosted,
                              zapTerminalPost: after && after.zapTerminalPost || stop && stop.zapTerminalPost || null,
                              statusBefore,
                              sessionId: explicitSessionId,
                              stopRequested: true,
                              stopVia: 'direct_zap_close',
                              reason: terminal.has(finalStatus) ? 'terminal_after_stop' : stop.error || 'close_requested'
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
                        if (typeof agent.stopScan !== 'function') {
                          done({
                            ok: false,
                            participant: 'ptk',
                            decision: 'wait',
                            scanState: statusBefore || 'running',
                            statusBefore,
                            sessionId: before && before.sessionId || null,
                            reason: 'stop_scan_unavailable'
                          });
                          return;
                        }
                        const stop = await Promise.race([
                          Promise.resolve(agent.stopScan({
                            wait: false,
                            stopTimeoutMs
                          })),
                          timeoutAfter('stop_scan', Math.min(5000, callTimeoutMs))
                        ]);
                        const stopStatus = String(stop && stop.status || stop && stop.summary && stop.summary.status || '').toLowerCase();
                        done({
                          ok: stop && stop.ok !== false,
                          participant: 'ptk',
                          decision: terminal.has(stopStatus) ? 'safe_to_close' : 'wait',
                          scanState: stopStatus || statusBefore || 'stopping',
                          statusBefore,
                          sessionId: before && before.sessionId || null,
                          stopRequested: true,
                          reason: stop && stop.code || stop && stop.error || 'close_requested'
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
                                    PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS,
                                    sessionId,
                                    zapid);
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
                                    PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS,
                                    sessionId,
                                    zapid);
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
                                    PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS,
                                    sessionId,
                                    zapid);
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
                    zapid != null && !zapid.isBlank() ? targetUrlByZapId.get(zapid) : null;
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

        @SuppressWarnings("unchecked")
        private String summarizeProgressPayload(Map<String, Object> progressData) {
            StringBuilder summary = new StringBuilder();
            Object enginesValue = progressData.get("engines");
            if (!(enginesValue instanceof Map<?, ?> engines) || engines.isEmpty()) {
                return "";
            }
            engines.forEach(
                    (engineName, engineValue) -> {
                        if (!(engineName instanceof String)
                                || !(engineValue instanceof Map<?, ?>)) {
                            return;
                        }
                        Map<String, Object> engine = (Map<String, Object>) engineValue;
                        if (!summary.isEmpty()) {
                            summary.append(',');
                        }
                        summary.append(engineName)
                                .append(':')
                                .append(getStringField(engine, "status"))
                                .append(':');
                        Object progress = engine.get("progress");
                        if (progress instanceof Number) {
                            summary.append(((Number) progress).intValue());
                        } else {
                            summary.append('0');
                        }
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
                            summary.append(']');
                        }
                    });
            return summary.toString();
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
                markCallbackStart(zapid);
                logBrowserEvidence(zapid, browserid, "config_callback", null, null);
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
                        if (closedZapIds.contains(zapid)) {
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
                        String mappedTargetUrl = targetUrlByZapId.get(zapid);
                        String evidenceTargetUrl =
                                mappedTargetUrl != null ? mappedTargetUrl : targetUrl;
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
                            evidenceTargetUrl = targetUrlByZapId.get(zapid);
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
                                    closeRequestedByZapId, zapid)) {
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
                        String progressSummary = summarizeProgressPayload(progressData);
                        boolean progressChanged =
                                zapid != null
                                        && !zapid.isBlank()
                                        && !progressSummary.isBlank()
                                        && !progressSummary.equals(
                                                lastProgressSummaryByZapId.put(
                                                        zapid, progressSummary));
                        if (firstProgress || sessionEstablished || terminalProgress) {
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
                        if (zapid != null && !zapid.isBlank()) {
                            Long closeRequestedAt = getCloseRequestedAtMs(zapid);
                            if (closeRequestedAt != null) {
                                response.put("closeRequested", true);
                                response.put("closeRequestedAt", closeRequestedAt);
                                response.put(
                                        "stopTimeoutMs",
                                        PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS);
                            }
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
            String browserid = browserIdByZapId.get(zapid);
            waitForSessionStartBeforeClose(zapid);
            boolean hadProgressBeforeClose = scanProgress.containsKey(zapid);
            Map<String, Object> closeDecision = requestPtkCloseDecision(ccbutils, zapid);
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
                        && System.currentTimeMillis() < sessionStartDeadline) {
                    try {
                        Thread.sleep(PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    retry++;
                }
                closeDecision = requestPtkCloseDecision(ccbutils, zapid);
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
                        && System.currentTimeMillis() < automationDisabledDeadline) {
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
                        && System.currentTimeMillis() < noProgressDeadline) {
                    try {
                        Thread.sleep(PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    closeDecision = requestPtkCloseDecision(ccbutils, zapid);
                    retry++;
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
                if (count >= PtkCloseContract.BROWSER_CLOSE_MAX_ATTEMPTS) {
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
                        && !isSafeToClose(zapid)) {
                    closeDecision = requestPtkCloseDecision(ccbutils, zapid);
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
            return isTerminalProgressValue(
                    scanProgress.getOrDefault(zapid, 100), scanStatus.get(zapid));
        }
    }
}
