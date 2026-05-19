package org.zaproxy.addon.ptk;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationJobException;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;

final class PtkBrowserCoverageJob extends AutomationJob {

    private static final Logger LOGGER = LogManager.getLogger(PtkBrowserCoverageJob.class);
    private static final String JOB_TYPE = "ptkBrowserCoverage";
    private static final String CLIENT_MAP_EVENT_SOURCE =
            "org.zaproxy.addon.client.internal.ClientMap";
    private static final int DEFAULT_NUMBER_OF_BROWSERS = 1;
    private static final int DEFAULT_INITIAL_LOAD_TIME_SECS = 5;
    private static final int DEFAULT_PAGE_LOAD_TIME_SECS = 5;
    private static final int DEFAULT_SHUTDOWN_TIME_SECS = 5;
    private static final int DEFAULT_MAX_RETRIES_PER_URL = 1;
    private static final int DEFAULT_ATTEMPT_TIMEOUT_SECS = 45;
    private static final int DEFAULT_EVIDENCE_GRACE_MS = 2500;
    private static final int DEFAULT_LAUNCH_STAGGER_MS = 250;
    private static final int DEFAULT_RETRY_NUMBER_OF_BROWSERS = 2;

    private final ExtensionPtk ptk;
    private final Data data = new Data();
    private final Parameters parameters = new Parameters();
    private volatile boolean stopRequested;

    PtkBrowserCoverageJob(ExtensionPtk ptk) {
        this.ptk = ptk;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        stopRequested = false;
        ExtensionClientIntegration client = getClientExtension();
        if (client == null) {
            progress.error(
                    "PTK browser coverage cannot run: Client Integration add-on unavailable");
            return;
        }
        ExtensionSelenium selenium = getSeleniumExtension();
        if (selenium == null) {
            progress.error("PTK browser coverage cannot run: Selenium add-on unavailable");
            return;
        }

        Context context = resolveContext(env);
        List<String> urls = resolveUrls(env, context);
        if (urls.isEmpty()) {
            progress.warn("PTK browser coverage skipped: no URLs resolved");
            return;
        }

        int concurrency = clamp(parameters.getNumberOfBrowsers(), DEFAULT_NUMBER_OF_BROWSERS, 32);
        int retryConcurrency =
                resolveRetryConcurrency(parameters.getRetryNumberOfBrowsers(), concurrency);
        int maxRetries = clamp(parameters.getMaxRetriesPerUrl(), DEFAULT_MAX_RETRIES_PER_URL, 5);
        int launchStaggerMs = launchStaggerMs();
        boolean requirePtkSession =
                parameters.getRequirePtkSession() == null || parameters.getRequirePtkSession();
        boolean failOnMissingBrowserLoad =
                Boolean.TRUE.equals(parameters.getFailOnMissingBrowserLoad());

        progress.info(
                "PTK browser coverage started: urls="
                        + urls.size()
                        + " browsers="
                        + concurrency
                        + " retryBrowsers="
                        + retryConcurrency
                        + " maxRetriesPerUrl="
                        + maxRetries
                        + " requirePtkSession="
                        + requirePtkSession);

        List<CoverageTarget> pending = new ArrayList<>();
        for (String url : urls) {
            pending.add(new CoverageTarget(url));
        }

        ExecutorService executor =
                Executors.newFixedThreadPool(concurrency, browserCoverageThreadFactory());
        try {
            while (!pending.isEmpty() && !stopRequested) {
                pending = pruneAlreadySatisfiedTargets(pending, requirePtkSession);
                if (pending.isEmpty()) {
                    break;
                }

                List<CoverageTarget> batch = new ArrayList<>();
                int batchLimit = batchLimitForNextTargets(pending, concurrency, retryConcurrency);
                while (!pending.isEmpty() && batch.size() < batchLimit) {
                    batch.add(pending.remove(0));
                }
                boolean retryBatch = batch.stream().anyMatch(target -> target.attempts > 0);
                if (retryBatch && batchLimit < concurrency) {
                    progress.info(
                            "PTK browser coverage retry batch: urls="
                                    + batch.size()
                                    + " browsers="
                                    + batchLimit);
                }

                List<RunningAttempt> running = new ArrayList<>();
                for (CoverageTarget target : batch) {
                    target.attempts += 1;
                    ptk.recordBrowserCoverageScheduled(target.url, target.attempts);
                    running.add(new RunningAttempt(target, System.currentTimeMillis()));
                    if (launchStaggerMs > 0 && running.size() < batch.size()) {
                        quietSleep(launchStaggerMs);
                    }
                }

                runDirectAttempts(executor, client, selenium, running, progress, requirePtkSession);
                quietSleep(evidenceGraceMs());

                for (RunningAttempt attempt : running) {
                    CoverageTarget target = attempt.target;
                    BrowserCoverageSnapshot snapshot = ptk.getBrowserCoverageSnapshot(target.url);
                    target.finalState = snapshot.classify(requirePtkSession);
                    if (isCoverageSatisfied(snapshot, requirePtkSession)) {
                        data.loadedUrls += 1;
                        ptk.logBrowserCoverageResult(
                                target.url, target.attempts, target.finalState, snapshot, true);
                        continue;
                    }
                    if (target.attempts <= maxRetries && !stopRequested) {
                        pending.add(target);
                        continue;
                    }
                    data.missingUrls += 1;
                    ptk.logBrowserCoverageResult(
                            target.url, target.attempts, target.finalState, snapshot, true);
                    String message =
                            "PTK browser coverage missing URL "
                                    + target.url
                                    + " state="
                                    + target.finalState
                                    + " attempts="
                                    + target.attempts;
                    if (failOnMissingBrowserLoad) {
                        progress.error(message);
                    } else {
                        progress.warn(message);
                    }
                }
            }
        } finally {
            executor.shutdownNow();
        }

        progress.info(
                "PTK browser coverage finished: loaded="
                        + data.loadedUrls
                        + " missing="
                        + data.missingUrls
                        + " total="
                        + urls.size());
    }

    private List<CoverageTarget> pruneAlreadySatisfiedTargets(
            List<CoverageTarget> targets, boolean requirePtkSession) {
        List<CoverageTarget> remaining = new ArrayList<>();
        for (CoverageTarget target : targets) {
            BrowserCoverageSnapshot snapshot = ptk.getBrowserCoverageSnapshot(target.url);
            if (isCoverageSatisfied(snapshot, requirePtkSession)) {
                target.finalState = snapshot.classify(requirePtkSession);
                data.loadedUrls += 1;
                ptk.logBrowserCoverageResult(
                        target.url, target.attempts, target.finalState, snapshot, true);
            } else {
                remaining.add(target);
            }
        }
        return remaining;
    }

    @Override
    public void stop() {
        stopRequested = true;
    }

    @Override
    public AutomationJob newJob() throws AutomationJobException {
        return new PtkBrowserCoverageJob(ptk);
    }

    @Override
    public String getType() {
        return JOB_TYPE;
    }

    @Override
    public Order getOrder() {
        return Order.LAST_EXPLORE;
    }

    @Override
    public Object getParamMethodObject() {
        return this;
    }

    @Override
    public String getParamMethodName() {
        return "getParameters";
    }

    @Override
    public String getTemplateDataMin() {
        return """
        - type: ptkBrowserCoverage
          parameters:
            source: contextUrls
            numberOfBrowsers: 1
            pageLoadTime: 5
            launchStaggerMs: 250
            retryNumberOfBrowsers: 2
            maxRetriesPerUrl: 1
            scopeCheck: STRICT
            requirePtkSession: true
            failOnMissingBrowserLoad: false
        """;
    }

    @Override
    public String getTemplateDataMax() {
        return """
        - type: ptkBrowserCoverage
          parameters:
            context: ""
            source: contextUrls
            urls: ""
            browserId: edge-headless
            numberOfBrowsers: 1
            initialLoadTime: 5
            pageLoadTime: 5
            shutdownTime: 5
            attemptTimeout: 45
            evidenceGraceMs: 2500
            launchStaggerMs: 250
            retryNumberOfBrowsers: 2
            maxRetriesPerUrl: 1
            scopeCheck: STRICT
            requirePtkSession: true
            failOnMissingBrowserLoad: false
        """;
    }

    @Override
    public void showDialog() {
        // No UI dialog yet; this job is intended for automation plans.
    }

    @Override
    public String getSummary() {
        return "PTK browser coverage";
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
    }

    private ExtensionClientIntegration getClientExtension() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class);
    }

    private ExtensionSelenium getSeleniumExtension() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
    }

    private Context resolveContext(AutomationEnvironment env) {
        String contextName = nonBlank(parameters.getContext());
        if (contextName != null) {
            Context context = env.getContext(contextName);
            if (context != null) {
                return context;
            }
        }
        return env.getDefaultContext();
    }

    private List<String> resolveUrls(AutomationEnvironment env, Context context) {
        Set<String> urls = new LinkedHashSet<>();
        addUrl(urls, env.replaceVars(parameters.getUrl()));
        addConfiguredUrls(urls, env, parameters.getUrls());

        String source = nonBlank(parameters.getSource());
        if (source == null) {
            source = "contextUrls";
        }
        if ("contextUrls".equalsIgnoreCase(source)
                || "contextAndHistoryUrls".equalsIgnoreCase(source)) {
            addContextUrls(urls, env, context);
        }
        if ("historyUrls".equalsIgnoreCase(source)
                || "contextAndHistoryUrls".equalsIgnoreCase(source)) {
            addHistoryUrls(urls, context);
        }
        if (urls.isEmpty() && !"historyUrls".equalsIgnoreCase(source)) {
            addContextUrls(urls, env, context);
        }
        return new ArrayList<>(urls);
    }

    private void addContextUrls(Set<String> urls, AutomationEnvironment env, Context context) {
        ContextWrapper wrapper = null;
        if (nonBlank(parameters.getContext()) != null) {
            wrapper = env.getContextWrapper(parameters.getContext());
        }
        if (wrapper == null && context != null) {
            wrapper = env.getContextWrapper(context.getName());
        }
        if (wrapper == null) {
            wrapper = env.getDefaultContextWrapper();
        }
        if (wrapper != null) {
            for (String url : wrapper.getUrls()) {
                addUrl(urls, env.replaceVars(url));
            }
        }
    }

    private void addHistoryUrls(Set<String> urls, Context context) {
        try {
            SiteNode root = Model.getSingleton().getSession().getSiteTree().getRoot();
            if (root == null) {
                return;
            }
            Enumeration<?> nodes = root.preorderEnumeration();
            while (nodes.hasMoreElements()) {
                Object candidate = nodes.nextElement();
                if (!(candidate instanceof SiteNode siteNode)) {
                    continue;
                }
                HistoryReference historyReference = siteNode.getHistoryReference();
                if (historyReference == null || historyReference.getHttpMessage() == null) {
                    continue;
                }
                String url =
                        historyReference.getHttpMessage().getRequestHeader().getURI().toString();
                if (context != null && !context.isInContext(url)) {
                    continue;
                }
                addUrl(urls, url);
            }
        } catch (Exception e) {
            LOGGER.warn("PTK browser coverage failed to resolve history URLs", e);
        }
    }

    private void runDirectAttempts(
            ExecutorService executor,
            ExtensionClientIntegration client,
            ExtensionSelenium selenium,
            List<RunningAttempt> running,
            AutomationProgress progress,
            boolean requirePtkSession) {
        if (running.isEmpty()) {
            return;
        }
        List<Future<?>> futures = new ArrayList<>();
        for (RunningAttempt attempt : running) {
            futures.add(
                    executor.submit(
                            () ->
                                    runDirectAttempt(
                                            client,
                                            selenium,
                                            attempt,
                                            progress,
                                            requirePtkSession)));
        }
        long timeoutMs =
                Math.max(30_000L, attemptTimeoutSecs() * 1000L)
                        + ptk.browserCloseMaxWallClockMs()
                        + 5_000L;
        long deadline = System.currentTimeMillis() + timeoutMs;
        for (int i = 0; i < futures.size(); i++) {
            Future<?> future = futures.get(i);
            long remainingMs = Math.max(1L, deadline - System.currentTimeMillis());
            try {
                future.get(remainingMs, TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                cancelTimedOutAttempt(future, running.get(i), requirePtkSession);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                cancelTimedOutAttempt(future, running.get(i), requirePtkSession);
                for (int j = i + 1; j < futures.size(); j++) {
                    cancelTimedOutAttempt(futures.get(j), running.get(j), requirePtkSession);
                }
                return;
            } catch (ExecutionException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                progress.warn(
                        "PTK browser coverage browser attempt failed for "
                                + running.get(i).target.url
                                + ": "
                                + cause.getMessage());
            }
        }
        for (int i = 0; i < futures.size(); i++) {
            Future<?> future = futures.get(i);
            if (!future.isDone()) {
                cancelTimedOutAttempt(future, running.get(i), requirePtkSession);
            }
        }
    }

    private void cancelTimedOutAttempt(
            Future<?> future, RunningAttempt attempt, boolean requirePtkSession) {
        if (future != null) {
            future.cancel(true);
        }
        BrowserCoverageSnapshot snapshot = ptk.getBrowserCoverageSnapshot(attempt.target.url);
        if (isCoverageSatisfied(snapshot, requirePtkSession)) {
            return;
        }
        attempt.target.finalState = "browser_session_invalid:attempt_timeout";
        ptk.recordBrowserCoverageInvalid(null, attempt.target.url, "attempt_timeout", null);
    }

    private static ThreadFactory browserCoverageThreadFactory() {
        AtomicInteger sequence = new AtomicInteger();
        return runnable -> {
            Thread thread =
                    new Thread(runnable, "ptk-browser-coverage-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    private void runDirectAttempt(
            ExtensionClientIntegration client,
            ExtensionSelenium selenium,
            RunningAttempt attempt,
            AutomationProgress progress,
            boolean requirePtkSession) {
        DirectBrowser browser = null;
        String zapid = null;
        String browserId = nonBlank(parameters.getBrowserId());
        if (browserId == null) {
            browserId = ClientOptions.DEFAULT_BROWSER_ID;
        }
        try {
            browser = openDirectBrowser(client, selenium, attempt.target);
            WebDriver driver = browser.driver;
            if (driver == null) {
                throw new IllegalStateException("Selenium returned no WebDriver for " + browserId);
            }
            zapid = waitForZapId(driver, Math.max(5_000L, launchStaggerMs() * 2L));
            ptk.rememberBrowserCoverageTarget(zapid, attempt.target.url);
            seedTargetUrlIntoZapCallback(driver, zapid, attempt.target.url, progress);
            waitForPtkSessionBeforeTargetNavigation(
                    driver, zapid, attempt.target.url, progress, requirePtkSession);
            driver.manage()
                    .timeouts()
                    .pageLoadTimeout(Duration.ofSeconds(Math.max(1, attemptTimeoutSecs())));
            driver.get(attempt.target.url);
            String observedUrl = safeCurrentUrl(driver);
            ptk.recordBrowserCoverageBrowserLoaded(
                    zapid, attempt.target.url, observedUrl, "browserCoverageDirect");
            waitForCoverageEvidence(attempt.target.url, observedUrl, zapid, requirePtkSession);
            if (requirePtkSession) {
                String sessionId = ptk.getBrowserCoverageSessionId(zapid);
                waitForPtkAnalysisReadiness(
                        driver, attempt.target.url, observedUrl, zapid, sessionId, progress);
            }
        } catch (RuntimeException e) {
            attempt.target.finalState = "browser_session_invalid:webdriver_navigation_failed";
            attempt.target.lastError = e.getMessage();
            ptk.recordBrowserCoverageInvalid(
                    zapid, attempt.target.url, "webdriver_navigation_failed", e.getMessage());
            progress.warn(
                    "PTK browser coverage failed browser load for "
                            + attempt.target.url
                            + ": "
                            + e.getMessage());
        } finally {
            closeDirectBrowser(client, browser, zapid, attempt.target.url, progress);
        }
    }

    private void waitForPtkSessionBeforeTargetNavigation(
            WebDriver driver,
            String zapid,
            String targetUrl,
            AutomationProgress progress,
            boolean requirePtkSession) {
        if (!requirePtkSession || !(driver instanceof JavascriptExecutor)) {
            return;
        }
        long maxWaitMs = Math.max(2_000L, Math.min(6_000L, attemptTimeoutSecs() * 1000L / 8L));
        long deadline = System.currentTimeMillis() + maxWaitMs;
        String lastReason = null;
        while (!stopRequested && System.currentTimeMillis() < deadline) {
            ptk.recordBrowserCoveragePtkSessionIfKnown(zapid, targetUrl, null);
            String sessionId = ptk.getBrowserCoverageSessionId(zapid);
            if (sessionId != null && !sessionId.isBlank()) {
                Map<String, Object> state = readPtkStartupReadiness(driver, zapid, sessionId);
                lastReason = stringValue(state, "reason");
                if (booleanValue(state, "ready")) {
                    return;
                }
            } else {
                lastReason = "session_id_unavailable";
            }
            quietSleep(150);
        }
        progress.info(
                "PTK browser coverage pre-navigation session wait timed out for "
                        + targetUrl
                        + (lastReason != null ? " reason=" + lastReason : ""));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readPtkStartupReadiness(
            WebDriver driver, String zapid, String sessionId) {
        if (!(driver instanceof JavascriptExecutor js)) {
            return Map.of("ok", false, "ready", false, "reason", "javascript_executor_unavailable");
        }

        String script =
                """
                const done = arguments[arguments.length - 1];
                const explicitZapId = arguments[0] || null;
                const explicitSessionId = arguments[1] || null;
                const terminal = new Set(['running', 'idle', 'ready', 'completed', 'stopped']);
                const bad = new Set(['starting', 'deferred_start', 'error', 'cancelled', 'engine_incomplete']);
                const str = (value) => value == null ? '' : String(value).toLowerCase();
                const timeout = (ms) => new Promise((resolve) => setTimeout(() => resolve({ ok: false, reason: 'startup_progress_timeout' }), ms));
                (async () => {
                  try {
                    const automation = window.PTK_AUTOMATION;
                    if (!automation || automation.bridgeId !== 'ptk-automation-bridge' || typeof automation.getSessionProgress !== 'function') {
                      done({ ok: false, ready: false, reason: 'automation_bridge_unavailable' });
                      return;
                    }
                    const progress = await Promise.race([
                      Promise.resolve(automation.getSessionProgress({ sessionId: explicitSessionId, source: 'zap_browser_close', zapid: explicitZapId })),
                      timeout(2500)
                    ]);
                    if (!progress || progress.ok === false) {
                      done({ ok: false, ready: false, reason: progress && (progress.error || progress.reason) || 'progress_unavailable' });
                      return;
                    }
                    const engines = progress.engines && typeof progress.engines === 'object' ? progress.engines : {};
                    const names = Object.keys(engines).map((name) => String(name || '').toUpperCase()).filter(Boolean);
                    if (!names.length) {
                      done({ ok: true, ready: false, reason: 'no_engines' });
                      return;
                    }
                    const notReady = [];
                    const states = [];
                    for (const name of names) {
                      const entry = engines[name] || {};
                      const state = str(entry.status || entry.state);
                      states.push(name + ':' + (state || 'unknown'));
                      if (bad.has(state) || !terminal.has(state)) {
                        notReady.push(name + ':' + (state || 'unknown'));
                      }
                    }
                    done({
                      ok: true,
                      ready: notReady.length === 0,
                      reason: notReady.length ? notReady.join(',') : 'ready',
                      summary: states.join(',')
                    });
                  } catch (error) {
                    done({ ok: false, ready: false, reason: error && error.message || String(error) });
                  }
                })();
                """;
        Object value = js.executeAsyncScript(script, zapid, sessionId);
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return Map.of("ok", false, "ready", false, "reason", "unexpected_result");
    }

    private void seedTargetUrlIntoZapCallback(
            WebDriver driver, String zapid, String targetUrl, AutomationProgress progress) {
        if (driver == null
                || zapid == null
                || zapid.isBlank()
                || targetUrl == null
                || targetUrl.isBlank()) {
            return;
        }
        String currentUrl = safeCurrentUrl(driver);
        if (currentUrl == null
                || !currentUrl.contains("/zapCallBackUrl/")
                || !currentUrl.contains("zapid=" + zapid)
                || currentUrl.contains("targetUrl=")) {
            return;
        }
        String separator = currentUrl.contains("?") ? "&" : "?";
        String seededUrl =
                currentUrl
                        + separator
                        + "targetUrl="
                        + URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        try {
            driver.navigate().to(seededUrl);
        } catch (RuntimeException e) {
            ptk.recordBrowserCoverageInvalid(
                    zapid, targetUrl, "webdriver_script_failed", e.getMessage());
            progress.warn(
                    "PTK browser coverage failed to seed callback target URL for "
                            + targetUrl
                            + ": "
                            + e.getMessage());
        }
    }

    private DirectBrowser openDirectBrowser(
            ExtensionClientIntegration client, ExtensionSelenium selenium, CoverageTarget target) {
        if (selenium == null) {
            throw new IllegalStateException("Selenium add-on unavailable");
        }
        ClientOptions options = createClientOptions();
        ClientSpider spider = new ClientSpider(client, target.url, target.url, options, 0);
        detachClientSpiderEventConsumer(spider);
        Object process = spider.getWebDriverProcess();
        WebDriver driver = extractWebDriver(process);
        if (driver == null) {
            throw new IllegalStateException("ClientSpider returned no WebDriver");
        }
        return new DirectBrowser(spider, process, driver);
    }

    private static WebDriver extractWebDriver(Object process) {
        if (process == null) {
            return null;
        }
        try {
            var method = process.getClass().getDeclaredMethod("getWebDriver");
            method.setAccessible(true);
            Object driver = method.invoke(process);
            return driver instanceof WebDriver webDriver ? webDriver : null;
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.warn(
                    "PTK_REFLECTION_FALLBACK component=client-spider-webdriver reason={}",
                    e.getMessage());
            throw new IllegalStateException(
                    "Failed to read WebDriver from ClientSpider process", e);
        }
    }

    private String waitForZapId(WebDriver driver, long timeoutMs) {
        long deadline = System.currentTimeMillis() + Math.max(0L, timeoutMs);
        while (!stopRequested && System.currentTimeMillis() < deadline) {
            String zapid = zapIdForDriver(driver);
            if (zapid != null && !zapid.isBlank()) {
                return zapid;
            }
            quietSleep(100);
        }
        return zapIdForDriver(driver);
    }

    private String zapIdForDriver(WebDriver driver) {
        String zapid = ptk.getZapIdForWebDriver(driver);
        if (zapid != null && !zapid.isBlank()) {
            return zapid;
        }
        zapid = extractZapIdFromCallbackUrl(safeCurrentUrl(driver));
        if (zapid != null && !zapid.isBlank()) {
            ptk.rememberWebDriverZapId(driver, zapid);
            return zapid;
        }
        return null;
    }

    private void waitForCoverageEvidence(
            String targetUrl, String observedUrl, String zapid, boolean requirePtkSession) {
        long startedAt = System.currentTimeMillis();
        long dwellMs = PtkBrowserCoverageTiming.pageDwellMs(parameters.getPageLoadTime());
        long minDwellDeadline = startedAt + dwellMs;
        long coverageWaitMs =
                requirePtkSession
                        ? Math.max(dwellMs, Math.max(1_000L, attemptTimeoutSecs() * 1000L))
                        : Math.max(1_000L, dwellMs);
        long deadline = startedAt + coverageWaitMs + evidenceGraceMs();
        while (!stopRequested && System.currentTimeMillis() < deadline) {
            if (requirePtkSession) {
                ptk.recordBrowserCoveragePtkSessionIfKnown(zapid, targetUrl, observedUrl);
            }
            BrowserCoverageSnapshot snapshot = ptk.getBrowserCoverageSnapshot(targetUrl);
            if (PtkBrowserCoverageTiming.coverageWaitComplete(
                    System.currentTimeMillis(),
                    minDwellDeadline,
                    isCoverageSatisfied(snapshot, requirePtkSession),
                    requirePtkSession)) {
                return;
            }
            quietSleep(250);
        }
    }

    private void waitForPtkAnalysisReadiness(
            WebDriver driver,
            String targetUrl,
            String observedUrl,
            String zapid,
            String sessionId,
            AutomationProgress progress) {
        if (!(driver instanceof JavascriptExecutor)) {
            return;
        }
        long deadline =
                System.currentTimeMillis()
                        + Math.max(
                                Math.max(
                                        8_000L,
                                        PtkBrowserCoverageTiming.pageDwellMs(
                                                parameters.getPageLoadTime())),
                                Math.max(8_000L, attemptTimeoutSecs() * 1000L));
        long readySince = 0L;
        Map<String, Object> lastState = null;

        while (!stopRequested && System.currentTimeMillis() < deadline) {
            Map<String, Object> state =
                    readPtkAnalysisReadinessAcrossWindows(driver, zapid, sessionId);
            lastState = state;
            if (booleanValue(state, "ready")) {
                if (readySince <= 0L) {
                    readySince = System.currentTimeMillis();
                }
                if (System.currentTimeMillis() - readySince >= 1_000L) {
                    ptk.recordBrowserCoverageAnalysisReady(
                            zapid, targetUrl, observedUrl, stringValue(state, "summary"));
                    return;
                }
            } else {
                readySince = 0L;
            }
            quietSleep(250);
        }

        String reason = stringValue(lastState, "reason");
        progress.info(
                "PTK browser coverage analysis readiness timeout for "
                        + targetUrl
                        + (reason != null ? " reason=" + reason : ""));
    }

    private Map<String, Object> readPtkAnalysisReadinessAcrossWindows(
            WebDriver driver, String zapid, String sessionId) {
        if (!(driver instanceof JavascriptExecutor js)) {
            return Map.of("ok", false, "ready", false, "reason", "javascript_executor_unavailable");
        }

        String originalWindow = null;
        List<String> windowHandles = new ArrayList<>();
        try {
            originalWindow = driver.getWindowHandle();
            windowHandles.addAll(driver.getWindowHandles());
        } catch (RuntimeException e) {
            return withReadinessDiagnostic(
                    Map.of("ok", false, "ready", false, "reason", "webdriver_windows_unavailable"),
                    -1,
                    0,
                    null,
                    e);
        }

        if (windowHandles.isEmpty()) {
            return withReadinessDiagnostic(
                    readPtkAnalysisReadiness(js, zapid, sessionId),
                    0,
                    0,
                    safeCurrentUrl(driver),
                    null);
        }

        Map<String, Object> best = null;
        for (int i = 0; i < windowHandles.size(); i++) {
            String currentUrl = null;
            Map<String, Object> state;
            try {
                driver.switchTo().window(windowHandles.get(i));
                currentUrl = safeCurrentUrl(driver);
                state =
                        withReadinessDiagnostic(
                                readPtkAnalysisReadiness(js, zapid, sessionId),
                                i,
                                windowHandles.size(),
                                currentUrl,
                                null);
            } catch (RuntimeException e) {
                state =
                        withReadinessDiagnostic(
                                Map.of(
                                        "ok",
                                        false,
                                        "ready",
                                        false,
                                        "reason",
                                        "webdriver_script_failed"),
                                i,
                                windowHandles.size(),
                                currentUrl,
                                e);
            }
            if (booleanValue(state, "ready")) {
                restoreWindow(driver, originalWindow);
                return state;
            }
            if (isBetterReadinessState(state, best)) {
                best = state;
            }
        }

        restoreWindow(driver, originalWindow);
        return best != null
                ? best
                : Map.of("ok", false, "ready", false, "reason", "progress_unavailable");
    }

    private static Map<String, Object> withReadinessDiagnostic(
            Map<String, Object> state,
            int windowIndex,
            int windowCount,
            String windowUrl,
            RuntimeException error) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (state != null) {
            result.putAll(state);
        }
        result.put("windowIndex", windowIndex);
        result.put("windowCount", windowCount);
        if (windowUrl != null && !windowUrl.isBlank()) {
            result.put("windowUrl", windowUrl);
        }
        if (error != null) {
            result.put("error", error.getMessage());
        }
        return result;
    }

    private static boolean isBetterReadinessState(
            Map<String, Object> candidate, Map<String, Object> current) {
        if (candidate == null) {
            return false;
        }
        if (current == null) {
            return true;
        }
        boolean candidateOk = booleanValue(candidate, "ok");
        boolean currentOk = booleanValue(current, "ok");
        if (candidateOk != currentOk) {
            return candidateOk;
        }
        String candidateReason = stringValue(candidate, "reason");
        String currentReason = stringValue(current, "reason");
        boolean candidateBridgeMissing = "zap_progress_bridge_unavailable".equals(candidateReason);
        boolean currentBridgeMissing = "zap_progress_bridge_unavailable".equals(currentReason);
        if (candidateBridgeMissing != currentBridgeMissing) {
            return !candidateBridgeMissing;
        }
        return false;
    }

    private static void restoreWindow(WebDriver driver, String originalWindow) {
        if (driver == null || originalWindow == null || originalWindow.isBlank()) {
            return;
        }
        try {
            driver.switchTo().window(originalWindow);
        } catch (RuntimeException ignored) {
            // The close path may have already removed the original window.
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readPtkAnalysisReadiness(
            JavascriptExecutor js, String zapid, String sessionId) {
        String script =
                """
                const done = arguments[arguments.length - 1];
                const explicitZapId = arguments[0] || null;
                const explicitSessionId = arguments[1] || null;
                const timeout = (ms) => new Promise((resolve) => setTimeout(() => resolve({ ok: false, reason: 'progress_timeout' }), ms));
                const terminal = new Set(['stopped', 'completed', 'cancelled', 'error', 'engine_incomplete']);
                const str = (value) => String(value || '').toLowerCase();
                const num = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
                const hasValue = (value) => value !== undefined && value !== null;
                const currentPageUrl = String(window.location && window.location.href || '');
                const sameDocumentUrl = (left, right) => {
                  try {
                    const a = new URL(String(left || ''), currentPageUrl);
                    const b = new URL(String(right || ''), currentPageUrl);
                    return a.origin === b.origin && a.pathname === b.pathname && a.search === b.search && a.hash === b.hash;
                  } catch (_) {
                    return String(left || '') === String(right || '');
                  }
                };
                const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms || 0)));
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
                const sendZapProgressMessage = (timeoutMs = 2500) => new Promise((resolve) => {
                  try {
                    const nonce = document.getElementById('__ptk_automation_nonce__')?.dataset?.nonce || '';
                    if (!nonce) {
                      resolve({ ok: false, reason: 'zap_progress_bridge_unavailable' });
                      return;
                    }
                    const requestId = 'ptk-zap-progress-' + Date.now() + '-' + Math.random().toString(36).slice(2);
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
                      type: 'get-session-progress',
                      sessionId: explicitSessionId,
                      options: {
                        sessionId: explicitSessionId,
                        source: 'zap_browser_close',
                        zapid: explicitZapId
                      }
                    }, '*');
                    setTimeout(() => finish(disabledFallback || { ok: false, reason: 'progress_direct_timeout' }), Math.max(500, timeoutMs || 2500));
                  } catch (error) {
                    resolve({ ok: false, reason: error && error.message || String(error) });
                  }
                });
                const readProgress = async () => {
                  await refreshAutomationStatus();
                  const automation = window.PTK_AUTOMATION;
                  if (automation && automation.bridgeId === 'ptk-automation-bridge' && typeof automation.getSessionProgress === 'function') {
                    const progress = await Promise.race([
                      Promise.resolve(automation.getSessionProgress({ sessionId: explicitSessionId, source: 'zap_browser_close', zapid: explicitZapId })),
                      timeout(2500)
                    ]);
                    if (progress && progress.ok !== false) return progress;
                    const reason = progress && (progress.error || progress.reason);
                    if (reason && reason !== 'automation_disabled') return progress;
                  }
                  return await sendZapProgressMessage(2500);
                };
                const readyForEngine = (name, entry, progress) => {
                  const state = str(entry && entry.status || entry && entry.state);
                  if (!entry || typeof entry !== 'object') return { ready: false, state: 'missing' };
                  const publisherDrain = progress && progress.zapPublisherDrain && typeof progress.zapPublisherDrain === 'object'
                    ? progress.zapPublisherDrain
                    : null;
                  const publisherReady = !publisherDrain || publisherDrain.drained !== false;
                  const terminalState = terminal.has(state);
                  if (name === 'SAST') {
                    const collectionState = str(entry.collectionState);
                    const analysisState = str(entry.analysisState);
                    const phase = str(entry.phase);
                    const firstStarted = entry.firstCollectionStarted === true
                      || entry.hasObservedCollection === true
                      || num(entry.currentGeneration) > 0
                      || num(entry.lastCompletedGeneration) > 0;
                    const firstSettled = entry.firstCollectionSettled === true
                      || num(entry.lastCompletedGeneration) >= num(entry.currentGeneration);
                    const active = num(entry.activeCollectionCount);
                    const pending = num(entry.pendingCollectionCount);
                    const completeState = collectionState === 'waiting_for_page_activity'
                      || collectionState === 'completed'
                      || collectionState === 'idle'
                      || analysisState === 'complete'
                      || phase === 'waiting'
                      || phase === 'idle';
                    const lastCompletedFile = entry.lastCompletedFile || '';
                    const collectionEvidence = hasValue(entry.lastCompletedScriptsCount)
                      || hasValue(entry.lastCompletedHtmlChars)
                      || hasValue(entry.lastCompletedFindingsCount)
                      || hasValue(entry.lastCompletedArtifactsCount);
                    const pageCollected = sameDocumentUrl(lastCompletedFile, currentPageUrl)
                      && collectionEvidence
                      && Boolean(entry.lastCompletedAt || entry.lastCompletedCollectionId);
                    const pageCollectionState = pageCollected
                      ? 'page_collection_complete'
                      : (terminalState
                        ? 'terminal_without_current_page_collection'
                        : (lastCompletedFile ? 'waiting_for_current_page_collection' : 'collection_not_completed'));
                    return {
                      ready: firstStarted && firstSettled && active === 0 && pending === 0 && completeState && pageCollected && publisherReady,
                      state: !publisherReady ? 'publisher_not_drained' : (!pageCollected ? pageCollectionState : (collectionState || analysisState || phase || state || 'unknown'))
                    };
                  }
                  if (name === 'IAST') {
                    const runtimeHealthState = str(entry.runtimeHealthState);
                    const modulesReady = entry.modulesLoaded === true;
                    const pendingFindingReports = num(entry.pendingFindingReports);
                    const lastModuleSend = entry.lastModuleSendResult && typeof entry.lastModuleSendResult === 'object'
                      ? entry.lastModuleSendResult
                      : null;
                    const modulesErrored = (lastModuleSend && lastModuleSend.ok === false) || /error|failed/.test(runtimeHealthState);
                    const moduleDeliveryObserved = entry.moduleDeliveryObserved === true
                      || num(entry.modulesSentOk) > 0
                      || modulesReady;
                    const agentObservedActivity = entry.agentObservedActivity === true
                      || num(entry.findingReportsAccepted) > 0
                      || num(entry.runtimeSignalsAccepted) > 0
                      || num(entry.runtimeHealthCount) > 0
                      || num(entry.runtimeEventsCount) > 0
                      || num(entry.findingsCount) > 0;
                    const iastReady = (entry.agentReady === true && (modulesReady || moduleDeliveryObserved)
                        || agentObservedActivity
                        || moduleDeliveryObserved)
                      && pendingFindingReports === 0
                      && !modulesErrored
                      && publisherReady;
                    return {
                      ready: iastReady,
                      state: !publisherReady
                        ? 'publisher_not_drained'
                        : (iastReady
                          ? (entry.readyEvidence || (agentObservedActivity ? 'agent_runtime_observed' : 'module_delivery_observed'))
                          : (terminalState ? 'terminal_without_iast_evidence' : (state || 'unknown'))),
                      detail: [
                        'ar=' + (entry.agentReady === true ? 1 : 0),
                        'ml=' + (modulesReady ? 1 : 0),
                        'pf=' + pendingFindingReports,
                        'fh=' + num(entry.findingReportsAccepted),
                        'rs=' + num(entry.runtimeSignalsAccepted),
                        'rh=' + num(entry.runtimeHealthCount),
                        'fc=' + num(entry.findingsCount)
                      ].join(';')
                    };
                  }
                  if (name === 'DAST') {
                    const captureStats = entry.captureStats && typeof entry.captureStats === 'object'
                      ? entry.captureStats
                      : {};
                    const pendingCaptures = num(entry.pendingCaptures || captureStats.pendingObservedRequests);
                    const active = num(entry.activeTasks)
                      + num(entry.taskQueue)
                      + num(entry.requestQueue)
                      + num(entry.pendingPlans)
                      + num(entry.planning)
                      + pendingCaptures;
                    const planned = num(entry.progress && entry.progress.total);
                    const executed = num(entry.progress && entry.progress.done);
                    return {
                      ready: active === 0,
                      state: pendingCaptures > 0 ? 'capture_pending' : (active === 0 ? 'quiet' : 'active'),
                      detail: [
                        'p=' + planned,
                        'e=' + executed,
                        'rq=' + num(entry.requestQueue),
                        'tq=' + num(entry.taskQueue),
                        'pp=' + num(entry.pendingPlans),
                        'pc=' + pendingCaptures,
                        'seed=' + num(entry.seededRequests),
                        'hseed=' + num(entry.historySeededRequests),
                        'pseed=' + num(entry.proxySeededRequests),
                        'f=' + num(entry.findingsCount)
                      ].join(';')
                    };
                  }
                  if (terminalState) return { ready: true, state };
                  return { ready: true, state: state || 'unknown' };
                };
                (async () => {
                  try {
                    const automation = window.PTK_AUTOMATION;
                    if (!automation || automation.bridgeId !== 'ptk-automation-bridge' || typeof automation.getSessionProgress !== 'function') {
                      if (!explicitSessionId) {
                        done({ ok: false, ready: false, reason: 'session_id_unavailable' });
                        return;
                      }
                    }
                    if (!explicitSessionId) {
                      done({ ok: false, ready: false, reason: 'session_id_unavailable' });
                      return;
                    }
                    const progress = await readProgress();
                    if (!progress || progress.ok === false) {
                      done({ ok: false, ready: false, reason: progress && progress.error || progress && progress.reason || 'progress_unavailable' });
                      return;
                    }
                    const engines = progress.engines && typeof progress.engines === 'object' ? progress.engines : {};
                    const names = Object.keys(engines).map((name) => String(name || '').toUpperCase()).filter(Boolean);
                    if (!names.length) {
                      done({ ok: true, ready: false, reason: 'no_engines' });
                      return;
                    }
                    const states = {};
                    const notReady = [];
                    for (const name of names) {
                      const result = readyForEngine(name, engines[name] || {}, progress);
                      states[name] = result.state + (result.detail ? '{' + result.detail + '}' : '');
                      if (!result.ready) notReady.push(name + ':' + result.state);
                    }
                    done({
                      ok: true,
                      ready: notReady.length === 0,
                      reason: notReady.length ? notReady.join(',') : 'ready',
                      summary: names.map((name) => name + ':' + (states[name] || 'unknown')).join(',')
                    });
                  } catch (error) {
                    done({ ok: false, ready: false, reason: error && error.message || String(error) });
                  }
                })();
                """;
        Object value = js.executeAsyncScript(script, zapid, sessionId);
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return Map.of("ok", false, "ready", false, "reason", "unexpected_result");
    }

    private static boolean booleanValue(Map<String, Object> map, String key) {
        Object value = map != null ? map.get(key) : null;
        return Boolean.TRUE.equals(value) || "true".equalsIgnoreCase(String.valueOf(value));
    }

    private static String stringValue(Map<String, Object> map, String key) {
        Object value = map != null ? map.get(key) : null;
        return value != null ? String.valueOf(value) : null;
    }

    private void closeDirectBrowser(
            ExtensionClientIntegration client,
            DirectBrowser browser,
            String zapid,
            String targetUrl,
            AutomationProgress progress) {
        if (browser == null || browser.driver == null) {
            return;
        }
        boolean closed = false;
        if (browser.process != null) {
            try {
                var shutdown = browser.process.getClass().getDeclaredMethod("shutdown");
                shutdown.setAccessible(true);
                shutdown.invoke(browser.process);
                closed = true;
            } catch (ReflectiveOperationException | RuntimeException e) {
                ptk.recordBrowserCoverageInvalid(
                        zapid, targetUrl, "webdriver_script_failed", e.getMessage());
                LOGGER.warn(
                        "PTK_REFLECTION_FALLBACK component=client-spider-shutdown zapid={} url={} reason={}",
                        zapid,
                        targetUrl,
                        e.getMessage());
                progress.warn(
                        "PTK browser coverage ClientSpider process shutdown failed for "
                                + targetUrl
                                + ": "
                                + e.getMessage());
            }
        }
        try {
            unregisterClientSpider(browser.spider);
        } catch (RuntimeException e) {
            progress.warn(
                    "PTK browser coverage failed to unregister ClientSpider for "
                            + targetUrl
                            + ": "
                            + e.getMessage());
        }
        if (closed) {
            return;
        }
        try {
            client.browserClosing(browser.driver);
        } catch (RuntimeException e) {
            ptk.recordBrowserCoverageInvalid(
                    zapid, targetUrl, "webdriver_script_failed", e.getMessage());
            progress.warn(
                    "PTK browser coverage close contract failed for "
                            + targetUrl
                            + ": "
                            + e.getMessage());
        } finally {
            try {
                browser.driver.quit();
            } catch (RuntimeException e) {
                progress.warn(
                        "PTK browser coverage failed to quit browser for "
                                + targetUrl
                                + ": "
                                + e.getMessage());
            }
        }
    }

    private static void unregisterClientSpider(ClientSpider spider) {
        if (spider == null) {
            return;
        }
        detachClientSpiderEventConsumer(spider);
        try {
            var unload = ClientSpider.class.getDeclaredMethod("unload");
            unload.setAccessible(true);
            unload.invoke(spider);
        } catch (ReflectiveOperationException | RuntimeException e) {
            // Best-effort cleanup only. The WebDriver process and callback proxy are already
            // closed.
            LOGGER.warn(
                    "PTK_REFLECTION_FALLBACK component=client-spider-unload reason={}",
                    e.getMessage());
        }
    }

    private static void detachClientSpiderEventConsumer(ClientSpider spider) {
        if (spider == null) {
            return;
        }
        ZAP.getEventBus().unregisterConsumer(spider, CLIENT_MAP_EVENT_SOURCE);
    }

    private static String safeCurrentUrl(WebDriver driver) {
        if (driver == null) {
            return null;
        }
        try {
            return driver.getCurrentUrl();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String extractZapIdFromCallbackUrl(String url) {
        if (url == null || url.isBlank() || !url.contains("zapid=")) {
            return null;
        }
        int start = url.indexOf("zapid=");
        if (start < 0) {
            return null;
        }
        start += "zapid=".length();
        int end = start;
        while (end < url.length()) {
            char ch = url.charAt(end);
            if (ch == '&' || ch == '#' || ch == '?' || Character.isWhitespace(ch)) {
                break;
            }
            end++;
        }
        return end > start ? url.substring(start, end) : null;
    }

    private ClientOptions createClientOptions() {
        ClientOptions options = new ClientOptions();
        options.load(new XMLConfiguration());
        String browserId = nonBlank(parameters.getBrowserId());
        if (browserId != null) {
            options.setBrowserId(browserId);
        }
        options.setThreadCount(1);
        options.setInitialLoadTimeInSecs(
                clamp(parameters.getInitialLoadTime(), DEFAULT_INITIAL_LOAD_TIME_SECS, 120));
        options.setPageLoadTimeInSecs(
                clamp(parameters.getPageLoadTime(), DEFAULT_PAGE_LOAD_TIME_SECS, 120));
        options.setShutdownTimeInSecs(
                clamp(parameters.getShutdownTime(), DEFAULT_SHUTDOWN_TIME_SECS, 120));
        options.setMaxChildren(0);
        options.setMaxDepth(0);
        options.setMaxDuration(0);
        String scopeCheck = nonBlank(parameters.getScopeCheck());
        if (scopeCheck != null) {
            options.setScopeCheck(scopeCheck);
        }
        if (parameters.getLogoutAvoidance() != null) {
            options.setLogoutAvoidance(parameters.getLogoutAvoidance());
        }
        return options;
    }

    private int attemptTimeoutSecs() {
        return clamp(parameters.getAttemptTimeout(), DEFAULT_ATTEMPT_TIMEOUT_SECS, 600);
    }

    private int evidenceGraceMs() {
        return clamp(parameters.getEvidenceGraceMs(), DEFAULT_EVIDENCE_GRACE_MS, 30000);
    }

    private int launchStaggerMs() {
        return clamp(parameters.getLaunchStaggerMs(), DEFAULT_LAUNCH_STAGGER_MS, 5000);
    }

    private static int retryConcurrencyFallback(int concurrency) {
        return Math.max(1, Math.min(DEFAULT_RETRY_NUMBER_OF_BROWSERS, concurrency));
    }

    static int resolveRetryConcurrency(Integer configured, int concurrency) {
        return clamp(configured, retryConcurrencyFallback(concurrency), concurrency);
    }

    private static int batchLimitForNextTargets(
            List<CoverageTarget> pending, int concurrency, int retryConcurrency) {
        if (pending.isEmpty()) {
            return concurrency;
        }
        return pending.get(0).attempts > 0 ? retryConcurrency : concurrency;
    }

    private static boolean isCoverageSatisfied(
            BrowserCoverageSnapshot snapshot, boolean requirePtkSession) {
        return requirePtkSession ? snapshot.hasPtkSession() : snapshot.hasBrowserLoad();
    }

    private static int clamp(Integer value, int fallback, int max) {
        int candidate = value != null ? value.intValue() : fallback;
        return Math.max(0, Math.min(max, candidate));
    }

    private static void addUrl(Set<String> urls, String value) {
        String normalized = normalizeHttpTargetUrl(value);
        if (normalized != null) {
            urls.add(normalized);
        }
    }

    private static void addConfiguredUrls(
            Set<String> urls, AutomationEnvironment env, String configuredUrls) {
        if (configuredUrls == null || configuredUrls.isBlank()) {
            return;
        }
        for (String candidate : configuredUrls.split("[\\r\\n,]+")) {
            addUrl(urls, env.replaceVars(candidate));
        }
    }

    private static String normalizeHttpTargetUrl(String targetUrl) {
        return PtkUrlUtils.normalizeHttpTargetUrl(targetUrl);
    }

    private static String nonBlank(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static void quietSleep(long ms) {
        try {
            Thread.sleep(Math.max(0L, ms));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static final class Data extends AutomationData {
        private int loadedUrls;
        private int missingUrls;

        public int getLoadedUrls() {
            return loadedUrls;
        }

        public int getMissingUrls() {
            return missingUrls;
        }
    }

    public static final class Parameters extends AutomationData {
        private String context;
        private String source = "contextUrls";
        private String url;
        private String urls;
        private String browserId;
        private Integer numberOfBrowsers = DEFAULT_NUMBER_OF_BROWSERS;
        private Integer initialLoadTime = DEFAULT_INITIAL_LOAD_TIME_SECS;
        private Integer pageLoadTime = DEFAULT_PAGE_LOAD_TIME_SECS;
        private Integer shutdownTime = DEFAULT_SHUTDOWN_TIME_SECS;
        private Integer attemptTimeout = DEFAULT_ATTEMPT_TIMEOUT_SECS;
        private Integer evidenceGraceMs = DEFAULT_EVIDENCE_GRACE_MS;
        private Integer launchStaggerMs = DEFAULT_LAUNCH_STAGGER_MS;
        private Integer retryNumberOfBrowsers = DEFAULT_RETRY_NUMBER_OF_BROWSERS;
        private Integer maxRetriesPerUrl = DEFAULT_MAX_RETRIES_PER_URL;
        private Boolean requirePtkSession = true;
        private Boolean failOnMissingBrowserLoad = false;
        private String scopeCheck = "STRICT";
        private Boolean logoutAvoidance;

        public String getContext() {
            return context;
        }

        public void setContext(String context) {
            this.context = context;
        }

        public String getSource() {
            return source;
        }

        public void setSource(String source) {
            this.source = source;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getUrls() {
            return urls;
        }

        public void setUrls(String urls) {
            this.urls = urls;
        }

        public String getBrowserId() {
            return browserId;
        }

        public void setBrowserId(String browserId) {
            this.browserId = browserId;
        }

        public Integer getNumberOfBrowsers() {
            return numberOfBrowsers;
        }

        public void setNumberOfBrowsers(Integer numberOfBrowsers) {
            this.numberOfBrowsers = numberOfBrowsers;
        }

        public Integer getInitialLoadTime() {
            return initialLoadTime;
        }

        public void setInitialLoadTime(Integer initialLoadTime) {
            this.initialLoadTime = initialLoadTime;
        }

        public Integer getPageLoadTime() {
            return pageLoadTime;
        }

        public void setPageLoadTime(Integer pageLoadTime) {
            this.pageLoadTime = pageLoadTime;
        }

        public Integer getShutdownTime() {
            return shutdownTime;
        }

        public void setShutdownTime(Integer shutdownTime) {
            this.shutdownTime = shutdownTime;
        }

        public Integer getAttemptTimeout() {
            return attemptTimeout;
        }

        public void setAttemptTimeout(Integer attemptTimeout) {
            this.attemptTimeout = attemptTimeout;
        }

        public Integer getEvidenceGraceMs() {
            return evidenceGraceMs;
        }

        public void setEvidenceGraceMs(Integer evidenceGraceMs) {
            this.evidenceGraceMs = evidenceGraceMs;
        }

        public Integer getLaunchStaggerMs() {
            return launchStaggerMs;
        }

        public void setLaunchStaggerMs(Integer launchStaggerMs) {
            this.launchStaggerMs = launchStaggerMs;
        }

        public Integer getRetryNumberOfBrowsers() {
            return retryNumberOfBrowsers;
        }

        public void setRetryNumberOfBrowsers(Integer retryNumberOfBrowsers) {
            this.retryNumberOfBrowsers = retryNumberOfBrowsers;
        }

        public Integer getMaxRetriesPerUrl() {
            return maxRetriesPerUrl;
        }

        public void setMaxRetriesPerUrl(Integer maxRetriesPerUrl) {
            this.maxRetriesPerUrl = maxRetriesPerUrl;
        }

        public Boolean getRequirePtkSession() {
            return requirePtkSession;
        }

        public void setRequirePtkSession(Boolean requirePtkSession) {
            this.requirePtkSession = requirePtkSession;
        }

        public Boolean getFailOnMissingBrowserLoad() {
            return failOnMissingBrowserLoad;
        }

        public void setFailOnMissingBrowserLoad(Boolean failOnMissingBrowserLoad) {
            this.failOnMissingBrowserLoad = failOnMissingBrowserLoad;
        }

        public String getScopeCheck() {
            return scopeCheck;
        }

        public void setScopeCheck(String scopeCheck) {
            this.scopeCheck = scopeCheck;
        }

        public Boolean getLogoutAvoidance() {
            return logoutAvoidance;
        }

        public void setLogoutAvoidance(Boolean logoutAvoidance) {
            this.logoutAvoidance = logoutAvoidance;
        }
    }

    private static final class CoverageTarget {
        private final String url;
        private int attempts;
        private String finalState = "pending";
        private String lastError;

        private CoverageTarget(String url) {
            this.url = url;
        }
    }

    private static final class RunningAttempt {
        private final CoverageTarget target;

        @SuppressWarnings("unused")
        private final long startedAtMs;

        private RunningAttempt(CoverageTarget target, long startedAtMs) {
            this.target = target;
            this.startedAtMs = startedAtMs;
        }
    }

    private static final class DirectBrowser {
        private final ClientSpider spider;
        private final Object process;
        private final WebDriver driver;

        private DirectBrowser(ClientSpider spider, Object process, WebDriver driver) {
            this.spider = spider;
            this.process = process;
            this.driver = driver;
        }
    }
}
