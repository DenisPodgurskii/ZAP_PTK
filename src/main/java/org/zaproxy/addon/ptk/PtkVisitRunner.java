package org.zaproxy.addon.ptk;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Collections;
import java.util.WeakHashMap;
import java.util.regex.Pattern;
import java.time.Duration;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.IntConsumer;
import java.util.function.LongSupplier;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WindowType;

/** A bounded, extension-owned transport for visit capability and checkpoint requests. */
final class PtkVisitRunner {
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9_-]{1,128}");
    private static final Pattern RUNNER_URL =
            Pattern.compile("chrome-extension://[a-p]{32}/ptk/internal/zap-runner\\.html");
    private static final String TRUSTED_RUNNER = "ptk-zap-visit-v1";
    private record RunnerTab(String handle, String url) {}
    // One trusted extension tab per owned WebDriver. Reopening and closing a
    // tab for every short checkpoint adds WebDriver navigation commands to
    // every dwell poll; the target remains selected between requests.
    private static final Map<WebDriver, RunnerTab> RUNNER_TABS =
            Collections.synchronizedMap(new WeakHashMap<>());
    private static final String READY_SCRIPT =
            "return {url: location.href, state: document.readyState, runtimeId: "
                    + "(globalThis.browser?.runtime || globalThis.chrome?.runtime)?.id};";
    private static final String SCRIPT =
            """
            const payload = arguments[0];
            const responseTimeoutMs = arguments[1];
            const done = arguments[arguments.length - 1];
            const runtime = globalThis.browser?.runtime || globalThis.chrome?.runtime;
            const localFailure = reason => ({ok:false, reason,
              trustedRunner:'ptk-zap-visit-v1', requestId:payload.requestId});
            let settled = false;
            const finish = value => {
              if (settled) return;
              settled = true;
              done(value || localFailure('visit_empty_response'));
            };
            if (!runtime || typeof runtime.sendMessage !== 'function') {
              finish(localFailure('visit_runtime_unavailable'));
            } else {
              const timer = setTimeout(() => finish(localFailure('visit_response_timeout')), responseTimeoutMs);
              const complete = value => { clearTimeout(timer); finish(value); };
              try {
                if (globalThis.browser?.runtime === runtime) {
                  Promise.resolve(runtime.sendMessage(payload)).then(
                    complete, () => complete(localFailure('visit_runtime_failed')));
                } else {
                  runtime.sendMessage(payload, value => complete(value || localFailure(
                    runtime.lastError ? 'visit_runtime_failed' : 'visit_empty_response')));
                }
              } catch (_) {
                complete(localFailure('visit_runtime_failed'));
              }
            }
            """;

    private PtkVisitRunner() {}

    private static final Set<String> RETRYABLE_VISIT_REASONS = Set.of(
            "visit_observation_started", "visit_observation_pending");

    /** Keep the target tab active during the observation interval, not the runner tab. */
    static Map<String, Object> observeWithTargetFocus(
            int observationMs, int maxWaitMs, boolean depart,
            BiFunction<String, Integer, Map<String, Object>> checkpoint) {
        return observeWithTargetFocus(observationMs, maxWaitMs, depart, checkpoint,
                System::nanoTime, millis -> {
                    try {
                        Thread.sleep(millis);
                    } catch (InterruptedException error) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("visit_observation_interrupted", error);
                    }
                });
    }

    static Map<String, Object> observeWithTargetFocus(
            int observationMs, int maxWaitMs, boolean depart,
            BiFunction<String, Integer, Map<String, Object>> checkpoint,
            LongSupplier clock, IntConsumer sleep) {
        if (observationMs < 1 || maxWaitMs < observationMs || maxWaitMs > 300000) {
            return Map.of("ok", false, "reason", "visit_request_invalid");
        }
        long started = clock.getAsLong();
        int rebinds = 0;
        String lastReason = "visit_no_checkpoint";
        while (true) {
            if (expired(clock, started, maxWaitMs)) {
                return observationTimeout(lastReason);
            }
            Map<String, Object> result = checkpoint.apply("advance", observationMs);
            if (result != null && result.get("reason") instanceof String reason) lastReason = reason;
            if (expired(clock, started, maxWaitMs)) {
                return observationTimeout(lastReason);
            }
            if (result == null) return Map.of("ok", false, "reason", "visit_response_invalid");
            if (Boolean.TRUE.equals(result.get("ok"))) {
                if (!"observed_interval".equals(result.get("kind"))) {
                    return Map.of("ok", false, "reason", "visit_response_invalid");
                }
                if (!depart) return result;
                Map<String, Object> departure = checkpoint.apply("departure", 0);
                if (departure != null && departure.get("reason") instanceof String reason) {
                    lastReason = reason;
                }
                if (expired(clock, started, maxWaitMs)) {
                    return observationTimeout(lastReason);
                }
                if (departure == null) return Map.of("ok", false, "reason", "visit_response_invalid");
                if (Boolean.TRUE.equals(departure.get("ok"))) {
                    if (!"departure_cut".equals(departure.get("kind"))) {
                        return Map.of("ok", false, "reason", "visit_response_invalid");
                    }
                    Map<String, Object> combined = new LinkedHashMap<>(departure);
                    combined.put("kind", "observed_departure_cut");
                    combined.put("elapsedMs", result.get("elapsedMs"));
                    return combined;
                }
                return departure;
            } else if ("visit_stream_rebind_unverified".equals(result.get("reason"))
                    && rebinds++ < 4) {
                Map<String, Object> rebound = checkpoint.apply("rebind", 0);
                if (rebound != null && rebound.get("reason") instanceof String reason) {
                    lastReason = reason;
                }
                if (expired(clock, started, maxWaitMs)) {
                    return observationTimeout(lastReason);
                }
                if (rebound == null || !Boolean.TRUE.equals(rebound.get("ok"))) {
                    return rebound == null ? Map.of("ok", false, "reason", "visit_rebind_unavailable") : rebound;
                }
            } else if (!(result.get("reason") instanceof String reason)
                    || !RETRYABLE_VISIT_REASONS.contains(reason)) {
                return result;
            }
            long remaining = maxWaitMs - (clock.getAsLong() - started) / 1_000_000L;
            if (remaining <= 0) return observationTimeout(lastReason);
            sleep.accept((int) Math.min(remaining, Math.max(100, observationMs)));
        }
    }

    private static Map<String, Object> observationTimeout(String lastReason) {
        return Map.of("ok", false, "reason", "visit_observation_timeout",
                "lastReason", lastReason);
    }

    private static boolean expired(LongSupplier clock, long started, int maxWaitMs) {
        long elapsed = clock.getAsLong() - started;
        return elapsed < 0 || elapsed >= Duration.ofMillis(maxWaitMs).toNanos();
    }

    static boolean isSupportedRunnerUrl(String runnerUrl) {
        return runnerUrl != null && RUNNER_URL.matcher(runnerUrl).matches();
    }

    static Map<String, Object> request(
            WebDriver driver, String runnerUrl, Map<String, Object> payload) {
        Objects.requireNonNull(driver);
        Objects.requireNonNull(payload);
        if (!(driver instanceof JavascriptExecutor javascript)
                || !isSupportedRunnerUrl(runnerUrl)
                || !ID.matcher(String.valueOf(payload.get("requestId"))).matches()) {
            throw new IllegalArgumentException("visit_runner_request_invalid");
        }
        synchronized (driver) {
            return requestOnDriver(driver, (JavascriptExecutor) driver, runnerUrl, payload);
        }
    }

    private static Map<String, Object> requestOnDriver(
            WebDriver driver, JavascriptExecutor javascript, String runnerUrl,
            Map<String, Object> payload) {
        String originalWindow = null;
        String runnerWindow = null;
        boolean keepRunner = false;
        Duration previousScriptTimeout = null;
        RuntimeException failure = null;
        try {
            long responseTimeoutMs = 3000;
            if ("visit_prestart".equals(payload.get("type"))) {
                responseTimeoutMs = 20000;
                previousScriptTimeout = driver.manage().timeouts().getScriptTimeout();
                if (previousScriptTimeout == null) {
                    throw new IllegalStateException("visit_runner_script_timeout_unavailable");
                }
                driver.manage().timeouts().scriptTimeout(Duration.ofMillis(responseTimeoutMs + 1000));
            } else if ("visit_observe".equals(payload.get("type"))) {
                Object budget = payload.get("maxWaitMs");
                if (!(budget instanceof Number value)
                        || value.longValue() < 1
                        || value.longValue() > 300000
                        || value.doubleValue() != value.longValue()) {
                    throw new IllegalArgumentException("visit_runner_budget_invalid");
                }
                responseTimeoutMs = value.longValue() + 2000;
                previousScriptTimeout = driver.manage().timeouts().getScriptTimeout();
                if (previousScriptTimeout == null) {
                    throw new IllegalStateException("visit_runner_script_timeout_unavailable");
                }
                driver.manage().timeouts().scriptTimeout(Duration.ofMillis(responseTimeoutMs + 1000));
            }
            originalWindow = driver.getWindowHandle();
            RunnerTab existing = RUNNER_TABS.get(driver);
            if (existing != null) {
                if (!runnerUrl.equals(existing.url())) {
                    throw new IllegalStateException("visit_runner_identity_changed");
                }
                try {
                    driver.switchTo().window(existing.handle());
                    runnerWindow = existing.handle();
                    awaitRunnerReady(javascript, runnerUrl);
                    keepRunner = true;
                } catch (RuntimeException error) {
                    RUNNER_TABS.remove(driver);
                    // A failed WebDriver command is not followed by another
                    // close command here; the process owner contains it.
                    keepRunner = true;
                    throw error;
                }
            } else {
                driver.switchTo().newWindow(WindowType.TAB);
                runnerWindow = driver.getWindowHandle();
                if (runnerWindow == null || runnerWindow.equals(originalWindow)) {
                    throw new IllegalStateException("visit_runner_window_unavailable");
                }
                driver.navigate().to(runnerUrl);
                awaitRunnerReady(javascript, runnerUrl);
                RUNNER_TABS.put(driver, new RunnerTab(runnerWindow, runnerUrl));
                keepRunner = true;
            }
            return validateResponse(javascript.executeAsyncScript(SCRIPT, payload, responseTimeoutMs),
                    String.valueOf(payload.get("requestId")));
        } catch (RuntimeException error) {
            failure = error;
            throw error;
        } finally {
            RuntimeException cleanupFailure = null;
            if (runnerWindow != null && !keepRunner) {
                try {
                    driver.switchTo().window(runnerWindow);
                    driver.close();
                } catch (RuntimeException error) {
                    cleanupFailure = error;
                }
            }
            if (originalWindow != null) {
                try {
                    driver.switchTo().window(originalWindow);
                } catch (RuntimeException error) {
                    if (cleanupFailure == null) cleanupFailure = error;
                    else cleanupFailure.addSuppressed(error);
                }
            }
            if (previousScriptTimeout != null) {
                try {
                    driver.manage().timeouts().scriptTimeout(previousScriptTimeout);
                } catch (RuntimeException error) {
                    if (cleanupFailure == null) cleanupFailure = error;
                    else cleanupFailure.addSuppressed(error);
                }
            }
            if (cleanupFailure != null) {
                if (failure != null) failure.addSuppressed(cleanupFailure);
                else throw cleanupFailure;
            }
        }
    }

    static void release(WebDriver driver) {
        if (driver == null) return;
        synchronized (driver) {
            RunnerTab runner = RUNNER_TABS.remove(driver);
            if (runner == null) return;
            String original = driver.getWindowHandle();
            try {
                driver.switchTo().window(runner.handle());
                driver.close();
            } finally {
                driver.switchTo().window(original);
            }
        }
    }

    static void forget(WebDriver driver) {
        if (driver != null) RUNNER_TABS.remove(driver);
    }

    /** A value-free failure site for retained multi-browser diagnostics. */
    static String failureDiagnostic(RuntimeException error) {
        StackTraceElement site = null;
        for (StackTraceElement frame : error.getStackTrace()) {
            if (PtkVisitRunner.class.getName().equals(frame.getClassName())) {
                site = frame;
                break;
            }
        }
        String message = error.getMessage();
        String code = site != null && message != null
                && message.matches("visit_[a-z0-9_]{1,127}")
                ? message : error.getClass().getSimpleName();
        return site == null ? code + "@external"
                : code + "@" + site.getMethodName() + ":" + site.getLineNumber();
    }

    private static void awaitRunnerReady(JavascriptExecutor javascript, String runnerUrl) {
        String extensionId = runnerUrl.substring("chrome-extension://".length(),
                "chrome-extension://".length() + 32);
        long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
        do {
            try {
                Object raw = javascript.executeScript(READY_SCRIPT);
                if (raw instanceof Map<?, ?> state
                        && runnerUrl.equals(state.get("url"))
                        && "complete".equals(state.get("state"))
                        && extensionId.equals(state.get("runtimeId"))) {
                    return;
                }
            } catch (RuntimeException ignored) {
                // pageLoadStrategy=none can return before the new execution
                // context exists. A bounded retry is not visit completion.
            }
            if (System.nanoTime() >= deadline) break;
            try {
                Thread.sleep(50);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("visit_runner_ready_interrupted", interrupted);
            }
        } while (true);
        throw new IllegalStateException("visit_runner_not_ready");
    }

    static Map<String, Object> validateResponse(Object raw, String requestId) {
        if (!ID.matcher(String.valueOf(requestId)).matches() || !(raw instanceof Map<?, ?> map)
                || !TRUSTED_RUNNER.equals(map.get("trustedRunner"))
                || !requestId.equals(map.get("requestId"))
                || !(map.get("ok") instanceof Boolean)) {
            throw new IllegalStateException("visit_runner_response_invalid");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        map.forEach((key, value) -> {
            if (key instanceof String name) result.put(name, value);
        });
        return result;
    }

    static boolean isValidCapability(Map<String, Object> response) {
        return response != null
                && Boolean.TRUE.equals(response.get("ok"))
                && "visit_capability".equals(response.get("kind"))
                && TRUSTED_RUNNER.equals(response.get("trustedRunner"))
                && Boolean.TRUE.equals(response.get("ownerBound"))
                && response.get("maxObservationMs") instanceof Number max
                && max.longValue() == 300000L
                && max.doubleValue() == 300000D
                && List.of("prestart", "advance", "departure", "clear", "rebind", "observe")
                        .equals(response.get("phases"));
    }
}
