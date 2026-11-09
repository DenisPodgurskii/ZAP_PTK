package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;

class PtkVisitRunnerTest {
    @Test
    void checkpointDiagnosticIdentifiesTheFailureSiteWithoutLoggingDriverValues() {
        IllegalStateException own = new IllegalStateException("visit_runner_not_ready");
        own.setStackTrace(new StackTraceElement[] {new StackTraceElement(
                PtkVisitRunner.class.getName(), "awaitRunnerReady", "PtkVisitRunner.java", 317)});
        assertEquals("visit_runner_not_ready@awaitRunnerReady:317",
                PtkVisitRunner.failureDiagnostic(own));

        IllegalStateException external = new IllegalStateException("secret=do-not-log");
        external.setStackTrace(new StackTraceElement[] {
                new StackTraceElement("org.openqa.selenium.remote.RemoteWebDriver", "getCurrentUrl", "RemoteWebDriver.java", 1),
                new StackTraceElement(PtkVisitRunner.class.getName(), "requestOnDriver", "PtkVisitRunner.java", 219)
        });
        assertEquals("IllegalStateException@requestOnDriver:219",
                PtkVisitRunner.failureDiagnostic(external));
    }

    @Test
    void runnerUrlMatchesPackagedInternalPageOnly() {
        String id = "a".repeat(32);
        assertTrue(PtkVisitRunner.isSupportedRunnerUrl(
                "chrome-extension://" + id + "/ptk/internal/zap-runner.html"));
        assertFalse(PtkVisitRunner.isSupportedRunnerUrl(
                "chrome-extension://" + id + "/ptk/zap-runner.html"));
        assertFalse(PtkVisitRunner.isSupportedRunnerUrl(
                "https://example.test/ptk/internal/zap-runner.html"));
    }

    @Test
    void onlyTheExactZapCallbackOwnerMaySkipTargetVisitObservation() {
        String callback = "https://zap/zapCallBackUrl/opaque/client"
                + "?zapenable=true&zapid=owner-1";
        assertTrue(ExtensionPtk.isOwnedClientCallbackUrl(callback, "owner-1"));
        assertFalse(ExtensionPtk.isOwnedClientCallbackUrl(callback, "owner-2"));
        assertFalse(ExtensionPtk.isOwnedClientCallbackUrl(
                "https://example.test/zapCallBackUrl/opaque/client?zapid=owner-1", "owner-1"));
        assertFalse(ExtensionPtk.isOwnedClientCallbackUrl(
                "https://zap.example.test/zapCallBackUrl/opaque/client?zapid=owner-1", "owner-1"));
    }

    @Test
    void nativeBrowserFamilyIsNotTheOpaquePtkOwnerId() {
        PtkZapSessionState state = new PtkZapSessionState("zap-1");
        state.rememberNativeBrowserFamily("edge-headless");
        state.rememberBrowserId("03142f9f-1ecd-43f8-bb91-357e3b96c9e5");
        assertEquals("edge-headless", state.nativeBrowserFamily());
        assertTrue(ExtensionPtk.isSupportedVisitBrowserFamily(state.nativeBrowserFamily()));
        assertFalse(ExtensionPtk.isSupportedVisitBrowserFamily(
                "03142f9f-1ecd-43f8-bb91-357e3b96c9e5"));
        assertFalse(ExtensionPtk.isSupportedVisitBrowserFamily("firefox"));
    }

    @Test
    void capabilityResponseIsBoundToExactRunnerAndRequest() {
        Map<String, Object> response = Map.of("ok", true, "kind", "visit_capability",
                "trustedRunner", "ptk-zap-visit-v1", "requestId", "cap-1");
        assertEquals(response, PtkVisitRunner.validateResponse(response, "cap-1"));
        assertThrows(IllegalStateException.class,
                () -> PtkVisitRunner.validateResponse(response, "cap-2"));
        assertThrows(IllegalStateException.class,
                () -> PtkVisitRunner.validateResponse(Map.of("ok", true,
                        "trustedRunner", "ptk-zap-control-v1", "requestId", "cap-1"), "cap-1"));
        assertThrows(IllegalStateException.class,
                () -> PtkVisitRunner.validateResponse(Map.of("ok", true,
                        "trustedRunner", "ptk-zap-visit-v1", "requestId", "cap-1".repeat(65)),
                        "cap-1"));
        Map<String, Object> capability = Map.of("ok", true, "kind", "visit_capability",
                "trustedRunner", "ptk-zap-visit-v1", "requestId", "cap-1",
                "ownerBound", true, "maxObservationMs", 300000,
                "phases", java.util.List.of("prestart", "advance", "departure", "clear", "rebind", "observe"));
        assertTrue(PtkVisitRunner.isValidCapability(capability));
        assertFalse(PtkVisitRunner.isValidCapability(Map.of("ok", true,
                "kind", "visit_capability", "trustedRunner", "ptk-zap-visit-v1",
                "ownerBound", false, "maxObservationMs", 300000,
                "phases", java.util.List.of("advance", "departure", "clear", "rebind", "observe"))));
    }

    @Test
    void runnerGeneratedFailureRetainsReasonWithoutBecomingSuccessfulEvidence() {
        Map<String, Object> timeout = Map.of("ok", false,
                "reason", "visit_response_timeout", "trustedRunner", "ptk-zap-visit-v1",
                "requestId", "visit-1");
        assertEquals(timeout, PtkVisitRunner.validateResponse(timeout, "visit-1"));
        assertFalse((Boolean) timeout.get("ok"));
        assertThrows(IllegalStateException.class,
                () -> PtkVisitRunner.validateResponse(timeout, "visit-2"));
        assertThrows(IllegalStateException.class,
                () -> PtkVisitRunner.validateResponse(Map.of("ok", false,
                        "reason", "visit_response_timeout", "requestId", "visit-1"), "visit-1"));
    }

    @Test
    void requestRestoresTargetWindowAfterSuccessAndRejectedResponse() {
        String url = "chrome-extension://" + "a".repeat(32)
                + "/ptk/internal/zap-runner.html";
        String requestId = "visit-1";
        Map<String, Object> payload = Map.of("type", "visit_capability",
                "channel", "ptk_extension_zap_runner", "requestId", requestId);
        for (boolean valid : new boolean[] {true, false}) {
            AtomicReference<String> current = new AtomicReference<>("target");
            AtomicInteger closed = new AtomicInteger();
            Map<String, Object> response = Map.of("ok", true, "kind", "visit_capability",
                    "trustedRunner", "ptk-zap-visit-v1",
                    "requestId", valid ? requestId : "wrong-request");
            WebDriver driver = fakeDriver(url, response, current, closed);
            if (valid) {
                assertEquals(response, PtkVisitRunner.request(driver, url, payload));
            } else {
                assertThrows(IllegalStateException.class,
                        () -> PtkVisitRunner.request(driver, url, payload));
            }
            assertEquals("target", current.get());
            assertEquals(0, closed.get(), "the trusted runner is reusable between requests");
            PtkVisitRunner.release(driver);
            assertEquals(1, closed.get());
        }
    }

    @Test
    void observationRestoresTheOriginalScriptTimeout() {
        String url = "chrome-extension://" + "a".repeat(32)
                + "/ptk/internal/zap-runner.html";
        String requestId = "observe-1";
        AtomicReference<String> current = new AtomicReference<>("target");
        AtomicInteger closed = new AtomicInteger();
        AtomicReference<Duration> scriptTimeout = new AtomicReference<>(Duration.ofSeconds(30));
        Map<String, Object> response = Map.of("ok", false,
                "reason", "visit_observation_timeout", "trustedRunner", "ptk-zap-visit-v1",
                "requestId", requestId);
        WebDriver driver = fakeDriver(url, response, current, closed, scriptTimeout);
        assertEquals(response, PtkVisitRunner.request(driver, url, Map.of(
                "channel", "ptk_extension_zap_runner", "type", "visit_observe",
                "requestId", requestId, "maxWaitMs", 15000)));
        assertEquals("target", current.get());
        PtkVisitRunner.release(driver);
        assertEquals(1, closed.get());
        assertEquals(Duration.ofSeconds(30), scriptTimeout.get());
    }

    @Test
    void prestartRestoresTheOriginalScriptTimeoutAndTargetWindow() {
        String url = "chrome-extension://" + "a".repeat(32)
                + "/ptk/internal/zap-runner.html";
        String requestId = "prestart-1";
        AtomicReference<String> current = new AtomicReference<>("target");
        AtomicInteger closed = new AtomicInteger();
        AtomicReference<Duration> scriptTimeout = new AtomicReference<>(Duration.ofSeconds(30));
        Map<String, Object> response = Map.of("ok", false,
                "reason", "visit_prestart_owner_unavailable", "trustedRunner", "ptk-zap-visit-v1",
                "requestId", requestId);
        WebDriver driver = fakeDriver(url, response, current, closed, scriptTimeout);
        assertEquals(response, PtkVisitRunner.request(driver, url, Map.of(
                "channel", "ptk_extension_zap_runner", "type", "visit_prestart",
                "requestId", requestId, "targetUrl", "https://app.test/target")));
        assertEquals("target", current.get());
        PtkVisitRunner.release(driver);
        assertEquals(1, closed.get());
        assertEquals(Duration.ofSeconds(30), scriptTimeout.get());
    }

    @Test
    void nonblockingRunnerNavigationWaitsForTheActualExtensionDocument() {
        String url = "chrome-extension://" + "a".repeat(32)
                + "/ptk/internal/zap-runner.html";
        AtomicReference<String> current = new AtomicReference<>("target");
        AtomicInteger closed = new AtomicInteger();
        AtomicInteger polls = new AtomicInteger();
        AtomicInteger urlReads = new AtomicInteger();
        Map<String, Object> response = Map.of("ok", true, "kind", "visit_capability",
                "trustedRunner", "ptk-zap-visit-v1", "requestId", "cap-1");
        WebDriver driver = fakeDriver(url, response, current, closed,
                new AtomicReference<>(Duration.ofSeconds(30)), polls,
                new AtomicInteger(), urlReads);
        assertEquals(response, PtkVisitRunner.request(driver, url, Map.of(
                "channel", "ptk_extension_zap_runner", "type", "visit_capability",
                "requestId", "cap-1")));
        assertTrue(polls.get() >= 2);
        assertEquals(0, urlReads.get(),
                "the runner's own URL and runtime ID make a Selenium URL query redundant");
        assertEquals("target", current.get());
        PtkVisitRunner.release(driver);
        assertEquals(1, closed.get());
    }

    @Test
    void twoCheckpointRequestsReuseOneTrustedTabAndRestoreTargetFocus() {
        String url = "chrome-extension://" + "a".repeat(32)
                + "/ptk/internal/zap-runner.html";
        AtomicReference<String> current = new AtomicReference<>("target");
        AtomicInteger closed = new AtomicInteger();
        AtomicInteger opened = new AtomicInteger();
        Map<String, Object> response = Map.of("ok", true, "kind", "departure_cut",
                "trustedRunner", "ptk-zap-visit-v1", "requestId", "cut-1");
        WebDriver driver = fakeDriver(url, response, current, closed,
                new AtomicReference<>(Duration.ofSeconds(30)), null, opened);
        Map<String, Object> payload = Map.of("channel", "ptk_extension_zap_runner",
                "type", "visit_checkpoint", "requestId", "cut-1", "phase", "departure");
        assertEquals(response, PtkVisitRunner.request(driver, url, payload));
        assertEquals("target", current.get());
        assertEquals(response, PtkVisitRunner.request(driver, url, payload));
        assertEquals("target", current.get());
        assertEquals(1, opened.get(), "repeated polling must not create a tab per checkpoint");
        assertEquals(0, closed.get());
        PtkVisitRunner.release(driver);
        assertEquals(1, closed.get());
    }

    @Test
    void observationKeepsTheTargetActiveBetweenShortRunnerRequests() {
        java.util.concurrent.atomic.AtomicLong nanos = new java.util.concurrent.atomic.AtomicLong();
        AtomicInteger requests = new AtomicInteger();
        java.util.List<String> phases = new java.util.ArrayList<>();
        Map<String, Object> cut = Map.of("root", Map.of("documentId", "doc-a"),
                "iast", Map.of("scanId", "scan-a"), "sast", Map.of(), "publisher", Map.of());
        Map<String, Object> result = PtkVisitRunner.observeWithTargetFocus(100, 500, true,
                (phase, intervalMs) -> {
                    phases.add(phase);
                    if ("departure".equals(phase)) {
                        return Map.of("ok", true, "kind", "departure_cut", "cut", cut);
                    }
                    return requests.incrementAndGet() == 1
                            ? Map.of("ok", false, "reason", "visit_observation_started")
                            : Map.of("ok", true, "kind", "observed_interval",
                                    "elapsedMs", 100, "cut", cut);
                }, nanos::get, millis -> {
                    assertEquals(1, requests.get(), "no runner request stays open during target dwell");
                    nanos.addAndGet(millis * 1_000_000L);
                });
        assertEquals("observed_departure_cut", result.get("kind"));
        assertEquals(java.util.List.of("advance", "advance", "departure"), phases);
    }

    @Test
    void lateShortRunnerResponseCannotCertifyTheVisit() {
        java.util.concurrent.atomic.AtomicLong nanos = new java.util.concurrent.atomic.AtomicLong();
        Map<String, Object> result = PtkVisitRunner.observeWithTargetFocus(100, 300, false,
                (phase, intervalMs) -> {
                    nanos.set(301_000_000L);
                    return Map.of("ok", true, "kind", "observed_interval", "elapsedMs", 300);
                }, nanos::get, millis -> nanos.addAndGet(millis * 1_000_000L));
        assertEquals(false, result.get("ok"));
        assertEquals("visit_observation_timeout", result.get("reason"));
    }

    @Test
    void unavailableRootDoesNotRestartTheExecutionInterval() {
        java.util.concurrent.atomic.AtomicLong nanos = new java.util.concurrent.atomic.AtomicLong();
        AtomicInteger requests = new AtomicInteger();
        Map<String, Object> result = PtkVisitRunner.observeWithTargetFocus(100, 300, false,
                (phase, intervalMs) -> {
                    requests.incrementAndGet();
                    return Map.of("ok", false, "reason", "visit_root_unavailable");
                },
                nanos::get, millis -> nanos.addAndGet(millis * 1_000_000L));
        assertEquals(false, result.get("ok"));
        assertEquals("visit_root_unavailable", result.get("reason"));
        assertEquals(1, requests.get());
    }

    private static WebDriver fakeDriver(String runnerUrl, Object response,
            AtomicReference<String> current, AtomicInteger closed) {
        return fakeDriver(runnerUrl, response, current, closed,
                new AtomicReference<>(Duration.ofSeconds(30)));
    }

    private static WebDriver fakeDriver(String runnerUrl, Object response,
            AtomicReference<String> current, AtomicInteger closed,
            AtomicReference<Duration> scriptTimeout) {
        return fakeDriver(runnerUrl, response, current, closed, scriptTimeout, null);
    }

    private static WebDriver fakeDriver(String runnerUrl, Object response,
            AtomicReference<String> current, AtomicInteger closed,
            AtomicReference<Duration> scriptTimeout, AtomicInteger readinessPolls) {
        return fakeDriver(runnerUrl, response, current, closed, scriptTimeout,
                readinessPolls, new AtomicInteger());
    }

    private static WebDriver fakeDriver(String runnerUrl, Object response,
            AtomicReference<String> current, AtomicInteger closed,
            AtomicReference<Duration> scriptTimeout, AtomicInteger readinessPolls,
            AtomicInteger opened) {
        return fakeDriver(runnerUrl, response, current, closed,
                scriptTimeout, readinessPolls, opened, null);
    }

    private static WebDriver fakeDriver(String runnerUrl, Object response,
            AtomicReference<String> current, AtomicInteger closed,
            AtomicReference<Duration> scriptTimeout, AtomicInteger readinessPolls,
            AtomicInteger opened, AtomicInteger urlReads) {
        AtomicReference<WebDriver> driver = new AtomicReference<>();
        WebDriver.Timeouts timeouts = (WebDriver.Timeouts) Proxy.newProxyInstance(
                PtkVisitRunnerTest.class.getClassLoader(),
                new Class<?>[] {WebDriver.Timeouts.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getScriptTimeout")) return scriptTimeout.get();
                    if (method.getName().equals("scriptTimeout")) {
                        scriptTimeout.set((Duration) args[0]);
                        return proxy;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        WebDriver.Options options = (WebDriver.Options) Proxy.newProxyInstance(
                PtkVisitRunnerTest.class.getClassLoader(),
                new Class<?>[] {WebDriver.Options.class}, (proxy, method, args) -> {
                    if (method.getName().equals("timeouts")) return timeouts;
                    throw new UnsupportedOperationException(method.getName());
                });
        WebDriver.Navigation navigation = (WebDriver.Navigation) Proxy.newProxyInstance(
                PtkVisitRunnerTest.class.getClassLoader(),
                new Class<?>[] {WebDriver.Navigation.class}, (proxy, method, args) -> {
                    if (method.getName().equals("to")) return null;
                    throw new UnsupportedOperationException(method.getName());
                });
        WebDriver.TargetLocator locator = (WebDriver.TargetLocator) Proxy.newProxyInstance(
                PtkVisitRunnerTest.class.getClassLoader(),
                new Class<?>[] {WebDriver.TargetLocator.class}, (proxy, method, args) -> {
                    if (method.getName().equals("newWindow")) {
                        opened.incrementAndGet();
                        current.set("runner");
                        return driver.get();
                    }
                    if (method.getName().equals("window")) {
                        current.set(String.valueOf(args[0]));
                        return driver.get();
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        WebDriver value = (WebDriver) Proxy.newProxyInstance(
                PtkVisitRunnerTest.class.getClassLoader(),
                new Class<?>[] {WebDriver.class, JavascriptExecutor.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    case "getWindowHandle" -> current.get();
                    case "switchTo" -> locator;
                    case "navigate" -> navigation;
                    case "manage" -> options;
                    case "getCurrentUrl" -> {
                        if (urlReads != null) urlReads.incrementAndGet();
                        yield current.get().equals("runner") ? runnerUrl : "about:blank";
                    }
                    case "executeScript" -> {
                        int poll = readinessPolls != null ? readinessPolls.incrementAndGet() : 2;
                        yield Map.of("url", runnerUrl, "state", poll < 2 ? "loading" : "complete",
                                "runtimeId", "a".repeat(32));
                    }
                    case "executeAsyncScript" -> response;
                    case "close" -> { closed.incrementAndGet(); yield null; }
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        driver.set(value);
        return value;
    }
}
