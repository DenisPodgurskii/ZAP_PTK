package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.MutableCapabilities;
import org.openqa.selenium.WebDriver;
import org.zaproxy.addon.client.spider.ScanOptions;
import org.zaproxy.addon.client.spider.SpiderScanLaunchContext;
import org.zaproxy.addon.client.spider.VisitOutcome;

class PtkSpiderPolicyTest {
    @Test
    void selectsOnlyOwnedChromiumParticipation() {
        assertTrue(PtkSpiderPolicy.eligible(true, "edge", false, true, false));
        assertTrue(PtkSpiderPolicy.eligible(true, "chrome", false, false, true));
        assertFalse(PtkSpiderPolicy.eligible(false, "edge", false, true, true));
        assertFalse(PtkSpiderPolicy.eligible(true, "firefox", false, true, true));
        assertFalse(PtkSpiderPolicy.eligible(true, "edge", true, true, true));
        assertFalse(PtkSpiderPolicy.eligible(true, "edge", false, false, false));
    }

    @Test
    void refusesConflictingNavigationPolicy() {
        MutableCapabilities caps = new MutableCapabilities();
        PtkSpiderPolicy.applyCapabilities(caps);
        assertEquals("none", caps.getCapability("pageLoadStrategy"));
        MutableCapabilities conflict = new MutableCapabilities();
        conflict.setCapability("pageLoadStrategy", "normal");
        assertThrows(IllegalStateException.class,
                () -> PtkSpiderPolicy.applyCapabilities(conflict));
        assertEquals("normal", conflict.getCapability("pageLoadStrategy"));
    }

    @Test
    void contextScopeAdmitsSiblingDocumentButNeverAnOutsideRoute() {
        String seed = "https://app.test/dom/dompropagation/";
        java.util.function.Predicate<String> officialScope =
                url -> url.startsWith("https://app.test/dom/");
        assertTrue(PtkSpiderPolicy.inVisitScope(seed,
                "https://app.test/dom/toxicdom/localStorage/function/eval", false,
                officialScope));
        assertFalse(PtkSpiderPolicy.inVisitScope(seed,
                "https://app.test/other/", false, officialScope));
        assertFalse(PtkSpiderPolicy.inVisitScope(seed,
                "https://other.test/dom/", false, officialScope));
        assertFalse(PtkSpiderPolicy.inVisitScope(seed,
                "https://app.test/dom/toxicdom/localStorage/function/eval", true,
                officialScope));
        assertFalse(PtkSpiderPolicy.inVisitScope(seed,
                "https://app.test/dom/toxicdom/localStorage/function/eval", false,
                null));
    }

    @Test
    void prestartsExactTargetAndFailsClosedOnRejectedBinding() {
        String url = "https://app.test/dom/target";
        SpiderScanLaunchContext context = context(url);
        StubPtk ptk = new StubPtk();
        assertTrue(new PtkSpiderPolicy.Coordinator(ptk, null, context).bind().isComplete());
        assertEquals(List.of("probe:edge", "prestart:" + url), ptk.calls);
        ptk.calls.clear();
        ptk.prestart = Map.of("ok", false, "reason", "visit_prestart_registration_unavailable");
        assertFalse(new PtkSpiderPolicy.Coordinator(ptk, null, context).bind().isComplete());
        assertEquals(List.of("probe:edge", "prestart:" + url), ptk.calls);
    }

    @Test
    void sameUrlNewNativeDocumentRequiresFreshObservation() {
        String url = "https://app.test/dom/target";
        AtomicReference<String> current = new AtomicReference<>(url);
        WebDriver driver = (WebDriver) Proxy.newProxyInstance(
                WebDriver.class.getClassLoader(), new Class<?>[] {WebDriver.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getCurrentUrl")) return current.get();
                    throw new UnsupportedOperationException(method.getName());
                });
        StubPtk ptk = new StubPtk();
        ptk.current = current;
        PtkSpiderPolicy.Coordinator coordinator =
                new PtkSpiderPolicy.Coordinator(ptk, driver, context(url));
        assertTrue(coordinator.bind().isComplete());
        assertTrue(coordinator.afterAction("first.navigation").isComplete());
        assertTrue(coordinator.beforeRelease().isComplete());
        ptk.currentDocument.set("doc-2");
        assertTrue(coordinator.beforeAction("second.navigation").isComplete());
        assertTrue(coordinator.beforeRelease().isComplete());
        // The first release reuses the already observed cut; a new native
        // document still receives its own interval.
        assertEquals(List.of("doc-1", "doc-2", "doc-2"), ptk.observedDocuments);
    }

    @Test
    void nextActionReusesObservedDocumentWithoutRepeatingFullDwell() {
        String url = "https://app.test/dom/target";
        AtomicReference<String> current = new AtomicReference<>(url);
        WebDriver driver = (WebDriver) Proxy.newProxyInstance(
                WebDriver.class.getClassLoader(), new Class<?>[] {WebDriver.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getCurrentUrl")) return current.get();
                    throw new UnsupportedOperationException(method.getName());
                });
        StubPtk ptk = new StubPtk();
        ptk.current = current;
        PtkSpiderPolicy.Coordinator coordinator =
                new PtkSpiderPolicy.Coordinator(ptk, driver, context(url));
        assertTrue(coordinator.bind().isComplete());
        assertTrue(coordinator.afterAction("first.navigation").isComplete());
        assertTrue(coordinator.beforeAction("second.navigation").isComplete());
        assertEquals(List.of("doc-1"), ptk.observedDocuments);
        assertTrue(coordinator.afterAction("second.navigation").isComplete());
        assertEquals(List.of("doc-1", "doc-1"), ptk.observedDocuments);
    }

    @Test
    void resultingPageUsesVerifiedCutWithoutAnotherBlockingDriverUrlRead() {
        String url = "https://app.test/dom/target";
        WebDriver driver = (WebDriver) Proxy.newProxyInstance(
                WebDriver.class.getClassLoader(), new Class<?>[] {WebDriver.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getCurrentUrl")) {
                        throw new IllegalStateException("driver_url_wait_blocked");
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        StubPtk ptk = new StubPtk();
        ptk.current = new AtomicReference<>(url);
        PtkSpiderPolicy.Coordinator coordinator =
                new PtkSpiderPolicy.Coordinator(ptk, driver, context(url));
        assertTrue(coordinator.bind().isComplete());
        assertTrue(coordinator.afterAction("target.navigation").isComplete(),
                "the native-root-verified observation already proves the resulting URL");
        assertTrue(coordinator.beforeRelease().isComplete(),
                "release must reuse the verified cut without a Selenium URL lookup");
        ptk.current.set("https://other.test/landing");
        assertEquals("visit_target_out_of_scope", coordinator.afterAction("external.redirect").reason());
    }

    @Test
    void nextActionUsesOwnedDepartureCutWithoutAnotherDriverUrlRead() {
        String url = "https://app.test/dom/target";
        WebDriver driver = (WebDriver) Proxy.newProxyInstance(
                WebDriver.class.getClassLoader(), new Class<?>[] {WebDriver.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getCurrentUrl")) {
                        throw new IllegalStateException("driver_url_wait_blocked");
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        StubPtk ptk = new StubPtk();
        ptk.current = new AtomicReference<>(url);
        PtkSpiderPolicy.Coordinator coordinator =
                new PtkSpiderPolicy.Coordinator(ptk, driver, context(url));
        assertTrue(coordinator.bind().isComplete());
        assertTrue(coordinator.afterAction("first.navigation").isComplete());
        int observed = ptk.observedDocuments.size();
        assertTrue(coordinator.beforeAction("second.navigation").isComplete(),
                "the verified departure cut is sufficient for the next action");
        assertEquals(observed, ptk.observedDocuments.size(),
                "the same document must not be observed twice");
    }

    @Test
    void directFallbackNavigationDoesNotNeedASecondDriverUrlLookup() {
        String url = "https://app.test/dom/target";
        WebDriver driver = (WebDriver) Proxy.newProxyInstance(
                WebDriver.class.getClassLoader(), new Class<?>[] {WebDriver.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getCurrentUrl")) {
                        throw new IllegalStateException("driver_url_wait_blocked");
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        StubPtk ptk = new StubPtk();
        ptk.current = new AtomicReference<>(url);
        PtkSpiderPolicy.Coordinator coordinator =
                new PtkSpiderPolicy.Coordinator(ptk, driver, context(url));
        assertTrue(coordinator.bind().isComplete());
        assertTrue(coordinator.beforeAction("follow.fallback.navigation").isComplete());
        assertTrue(coordinator.afterAction("follow.fallback.navigation").isComplete());
        assertTrue(coordinator.beforeAction("follow.fallback.navigation").isComplete(),
                "the existing departure cut checks the owned page without Selenium URL lookup");
        ptk.current.set("https://other.test/landing");
        assertEquals("visit_target_out_of_scope",
                coordinator.beforeAction("follow.fallback.navigation").reason());
    }

    @Test
    void externalRedirectIsReportedIncompleteWithoutPollingTheOldDocument() {
        String url = "https://app.test/dom/target";
        AtomicReference<String> current = new AtomicReference<>(url);
        WebDriver driver = (WebDriver) Proxy.newProxyInstance(
                WebDriver.class.getClassLoader(), new Class<?>[] {WebDriver.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getCurrentUrl")) return current.get();
                    throw new UnsupportedOperationException(method.getName());
                });
        StubPtk ptk = new StubPtk();
        ptk.current = current;
        PtkSpiderPolicy.Coordinator coordinator =
                new PtkSpiderPolicy.Coordinator(ptk, driver, context(url));
        assertTrue(coordinator.bind().isComplete());
        assertTrue(coordinator.afterAction("target.navigation").isComplete());
        int observed = ptk.observedDocuments.size();
        current.set("https://other.test/landing");
        ptk.currentDocument.set("foreign-doc");
        assertEquals("visit_target_out_of_scope", coordinator.afterAction("redirect").reason());
        assertEquals("visit_target_out_of_scope", coordinator.beforeAction("next").reason());
        assertEquals("visit_observation_unavailable", coordinator.beforeRelease().reason(),
                "the foreign cut was already consumed; release remains incomplete");
        assertEquals(observed + 1, ptk.observedDocuments.size(),
                "the verified foreign result is rejected without retrying the old document");
        assertEquals("foreign-doc", ptk.observedDocuments.get(observed));
        current.set("https://app.test/dom/another");
        assertTrue(coordinator.afterAction("in.scope").isComplete(),
                "the scoped browser remains usable after an external redirect");
    }

    @Test
    void releaseDoesNotRepeatFullObservationAfterAnUnavailableRoot() {
        String url = "https://app.test/address/target";
        AtomicReference<String> current = new AtomicReference<>(url);
        WebDriver driver = (WebDriver) Proxy.newProxyInstance(
                WebDriver.class.getClassLoader(), new Class<?>[] {WebDriver.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("getCurrentUrl")) return current.get();
                    throw new UnsupportedOperationException(method.getName());
                });
        StubPtk ptk = new StubPtk();
        ptk.current = current;
        ptk.rootUnavailable = true;
        PtkSpiderPolicy.Coordinator coordinator =
                new PtkSpiderPolicy.Coordinator(ptk, driver, context(url));
        assertTrue(coordinator.bind().isComplete());
        assertEquals("visit_root_unavailable", coordinator.afterAction("navigation").reason());
        assertEquals(1, ptk.observedDocuments.size());
        assertEquals("visit_observation_unavailable", coordinator.beforeRelease().reason());
        assertEquals(1, ptk.observedDocuments.size(),
                "release must not repeat a full interval after a failed observation");
        assertEquals(1, ptk.departureChecks);
        ptk.rootUnavailable = false;
        assertTrue(coordinator.beforeAction("next.navigation").isComplete(),
                "the next action still gives a now-available document an interval");
        assertEquals(2, ptk.observedDocuments.size());
        ptk.rootUnavailable = true;
        assertEquals("visit_root_unavailable", coordinator.afterAction("next.navigation").reason());
        int attempts = ptk.observedDocuments.size();
        assertEquals("visit_observation_unavailable", coordinator.beforeRelease().reason());
        assertEquals(attempts, ptk.observedDocuments.size(),
                "a prior successful visit must not cause a new failed action to dwell at release");
    }

    @Test
    void releaseRejectsRevokedOwnerEvenWithoutAnObservedCut() {
        String url = "https://app.test/address/target";
        StubPtk ptk = new StubPtk();
        ptk.current = new AtomicReference<>(url);
        ptk.rootUnavailable = true;
        PtkSpiderPolicy.Coordinator coordinator =
                new PtkSpiderPolicy.Coordinator(ptk, null, context(url));
        assertTrue(coordinator.bind().isComplete());
        assertEquals("visit_root_unavailable", coordinator.afterAction("navigation").reason());
        ptk.ownerAvailable = false;
        VisitOutcome departure = coordinator.beforeRelease();
        assertEquals("visit_owner_unavailable", departure.reason());
        assertEquals(VisitOutcome.Status.FAILED, departure.status());
        assertEquals(1, ptk.departureChecks);
    }

    private static SpiderScanLaunchContext context(String url) {
        return new SpiderScanLaunchContext(7, url, "edge", ScanOptions.builder().build(),
                true, 15_000, 2_500);
    }

    private static final class StubPtk extends ExtensionPtk {
        final List<String> calls = new ArrayList<>();
        final List<String> observedDocuments = new ArrayList<>();
        Map<String, Object> prestart = Map.of("ok", true, "kind", "visit_prestarted");
        AtomicReference<String> current;
        final AtomicReference<String> currentDocument = new AtomicReference<>("doc-1");
        boolean rootUnavailable;
        boolean ownerAvailable = true;
        int departureChecks;

        @Override
        boolean probeInstalledVisitCapability(WebDriver driver, String browserId) {
            calls.add("probe:" + browserId);
            return true;
        }

        @Override
        Map<String, Object> requestOwnedVisitPrestart(WebDriver driver, String url) {
            calls.add("prestart:" + url);
            return prestart;
        }

        @Override
        PtkVisitGate createOwnedVisitGate(WebDriver driver, int observationMs, int maxWaitMs) {
            if (current == null) return null;
            return new PtkVisitGate(new PtkVisitGate.Endpoint() {
                @Override
                public Map<String, Object> observe(int observedMs, int maximumMs) {
                    observedDocuments.add(currentDocument.get());
                    if (rootUnavailable) return Map.of("ok", false,
                            "reason", "visit_root_unavailable");
                    return Map.of("ok", true, "kind", "observed_interval", "elapsedMs", observedMs,
                            "cut", cut());
                }

                @Override
                public Map<String, Object> observeAndDepart(int observedMs, int maximumMs) {
                    observedDocuments.add(currentDocument.get());
                    if (rootUnavailable) return Map.of("ok", false,
                            "reason", "visit_root_unavailable");
                    return Map.of("ok", true, "kind", "observed_departure_cut",
                            "elapsedMs", observedMs, "cut", cut());
                }

                @Override
                public Map<String, Object> checkpoint(String phase) {
                    if ("departure".equals(phase)) departureChecks++;
                    if (!ownerAvailable) return Map.of("ok", false,
                            "reason", "visit_owner_unavailable");
                    return Map.of("ok", true, "kind", "departure_cut", "cut", cut());
                }

                private Map<String, Object> cut() {
                    return Map.of("root", Map.of("url", current.get(),
                                    "documentId", currentDocument.get()),
                            "iast", Map.of(), "sast", Map.of(), "publisher", Map.of());
                }
            }, observationMs, maxWaitMs);
        }
    }
}
