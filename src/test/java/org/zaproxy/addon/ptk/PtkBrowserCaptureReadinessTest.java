package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class PtkBrowserCaptureReadinessTest {
    private static final String ROUTE = "/zapCallBackUrl/owned/ptk/browser-capture";
    private static final String PHASE = "CLIENT_SPIDER";
    private static final Set<String> CAPS = Set.of("network", "sources");
    private final AtomicLong clock = new AtomicLong(100);
    private final PtkBrowserCaptureReadiness registry = new PtkBrowserCaptureReadiness(clock::get);

    private boolean prepare(String zapid, String captureId) {
        assertTrue(registry.bindBrowser(ROUTE, zapid, "chrome", PHASE));
        return registry.prepare(ROUTE, zapid, "browser", captureId, PHASE, CAPS);
    }

    private boolean ready(String zapid, String captureId) {
        return registry.ready(ROUTE, zapid, "browser", captureId, PHASE, CAPS, CAPS);
    }

    @Test
    void exactOwnerRepeatsAreIdempotentWithoutChangingGenerationOrExpiry() throws Exception {
        assertTrue(prepare("zap", "capture"));
        assertTrue(prepare("zap", "capture"));
        assertFalse(registry.awaitReady(ROUTE, "zap", PHASE, 0));
        assertTrue(ready("zap", "capture"));
        assertTrue(ready("zap", "capture"));
        assertTrue(registry.awaitReady(ROUTE, "zap", PHASE, 0));
        clock.addAndGet(PtkBrowserCaptureReadiness.TTL_MS);
        assertFalse(registry.awaitReady(ROUTE, "zap", PHASE, 0));
        assertFalse(ready("zap", "capture"));
    }

    @Test
    void rejectsForeignRouteBrowserCapturePhaseAndWrongArmedCapabilities() throws Exception {
        assertTrue(prepare("zap", "capture"));
        assertFalse(registry.ready(ROUTE + "x", "zap", "browser", "capture", PHASE, CAPS, CAPS));
        assertFalse(registry.ready(ROUTE, "foreign", "browser", "capture", PHASE, CAPS, CAPS));
        assertFalse(registry.ready(ROUTE, "zap", "foreign", "capture", PHASE, CAPS, CAPS));
        assertFalse(registry.ready(ROUTE, "zap", "browser", "foreign", PHASE, CAPS, CAPS));
        assertFalse(
                registry.ready(ROUTE, "zap", "browser", "capture", "ACTIVE_SCAN_RULE", CAPS, CAPS));
        assertFalse(
                registry.ready(ROUTE, "zap", "browser", "capture", PHASE, CAPS, Set.of("network")));
        assertFalse(
                registry.ready(
                        ROUTE,
                        "zap",
                        "browser",
                        "capture",
                        PHASE,
                        CAPS,
                        Set.of("network", "sources", "input")));
        assertFalse(registry.awaitReady(ROUTE, "zap", PHASE, 0));
    }

    @Test
    void staleReleaseCannotDeleteReplacementAndReleasedCaptureCannotBeRevived() throws Exception {
        assertTrue(prepare("zap", "first"));
        assertFalse(prepare("zap", "replacement"));
        assertTrue(registry.release(ROUTE, "zap", "browser", "first", PHASE));
        assertTrue(registry.release(ROUTE, "zap", "browser", "first", PHASE));
        assertFalse(prepare("zap", "first"));
        assertFalse(ready("zap", "first"));
        assertTrue(prepare("zap", "replacement"));
        assertFalse(registry.release(ROUTE, "zap", "browser", "first", PHASE));
        assertTrue(ready("zap", "replacement"));
        assertTrue(registry.awaitReady(ROUTE, "zap", PHASE, 0));
    }

    @Test
    void isolatesFiveWorkerReadinessAndDoesNotConfuseReadinessWithActivation() throws Exception {
        for (int i = 0; i < 5; i++) assertTrue(prepare("zap" + i, "capture" + i));
        assertTrue(ready("zap3", "capture3"));
        for (int i = 0; i < 5; i++) {
            assertEquals(i == 3, registry.awaitReady(ROUTE, "zap" + i, PHASE, 0));
        }
        registry.releaseOwner("zap3");
        assertFalse(registry.awaitReady(ROUTE, "zap3", PHASE, 0));
    }

    @Test
    void waitsOutsideTheMetadataMonitorAndTimesOutWithoutAReadyMessage() throws Exception {
        assertTrue(prepare("zap", "capture"));
        var pool = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            var pending = pool.submit(() -> registry.awaitReady(ROUTE, "zap", PHASE, 1000));
            assertTrue(ready("zap", "capture"));
            assertTrue(pending.get(2, TimeUnit.SECONDS));
            assertFalse(registry.awaitReady(ROUTE, "missing", PHASE, 1));
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void boundsMetadataAndRejectsInvalidOrDuplicateIdentities() {
        assertFalse(registry.prepare(ROUTE, "zap", "browser", "id", PHASE, Set.of()));
        assertFalse(
                registry.prepare(
                        ROUTE, "zap", "browser", "id", PHASE, Set.of("network", "authBodies")));
        assertFalse(registry.prepare(ROUTE + "?query", "zap", "browser", "id", PHASE, CAPS));
        assertTrue(prepare("zap", "capture"));
        assertFalse(prepare("foreign", "capture"));
        registry.releaseOwner("foreign");
        for (int i = 1; i < PtkBrowserCaptureReadiness.MAX_OWNERS; i++)
            assertTrue(prepare("zap" + i, "capture" + i));
        assertFalse(registry.bindBrowser(ROUTE, "overflow", "chrome", PHASE));
        registry.clear();
        assertTrue(prepare("fresh", "fresh"));
    }

    @Test
    void responsesContainOnlySanitizedReadinessMetadata() {
        assertEquals(
                Set.of("ok", "version", "reason"),
                PtkBrowserCaptureReadiness.response(false, "capture_refused").keySet());
        assertEquals(1, PtkBrowserCaptureReadiness.response(true, "ready").get("version"));
    }

    @Test
    void nativeBindingMustExistAndCannotBeReboundToForeignRouteFamilyOrPhase() {
        assertFalse(registry.prepare(ROUTE, "zap", "browser", "capture", PHASE, CAPS));
        assertTrue(registry.bindBrowser(ROUTE, "zap", "chrome", PHASE));
        assertFalse(registry.bindBrowser(ROUTE + "x", "zap", "chrome", PHASE));
        assertFalse(registry.bindBrowser(ROUTE, "zap", "firefox", PHASE));
        assertFalse(registry.bindBrowser(ROUTE, "zap", "chrome", "ACTIVE_SCAN_RULE"));
        assertFalse(registry.isBrowserOwner(ROUTE, "zap", "ACTIVE_SCAN_RULE"));
        assertEquals("chrome", registry.browserFamily("zap"));
        clock.addAndGet(PtkBrowserCaptureReadiness.TTL_MS);
        assertNull(registry.browserFamily("zap"));
        assertFalse(registry.isBrowserOwner(ROUTE, "zap", PHASE));
    }

    @Test
    void earlyConfigWaitWakesOnlyForItsExactNativeBindingAndBothPhases() throws Exception {
        var pool = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            for (String phase : Set.of(PHASE, "ACTIVE_SCAN_RULE")) {
                String zapid = "zap_" + phase;
                var started = new java.util.concurrent.CountDownLatch(1);
                var pending =
                        pool.submit(
                                () -> {
                                    started.countDown();
                                    return registry.awaitBrowserPhase(ROUTE, zapid, 2000);
                                });
                assertTrue(started.await(1, TimeUnit.SECONDS));
                assertTrue(registry.bindBrowser(ROUTE, "foreign_" + phase, "firefox", phase));
                assertFalse(pending.isDone());
                assertTrue(registry.bindBrowser(ROUTE, zapid, "firefox", phase));
                assertEquals(phase, pending.get(1, TimeUnit.SECONDS));
                assertEquals(phase, registry.awaitBrowserPhase(ROUTE, zapid, 0));
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void nativeConfigWaitRejectsForeignRouteExpiredOwnerAndUnknownTimeout() throws Exception {
        assertEquals(2000, PtkBrowserCaptureReadiness.CONFIG_NATIVE_BIND_TIMEOUT_MS);
        assertTrue(registry.bindBrowser(ROUTE, "zap", "chrome", PHASE));
        assertNull(registry.awaitBrowserPhase(ROUTE + "x", "zap", 2000));
        assertNull(registry.awaitBrowserPhase(ROUTE, "unknown", 1));
        assertNull(registry.awaitBrowserPhase(ROUTE, "invalid/id", 2000));
        clock.addAndGet(PtkBrowserCaptureReadiness.TTL_MS);
        assertNull(registry.awaitBrowserPhase(ROUTE, "zap", 0));
        assertTrue(registry.bindBrowser(ROUTE, "zap", "chrome", "ACTIVE_SCAN_RULE"));
        assertEquals("ACTIVE_SCAN_RULE", registry.awaitBrowserPhase(ROUTE, "zap", 0));
    }
}
