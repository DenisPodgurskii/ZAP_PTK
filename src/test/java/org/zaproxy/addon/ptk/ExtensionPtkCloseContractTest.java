package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;

/** Smoke-level tests for the PTK browser close contract. */
@SuppressWarnings("auxiliaryclass")
class ExtensionPtkCloseContractTest {

    @Test
    void timeoutConstantsDescribeCloseContractBudget() {
        assertEquals(
                PtkCloseContract.BROWSER_CLOSE_MAX_ATTEMPTS
                        * PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS,
                PtkCloseContract.BROWSER_CLOSE_TOTAL_WAIT_MS);
        assertTrue(
                PtkCloseContract.BROWSER_CLOSE_SCRIPT_TIMEOUT_MS
                        >= PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS);
        assertEquals(
                PtkCloseContract.BROWSER_CLOSE_MAX_ATTEMPTS
                        / PtkCloseContract.BROWSER_CLOSE_FOLLOW_UP_DECISION_EVERY_ATTEMPTS,
                PtkCloseContract.BROWSER_CLOSE_MAX_FOLLOW_UP_DECISIONS);
        assertEquals(
                PtkCloseContract.BROWSER_CLOSE_SCRIPT_TIMEOUT_MS
                        + PtkCloseContract.BROWSER_CLOSE_NO_PROGRESS_GRACE_MS
                        + PtkCloseContract.BROWSER_CLOSE_AUTOMATION_DISABLED_GRACE_MS
                        + PtkCloseContract.BROWSER_CLOSE_TOTAL_WAIT_MS
                        + (PtkCloseContract.BROWSER_CLOSE_MAX_FOLLOW_UP_DECISIONS
                                * PtkCloseContract.BROWSER_CLOSE_SCRIPT_TIMEOUT_MS),
                PtkCloseContract.BROWSER_CLOSE_MAX_WALL_CLOCK_MS);
    }

    @Test
    void closeRequestedIsNotVisibleUntilCloseDecisionAttemptIsRecorded() {
        Map<String, Long> closeRequestedByZapId = new ConcurrentHashMap<>();

        assertNull(PtkCloseContract.getCloseRequestedAtMs(closeRequestedByZapId, "zap-1"));
        assertEquals(false, PtkCloseContract.canAcceptSafeToClose(closeRequestedByZapId, "zap-1"));

        PtkCloseContract.markCloseDecisionAttempted(closeRequestedByZapId, "zap-1", 123L);

        assertEquals(123L, PtkCloseContract.getCloseRequestedAtMs(closeRequestedByZapId, "zap-1"));
        assertEquals(true, PtkCloseContract.canAcceptSafeToClose(closeRequestedByZapId, "zap-1"));
    }

    @Test
    void firstCloseDecisionAttemptTimestampIsPreserved() {
        Map<String, Long> closeRequestedByZapId = new ConcurrentHashMap<>();

        PtkCloseContract.markCloseDecisionAttempted(closeRequestedByZapId, "zap-1", 123L);
        PtkCloseContract.markCloseDecisionAttempted(closeRequestedByZapId, "zap-1", 456L);

        assertEquals(123L, PtkCloseContract.getCloseRequestedAtMs(closeRequestedByZapId, "zap-1"));
        assertNull(PtkCloseContract.getCloseRequestedAtMs(closeRequestedByZapId, null));
        assertNull(PtkCloseContract.getCloseRequestedAtMs(closeRequestedByZapId, ""));
    }

    @Test
    void targetUrlMustBeHttpAndStoredFirstWins() {
        Map<String, String> targetUrlByZapId = new ConcurrentHashMap<>();

        assertNull(PtkCloseContract.normalizeHttpTargetUrl("javascript:alert(1)"));
        assertNull(PtkCloseContract.normalizeHttpTargetUrl("https:///missing-host"));
        assertEquals(
                "https://example.test/app",
                PtkCloseContract.normalizeHttpTargetUrl(" https://example.test/app "));

        assertEquals(
                true,
                PtkCloseContract.rememberInitialTargetUrl(
                        targetUrlByZapId, "zap-1", "https://example.test/app"));
        assertEquals("https://example.test/app", targetUrlByZapId.get("zap-1"));

        assertEquals(
                false,
                PtkCloseContract.rememberInitialTargetUrl(
                        targetUrlByZapId, "zap-1", "https://attacker.test/close"));
        assertEquals("https://example.test/app", targetUrlByZapId.get("zap-1"));

        assertEquals(
                true,
                PtkCloseContract.rememberInitialTargetUrl(
                        targetUrlByZapId, "zap-1", "https://example.test/app"));
    }

    @Test
    void browserCoverageTargetUsesSeparateNormalizedFirstWinsMapping() {
        Map<String, String> closeTargets = new ConcurrentHashMap<>();
        Map<String, String> coverageTargets = new ConcurrentHashMap<>();

        assertEquals(
                true,
                PtkCloseContract.rememberInitialTargetUrl(
                        closeTargets, "zap-1", "https://example.test/current"));
        assertEquals(
                true,
                PtkCloseContract.rememberBrowserCoverageTargetUrl(
                        coverageTargets, "zap-1", "https://example.test/address/"));

        assertEquals("https://example.test/current", closeTargets.get("zap-1"));
        assertEquals("https://example.test/address/index.html", coverageTargets.get("zap-1"));
        assertEquals(
                false,
                PtkCloseContract.rememberBrowserCoverageTargetUrl(
                        coverageTargets, "zap-1", "https://attacker.test/address/"));
        assertEquals("https://example.test/address/index.html", coverageTargets.get("zap-1"));
    }

    @Test
    void closedZapIdsAreBoundedAndExpire() {
        Map<String, Long> closedZapIds = new ConcurrentHashMap<>();

        PtkCloseContract.rememberClosedZapId(closedZapIds, "old", 1L);
        assertEquals(false, PtkCloseContract.isRecentlyClosedZapId(closedZapIds, "old", 70_000L));

        for (int i = 0; i < PtkCloseContract.CLOSED_ZAPID_MAX_ENTRIES + 25; i++) {
            PtkCloseContract.rememberClosedZapId(closedZapIds, "zap-" + i, 80_000L + i);
        }

        assertTrue(closedZapIds.size() <= PtkCloseContract.CLOSED_ZAPID_MAX_ENTRIES);
        assertEquals(
                true, PtkCloseContract.isRecentlyClosedZapId(closedZapIds, "zap-1024", 81_100L));
    }

    @Test
    void runningStatusIsNotTerminalJustBecauseProgressReachedOneHundred() {
        assertEquals(false, PtkCloseContract.isTerminalProgressValue(100, "running"));
        assertEquals(false, PtkCloseContract.isTerminalProgressValue(100, "ready"));
        assertEquals(true, PtkCloseContract.isTerminalProgressValue(100, ""));
        assertEquals(true, PtkCloseContract.isTerminalProgressValue(72, "completed"));
        assertEquals(true, PtkCloseContract.isTerminalProgressValue(72, "cancelled"));
        assertEquals(true, PtkCloseContract.isTerminalProgressValue(72, "engine_incomplete"));
    }

    @Test
    void closeDecisionSafeToCloseRequiresTerminalProgress() {
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose("safe_to_close", 99, "running"));
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(
                        "safe_to_close", 100, "running"));
        assertEquals(
                true,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(
                        "safe_to_close", 100, "completed"));
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose("wait", 100, "completed"));
    }

    @Test
    void closeDecisionCanUseTerminalPostedDecisionBeforeProgressMapUpdates() {
        Map<String, Object> closeDecision = new LinkedHashMap<>();
        closeDecision.put("decision", "safe_to_close");
        closeDecision.put("scanState", "engine_incomplete");
        closeDecision.put("zapProgressTerminalPosted", true);

        assertEquals(
                true,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 67, "running"));

        closeDecision.put("zapProgressTerminalPosted", false);
        closeDecision.put("stopRequested", true);
        assertEquals(
                true,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 67, "running"));

        closeDecision.put("stopRequested", false);
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 67, "running"));
    }

    @Test
    void closeDecisionAcceptsAlreadyTerminalStateBeforeProgressMapUpdates() {
        Map<String, Object> closeDecision = new LinkedHashMap<>();
        closeDecision.put("decision", "safe_to_close");
        closeDecision.put("scanState", "completed");
        closeDecision.put("reason", "already_terminal");

        assertEquals(
                true,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 35, "running"));

        closeDecision.put("reason", "close_requested");
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 35, "running"));
    }

    @Test
    void browserCoverageSnapshotClassifiesRouteEvidenceFailures() {
        assertEquals(
                "not_browser_loaded",
                new BrowserCoverageSnapshot("https://example.test/a", 1, 0, 0, 0, 0, 0, 0, 0, 0)
                        .classify(true));
        assertEquals(
                "browser_loaded_no_ptk",
                new BrowserCoverageSnapshot("https://example.test/a", 1, 1, 0, 0, 0, 0, 0, 0, 0)
                        .classify(true));
        assertEquals(
                "browser_session_invalid:no_ptk_progress",
                new BrowserCoverageSnapshot("https://example.test/a", 1, 0, 0, 0, 1, 0, 0, 1, 0)
                        .classify(true));
        assertEquals(
                "browser_loaded",
                new BrowserCoverageSnapshot("https://example.test/a", 1, 1, 1, 0, 0, 0, 0, 0, 0)
                        .classify(true));
    }

    @Test
    void browserCloseDoesNotSatisfyScheduledTargetCoverage() {
        BrowserCoverageEvidence evidence = new BrowserCoverageEvidence();

        evidence.scheduled(1);
        evidence.record("browser_close", Map.of("decision", "safe_to_close"));

        BrowserCoverageSnapshot snapshot = evidence.snapshot("https://example.test/a");
        assertEquals(0, snapshot.browserLoaded());
        assertEquals(0, snapshot.ptkSessionEstablished());
        assertEquals("not_browser_loaded", snapshot.classify(true));
    }

    @Test
    void ptkSessionEstablishedSatisfiesScheduledTargetCoverage() {
        BrowserCoverageEvidence evidence = new BrowserCoverageEvidence();

        evidence.scheduled(1);
        evidence.record("browser_loaded", Map.of("source", "browserCoverageNavigation"));
        evidence.record("ptk_session_established", Map.of("progress", 0));

        BrowserCoverageSnapshot snapshot = evidence.snapshot("https://example.test/a");
        assertEquals(1, snapshot.browserLoaded());
        assertEquals(1, snapshot.ptkSessionEstablished());
        assertEquals("browser_loaded", snapshot.classify(true));
    }

    @Test
    void ptkAnalysisReadyKeepsIndependentCountersButSatisfiesReadiness() {
        BrowserCoverageEvidence evidence = new BrowserCoverageEvidence();

        evidence.scheduled(1);
        evidence.record("ptk_analysis_ready", Map.of("readiness", "ready"));

        BrowserCoverageSnapshot snapshot = evidence.snapshot("https://example.test/a");
        assertEquals(0, snapshot.browserLoaded());
        assertEquals(0, snapshot.ptkSessionEstablished());
        assertEquals(1, snapshot.ptkAnalysisReady());
        assertEquals(true, snapshot.hasBrowserLoad());
        assertEquals(true, snapshot.hasPtkSession());
        assertEquals("browser_loaded", snapshot.classify(true));
    }

    @Test
    void browserCoverageDetectsFragmentTargetsForExactNavigation() {
        assertEquals(true, PtkUrlUtils.hasFragment("https://example.test/a#x"));
        assertEquals(true, PtkUrlUtils.hasFragment("https://example.test/a?q=1#x"));
        assertEquals(false, PtkUrlUtils.hasFragment("https://example.test/a?q=1"));
        assertEquals(false, PtkUrlUtils.hasFragment("not a url"));
    }

    @Test
    void browserCoverageNormalizesDirectoryIndexEquivalence() {
        assertEquals(
                "https://example.test/address/index.html",
                PtkUrlUtils.normalizeBrowserCoverageUrl("https://example.test/address/"));
        assertEquals(
                "https://example.test/address/index.html",
                PtkUrlUtils.normalizeBrowserCoverageUrl("https://example.test/address/index.html"));
        assertEquals(
                "https://example.test/address/index.html?q=a",
                PtkUrlUtils.normalizeBrowserCoverageUrl("https://example.test/address/?q=a"));
        assertNull(PtkUrlUtils.normalizeBrowserCoverageUrl("https://zap/zapCallBackUrl/1"));
    }
}
