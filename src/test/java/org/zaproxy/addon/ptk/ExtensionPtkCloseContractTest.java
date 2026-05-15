package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
