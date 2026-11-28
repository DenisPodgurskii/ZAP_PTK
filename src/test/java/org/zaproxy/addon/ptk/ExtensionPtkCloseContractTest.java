package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.remote.SessionId;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ClientCallBackUtils;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;

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
        assertTrue(
                PtkCloseContract.BROWSER_CLOSE_ACTIVITY_STALE_MS
                        > PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS);
        assertTrue(
                PtkCloseContract.BROWSER_CALLBACK_BOOTSTRAP_HANDSHAKE_MS
                        >= PtkCloseContract.BROWSER_CALLBACK_BOOTSTRAP_RELOAD_AFTER_MS + 9000L);
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
    void callbackBootstrapHandshakeReturnsImmediatelyWhenCallbackAlreadySeen() {
        AtomicInteger reloads = new AtomicInteger();

        PtkCloseContract.CallbackBootstrapHandshakeResult result =
                PtkCloseContract.awaitCallbackBootstrapHandshake(
                        () -> true,
                        reloads::incrementAndGet,
                        () -> 1000L,
                        sleepMs -> {
                            throw new AssertionError("sleep should not be called");
                        },
                        1000,
                        250,
                        100);

        assertEquals(true, result.handshakeSeen());
        assertEquals(0, result.handshakePolls());
        assertEquals(false, result.callbackReloadAttempted());
        assertEquals(0, reloads.get());
    }

    @Test
    void callbackBootstrapHandshakeWaitsForDelayedCallbackWithoutReload() {
        AtomicLong now = new AtomicLong(1000L);

        PtkCloseContract.CallbackBootstrapHandshakeResult result =
                PtkCloseContract.awaitCallbackBootstrapHandshake(
                        () -> now.get() >= 1200L,
                        () -> {
                            throw new AssertionError("reload should not be called");
                        },
                        now::get,
                        now::addAndGet,
                        1000,
                        500,
                        100);

        assertEquals(true, result.handshakeSeen());
        assertEquals(200, result.handshakeWaitedMs());
        assertEquals(2, result.handshakePolls());
        assertEquals(false, result.callbackReloadAttempted());
    }

    @Test
    void callbackBootstrapHandshakeReloadsOnceWhenCallbackIsLate() {
        AtomicLong now = new AtomicLong(1000L);
        AtomicBoolean callbackSeen = new AtomicBoolean(false);
        AtomicInteger reloads = new AtomicInteger();

        PtkCloseContract.CallbackBootstrapHandshakeResult result =
                PtkCloseContract.awaitCallbackBootstrapHandshake(
                        callbackSeen::get,
                        () -> {
                            reloads.incrementAndGet();
                            callbackSeen.set(true);
                        },
                        now::get,
                        now::addAndGet,
                        1000,
                        250,
                        100);

        assertEquals(true, result.handshakeSeen());
        assertEquals(true, result.callbackReloadAttempted());
        assertEquals(1, reloads.get());
        assertEquals(300, result.handshakeWaitedMs());
    }

    @Test
    void callbackBootstrapHandshakeReloadsOnceAndReturnsPreciseStateOnTimeout() {
        AtomicLong now = new AtomicLong(1000L);
        AtomicInteger reloads = new AtomicInteger();

        PtkCloseContract.CallbackBootstrapHandshakeResult result =
                PtkCloseContract.awaitCallbackBootstrapHandshake(
                        () -> false,
                        () -> "callback_acquired_no_config",
                        reloads::incrementAndGet,
                        now::get,
                        now::addAndGet,
                        750,
                        200,
                        100);

        assertEquals(false, result.handshakeSeen());
        assertEquals(750, result.handshakeWaitedMs());
        assertEquals(true, result.callbackReloadAttempted());
        assertEquals(1, result.callbackReloadAttempts());
        assertEquals(1, reloads.get());
        assertEquals("callback_acquired_no_config", result.handshakeState());
    }

    @Test
    void chromiumExtensionIdUsesNormalizedUnpackedExtensionPath() {
        Path path =
                Path.of(
                        "/Users/ptk/dev/ptk_pro/ZAP_PTK/src/main/zapHomeFiles/selenium/extensions/ptk-latest");

        assertEquals(
                "cghijnohgofbonplhadglampeljmepgd", ExtensionPtk.chromiumExtensionIdForPath(path));
        assertEquals(
                "chrome-extension://cghijnohgofbonplhadglampeljmepgd/ptk/internal/zap-runner.html",
                ExtensionPtk.buildChromiumZapRunnerUrl(path));
    }

    @Test
    void trustedRunnerUsesWebDriverBrowserNameInsteadOfClientWorkerUuid() {
        assertEquals(true, ExtensionPtk.isChromiumBrowserName("MicrosoftEdge"));
        assertEquals(true, ExtensionPtk.isChromiumBrowserName("chrome"));
        assertEquals(true, ExtensionPtk.isChromiumBrowserName("chromium"));
        assertEquals(false, ExtensionPtk.isChromiumBrowserName("firefox"));
        assertEquals(
                false, ExtensionPtk.isChromiumBrowserName("6ad8a9c8-9077-47b5-976f-346d858b5f0b"));
    }

    @Test
    void trustedRunnerTerminalDecisionIsBoundToExactSessionAndCloseRequest() {
        Map<String, Object> decision = new LinkedHashMap<>();
        decision.put("trustedRunnerVerified", true);
        decision.put("trustedRunner", "ptk-zap-control-v1");
        decision.put("source", "webdriver_extension_runner");
        decision.put("decision", "safe_to_close");
        decision.put("scanState", "cancelled");
        decision.put("terminalFinalized", true);
        decision.put("idleVerified", true);
        decision.put("completionStatus", "cancelled");
        decision.put("releaseStatus", "incomplete");
        decision.put("publisherDrained", false);
        decision.put("sessionId", "ptk-session-1");
        decision.put("closeRequestId", "close-1");
        decision.put("closeRequestAck", true);

        assertEquals(
                true,
                PtkCloseContract.isTrustedRunnerTerminalCloseDecision(
                        decision, "ptk-session-1", "close-1"));
        assertEquals(
                false,
                PtkCloseContract.isTrustedRunnerTerminalCloseDecision(
                        decision, "ptk-session-other", "close-1"));
        assertEquals(
                false,
                PtkCloseContract.isTrustedRunnerTerminalCloseDecision(
                        decision, "ptk-session-1", "close-other"));

        decision.put("trustedRunner", "attacker-controlled");
        assertEquals(
                false,
                PtkCloseContract.isTrustedRunnerTerminalCloseDecision(
                        decision, "ptk-session-1", "close-1"));

        decision.put("trustedRunner", "ptk-zap-control-v1");
        decision.put("idleVerified", false);
        assertEquals(
                false,
                PtkCloseContract.isTrustedRunnerTerminalCloseDecision(
                        decision, "ptk-session-1", "close-1"));
    }

    @Test
    void callbackRunnerRequiresEffectiveZapAutomationAndChromiumBrowser() {
        String callbackUrl = "https://zap/zapCallBackUrl/secret?zapenable=true&zapid=zap-1";

        assertEquals(
                "zap_automation_disabled",
                ExtensionPtk.zapCallbackRunnerSkipReason(false, "edge", callbackUrl));
        assertEquals(
                "non_chromium_browser",
                ExtensionPtk.zapCallbackRunnerSkipReason(true, "firefox", callbackUrl));
        assertEquals(
                "not_zap_callback",
                ExtensionPtk.zapCallbackRunnerSkipReason(true, "edge", "https://example.test/"));
        assertEquals("", ExtensionPtk.zapCallbackRunnerSkipReason(true, "edge", callbackUrl));
        assertEquals(
                "", ExtensionPtk.zapCallbackRunnerSkipReason(true, "chrome-headless", callbackUrl));
    }

    @Test
    void browserTaskStateRedactsCallbackLoadedUrlInLogFields() {
        PtkBrowserTaskState state =
                PtkBrowserTaskState.loaded(
                        "zap-1",
                        "browser-1",
                        "https://zap/zapCallBackUrl/raw-secret?zapenable=true&zapid=zap-1",
                        1000L);

        Map<String, Object> fields = state.toLogFields(1250L);

        assertEquals(
                "https://zap/zapCallBackUrl/<redacted>?zapenable=true&zapid=<redacted>",
                fields.get("loadedUrl"));
    }

    @Test
    void canonicalProgressSummaryIgnoresVolatileHeartbeatFields() {
        Map<String, Object> first = progressPayload(1_000L, 10);
        Map<String, Object> second = progressPayload(2_000L, 10);

        assertEquals(
                PtkCloseContract.canonicalProgressSummary(first),
                PtkCloseContract.canonicalProgressSummary(second));
    }

    @Test
    @SuppressWarnings("unchecked")
    void canonicalProgressSummaryIgnoresExtensionActivityAndModuleDeliveryCounters() {
        Map<String, Object> first = progressPayload(1_000L, 10);
        Map<String, Object> second = progressPayload(1_000L, 10);
        Map<String, Object> secondDetails =
                (Map<String, Object>)
                        ((Map<String, Object>)
                                        ((Map<String, Object>) second.get("engines")).get("DAST"))
                                .get("details");

        first.put("activitySeq", 42);
        first.put("activityFingerprint", "extension-fingerprint-1");
        second.put("activitySeq", 99);
        second.put("activityFingerprint", "extension-fingerprint-2");
        secondDetails.put("modulesSentOk", 150);
        secondDetails.put("modulesSentSkipped", 3);
        secondDetails.put("modulesSentError", 1);
        secondDetails.put("requestsCount", 400);
        secondDetails.put("runtimeEventsCount", 800);
        secondDetails.put("runtimeSignalsAccepted", 700);

        assertEquals(
                PtkCloseContract.canonicalProgressSummary(first),
                PtkCloseContract.canonicalProgressSummary(second));
    }

    @Test
    @SuppressWarnings("unchecked")
    void canonicalProgressSummaryChangesOnMeaningfulProgressAndPublisherState() {
        Map<String, Object> first = progressPayload(1_000L, 10);
        Map<String, Object> progressChanged = progressPayload(1_000L, 11);
        Map<String, Object> publisherChanged = progressPayload(1_000L, 10);
        ((Map<String, Object>) publisherChanged.get("publisher")).put("pendingFindings", 2);

        assertTrue(
                !PtkCloseContract.canonicalProgressSummary(first)
                        .equals(PtkCloseContract.canonicalProgressSummary(progressChanged)));
        assertTrue(
                !PtkCloseContract.canonicalProgressSummary(first)
                        .equals(PtkCloseContract.canonicalProgressSummary(publisherChanged)));
    }

    @Test
    void activityFreshnessUsesJavaReceiptTimeOnly() {
        assertEquals(false, PtkCloseContract.isActivityFresh(null, 1_000L));
        assertEquals(true, PtkCloseContract.isActivityFresh(1_000L, 1_000L));
        assertEquals(
                false,
                PtkCloseContract.isActivityFresh(
                        1_000L, 1_001L + PtkCloseContract.BROWSER_CLOSE_ACTIVITY_STALE_MS));
        assertEquals(25L, PtkCloseContract.activityIdleMs(1_000L, 1_025L));
        assertEquals(-1L, PtkCloseContract.activityIdleMs(null, 1_025L));
    }

    @Test
    void safeToCloseIsNotAcceptedUntilCloseDecisionAttemptIsRecorded() {
        Map<String, Long> closeDecisionAttemptedByZapId = new ConcurrentHashMap<>();

        assertNull(
                PtkCloseContract.getCloseDecisionAttemptedAtMs(
                        closeDecisionAttemptedByZapId, "zap-1"));
        assertEquals(
                false,
                PtkCloseContract.canAcceptSafeToClose(closeDecisionAttemptedByZapId, "zap-1"));

        PtkCloseContract.markCloseDecisionAttempted(closeDecisionAttemptedByZapId, "zap-1", 123L);

        assertEquals(
                123L,
                PtkCloseContract.getCloseDecisionAttemptedAtMs(
                        closeDecisionAttemptedByZapId, "zap-1"));
        assertEquals(
                true,
                PtkCloseContract.canAcceptSafeToClose(closeDecisionAttemptedByZapId, "zap-1"));
    }

    @Test
    void firstCloseDecisionAttemptTimestampIsPreserved() {
        Map<String, Long> closeDecisionAttemptedByZapId = new ConcurrentHashMap<>();

        PtkCloseContract.markCloseDecisionAttempted(closeDecisionAttemptedByZapId, "zap-1", 123L);
        PtkCloseContract.markCloseDecisionAttempted(closeDecisionAttemptedByZapId, "zap-1", 456L);

        assertEquals(
                123L,
                PtkCloseContract.getCloseDecisionAttemptedAtMs(
                        closeDecisionAttemptedByZapId, "zap-1"));
        assertNull(
                PtkCloseContract.getCloseDecisionAttemptedAtMs(
                        closeDecisionAttemptedByZapId, null));
        assertNull(
                PtkCloseContract.getCloseDecisionAttemptedAtMs(closeDecisionAttemptedByZapId, ""));
    }

    @Test
    void zapSessionStateKeepsCloseRequestStableAndAcknowledgesOnlyMatchingId() {
        PtkZapSessionState state = new PtkZapSessionState("zap-state-1");
        state.rememberSessionContext("browser-1", "session-1");

        PtkCloseRequestState first = state.ensureCloseRequest("activity_stale", 1_000L);
        PtkCloseRequestState second = state.ensureCloseRequest("activity_stale_again", 2_000L);

        assertEquals(first.id(), second.id());
        assertEquals("session-1", first.sessionId());
        assertEquals("browser-1", first.browserId());
        assertEquals("activity_stale", state.snapshot().closeRequest().reason());
        assertEquals(false, state.snapshot().closeRequest().acknowledged());
        assertEquals(true, state.isCloseRequestForSession(first, "session-1", "browser-1"));
        assertEquals(false, state.isCloseRequestForSession(first, null, "browser-1"));
        assertEquals(false, state.isCloseRequestForSession(first, "session-1", null));
        assertEquals(false, state.isCloseRequestForSession(first, "old-session", "browser-1"));
        assertEquals(false, state.isCloseRequestForSession(first, "session-1", "browser-2"));

        state.acknowledgeCloseRequest("wrong-request");
        assertEquals(false, state.snapshot().closeRequest().acknowledged());

        state.acknowledgeCloseRequest(first.id());
        assertEquals(true, state.snapshot().closeRequest().acknowledged());
    }

    @Test
    void zapSessionStateRejectsOutOfOrderProgressActivitySeq() {
        PtkZapSessionState state = new PtkZapSessionState("zap-state-2");

        PtkZapSessionState.ProgressActivity first =
                state.recordProgress(
                        "browser-1",
                        "session-1",
                        10,
                        "running",
                        "activity=10",
                        false,
                        2,
                        false,
                        10,
                        1_000L);
        PtkZapSessionSnapshot firstSnapshot = state.snapshot();
        PtkZapSessionState.ProgressActivity stale =
                state.recordProgress(
                        "browser-1",
                        "session-1",
                        90,
                        "completed",
                        "activity=9",
                        true,
                        2,
                        true,
                        9,
                        2_000L);

        assertEquals(false, first.outOfOrder());
        assertEquals(true, stale.outOfOrder());
        assertEquals(10, state.snapshot().progress());
        assertEquals("running", state.snapshot().status());
        assertEquals(
                firstSnapshot.lastProgressChangedAtMs(),
                state.snapshot().lastProgressChangedAtMs());
    }

    @Test
    void v2TerminalProgressRequiresPublisherDrainBeforeCleanCloseEvidence() {
        PtkZapSessionState state = new PtkZapSessionState("zap-state-3");

        state.recordProgress(
                "browser-1",
                "session-1",
                100,
                "completed",
                "status=completed,publisher=false",
                true,
                2,
                false,
                10,
                1_000L);

        assertEquals(false, state.snapshot().isV2TerminalAndDrained());

        state.recordProgress(
                "browser-1",
                "session-1",
                100,
                "completed",
                "status=completed,publisher=true",
                true,
                2,
                true,
                11,
                2_000L);

        assertEquals(true, state.snapshot().isV2TerminalAndDrained());
    }

    @Test
    void v2ReleaseCleanRequiresCompletedCompletionStatus() {
        PtkZapSessionState state = new PtkZapSessionState("zap-state-4");

        state.rememberReleaseState("engine_incomplete", "incomplete");
        state.recordProgress(
                "browser-1",
                "session-1",
                100,
                "cancelled",
                "status=cancelled,publisher=true",
                true,
                2,
                true,
                10,
                1_000L);

        assertEquals(true, state.snapshot().isV2TerminalAndDrained());
        assertEquals(false, state.snapshot().isV2ReleaseClean());

        state.rememberReleaseState("completed", "clean");

        assertEquals(true, state.snapshot().isV2ReleaseClean());
    }

    @Test
    void v2LateAckProgressDoesNotRegressTerminalSessionState() {
        PtkZapSessionState state = new PtkZapSessionState("zap-state-late-ack");

        state.rememberReleaseState("completed", "clean");
        state.recordProgress(
                "browser-1",
                "session-1",
                100,
                "completed",
                "status=completed,publisher=true",
                true,
                2,
                true,
                50,
                1_000L);

        PtkZapSessionState.ProgressActivity lateAck =
                state.recordProgress(
                        "browser-1",
                        "session-1",
                        99,
                        "running",
                        "status=running,progress=99",
                        false,
                        2,
                        false,
                        51,
                        2_000L);

        assertEquals(true, lateAck.ignoredAfterTerminal());
        assertEquals(100, state.snapshot().progress());
        assertEquals("completed", state.snapshot().status());
        assertEquals(true, state.snapshot().isV2ReleaseClean());
    }

    @Test
    void v2LateReleaseStateDoesNotRegressCleanTerminalSession() {
        PtkZapSessionState state = new PtkZapSessionState("zap-state-late-release");

        state.rememberReleaseState("completed", "clean");
        state.recordProgress(
                "browser-1",
                "session-1",
                100,
                "completed",
                "status=completed,publisher=true",
                true,
                2,
                true,
                50,
                1_000L);

        state.rememberReleaseState("engine_incomplete", "incomplete");

        assertEquals("completed", state.snapshot().completionStatus());
        assertEquals("clean", state.snapshot().releaseStatus());
        assertEquals(true, state.snapshot().isV2ReleaseClean());
    }

    @Test
    void v2PhysicalCloseCanBeSafeWhileReleaseIsIncomplete() {
        PtkZapSessionState state = new PtkZapSessionState("zap-state-physical");

        state.rememberReleaseState("publisher_incomplete", "incomplete");
        state.recordProgress(
                "browser-1",
                "session-1",
                100,
                "engine_incomplete",
                "status=engine_incomplete,publisher=false",
                true,
                2,
                false,
                10,
                1_000L);

        assertEquals(true, state.snapshot().isV2PhysicallySafeToClose());
        assertEquals(false, state.snapshot().isV2TerminalAndDrained());
        assertEquals(false, state.snapshot().isV2ReleaseClean());
        assertEquals(true, state.snapshot().isV2ReleaseIncomplete());
    }

    @Test
    void adaptiveStaleControlRequestRequiresLateV2RunningSession() {
        PtkZapSessionState state = new PtkZapSessionState("zap-state-adaptive");
        state.recordProgress(
                "browser-1",
                "session-1",
                99,
                "running",
                "status=running,progress=99",
                false,
                2,
                false,
                10,
                1_000L);

        assertEquals(
                false,
                PtkCloseContract.shouldCreateAdaptiveStaleCloseRequest(
                        state.snapshot(), "session-1", "browser-1", 30_000L));
        assertEquals(
                true,
                PtkCloseContract.shouldCreateAdaptiveStaleCloseRequest(
                        state.snapshot(), "session-1", "browser-1", 31_001L));
        assertEquals(
                false,
                PtkCloseContract.shouldCreateAdaptiveStaleCloseRequest(
                        state.snapshot(), "other-session", "browser-1", 31_001L));
        assertEquals(
                false,
                PtkCloseContract.shouldCreateAdaptiveStaleCloseRequest(
                        state.snapshot(), "session-1", "other-browser", 31_001L));

        state.ensureCloseRequest("activity_stale_before_browser_close", 31_001L);
        assertEquals(
                false,
                PtkCloseContract.shouldCreateAdaptiveStaleCloseRequest(
                        state.snapshot(), "session-1", "browser-1", 62_000L));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sast", "iast"})
    void passiveOnlyControlPollWaitsForBrowserOwnerClose(String engine) throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        String zapid = "zap-control-" + engine;
        PtkZapSessionState state = new PtkZapSessionState(zapid);
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("mode", "auto");
        config.put("sast", Map.of());
        config.put("iast", Map.of());
        config.put("dast", Map.of());
        config.put(engine, Map.of("modules", List.of("fixture")));
        int initiator =
                "sast".equals(engine)
                        ? HttpSender.SPIDER_INITIATOR
                        : HttpSender.ACTIVE_SCANNER_INITIATOR;
        state.rememberPassiveOnlyConfig(
                PtkCloseContract.isPassiveOnlyAutoConfig(config, initiator));
        state.recordProgress(
                "browser-1", "session-1", 99, "running", "findings=74", false, 2, true, 24, 1L);
        sessionStateByZapId(extension).put(zapid, state);
        Map<String, Object> poll =
                Map.of("zapid", zapid, "browserid", "browser-1", "sessionId", "session-1");

        assertEquals(false, invokeControlPoll(extension, poll).get("closeRequested"));
        assertNull(state.snapshot().closeRequest());
        assertNull(closeRequestIdByZapId(extension).get(zapid));
        var later =
                state.recordProgress(
                        "browser-1",
                        "session-1",
                        99,
                        "running",
                        "findings=75",
                        false,
                        2,
                        true,
                        25,
                        System.currentTimeMillis());
        assertTrue(later.progressChanged());
        assertEquals(false, invokeControlPoll(extension, poll).get("closeRequested"));

        PtkCloseRequestState request =
                state.ensureCloseRequest(
                        "owner_browser_close_requested", System.currentTimeMillis());
        assertEquals(request.id(), invokeControlPoll(extension, poll).get("closeRequestId"));
    }

    @Test
    void passiveOnlyCloseScopeUsesTheDeliveredEngineConfigAndRejectsMixedOwners() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("mode", "auto");
        config.put("sast", Map.of());
        config.put("iast", Map.of("modules", List.of("fixture")));
        config.put("dast", Map.of());
        int active = HttpSender.ACTIVE_SCANNER_INITIATOR;
        assertTrue(PtkCloseContract.isPassiveOnlyAutoConfig(config, HttpSender.SPIDER_INITIATOR));
        assertFalse(PtkCloseContract.isPassiveOnlyAutoConfig(config, -1));

        PtkZapSessionState state = new PtkZapSessionState("zap-config-scope");
        state.rememberPassiveOnlyConfig(PtkCloseContract.isPassiveOnlyAutoConfig(config, active));
        assertTrue(state.hasPassiveOnlyConfig());
        config.put("dast", Map.of("modules", List.of("fixture")));
        assertFalse(PtkCloseContract.isPassiveOnlyAutoConfig(config, active));
        state.rememberPassiveOnlyConfig(PtkCloseContract.isPassiveOnlyAutoConfig(config, active));
        config.put("dast", Map.of());
        state.rememberPassiveOnlyConfig(PtkCloseContract.isPassiveOnlyAutoConfig(config, active));
        assertFalse(state.hasPassiveOnlyConfig());
        config.put("sca", Map.of("modules", List.of("fixture")));
        assertFalse(PtkCloseContract.isPassiveOnlyAutoConfig(config, active));
        config.remove("sca");
        config.remove("iast");
        assertFalse(PtkCloseContract.isPassiveOnlyAutoConfig(config, active));
    }

    @Test
    void mixedDastStopHasItsOwnReceiptAndDoesNotAuthorizeClose() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        PtkZapSessionState state = new PtkZapSessionState("zap-mixed");
        Map<String, Object> config =
                Map.of(
                        "mode",
                        "auto",
                        "sast",
                        Map.of(),
                        "iast",
                        Map.of("modules", List.of("iast")),
                        "dast",
                        Map.of("modules", List.of("dast")));
        assertFalse(
                PtkCloseContract.isMixedIastDastAutoConfig(config, HttpSender.SPIDER_INITIATOR));
        state.rememberMixedIastDastConfig(
                PtkCloseContract.isMixedIastDastAutoConfig(
                        config, HttpSender.ACTIVE_SCANNER_INITIATOR),
                "browser-1");
        state.recordProgress(
                "browser-1", "session-1", 99, "running", "idle", false, 2, true, 24, 1L);
        sessionStateByZapId(extension).put("zap-mixed", state);
        Map<String, Object> poll =
                new LinkedHashMap<>(
                        Map.of(
                                "zapid",
                                "zap-mixed",
                                "browserid",
                                "browser-1",
                                "sessionId",
                                "session-1",
                                "dastStopSupported",
                                true));

        poll.put("browserid", "foreign");
        assertNull(invokeControlPoll(extension, poll).get("dastStop"));
        poll.put("browserid", "browser-1");
        poll.put("sessionId", "foreign");
        assertNull(invokeControlPoll(extension, poll).get("dastStop"));
        poll.put("sessionId", "session-1");
        Map<String, Object> response = invokeControlPoll(extension, poll);
        Map<?, ?> request = (Map<?, ?>) response.get("dastStop");
        assertNotNull(request);
        assertEquals("stop_dast_and_drain", request.get("mode"));
        assertEquals(false, response.get("closeRequested"));
        assertNull(state.closeRequest());
        poll.put("dastStopReceipt", Map.of("id", "foreign", "result", "completed"));
        assertEquals(request, invokeControlPoll(extension, poll).get("dastStop"));
        poll.put(
                "dastStopReceipt",
                Map.of(
                        "id",
                        request.get("id"),
                        "result",
                        "engine_incomplete",
                        "error",
                        "stop_timeout"));
        response = invokeControlPoll(extension, poll);
        assertEquals(request.get("id"), response.get("dastStopAcknowledged"));
        assertEquals(false, response.get("closeRequested"));
        assertNull(state.closeRequest());
        poll.remove("dastStopSupported");
        assertEquals(false, invokeControlPoll(extension, poll).get("closeRequested"));

        PtkCloseRequestState close =
                state.ensureCloseRequest(
                        "owner_browser_close_requested", System.currentTimeMillis());
        response = invokeControlPoll(extension, poll);
        assertEquals(close.id(), response.get("closeRequestId"));
        assertFalse(close.id().equals(request.get("id")));
    }

    @Test
    void mixedConfigWithLegacyBridgeStillUsesExistingStaleClose() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        PtkZapSessionState state = new PtkZapSessionState("zap-legacy");
        state.rememberMixedIastDastConfig(true, "browser-1");
        state.recordProgress(
                "browser-1", "session-1", 99, "running", "idle", false, 2, true, 24, 1L);
        sessionStateByZapId(extension).put("zap-legacy", state);
        Map<String, Object> response =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-legacy",
                                "sessionId",
                                "session-1",
                                "browserid",
                                "browser-1"));
        assertEquals(true, response.get("closeRequested"));
        assertNull(response.get("dastStop"));
    }

    @Test
    void controlPollCreatesCloseRequestForStaleRunningSessionWithUnknownConfig() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        PtkZapSessionState state = new PtkZapSessionState("zap-control-stale");
        state.recordProgress(
                "browser-1",
                "session-1",
                99,
                "running",
                "status=running,progress=99",
                false,
                2,
                false,
                10,
                1L);
        sessionStateByZapId(extension).put("zap-control-stale", state);

        Map<String, Object> response =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-control-stale",
                                "browserid",
                                "browser-1",
                                "sessionId",
                                "session-1",
                                "activitySeq",
                                10));

        assertEquals("OK", response.get("result"));
        assertEquals(true, response.get("closeRequested"));
        assertEquals("graceful_stop_and_drain", response.get("mode"));
        assertEquals("activity_stale_before_browser_close", response.get("reason"));
        assertNotNull(response.get("closeRequestId"));
        PtkCloseRequestState closeRequest = state.snapshot().closeRequest();
        assertNotNull(closeRequest);
        assertEquals(response.get("closeRequestId"), closeRequest.id());
        assertEquals(
                response.get("closeRequestId"),
                closeRequestIdByZapId(extension).get("zap-control-stale"));
    }

    @Test
    void controlPollDoesNotCreateEmptySessionState() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();

        Map<String, Object> response =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-control-unknown",
                                "browserid",
                                "browser-1",
                                "sessionId",
                                "session-1"));

        assertEquals("OK", response.get("result"));
        assertEquals(false, response.get("closeRequested"));
        assertEquals(false, sessionStateByZapId(extension).containsKey("zap-control-unknown"));
        assertEquals(false, browserIdByZapId(extension).containsKey("zap-control-unknown"));
        assertEquals(false, closeRequestIdByZapId(extension).containsKey("zap-control-unknown"));
    }

    @Test
    void controlPollReturnsAndAcknowledgesExistingCloseRequest() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        PtkZapSessionState state = new PtkZapSessionState("zap-control-existing");
        state.rememberSessionContext("browser-1", "session-1");
        PtkCloseRequestState closeRequest =
                state.ensureCloseRequest("activity_stale_after_close_request", 1_000L);
        sessionStateByZapId(extension).put("zap-control-existing", state);

        Map<String, Object> returned =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-control-existing",
                                "browserid",
                                "browser-1",
                                "sessionId",
                                "session-1"));

        assertEquals(true, returned.get("closeRequested"));
        assertEquals(closeRequest.id(), returned.get("closeRequestId"));

        Map<String, Object> acked =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-control-existing",
                                "browserid",
                                "browser-1",
                                "sessionId",
                                "session-1",
                                "closeRequestId",
                                closeRequest.id(),
                                "closeRequestAck",
                                true));

        assertEquals(true, state.snapshot().closeRequest().acknowledged());
        assertEquals(false, acked.get("closeRequested"));
    }

    @Test
    void controlPollRejectsMismatchedCloseRequestAckAndDelivery() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        PtkZapSessionState state = new PtkZapSessionState("zap-control-mismatch");
        state.rememberSessionContext("browser-1", "session-1");
        PtkCloseRequestState closeRequest =
                state.ensureCloseRequest("activity_stale_after_close_request", 1_000L);
        sessionStateByZapId(extension).put("zap-control-mismatch", state);

        Map<String, Object> mismatchedSessionAck =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-control-mismatch",
                                "browserid",
                                "browser-2",
                                "sessionId",
                                "session-1",
                                "closeRequestId",
                                closeRequest.id(),
                                "closeRequestAck",
                                true));

        assertEquals(false, mismatchedSessionAck.get("closeRequested"));
        assertEquals(false, state.snapshot().closeRequest().acknowledged());

        Map<String, Object> wrongRequestAck =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-control-mismatch",
                                "browserid",
                                "browser-1",
                                "sessionId",
                                "session-1",
                                "closeRequestId",
                                closeRequest.id() + "-stale",
                                "closeRequestAck",
                                true));

        assertEquals(true, wrongRequestAck.get("closeRequested"));
        assertEquals(closeRequest.id(), wrongRequestAck.get("closeRequestId"));
        assertEquals(false, state.snapshot().closeRequest().acknowledged());

        Map<String, Object> correctAck =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-control-mismatch",
                                "browserid",
                                "browser-1",
                                "sessionId",
                                "session-1",
                                "closeRequestId",
                                closeRequest.id(),
                                "closeRequestAck",
                                true));

        assertEquals(false, correctAck.get("closeRequested"));
        assertEquals(true, state.snapshot().closeRequest().acknowledged());
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
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 67, "running"));

        closeDecision.put("stopRequested", false);
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 67, "running"));
    }

    @Test
    void closeDecisionAcceptsAlreadyTerminalStateWhenJavaProgressStillRuns() {
        Map<String, Object> closeDecision = new LinkedHashMap<>();
        closeDecision.put("decision", "safe_to_close");
        closeDecision.put("scanState", "completed");
        closeDecision.put("reason", "already_terminal");

        assertEquals(
                true,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 35, "running"));

        closeDecision.put("zapProgressTerminalPosted", true);
        assertEquals(
                true,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 35, "running"));

        closeDecision.put("zapProgressTerminalPosted", false);
        closeDecision.put("reason", "close_requested");
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 35, "running"));
    }

    @Test
    void closeDecisionRejectsNoActiveBrowserWorkWhileSessionRuns() {
        Map<String, Object> closeDecision = new LinkedHashMap<>();
        closeDecision.put("decision", "safe_to_close");
        closeDecision.put("scanState", "running");
        closeDecision.put("reason", "no_active_browser_work");
        closeDecision.put("stopRequested", false);

        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 99, "running"));
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 100, "running"));

        closeDecision.put("scanState", "completed");
        closeDecision.put("zapProgressTerminalPosted", true);
        assertEquals(
                true,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 99, "running"));
    }

    @Test
    void browserLocalTabSafeToCloseDoesNotRepresentSessionTerminalState() {
        Map<String, Object> closeDecision = new LinkedHashMap<>();
        closeDecision.put("decision", "browser_tab_safe_to_close");
        closeDecision.put("scanState", "running");
        closeDecision.put("reason", "no_active_browser_work");
        closeDecision.put("stopRequested", false);

        assertEquals(true, PtkCloseContract.isBrowserLocalTabSafeToCloseDecision(closeDecision));
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 99, "running"));

        closeDecision.put("reason", "non_owner_active_work");
        assertEquals(true, PtkCloseContract.isBrowserLocalTabSafeToCloseDecision(closeDecision));
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 99, "running"));

        closeDecision.put("stopRequested", true);
        assertEquals(false, PtkCloseContract.isBrowserLocalTabSafeToCloseDecision(closeDecision));

        closeDecision.put("stopRequested", false);
        closeDecision.put("reason", "ptk_active_work");
        assertEquals(false, PtkCloseContract.isBrowserLocalTabSafeToCloseDecision(closeDecision));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void boundNativeCloseWaitsForTheExactTerminalDrain(boolean partial) throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        ExtensionPtk.CallBackImplementor callback = extension.new CallBackImplementor();
        UUID uuid = UUID.randomUUID();
        String zapid = uuid.toString();
        ClientCallBackUtils owner = closeCallback(uuid, "native-owner");
        postCloseProgress(callback, zapid, "session-1", "ptk-browser", null, "running", true, 1);
        PtkZapSessionState state = sessionStateByZapId(extension).get(zapid);
        assertNotNull(state);

        ClientCallBackUtils sibling = closeCallback(uuid, "native-sibling");
        callback.browserClosing(sibling);
        extension.rememberWebDriverZapId(sibling.getWebDriver(), UUID.randomUUID().toString());
        callback.browserClosing(sibling);
        assertNull(state.closeRequest());
        assertEquals(state, sessionStateByZapId(extension).get(zapid));

        extension.rememberWebDriverZapId(owner.getWebDriver(), zapid);
        String terminalStatus = partial ? "engine_incomplete" : "completed";
        var executor = Executors.newSingleThreadExecutor();
        try {
            var closing = executor.submit(() -> callback.browserClosing(owner));
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
            while (state.closeRequest() == null && !closing.isDone() && System.nanoTime() < until) {
                Thread.sleep(5);
            }
            PtkCloseRequestState request = state.closeRequest();
            assertNotNull(request, "bound owner gets a close even with no readable page URL");
            assertEquals("owner_browser_close_requested", request.reason());
            assertEquals("ptk-browser", request.browserId());
            assertEquals(request.id(), callback.requestBoundOwnerClose(zapid, zapid));

            postCloseProgress(
                    callback,
                    zapid,
                    "session-1",
                    "ptk-browser",
                    request.id(),
                    terminalStatus,
                    false,
                    2);
            assertTrue(state.snapshot().terminalProgressSeen());
            assertTrue(request.acknowledged());
            assertFalse(state.snapshot().isV2ReadyForBrowserRelease());
            postCloseProgress(
                    callback,
                    zapid,
                    "foreign",
                    "ptk-browser",
                    request.id(),
                    terminalStatus,
                    true,
                    7);
            postCloseProgress(
                    callback, zapid, "session-1", "foreign", request.id(), terminalStatus, true, 7);
            postCloseProgress(
                    callback,
                    zapid,
                    "session-1",
                    "ptk-browser",
                    "wrong-close",
                    terminalStatus,
                    true,
                    7);
            postCloseProgress(
                    callback,
                    zapid,
                    "session-1",
                    "ptk-browser",
                    request.id(),
                    terminalStatus,
                    true,
                    1);
            postCloseProgress(
                    callback, zapid, "session-1", "ptk-browser", request.id(), "running", true, 7);
            assertFalse(state.snapshot().isV2ReadyForBrowserRelease());
            assertThrows(
                    TimeoutException.class,
                    () ->
                            closing.get(
                                    PtkCloseContract.BROWSER_CLOSE_WAIT_SLICE_MS + 300,
                                    TimeUnit.MILLISECONDS));

            postCloseProgress(
                    callback,
                    zapid,
                    "session-1",
                    "ptk-browser",
                    request.id(),
                    terminalStatus,
                    true,
                    3);
            closing.get(6, TimeUnit.SECONDS);
            assertTrue(state.snapshot().isV2ReadyForBrowserRelease());
            assertEquals(!partial, state.snapshot().isV2ReleaseClean());
            assertNull(sessionStateByZapId(extension).get(zapid));
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void expiredOwnerCloseReleasesWithAnUnsettledPublisher() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        ExtensionPtk.CallBackImplementor callback = extension.new CallBackImplementor();
        UUID uuid = UUID.randomUUID();
        String zapid = uuid.toString();
        ClientCallBackUtils owner = closeCallback(uuid, "native-owner");
        extension.rememberWebDriverZapId(owner.getWebDriver(), zapid);
        postCloseProgress(callback, zapid, "session-1", "ptk-browser", null, "running", true, 1);
        PtkZapSessionState state = sessionStateByZapId(extension).get(zapid);
        String request = callback.requestBoundOwnerClose(zapid, zapid);
        assertNotNull(request);
        postCloseProgress(
                callback, zapid, "session-1", "ptk-browser", request, "completed", false, 2);

        callback.browserClosing(
                owner,
                System.currentTimeMillis() - PtkCloseContract.BROWSER_CLOSE_MAX_WALL_CLOCK_MS);

        assertNull(sessionStateByZapId(extension).get(zapid));
        assertFalse(state.snapshot().isV2ReadyForBrowserRelease());
        assertTrue(state.snapshot().isV2ReleaseIncomplete());
    }

    private static ClientCallBackUtils closeCallback(UUID zapid, String webDriverSession) {
        RemoteWebDriver driver =
                new RemoteWebDriver() {
                    @Override
                    public SessionId getSessionId() {
                        return new SessionId(webDriverSession);
                    }

                    @Override
                    public String getCurrentUrl() {
                        throw new IllegalStateException("closing page unavailable");
                    }

                    @Override
                    public Set<String> getWindowHandles() {
                        return Set.of();
                    }
                };
        return new ClientCallBackUtils(
                new SeleniumScriptUtils(
                        driver, HttpSender.SPIDER_INITIATOR, "edge-headless", "", 0),
                zapid);
    }

    private static void postCloseProgress(
            ExtensionPtk.CallBackImplementor callback,
            String zapid,
            String sessionId,
            String browserid,
            String requestId,
            String status,
            boolean drained,
            int activitySeq)
            throws Exception {
        boolean terminal = !"running".equals(status);
        Map<String, Object> progress =
                new LinkedHashMap<>(
                        Map.of(
                                "contractVersion",
                                2,
                                "zapid",
                                zapid,
                                "sessionId",
                                sessionId,
                                "browserid",
                                browserid,
                                "progress",
                                terminal ? 100 : 99,
                                "status",
                                status,
                                "activitySeq",
                                activitySeq,
                                "publisher",
                                Map.of("drained", drained),
                                "safeToClose",
                                terminal && drained));
        if (requestId != null) {
            progress.put("closeRequestId", requestId);
            progress.put("closeRequestAck", true);
        }
        if (terminal) {
            progress.put("completionStatus", status);
            progress.put(
                    "releaseStatus",
                    drained && "completed".equals(status) ? "clean" : "incomplete");
        }
        HttpMessage message = new HttpMessage();
        message.getRequestHeader().setURI(new URI("https://zap/test/ptk/progress", true));
        message.getRequestHeader().setMethod("POST");
        message.getRequestBody().setBody(new com.google.gson.Gson().toJson(progress));
        callback.handleCallBack(message, null);
        assertEquals(
                "OK",
                com.google.gson.JsonParser.parseString(message.getResponseBody().toString())
                        .getAsJsonObject()
                        .get("result")
                        .getAsString());
    }

    @Test
    void localNonParticipantCloseDecisionDoesNotRepresentSessionTerminalState() {
        Map<String, Object> closeDecision = new LinkedHashMap<>();
        closeDecision.put("decision", "not_applicable");
        closeDecision.put("scanState", "callback");
        closeDecision.put("reason", "automation_disabled");

        assertEquals(
                true, PtkCloseContract.isBrowserLocalNonParticipantCloseDecision(closeDecision));
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 99, "running"));

        closeDecision.put("reason", "manual_mode");
        assertEquals(
                true, PtkCloseContract.isBrowserLocalNonParticipantCloseDecision(closeDecision));
        assertEquals(
                false,
                PtkCloseContract.canAcceptCloseDecisionSafeToClose(closeDecision, 99, "running"));

        closeDecision.put("decision", "wait");
        assertEquals(
                false, PtkCloseContract.isBrowserLocalNonParticipantCloseDecision(closeDecision));
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

    @Test
    void zapHistorySeedScopeStaysOnSameOriginAndDirectory() {
        String target = "https://example.test/dom/index.html";

        assertEquals("/dom/", PtkUrlUtils.deriveSameDirectoryPathScope(target));
        assertEquals(
                true,
                PtkUrlUtils.isSameOriginAndPathScoped(
                        target,
                        "https://example.test/dom/toxicdom/external/localStorage/array/eval"));
        assertEquals(
                "https://example.test/dom/toxicdom/external/localStorage/array/eval?q=1",
                PtkUrlUtils.normalizeHttpUrlWithoutFragment(
                        "https://example.test/dom/toxicdom/external/localStorage/array/eval?q=1#x"));
        assertEquals(
                false,
                PtkUrlUtils.isSameOriginAndPathScoped(
                        target, "https://example.test/angular/index.html"));
        assertEquals(
                false,
                PtkUrlUtils.isSameOriginAndPathScoped(
                        target, "https://other.example.test/dom/index.html"));
        assertNull(PtkUrlUtils.normalizeHttpUrlWithoutFragment("https://zap/zapCallBackUrl/1"));
    }

    @Test
    void zapHistorySeedScopeTreatsImplicitAndExplicitDefaultPortsAsSameOrigin() {
        assertEquals(
                true,
                PtkUrlUtils.isSameOriginAndPathScoped(
                        "https://example.test/dom/index.html",
                        "https://example.test:443/dom/location/hash/eval"));
        assertEquals(
                true,
                PtkUrlUtils.isSameOriginAndPathScoped(
                        "http://example.test:80/dom/index.html",
                        "http://example.test/dom/location/hash/eval"));
        assertEquals(
                false,
                PtkUrlUtils.isSameOriginAndPathScoped(
                        "https://example.test/dom/index.html",
                        "https://example.test:444/dom/location/hash/eval"));
        assertEquals(
                false,
                PtkUrlUtils.isSameOriginAndPathScoped(
                        "https://example.test/dom/index.html", "file:///dom/location/hash/eval"));
    }

    @Test
    void zapHistorySeedCandidateFilteringKeepsOnlyScopedHttpUrls() {
        List<String> urls =
                ExtensionPtk.collectZapHistorySeedUrlsFromCandidates(
                        "https://example.test/dom/index.html",
                        10,
                        List.of(
                                "https://example.test/dom/location/hash/eval#fragment",
                                "https://example.test/dom/location/hash/eval",
                                "https://example.test:443/dom/location/search/eval",
                                "https://example.test/angular/index.html",
                                "https://zap/zapCallBackUrl/1",
                                "https://other.example.test/dom/location/hash/eval"),
                        List.of());

        assertEquals(
                List.of(
                        "https://example.test/dom/index.html",
                        "https://example.test/dom/location/hash/eval",
                        "https://example.test:443/dom/location/search/eval"),
                urls);
    }

    private static Map<String, Object> progressPayload(long timestampMs, int executed) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("planned", 16);
        details.put("executed", executed);
        details.put("remaining", 16 - executed);
        details.put("heartbeatCount", timestampMs);
        details.put("lastPostAt", timestampMs);

        Map<String, Object> dast = new LinkedHashMap<>();
        dast.put("status", "running");
        dast.put("progress", 35);
        dast.put("details", details);

        Map<String, Object> engines = new LinkedHashMap<>();
        engines.put("DAST", dast);

        Map<String, Object> publisher = new LinkedHashMap<>();
        publisher.put("pendingFindings", 1);
        publisher.put("inFlightBatches", 0);
        publisher.put("drained", false);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sessionId", "session-1");
        payload.put("status", "running");
        payload.put("progress", 35);
        payload.put("timestamp", timestampMs);
        payload.put("elapsedMs", timestampMs);
        payload.put("lastPostAt", timestampMs);
        payload.put("heartbeatCount", timestampMs);
        payload.put("publisher", publisher);
        payload.put("engines", engines);
        return payload;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, PtkZapSessionState> sessionStateByZapId(ExtensionPtk extension)
            throws Exception {
        Field field = ExtensionPtk.class.getDeclaredField("sessionStateByZapId");
        field.setAccessible(true);
        return (Map<String, PtkZapSessionState>) field.get(extension);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> closeRequestIdByZapId(ExtensionPtk extension)
            throws Exception {
        Field field = ExtensionPtk.class.getDeclaredField("closeRequestIdByZapId");
        field.setAccessible(true);
        return (Map<String, String>) field.get(extension);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> browserIdByZapId(ExtensionPtk extension) throws Exception {
        Field field = ExtensionPtk.class.getDeclaredField("browserIdByZapId");
        field.setAccessible(true);
        return (Map<String, String>) field.get(extension);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> invokeControlPoll(
            ExtensionPtk extension, Map<String, Object> payload) throws Exception {
        ExtensionPtk.CallBackImplementor callback = extension.new CallBackImplementor();
        Method method =
                callback.getClass().getDeclaredMethod("buildControlPollResponse", Map.class);
        method.setAccessible(true);
        return (Map<String, Object>) method.invoke(callback, payload);
    }

    @Test
    void normalClosedOwnerRetainsActualCallbackAck3AndLegacyRetrySemantics() throws Exception {
        for (boolean v3 : List.of(true, false)) {
            try (var receiver = new PtkIastOfflineReceiver()) {
                var batch = PtkIastV3ContractTest.fixture();
                if (!v3) {
                    batch.addProperty("schema", "ptk-zap-iast-finding-v2");
                    PtkIastV3ContractTest.finding(batch).remove("flow");
                }
                String zapid = batch.get("zapid").getAsString();
                String sessionId = batch.getAsJsonObject("payload").get("sessionId").getAsString();
                ExtensionPtk extension = new ExtensionPtk();
                ExtensionPtk.CallBackImplementor callback = extension.new CallBackImplementor();
                HttpMessage message = new HttpMessage();
                message.getRequestHeader().setURI(new URI("https://zap/test/ptk/alert", true));
                message.getRequestHeader().setMethod("POST");
                message.getRequestBody().setBody(batch.toString());
                callback.handleCallBack(message, null);
                String original = message.getResponseBody().toString();
                assertEquals(
                        v3 ? 3 : 2,
                        com.google.gson.JsonParser.parseString(original)
                                .getAsJsonObject()
                                .get("contractVersion")
                                .getAsInt());
                var sessionIds = ExtensionPtk.class.getDeclaredField("sessionIdByZapId");
                sessionIds.setAccessible(true);
                @SuppressWarnings("unchecked")
                var sessions = (Map<String, String>) sessionIds.get(extension);
                sessions.put(zapid, sessionId);
                Method cleanup =
                        callback.getClass().getDeclaredMethod("clearTrackingState", String.class);
                cleanup.setAccessible(true);
                cleanup.invoke(callback, zapid);
                callback.handleCallBack(message, null);
                assertEquals(
                        original,
                        message.getResponseBody().toString(),
                        "normal closed owner must retain exact retired publication ACK");
                assertEquals(1, receiver.receive(batch.toString()).get("historyWrites").getAsInt());
            }
        }
    }
}
