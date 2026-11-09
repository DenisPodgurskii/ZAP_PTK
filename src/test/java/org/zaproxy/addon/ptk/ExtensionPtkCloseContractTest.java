package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.ImmutableCapabilities;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.remote.CommandPayload;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.remote.Response;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ClientCallBackImplementor.ClientCallBackContext;
import org.zaproxy.addon.client.ClientCallBackUtils;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Smoke-level tests for the PTK browser close contract. */
@SuppressWarnings("auxiliaryclass")
class ExtensionPtkCloseContractTest {

    private static final String OWNER_ZAP_ID = "00000000-0000-0000-0000-000000000111";
    private static final String OWNER_BROWSER = "firefox-headless";
    private static final String OWNER_SESSION = "offline-owner-session";

    @org.junit.jupiter.api.BeforeAll
    static void bindAndVerifyActualPrivateZapHomeBeforeModelAccess() throws java.io.IOException {
        String configured = System.getProperty("ptk.offline.zapHome");
        Path home =
                (configured == null || configured.isBlank()
                                ? java.nio.file.Files.createTempDirectory("ptk-offline-close-")
                                : Path.of(configured))
                        .toAbsolutePath()
                        .normalize();
        org.parosproxy.paros.Constant.setZapHome(home.toString());
        assertEquals(
                home,
                Path.of(org.parosproxy.paros.Constant.getZapHome()).toAbsolutePath().normalize(),
                "actual ZAP Constant home must match the private test home before Model/options access");
    }

    @Test
    void browserClosingBoundNativeOwnerRequestsStopWithoutReadingSelectedUrl() throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        assertEquals(OWNER_ZAP_ID, fixture.extension.getZapIdForWebDriver(fixture.driver));
        assertTrue(fixture.driver.commands.isEmpty(), "native binding must be local metadata");
        assertEquals(false, fixture.poll(Map.of()).get("closeRequested"));

        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            PtkCloseRequestState request = fixture.awaitRequest();
            assertEquals("owner_browser_close_requested", request.reason());
            assertEquals(OWNER_BROWSER, request.browserId());
            assertEquals(OWNER_SESSION, request.sessionId());
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
            Map<String, Object> delivered = fixture.poll(Map.of());
            assertEquals(true, delivered.get("closeRequested"));
            assertEquals(request.id(), delivered.get("closeRequestId"));
            assertEquals("owner_browser_close_requested", delivered.get("reason"));
            assertEquals("graceful_stop_and_drain", delivered.get("mode"));
            assertEquals(request.id(), fixture.poll(Map.of()).get("closeRequestId"));

            fixture.poll(Map.of("closeRequestId", request.id(), "closeRequestAck", true));
            assertTrue(fixture.state.snapshot().closeRequest().acknowledged());
            assertFalse(fixture.safe());
            fixture.postTerminal(request.id(), 2, false, false);
            assertFalse(fixture.safe(), "terminal ACK without final publisher drain is unsafe");
            assertTrue(closer.thread.isAlive());
            fixture.postTerminal(request.id(), 3, true, false);
            assertTrue(fixture.state.snapshot().isV2ReleaseClean());
            closer.awaitNaturalExit();
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
        }
    }

    @Test
    void browserClosingDelayedSessionRequiresCompleteContextAndKeepsOwnerReason() throws Exception {
        assertDelayedOwnerContext("sessionId");
    }

    @Test
    void browserClosingDelayedBrowserRequiresCompleteContextAndKeepsOwnerReason() throws Exception {
        assertDelayedOwnerContext("browserid");
    }

    @Test
    void browserClosingPartialSnapshotCannotEscapeWhileCallbackContextMapsAreIncomplete()
            throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture("sessionId");
        // Model the exact receiver interleaving: the synchronized snapshot is committed,
        // but its outer session/browser/progress maps have not all caught up yet.
        fixture.state.recordProgress(
                OWNER_BROWSER,
                OWNER_SESSION,
                100,
                "cancelled",
                "late Partial snapshot",
                true,
                2,
                false,
                2,
                1L);
        fixture.state.rememberReleaseState("engine_incomplete", "incomplete");
        fixture.state.rememberResolvedDastAssignment(OWNER_BROWSER, true);
        assertTrue(fixture.state.snapshot().safeToClose(), "exercise the raw no-request race");
        assertFalse(fixture.state.snapshot().isV2ReleaseClean());
        assertNull(extensionMap(fixture.extension, "sessionIdByZapId").get(OWNER_ZAP_ID));
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            awaitCondition(() -> closer.thread.getState() == Thread.State.TIMED_WAITING, 3000);
            assertTrue(closer.thread.isAlive(), "raw Partial snapshot must not finish owner close");
            assertNull(fixture.state.snapshot().closeRequest(), "never create mismatched context");
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
            // Complete the actual receiver/map update. Only now may the owner request exist.
            fixture.postTerminal(null, 3, false, true);
            PtkCloseRequestState request = fixture.awaitRequest();
            assertEquals("owner_browser_close_requested", request.reason());
            assertEquals(OWNER_SESSION, request.sessionId());
            assertEquals(OWNER_BROWSER, request.browserId());
            assertEquals(request.id(), fixture.poll(Map.of()).get("closeRequestId"));
            fixture.postTerminal(request.id(), 4, false, true);
            assertFalse(fixture.safe());
            assertTrue(closer.thread.isAlive());
            fixture.postTerminal(request.id(), 5, true, false);
            closer.awaitNaturalExit();
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
        }
    }

    private static void assertDelayedOwnerContext(String missingField) throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(missingField);
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            awaitCondition(() -> closer.thread.getState() == Thread.State.TIMED_WAITING, 3000);
            assertNull(fixture.state.snapshot().closeRequest(), "do not mint an unbound request");
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
            Map<String, Object> progress = ownerProgress(2);
            postProgress(fixture.extension, progress);
            PtkCloseRequestState request = fixture.awaitRequest();
            assertEquals("owner_browser_close_requested", request.reason());
            assertEquals(OWNER_SESSION, request.sessionId());
            assertEquals(OWNER_BROWSER, request.browserId());
            assertEquals(request.id(), fixture.poll(Map.of()).get("closeRequestId"));
            fixture.postTerminal(request.id(), 3, true, false);
            assertTrue(fixture.state.snapshot().isV2ReleaseClean());
            closer.awaitNaturalExit();
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
        }
    }

    @Test
    void browserClosingOwnerFollowUpNeverUsesRemoteCommandsOrAcceptsUndrainedPartial()
            throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        fixture.state.rememberResolvedDastAssignment(OWNER_BROWSER, true);
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            PtkCloseRequestState request = fixture.awaitRequest();
            fixture.postTerminal(request.id(), 2, false, true);
            assertTrue(fixture.state.snapshot().closeRequest().acknowledged());
            assertTrue(fixture.state.snapshot().terminalProgressSeen());
            assertFalse(fixture.safe());
            assertFalse(fixture.state.snapshot().isV2ReleaseClean());
            // Cross the actual follow-up-decision boundary, not only a reflected helper.
            long followUpAt = System.nanoTime() + TimeUnit.SECONDS.toNanos(17);
            while (System.nanoTime() < followUpAt) {
                assertTrue(closer.thread.isAlive(), "Partial/undrained must not end owner close");
                assertFalse(fixture.safe());
                assertEquals(request.id(), fixture.state.snapshot().closeRequest().id());
                assertEquals(
                        "owner_browser_close_requested",
                        fixture.state.snapshot().closeRequest().reason());
                assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
                Thread.sleep(25);
            }
            fixture.postTerminal(request.id(), 3, true, false);
            closer.awaitNaturalExit();
            assertTrue(fixture.state.snapshot().isV2ReleaseClean());
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
        }
    }

    @Test
    void browserClosingRejectsForeignNativeBindingAndCopiedCallbackUuid() throws Exception {
        for (String binding : List.of("00000000-0000-0000-0000-000000000222", "")) {
            OwnerCloseFixture fixture = new OwnerCloseFixture(null);
            extensionMap(fixture.extension, "zapIdByWebDriverSessionId").clear();
            if (!binding.isEmpty())
                fixture.extension.rememberWebDriverZapId(fixture.driver, binding);
            try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
                awaitCondition(() -> closer.thread.getState() == Thread.State.TIMED_WAITING, 3000);
                assertNull(fixture.state.snapshot().closeRequest());
                assertEquals(false, fixture.poll(Map.of()).get("closeRequested"));
                assertFalse(fixture.safe());
            }
            // A controlled interruption bounds this negative test; it is not clean-close proof.
        }
    }

    @Test
    void browserClosingOwnerRejectsForeignControlDeliveryAndAcknowledgements() throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            PtkCloseRequestState request = fixture.awaitRequest();
            for (Map<String, Object> wrong :
                    List.of(
                            Map.<String, Object>of("sessionId", "foreign-session"),
                            Map.<String, Object>of("browserid", "foreign-browser"),
                            Map.<String, Object>of(
                                    "zapid", "00000000-0000-0000-0000-000000000222"))) {
                Map<String, Object> ack = new LinkedHashMap<>(wrong);
                ack.put("closeRequestId", request.id());
                ack.put("closeRequestAck", true);
                assertEquals(false, fixture.poll(ack).get("closeRequested"));
                assertFalse(fixture.state.snapshot().closeRequest().acknowledged());
                assertFalse(fixture.safe());
            }
            fixture.poll(
                    Map.of("closeRequestId", request.id() + "-foreign", "closeRequestAck", true));
            assertFalse(fixture.state.snapshot().closeRequest().acknowledged());
            fixture.postTerminal(request.id(), 2, true, false);
            closer.awaitNaturalExit();
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
        }
    }

    @Test
    void browserClosingAlreadyTerminalOwnerDoesNotCreateStopOrReadUrl() throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        fixture.postTerminal(null, 2, true, false);
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            closer.awaitNaturalExit();
            assertNull(fixture.state.snapshot().closeRequest());
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void browserClosingManualConfigOnlyOwnerDoesNotStopOrReadUrl() throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        extensionMap(fixture.extension, "sessionIdByZapId").clear();
        extensionMap(fixture.extension, "scanProgress").put(OWNER_ZAP_ID, 0);
        extensionMap(fixture.extension, "scanStatus").put(OWNER_ZAP_ID, "callback");
        Field manual = ExtensionPtk.class.getDeclaredField("manualModeConfigZapIds");
        manual.setAccessible(true);
        ((Set<String>) manual.get(fixture.extension)).add(OWNER_ZAP_ID);
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            closer.awaitNaturalExit();
            assertNull(fixture.state.snapshot().closeRequest());
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
        }
    }

    @Test
    void browserClosingBoundOwnerNoSessionInterruptedDiagnosticExitDoesNotReadUrl()
            throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        extensionMap(fixture.extension, "sessionIdByZapId").clear();
        extensionMap(fixture.extension, "sessionStateByZapId").clear();
        extensionMap(fixture.extension, "scanProgress").clear();
        extensionMap(fixture.extension, "scanStatus").clear();
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            awaitCondition(() -> closer.thread.getState() == Thread.State.TIMED_WAITING, 3000);
            closer.thread.interrupt();
            // Only a bounded diagnostic exit. This is expressly not clean lifecycle proof.
            closer.thread.join(3500);
            assertFalse(closer.thread.isAlive());
            assertNull(closer.failure.get());
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
            assertFalse(closeRequestIdByZapId(fixture.extension).containsKey(OWNER_ZAP_ID));
        }
    }

    @Test
    void intentionallyDisabledStartupClosesWithoutProbeOrStartupWait() throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        for (String name :
                List.of(
                        "sessionIdByZapId",
                        "scanProgress",
                        "scanStatus",
                        "callbackFirstSeenAtMs",
                        "sessionStateByZapId")) {
            extensionMap(fixture.extension, name).clear();
        }
        PtkBrowserTaskState task =
                PtkBrowserTaskState.loaded(
                        OWNER_ZAP_ID, OWNER_BROWSER, "https://zap/zapCallBackUrl/test", 1L);
        Method receipt =
                PtkBrowserTaskState.class.getDeclaredMethod(
                        "rememberStartupDecision", boolean.class, boolean.class, boolean.class);
        receipt.setAccessible(true);
        receipt.invoke(task, true, true, true);
        extensionMap(fixture.extension, "browserTaskStateByZapIdAndBrowserId")
                .put(PtkBrowserTaskState.key(OWNER_ZAP_ID, OWNER_BROWSER), task);
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            closer.awaitNaturalExit();
            assertTrue(fixture.driver.commands.isEmpty(), fixture.driver.commands.toString());
            assertFalse(closeRequestIdByZapId(fixture.extension).containsKey(OWNER_ZAP_ID));
            assertEquals("startup_intentionally_disabled", task.toLogFields(2L).get("reason"));
        }
    }

    @Test
    void disabledReceiptRequiresAllLaunchPredicatesAndCannotBeRearmed() throws Exception {
        Method receipt =
                PtkBrowserTaskState.class.getDeclaredMethod(
                        "rememberStartupDecision", boolean.class, boolean.class, boolean.class);
        Method eligible = PtkBrowserTaskState.class.getDeclaredMethod("isStartupNonParticipant");
        Method invalidate = PtkBrowserTaskState.class.getDeclaredMethod("rememberParticipation");
        receipt.setAccessible(true);
        eligible.setAccessible(true);
        invalidate.setAccessible(true);
        for (int bits = 0; bits < 8; bits++) {
            PtkBrowserTaskState task =
                    PtkBrowserTaskState.loaded(OWNER_ZAP_ID, OWNER_BROWSER, "", 1);
            receipt.invoke(task, (bits & 1) != 0, (bits & 2) != 0, (bits & 4) != 0);
            assertEquals(bits == 7, eligible.invoke(task), "launch predicate " + bits);
            invalidate.invoke(task);
            receipt.invoke(task, true, true, true);
            assertEquals(false, eligible.invoke(task), "participation must be permanent");
        }
    }

    @Test
    void startupNonParticipantReceiptRejectsForeignOwnerAndLaterAdmission() throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        for (String name :
                List.of(
                        "sessionIdByZapId",
                        "scanProgress",
                        "scanStatus",
                        "sessionStateByZapId",
                        "callbackFirstSeenAtMs")) extensionMap(fixture.extension, name).clear();
        PtkBrowserTaskState task = PtkBrowserTaskState.loaded(OWNER_ZAP_ID, OWNER_BROWSER, "", 1);
        task.rememberStartupDecision(true, true, true);
        extensionMap(fixture.extension, "browserTaskStateByZapIdAndBrowserId")
                .put(PtkBrowserTaskState.key(OWNER_ZAP_ID, OWNER_BROWSER), task);
        ExtensionPtk.CallBackImplementor callback = fixture.extension.new CallBackImplementor();
        Method eligible =
                callback.getClass()
                        .getDeclaredMethod(
                                "isIntentionalStartupNonParticipantClose",
                                ClientCallBackUtils.class,
                                String.class);
        eligible.setAccessible(true);
        ClientCallBackUtils owned =
                new ClientCallBackUtils(
                        new SeleniumScriptUtils(
                                fixture.driver, 0, OWNER_BROWSER, "offline.invalid", 0),
                        UUID.fromString(OWNER_ZAP_ID));
        assertEquals(true, eligible.invoke(callback, owned, OWNER_ZAP_ID));
        ClientCallBackUtils foreign =
                new ClientCallBackUtils(
                        new SeleniumScriptUtils(
                                new RejectingOwnerDriver(), 0, OWNER_BROWSER, "offline.invalid", 0),
                        UUID.fromString(OWNER_ZAP_ID));
        assertEquals(false, eligible.invoke(callback, foreign, OWNER_ZAP_ID));
        ClientCallBackUtils foreignBrowser =
                new ClientCallBackUtils(
                        new SeleniumScriptUtils(fixture.driver, 0, "foreign", "offline.invalid", 0),
                        UUID.fromString(OWNER_ZAP_ID));
        assertEquals(false, eligible.invoke(callback, foreignBrowser, OWNER_ZAP_ID));
        extensionMap(fixture.extension, "browserIdByZapId").put(OWNER_ZAP_ID, "foreign");
        assertEquals(false, eligible.invoke(callback, owned, OWNER_ZAP_ID));
        extensionMap(fixture.extension, "browserIdByZapId").put(OWNER_ZAP_ID, OWNER_BROWSER);
        postProgress(fixture.extension, ownerProgress(2));
        assertFalse(task.isStartupNonParticipant());
        assertEquals(false, eligible.invoke(callback, owned, OWNER_ZAP_ID));
        assertTrue(fixture.driver.commands.isEmpty());
    }

    @Test
    void explicitExtensionDisableIsNotMissingOrUnsupportedExtension() {
        var disabled =
                new org.zaproxy.zap.extension.selenium.BrowserExtension(Path.of("ptk-latest"));
        disabled.setEnabled(false);
        assertTrue(
                ExtensionPtk.isPtkExtensionExplicitlyDisabled(List.of(disabled), "edge-headless"));
        assertFalse(ExtensionPtk.isPtkExtensionExplicitlyDisabled(List.of(), "edge-headless"));
        assertFalse(ExtensionPtk.isPtkExtensionExplicitlyDisabled(List.of(disabled), "unknown"));
        assertFalse(ExtensionPtk.isPtkExtensionExplicitlyDisabled(List.of(disabled), "firefox"));
        var enabled =
                new org.zaproxy.zap.extension.selenium.BrowserExtension(Path.of("ptk-latest"));
        assertFalse(
                ExtensionPtk.isPtkExtensionExplicitlyDisabled(List.of(disabled, enabled), "edge"));
    }

    @Test
    void globalAutomationDisabledCannotOverrideEffectiveChildRuleParticipation() {
        var param = new org.zaproxy.addon.ptk.options.PtkParam();
        param.load(new org.zaproxy.zap.utils.ZapXmlConfiguration());
        param.setUseRecommendedDefaults(false);
        param.setAutomatedScanningEnabled(false);
        param.setActiveScanRuleEnabled(false);
        param.setEngineEnabled("IAST", false);
        param.setRuleEnabled("IAST", "m", "r", true);
        var definition =
                new Gson()
                        .fromJson(
                                "{\"engine\":\"IAST\",\"modules\":[{\"id\":\"m\",\"rules\":[{\"id\":\"r\"}]}]}",
                                org.zaproxy.addon.ptk.model.PtkModulesDefinition.class);
        var resources = new PtkResourcesLoader.LoadedPtkResources(null, definition, null, null);
        boolean empty = PtkConfigFilter.filter(resources, param).isEmpty();
        assertFalse(empty);
        PtkBrowserTaskState task = PtkBrowserTaskState.loaded(OWNER_ZAP_ID, OWNER_BROWSER, "", 1);
        task.rememberStartupDecision(!param.isZapAutomationEnabled(), true, empty);
        assertFalse(task.isStartupNonParticipant());
    }

    private static Map<String, Object> ownerProgress(int sequence) {
        Map<String, Object> progress = new LinkedHashMap<>();
        progress.put("zapid", OWNER_ZAP_ID);
        progress.put("browserid", OWNER_BROWSER);
        progress.put("sessionId", OWNER_SESSION);
        progress.put("contractVersion", 2);
        progress.put("activitySeq", sequence);
        progress.put("status", "running");
        progress.put("progress", 50);
        progress.put(
                "publisher", Map.of("drained", false, "pendingFindings", 1, "inFlightBatches", 0));
        progress.put("engines", Map.of("DAST", Map.of("status", "running", "progress", 50)));
        return progress;
    }

    @Test
    void nonparticipantCloseClaimExcludesConcurrentProgressBeforeAnyOwnerMutation()
            throws Exception {
        OwnerCloseFixture fixture = disabledStartupFixture();
        var gate = new CloseEligibilityGate();
        Field alerts = ExtensionPtk.class.getDeclaredField("alertsRaisedByZapId");
        alerts.setAccessible(true);
        alerts.set(fixture.extension, gate);
        AtomicBoolean callbackAdmitted = new AtomicBoolean();
        AtomicReference<Throwable> callbackFailure = new AtomicReference<>();
        Thread callback =
                new Thread(
                        () -> {
                            try {
                                postProgress(fixture.extension, ownerProgress(2));
                                callbackAdmitted.set(
                                        extensionMap(fixture.extension, "scanProgress")
                                                .containsKey(OWNER_ZAP_ID));
                            } catch (Throwable failure) {
                                callbackFailure.set(failure);
                            }
                        },
                        "ptk-racing-progress");
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            assertTrue(gate.reached.await(3, TimeUnit.SECONDS));
            callback.start();
            awaitCondition(
                    () -> !callback.isAlive() || callback.getState() == Thread.State.BLOCKED, 3000);
            gate.release.countDown();
            closer.awaitNaturalExit();
            callback.join(3500);
            assertFalse(callback.isAlive());
            assertNull(callbackFailure.get());
            assertFalse(
                    callbackAdmitted.get(), "callback must not admit then be erased by fast close");
            assertFalse(
                    extensionMap(fixture.extension, "sessionStateByZapId")
                            .containsKey(OWNER_ZAP_ID));
            assertFalse(extensionMap(fixture.extension, "scanProgress").containsKey(OWNER_ZAP_ID));
            assertTrue(fixture.driver.commands.isEmpty());
        } finally {
            gate.release.countDown();
            callback.join(3500);
            assertFalse(callback.isAlive(), "owned racing callback leaked");
        }
    }

    @Test
    void progressAdmissionWinsBeforeCloseClaimAndRetainsNormalOwnerDrain() throws Exception {
        OwnerCloseFixture fixture = disabledStartupFixture();
        postProgress(fixture.extension, ownerProgress(2));
        PtkZapSessionState admitted = sessionStateByZapId(fixture.extension).get(OWNER_ZAP_ID);
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            awaitCondition(() -> admitted.snapshot().closeRequest() != null, 3500);
            PtkCloseRequestState request = admitted.snapshot().closeRequest();
            fixture.poll(Map.of("closeRequestId", request.id(), "closeRequestAck", true));
            fixture.postTerminal(request.id(), 3, false, false);
            assertTrue(closer.thread.isAlive());
            fixture.postTerminal(request.id(), 4, true, false);
            closer.awaitNaturalExit();
            assertTrue(fixture.driver.commands.isEmpty());
        }
    }

    @Test
    void claimedNonparticipantRejectsEveryCallbackRouteBeforeAndAfterCleanup() throws Exception {
        OwnerCloseFixture fixture = disabledStartupFixture();
        ExtensionPtk.CallBackImplementor callback = fixture.extension.new CallBackImplementor();
        Method claim =
                callback.getClass()
                        .getDeclaredMethod(
                                "claimIntentionalStartupNonParticipantClose",
                                ClientCallBackUtils.class,
                                String.class);
        claim.setAccessible(true);
        ClientCallBackUtils owned =
                new ClientCallBackUtils(
                        new SeleniumScriptUtils(
                                fixture.driver, 0, OWNER_BROWSER, "offline.invalid", 0),
                        UUID.fromString(OWNER_ZAP_ID));
        assertEquals(true, claim.invoke(callback, owned, OWNER_ZAP_ID));
        Method cleanup = callback.getClass().getDeclaredMethod("clearTrackingState", String.class);
        cleanup.setAccessible(true);
        for (int phase = 0; phase < 2; phase++) {
            for (String route :
                    List.of("config", "browser-capture", "alert", "progress", "control")) {
                HttpMessage message = new HttpMessage();
                message.getRequestHeader()
                        .setURI(new URI("https://zap/zapCallBackUrl/owned/ptk/" + route, true));
                message.getRequestHeader().setMethod("POST");
                Map<String, Object> payload = new LinkedHashMap<>(ownerProgress(2));
                payload.put("version", 1);
                payload.put("captureId", "capture-retired");
                payload.put("action", "prepare");
                message.getRequestBody().setBody(new Gson().toJson(payload));
                callback.handleCallBack(
                        message, new ClientCallBackContext(HttpSender.SPIDER_INITIATOR));
                for (String name :
                        List.of(
                                "sessionStateByZapId",
                                "sessionIdByZapId",
                                "scanProgress",
                                "callbackFirstSeenAtMs",
                                "configServedAtMsByZapId",
                                "alertsRaisedByZapId")) {
                    assertFalse(
                            extensionMap(fixture.extension, name).containsKey(OWNER_ZAP_ID),
                            route + " recreated " + name + " phase " + phase);
                }
            }
            cleanup.invoke(callback, OWNER_ZAP_ID);
        }
        assertTrue(fixture.driver.commands.isEmpty());
    }

    @Test
    void callbackAdmissionBeforeNativeTaskCannotBeForgottenAtTaskCreation() throws Exception {
        OwnerCloseFixture fixture = disabledStartupFixture();
        extensionMap(fixture.extension, "browserTaskStateByZapIdAndBrowserId").clear();
        postProgress(fixture.extension, ownerProgress(2));
        assertTrue(
                extensionMap(fixture.extension, "callbackFirstSeenAtMs").containsKey(OWNER_ZAP_ID));
        // Even before delayed owner maps become visible, admission itself is permanent.
        for (String name : List.of("scanProgress", "sessionStateByZapId", "sessionIdByZapId")) {
            extensionMap(fixture.extension, name).clear();
        }
        PtkBrowserTaskState task = PtkBrowserTaskState.loaded(OWNER_ZAP_ID, OWNER_BROWSER, "", 1L);
        task.rememberStartupDecision(true, true, true);
        extensionMap(fixture.extension, "browserTaskStateByZapIdAndBrowserId")
                .put(PtkBrowserTaskState.key(OWNER_ZAP_ID, OWNER_BROWSER), task);
        ExtensionPtk.CallBackImplementor callback = fixture.extension.new CallBackImplementor();
        Method claim =
                callback.getClass()
                        .getDeclaredMethod(
                                "claimIntentionalStartupNonParticipantClose",
                                ClientCallBackUtils.class,
                                String.class);
        claim.setAccessible(true);
        ClientCallBackUtils owned =
                new ClientCallBackUtils(
                        new SeleniumScriptUtils(
                                fixture.driver, 0, OWNER_BROWSER, "offline.invalid", 0),
                        UUID.fromString(OWNER_ZAP_ID));
        assertEquals(false, claim.invoke(callback, owned, OWNER_ZAP_ID));
        assertTrue(fixture.driver.commands.isEmpty());
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
                extensionMap(extension, "sessionIdByZapId").put(zapid, sessionId);
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

    @Test
    void claimedTaskLifetimeAndCardinalityAreCoupledToExistingClosedCache() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        Map<String, Object> closed = extensionMap(extension, "closedZapIds");
        Map<String, Object> tasks = extensionMap(extension, "browserTaskStateByZapIdAndBrowserId");
        long now = System.currentTimeMillis();
        for (int i = 0; i < PtkCloseContract.CLOSED_ZAPID_MAX_ENTRIES + 1; i++) {
            String id = "closed-" + i;
            PtkBrowserTaskState task = PtkBrowserTaskState.loaded(id, "edge", "", 1L);
            task.rememberStartupDecision(true, true, true);
            assertTrue(task.claimNonParticipantClose());
            tasks.put(PtkBrowserTaskState.key(id, "edge"), task);
            closed.put(id, now - 2000 + i);
        }
        PtkCloseContract.pruneClosedZapIds(castClosedMap(closed), now);
        PtkBrowserTaskState live = PtkBrowserTaskState.loaded("live", "edge", "", 1L);
        tasks.put(PtkBrowserTaskState.key("live", "edge"), live);
        Method prune =
                extension.new CallBackImplementor()
                        .getClass()
                        .getDeclaredMethod("pruneClaimedNonParticipantTasks", long.class);
        prune.setAccessible(true);
        ExtensionPtk.CallBackImplementor callback = extension.new CallBackImplementor();
        prune.invoke(callback, now);
        assertEquals(PtkCloseContract.CLOSED_ZAPID_MAX_ENTRIES, closed.size());
        assertEquals(PtkCloseContract.CLOSED_ZAPID_MAX_ENTRIES + 1, tasks.size());
        assertFalse(tasks.containsKey(PtkBrowserTaskState.key("closed-0", "edge")));
        prune.invoke(callback, now + PtkCloseContract.CLOSED_ZAPID_RETENTION_MS + 1);
        assertEquals(Map.of(PtkBrowserTaskState.key("live", "edge"), live), tasks);
        assertTrue(closed.isEmpty());
    }

    @Test
    void crossOwnerPruningCannotObserveHalfPublishedIntentionalCloseReceipt() throws Exception {
        OwnerCloseFixture fixture = disabledStartupFixture();
        var gate = new RetirementPublicationGate();
        Field closed = ExtensionPtk.class.getDeclaredField("closedZapIds");
        closed.setAccessible(true);
        closed.set(fixture.extension, gate);
        ExtensionPtk.CallBackImplementor callback = fixture.extension.new CallBackImplementor();
        Method admit =
                callback.getClass().getDeclaredMethod("admitBrowserParticipation", String.class);
        admit.setAccessible(true);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread other =
                new Thread(
                        () -> {
                            try {
                                assertEquals(true, admit.invoke(callback, "other-owner"));
                            } catch (Throwable thrown) {
                                failure.set(thrown);
                            }
                        },
                        "ptk-cross-owner-prune");
        try (ClosingThread closer = fixture.startClosing(OWNER_ZAP_ID)) {
            assertTrue(gate.reached.await(3, TimeUnit.SECONDS));
            other.start();
            awaitCondition(
                    () -> !other.isAlive() || other.getState() == Thread.State.BLOCKED, 3000);
            gate.release.countDown();
            closer.awaitNaturalExit();
            other.join(3500);
            assertFalse(other.isAlive());
            assertNull(failure.get());
            HttpMessage late = new HttpMessage();
            late.getRequestHeader().setURI(new URI("https://zap/test/ptk/alert", true));
            late.getRequestHeader().setMethod("POST");
            late.getRequestBody()
                    .setBody(
                            new Gson()
                                    .toJson(
                                            Map.of(
                                                    "zapid",
                                                    OWNER_ZAP_ID,
                                                    "browserid",
                                                    OWNER_BROWSER)));
            callback.handleCallBack(late, null);
            assertFalse(
                    extensionMap(fixture.extension, "sessionStateByZapId")
                            .containsKey(OWNER_ZAP_ID),
                    "cross-owner prune must not lose the exact closed-owner receipt");
            assertEquals(
                    "FAIL",
                    new Gson()
                            .fromJson(late.getResponseBody().toString(), Map.class)
                            .get("result"));
        } finally {
            gate.release.countDown();
            other.join(3500);
            assertFalse(other.isAlive(), "owned cross-owner observer leaked");
        }
        assertTrue(fixture.driver.commands.isEmpty());
    }

    @SuppressWarnings("serial")
    private static final class RetirementPublicationGate extends ConcurrentHashMap<String, Long> {
        final java.util.concurrent.CountDownLatch reached =
                new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.CountDownLatch release =
                new java.util.concurrent.CountDownLatch(1);

        @Override
        public Long put(String key, Long value) {
            if (OWNER_ZAP_ID.equals(key)
                    && Thread.currentThread().getName().equals("ptk-owner-close-contract")) {
                reached.countDown();
                try {
                    if (!release.await(5, TimeUnit.SECONDS))
                        throw new AssertionError("unreleased publication gate");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(e);
                }
            }
            return super.put(key, value);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Long> castClosedMap(Map<String, Object> map) {
        return (Map<String, Long>) (Map<?, ?>) map;
    }

    private static OwnerCloseFixture disabledStartupFixture() throws Exception {
        OwnerCloseFixture fixture = new OwnerCloseFixture(null);
        for (String name :
                List.of(
                        "sessionIdByZapId",
                        "scanProgress",
                        "scanStatus",
                        "callbackFirstSeenAtMs",
                        "sessionStateByZapId")) {
            extensionMap(fixture.extension, name).clear();
        }
        PtkBrowserTaskState task = PtkBrowserTaskState.loaded(OWNER_ZAP_ID, OWNER_BROWSER, "", 1L);
        task.rememberStartupDecision(true, true, true);
        extensionMap(fixture.extension, "browserTaskStateByZapIdAndBrowserId")
                .put(PtkBrowserTaskState.key(OWNER_ZAP_ID, OWNER_BROWSER), task);
        return fixture;
    }

    @SuppressWarnings("serial")
    private static final class CloseEligibilityGate extends ConcurrentHashMap<String, Integer> {
        final java.util.concurrent.CountDownLatch reached =
                new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.CountDownLatch release =
                new java.util.concurrent.CountDownLatch(1);

        @Override
        public Integer getOrDefault(Object key, Integer defaultValue) {
            Integer observed = super.getOrDefault(key, defaultValue);
            if (Thread.currentThread().getName().equals("ptk-owner-close-contract")) {
                reached.countDown();
                try {
                    if (!release.await(5, TimeUnit.SECONDS))
                        throw new AssertionError("unreleased close gate");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(e);
                }
            }
            return observed;
        }
    }

    private static final class OwnerCloseFixture {
        final ExtensionPtk extension = new ExtensionPtk();
        final RejectingOwnerDriver driver = new RejectingOwnerDriver();
        final PtkZapSessionState state;

        OwnerCloseFixture(String missingField) throws Exception {
            Map<String, Object> progress = ownerProgress(1);
            if (missingField != null) progress.remove(missingField);
            postProgress(extension, progress);
            state = sessionStateByZapId(extension).get(OWNER_ZAP_ID);
            state.rememberNativeBrowserFamily("firefox");
            state.recordProgress(
                    "browserid".equals(missingField) ? null : OWNER_BROWSER,
                    "sessionId".equals(missingField) ? null : OWNER_SESSION,
                    50,
                    "running",
                    "stale offline owner",
                    false,
                    2,
                    false,
                    1,
                    1L);
            extensionMap(extension, "lastProgressChangedAtMsByZapId").put(OWNER_ZAP_ID, 1L);
            extension.rememberWebDriverZapId(driver, OWNER_ZAP_ID);
            extensionMap(extension, "targetUrlByZapId")
                    .put(OWNER_ZAP_ID, "https://example.test/address/index.html");
        }

        ClosingThread startClosing(String callbackZapId) {
            ClientCallBackUtils utils =
                    new ClientCallBackUtils(
                            new SeleniumScriptUtils(driver, 0, OWNER_BROWSER, "offline.invalid", 0),
                            UUID.fromString(callbackZapId));
            return new ClosingThread(
                    () -> extension.new CallBackImplementor().browserClosing(utils));
        }

        PtkCloseRequestState awaitRequest() throws Exception {
            awaitCondition(() -> state.snapshot().closeRequest() != null, 3500);
            return state.snapshot().closeRequest();
        }

        Map<String, Object> poll(Map<String, Object> overrides) throws Exception {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("zapid", OWNER_ZAP_ID);
            payload.put("browserid", OWNER_BROWSER);
            payload.put("sessionId", OWNER_SESSION);
            payload.putAll(overrides);
            HttpMessage message = new HttpMessage();
            message.getRequestHeader().setURI(new URI("https://zap/test/ptk/control", true));
            message.getRequestHeader().setMethod("POST");
            message.getRequestBody().setBody(new Gson().toJson(payload));
            extension.new CallBackImplementor().handleCallBack(message, null);
            return decodeControlResponse(message);
        }

        @SuppressWarnings("unchecked")
        private static Map<String, Object> decodeControlResponse(HttpMessage message) {
            Map<String, Object> response =
                    new Gson().fromJson(message.getResponseBody().toString(), Map.class);
            assertEquals("OK", response.get("result"));
            return response;
        }

        boolean safe() throws Exception {
            ExtensionPtk.CallBackImplementor callback = extension.new CallBackImplementor();
            Method method = callback.getClass().getDeclaredMethod("isSafeToClose", String.class);
            method.setAccessible(true);
            return (boolean) method.invoke(callback, OWNER_ZAP_ID);
        }

        void postTerminal(String requestId, int sequence, boolean drained, boolean partial)
                throws Exception {
            Map<String, Object> payload = ownerProgress(sequence);
            payload.put("status", partial ? "cancelled" : "completed");
            payload.put("progress", 100);
            payload.put("terminalSeen", true);
            payload.put("safeToClose", false);
            payload.put("completionStatus", partial ? "engine_incomplete" : "completed");
            payload.put("releaseStatus", partial ? "incomplete" : "clean");
            payload.put(
                    "publisher",
                    Map.of(
                            "drained",
                            drained,
                            "pendingFindings",
                            drained ? 0 : 1,
                            "inFlightBatches",
                            drained ? 0 : 1));
            payload.put(
                    "engines",
                    Map.of(
                            "DAST",
                            Map.of(
                                    "status",
                                    partial ? "cancelled" : "completed",
                                    "progress",
                                    100,
                                    "completionStatus",
                                    partial ? "engine_incomplete" : "completed",
                                    "details",
                                    Map.of(
                                            "remaining",
                                            partial ? 1250 : 0,
                                            "taskQueue",
                                            partial ? 1156 : 0))));
            if (requestId != null) {
                payload.put("closeRequestId", requestId);
                payload.put("closeRequestAck", true);
            }
            postProgress(extension, payload);
        }
    }

    /** No constructor starts a session; every remote-command entry point rejects transport. */
    private static final class RejectingOwnerDriver extends RemoteWebDriver {
        final List<String> commands = new CopyOnWriteArrayList<>();

        RejectingOwnerDriver() {
            super();
            setSessionId("offline-native-" + UUID.randomUUID());
            capabilities = new ImmutableCapabilities("browserName", "firefox");
            setCommandExecutor(
                    command -> {
                        throw new AssertionError("no transport permitted");
                    });
        }

        private Response reject(String command) {
            commands.add(command);
            throw new WebDriverException("offline rejecting remote command: " + command);
        }

        @Override
        protected Response execute(CommandPayload payload) {
            return reject(payload.getName());
        }

        @Override
        protected Response execute(String command, Map<String, ?> parameters) {
            return reject(command);
        }

        @Override
        protected Response execute(String command) {
            return reject(command);
        }
    }

    private static final class ClosingThread implements AutoCloseable {
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final Thread thread;

        ClosingThread(Runnable callback) {
            thread =
                    new Thread(
                            () -> {
                                try {
                                    callback.run();
                                } catch (Throwable thrown) {
                                    failure.set(thrown);
                                }
                            },
                            "ptk-owner-close-contract");
            thread.setDaemon(true);
            thread.start();
        }

        void awaitNaturalExit() throws Exception {
            thread.join(3500);
            assertFalse(
                    thread.isAlive(),
                    "close must finish from matched terminal/drain, not interruption");
            assertNull(failure.get());
        }

        @Override
        public void close() {
            if (thread.isAlive()) thread.interrupt();
            try {
                thread.join(2000);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new AssertionError(
                        "test cleanup interrupted before callback joined", interrupted);
            }
            assertFalse(thread.isAlive(), "owned callback thread leaked after bounded cleanup");
            assertNull(failure.get());
        }
    }

    private static void awaitCondition(BooleanSupplier condition, long timeoutMs) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue(
                condition.getAsBoolean(),
                "callback did not reach the expected state within budget");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> extensionMap(ExtensionPtk extension, String name)
            throws Exception {
        Field field = ExtensionPtk.class.getDeclaredField(name);
        field.setAccessible(true);
        return (Map<String, Object>) field.get(extension);
    }

    @Test
    void progressAndAlertsDoNotDependOnClientSpiderPrivateShutdownClock() throws Exception {
        // Inspect the compiled callback owner, not a source copy that might differ
        // from the tested add-on. Referencing this private field let otherwise idle
        // PTK progress keep rearming Client Spider indefinitely.
        try (var stream = ExtensionPtk.class.getResourceAsStream("ExtensionPtk.class")) {
            assertNotNull(stream);
            String compiled = new String(stream.readAllBytes(), StandardCharsets.ISO_8859_1);
            assertFalse(compiled.contains("lastEventReceivedtime"));
            assertFalse(compiled.contains("touchActiveClientSpidersForPtkActivity"));
        }
    }

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
    void ownerPartialTerminalWaitsForSameCallbackCleanupAndFinalPublisherProof() throws Exception {
        ExtensionPtk extension = requestedPartialOwner("edge-headless");
        Map<String, Object> first = partialCleanupProgress(11, null);
        postProgress(extension, first);

        PtkZapSessionState state = sessionStateByZapId(extension).get("zap-partial");
        assertTrue(state.snapshot().terminalProgressSeen());
        assertTrue(state.snapshot().publisherDrained());
        assertFalse(state.snapshot().isV2PhysicallySafeToClose());
        assertFalse(invokeSafeToClose(extension));

        postProgress(extension, partialCleanupProgress(12, "ptk_remote_cleanup_v1"));
        assertTrue(invokeSafeToClose(extension));
        assertTrue(state.snapshot().requestedPartialCleanupQualified());
        assertEquals("cancelled", state.snapshot().status());
        assertEquals("engine_incomplete", state.snapshot().completionStatus());
        assertEquals("incomplete", state.snapshot().releaseStatus());
        assertFalse(state.snapshot().isV2ReleaseClean());
        assertTrue(state.snapshot().isV2ReleaseIncomplete());
        // Same final observation is safe to receive more than once.
        postProgress(extension, partialCleanupProgress(12, "ptk_remote_cleanup_v1"));
        assertTrue(invokeSafeToClose(extension));
    }

    @Test
    void ownerPartialCannotUseCachedSafeBooleanOrTrustedRunnerShortcut() throws Exception {
        ExtensionPtk extension = requestedPartialOwner("edge-headless");
        postProgress(extension, partialCleanupProgress(11, null));
        Field safeField = ExtensionPtk.class.getDeclaredField("safeToCloseByZapId");
        safeField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Boolean> safe = (Map<String, Boolean>) safeField.get(extension);
        safe.put("zap-partial", true);
        assertFalse(invokeSafeToClose(extension));

        Map<String, Object> runner = new LinkedHashMap<>();
        runner.put("decision", "safe_to_close");
        runner.put("scanState", "cancelled");
        runner.put("contractVersion", 2);
        runner.put("trustedRunnerVerified", true);
        runner.put("trustedRunner", "ptk-zap-control-v1");
        runner.put("source", "webdriver_extension_runner");
        runner.put("terminalFinalized", true);
        runner.put("idleVerified", true);
        runner.put("completionStatus", "cancelled");
        runner.put("releaseStatus", "incomplete");
        runner.put("sessionId", "session-partial");
        runner.put("closeRequestId", "close-partial");
        runner.put("closeRequestAck", true);
        assertFalse(invokeCloseDecision(extension, runner));
        // An already-terminal label without the runner fields is not a bypass either.
        assertFalse(
                invokeCloseDecision(
                        extension,
                        Map.of(
                                "decision", "safe_to_close",
                                "scanState", "cancelled",
                                "reason", "already_terminal")));
    }

    @Test
    void ownerPartialRejectsForeignAndLowerSequenceReceiptWithoutChangingOwner() throws Exception {
        for (String key : List.of("sessionId", "browserid", "closeRequestId")) {
            ExtensionPtk extension = requestedPartialOwner("edge-headless");
            postProgress(extension, partialCleanupProgress(11, null));
            Map<String, Object> foreign = partialCleanupProgress(12, "ptk_remote_cleanup_v1");
            foreign.put(key, "foreign");
            postProgress(extension, foreign);
            PtkZapSessionSnapshot snapshot =
                    sessionStateByZapId(extension).get("zap-partial").snapshot();
            assertFalse(invokeSafeToClose(extension), key);
            assertEquals("session-partial", snapshot.sessionId());
            assertEquals("browser-partial", snapshot.browserId());
            assertEquals("close-partial", snapshot.closeRequest().id());
            // Rejected foreign progress cannot consume sequence12.
            postProgress(extension, partialCleanupProgress(12, "ptk_remote_cleanup_v1"));
            assertTrue(invokeSafeToClose(extension), key);
        }
        ExtensionPtk extension = requestedPartialOwner("edge-headless");
        postProgress(extension, partialCleanupProgress(12, null));
        postProgress(extension, partialCleanupProgress(11, "ptk_remote_cleanup_v1"));
        assertFalse(invokeSafeToClose(extension));
        // Nor can a lower-sequence false drain revoke a later valid receipt.
        postProgress(extension, partialCleanupProgress(13, "ptk_remote_cleanup_v1"));
        postProgress(extension, partialCleanupProgress(11, null));
        assertTrue(invokeSafeToClose(extension));
    }

    @Test
    void ownerPartialReceiptRequiresOneAcceptedTerminalAckAndPublisherObservation()
            throws Exception {
        for (int sequence : List.of(0, -1)) {
            ExtensionPtk extension = requestedPartialOwner("edge-headless");
            postProgress(extension, partialCleanupProgress(11, null));
            assertFalse(
                    PtkCloseContract.hasRequestedPartialCleanupEvidence(
                            sessionStateByZapId(extension).get("zap-partial").snapshot(),
                            partialCleanupProgress(sequence, "ptk_remote_cleanup_v1"),
                            "edge-headless"));
            postProgress(extension, partialCleanupProgress(sequence, "ptk_remote_cleanup_v1"));
            assertFalse(invokeSafeToClose(extension), "nonpositive activity sequence");
        }
        for (String missing :
                List.of(
                        "closeRequestId",
                        "closeRequestAck",
                        "safeToClose",
                        "activitySeq",
                        "publisher")) {
            ExtensionPtk extension = requestedPartialOwner("edge-headless");
            Map<String, Object> payload = partialCleanupProgress(11, "ptk_remote_cleanup_v1");
            payload.remove(missing);
            postProgress(extension, payload);
            assertFalse(invokeSafeToClose(extension), missing);
        }
        for (String key : List.of("pendingFindings", "inFlightBatches")) {
            for (Object nonzero : List.of(1, 0.5, "0")) {
                ExtensionPtk extension = requestedPartialOwner("edge-headless");
                Map<String, Object> payload = partialCleanupProgress(11, "ptk_remote_cleanup_v1");
                nested(payload, "publisher").put(key, nonzero);
                postProgress(extension, payload);
                assertFalse(invokeSafeToClose(extension), key + ":" + nonzero);
            }
        }
        ExtensionPtk extension = requestedPartialOwner("edge-headless");
        postProgress(extension, partialCleanupProgress(11, null));
        Map<String, Object> pending = partialCleanupProgress(12, "ptk_remote_cleanup_v1");
        nested(pending, "publisher").put("drained", false);
        postProgress(extension, pending);
        assertFalse(invokeSafeToClose(extension));
        // Do not combine that earlier marker with a later marker-free drained observation.
        postProgress(extension, partialCleanupProgress(13, null));
        assertFalse(invokeSafeToClose(extension));
        postProgress(extension, partialCleanupProgress(14, "ptk_remote_cleanup_v1"));
        assertTrue(invokeSafeToClose(extension));
    }

    @Test
    void ownerPartialReceiptRequiresNativeFamilyAndNoCleanupError() throws Exception {
        for (String family : List.of("edge-headless", "firefox-headless", "unknown")) {
            for (String token : List.of("ptk_remote_cleanup_v1", "ptk_local_cleanup_v1")) {
                ExtensionPtk extension = requestedPartialOwner(family);
                postProgress(extension, partialCleanupProgress(11, token));
                assertEquals(
                        (family.equals("edge-headless") && token.equals("ptk_remote_cleanup_v1"))
                                || (family.equals("firefox-headless")
                                        && token.equals("ptk_local_cleanup_v1")),
                        invokeSafeToClose(extension),
                        family + ":" + token);
            }
        }
        ExtensionPtk extension = requestedPartialOwner("edge-headless");
        Map<String, Object> error = partialCleanupProgress(11, "ptk_remote_cleanup_v1");
        nested(nested(nested(error, "engines"), "DAST"), "details")
                .put("error", "native_release_failed");
        postProgress(extension, error);
        assertFalse(invokeSafeToClose(extension));
    }

    @Test
    void ownerNormalCompletedCloseStillNeedsNoPartialToken() throws Exception {
        ExtensionPtk extension = requestedPartialOwner("edge-headless");
        Map<String, Object> completed = partialCleanupProgress(11, null);
        completed.put("status", "completed");
        completed.put("completionStatus", "completed");
        completed.put("releaseStatus", "clean");
        Map<String, Object> dast = nested(nested(completed, "engines"), "DAST");
        dast.put("status", "idle");
        dast.put("completionStatus", "completed");
        postProgress(extension, completed);
        assertTrue(invokeSafeToClose(extension));
        assertTrue(sessionStateByZapId(extension).get("zap-partial").snapshot().isV2ReleaseClean());
    }

    @Test
    void resolvedClientConfigPreservesIastSastOnlyPartialClose() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        extension.getParam().load(new ZapXmlConfiguration());
        Map<String, Object> config =
                postConfig(extension, "browser-partial", HttpSender.SPIDER_INITIATOR);
        assertTrue(nested(config, "dast").isEmpty());
        assertFalse(nested(config, "sast").isEmpty());
        assertFalse(nested(config, "iast").isEmpty());
        armRequestedPartialOwner(extension, "edge-headless");
        assertEquals(
                Boolean.FALSE,
                sessionStateByZapId(extension).get("zap-partial").snapshot().dastAssigned());

        Map<String, Object> partial = partialCleanupProgress(11, null);
        partial.put(
                "engines",
                Map.of(
                        "IAST",
                                Map.of(
                                        "status",
                                        "cancelled",
                                        "completionStatus",
                                        "engine_incomplete"),
                        "SAST",
                                Map.of(
                                        "status",
                                        "cancelled",
                                        "completionStatus",
                                        "engine_incomplete")));
        nested(partial, "publisher").put("drained", false);
        postProgress(extension, partial);
        assertFalse(invokeSafeToClose(extension));
        partial.put("activitySeq", 12);
        nested(partial, "publisher").put("drained", true);
        partial.put("safeToClose", false);
        postProgress(extension, partial);
        assertFalse(invokeSafeToClose(extension));
        partial.put("activitySeq", 13);
        partial.put("safeToClose", true);
        postProgress(extension, partial);
        assertTrue(invokeSafeToClose(extension));
        PtkZapSessionSnapshot snapshot =
                sessionStateByZapId(extension).get("zap-partial").snapshot();
        assertEquals("engine_incomplete", snapshot.completionStatus());
        assertFalse(snapshot.isV2ReleaseClean());
        assertTrue(snapshot.requestedPartialCleanupQualified());
        assertFalse(nested(partial, "engines").containsKey("DAST"));
    }

    @Test
    void resolvedDastConfigCannotBeDisabledByOmittedRuntimeEngineOrLaterConfig() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        extension.getParam().load(new ZapXmlConfiguration());
        Map<String, Object> active =
                postConfig(extension, "browser-partial", HttpSender.ACTIVE_SCANNER_INITIATOR);
        assertFalse(nested(active, "dast").isEmpty());
        assertEquals(
                Boolean.TRUE,
                sessionStateByZapId(extension).get("zap-partial").snapshot().dastAssigned());
        // This is another real server-resolved response, not a forged runtime omission.
        postConfig(extension, "browser-partial", HttpSender.SPIDER_INITIATOR);
        assertEquals(
                Boolean.TRUE,
                sessionStateByZapId(extension).get("zap-partial").snapshot().dastAssigned());
        assertTrue(postConfig(extension, "foreign-browser", HttpSender.SPIDER_INITIATOR).isEmpty());
        assertEquals(
                "browser-partial",
                sessionStateByZapId(extension).get("zap-partial").snapshot().browserId());
        armRequestedPartialOwner(extension, "edge-headless");
        Map<String, Object> omitted = partialCleanupProgress(11, null);
        omitted.put("engines", Map.of("SAST", Map.of("status", "idle")));
        postProgress(extension, omitted);
        assertFalse(invokeSafeToClose(extension));
        postProgress(extension, partialCleanupProgress(12, "ptk_remote_cleanup_v1"));
        assertTrue(invokeSafeToClose(extension));
    }

    @Test
    void unknownOrForeignConfigAssignmentDoesNotExemptNativeCleanup() throws Exception {
        assertNull(PtkCloseContract.resolvedDastAssignment(Map.of()));
        assertNull(PtkCloseContract.resolvedDastAssignment(Map.of("dast", "disabled")));
        assertNull(
                PtkCloseContract.resolvedDastAssignment(
                        Map.of("dast", Map.of("modules", List.of()))));
        assertEquals(
                Boolean.FALSE, PtkCloseContract.resolvedDastAssignment(Map.of("dast", Map.of())));
        ExtensionPtk extension = requestedPartialOwner("edge-headless");
        Map<String, Object> missing = partialCleanupProgress(11, null);
        missing.remove("engines");
        postProgress(extension, missing);
        assertNull(sessionStateByZapId(extension).get("zap-partial").snapshot().dastAssigned());
        assertFalse(invokeSafeToClose(extension));

        PtkZapSessionState state = new PtkZapSessionState("bound");
        state.rememberBrowserId("browser-one");
        state.rememberResolvedDastAssignment("foreign", false);
        assertNull(state.snapshot().dastAssigned());
        state.rememberResolvedDastAssignment("browser-one", false);
        assertEquals(Boolean.FALSE, state.snapshot().dastAssigned());
        state.rememberBrowserId("browser-two");
        assertNull(state.snapshot().dastAssigned());
        state.rememberResolvedDastAssignment("browser-two", false);
        assertNull(state.snapshot().dastAssigned());
    }

    @Test
    void ignoredNonterminalAckCannotCompletePriorTerminalPublisherDrain() throws Exception {
        ExtensionPtk extension = requestedPartialOwner("edge-headless");
        Map<String, Object> completed = partialCleanupProgress(11, null);
        completed.put("status", "completed");
        completed.put("completionStatus", "completed");
        completed.put("releaseStatus", "clean");
        nested(completed, "publisher").put("drained", false);
        postProgress(extension, completed);
        assertFalse(invokeSafeToClose(extension));

        Map<String, Object> ack = partialCleanupProgress(12, null);
        ack.put("status", "running");
        ack.put("progress", 99);
        ack.put("terminalSeen", false);
        ack.put("safeToClose", false);
        ack.remove("completionStatus");
        ack.remove("releaseStatus");
        postProgress(extension, ack);
        PtkZapSessionSnapshot snapshot =
                sessionStateByZapId(extension).get("zap-partial").snapshot();
        assertEquals("completed", snapshot.status());
        assertFalse(snapshot.publisherDrained());
        assertFalse(snapshot.isV2ReleaseClean());
        assertFalse(invokeSafeToClose(extension));

        completed.put("activitySeq", 13);
        nested(completed, "publisher").put("drained", true);
        postProgress(extension, completed);
        assertTrue(invokeSafeToClose(extension));
        assertTrue(sessionStateByZapId(extension).get("zap-partial").snapshot().isV2ReleaseClean());
    }

    @Test
    void controlPollDoesNotStopQuietRunningSession() throws Exception {
        for (int progress : List.of(99, 100)) {
            for (boolean publisherDrained : List.of(false, true)) {
                ExtensionPtk extension = new ExtensionPtk();
                PtkZapSessionState state = new PtkZapSessionState("zap-control-quiet");
                state.recordProgress(
                        "browser-1",
                        "session-1",
                        progress,
                        "running",
                        "quiet progress",
                        false,
                        2,
                        publisherDrained,
                        10,
                        1L);
                sessionStateByZapId(extension).put("zap-control-quiet", state);
                assertFalse(
                        PtkCloseContract.isActivityFresh(
                                state.snapshot().newestActivityAt(), System.currentTimeMillis()));

                // A crawler may admit more pages after arbitrarily quiet progress.
                // Repeated polling alone cannot authorize stopping its engines.
                for (int poll = 0; poll < 3; poll++) {
                    Map<String, Object> response =
                            invokeControlPoll(
                                    extension,
                                    Map.of(
                                            "zapid",
                                            "zap-control-quiet",
                                            "browserid",
                                            "browser-1",
                                            "sessionId",
                                            "session-1",
                                            "activitySeq",
                                            10));

                    assertEquals("OK", response.get("result"));
                    assertEquals(false, response.get("closeRequested"));
                    assertFalse(response.containsKey("closeRequestId"));
                    assertFalse(response.containsKey("mode"));
                    assertNull(state.snapshot().closeRequest());
                    assertFalse(closeRequestIdByZapId(extension).containsKey("zap-control-quiet"));
                    assertEquals("running", state.snapshot().status());
                    assertEquals(progress, state.snapshot().progress());
                    assertFalse(state.snapshot().terminalProgressSeen());
                    assertFalse(state.snapshot().safeToClose());
                    assertEquals(1L, state.snapshot().newestActivityAt());
                }
            }
        }
    }

    @Test
    void quietSessionAcceptsLaterPageProgressWithoutCloseRequest() throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        PtkZapSessionState state = new PtkZapSessionState("zap-control-later");
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
        sessionStateByZapId(extension).put("zap-control-later", state);

        Map<String, Object> poll =
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid",
                                "zap-control-later",
                                "browserid",
                                "browser-1",
                                "sessionId",
                                "session-1",
                                "activitySeq",
                                10));

        assertEquals(false, poll.get("closeRequested"));

        Map<String, Object> laterPage = new LinkedHashMap<>();
        laterPage.put("zapid", "zap-control-later");
        laterPage.put("browserid", "browser-1");
        laterPage.put("sessionId", "session-1");
        laterPage.put("contractVersion", 2);
        laterPage.put("activitySeq", 11);
        laterPage.put("progress", 50);
        laterPage.put("status", "running");
        laterPage.put("safeToClose", false);
        laterPage.put("publisher", Map.of("drained", false, "pendingFindings", 1));
        laterPage.put(
                "engines",
                Map.of(
                        "SAST",
                        Map.of(
                                "status",
                                "running",
                                "progress",
                                50,
                                "details",
                                Map.of("findingsCount", 1, "totalFiles", 2))));
        postProgress(extension, laterPage);

        assertEquals(50, state.snapshot().progress());
        assertEquals("running", state.snapshot().status());
        assertTrue(state.snapshot().lastProgressChangedAtMs() > 1L);
        assertFalse(state.acceptsProgressSequence(10));
        assertTrue(state.acceptsProgressSequence(11));
        assertFalse(state.snapshot().terminalProgressSeen());
        assertFalse(state.snapshot().safeToClose());
        assertNull(state.snapshot().closeRequest());
        assertFalse(closeRequestIdByZapId(extension).containsKey("zap-control-later"));
        assertEquals(false, invokeControlPoll(extension, laterPage).get("closeRequested"));
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
                state.ensureCloseRequest("owner_browser_close_requested", 1_000L);
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
        assertEquals("owner_browser_close_requested", returned.get("reason"));
        assertEquals("graceful_stop_and_drain", returned.get("mode"));
        assertEquals(
                PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS, returned.get("stopTimeoutMs"));
        assertEquals(
                PtkCloseContract.BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS, returned.get("drainTimeoutMs"));
        assertEquals(
                returned,
                invokeControlPoll(
                        extension,
                        Map.of(
                                "zapid", "zap-control-existing",
                                "browserid", "browser-1",
                                "sessionId", "session-1")));

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
        assertFalse(state.snapshot().terminalProgressSeen());
        assertFalse(state.snapshot().safeToClose());
        assertFalse(state.snapshot().isV2ReleaseClean());
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

    @Test
    void activeBrowserWorkWaitDecisionIsRecognizedButNotTerminal() {
        Map<String, Object> closeDecision = new LinkedHashMap<>();
        closeDecision.put("decision", "wait");
        closeDecision.put("scanState", "running");
        closeDecision.put("reason", "active_browser_work");
        closeDecision.put("stopRequested", false);

        assertEquals(true, PtkCloseContract.isActiveBrowserWorkCloseDecision(closeDecision));

        closeDecision.put("stopRequested", true);
        assertEquals(false, PtkCloseContract.isActiveBrowserWorkCloseDecision(closeDecision));

        closeDecision.put("stopRequested", false);
        closeDecision.put("reason", "owner_waiting_for_terminal");
        assertEquals(false, PtkCloseContract.isActiveBrowserWorkCloseDecision(closeDecision));

        closeDecision.put("decision", "safe_to_close");
        closeDecision.put("reason", "active_browser_work");
        assertEquals(false, PtkCloseContract.isActiveBrowserWorkCloseDecision(closeDecision));
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

    private static ExtensionPtk requestedPartialOwner(String nativeFamily) throws Exception {
        ExtensionPtk extension = new ExtensionPtk();
        armRequestedPartialOwner(extension, nativeFamily);
        return extension;
    }

    private static void armRequestedPartialOwner(ExtensionPtk extension, String nativeFamily)
            throws Exception {
        PtkZapSessionState state =
                sessionStateByZapId(extension)
                        .computeIfAbsent("zap-partial", PtkZapSessionState::new);
        state.rememberNativeBrowserFamily(nativeFamily);
        state.recordProgress(
                "browser-partial",
                "session-partial",
                50,
                "running",
                "running",
                false,
                2,
                false,
                10,
                1_000L);
        state.ensureCloseRequest("close-partial", "owner_browser_close_requested", 1_001L);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> postConfig(
            ExtensionPtk extension, String browserId, int initiator) throws Exception {
        HttpMessage message = new HttpMessage();
        message.getRequestHeader()
                .setURI(new URI("https://zap/zapCallBackUrl/owned/ptk/config", true));
        message.getRequestHeader().setMethod("POST");
        message.getRequestBody()
                .setBody(new Gson().toJson(Map.of("zapid", "zap-partial", "browserid", browserId)));
        extension.new CallBackImplementor()
                .handleCallBack(message, new ClientCallBackContext(initiator));
        String body = message.getResponseBody().toString();
        return body.isEmpty() ? Map.of() : new Gson().fromJson(body, Map.class);
    }

    private static Map<String, Object> partialCleanupProgress(int sequence, String token) {
        Map<String, Object> details = new LinkedHashMap<>();
        if (token != null) details.put("message", token);
        // Cancelled counters can retain unexecuted work. They are not physical proof.
        details.put("remaining", 1250);
        details.put("taskQueue", 1156);
        Map<String, Object> dast = new LinkedHashMap<>();
        dast.put("status", "cancelled");
        dast.put("progress", 100);
        dast.put("completionStatus", "engine_incomplete");
        dast.put("details", details);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("zapid", "zap-partial");
        payload.put("browserid", "browser-partial");
        payload.put("sessionId", "session-partial");
        payload.put("closeRequestId", "close-partial");
        payload.put("closeRequestAck", true);
        payload.put("contractVersion", 2);
        payload.put("activitySeq", sequence);
        payload.put("progress", 100);
        payload.put("status", "cancelled");
        payload.put("completionStatus", "engine_incomplete");
        payload.put("releaseStatus", "incomplete");
        payload.put("terminalSeen", true);
        payload.put("safeToClose", true);
        payload.put(
                "publisher",
                new LinkedHashMap<>(
                        Map.of("drained", true, "pendingFindings", 0, "inFlightBatches", 0)));
        payload.put("engines", new LinkedHashMap<>(Map.of("DAST", dast)));
        return payload;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> nested(Map<String, Object> value, String key) {
        return (Map<String, Object>) value.get(key);
    }

    private static void postProgress(ExtensionPtk extension, Map<String, Object> payload)
            throws Exception {
        HttpMessage message = new HttpMessage();
        message.getRequestHeader().setURI(new URI("https://zap/test/ptk/progress", true));
        message.getRequestHeader().setMethod("POST");
        message.getRequestBody().setBody(new Gson().toJson(payload));
        extension.new CallBackImplementor().handleCallBack(message, null);
        assertEquals(
                "OK",
                new Gson().fromJson(message.getResponseBody().toString(), Map.class).get("result"));
    }

    private static boolean invokeSafeToClose(ExtensionPtk extension) throws Exception {
        ExtensionPtk.CallBackImplementor callback = extension.new CallBackImplementor();
        Method method = callback.getClass().getDeclaredMethod("isSafeToClose", String.class);
        method.setAccessible(true);
        return (boolean) method.invoke(callback, "zap-partial");
    }

    private static boolean invokeCloseDecision(ExtensionPtk extension, Map<String, Object> decision)
            throws Exception {
        ExtensionPtk.CallBackImplementor callback = extension.new CallBackImplementor();
        Method method =
                callback.getClass()
                        .getDeclaredMethod(
                                "canAcceptCloseDecisionSafeToClose",
                                String.class,
                                Map.class,
                                Integer.class,
                                String.class);
        method.setAccessible(true);
        return (boolean) method.invoke(callback, "zap-partial", decision, 100, "cancelled");
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
}
