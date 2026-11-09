package org.zaproxy.addon.ptk;

import java.nio.file.Files;
import java.util.Map;
import java.util.UUID;
import java.util.function.Predicate;
import org.openqa.selenium.MutableCapabilities;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.SpiderScanLaunchContext;
import org.zaproxy.addon.client.spider.SpiderSessionPolicy;
import org.zaproxy.addon.client.spider.SpiderSessionPolicyProvider;
import org.zaproxy.addon.client.spider.SpiderVisitCoordinator;
import org.zaproxy.addon.client.spider.VisitOutcome;
import org.zaproxy.zap.extension.selenium.SeleniumOptions;

/** PTK-owned Chromium Client Spider policy; nonparticipants keep Client's ordinary browser policy. */
final class PtkSpiderPolicy {
    private final ExtensionPtk ptk;
    private final SpiderSessionPolicyProvider provider;
    private ExtensionClientIntegration client;

    PtkSpiderPolicy(ExtensionPtk ptk) {
        this.ptk = ptk;
        this.provider = this::select;
    }

    void register(ExtensionClientIntegration client) {
        if (client == null || this.client != null) {
            throw new IllegalStateException("visit_client_extension_unavailable");
        }
        client.registerSpiderSessionPolicyProvider(provider);
        this.client = client;
    }

    void unregister() {
        if (client != null) {
            client.deregisterSpiderSessionPolicyProvider(provider);
            client = null;
        }
    }

    private SpiderSessionPolicy select(SpiderScanLaunchContext context) {
        SeleniumOptions selenium = Model.getSingleton().getOptionsParam()
                .getParamSet(SeleniumOptions.class);
        boolean included = context.scanOptions().getIncludeExtensions().contains("ptk-latest");
        boolean globallyEnabled = selenium != null
                && ExtensionPtk.isBrowserCaptureExtensionEnabled(
                        selenium.getBrowserExtensions(), context.browserId());
        if (!eligible(ptk.getParam().isZapAutomationEnabled(), context.browserId(),
                context.scanOptions().getExcludeExtensions().contains("ptk-latest"),
                included, globallyEnabled)) {
            return null;
        }
        if (!Files.isDirectory(ExtensionPtk.getPtkChromiumExtensionPath())
                || !context.adaptiveWaitEnabled()
                || context.adaptiveTimeoutMs() < 1
                || context.adaptiveQuiesceFirstAccessMs() < 1
                || context.adaptiveQuiesceFirstAccessMs() > context.adaptiveTimeoutMs()) {
            throw new IllegalStateException("visit_policy_prerequisite_unavailable");
        }
        return new SpiderSessionPolicy(PtkSpiderPolicy::applyCapabilities,
                (driver, proxyPort) -> new Coordinator(ptk, driver, context));
    }

    static boolean eligible(boolean automation, String browserId, boolean excluded,
            boolean included, boolean globallyEnabled) {
        return automation && ExtensionPtk.isChromiumBrowserName(browserId) && !excluded
                && (included || globallyEnabled);
    }

    static void applyCapabilities(MutableCapabilities capabilities) {
        Object existing = capabilities.getCapability("pageLoadStrategy");
        if (existing != null && !"none".equals(String.valueOf(existing))) {
            throw new IllegalStateException("visit_page_load_policy_conflict");
        }
        capabilities.setCapability("pageLoadStrategy", "none");
    }

    static boolean inVisitScope(String targetUrl, String candidateUrl, boolean subtreeOnly,
            Predicate<String> contextScope) {
        if (contextScope != null && !subtreeOnly) return contextScope.test(candidateUrl);
        return PtkUrlUtils.isSameOriginAndPathScoped(targetUrl, candidateUrl);
    }

    static final class Coordinator implements SpiderVisitCoordinator {
        private final ExtensionPtk ptk;
        private final WebDriver driver;
        private final PtkVisitGate gate;
        private final String browserId;
        private final String targetUrl;
        private final boolean subtreeOnly;
        private final Predicate<String> contextScope;
        private final String checkpointId = "visit-" + UUID.randomUUID();
        private boolean bound;
        private boolean visitedTarget;
        private boolean cancelled;
        private boolean lastActionObservationIncomplete;

        Coordinator(ExtensionPtk ptk, WebDriver driver, SpiderScanLaunchContext context) {
            this.ptk = ptk;
            this.driver = driver;
            this.browserId = context.browserId();
            this.targetUrl = context.targetUrl();
            this.subtreeOnly = context.scanOptions().isSubtreeOnly();
            this.contextScope = context.scanOptions().getContext() == null
                    ? null : context.scanOptions().getContext()::isInContext;
            this.gate = ptk.createOwnedVisitGate(driver,
                    context.adaptiveQuiesceFirstAccessMs(), context.adaptiveTimeoutMs());
        }

        @Override
        public VisitOutcome bind() {
            if (cancelled || !ptk.probeInstalledVisitCapability(driver, browserId)) {
                return incomplete("visit_capability_unavailable");
            }
            Map<String, Object> prestart = ptk.requestOwnedVisitPrestart(driver, targetUrl);
            if (!Boolean.TRUE.equals(prestart.get("ok"))
                    || !"visit_prestarted".equals(prestart.get("kind"))) {
                Object reason = prestart.get("reason");
                return incomplete(reason instanceof String value
                        && value.matches("[a-z][a-z0-9_]{0,127}")
                        ? value : "visit_prestart_unverified");
            }
            bound = true;
            return complete();
        }

        @Override
        public VisitOutcome beforeAction(String action) {
            if (!bound || cancelled) return failed("visit_coordinator_unavailable");
            if ("follow.fallback.navigation".equals(action)) {
                // Direct navigation already has an in-scope destination. A
                // Selenium URL lookup is not needed to choose it and can fail
                // during document replacement; the owned cut checks any
                // previously observed page before departure.
                VisitOutcome outcome = visitedTarget ? observePriorCutOrDeparture() : complete();
                if (outcome.isComplete()) lastActionObservationIncomplete = false;
                return outcome;
            }
            try {
                if (!gate.hasObservedCut()) {
                    // Without a cut, keep the existing browser/scope check;
                    // a foreign redirect must not trigger another full dwell.
                    String current = driver.getCurrentUrl();
                    if (("about:blank".equals(current) || isOwnCallback(current))
                            && !visitedTarget) return complete();
                    if (current != null && !"about:blank".equals(current)
                            && !isOwnCallback(current)
                            && !inScope(current)) {
                        return incomplete("visit_target_out_of_scope");
                    }
                }
                // A successful owned cut already supplies a native-verified
                // URL and scope; an extra Selenium lookup adds no proof.
                VisitOutcome outcome = observePriorCutOrDeparture();
                if (outcome.isComplete()) lastActionObservationIncomplete = false;
                return outcome;
            } catch (RuntimeException error) {
                return failed("visit_browser_unavailable");
            }
        }

        @Override
        public VisitOutcome afterAction(String action) {
            if (!bound || cancelled) return failed("visit_coordinator_unavailable");
            VisitOutcome outcome = observeTarget();
            lastActionObservationIncomplete = !outcome.isComplete();
            return outcome;
        }

        @Override
        public VisitOutcome beforeRelease() {
            if (!bound || cancelled) return failed("visit_coordinator_unavailable");
            // The owned departure cut already supplies the verified current
            // root URL. A second Selenium URL command can block or time out
            // during a document transition and needlessly retire the browser.
            VisitOutcome departure = lastActionObservationIncomplete
                    && !gate.hasObservedCut()
                    ? convert(gate.depart()) : observePriorCutOrDeparture();
            if (!departure.isComplete()) return departure;
            return visitedTarget ? departure : incomplete("visit_target_unvisited");
        }

        @Override
        public void cancel() {
            cancelled = true;
            try {
                gate.clear();
            } catch (RuntimeException ignored) {
                // Cleanup must not replace the original visit outcome.
            }
            // Do not issue another potentially blocked WebDriver command on a
            // failed visit. The Client process owner closes the full session.
            PtkVisitRunner.forget(driver);
        }

        private VisitOutcome observeTarget() {
            try {
                PtkVisitGate.Outcome result = gate.observe();
                VisitOutcome outcome = convert(result);
                if (outcome.isComplete()) visitedTarget = true;
                return outcome;
            } catch (RuntimeException error) {
                return failed("visit_browser_unavailable");
            }
        }

        private VisitOutcome observeDeparture() {
            try {
                PtkVisitGate.Outcome result = gate.observeAndDepart();
                VisitOutcome outcome = convert(result);
                if (outcome.isComplete()) visitedTarget = true;
                return outcome;
            } catch (RuntimeException error) {
                return failed("visit_browser_unavailable");
            }
        }

        private VisitOutcome observePriorCutOrDeparture() {
            if (!gate.hasObservedCut()) return observeDeparture();
            PtkVisitGate.Outcome result = gate.depart();
            // An already observed document does not need a second full dwell
            // before the next action. A real document/stream change still does.
            return "visit_departure_changed".equals(result.reason())
                    ? observeDeparture() : convert(result);
        }

        private boolean isOwnCallback(String url) {
            return ExtensionPtk.isOwnedClientCallbackUrl(url, ptk.getZapIdForWebDriver(driver));
        }

        private boolean inScope(String url) {
            return inVisitScope(targetUrl, url, subtreeOnly, contextScope);
        }

        private VisitOutcome convert(PtkVisitGate.Outcome result) {
            if (result.complete()) {
                if (result.url() == null || "about:blank".equals(result.url())
                        || isOwnCallback(result.url())) return incomplete("visit_target_unavailable");
                return inScope(result.url()) ? complete() : incomplete("visit_target_out_of_scope");
            }
            String reason = result.reason();
            if (reason.contains("owner_mismatch") || reason.contains("owner_changed")
                    || "visit_owner_unavailable".equals(reason)
                    || reason.contains("session_unavailable")) return failed(reason);
            return incomplete(reason);
        }

        private VisitOutcome complete() {
            return new VisitOutcome(VisitOutcome.Status.COMPLETE, "", checkpointId);
        }

        private VisitOutcome incomplete(String reason) {
            return new VisitOutcome(VisitOutcome.Status.INCOMPLETE, reason, checkpointId);
        }

        private VisitOutcome failed(String reason) {
            return new VisitOutcome(VisitOutcome.Status.FAILED, reason, checkpointId);
        }
    }
}
