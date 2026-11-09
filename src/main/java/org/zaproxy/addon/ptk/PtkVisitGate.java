package org.zaproxy.addon.ptk;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/** Fail-closed Java side of an exact-owner PTK visit observation and departure cut. */
final class PtkVisitGate {
    interface Endpoint {
        Map<String, Object> observe(int observationMs, int maxWaitMs);

        Map<String, Object> observeAndDepart(int observationMs, int maxWaitMs);

        Map<String, Object> checkpoint(String phase);
    }

    record Outcome(boolean complete, String reason, String url) {
        static Outcome success(Object cut) {
            return new Outcome(true, "", rootUrl(cut));
        }

        static Outcome incomplete(String reason) {
            return new Outcome(false, reason, null);
        }
    }

    private final Endpoint endpoint;
    private final int observationMs;
    private final int maxWaitMs;
    private Map<?, ?> observedCut;

    PtkVisitGate(Endpoint endpoint, int observationMs, int maxWaitMs) {
        this.endpoint = Objects.requireNonNull(endpoint);
        if (observationMs < 1 || maxWaitMs < observationMs || maxWaitMs > 300000) {
            throw new IllegalArgumentException("visit_observation_budget_invalid");
        }
        this.observationMs = observationMs;
        this.maxWaitMs = maxWaitMs;
    }

    synchronized Outcome observe() {
        observedCut = null;
        Map<String, Object> response = endpoint.observe(observationMs, maxWaitMs);
        if (response == null) return Outcome.incomplete("visit_observation_unverified");
        if (!Boolean.TRUE.equals(response.get("ok"))
                || !"observed_interval".equals(response.get("kind"))
                || !validCut(response.get("cut"))
                || !(response.get("elapsedMs") instanceof Number elapsed)
                || !Double.isFinite(elapsed.doubleValue())
                || elapsed.doubleValue() < observationMs) {
            return Outcome.incomplete(reason(response, "visit_observation_unverified"));
        }
        observedCut = (Map<?, ?>) response.get("cut");
        return Outcome.success(observedCut);
    }

    synchronized Outcome observeAndDepart() {
        observedCut = null;
        Map<String, Object> response = endpoint.observeAndDepart(observationMs, maxWaitMs);
        if (response == null) return Outcome.incomplete("visit_departure_unverified");
        if (!Boolean.TRUE.equals(response.get("ok"))
                || !"observed_departure_cut".equals(response.get("kind"))
                || !validCut(response.get("cut"))
                || !(response.get("elapsedMs") instanceof Number elapsed)
                || !Double.isFinite(elapsed.doubleValue())
                || elapsed.doubleValue() < observationMs) {
            return Outcome.incomplete(reason(response, "visit_departure_unverified"));
        }
        return Outcome.success(response.get("cut"));
    }

    synchronized Outcome depart() {
        Map<?, ?> first = observedCut;
        observedCut = null;
        Map<String, Object> response = endpoint.checkpoint("departure");
        if (response == null) return Outcome.incomplete("visit_departure_unverified");
        if (!Boolean.TRUE.equals(response.get("ok"))
                || !"departure_cut".equals(response.get("kind"))
                || !validCut(response.get("cut"))) {
            return Outcome.incomplete(reason(response, "visit_departure_unverified"));
        }
        if (first == null) return Outcome.incomplete("visit_observation_unavailable");
        Map<?, ?> last = (Map<?, ?>) response.get("cut");
        if (!sameDocumentAndScan(first, last)) {
            return Outcome.incomplete("visit_departure_changed");
        }
        return Outcome.success(last);
    }

    synchronized boolean hasObservedCut() {
        return observedCut != null;
    }

    synchronized void clear() {
        observedCut = null;
        endpoint.checkpoint("clear");
    }

    private static boolean validCut(Object value) {
        if (!(value instanceof Map<?, ?> cut)) return false;
        return cut.get("root") instanceof Map<?, ?>
                && cut.get("iast") instanceof Map<?, ?>
                && cut.get("sast") instanceof Map<?, ?>;
    }

    private static String rootUrl(Object cut) {
        if (!(cut instanceof Map<?, ?> fields)
                || !(fields.get("root") instanceof Map<?, ?> root)
                || !(root.get("url") instanceof String url)) return null;
        return url;
    }

    private static boolean sameDocumentAndScan(Map<?, ?> first, Map<?, ?> last) {
        if (!sameRoot(first.get("root"), last.get("root"))) return false;
        Map<?, ?> firstIast = (Map<?, ?>) first.get("iast");
        Map<?, ?> lastIast = (Map<?, ?>) last.get("iast");
        Map<?, ?> firstSast = (Map<?, ?>) first.get("sast");
        Map<?, ?> lastSast = (Map<?, ?>) last.get("sast");
        return Objects.equals(firstIast.get("scanId"), lastIast.get("scanId"))
                && Objects.equals(firstIast.get("documentId"), lastIast.get("documentId"))
                && Objects.equals(firstSast.get("scanId"), lastSast.get("scanId"));
    }

    private static boolean sameRoot(Object first, Object last) {
        if (!(first instanceof Map<?, ?> firstRoot)
                || !(last instanceof Map<?, ?> lastRoot)) return false;
        Map<Object, Object> firstFields = new HashMap<>(firstRoot);
        Map<Object, Object> lastFields = new HashMap<>(lastRoot);
        Object firstUrl = firstFields.remove("url");
        Object lastUrl = lastFields.remove("url");
        if (!firstFields.equals(lastFields)) return false;
        if (firstUrl == null || lastUrl == null) return firstUrl == lastUrl;
        if (!(firstUrl instanceof String before) || !(lastUrl instanceof String after)) return false;
        int beforeFragment = before.indexOf('#');
        int afterFragment = after.indexOf('#');
        return before.substring(0, beforeFragment < 0 ? before.length() : beforeFragment)
                .equals(after.substring(0, afterFragment < 0 ? after.length() : afterFragment));
    }

    private static String reason(Map<String, Object> response, String fallback) {
        Object raw = response.get("reason");
        return raw instanceof String value && value.matches("[a-z][a-z0-9_]{0,127}")
                ? value
                : fallback;
    }
}
