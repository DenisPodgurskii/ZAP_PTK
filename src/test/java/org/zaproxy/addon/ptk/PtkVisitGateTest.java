package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class PtkVisitGateTest {
    private static final Map<String, Object> CUT = Map.of(
            "root", Map.of("documentId", "native-doc", "streamGeneration", 1),
            "iast", Map.of("documentId", "web-doc", "revision", 4),
            "sast", Map.of("revision", 2),
            "publisher", Map.of("lastAckedBatchSeq", 3));

    @Test
    void stableObservationAndDepartureAreBothRequired() {
        AtomicReference<Map<String, Object>> observation = new AtomicReference<>(Map.of(
                "ok", true, "kind", "observed_interval", "elapsedMs", 2500, "cut", CUT));
        AtomicReference<Map<String, Object>> departure = new AtomicReference<>(Map.of(
                "ok", true, "kind", "departure_cut", "cut", CUT));
        PtkVisitGate gate = gate(observation, departure);
        assertFalse(gate.depart().complete());
        assertTrue(gate.observe().complete());
        assertTrue(gate.depart().complete());
        assertFalse(gate.depart().complete(), "a departure receipt is consumed once");

        assertTrue(gate.observe().complete());
        departure.set(Map.of("ok", true, "kind", "departure_cut", "cut", Map.of(
                "root", Map.of("documentId", "other-doc"),
                "iast", CUT.get("iast"), "sast", CUT.get("sast"),
                "publisher", CUT.get("publisher"))));
        assertEquals("visit_departure_changed", gate.depart().reason());
    }

    @Test
    void timeoutOrMissingEvidenceNeverProducesCompletion() {
        AtomicReference<Map<String, Object>> observation = new AtomicReference<>(Map.of(
                "ok", false, "reason", "visit_observation_timeout"));
        AtomicReference<Map<String, Object>> departure = new AtomicReference<>(Map.of(
                "ok", true, "kind", "departure_cut", "cut", CUT));
        PtkVisitGate gate = gate(observation, departure);
        assertEquals("visit_observation_timeout", gate.observe().reason());
        assertFalse(gate.depart().complete());
        observation.set(Map.of("ok", true, "kind", "observed_interval",
                "elapsedMs", 2500));
        assertFalse(gate.observe().complete());
        observation.set(Map.of("ok", true, "kind", "observed_interval",
                "elapsedMs", 2499, "cut", CUT));
        assertFalse(gate.observe().complete());
    }

    @Test
    void publicationAdvancingAfterObservationDoesNotInvalidateDocumentExecution() {
        AtomicReference<Map<String, Object>> observation = new AtomicReference<>(Map.of(
                "ok", true, "kind", "observed_interval", "elapsedMs", 2500, "cut", CUT));
        AtomicReference<Map<String, Object>> departure = new AtomicReference<>(Map.of(
                "ok", true, "kind", "departure_cut", "cut", Map.of(
                        "root", CUT.get("root"), "iast", CUT.get("iast"),
                        "sast", CUT.get("sast"),
                        "publisher", Map.of("lastAckedBatchSeq", 4))));
        PtkVisitGate gate = gate(observation, departure);
        assertTrue(gate.observe().complete());
        assertTrue(gate.depart().complete(),
                "a later stored alert is progress, not a different document");
    }

    @Test
    void publicationSnapshotIsNotRequiredForDocumentExecution() {
        Map<String, Object> documentCut = Map.of(
                "root", CUT.get("root"), "iast", CUT.get("iast"),
                "sast", CUT.get("sast"));
        AtomicReference<Map<String, Object>> observation = new AtomicReference<>(Map.of(
                "ok", true, "kind", "observed_interval", "elapsedMs", 2500,
                "cut", documentCut));
        AtomicReference<Map<String, Object>> departure = new AtomicReference<>(Map.of(
                "ok", true, "kind", "departure_cut", "cut", documentCut));
        PtkVisitGate gate = gate(observation, departure);
        assertTrue(gate.observe().complete());
        assertTrue(gate.depart().complete(),
                "publisher progress belongs to final close, not the page cut");
    }

    @Test
    void fragmentOnlyUrlChangeKeepsTheSameNativeDocumentCut() {
        Map<String, Object> first = Map.of(
                "root", Map.of("documentId", "native-doc", "streamGeneration", 1,
                        "url", "https://app.test/page#first"),
                "iast", CUT.get("iast"), "sast", CUT.get("sast"),
                "publisher", CUT.get("publisher"));
        AtomicReference<Map<String, Object>> observation = new AtomicReference<>(Map.of(
                "ok", true, "kind", "observed_interval", "elapsedMs", 2500,
                "cut", first));
        AtomicReference<Map<String, Object>> departure = new AtomicReference<>(Map.of(
                "ok", true, "kind", "departure_cut", "cut", Map.of(
                        "root", Map.of("documentId", "native-doc", "streamGeneration", 1,
                                "url", "https://app.test/page#second"),
                        "iast", CUT.get("iast"), "sast", CUT.get("sast"),
                        "publisher", CUT.get("publisher"))));
        PtkVisitGate gate = gate(observation, departure);
        assertTrue(gate.observe().complete());
        assertTrue(gate.depart().complete(),
                "fragment-only navigation cannot invalidate a same-document visit");

        assertTrue(gate.observe().complete());
        departure.set(Map.of("ok", true, "kind", "departure_cut", "cut", Map.of(
                "root", Map.of("documentId", "native-doc", "streamGeneration", 1,
                        "url", "https://app.test/page?changed=1#second"),
                "iast", CUT.get("iast"), "sast", CUT.get("sast"),
                "publisher", CUT.get("publisher"))));
        assertEquals("visit_departure_changed", gate.depart().reason(),
                "a query change must not borrow the old document interval");
    }

    @Test
    void missingSastCutCannotCertifyAVisit() {
        Map<String, Object> incompleteCut = Map.of(
                "root", CUT.get("root"), "iast", CUT.get("iast"),
                "publisher", CUT.get("publisher"));
        AtomicReference<Map<String, Object>> observation = new AtomicReference<>(Map.of(
                "ok", true, "kind", "observed_interval", "elapsedMs", 2500,
                "cut", incompleteCut));
        AtomicReference<Map<String, Object>> departure = new AtomicReference<>(Map.of(
                "ok", true, "kind", "departure_cut", "cut", incompleteCut));
        PtkVisitGate gate = gate(observation, departure);
        assertEquals("visit_observation_unverified", gate.observe().reason());
        assertFalse(gate.depart().complete());
    }

    @Test
    void combinedObservationAndDepartureRequiresCompleteSingleRequestProof() {
        AtomicReference<Map<String, Object>> combined = new AtomicReference<>(Map.of(
                "ok", true, "kind", "observed_departure_cut", "elapsedMs", 2500,
                "cut", CUT));
        PtkVisitGate gate = gate(new AtomicReference<>(Map.of()),
                new AtomicReference<>(Map.of()), combined);
        assertTrue(gate.observeAndDepart().complete());
        assertFalse(gate.hasObservedCut(), "a combined receipt is not reusable");
        combined.set(Map.of("ok", false, "reason", "visit_observation_timeout"));
        assertEquals("visit_observation_timeout", gate.observeAndDepart().reason());
        combined.set(Map.of("ok", true, "kind", "observed_departure_cut",
                "elapsedMs", 2499, "cut", CUT));
        assertFalse(gate.observeAndDepart().complete());
        combined.set(Map.of("ok", true, "kind", "observed_departure_cut",
                "elapsedMs", 2500, "cut", Map.of("root", CUT.get("root"))));
        assertFalse(gate.observeAndDepart().complete());
    }

    private static PtkVisitGate gate(
            AtomicReference<Map<String, Object>> observation,
            AtomicReference<Map<String, Object>> departure) {
        return gate(observation, departure,
                new AtomicReference<>(Map.of("ok", false, "reason", "visit_departure_unverified")));
    }

    private static PtkVisitGate gate(
            AtomicReference<Map<String, Object>> observation,
            AtomicReference<Map<String, Object>> departure,
            AtomicReference<Map<String, Object>> combined) {
        return new PtkVisitGate(new PtkVisitGate.Endpoint() {
            @Override
            public Map<String, Object> observe(int observationMs, int maxWaitMs) {
                assertEquals(2500, observationMs);
                assertEquals(15000, maxWaitMs);
                return observation.get();
            }

            @Override
            public Map<String, Object> observeAndDepart(int observationMs, int maxWaitMs) {
                assertEquals(2500, observationMs);
                assertEquals(15000, maxWaitMs);
                return combined.get();
            }

            @Override
            public Map<String, Object> checkpoint(String phase) {
                return "departure".equals(phase) ? departure.get()
                        : Map.of("ok", true, "kind", "observation_cleared");
            }
        }, 2500, 15000);
    }
}
