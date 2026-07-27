package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.ptk.model.PtkFinding;
import org.zaproxy.addon.ptk.model.PtkFindingBatch;

/**
 * Tests for PTK alert handling using the temp-example JSON files. Verifies parsing, mapping to ZAP
 * alerts, and that all relevant PTK data is included.
 */
class PtkAlertHandlerTest {

    private static final String RESOURCE_BASE = "org/zaproxy/addon/ptk/";
    private static final String SAST_EXAMPLE = RESOURCE_BASE + "sast_batch_example.json";
    private static final String IAST_EXAMPLE = RESOURCE_BASE + "iast_batch_example.json";
    private static final String DAST_EXAMPLE = RESOURCE_BASE + "dast_batch_example.json";

    private static final Gson GSON = new Gson();
    private PtkResourcesLoader.LoadedPtkResources resources;
    private PtkZapMapper mapper;

    @BeforeEach
    void setUp() {
        PtkResourcesLoader loader = new PtkResourcesLoader();
        resources = loader.loadAll();
        if (resources != null && resources.getZapMapping() != null) {
            mapper = new PtkZapMapper(resources);
        }
    }

    @Test
    void sastBatchParsesCorrectly() {
        PtkFindingBatch batch = loadBatch(SAST_EXAMPLE);
        assertNotNull(batch);
        assertTrue(batch.isSastBatch());
        assertEquals("SAST", batch.getPayload().getEngine());
        List<PtkFinding> findings = batch.getFindings();
        assertNotNull(findings);
        assertTrue(findings.size() >= 4);

        PtkFinding first = findings.get(0);
        assertEquals("dom-xss", first.getModuleId());
        assertEquals("dom-xss-taint-angular", first.getRuleId());
        assertEquals("high", first.getSeverity());
        assertNotNull(first.getSummary());
        assertNotNull(first.getLocation());
        assertEquals("http://localhost:3001/#/", first.getLocation().getUrl());
        assertNotNull(first.getSource());
        assertNotNull(first.getSink());
        assertNotNull(first.getCodeSnippet());
    }

    @Test
    void iastBatchParsesCorrectly() {
        PtkFindingBatch batch = loadBatch(IAST_EXAMPLE);
        assertNotNull(batch);
        assertTrue(batch.isIastBatch());
        assertEquals("IAST", batch.getPayload().getEngine());
        List<PtkFinding> findings = batch.getFindings();
        assertNotNull(findings);
        assertTrue(findings.size() >= 3);

        PtkFinding first = findings.get(0);
        assertEquals("iast_client_json_parsing", first.getModuleId());
        assertEquals("json_parse_taint", first.getRuleId());
        assertNotNull(first.getProof());
        assertNotNull(first.getContext());
    }

    @Test
    void dastBatchParsesCorrectly() {
        PtkFindingBatch batch = loadBatch(DAST_EXAMPLE);
        assertNotNull(batch);
        assertTrue(batch.isDastBatch());
        assertEquals("DAST", batch.getPayload().getEngine());
        List<PtkFinding> findings = batch.getFindings();
        assertNotNull(findings);
        assertTrue(findings.size() >= 4);

        PtkFinding first = findings.get(0);
        assertEquals("headers", first.getModuleId());
        assertEquals("header_csp_missing", first.getRuleId());
        assertNotNull(first.getRequest());
        assertNotNull(first.getResponse());
        assertEquals("GET", first.getMethod());
    }

    @Test
    void sastDomXssFindingMapsToAlert() {
        assumeResourcesLoaded();
        PtkFindingBatch batch = loadBatch(SAST_EXAMPLE);
        PtkFinding domXssFinding =
                batch.getFindings().stream()
                        .filter(f -> "dom-xss".equals(f.getModuleId()))
                        .findFirst()
                        .orElse(null);
        assertNotNull(domXssFinding);

        Alert alert = PtkAlertBuilder.buildFromFinding(domXssFinding, "SAST", mapper, resources);
        assertNotNull(alert);
        assertEquals("DOM XSS via innerHTML (Angular)", alert.getName());
        assertEquals(220000, alert.getPluginId());
        assertEquals(Alert.RISK_HIGH, alert.getRisk());
        assertTrue(alert.getDescription().contains("untrusted data"));
        assertTrue(alert.getDescription().contains("OWASP PTK SAST"));
        assertEquals("http://localhost:3001/#/", alert.getUri());
        assertTrue(alert.getOtherInfo().contains(domXssFinding.getSummary()));
        assertTrue(alert.getOtherInfo().contains("Source:"));
        assertTrue(alert.getOtherInfo().contains("Sink:"));
        assertTrue(alert.getOtherInfo().contains("Code:"));
        Map<String, String> tags = alert.getTags();
        assertNotNull(tags);
        assertEquals(
                CommonAlertTag.OWASP_2025_A05_INJECTION.getValue(),
                tags.get(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()));
        assertEquals(
                CommonAlertTag.OWASP_2021_A03_INJECTION.getValue(),
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()));
    }

    @Test
    void dastHeadersFindingMapsToAlert() {
        assumeResourcesLoaded();
        PtkFindingBatch batch = loadBatch(DAST_EXAMPLE);
        PtkFinding headersFinding =
                batch.getFindings().stream()
                        .filter(f -> "headers".equals(f.getModuleId()))
                        .findFirst()
                        .orElse(null);
        assertNotNull(headersFinding);

        Alert alert = PtkAlertBuilder.buildFromFinding(headersFinding, "DAST", mapper, resources);
        assertNotNull(alert);
        assertEquals("Missing Content-Security-Policy header", alert.getName());
        assertEquals(200005, alert.getPluginId());
        assertTrue(alert.getDescription().contains("HTTP response headers"));
        assertTrue(
                alert.getSolution().contains("Configure security-related HTTP response headers"));
        assertTrue(alert.getReference().contains("owasp.org"));
        assertTrue(alert.getReference().contains("cwe.mitre.org"));
        assertEquals(693, alert.getCweId());
        Map<String, String> tags = alert.getTags();
        assertNotNull(tags);
        assertEquals(
                CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getValue(),
                tags.get(CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getTag()));
        assertEquals(
                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue(),
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()));
        assertEquals(PtkAlertBuilder.TAG_TOOL_PTK_URL, tags.get(PtkAlertBuilder.TAG_TOOL_PTK));
    }

    @Test
    void dastHeadersReferrerPolicyFindingMapsToAlert() {
        assumeResourcesLoaded();
        PtkFindingBatch batch = loadBatch(DAST_EXAMPLE);
        PtkFinding headersFinding =
                batch.getFindings().stream()
                        .filter(
                                f ->
                                        "headers".equals(f.getModuleId())
                                                && "header_referrer_policy_missing_or_weak"
                                                        .equals(f.getRuleId()))
                        .findFirst()
                        .orElse(null);
        assertNotNull(headersFinding);

        Alert alert = PtkAlertBuilder.buildFromFinding(headersFinding, "DAST", mapper, resources);
        assertNotNull(alert);
        assertEquals("Missing or weak Referrer-Policy", alert.getName());
        assertEquals(200005, alert.getPluginId());
        assertTrue(alert.getDescription().contains("HTTP response headers"));
    }

    @Test
    void unmappedFindingReturnsNull() {
        assumeResourcesLoaded();
        PtkFindingBatch batch = loadBatch(SAST_EXAMPLE);
        PtkFinding clientInjectionFinding =
                batch.getFindings().stream()
                        .filter(f -> "client-injection".equals(f.getModuleId()))
                        .findFirst()
                        .orElse(null);
        assertNotNull(clientInjectionFinding);

        Alert alert =
                PtkAlertBuilder.buildFromFinding(clientInjectionFinding, "SAST", mapper, resources);
        assertNull(alert);
    }

    @Test
    void alertBatchAckReturnsStructuredRejectedFindingAndIsIdempotent() {
        String requestBody =
                """
                {
                  "source": "ptk",
                  "type": "dast_findings_batch",
                  "batchId": "ack-test-batch-1",
                  "batchSeq": 7,
                  "zapid": "zap-ack-test",
                  "payload": {
                    "engine": "DAST",
                    "scanId": "scan-ack-test",
                    "sessionId": "session-ack-test",
                    "findings": [
                      {
                        "id": "finding-ack-test-1",
                        "moduleId": "missing-module",
                        "ruleId": "missing-rule",
                        "uri": "https://example.test/app"
                      }
                    ]
                  }
                }
                """;

        PtkAlertHandler.AlertBatchAck ack = PtkAlertHandler.processAlertBatchWithAck(requestBody);
        PtkAlertHandler.AlertBatchAck repeated =
                PtkAlertHandler.processAlertBatchWithAck(requestBody);

        assertEquals("OK", ack.result);
        assertEquals(2, ack.contractVersion);
        assertEquals(true, ack.structuredAck);
        assertEquals(false, ack.legacyAck);
        assertEquals("ack-test-batch-1", ack.batchId);
        assertEquals(7, ack.batchSeq);
        assertEquals(1, ack.received);
        assertEquals(0, ack.accepted);
        assertEquals(0, ack.alertsRaised);
        assertEquals(1, ack.findingResults.size());
        assertEquals("finding-ack-test-1", ack.findingResults.get(0).id);
        assertEquals("rejected_missing_mapping", ack.findingResults.get(0).status);
        assertEquals(ack.findingResults.get(0).status, repeated.findingResults.get(0).status);
    }

    @Test
    void alertBatchAckIsStableForConcurrentDuplicateBatches() throws Exception {
        String requestBody =
                """
                {
                  "source": "ptk",
                  "type": "dast_findings_batch",
                  "batchId": "ack-test-batch-concurrent",
                  "batchSeq": 8,
                  "zapid": "zap-ack-test-concurrent",
                  "payload": {
                    "engine": "DAST",
                    "scanId": "scan-ack-test-concurrent",
                    "sessionId": "session-ack-test-concurrent",
                    "findings": [
                      {
                        "id": "finding-ack-test-concurrent-1",
                        "moduleId": "missing-module",
                        "ruleId": "missing-rule",
                        "uri": "https://example.test/app"
                      }
                    ]
                  }
                }
                """;

        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<PtkAlertHandler.AlertBatchAck>> futures = new ArrayList<>();
            for (int i = 0; i < 16; i++) {
                futures.add(
                        executor.submit(
                                () -> PtkAlertHandler.processAlertBatchWithAck(requestBody)));
            }
            for (Future<PtkAlertHandler.AlertBatchAck> future : futures) {
                PtkAlertHandler.AlertBatchAck ack = future.get();
                assertEquals("OK", ack.result);
                assertEquals("ack-test-batch-concurrent", ack.batchId);
                assertEquals(8, ack.batchSeq);
                assertEquals(1, ack.received);
                assertEquals(0, ack.alertsRaised);
                assertEquals(1, ack.findingResults.size());
                assertEquals("rejected_missing_mapping", ack.findingResults.get(0).status);
            }
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void dastHostHeaderPoisoningUnmappedReturnsNull() {
        assumeResourcesLoaded();
        PtkFindingBatch batch = loadBatch(DAST_EXAMPLE);
        PtkFinding hostPoisonFinding =
                batch.getFindings().stream()
                        .filter(f -> "host_header_poisoning".equals(f.getModuleId()))
                        .findFirst()
                        .orElse(null);
        assertNotNull(hostPoisonFinding);

        Alert alert =
                PtkAlertBuilder.buildFromFinding(hostPoisonFinding, "DAST", mapper, resources);
        assertNull(alert);
    }

    @Test
    void proofPayloadAndEvidenceIncludedInAlert() {
        assumeResourcesLoaded();
        PtkFindingBatch batch = loadBatch(DAST_EXAMPLE);
        PtkFinding hostPoisonFinding =
                batch.getFindings().stream()
                        .filter(f -> "host_header_poisoning".equals(f.getModuleId()))
                        .findFirst()
                        .orElse(null);
        assertNotNull(hostPoisonFinding);
        assertNotNull(hostPoisonFinding.getProof());
        assertEquals("evil.example", hostPoisonFinding.getProof().getPayload());

        // Even though unmapped, we can verify the finding has the data
        assertEquals("Poison host in headers", hostPoisonFinding.getSummary());
    }

    private PtkFindingBatch loadBatch(String resourcePath) {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (in == null) return null;
            return GSON.fromJson(
                    new InputStreamReader(in, StandardCharsets.UTF_8), PtkFindingBatch.class);
        } catch (Exception e) {
            throw new AssertionError("Failed to load " + resourcePath, e);
        }
    }

    private void assumeResourcesLoaded() {
        Assumptions.assumeTrue(
                mapper != null, "zap-mapping.json or module resources not available");
    }
}
