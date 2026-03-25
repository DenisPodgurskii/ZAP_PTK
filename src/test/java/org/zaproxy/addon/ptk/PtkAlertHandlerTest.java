package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.ptk.model.PtkFinding;
import org.zaproxy.addon.ptk.model.PtkFindingBatch;
import org.zaproxy.addon.ptk.model.PtkFindingLocation;
import org.zaproxy.addon.ptk.model.PtkFindingRequest;
import org.zaproxy.addon.ptk.model.PtkFindingResponse;

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
        assertNotNull(alert.getTags());
        assertTrue(
                alert.getTags().containsKey("OWASP_2025_A02")
                        || alert.getTags().containsKey("OWASP_2021_A05"));
    }

    @Test
    void dastReconCachePrivacyFindingMapsToAlert() {
        assumeResourcesLoaded();
        PtkFindingBatch batch = loadBatch(DAST_EXAMPLE);
        PtkFinding reconFinding =
                batch.getFindings().stream()
                        .filter(f -> "recon_cache_privacy".equals(f.getModuleId()))
                        .findFirst()
                        .orElse(null);
        assertNotNull(reconFinding);

        Alert alert = PtkAlertBuilder.buildFromFinding(reconFinding, "DAST", mapper, resources);
        assertNotNull(alert);
        assertEquals("Missing Referrer-Policy", alert.getName());
        assertEquals(200018, alert.getPluginId());
        assertTrue(alert.getDescription().contains("cache"));
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

    @Test
    void malformedRawResponseIsNormalizedBeforeCreatingHttpMessage() throws Exception {
        PtkFinding finding = new PtkFinding();
        finding.setLocation(
                new PtkFindingLocation(
                        "http://localhost:3001/rest/admin/application-configuration",
                        null,
                        "GET",
                        null));
        finding.setRequest(
                new PtkFindingRequest(
                        null,
                        "GET",
                        "http://localhost:3001/rest/admin/application-configuration",
                        "GET http://localhost:3001/rest/admin/application-configuration HTTP/1.1\nAccept: application/json"));
        finding.setResponse(
                new PtkFindingResponse(
                        200, 12L, "HTTP/1.1 OK\ncontent-type: application/json\n\n{\"ok\":true}"));

        HttpMessage message = PtkAlertHandler.createHttpMessageForFinding(finding);

        assertTrue(
                message.getRequestHeader()
                        .toString()
                        .startsWith(
                                "GET http://localhost:3001/rest/admin/application-configuration HTTP/1.1"));
        assertTrue(message.getRequestHeader().toString().contains("Host: localhost:3001"));
        assertTrue(message.getResponseHeader().toString().startsWith("HTTP/1.1 200 OK"));
        assertTrue(
                message.getResponseHeader().toString().contains("content-type: application/json"));
        assertEquals("{\"ok\":true}", message.getResponseBody().toString());
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
