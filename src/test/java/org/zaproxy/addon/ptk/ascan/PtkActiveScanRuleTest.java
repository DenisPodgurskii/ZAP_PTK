package org.zaproxy.addon.ptk.ascan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Set;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.StructuralNode;

class PtkActiveScanRuleTest {

    @Test
    void incompleteSecondPassHasAnExplicitNonSuccessReason() {
        assertEquals(
                "PTK Client Spider did not complete: INCOMPLETE",
                PtkActiveScanRule.incompleteClientSpiderReason(
                        ClientSpider.CompletionOutcome.INCOMPLETE));
        assertEquals(
                "PTK Client Spider did not complete: CANCELLED",
                PtkActiveScanRule.incompleteClientSpiderReason(
                        ClientSpider.CompletionOutcome.CANCELLED));
        assertEquals(
                "PTK Client Spider did not complete: UNAVAILABLE",
                PtkActiveScanRule.incompleteClientSpiderReason(null));
    }

    @Test
    void shouldReturnDefaultMetadata() {
        PtkActiveScanRule rule = new PtkActiveScanRule();
        assertEquals(230000, rule.getId());
        assertEquals(Category.BROWSER, rule.getCategory());
        assertEquals(Alert.RISK_INFO, rule.getRisk());
        assertEquals(0, rule.getCweId());
        assertEquals(0, rule.getWascId());
        assertNotNull(rule.getAlertTags());
        assertEquals(
                Set.of(
                        PolicyTag.DEV_FULL.getTag(),
                        PolicyTag.QA_STD.getTag(),
                        PolicyTag.QA_FULL.getTag(),
                        PolicyTag.SEQUENCE.getTag()),
                rule.getAlertTags().keySet());
    }

    // ---- resolveClientSpiderStartUrl ----

    @Test
    void resolveClientSpiderStartUrl_returnsNullWhenBothNull() {
        assertNull(PtkActiveScanRule.resolveClientSpiderStartUrl(null, null, null));
    }

    @Test
    void resolveClientSpiderStartUrl_fallsBackToBaseMsgWhenHostProcessIsNull() throws Exception {
        HttpMessage baseMsg = messageForUrl("https://example.com/fallback/");
        assertEquals(
                "https://example.com/fallback/",
                PtkActiveScanRule.resolveClientSpiderStartUrl(null, baseMsg, null));
    }

    @Test
    void contextWideScanUsesConfiguredDomRootInsteadOfHostRuleMessage() throws Exception {
        assertEquals(
                "https://example.com/dom/",
                resolve(
                        "https://example.com/dom/dompropagation/",
                        List.of(startNode("https://example.com/")),
                        List.of("https://example.com/dom/.*"),
                        url -> url.startsWith("https://example.com/dom/")));
    }

    @Test
    void explicitLeafScanKeepsItsRequestedStartUrl() throws Exception {
        assertEquals(
                "https://example.com/dom/dompropagation/",
                resolve(
                        "https://example.com/dom/dompropagation/child",
                        List.of(startNode("https://example.com/dom/dompropagation/")),
                        List.of("https://example.com/dom/.*"),
                        url -> url.startsWith("https://example.com/dom/")));
    }

    @Test
    void explicitContextRootScanKeepsItsRequestedStartUrl() throws Exception {
        assertEquals(
                "https://example.com/dom/",
                resolve(
                        "https://example.com/dom/dompropagation/",
                        List.of(startNode("https://example.com/dom/")),
                        List.of("https://example.com/dom/.*"),
                        url -> url.startsWith("https://example.com/dom/")));
    }

    @Test
    void ambiguousOrNonliteralContextRetainsBaseMessage() throws Exception {
        String baseUrl = "https://example.com/dom/dompropagation/";
        List<StructuralNode> hostRoot = List.of(startNode("https://example.com/"));
        assertEquals(
                baseUrl,
                resolve(
                        baseUrl,
                        hostRoot,
                        List.of("https://example.com/dom/.*", "https://example.com/other/.*"),
                        url -> true));
        assertEquals(
                baseUrl,
                resolve(
                        baseUrl,
                        hostRoot,
                        List.of("https://example.com/dom/(foo|bar)/.*"),
                        url -> true));
        assertEquals(
                baseUrl,
                resolve(baseUrl, hostRoot, List.of("https://other.example/dom/.*"), url -> true));
        assertEquals(
                baseUrl,
                resolve(baseUrl, hostRoot, List.of("https://example.com/domain/.*"), url -> true));
        assertEquals(
                baseUrl,
                resolve(baseUrl, hostRoot, List.of("https://example.com/.*"), url -> true));
    }

    @Test
    void excludedContextRootAndUnknownStartNodesRetainBaseMessage() throws Exception {
        String baseUrl = "https://example.com/dom/dompropagation/";
        List<String> include = List.of("https://example.com/dom/.*");
        assertEquals(
                baseUrl,
                resolve(
                        baseUrl,
                        List.of(startNode("https://example.com/")),
                        include,
                        url -> !url.equals("https://example.com/dom/")));
        assertEquals(baseUrl, resolve(baseUrl, List.of(), include, url -> true));
        assertEquals(
                baseUrl,
                resolve(
                        baseUrl,
                        List.of(startNode("https://example.com/dom/unknown/")),
                        include,
                        url -> true));
        assertEquals(
                baseUrl,
                resolve(
                        baseUrl,
                        List.of(startNode("https://other.example/dom/")),
                        include,
                        url -> true));
    }

    @Test
    void multipleMatchingStartNodesDoNotSelectAnAmbiguousRoot() throws Exception {
        String baseUrl = "https://example.com/dom/dompropagation/child";
        assertEquals(
                baseUrl,
                resolve(
                        baseUrl,
                        List.of(
                                startNode("https://example.com/dom/"),
                                startNode("https://example.com/dom/dompropagation/")),
                        List.of("https://example.com/dom/.*"),
                        url -> url.startsWith("https://example.com/dom/")));
    }

    @Test
    void isClientSpiderSeedInScope_rejectsOutsideContext() {
        assertEquals(
                true,
                PtkActiveScanRule.isClientSpiderSeedInScope(
                        "https://example.com/dom/page",
                        url -> url.startsWith("https://example.com/dom/")));
        assertEquals(
                false,
                PtkActiveScanRule.isClientSpiderSeedInScope(
                        "https://example.com/", url -> url.startsWith("https://example.com/dom/")));
        assertEquals(false, PtkActiveScanRule.isClientSpiderSeedInScope(null, url -> true));
    }

    private static HttpMessage messageForUrl(String url)
            throws URIException, HttpMalformedHeaderException {
        return new HttpMessage(new HttpRequestHeader("GET " + url + " HTTP/1.1"));
    }

    private static String resolve(
            String baseUrl,
            List<StructuralNode> startNodes,
            List<String> includeRegexes,
            java.util.function.Predicate<String> inContext) {
        return PtkActiveScanRule.resolveClientSpiderStartUrl(
                baseUrl, startNodes, includeRegexes, inContext);
    }

    private static StructuralNode startNode(String url) throws URIException {
        org.apache.commons.httpclient.URI uri = new org.apache.commons.httpclient.URI(url, true);
        return (StructuralNode)
                Proxy.newProxyInstance(
                        StructuralNode.class.getClassLoader(),
                        new Class<?>[] {StructuralNode.class},
                        (proxy, method, args) -> {
                            if (method.getName().equals("getURI")) {
                                return uri;
                            }
                            throw new UnsupportedOperationException(method.getName());
                        });
    }
}
