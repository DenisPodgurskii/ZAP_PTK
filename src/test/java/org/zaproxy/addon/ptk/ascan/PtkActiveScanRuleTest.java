package org.zaproxy.addon.ptk.ascan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

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

class PtkActiveScanRuleTest {

    @Test
    void incompleteSecondPassHasAnExplicitNonSuccessReason() {
        assertEquals("PTK Client Spider did not complete: INCOMPLETE",
                PtkActiveScanRule.incompleteClientSpiderReason(
                        ClientSpider.CompletionOutcome.INCOMPLETE));
        assertEquals("PTK Client Spider did not complete: CANCELLED",
                PtkActiveScanRule.incompleteClientSpiderReason(
                        ClientSpider.CompletionOutcome.CANCELLED));
        assertEquals("PTK Client Spider did not complete: UNAVAILABLE",
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
        assertNull(PtkActiveScanRule.resolveClientSpiderStartUrl(null, null));
    }

    @Test
    void resolveClientSpiderStartUrl_fallsBackToBaseMsgWhenHostProcessIsNull() throws Exception {
        HttpMessage baseMsg = messageForUrl("https://example.com/fallback/");
        assertEquals(
                "https://example.com/fallback/",
                PtkActiveScanRule.resolveClientSpiderStartUrl(null, baseMsg));
    }

    @Test
    void resolveClientSpiderStartUrl_usesExactBaseMessageNotHostRoot() throws Exception {
        HttpMessage baseMsg = messageForUrl("https://example.com/dom/dompropagation/");
        assertEquals(
                "https://example.com/dom/dompropagation/",
                PtkActiveScanRule.resolveClientSpiderStartUrl(null, baseMsg));
    }

    @Test
    void isClientSpiderSeedInScope_rejectsOutsideContext() {
        assertEquals(true, PtkActiveScanRule.isClientSpiderSeedInScope(
                "https://example.com/dom/page", url -> url.startsWith("https://example.com/dom/")));
        assertEquals(false, PtkActiveScanRule.isClientSpiderSeedInScope(
                "https://example.com/", url -> url.startsWith("https://example.com/dom/")));
        assertEquals(false, PtkActiveScanRule.isClientSpiderSeedInScope(null, url -> true));
    }

    private static HttpMessage messageForUrl(String url)
            throws URIException, HttpMalformedHeaderException {
        return new HttpMessage(new HttpRequestHeader("GET " + url + " HTTP/1.1"));
    }
}
