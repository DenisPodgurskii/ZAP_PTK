package org.zaproxy.addon.ptk.ascan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.model.StructuralNode;

class PtkActiveScanRuleTest {

    @Test
    void shouldReturnDefaultMetadata() {
        PtkActiveScanRule rule = new PtkActiveScanRule();
        assertEquals(230000, rule.getId());
        assertEquals(Category.BROWSER, rule.getCategory());
        assertEquals(Alert.RISK_INFO, rule.getRisk());
        assertEquals(0, rule.getCweId());
        assertEquals(0, rule.getWascId());
        assertNotNull(rule.getAlertTags());
        assertTrue(rule.getAlertTags().isEmpty());
    }

    // ---- getFirstStartNodeUrl(List<?>) ----

    @Test
    void getFirstStartNodeUrl_returnsUrlOfFirstNode() throws URIException {
        StructuralNode node = structuralNodeWithUri(new URI("https://example.com/app/", true));
        assertEquals(
                "https://example.com/app/", PtkActiveScanRule.getFirstStartNodeUrl(List.of(node)));
    }

    @Test
    void getFirstStartNodeUrl_usesFirstOfMultipleNodes() throws URIException {
        StructuralNode first = structuralNodeWithUri(new URI("https://example.com/first/", true));
        StructuralNode second = structuralNodeWithUri(new URI("https://example.com/second/", true));
        assertEquals(
                "https://example.com/first/",
                PtkActiveScanRule.getFirstStartNodeUrl(List.of(first, second)));
    }

    @Test
    void getFirstStartNodeUrl_returnsNullForEmptyList() {
        assertNull(PtkActiveScanRule.getFirstStartNodeUrl(List.of()));
    }

    @Test
    void getFirstStartNodeUrl_returnsNullForNullList() {
        assertNull(PtkActiveScanRule.getFirstStartNodeUrl((List<?>) null));
    }

    @Test
    void getFirstStartNodeUrl_returnsNullWhenFirstNodeHasNoUri() {
        assertNull(PtkActiveScanRule.getFirstStartNodeUrl(List.of(structuralNodeWithUri(null))));
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

    // ---- urlFromStructuralNode ----

    @Test
    void urlFromStructuralNode_returnsNullForNullNode() {
        assertNull(PtkActiveScanRule.urlFromStructuralNode(null));
    }

    @Test
    void urlFromStructuralNode_returnsUriString() throws URIException {
        URI uri = new URI("https://example.com/path/", true);
        assertEquals(
                "https://example.com/path/",
                PtkActiveScanRule.urlFromStructuralNode(structuralNodeWithUri(uri)));
    }

    @Test
    void urlFromStructuralNode_returnsNullWhenNoUriAvailable() {
        assertNull(PtkActiveScanRule.urlFromStructuralNode(structuralNodeWithUri(null)));
    }

    private static StructuralNode structuralNodeWithUri(URI uri) {
        return new StructuralNode() {
            @Override
            public StructuralNode getParent() {
                return null;
            }

            @Override
            public java.util.Iterator<StructuralNode> getChildIterator() {
                return List.<StructuralNode>of().iterator();
            }

            @Override
            public long getChildNodeCount() {
                return 0;
            }

            @Override
            public org.parosproxy.paros.model.HistoryReference getHistoryReference() {
                return null;
            }

            @Override
            public String getName() {
                return null;
            }

            @Override
            public String getRegexPattern() {
                return null;
            }

            @Override
            public String getRegexPattern(boolean incChildren) {
                return null;
            }

            @Override
            public URI getURI() {
                return uri;
            }

            @Override
            public String getMethod() {
                return null;
            }

            @Override
            public boolean isRoot() {
                return false;
            }

            @Override
            public boolean isLeaf() {
                return false;
            }

            @Override
            public boolean isDataDriven() {
                return false;
            }

            @Override
            public boolean isSameAs(StructuralNode node) {
                return false;
            }
        };
    }

    private static HttpMessage messageForUrl(String url)
            throws URIException, HttpMalformedHeaderException {
        return new HttpMessage(new HttpRequestHeader("GET " + url + " HTTP/1.1"));
    }
}
