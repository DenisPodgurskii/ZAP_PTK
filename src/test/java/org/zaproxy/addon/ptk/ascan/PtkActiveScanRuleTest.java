package org.zaproxy.addon.ptk.ascan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Set;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.Target;

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
        assertEquals(
                Set.of(
                        PolicyTag.DEV_FULL.getTag(),
                        PolicyTag.QA_STD.getTag(),
                        PolicyTag.QA_FULL.getTag(),
                        PolicyTag.SEQUENCE.getTag()),
                rule.getAlertTags().keySet());
    }

    @Test
    void contextOnlyTargetKeepsItsSectionRoot() {
        Context context = sectionContext();
        assertEquals(
                "https://example.invalid/dom/",
                PtkActiveScanTargets.select(
                        PtkActiveScanTargets.snapshot(new Target(context)),
                        "https://example.invalid/dom/child/"));
    }

    @Test
    void explicitChildKeepsItsOwnUrlInsideTheSameContext() throws Exception {
        String child = "https://example.invalid/dom/child/";
        Target target = new Target(structuralNodeWithUri(new URI(child, true)));
        target.setContext(sectionContext());
        var scope = PtkActiveScanTargets.snapshot(target);
        assertEquals(child, PtkActiveScanTargets.select(scope, child));
        assertNull(PtkActiveScanTargets.select(scope, "https://example.invalid/dom/sibling/"));
    }

    @Test
    void contextRejectsHostRootUnrelatedPathsAndExclusions() {
        Context context = sectionContext();
        context.addExcludeFromContextRegex("https://example.invalid/dom/excluded/.*");
        var scope = PtkActiveScanTargets.snapshot(new Target(context));
        for (String url :
                List.of(
                        "https://example.invalid/",
                        "https://example.invalid/dom2/child/",
                        "https://other.invalid/dom/child/",
                        "https://example.invalid/dom/excluded/child/",
                        "https://example.invalid/dom/%2e%2e/sibling/")) {
            assertNull(PtkActiveScanTargets.select(scope, url), url);
        }
    }

    @Test
    void ambiguousTargetsNeverFallBackToTheRepresentativePage() throws Exception {
        String child = "https://example.invalid/dom/child/";
        var first = structuralNodeWithUri(new URI(child, true));
        var second = structuralNodeWithUri(new URI("https://example.invalid/dom/sibling/", true));
        Context ambiguous = sectionContext();
        ambiguous.addIncludeInContextRegex("https://example.invalid/other/.*");
        Context wholeHost = new Context(null, 2);
        wholeHost.addIncludeInContextRegex("https://example.invalid/.*");
        for (Target target :
                List.of(
                        new Target(),
                        new Target(ambiguous),
                        new Target(wholeHost),
                        new Target(List.of(first, second)))) {
            assertNull(PtkActiveScanTargets.select(PtkActiveScanTargets.snapshot(target), child));
        }
    }

    private static Context sectionContext() {
        Context context = new Context(null, 1);
        context.addIncludeInContextRegex("https://example.invalid/dom/.*");
        return context;
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
}
