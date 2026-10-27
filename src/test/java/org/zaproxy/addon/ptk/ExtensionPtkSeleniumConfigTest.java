package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ClientCallBackImplementor.ClientCallBackContext;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.BrowserExtension;

/** Tests PTK's ZAP Selenium browser registration coverage. */
class ExtensionPtkSeleniumConfigTest {

    @Test
    void managedConfigUsesExactNativePhaseNotEarlyOrConflictingCallbackContext() throws Exception {
        var registry = new PtkBrowserCaptureReadiness();
        String route = "/zapCallBackUrl/owned/ptk/browser-capture";
        String configUrl = "https://zap/zapCallBackUrl/owned/ptk/config";
        assertTrue(registry.bindBrowser(route, "active", "chrome", "ACTIVE_SCAN_RULE"));
        assertEquals(
                HttpSender.ACTIVE_SCANNER_INITIATOR,
                ExtensionPtk.browserCaptureConfigContext(
                                registry, configUrl, "active", new ClientCallBackContext(-1), true)
                        .initiator());
        assertTrue(registry.bindBrowser(route, "spider", "firefox", "CLIENT_SPIDER"));
        assertEquals(
                HttpSender.SPIDER_INITIATOR,
                ExtensionPtk.browserCaptureConfigContext(
                                registry,
                                configUrl,
                                "spider",
                                new ClientCallBackContext(HttpSender.ACTIVE_SCANNER_INITIATOR),
                                true)
                        .initiator());
        assertNull(
                ExtensionPtk.browserCaptureConfigContext(
                        registry,
                        "https://zap/zapCallBackUrl/foreign/ptk/config",
                        "active",
                        new ClientCallBackContext(-1),
                        true));
        assertNull(
                ExtensionPtk.browserCaptureConfigContext(
                        registry,
                        configUrl + "?extra=1",
                        "active",
                        new ClientCallBackContext(-1),
                        true));
    }

    @Test
    void configBypassIsPhaseIndependentForNoEnginesOrDisabledPtk() throws Exception {
        var installed = List.of(new BrowserExtension(Path.of("ptk-latest.xpi")));
        var enabled = Map.of("sast", Map.of());
        assertFalse(
                ExtensionPtk.browserCaptureConfigNeedsNativeOwner(Map.of(), Map.of(), installed));
        assertTrue(ExtensionPtk.browserCaptureConfigNeedsNativeOwner(enabled, Map.of(), installed));
        assertTrue(ExtensionPtk.browserCaptureConfigNeedsNativeOwner(Map.of(), enabled, installed));
        assertFalse(ExtensionPtk.browserCaptureConfigNeedsNativeOwner(enabled, enabled, List.of()));
        BrowserExtension disabled = new BrowserExtension(Path.of("ptk-latest.xpi"));
        disabled.setEnabled(false);
        assertFalse(
                ExtensionPtk.browserCaptureConfigNeedsNativeOwner(
                        enabled, enabled, List.of(disabled)));
        var original = new ClientCallBackContext(-1);
        assertSame(
                original,
                ExtensionPtk.browserCaptureConfigContext(
                        new PtkBrowserCaptureReadiness(), "unknown", "unknown", original, false));
    }

    @Test
    void unknownManagedConfigTimesOutWithoutProducingManualContext() throws Exception {
        var pool = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            var pending =
                    pool.submit(
                            () ->
                                    ExtensionPtk.browserCaptureConfigContext(
                                            new PtkBrowserCaptureReadiness(),
                                            "https://zap/zapCallBackUrl/owned/ptk/config",
                                            "unknown",
                                            new ClientCallBackContext(-1),
                                            true));
            assertNull(pending.get(3, java.util.concurrent.TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void configWaitPrecedesBookkeepingAndCacheAndPendingResponseIsNotJson() throws Exception {
        String source =
                Files.readString(Path.of("src/main/java/org/zaproxy/addon/ptk/ExtensionPtk.java"));
        int handler = source.indexOf("} else if (uri.contains(PTK_CONFIG_PATH))");
        assertTrue(handler >= 0);
        var waitAssignment =
                java.util.regex.Pattern.compile(
                                "cbContext\\s*=\\s*browserCaptureConfigContext\\s*\\(")
                        .matcher(source);
        int wait = waitAssignment.find(handler) ? waitAssignment.start() : -1;
        int remember = source.indexOf("rememberBrowserId(zapid, browserid)", handler);
        int cache = source.indexOf("getConfigJsonForRequest(requestData, cbContext)", handler);
        assertTrue(wait > handler && remember > wait && cache > remember);
        String pending = source.substring(source.indexOf("if (cbContext == null)", wait), remember);
        assertTrue(pending.contains("setBody(\"\")"));
        assertTrue(pending.contains("\"text/plain\""));
        assertFalse(pending.contains("GSON"));
        assertTrue(pending.contains("return \"\""));
        assertEquals(
                1,
                source.split("\\.registerBrowserHook\\(browserCaptureReadyHook\\)", -1).length - 1);
    }

    @Test
    void readinessRouteIsBoundToTheNativeExactCallbackWithoutUrlOrSourceData() {
        assertEquals(
                "/zapCallBackUrl/owned/ptk/browser-capture",
                ExtensionPtk.browserCaptureCallbackRoute(
                        "https://zap/zapCallBackUrl/owned/?zapenable=true", false));
        assertEquals(
                "/zapCallBackUrl/owned/ptk/browser-capture",
                ExtensionPtk.browserCaptureCallbackRoute(
                        "https://zap/zapCallBackUrl/owned/ptk/browser-capture", true));
        for (String url :
                List.of(
                        "http://zap/zapCallBackUrl/owned/ptk/browser-capture",
                        "https://foreign/zapCallBackUrl/owned/ptk/browser-capture",
                        "https://zap:443/zapCallBackUrl/owned/ptk/browser-capture",
                        "https://user@zap/zapCallBackUrl/owned/ptk/browser-capture",
                        "https://zap/zapCallBackUrl/owned/ptk/browser-capture?extra=1",
                        "https://zap/zapCallBackUrl/owned/ptk/browser-capture#fragment",
                        "https://zap/zapCallBackUrl/owned/ptk/browser-capture/extra",
                        "https://zap/zapCallBackUrl/%6fwned/ptk/browser-capture")) {
            assertEquals("", ExtensionPtk.browserCaptureCallbackRoute(url, true), url);
        }
    }

    @Test
    void everyEnabledEnginePhaseRequiresNetworkAndOnlySastRequiresPreparedSources() {
        assertEquals(Set.of(), ExtensionPtk.configuredBrowserCaptureCapabilities(Map.of()));
        for (String engine : List.of("iast", "dast")) {
            assertEquals(
                    Set.of("network"),
                    ExtensionPtk.configuredBrowserCaptureCapabilities(Map.of(engine, Map.of())));
        }
        assertEquals(
                Set.of("network", "sources"),
                ExtensionPtk.configuredBrowserCaptureCapabilities(Map.of("sast", Map.of())));
        assertEquals(
                Set.of("network", "sources"),
                ExtensionPtk.configuredBrowserCaptureCapabilities(
                        Map.of("sast", Map.of(), "iast", Map.of(), "dast", Map.of())));
        assertEquals(
                null, ExtensionPtk.browserCaptureArmedCapabilities(List.of("network", "network")));
        assertEquals(
                null, ExtensionPtk.browserCaptureArmedCapabilities(List.of("network", "input")));
        assertEquals(null, ExtensionPtk.browserCaptureArmedCapabilities("network"));
        assertEquals(
                Set.of("network", "sources"),
                ExtensionPtk.browserCaptureArmedCapabilities(List.of("network", "sources")));
    }

    @Test
    void readinessMigrationContainsNoLegacySourceProxyOrHistoryOperations() throws Exception {
        String source =
                Files.readString(Path.of("src/main/java/org/zaproxy/addon/ptk/ExtensionPtk.java"));
        assertFalse(source.contains("PtkSastSources"));
        assertFalse(source.contains("addProxyListener(sastSources)"));
        assertFalse(source.contains("sastSourceCaptureVersion"));
        assertTrue(source.contains("browserCaptureVersion"));
        assertTrue(source.contains("browserCaptureReadiness.isBrowserOwner"));
        assertTrue(source.contains("browserCaptureReadiness.browserFamily"));
        assertTrue(source.contains("version.doubleValue() == PtkBrowserCaptureReadiness.VERSION"));
    }

    @Test
    void captureReadyHookRegistersAfterClientIntegrationPostInitNotDuringHook() throws Exception {
        // ZAP initializes every extension's hook before any postInit. Client
        // Integration registers RedirectScript in postInit, so a dependent PTK
        // hook registered earlier cannot observe its completed redirect.
        assertEquals(
                ExtensionPtk.class,
                ExtensionPtk.class.getDeclaredMethod("postInit").getDeclaringClass());
        String source =
                Files.readString(Path.of("src/main/java/org/zaproxy/addon/ptk/ExtensionPtk.java"));
        int hook = source.indexOf("public void hook(ExtensionHook extensionHook)");
        int postInit = source.indexOf("public void postInit()");
        int registration = source.indexOf(".registerBrowserHook(browserCaptureReadyHook)");
        int nextMethod = source.indexOf("\n    @Override", postInit);
        assertTrue(hook >= 0 && postInit > hook, "explicit postInit lifecycle required");
        assertTrue(registration > postInit && registration < nextMethod);
        assertTrue(
                readBrowserList("EXTENSION_DEPENDENCIES")
                        .contains(org.zaproxy.addon.client.ExtensionClientIntegration.class));
    }

    @Test
    void captureReadyGateUsesSeleniumBaseExtensionFamilyForEverySupportedVariant() {
        var chromium = List.of(new BrowserExtension(Path.of("ptk-latest")));
        for (String id : List.of("chrome", "chrome-headless", "edge", "edge-headless")) {
            assertTrue(ExtensionPtk.isBrowserCaptureExtensionEnabled(chromium, id), id);
        }
        var firefox = List.of(new BrowserExtension(Path.of("ptk-latest.xpi")));
        for (String id : List.of("firefox", "firefox-headless")) {
            assertTrue(ExtensionPtk.isBrowserCaptureExtensionEnabled(firefox, id), id);
        }
    }

    @Test
    void captureReadyGateNeverTreatsDisabledWrongFamilyOrOtherExtensionsAsPtk() {
        BrowserExtension disabled = new BrowserExtension(Path.of("ptk-latest.xpi"));
        disabled.setEnabled(false);
        assertFalse(ExtensionPtk.isBrowserCaptureExtensionEnabled(List.of(disabled), "firefox"));
        var firefox = List.of(new BrowserExtension(Path.of("ptk-latest.xpi")));
        assertFalse(ExtensionPtk.isBrowserCaptureExtensionEnabled(firefox, "edge-headless"));
        assertFalse(ExtensionPtk.isBrowserCaptureExtensionEnabled(firefox, "unknown"));
        assertFalse(ExtensionPtk.isBrowserCaptureExtensionEnabled(null, "firefox"));
        assertFalse(ExtensionPtk.isBrowserCaptureExtensionEnabled(firefox, null));
        assertFalse(ExtensionPtk.isBrowserCaptureExtensionEnabled(firefox, ""));
        assertFalse(
                ExtensionPtk.isBrowserCaptureExtensionEnabled(
                        List.of(new BrowserExtension(Path.of("other.xpi"))), "firefox"));
    }

    @Test
    void chromiumRegistrationIncludesHeadedAndHeadlessBrowsers() throws Exception {
        List<?> browsers = readBrowserList("PTK_CHROMIUM_BROWSERS");

        assertTrue(browsers.contains(Browser.CHROME));
        assertTrue(browsers.contains(Browser.CHROME_HEADLESS));
        assertTrue(browsers.contains(Browser.EDGE));
        assertTrue(browsers.contains(Browser.EDGE_HEADLESS));
    }

    @Test
    void firefoxRegistrationIncludesHeadedAndHeadlessBrowsers() throws Exception {
        List<?> browsers = readBrowserList("PTK_FIREFOX_BROWSERS");

        assertTrue(browsers.contains(Browser.FIREFOX));
        assertTrue(browsers.contains(Browser.FIREFOX_HEADLESS));
    }

    @Test
    void firefoxXpiIsAValidArtifactForHeadedAndHeadlessBrowsers(@TempDir Path tempDir)
            throws Exception {
        Path xpi = Files.createFile(tempDir.resolve("ptk-latest.xpi"));

        assertTrue(ExtensionPtk.isPtkExtensionPathPresent(xpi, Browser.FIREFOX));
        assertTrue(ExtensionPtk.isPtkExtensionPathPresent(xpi, Browser.FIREFOX_HEADLESS));
        assertFalse(ExtensionPtk.isPtkExtensionPathPresent(xpi, Browser.CHROME));
    }

    @Test
    void chromiumUnpackedDirectoryIsAValidArtifactForHeadedAndHeadlessBrowsers(
            @TempDir Path tempDir) throws Exception {
        Path unpacked = Files.createDirectory(tempDir.resolve("ptk-latest"));

        assertTrue(ExtensionPtk.isPtkExtensionPathPresent(unpacked, Browser.CHROME));
        assertTrue(ExtensionPtk.isPtkExtensionPathPresent(unpacked, Browser.CHROME_HEADLESS));
        assertTrue(ExtensionPtk.isPtkExtensionPathPresent(unpacked, Browser.EDGE));
        assertTrue(ExtensionPtk.isPtkExtensionPathPresent(unpacked, Browser.EDGE_HEADLESS));
        assertFalse(ExtensionPtk.isPtkExtensionPathPresent(unpacked, Browser.FIREFOX));
    }

    @Test
    void reflectiveFailureDiagnosticsExposeUnderlyingCause() {
        InvocationTargetException wrapper =
                new InvocationTargetException(
                        new IllegalArgumentException("unsupported Selenium browser key"));

        assertEquals(
                "IllegalArgumentException: unsupported Selenium browser key",
                ExtensionPtk.describeExceptionForLog(wrapper));
    }

    @Test
    void browserBackgroundTrafficSuppressionIsLimitedToBrowserUpdateEndpoints() {
        assertTrue(
                ExtensionPtk.isBrowserBackgroundRequestToSuppress(
                        "edge.microsoft.com", "/componentupdater/api/v1/update"));
        assertTrue(
                ExtensionPtk.isBrowserBackgroundRequestToSuppress(
                        "msedge.f.tlu.dl.delivery.mp.microsoft.com",
                        "/filestreamingservice/files/aeee40bc-5e6e-48fa-a38f-7990dcdbcd2d"));
        assertTrue(
                ExtensionPtk.isBrowserBackgroundRequestToSuppress(
                        "firefox.settings.services.mozilla.com",
                        "/v1/buckets/main/collections/ai-window-prompts/changeset"));

        assertFalse(
                ExtensionPtk.isBrowserBackgroundRequestToSuppress(
                        "edge.microsoft.com", "/not-componentupdater/api/v1/update"));
        assertFalse(
                ExtensionPtk.isBrowserBackgroundRequestToSuppress(
                        "public-firing-range.appspot.com",
                        "/escape/serverside/escapeHtml/attribute_unquoted"));
        assertFalse(
                ExtensionPtk.isBrowserBackgroundRequestToSuppress(
                        "example.dl.delivery.mp.microsoft.com", "/ordinary/file"));
        assertFalse(
                ExtensionPtk.isBrowserBackgroundRequestToSuppress(
                        "firefox.settings.services.mozilla.com", "/ordinary/file"));
    }

    private static List<?> readBrowserList(String fieldName) throws Exception {
        Field field = ExtensionPtk.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        Object value = field.get(null);
        assertTrue(value instanceof List<?>);
        return (List<?>) value;
    }
}
