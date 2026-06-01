package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.selenium.Browser;

/** Tests PTK's ZAP Selenium browser registration coverage. */
class ExtensionPtkSeleniumConfigTest {

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
    void chromiumArgumentsBypassBrowserUpdateEndpoints() throws Exception {
        List<?> arguments = readBrowserList("PTK_CHROMIUM_BACKGROUND_ARGS");

        assertTrue(
                arguments.contains(
                        "--proxy-bypass-list=edge.microsoft.com;*.dl.delivery.mp.microsoft.com;update.googleapis.com;dl.google.com;*.gvt1.com"));
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
