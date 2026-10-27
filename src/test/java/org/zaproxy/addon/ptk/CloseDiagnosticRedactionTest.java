package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CloseDiagnosticRedactionTest {
    @Test
    void retainsUsefulExceptionAndPhase() {
        assertEquals(
                "org.openqa.selenium.NoSuchWindowException",
                ExtensionPtk.sanitizeCloseDiagnostic("org.openqa.selenium.NoSuchWindowException"));
        assertEquals(
                "execute_async_close_control",
                ExtensionPtk.sanitizeCloseDiagnostic("execute_async_close_control"));
        assertNull(ExtensionPtk.sanitizeCloseDiagnostic(null));
    }

    @Test
    void redactsCallbackTokensQueryValuesAndUrlCredentials() {
        String output =
                ExtensionPtk.sanitizeCloseDiagnostic(
                        "navigation https://zap/zapCallBackUrl/callbackSecret?zapid=sessionSecret&token=querySecret https://user:pass@example.test/path?key=anotherSecret");
        for (String secret :
                new String[] {
                    "callbackSecret", "sessionSecret", "querySecret", "user:pass", "anotherSecret"
                }) assertFalse(output.contains(secret));
        assertTrue(output.contains("navigation"));
        assertTrue(output.contains("/zapCallBackUrl/"));
    }

    @Test
    void redactsSensitiveHeadersAndAssignmentsAndNormalizesLogLines() {
        String output =
                ExtensionPtk.sanitizeCloseDiagnostic(
                        "NoSuchWindowException\nAuthorization: Bearer authSecret\nCookie: session=cookieSecret\nSet-Cookie: credential=otherSecret\npassword=passSecret token=tokenSecret api_key=apiSecret\tclosed");
        for (String secret :
                new String[] {
                    "authSecret",
                    "cookieSecret",
                    "otherSecret",
                    "passSecret",
                    "tokenSecret",
                    "apiSecret"
                }) assertFalse(output.contains(secret));
        assertFalse(output.contains("\n"));
        assertTrue(output.contains("NoSuchWindowException"));
    }

    @Test
    void boundsLongUntrustedErrorMessages() {
        String output = ExtensionPtk.sanitizeCloseDiagnostic("x".repeat(5000));
        assertEquals(1011, output.length());
        assertTrue(output.endsWith("<truncated>"));
    }

    @Test
    void quotedAndEscapedJsonCredentialsAndBearerTokensAreRedacted() {
        String output =
                ExtensionPtk.sanitizeCloseDiagnostic(
                        "error {\"password\":\"passwordSecret\",\"token\":\"tokenSecret\",\"Authorization\":\"Bearer authSecret\"} \\\"api_key\\\":\\\"apiSecret\\\" Bearer directSecret");
        for (String secret :
                new String[] {
                    "passwordSecret", "tokenSecret", "authSecret", "apiSecret", "directSecret"
                }) assertFalse(output.contains(secret));
        assertTrue(output.contains("error"));
    }

    @Test
    void fragmentsAndMultilineCapabilityDumpsAreNotRetained() {
        String output =
                ExtensionPtk.sanitizeCloseDiagnostic(
                        "Browsing context discarded https://example.test/path#fragmentSecret\nCapabilities: {password=capabilitySecret}\nremote endpoint secretEndpoint");
        for (String secret : new String[] {"fragmentSecret", "capabilitySecret", "secretEndpoint"})
            assertFalse(output.contains(secret));
        assertFalse(output.contains("Capabilities"));
        assertTrue(output.startsWith("Browsing context discarded"));
    }
}
