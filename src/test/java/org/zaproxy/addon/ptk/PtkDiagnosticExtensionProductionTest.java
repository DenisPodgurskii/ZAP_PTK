package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class PtkDiagnosticExtensionProductionTest {

    @Test
    void productionClasspathDoesNotRegisterDiagnosticProvider() {
        assertNull(
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource(
                                "META-INF/services/org.zaproxy.addon.ptk.PtkDiagnosticExtension"));
    }
}
