package org.zaproxy.addon.ptk;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.automation.ExtensionAutomation;

/** Registers the diagnostic-only PTK browser coverage Automation Framework job. */
public final class PtkBrowserCoverageDiagnostic implements PtkDiagnosticExtension {

    private static final Logger LOGGER = LogManager.getLogger(PtkBrowserCoverageDiagnostic.class);

    private PtkBrowserCoverageJob browserCoverageJob;

    public PtkBrowserCoverageDiagnostic() {}

    @Override
    public void hook(ExtensionPtk ptk, ExtensionHook extensionHook) {
        ExtensionAutomation extensionAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        if (extensionAutomation == null) {
            LOGGER.warn("PTK diagnostic browser coverage unavailable; Automation add-on missing");
            return;
        }
        browserCoverageJob = new PtkBrowserCoverageJob(ptk);
        extensionAutomation.registerAutomationJob(browserCoverageJob);
        LOGGER.warn("PTK diagnostic browser coverage artifact is not a production release");
        LOGGER.info("PTK diagnostic browser coverage job registered");
    }

    @Override
    public void unload(ExtensionPtk ptk) {
        ExtensionAutomation extensionAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        if (extensionAutomation != null && browserCoverageJob != null) {
            extensionAutomation.unregisterAutomationJob(browserCoverageJob);
        }
        browserCoverageJob = null;
    }
}
