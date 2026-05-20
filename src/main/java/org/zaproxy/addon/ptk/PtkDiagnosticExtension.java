package org.zaproxy.addon.ptk;

import org.parosproxy.paros.extension.ExtensionHook;

/**
 * Optional PTK diagnostic extension point loaded only when a diagnostic build packages a provider.
 */
public interface PtkDiagnosticExtension {

    void hook(ExtensionPtk ptk, ExtensionHook extensionHook);

    void unload(ExtensionPtk ptk);
}
