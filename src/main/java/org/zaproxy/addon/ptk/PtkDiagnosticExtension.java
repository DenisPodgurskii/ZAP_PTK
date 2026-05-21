package org.zaproxy.addon.ptk;

import org.parosproxy.paros.extension.ExtensionHook;

/**
 * Optional PTK diagnostic extension point loaded only when a diagnostic build packages a provider.
 */
public interface PtkDiagnosticExtension {

    /**
     * Called once from {@link ExtensionPtk#hook(ExtensionHook)} after the production PTK callbacks
     * and Selenium configuration are registered.
     *
     * <p>Implementations are discovered with {@link java.util.ServiceLoader} from the add-on
     * classloader. Runtime exceptions are logged and swallowed by {@link ExtensionPtk}, so a broken
     * diagnostic provider does not prevent the production extension from loading.
     */
    void hook(ExtensionPtk ptk, ExtensionHook extensionHook);

    /**
     * Called from {@link ExtensionPtk#unload()} for providers that successfully completed {@link
     * #hook(ExtensionPtk, ExtensionHook)}.
     *
     * <p>Implementations should release only resources they registered during {@code hook}. Runtime
     * exceptions are logged and swallowed by {@link ExtensionPtk} so unload can continue.
     */
    void unload(ExtensionPtk ptk);
}
