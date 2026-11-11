package org.zaproxy.addon.ptk;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import org.zaproxy.addon.client.ClientCallBackImplementor;
import org.zaproxy.addon.client.ClientCallBackUtils;
import org.zaproxy.zap.extension.selenium.BrowserHook;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;

/**
 * Tracks whether PTK should hold off attacking the target in a launched browser, because something
 * that runs on browser launch (e.g. authentication via the authhelper add-on) may still be in
 * progress.
 *
 * <p>The gate only holds when a running scan may authenticate on browser launch, when the installed
 * add-ons can report that the browser is ready, and until {@link #browserReady(String)} is called
 * for the browser or the scan ends. There is no timeout here, the PTK extension limits how long it
 * waits. Anything else is "not pending", which is the original behaviour of starting immediately.
 */
final class PtkStartGate {

    private final boolean supported;
    private final BooleanSupplier authenticationExpected;
    private final Set<String> ready = ConcurrentHashMap.newKeySet();

    /**
     * @param supported whether the installed add-ons will report when a browser is ready
     * @param authenticationExpected whether a running scan may authenticate on browser launch
     */
    PtkStartGate(boolean supported, BooleanSupplier authenticationExpected) {
        this.supported = supported;
        this.authenticationExpected = authenticationExpected;
    }

    /**
     * Whether the installed Selenium and Client add-ons will call {@code browserReady}. Older
     * versions will not, in which case the gate never holds.
     */
    static boolean isReadyApiAvailable() {
        try {
            BrowserHook.class.getMethod("browserReady", SeleniumScriptUtils.class);
            ClientCallBackImplementor.class.getMethod("browserReady", ClientCallBackUtils.class);
            return true;
        } catch (NoSuchMethodException | LinkageError e) {
            return false;
        }
    }

    boolean isSupported() {
        return supported;
    }

    boolean isAuthenticationExpected() {
        return authenticationExpected.getAsBoolean();
    }

    void browserReady(String zapid) {
        if (zapid != null) {
            ready.add(zapid);
        }
    }

    /** Forgets the state for the browser, call when it closes. */
    void forget(String zapid) {
        if (zapid != null) {
            ready.remove(zapid);
        }
    }

    boolean isPending(String zapid) {
        return supported
                && zapid != null
                && authenticationExpected.getAsBoolean()
                && !ready.contains(zapid);
    }
}
