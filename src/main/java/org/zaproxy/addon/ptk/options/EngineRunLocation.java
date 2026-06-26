package org.zaproxy.addon.ptk.options;

import java.util.Locale;
import org.parosproxy.paros.Constant;

/** Where a PTK engine runs during a scan. */
public enum EngineRunLocation {
    CLIENT_SPIDER,
    ACTIVE_SCAN_RULE,
    MANUAL;

    @Override
    public String toString() {
        return Constant.messages.getString(
                "ptk.options.runLocation." + name().toLowerCase(Locale.ROOT));
    }
}
