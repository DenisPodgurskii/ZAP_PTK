package org.zaproxy.addon.ptk.options;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.common.VersionedAbstractParam;

/**
 * PTK add-on parameters persisted in the ZAP config file. Stores the scan rules tree checkbox state
 * as a list of path strings (e.g. "0", "0/1", "0/1/2") where each segment is the child index from
 * the root.
 */
public class PtkParam extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(PtkParam.class);
    private static final int CURRENT_CONFIG_VERSION = 1;

    private static final String BASE_KEY = "ptk";
    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;
    private static final String SCAN_RULES_CHECKED_KEY = BASE_KEY + ".scanrules.checked";
    private static final String AUTOMATED_SCANNING_ENABLED_KEY =
            BASE_KEY + ".automatedScanning.enabled";

    /** Path strings of checked nodes (e.g. "0", "0/1"). Empty means use default (all checked). */
    private Set<String> checkedPathStrings = new HashSet<>();

    /** When false, the config URL returns empty objects for dast, iast, and sast. Default false. */
    private boolean automatedScanningEnabled = false;

    @Override
    protected void parseImpl() {
        checkedPathStrings = new HashSet<>();
        automatedScanningEnabled = false;
        List<?> list = getConfig().getList(SCAN_RULES_CHECKED_KEY);
        if (list != null) {
            for (Object o : list) {
                if (o != null) {
                    checkedPathStrings.add(o.toString().trim());
                }
            }
        }
        automatedScanningEnabled = getConfig().getBoolean(AUTOMATED_SCANNING_ENABLED_KEY, false);
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // first version, nothing to update yet
    }

    /**
     * Returns the set of checked path strings. Empty set means no saved state (default to all
     * checked when loading the panel).
     */
    public Set<String> getCheckedPathStrings() {
        return Collections.unmodifiableSet(checkedPathStrings);
    }

    public boolean isAutomatedScanningEnabled() {
        return automatedScanningEnabled;
    }

    public void setAutomatedScanningEnabled(boolean enabled) {
        this.automatedScanningEnabled = enabled;
        getConfig().setProperty(AUTOMATED_SCANNING_ENABLED_KEY, this.automatedScanningEnabled);
    }

    /**
     * Sets the checked path strings and persists to the ZAP config file.
     *
     * @param paths path strings (e.g. "0", "0/1/2")
     */
    public void setCheckedPathStrings(Set<String> paths) {
        this.checkedPathStrings = paths != null ? new HashSet<>(paths) : new HashSet<>();
        getConfig().setProperty(SCAN_RULES_CHECKED_KEY, new ArrayList<>(this.checkedPathStrings));
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }
}
