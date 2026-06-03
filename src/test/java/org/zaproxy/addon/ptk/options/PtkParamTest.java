package org.zaproxy.addon.ptk.options;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link PtkParam}. */
class PtkParamTest {

    // IDs from the bundled JSON resources (verified against actual files).
    // SAST engine, module 0 = dom-xss; rules[0]=no-inner-outer-html, rules[2]=no-document-write
    // IAST engine, module 0 = iast_dom_xss; rules[0]=dom_inline_event_handler
    private static final String SAST = "SAST";
    private static final String IAST = "IAST";
    private static final String DAST = "DAST";
    private static final String SAST_MOD = "dom-xss";
    private static final String SAST_RULE_0 = "no-inner-outer-html";
    private static final String SAST_RULE_2 = "no-document-write";
    private static final String IAST_MOD = "iast_dom_xss";
    private static final String IAST_RULE_0 = "dom_inline_event_handler";

    private ZapXmlConfiguration config;
    private PtkParam param;

    @BeforeEach
    void setUp() {
        config = new ZapXmlConfiguration();
        param = new PtkParam();
        param.load(config);
    }

    // --- defaults ---

    @Test
    void freshConfig_allEnabled() {
        assertTrue(param.isEngineEnabled(SAST));
        assertTrue(param.isModuleEnabled(SAST, SAST_MOD));
        assertTrue(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertFalse(param.isAutomatedScanningEnabled());
        assertFalse(param.isActiveScanRuleEnabled());
        assertEquals(PtkParam.DEFAULT_ACTIVE_SCAN_BROWSER_ID, param.getActiveScanBrowserId());
        assertEquals(
                PtkParam.DEFAULT_ACTIVE_SCAN_ACTION_WAIT_TIME,
                param.getActiveScanActionWaitTimeInSecs());
        assertEquals(PtkParam.getDefaultActiveScanThreadCount(), param.getActiveScanThreadCount());
    }

    @Test
    void activeScanOptions_persistedAndReloaded() {
        param.setActiveScanRuleEnabled(true);
        param.setActiveScanBrowserId(ClientOptions.DEFAULT_BROWSER_ID);
        param.setActiveScanActionWaitTimeInSecs(5);
        param.setActiveScanThreadCount(3);

        PtkParam reloaded = new PtkParam();
        reloaded.load(config);

        assertTrue(reloaded.isActiveScanRuleEnabled());
        assertEquals(ClientOptions.DEFAULT_BROWSER_ID, reloaded.getActiveScanBrowserId());
        assertEquals(5, reloaded.getActiveScanActionWaitTimeInSecs());
        assertEquals(3, reloaded.getActiveScanThreadCount());
    }

    @Test
    void activeScanThreadCount_minimumIsOne() {
        param.setActiveScanThreadCount(0);
        assertEquals(1, param.getActiveScanThreadCount());
    }

    @Test
    void unknownActiveScanBrowser_fallsBackToDefault() {
        config.setProperty("ptk.activescan.browserId", "not-a-real-browser");
        PtkParam reloaded = new PtkParam();
        reloaded.load(config);
        assertEquals(PtkParam.DEFAULT_ACTIVE_SCAN_BROWSER_ID, reloaded.getActiveScanBrowserId());
    }

    // --- engine-level flag ---

    @Test
    void engineFalse_disablesModuleAndRule() {
        param.setEngineEnabled(SAST, false);
        assertFalse(param.isEngineEnabled(SAST));
        assertFalse(param.isModuleEnabled(SAST, SAST_MOD));
        assertFalse(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
    }

    @Test
    void engineFalse_doesNotAffectOtherEngine() {
        param.setEngineEnabled(SAST, false);
        assertTrue(param.isEngineEnabled(IAST));
        assertTrue(param.isRuleEnabled(IAST, IAST_MOD, IAST_RULE_0));
    }

    @Test
    void engineFalse_persistedAndReloaded() {
        param.setEngineEnabled(SAST, false);
        PtkParam reloaded = new PtkParam();
        reloaded.load(config);
        assertFalse(reloaded.isEngineEnabled(SAST));
        assertFalse(reloaded.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
    }

    // --- module-level flag ---

    @Test
    void moduleFalse_disablesRulesInThatModule() {
        param.setModuleEnabled(SAST, SAST_MOD, false);
        assertFalse(param.isModuleEnabled(SAST, SAST_MOD));
        assertFalse(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertFalse(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_2));
    }

    @Test
    void moduleFalse_doesNotDisableEngine() {
        param.setModuleEnabled(SAST, SAST_MOD, false);
        assertTrue(param.isEngineEnabled(SAST));
    }

    // --- rule-level flag ---

    @Test
    void ruleFalse_disablesOnlyThatRule() {
        param.setRuleEnabled(SAST, SAST_MOD, SAST_RULE_0, false);
        assertFalse(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertTrue(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_2));
        assertTrue(param.isModuleEnabled(SAST, SAST_MOD));
        assertTrue(param.isEngineEnabled(SAST));
    }

    // --- child overrides parent ---

    @Test
    void ruleTrueOverridesModuleFalse() {
        param.setModuleEnabled(SAST, SAST_MOD, false);
        param.setRuleEnabled(SAST, SAST_MOD, SAST_RULE_0, true);
        assertTrue(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertFalse(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_2));
    }

    @Test
    void ruleTrueOverridesEngineFalse() {
        param.setEngineEnabled(SAST, false);
        param.setRuleEnabled(SAST, SAST_MOD, SAST_RULE_0, true);
        assertTrue(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertFalse(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_2));
    }

    @Test
    void moduleTrueOverridesEngineFalse() {
        param.setEngineEnabled(SAST, false);
        param.setModuleEnabled(SAST, SAST_MOD, true);
        assertTrue(param.isModuleEnabled(SAST, SAST_MOD));
        assertTrue(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
    }

    // --- clearScanRulesConfig ---

    @Test
    void clearScanRulesConfig_removesAllFlags() {
        param.setEngineEnabled(SAST, false);
        param.setModuleEnabled(IAST, IAST_MOD, false);
        param.setRuleEnabled(SAST, SAST_MOD, SAST_RULE_0, false);

        param.clearScanRulesConfig();

        assertTrue(param.isEngineEnabled(SAST));
        assertTrue(param.isModuleEnabled(IAST, IAST_MOD));
        assertTrue(param.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        // Version key must not be affected
        assertEquals(2, config.getInt("ptk[@version]"));
        // No keys left under ptk.scanrules
        Iterator<String> remaining = config.getKeys(PtkParam.SCAN_RULES_KEY);
        assertFalse(remaining.hasNext());
    }

    // --- automatedScanning ---

    @Test
    void automatedScanning_roundTrip() {
        param.setAutomatedScanningEnabled(true);
        PtkParam reloaded = new PtkParam();
        reloaded.load(config);
        assertTrue(reloaded.isAutomatedScanningEnabled());
    }

    @Test
    void zapAutomationEnabled_whenDeprecatedAutomatedScanningEnabled() {
        param.setAutomatedScanningEnabled(true);
        assertTrue(param.isZapAutomationEnabled());
    }

    @Test
    void zapAutomationEnabled_whenActiveScanRuleEnabled() {
        param.setActiveScanRuleEnabled(true);
        assertTrue(param.isZapAutomationEnabled());
    }

    @Test
    void configCacheKey_changesWhenActiveScanRuleModeChanges() {
        String manualKey = param.buildConfigCacheKey(null);

        param.setActiveScanRuleEnabled(true);
        String activeRuleKey = param.buildConfigCacheKey(null);

        assertFalse(activeRuleKey.equals(manualKey));
        assertTrue(activeRuleKey.startsWith("mode:auto"));
    }

    // --- migration: v1 → v2 ---

    @Test
    void migration_fromV1_convertsPositionalPathsToHierarchicalFlags() {
        // v1: "0/0/0" = SAST/dom-xss/no-inner-outer-html; "0/0/2" = SAST/dom-xss/no-document-write
        // "1/0/0" = IAST/iast_dom_xss/dom_inline_event_handler
        // Parent paths ("0", "0/0") must be ignored (not 3 segments).
        config.setProperty("ptk[@version]", 1);
        config.setProperty("ptk.scanrules.checked", List.of("0", "0/0", "0/0/0", "0/0/2", "1/0/0"));

        PtkParam migrated = new PtkParam();
        migrated.load(config);

        // Explicitly checked rules must remain enabled
        assertTrue(migrated.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertTrue(migrated.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_2));
        assertTrue(migrated.isRuleEnabled(IAST, IAST_MOD, IAST_RULE_0));

        // Rules NOT in the v1 list must be disabled
        assertFalse(migrated.isRuleEnabled(SAST, SAST_MOD, "no-appendchild"));

        assertEquals(2, config.getInt("ptk[@version]"));
        assertFalse(config.containsKey("ptk.scanrules.checked"));
    }

    @Test
    void migration_fromV1_emptyList_noFlagsWritten() {
        config.setProperty("ptk[@version]", 1);
        // No checked paths — all rules were enabled

        PtkParam migrated = new PtkParam();
        migrated.load(config);

        assertTrue(migrated.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertEquals(2, config.getInt("ptk[@version]"));
        assertFalse(config.getKeys(PtkParam.SCAN_RULES_KEY).hasNext());
    }

    @Test
    void migration_fromV1_unrecognisedPositions_silentlyDropped() {
        config.setProperty("ptk[@version]", 1);
        // "9/9/9" is out of range; "0/0/0" is valid
        config.setProperty("ptk.scanrules.checked", List.of("9/9/9", "0/0/0"));

        PtkParam migrated = new PtkParam();
        migrated.load(config);

        assertTrue(migrated.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        // "9/9/9" dropped: DAST should be entirely disabled (no enabled rules found there)
        assertFalse(migrated.isEngineEnabled(DAST));
    }

    @Test
    void migration_fromV1_engineFullyDisabled_writesEngineLevelFlag() {
        // Only one SAST rule is enabled; IAST and DAST have no enabled rules → engine-level false.
        config.setProperty("ptk[@version]", 1);
        config.setProperty(
                "ptk.scanrules.checked", List.of("0/0/0")); // SAST/dom-xss/no-inner-outer-html only

        PtkParam migrated = new PtkParam();
        migrated.load(config);

        assertFalse(migrated.isEngineEnabled(IAST));
        assertFalse(migrated.isEngineEnabled(DAST));
        assertTrue(migrated.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
    }

    @Test
    void migration_fromV1_nonPositionalEntries_allRulesRemainEnabled() {
        // If v1 entries are ID strings (not integers), none resolve → treat as all-enabled.
        config.setProperty("ptk[@version]", 1);
        config.setProperty(
                "ptk.scanrules.checked",
                List.of(
                        "SAST/dom-xss/no-inner-outer-html",
                        "IAST/iast_dom_xss/dom_inline_event_handler"));

        PtkParam migrated = new PtkParam();
        migrated.load(config);

        assertTrue(migrated.isEngineEnabled(SAST));
        assertTrue(migrated.isEngineEnabled(IAST));
        assertTrue(migrated.isEngineEnabled(DAST));
        assertTrue(migrated.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertEquals(2, config.getInt("ptk[@version]"));
    }

    @Test
    void migration_fromV1_configVersionUpdatedAfterMigration() {
        // After migration the in-memory config must reflect version 2 so a reload
        // does not re-run the migration.
        config.setProperty("ptk[@version]", 1);
        config.setProperty("ptk.scanrules.checked", List.of("0/0/0"));

        PtkParam migrated = new PtkParam();
        migrated.load(config);

        assertEquals(2, config.getInt("ptk[@version]"));

        // Loading again from the same (already-migrated) config object must not re-disable rules.
        PtkParam reloaded = new PtkParam();
        reloaded.load(config);
        assertTrue(reloaded.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
    }

    @Test
    void migration_fromV1_automatedScanningPreserved() {
        config.setProperty("ptk[@version]", 1);
        config.setProperty("ptk.automatedScanning.enabled", true);

        PtkParam migrated = new PtkParam();
        migrated.load(config);

        assertTrue(migrated.isAutomatedScanningEnabled());
    }

    // --- new install ---

    @Test
    void noVersion_treatedAsNewInstall_allEnabled() {
        PtkParam fresh = new PtkParam();
        fresh.load(new ZapXmlConfiguration());

        assertTrue(fresh.isRuleEnabled(SAST, SAST_MOD, SAST_RULE_0));
        assertTrue(fresh.isEngineEnabled(IAST));
    }
}
