package org.zaproxy.addon.ptk.options;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.ptk.PtkResourcesLoader;
import org.zaproxy.addon.ptk.PtkResourcesLoader.LoadedPtkResources;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.zap.common.VersionedAbstractParam;

/**
 * PTK add-on parameters persisted in the ZAP config file.
 *
 * <p>Scan-rule state is stored as hierarchical boolean flags under {@code ptk.scanrules}:
 *
 * <ul>
 *   <li>{@code ptk.scanrules.{engine}.enabled} — engine-level flag
 *   <li>{@code ptk.scanrules.{engine}.{moduleId}.enabled} — module-level flag
 *   <li>{@code ptk.scanrules.{engine}.{moduleId}.{ruleId}.enabled} — rule-level flag
 * </ul>
 *
 * <p>The default (no key present) is {@code true} (enabled). Inheritance: rule key wins over module
 * key wins over engine key wins over the default. Only {@code false} entries need to be written;
 * the default covers the {@code true} case. A child {@code true} can override a parent {@code
 * false} (useful with {@code -config} on the command line).
 *
 * <p>This format allows simple CLI configuration, e.g.:
 *
 * <pre>
 *   -config ptk.scanrules.IAST.enabled=false
 *   -config ptk.scanrules.DAST.enabled=false
 * </pre>
 *
 * <p><strong>Constraint:</strong> engine, module, and rule IDs must not contain dots, as dots are
 * used as node separators in the Apache Commons Configuration key syntax.
 */
public class PtkParam extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(PtkParam.class);
    private static final int CURRENT_CONFIG_VERSION = 2;

    private static final String BASE_KEY = "ptk";
    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;
    static final String SCAN_RULES_KEY = BASE_KEY + ".scanrules";
    // Key used by the v1 config format (positional path list); only read during migration.
    private static final String V1_CHECKED_LIST_KEY = SCAN_RULES_KEY + ".checked";
    private static final String AUTOMATED_SCANNING_ENABLED_KEY =
            BASE_KEY + ".automatedScanning.enabled";

    private boolean automatedScanningEnabled = false;

    @Override
    protected void parseImpl() {
        automatedScanningEnabled = getConfig().getBoolean(AUTOMATED_SCANNING_ENABLED_KEY, false);
        // Scan-rule flags are read on demand via isRuleEnabled / isModuleEnabled / isEngineEnabled.
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        switch (fileVersion) {
            case NO_CONFIG_VERSION:
                break;
            case 1:
                migrateV1ToV2();
                break;
            default:
                break;
        }
    }

    // -------------------------------------------------------------------------
    // Inheritance query methods
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} if the engine is enabled. Checks the engine-level key; defaults to
     * {@code true} if absent.
     */
    public boolean isEngineEnabled(String engine) {
        String key = engineKey(engine);
        if (getConfig().containsKey(key)) {
            return getConfig().getBoolean(key, true);
        }
        return true;
    }

    /**
     * Returns {@code true} if the module is enabled. Checks the module-level key first, then the
     * engine-level key, then defaults to {@code true}.
     */
    public boolean isModuleEnabled(String engine, String moduleId) {
        String mk = moduleKey(engine, moduleId);
        if (getConfig().containsKey(mk)) {
            return getConfig().getBoolean(mk, true);
        }
        return isEngineEnabled(engine);
    }

    /**
     * Returns {@code true} if the rule/attack is enabled. Checks the rule-level key first, then the
     * module-level key, then the engine-level key, then defaults to {@code true}.
     */
    public boolean isRuleEnabled(String engine, String moduleId, String ruleId) {
        String rk = ruleKey(engine, moduleId, ruleId);
        if (getConfig().containsKey(rk)) {
            return getConfig().getBoolean(rk, true);
        }
        return isModuleEnabled(engine, moduleId);
    }

    // -------------------------------------------------------------------------
    // Setters (write unconditionally; callers decide whether to write true/false)
    // -------------------------------------------------------------------------

    public void setEngineEnabled(String engine, boolean enabled) {
        getConfig().setProperty(engineKey(engine), enabled);
    }

    public void setModuleEnabled(String engine, String moduleId, boolean enabled) {
        getConfig().setProperty(moduleKey(engine, moduleId), enabled);
    }

    public void setRuleEnabled(String engine, String moduleId, String ruleId, boolean enabled) {
        getConfig().setProperty(ruleKey(engine, moduleId, ruleId), enabled);
    }

    // -------------------------------------------------------------------------
    // Bulk operations used by the options panel
    // -------------------------------------------------------------------------

    /**
     * Removes all scan-rule flags (everything under {@code ptk.scanrules.*}). Safe to call before
     * writing a fresh minimized set.
     */
    public void clearScanRulesConfig() {
        List<String> toRemove = new ArrayList<>();
        Iterator<String> it = getConfig().getKeys(SCAN_RULES_KEY);
        while (it.hasNext()) {
            toRemove.add(it.next());
        }
        for (String key : toRemove) {
            getConfig().clearProperty(key);
        }
    }

    /**
     * Clears all scan-rule flags and writes a minimal set derived from which leaf IDs (in {@code
     * "ENGINE/moduleId/ruleId"} format) are enabled. Called from the options panel after the user
     * saves.
     *
     * @param enabledLeafIds the set of fully-qualified leaf IDs that are checked
     * @param resources the loaded module definitions used to enumerate all possible rules
     */
    public void saveFromEnabledLeafs(Set<String> enabledLeafIds, LoadedPtkResources resources) {
        clearScanRulesConfig();
        writeMinimizedFlags(resources.getAllModuleDefinitions(), enabledLeafIds);
    }

    // -------------------------------------------------------------------------
    // automatedScanning
    // -------------------------------------------------------------------------

    public boolean isAutomatedScanningEnabled() {
        return automatedScanningEnabled;
    }

    public void setAutomatedScanningEnabled(boolean enabled) {
        this.automatedScanningEnabled = enabled;
        getConfig().setProperty(AUTOMATED_SCANNING_ENABLED_KEY, this.automatedScanningEnabled);
    }

    /**
     * Builds a stable cache key for the effective PTK config returned by {@code /ptk/config}. The
     * key changes whenever the automated-scanning mode or any enabled/disabled rule state changes.
     */
    public String buildConfigCacheKey(LoadedPtkResources resources) {
        StringBuilder key = new StringBuilder(512);
        key.append(automatedScanningEnabled ? "mode:auto" : "mode:manual");
        appendDefinitionCacheKey(key, resources != null ? resources.getSastModules() : null);
        appendDefinitionCacheKey(key, resources != null ? resources.getIastModules() : null);
        appendDefinitionCacheKey(key, resources != null ? resources.getDastModules() : null);
        return key.toString();
    }

    // -------------------------------------------------------------------------
    // Config version key
    // -------------------------------------------------------------------------

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    // -------------------------------------------------------------------------
    // Migration
    // -------------------------------------------------------------------------

    /**
     * Migrates from v1 to v2. v1 stored a list of checked positional paths (e.g. {@code "0/1/2"})
     * under {@code ptk.scanrules.checked}. Each 3-segment path is resolved to the corresponding
     * engine/module/rule using the current module definitions. The resulting enabled-leaf set is
     * then written as minimal v2 hierarchical flags via {@link #writeMinimizedFlags}. Parent paths
     * (1- or 2-segment) in the v1 list are ignored. Paths that no longer resolve to a known
     * rule/attack are silently dropped.
     */
    private void migrateV1ToV2() {
        List<?> oldPaths = getConfig().getList(V1_CHECKED_LIST_KEY);
        getConfig().clearProperty(V1_CHECKED_LIST_KEY);

        if (oldPaths == null || oldPaths.isEmpty()) {
            // Empty list means all rules were enabled — no flags needed (default is true).
            LOGGER.info("PTK v1→v2: empty path list, all rules remain default-enabled");
            return;
        }

        LoadedPtkResources resources = new PtkResourcesLoader().loadAll();
        List<PtkModulesDefinition> defs = resources.getAllModuleDefinitions();

        // Resolve each 3-segment positional path to an "ENGINE/moduleId/ruleId" leaf ID.
        Set<String> enabledLeafIds = new HashSet<>();
        for (Object o : oldPaths) {
            if (o == null) continue;
            String[] parts = o.toString().trim().split("/");
            if (parts.length != 3) continue; // skip parent paths ("0", "0/1")
            try {
                int engineIdx = Integer.parseInt(parts[0]);
                int moduleIdx = Integer.parseInt(parts[1]);
                int childIdx = Integer.parseInt(parts[2]);
                if (engineIdx < 0 || engineIdx >= defs.size()) continue;
                PtkModulesDefinition def = defs.get(engineIdx);
                List<PtkModule> modules = def.getModules();
                if (modules == null || moduleIdx >= modules.size()) continue;
                PtkModule mod = modules.get(moduleIdx);
                int numRules = mod.getRules() != null ? mod.getRules().size() : 0;
                String childId;
                if (childIdx < numRules) {
                    childId = mod.getRules().get(childIdx).getId();
                } else {
                    int attackIdx = childIdx - numRules;
                    if (mod.getAttacks() == null || attackIdx >= mod.getAttacks().size()) continue;
                    childId = mod.getAttacks().get(attackIdx).getId();
                }
                if (def.getEngine() != null && mod.getId() != null && childId != null) {
                    enabledLeafIds.add(def.getEngine() + "/" + mod.getId() + "/" + childId);
                }
            } catch (NumberFormatException e) {
                LOGGER.debug("Skipping non-numeric v1 path during migration: {}", o);
            }
        }

        if (enabledLeafIds.isEmpty()) {
            // None of the v1 entries resolved to a known rule (e.g. they were non-positional
            // strings from an intermediate format). Treat as all-enabled rather than disabling
            // every engine.
            LOGGER.warn(
                    "PTK v1→v2: no paths resolved from {} v1 entries; treating as all-enabled",
                    oldPaths.size());
            return;
        }

        writeMinimizedFlags(defs, enabledLeafIds);
        LOGGER.info(
                "PTK v1→v2: {} positional paths → {} enabled leaf IDs → hierarchical flags",
                oldPaths.size(),
                enabledLeafIds.size());

        // Persist immediately so the migrated config survives an unclean ZAP exit.
        try {
            getConfig().save();
            LOGGER.info("PTK v1→v2: migrated config saved to disk");
        } catch (ConfigurationException e) {
            LOGGER.warn("PTK v1→v2: could not save migrated config to disk", e);
        }
    }

    // -------------------------------------------------------------------------
    // Minimization algorithm (shared by saveFromEnabledLeafs and migrateV1ToV2)
    // -------------------------------------------------------------------------

    /**
     * Writes the minimal set of {@code enabled=false} flags to represent which rules are disabled,
     * given the set of enabled leaf IDs ({@code "ENGINE/moduleId/ruleId"}).
     *
     * <p>Minimization rules (applied top-down):
     *
     * <ol>
     *   <li>If no leaves in an engine are enabled → write one engine-level {@code false}.
     *   <li>Else if no leaves in a module are enabled → write one module-level {@code false}.
     *   <li>Else for each disabled leaf → write one rule-level {@code false}.
     * </ol>
     *
     * <p>Fully-enabled engines, modules, and rules require no config (the default is {@code true}).
     */
    private void writeMinimizedFlags(List<PtkModulesDefinition> defs, Set<String> enabledLeafIds) {
        for (PtkModulesDefinition def : defs) {
            if (def == null || def.getModules() == null) continue;
            String engine = def.getEngine();
            if (engine == null) continue;

            List<String> engineLeafs = collectLeafIds(engine, def.getModules());
            if (engineLeafs.isEmpty()) continue;

            boolean anyEnabledInEngine = engineLeafs.stream().anyMatch(enabledLeafIds::contains);
            if (!anyEnabledInEngine) {
                setEngineEnabled(engine, false);
                continue;
            }

            for (PtkModule mod : def.getModules()) {
                if (mod.getId() == null) continue;
                String moduleId = mod.getId();
                List<String> moduleLeafs = collectLeafIds(engine, moduleId, mod);
                if (moduleLeafs.isEmpty()) continue;

                boolean anyEnabledInModule =
                        moduleLeafs.stream().anyMatch(enabledLeafIds::contains);
                if (!anyEnabledInModule) {
                    setModuleEnabled(engine, moduleId, false);
                    continue;
                }

                for (String leafId : moduleLeafs) {
                    if (!enabledLeafIds.contains(leafId)) {
                        String ruleId = leafId.substring(leafId.lastIndexOf('/') + 1);
                        setRuleEnabled(engine, moduleId, ruleId, false);
                    }
                }
            }
        }
    }

    /** Returns all {@code "ENGINE/moduleId/ruleId"} strings across all modules in the engine. */
    private static List<String> collectLeafIds(String engine, List<PtkModule> modules) {
        List<String> result = new ArrayList<>();
        for (PtkModule mod : modules) {
            if (mod.getId() != null) {
                result.addAll(collectLeafIds(engine, mod.getId(), mod));
            }
        }
        return result;
    }

    /** Returns all {@code "ENGINE/moduleId/ruleId"} strings for a single module. */
    static List<String> collectLeafIds(String engine, String moduleId, PtkModule mod) {
        List<String> result = new ArrayList<>();
        if (mod.getRules() != null) {
            for (PtkRule r : mod.getRules()) {
                if (r.getId() != null) result.add(engine + "/" + moduleId + "/" + r.getId());
            }
        }
        if (mod.getAttacks() != null) {
            for (PtkAttack a : mod.getAttacks()) {
                if (a.getId() != null) result.add(engine + "/" + moduleId + "/" + a.getId());
            }
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Key builders
    // -------------------------------------------------------------------------

    private static String engineKey(String engine) {
        return SCAN_RULES_KEY + "." + engine + ".enabled";
    }

    private static String moduleKey(String engine, String moduleId) {
        return SCAN_RULES_KEY + "." + engine + "." + moduleId + ".enabled";
    }

    private static String ruleKey(String engine, String moduleId, String ruleId) {
        return SCAN_RULES_KEY + "." + engine + "." + moduleId + "." + ruleId + ".enabled";
    }

    private void appendDefinitionCacheKey(StringBuilder key, PtkModulesDefinition def) {
        if (def == null || def.getModules() == null) {
            return;
        }
        String engine = def.getEngine();
        if (engine == null) {
            return;
        }
        key.append('|').append(engine);
        for (PtkModule mod : def.getModules()) {
            if (mod == null || mod.getId() == null) {
                continue;
            }
            key.append('|').append(mod.getId()).append('=');
            appendLeafCacheKey(key, engine, mod.getId(), mod.getRules());
            appendLeafCacheKey(key, engine, mod.getId(), mod.getAttacks());
        }
    }

    private void appendLeafCacheKey(
            StringBuilder key, String engine, String moduleId, List<?> leafs) {
        if (leafs == null) {
            return;
        }
        for (Object leaf : leafs) {
            String leafId = null;
            if (leaf instanceof PtkRule) {
                leafId = ((PtkRule) leaf).getId();
            } else if (leaf instanceof PtkAttack) {
                leafId = ((PtkAttack) leaf).getId();
            }
            if (leafId == null) {
                continue;
            }
            key.append(leafId)
                    .append(':')
                    .append(isRuleEnabled(engine, moduleId, leafId) ? '1' : '0')
                    .append(',');
        }
    }
}
