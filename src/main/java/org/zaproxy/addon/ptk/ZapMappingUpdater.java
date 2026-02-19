package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.zaproxy.addon.ptk.model.EngineMapping;
import org.zaproxy.addon.ptk.model.ModuleRuleMapping;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.addon.ptk.model.ZapMappingDefinition;

/**
 * Updates zap-mapping.json from the module definition files. Preserves existing base alert IDs and
 * rule→subId mappings; only adds new modules and new rules with new IDs.
 *
 * <p>Usage: path to zap-mapping.json as first argument (module files are read from the same
 * directory).
 */
public final class ZapMappingUpdater {

    private static final String SAST_MODULES = "sast-modules.json";
    private static final String IAST_MODULES = "iast-modules.json";
    private static final String DAST_MODULES = "dast-modules.json";

    private static final int BASE_DAST = 200000;
    private static final int BASE_IAST = 210000;
    private static final int BASE_SAST = 220000;

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.err.println("Usage: ZapMappingUpdater <path-to-zap-mapping.json>");
            System.exit(1);
        }
        Path mappingPath = Path.of(args[0]);
        Path dir = mappingPath.getParent();
        if (!Files.isDirectory(dir)) {
            System.err.println("Directory not found: " + dir);
            System.exit(1);
        }

        ZapMappingDefinition existing = readMapping(mappingPath);
        PtkModulesDefinition sast = readModules(dir, SAST_MODULES);
        PtkModulesDefinition iast = readModules(dir, IAST_MODULES);
        PtkModulesDefinition dast = readModules(dir, DAST_MODULES);

        ZapMappingDefinition updated = merge(existing, sast, iast, dast);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        Files.createDirectories(mappingPath.getParent());
        Files.writeString(mappingPath, gson.toJson(updated), StandardCharsets.UTF_8);
        System.out.println("Updated " + mappingPath);
    }

    static ZapMappingDefinition readMapping(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            return null;
        }
        String json = Files.readString(path, StandardCharsets.UTF_8);
        return new Gson().fromJson(json, ZapMappingDefinition.class);
    }

    static PtkModulesDefinition readModules(Path dir, String name) throws IOException {
        Path path = dir.resolve(name);
        if (!Files.isRegularFile(path)) {
            return null;
        }
        String json = Files.readString(path, StandardCharsets.UTF_8);
        return new Gson().fromJson(json, PtkModulesDefinition.class);
    }

    static ZapMappingDefinition merge(
            ZapMappingDefinition existing,
            PtkModulesDefinition sast,
            PtkModulesDefinition iast,
            PtkModulesDefinition dast) {
        ZapMappingDefinition out = new ZapMappingDefinition();
        out.setSchema("ptk-zap-mapping-v1");
        out.setVersion(1);

        List<EngineMapping> engines = new ArrayList<>();
        engines.add(mergeEngine("DAST", BASE_DAST, existing, dast));
        engines.add(mergeEngine("IAST", BASE_IAST, existing, iast));
        engines.add(mergeEngine("SAST", BASE_SAST, existing, sast));
        out.setEngines(engines);
        return out;
    }

    private static EngineMapping mergeEngine(
            String engine,
            int defaultBaseId,
            ZapMappingDefinition existing,
            PtkModulesDefinition def) {
        EngineMapping result = new EngineMapping();
        result.setEngine(engine);

        Map<String, ModuleRuleMapping> existingByModule = new LinkedHashMap<>();
        int maxBaseId = defaultBaseId - 1;
        if (existing != null && existing.getEngines() != null) {
            for (EngineMapping em : existing.getEngines()) {
                if (!engine.equals(em.getEngine())) continue;
                if (em.getModuleMappings() != null) {
                    for (ModuleRuleMapping mrm : em.getModuleMappings()) {
                        existingByModule.put(mrm.getModuleId(), mrm);
                        if (mrm.getBaseAlertId() > maxBaseId) {
                            maxBaseId = mrm.getBaseAlertId();
                        }
                    }
                } else if (em.getMappings() != null) {
                    for (Map.Entry<String, Integer> e : em.getMappings().entrySet()) {
                        ModuleRuleMapping mrm = new ModuleRuleMapping();
                        mrm.setModuleId(e.getKey());
                        mrm.setBaseAlertId(e.getValue());
                        mrm.setRules(new LinkedHashMap<>());
                        existingByModule.put(e.getKey(), mrm);
                        if (e.getValue() > maxBaseId) {
                            maxBaseId = e.getValue();
                        }
                    }
                }
                break;
            }
        }

        List<ModuleRuleMapping> merged = new ArrayList<>();
        int nextBaseId = maxBaseId + 1;

        if (def != null && def.getModules() != null) {
            for (PtkModule m : def.getModules()) {
                if (m.getId() == null) continue;
                ModuleRuleMapping mrm = existingByModule.get(m.getId());
                if (mrm != null) {
                    merged.add(mergeModuleRules(mrm, m));
                } else {
                    ModuleRuleMapping newMrm = new ModuleRuleMapping();
                    newMrm.setModuleId(m.getId());
                    newMrm.setBaseAlertId(nextBaseId++);
                    newMrm.setRules(collectRuleSubIds(m, null));
                    merged.add(newMrm);
                }
            }
        }

        result.setModuleMappings(merged);
        return result;
    }

    /** Keeps existing baseAlertId and rule→subId; adds new rules with next available subIds. */
    private static ModuleRuleMapping mergeModuleRules(
            ModuleRuleMapping existing, PtkModule module) {
        ModuleRuleMapping out = new ModuleRuleMapping();
        out.setModuleId(existing.getModuleId());
        out.setBaseAlertId(existing.getBaseAlertId());
        Map<String, Integer> rules =
                existing.getRules() != null
                        ? new LinkedHashMap<>(existing.getRules())
                        : new LinkedHashMap<>();
        int nextSubId =
                rules.isEmpty() ? 1 : rules.values().stream().max(Integer::compareTo).orElse(0) + 1;
        if (module.getRules() != null) {
            for (PtkRule r : module.getRules()) {
                if (r.getId() != null && !rules.containsKey(r.getId())) {
                    rules.put(r.getId(), nextSubId++);
                }
            }
        }
        if (module.getAttacks() != null) {
            for (PtkAttack a : module.getAttacks()) {
                if (a.getId() != null && !rules.containsKey(a.getId())) {
                    rules.put(a.getId(), nextSubId++);
                }
            }
        }
        if (rules.isEmpty() && module.getId() != null) {
            rules.put(module.getId(), 1);
        }
        out.setRules(rules);
        return out;
    }

    /**
     * Collects rule/attack ids. If existing is provided, keeps existing subIds; else assigns
     * 1,2,3...
     */
    private static Map<String, Integer> collectRuleSubIds(
            PtkModule m, Map<String, Integer> existing) {
        Map<String, Integer> out = new LinkedHashMap<>();
        int subId = 1;
        if (m.getRules() != null) {
            for (PtkRule r : m.getRules()) {
                if (r.getId() == null) continue;
                if (existing != null && existing.containsKey(r.getId())) {
                    out.put(r.getId(), existing.get(r.getId()));
                } else {
                    out.put(r.getId(), subId++);
                }
            }
        }
        if (m.getAttacks() != null) {
            for (PtkAttack a : m.getAttacks()) {
                if (a.getId() == null) continue;
                if (existing != null && existing.containsKey(a.getId())) {
                    out.put(a.getId(), existing.get(a.getId()));
                } else {
                    out.put(a.getId(), subId++);
                }
            }
        }
        if (out.isEmpty() && m.getId() != null) {
            out.put(m.getId(), 1);
        }
        return out;
    }
}
