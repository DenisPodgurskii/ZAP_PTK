package org.zaproxy.addon.ptk.gspm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSource;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar;
import org.zaproxy.addon.commonlib.gspm.GspmScanRuleRegistrar.RuleOwner;
import org.zaproxy.addon.ptk.PtkAlertBuilder;
import org.zaproxy.addon.ptk.PtkConfigFilter;
import org.zaproxy.addon.ptk.PtkResourcesLoader.LoadedPtkResources;
import org.zaproxy.addon.ptk.model.EngineMapping;
import org.zaproxy.addon.ptk.model.ModuleRuleMapping;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.ZapMappingDefinition;
import org.zaproxy.addon.ptk.options.PtkParam;
import org.zaproxy.zap.control.AddOn;

/**
 * Registers the PTK modules with the Global Scan Policy Manager (GSPM) in commonlib.
 *
 * <p>Each PTK engine is registered as its own GSPM tool ({@code ptk-dast}, {@code ptk-iast}, {@code
 * ptk-sast}). Each module is one GSPM rule, identified by its existing ZAP alert id (the module's
 * {@code baseAlertId} in {@code zap-mapping.json}); the module's rules/attacks are its alert
 * references, which GSPM does not model individually, as with ZAP's own scan rules. Rules are shown
 * under "Active / Client Browser / DAST", "Active / Client Browser / IAST" and "Passive / Client
 * Browser / SAST".
 *
 * <p>For now the rules are read-only: they reflect PTK's own configuration, but changes made via
 * GSPM are not applied to PTK.
 */
public class GspmPtkRegistrar {

    private static final Logger LOGGER = LogManager.getLogger(GspmPtkRegistrar.class);

    /**
     * The id of the top-level category of all PTK rules. The same id as ZAP's own "Client Browser"
     * active scan rule category, so that the PTK DAST and IAST rules are shown in the same "Active
     * / Client Browser" node as those rules.
     */
    static final String CATEGORY_CLIENT_BROWSER = "browser";

    /** The PTK engines, each registered as a separate GSPM tool. */
    enum Engine {
        DAST(GspmPhase.ACTIVE),
        IAST(GspmPhase.ACTIVE),
        SAST(GspmPhase.PASSIVE);

        private final GspmPhase phase;

        Engine(GspmPhase phase) {
            this.phase = phase;
        }

        GspmPhase getPhase() {
            return phase;
        }

        /** The id of the engine's category and the suffix of its tool id, e.g. {@code dast}. */
        String getKey() {
            return name().toLowerCase(Locale.ROOT);
        }

        String getToolId() {
            return "ptk-" + getKey();
        }

        PtkModulesDefinition getModules(LoadedPtkResources resources) {
            return switch (this) {
                case DAST -> resources.getDastModules();
                case IAST -> resources.getIastModules();
                case SAST -> resources.getSastModules();
            };
        }
    }

    private final UnaryOperator<String> messages;
    private final Supplier<String> clientBrowserName;
    private final Supplier<LoadedPtkResources> resources;
    private final Supplier<PtkParam> param;
    private final AddOn addOn;
    private final List<GspmScanRuleRegistrar> registrars = new ArrayList<>();

    /**
     * @param resources supplies the PTK module definitions and ZAP mapping
     * @param param supplies PTK's configuration, used to report whether each module is enabled
     * @param addOn the PTK add-on, used for the rules' status and add-on name; may be {@code null}
     */
    public GspmPtkRegistrar(
            Supplier<LoadedPtkResources> resources, Supplier<PtkParam> param, AddOn addOn) {
        this(
                Constant.messages::getString,
                () -> Category.getName(Category.BROWSER),
                resources,
                param,
                addOn);
    }

    /**
     * @param messages returns the i18n message for a key
     * @param clientBrowserName supplies the display name of the "Client Browser" category, the same
     *     as ZAP's own, so the shared node has the same name whichever tool's rules are registered
     *     first
     */
    GspmPtkRegistrar(
            UnaryOperator<String> messages,
            Supplier<String> clientBrowserName,
            Supplier<LoadedPtkResources> resources,
            Supplier<PtkParam> param,
            AddOn addOn) {
        this.messages = messages;
        this.clientBrowserName = clientBrowserName;
        this.resources = resources;
        this.param = param;
        this.addOn = addOn;
        for (Engine engine : Engine.values()) {
            registrars.add(
                    new GspmScanRuleRegistrar(
                            engine.getToolId(),
                            () -> messages.apply("ptk.gspm.tool." + engine.getKey()),
                            engine.getPhase(),
                            () -> getRules(engine),
                            // The rules are bundled with PTK itself, not contributed by other
                            // add-ons, so there is nothing to add on other add-on installs.
                            a -> List.of()));
        }
    }

    /** Returns the GSPM rule sources, one per engine. */
    List<? extends GspmRuleSource> getRuleSources() {
        return registrars;
    }

    /** Registers the PTK rules with GSPM. */
    public void register(ExtensionCommonlib commonlib) {
        registrars.forEach(commonlib::registerGspmRuleSource);
    }

    /** Unregisters the PTK rules from GSPM. */
    public void unregister(ExtensionCommonlib commonlib) {
        registrars.forEach(commonlib::unregisterGspmRuleSource);
    }

    List<RuleOwner> getRules(Engine engine) {
        LoadedPtkResources res = resources.get();
        PtkModulesDefinition def = engine.getModules(res);
        if (def == null || def.getModules() == null) {
            return List.of();
        }
        Map<String, Integer> alertIds = getModuleAlertIds(res.getZapMapping(), engine);
        List<GspmCategory> categories =
                List.of(
                        new GspmCategory(CATEGORY_CLIENT_BROWSER, clientBrowserName.get()),
                        new GspmCategory(
                                engine.getKey(),
                                messages.apply("ptk.gspm.category." + engine.getKey())));
        List<RuleOwner> rules = new ArrayList<>();
        for (PtkModule module : def.getModules()) {
            Integer id = alertIds.get(module.getId());
            if (id == null) {
                LOGGER.debug("No ZAP alert id for PTK {} module {}", engine, module.getId());
                continue;
            }
            rules.add(new RuleOwner(new PtkGspmRule(id, engine, module, categories), null));
        }
        return rules;
    }

    /** Returns the module id → ZAP alert id (base alert id) for the given engine. */
    static Map<String, Integer> getModuleAlertIds(ZapMappingDefinition mapping, Engine engine) {
        Map<String, Integer> ids = new HashMap<>();
        if (mapping == null || mapping.getEngines() == null) {
            return ids;
        }
        for (EngineMapping em : mapping.getEngines()) {
            if (!engine.name().equalsIgnoreCase(em.getEngine())) {
                continue;
            }
            if (em.getModuleMappings() != null && !em.getModuleMappings().isEmpty()) {
                for (ModuleRuleMapping mm : em.getModuleMappings()) {
                    ids.put(mm.getModuleId(), mm.getBaseAlertId());
                }
            } else if (em.getMappings() != null) {
                ids.putAll(em.getMappings());
            }
        }
        return ids;
    }

    private final class PtkGspmRule implements GspmRule {

        private final int id;
        private final Engine engine;
        private final PtkModule module;
        private final List<GspmCategory> categories;
        private final Map<String, String> alertTags;

        PtkGspmRule(int id, Engine engine, PtkModule module, List<GspmCategory> categories) {
            this.id = id;
            this.engine = engine;
            this.module = module;
            this.categories = categories;
            this.alertTags = Collections.unmodifiableMap(PtkAlertBuilder.getModuleTags(module));
        }

        @Override
        public int getId() {
            return id;
        }

        @Override
        public String getName() {
            return module.getName() != null ? module.getName() : module.getId();
        }

        @Override
        public String getTool() {
            return engine.getToolId();
        }

        @Override
        public GspmPhase getPhase() {
            return engine.getPhase();
        }

        @Override
        public List<GspmCategory> getCategories() {
            return categories;
        }

        @Override
        public Map<String, String> getAlertTags() {
            return alertTags;
        }

        @Override
        public boolean isEnabled() {
            return PtkConfigFilter.isModuleEnabled(
                    engine.name(), module, param.get(), resources.get());
        }

        @Override
        public void setEnabled(boolean enabled) {
            // TODO Apply to PTK's configuration once GSPM is used to configure the PTK rules.
        }

        @Override
        public AlertThreshold getAlertThreshold() {
            // PTK rules can only be enabled or disabled.
            return isEnabled() ? AlertThreshold.MEDIUM : AlertThreshold.OFF;
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {
            // TODO Apply to PTK's configuration once GSPM is used to configure the PTK rules.
        }

        @Override
        public AttackStrength getAttackStrength() {
            return null;
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {
            // No-op: PTK rules do not have an attack strength.
        }

        @Override
        public AddOn.Status getStatus() {
            return addOn != null ? addOn.getStatus() : AddOn.Status.unknown;
        }

        @Override
        public String getAddOnName() {
            return addOn != null ? addOn.getName() : null;
        }
    }
}
