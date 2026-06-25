package org.zaproxy.addon.ptk.options;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseEvent;
import java.util.HashSet;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.ToolTipManager;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.ptk.PtkResourcesLoader;
import org.zaproxy.addon.ptk.PtkResourcesLoader.LoadedPtkResources;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.JCheckBoxTree;
import org.zaproxy.zap.view.LayoutHelper;

/**
 * Options panel that displays a checkbox tree of PTK engines, modules, and rules/attacks loaded
 * from the module definition files. Uses ZAP core {@link JCheckBoxTree}. Engines and modules are
 * expanded by default; rules are collapsed until the user expands a module.
 */
public class PtkOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final String MESSAGE_PREFIX = "ptk.options.";

    private static final String CLIENT_LABEL_BROWSER = "client.scandialog.label.browser";
    private static final String CLIENT_LABEL_ACTION_WAIT_TIME =
            "client.options.label.actionwaittime";
    private static final String CLIENT_LABEL_THREAD_COUNT = "client.options.label.browsers";

    /**
     * User object stored in each tree node. The label is shown in the tree; the id is used when
     * persisting the enabled state to config.
     */
    private record NodeEntry(String label, String id) {
        @Override
        public String toString() {
            return label;
        }
    }

    private final JCheckBox enableActiveScanRuleCheckBox;
    private final JCheckBox enableAutomatedScanningCheckBox;
    private final JComboBox<String> browserComboBox;
    private final ZapNumberSpinner actionWaitTimeSpinner;
    private final ZapNumberSpinner threadCountSpinner;
    private final JCheckBoxTree tree;
    private final JComboBox<EngineRunLocation> dastRunLocationComboBox;
    private final JComboBox<EngineRunLocation> sastRunLocationComboBox;
    private final JComboBox<EngineRunLocation> iastRunLocationComboBox;

    public PtkOptionsPanel() {
        super();
        setName(Constant.messages.getString(MESSAGE_PREFIX + "panel.title"));
        setLayout(new BorderLayout());
        enableActiveScanRuleCheckBox =
                new JCheckBox(
                        Constant.messages.getString(MESSAGE_PREFIX + "enableActiveScanRule"),
                        false);
        enableAutomatedScanningCheckBox =
                new JCheckBox(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "enableAutomatedScanningDeprecated"),
                        false);
        browserComboBox = new JComboBox<>();
        actionWaitTimeSpinner =
                new ZapNumberSpinner(
                        0, PtkParam.DEFAULT_ACTIVE_SCAN_ACTION_WAIT_TIME, Integer.MAX_VALUE);
        threadCountSpinner =
                new ZapNumberSpinner(
                        1, PtkParam.getDefaultActiveScanThreadCount(), Integer.MAX_VALUE);
        enableActiveScanRuleCheckBox.addItemListener(e -> syncActiveScanTabState());
        dastRunLocationComboBox = createRunLocationComboBox();
        dastRunLocationComboBox.setSelectedItem(PtkParam.DEFAULT_DAST_RUN_LOCATION);
        sastRunLocationComboBox = createRunLocationComboBox();
        sastRunLocationComboBox.setSelectedItem(PtkParam.DEFAULT_SAST_RUN_LOCATION);
        iastRunLocationComboBox = createRunLocationComboBox();
        iastRunLocationComboBox.setSelectedItem(PtkParam.DEFAULT_IAST_RUN_LOCATION);
        tree =
                new JCheckBoxTree() {
                    @Override
                    public String getToolTipText(MouseEvent e) {
                        TreePath path = getPathForLocation(e.getX(), e.getY());
                        if (path == null) return null;
                        Object comp = path.getLastPathComponent();
                        if (comp instanceof DefaultMutableTreeNode node
                                && node.getUserObject() instanceof NodeEntry entry
                                && !entry.id().equals(entry.label())) {
                            return entry.id();
                        }
                        return null;
                    }
                };
        ToolTipManager.sharedInstance().registerComponent(tree);
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setModel(buildTreeModel());
        expandEnginesAndModulesOnly(tree);
        checkAll(tree);

        JPanel scanRulesTab = new JPanel(new BorderLayout());
        scanRulesTab.add(new JScrollPane(tree), BorderLayout.CENTER);

        JPanel activeScanTab = new JPanel(new GridBagLayout());
        activeScanTab.setBorder(new EmptyBorder(10, 10, 10, 10));
        int row = 0;
        activeScanTab.add(
                enableActiveScanRuleCheckBox,
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;
        activeScanTab.add(
                enableAutomatedScanningCheckBox,
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 8, 2)));
        row++;

        JLabel browserLabel = new JLabel(Constant.messages.getString(CLIENT_LABEL_BROWSER));
        browserLabel.setLabelFor(browserComboBox);
        activeScanTab.add(
                browserLabel,
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.RELATIVE, 1.0, new Insets(2, 2, 2, 2)));
        activeScanTab.add(
                browserComboBox,
                LayoutHelper.getGBC(
                        1, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        JLabel actionWaitLabel =
                new JLabel(Constant.messages.getString(CLIENT_LABEL_ACTION_WAIT_TIME));
        actionWaitLabel.setLabelFor(actionWaitTimeSpinner);
        activeScanTab.add(
                actionWaitLabel,
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.RELATIVE, 1.0, new Insets(2, 2, 2, 2)));
        activeScanTab.add(
                actionWaitTimeSpinner,
                LayoutHelper.getGBC(
                        1, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        JLabel threadCountLabel =
                new JLabel(Constant.messages.getString(CLIENT_LABEL_THREAD_COUNT));
        threadCountLabel.setLabelFor(threadCountSpinner);
        activeScanTab.add(
                threadCountLabel,
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.RELATIVE, 1.0, new Insets(2, 2, 2, 2)));
        activeScanTab.add(
                threadCountSpinner,
                LayoutHelper.getGBC(
                        1, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        activeScanTab.add(new JLabel(), LayoutHelper.getGBC(0, row + 1, 1, 0.5D, 1.0D));
        syncActiveScanTabState();

        JPanel enginesTab = new JPanel(new BorderLayout());
        enginesTab.add(buildRunLocationPanel(), BorderLayout.NORTH);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab(Constant.messages.getString(MESSAGE_PREFIX + "tab.engines"), enginesTab);
        tabbedPane.addTab(
                Constant.messages.getString(MESSAGE_PREFIX + "tab.scanRules"), scanRulesTab);
        tabbedPane.addTab(
                Constant.messages.getString(MESSAGE_PREFIX + "tab.activeScan"), activeScanTab);
        add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel buildRunLocationPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(
                new CompoundBorder(
                        new EmptyBorder(4, 4, 0, 4),
                        BorderFactory.createTitledBorder(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "runLocation.sectionLabel"))));
        addRunLocationRow(panel, "SAST", sastRunLocationComboBox, 0);
        addRunLocationRow(panel, "IAST", iastRunLocationComboBox, 1);
        addRunLocationRow(panel, "DAST", dastRunLocationComboBox, 2);
        return panel;
    }

    private static void addRunLocationRow(
            JPanel panel, String engine, JComboBox<EngineRunLocation> combo, int row) {
        JLabel label = new JLabel(engine + ":");
        label.setLabelFor(combo);
        panel.add(
                label,
                LayoutHelper.getGBC(
                        0, row, GridBagConstraints.RELATIVE, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(
                combo,
                LayoutHelper.getGBC(
                        1, row, GridBagConstraints.REMAINDER, 1.0, new Insets(2, 2, 2, 2)));
    }

    private static JComboBox<EngineRunLocation> createRunLocationComboBox() {
        return new JComboBox<>(EngineRunLocation.values());
    }

    private static TreeModel buildTreeModel() {
        DefaultMutableTreeNode root =
                new DefaultMutableTreeNode(
                        Constant.messages.getString(MESSAGE_PREFIX + "tree.root"));
        PtkResourcesLoader loader = new PtkResourcesLoader();
        PtkResourcesLoader.LoadedPtkResources resources = loader.loadAll();

        if (resources.getSastModules() != null) {
            addEngine(root, resources.getSastModules());
        }
        if (resources.getIastModules() != null) {
            addEngine(root, resources.getIastModules());
        }
        if (resources.getDastModules() != null) {
            addEngine(root, resources.getDastModules());
        }

        return new DefaultTreeModel(root);
    }

    /**
     * Expands root and engine nodes so modules are visible; leaves module nodes collapsed (rules
     * hidden).
     */
    private static void expandEnginesAndModulesOnly(JCheckBoxTree t) {
        Object root = t.getModel().getRoot();
        if (!(root instanceof DefaultMutableTreeNode)) return;
        expandToDepth(t, (DefaultMutableTreeNode) root, 0, 1);
    }

    private static void expandToDepth(
            JCheckBoxTree t, DefaultMutableTreeNode node, int depth, int maxDepth) {
        if (depth <= maxDepth) {
            TreePath path = new TreePath(node.getPath());
            t.expandPath(path);
        }
        if (depth >= maxDepth) return;
        for (int i = 0; i < node.getChildCount(); i++) {
            expandToDepth(t, (DefaultMutableTreeNode) node.getChildAt(i), depth + 1, maxDepth);
        }
    }

    private static void checkAll(JCheckBoxTree t) {
        Object root = t.getModel().getRoot();
        if (root != null) {
            t.checkSubTree(new TreePath(root), true);
        }
    }

    /** Returns the ID segment stored in the {@link NodeEntry} of the given node. */
    private static String nodeId(DefaultMutableTreeNode node) {
        Object obj = node.getUserObject();
        return obj instanceof NodeEntry e ? e.id() : (obj != null ? obj.toString() : "");
    }

    /**
     * Converts a tree path (engine/module/rule) to a slash-delimited ID string using each node's
     * {@link NodeEntry#id()}.
     */
    private static String treePathToIdString(TreePath path) {
        if (path == null || path.getPathCount() < 2) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i < path.getPathCount(); i++) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getPathComponent(i);
            Object obj = node.getUserObject();
            String id = obj instanceof NodeEntry e ? e.id() : (obj != null ? obj.toString() : "");
            if (i > 1) sb.append('/');
            sb.append(id);
        }
        return sb.toString();
    }

    private static void addEngine(DefaultMutableTreeNode root, PtkModulesDefinition def) {
        String engineName = def.getEngine();
        if (engineName == null) return;
        DefaultMutableTreeNode engineNode =
                new DefaultMutableTreeNode(new NodeEntry(engineName, engineName));
        root.add(engineNode);
        if (def.getModules() == null) return;
        for (PtkModule m : def.getModules()) {
            if (m.getId() == null) continue;
            String moduleLabel = m.getName() != null ? m.getName() : m.getId();
            DefaultMutableTreeNode moduleNode =
                    new DefaultMutableTreeNode(new NodeEntry(moduleLabel, m.getId()));
            engineNode.add(moduleNode);
            if (m.getRules() != null) {
                for (PtkRule r : m.getRules()) {
                    if (r.getId() == null) continue;
                    String ruleLabel = r.getName() != null ? r.getName() : r.getId();
                    moduleNode.add(new DefaultMutableTreeNode(new NodeEntry(ruleLabel, r.getId())));
                }
            }
            if (m.getAttacks() != null) {
                for (PtkAttack a : m.getAttacks()) {
                    if (a.getId() == null) continue;
                    String attackLabel = a.getName() != null ? a.getName() : a.getId();
                    moduleNode.add(
                            new DefaultMutableTreeNode(new NodeEntry(attackLabel, a.getId())));
                }
            }
        }
    }

    @Override
    public void initParam(Object obj) {
        PtkParam param = getPtkParam(obj);
        enableActiveScanRuleCheckBox.setSelected(param.isActiveScanRuleEnabled());
        enableAutomatedScanningCheckBox.setSelected(param.isAutomatedScanningEnabled());
        updateBrowsers(param.getActiveScanBrowserId());
        actionWaitTimeSpinner.setValue(param.getActiveScanActionWaitTimeInSecs());
        threadCountSpinner.setValue(param.getActiveScanThreadCount());
        sastRunLocationComboBox.setSelectedItem(param.getSastRunLocation());
        iastRunLocationComboBox.setSelectedItem(param.getIastRunLocation());
        dastRunLocationComboBox.setSelectedItem(param.getDastRunLocation());
        syncActiveScanTabState();
        tree.setModel(buildTreeModel());
        expandEnginesAndModulesOnly(tree);

        // JCheckBoxTree.check(leaf, true) does NOT propagate isSelected=true up to parent
        // nodes — only checkSubTree does. Start from all-checked so parents are already
        // selected, then uncheck disabled nodes top-down: checkSubTree for fully-disabled
        // engines/modules (efficient), check for individually disabled rules.
        checkAll(tree);
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) tree.getModel().getRoot();
        for (int ei = 0; ei < root.getChildCount(); ei++) {
            DefaultMutableTreeNode engineNode = (DefaultMutableTreeNode) root.getChildAt(ei);
            String engine = nodeId(engineNode);
            boolean anyEnabledInEngine = false;

            for (int mi = 0; mi < engineNode.getChildCount(); mi++) {
                DefaultMutableTreeNode moduleNode =
                        (DefaultMutableTreeNode) engineNode.getChildAt(mi);
                String moduleId = nodeId(moduleNode);
                boolean anyEnabledInModule = false;

                for (int ri = 0; ri < moduleNode.getChildCount(); ri++) {
                    DefaultMutableTreeNode ruleNode =
                            (DefaultMutableTreeNode) moduleNode.getChildAt(ri);
                    if (param.isRuleEnabled(engine, moduleId, nodeId(ruleNode))) {
                        anyEnabledInModule = true;
                        anyEnabledInEngine = true;
                    }
                }

                if (!anyEnabledInModule) {
                    tree.checkSubTree(new TreePath(moduleNode.getPath()), false);
                } else {
                    for (int ri = 0; ri < moduleNode.getChildCount(); ri++) {
                        DefaultMutableTreeNode ruleNode =
                                (DefaultMutableTreeNode) moduleNode.getChildAt(ri);
                        String ruleId = nodeId(ruleNode);
                        if (!param.isRuleEnabled(engine, moduleId, ruleId)) {
                            tree.check(new TreePath(ruleNode.getPath()), false);
                        }
                    }
                }
            }

            if (!anyEnabledInEngine) {
                tree.checkSubTree(new TreePath(engineNode.getPath()), false);
            }
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        PtkParam param = getPtkParam(obj);
        boolean activeScanRuleEnabled = enableActiveScanRuleCheckBox.isSelected();
        param.setActiveScanRuleEnabled(activeScanRuleEnabled);
        if (activeScanRuleEnabled) {
            param.setAutomatedScanningEnabled(false);
        } else {
            param.setAutomatedScanningEnabled(enableAutomatedScanningCheckBox.isSelected());
        }
        String browserId = getSelectedBrowserId();
        if (browserId != null) {
            param.setActiveScanBrowserId(browserId);
        }
        param.setActiveScanActionWaitTimeInSecs(actionWaitTimeSpinner.getValue());
        param.setActiveScanThreadCount(threadCountSpinner.getValue());
        param.setSastRunLocation(
                getSelectedRunLocation(
                        sastRunLocationComboBox, PtkParam.DEFAULT_SAST_RUN_LOCATION));
        param.setIastRunLocation(
                getSelectedRunLocation(
                        iastRunLocationComboBox, PtkParam.DEFAULT_IAST_RUN_LOCATION));
        param.setDastRunLocation(
                getSelectedRunLocation(
                        dastRunLocationComboBox, PtkParam.DEFAULT_DAST_RUN_LOCATION));

        // Collect the IDs of enabled leaves (rule/attack nodes only; ignore parent paths).
        Set<String> enabledLeafIds = new HashSet<>();
        TreePath[] checked = tree.getCheckedPaths();
        if (checked != null) {
            for (TreePath path : checked) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                if (node.isLeaf()) {
                    String s = treePathToIdString(path);
                    if (!s.isEmpty()) enabledLeafIds.add(s);
                }
            }
        }

        LoadedPtkResources resources = new PtkResourcesLoader().loadAll();
        param.saveFromEnabledLeafs(enabledLeafIds, resources);
    }

    private static PtkParam getPtkParam(Object obj) {
        return ((OptionsParam) obj).getParamSet(PtkParam.class);
    }

    /**
     * Updates the browser combo box from the Selenium extension, selecting the entry for {@code
     * browserId} when present.
     */
    private void syncActiveScanTabState() {
        boolean activeScanRuleEnabled = enableActiveScanRuleCheckBox.isSelected();
        enableAutomatedScanningCheckBox.setEnabled(!activeScanRuleEnabled);
        browserComboBox.setEnabled(activeScanRuleEnabled);
        actionWaitTimeSpinner.setEnabled(activeScanRuleEnabled);
        threadCountSpinner.setEnabled(activeScanRuleEnabled);
        if (activeScanRuleEnabled) {
            enableAutomatedScanningCheckBox.setSelected(false);
        }
    }

    private void updateBrowsers(String browserId) {
        browserComboBox.removeAllItems();
        ExtensionSelenium extSel = getExtensionSelenium();
        if (extSel == null) {
            return;
        }

        String selectedName = null;
        for (ProvidedBrowserUI browser : extSel.getProvidedBrowserUIList()) {
            browserComboBox.addItem(browser.getName());
            if (browser.getBrowser().getId().equals(browserId)) {
                selectedName = browser.getName();
            }
        }
        if (selectedName != null) {
            browserComboBox.setSelectedItem(selectedName);
        } else if (browserComboBox.getItemCount() > 0) {
            browserComboBox.setSelectedIndex(0);
        }
    }

    private static EngineRunLocation getSelectedRunLocation(
            JComboBox<EngineRunLocation> combo, EngineRunLocation defaultValue) {
        Object selected = combo.getSelectedItem();
        return selected instanceof EngineRunLocation loc ? loc : defaultValue;
    }

    private String getSelectedBrowserId() {
        Object selected = browserComboBox.getSelectedItem();
        if (!(selected instanceof String browserName) || browserName.isEmpty()) {
            return null;
        }

        ExtensionSelenium extSel = getExtensionSelenium();
        if (extSel == null) {
            return null;
        }

        for (ProvidedBrowserUI browser : extSel.getProvidedBrowserUIList()) {
            if (browserName.equals(browser.getName())) {
                return browser.getBrowser().getId();
            }
        }
        return null;
    }

    private static ExtensionSelenium getExtensionSelenium() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
    }

    public void unload() {
        ToolTipManager.sharedInstance().unregisterComponent(tree);
    }

    @Override
    public String getHelpIndex() {
        return "ptk.options";
    }
}
