package org.zaproxy.addon.ptk.options;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.HashSet;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ToolTipManager;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.ptk.PtkResourcesLoader;
import org.zaproxy.addon.ptk.PtkResourcesLoader.LoadedPtkResources;
import org.zaproxy.addon.ptk.model.PtkAttack;
import org.zaproxy.addon.ptk.model.PtkModule;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.model.PtkRule;
import org.zaproxy.zap.view.JCheckBoxTree;

/**
 * Options panel that displays a checkbox tree of PTK engines, modules, and rules/attacks loaded
 * from the module definition files. Uses ZAP core {@link JCheckBoxTree}. Engines and modules are
 * expanded by default; rules are collapsed until the user expands a module.
 */
public class PtkOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final String MESSAGE_PREFIX = "ptk.options.";

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

    private final JCheckBox enableAutomatedScanningCheckBox;
    private final JCheckBoxTree tree;

    public PtkOptionsPanel() {
        super();
        setName(Constant.messages.getString(MESSAGE_PREFIX + "panel.title"));
        setLayout(new BorderLayout());
        enableAutomatedScanningCheckBox =
                new JCheckBox(
                        Constant.messages.getString(MESSAGE_PREFIX + "enableAutomatedScanning"),
                        false);
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(new EmptyBorder(0, 0, 10, 0));
        topPanel.add(enableAutomatedScanningCheckBox, BorderLayout.WEST);
        add(topPanel, BorderLayout.NORTH);
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
        JPanel scanRulesSection = new JPanel(new BorderLayout());
        scanRulesSection.setBorder(
                BorderFactory.createTitledBorder(
                        BorderFactory.createEtchedBorder(),
                        Constant.messages.getString(MESSAGE_PREFIX + "scanRules.title"),
                        TitledBorder.LEADING,
                        TitledBorder.DEFAULT_POSITION));
        scanRulesSection.add(new JScrollPane(tree), BorderLayout.CENTER);
        add(scanRulesSection, BorderLayout.CENTER);
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
        enableAutomatedScanningCheckBox.setSelected(param.isAutomatedScanningEnabled());
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
        param.setAutomatedScanningEnabled(enableAutomatedScanningCheckBox.isSelected());

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

    public void unload() {
        ToolTipManager.sharedInstance().unregisterComponent(tree);
    }

    @Override
    public String getHelpIndex() {
        return "ptk.options";
    }
}
