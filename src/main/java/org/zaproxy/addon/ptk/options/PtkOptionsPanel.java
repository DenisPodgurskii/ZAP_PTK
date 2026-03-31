package org.zaproxy.addon.ptk.options;

import java.awt.BorderLayout;
import java.util.Set;
import java.util.TreeSet;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.ptk.PtkResourcesLoader;
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
        tree = new JCheckBoxTree();
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

    private static void uncheckAll(JCheckBoxTree t) {
        Object root = t.getModel().getRoot();
        if (root != null) {
            t.checkSubTree(new TreePath(root), false);
        }
    }

    /**
     * Converts a tree path to a persistent index string (e.g. "0/1/2") where each segment is the
     * child index from the root. Root is not included.
     */
    private static String treePathToIndexString(TreePath path) {
        if (path == null || path.getPathCount() < 2) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i < path.getPathCount(); i++) {
            DefaultMutableTreeNode parent = (DefaultMutableTreeNode) path.getPathComponent(i - 1);
            Object child = path.getPathComponent(i);
            if (i > 1) sb.append('/');
            sb.append(parent.getIndex((TreeNode) child));
        }
        return sb.toString();
    }

    /**
     * Converts an index string (e.g. "0/1/2") back to a TreePath for the given tree. Returns null
     * if the string is invalid or the path does not exist.
     */
    private static TreePath indexStringToTreePath(JCheckBoxTree t, String pathString) {
        if (pathString == null || pathString.isEmpty()) return null;
        Object root = t.getModel().getRoot();
        if (!(root instanceof DefaultMutableTreeNode)) return null;
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) root;
        String[] parts = pathString.trim().split("/");
        for (String part : parts) {
            int index;
            try {
                index = Integer.parseInt(part.trim());
            } catch (NumberFormatException e) {
                return null;
            }
            if (index < 0 || index >= node.getChildCount()) return null;
            node = (DefaultMutableTreeNode) node.getChildAt(index);
        }
        return new TreePath(node.getPath());
    }

    private static void addEngine(DefaultMutableTreeNode root, PtkModulesDefinition def) {
        String engineName = def.getEngine();
        if (engineName == null) return;
        DefaultMutableTreeNode engineNode = new DefaultMutableTreeNode(engineName);
        root.add(engineNode);
        if (def.getModules() == null) return;
        for (PtkModule m : def.getModules()) {
            String moduleLabel = m.getName() != null ? m.getName() : m.getId();
            if (moduleLabel == null) continue;
            DefaultMutableTreeNode moduleNode = new DefaultMutableTreeNode(moduleLabel);
            engineNode.add(moduleNode);
            if (m.getRules() != null) {
                for (PtkRule r : m.getRules()) {
                    String ruleLabel = r.getName() != null ? r.getName() : r.getId();
                    if (ruleLabel != null) {
                        moduleNode.add(new DefaultMutableTreeNode(ruleLabel));
                    }
                }
            }
            if (m.getAttacks() != null) {
                for (PtkAttack a : m.getAttacks()) {
                    String attackLabel = a.getName() != null ? a.getName() : a.getId();
                    if (attackLabel != null) {
                        moduleNode.add(new DefaultMutableTreeNode(attackLabel));
                    }
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
        Set<String> savedPaths = param.getCheckedPathStrings();
        if (savedPaths.isEmpty()) {
            checkAll(tree);
        } else {
            uncheckAll(tree);
            for (String pathString : savedPaths) {
                TreePath path = indexStringToTreePath(tree, pathString);
                if (path != null) {
                    tree.check(path, true);
                }
            }
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        PtkParam param = getPtkParam(obj);
        param.setAutomatedScanningEnabled(enableAutomatedScanningCheckBox.isSelected());
        Set<String> paths = new TreeSet<>();
        TreePath[] checked = tree.getCheckedPaths();
        if (checked != null) {
            for (TreePath path : checked) {
                String s = treePathToIndexString(path);
                if (!s.isEmpty()) paths.add(s);
            }
        }
        param.setCheckedPathStrings(paths);
    }

    private static PtkParam getPtkParam(Object obj) {
        return ((OptionsParam) obj).getParamSet(PtkParam.class);
    }

    @Override
    public String getHelpIndex() {
        return "ptk.options";
    }
}
