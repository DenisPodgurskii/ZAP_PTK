package org.zaproxy.addon.ptk.ascan;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.client.spider.ScanOptions;
import org.zaproxy.addon.ptk.ExtensionPtk;
import org.zaproxy.addon.ptk.options.PtkParam;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.users.User;

/**
 * Active scan rule that drives the Client Spider so PTK's in-browser engines (SAST/IAST/DAST) run
 * over the target host. The rule itself raises no alerts; PTK reports findings asynchronously
 * through the existing PTK callback flow.
 */
public class PtkActiveScanRule extends AbstractHostPlugin {

    private static final Logger LOGGER = LogManager.getLogger(PtkActiveScanRule.class);

    private static final int PLUGIN_ID = 230000;
    private static final String MESSAGE_PREFIX = "ptk.ascan.";

    private static final long POLL_INTERVAL_MS = 500L;

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.BROWSER;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getCweId() {
        return 0;
    }

    @Override
    public int getWascId() {
        return 0;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return Collections.emptyMap();
    }

    @Override
    public void init() {}

    @Override
    public void scan() {
        HostProcess hostProcess = getParent();
        if (hostProcess == null) {
            LOGGER.warn(
                    "PTK active scan rule skipped: {}",
                    Constant.messages.getString(MESSAGE_PREFIX + "fail.missingdependency"));
            return;
        }

        ExtensionClientIntegration extClient = getExtension(ExtensionClientIntegration.class);
        ExtensionPtk extPtk = getExtension(ExtensionPtk.class);
        if (extClient == null || extPtk == null || extPtk.getParam() == null) {
            skipScan(hostProcess, "fail.missingdependency");
            return;
        }
        PtkParam ptkParam = extPtk.getParam();

        if (!ptkParam.isActiveScanRuleEnabled()) {
            skipScan(hostProcess, "fail.skipped");
            return;
        }

        HttpMessage baseMsg = getBaseMsg();
        String url = resolveClientSpiderStartUrl(hostProcess, baseMsg);
        if (url == null || url.isBlank()) {
            skipScan(hostProcess, "fail.badurl");
            return;
        }
        String baseUrl =
                baseMsg != null
                                && baseMsg.getRequestHeader() != null
                                && baseMsg.getRequestHeader().getURI() != null
                        ? baseMsg.getRequestHeader().getURI().toString()
                        : null;
        if (baseUrl != null && !baseUrl.equals(url)) {
            LOGGER.debug(
                    "PTK active scan rule using HostProcess start node URL {} (base message URL {})",
                    url,
                    baseUrl);
        }
        if (hostProcess.getHttpSender() == null) {
            skipScan(hostProcess, "fail.missingdependency");
            return;
        }
        Context context = hostProcess.getContext();
        User user = baseMsg != null ? hostProcess.getHttpSender().getUser(baseMsg) : null;

        if (extClient.getClientParam() == null) {
            skipScan(hostProcess, "fail.missingdependency");
            return;
        }
        ClientOptions options = extClient.getClientParam().clone();
        options.setBrowserId(ptkParam.getActiveScanBrowserId());
        options.setActionWaitTimeInSecs(ptkParam.getActiveScanActionWaitTimeInSecs());
        options.setThreadCount(ptkParam.getActiveScanThreadCount());
        // TODO - inherit these from the client spider
        /*
        options.setPageLoadTimeInSecs(1);
        options.setInitialLoadTimeInSecs(5);
        options.setMaxDepth(5);
        options.setMaxChildren(0);
        options.setShutdownTimeInSecs(5);
        options.setMaxDuration(0);
        */

        ScanOptions scanOptions =
                ScanOptions.builder()
                        .setContext(context)
                        .setUser(user)
                        .setSubtreeOnly(false)
                        .setExternalControl(true)
                        .setHrefType(HistoryReference.TYPE_SCANNER)
                        .setTmpHrefType(HistoryReference.TYPE_SCANNER_TEMPORARY)
                        .setInitiator(HttpSender.ACTIVE_SCANNER_INITIATOR)
                        .setHttpSender(hostProcess.getHttpSender())
                        .setIncludeExtensions(List.of("ptk-latest", "ptk-latest.xpi"))
                        .build();

        int scanId;
        try {
            scanId = extClient.startScan(url, options, scanOptions);
        } catch (Exception e) {
            skipScan(hostProcess, "fail.spiderstart");
            return;
        }

        ClientSpider spider = extClient.getScan(scanId);
        if (spider == null) {
            skipScan(hostProcess, "fail.spidernull");
            return;
        }
        extPtk.seedActiveScanClientSpiderTasks(url);

        long start = System.currentTimeMillis();
        LOGGER.debug("PTK active scan rule started client spider id={} url={}", scanId, url);

        boolean spiderPaused = false;
        try {
            while (spider.isRunning()) {
                if (isStop()) {
                    LOGGER.debug(
                            "PTK active scan rule stopping client spider id={} (active scan stopped)",
                            scanId);
                    spider.stopScan();
                    break;
                }
                boolean parentPaused = hostProcess.isPaused();
                if (parentPaused && !spiderPaused) {
                    spider.pauseScan();
                    spiderPaused = true;
                } else if (!parentPaused && spiderPaused) {
                    spider.resumeScan();
                    spiderPaused = false;
                }
                try {
                    Thread.sleep(POLL_INTERVAL_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    spider.stopScan();
                    break;
                }
            }
        } finally {
            LOGGER.debug(
                    "PTK active scan rule finished client spider id={} url={} elapsedMs={}",
                    scanId,
                    url,
                    System.currentTimeMillis() - start);
        }
    }

    private void skipScan(HostProcess hostProcess, String messageKey) {
        String message = Constant.messages.getString(MESSAGE_PREFIX + messageKey);
        if (hostProcess != null) {
            hostProcess.pluginSkipped(this, message);
        } else {
            LOGGER.warn("PTK active scan rule skipped: {}", message);
        }
    }

    /**
     * Resolves the client spider seed URL from the host process's first {@code startNodes} entry,
     * falling back to the active scan rule's base message when reflection is unavailable.
     */
    static String resolveClientSpiderStartUrl(HostProcess hostProcess, HttpMessage baseMsg) {
        String startNodeUrl = getFirstStartNodeUrl(hostProcess);
        if (startNodeUrl != null && !startNodeUrl.isBlank()) {
            return startNodeUrl;
        }
        if (baseMsg == null || baseMsg.getRequestHeader().getURI() == null) {
            return null;
        }
        return baseMsg.getRequestHeader().getURI().toString();
    }

    private static String getFirstStartNodeUrl(HostProcess hostProcess) {
        if (hostProcess == null) {
            return null;
        }
        try {
            // The startNodes will be publicly accessible from ZAP 2.18.0
            Field startNodesField = HostProcess.class.getDeclaredField("startNodes");
            startNodesField.setAccessible(true);
            Object value = startNodesField.get(hostProcess);
            if (!(value instanceof List<?> nodes)) {
                return null;
            }
            return getFirstStartNodeUrl(nodes);
        } catch (ReflectiveOperationException e) {
            LOGGER.debug(
                    "PTK active scan rule could not read HostProcess.startNodes; using base message URL",
                    e);
            return null;
        }
    }

    // Package-private for testing; avoids constructing a HostProcess in unit tests.
    static String getFirstStartNodeUrl(List<?> startNodes) {
        if (startNodes == null || startNodes.isEmpty()) {
            return null;
        }
        Object first = startNodes.get(0);
        if (!(first instanceof StructuralNode startNode)) {
            return null;
        }
        return urlFromStructuralNode(startNode);
    }

    static String urlFromStructuralNode(StructuralNode startNode) {
        if (startNode == null) {
            return null;
        }
        URI uri = startNode.getURI();
        if (uri != null) {
            return uri.toString();
        }
        if (startNode.getHistoryReference() != null
                && startNode.getHistoryReference().getURI() != null) {
            return startNode.getHistoryReference().getURI().toString();
        }
        return null;
    }

    private static <T extends org.parosproxy.paros.extension.Extension> T getExtension(
            Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }
}
