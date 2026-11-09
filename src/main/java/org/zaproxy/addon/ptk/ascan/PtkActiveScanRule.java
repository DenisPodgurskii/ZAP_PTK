package org.zaproxy.addon.ptk.ascan;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.client.spider.ClientSpiderOptions;
import org.zaproxy.addon.client.spider.ScanOptions;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.ptk.ExtensionPtk;
import org.zaproxy.addon.ptk.options.PtkParam;
import org.zaproxy.zap.model.Context;
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

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags = new LinkedHashMap<>();
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

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
        return ALERT_TAGS;
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
        if (hostProcess.getHttpSender() == null) {
            skipScan(hostProcess, "fail.missingdependency");
            return;
        }
        Context context = hostProcess.getContext();
        if (context == null) {
            // The active rule can be launched without a named context even
            // though the official plan has one. Use only an unambiguous ZAP
            // context containing this seed; never infer a host-root scope.
            List<Context> matching = Model.getSingleton().getSession().getContextsForUrl(url);
            if (matching.size() > 1) {
                skipScan(hostProcess, "fail.badurl");
                return;
            }
            if (matching.size() == 1) context = matching.get(0);
        }
        if (!isClientSpiderSeedInScope(url, context == null ? null : context::isInContext)) {
            skipScan(hostProcess, "fail.badurl");
            return;
        }
        User user = baseMsg != null ? hostProcess.getHttpSender().getUser(baseMsg) : null;

        if (extClient.getClientParam() == null) {
            skipScan(hostProcess, "fail.missingdependency");
            return;
        }
        ClientSpiderOptions options = extClient.getClientSpiderParam().clone();
        options.setBrowserId(ptkParam.getActiveScanBrowserId());
        options.setThreadCount(ptkParam.getActiveScanThreadCount());

        ScanOptions scanOptions =
                ScanOptions.builder()
                        .setContext(context)
                        .setUser(user)
                        .setSubtreeOnly(false)
                        .setExternalControl(true)
                        .setExistingOnly(true)
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
        ClientSpider.CompletionOutcome outcome = spider.getCompletionOutcome();
        if (outcome != ClientSpider.CompletionOutcome.COMPLETE) {
            String reason = incompleteClientSpiderReason(outcome);
            LOGGER.warn("PTK active scan rule client spider id={} {}", scanId, reason);
            // This is called while the rule is still running. ZAP's public
            // HostProcess API exposes a skipped reason, not a typed partial
            // outcome; stored PTK alerts remain available for assessment.
            hostProcess.pluginSkipped(this, reason);
        }
    }

    static String incompleteClientSpiderReason(ClientSpider.CompletionOutcome outcome) {
        return "PTK Client Spider did not complete: "
                + (outcome == null ? "UNAVAILABLE" : outcome.name());
    }

    private void skipScan(HostProcess hostProcess, String messageKey) {
        String message = Constant.messages.getString(MESSAGE_PREFIX + messageKey);
        if (hostProcess != null) {
            hostProcess.pluginSkipped(this, message);
        } else {
            LOGGER.warn("PTK active scan rule skipped: {}", message);
        }
    }

    /** The active rule's public base message is the in-scope seed, not the host tree root. */
    static String resolveClientSpiderStartUrl(HostProcess hostProcess, HttpMessage baseMsg) {
        if (baseMsg == null
                || baseMsg.getRequestHeader() == null
                || baseMsg.getRequestHeader().getURI() == null) {
            return null;
        }
        return baseMsg.getRequestHeader().getURI().toString();
    }

    static boolean isClientSpiderSeedInScope(String url, Predicate<String> inContext) {
        return url != null && !url.isBlank() && (inContext == null || inContext.test(url));
    }

    private static <T extends org.parosproxy.paros.extension.Extension> T getExtension(
            Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }
}
