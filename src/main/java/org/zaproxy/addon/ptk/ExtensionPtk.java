package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.client.ClientCallBackImplementor;
import org.zaproxy.addon.client.ClientCallBackUtils;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.ptk.model.PtkModulesDefinition;
import org.zaproxy.addon.ptk.options.PtkOptionsPanel;
import org.zaproxy.addon.ptk.options.PtkParam;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;

public class ExtensionPtk extends ExtensionAdaptor implements ExampleAlertProvider {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionPtk.class);
    private static final String PREFIX = "ptk";

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionClientIntegration.class);

    private ClientCallBackImplementor callBackImplementor;
    private PtkOptionsPanel optionsPanel;
    private PtkParam ptkParam;

    private Map<String, Integer> scanProgress = new HashMap<>();

    public ExtensionPtk() {
        super("ExtensionPtk");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        callBackImplementor = new CallBackImplementor();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .registerClientCallBack(callBackImplementor);
        extensionHook.addOptionsParamSet(getParam());
        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
        }
    }

    private PtkOptionsPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new PtkOptionsPanel();
        }
        return optionsPanel;
    }

    private PtkParam getParam() {
        if (ptkParam == null) {
            ptkParam = new PtkParam();
        }
        return ptkParam;
    }

    @Override
    public void unload() {
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .unregisterClientCallBack(callBackImplementor);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        PtkResourcesLoader loader = new PtkResourcesLoader();
        PtkResourcesLoader.LoadedPtkResources resources = loader.loadAll();
        return PtkExampleAlerts.getExampleAlerts(resources);
    }

    class CallBackImplementor implements ClientCallBackImplementor {

        private static final String PTK_ALERT_PATH = "/ptk/alert";
        private static final String PTK_CONFIG_PATH = "/ptk/config";
        private static final String PTK_PING_PATH = "/ptk/ping";
        private static final String PTK_PROGRESS_PATH = "/ptk/progress";
        private static final Gson GSON = new Gson();

        @Override
        public String getImplementorName() {
            return PREFIX;
        }

        @Override
        public String handleCallBack(HttpMessage msg) {
            String uri =
                    msg.getRequestHeader().getURI() != null
                            ? msg.getRequestHeader().getURI().toString()
                            : "";
            if (uri.contains(PTK_CONFIG_PATH)) {
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("mode", getParam().isAutomatedScanningEnabled() ? "auto" : "manual");
                PtkResourcesLoader loader = new PtkResourcesLoader();
                PtkResourcesLoader.LoadedPtkResources resources = loader.loadAll();
                Set<String> checkedPaths = getParam().getCheckedPathStrings();
                Map<String, PtkModulesDefinition> config =
                        PtkConfigFilter.filterByCheckedPaths(resources, checkedPaths);
                response.put("sast", config.get("sast") != null ? config.get("sast") : Map.of());
                response.put("iast", config.get("iast") != null ? config.get("iast") : Map.of());
                response.put("dast", config.get("dast") != null ? config.get("dast") : Map.of());
                String json = GSON.toJson(response);
                msg.getResponseBody().setBody(json);
            } else if (uri.contains(PTK_ALERT_PATH)) {
                String requestBody = msg.getRequestBody().toString();
                int raised = PtkAlertHandler.processAlertBatch(requestBody);
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("result", "OK");
                response.put("alertsRaised", raised);
                msg.getResponseBody().setBody(GSON.toJson(response));
            } else if (uri.contains(PTK_PING_PATH)) {
                // Will use in the future
                LOGGER.debug(
                        "PTK got ping: {} {} {}",
                        msg.getRequestHeader().getMethod(),
                        msg.getRequestHeader().getURI(),
                        msg.getRequestBody());
            } else if (uri.contains(PTK_PROGRESS_PATH)) {
                String requestBody = msg.getRequestBody().toString();
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> progressData = GSON.fromJson(requestBody, Map.class);
                    String zapid = (String) progressData.get("zapid");
                    Number progress = (Number) progressData.get("progress");
                    if (zapid != null && progress != null) {
                        scanProgress.put(zapid, progress.intValue());
                        LOGGER.debug(
                                "PTK progress: zapid={} progress={}", zapid, progress.intValue());
                    } else {
                        LOGGER.warn("PTK progress missing zapid or progress: {}", requestBody);
                    }
                } catch (Exception e) {
                    LOGGER.warn("PTK failed to parse progress body: {}", requestBody, e);
                }
                msg.getResponseBody().setBody("{\"result\": \"OK\"}");
            } else {
                LOGGER.warn(
                        "PTK unexpected request: {} {} {}",
                        msg.getRequestHeader().getMethod(),
                        msg.getRequestHeader().getURI(),
                        msg.getRequestBody());
                msg.getResponseBody().setBody("{\"result\": \"FAIL\"}");
            }
            msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/json");
            msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
            return "";
        }

        @Override
        public void browserClosing(ClientCallBackUtils ccbutils) {
            LOGGER.debug("PTK browserExiting {}", ccbutils.getUuid());
            if (ccbutils.getUuid() == null) {
                return;
            }
            String zapid = ccbutils.getUuid().toString();
            if (!scanProgress.containsKey(zapid)) {
                LOGGER.warn("PTK browserExiting: no progress for UUID {}", ccbutils.getUuid());
                return;
            }
            long start = System.currentTimeMillis();
            int count = 0;
            while (scanProgress.getOrDefault(zapid, 100) < 100) {
                count++;
                if (count >= 20) {
                    LOGGER.warn(
                            "PTK browserExiting: UUID {} forced exit after {} ms, progress was {}",
                            ccbutils.getUuid(),
                            (System.currentTimeMillis() - start),
                            scanProgress.get(zapid));
                    scanProgress.remove(zapid);
                    return;
                }
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            scanProgress.remove(zapid);
            LOGGER.debug(
                    "PTK browserExiting: UUID {} exited cleanly waited for {} ms",
                    ccbutils.getUuid(),
                    (System.currentTimeMillis() - start));
        }
    }
}
