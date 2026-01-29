package org.zaproxy.addon.ptk;

import java.util.List;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.client.ClientCallBackImplementor;
import org.zaproxy.addon.client.ExtensionClientIntegration;

public class ExtensionPtk extends ExtensionAdaptor {

    private static final String PREFIX = "ptk";

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionClientIntegration.class);

    private ClientCallBackImplementor callBackImplementor;

    public ExtensionPtk() {
        super("ExtensionPtk");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        callBackImplementor = new CallBackImplementor();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionClientIntegration.class)
                .registerClientCallBack(callBackImplementor);
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

    class CallBackImplementor implements ClientCallBackImplementor {

        public String getImplementorName() {
            return PREFIX;
        }

        public String handleCallBack(HttpMessage msg) {
            // TODO temporary code for testing - have full access to the request here
            System.out.println("PTK got callback");
            System.out.println(
                    msg.getRequestHeader().getMethod() + " " + msg.getRequestHeader().getURI());
            System.out.println(msg.getRequestBody().toString());

            msg.getResponseBody().setBody("{\"result\": \"OK\"}");
            msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/json");
            msg.getResponseHeader().setContentLength(msg.getResponseBody().length());

            return "";
        }
    }
}
