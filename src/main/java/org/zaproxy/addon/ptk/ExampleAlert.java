package org.zaproxy.addon.ptk;

import org.parosproxy.paros.core.scanner.Alert;

/**
 * An example alert that extends {@link Alert} with PTK-specific attributes for documentation and
 * traceability to the source module definitions.
 */
public class ExampleAlert extends Alert {

    private String parentAlertName;
    private String codeLink;
    private String codeLinkText;

    /**
     * Creates an ExampleAlert by copying the given alert and adding PTK-specific attributes.
     *
     * @param source the base alert to copy
     * @param parentAlertName the module name (e.g. "SQL Injection")
     * @param codeLink full URL to the module definition in the pentestkit repo
     * @param codeLinkText the path portion from "src/ptk" (e.g.
     *     "src/ptk/background/dast/modules/modules.json")
     */
    public ExampleAlert(
            Alert source, String parentAlertName, String codeLink, String codeLinkText) {
        super(source.getPluginId(), source.getRisk(), source.getConfidence(), source.getName());
        setDetail(
                source.getDescription(),
                source.getUri(),
                source.getParam(),
                source.getAttack(),
                source.getOtherInfo(),
                source.getSolution(),
                source.getReference(),
                source.getEvidence(),
                source.getCweId(),
                source.getWascId(),
                null);
        setAlertRef(source.getAlertRef());
        setInputVector(source.getInputVector());
        setSource(source.getSource());
        setTags(source.getTags());
        this.parentAlertName = parentAlertName;
        this.codeLink = codeLink;
        this.codeLinkText = codeLinkText;
    }

    public String getParentAlertName() {
        return parentAlertName;
    }

    public String getCodeLink() {
        return codeLink;
    }

    public String getCodeLinkText() {
        return codeLinkText;
    }
}
