package org.zaproxy.addon.ptk.model;

import com.google.gson.JsonElement;

/**
 * A DAST attack definition: id, name, action (params etc.), and validation (rule/proof). The action
 * and validation trees are kept as JsonElement for flexibility.
 */
public class PtkAttack {

    private String id;
    private String name;
    private JsonElement action;
    private JsonElement validation;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public JsonElement getAction() {
        return action;
    }

    public void setAction(JsonElement action) {
        this.action = action;
    }

    public JsonElement getValidation() {
        return validation;
    }

    public void setValidation(JsonElement validation) {
        this.validation = validation;
    }
}
