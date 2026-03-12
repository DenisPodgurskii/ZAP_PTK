package org.zaproxy.addon.ptk.model;

import com.google.gson.JsonElement;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A DAST attack definition: id, name, action (params etc.), and validation (rule/proof). The action
 * and validation trees are kept as JsonElement for flexibility.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkAttack {

    private String id;
    private String name;
    private JsonElement runtime;
    private JsonElement action;
    private JsonElement validation;
    private JsonElement condition;
    private JsonElement target;
    private JsonElement requestGrouping;
    private JsonElement metadata;
    private JsonElement spa;
}
