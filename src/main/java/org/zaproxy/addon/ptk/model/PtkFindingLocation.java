package org.zaproxy.addon.ptk.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Location of a PTK finding: URL, route, method, param. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFindingLocation {

    private String url;
    private String route;
    private String method;
    private String param;
}
