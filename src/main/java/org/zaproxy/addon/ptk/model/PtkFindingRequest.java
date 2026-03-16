package org.zaproxy.addon.ptk.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** DAST request: timestamp, method, url, raw. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFindingRequest {

    private Long timestamp;
    private String method;
    private String url;
    private String raw;
}
