package org.zaproxy.addon.ptk.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** DAST response: statusCode, timeMs, raw. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PtkFindingResponse {

    private Integer statusCode;
    private Long timeMs;
    private String raw;
}
