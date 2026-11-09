package org.zaproxy.addon.ptk;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/** Fail-closed validation before Gson model binding can discard unknown v2 fields. */
final class PtkIastV2Contract {
    static final String V2 = "ptk-zap-iast-finding-v2";
    // 512-char admitted capture route - 20-char endpoint + 11-char origin + '|' + 128-char owner.
    private static final int MAX_ZAP_SESSION_KEY = 632;
    private static final Set<String> GRADES =
            Set.of(
                    "substring",
                    "lexical_word_boundary",
                    "canonical_url_equality",
                    "primitive_fingerprint_equality",
                    "complete_value_equality",
                    "instrumented_propagation",
                    "object_identity");

    private PtkIastV2Contract() {}

    static void validate(JsonObject root) {
        fields(
                root,
                "source,type,schema,ts,batchId,batchSeq,zapid,browserid,zapSessionKey,payload",
                "source,type,schema,ts,batchId,payload");
        require(
                "ptk".equals(string(root, "source", 8, false))
                        && "iast_findings_batch".equals(string(root, "type", 32, false)));
        require(V2.equals(string(root, "schema", 64, false)));
        string(root, "batchId", 128, false);
        string(root, "zapid", 128, false);
        integer(root.get("ts"), 0, Long.MAX_VALUE);
        if (root.has("batchSeq")) integer(root.get("batchSeq"), 0, Integer.MAX_VALUE);
        JsonObject payload = object(root.get("payload"));
        fields(
                payload,
                "engine,scanId,sessionId,zapSessionKey,truncated,findings,scanCompleteness",
                "engine,scanId,sessionId,findings,scanCompleteness");
        require("IAST".equals(string(payload, "engine", 8, false)));
        string(payload, "scanId", 128, false);
        string(payload, "sessionId", 128, false);
        validateZapSessionKeys(root, payload);
        validateSummary(object(payload.get("scanCompleteness")));
        require(
                payload.get("findings").isJsonArray()
                        && payload.getAsJsonArray("findings").size() <= 200);
        for (JsonElement item : payload.getAsJsonArray("findings")) {
            JsonObject finding = object(item);
            require(item.toString().getBytes(StandardCharsets.UTF_8).length <= 65536);
            fields(
                    finding,
                    "id,fingerprint,moduleId,ruleId,severity,confidence,summary,location,proof,source,sink,trace,context,request,response,observation",
                    "id,fingerprint,moduleId,ruleId,severity,confidence,summary,location,proof,source,sink,context,observation");
            for (String key : new String[] {"id", "fingerprint", "moduleId", "ruleId"})
                string(finding, key, 128, false);
            enumValue(finding, "severity", Set.of("info", "low", "medium", "high"));
            integer(finding.get("confidence"), 0, 100);
            string(finding, "summary", 1024, false);
            JsonObject location = object(finding.get("location"));
            fields(location, "url,route,method,param", "url,route,method,param");
            string(location, "url", 8192, false);
            for (String key : new String[] {"route", "method", "param"})
                string(location, key, 2048, true);
            JsonObject observation = object(finding.get("observation"));
            validateObservation(observation);
            JsonObject proof = object(finding.get("proof"));
            fields(proof, "mode,payload,proof,summary", "mode,payload,proof,summary");
            enumValue(proof, "mode", Set.of("signal", "taint"));
            if ("policy_signal".equals(observation.get("kind").getAsString()))
                require("signal".equals(proof.get("mode").getAsString()));
            string(proof, "payload", 1024, true);
            string(proof, "proof", 4096, true);
            string(proof, "summary", 1024, false);
            JsonObject source = object(finding.get("source"));
            fields(source, "id,label,kind", "id,label,kind");
            string(source, "id", 512, true);
            string(source, "label", 256, true);
            string(source, "kind", 80, true);
            JsonObject sink = object(finding.get("sink"));
            fields(sink, "id,label", "id,label");
            string(sink, "id", 256, true);
            string(sink, "label", 256, true);
            JsonObject context = object(finding.get("context"));
            fields(context, "domPath,elementId,tagName", "domPath,elementId,tagName");
            for (String key : new String[] {"domPath", "elementId", "tagName"})
                string(context, key, 1024, true);
            if (finding.has("trace")) string(finding, "trace", 2048, true);
            if (finding.has("request")) {
                JsonObject request = object(finding.get("request"));
                fields(request, "method,url,raw", "method,url,raw");
                string(request, "method", 32, false);
                string(request, "url", 8192, false);
                string(request, "raw", 16384, false);
            }
            if (finding.has("response")) {
                JsonObject response = object(finding.get("response"));
                fields(response, "statusCode,raw", "statusCode,raw");
                integer(response.get("statusCode"), 100, 599);
                string(response, "raw", 4096, false);
            }
            if ("sink_storage_snapshot".equals(observation.get("acquisition").getAsString())) {
                require(
                        Set.of("info", "low").contains(finding.get("severity").getAsString())
                                && "signal".equals(proof.get("mode").getAsString()));
                require(
                        Set.of("localStorage", "sessionStorage")
                                        .contains(
                                                observation
                                                        .getAsJsonObject("sourceBinding")
                                                        .get("kind")
                                                        .getAsString())
                                && "complete_value_equality"
                                        .equals(observation.get("evidenceGrade").getAsString())
                                && "complete_value_equality"
                                        .equals(observation.get("valueRelation").getAsString())
                                && Set.of("unknown", "inferred")
                                        .contains(
                                                observation.get("attackerControl").getAsString()));
            }
            if (!observation.get("sourceBinding").isJsonNull()) {
                JsonObject binding = observation.getAsJsonObject("sourceBinding");
                require(
                        binding.get("kind").equals(source.get("kind"))
                                && (binding.get("key").equals(source.get("id"))
                                        || binding.get("sourceId").equals(source.get("id"))));
            }
        }
    }

    private static void validateZapSessionKeys(JsonObject root, JsonObject payload) {
        String outer =
                root.has("zapSessionKey")
                        ? string(root, "zapSessionKey", MAX_ZAP_SESSION_KEY, false)
                        : null;
        String inner =
                payload.has("zapSessionKey")
                        ? string(payload, "zapSessionKey", MAX_ZAP_SESSION_KEY, false)
                        : null;
        if (outer != null && inner != null) require(outer.equals(inner));
        String ownerSuffix = "|" + root.get("zapid").getAsString();
        for (String key : new String[] {outer, inner}) {
            if (key != null)
                require(
                        key.lastIndexOf('|') > 0
                                && key.length() > ownerSuffix.length()
                                && key.substring(key.lastIndexOf('|')).equals(ownerSuffix));
        }
    }

    static void validateSummary(JsonObject value) {
        fields(
                value,
                "schemaVersion,revision,status,reasons,counters,terminal",
                "schemaVersion,revision,status,reasons,counters,terminal");
        require(integer(value.get("schemaVersion"), 2, 2) == 2);
        integer(value.get("revision"), 0, 9007199254740991L);
        enumValue(value, "status", Set.of("unknown", "partial", "complete"));
        reasons(value.get("reasons"));
        JsonObject counters = object(value.get("counters"));
        fields(counters, "lossCount,recordsRejected", "lossCount,recordsRejected");
        long loss = integer(counters.get("lossCount"), 0, 9007199254740991L),
                rejected = integer(counters.get("recordsRejected"), 0, 9007199254740991L);
        require(
                value.get("terminal").isJsonPrimitive()
                        && value.get("terminal").getAsJsonPrimitive().isBoolean());
        if ("complete".equals(value.get("status").getAsString()))
            require(
                    value.get("terminal").getAsBoolean()
                            && loss == 0
                            && rejected == 0
                            && value.getAsJsonArray("reasons").isEmpty());
    }

    private static void validateObservation(JsonObject value) {
        fields(
                value,
                "schemaVersion,identityVersion,kind,operationId,acquisition,evidenceGrade,inheritedGrade,valueRelation,propagation,gradeAuthority,attackerControl,controlReason,site,completeness,sourceBinding",
                "schemaVersion,identityVersion,kind,operationId,acquisition,evidenceGrade,inheritedGrade,valueRelation,propagation,gradeAuthority,attackerControl,controlReason,site,completeness,sourceBinding");
        integer(value.get("schemaVersion"), 2, 2);
        integer(value.get("identityVersion"), 2, 2);
        enumValue(value, "kind", Set.of("source_relationship", "policy_signal"));
        string(value, "operationId", 128, false);
        string(value, "controlReason", 160, false);
        enumValue(
                value,
                "acquisition",
                Set.of(
                        "instrumented_read",
                        "instrumented_write",
                        "initial_snapshot",
                        "sink_storage_snapshot",
                        "existing_other"));
        require("page_observed_untrusted".equals(string(value, "gradeAuthority", 64, false)));
        enumValue(
                value,
                "attackerControl",
                Set.of("observed", "inferred", "unknown", "not_applicable"));
        boolean policy = "policy_signal".equals(value.get("kind").getAsString());
        if (policy)
            require(
                    value.get("evidenceGrade").isJsonNull()
                            && value.get("inheritedGrade").isJsonNull()
                            && value.get("sourceBinding").isJsonNull()
                            && "not_applicable".equals(value.get("attackerControl").getAsString())
                            && "unavailable".equals(value.get("valueRelation").getAsString()));
        else {
            enumValue(value, "evidenceGrade", GRADES);
            if (!value.get("inheritedGrade").isJsonNull())
                enumValue(value, "inheritedGrade", GRADES);
            enumValue(value, "valueRelation", GRADES);
            require(!"instrumented_propagation".equals(value.get("valueRelation").getAsString()));
            JsonObject binding = object(value.get("sourceBinding"));
            fields(binding, "sourceId,key,kind", "sourceId,key,kind");
            string(binding, "sourceId", 128, true);
            string(binding, "key", 512, false);
            string(binding, "kind", 80, false);
        }
        if (!value.get("propagation").isJsonNull()) {
            require(!policy);
            JsonObject propagation = object(value.get("propagation"));
            fields(propagation, "operation,inheritedGrade", "operation,inheritedGrade");
            string(propagation, "operation", 128, false);
            enumValue(propagation, "inheritedGrade", GRADES);
        }
        JsonObject site = object(value.get("site"));
        fields(
                site,
                "kind,scriptUrl,line,column,domPath,attribute,operation,observationId",
                "kind");
        enumValue(site, "kind", Set.of("code", "dom", "unresolved"));
        for (String key :
                new String[] {"scriptUrl", "domPath", "attribute", "operation", "observationId"})
            if (site.has(key))
                string(
                        site,
                        key,
                        "scriptUrl".equals(key)
                                ? 2048
                                : "domPath".equals(key) ? 1024 : "attribute".equals(key) ? 80 : 128,
                        true);
        for (String key : new String[] {"line", "column"})
            if (site.has(key) && !site.get(key).isJsonNull())
                integer(site.get(key), "line".equals(key) ? 1 : 0, Integer.MAX_VALUE);
        if ("code".equals(site.get("kind").getAsString())) {
            string(site, "scriptUrl", 2048, false);
            integer(site.get("line"), 1, Integer.MAX_VALUE);
            integer(site.get("column"), 0, Integer.MAX_VALUE);
        }
        JsonObject completeness = object(value.get("completeness"));
        fields(completeness, "status,reasons", "status,reasons");
        enumValue(completeness, "status", Set.of("complete", "limited"));
        reasons(completeness.get("reasons"));
        require(value.toString().length() <= 8192);
    }

    private static void reasons(JsonElement value) {
        require(value != null && value.isJsonArray() && value.getAsJsonArray().size() <= 16);
        Set<String> seen = new HashSet<>();
        for (JsonElement reason : value.getAsJsonArray())
            require(
                    reason.isJsonPrimitive()
                            && reason.getAsJsonPrimitive().isString()
                            && reason.getAsString().matches("[a-z][a-z0-9_.:-]{0,63}")
                            && seen.add(reason.getAsString()));
    }

    private static void enumValue(JsonObject value, String key, Set<String> values) {
        require(values.contains(string(value, key, 80, false)));
    }

    private static String string(JsonObject value, String key, int max, boolean nullable) {
        JsonElement item = value.get(key);
        require(item != null);
        if (nullable && item.isJsonNull()) return null;
        require(item.isJsonPrimitive() && item.getAsJsonPrimitive().isString());
        String text = item.getAsString();
        require(
                !text.isEmpty()
                        && text.length() <= max
                        && !text.matches("(?s).*[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f].*"));
        return text;
    }

    private static long integer(JsonElement value, long min, long max) {
        require(value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber());
        try {
            long number = value.getAsBigDecimal().longValueExact();
            require(number >= min && number <= max);
            return number;
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("invalid_payload");
        }
    }

    private static JsonObject object(JsonElement value) {
        require(value != null && value.isJsonObject());
        return value.getAsJsonObject();
    }

    private static void fields(JsonObject value, String allowed, String required) {
        Set<String> keys = Set.of(allowed.split(","));
        require(value.keySet().stream().allMatch(keys::contains));
        for (String key : required.split(",")) require(value.has(key));
    }

    private static void require(boolean valid) {
        if (!valid) throw new IllegalArgumentException("invalid_payload");
    }
}
