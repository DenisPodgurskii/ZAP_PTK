package org.zaproxy.addon.ptk;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/** Strict v3 validation before model binding; v2 observation/identity semantics stay unchanged. */
final class PtkIastV3Contract {
    static final String V3 = "ptk-zap-iast-finding-v3";
    private static final Set<String> REASONS = Set.of(
            "flow_absent", "flow_policy_signal", "flow_step_limit", "flow_upstream_at_limit",
            "flow_byte_limit", "flow_field_limit", "flow_operation_unavailable", "flow_source_not_retained");
    private static final Set<String> EMPTY_LIMITS = Set.of(
            "flow_step_limit", "flow_upstream_at_limit", "flow_byte_limit", "flow_source_not_retained");

    private PtkIastV3Contract() {}

    static void validate(JsonObject root) {
        require(V3.equals(text(root.get("schema"), 64, false)));
        if (root.has("browserid")) text(root.get("browserid"), 128, true);
        JsonObject payload = object(root.get("payload"));
        if (payload.has("truncated")) bool(payload.get("truncated"));
        JsonObject legacy = root.deepCopy();
        legacy.addProperty("schema", PtkIastV2Contract.V2);
        require(payload.has("findings") && payload.get("findings").isJsonArray());
        Set<String> ids = new HashSet<>();
        Set<String> fingerprints = new HashSet<>();
        int index = 0;
        for (JsonElement item : payload.getAsJsonArray("findings")) {
            JsonObject finding = object(item);
            require(item.toString().getBytes(StandardCharsets.UTF_8).length <= 65536);
            require(ids.add(text(finding.get("id"), 128, false)));
            require(fingerprints.add(text(finding.get("fingerprint"), 128, false)));
            validateFlow(finding);
            legacy.getAsJsonObject("payload").getAsJsonArray("findings")
                    .get(index++).getAsJsonObject().remove("flow");
        }
        // No changes to the existing v2 validator or its public acceptance behavior.
        PtkIastV2Contract.validate(legacy);
    }

    private static void validateFlow(JsonObject finding) {
        JsonObject flow = object(finding.get("flow"));
        fields(flow, "schemaVersion,status,reasons,steps");
        integer(flow.get("schemaVersion"), 1, 1);
        String status = text(flow.get("status"), 32, false);
        require(Set.of("observed", "limited", "unavailable").contains(status));
        require(flow.toString().getBytes(StandardCharsets.UTF_8).length <= 8192);
        JsonElement reasonArray = flow.get("reasons");
        require(reasonArray.isJsonArray() && reasonArray.getAsJsonArray().size() <= 8);
        Set<String> reasons = new HashSet<>();
        for (JsonElement reason : reasonArray.getAsJsonArray()) {
            String value = text(reason, 80, false);
            require(REASONS.contains(value) && reasons.add(value));
        }
        require(flow.get("steps").isJsonArray());
        var steps = flow.getAsJsonArray("steps");
        require(steps.size() <= 22);
        boolean policy = "policy_signal".equals(object(finding.get("observation")).get("kind").getAsString());
        if (policy) require("unavailable".equals(status) && reasons.equals(Set.of("flow_policy_signal")) && steps.isEmpty());
        if ("observed".equals(status)) require(!steps.isEmpty() && reasons.isEmpty());
        if ("unavailable".equals(status)) require(steps.isEmpty() && reasons.equals(Set.of(policy ? "flow_policy_signal" : "flow_absent")));
        if ("limited".equals(status)) {
            require(!reasons.isEmpty() && !reasons.contains("flow_absent") && !reasons.contains("flow_policy_signal"));
            if (steps.isEmpty()) require(reasons.stream().anyMatch(EMPTY_LIMITS::contains));
        }
        if (reasons.contains("flow_byte_limit") || reasons.contains("flow_source_not_retained")) require(steps.isEmpty());
        if (steps.size() == 22) require("limited".equals(status) && reasons.contains("flow_upstream_at_limit"));
        long prior = -1;
        boolean source = false;
        for (int i = 0; i < steps.size(); i++) {
            JsonObject step = object(steps.get(i));
            fields(step, "index,stage,operation,sourceRef,sinkRef,label,location,value");
            long current = integer(step.get("index"), 0, Integer.MAX_VALUE);
            require(current > prior);
            prior = current;
            String stage = text(step.get("stage"), 32, false);
            require(Set.of("source", "propagation", "sink").contains(stage));
            text(step.get("operation"), 128, true);
            text(step.get("label"), 256, true);
            String location = text(step.get("location"), 2048, true);
            if (location != null) {
                try {
                    URI uri = new URI(location);
                    require(("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                            && uri.getHost() != null && uri.getRawUserInfo() == null
                            && uri.getRawQuery() == null && uri.getRawFragment() == null);
                } catch (java.net.URISyntaxException invalid) {
                    throw new IllegalArgumentException("invalid_payload");
                }
            }
            boolean sourceRef = ref(step.get("sourceRef"));
            boolean sinkRef = ref(step.get("sinkRef"));
            require(!sourceRef || "source".equals(stage) || "propagation".equals(stage));
            require(!sinkRef || "sink".equals(stage));
            source |= sourceRef;
            if (i == steps.size() - 1) require("sink".equals(stage) && sinkRef);
            validateValue(object(step.get("value")));
        }
        if (!steps.isEmpty()) {
            require(!policy && source);
            require(!object(finding.get("source")).get("id").isJsonNull());
            require(!object(finding.get("sink")).get("id").isJsonNull());
        }
    }

    private static void validateValue(JsonObject value) {
        fields(value, "state,type,length,atLimit");
        String state = text(value.get("state"), 32, false);
        boolean atLimit = bool(value.get("atLimit"));
        String type = text(value.get("type"), 32, true);
        if ("unavailable".equals(state)) {
            require(type == null && value.get("length").isJsonNull() && !atLimit);
            return;
        }
        require("withheld".equals(state) && type != null && Set.of(
                "string", "number", "boolean", "bigint", "symbol", "function", "object", "undefined", "null").contains(type));
        if ("string".equals(type)) {
            long length = integer(value.get("length"), 0, 4096);
            require(atLimit == (length == 4096));
        } else require(value.get("length").isJsonNull() && !atLimit);
    }

    private static boolean ref(JsonElement value) {
        require(value != null);
        if (value.isJsonNull()) return false;
        integer(value, 0, 0);
        return true;
    }

    private static String text(JsonElement value, int max, boolean nullable) {
        require(value != null);
        if (nullable && value.isJsonNull()) return null;
        require(value.isJsonPrimitive() && value.getAsJsonPrimitive().isString());
        String text = value.getAsString();
        require(text.length() <= max && (nullable || !text.isEmpty())
                && !text.matches("(?s).*[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f].*"));
        return text;
    }

    private static long integer(JsonElement value, long min, long max) {
        require(value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber());
        try {
            long number = value.getAsBigDecimal().longValueExact();
            require(number >= min && number <= max);
            return number;
        } catch (ArithmeticException invalid) {
            throw new IllegalArgumentException("invalid_payload");
        }
    }

    private static boolean bool(JsonElement value) {
        require(value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isBoolean());
        return value.getAsBoolean();
    }

    private static JsonObject object(JsonElement value) {
        require(value != null && value.isJsonObject());
        return value.getAsJsonObject();
    }

    private static void fields(JsonObject object, String fields) {
        require(object.keySet().equals(Set.of(fields.split(","))));
    }

    private static void require(boolean valid) {
        if (!valid) throw new IllegalArgumentException("invalid_payload");
    }
}
