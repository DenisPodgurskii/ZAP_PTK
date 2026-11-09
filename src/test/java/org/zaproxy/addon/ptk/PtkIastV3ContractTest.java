package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.*;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class PtkIastV3ContractTest {
    static JsonObject fixture() throws Exception {
        try (var input = PtkIastV3ContractTest.class.getResourceAsStream(
                "/org/zaproxy/addon/ptk/iast_v2_actual_content_fixture.json")) {
            JsonObject batch = JsonParser.parseReader(new InputStreamReader(input, StandardCharsets.UTF_8)).getAsJsonObject();
            batch.addProperty("schema", "ptk-zap-iast-finding-v3");
            finding(batch).add("flow", JsonParser.parseString("""
                {"schemaVersion":1,"status":"observed","reasons":[],"steps":[
                  {"index":0,"stage":"source","operation":"storage.read","sourceRef":0,"sinkRef":null,"label":"Stored value","location":"https://app.test/source","value":{"state":"withheld","type":"string","length":8,"atLimit":false}},
                  {"index":2,"stage":"propagation","operation":"String.concat","sourceRef":null,"sinkRef":null,"label":null,"location":null,"value":{"state":"unavailable","type":null,"length":null,"atLimit":false}},
                  {"index":3,"stage":"sink","operation":"code.eval","sourceRef":null,"sinkRef":0,"label":"eval","location":"https://app.test/sink","value":{"state":"withheld","type":"string","length":8,"atLimit":false}}
                ]}
                """));
            return batch;
        }
    }

    static JsonObject finding(JsonObject batch) {
        return batch.getAsJsonObject("payload").getAsJsonArray("findings").get(0).getAsJsonObject();
    }

    static JsonObject ack(JsonObject response) {
        return JsonParser.parseString(response.get("ackJson").getAsString()).getAsJsonObject();
    }

    @Test
    void orderedFlowSurvivesActualHandlerHistorySinkAndLostAckRetry() throws Exception {
        try (var receiver = new PtkIastOfflineReceiver()) {
            var batch = fixture();
            var response = receiver.receive(batch.toString());
            var ack = ack(response);
            assertEquals(3, ack.get("contractVersion").getAsInt());
            assertEquals("ptk-zap-iast-finding-v3", ack.get("schema").getAsString());
            assertEquals(1, ack.get("accepted").getAsInt());
            assertEquals(1, ack.get("alertsRaised").getAsInt());
            String other = response.getAsJsonArray("alerts").get(0).getAsJsonObject().get("otherInfo").getAsString();
            assertTrue(other.contains("Ordered redacted flow (page-observed, untrusted; not proven causality):"));
            assertTrue(other.indexOf("storage.read") < other.indexOf("String.concat"));
            assertTrue(other.indexOf("String.concat") < other.lastIndexOf("code.eval"));
            assertTrue(other.contains("withheld"));
            var retry = receiver.receive(batch.toString());
            assertEquals(response.get("ackJson"), retry.get("ackJson"));
            assertEquals(1, retry.getAsJsonArray("alerts").size());
            assertEquals(1, retry.get("historyWrites").getAsInt());
        }
    }

    @Test
    void escapedRedactionBracketsRemainStoredWithoutCredentialsQueryOrHash() throws Exception {
        try (var receiver = new PtkIastOfflineReceiver()) {
            var batch = fixture();
            step(finding(batch), 0).addProperty("location", "https://app.test/%5BREDACTED%5D/test");
            var response = receiver.receive(batch.toString());
            assertEquals(1, ack(response).get("accepted").getAsInt());
            assertTrue(response.getAsJsonArray("alerts").get(0).getAsJsonObject().get("otherInfo").getAsString().contains("https://app.test/%5BREDACTED%5D/test"));
        }
    }

    @Test
    void malformedFlowIsVersionedRejectedBeforeActualPublicSink() throws Exception {
        List<Consumer<JsonObject>> mutations = new ArrayList<>();
        mutations.add(f -> f.remove("flow"));
        mutations.add(f -> f.add("flow", com.google.gson.JsonNull.INSTANCE));
        mutations.add(f -> f.getAsJsonObject("flow").addProperty("extra", true));
        mutations.add(f -> f.getAsJsonObject("flow").addProperty("schemaVersion", 2));
        mutations.add(f -> f.getAsJsonObject("flow").addProperty("status", "complete"));
        mutations.add(f -> f.getAsJsonObject("flow").getAsJsonArray("reasons").add("unknown"));
        mutations.add(f -> f.getAsJsonObject("flow").getAsJsonArray("reasons").add("flow_field_limit"));
        mutations.add(f -> f.getAsJsonObject("flow").getAsJsonArray("steps").remove(2));
        mutations.add(f -> step(f, 1).addProperty("index", 0));
        mutations.add(f -> step(f, 1).addProperty("index", -1));
        mutations.add(f -> step(f, 1).addProperty("index", 0.5));
        mutations.add(f -> step(f, 1).addProperty("stage", "unknown"));
        mutations.add(f -> step(f, 0).add("sourceRef", com.google.gson.JsonNull.INSTANCE));
        mutations.add(f -> step(f, 0).addProperty("sourceRef", 1));
        mutations.add(f -> step(f, 2).add("sinkRef", com.google.gson.JsonNull.INSTANCE));
        mutations.add(f -> step(f, 1).addProperty("sinkRef", 0));
        mutations.add(f -> step(f, 2).addProperty("sourceRef", 0));
        mutations.add(f -> step(f, 0).addProperty("operation", "x".repeat(129)));
        mutations.add(f -> step(f, 0).addProperty("label", "x".repeat(257)));
        mutations.add(f -> step(f, 0).addProperty("location", "https://user:pass@app.test/a"));
        mutations.add(f -> step(f, 0).addProperty("location", "https://app.test/a?token=secret"));
        mutations.add(f -> step(f, 0).addProperty("location", "https://app.test/a#secret"));
        mutations.add(f -> step(f, 0).addProperty("location", "file:///tmp/a"));
        mutations.add(f -> step(f, 0).addProperty("rawValue", "SECRET"));
        mutations.add(f -> step(f, 0).getAsJsonObject("value").addProperty("raw", "SECRET"));
        mutations.add(f -> step(f, 0).getAsJsonObject("value").addProperty("length", 4097));
        mutations.add(f -> step(f, 0).getAsJsonObject("value").addProperty("state", "raw"));
        mutations.add(f -> step(f, 0).getAsJsonObject("value").addProperty("atLimit", true));
        mutations.add(f -> step(f, 1).getAsJsonObject("value").addProperty("type", "string"));
        mutations.add(f -> f.getAsJsonObject("source").addProperty("id", "wrong-source"));
        int index = 0;
        for (var mutation : mutations) {
            try (var receiver = new PtkIastOfflineReceiver()) {
                var batch = fixture();
                mutation.accept(finding(batch));
                var response = receiver.receive(batch.toString());
                var ack = ack(response);
                assertEquals(3, ack.get("contractVersion").getAsInt(), "mutation " + index);
                assertEquals("ERROR", ack.get("result").getAsString(), "mutation " + index++);
                assertEquals("invalid_payload", ack.get("errorCode").getAsString());
                assertEquals(0, ack.get("accepted").getAsInt());
                assertTrue(response.getAsJsonArray("alerts").isEmpty());
                assertEquals(0, response.get("historyWrites").getAsInt());
            }
        }
    }

    private static JsonObject step(JsonObject finding, int index) {
        return finding.getAsJsonObject("flow").getAsJsonArray("steps").get(index).getAsJsonObject();
    }

    @Test
    void zeroSummaryAndUnavailableLimitedFlowAreExplicitAndVersioned() throws Exception {
        for (String flow : List.of(
                "{\"schemaVersion\":1,\"status\":\"unavailable\",\"reasons\":[\"flow_absent\"],\"steps\":[]}",
                "{\"schemaVersion\":1,\"status\":\"limited\",\"reasons\":[\"flow_byte_limit\"],\"steps\":[]}",
                "{\"schemaVersion\":1,\"status\":\"limited\",\"reasons\":[\"flow_source_not_retained\"],\"steps\":[]}")) {
            try (var receiver = new PtkIastOfflineReceiver()) {
                var batch = fixture();
                finding(batch).add("flow", JsonParser.parseString(flow));
                var response = receiver.receive(batch.toString());
                assertEquals(1, ack(response).get("accepted").getAsInt());
                assertTrue(response.getAsJsonArray("alerts").get(0).getAsJsonObject().get("otherInfo").getAsString().contains(flow));
                batch.addProperty("batchId", "terminal-summary");
                batch.addProperty("batchSeq", 2);
                batch.getAsJsonObject("payload").getAsJsonArray("findings").remove(0);
                var summary = batch.getAsJsonObject("payload").getAsJsonObject("scanCompleteness");
                summary.addProperty("revision", 2);
                summary.addProperty("terminal", true);
                var result = ack(receiver.receive(batch.toString()));
                assertEquals(3, result.get("contractVersion").getAsInt());
                assertEquals(0, result.get("received").getAsInt());
                assertEquals(2, result.get("scanCompletenessRevision").getAsInt());
                assertTrue(result.get("scanCompletenessAccepted").getAsBoolean());
                batch.addProperty("batchId", "stale-summary");
                summary.addProperty("revision", 1);
                var stale = ack(receiver.receive(batch.toString()));
                assertEquals(3, stale.get("contractVersion").getAsInt());
                assertEquals("invalid_completeness_revision", stale.get("errorCode").getAsString());
            }
        }
    }

    @Test
    void wireVersionsCannotBorrowBatchFindingOrCompletenessReceiptsAndRetireExactly() throws Exception {
        try (var receiver = new PtkIastOfflineReceiver()) {
            var v3 = fixture();
            var v2 = v3.deepCopy();
            v2.addProperty("schema", "ptk-zap-iast-finding-v2");
            finding(v2).remove("flow");
            var ack2 = ack(receiver.receive(v2.toString()));
            assertEquals(2, ack2.get("contractVersion").getAsInt());
            assertFalse(ack2.has("schema"));
            var response3 = receiver.receive(v3.toString());
            assertEquals(1, ack(response3).get("alertsRaised").getAsInt());
            assertEquals(2, response3.getAsJsonArray("alerts").size());
            PtkAlertHandler.retireSession("owner", "session");
            assertEquals(ack(response3), ack(receiver.receive(v3.toString())));
            v3.addProperty("batchId", "after-retire");
            assertEquals("retired_session", ack(receiver.receive(v3.toString())).get("errorCode").getAsString());
            // Same session text, different owner remains independently admissible.
            v3.addProperty("zapid", "owner2");
            v3.remove("zapSessionKey");
            v3.getAsJsonObject("payload").remove("zapSessionKey");
            assertEquals(1, ack(receiver.receive(v3.toString())).get("alertsRaised").getAsInt());
        }
    }

    @Test
    void flowUnderV2AndDuplicateIdentitiesNeverInsertAndRaiseFailureNeverAccepts() throws Exception {
        try (var receiver = new PtkIastOfflineReceiver()) {
            var batch = fixture();
            batch.addProperty("schema", "ptk-zap-iast-finding-v2");
            var rejected = receiver.receive(batch.toString());
            assertEquals("invalid_payload", ack(rejected).get("errorCode").getAsString());
            assertTrue(rejected.getAsJsonArray("alerts").isEmpty());
            batch = fixture();
            batch.getAsJsonObject("payload").getAsJsonArray("findings").add(finding(batch).deepCopy());
            rejected = receiver.receive(batch.toString());
            assertEquals(3, ack(rejected).get("contractVersion").getAsInt());
            assertTrue(rejected.getAsJsonArray("alerts").isEmpty());
            receiver.rejectRaises(true);
            var failure = ack(receiver.receive(fixture().toString()));
            assertEquals(3, failure.get("contractVersion").getAsInt());
            assertEquals(0, failure.get("accepted").getAsInt());
            assertEquals("rejected_raise_failed", failure.getAsJsonArray("findingResults").get(0).getAsJsonObject().get("status").getAsString());
        }
    }

    @Test
    void stepAndUtf8BudgetsRejectBeforeSinkRatherThanDroppingFields() throws Exception {
        for (boolean utf8 : List.of(false, true)) {
            try (var receiver = new PtkIastOfflineReceiver()) {
                var batch = fixture();
                var steps = finding(batch).getAsJsonObject("flow").getAsJsonArray("steps");
                var template = steps.get(1).deepCopy().getAsJsonObject();
                steps.remove(2);
                int count = utf8 ? 5 : 23;
                for (int i = 2; i < count; i++) {
                    var step = template.deepCopy();
                    step.addProperty("index", i);
                    if (utf8) {
                        step.addProperty("operation", "字".repeat(128));
                        step.addProperty("label", "字".repeat(256));
                        step.addProperty("location", "https://app.test/" + "字".repeat(1600));
                    }
                    if (i == count - 1) {
                        step.addProperty("stage", "sink");
                        step.addProperty("sinkRef", 0);
                    }
                    steps.add(step);
                }
                var response = receiver.receive(batch.toString());
                assertEquals(3, ack(response).get("contractVersion").getAsInt());
                assertEquals("invalid_payload", ack(response).get("errorCode").getAsString());
                assertTrue(response.getAsJsonArray("alerts").isEmpty());
                assertEquals(0, response.get("historyWrites").getAsInt());
            }
        }
    }

    @Test
    void malformedAndOversizeCannotReturnAcceptedV3Receipt() throws Exception {
        try (var receiver = new PtkIastOfflineReceiver()) {
            for (String body : List.of("{\"schema\":\"ptk-zap-iast-finding-v3\",", "x".repeat(16 * 1024 * 1024 + 1))) {
                var response = receiver.receive(body);
                var ack = ack(response);
                assertEquals("ERROR", ack.get("result").getAsString());
                assertEquals(0, ack.get("accepted").getAsInt());
                assertFalse(ack.get("scanCompletenessAccepted").getAsBoolean());
                assertTrue(response.getAsJsonArray("alerts").isEmpty());
            }
        }
    }

    @Test
    void retiredV3RetryRequiresIdenticalBodyWhileLegacyRetirementStaysUnchanged() throws Exception {
        for (boolean v3 : List.of(true, false)) {
            try (var receiver = new PtkIastOfflineReceiver()) {
                var batch = fixture();
                if (!v3) {
                    batch.addProperty("schema", "ptk-zap-iast-finding-v2");
                    finding(batch).remove("flow");
                }
                var original = receiver.receive(batch.toString());
                PtkAlertHandler.retireSession("owner", "session");
                assertEquals(original.get("ackJson"), receiver.receive(batch.toString()).get("ackJson"));
                if (v3) step(finding(batch), 0).addProperty("operation", "changed.operation");
                else finding(batch).addProperty("summary", "changed legacy summary");
                var changed = receiver.receive(batch.toString());
                if (v3) {
                    assertEquals("ERROR", ack(changed).get("result").getAsString());
                    assertEquals(3, ack(changed).get("contractVersion").getAsInt());
                    assertEquals("immutable_identity_conflict", ack(changed).get("errorCode").getAsString());
                } else assertEquals(original.get("ackJson"), changed.get("ackJson"));
                assertEquals(1, changed.get("historyWrites").getAsInt());
                assertEquals(1, changed.getAsJsonArray("alerts").size());
            }
        }
    }
}
