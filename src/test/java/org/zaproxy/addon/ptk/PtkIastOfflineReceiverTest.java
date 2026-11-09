package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

class PtkIastOfflineReceiverTest {
    private static JsonObject fixture() throws Exception {
        try (var input =
                PtkIastOfflineReceiverTest.class.getResourceAsStream(
                        "/org/zaproxy/addon/ptk/iast_v2_actual_content_fixture.json")) {
            return JsonParser.parseReader(new InputStreamReader(input, StandardCharsets.UTF_8))
                    .getAsJsonObject();
        }
    }

    @Test
    void nonzeroHandlerRaisesRealMappedAlertIntoPublicTestSinkAndDeduplicatesAckLoss()
            throws Exception {
        try (var receiver = new PtkIastOfflineReceiver()) {
            String body = fixture().toString();
            var result = receiver.receive(body);
            var ack = JsonParser.parseString(result.get("ackJson").getAsString()).getAsJsonObject();
            assertFalse(ack.get("permanentFailure").getAsBoolean());
            assertEquals(1, ack.get("accepted").getAsInt());
            assertEquals(1, ack.get("alertsRaised").getAsInt());
            assertTrue(ack.get("scanCompletenessAccepted").getAsBoolean());
            var alert = result.getAsJsonArray("alerts").get(0).getAsJsonObject();
            assertEquals(1, alert.get("risk").getAsInt());
            assertTrue(alert.get("otherInfo").getAsString().contains("sink_storage_snapshot"));
            assertTrue(alert.get("otherInfo").getAsString().contains("localStorage:badValue"));
            assertTrue(alert.get("otherInfo").getAsString().contains("complete_value_equality"));
            var retry = receiver.receive(body);
            assertEquals(result.get("ackJson"), retry.get("ackJson"));
            assertEquals(1, retry.getAsJsonArray("alerts").size());
            assertEquals(1, retry.get("historyWrites").getAsInt());
        }
    }

    @Test
    void raiseFailureIsNotAcceptedAndInfoIsNotRaisedToRuleDefault() throws Exception {
        try (var receiver = new PtkIastOfflineReceiver()) {
            var batch = fixture();
            batch.getAsJsonObject("payload")
                    .getAsJsonArray("findings")
                    .get(0)
                    .getAsJsonObject()
                    .addProperty("severity", "info");
            var result = receiver.receive(batch.toString());
            assertEquals(
                    0,
                    result.getAsJsonArray("alerts")
                            .get(0)
                            .getAsJsonObject()
                            .get("risk")
                            .getAsInt());
        }
        try (var receiver = new PtkIastOfflineReceiver()) {
            receiver.rejectRaises(true);
            var result = receiver.receive(fixture().toString());
            var ack = JsonParser.parseString(result.get("ackJson").getAsString()).getAsJsonObject();
            assertEquals(0, ack.get("accepted").getAsInt());
            assertEquals(0, ack.get("alertsRaised").getAsInt());
            assertEquals(
                    "rejected_raise_failed",
                    ack.getAsJsonArray("findingResults")
                            .get(0)
                            .getAsJsonObject()
                            .get("status")
                            .getAsString());
            assertTrue(result.getAsJsonArray("alerts").isEmpty());
        }
    }

    @Test
    void returningFromAlertFoundWithoutStorageCannotProduceAcceptedReceipt() throws Exception {
        try (var receiver = new PtkIastOfflineReceiver()) {
            receiver.silentlyDropRaises(true);
            var result = receiver.receive(fixture().toString());
            var ack = JsonParser.parseString(result.get("ackJson").getAsString()).getAsJsonObject();
            assertEquals(0, ack.get("accepted").getAsInt());
            assertEquals(0, ack.get("alertsRaised").getAsInt());
            assertEquals(
                    "rejected_raise_failed",
                    ack.getAsJsonArray("findingResults")
                            .get(0)
                            .getAsJsonObject()
                            .get("status")
                            .getAsString());
            assertTrue(result.getAsJsonArray("alerts").isEmpty());
        }
    }
}
