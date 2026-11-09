package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.ptk.model.PtkFinding;

class PtkIastV2ContractTest {
    @BeforeEach
    void reset() {
        PtkAlertHandler.clearAllReceipts();
    }

    static JsonObject emptyBatch() {
        return JsonParser.parseString(
                        """
                {"source":"ptk","type":"iast_findings_batch","schema":"ptk-zap-iast-finding-v2",
                 "ts":1,"batchId":"batch-one","batchSeq":1,"zapid":"owner","browserid":"edge",
                 "payload":{"engine":"IAST","scanId":"scan","sessionId":"session","findings":[],
                 "truncated":true,"scanCompleteness":{"schemaVersion":2,"revision":1,"status":"unknown",
                 "reasons":["document_receipt_pending"],"counters":{"lossCount":0,"recordsRejected":0},"terminal":false}}}
                """)
                .getAsJsonObject();
    }

    @Test
    void zeroFindingCompletenessHasRevisionAckAndExactRetryReceipt() {
        JsonObject batch = emptyBatch();
        PtkIastV2Contract.validate(batch);
        var ack = PtkAlertHandler.processAlertBatchWithAck(batch.toString());
        assertFalse(ack.permanentFailure);
        assertEquals(0, ack.received);
        assertTrue(ack.scanCompletenessAccepted);
        assertEquals(1L, ack.scanCompletenessRevision);
        assertEquals(ack, PtkAlertHandler.processAlertBatchWithAck(batch.toString()));
        batch.getAsJsonObject("payload")
                .getAsJsonObject("scanCompleteness")
                .addProperty("revision", 2);
        assertEquals(
                "immutable_identity_conflict",
                PtkAlertHandler.processAlertBatchWithAck(batch.toString()).errorCode);
    }

    @Test
    void unknownSchemaAndUnknownFieldsFailPermanently() {
        JsonObject batch = emptyBatch();
        batch.addProperty("schema", "ptk-zap-iast-finding-v77");
        assertEquals(
                "unsupported_schema",
                PtkAlertHandler.processAlertBatchWithAck(batch.toString()).errorCode);
        batch = emptyBatch();
        batch.addProperty("unexpected", "not allowed");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        PtkIastV2Contract.validate(
                                JsonParser.parseString(batchWithUnexpected()).getAsJsonObject()));
        assertEquals(
                "invalid_payload",
                PtkAlertHandler.processAlertBatchWithAck(batch.toString()).errorCode);
    }

    private static String batchWithUnexpected() {
        JsonObject batch = emptyBatch();
        batch.addProperty("unexpected", "not allowed");
        return batch.toString();
    }

    @Test
    void v2SchemaAlwaysUsesStrictValidatorEvenWithMismatchedType() {
        JsonObject batch = emptyBatch();
        batch.addProperty("type", "dast_findings_batch");
        var ack = PtkAlertHandler.processAlertBatchWithAck(batch.toString());
        assertTrue(ack.permanentFailure);
        assertEquals("invalid_payload", ack.errorCode);
        assertFalse(ack.scanCompletenessAccepted);
    }

    @Test
    void falseCompleteAndCounterRegressionAreRejected() {
        JsonObject batch = emptyBatch();
        batch.getAsJsonObject("payload")
                .getAsJsonObject("scanCompleteness")
                .addProperty("status", "complete");
        assertEquals(
                "invalid_payload",
                PtkAlertHandler.processAlertBatchWithAck(batch.toString()).errorCode);
        batch = emptyBatch();
        assertTrue(
                PtkAlertHandler.processAlertBatchWithAck(batch.toString())
                        .scanCompletenessAccepted);
        batch.addProperty("batchId", "batch-two");
        batch.getAsJsonObject("payload")
                .getAsJsonObject("scanCompleteness")
                .addProperty("revision", 0);
        assertEquals(
                "invalid_completeness_revision",
                PtkAlertHandler.processAlertBatchWithAck(batch.toString()).errorCode);
    }

    @Test
    void receiptCapacityIsAllEngineSessionBoundAndNeverEvictsActiveIdentity() {
        PtkAlertReceipts receipts = new PtkAlertReceipts();
        for (int i = 0; i < 8192; i++)
            assertEquals(
                    PtkAlertReceipts.Admission.NEW,
                    receipts.admit("session-a", "engine-" + (i % 3) + ":" + i, "digest", 16));
        assertEquals(
                PtkAlertReceipts.Admission.CAPACITY,
                receipts.admit("session-a", "overflow", "digest", 16));
        assertEquals(
                PtkAlertReceipts.Admission.DUPLICATE,
                receipts.admit("session-a", "engine-0:0", "digest", 16));
        assertEquals(
                PtkAlertReceipts.Admission.CONFLICT,
                receipts.admit("session-a", "engine-0:0", "changed", 16));
        for (int i = 0; i < 8192; i++)
            assertEquals(
                    PtkAlertReceipts.Admission.NEW,
                    receipts.admit("session-b", "key-" + i, "digest", 16));
        assertEquals(
                PtkAlertReceipts.Admission.CAPACITY,
                receipts.admit("session-c", "key", "digest", 16));
        assertEquals(8192, receipts.retire("session-a").size());
        assertEquals(
                PtkAlertReceipts.Admission.RETIRED,
                receipts.admit("session-a", "key", "digest", 16));
        assertEquals(
                PtkAlertReceipts.Admission.NEW, receipts.admit("session-c", "key", "digest", 16));
    }

    @Test
    void receiptByteBudgetAndLifecycleClearAreIndependentOfEntryBudget() {
        PtkAlertReceipts receipts = new PtkAlertReceipts();
        assertEquals(
                PtkAlertReceipts.Admission.NEW,
                receipts.admit("a", "large", "digest", PtkAlertReceipts.SESSION_BYTES));
        assertEquals(PtkAlertReceipts.Admission.CAPACITY, receipts.admit("a", "next", "digest", 1));
        assertEquals(
                PtkAlertReceipts.Admission.NEW,
                receipts.admit("b", "large", "digest", PtkAlertReceipts.SESSION_BYTES));
        assertEquals(PtkAlertReceipts.Admission.CAPACITY, receipts.admit("c", "next", "digest", 1));
        receipts.clear();
        assertEquals(PtkAlertReceipts.Admission.NEW, receipts.admit("a", "next", "digest", 1));
    }

    @Test
    void terminalRetirementKeepsOnlyBoundedOldAckHistory() {
        JsonObject batch = emptyBatch();
        var first = PtkAlertHandler.processAlertBatchWithAck(batch.toString());
        PtkAlertHandler.retireSession("owner", "session");
        assertEquals(first, PtkAlertHandler.processAlertBatchWithAck(batch.toString()));
        batch.addProperty("batchId", "new-batch-after-retirement");
        assertEquals(
                "retired_session",
                PtkAlertHandler.processAlertBatchWithAck(batch.toString()).errorCode);
    }

    private static JsonObject actualContentBatch() {
        try (var input =
                PtkIastV2ContractTest.class.getResourceAsStream(
                        "/org/zaproxy/addon/ptk/iast_v2_actual_content_fixture.json")) {
            return JsonParser.parseReader(new InputStreamReader(input, StandardCharsets.UTF_8))
                    .getAsJsonObject();
        } catch (java.io.IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    @Test
    void realManagedBridgeEnvelopeAcceptsZeroAndNonzeroFindings() {
        JsonObject batch = actualContentBatch();
        PtkIastV2Contract.validate(batch);
        batch.getAsJsonObject("payload").getAsJsonArray("findings").remove(0);
        PtkIastV2Contract.validate(batch);
        var ack = PtkAlertHandler.processAlertBatchWithAck(batch.toString());
        assertFalse(ack.permanentFailure);
        assertEquals(batch.get("batchId").getAsString(), ack.batchId);
        assertTrue(ack.scanCompletenessAccepted);
        assertEquals(1L, ack.scanCompletenessRevision);
    }

    @Test
    void managedRoutingKeyBoundsCopiesAndOwnerAreStrictWithoutCouplingNativeSessionId() {
        JsonObject batch = actualContentBatch();
        String owner = "o".repeat(128);
        String key = "https://zap/zapCallBackUrl/" + "s".repeat(476) + "|" + owner;
        assertEquals(632, key.length());
        batch.addProperty("zapid", owner);
        batch.addProperty("zapSessionKey", key);
        batch.getAsJsonObject("payload").addProperty("zapSessionKey", key);
        batch.getAsJsonObject("payload").addProperty("sessionId", "independent-native-session");
        PtkIastV2Contract.validate(batch);
        for (boolean outer : new boolean[] {true, false}) {
            JsonObject bad = batch.deepCopy();
            (outer ? bad : bad.getAsJsonObject("payload")).addProperty("zapSessionKey", "s" + key);
            JsonObject oversizedKey = bad;
            assertThrows(
                    IllegalArgumentException.class, () -> PtkIastV2Contract.validate(oversizedKey));
            bad = batch.deepCopy();
            (outer ? bad : bad.getAsJsonObject("payload")).add("zapSessionKey", JsonNull.INSTANCE);
            JsonObject nullKey = bad;
            assertThrows(IllegalArgumentException.class, () -> PtkIastV2Contract.validate(nullKey));
            bad = batch.deepCopy();
            (outer ? bad : bad.getAsJsonObject("payload")).addProperty("zapSessionKey", 1);
            JsonObject numericKey = bad;
            assertThrows(
                    IllegalArgumentException.class, () -> PtkIastV2Contract.validate(numericKey));
        }
        JsonObject mismatchedCopies = actualContentBatch();
        mismatchedCopies
                .getAsJsonObject("payload")
                .addProperty("zapSessionKey", "https://zap/zapCallBackUrl/different_fixture|owner");
        assertEquals(
                "invalid_payload",
                PtkAlertHandler.processAlertBatchWithAck(mismatchedCopies.toString()).errorCode);
        JsonObject mismatchedOwner = actualContentBatch();
        mismatchedOwner.addProperty("zapid", "other-owner");
        var ack = PtkAlertHandler.processAlertBatchWithAck(mismatchedOwner.toString());
        assertTrue(ack.permanentFailure);
        assertFalse(ack.scanCompletenessAccepted);
        assertEquals("invalid_payload", ack.errorCode);
        for (boolean outer : new boolean[] {true, false}) {
            JsonObject optionalCopy = actualContentBatch();
            (outer ? optionalCopy : optionalCopy.getAsJsonObject("payload"))
                    .remove("zapSessionKey");
            PtkIastV2Contract.validate(optionalCopy);
        }
    }

    @Test
    void actualContentNativeMapperFixtureIncludingRawRequestValidatesAndPreservesInfo() {
        JsonObject batch = actualContentBatch();
        PtkIastV2Contract.validate(batch);
        JsonObject finding =
                batch.getAsJsonObject("payload")
                        .getAsJsonArray("findings")
                        .get(0)
                        .getAsJsonObject();
        finding.addProperty("severity", "info");
        PtkIastV2Contract.validate(batch);
        var resources = new PtkResourcesLoader().loadAll();
        PtkFinding model = new Gson().fromJson(finding, PtkFinding.class);
        Alert alert =
                PtkAlertBuilder.buildFromFinding(
                        model, "IAST", new PtkZapMapper(resources), resources);
        assertEquals(Alert.RISK_INFO, alert.getRisk());
        assertTrue(alert.getOtherInfo().contains("page-observed, untrusted"));
        assertTrue(alert.getOtherInfo().contains("sink_storage_snapshot"));
        for (String field : new String[] {"scriptUrl", "line", "column"}) {
            JsonObject bad = actualContentBatch();
            bad.getAsJsonObject("payload")
                    .getAsJsonArray("findings")
                    .get(0)
                    .getAsJsonObject()
                    .getAsJsonObject("observation")
                    .getAsJsonObject("site")
                    .add(field, JsonNull.INSTANCE);
            assertThrows(IllegalArgumentException.class, () -> PtkIastV2Contract.validate(bad));
        }
        finding.getAsJsonObject("request").addProperty("unrecognized", true);
        assertThrows(IllegalArgumentException.class, () -> PtkIastV2Contract.validate(batch));
    }

    @Test
    void sourceLessPolicyCannotClaimTaintProof() {
        JsonObject batch = actualContentBatch();
        JsonObject finding =
                batch.getAsJsonObject("payload")
                        .getAsJsonArray("findings")
                        .get(0)
                        .getAsJsonObject();
        JsonObject observation = finding.getAsJsonObject("observation");
        observation.addProperty("kind", "policy_signal");
        observation.addProperty("acquisition", "existing_other");
        observation.add("evidenceGrade", JsonNull.INSTANCE);
        observation.add("inheritedGrade", JsonNull.INSTANCE);
        observation.add("sourceBinding", JsonNull.INSTANCE);
        observation.addProperty("attackerControl", "not_applicable");
        observation.addProperty("valueRelation", "unavailable");
        PtkIastV2Contract.validate(batch);
        finding.getAsJsonObject("proof").addProperty("mode", "taint");
        assertThrows(IllegalArgumentException.class, () -> PtkIastV2Contract.validate(batch));
    }
}
