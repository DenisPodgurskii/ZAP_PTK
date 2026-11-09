package org.zaproxy.addon.ptk;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseServer;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.RecordTag;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.db.TableTag;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.I18N;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Offline contract receiver. Only the public ZAP database/alert side-effect boundaries are
 * substituted; validation, handler, resources, mapping, builder and ACK serialization are real.
 * This deliberately does not claim native ZAP database insertion or browser qualification.
 */
public final class PtkIastOfflineReceiver implements AutoCloseable {
    private static final Gson GSON = new Gson();
    private final Model previousModel;
    private final ExtensionLoader previousLoader;
    private final Model model;
    private final Sink sink = new Sink();
    private final History history = new History();

    public PtkIastOfflineReceiver() {
        String home = System.getProperty("ptk.offline.zapHome");
        if (home != null) {
            try {
                Files.createDirectories(Path.of(home));
            } catch (java.io.IOException exception) {
                throw new IllegalStateException("offline test home unavailable", exception);
            }
            Constant.setZapHome(home);
        }
        if (Constant.messages == null) Constant.messages = new I18N(Locale.ENGLISH);
        previousModel = Model.getSingleton();
        previousLoader =
                Control.getSingleton() == null ? null : Control.getSingleton().getExtensionLoader();
        model = new Model();
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(
                model,
                new ExtensionLoader(model, null) {
                    @Override
                    public <T extends Extension> T getExtension(Class<T> type) {
                        return type == ExtensionAlert.class ? type.cast(sink) : null;
                    }
                });
        HistoryReference.setTableHistory(history);
        HistoryReference.setTableTag(new Tags());
        HistoryReference.setTableAlert(new Alerts());
        PtkAlertHandler.clearAllReceipts();
    }

    public JsonObject receive(String body) {
        var ack = PtkAlertHandler.processAlertBatchWithAck(body);
        JsonObject result = new JsonObject();
        // The transport consumes these exact Gson bytes, not a JS-authored ACK.
        result.addProperty("ackJson", GSON.toJson(ack));
        result.add("alerts", GSON.toJsonTree(sink.alerts));
        result.addProperty("historyWrites", history.writes);
        return result;
    }

    public void rejectRaises(boolean reject) {
        sink.reject = reject;
    }

    public void silentlyDropRaises(boolean drop) {
        sink.silentDrop = drop;
    }

    @Override
    public void close() {
        PtkAlertHandler.clearAllReceipts();
        Model.setSingletonForTesting(previousModel);
        Control.initSingletonForTesting(previousModel, previousLoader);
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableTag(null);
        HistoryReference.setTableAlert(null);
    }

    // Fail on every unanticipated database operation: this sink must not silently
    // become an alternative database or hide a new production side effect.
    private static UnsupportedOperationException unexpected() {
        return new UnsupportedOperationException("unexpected offline database operation");
    }

    private static final class History implements TableHistory {
        int writes;

        @Override
        public RecordHistory write(long sessionId, int type, HttpMessage message) {
            RecordHistory record = new RecordHistory();
            record.setHistoryId(++writes);
            record.setHistoryType(type);
            record.setSessionId(sessionId);
            return record;
        }

        public void databaseOpen(DatabaseServer server) {
            throw unexpected();
        }

        public RecordHistory read(int id) {
            throw unexpected();
        }

        public List<Integer> getHistoryIds(long id) {
            throw unexpected();
        }

        public List<Integer> getHistoryIdsStartingAt(long id, int start) {
            throw unexpected();
        }

        public List<Integer> getHistoryIdsOfHistType(long id, int... types) {
            throw unexpected();
        }

        public List<Integer> getHistoryIdsOfHistTypeStartingAt(long id, int start, int... types) {
            throw unexpected();
        }

        public List<Integer> getHistoryIdsExceptOfHistType(long id, int... types) {
            throw unexpected();
        }

        public List<Integer> getHistoryIdsExceptOfHistTypeStartingAt(
                long id, int start, int... types) {
            throw unexpected();
        }

        public List<Integer> getHistoryList(long id, int type, String filter, boolean inverse) {
            throw unexpected();
        }

        public void deleteHistorySession(long id) {
            throw unexpected();
        }

        public void deleteHistoryType(long id, int type) {
            throw unexpected();
        }

        public void delete(int id) {
            throw unexpected();
        }

        public void delete(List<Integer> ids) {
            throw unexpected();
        }

        public void delete(List<Integer> ids, int type) {
            throw unexpected();
        }

        public void deleteTemporary() {
            throw unexpected();
        }

        public boolean containsURI(long id, int type, String uri, String method, byte[] body) {
            throw unexpected();
        }

        public RecordHistory getHistoryCache(HistoryReference reference, HttpMessage message) {
            throw unexpected();
        }

        public void updateNote(int id, String note) {
            throw unexpected();
        }

        public int lastIndex() {
            throw unexpected();
        }
    }

    private static final class Tags implements TableTag {
        public List<RecordTag> getTagsForHistoryID(long id) {
            return List.of();
        }

        public void databaseOpen(DatabaseServer server) {
            throw unexpected();
        }

        public RecordTag read(long id) {
            throw unexpected();
        }

        public RecordTag insert(long id, String tag) {
            throw unexpected();
        }

        public void delete(long id, String tag) {
            throw unexpected();
        }

        public List<String> getAllTags() {
            throw unexpected();
        }

        public void deleteTagsForHistoryID(long id) {
            throw unexpected();
        }
    }

    private static final class Alerts implements TableAlert {
        public List<RecordAlert> getAlertsBySourceHistoryId(int id) {
            return List.of();
        }

        public void databaseOpen(DatabaseServer server) {
            throw unexpected();
        }

        public RecordAlert read(int id) {
            throw unexpected();
        }

        public RecordAlert write(
                int a,
                int b,
                String c,
                int d,
                int e,
                String f,
                String g,
                String h,
                String i,
                String j,
                String k,
                String l,
                String m,
                int n,
                int o,
                int p,
                int q,
                int r,
                String s,
                String t,
                String u) {
            throw unexpected();
        }

        public java.util.Vector<Integer> getAlertListBySession(long id) {
            throw unexpected();
        }

        public void deleteAlert(int id) {
            throw unexpected();
        }

        public int deleteAllAlerts() {
            throw unexpected();
        }

        public void update(
                int a,
                String b,
                int c,
                int d,
                String e,
                String f,
                String g,
                String h,
                String i,
                String j,
                String k,
                String l,
                int m,
                int n,
                int o,
                String p,
                String q) {
            throw unexpected();
        }

        public void updateHistoryIds(int id, int history, int source) {
            throw unexpected();
        }

        public java.util.Vector<Integer> getAlertList() {
            throw unexpected();
        }
    }

    private static final class Sink extends ExtensionAlert {
        final List<JsonObject> alerts = new ArrayList<>();
        boolean reject;
        boolean silentDrop;

        @Override
        public void alertFound(Alert alert, HistoryReference history) {
            if (reject) throw new IllegalStateException("offline test sink rejected alert");
            if (silentDrop) return;
            alert.setAlertId(alerts.size() + 1);
            JsonObject stored = new JsonObject();
            stored.addProperty("pluginId", alert.getPluginId());
            stored.addProperty("alertRef", alert.getAlertRef());
            stored.addProperty("risk", alert.getRisk());
            stored.addProperty("confidence", alert.getConfidence());
            stored.addProperty("uri", alert.getUri());
            stored.addProperty("name", alert.getName());
            stored.addProperty("evidence", alert.getEvidence());
            stored.addProperty("otherInfo", alert.getOtherInfo());
            stored.addProperty("historyId", history.getHistoryId());
            stored.addProperty(
                    "messageUri", alert.getMessage().getRequestHeader().getURI().toString());
            alerts.add(stored);
        }

    }

    public static void main(String[] args) throws Exception {
        try (var receiver = new PtkIastOfflineReceiver();
                var reader =
                        new BufferedReader(
                                new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String body;
            while ((body = reader.readLine()) != null) {
                if ("REJECT_RAISES".equals(body)) {
                    receiver.rejectRaises(true);
                    continue;
                }
                if ("RESET".equals(body)) {
                    PtkAlertHandler.clearAllReceipts();
                    receiver.sink.alerts.clear();
                    receiver.history.writes = 0;
                    receiver.rejectRaises(false);
                    receiver.silentlyDropRaises(false);
                    continue;
                }
                System.out.println("PTK_OFFLINE_RESULT " + receiver.receive(body));
                System.out.flush();
            }
        }
    }
}
