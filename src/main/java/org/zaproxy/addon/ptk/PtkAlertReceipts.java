package org.zaproxy.addon.ptk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Serialized receipt budgets, not a Java heap estimate. Active receipts are never evicted. */
final class PtkAlertReceipts {
    static final int SESSION_ENTRIES = 8192;
    static final long SESSION_BYTES = 8L * 1024 * 1024;
    static final int GLOBAL_ENTRIES = 16384;
    static final long GLOBAL_BYTES = 16L * 1024 * 1024;

    enum Admission {
        NEW,
        DUPLICATE,
        CONFLICT,
        CAPACITY,
        RETIRED
    }

    private record Receipt(String digest, long bytes) {}

    private final Map<String, LinkedHashMap<String, Receipt>> active = new LinkedHashMap<>();
    private final LinkedHashMap<String, Boolean> retired = new LinkedHashMap<>();
    private long bytes;
    private int entries;

    synchronized Admission admit(String scope, String key, String digest, long size) {
        if (retired.containsKey(scope)) return Admission.RETIRED;
        Map<String, Receipt> session = active.get(scope);
        Receipt old = session != null ? session.get(key) : null;
        if (old != null)
            return old.digest().equals(digest) ? Admission.DUPLICATE : Admission.CONFLICT;
        long sessionBytes =
                session == null ? 0 : session.values().stream().mapToLong(Receipt::bytes).sum();
        if (size < 0
                || size > SESSION_BYTES
                || entries >= GLOBAL_ENTRIES
                || bytes + size > GLOBAL_BYTES
                || session != null && session.size() >= SESSION_ENTRIES
                || sessionBytes + size > SESSION_BYTES) return Admission.CAPACITY;
        active.computeIfAbsent(scope, ignored -> new LinkedHashMap<>())
                .put(key, new Receipt(digest, size));
        entries++;
        bytes += size;
        return Admission.NEW;
    }

    synchronized void release(String scope, String key) {
        Map<String, Receipt> session = active.get(scope);
        Receipt receipt = session != null ? session.remove(key) : null;
        if (receipt != null) {
            entries--;
            bytes -= receipt.bytes();
        }
        if (session != null && session.isEmpty()) active.remove(scope);
    }

    synchronized List<String> retire(String scope) {
        Map<String, Receipt> session = active.remove(scope);
        List<String> keys = session == null ? List.of() : new ArrayList<>(session.keySet());
        if (session != null)
            for (Receipt receipt : session.values()) {
                entries--;
                bytes -= receipt.bytes();
            }
        retired.put(scope, true);
        while (retired.size() > 2000) retired.remove(retired.keySet().iterator().next());
        return keys;
    }

    synchronized void clear() {
        active.clear();
        retired.clear();
        entries = 0;
        bytes = 0;
    }
}
