package org.zaproxy.addon.ptk;

final class PtkCloseRequestState {
    private final String id;
    private final String reason;
    private final long createdAtMs;
    private final String sessionId;
    private final String browserId;
    private boolean acknowledged;

    PtkCloseRequestState(String id, String reason, long createdAtMs) {
        this(id, reason, createdAtMs, null, null);
    }

    PtkCloseRequestState(
            String id, String reason, long createdAtMs, String sessionId, String browserId) {
        this.id = id;
        this.reason = reason;
        this.createdAtMs = createdAtMs;
        this.sessionId = sessionId;
        this.browserId = browserId;
    }

    synchronized String id() {
        return id;
    }

    synchronized String reason() {
        return reason;
    }

    synchronized long createdAtMs() {
        return createdAtMs;
    }

    synchronized String sessionId() {
        return sessionId;
    }

    synchronized String browserId() {
        return browserId;
    }

    synchronized boolean acknowledged() {
        return acknowledged;
    }

    synchronized void acknowledge() {
        acknowledged = true;
    }
}
