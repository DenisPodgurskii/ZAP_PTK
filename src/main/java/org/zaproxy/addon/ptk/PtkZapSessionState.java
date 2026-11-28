package org.zaproxy.addon.ptk;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

final class PtkZapSessionState {

    private static final Set<String> DAST_STOP_ERRORS =
            Set.of(
                    "owner_mismatch",
                    "stop_not_available",
                    "stop_timeout",
                    "stop_incomplete",
                    "stop_failed");

    private final String zapid;
    private String browserId;
    private String sessionId;
    private Integer progress;
    private String status;
    private String lastProgressSummary;
    private Long lastProgressChangedAtMs;
    private Long lastAlertChangedAtMs;
    private int alertsRaisedTotal;
    private int contractVersion;
    private boolean publisherDrained;
    private boolean safeToClose;
    private boolean terminalProgressSeen;
    private String completionStatus;
    private String releaseStatus;
    private Long callbackFirstSeenAtMs;
    private Long firstAlertSeenAtMs;
    private Long closeDecisionAttemptedAtMs;
    private PtkCloseRequestState closeRequest;
    private long lastActivitySeq = Long.MIN_VALUE;
    private Boolean passiveOnlyConfig;
    private Boolean mixedIastDastConfig;
    private String mixedConfigBrowserId;
    private DastStopRequest dastStopRequest;

    record DastStopRequest(
            String id, String sessionId, String browserId, String result, String error) {}

    PtkZapSessionState(String zapid) {
        this.zapid = zapid;
    }

    synchronized String zapid() {
        return zapid;
    }

    synchronized void rememberBrowserId(String browserId) {
        if (browserId != null && !browserId.isBlank()) {
            this.browserId = browserId;
        }
    }

    synchronized void rememberSessionContext(String browserId, String sessionId) {
        rememberBrowserId(browserId);
        if (sessionId != null && !sessionId.isBlank()) {
            this.sessionId = sessionId;
        }
    }

    synchronized void rememberPassiveOnlyConfig(boolean passiveOnly) {
        // A later config cannot establish that every config served to this owner was passive only.
        passiveOnlyConfig = !Boolean.FALSE.equals(passiveOnlyConfig) && passiveOnly;
    }

    synchronized boolean hasPassiveOnlyConfig() {
        return Boolean.TRUE.equals(passiveOnlyConfig);
    }

    synchronized void rememberMixedIastDastConfig(boolean mixed, String browserId) {
        mixedIastDastConfig =
                !Boolean.FALSE.equals(mixedIastDastConfig)
                        && mixed
                        && nonBlankOrNull(browserId) != null
                        && (mixedConfigBrowserId == null || mixedConfigBrowserId.equals(browserId));
        if (mixedIastDastConfig) mixedConfigBrowserId = browserId;
    }

    synchronized boolean usesDastStop(boolean supportsDastStop) {
        return dastStopRequest != null
                || (supportsDastStop && Boolean.TRUE.equals(mixedIastDastConfig));
    }

    synchronized DastStopRequest pollDastStop(
            String sessionId,
            String browserId,
            boolean stale,
            String id,
            String result,
            String error) {
        if (sessionId == null
                || !sessionId.equals(this.sessionId)
                || browserId == null
                || !browserId.equals(this.browserId)
                || !browserId.equals(mixedConfigBrowserId)) return null;
        if (dastStopRequest == null && closeRequest == null && stale) {
            dastStopRequest =
                    new DastStopRequest(
                            UUID.randomUUID().toString(), sessionId, browserId, null, null);
        }
        DastStopRequest request = dastStopRequest;
        if (request == null
                || !request.sessionId().equals(sessionId)
                || !request.browserId().equals(browserId)) {
            return null;
        }
        boolean validReceipt =
                ("completed".equals(result) && error == null)
                        || ("engine_incomplete".equals(result)
                                && error != null
                                && DAST_STOP_ERRORS.contains(error));
        if (request.result() == null && request.id().equals(id) && validReceipt) {
            dastStopRequest =
                    new DastStopRequest(request.id(), sessionId, browserId, result, error);
        }
        return dastStopRequest;
    }

    synchronized long markCallbackStart(long nowMs) {
        if (callbackFirstSeenAtMs == null) {
            callbackFirstSeenAtMs = nowMs;
        }
        return callbackFirstSeenAtMs;
    }

    synchronized Long elapsedSinceFirst(long nowMs) {
        if (callbackFirstSeenAtMs == null) {
            return null;
        }
        return Math.max(0L, nowMs - callbackFirstSeenAtMs);
    }

    synchronized ProgressActivity recordProgress(
            String browserId,
            String sessionId,
            Integer progress,
            String status,
            String progressSummary,
            boolean terminalProgress,
            Integer contractVersion,
            Boolean publisherDrained,
            Integer activitySeq,
            long nowMs) {
        if (activitySeq != null && activitySeq.longValue() < lastActivitySeq) {
            return new ProgressActivity(false, false, false, true, false);
        }
        if (terminalProgressSeen && !terminalProgress) {
            return new ProgressActivity(false, false, false, false, true);
        }
        rememberBrowserId(browserId);
        if (activitySeq != null) {
            lastActivitySeq = activitySeq.longValue();
        }
        boolean sessionEstablished = false;
        if (sessionId != null && !sessionId.isBlank() && !sessionId.equals(this.sessionId)) {
            this.sessionId = sessionId;
            sessionEstablished = true;
        }
        boolean firstProgress = this.progress == null;
        if (contractVersion != null && contractVersion.intValue() > this.contractVersion) {
            this.contractVersion = contractVersion;
        }
        if (publisherDrained != null) {
            this.publisherDrained = publisherDrained;
        }
        if (progress != null) {
            this.progress = progress;
        }
        if (status != null && !status.isBlank()) {
            this.status = status;
        }
        if (terminalProgress) {
            this.terminalProgressSeen = true;
            this.safeToClose = true;
        }
        boolean progressChanged = false;
        if (progressSummary != null && !progressSummary.isBlank()) {
            progressChanged = !progressSummary.equals(lastProgressSummary);
            if (progressChanged) {
                lastProgressSummary = progressSummary;
                lastProgressChangedAtMs = nowMs;
            }
        }
        return new ProgressActivity(
                firstProgress, sessionEstablished, progressChanged, false, false);
    }

    synchronized int addAlerts(int raised, long nowMs) {
        int sanitizedRaised = Math.max(0, raised);
        if (sanitizedRaised > 0) {
            alertsRaisedTotal += sanitizedRaised;
            lastAlertChangedAtMs = nowMs;
        }
        return alertsRaisedTotal;
    }

    synchronized void markFirstAlertSeen(long nowMs) {
        if (firstAlertSeenAtMs == null) {
            firstAlertSeenAtMs = nowMs;
        }
    }

    synchronized Long firstAlertElapsed(long nowMs) {
        if (callbackFirstSeenAtMs == null || firstAlertSeenAtMs == null) {
            return null;
        }
        return Math.max(0L, firstAlertSeenAtMs - callbackFirstSeenAtMs);
    }

    synchronized Long newestActivityAt() {
        if (lastProgressChangedAtMs == null) {
            return lastAlertChangedAtMs;
        }
        if (lastAlertChangedAtMs == null) {
            return lastProgressChangedAtMs;
        }
        return Math.max(lastProgressChangedAtMs, lastAlertChangedAtMs);
    }

    synchronized void markCloseDecisionAttempted(long decidedAtMs) {
        if (closeDecisionAttemptedAtMs == null) {
            closeDecisionAttemptedAtMs = decidedAtMs;
        }
    }

    synchronized Long closeDecisionAttemptedAtMs() {
        return closeDecisionAttemptedAtMs;
    }

    synchronized PtkCloseRequestState ensureCloseRequest(
            String closeRequestId, String reason, long nowMs) {
        return ensureCloseRequest(closeRequestId, reason, nowMs, sessionId, browserId);
    }

    synchronized PtkCloseRequestState ensureCloseRequest(
            String closeRequestId, String reason, long nowMs, String sessionId, String browserId) {
        if (closeRequest != null) {
            return closeRequest;
        }
        closeRequest =
                new PtkCloseRequestState(
                        closeRequestId,
                        reason,
                        nowMs,
                        nonBlankOrNull(sessionId != null ? sessionId : this.sessionId),
                        nonBlankOrNull(browserId != null ? browserId : this.browserId));
        return closeRequest;
    }

    synchronized PtkCloseRequestState ensureCloseRequest(String reason, long nowMs) {
        return ensureCloseRequest(reason, nowMs, sessionId, browserId);
    }

    synchronized PtkCloseRequestState ensureCloseRequest(
            String reason, long nowMs, String sessionId, String browserId) {
        if (closeRequest != null) {
            return closeRequest;
        }
        String closeRequestId =
                zapid
                        + "-"
                        + nowMs
                        + "-"
                        + Long.toHexString(ThreadLocalRandom.current().nextLong());
        closeRequest =
                new PtkCloseRequestState(
                        closeRequestId,
                        reason,
                        nowMs,
                        nonBlankOrNull(sessionId != null ? sessionId : this.sessionId),
                        nonBlankOrNull(browserId != null ? browserId : this.browserId));
        return closeRequest;
    }

    synchronized void acknowledgeCloseRequest(String closeRequestId) {
        if (closeRequest != null && closeRequest.id().equals(closeRequestId)) {
            closeRequest.acknowledge();
        }
    }

    synchronized boolean matchesActiveSession(
            String requestedSessionId, String requestedBrowserId) {
        String safeSessionId = nonBlankOrNull(requestedSessionId);
        if (safeSessionId != null && sessionId != null && !safeSessionId.equals(sessionId)) {
            return false;
        }
        String safeBrowserId = nonBlankOrNull(requestedBrowserId);
        if (safeBrowserId != null && browserId != null && !safeBrowserId.equals(browserId)) {
            return false;
        }
        return true;
    }

    synchronized boolean isCloseRequestForSession(
            PtkCloseRequestState request, String requestedSessionId, String requestedBrowserId) {
        if (request == null) {
            return false;
        }
        String safeSessionId = nonBlankOrNull(requestedSessionId);
        String requestSessionId = nonBlankOrNull(request.sessionId());
        if (requestSessionId != null && safeSessionId == null) {
            return false;
        }
        if (safeSessionId != null
                && requestSessionId != null
                && !safeSessionId.equals(requestSessionId)) {
            return false;
        }
        String safeBrowserId = nonBlankOrNull(requestedBrowserId);
        String requestBrowserId = nonBlankOrNull(request.browserId());
        if (requestBrowserId != null && safeBrowserId == null) {
            return false;
        }
        if (safeBrowserId != null
                && requestBrowserId != null
                && !safeBrowserId.equals(requestBrowserId)) {
            return false;
        }
        return matchesActiveSession(requestedSessionId, requestedBrowserId);
    }

    synchronized PtkCloseRequestState closeRequest() {
        return closeRequest;
    }

    synchronized void setSafeToClose(boolean safeToClose) {
        this.safeToClose = safeToClose;
    }

    synchronized void rememberReleaseState(String completionStatus, String releaseStatus) {
        if (terminalProgressSeen && isCleanRelease(this.completionStatus, this.releaseStatus)) {
            boolean nextClean = isCleanRelease(completionStatus, releaseStatus);
            if (!nextClean) {
                return;
            }
        }
        if (completionStatus != null && !completionStatus.isBlank()) {
            this.completionStatus = completionStatus;
        }
        if (releaseStatus != null && !releaseStatus.isBlank()) {
            this.releaseStatus = releaseStatus;
        }
    }

    synchronized void markTerminalProgressSeen() {
        terminalProgressSeen = true;
    }

    synchronized PtkZapSessionSnapshot snapshot() {
        return new PtkZapSessionSnapshot(
                zapid,
                browserId,
                sessionId,
                progress,
                status,
                alertsRaisedTotal,
                lastProgressChangedAtMs,
                lastAlertChangedAtMs,
                contractVersion,
                publisherDrained,
                safeToClose,
                terminalProgressSeen,
                completionStatus,
                releaseStatus,
                closeDecisionAttemptedAtMs,
                closeRequest);
    }

    private static String nonBlankOrNull(String value) {
        return value != null && !value.isBlank() ? value : null;
    }

    private static boolean isCleanRelease(String completionStatus, String releaseStatus) {
        if (!"completed".equals(completionStatus)) {
            return false;
        }
        return releaseStatus == null || releaseStatus.isBlank() || "clean".equals(releaseStatus);
    }

    record ProgressActivity(
            boolean firstProgress,
            boolean sessionEstablished,
            boolean progressChanged,
            boolean outOfOrder,
            boolean ignoredAfterTerminal) {}
}
