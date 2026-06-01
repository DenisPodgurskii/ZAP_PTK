package org.zaproxy.addon.ptk;

record PtkZapSessionSnapshot(
        String zapid,
        String browserId,
        String sessionId,
        Integer progress,
        String status,
        int alertsRaisedTotal,
        Long lastProgressChangedAtMs,
        Long lastAlertChangedAtMs,
        int contractVersion,
        boolean publisherDrained,
        boolean safeToClose,
        boolean terminalProgressSeen,
        String completionStatus,
        String releaseStatus,
        Long closeDecisionAttemptedAtMs,
        PtkCloseRequestState closeRequest) {

    Long newestActivityAt() {
        if (lastProgressChangedAtMs == null) {
            return lastAlertChangedAtMs;
        }
        if (lastAlertChangedAtMs == null) {
            return lastProgressChangedAtMs;
        }
        return Math.max(lastProgressChangedAtMs, lastAlertChangedAtMs);
    }

    boolean isV2PhysicallySafeToClose() {
        return contractVersion >= 2 && safeToClose && terminalProgressSeen;
    }

    boolean hasV2CleanTerminalEvidence() {
        return contractVersion >= 2
                && terminalProgressSeen
                && publisherDrained
                && "completed".equals(completionStatus)
                && (releaseStatus == null
                        || releaseStatus.isBlank()
                        || "clean".equals(releaseStatus));
    }

    boolean isV2TerminalAndDrained() {
        return isV2PhysicallySafeToClose() && publisherDrained;
    }

    boolean isV2ReleaseClean() {
        return isV2PhysicallySafeToClose() && hasV2CleanTerminalEvidence();
    }

    boolean isV2ReleaseIncomplete() {
        return isV2PhysicallySafeToClose() && !isV2ReleaseClean();
    }
}
