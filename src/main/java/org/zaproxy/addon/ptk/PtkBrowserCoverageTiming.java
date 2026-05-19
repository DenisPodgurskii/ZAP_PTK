package org.zaproxy.addon.ptk;

final class PtkBrowserCoverageTiming {

    private static final int DEFAULT_PAGE_LOAD_TIME_SECS = 5;

    private PtkBrowserCoverageTiming() {}

    static long pageDwellMs(Integer pageLoadTimeSeconds) {
        return clamp(pageLoadTimeSeconds, DEFAULT_PAGE_LOAD_TIME_SECS, 120) * 1000L;
    }

    static boolean coverageWaitComplete(
            long nowMs,
            long minDwellDeadlineMs,
            boolean coverageSatisfied,
            boolean requirePtkSession) {
        if (nowMs < minDwellDeadlineMs) {
            return false;
        }
        return !requirePtkSession || coverageSatisfied;
    }

    private static int clamp(Integer value, int fallback, int max) {
        int candidate = value != null ? value.intValue() : fallback;
        return Math.max(0, Math.min(max, candidate));
    }
}
