package org.zaproxy.addon.ptk;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

final class BrowserCoverageEvidence {

    private final AtomicInteger scheduledAttempts = new AtomicInteger();
    private final AtomicInteger browserLoaded = new AtomicInteger();
    private final AtomicInteger ptkSessionEstablished = new AtomicInteger();
    private final AtomicInteger ptkAnalysisReady = new AtomicInteger();
    private final AtomicInteger browserSessionInvalid = new AtomicInteger();
    private final AtomicInteger webdriverScriptFailed = new AtomicInteger();
    private final AtomicInteger forcedClose = new AtomicInteger();
    private final AtomicInteger noPtkProgress = new AtomicInteger();
    private final AtomicLong lastEventAtMs = new AtomicLong();

    void scheduled(int attempt) {
        scheduledAttempts.accumulateAndGet(Math.max(1, attempt), Math::max);
        lastEventAtMs.set(System.currentTimeMillis());
    }

    void record(String event, Map<String, Object> extra) {
        lastEventAtMs.set(System.currentTimeMillis());
        if ("browser_loaded".equals(event)) {
            browserLoaded.incrementAndGet();
            return;
        }
        if ("ptk_session_established".equals(event)) {
            ptkSessionEstablished.incrementAndGet();
            return;
        }
        if ("ptk_analysis_ready".equals(event)) {
            ptkAnalysisReady.incrementAndGet();
            return;
        }
        if ("browser_session_invalid".equals(event)) {
            browserSessionInvalid.incrementAndGet();
            if ("no_ptk_progress".equals(stringValue(extra, "reason"))) {
                noPtkProgress.incrementAndGet();
            }
            return;
        }
        if ("browser_close".equals(event)) {
            if ("webdriver_script_failed".equals(stringValue(extra, "reason"))) {
                webdriverScriptFailed.incrementAndGet();
            }
            if ("forced_closed".equals(stringValue(extra, "decision"))) {
                forcedClose.incrementAndGet();
            }
        }
    }

    BrowserCoverageSnapshot snapshot(String url) {
        return new BrowserCoverageSnapshot(
                url,
                scheduledAttempts.get(),
                browserLoaded.get(),
                ptkSessionEstablished.get(),
                ptkAnalysisReady.get(),
                browserSessionInvalid.get(),
                webdriverScriptFailed.get(),
                forcedClose.get(),
                noPtkProgress.get(),
                lastEventAtMs.get());
    }

    private static String stringValue(Map<String, Object> extra, String key) {
        if (extra == null || key == null) {
            return null;
        }
        Object value = extra.get(key);
        return value != null ? String.valueOf(value) : null;
    }
}
