package org.zaproxy.addon.ptk;

record BrowserCoverageSnapshot(
        String url,
        int scheduledAttempts,
        int browserLoaded,
        int ptkSessionEstablished,
        int ptkAnalysisReady,
        int browserSessionInvalid,
        int webdriverScriptFailed,
        int forcedClose,
        int noPtkProgress,
        long lastEventAtMs) {

    static BrowserCoverageSnapshot empty(String url) {
        return new BrowserCoverageSnapshot(url, 0, 0, 0, 0, 0, 0, 0, 0, 0L);
    }

    boolean hasBrowserLoad() {
        return browserLoaded > 0;
    }

    boolean hasPtkSession() {
        return ptkSessionEstablished > 0;
    }

    boolean hasPtkAnalysisReady() {
        return ptkAnalysisReady > 0;
    }

    boolean hasInvalidSession() {
        return browserSessionInvalid > 0
                || webdriverScriptFailed > 0
                || forcedClose > 0
                || noPtkProgress > 0;
    }

    String classify(boolean requirePtkSession) {
        if (requirePtkSession ? hasPtkSession() : hasBrowserLoad()) {
            return "browser_loaded";
        }
        if (forcedClose > 0) {
            return "browser_session_invalid:forced_close";
        }
        if (webdriverScriptFailed > 0) {
            return "browser_session_invalid:webdriver_script_failed";
        }
        if (noPtkProgress > 0 || browserSessionInvalid > 0) {
            return "browser_session_invalid:no_ptk_progress";
        }
        if (hasBrowserLoad()) {
            return "browser_loaded_no_ptk";
        }
        return "not_browser_loaded";
    }
}
