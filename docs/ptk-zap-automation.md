# PTK ZAP Automation Runbook

This document describes how PTK is expected to work inside ZAP automation plans, how to validate results, and which diagnostic jobs can be added when a run is unstable.

The important rule is simple: do not hide instability by changing scan strategy, rulepacks, seed URLs, or `spiderClient` behavior. First prove where the loss happens.

## Standard Flow

A normal PTK/ZAP browser automation run should keep the ZAP exploration path intact:

1. ZAP `spider` discovers URLs.
2. ZAP `spiderClient` loads in-scope URLs in real browsers.
3. The bundled PTK extension starts a PTK automation session in each ZAP-managed browser.
4. PTK publishes findings back to ZAP through the PTK callback endpoints.
5. ZAP stores and reports the imported PTK alerts.

The canonical Firing Range release-style plans are the project-level `plan_range_edge.yaml` and `plan_range_ff.yaml`. They are the templates for release validation. Local runs may override browser id, browser count, or headed/headless mode for capacity testing, but that must be reported as a different test case.

Do not compare a diagnostic plan with fewer browsers, extra coverage jobs, or explicit URL lists as if it were the same release plan.

## Required ZAP Configuration

The add-on expects PTK automation to be enabled when ZAP starts:

```text
-config ptk.automatedScanning.enabled=true
```

The PTK extension is bundled into the ZAP add-on under:

```text
src/main/zapHomeFiles/selenium/extensions/
```

For local rebuilds, refresh the extension bundle before rebuilding the add-on. Do not assume a rebuilt CRX/XPI is used by ZAP until it has been copied into the ZAP add-on extension bundle and the add-on has been rebuilt.

## Browser Close Contract

ZAP should not force-close a PTK browser while PTK is still producing findings. The close contract is a cooperative shutdown path:

1. ZAP calls a WebDriver script in the browser before closing it.
2. The script asks PTK for current session progress.
3. If needed, the script asks PTK to stop the session.
4. PTK flushes findings and reports a terminal state or `safeToClose=true`.
5. ZAP closes the browser only when the close decision is safe, or after a bounded timeout.

`safeToClose` from progress callbacks is accepted only after ZAP has explicitly started the close request for that zapid. This prevents a normal page/progress callback from pre-setting close readiness.

Important close-decision states:

| Decision / Reason | Meaning |
|---|---|
| `safe_to_close` + `terminal_after_stop` | PTK stopped and reached terminal state during close. |
| `safe_to_close` + `already_terminal` | PTK was already terminal before the close request completed. |
| `wait` + `close_requested` | PTK accepted stop, but Java should keep waiting for terminal progress. |
| `not_applicable` + `automation_disabled` | The page bridge did not expose PTK automation for the current tab. Treat this as a startup/session issue, not as a finding issue. |
| `forced_closed` | ZAP exhausted the close budget. This is a lifecycle warning even if findings were imported. |
| `browser_session_invalid:*` | ZAP could not prove a valid browser/PTK session for the target. |

Do not treat `progress=0 status=callback` as a started PTK scan. It only proves callback/config handshake. A real PTK session starts when a `sessionId` appears.

## Browser Evidence Logs

The add-on logs PTK/ZAP browser truth as `PTK_BROWSER_EVIDENCE` lines in `zap.log`.

Key events:

| Event | Meaning |
|---|---|
| `browser_loaded` | ZAP launched or navigated a browser to a URL. |
| `config_callback` | Browser requested PTK configuration from ZAP. |
| `ptk_progress_seen` | ZAP received progress, usually initial callback state. May not include a PTK session yet. |
| `ptk_session_established` | A PTK session id was observed for the zapid. This is the session-start proof. |
| `ptk_session_terminal` | PTK reported terminal progress. |
| `browser_close` | ZAP close-contract decision for a browser. |
| `browser_session_invalid` | ZAP could not prove a valid browser/PTK session. |

When debugging a missing finding, track these four truths separately:

1. URL is in ZAP context/history.
2. URL was loaded by a browser.
3. PTK session was established for that browser.
4. Finding was published/imported into ZAP.

A finding pass does not prove browser/session health. A browser/session pass does not prove finding coverage.

## ptkBrowserCoverage Diagnostic Job

`ptkBrowserCoverage` is a diagnostic and retry job. It is not a replacement for `spiderClient`.

Use it when you need to answer:

- Did each expected URL get loaded by a browser?
- Did PTK establish a session for that URL?
- Did a failure come from browser loading, PTK startup, WebDriver, forced close, or missing findings?

Place it after `spiderClient` when diagnosing coverage:

```yaml
- type: ptkBrowserCoverage
  parameters:
    source: historyUrls
    browserId: edge-headless
    numberOfBrowsers: 5
    retryNumberOfBrowsers: 2
    pageLoadTime: 5
    attemptTimeout: 45
    evidenceGraceMs: 2500
    launchStaggerMs: 250
    maxRetriesPerUrl: 1
    scopeCheck: STRICT
    requirePtkSession: true
    failOnMissingBrowserLoad: false
```

Supported parameters:

| Parameter | Purpose |
|---|---|
| `context` | Optional ZAP context name. Defaults to the automation environment default context. |
| `source` | URL source: `contextUrls`, `historyUrls`, or `contextAndHistoryUrls`. |
| `url` | One explicit URL. |
| `urls` | Additional explicit URLs. |
| `browserId` | Selenium browser id, for example `edge`, `edge-headless`, `firefox`, `firefox-headless`. |
| `numberOfBrowsers` | Browser concurrency for initial diagnostic attempts. |
| `retryNumberOfBrowsers` | Lower retry concurrency for URLs that failed the first attempt. |
| `initialLoadTime` | Browser initial-load delay in seconds. |
| `pageLoadTime` | Page dwell/load time in seconds. |
| `shutdownTime` | Browser shutdown wait in seconds. |
| `attemptTimeout` | Max per-URL attempt time in seconds. |
| `evidenceGraceMs` | Extra wait after browser attempts for evidence callbacks to arrive. |
| `launchStaggerMs` | Delay between launching browsers in a batch. |
| `maxRetriesPerUrl` | Retry count for URLs missing required browser/PTK evidence. |
| `scopeCheck` | Client spider scope mode, normally `STRICT`. |
| `requirePtkSession` | If true, URL is satisfied only when PTK session evidence exists. |
| `failOnMissingBrowserLoad` | If true, the job can fail the automation plan on missing browser load/session evidence. |
| `logoutAvoidance` | Pass-through logout avoidance option for direct browser attempts. |

The job also reports close-contract state through `PTK_TIMING` and `PTK_CLOSE_CONTRACT` log lines. Important close states are:

| State | Meaning |
|---|---|
| `safe_to_close` | PTK reported terminal progress or an accepted safe close decision after ZAP requested close. |
| `forced_closed` | ZAP exhausted the bounded close budget and closed the browser without terminal PTK evidence. |
| `engine_incomplete` | PTK stopped but at least one engine reported incomplete/cancelled work. Treat findings as usable only with lifecycle warning. |
| `completionStatus` | PTK engine completion status returned by the browser-side close decision. |
| `zapProgressTerminalPosted` | PTK says it posted a terminal progress callback to ZAP. ZAP does not treat this as analysis-ready by itself. |

`safeToClose=true` from progress callbacks is ignored until ZAP has recorded that it started a close request for the zapid. This prevents regular progress callbacks from pre-setting close readiness.

Coverage classifications:

| Classification | Meaning |
|---|---|
| `browser_loaded` | Required evidence was satisfied. If `requirePtkSession=true`, this means PTK session evidence exists. |
| `not_browser_loaded` | The target URL was scheduled but no browser load evidence was observed. |
| `browser_loaded_no_ptk` | Browser loaded, but PTK session evidence did not arrive. |
| `browser_session_invalid:no_ptk_progress` | Browser reached close with no PTK progress beyond callback/config evidence. |
| `browser_session_invalid:forced_close` | Browser was force-closed before safe terminal evidence. |
| `browser_session_invalid:webdriver_script_failed` | WebDriver close/progress script failed. |
| `browser_session_invalid:webdriver_navigation_failed` | Browser navigation failed for the target URL. |

Use `source: historyUrls` when `spiderClient` has already discovered target URLs and you want to verify that ZAP history entries were actually loaded by PTK-enabled browsers.

Use `source: contextUrls` only when you want to verify context seed URLs. It will not check every URL discovered by the traditional spider.

## Validation

For each automation validation run, check both:

- lifecycle: loaded browsers, PTK sessions, forced close count, invalid session count
- findings: expected unique PTK findings for the target and rule configuration

If the finding gate passes but lifecycle shows forced close or missing sessions, do not call the run clean. Treat it as "finding evidence valid, lifecycle warning open".

## What Not To Do

Do not make these changes to make a test pass:

- Disable `spiderClient`.
- Lower browser count without calling it a separate capacity test.
- Add broad/comprehensive DAST strategy only for Firing Range.
- Add benchmark-specific seed URLs to claim product stability.
- Treat `ptkBrowserCoverage` retry success as proof that original `spiderClient` execution was stable.
- Treat old matrices as source truth when current browser artifacts contradict them.

## Debugging Missing Findings

When a finding is missing:

1. Check browser-side PTK artifacts first when available, especially `__ptk_scans`.
2. Check `zap.log` for `PTK_BROWSER_EVIDENCE` lines for the target zapid and URL.
3. Confirm whether the target URL appears in ZAP history.
4. Confirm whether the target URL was loaded by a browser.
5. Confirm whether PTK session evidence exists.
6. Confirm whether PTK alert callbacks were accepted by ZAP.
7. Confirm whether ZAP session/report output contains the imported alert.

Only after that should rule coverage be questioned.

If `__ptk_scans` contains the finding but ZAP output does not, the loss boundary is export/publish/import/reporting, not DAST/SAST/IAST detection.

If the browser shows "can't reach this page" or target load timeout, the result is a browser-load/environment capacity issue until proven otherwise.

## Reading Test Results

Useful summary counters:

| Counter | Meaning |
|---|---|
| `browser_evidence_loaded_count` | Number of browser load evidence events. |
| `browser_evidence_ptk_session_count` | Number of zapids with PTK session evidence. |
| `browser_evidence_forced_close_count` | Browser evidence recorded forced close. |
| `browser_evidence_no_ptk_progress_count` | Browser/session reached close without PTK progress. |
| `close_contract_safe_count` | Close contract accepted safe terminal state. |
| `close_contract_forced_count` | Close contract timed out or forced close. |
| `close_contract_running_count` | Close decision saw running status at some point. Review with final forced/safe state. |
| `spider_started_count` / `spider_finished_count` | Confirms ZAP spider execution. |
| `renderer_timeout_count` / `nav_timeout_5000_count` | Browser/renderer load symptoms. |

For a clean run, expect:

- `spider_started_count=1`
- `spider_finished_count=1`
- browser loaded count matches expected browser count
- PTK session count matches expected browser count
- forced close count is `0`
- required finding count is met

## Reporting Results

When reporting a PTK/ZAP automation matrix, include:

| Field | Why |
|---|---|
| Browser and headed/headless mode | Browser behavior differs. |
| Browser count | Local capacity affects stability. |
| Plan file | Canonical vs diagnostic plans are not equivalent. |
| Whether `ptkBrowserCoverage` was enabled | Distinguishes stock `spiderClient` from retry diagnostics. |
| Browser loaded count | Proves WebDriver reached target pages. |
| PTK session count | Proves PTK started in the browser. |
| Forced close / invalid session counts | Shows lifecycle health. |
| Unique finding count | Shows security coverage. |
| Missing URL-alert pairs | Shows exact regression surface. |

Do not report only raw alert totals. They can hide missing URLs, duplicate findings, or lifecycle failures.
