# PTK ZAP Automation Runbook

This document describes how PTK is expected to work inside production ZAP automation plans and how to validate results.

The important rule is simple: do not hide instability by changing scan strategy, rulepacks, seed URLs, or `spiderClient` behavior. First prove where the loss happens.

For the full callback, progress, finding-publish, Client Spider, and browser-close lifecycle contract, see [ptk-zap-lifecycle-contract.md](ptk-zap-lifecycle-contract.md).

## Standard Flow

A normal PTK/ZAP browser automation run should keep the ZAP exploration path intact:

1. ZAP `spider` discovers URLs.
2. ZAP `spiderClient` loads in-scope URLs in real browsers.
3. The bundled PTK extension starts a PTK automation session in each ZAP-managed browser.
4. PTK publishes findings back to ZAP through the PTK callback endpoints.
5. ZAP stores and reports the imported PTK alerts.

The canonical Firing Range release-style plans are the project-level `plan_range_edge.yaml` and `plan_range_ff.yaml`. They are the templates for release validation. Local runs may override browser id, browser count, or headed/headless mode for capacity testing, but that must be reported as a different test case.

Do not compare a diagnostic plan with fewer browsers, diagnostic-only jobs, or explicit URL lists as if it were the same release plan.

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
3. The script reports terminal, local-tab-safe, or wait state. It must not stop PTK merely because a close grace window elapsed.
4. While owner-tab PTK activity is still fresh, Java keeps the WebDriver close blocked, uses callback progress as the source of truth, and does not send a close request to PTK.
5. Only after meaningful PTK activity becomes stale does Java create a `closeRequestId` and ask PTK for graceful stop/drain.
6. PTK continues publishing findings/progress through normal callbacks.
7. ZAP closes the browser only when the close decision is terminal-safe, local-tab-safe, or after a bounded forced/incomplete timeout.

`safeToClose` from progress callbacks is accepted only after ZAP has explicitly started the close request for that zapid. This prevents a normal page/progress callback from pre-setting close readiness.

### Close Control Delivery

`/ptk/control` is the extension-background polling channel for close-control delivery. It is not a second close-request creator. Java creates a close request from the browser-close/adaptive-stale path, then `/ptk/control` returns that active request to the matching zapid/sessionId/browserid until PTK acknowledges it.

Control acknowledgement is strict and idempotent:

- a mismatched `closeRequestId`, `sessionId`, or `browserid` is ignored;
- `closeRequestAck=true` means PTK received the active request, not that the session is terminal or release-clean;
- the extension records acknowledgement before trying to echo it through `/ptk/progress`, so a failed progress ack post does not erase the control ack path;
- stop/drain work is scheduled asynchronously and must not hold the control poll in flight.

Clean close still requires terminal progress, publisher drain, completed release state, and no forced/incomplete lifecycle. The MV3 `chrome.alarms` wakeup is allowed only as a recovery trigger while ZAP progress monitors are active; it complements the normal timer/event poll path.

The close budget is intentionally generous for overloaded multi-browser client-spider runs: Java can wait through the configured polling window plus bounded follow-up close-decision scripts before recording `forced_closed`. Tab-local decisions such as `browser_tab_safe_to_close` return through a fast path and should not consume that budget.

Important close-decision states:

| Decision / Reason | Meaning |
|---|---|
| `safe_to_close` + `already_terminal` | PTK was already terminal before the close request completed. |
| `browser_tab_safe_to_close` + `no_active_browser_work` | The current WebDriver tab has no PTK browser-local work left and may close, but this is not global PTK session terminal evidence. |
| `browser_tab_safe_to_close` + `non_owner_active_work` | The current WebDriver tab is not the PTK session owner for the active target and may close without stopping the global PTK session. |
| `wait` + `active_browser_work` | The ZAP-owned PTK session still has concrete queue/task work. Java should keep waiting while meaningful progress or alert activity remains fresh. |
| `wait` + `owner_waiting_for_terminal` | The owner tab is non-terminal but has no concrete browser-local work in the progress snapshot. This is not clean close evidence. |
| `wait` + `activity_stale_waiting_for_terminal` | Java has not seen meaningful progress/alert activity recently. This is when Java may request graceful stop/drain through an explicit `closeRequestId`; it is not clean-close evidence by itself. |
| `not_applicable` + `automation_disabled` | The page bridge did not expose PTK automation for the current tab. Treat this as a startup/session issue, not as a finding issue. |
| `forced_closed` | ZAP exhausted the close budget. This is a lifecycle warning even if findings were imported. |
| `browser_session_invalid:*` | ZAP could not prove a valid browser/PTK session for the target. |

Do not treat `progress=0 status=callback` as a started PTK scan. It only proves callback/config handshake. A real PTK session starts when a `sessionId` appears.

## Timeout Model

Timeouts are allowed only as safety caps around asynchronous boundaries. They must not be the evidence that makes a run pass. In particular, Client Spider `shutdownTime` is crawl queue tuning, not PTK finding-drain or close-readiness proof. Omitting it from an Automation plan does not disable it; Client Spider uses its default quiet window, currently 5 seconds.

### Plan And Release Runner Timing

| Setting | Current Use | Meaning |
|---|---|---|
| `pageLoadTime: 5` | Canonical Firing Range plans and release runner default | Per-page browser dwell/load time for Client Spider tasks. It can affect coverage, but it is not PTK drain evidence. |
| `shutdownTime` | Explicit value omitted by default in `tasks/release/zap-escape-matrix.sh`; optional via `--shutdown-time <seconds>` | Client Spider quiet-window after its queue becomes empty. When omitted, ZAP uses its default, currently 5 seconds. Use larger values only for explicit crawl-coverage comparisons. Do not rely on it for PTK close correctness. |
| `maxDuration: 0` | Canonical plans | No explicit max-duration cap from the plan. |
| `maxChildren: 0` | Canonical plans | No explicit child-count cap from the plan. |
| `numberOfBrowsers` | `1` and `5` release slices | Maximum Client Spider concurrency. It is not a guarantee that exactly this many WebDriver workers will be launched. |

### ZAP Add-On Close Timing

| Constant | Value | Purpose |
|---|---:|---|
| `BROWSER_CLOSE_SCRIPT_TIMEOUT_MS` | `30000ms` | Selenium async-script budget for one browser close-decision call. Prevents WebDriver hangs. |
| `BROWSER_CLOSE_PTK_STOP_TIMEOUT_MS` | `25000ms` | Budget passed to PTK graceful stop/drain when ZAP explicitly asks for close. Clean close still requires terminal/drained/ack evidence. |
| `BROWSER_CLOSE_MAX_ATTEMPTS` x `BROWSER_CLOSE_WAIT_SLICE_MS` | `120 x 1000ms` | Java polling budget after close starts. This is bounded waiting, not a success condition. |
| `BROWSER_CLOSE_ACTIVITY_STALE_MS` | `30000ms` | Staleness diagnostic threshold. It explains why Java is still waiting or later forced/incomplete; it is not clean-close evidence and should not be used to make the scan pass. |
| `BROWSER_CLOSE_NO_PROGRESS_GRACE_MS` | `25000ms` | Startup grace for a browser that reaches close before PTK progress is observed. Prevents misclassifying delayed extension handshakes too early. |
| `BROWSER_CLOSE_AUTOMATION_DISABLED_GRACE_MS` | `2500ms` | Small grace for tabs where PTK reports automation disabled/not applicable. |
| `BROWSER_CLOSE_FOLLOW_UP_DECISION_EVERY_ATTEMPTS` | `15` | Java may retry close-decision roughly every 15 seconds while the close loop remains open. |
| `BROWSER_CLOSE_MAX_WALL_CLOCK_MS` | About 7 minutes | Absolute worst-case safety ceiling. If reached, the result is forced/incomplete, not clean. |

### ZAP Config And Callback Timing

| Timer | Value | Purpose |
|---|---:|---|
| Config fetch retry delays | `0, 250, 1000, 2500, 5000ms` | Startup robustness when several browser sessions hit `/ptk/config` at once. |
| Config fetch timeout | `2500ms` per attempt | Prevents a stalled config request from blocking startup forever. |
| Callback post retry delays | `250, 1000, 4000ms` | Network retry for ZAP callback posts. |
| ZAP history seed cache TTL | `2000ms` | Avoids walking the ZAP SiteTree on every `/ptk/config` request. |
| ZAP history failure log interval | `60000ms` | Rate-limits repeated SiteTree/history warning logs. |

### Extension Progress, Publisher, And Engine Timing

| Timer | Value | Purpose |
|---|---:|---|
| Progress heartbeat | `2000ms` | Regular `/ptk/progress` callback cadence. |
| Progress idle grace | `6000ms` | Extension-side quiet check for progress. |
| Passive engine idle grace | `8000ms` | Lets passive engines settle when they do not have explicit active tasks. |
| Target activity quiet grace | `2500ms` | Avoids treating navigation/target activity as stable too early. |
| Publisher poll interval | `2000ms` | Finding export cadence from PTK to ZAP. |
| Publisher terminal drain | `2` stable passes, `3000ms` flush timeout, max `4` passes | Actual publisher drain evidence. This must be reported through the close-readiness contract. |
| ZAP close engine stop timeout | `25000ms` | Caps engine stop work after explicit ZAP close request. |
| Close terminal retry | Every `2000ms`, max `30000ms` | Retries terminal progress publication if the first terminal callback does not land. |
| Child-tab waits | `750ms` engine-ready, `250ms` IAST drain, `2500ms` SAST collection | Browser child-tab orchestration only; not ZAP close evidence. |

### Release Matrix Timing Outside ZAP

The agent and npm release matrices use longer process-level budgets such as `--ptk-drain-timeout-ms 600000` and provider budget `120000ms`. These are CLI/process gates and are separate from ZAP browser-close correctness.

When a test needs an increased `shutdownTime` to pass, classify the result as a crawl-coverage/timing finding first. Do not call it a stable PTK close-readiness result until the same close/drain path is proven with the default ZAP quiet window.

## ZAP-Managed PTK Attack Tabs

For ZAP-managed DAST sessions, PTK browser attack tabs are extension-owned work, not Client Spider target-window work. The extension opens these DAST attack tabs in a PTK-owned auxiliary browser window when the browser supports that API, and falls back to the current-window tab path only if the auxiliary window cannot be created.

This avoids coupling PTK finding generation to the lifetime of the WebDriver-owned target window. Client Spider may request close for that target window as soon as its own crawl queue is quiet; PTK attack tabs must still be able to finish and publish findings without relying on a larger `shutdownTime`.

Manual browser scans and non-ZAP sessions keep the normal same-window attack-tab behavior.

## Browser Evidence Logs

The add-on logs PTK/ZAP browser truth as `PTK_BROWSER_EVIDENCE` lines in `zap.log`. Config callbacks are logged through debug callback/timing logs rather than browser evidence; do not treat config callback evidence as scan-start evidence.

Key events:

| Event | Meaning |
|---|---|
| `browser_loaded` | ZAP launched or navigated a browser to a URL. |
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

## Diagnostic Browser Coverage Builds

The production add-on does not package the `ptkBrowserCoverage` Automation Framework job. That job depends on Automation add-on classes and diagnostic browser-control fallbacks that are useful for instability analysis but should not be part of the production release artifact.

Use the diagnostic artifact only when investigating browser coverage or PTK session-start instability:

```text
./gradlew jarZapAddOnDiagnostic
./gradlew testDiagnostic
```

The diagnostic build appends `-diagnostic` to the add-on version and registers `ptkBrowserCoverage` through a service-loaded diagnostic extension. See [diagnostics/ptk-browser-coverage.md](diagnostics/ptk-browser-coverage.md) for the job parameters and usage rules.

Diagnostic plans must not be reported as production release plans. They are for answering whether URLs were loaded in browsers, whether PTK sessions were established, and whether close-contract failures happened before findings could be imported.

Important close states are:

| State | Meaning |
|---|---|
| `safe_to_close` | PTK reported terminal progress or an accepted safe close decision after ZAP requested close. |
| `browser_tab_safe_to_close` | ZAP can close the current browser tab without treating the whole PTK scan as terminal. |
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
- Treat diagnostic retry success as proof that original `spiderClient` execution was stable.
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
| Artifact type | Production and diagnostic add-ons are not equivalent. |
| Browser loaded count | Proves WebDriver reached target pages. |
| PTK session count | Proves PTK started in the browser. |
| Forced close / invalid session counts | Shows lifecycle health. |
| Unique finding count | Shows security coverage. |
| Missing URL-alert pairs | Shows exact regression surface. |

Do not report only raw alert totals. They can hide missing URLs, duplicate findings, or lifecycle failures.
