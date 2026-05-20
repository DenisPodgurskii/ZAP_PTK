# PTK Browser Coverage Diagnostic Build

`ptkBrowserCoverage` is an internal diagnostic Automation Framework job. It is excluded from the production add-on build.

Use this build only when investigating unstable ZAP browser automation runs. The job is not a replacement for `spiderClient`, and it must not be used to make a production validation plan look stable.

## Build

Production build:

```text
./gradlew jarZapAddOn
```

Diagnostic build:

```text
./gradlew jarZapAddOnDiagnostic
./gradlew testDiagnostic
```

The diagnostic build:

- appends `-diagnostic` to the add-on version
- adds the Automation add-on only to the diagnostic compile/test classpath
- registers `ptkBrowserCoverage`
- packages diagnostic-only classes from `src/diagnostic`
- is not intended for production release

The production `check` task verifies that diagnostic browser coverage classes are not packaged into the production `.zap`.

## Why It Is Isolated

`ptkBrowserCoverage` exists to diagnose browser execution truth:

- URL was scheduled by ZAP
- URL was loaded by WebDriver
- PTK configuration callback happened
- PTK progress was observed
- PTK session was established
- browser close was safe, forced, or invalid
- findings were imported into ZAP

To collect this evidence it uses Automation add-on APIs and diagnostic browser-control fallbacks. Some paths also rely on reflection against Client Spider or Selenium internals. Those fallbacks are acceptable for investigation but are intentionally excluded from the production artifact because upstream internal APIs can change without notice.

## Example Plan Snippet

Place the job after `spiderClient` when diagnosing coverage:

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

## Parameters

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

## Classifications

| Classification | Meaning |
|---|---|
| `browser_loaded` | Required evidence was satisfied. If `requirePtkSession=true`, this means PTK session evidence exists. |
| `not_browser_loaded` | The target URL was scheduled but no browser load evidence was observed. |
| `browser_loaded_no_ptk` | Browser loaded, but PTK session evidence did not arrive. |
| `browser_session_invalid:no_ptk_progress` | Browser reached close with no PTK progress beyond callback/config evidence. |
| `browser_session_invalid:forced_close` | Browser was force-closed before safe terminal evidence. |
| `browser_session_invalid:webdriver_script_failed` | WebDriver close/progress script failed. |
| `browser_session_invalid:webdriver_navigation_failed` | Browser navigation failed for the target URL. |

## Usage Rules

Use `source: historyUrls` when `spiderClient` has already discovered target URLs and you want to verify that ZAP history entries were actually loaded by PTK-enabled browsers.

Use `source: contextUrls` only when you want to verify context seed URLs. It will not check every URL discovered by the traditional spider.

Do not:

- disable `spiderClient` and replace it with `ptkBrowserCoverage`
- lower browser count without reporting it as a separate capacity test
- add benchmark-specific URLs to claim product stability
- treat retry success as proof that the original run was stable
- merge a diagnostic artifact as a production release

When reporting a diagnostic matrix, include the add-on artifact type, browser count, browser mode, browser loaded count, PTK session count, forced close count, invalid session count, unique finding count, and missing URL-alert pairs.
