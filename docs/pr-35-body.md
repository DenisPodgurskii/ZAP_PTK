# PR #35: 9.9.5 Pre-Release

## Summary

This pre-release bundles the PTK/ZAP automation stability work needed before extension publication:

- Adds the `ptkBrowserCoverage` automation diagnostic job.
- Hardens the browser close contract so ZAP asks PTK to stop, flush findings, and report terminal state before browser shutdown.
- Refreshes the bundled PTK browser extension used by Selenium/ZAP.
- Adds browser coverage evidence logs for distinguishing URL discovery, browser load, PTK session establishment, and finding publication.
- Adds ZAP/PTK automation runbook documentation.

## Review Fixes Included

- Removed hardcoded local `/Users/ptk/...` build paths.
- Removed dependency on another add-on's runtime `tmp/addOnData` directory.
- Preserved close-contract target URL first-wins behavior.
- Split browser-coverage target URL tracking from close-contract target URL tracking.
- Normalized browser coverage URL keys consistently.
- Bounded and TTL-pruned closed zapid tracking.
- Put close-contract retry paths under one wall-clock budget.
- Reused a named bounded executor for `ptkBrowserCoverage` batches.
- Promoted reflection fallback failures to WARN with stable `PTK_REFLECTION_FALLBACK` markers.
- Made browser coverage counters independent instead of inflated by stronger events.
- Removed team-local Firing Range notes from public documentation.

## Validation

- `./gradlew test --tests org.zaproxy.addon.ptk.ExtensionPtkCloseContractTest`
- `./gradlew test`
- `./gradlew clean build`

## Known Follow-Ups

- Add deeper browser/WebDriver integration tests around real `browserClosing` callback behavior.
- Keep binary CRX/XPI provenance tied to the source extension build and store-published artifacts.
- Revisit reflection use with upstream ZAP APIs if stable public hooks become available.
