package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.ExecutorService;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

class PtkBrowserCoverageJobTest {

    @Test
    void runJobReportsMissingConfiguredUrlsWhenBrowserEvidenceNeverArrives() {
        ExtensionPtk ptk = newPtkForTest();
        TestBrowserCoverageJob job = new TestBrowserCoverageJob(ptk);
        job.getParameters().setSource("none");
        job.getParameters().setUrls("https://example.test/a\nhttps://example.test/b");
        job.getParameters().setMaxRetriesPerUrl(0);
        job.getParameters().setNumberOfBrowsers(2);
        job.getParameters().setEvidenceGraceMs(0);
        job.getParameters().setFailOnMissingBrowserLoad(true);
        AutomationProgress progress = new AutomationProgress();

        job.runJob(new AutomationEnvironment(progress), progress);

        assertEquals(2, job.getData().getMissingUrls());
        assertEquals(0, job.getData().getLoadedUrls());
        assertEquals(1, job.runDirectAttemptsCalls);
        assertEquals(
                List.of(List.of("https://example.test/a", "https://example.test/b")), job.batches);
        assertEquals(2, progress.getErrors().size());
        assertTrue(progress.getErrors().get(0).contains("not_browser_loaded"));
    }

    private static ExtensionPtk newPtkForTest() {
        // ExtensionPtk is expected to stay side-effect free at construction time.
        return new ExtensionPtk();
    }

    private static final class TestBrowserCoverageJob extends PtkBrowserCoverageJob {
        private int runDirectAttemptsCalls;
        private final java.util.ArrayList<List<String>> batches = new java.util.ArrayList<>();

        private TestBrowserCoverageJob(ExtensionPtk ptk) {
            super(ptk);
        }

        @Override
        protected boolean isClientExtensionAvailable() {
            return true;
        }

        @Override
        protected boolean isSeleniumExtensionAvailable() {
            return true;
        }

        @Override
        protected ExtensionClientIntegration getClientExtension() {
            return null;
        }

        @Override
        protected ExtensionSelenium getSeleniumExtension() {
            return null;
        }

        @Override
        protected void runDirectAttempts(
                ExecutorService executor,
                ExtensionClientIntegration client,
                ExtensionSelenium selenium,
                List<RunningAttempt> running,
                AutomationProgress progress,
                boolean requirePtkSession) {
            runDirectAttemptsCalls++;
            batches.add(running.stream().map(attempt -> attempt.target.url).toList());
        }
    }
}
