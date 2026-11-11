package org.zaproxy.addon.ptk;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class PtkStartGateTest {

    @Test
    void shouldNotBePendingWhenAuthenticationNotExpected() {
        PtkStartGate gate = new PtkStartGate(true, () -> false);
        assertFalse(gate.isPending("z1"));
    }

    @Test
    void shouldBePendingUntilBrowserReady() {
        PtkStartGate gate = new PtkStartGate(true, () -> true);
        assertTrue(gate.isPending("z1"));
        gate.browserReady("z1");
        assertFalse(gate.isPending("z1"));
    }

    @Test
    void shouldOnlyReleaseTheReadyBrowser() {
        PtkStartGate gate = new PtkStartGate(true, () -> true);
        gate.browserReady("z1");
        assertTrue(gate.isPending("z2"));
    }

    @Test
    void shouldStopBeingPendingWhenNoLongerExpectingAuthentication() {
        AtomicBoolean expected = new AtomicBoolean(true);
        PtkStartGate gate = new PtkStartGate(true, expected::get);
        assertTrue(gate.isPending("z1"));
        expected.set(false);
        assertFalse(gate.isPending("z1"));
    }

    @Test
    void shouldNeverBePendingWhenUnsupported() {
        PtkStartGate gate = new PtkStartGate(false, () -> true);
        assertFalse(gate.isPending("z1"));
    }

    @Test
    void shouldNotBePendingWithoutZapId() {
        PtkStartGate gate = new PtkStartGate(true, () -> true);
        assertFalse(gate.isPending(null));
    }

    @Test
    void shouldForgetBrowser() {
        PtkStartGate gate = new PtkStartGate(true, () -> true);
        gate.browserReady("z1");
        gate.forget("z1");
        assertTrue(gate.isPending("z1"));
    }
}
