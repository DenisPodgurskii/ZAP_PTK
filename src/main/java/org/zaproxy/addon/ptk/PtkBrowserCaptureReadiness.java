package org.zaproxy.addon.ptk;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/** Bounded, owner-bound readiness metadata only. Never observes traffic or retains source data. */
final class PtkBrowserCaptureReadiness {
    static final int VERSION = 1;
    static final int MAX_OWNERS = 64;
    static final long TTL_MS = 60_000L;
    static final long CONFIG_NATIVE_BIND_TIMEOUT_MS = 2000L;

    private record Owner(
            String route,
            String browserid,
            String captureId,
            String phase,
            Set<String> required,
            boolean ready,
            boolean released,
            long expires) {}

    private record BrowserOwner(String route, String family, String phase, long expires) {}

    private final Map<String, Owner> owners = new HashMap<>();
    private final Map<String, BrowserOwner> browsers = new HashMap<>();
    private final LongSupplier clock;

    PtkBrowserCaptureReadiness() {
        this(System::currentTimeMillis);
    }

    PtkBrowserCaptureReadiness(LongSupplier clock) {
        this.clock = clock;
    }

    synchronized boolean bindBrowser(String route, String zapid, String family, String phase) {
        prune();
        if (!validRoute(route) || !validId(zapid) || !validId(family) || !validPhase(phase))
            return false;
        BrowserOwner existing = browsers.get(zapid);
        if (existing != null)
            return existing.route.equals(route)
                    && existing.family.equals(family)
                    && existing.phase.equals(phase);
        if (browsers.size() >= MAX_OWNERS) return false;
        browsers.put(zapid, new BrowserOwner(route, family, phase, clock.getAsLong() + TTL_MS));
        notifyAll();
        return true;
    }

    synchronized String awaitBrowserPhase(String route, String zapid, long timeoutMs)
            throws InterruptedException {
        if (!validRoute(route) || !validId(zapid)) return null;
        long deadline =
                System.nanoTime()
                        + Math.min(CONFIG_NATIVE_BIND_TIMEOUT_MS, Math.max(0, timeoutMs))
                                * 1_000_000L;
        while (true) {
            prune();
            BrowserOwner owner = browsers.get(zapid);
            if (owner != null) return owner.route.equals(route) ? owner.phase : null;
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) return null;
            // No config-cache or Client Integration registry lock is held by the caller.
            wait(Math.max(1, remaining / 1_000_000L));
        }
    }

    synchronized boolean isBrowserOwner(String route, String zapid, String phase) {
        prune();
        BrowserOwner owner = browsers.get(zapid);
        return owner != null && owner.route.equals(route) && owner.phase.equals(phase);
    }

    synchronized String browserFamily(String zapid) {
        prune();
        BrowserOwner owner = browsers.get(zapid);
        return owner == null ? null : owner.family;
    }

    synchronized boolean prepare(
            String route,
            String zapid,
            String browserid,
            String captureId,
            String phase,
            Set<String> required) {
        prune();
        if (!validRoute(route)
                || !validId(zapid)
                || !validId(browserid)
                || !validId(captureId)
                || !validPhase(phase)
                || !isBrowserOwner(route, zapid, phase)
                || required == null
                || !required.contains("network")
                || !Set.of("network", "sources").containsAll(required)) return false;
        Owner previous = owners.get(zapid);
        if (previous != null && !previous.released) {
            return matches(previous, route, browserid, captureId, phase)
                    && previous.required.equals(required);
        }
        if (previous != null && previous.captureId.equals(captureId)) return false;
        if (owners.entrySet().stream()
                .anyMatch(
                        entry ->
                                !entry.getKey().equals(zapid)
                                        && entry.getValue().captureId.equals(captureId)))
            return false;
        if (previous == null && owners.size() >= MAX_OWNERS) {
            owners.values().removeIf(owner -> owner.released);
            if (owners.size() >= MAX_OWNERS) return false;
        }
        owners.put(
                zapid,
                new Owner(
                        route,
                        browserid,
                        captureId,
                        phase,
                        Set.copyOf(required),
                        false,
                        false,
                        clock.getAsLong() + TTL_MS));
        BrowserOwner browser = browsers.get(zapid);
        browsers.put(
                zapid, new BrowserOwner(route, browser.family, phase, clock.getAsLong() + TTL_MS));
        return true;
    }

    synchronized boolean ready(
            String route,
            String zapid,
            String browserid,
            String captureId,
            String phase,
            Set<String> required,
            Set<String> armed) {
        prune();
        Owner owner = owners.get(zapid);
        if (!matches(owner, route, browserid, captureId, phase)
                || owner.released
                || !owner.required.equals(required)
                || !owner.required.equals(armed)) return false;
        owners.put(
                zapid,
                new Owner(
                        route,
                        browserid,
                        captureId,
                        phase,
                        owner.required,
                        true,
                        false,
                        owner.expires));
        notifyAll();
        return true;
    }

    synchronized boolean release(
            String route, String zapid, String browserid, String captureId, String phase) {
        prune();
        Owner owner = owners.get(zapid);
        if (!matches(owner, route, browserid, captureId, phase)) return false;
        owners.put(
                zapid,
                new Owner(
                        route,
                        browserid,
                        captureId,
                        phase,
                        owner.required,
                        false,
                        true,
                        owner.expires));
        notifyAll();
        return true;
    }

    synchronized boolean awaitReady(String route, String zapid, String phase, long timeoutMs)
            throws InterruptedException {
        long deadline = System.nanoTime() + Math.max(0, timeoutMs) * 1_000_000L;
        while (true) {
            prune();
            Owner owner = owners.get(zapid);
            if (owner != null
                    && owner.route.equals(route)
                    && owner.phase.equals(phase)
                    && owner.ready
                    && !owner.released) return true;
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) return false;
            // Releases only this metadata monitor. The caller holds no Client Integration lock.
            wait(Math.max(1, remaining / 1_000_000L));
        }
    }

    synchronized void releaseOwner(String zapid) {
        owners.remove(zapid);
        browsers.remove(zapid);
        notifyAll();
    }

    synchronized void clear() {
        owners.clear();
        browsers.clear();
        notifyAll();
    }

    private void prune() {
        long now = clock.getAsLong();
        browsers.values().removeIf(owner -> owner.expires <= now);
        owners.entrySet()
                .removeIf(
                        entry ->
                                entry.getValue().expires <= now
                                        || !browsers.containsKey(entry.getKey()));
    }

    static Map<String, Object> response(boolean ok, String reason) {
        return Map.of("ok", ok, "version", VERSION, "reason", reason);
    }

    static boolean validRoute(String route) {
        return route != null
                && route.matches("/zapCallBackUrl/[A-Za-z0-9_-]+/ptk/browser-capture")
                && route.length() <= 512;
    }

    private static boolean validId(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{1,128}");
    }

    private static boolean validPhase(String phase) {
        return "CLIENT_SPIDER".equals(phase) || "ACTIVE_SCAN_RULE".equals(phase);
    }

    private static boolean matches(
            Owner owner, String route, String browserid, String captureId, String phase) {
        return owner != null
                && owner.route.equals(route)
                && owner.browserid.equals(browserid)
                && owner.captureId.equals(captureId)
                && owner.phase.equals(phase);
    }
}
