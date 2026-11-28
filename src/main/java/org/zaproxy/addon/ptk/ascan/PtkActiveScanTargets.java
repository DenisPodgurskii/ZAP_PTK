package org.zaproxy.addon.ptk.ascan;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ScanEventPublisher;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.Target;

/** Original target metadata for the active scans that own PTK host rule invocations. */
public final class PtkActiveScanTargets implements EventConsumer, SessionChangedListener {

    private static final Pattern LITERAL_DIRECTORY =
            Pattern.compile("https?://[A-Za-z0-9.-]+(?::[0-9]+)?/(?:[A-Za-z0-9_~/-]+/)?");
    private static final Pattern AMBIGUOUS_ESCAPE = Pattern.compile("(?i)%(?:2e|2f|5c|25)");

    private final ExtensionActiveScan activeScan;
    private final Map<Integer, Entry> targets = new ConcurrentHashMap<>();

    public PtkActiveScanTargets(ExtensionActiveScan activeScan) {
        this.activeScan = activeScan;
    }

    @Override
    public void eventReceived(Event event) {
        int scanId;
        try {
            scanId = Integer.parseInt(event.getParameters().get(ScanEventPublisher.SCAN_ID));
        } catch (NumberFormatException e) {
            return;
        }
        switch (event.getEventType()) {
            case ScanEventPublisher.SCAN_STARTED_EVENT -> {
                Target target = event.getTarget();
                ActiveScan owner = activeScan.getScan(scanId);
                if (owner != null && target != null) {
                    targets.put(scanId, new Entry(owner, snapshot(target)));
                }
            }
            case ScanEventPublisher.SCAN_STOPPED_EVENT,
                    ScanEventPublisher.SCAN_COMPLETED_EVENT -> targets.remove(scanId);
            default -> {}
        }
    }

    public String resolve(HostProcess host, String representativeUrl) {
        if (host == null) return null;
        // The controller publishes scan.started while it holds the scan-list lock.
        // Snapshot the live scans before looking up the metadata from that event.
        String result = null;
        for (ActiveScan scan : activeScan.getActiveScans()) {
            Entry entry = targets.get(scan.getScanId());
            if (entry == null || entry.owner() != scan || !scan.getHostProcesses().contains(host)) {
                continue;
            }
            if (result != null || entry.target().context() != host.getContext()) return null;
            result = select(entry.target(), representativeUrl);
            if (result == null || !scan.isInScope(result) || !scan.isInScope(representativeUrl)) {
                return null;
            }
        }
        return result;
    }

    static Scope snapshot(Target target) {
        Context context = target.getContext();
        var nodes = target.getStartNodes();
        if (nodes != null) {
            String explicit = nodes.size() == 1 ? nodeUrl(nodes.get(0)) : null;
            return new Scope(context, explicit);
        }
        if (context == null) return new Scope(null, null);

        var includes = context.getIncludeInContextRegexs();
        if (includes.size() != 1) return new Scope(context, null);
        String include = includes.get(0);
        if (!include.endsWith(".*")) return new Scope(context, null);
        String prefix = include.substring(0, include.length() - 2);
        URI root = LITERAL_DIRECTORY.matcher(prefix).matches() ? httpUri(prefix) : null;
        if (root == null || "/".equals(root.getRawPath())) return new Scope(context, null);
        return new Scope(context, prefix);
    }

    static String select(Scope scope, String representativeUrl) {
        URI start = httpUri(scope.startUrl());
        URI page = httpUri(representativeUrl);
        if (start == null || page == null || !contains(start, page)) return null;
        Context context = scope.context();
        if (context != null
                && (!context.isInContext(scope.startUrl())
                        || !context.isInContext(representativeUrl))) {
            return null;
        }
        return scope.startUrl();
    }

    private static URI httpUri(String url) {
        if (url == null) return null;
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            if (("https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme))
                    && uri.getHost() != null
                    && uri.getRawUserInfo() == null
                    && uri.getRawFragment() == null
                    && uri.equals(uri.normalize())
                    && !AMBIGUOUS_ESCAPE.matcher(uri.getRawPath()).find()) {
                return uri;
            }
        } catch (IllegalArgumentException e) {
            // An invalid URL has no provable scope.
        }
        return null;
    }

    private static boolean contains(URI start, URI page) {
        if (!start.getScheme().equalsIgnoreCase(page.getScheme())
                || !start.getHost().equalsIgnoreCase(page.getHost())
                || effectivePort(start) != effectivePort(page)) {
            return false;
        }
        String startPath = start.getRawPath().isEmpty() ? "/" : start.getRawPath();
        String pagePath = page.getRawPath().isEmpty() ? "/" : page.getRawPath();
        if (start.getRawQuery() != null) {
            return startPath.equals(pagePath) && start.getRawQuery().equals(page.getRawQuery());
        }
        String prefix = startPath.endsWith("/") ? startPath : startPath + "/";
        return pagePath.equals(startPath) || pagePath.startsWith(prefix);
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() == -1
                ? ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80)
                : uri.getPort();
    }

    private static String nodeUrl(StructuralNode node) {
        if (node == null) return null;
        var uri = node.getURI();
        if (uri != null) return uri.toString();
        var history = node.getHistoryReference();
        return history == null || history.getURI() == null ? null : history.getURI().toString();
    }

    public void clear() {
        targets.clear();
    }

    @Override
    public void sessionAboutToChange(Session session) {
        clear();
    }

    @Override
    public void sessionChanged(Session session) {
        clear();
    }

    @Override
    public void sessionScopeChanged(Session session) {}

    @Override
    public void sessionModeChanged(Control.Mode mode) {}

    record Scope(Context context, String startUrl) {}

    private record Entry(ActiveScan owner, Scope target) {}
}
