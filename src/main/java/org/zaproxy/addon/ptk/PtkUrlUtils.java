package org.zaproxy.addon.ptk;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

final class PtkUrlUtils {

    private PtkUrlUtils() {}

    static String normalizeHttpTargetUrl(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return null;
        }
        try {
            URI uri = new URI(targetUrl.trim()).normalize();
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return null;
            }
            if (uri.getHost() == null || uri.getHost().isBlank()) {
                return null;
            }
            return uri.toString();
        } catch (Exception e) {
            return null;
        }
    }

    static String normalizeHttpUrlWithoutFragment(String targetUrl) {
        String normalized = normalizeHttpTargetUrl(targetUrl);
        if (normalized == null) {
            return null;
        }
        try {
            URI uri = new URI(normalized);
            if ("zap".equalsIgnoreCase(uri.getHost())) {
                return null;
            }
            return new URI(
                            uri.getScheme(),
                            uri.getRawUserInfo(),
                            uri.getHost(),
                            uri.getPort(),
                            uri.getRawPath(),
                            uri.getRawQuery(),
                            null)
                    .toString();
        } catch (Exception e) {
            return null;
        }
    }

    static String deriveSameDirectoryPathScope(String targetUrl) {
        String normalized = normalizeHttpTargetUrl(targetUrl);
        if (normalized == null) {
            return null;
        }
        try {
            URI uri = new URI(normalized);
            String path = uri.getPath();
            if (path == null || path.isBlank() || "/".equals(path)) {
                return "/";
            }
            if (path.endsWith("/")) {
                return path;
            }
            int slash = path.lastIndexOf('/');
            if (slash < 0) {
                return "/";
            }
            return path.substring(0, slash + 1);
        } catch (Exception e) {
            return null;
        }
    }

    static boolean isSameOriginAndPathScoped(String targetUrl, String candidateUrl) {
        String normalizedTarget = normalizeHttpTargetUrl(targetUrl);
        String normalizedCandidate = normalizeHttpUrlWithoutFragment(candidateUrl);
        String pathScope = deriveSameDirectoryPathScope(normalizedTarget);
        if (normalizedTarget == null || normalizedCandidate == null || pathScope == null) {
            return false;
        }
        try {
            URI target = new URI(normalizedTarget);
            URI candidate = new URI(normalizedCandidate);
            if (!target.getScheme().equalsIgnoreCase(candidate.getScheme())) {
                return false;
            }
            if (!target.getHost().equalsIgnoreCase(candidate.getHost())) {
                return false;
            }
            if (target.getPort() != candidate.getPort()) {
                return false;
            }
            String candidatePath = candidate.getPath();
            if (candidatePath == null || candidatePath.isBlank()) {
                candidatePath = "/";
            }
            return candidatePath.startsWith(pathScope);
        } catch (Exception e) {
            return false;
        }
    }

    static String normalizeBrowserCoverageUrl(String targetUrl) {
        String normalized = normalizeHttpTargetUrl(targetUrl);
        if (normalized == null) {
            return null;
        }
        try {
            URI uri = new URI(normalized);
            if ("zap".equalsIgnoreCase(uri.getHost())) {
                return null;
            }
            String path = uri.getRawPath();
            if (path == null || path.isBlank()) {
                path = "/";
            }
            if (!path.endsWith("/")) {
                return uri.toString();
            }
            return new URI(
                            uri.getScheme(),
                            uri.getRawUserInfo(),
                            uri.getHost(),
                            uri.getPort(),
                            path + "index.html",
                            uri.getRawQuery(),
                            uri.getRawFragment())
                    .toString();
        } catch (Exception e) {
            return null;
        }
    }

    static boolean hasFragment(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return false;
        }
        try {
            URI uri = new URI(targetUrl.trim());
            return uri.getRawFragment() != null;
        } catch (Exception e) {
            return false;
        }
    }

    static String extractZapIdFromUrl(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return null;
        }
        try {
            URI uri = new URI(targetUrl.trim());
            String query = uri.getRawQuery();
            if (query == null || query.isBlank()) {
                return null;
            }
            for (String pair : query.split("&")) {
                int separator = pair.indexOf('=');
                String rawName = separator >= 0 ? pair.substring(0, separator) : pair;
                if (!"zapid".equals(URLDecoder.decode(rawName, StandardCharsets.UTF_8))) {
                    continue;
                }
                String rawValue = separator >= 0 ? pair.substring(separator + 1) : "";
                String value = URLDecoder.decode(rawValue, StandardCharsets.UTF_8);
                return value.isBlank() ? null : value;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
