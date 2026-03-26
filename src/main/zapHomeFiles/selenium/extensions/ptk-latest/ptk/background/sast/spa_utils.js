"use strict";

export function getUrlParts(raw) {
  if (!raw) return null;
  try {
    const u = new URL(String(raw));
    return {
      origin: u.origin,
      pathname: u.pathname,
      search: u.search || "",
      hash: u.hash || ""
    };
  } catch {
    return null;
  }
}

export function isHashOnlyNavigation(currentUrl, targetUrl) {
  const current = getUrlParts(currentUrl);
  const target = getUrlParts(targetUrl);
  if (!current || !target) return false;
  const sameBase = current.origin === target.origin &&
    current.pathname === target.pathname &&
    current.search === target.search;
  if (!sameBase) return false;
  return current.hash !== target.hash;
}

export function applyRouteToFinding(finding, routeUrl) {
  if (!finding || !routeUrl) return finding;
  if (!finding.location || typeof finding.location !== "object") {
    finding.location = {};
  }
  const existingPageUrls = Array.isArray(finding.location.pageUrls)
    ? finding.location.pageUrls.map((value) => String(value || "").trim()).filter(Boolean)
    : [];
  const existingRuntimeUrls = Array.isArray(finding.location.runtimeUrls)
    ? finding.location.runtimeUrls.map((value) => String(value || "").trim()).filter(Boolean)
    : [];
  const mergedPageUrls = Array.from(new Set([
    ...existingPageUrls,
    ...existingRuntimeUrls,
    String(routeUrl || "").trim()
  ].filter(Boolean)));
  finding.location.url = routeUrl;
  finding.location.pageUrl = routeUrl;
  finding.location.runtimeUrl = routeUrl;
  finding.location.pageUrls = mergedPageUrls;
  finding.location.runtimeUrls = mergedPageUrls;
  finding.pageUrl = routeUrl;
  return finding;
}
