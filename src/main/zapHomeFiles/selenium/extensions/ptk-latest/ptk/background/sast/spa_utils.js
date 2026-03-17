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
  finding.location.url = routeUrl;
  finding.location.pageUrl = routeUrl;
  finding.location.runtimeUrl = routeUrl;
  finding.pageUrl = routeUrl;
  return finding;
}
