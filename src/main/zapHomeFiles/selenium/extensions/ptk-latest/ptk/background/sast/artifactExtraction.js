"use strict";

import { ancestor } from "./acorn/walk.mjs";
import { buildRouteKey, normalizeMethod } from "../analysis/canonicalize.js";

const ROUTE_MARKER_KEYS = new Set([
  "path",
  "component",
  "element",
  "children",
  "name",
  "loader",
  "action",
  "beforeEnter",
  "redirect",
  "meta",
  "lazy",
  "caseSensitive",
  "index"
]);

const ROUTE_PARENT_KEYS = new Set(["routes", "children"]);
const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const DOM_HTML_ASSIGN_PROPS = new Set(["innerHTML", "outerHTML", "srcdoc"]);
const DOM_HTML_CALLS = new Set(["insertAdjacentHTML", "write", "writeln", "createContextualFragment"]);
const CODE_EXEC_CALLS = new Set(["eval", "setTimeout", "setInterval", "Function"]);

const ADMIN_LIKE_RE = /(?:^|[^a-z0-9])(admin|internal|debug|staff|ops|console|manage|management|moderation|moderator|backoffice|superuser|root)(?:$|[^a-z0-9])/i;
const AUTH_LIKE_RE = /(?:auth|session|token|jwt|login|oauth|sso|role|permission|guard|acl|privilege|csrf|admin|secure)/i;
const ROUTER_CALL_RE = /(?:^|\.)(?:createRouter|createBrowserRouter|createMemoryRouter|createHashRouter|Router|useRoutes)$/i;
const FEATURE_FLAG_RE = /(?:feature|flag|toggle|experiment|beta|preview|canary|rollout|variant|gate|kill[\W_]?switch|enable[a-z0-9_]*)/i;
const DEBUG_LIKE_RE = /(?:debug|preview|beta|canary|trace|staging|sandbox|lab|testmode|devtools)/i;
const HIDDEN_PARAM_RE = /(?:redirect|return(?:url)?|next|dest(?:ination)?|continue|callback|url|target|preview|debug|admin|role|scope|token|jwt|csrf|feature|flag|toggle|experiment|beta|canary|impersonate|method|template|format|download|locale|lang|view|mode|client_id|redirect_uri|response_type|response_mode|nonce|state|code_verifier|code_challenge|resource|audience|grant_type|device_code|samlrequest|samlresponse|relaystate|x-amz-|googleaccessid|signature|expires|awsaccesskeyid|credential)/i;
const GRAPHQL_ENDPOINT_RE = /(?:^|\/)(graphql|gql)(?:$|[/?#])/i;
const OAUTH_PATH_RE = /(?:^|\/)(?:oauth(?:2)?|oidc|authorize|authorization|token|userinfo|revoke|logout|callback|signin-oidc|connect\/authorize|connect\/token)(?:$|[/?#])/i;
const SAML_PATH_RE = /(?:^|\/)(?:saml(?:2)?|sso|acs|assertion|idp|sp)(?:$|[/?#])/i;
const CALLBACK_ROUTE_RE = /(?:^|\/)(?:callback|signin-oidc|oidc-callback|auth\/callback|acs)(?:$|[/?#])/i;
const OAUTH_PARAM_RE = /^(?:client_id|redirect_uri|response_type|response_mode|scope|state|nonce|code_verifier|code_challenge|code_challenge_method|prompt|resource|audience|id_token_hint|post_logout_redirect_uri|grant_type|device_code)$/i;
const SAML_PARAM_RE = /^(?:SAMLRequest|SAMLResponse|RelayState)$/i;
const SIGNED_URL_PARAM_RE = /^(?:X-Amz-[A-Za-z-]+|GoogleAccessId|Signature|Expires|AWSAccessKeyId|sv|sig|sp|se|sr|skoid|sktid|skt|ske|sks|skv|x-goog-signature|x-goog-credential|x-goog-algorithm|x-goog-date|x-goog-expires)$/i;
const UPLOAD_LIKE_RE = /(?:upload|import|attachment|avatar|media|file|image|photo|document|resume|logo|multipart|binary|formdata|content-type|filename|contenttype|content_type|presign|signed(?:-|_)?url)/i;
const OBJECT_STORAGE_HOST_RE = /(?:s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|digitaloceanspaces\.com|objects\.cdn\.cloudflare\.net)$/i;
const INTERNAL_HOST_RE = /^(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|.+\.(?:internal|corp|local))$/i;
const ENV_HOST_RE = /(?:^|[.-])(staging|stage|dev|sandbox|qa|preprod|uat|demo|test)(?:[.-]|$)/i;
const WEBAUTHN_PATH_RE = /(?:webauthn|passkey|assertion|attestation|publickeycredential)/i;
const WEBAUTHN_PARAM_RE = /^(?:publicKey|credentialId|rawId|attestation|assertion|allowCredentials|excludeCredentials|challenge|userVerification|rpId|authenticatorAttachment)$/i;
const SURFACE_HINT_MAX_LEN = 120;

function toNonEmptyString(value) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed.length ? trimmed : null;
}

function normalizeLocation(loc) {
  if (!loc || typeof loc !== "object" || !loc.start) return null;
  const line = Number(loc.start.line);
  const column = Number(loc.start.column);
  return {
    line: Number.isFinite(line) ? line : null,
    column: Number.isFinite(column) ? column : null
  };
}

function propertyName(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  return null;
}

function templateLiteralValue(node, bindings = new Map()) {
  if (!node || node.type !== "TemplateLiteral") return null;
  if (!Array.isArray(node.quasis) || !Array.isArray(node.expressions)) return null;
  if (!node.expressions.length) {
    return node.quasis.map((part) => part?.value?.cooked || "").join("");
  }
  let out = "";
  for (let idx = 0; idx < node.quasis.length; idx += 1) {
    out += node.quasis[idx]?.value?.cooked || "";
    if (idx >= node.expressions.length) continue;
    const resolved = resolveStaticString(node.expressions[idx], bindings);
    if (resolved == null) return null;
    out += resolved;
  }
  return out;
}

function stringLiteralValue(node, bindings = new Map()) {
  if (!node) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral") return templateLiteralValue(node, bindings);
  if (node.type === "TaggedTemplateExpression") {
    return templateLiteralValue(node.quasi, bindings);
  }
  return null;
}

function buildStaticStringBindings(masterAST) {
  const bindings = new Map();
  const remember = (name, value) => {
    const key = toNonEmptyString(name);
    const normalized = toNonEmptyString(value);
    if (!key || !normalized) return;
    bindings.set(key, normalized);
  };

  ancestor(masterAST, {
    VariableDeclarator(node) {
      if (!node?.id || node.id.type !== "Identifier") return;
      const value = resolveStaticString(node.init, bindings);
      if (value != null) remember(node.id.name, value);
    },
    AssignmentExpression(node) {
      if (!node?.left || node.left.type !== "Identifier") return;
      const value = resolveStaticString(node.right, bindings);
      if (value != null) remember(node.left.name, value);
    }
  });

  return bindings;
}

function calleeName(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const objectName = calleeName(node.object);
    const propName = !node.computed ? propertyName(node.property) : null;
    return objectName && propName ? `${objectName}.${propName}` : (propName || objectName || "");
  }
  if (node.type === "NewExpression") {
    return calleeName(node.callee);
  }
  return "";
}

function resolveStaticString(node, bindings = new Map()) {
  const direct = stringLiteralValue(node, bindings);
  if (direct != null) return direct;
  if (!node || typeof node !== "object") return null;

  if (node.type === "Identifier") {
    return bindings.get(node.name) || null;
  }

  if (node.type === "BinaryExpression" && node.operator === "+") {
    const left = resolveStaticString(node.left, bindings);
    const right = resolveStaticString(node.right, bindings);
    if (left == null || right == null) return null;
    return `${left}${right}`;
  }

  if (node.type === "CallExpression") {
    const name = calleeName(node.callee);
    if (name === "gql" || name.endsWith(".gql")) {
      return resolveStaticString(node.arguments?.[0], bindings);
    }
  }

  if (node.type === "NewExpression" && node.callee?.type === "Identifier" && node.callee.name === "URL") {
    const raw = resolveStaticString(node.arguments?.[0], bindings);
    const base = resolveStaticString(node.arguments?.[1], bindings);
    if (!raw) return null;
    if (!base) return raw;
    try {
      return new URL(raw, base).toString();
    } catch (_) {
      return raw;
    }
  }

  return null;
}

function objectProperty(node, name) {
  if (!node || node.type !== "ObjectExpression") return null;
  return (node.properties || []).find((prop) => {
    if (!prop || prop.type !== "Property") return false;
    return propertyName(prop.key) === name;
  }) || null;
}

function objectKeys(node) {
  if (!node || node.type !== "ObjectExpression") return [];
  return (node.properties || [])
    .filter((prop) => prop && prop.type === "Property")
    .map((prop) => propertyName(prop.key))
    .filter(Boolean);
}

function objectKeyNames(node) {
  if (!node || node.type !== "ObjectExpression") return [];
  return (node.properties || [])
    .filter((prop) => prop?.type === "Property")
    .map((prop) => propertyName(prop.key))
    .filter(Boolean);
}

function staticArrayStrings(node, bindings = new Map()) {
  if (!node || node.type !== "ArrayExpression") return [];
  return (node.elements || [])
    .map((element) => resolveStaticString(element, bindings))
    .filter((value) => typeof value === "string" && value.trim().length > 0);
}

function urlParamNames(rawUrl, hostHint = null) {
  const raw = toNonEmptyString(rawUrl);
  if (!raw) return [];
  try {
    const parsed = new URL(raw, hostHint ? `http://${String(hostHint).trim()}` : "http://localhost");
    return Array.from(new Set(Array.from(parsed.searchParams.keys()).map((key) => String(key || "").trim()).filter(Boolean)))
      .sort((a, b) => a.localeCompare(b));
  } catch (_) {
    return [];
  }
}

function parseUrlParts(rawUrl, hostHint = null) {
  const raw = toNonEmptyString(rawUrl);
  if (!raw) return null;
  try {
    const parsed = new URL(raw, hostHint ? `http://${String(hostHint).trim()}` : "http://localhost");
    return {
      href: parsed.toString(),
      hostname: toNonEmptyString(parsed.hostname) || null,
      pathname: toNonEmptyString(parsed.pathname) || "/",
      searchParams: Array.from(parsed.searchParams.keys())
    };
  } catch (_) {
    return {
      href: raw,
      hostname: null,
      pathname: raw,
      searchParams: []
    };
  }
}

function objectStorageProvider(hostname) {
  const host = toNonEmptyString(hostname);
  if (!host) return null;
  if (/amazonaws\.com$/i.test(host)) return "aws-s3";
  if (/storage\.googleapis\.com$/i.test(host)) return "gcs";
  if (/blob\.core\.windows\.net$/i.test(host)) return "azure-blob";
  if (/digitaloceanspaces\.com$/i.test(host)) return "do-spaces";
  if (/objects\.cdn\.cloudflare\.net$/i.test(host)) return "cloudflare-r2";
  return null;
}

function headerEntries(node, bindings = new Map()) {
  if (!node) return [];
  if (node.type === "ObjectExpression") {
    return (node.properties || [])
      .filter((prop) => prop?.type === "Property")
      .map((prop) => ({
        name: propertyName(prop.key),
        value: resolveStaticString(prop.value, bindings)
      }))
      .filter((entry) => entry.name);
  }
  if (node.type === "NewExpression" && node.callee?.type === "Identifier" && node.callee.name === "Headers") {
    const arg = node.arguments?.[0];
    if (arg?.type === "ObjectExpression") return headerEntries(arg, bindings);
  }
  return [];
}

function bodyTraits(node, bindings = new Map()) {
  if (!node) return { bodyKeys: [], uploadSignals: [] };

  if (node.type === "ObjectExpression") {
    const bodyKeys = objectKeyNames(node);
    const uploadSignals = bodyKeys.filter((key) => UPLOAD_LIKE_RE.test(key));
    return {
      bodyKeys: bodyKeys.sort((a, b) => a.localeCompare(b)),
      uploadSignals: normalizeStringList(uploadSignals)
    };
  }

  if (node.type === "CallExpression" && calleeName(node.callee) === "JSON.stringify") {
    return bodyTraits(node.arguments?.[0], bindings);
  }

  if (node.type === "NewExpression" && node.callee?.type === "Identifier") {
    const ctor = node.callee.name;
    if (ctor === "FormData" || ctor === "File" || ctor === "Blob" || ctor === "ReadableStream") {
      return {
        bodyKeys: [],
        uploadSignals: [ctor]
      };
    }
  }

  if (node.type === "Identifier") {
    if (UPLOAD_LIKE_RE.test(node.name)) {
      return {
        bodyKeys: [],
        uploadSignals: [node.name]
      };
    }
  }

  return {
    bodyKeys: bodyKeyNames(node, bindings),
    uploadSignals: []
  };
}

function classifyEndpointMetadata({
  rawUrl,
  resolvedUrl,
  paramNames = [],
  bodyKeys = [],
  headerNames = [],
  headerEntriesList = [],
  uploadSignals = []
} = {}) {
  const urlValue = resolvedUrl || rawUrl || "";
  const parsed = parseUrlParts(urlValue);
  const hostname = parsed?.hostname || null;
  const pathname = parsed?.pathname || urlValue;
  const allNames = normalizeStringList([
    ...(paramNames || []),
    ...(bodyKeys || []),
    ...(headerNames || [])
  ]);

  const discoveryTags = [];
  const protocolHints = [];
  const environmentHints = [];
  const storageHints = [];
  const authHints = [];
  const normalizedUploadSignals = normalizeStringList(uploadSignals);

  const push = (list, value) => {
    const normalized = toNonEmptyString(value);
    if (!normalized || list.includes(normalized)) return;
    list.push(normalized);
  };

  const addProtocol = (value) => {
    push(protocolHints, value);
    push(discoveryTags, value);
    if (/oauth|oidc|saml|webauthn|callback/i.test(value)) push(authHints, value);
  };

  if (hostname) {
    if (INTERNAL_HOST_RE.test(hostname)) {
      push(environmentHints, "internal");
      push(discoveryTags, "internal-host");
    }
    const envMatch = hostname.match(ENV_HOST_RE);
    if (envMatch?.[1]) {
      push(environmentHints, String(envMatch[1]).toLowerCase());
      push(discoveryTags, "nonprod-host");
    }
    const provider = objectStorageProvider(hostname);
    if (provider || OBJECT_STORAGE_HOST_RE.test(hostname)) {
      push(storageHints, provider || "object-storage");
      push(discoveryTags, "object-storage");
    }
  }

  if (OAUTH_PATH_RE.test(pathname) || allNames.some((name) => OAUTH_PARAM_RE.test(name))) {
    addProtocol(/oidc|signin-oidc/i.test(pathname) || allNames.some((name) => /nonce|code_verifier|code_challenge/i.test(name)) ? "oidc" : "oauth");
  }
  if (SAML_PATH_RE.test(pathname) || allNames.some((name) => SAML_PARAM_RE.test(name))) {
    addProtocol("saml");
  }
  if (CALLBACK_ROUTE_RE.test(pathname) || allNames.some((name) => /^(?:state|nonce|code|RelayState|SAMLResponse)$/i.test(name))) {
    addProtocol("auth-callback");
  }
  if (WEBAUTHN_PATH_RE.test(pathname) || allNames.some((name) => WEBAUTHN_PARAM_RE.test(name))) {
    addProtocol("webauthn");
  }

  if (UPLOAD_LIKE_RE.test(pathname)
    || normalizedUploadSignals.length
    || allNames.some((name) => UPLOAD_LIKE_RE.test(name))
    || headerEntriesList.some((entry) => String(entry.name || "").toLowerCase() === "content-type" && /multipart\/form-data/i.test(entry.value || ""))) {
    push(discoveryTags, "upload");
  }

  if (allNames.some((name) => SIGNED_URL_PARAM_RE.test(name))) {
    push(storageHints, "signed-url");
    push(discoveryTags, "signed-url");
  }

  allNames.filter((name) => AUTH_LIKE_RE.test(name)).forEach((name) => push(authHints, name));

  return {
    discoveryTags: normalizeStringList(discoveryTags),
    protocolHints: normalizeStringList(protocolHints),
    environmentHints: normalizeStringList(environmentHints),
    storageHints: normalizeStringList(storageHints),
    authHints: normalizeStringList(authHints),
    uploadSignals: normalizedUploadSignals,
    uploadLike: discoveryTags.includes("upload"),
    objectStorageLike: discoveryTags.includes("object-storage") || storageHints.length > 0,
    internalLike: environmentHints.includes("internal")
  };
}

function looksLikeRegexUrlPattern(rawValue) {
  const value = toNonEmptyString(rawValue);
  if (!value) return false;
  if (/\(\?[!:=<]/.test(value)) return true;
  if (/\\[dDsSwWbB]/.test(value)) return true;
  if (/\[[^\]]+\]/.test(value) && /[|+]/.test(value)) return true;
  return false;
}

function isValidEndpointUrlCandidate(rawValue) {
  const value = toNonEmptyString(rawValue);
  if (!value) return false;
  if (/[\r\n]/.test(value)) return false;
  if (looksLikeRegexUrlPattern(value)) return false;
  return true;
}

function routePathLike(pathValue) {
  const path = toNonEmptyString(pathValue);
  if (!path) return false;
  if (path.startsWith("/")) return true;
  if (/[:*]/.test(path)) return true;
  if (/^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._:*~-]+)*$/.test(path)) return true;
  return false;
}

function nearestParentPropertyKey(ancestors = []) {
  for (let idx = ancestors.length - 2; idx >= 0; idx -= 1) {
    const parent = ancestors[idx];
    if (parent?.type === "Property") {
      return propertyName(parent.key);
    }
  }
  return null;
}

function nearestVariableName(ancestors = []) {
  for (let idx = ancestors.length - 2; idx >= 0; idx -= 1) {
    const parent = ancestors[idx];
    if (parent?.type === "VariableDeclarator" && parent.id?.type === "Identifier") {
      return parent.id.name;
    }
  }
  return null;
}

function hasRouterCallAncestor(ancestors = []) {
  return ancestors.some((node) => node?.type === "CallExpression" && ROUTER_CALL_RE.test(calleeName(node.callee)));
}

function collectHintValues(node, bindings = new Map(), out = new Set(), depth = 0) {
  if (!node || depth > 2) return out;

  if (node.type === "ObjectExpression") {
    (node.properties || []).forEach((prop) => {
      if (!prop || prop.type !== "Property") return;
      const key = propertyName(prop.key);
      if (key && AUTH_LIKE_RE.test(key)) out.add(key);
      collectHintValues(prop.value, bindings, out, depth + 1);
    });
    return out;
  }

  if (node.type === "ArrayExpression") {
    (node.elements || []).forEach((entry) => collectHintValues(entry, bindings, out, depth + 1));
    return out;
  }

  const value = resolveStaticString(node, bindings);
  if (value && AUTH_LIKE_RE.test(value)) out.add(value);
  return out;
}

function normalizeBaseUrl(rawBase) {
  const base = toNonEmptyString(rawBase);
  if (!base) return null;
  try {
    return new URL(base).toString().replace(/\/+$/, "");
  } catch (_) {
    return base.replace(/\/+$/, "");
  }
}

function joinUrl(baseUrl, rawUrl) {
  const base = normalizeBaseUrl(baseUrl);
  const raw = toNonEmptyString(rawUrl);
  if (!raw) return null;
  if (!base) return raw;
  try {
    return new URL(raw, base).toString();
  } catch (_) {
    if (raw.startsWith("/")) return `${base}${raw}`;
    return `${base}/${raw}`.replace(/([^:]\/)\/+/g, "$1");
  }
}

function resolveSourceRef(sourceFile, pageUrl) {
  const source = toNonEmptyString(sourceFile);
  if (source && /^inline/i.test(source)) {
    return `${toNonEmptyString(pageUrl) || "inline"} :: ${source}`;
  }
  return source || toNonEmptyString(pageUrl) || "unknown";
}

function sourceRouteKey(pageUrl, hostHint, method = "*") {
  return buildRouteKey({
    url: pageUrl || "/",
    method,
    host: hostHint
  });
}

function artifactId(prefix, { sourceRef, loc, suffix }) {
  const line = loc?.line || 0;
  const column = loc?.column || 0;
  return `${prefix}::${sourceRef || "unknown"}::${line}:${column}::${suffix || "artifact"}`;
}

function routeArtifactId({ sourceRef, loc, path }) {
  return artifactId("sast-route", { sourceRef, loc, suffix: path || "/" });
}

function endpointArtifactId({ sourceRef, loc, transport, method, url }) {
  return artifactId("sast-endpoint", {
    sourceRef,
    loc,
    suffix: `${transport || "request"}::${method || "GET"}::${url || "/"}`
  });
}

function graphqlArtifactId({ sourceRef, loc, routeKey, operationNames }) {
  return artifactId("sast-graphql", {
    sourceRef,
    loc,
    suffix: `${routeKey || "unknown"}::${(operationNames || []).join(",") || "anonymous"}`
  });
}

function surfaceArtifactId({ sourceRef, loc, surfaceType, label }) {
  return artifactId("sast-surface", {
    sourceRef,
    loc,
    suffix: `${surfaceType || "surface"}::${label || "hint"}`
  });
}

function surfaceBucketId({ routeKey, surfaceType, label }) {
  return `sast-surface::${routeKey || "unknown"}::${surfaceType || "surface"}::${label || "hint"}`;
}

function hiddenParamArtifactId({ sourceRef, loc, container, paramName }) {
  return artifactId("sast-hidden-param", {
    sourceRef,
    loc,
    suffix: `${container || "param"}::${paramName || "unknown"}`
  });
}

function hiddenParamBucketId({ routeKey, container, paramName }) {
  return `sast-hidden-param::${routeKey || "unknown"}::${container || "param"}::${paramName || "unknown"}`;
}

function gadgetArtifactId({ sourceRef, loc, gadgetType, label }) {
  return artifactId("sast-gadget", {
    sourceRef,
    loc,
    suffix: `${gadgetType || "gadget"}::${label || "hint"}`
  });
}

function gadgetBucketId({ routeKey, gadgetType, label }) {
  return `sast-gadget::${routeKey || "unknown"}::${gadgetType || "gadget"}::${label || "hint"}`;
}

function normalizeStringList(values = []) {
  return Array.from(new Set((values || []).map((value) => toNonEmptyString(value)).filter(Boolean)))
    .sort((a, b) => a.localeCompare(b));
}

function normalizeSurfaceHintValue(value) {
  const normalized = toNonEmptyString(value);
  if (!normalized) return null;
  if (normalized.length > SURFACE_HINT_MAX_LEN) return null;
  if (/[\r\n{};]/.test(normalized)) return null;
  if (/^[.#:]/.test(normalized)) return null;
  return normalized;
}

function buildRouteArtifact(node, ancestors, { bindings, pageUrl, hostHint }) {
  const pathProp = objectProperty(node, "path");
  const pathValue = resolveStaticString(pathProp?.value, bindings);
  if (!routePathLike(pathValue)) return null;

  const siblingKeys = objectKeys(node);
  let score = 0;
  if (siblingKeys.some((key) => ROUTE_MARKER_KEYS.has(key) && key !== "path")) score += 1;

  const parentKey = nearestParentPropertyKey(ancestors);
  if (parentKey && ROUTE_PARENT_KEYS.has(parentKey)) score += 1;

  const varName = nearestVariableName(ancestors);
  if (varName && /route|router/i.test(varName)) score += 1;

  if (hasRouterCallAncestor(ancestors)) score += 1;

  if (score <= 0) return null;

  const path = pathValue || "/";
  const protocolHints = [];
  if (OAUTH_PATH_RE.test(path)) protocolHints.push(/oidc|signin-oidc/i.test(path) ? "oidc" : "oauth");
  if (SAML_PATH_RE.test(path)) protocolHints.push("saml");
  if (CALLBACK_ROUTE_RE.test(path)) protocolHints.push("auth-callback");
  if (WEBAUTHN_PATH_RE.test(path)) protocolHints.push("webauthn");
  const environmentHints = [];
  const pathEnvMatch = path.match(ENV_HOST_RE);
  if (pathEnvMatch?.[1]) environmentHints.push(String(pathEnvMatch[1]).toLowerCase());
  const authHints = normalizeStringList([
    ...Array.from(collectHintValues(node, bindings)),
    ...protocolHints
  ]);
  const sourceFile = node?.sourceFile || null;
  const sourceRef = resolveSourceRef(sourceFile, pageUrl);
  const loc = normalizeLocation(node.loc);
  const routeKey = buildRouteKey({
    url: path,
    method: "*",
    host: hostHint
  });
  const adminLike = ADMIN_LIKE_RE.test(path) || authHints.some((hint) => ADMIN_LIKE_RE.test(hint));

  return {
    id: routeArtifactId({ sourceRef, loc, path }),
    artifactType: "route",
    moduleId: "sast-route-discovery",
    ruleId: "route-artifact",
    framework: hasRouterCallAncestor(ancestors) ? "router-config" : "route-object",
    path,
    routeKey,
    authHints,
    protocolHints: normalizeStringList(protocolHints),
    environmentHints: normalizeStringList(environmentHints),
    adminLike,
    sourceFile: sourceRef,
    sourceLoc: loc,
    pageUrl: toNonEmptyString(pageUrl) || null
  };
}

function bodyKeyNames(node, bindings = new Map()) {
  if (!node) return [];
  if (node.type === "ObjectExpression") {
    return objectKeyNames(node).sort((a, b) => a.localeCompare(b));
  }
  if (node.type === "CallExpression" && calleeName(node.callee) === "JSON.stringify") {
    return bodyKeyNames(node.arguments?.[0], bindings);
  }
  if (node.type === "NewExpression" && node.callee?.type === "Identifier" && node.callee.name === "URLSearchParams") {
    const arg = node.arguments?.[0];
    if (arg?.type === "ObjectExpression") return objectKeyNames(arg).sort((a, b) => a.localeCompare(b));
    const text = resolveStaticString(arg, bindings);
    if (text) return urlParamNames(text);
  }
  return [];
}

function headerKeyNames(node) {
  if (!node || node.type !== "ObjectExpression") return [];
  return objectKeyNames(node).sort((a, b) => a.localeCompare(b));
}

function unwrapJsonLikeNode(node) {
  if (!node) return null;
  if (node.type === "ObjectExpression") return node;
  if (node.type === "CallExpression" && calleeName(node.callee) === "JSON.stringify") {
    return node.arguments?.[0] || null;
  }
  return null;
}

function stripGraphqlComments(text) {
  return String(text || "")
    .replace(/#[^\n\r]*/g, "")
    .trim();
}

function looksLikeGraphqlDocument(text) {
  const normalized = stripGraphqlComments(text);
  if (!normalized) return false;
  if (/\b(query|mutation|subscription|fragment)\b/i.test(normalized)) return true;
  return normalized.includes("{") && normalized.includes("}");
}

function extractGraphqlRootFields(documentText) {
  const tokens = stripGraphqlComments(documentText).match(/\.\.\.|[{}():]|[A-Za-z_][A-Za-z0-9_]*/g) || [];
  const fields = new Set();
  let depth = 0;
  let parenDepth = 0;
  let previous = "";
  tokens.forEach((token) => {
    if (token === "{") {
      depth += 1;
      previous = token;
      return;
    }
    if (token === "}") {
      depth = Math.max(0, depth - 1);
      previous = token;
      return;
    }
    if (token === "(") {
      parenDepth += 1;
      previous = token;
      return;
    }
    if (token === ")") {
      parenDepth = Math.max(0, parenDepth - 1);
      previous = token;
      return;
    }
    if (token === ":" || token === "...") {
      previous = token;
      return;
    }
    if (depth === 1 && parenDepth === 0 && /^[A-Za-z_]/.test(token)) {
      if (previous !== "..." && previous !== ":" && token !== "on") {
        fields.add(token);
      }
    }
    previous = token;
  });
  return Array.from(fields).sort((a, b) => a.localeCompare(b));
}

function summarizeGraphqlDocument(documentText, explicitOperationName = null) {
  const normalized = stripGraphqlComments(documentText);
  if (!normalized) {
    return {
      operationTypes: [],
      operationNames: [],
      rootFields: []
    };
  }
  const opMatches = Array.from(normalized.matchAll(/\b(query|mutation|subscription)\b(?:\s+([A-Za-z_][A-Za-z0-9_]*))?/gi));
  const operationTypes = opMatches.map((match) => String(match[1] || "").toLowerCase()).filter(Boolean);
  const operationNames = opMatches.map((match) => toNonEmptyString(match[2])).filter(Boolean);
  if (!operationTypes.length) {
    operationTypes.push("query");
  }
  if (explicitOperationName && !operationNames.includes(explicitOperationName)) {
    operationNames.push(explicitOperationName);
  }
  return {
    operationTypes: normalizeStringList(operationTypes),
    operationNames: normalizeStringList(operationNames),
    rootFields: extractGraphqlRootFields(normalized)
  };
}

function graphqlPayloadFromNode(node, bindings = new Map()) {
  const bodyNode = unwrapJsonLikeNode(node);
  if (bodyNode?.type === "ObjectExpression") {
    const queryProp = objectProperty(bodyNode, "query")
      || objectProperty(bodyNode, "mutation")
      || objectProperty(bodyNode, "subscription")
      || objectProperty(bodyNode, "document");
    const operationNameProp = objectProperty(bodyNode, "operationName");
    const variablesProp = objectProperty(bodyNode, "variables");
    const directDocument = resolveStaticString(queryProp?.value, bindings);
    if (directDocument && looksLikeGraphqlDocument(directDocument)) {
      return {
        documentText: directDocument,
        explicitOperationName: resolveStaticString(operationNameProp?.value, bindings),
        variableNames: objectKeyNames(variablesProp?.value)
      };
    }
  }

  const direct = resolveStaticString(node, bindings);
  if (direct && looksLikeGraphqlDocument(direct)) {
    return {
      documentText: direct,
      explicitOperationName: null,
      variableNames: []
    };
  }
  return null;
}

function buildGraphqlArtifact({
  transport = "http",
  clientKind = "http",
  method = "POST",
  rawUrl = null,
  resolvedUrl = null,
  routeKey = null,
  authHints = [],
  sourceRef,
  loc,
  pageUrl,
  payload
} = {}) {
  if (!payload || !payload.documentText) return null;
  const summary = summarizeGraphqlDocument(payload.documentText, payload.explicitOperationName);
  const finalRouteKey = routeKey || buildRouteKey({
    url: resolvedUrl || rawUrl || "/graphql",
    method,
    host: pageUrl || null
  });
  const adminSignals = [
    ...(summary.operationNames || []),
    ...(summary.rootFields || []),
    ...(authHints || [])
  ];
  const adminLike = ADMIN_LIKE_RE.test(resolvedUrl || rawUrl || "")
    || adminSignals.some((value) => ADMIN_LIKE_RE.test(value));

  return {
    id: graphqlArtifactId({
      sourceRef,
      loc,
      routeKey: finalRouteKey,
      operationNames: summary.operationNames
    }),
    artifactType: "graphql",
    moduleId: "sast-graphql-artifacts",
    ruleId: "graphql-artifact",
    clientKind,
    transport,
    method,
    url: rawUrl || null,
    resolvedUrl: resolvedUrl || rawUrl || null,
    routeKey: finalRouteKey,
    operationTypes: summary.operationTypes,
    operationNames: summary.operationNames,
    rootFields: summary.rootFields,
    variableNames: normalizeStringList(payload.variableNames || []),
    authHints: normalizeStringList(authHints),
    adminLike,
    sourceFile: sourceRef,
    sourceLoc: loc,
    pageUrl: toNonEmptyString(pageUrl) || null
  };
}

function graphqlArtifactsFromHttpRequest({
  transport,
  method,
  rawUrl,
  resolvedUrl,
  bodyNode,
  authHints,
  sourceRef,
  loc,
  pageUrl,
  hostHint,
  bindings
} = {}) {
  const payload = graphqlPayloadFromNode(bodyNode, bindings);
  const looksGraphql = GRAPHQL_ENDPOINT_RE.test(resolvedUrl || rawUrl || "");
  if (!payload && !looksGraphql) return [];
  if (!payload?.documentText) return [];
  return [
    buildGraphqlArtifact({
      transport,
      clientKind: "http",
      method,
      rawUrl,
      resolvedUrl,
      routeKey: buildRouteKey({
        url: resolvedUrl || rawUrl || "/graphql",
        method,
        host: hostHint
      }),
      authHints,
      sourceRef,
      loc,
      pageUrl,
      payload
    })
  ].filter(Boolean);
}

function graphqlArtifactsFromClientCall(node, { bindings, pageUrl, hostHint }) {
  const name = calleeName(node.callee);
  if (!/\.(?:query|mutate|subscribe|watchQuery)$/i.test(name)) return [];
  const configNode = node.arguments?.[0];
  if (!configNode || configNode.type !== "ObjectExpression") return [];
  const payload = graphqlPayloadFromNode(
    objectProperty(configNode, "query")?.value
      || objectProperty(configNode, "mutation")?.value
      || objectProperty(configNode, "subscription")?.value,
    bindings
  );
  if (!payload?.documentText) return [];

  const variablesNode = objectProperty(configNode, "variables")?.value || null;
  const uri = resolveStaticString(objectProperty(configNode, "uri")?.value, bindings) || "/graphql";
  const resolvedUrl = joinUrl(pageUrl, uri);
  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);

  return [
    buildGraphqlArtifact({
      transport: "graphql-client",
      clientKind: name,
      method: "POST",
      rawUrl: uri,
      resolvedUrl,
      routeKey: buildRouteKey({
        url: resolvedUrl || uri,
        method: "POST",
        host: hostHint
      }),
      authHints: [],
      sourceRef,
      loc,
      pageUrl,
      payload: {
        ...payload,
        variableNames: [
          ...(payload.variableNames || []),
          ...objectKeyNames(variablesNode)
        ]
      }
    })
  ].filter(Boolean);
}

function fetchArtifactFromCall(node, { bindings, pageUrl, hostHint }) {
  const name = calleeName(node.callee);
  if (!/^(?:fetch|window\.fetch|globalThis\.fetch)$/i.test(name)) return null;

  let urlNode = node.arguments?.[0] || null;
  let optionsNode = node.arguments?.[1] || null;

  if (urlNode?.type === "NewExpression" && urlNode.callee?.type === "Identifier" && urlNode.callee.name === "Request") {
    optionsNode = optionsNode || urlNode.arguments?.[1] || null;
    urlNode = urlNode.arguments?.[0] || null;
  }

  const rawUrl = resolveStaticString(urlNode, bindings);
  if (!isValidEndpointUrlCandidate(rawUrl)) return null;
  const methodProp = optionsNode?.type === "ObjectExpression" ? objectProperty(optionsNode, "method") : null;
  const bodyProp = optionsNode?.type === "ObjectExpression" ? objectProperty(optionsNode, "body") : null;
  const headersProp = optionsNode?.type === "ObjectExpression" ? objectProperty(optionsNode, "headers") : null;
  const method = normalizeMethod(resolveStaticString(methodProp?.value, bindings) || "GET");
  const resolvedUrl = joinUrl(pageUrl, rawUrl);
  const paramNames = urlParamNames(resolvedUrl || rawUrl, hostHint);
  const bodyInfo = bodyTraits(bodyProp?.value, bindings);
  const bodyKeys = bodyInfo.bodyKeys;
  const headerEntriesList = headerEntries(headersProp?.value, bindings);
  const headerNames = normalizeStringList(headerEntriesList.map((entry) => entry.name));
  const endpointMeta = classifyEndpointMetadata({
    rawUrl,
    resolvedUrl,
    paramNames,
    bodyKeys,
    headerNames,
    headerEntriesList,
    uploadSignals: bodyInfo.uploadSignals
  });
  const authHints = normalizeStringList([
    ...headerNames.filter((nameValue) => AUTH_LIKE_RE.test(nameValue)),
    ...endpointMeta.authHints
  ]);
  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);
  const routeKey = buildRouteKey({
    url: resolvedUrl || rawUrl,
    method,
    host: hostHint
  });
  const artifact = {
    id: endpointArtifactId({ sourceRef, loc, transport: "fetch", method, url: resolvedUrl || rawUrl }),
    artifactType: "endpoint",
    moduleId: "sast-endpoint-artifacts",
    ruleId: "endpoint-artifact",
    transport: "fetch",
    method,
    url: rawUrl,
    resolvedUrl: resolvedUrl || rawUrl,
    routeKey,
    paramNames,
    bodyKeys,
    headerNames,
    authHints,
    protocolHints: endpointMeta.protocolHints,
    discoveryTags: endpointMeta.discoveryTags,
    environmentHints: endpointMeta.environmentHints,
    storageHints: endpointMeta.storageHints,
    uploadSignals: endpointMeta.uploadSignals,
    uploadLike: endpointMeta.uploadLike,
    objectStorageLike: endpointMeta.objectStorageLike,
    internalLike: endpointMeta.internalLike,
    adminLike: ADMIN_LIKE_RE.test(resolvedUrl || rawUrl) || authHints.some((hint) => ADMIN_LIKE_RE.test(hint)),
    sourceFile: sourceRef,
    sourceLoc: loc,
    pageUrl: toNonEmptyString(pageUrl) || null
  };

  return {
    artifact,
    graphqlArtifacts: graphqlArtifactsFromHttpRequest({
      transport: "fetch",
      method,
      rawUrl,
      resolvedUrl,
      bodyNode: bodyProp?.value || null,
      authHints,
      sourceRef,
      loc,
      pageUrl,
      hostHint,
      bindings
    }),
    hiddenParamArtifacts: hiddenParamArtifactsFromEndpointShape({
      routeKey,
      sourceRef,
      loc,
      pageUrl,
      queryParamNames: paramNames,
      bodyKeys,
      headerNames
    })
  };
}

function xhrArtifactFromCall(node, { bindings, pageUrl, hostHint }) {
  if (node?.callee?.type !== "MemberExpression") return null;
  if (propertyName(node.callee.property) !== "open") return null;
  const method = normalizeMethod(resolveStaticString(node.arguments?.[0], bindings));
  const rawUrl = resolveStaticString(node.arguments?.[1], bindings);
  if (!HTTP_METHODS.has(method) || !isValidEndpointUrlCandidate(rawUrl)) return null;

  const resolvedUrl = joinUrl(pageUrl, rawUrl);
  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);
  const paramNames = urlParamNames(resolvedUrl || rawUrl, hostHint);
  const endpointMeta = classifyEndpointMetadata({
    rawUrl,
    resolvedUrl,
    paramNames
  });
  return {
    id: endpointArtifactId({ sourceRef, loc, transport: "xhr", method, url: resolvedUrl || rawUrl }),
    artifactType: "endpoint",
    moduleId: "sast-endpoint-artifacts",
    ruleId: "endpoint-artifact",
    transport: "xhr",
    method,
    url: rawUrl,
    resolvedUrl: resolvedUrl || rawUrl,
    routeKey: buildRouteKey({
      url: resolvedUrl || rawUrl,
      method,
      host: hostHint
    }),
    paramNames,
    bodyKeys: [],
    headerNames: [],
    authHints: endpointMeta.authHints,
    protocolHints: endpointMeta.protocolHints,
    discoveryTags: endpointMeta.discoveryTags,
    environmentHints: endpointMeta.environmentHints,
    storageHints: endpointMeta.storageHints,
    uploadSignals: endpointMeta.uploadSignals,
    uploadLike: endpointMeta.uploadLike,
    objectStorageLike: endpointMeta.objectStorageLike,
    internalLike: endpointMeta.internalLike,
    adminLike: ADMIN_LIKE_RE.test(resolvedUrl || rawUrl),
    sourceFile: sourceRef,
    sourceLoc: loc,
    pageUrl: toNonEmptyString(pageUrl) || null
  };
}

function axiosArtifactFromCall(node, { bindings, pageUrl, hostHint }) {
  const name = calleeName(node.callee);
  if (!/^axios(?:\.[A-Za-z]+)?$/i.test(name)) return null;

  const methodMatch = name.match(/^axios\.([A-Za-z]+)$/i);
  let method = methodMatch ? methodMatch[1].toUpperCase() : null;
  let rawUrl = null;
  let configNode = null;
  let dataNode = null;

  if (method && HTTP_METHODS.has(method)) {
    rawUrl = resolveStaticString(node.arguments?.[0], bindings);
    if (method === "POST" || method === "PUT" || method === "PATCH") {
      dataNode = node.arguments?.[1] || null;
      configNode = node.arguments?.[2] || null;
    } else {
      configNode = node.arguments?.[1] || null;
    }
  } else {
    configNode = node.arguments?.[0] || null;
    if (configNode?.type !== "ObjectExpression") return null;
    method = normalizeMethod(resolveStaticString(objectProperty(configNode, "method")?.value, bindings) || "GET");
    rawUrl = resolveStaticString(objectProperty(configNode, "url")?.value, bindings);
    dataNode = objectProperty(configNode, "data")?.value || null;
  }

  if (!isValidEndpointUrlCandidate(rawUrl)) return null;

  const baseUrl = configNode?.type === "ObjectExpression"
    ? resolveStaticString(objectProperty(configNode, "baseURL")?.value, bindings)
    : null;
  const resolvedUrl = joinUrl(baseUrl || pageUrl, rawUrl);
  const paramsNode = configNode?.type === "ObjectExpression" ? objectProperty(configNode, "params")?.value : null;
  const headersNode = configNode?.type === "ObjectExpression" ? objectProperty(configNode, "headers")?.value : null;
  const paramNames = Array.from(new Set([
    ...urlParamNames(resolvedUrl || rawUrl, hostHint),
    ...objectKeyNames(paramsNode)
  ])).sort((a, b) => a.localeCompare(b));
  const bodyInfo = bodyTraits(dataNode, bindings);
  const bodyKeys = bodyInfo.bodyKeys;
  const headerEntriesList = headerEntries(headersNode, bindings);
  const headerNames = normalizeStringList(headerEntriesList.map((entry) => entry.name));
  const endpointMeta = classifyEndpointMetadata({
    rawUrl,
    resolvedUrl,
    paramNames,
    bodyKeys,
    headerNames,
    headerEntriesList,
    uploadSignals: bodyInfo.uploadSignals
  });
  const authHints = normalizeStringList([
    ...headerNames.filter((header) => AUTH_LIKE_RE.test(header)),
    ...endpointMeta.authHints
  ]);
  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);
  const routeKey = buildRouteKey({
    url: resolvedUrl || rawUrl,
    method,
    host: hostHint
  });

  return {
    artifact: {
      id: endpointArtifactId({ sourceRef, loc, transport: "axios", method, url: resolvedUrl || rawUrl }),
      artifactType: "endpoint",
      moduleId: "sast-endpoint-artifacts",
      ruleId: "endpoint-artifact",
      transport: "axios",
      method,
      url: rawUrl,
      resolvedUrl: resolvedUrl || rawUrl,
      routeKey,
      paramNames,
      bodyKeys,
      headerNames,
      authHints,
      protocolHints: endpointMeta.protocolHints,
      discoveryTags: endpointMeta.discoveryTags,
      environmentHints: endpointMeta.environmentHints,
      storageHints: endpointMeta.storageHints,
      uploadSignals: endpointMeta.uploadSignals,
      uploadLike: endpointMeta.uploadLike,
      objectStorageLike: endpointMeta.objectStorageLike,
      internalLike: endpointMeta.internalLike,
      adminLike: ADMIN_LIKE_RE.test(resolvedUrl || rawUrl) || authHints.some((hint) => ADMIN_LIKE_RE.test(hint)),
      sourceFile: sourceRef,
      sourceLoc: loc,
      pageUrl: toNonEmptyString(pageUrl) || null
    },
    graphqlArtifacts: graphqlArtifactsFromHttpRequest({
      transport: "axios",
      method,
      rawUrl,
      resolvedUrl,
      bodyNode: dataNode,
      authHints,
      sourceRef,
      loc,
      pageUrl,
      hostHint,
      bindings
    }),
    hiddenParamArtifacts: hiddenParamArtifactsFromEndpointShape({
      routeKey,
      sourceRef,
      loc,
      pageUrl,
      queryParamNames: paramNames,
      bodyKeys,
      headerNames
    })
  };
}

function realtimeArtifactFromNew(node, { bindings, pageUrl, hostHint }) {
  const callee = node?.callee;
  const ctorName = callee?.type === "Identifier" ? callee.name : null;
  if (ctorName !== "WebSocket" && ctorName !== "EventSource") return null;
  const rawUrl = resolveStaticString(node.arguments?.[0], bindings);
  if (!isValidEndpointUrlCandidate(rawUrl)) return null;
  const resolvedUrl = joinUrl(pageUrl, rawUrl);
  const method = "GET";
  const transport = ctorName.toLowerCase();
  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);
  const finalUrl = resolvedUrl || rawUrl;
  const paramNames = urlParamNames(finalUrl, hostHint);
  const endpointMeta = classifyEndpointMetadata({
    rawUrl,
    resolvedUrl: finalUrl,
    paramNames
  });

  return {
    id: endpointArtifactId({ sourceRef, loc, transport, method, url: finalUrl }),
    artifactType: "endpoint",
    moduleId: "sast-endpoint-artifacts",
    ruleId: "endpoint-artifact",
    transport,
    method,
    url: rawUrl,
    resolvedUrl: finalUrl,
    routeKey: buildRouteKey({
      url: finalUrl,
      method,
      host: hostHint
    }),
    paramNames,
    bodyKeys: [],
    headerNames: [],
    authHints: endpointMeta.authHints,
    protocolHints: endpointMeta.protocolHints,
    discoveryTags: endpointMeta.discoveryTags,
    environmentHints: endpointMeta.environmentHints,
    storageHints: endpointMeta.storageHints,
    uploadSignals: endpointMeta.uploadSignals,
    uploadLike: endpointMeta.uploadLike,
    objectStorageLike: endpointMeta.objectStorageLike,
    internalLike: endpointMeta.internalLike,
    adminLike: ADMIN_LIKE_RE.test(finalUrl),
    sourceFile: sourceRef,
    sourceLoc: loc,
    pageUrl: toNonEmptyString(pageUrl) || null
  };
}

function collectExpressionHints(node, bindings = new Map(), out = new Set(), depth = 0) {
  if (!node || depth > 4) return out;

  const direct = normalizeSurfaceHintValue(resolveStaticString(node, bindings));
  if (direct && (FEATURE_FLAG_RE.test(direct) || ADMIN_LIKE_RE.test(direct) || DEBUG_LIKE_RE.test(direct) || AUTH_LIKE_RE.test(direct))) {
    out.add(direct);
  }

  switch (node.type) {
    case "Identifier":
      if (FEATURE_FLAG_RE.test(node.name) || ADMIN_LIKE_RE.test(node.name) || DEBUG_LIKE_RE.test(node.name) || AUTH_LIKE_RE.test(node.name)) {
        out.add(node.name);
      }
      break;
    case "Literal":
      if (typeof node.value === "string") {
        const normalizedLiteral = normalizeSurfaceHintValue(node.value);
        if (normalizedLiteral && (FEATURE_FLAG_RE.test(normalizedLiteral) || ADMIN_LIKE_RE.test(normalizedLiteral) || DEBUG_LIKE_RE.test(normalizedLiteral) || AUTH_LIKE_RE.test(normalizedLiteral))) {
          out.add(normalizedLiteral);
        }
      }
      break;
    case "MemberExpression": {
      const name = calleeName(node);
      if (name && (FEATURE_FLAG_RE.test(name) || ADMIN_LIKE_RE.test(name) || DEBUG_LIKE_RE.test(name) || AUTH_LIKE_RE.test(name))) {
        out.add(name);
      }
      collectExpressionHints(node.object, bindings, out, depth + 1);
      if (node.computed) collectExpressionHints(node.property, bindings, out, depth + 1);
      break;
    }
    case "CallExpression":
      collectExpressionHints(node.callee, bindings, out, depth + 1);
      (node.arguments || []).forEach((arg) => collectExpressionHints(arg, bindings, out, depth + 1));
      break;
    case "UnaryExpression":
    case "UpdateExpression":
      collectExpressionHints(node.argument, bindings, out, depth + 1);
      break;
    case "BinaryExpression":
    case "LogicalExpression":
      collectExpressionHints(node.left, bindings, out, depth + 1);
      collectExpressionHints(node.right, bindings, out, depth + 1);
      break;
    case "ConditionalExpression":
      collectExpressionHints(node.test, bindings, out, depth + 1);
      collectExpressionHints(node.consequent, bindings, out, depth + 1);
      collectExpressionHints(node.alternate, bindings, out, depth + 1);
      break;
    case "ObjectExpression":
      (node.properties || []).forEach((prop) => {
        if (!prop || prop.type !== "Property") return;
        const key = propertyName(prop.key);
        if (key && (FEATURE_FLAG_RE.test(key) || ADMIN_LIKE_RE.test(key) || DEBUG_LIKE_RE.test(key) || AUTH_LIKE_RE.test(key))) {
          out.add(key);
        }
        collectExpressionHints(prop.value, bindings, out, depth + 1);
      });
      break;
    case "ArrayExpression":
      (node.elements || []).forEach((element) => collectExpressionHints(element, bindings, out, depth + 1));
      break;
    default:
      break;
  }

  return out;
}

function buildSurfaceArtifacts(exprNode, node, { bindings, pageUrl, hostHint }) {
  const hintNames = normalizeStringList(Array.from(collectExpressionHints(exprNode, bindings)));
  if (!hintNames.length) return [];
  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);
  const routeKey = sourceRouteKey(pageUrl, hostHint, "*");
  const groups = [];
  const pushSurface = (surfaceType, hints) => {
    const normalizedHints = normalizeStringList(hints);
    if (!normalizedHints.length) return;
    const label = normalizedHints[0];
    groups.push({
      id: surfaceArtifactId({ sourceRef, loc, surfaceType, label }),
      bucketId: surfaceBucketId({ routeKey, surfaceType, label }),
      artifactType: "surface",
      moduleId: "sast-admin-feature-flag-discovery",
      ruleId: "surface-artifact",
      surfaceType,
      label,
      hintNames: normalizedHints,
      adminLike: normalizedHints.some((hint) => ADMIN_LIKE_RE.test(hint)),
      routeKey,
      occurrenceCount: 1,
      sourceFiles: sourceRef ? [sourceRef] : [],
      sourceFile: sourceRef,
      sourceLoc: loc,
      pageUrl: toNonEmptyString(pageUrl) || null
    });
  };

  pushSurface("feature-flag", hintNames.filter((hint) => FEATURE_FLAG_RE.test(hint)));
  pushSurface("role-gate", hintNames.filter((hint) => ADMIN_LIKE_RE.test(hint) || AUTH_LIKE_RE.test(hint)));
  pushSurface("debug-toggle", hintNames.filter((hint) => DEBUG_LIKE_RE.test(hint)));
  return groups;
}

function buildAuthFlowSurface(node, { pageUrl, hostHint, label, hints = [] } = {}) {
  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);
  const routeKey = sourceRouteKey(pageUrl, hostHint, "*");
  const hintNames = normalizeStringList(hints);
  const surfaceLabel = toNonEmptyString(label) || hintNames[0] || "auth-flow";
  return {
    id: surfaceArtifactId({ sourceRef, loc, surfaceType: "auth-flow", label: surfaceLabel }),
    bucketId: surfaceBucketId({ routeKey, surfaceType: "auth-flow", label: surfaceLabel }),
    artifactType: "surface",
    moduleId: "sast-webauthn-passkey-discovery",
    ruleId: "auth-flow-artifact",
    surfaceType: "auth-flow",
    label: surfaceLabel,
    hintNames,
    adminLike: false,
    routeKey,
    occurrenceCount: 1,
    sourceFiles: sourceRef ? [sourceRef] : [],
    sourceFile: sourceRef,
    sourceLoc: loc,
    pageUrl: toNonEmptyString(pageUrl) || null
  };
}

function authFlowArtifactsFromCall(node, { pageUrl, hostHint }) {
  const name = calleeName(node?.callee);
  if (!name) return [];
  const artifacts = [];
  if (/^(?:navigator\.)?credentials\.create$/i.test(name)) {
    artifacts.push(buildAuthFlowSurface(node, {
      pageUrl,
      hostHint,
      label: "webauthn:create",
      hints: ["webauthn", "passkey", "credentials.create"]
    }));
  } else if (/^(?:navigator\.)?credentials\.get$/i.test(name)) {
    artifacts.push(buildAuthFlowSurface(node, {
      pageUrl,
      hostHint,
      label: "webauthn:get",
      hints: ["webauthn", "passkey", "credentials.get"]
    }));
  } else if (/^PublicKeyCredential\./.test(name)) {
    artifacts.push(buildAuthFlowSurface(node, {
      pageUrl,
      hostHint,
      label: `webauthn:${name.split(".").pop() || "api"}`,
      hints: ["webauthn", "PublicKeyCredential", name]
    }));
  }
  return artifacts.filter(Boolean);
}

function classifyHiddenParamContainer(node) {
  if (node?.callee?.type !== "MemberExpression") return null;
  const prop = propertyName(node.callee.property);
  const objectNode = node.callee.object;
  const objectName = calleeName(objectNode);

  if ((prop === "getItem" || prop === "setItem") && /(?:localStorage|sessionStorage)/i.test(objectName)) {
    return "storage";
  }
  if (objectNode?.type === "NewExpression" && objectNode.callee?.type === "Identifier" && objectNode.callee.name === "URLSearchParams") {
    return "query";
  }
  if (objectNode?.type === "MemberExpression" && propertyName(objectNode.property) === "searchParams") {
    return "query";
  }
  if (/searchparams|params$/i.test(objectName)) return "query";
  if (/formdata/i.test(objectName)) return "form";
  if (/headers/i.test(objectName)) return "header";
  return null;
}

function classifyHiddenParamHint(paramName) {
  const value = String(paramName || "");
  if (SIGNED_URL_PARAM_RE.test(value)) return "signature";
  if (FEATURE_FLAG_RE.test(value)) return "feature-flag";
  if (/redirect|return|next|dest|continue|callback|target|url/i.test(value)) return "navigation";
  if (OAUTH_PARAM_RE.test(value) || SAML_PARAM_RE.test(value)) return "auth";
  if (/filename|contenttype|content_type|policy|key|bucket|upload/i.test(value)) return "upload";
  if (/admin|role|permission|scope|impersonate|token|jwt|csrf/i.test(value)) return "auth";
  if (/debug|preview|beta|canary|experiment|toggle|mode|view|template/i.test(value)) return "debug";
  return "generic";
}

function hiddenParamArtifactsFromEndpointShape({
  routeKey,
  sourceRef,
  loc,
  pageUrl,
  queryParamNames = [],
  bodyKeys = [],
  headerNames = []
} = {}) {
  const entries = [];
  const addEntry = (container, paramName) => {
    if (!paramName) return;
    if (!(HIDDEN_PARAM_RE.test(paramName) || OAUTH_PARAM_RE.test(paramName) || SAML_PARAM_RE.test(paramName) || SIGNED_URL_PARAM_RE.test(paramName) || UPLOAD_LIKE_RE.test(paramName))) {
      return;
    }
    const hintType = classifyHiddenParamHint(paramName);
    entries.push({
      id: hiddenParamArtifactId({ sourceRef, loc, container, paramName }),
      bucketId: hiddenParamBucketId({ routeKey, container, paramName }),
      artifactType: "hidden_param",
      moduleId: "sast-hidden-param-discovery",
      ruleId: "hidden-param-artifact",
      paramName,
      container,
      action: "write",
      actions: ["write"],
      hintType,
      hintTypes: [hintType],
      adminLike: ADMIN_LIKE_RE.test(paramName) || AUTH_LIKE_RE.test(paramName),
      routeKey,
      occurrenceCount: 1,
      sourceFiles: sourceRef ? [sourceRef] : [],
      sourceFile: sourceRef,
      sourceLoc: loc,
      pageUrl: toNonEmptyString(pageUrl) || null
    });
  };

  normalizeStringList(queryParamNames).forEach((paramName) => addEntry("query", paramName));
  normalizeStringList(bodyKeys).forEach((paramName) => addEntry("body", paramName));
  normalizeStringList(headerNames).forEach((paramName) => addEntry("header", paramName));
  return entries;
}

function hiddenParamArtifactFromCall(node, { bindings, pageUrl, hostHint }) {
  if (node?.callee?.type !== "MemberExpression") return null;
  const prop = propertyName(node.callee.property);
  if (!["get", "getAll", "has", "set", "append", "getItem", "setItem"].includes(prop)) return null;
  const paramName = resolveStaticString(node.arguments?.[0], bindings);
  if (!paramName || !HIDDEN_PARAM_RE.test(paramName)) return null;
  const container = classifyHiddenParamContainer(node);
  if (!container) return null;

  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);
  const hintType = classifyHiddenParamHint(paramName);
  const action = prop === "has" ? "check" : ((prop === "set" || prop === "append" || prop === "setItem") ? "write" : "read");
  const routeKey = sourceRouteKey(pageUrl, hostHint, "GET");
  return {
    id: hiddenParamArtifactId({ sourceRef, loc, container, paramName }),
    bucketId: hiddenParamBucketId({ routeKey, container, paramName }),
    artifactType: "hidden_param",
    moduleId: "sast-hidden-param-discovery",
    ruleId: "hidden-param-artifact",
    paramName,
    container,
    action,
    actions: [action],
    hintType,
    hintTypes: [hintType],
    adminLike: ADMIN_LIKE_RE.test(paramName) || AUTH_LIKE_RE.test(paramName),
    routeKey,
    occurrenceCount: 1,
    sourceFiles: sourceRef ? [sourceRef] : [],
    sourceFile: sourceRef,
    sourceLoc: loc,
    pageUrl: toNonEmptyString(pageUrl) || null
  };
}

function buildGadgetArtifact(node, {
  pageUrl,
  hostHint,
  gadgetType,
  label
} = {}) {
  const sourceRef = resolveSourceRef(node?.sourceFile || null, pageUrl);
  const loc = normalizeLocation(node.loc);
  const routeKey = sourceRouteKey(pageUrl, hostHint, "*");
  return {
    id: gadgetArtifactId({ sourceRef, loc, gadgetType, label }),
    bucketId: gadgetBucketId({ routeKey, gadgetType, label }),
    artifactType: "gadget",
    moduleId: "sast-gadget-path-hints",
    ruleId: "gadget-artifact",
    gadgetType,
    label,
    routeKey,
    occurrenceCount: 1,
    sourceFiles: sourceRef ? [sourceRef] : [],
    sourceFile: sourceRef,
    sourceLoc: loc,
    pageUrl: toNonEmptyString(pageUrl) || null
  };
}

function gadgetArtifactsFromCall(node, { bindings, pageUrl, hostHint }) {
  const artifacts = [];
  const name = calleeName(node.callee);
  const prop = node?.callee?.type === "MemberExpression" ? propertyName(node.callee.property) : propertyName(node.callee);
  const firstArg = resolveStaticString(node.arguments?.[0], bindings);

  if (prop === "addEventListener" && firstArg === "message") {
    artifacts.push(buildGadgetArtifact(node, {
      pageUrl,
      hostHint,
      gadgetType: "message-listener",
      label: 'addEventListener("message")'
    }));
  }

  if (prop === "postMessage") {
    artifacts.push(buildGadgetArtifact(node, {
      pageUrl,
      hostHint,
      gadgetType: "postmessage-emitter",
      label: "postMessage"
    }));
  }

  if (DOM_HTML_CALLS.has(prop)) {
    artifacts.push(buildGadgetArtifact(node, {
      pageUrl,
      hostHint,
      gadgetType: "dom-html-sink",
      label: prop || name
    }));
  }

  if (prop === "setPrototypeOf" && /^Object(?:\.setPrototypeOf)?$/i.test(name)) {
    artifacts.push(buildGadgetArtifact(node, {
      pageUrl,
      hostHint,
      gadgetType: "prototype-mutation",
      label: name || "Object.setPrototypeOf"
    }));
  }

  if (prop === "assign" && name === "Object.assign") {
    const targetArg = calleeName(node.arguments?.[0]);
    if (/Object\.prototype/i.test(targetArg)) {
      artifacts.push(buildGadgetArtifact(node, {
        pageUrl,
        hostHint,
        gadgetType: "prototype-mutation",
        label: "Object.assign(Object.prototype, ...)"
      }));
    }
  }

  if (CODE_EXEC_CALLS.has(prop || name)) {
    artifacts.push(buildGadgetArtifact(node, {
      pageUrl,
      hostHint,
      gadgetType: "code-exec-sink",
      label: prop || name
    }));
  }

  return artifacts.filter(Boolean);
}

function gadgetArtifactsFromAssignment(node, { pageUrl, hostHint }) {
  if (node?.left?.type !== "MemberExpression") return [];
  const prop = propertyName(node.left.property);
  const artifacts = [];
  if (DOM_HTML_ASSIGN_PROPS.has(prop)) {
    artifacts.push(buildGadgetArtifact(node, {
      pageUrl,
      hostHint,
      gadgetType: "dom-html-sink",
      label: prop
    }));
  }
  if (prop === "__proto__" || prop === "prototype") {
    artifacts.push(buildGadgetArtifact(node, {
      pageUrl,
      hostHint,
      gadgetType: "prototype-mutation",
      label: prop
    }));
  }
  return artifacts.filter(Boolean);
}

function dedupeArtifacts(list = []) {
  const seen = new Set();
  return list.filter((entry) => {
    const id = toNonEmptyString(entry?.id);
    if (!id || seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

function aggregateHiddenParamArtifacts(list = []) {
  const map = new Map();
  const push = (entry) => {
    if (!entry || typeof entry !== "object") return;
    const routeKey = toNonEmptyString(entry.routeKey) || "unknown";
    const container = toNonEmptyString(entry.container) || "param";
    const paramName = toNonEmptyString(entry.paramName) || "unknown";
    const bucketId = toNonEmptyString(entry.bucketId) || hiddenParamBucketId({ routeKey, container, paramName });
    const occurrenceCount = Number.isFinite(Number(entry.occurrenceCount)) ? Number(entry.occurrenceCount) : 1;
    const actions = normalizeStringList([
      ...(Array.isArray(entry.actions) ? entry.actions : []),
      entry.action
    ]);
    const hintTypes = normalizeStringList([
      ...(Array.isArray(entry.hintTypes) ? entry.hintTypes : []),
      entry.hintType
    ]);
    const sourceFiles = normalizeStringList([
      ...(Array.isArray(entry.sourceFiles) ? entry.sourceFiles : []),
      entry.sourceFile
    ]);

    if (!map.has(bucketId)) {
      map.set(bucketId, Object.assign({}, entry, {
        id: bucketId,
        routeKey,
        container,
        paramName,
        action: actions[0] || entry.action || null,
        actions,
        hintType: hintTypes[0] || entry.hintType || null,
        hintTypes,
        occurrenceCount,
        sourceFiles
      }));
      return;
    }

    const existing = map.get(bucketId);
    map.set(bucketId, Object.assign({}, existing, {
      adminLike: Boolean(existing.adminLike || entry.adminLike),
      action: existing.action || entry.action || null,
      actions: normalizeStringList([...(existing.actions || []), ...actions]),
      hintType: existing.hintType || entry.hintType || null,
      hintTypes: normalizeStringList([...(existing.hintTypes || []), ...hintTypes]),
      occurrenceCount: Number(existing.occurrenceCount || 0) + occurrenceCount,
      sourceFiles: normalizeStringList([...(existing.sourceFiles || []), ...sourceFiles]),
      sourceFile: existing.sourceFile || entry.sourceFile || null,
      sourceLoc: existing.sourceLoc || entry.sourceLoc || null,
      pageUrl: existing.pageUrl || entry.pageUrl || null
    }));
  };

  (Array.isArray(list) ? list : []).forEach(push);
  return Array.from(map.values());
}

function aggregateGadgetArtifacts(list = []) {
  const map = new Map();
  const push = (entry) => {
    if (!entry || typeof entry !== "object") return;
    const routeKey = toNonEmptyString(entry.routeKey) || "unknown";
    const gadgetType = toNonEmptyString(entry.gadgetType) || "gadget";
    const label = toNonEmptyString(entry.label) || gadgetType;
    const bucketId = toNonEmptyString(entry.bucketId) || gadgetBucketId({ routeKey, gadgetType, label });
    const occurrenceCount = Number.isFinite(Number(entry.occurrenceCount)) ? Number(entry.occurrenceCount) : 1;
    const sourceFiles = normalizeStringList([
      ...(Array.isArray(entry.sourceFiles) ? entry.sourceFiles : []),
      entry.sourceFile
    ]);

    if (!map.has(bucketId)) {
      map.set(bucketId, Object.assign({}, entry, {
        id: bucketId,
        routeKey,
        gadgetType,
        label,
        occurrenceCount,
        sourceFiles
      }));
      return;
    }

    const existing = map.get(bucketId);
    map.set(bucketId, Object.assign({}, existing, {
      occurrenceCount: Number(existing.occurrenceCount || 0) + occurrenceCount,
      sourceFiles: normalizeStringList([...(existing.sourceFiles || []), ...sourceFiles]),
      sourceFile: existing.sourceFile || entry.sourceFile || null,
      sourceLoc: existing.sourceLoc || entry.sourceLoc || null,
      pageUrl: existing.pageUrl || entry.pageUrl || null
    }));
  };

  (Array.isArray(list) ? list : []).forEach(push);
  return Array.from(map.values());
}

function aggregateSurfaceArtifacts(list = []) {
  const map = new Map();
  const push = (entry) => {
    if (!entry || typeof entry !== "object") return;
    const routeKey = toNonEmptyString(entry.routeKey) || "unknown";
    const surfaceType = toNonEmptyString(entry.surfaceType) || "surface";
    const label = toNonEmptyString(entry.label) || surfaceType;
    const bucketId = toNonEmptyString(entry.bucketId) || surfaceBucketId({ routeKey, surfaceType, label });
    const occurrenceCount = Number.isFinite(Number(entry.occurrenceCount)) ? Number(entry.occurrenceCount) : 1;
    const hintNames = normalizeStringList(entry.hintNames);
    const protocolHints = normalizeStringList(entry.protocolHints);
    const sourceFiles = normalizeStringList([
      ...(Array.isArray(entry.sourceFiles) ? entry.sourceFiles : []),
      entry.sourceFile
    ]);

    if (!map.has(bucketId)) {
      map.set(bucketId, Object.assign({}, entry, {
        id: bucketId,
        bucketId,
        routeKey,
        surfaceType,
        label,
        hintNames,
        protocolHints,
        occurrenceCount,
        sourceFiles
      }));
      return;
    }

    const existing = map.get(bucketId);
    map.set(bucketId, Object.assign({}, existing, {
      adminLike: Boolean(existing.adminLike || entry.adminLike),
      hintNames: normalizeStringList([...(existing.hintNames || []), ...hintNames]),
      protocolHints: normalizeStringList([...(existing.protocolHints || []), ...protocolHints]),
      occurrenceCount: Number(existing.occurrenceCount || 0) + occurrenceCount,
      sourceFiles: normalizeStringList([...(existing.sourceFiles || []), ...sourceFiles]),
      sourceFile: existing.sourceFile || entry.sourceFile || null,
      sourceLoc: existing.sourceLoc || entry.sourceLoc || null,
      pageUrl: existing.pageUrl || entry.pageUrl || null
    }));
  };

  (Array.isArray(list) ? list : []).forEach(push);
  return Array.from(map.values());
}

export function extractSastCodeArtifacts(masterAST, opts = {}) {
  if (!masterAST || typeof masterAST !== "object") {
    return {
      sast: {
        version: 2,
        routes: [],
        endpoints: [],
        graphql: [],
        surfaces: [],
        hiddenParams: [],
        gadgets: []
      }
    };
  }

  const pageUrl = toNonEmptyString(opts.pageUrl) || null;
  const hostHint = toNonEmptyString(opts.hostHint) || null;
  const bindings = opts.bindings instanceof Map ? opts.bindings : buildStaticStringBindings(masterAST);
  const routes = [];
  const endpoints = [];
  const graphql = [];
  const surfaces = [];
  const hiddenParams = [];
  const gadgets = [];

  ancestor(masterAST, {
    ObjectExpression(node, _state, ancestors) {
      const artifact = buildRouteArtifact(node, ancestors, { bindings, pageUrl, hostHint });
      if (artifact) routes.push(artifact);
    },
    IfStatement(node) {
      surfaces.push(...buildSurfaceArtifacts(node.test, node, { bindings, pageUrl, hostHint }));
    },
    ConditionalExpression(node) {
      surfaces.push(...buildSurfaceArtifacts(node.test, node, { bindings, pageUrl, hostHint }));
    },
    CallExpression(node) {
      const fetchResult = fetchArtifactFromCall(node, { bindings, pageUrl, hostHint });
      if (fetchResult?.artifact) endpoints.push(fetchResult.artifact);
      if (Array.isArray(fetchResult?.graphqlArtifacts)) graphql.push(...fetchResult.graphqlArtifacts);
      if (Array.isArray(fetchResult?.hiddenParamArtifacts)) hiddenParams.push(...fetchResult.hiddenParamArtifacts);

      const xhrArtifact = xhrArtifactFromCall(node, { bindings, pageUrl, hostHint });
      if (xhrArtifact) {
        endpoints.push(xhrArtifact);
        hiddenParams.push(...hiddenParamArtifactsFromEndpointShape({
          routeKey: xhrArtifact.routeKey,
          sourceRef: xhrArtifact.sourceFile,
          loc: xhrArtifact.sourceLoc,
          pageUrl,
          queryParamNames: xhrArtifact.paramNames,
          bodyKeys: xhrArtifact.bodyKeys,
          headerNames: xhrArtifact.headerNames
        }));
      }

      const axiosResult = axiosArtifactFromCall(node, { bindings, pageUrl, hostHint });
      if (axiosResult?.artifact) endpoints.push(axiosResult.artifact);
      if (Array.isArray(axiosResult?.graphqlArtifacts)) graphql.push(...axiosResult.graphqlArtifacts);
      if (Array.isArray(axiosResult?.hiddenParamArtifacts)) hiddenParams.push(...axiosResult.hiddenParamArtifacts);

      graphql.push(...graphqlArtifactsFromClientCall(node, { bindings, pageUrl, hostHint }));

      const hiddenParamArtifact = hiddenParamArtifactFromCall(node, { bindings, pageUrl, hostHint });
      if (hiddenParamArtifact) hiddenParams.push(hiddenParamArtifact);

      gadgets.push(...gadgetArtifactsFromCall(node, { bindings, pageUrl, hostHint }));
      surfaces.push(...authFlowArtifactsFromCall(node, { pageUrl, hostHint }));
    },
    NewExpression(node) {
      const artifact = realtimeArtifactFromNew(node, { bindings, pageUrl, hostHint });
      if (artifact) {
        endpoints.push(artifact);
        hiddenParams.push(...hiddenParamArtifactsFromEndpointShape({
          routeKey: artifact.routeKey,
          sourceRef: artifact.sourceFile,
          loc: artifact.sourceLoc,
          pageUrl,
          queryParamNames: artifact.paramNames,
          bodyKeys: artifact.bodyKeys,
          headerNames: artifact.headerNames
        }));
      }
    },
    AssignmentExpression(node) {
      gadgets.push(...gadgetArtifactsFromAssignment(node, { pageUrl, hostHint }));
    }
  });

  return {
    sast: {
      version: 2,
      routes: dedupeArtifacts(routes),
      endpoints: dedupeArtifacts(endpoints),
      graphql: dedupeArtifacts(graphql),
      surfaces: aggregateSurfaceArtifacts(surfaces),
      hiddenParams: aggregateHiddenParamArtifacts(hiddenParams),
      gadgets: aggregateGadgetArtifacts(gadgets)
    }
  };
}

export default extractSastCodeArtifacts;
