/* Author: Denis Podgurskii */
import buildExportScanResult from "../export/buildExportScanResult.js";
import { compressScanPayload } from "../export/compressScanPayload.js";
import { parseDownloadedScanPayload } from "../export/parseDownloadedScanPayload.js";
import {
  buildStoredCredentialPortalUrl,
  initializePortalRuntimeConfig
} from "../../common/portalConfig.js";

export class SastPortalClient {
  constructor({ getProfile } = {}) {
    this.getProfile = typeof getProfile === "function" ? getProfile : (() => ({}));
  }

  buildPortalUrl(endpoint, profile = null) {
    return buildStoredCredentialPortalUrl(endpoint);
  }

  async getProjects() {
    await initializePortalRuntimeConfig();
    const profile = this.getProfile() || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const url = this.buildPortalUrl("/projects", profile);
    if (!url) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    return fetch(url, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (httpResponse.ok) {
          return { success: true, json };
        }
        return { success: false, json: json || { message: "Unable to load projects" } };
      })
      .catch(e => ({ success: false, json: { message: "Error while loading projects: " + e.message } }));
  }

  async saveScan({ scanResult, projectId = null } = {}) {
    await initializePortalRuntimeConfig();
    const profile = this.getProfile() || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const findingCount = Array.isArray(scanResult?.findings) ? scanResult.findings.length : 0;
    if (!findingCount) {
      return { success: false, json: { message: "Scan result is empty" } };
    }
    const url = this.buildPortalUrl("/scans", profile);
    if (!url) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    const payload = buildExportScanResult(scanResult?.scanId, {
      target: "portal",
      scanResult
    });
    if (!payload) {
      return { success: false, json: { message: "Scan result is empty" } };
    }
    if (projectId) {
      payload.projectId = projectId;
    }
    let compressed;
    try {
      compressed = await compressScanPayload(payload);
    } catch (err) {
      return {
        success: false,
        json: { message: "Unable to compress scan payload: " + (err?.message || "compression_failed") }
      };
    }
    return fetch(url, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json',
        'Content-Type': compressed.contentType,
        'X-PTK-Compression': compressed.compression
      },
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-cache',
      body: compressed.body
    })
      .then(async (httpResponse) => {
        if (httpResponse.status === 201) {
          return { success: true };
        }
        const json = await httpResponse.json().catch(() => ({ message: httpResponse.statusText }));
        return { success: false, json };
      })
      .catch(e => ({ success: false, json: { message: "Error while saving report: " + e.message } }));
  }

  async downloadScans({ projectId = null, engine = "sast" } = {}) {
    await initializePortalRuntimeConfig();
    const profile = this.getProfile() || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    const baseUrl = this.buildPortalUrl("/scans", profile);
    if (!baseUrl) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    let requestUrl = baseUrl;
    try {
      const url = new URL(baseUrl);
      if (projectId) {
        url.searchParams.set('projectId', projectId);
      }
      if (engine) {
        url.searchParams.set('engine', engine);
      }
      requestUrl = url.toString();
    } catch (_) {
      return { success: false, json: { message: "Invalid scans endpoint." } };
    }
    return fetch(requestUrl, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/json'
      },
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        const json = await httpResponse.json().catch(() => null);
        if (httpResponse.ok) {
          return { success: true, json };
        }
        return { success: false, json: json || { message: "Unable to load scans" } };
      })
      .catch(e => ({ success: false, json: { message: "Error while loading scans: " + e.message } }));
  }

  async downloadScanById({ scanId } = {}) {
    await initializePortalRuntimeConfig();
    const profile = this.getProfile() || {};
    const apiKey = profile?.api_key;
    if (!apiKey) {
      return { success: false, json: { message: "No API key found" } };
    }
    if (!scanId) {
      return { success: false, json: { message: "Scan identifier is required." } };
    }
    const baseUrl = this.buildPortalUrl("/scans", profile);
    if (!baseUrl) {
      return { success: false, json: { message: "Portal endpoint is not configured." } };
    }
    const normalizedBase = baseUrl.replace(/\/+$/, "");
    const downloadUrl = `${normalizedBase}/${encodeURIComponent(scanId)}/download`;
    return fetch(downloadUrl, {
      headers: {
        Authorization: 'Bearer ' + apiKey,
        Accept: 'application/gzip, application/x-gzip'
      },
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-cache'
    })
      .then(async (httpResponse) => {
        if (!httpResponse.ok) {
          const json = await httpResponse.json().catch(() => null);
          return { success: false, json: json || { message: "Unable to download scan" } };
        }
        const parsed = await parseDownloadedScanPayload(httpResponse);
        if (!parsed?.ok || !parsed?.json) {
          return { success: false, json: { message: "Downloaded scan payload is invalid JSON." } };
        }
        return parsed.json;
      })
      .catch(e => ({ success: false, json: { message: "Error while downloading scan: " + e.message } }));
  }

}

export default SastPortalClient;
