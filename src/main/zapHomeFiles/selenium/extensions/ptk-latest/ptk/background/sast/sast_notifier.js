/* Author: Denis Podgurskii */
import { applyRouteToFinding } from "./spa_utils.js";
import {
  applyStructuredSastProgressEvent,
  createSastProgressState,
  isStructuredSastEvent
} from "./sast_progress.js";

export class SastNotifier {
  constructor({
    browserApi = browser,
    getScanResult = () => ({}),
    getIsScanRunning = () => false,
    setIsScanRunning = () => {},
    getProgressState = () => createSastProgressState(),
    setProgressState = () => {},
    buildProgressSnapshot = () => ({}),
    countArtifacts = () => 0,
    mergeArtifacts = () => {},
    addUnifiedFinding = () => null,
    updateScanResult = () => {},
    rebuildGroupsFromFindings = () => {},
    flushPersist = () => {},
    startHeartbeat = () => {},
    stopHeartbeat = () => {}
  } = {}) {
    this.browserApi = browserApi;
    this.getScanResult = getScanResult;
    this.getIsScanRunning = getIsScanRunning;
    this.setIsScanRunning = setIsScanRunning;
    this.getProgressState = getProgressState;
    this.setProgressState = setProgressState;
    this.buildProgressSnapshot = buildProgressSnapshot;
    this.countArtifacts = countArtifacts;
    this.mergeArtifacts = mergeArtifacts;
    this.addUnifiedFinding = addUnifiedFinding;
    this.updateScanResult = updateScanResult;
    this.rebuildGroupsFromFindings = rebuildGroupsFromFindings;
    this.flushPersist = flushPersist;
    this.startHeartbeat = startHeartbeat;
    this.stopHeartbeat = stopHeartbeat;
  }

  send(message) {
    this.browserApi.runtime.sendMessage(message).catch(() => { });
  }

  isStructuredEvent(type) {
    return isStructuredSastEvent(type);
  }

  handleProgress(data) {
    const scanResult = this.getScanResult();
    if (data?.file && !data.file.startsWith("about:") && !scanResult.files.includes(data.file)) {
      scanResult.files.push(data.file);
    }

    this.send({
      channel: "ptk_background2popup_sast",
      type: "progress",
      info: data
    });
  }

  handleScanResultFromWorker(file, findings = [], artifacts = null, { canonicalizeFileId } = {}) {
    const scanResult = this.getScanResult();
    const normalized = Array.isArray(findings) ? findings : [];
    const pageUrl = file || "";
    const pageCanon = typeof canonicalizeFileId === "function" ? canonicalizeFileId(pageUrl) : pageUrl;
    const artifactCount = this.countArtifacts(artifacts?.sast);
    const hadArtifacts = artifactCount > 0;

    if (artifacts) {
      this.mergeArtifacts(artifacts, { pageUrl, pageCanon });
    }
    if (!normalized.length) {
      if (hadArtifacts) {
        this.updateScanResult();
      }
      return;
    }

    const newUnifiedFindings = [];
    const upsertedFindings = [];
    normalized.forEach((finding, index) => {
      finding.pageUrl = pageUrl;
      finding.pageCanon = pageCanon;
      applyRouteToFinding(finding, pageUrl);
      const upserted = this.addUnifiedFinding(finding, index);
      if (!upserted?.finding) return;
      upsertedFindings.push(upserted.finding);
      if (upserted.isNew) {
        newUnifiedFindings.push(upserted.finding);
      }
    });

    this.updateScanResult();
    if (newUnifiedFindings.length) {
      this.send({
        channel: "ptk_background2popup_sast",
        type: "findings_delta",
        findings: newUnifiedFindings,
        stats: scanResult.stats || {},
        files: pageUrl ? [pageUrl] : [],
        isScanRunning: this.getIsScanRunning(),
        progress: this.buildProgressSnapshot()
      });
    }
  }

  handleStructuredEvent(type, payload) {
    const scanResult = this.getScanResult();
    const data = payload?.payload || payload || {};
    const file = data.file;

    if (type === "scan:start") {
      this.setIsScanRunning(true);
      this.setProgressState(applyStructuredSastProgressEvent(createSastProgressState(), type, data));
      this.startHeartbeat();
    } else {
      this.setProgressState(applyStructuredSastProgressEvent(this.getProgressState(), type, data));
    }

    if (type === "scan:summary" || type === "collection:summary") {
      this.rebuildGroupsFromFindings();
      this.updateScanResult();
      this.flushPersist();
      this.send({
        channel: "ptk_background2popup_sast",
        type,
        payload: Object.assign({}, data, {
          isScanRunning: this.getIsScanRunning(),
          progress: this.buildProgressSnapshot()
        })
      });
      return;
    }

    if (type === "file:start") {
      if (file && !file.startsWith("about:") && !scanResult.files.includes(file)) {
        scanResult.files.push(file);
        this.updateScanResult();
      }
      this.send({
        channel: "ptk_background2popup_sast",
        type,
        payload: Object.assign({}, data, { progress: this.buildProgressSnapshot() })
      });
      return;
    }

    if (
      type === "file:end" ||
      type === "scan:start" ||
      type === "collection:start" ||
      type === "collection:payload" ||
      type === "collection:analysis:start" ||
      type === "module:start" ||
      type === "module:end"
    ) {
      this.send({
        channel: "ptk_background2popup_sast",
        type,
        payload: Object.assign({}, data, { progress: this.buildProgressSnapshot() })
      });
      return;
    }

    if (type === "collection:error") {
      this.send({
        channel: "ptk_background2popup_sast",
        type,
        payload: Object.assign({}, data, { progress: this.buildProgressSnapshot() })
      });
      return;
    }

    if (type === "scan:error") {
      this.setIsScanRunning(false);
      this.stopHeartbeat();
      this.send({
        channel: "ptk_background2popup_sast",
        type,
        payload: Object.assign({}, data, { progress: this.buildProgressSnapshot() })
      });
    }
  }
}

export default SastNotifier;
