/* Structured SAST scan event bus: bridges engine events to popup messages */

export class SastScanBus {
  /**
   * @param {object} sastInstance - instance of ptk_sast (sast.js)
   * @param {object} engine - instance of sastEngine
   */
  constructor(sastInstance, engine) {
    this.sast = sastInstance;
    this.engine = engine;
  }

  attach() {
    if (!this.engine?.events) return;
    const events = this.engine.events;
    events.subscribe("scan:start", (e) => this.onScanStart(e));
    events.subscribe("collection:start", (e) => this.onCollectionStart(e));
    events.subscribe("collection:payload", (e) => this.onCollectionPayload(e));
    events.subscribe("collection:analysis:start", (e) => this.onCollectionAnalysisStart(e));
    events.subscribe("file:start", (e) => this.onFileStart(e));
    events.subscribe("file:end", (e) => this.onFileEnd(e));
    events.subscribe("module:start", (e) => this.onModuleStart(e));
    events.subscribe("module:end", (e) => this.onModuleEnd(e));
    events.subscribe("collection:summary", (e) => this.onCollectionSummary(e));
    events.subscribe("collection:error", (e) => this.onCollectionError(e));
    events.subscribe("scan:summary", (e) => this.onScanSummary(e));
    events.subscribe("scan:error", (e) => this.onScanError(e));
  }

  cloneScanResult() {
    return JSON.parse(JSON.stringify(this.sast.scanResult));
  }

  dispatchStructuredEvent(type, payload, { includeScanResult = false } = {}) {
    if (this.sast?.notifier?.handleStructuredEvent) {
      this.sast.notifier.handleStructuredEvent(type, { payload });
      return;
    }
    const progress = this.sast?._buildSastProgressSnapshot?.() || payload?.progress || null;
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type,
      payload: Object.assign({}, payload || {}, progress ? { progress } : {}),
      ...(includeScanResult ? { scanResult: this.cloneScanResult() } : {})
    }).catch(() => { });
  }

  onScanStart(e) {
    if (this.sast?.sessionCoordinator?.firstCollectionStarted) return;
    this.dispatchStructuredEvent("scan:start", e);
  }

  sendCollectionEvent(type, e) {
    this.dispatchStructuredEvent(type, e);
  }

  onCollectionStart(e) {
    this.sendCollectionEvent("collection:start", e);
  }

  onCollectionPayload(e) {
    this.sendCollectionEvent("collection:payload", e);
  }

  onCollectionAnalysisStart(e) {
    this.sendCollectionEvent("collection:analysis:start", e);
  }

  onFileStart(e) {
    const file = e?.file;
    if (
      file &&
      !file.startsWith("about:") &&
      !/^inline[-‐]/i.test(file) &&
      !this.sast.scanResult.files.includes(file)
    ) {
      this.sast.scanResult.files.push(file);
    }

    this.dispatchStructuredEvent("file:start", e);
  }

  onFileEnd(e) {
    this.dispatchStructuredEvent("file:end", e);
  }

  onModuleStart(e) {
    this.dispatchStructuredEvent("module:start", e);
  }

  onModuleEnd(e) {
    this.dispatchStructuredEvent("module:end", e);
  }

  onScanSummary(e) {
    this.dispatchStructuredEvent("scan:summary", e, { includeScanResult: true });
  }

  onCollectionSummary(e) {
    this.dispatchStructuredEvent("collection:summary", e, { includeScanResult: true });
  }

  onCollectionError(e) {
    this.sendCollectionEvent("collection:error", e);
  }

  onScanError(e) {
    this.sast.isScanRunning = false;
    this.dispatchStructuredEvent("scan:error", e);
  }
}
