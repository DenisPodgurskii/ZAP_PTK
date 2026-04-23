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
    events.subscribe("file:start", (e) => this.onFileStart(e));
    events.subscribe("file:end", (e) => this.onFileEnd(e));
    events.subscribe("module:start", (e) => this.onModuleStart(e));
    events.subscribe("module:end", (e) => this.onModuleEnd(e));
    events.subscribe("scan:summary", (e) => this.onScanSummary(e));
    events.subscribe("scan:error", (e) => this.onScanError(e));
  }

  cloneScanResult() {
    return JSON.parse(JSON.stringify(this.sast.scanResult));
  }

  onScanStart(e) {
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "scan:start",
      payload: e
    }).catch(() => { });
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

    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "file:start",
      payload: e
    }).catch(() => { });
  }

  onFileEnd(e) {
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "file:end",
      payload: e
    }).catch(() => { });
  }

  onModuleStart(e) {
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "module:start",
      payload: e
    }).catch(() => { });
  }

  onModuleEnd(e) {
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "module:end",
      payload: e
    }).catch(() => { });
  }

  onScanSummary(e) {
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "scan:summary",
      payload: e,
      scanResult: this.cloneScanResult()
    }).catch(() => { });
  }

  onScanError(e) {
    this.sast.isScanRunning = false;
    browser.runtime.sendMessage({
      channel: "ptk_background2popup_sast",
      type: "scan:error",
      payload: e
    }).catch(() => { });
  }
}
