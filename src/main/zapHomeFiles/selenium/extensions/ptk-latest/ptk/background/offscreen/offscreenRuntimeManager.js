const OFFSCREEN_URL = "ptk/offscreen/runtime_offscreen.html"

export class OffscreenRuntimeManager {
  constructor({ chromeApi = globalThis.chrome } = {}) {
    this.chromeApi = chromeApi
    this.ensurePromise = null
  }

  async hasRuntimeDocument() {
    const runtime = this.chromeApi?.runtime
    if (runtime?.getContexts) {
      const url = runtime.getURL(OFFSCREEN_URL)
      const contexts = await runtime.getContexts({
        contextTypes: ["OFFSCREEN_DOCUMENT"],
        documentUrls: [url]
      })
      return Array.isArray(contexts) && contexts.length > 0
    }
    return await this.chromeApi?.offscreen?.hasDocument?.() === true
  }

  async ensureDocument() {
    if (!this.chromeApi?.offscreen?.createDocument) return false
    if (!this.ensurePromise) {
      this.ensurePromise = (async () => {
        if (await this.hasRuntimeDocument()) return true
        try {
          await this.chromeApi.offscreen.createDocument({
            url: OFFSCREEN_URL,
            reasons: ["WORKERS"],
            justification: "Run PTK analysis workers independently of the MV3 service worker"
          })
        } catch (error) {
          // Another caller or replacement worker may have won the one-document race.
          if (!await this.hasRuntimeDocument()) throw error
        }
        return true
      })().finally(() => {
        // Serialize creation, but re-check the real context on later calls so an
        // offscreen document lost by the browser can be recreated.
        this.ensurePromise = null
      })
    }
    return this.ensurePromise
  }
}

export default OffscreenRuntimeManager
