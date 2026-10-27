import { DAST_RUNTIME_MESSAGE } from "../background/dast/runtime/protocol.js"
import { sanitizeOneTimeDastProgressMessage } from "../background/dast/runtime/oneTimeDisplay.js"

const runtime = globalThis.chrome?.runtime || globalThis.browser?.runtime || null
const workerUrl = runtime?.getURL("ptk/background/sast/sast_worker.js")
let sastWorker = null
const sastOwners = new Set()
function ensureSastWorker() {
  if (!sastWorker && workerUrl) {
    const instance = new Worker(workerUrl, { type: 'module' })
    sastWorker = instance
    const relay = data => {
      if (sastWorker === instance) runtime?.sendMessage({ channel: 'ptk_offscreen2background_sast', ...data })
    }
    instance.onmessage = event => relay(event.data || {})
    instance.onerror = error => relay({ type: 'error', error: error?.message || String(error) })
    instance.onmessageerror = error => relay({ type: 'error', error: error?.message || 'sast_worker_message_error' })
  }
  return sastWorker
}
ensureSastWorker()
const dastWorkerUrl = runtime?.getURL("ptk/offscreen/dast_runtime_worker.js")
const dastWorker = dastWorkerUrl ? new Worker(dastWorkerUrl, { type: "module" }) : null
const dastPending = new Map()
const privilegedByController = new Map()
const oneTimeDisplayOwners = new Map()
let activeDastController = null
let activeDastControllerNonce = null

function isTrustedDastController(port) {
  return port?.name === "ptk_dast_runtime_v1"
    && port?.sender?.id === runtime?.id
    && !port?.sender?.tab
}

runtime?.onConnect?.addListener(port => {
  if (!isTrustedDastController(port) || !dastWorker) {
    port?.disconnect?.()
    return
  }
  let controllerNonce = null
  port.onMessage.addListener(message => {
    if (message?.type === "controller_hello" && typeof message.controllerNonce === "string" && message.controllerNonce) {
      if (activeDastController && activeDastController !== port) activeDastController.disconnect?.()
      activeDastController = port
      activeDastControllerNonce = message.controllerNonce
      dastWorker.postMessage({ type: "controller_available" })
      controllerNonce = message.controllerNonce
      port.postMessage({ requestId: message.requestId, controllerNonce, response: { ok: true, controllerNonce } })
      return
    }
    if (!controllerNonce || message?.controllerNonce !== controllerNonce || message?.type !== "runtime_request") return
    const operationId = message.message?.type === DAST_RUNTIME_MESSAGE.ONE_TIME_SCAN
      ? String(message.message?.payload?.operationId || "")
      : ""
    dastPending.set(message.requestId, { port, controllerNonce, operationId })
    if (operationId) oneTimeDisplayOwners.set(operationId, { port, controllerNonce })
    dastWorker.postMessage({ requestId: message.requestId, message: message.message })
  })
  port.onMessage.addListener(message => {
    if (!controllerNonce || message?.controllerNonce !== controllerNonce || message?.type !== "privileged_event") return
    dastWorker.postMessage(message)
  })
  port.onMessage.addListener(message => {
    if (!controllerNonce || message?.controllerNonce !== controllerNonce || message?.type !== "privileged_response") return
    privilegedByController.delete(message.requestId)
    dastWorker.postMessage(message)
  })
  port.onDisconnect.addListener(() => {
    if (activeDastController === port) {
      activeDastController = null
      activeDastControllerNonce = null
    }
    for (const [requestId, pending] of dastPending) {
      if (pending.port === port) dastPending.delete(requestId)
    }
    for (const [operationId, owner] of oneTimeDisplayOwners) {
      if (owner.port === port) oneTimeDisplayOwners.delete(operationId)
    }
    for (const [requestId, owner] of privilegedByController) {
      if (owner !== port) continue
      privilegedByController.delete(requestId)
      dastWorker.postMessage({ type: "privileged_response", requestId, error: "controller_replaced" })
    }
  })
})

if (dastWorker) {
  dastWorker.onmessage = event => {
    if (event.data?.type === "engine_event") {
      activeDastController?.postMessage?.({ ...event.data, controllerNonce: activeDastControllerNonce })
      return
    }
    if (event.data?.type === "one_time_display_event") {
      const operationId = String(event.data.operationId || "")
      const owner = oneTimeDisplayOwners.get(operationId)
      const message = sanitizeOneTimeDastProgressMessage(event.data.message)
      if (owner && owner.port === activeDastController && owner.controllerNonce === activeDastControllerNonce && message) {
        owner.port.postMessage({
          type: "one_time_display_event",
          operationId,
          message,
          controllerNonce: owner.controllerNonce
        })
      }
      return
    }
    if (event.data?.type === "privileged_request") {
      if (!activeDastController) {
        dastWorker.postMessage({ type: "privileged_response", requestId: event.data.requestId, error: "controller_replaced" })
        return
      }
      privilegedByController.set(event.data.requestId, activeDastController)
      activeDastController.postMessage({ ...event.data, controllerNonce: activeDastControllerNonce })
      return
    }
    const pending = dastPending.get(event.data?.requestId)
    if (!pending) return
    dastPending.delete(event.data.requestId)
    if (pending.operationId) oneTimeDisplayOwners.delete(pending.operationId)
    pending.port.postMessage({
      requestId: event.data.requestId,
      controllerNonce: pending.controllerNonce,
      response: event.data.response,
      transportError: event.data.transportError,
      ok: !event.data.transportError
    })
  }
}

runtime?.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.channel !== "ptk_bg2offscreen_sast") return undefined
  const { type, scanId } = msg
  if (type === 'cancel_scan') {
    if (sender?.id !== runtime.id || sender?.tab || sastOwners.size !== 1 || !sastOwners.has(scanId) || !sastWorker) {
      sendResponse?.({ ok: false, cancelled: false }); return true
    }
    const stopped = sastWorker
    stopped.terminate()
    sastWorker = null
    sastOwners.clear()
    sendResponse?.({ ok: true, cancelled: true })
    return true
  }
  if (type === "start_scan") {
    if (typeof scanId !== 'string' || !scanId || !ensureSastWorker()) return undefined
    sastOwners.add(scanId)
    sastWorker.postMessage({ type, scanId, scanStrategy: msg.scanStrategy, policy: msg.policy, opts: msg.opts })
  } else if (type === "scan_code") {
    if (!sastWorker || !sastOwners.has(scanId)) return undefined
    sastWorker.postMessage({
      type,
      scanId,
      scripts: msg.scripts,
      html: msg.html,
      file: msg.file,
      generation: msg.generation,
      collectionId: msg.collectionId
    })
  } else if (type === "stop_scan") {
    sastWorker?.postMessage({ type, scanId })
    sastOwners.delete(scanId)
  } else {
    return undefined
  }
  sendResponse?.({ ok: true })
  return true
})
