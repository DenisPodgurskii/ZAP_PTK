(() => {
    // ---------- utilities ----------
    const sendToExt = (kind, payload) => {
        try { 
            const msg = {
                ptk_ws: 'websocket',
                channel: 'ptk_contentws2rattacker',
                kind: kind, 
                payload:payload
            }
            window.postMessage(msg, '*')
            browser.runtime.sendMessage(msg); 
        } catch { }
    };

    // Serialize minimal preview to avoid big copies
    const serialize = (data) => {
        try {
            if (typeof data === "string") return { type: "text", len: data.length, preview: data.slice(0, 2048) };
            if (data instanceof ArrayBuffer) return { type: "arraybuffer", len: data.byteLength };
            if (ArrayBuffer.isView(data)) return { type: "typedarray", len: data.byteLength };
            if (data instanceof Blob) return { type: "blob", size: data.size };
            return { type: typeof data, preview: String(data).slice(0, 256) };
        } catch (e) { return { type: "unknown", err: String(e) }; }
    };

    // ---------- main-thread WebSocket hook ----------
    const hookMainThreadWebSocket = () => {
        const NativeWS = window.WebSocket;
        if (!NativeWS || NativeWS.__ptkHooked) return;

        const patched = new Proxy(NativeWS, {
            construct(target, args) {
                const [url, protocols] = args;
                const ws = new target(...args);
                const id = Math.random().toString(36).slice(2);
                const meta = { id, url: String(url), protocols: protocols ?? null, ctx: "window", t: Date.now() };
                sendToExt("open", meta);

                const origSend = ws.send;
                ws.send = new Proxy(origSend, {
                    apply(fn, thisArg, argArray) {
                        try { sendToExt("send", { id, t: Date.now(), data: serialize(argArray[0]) }); } catch { }
                        return fn.apply(thisArg, argArray);
                    }
                });

                ws.addEventListener("message", (evt) => {
                    sendToExt("message", { id, t: Date.now(), data: serialize(evt.data) });
                });
                ws.addEventListener("error", (evt) => {
                    sendToExt("error", { id, t: Date.now(), msg: String(evt?.message || "ws error") });
                });
                ws.addEventListener("close", (evt) => {
                    sendToExt("close", { id, t: Date.now(), code: evt.code, reason: evt.reason, clean: evt.wasClean });
                });
                return ws;
            }
        });
        Object.defineProperty(patched, "__ptkHooked", { value: true });
        Object.defineProperty(window, "WebSocket", { value: patched, writable: false, configurable: false });
        // also set on globalThis for safety
        try { Object.defineProperty(globalThis, "WebSocket", { value: patched, writable: false, configurable: false }); } catch { }
        // console.log("[PTK] WS hook (window) installed");
    };

    // ---------- Worker bootstrap URLs ----------
    // We’ll create two bootstrap blobs: one for classic workers, one for module workers.
    const workerHookSrcClassic = `
    (function(){
      // Hook inside worker (classic)
      const send = (k,p)=>{ try{ self.postMessage({__ptkWS__:true, k, p}); }catch(e){} };
      const serialize = ${serialize.toString()};
      const NativeWS = self.WebSocket;
      if (NativeWS && !NativeWS.__ptkHooked) {
        const Patched = new Proxy(NativeWS, {
          construct(target, args) {
            const [url, protocols] = args;
            const ws = new target(...args);
            const id = Math.random().toString(36).slice(2);
            const meta = { id, url: String(url), protocols: protocols ?? null, ctx: "worker", t: Date.now() };
            send("open", meta);
            const origSend = ws.send;
            ws.send = new Proxy(origSend, {
              apply(fn, thisArg, argArray){
                try { send("send", { id, t: Date.now(), data: serialize(argArray[0]) }); } catch {}
                return fn.apply(thisArg, argArray);
              }
            });
            ws.addEventListener("message", (evt)=> send("message", { id, t: Date.now(), data: serialize(evt.data) }));
            ws.addEventListener("error",   (evt)=> send("error",   { id, t: Date.now(), msg: String(evt?.message||"ws error") }));
            ws.addEventListener("close",   (evt)=> send("close",   { id, t: Date.now(), code: evt.code, reason: evt.reason, clean: evt.wasClean }));
            return ws;
          }
        });
        Object.defineProperty(Patched, "__ptkHooked", { value: true });
        try { Object.defineProperty(self, "WebSocket", { value: Patched, writable:false, configurable:false }); } catch {}
      }
    })();
    // After hooking, import the real worker code:
    importScripts(__PTK_ORIGINAL_URL__);
  `;

    const workerHookSrcModule = `
    // Hook inside module worker
    const send = (k,p)=>{ try{ self.postMessage({__ptkWS__:true, k, p}); }catch(e){} };
    const serialize = ${serialize.toString()};
    const NativeWS = self.WebSocket;
    if (NativeWS && !NativeWS.__ptkHooked) {
      const Patched = new Proxy(NativeWS, {
        construct(target, args) {
          const [url, protocols] = args;
          const ws = new target(...args);
          const id = Math.random().toString(36).slice(2);
          const meta = { id, url: String(url), protocols: protocols ?? null, ctx: "worker-module", t: Date.now() };
          send("open", meta);
          const origSend = ws.send;
          ws.send = new Proxy(origSend, {
            apply(fn, thisArg, argArray){
              try { send("send", { id, t: Date.now(), data: serialize(argArray[0]) }); } catch {}
              return fn.apply(thisArg, argArray);
            }
          });
          ws.addEventListener("message", (evt)=> send("message", { id, t: Date.now(), data: serialize(evt.data) }));
          ws.addEventListener("error",   (evt)=> send("error",   { id, t: Date.now(), msg: String(evt?.message||"ws error") }));
          ws.addEventListener("close",   (evt)=> send("close",   { id, t: Date.now(), code: evt.code, reason: evt.reason, clean: evt.wasClean }));
          return ws;
        }
      });
      Object.defineProperty(Patched, "__ptkHooked", { value: true });
      try { Object.defineProperty(self, "WebSocket", { value: Patched, writable:false, configurable:false }); } catch {}
    }
    // Import original as module
    import(__PTK_ORIGINAL_URL__);
  `;

    const makeBootstrapBlob = (code, originalURL) => {
        const src = code.replace("__PTK_ORIGINAL_URL__", JSON.stringify(originalURL));
        return URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
    };

    // Bridge worker->page->extension
    const attachWorkerMessageBridge = (worker, originUrl) => {
        const handler = (evt) => {
            const data = evt?.data;
            if (data && data.__ptkWS__ === true) {
                sendToExt("worker", { originUrl, k: data.k, p: data.p });
            }
        };
        worker.addEventListener?.("message", handler);
        // Some libs use onmessage directly; keep addEventListener to avoid clobbering.
    };

    // ---------- wrap Worker & SharedWorker constructors ----------
    const hookWorkers = () => {
        const NativeWorker = window.Worker;
        const NativeSharedWorker = window.SharedWorker;

        if (NativeWorker && !NativeWorker.__ptkHooked) {
            const WrappedWorker = new Proxy(NativeWorker, {
                construct(target, args) {
                    const [scriptURL, options] = args;
                    const type = options?.type === "module" ? "module" : "classic";
                    const bootstrapUrl = (type === "module")
                        ? makeBootstrapBlob(workerHookSrcModule, String(scriptURL))
                        : makeBootstrapBlob(workerHookSrcClassic, String(scriptURL));
                    const w = new target(bootstrapUrl, options);
                    attachWorkerMessageBridge(w, String(scriptURL));
                    return w;
                }
            });
            Object.defineProperty(WrappedWorker, "__ptkHooked", { value: true });
            try { Object.defineProperty(window, "Worker", { value: WrappedWorker, writable: false, configurable: false }); } catch { }
        }

        if (NativeSharedWorker && !NativeSharedWorker.__ptkHooked) {
            const WrappedShared = new Proxy(NativeSharedWorker, {
                construct(target, args) {
                    const [scriptURL, options] = args;
                    const type = options?.type === "module" ? "module" : "classic";
                    const bootstrapUrl = (type === "module")
                        ? makeBootstrapBlob(workerHookSrcModule, String(scriptURL))
                        : makeBootstrapBlob(workerHookSrcClassic, String(scriptURL));
                    const sw = new target(bootstrapUrl, options);
                    try {
                        // SharedWorker uses .port for messaging
                        sw.port.addEventListener("message", (evt) => {
                            const data = evt?.data;
                            if (data && data.__ptkWS__ === true) {
                                sendToExt("worker", { originUrl: String(scriptURL), k: data.k, p: data.p });
                            }
                        });
                        sw.port.start();
                    } catch { }
                    return sw;
                }
            });
            Object.defineProperty(WrappedShared, "__ptkHooked", { value: true });
            try { Object.defineProperty(window, "SharedWorker", { value: WrappedShared, writable: false, configurable: false }); } catch { }
        }
    };

    // Install everything ASAP
    hookMainThreadWebSocket();
    hookWorkers();
})();
