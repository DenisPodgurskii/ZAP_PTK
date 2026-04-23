/* Stubs for sandboxed context (no allow-same-origin) */
(function() {
    // Storage stub - provides in-memory storage when localStorage is blocked
    var memoryStorage = {};
    var storageStub = {
        getItem: function(key) { return memoryStorage[key] || null; },
        setItem: function(key, value) { memoryStorage[key] = String(value); },
        removeItem: function(key) { delete memoryStorage[key]; },
        clear: function() { memoryStorage = {}; },
        get length() { return Object.keys(memoryStorage).length; },
        key: function(i) { return Object.keys(memoryStorage)[i] || null; }
    };
    try { window.localStorage; } catch(e) {
        Object.defineProperty(window, 'localStorage', { value: storageStub, writable: false });
    }
    try { window.sessionStorage; } catch(e) {
        Object.defineProperty(window, 'sessionStorage', { value: storageStub, writable: false });
    }

    // Worker stub - handle worker creation failures in sandboxed context
    // Chrome: Worker constructor throws SecurityError - Monaco catches this
    // Firefox: Worker is created but fails to load - causes error events
    var OriginalWorker = window.Worker;
    var isFirefox = navigator.userAgent.includes('Firefox');

    function createWorkerStub() {
        return {
            postMessage: function() {},
            terminate: function() {},
            onmessage: null,
            onerror: null,
            onmessageerror: null,
            addEventListener: function() {},
            removeEventListener: function() {},
            dispatchEvent: function() { return true; }
        };
    }

    window.Worker = function(scriptURL, options) {
        // In Firefox sandbox, return stub immediately to avoid error events
        if (isFirefox) {
            return createWorkerStub();
        }
        // In Chrome sandbox, try to create worker but return stub on failure
        try {
            return new OriginalWorker(scriptURL, options);
        } catch (e) {
            // SecurityError in Chrome sandbox - return stub silently
            return createWorkerStub();
        }
    };
    window.Worker.prototype = OriginalWorker ? OriginalWorker.prototype : {};
})();
