// emitter.js
export function createEmitter(opts = {}) {
  const {
    async = false,                       // deliver on next microtask if true
    replay = 0,                          // number of last events to replay per name; 0 = off
  } = opts;

  const listeners = new Map();           // name -> Set<fn>
  const history = replay ? new Map() : null;

  const deliver = async
    ? (fn, payload) => Promise.resolve().then(() => fn(payload))
    : (fn, payload) => { fn(payload); };

  function _pushHistory(name, payload) {
    if (!history) return;
    const arr = history.get(name) || [];
    arr.push(payload);
    if (arr.length > replay) arr.shift();
    history.set(name, arr);
  }

  function on(name, fn) {
    if (typeof fn !== 'function') throw new TypeError('listener must be a function');
    let set = listeners.get(name);
    if (!set) listeners.set(name, (set = new Set()));
    set.add(fn);

    // optional replay of recent events for late subscribers
    if (history && history.has(name)) {
      for (const payload of history.get(name)) deliver(fn, payload);
    }
    // unsubscribe
    return () => off(name, fn);
  }

  // alias
  const subscribe = on;

  function once(name, fn) {
    const offFn = on(name, (payload) => { try { fn(payload); } finally { offFn(); } });
    return offFn;
  }

  function off(name, fn) {
    const set = listeners.get(name);
    if (!set) return;
    set.delete(fn);
    if (set.size === 0) listeners.delete(name);
  }

  function emit(name, data) {
    const set = listeners.get(name);
    if (!set || set.size === 0) { _pushHistory(name, data); return 0; }
    _pushHistory(name, data);
    // copy to array to avoid mutation during emit
    const fns = [...set];
    for (const fn of fns) {
      try { deliver(fn, data); }
      catch (e) { /* isolate listener errors */ console.error('listener error', e); }
    }
    return fns.length;
  }

  function clear(name) {
    if (name) { listeners.delete(name); history && history.delete(name); }
    else { listeners.clear(); history && history.clear(); }
  }

  return { on, subscribe, once, off, emit, clear };
}
