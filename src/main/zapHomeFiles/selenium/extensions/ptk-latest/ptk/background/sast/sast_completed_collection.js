// Scan-local receipts, not a source/AST cache. Unsupported or oversized values
// are deliberately ineligible: they must continue through normal analysis.
const INPUT_LIMIT = 8 * 1024 * 1024;
export const SAST_REUSE_RESULT_LIMIT = 1024 * 1024;

export function serializeSastReuseValue(value, limit = INPUT_LIMIT, allowUndefined = false) {
  let size = 0;
  const ancestors = new Set();
  const valid = item => {
    if (allowUndefined && item === undefined) return (size += 5) <= limit;
    if (item === null || typeof item === 'boolean') return (size += 5) <= limit;
    if (typeof item === 'string') return (size += item.length + 2) <= limit;
    if (typeof item === 'number') return Number.isFinite(item) && (size += 24) <= limit;
    if (!item || typeof item !== 'object' || ancestors.has(item)) return false;
    if (!Array.isArray(item) && Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null) return false;
    ancestors.add(item);
    let ok = (size += 2) <= limit;
    // Do not invoke getters/toJSON or collapse holes, undefined and non-JSON data.
    const descriptors = Object.getOwnPropertyDescriptors(item);
    const keys = Object.keys(item);
    if (Array.isArray(item) && keys.length !== item.length) ok = false;
    for (const key of keys) {
      const property = descriptors[key];
      if (!ok || !Object.hasOwn(property, 'value') || (size += key.length + 4) > limit || !valid(property.value)) { ok = false; break; }
    }
    ancestors.delete(item);
    return ok;
  };
  try {
    if (!valid(value)) return null;
    const serialized = JSON.stringify(value);
    return serialized.length <= limit ? serialized : null;
  } catch (_) { return null; }
}

export async function sastCompletedCollectionKey(input) {
  const serialized = serializeSastReuseValue(input);
  if (serialized === null || !globalThis.crypto?.subtle) return null;
  try {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(serialized));
    return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
  } catch (_) { return null; }
}

export function cloneSastReuseFindings(findings) {
  // Findings legitimately include optional undefined fields. Preserve them in
  // the bounded clone; unlike the input key this JSON is only a size check.
  if (!Array.isArray(findings)) return null;
  try {
    // Local Acorn locations become plain data, just as on the worker channel.
    const copy = structuredClone(findings);
    return serializeSastReuseValue(copy, SAST_REUSE_RESULT_LIMIT, true) !== null ? copy : null;
  } catch (_) { return null; }
}

// Account only retained result data and finite keys. Run/engine/token are
// identity references, not additional copies of the engine or rule catalogue.
export function sastAnalysisReceiptBytes(receipt) {
  const data = serializeSastReuseValue([receipt.key || null, receipt.originalKey || null,
    receipt.failedOriginalKey || null, receipt.findings || [], receipt.originalCount || 0,
    receipt.failedOriginalCode || null, receipt.failedLiveCode || null, receipt.failurePhase || null],
    SAST_REUSE_RESULT_LIMIT + 2048, true);
  return data === null ? null : data.length * 2 + 1024;
}
