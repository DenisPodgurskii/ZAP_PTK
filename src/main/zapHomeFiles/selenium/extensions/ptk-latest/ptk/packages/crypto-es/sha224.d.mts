import { HMACHashFn, HashFn, WordArray } from "./core.mjs";
import { SHA256Algo } from "./sha256.mjs";

//#region src/sha224.d.ts

/**
 * SHA-224 hash algorithm.
 */
declare class SHA224Algo extends SHA256Algo {
  _doReset(): void;
  _doFinalize(): WordArray;
  clone(): this;
}
/**
 * Shortcut function to the hasher's object interface.
 *
 * @param message - The message to hash.
 * @returns The hash.
 *
 * @example
 * ```js
 * const hash = SHA224('message');
 * const hash = SHA224(wordArray);
 * ```
 */
declare const SHA224: HashFn;
/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param message - The message to hash.
 * @param key - The secret key.
 * @returns The HMAC.
 *
 * @example
 * ```js
 * const hmac = HmacSHA224(message, key);
 * ```
 */
declare const HmacSHA224: HMACHashFn;
//#endregion
export { HmacSHA224, SHA224, SHA224Algo };
//# sourceMappingURL=sha224.d.mts.map