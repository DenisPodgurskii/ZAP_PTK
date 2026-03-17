import { HMACHashFn, HashFn, WordArray } from "./core.cjs";
import { SHA512Algo } from "./sha512.cjs";

//#region src/sha384.d.ts

/**
 * SHA-384 hash algorithm.
 */
declare class SHA384Algo extends SHA512Algo {
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
 * const hash = SHA384('message');
 * const hash = SHA384(wordArray);
 * ```
 */
declare const SHA384: HashFn;
/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param message - The message to hash.
 * @param key - The secret key.
 * @returns The HMAC.
 *
 * @example
 * ```js
 * const hmac = HmacSHA384(message, key);
 * ```
 */
declare const HmacSHA384: HMACHashFn;
//#endregion
export { HmacSHA384, SHA384, SHA384Algo };
//# sourceMappingURL=sha384.d.cts.map