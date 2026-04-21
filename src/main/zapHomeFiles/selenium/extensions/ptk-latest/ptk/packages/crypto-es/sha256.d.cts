import { HMACHashFn, HashFn, Hasher32, WordArray } from "./core.cjs";

//#region src/sha256.d.ts

/**
 * SHA-256 hash algorithm.
 */
declare class SHA256Algo extends Hasher32 {
  _doReset(): void;
  _doProcessBlock(M: number[], offset: number): void;
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
 * const hash = SHA256('message');
 * const hash = SHA256(wordArray);
 * ```
 */
declare const SHA256: HashFn;
/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param message - The message to hash.
 * @param key - The secret key.
 * @returns The HMAC.
 *
 * @example
 * ```js
 * const hmac = HmacSHA256(message, key);
 * ```
 */
declare const HmacSHA256: HMACHashFn;
//#endregion
export { HmacSHA256, SHA256, SHA256Algo };
//# sourceMappingURL=sha256.d.cts.map