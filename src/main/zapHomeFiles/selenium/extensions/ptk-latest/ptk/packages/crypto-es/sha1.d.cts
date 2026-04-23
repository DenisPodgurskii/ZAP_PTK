import { HMACHashFn, HashFn, Hasher32, WordArray } from "./core.cjs";

//#region src/sha1.d.ts

/**
 * SHA-1 hash algorithm.
 */
declare class SHA1Algo extends Hasher32 {
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
 * const hash = SHA1('message');
 * const hash = SHA1(wordArray);
 * ```
 */
declare const SHA1: HashFn;
/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param message - The message to hash.
 * @param key - The secret key.
 * @returns The HMAC.
 *
 * @example
 * ```js
 * const hmac = HmacSHA1(message, key);
 * ```
 */
declare const HmacSHA1: HMACHashFn;
//#endregion
export { HmacSHA1, SHA1, SHA1Algo };
//# sourceMappingURL=sha1.d.cts.map