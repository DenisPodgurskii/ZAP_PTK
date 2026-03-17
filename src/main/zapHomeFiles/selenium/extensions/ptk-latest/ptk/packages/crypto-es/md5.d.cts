import { HMACHashFn, HashFn, Hasher32, WordArray } from "./core.cjs";

//#region src/md5.d.ts

/**
 * MD5 hash algorithm.
 */
declare class MD5Algo extends Hasher32 {
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
 * const hash = MD5('message');
 * const hash = MD5(wordArray);
 * ```
 */
declare const MD5: HashFn;
/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param message - The message to hash.
 * @param key - The secret key.
 * @returns The HMAC.
 *
 * @example
 * ```js
 * const hmac = HmacMD5(message, key);
 * ```
 */
declare const HmacMD5: HMACHashFn;
//#endregion
export { HmacMD5, MD5, MD5Algo };
//# sourceMappingURL=md5.d.cts.map