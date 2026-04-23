import { X64WordArray } from "./x64-core.mjs";
import { HMACHashFn, HashFn, Hasher64, HasherCfg, WordArray } from "./core.mjs";

//#region src/sha512.d.ts

/**
 * SHA-512 hash algorithm.
 */
declare class SHA512Algo extends Hasher64 {
  _hash: X64WordArray;
  constructor(cfg?: HasherCfg);
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
 * const hash = SHA512('message');
 * const hash = SHA512(wordArray);
 * ```
 */
declare const SHA512: HashFn;
/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param message - The message to hash.
 * @param key - The secret key.
 * @returns The HMAC.
 *
 * @example
 * ```js
 * const hmac = HmacSHA512(message, key);
 * ```
 */
declare const HmacSHA512: HMACHashFn;
//#endregion
export { HmacSHA512, SHA512, SHA512Algo };
//# sourceMappingURL=sha512.d.mts.map