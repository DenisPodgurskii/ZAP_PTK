import { HMACHashFn, HashFn, Hasher32, WordArray } from "./core.mjs";

//#region src/ripemd160.d.ts

/**
 * RIPEMD160 hash algorithm.
 */
declare class RIPEMD160Algo extends Hasher32 {
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
 * const hash = RIPEMD160('message');
 * const hash = RIPEMD160(wordArray);
 * ```
 */
declare const RIPEMD160: HashFn;
/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param message - The message to hash.
 * @param key - The secret key.
 * @returns The HMAC.
 *
 * @example
 * ```js
 * const hmac = HmacRIPEMD160(message, key);
 * ```
 */
declare const HmacRIPEMD160: HMACHashFn;
//#endregion
export { HmacRIPEMD160, RIPEMD160, RIPEMD160Algo };
//# sourceMappingURL=ripemd160.d.mts.map