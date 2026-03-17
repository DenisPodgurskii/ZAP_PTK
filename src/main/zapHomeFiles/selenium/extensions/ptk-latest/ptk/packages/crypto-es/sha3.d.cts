import { HMACHashFn, HashFn, Hasher32, HasherCfg, WordArray } from "./core.cjs";

//#region src/sha3.d.ts
interface SHA3Config extends HasherCfg {
  outputLength?: number;
}
/**
 * SHA-3 hash algorithm.
 */
declare class SHA3Algo extends Hasher32 {
  cfg: SHA3Config;
  private _state;
  /**
   * Initializes a newly created hasher.
   *
   * @param cfg - Configuration options.
   * @property {number} outputLength - The desired number of bits in the output hash.
   *   Only values permitted are: 224, 256, 384, 512.
   *   Default: 512
   */
  constructor(cfg?: SHA3Config);
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
 * const hash = SHA3('message');
 * const hash = SHA3(wordArray);
 * ```
 */
declare const SHA3: HashFn;
/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param message - The message to hash.
 * @param key - The secret key.
 * @returns The HMAC.
 *
 * @example
 * ```js
 * const hmac = HmacSHA3(message, key);
 * ```
 */
declare const HmacSHA3: HMACHashFn;
//#endregion
export { HmacSHA3, SHA3, SHA3Algo };
//# sourceMappingURL=sha3.d.cts.map