import { Base, WordArray } from "./core.mjs";
import { MD5Algo } from "./md5.mjs";

//#region src/evpkdf.d.ts
interface EvpKDFCfg {
  keySize?: number;
  hasher?: typeof MD5Algo;
  iterations?: number;
}
/**
 * This key derivation function is meant to conform with EVP_BytesToKey.
 * www.openssl.org/docs/crypto/EVP_BytesToKey.html
 */
declare class EvpKDFAlgo extends Base {
  cfg: EvpKDFCfg;
  /**
   * Initializes a newly created key derivation function.
   *
   * @param {Object} cfg (Optional) The configuration options to use for the derivation.
   *
   * @example
   *
   *     const kdf = new EvpKDFAlgo();
   *     const kdf = new EvpKDFAlgo({ keySize: 8 });
   *     const kdf = new EvpKDFAlgo({ keySize: 8, iterations: 1000 });
   */
  constructor(cfg?: EvpKDFCfg);
  /**
   * Derives a key from a password.
   *
   * @param {WordArray|string} password The password.
   * @param {WordArray|string} salt A salt.
   *
   * @return {WordArray} The derived key.
   *
   * @example
   *
   *     const key = kdf.compute(password, salt);
   */
  compute(password: WordArray | string, salt: WordArray | string): WordArray;
}
/**
 * Derives a key from a password.
 *
 * @param {WordArray|string} password The password.
 * @param {WordArray|string} salt A salt.
 * @param {Object} cfg (Optional) The configuration options to use for this computation.
 *
 * @return {WordArray} The derived key.
 *
 * @static
 *
 * @example
 *
 *     var key = EvpKDF(password, salt);
 *     var key = EvpKDF(password, salt, { keySize: 8 });
 *     var key = EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
 */
declare const EvpKDF: (password: WordArray | string, salt: WordArray | string, cfg?: EvpKDFCfg) => WordArray;
//#endregion
export { EvpKDF, EvpKDFAlgo };
//# sourceMappingURL=evpkdf.d.mts.map