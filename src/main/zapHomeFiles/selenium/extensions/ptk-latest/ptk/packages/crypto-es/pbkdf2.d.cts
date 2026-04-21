import { Base, WordArray } from "./core.cjs";
import { SHA256Algo } from "./sha256.cjs";

//#region src/pbkdf2.d.ts
interface PBKDF2Cfg {
  keySize?: number;
  hasher?: typeof SHA256Algo;
  iterations?: number;
}
/**
 * Password-Based Key Derivation Function 2 algorithm.
 */
declare class PBKDF2Algo extends Base {
  cfg: PBKDF2Cfg;
  /**
   * Initializes a newly created key derivation function.
   *
   * @param {Object} cfg (Optional) The configuration options to use for the derivation.
   *
   * @example
   *
   *     const kdf = new PBKDF2Algo();
   *     const kdf = new PBKDF2Algo({ keySize: 8 });
   *     const kdf = new PBKDF2Algo({ keySize: 8, iterations: 1000 });
   */
  constructor(cfg?: PBKDF2Cfg);
  /**
   * Computes the Password-Based Key Derivation Function 2.
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
 * Computes the Password-Based Key Derivation Function 2.
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
 *     var key = PBKDF2(password, salt);
 *     var key = PBKDF2(password, salt, { keySize: 8 });
 *     var key = PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
 */
declare const PBKDF2: (password: WordArray | string, salt: WordArray | string, cfg?: PBKDF2Cfg) => WordArray;
//#endregion
export { PBKDF2, PBKDF2Algo };
//# sourceMappingURL=pbkdf2.d.cts.map