import { WordArray } from "./core.mjs";
import { CipherCfg, CipherObj, StreamCipher } from "./cipher-core.mjs";

//#region src/rc4.d.ts
interface RC4DropCfg extends CipherCfg {
  drop?: number;
}
/**
 * RC4 stream cipher algorithm.
 */
declare class RC4Algo extends StreamCipher {
  static keySize: number;
  static ivSize: number;
  protected _S: number[];
  protected _i: number;
  protected _j: number;
  protected generateKeystreamWord(): number;
  protected _doReset(): void;
  protected _doProcessBlock(M: number[], offset: number): void;
}
/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = RC4.encrypt(message, key, cfg);
 *     var plaintext  = RC4.decrypt(ciphertext, key, cfg);
 */
declare const RC4: CipherObj;
/**
 * Modified RC4 stream cipher algorithm.
 */
declare class RC4DropAlgo extends RC4Algo {
  cfg: RC4DropCfg;
  constructor(xformMode: number, key: WordArray, cfg?: RC4DropCfg);
  protected _doReset(): void;
}
/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = RC4Drop.encrypt(message, key, cfg);
 *     var plaintext  = RC4Drop.decrypt(ciphertext, key, cfg);
 */
declare const RC4Drop: CipherObj;
//#endregion
export { RC4, RC4Algo, RC4Drop, RC4DropAlgo };
//# sourceMappingURL=rc4.d.mts.map