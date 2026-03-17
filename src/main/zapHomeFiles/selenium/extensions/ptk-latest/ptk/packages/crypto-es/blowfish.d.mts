import { WordArray } from "./core.mjs";
import { BlockCipher, CipherObj } from "./cipher-core.mjs";

//#region src/blowfish.d.ts

/**
 * Blowfish block cipher algorithm.
 */
declare class BlowfishAlgo extends BlockCipher {
  static keySize: number;
  static ivSize: number;
  private _keyPriorReset?;
  constructor(xformMode: number, key: WordArray, cfg?: any);
  protected _doReset(): void;
  encryptBlock(M: number[], offset: number): void;
  decryptBlock(M: number[], offset: number): void;
}
/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = Blowfish.encrypt(message, key, cfg);
 *     var plaintext  = Blowfish.decrypt(ciphertext, key, cfg);
 */
declare const Blowfish: CipherObj;
//#endregion
export { Blowfish, BlowfishAlgo };
//# sourceMappingURL=blowfish.d.mts.map