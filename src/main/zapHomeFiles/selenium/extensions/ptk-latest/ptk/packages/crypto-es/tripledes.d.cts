import { WordArray } from "./core.cjs";
import { BlockCipher, CipherCfg, CipherObj } from "./cipher-core.cjs";

//#region src/tripledes.d.ts

/**
 * DES block cipher algorithm.
 */
declare class DESAlgo extends BlockCipher {
  /** Key size in 32-bit words */
  static keySize: number;
  /** IV size in 32-bit words */
  static ivSize: number;
  /** Block size in 32-bit words */
  blockSize: number;
  /** Subkeys for encryption */
  private _subKeys;
  /** Inverse subkeys for decryption */
  private _invSubKeys;
  /** Left block for processing */
  protected _lBlock: number;
  /** Right block for processing */
  protected _rBlock: number;
  constructor(xformMode: number, key: WordArray, cfg?: CipherCfg);
  protected _doReset(): void;
  encryptBlock(M: number[], offset: number): void;
  decryptBlock(M: number[], offset: number): void;
  private _doCryptBlock;
}
/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = DES.encrypt(message, key, cfg);
 *     var plaintext  = DES.decrypt(ciphertext, key, cfg);
 */
declare const DES: CipherObj;
/**
 * Triple-DES block cipher algorithm.
 */
declare class TripleDESAlgo extends BlockCipher {
  /** Key size in 32-bit words */
  static keySize: number;
  /** IV size in 32-bit words */
  static ivSize: number;
  /** Block size in 32-bit words */
  blockSize: number;
  /** First DES instance */
  private _des1;
  /** Second DES instance */
  private _des2;
  /** Third DES instance */
  private _des3;
  protected _doReset(): void;
  encryptBlock(M: number[], offset: number): void;
  decryptBlock(M: number[], offset: number): void;
}
/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = TripleDES.encrypt(message, key, cfg);
 *     var plaintext  = TripleDES.decrypt(ciphertext, key, cfg);
 */
declare const TripleDES: CipherObj;
//#endregion
export { DES, DESAlgo, TripleDES, TripleDESAlgo };
//# sourceMappingURL=tripledes.d.cts.map