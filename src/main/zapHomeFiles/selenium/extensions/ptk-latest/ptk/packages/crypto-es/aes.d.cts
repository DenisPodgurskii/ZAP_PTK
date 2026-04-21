import { BlockCipher, CipherObj } from "./cipher-core.cjs";

//#region src/aes.d.ts

/**
 * AES block cipher algorithm.
 */
declare class AESAlgo extends BlockCipher {
  /** Number of rounds for this key size */
  private _nRounds;
  /** Previous key for optimization */
  private _keyPriorReset?;
  /** Key schedule for encryption */
  private _keySchedule;
  /** Inverse key schedule for decryption */
  private _invKeySchedule;
  /** Key size in 32-bit words */
  static keySize: number;
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
 *     var ciphertext = AES.encrypt(message, key, cfg);
 *     var plaintext  = AES.decrypt(ciphertext, key, cfg);
 */
declare const AES: CipherObj;
//#endregion
export { AES, AESAlgo };
//# sourceMappingURL=aes.d.cts.map