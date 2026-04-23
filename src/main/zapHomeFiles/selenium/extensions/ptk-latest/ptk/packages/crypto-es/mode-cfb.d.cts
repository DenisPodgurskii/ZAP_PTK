import { BlockCipherMode } from "./cipher-core.cjs";

//#region src/mode-cfb.d.ts

/**
 * CFB Encryptor
 */
declare class CFBEncryptor extends BlockCipherMode {
  processBlock(words: number[], offset: number): void;
}
/**
 * CFB Decryptor
 */
declare class CFBDecryptor extends BlockCipherMode {
  processBlock(words: number[], offset: number): void;
}
/**
 * Cipher Feedback block mode.
 */
declare class CFB extends BlockCipherMode {
  static readonly Encryptor: typeof CFBEncryptor;
  static readonly Decryptor: typeof CFBDecryptor;
}
//#endregion
export { CFB };
//# sourceMappingURL=mode-cfb.d.cts.map