import { BlockCipherMode } from "./cipher-core.mjs";

//#region src/mode-ecb.d.ts

/**
 * ECB Encryptor
 */
declare class ECBEncryptor extends BlockCipherMode {
  processBlock(words: number[], offset: number): void;
}
/**
 * ECB Decryptor
 */
declare class ECBDecryptor extends BlockCipherMode {
  processBlock(words: number[], offset: number): void;
}
/**
 * Electronic Codebook block mode.
 */
declare class ECB extends BlockCipherMode {
  static readonly Encryptor: typeof ECBEncryptor;
  static readonly Decryptor: typeof ECBDecryptor;
}
//#endregion
export { ECB };
//# sourceMappingURL=mode-ecb.d.mts.map