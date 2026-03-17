import { BlockCipherMode } from "./cipher-core.cjs";

//#region src/mode-ctr.d.ts

/**
 * CTR Encryptor/Decryptor (same operation)
 */
declare class CTRMode extends BlockCipherMode {
  /** Counter for CTR mode */
  _counter?: number[];
  processBlock(words: number[], offset: number): void;
}
/**
 * Counter block mode.
 */
declare class CTR extends BlockCipherMode {
  /** Counter for CTR mode */
  _counter?: number[];
  static readonly Encryptor: typeof CTRMode;
  static readonly Decryptor: typeof CTRMode;
}
//#endregion
export { CTR };
//# sourceMappingURL=mode-ctr.d.cts.map