import { BlockCipherMode } from "./cipher-core.mjs";

//#region src/mode-ctr-gladman.d.ts

/**
 * CTRGladman Encryptor/Decryptor (same operation)
 */
declare class CTRGladmanMode extends BlockCipherMode {
  /** Counter for CTR Gladman mode */
  _counter?: number[];
  processBlock(words: number[], offset: number): void;
}
/** @preserve
 * Counter block mode compatible with  Dr Brian Gladman fileenc.c
 * derived from CTR mode
 * Jan Hruby jhruby.web@gmail.com
 */
declare class CTRGladman extends BlockCipherMode {
  /** Counter for CTR Gladman mode */
  _counter?: number[];
  static readonly Encryptor: typeof CTRGladmanMode;
  static readonly Decryptor: typeof CTRGladmanMode;
}
//#endregion
export { CTRGladman };
//# sourceMappingURL=mode-ctr-gladman.d.mts.map