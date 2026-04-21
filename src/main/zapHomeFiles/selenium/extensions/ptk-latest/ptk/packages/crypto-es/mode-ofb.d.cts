import { BlockCipherMode } from "./cipher-core.cjs";

//#region src/mode-ofb.d.ts

/**
 * OFB Encryptor/Decryptor (same operation)
 */
declare class OFBMode extends BlockCipherMode {
  /** Keystream for OFB mode */
  _keystream?: number[];
  processBlock(words: number[], offset: number): void;
}
/**
 * Output Feedback block mode.
 */
declare class OFB extends BlockCipherMode {
  /** Keystream for OFB mode */
  _keystream?: number[];
  static readonly Encryptor: typeof OFBMode;
  static readonly Decryptor: typeof OFBMode;
}
//#endregion
export { OFB };
//# sourceMappingURL=mode-ofb.d.cts.map