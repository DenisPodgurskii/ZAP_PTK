import { WordArray } from "./core.cjs";
import { CipherCfg, CipherObj, StreamCipher } from "./cipher-core.cjs";

//#region src/rabbit-legacy.d.ts

/**
 * Rabbit stream cipher algorithm.
 *
 * This is a legacy version that neglected to convert the key to little-endian.
 * This error doesn't affect the cipher's security,
 * but it does affect its compatibility with other implementations.
 */
declare class RabbitLegacyAlgo extends StreamCipher {
  protected _X: number[];
  protected _C: number[];
  protected _b: number;
  static readonly ivSize: number;
  constructor(xformMode: number, key: WordArray, cfg?: CipherCfg);
  protected _doReset(): void;
  protected _doProcessBlock(M: number[], offset: number): void;
}
/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = RabbitLegacy.encrypt(message, key, cfg);
 *     var plaintext  = RabbitLegacy.decrypt(ciphertext, key, cfg);
 */
declare const RabbitLegacy: CipherObj;
//#endregion
export { RabbitLegacy, RabbitLegacyAlgo };
//# sourceMappingURL=rabbit-legacy.d.cts.map