import { WordArray } from "./core.mjs";
import { CipherCfg, CipherObj, StreamCipher } from "./cipher-core.mjs";

//#region src/rabbit.d.ts
/**
 * Rabbit stream cipher algorithm
 */
declare class RabbitAlgo extends StreamCipher {
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
 *     var ciphertext = Rabbit.encrypt(message, key, cfg);
 *     var plaintext  = Rabbit.decrypt(ciphertext, key, cfg);
 */
declare const Rabbit: CipherObj;
//#endregion
export { Rabbit, RabbitAlgo };
//# sourceMappingURL=rabbit.d.mts.map