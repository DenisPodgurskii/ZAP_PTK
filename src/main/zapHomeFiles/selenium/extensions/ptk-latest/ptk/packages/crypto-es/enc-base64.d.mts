import { Encoder } from "./core.mjs";

//#region src/enc-base64.d.ts

/**
 * Base64 encoding strategy.
 * Converts between WordArrays and Base64 strings.
 *
 * @example
 * ```javascript
 * // Encoding
 * const base64String = Base64.stringify(wordArray);
 *
 * // Decoding
 * const wordArray = Base64.parse(base64String);
 * ```
 */
declare const Base64: Encoder;
//#endregion
export { Base64 };
//# sourceMappingURL=enc-base64.d.mts.map