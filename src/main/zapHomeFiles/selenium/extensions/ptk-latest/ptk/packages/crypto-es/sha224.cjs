const require_core = require('./core.cjs');
const require_sha256 = require('./sha256.cjs');

//#region src/sha224.ts
/**
* SHA-224 hash algorithm.
*/
var SHA224Algo = class extends require_sha256.SHA256Algo {
	_doReset() {
		this._hash = new require_core.WordArray([
			3238371032,
			914150663,
			812702999,
			4144912697,
			4290775857,
			1750603025,
			1694076839,
			3204075428
		]);
	}
	_doFinalize() {
		const hash = super._doFinalize.call(this);
		hash.sigBytes -= 4;
		return hash;
	}
	clone() {
		const clone = super.clone.call(this);
		return clone;
	}
};
/**
* Shortcut function to the hasher's object interface.
*
* @param message - The message to hash.
* @returns The hash.
*
* @example
* ```js
* const hash = SHA224('message');
* const hash = SHA224(wordArray);
* ```
*/
const SHA224 = require_sha256.SHA256Algo._createHelper(SHA224Algo);
/**
* Shortcut function to the HMAC's object interface.
*
* @param message - The message to hash.
* @param key - The secret key.
* @returns The HMAC.
*
* @example
* ```js
* const hmac = HmacSHA224(message, key);
* ```
*/
const HmacSHA224 = require_sha256.SHA256Algo._createHmacHelper(SHA224Algo);

//#endregion
exports.HmacSHA224 = HmacSHA224;
exports.SHA224 = SHA224;
exports.SHA224Algo = SHA224Algo;
//# sourceMappingURL=sha224.cjs.map