const require_core = require('./core.cjs');
const require_cipher_core = require('./cipher-core.cjs');

//#region src/format-hex.ts
/**
* Hex formatter for cipher params.
* Converts cipher params to/from hexadecimal strings.
*/
const HexFormatter = {
	stringify(cipherParams) {
		if (!cipherParams.ciphertext) throw new Error("Ciphertext is required");
		return cipherParams.ciphertext.toString(require_core.Hex);
	},
	parse(input) {
		const ciphertext = require_core.Hex.parse(input);
		return require_cipher_core.CipherParams.create({ ciphertext });
	}
};

//#endregion
exports.HexFormatter = HexFormatter;
//# sourceMappingURL=format-hex.cjs.map