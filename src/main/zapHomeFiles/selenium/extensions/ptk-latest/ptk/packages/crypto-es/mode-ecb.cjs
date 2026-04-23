const require_cipher_core = require('./cipher-core.cjs');

//#region src/mode-ecb.ts
/**
* ECB Encryptor
*/
var ECBEncryptor = class extends require_cipher_core.BlockCipherMode {
	processBlock(words, offset) {
		this._cipher.encryptBlock(words, offset);
	}
};
/**
* ECB Decryptor
*/
var ECBDecryptor = class extends require_cipher_core.BlockCipherMode {
	processBlock(words, offset) {
		this._cipher.decryptBlock(words, offset);
	}
};
/**
* Electronic Codebook block mode.
*/
var ECB = class extends require_cipher_core.BlockCipherMode {
	static Encryptor = ECBEncryptor;
	static Decryptor = ECBDecryptor;
};

//#endregion
exports.ECB = ECB;
//# sourceMappingURL=mode-ecb.cjs.map