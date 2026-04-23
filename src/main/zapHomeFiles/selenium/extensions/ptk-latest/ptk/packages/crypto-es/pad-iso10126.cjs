const require_core = require('./core.cjs');

//#region src/pad-iso10126.ts
/**
* ISO 10126 padding strategy.
*/
const Iso10126 = {
	pad(data, blockSize) {
		const blockSizeBytes = blockSize * 4;
		const nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;
		data.concat(require_core.WordArray.random(nPaddingBytes - 1)).concat(require_core.WordArray.create([nPaddingBytes << 24], 1));
	},
	unpad(data) {
		const _data = data;
		const nPaddingBytes = _data.words[_data.sigBytes - 1 >>> 2] & 255;
		_data.sigBytes -= nPaddingBytes;
	}
};

//#endregion
exports.Iso10126 = Iso10126;
//# sourceMappingURL=pad-iso10126.cjs.map