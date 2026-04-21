const require_core = require('./core.cjs');
const require_pad_zeropadding = require('./pad-zeropadding.cjs');

//#region src/pad-iso97971.ts
/**
* ISO/IEC 9797-1 Padding Method 2.
*/
const Iso97971 = {
	pad(data, blockSize) {
		data.concat(require_core.WordArray.create([2147483648], 1));
		require_pad_zeropadding.ZeroPadding.pad(data, blockSize);
	},
	unpad(data) {
		const _data = data;
		require_pad_zeropadding.ZeroPadding.unpad(_data);
		_data.sigBytes -= 1;
	}
};

//#endregion
exports.Iso97971 = Iso97971;
//# sourceMappingURL=pad-iso97971.cjs.map