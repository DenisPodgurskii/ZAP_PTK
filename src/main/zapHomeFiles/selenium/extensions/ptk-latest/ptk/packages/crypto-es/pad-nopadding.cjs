
//#region src/pad-nopadding.ts
/**
* A noop padding strategy.
*/
const NoPadding = {
	pad(_data, _blockSize) {},
	unpad(_data) {}
};

//#endregion
exports.NoPadding = NoPadding;
//# sourceMappingURL=pad-nopadding.cjs.map