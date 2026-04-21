import * as CryptoESExports from './index.mjs';

const CryptoES = {
  lib: {
    Base: CryptoESExports.Base,
    WordArray: CryptoESExports.WordArray,
    BufferedBlockAlgorithm: CryptoESExports.BufferedBlockAlgorithm,
    Hasher: CryptoESExports.Hasher,
    Cipher: CryptoESExports.Cipher,
    StreamCipher: CryptoESExports.StreamCipher,
    BlockCipherMode: CryptoESExports.BlockCipherMode,
    BlockCipher: CryptoESExports.BlockCipher,
    CipherParams: CryptoESExports.CipherParams,
    SerializableCipher: CryptoESExports.SerializableCipher,
    PasswordBasedCipher: CryptoESExports.PasswordBasedCipher,
  },

  x64: {
    Word: CryptoESExports.X64Word,
    WordArray: CryptoESExports.X64WordArray,
  },

  enc: {
    Hex: CryptoESExports.Hex,
    Latin1: CryptoESExports.Latin1,
    Utf8: CryptoESExports.Utf8,
    Utf16: CryptoESExports.Utf16,
    Utf16BE: CryptoESExports.Utf16BE,
    Utf16LE: CryptoESExports.Utf16LE,
    Base64: CryptoESExports.Base64,
    Base64url: CryptoESExports.Base64url,
  },

  algo: {
    HMAC: CryptoESExports.HMAC,
    MD5: CryptoESExports.MD5Algo,
    SHA1: CryptoESExports.SHA1Algo,
    SHA224: CryptoESExports.SHA224Algo,
    SHA256: CryptoESExports.SHA256Algo,
    SHA384: CryptoESExports.SHA384Algo,
    SHA512: CryptoESExports.SHA512Algo,
    SHA3: CryptoESExports.SHA3Algo,
    RIPEMD160: CryptoESExports.RIPEMD160Algo,
    PBKDF2: CryptoESExports.PBKDF2Algo,
    EvpKDF: CryptoESExports.EvpKDFAlgo,
    AES: CryptoESExports.AESAlgo,
    DES: CryptoESExports.DESAlgo,
    TripleDES: CryptoESExports.TripleDESAlgo,
    Rabbit: CryptoESExports.RabbitAlgo,
    RabbitLegacy: CryptoESExports.RabbitLegacyAlgo,
    RC4: CryptoESExports.RC4Algo,
    RC4Drop: CryptoESExports.RC4DropAlgo,
    Blowfish: CryptoESExports.BlowfishAlgo,
  },

  mode: {
    CBC: CryptoESExports.CBC,
    CFB: CryptoESExports.CFB,
    CTR: CryptoESExports.CTR,
    CTRGladman: CryptoESExports.CTRGladman,
    ECB: CryptoESExports.ECB,
    OFB: CryptoESExports.OFB,
  },

  pad: {
    Pkcs7: CryptoESExports.Pkcs7,
    AnsiX923: CryptoESExports.AnsiX923,
    Iso10126: CryptoESExports.Iso10126,
    Iso97971: CryptoESExports.Iso97971,
    NoPadding: CryptoESExports.NoPadding,
    ZeroPadding: CryptoESExports.ZeroPadding,
  },

  format: {
    OpenSSL: CryptoESExports.OpenSSLFormatter,
    Hex: CryptoESExports.HexFormatter,
  },

  kdf: {
    OpenSSL: CryptoESExports.OpenSSLKdf,
  },

  MD5: CryptoESExports.MD5,
  HmacMD5: CryptoESExports.HmacMD5,
  SHA1: CryptoESExports.SHA1,
  HmacSHA1: CryptoESExports.HmacSHA1,
  SHA224: CryptoESExports.SHA224,
  HmacSHA224: CryptoESExports.HmacSHA224,
  SHA256: CryptoESExports.SHA256,
  HmacSHA256: CryptoESExports.HmacSHA256,
  SHA384: CryptoESExports.SHA384,
  HmacSHA384: CryptoESExports.HmacSHA384,
  SHA512: CryptoESExports.SHA512,
  HmacSHA512: CryptoESExports.HmacSHA512,
  SHA3: CryptoESExports.SHA3,
  HmacSHA3: CryptoESExports.HmacSHA3,
  RIPEMD160: CryptoESExports.RIPEMD160,
  HmacRIPEMD160: CryptoESExports.HmacRIPEMD160,

  PBKDF2: CryptoESExports.PBKDF2,
  EvpKDF: CryptoESExports.EvpKDF,

  AES: CryptoESExports.AES,
  DES: CryptoESExports.DES,
  TripleDES: CryptoESExports.TripleDES,
  Rabbit: CryptoESExports.Rabbit,
  RabbitLegacy: CryptoESExports.RabbitLegacy,
  RC4: CryptoESExports.RC4,
  RC4Drop: CryptoESExports.RC4Drop,
  Blowfish: CryptoESExports.Blowfish,
};

export * from './index.mjs';
export default CryptoES;
