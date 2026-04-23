import { Base, BufferedBlockAlgorithm, Hasher, HasherCfg, WordArray } from "./core.mjs";

//#region src/cipher-core.d.ts

/**
 * Configuration options for ciphers
 */
interface CipherCfg {
  /** Initialization vector */
  iv?: WordArray;
  /** Block cipher mode */
  mode?: typeof BlockCipherMode;
  /** Padding strategy */
  padding?: Padding;
  /** Formatter for serialization */
  format?: Format;
  /** Key derivation function */
  kdf?: Kdf;
  /** Salt for key derivation */
  salt?: WordArray | string;
  /** Hasher for key derivation */
  hasher?: new (cfg?: HasherCfg) => Hasher;
  /** Drop value for RC4Drop */
  drop?: number;
}
/**
 * Cipher parameters configuration
 */
interface CipherParamsCfg {
  /** The raw ciphertext */
  ciphertext?: WordArray;
  /** The key to this ciphertext */
  key?: WordArray;
  /** The IV used in the ciphering operation */
  iv?: WordArray;
  /** The salt used with a key derivation function */
  salt?: WordArray;
  /** The cipher algorithm */
  algorithm?: typeof Cipher;
  /** The block mode used in the ciphering operation */
  mode?: typeof BlockCipherMode;
  /** The padding scheme used in the ciphering operation */
  padding?: Padding;
  /** The block size of the cipher */
  blockSize?: number;
  /** The default formatting strategy */
  formatter?: Format;
  /** Allow additional properties */
  [key: string]: unknown;
}
/**
 * Cipher object interface
 */
interface CipherObj {
  /**
   * Encrypts a message
   * @param message - The message to encrypt
   * @param key - The key
   * @param cfg - Configuration options
   * @returns The encrypted cipher params
   */
  encrypt(message: WordArray | string, key: WordArray | string, cfg?: CipherCfg): CipherParams;
  /**
   * Decrypts ciphertext
   * @param ciphertext - The ciphertext to decrypt
   * @param key - The key
   * @param cfg - Configuration options
   * @returns The decrypted plaintext
   */
  decrypt(ciphertext: CipherParams | CipherParamsCfg | string, key: WordArray | string, cfg?: CipherCfg): WordArray;
}
/**
 * Padding strategy interface
 */
interface Padding {
  /**
   * Pads data to a multiple of blockSize
   * @param data - The data to pad
   * @param blockSize - The block size in words
   */
  pad(data: WordArray, blockSize: number): void;
  /**
   * Unpads data
   * @param data - The data to unpad
   */
  unpad(data: WordArray): void;
}
/**
 * Format strategy interface
 */
interface Format {
  /**
   * Converts cipher params to string
   * @param cipherParams - The cipher params
   * @returns The string representation
   */
  stringify(cipherParams: CipherParams): string;
  /**
   * Parses string to cipher params
   * @param str - The string to parse
   * @param cipher - The cipher class
   * @returns The cipher params
   */
  parse(str: string, cipher?: any): CipherParams;
}
/**
 * Key derivation function interface
 */
interface Kdf {
  /**
   * Derives key and IV from password
   * @param password - The password
   * @param keySize - Key size in words
   * @param ivSize - IV size in words
   * @param salt - Optional salt
   * @param hasher - Optional hasher
   * @returns The derived cipher params
   */
  execute(password: string, keySize: number, ivSize: number, salt?: WordArray | string, hasher?: new (cfg?: HasherCfg) => Hasher): CipherParams;
}
/**
 * Abstract base cipher template.
 * Provides the foundation for all encryption and decryption algorithms.
 *
 * @property keySize - This cipher's key size in words (default: 4 = 128 bits)
 * @property ivSize - This cipher's IV size in words (default: 4 = 128 bits)
 * @property _ENC_XFORM_MODE - A constant representing encryption mode
 * @property _DEC_XFORM_MODE - A constant representing decryption mode
 */
declare abstract class Cipher extends BufferedBlockAlgorithm {
  /** Encryption mode constant */
  static readonly _ENC_XFORM_MODE: number;
  /** Decryption mode constant */
  static readonly _DEC_XFORM_MODE: number;
  /** Default key size in words (128 bits) */
  static keySize: number;
  /** Default IV size in words (128 bits) */
  static ivSize: number;
  /** Configuration options */
  cfg: CipherCfg;
  /** Transform mode (encryption or decryption) */
  protected _xformMode: number;
  /** The key */
  protected _key: WordArray;
  /** Block size in words */
  blockSize: number;
  /**
   * Initializes a newly created cipher.
   *
   * @param xformMode - Either the encryption or decryption transformation mode constant
   * @param key - The key
   * @param cfg - Configuration options to use for this operation
   * @example
   * ```javascript
   * const cipher = new AESAlgo(
   *   Cipher._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray }
   * );
   * ```
   */
  constructor(xformMode: number, key: WordArray, cfg?: CipherCfg);
  /**
   * Creates this cipher in encryption mode.
   *
   * @param key - The key
   * @param cfg - Configuration options to use for this operation
   * @returns A cipher instance
   * @static
   * @example
   * ```javascript
   * const cipher = AESAlgo.createEncryptor(keyWordArray, { iv: ivWordArray });
   * ```
   */
  static createEncryptor<T extends Cipher>(this: new (xformMode: number, key: WordArray, cfg?: CipherCfg) => T, key: WordArray, cfg?: CipherCfg): T;
  /**
   * Creates this cipher in decryption mode.
   *
   * @param key - The key
   * @param cfg - Configuration options to use for this operation
   * @returns A cipher instance
   * @static
   * @example
   * ```javascript
   * const cipher = AESAlgo.createDecryptor(keyWordArray, { iv: ivWordArray });
   * ```
   */
  static createDecryptor<T extends Cipher>(this: new (xformMode: number, key: WordArray, cfg?: CipherCfg) => T, key: WordArray, cfg?: CipherCfg): T;
  /**
   * Factory method to create a cipher instance.
   *
   * @param xformMode - Transform mode
   * @param key - The key
   * @param cfg - Configuration options
   * @returns A cipher instance
   * @static
   */
  static create<T extends Cipher>(this: new (xformMode: number, key: WordArray, cfg?: CipherCfg) => T, xformMode: number, key: WordArray, cfg?: CipherCfg): T;
  static create<T extends Base>(this: new (...args: any[]) => T, ...args: any[]): T;
  /**
   * Creates shortcut functions to a cipher's object interface.
   *
   * @param SubCipher - The cipher to create a helper for
   * @returns An object with encrypt and decrypt shortcut functions
   * @static
   * @example
   * ```javascript
   * const AES = Cipher._createHelper(AESAlgo);
   * ```
   */
  static _createHelper(SubCipher: typeof Cipher): CipherObj;
  /**
   * Resets this cipher to its initial state.
   *
   * @example
   * ```javascript
   * cipher.reset();
   * ```
   */
  reset(): void;
  /**
   * Adds data to be encrypted or decrypted.
   *
   * @param dataUpdate - The data to encrypt or decrypt
   * @returns The data after processing
   * @example
   * ```javascript
   * const encrypted = cipher.process('data');
   * const encrypted = cipher.process(wordArray);
   * ```
   */
  process(dataUpdate: WordArray | string): WordArray;
  /**
   * Finalizes the encryption or decryption process.
   * Note that the finalize operation is effectively a destructive, read-once operation.
   *
   * @param dataUpdate - The final data to encrypt or decrypt
   * @returns The data after final processing
   * @example
   * ```javascript
   * const encrypted = cipher.finalize();
   * const encrypted = cipher.finalize('data');
   * const encrypted = cipher.finalize(wordArray);
   * ```
   */
  finalize(dataUpdate?: WordArray | string): WordArray;
  /**
   * Reset implementation for concrete cipher
   * Must be implemented by subclasses
   */
  protected abstract _doReset(): void;
  /**
   * Finalize implementation for concrete cipher
   * Must be implemented by subclasses
   */
  protected abstract _doFinalize(): WordArray;
  /**
   * Encrypt a block of data
   * Must be implemented by block ciphers
   */
  encryptBlock?(words: number[], offset: number): void;
  /**
   * Decrypt a block of data
   * Must be implemented by block ciphers
   */
  decryptBlock?(words: number[], offset: number): void;
}
/**
 * Abstract base stream cipher template.
 * Stream ciphers process data one unit at a time rather than in blocks.
 *
 * @property blockSize - The number of 32-bit words this cipher operates on (default: 1 = 32 bits)
 */
declare abstract class StreamCipher extends Cipher {
  blockSize: number;
  constructor(xformMode: number, key: WordArray, cfg?: CipherCfg);
  protected _doFinalize(): WordArray;
}
/**
 * Abstract base block cipher mode template.
 * Defines how multiple blocks are processed together.
 */
declare class BlockCipherMode extends Base {
  /** The cipher instance */
  _cipher: Cipher;
  /** The initialization vector */
  _iv?: number[];
  /** The previous block (for chaining modes) */
  _prevBlock?: number[];
  /**
   * Initializes a newly created mode.
   *
   * @param cipher - A block cipher instance
   * @param iv - The IV words
   * @example
   * ```javascript
   * const mode = new CBCMode(cipher, iv.words);
   * ```
   */
  constructor(cipher: Cipher, iv?: number[]);
  /**
   * Creates this mode for encryption.
   *
   * @param cipher - A block cipher instance
   * @param iv - The IV words
   * @returns The mode instance
   * @static
   * @example
   * ```javascript
   * const mode = CBC.createEncryptor(cipher, iv.words);
   * ```
   */
  static createEncryptor(cipher: Cipher, iv?: number[]): BlockCipherMode;
  /**
   * Creates this mode for decryption.
   *
   * @param cipher - A block cipher instance
   * @param iv - The IV words
   * @returns The mode instance
   * @static
   * @example
   * ```javascript
   * const mode = CBC.createDecryptor(cipher, iv.words);
   * ```
   */
  static createDecryptor(cipher: Cipher, iv?: number[]): BlockCipherMode;
  /**
   * Process a block of data
   * Must be implemented by concrete modes
   */
  processBlock(_words: number[], _offset: number): void;
}
/**
 * CBC Encryptor
 */
declare class CBCEncryptor extends BlockCipherMode {
  /**
   * Processes the data block at offset.
   *
   * @param words - The data words to operate on
   * @param offset - The offset where the block starts
   * @example
   * ```javascript
   * mode.processBlock(data.words, offset);
   * ```
   */
  processBlock(words: number[], offset: number): void;
}
/**
 * CBC Decryptor
 */
declare class CBCDecryptor extends BlockCipherMode {
  /**
   * Processes the data block at offset.
   *
   * @param words - The data words to operate on
   * @param offset - The offset where the block starts
   * @example
   * ```javascript
   * mode.processBlock(data.words, offset);
   * ```
   */
  processBlock(words: number[], offset: number): void;
}
/**
 * Cipher Block Chaining mode.
 * Each block is XORed with the previous ciphertext block before encryption.
 */
declare class CBC extends BlockCipherMode {
  /** CBC Encryptor */
  static Encryptor: typeof CBCEncryptor;
  /** CBC Decryptor */
  static Decryptor: typeof CBCDecryptor;
}
/**
 * PKCS #5/7 padding strategy.
 * Pads data with bytes all of the same value as the count of padding bytes.
 */
declare const Pkcs7: Padding;
/**
 * Abstract base block cipher template.
 * Block ciphers process data in fixed-size blocks.
 *
 * @property blockSize - The number of 32-bit words this cipher operates on (default: 4 = 128 bits)
 */
declare abstract class BlockCipher extends Cipher {
  /** Block mode instance */
  protected _mode?: BlockCipherMode & {
    __creator?: Function;
  };
  /**
   * Initializes a newly created block cipher.
   *
   * @param xformMode - Transform mode
   * @param key - The key
   * @param cfg - Configuration options
   */
  constructor(xformMode: number, key: WordArray, cfg?: CipherCfg);
  reset(): void;
  protected _doProcessBlock(words: number[], offset: number): void;
  /**
   * Encrypt a block of data
   * Must be implemented by block ciphers
   */
  abstract encryptBlock(words: number[], offset: number): void;
  /**
   * Decrypt a block of data
   * Must be implemented by block ciphers
   */
  abstract decryptBlock(words: number[], offset: number): void;
  protected _doFinalize(): WordArray;
}
/**
 * A collection of cipher parameters.
 * Encapsulates all the parameters used in a cipher operation.
 *
 * @property ciphertext - The raw ciphertext
 * @property key - The key to this ciphertext
 * @property iv - The IV used in the ciphering operation
 * @property salt - The salt used with a key derivation function
 * @property algorithm - The cipher algorithm
 * @property mode - The block mode used in the ciphering operation
 * @property padding - The padding scheme used in the ciphering operation
 * @property blockSize - The block size of the cipher
 * @property formatter - The default formatting strategy
 */
declare class CipherParams extends Base implements CipherParamsCfg {
  ciphertext?: WordArray;
  key?: WordArray;
  iv?: WordArray;
  salt?: WordArray;
  algorithm?: typeof Cipher;
  mode?: typeof BlockCipherMode;
  padding?: Padding;
  blockSize?: number;
  formatter?: Format;
  [key: string]: unknown;
  /**
   * Initializes a newly created cipher params object.
   *
   * @param cipherParams - An object with any of the possible cipher parameters
   * @example
   * ```javascript
   * const cipherParams = new CipherParams({
   *   ciphertext: ciphertextWordArray,
   *   key: keyWordArray,
   *   iv: ivWordArray,
   *   salt: saltWordArray,
   *   algorithm: AESAlgo,
   *   mode: CBC,
   *   padding: Pkcs7,
   *   blockSize: 4,
   *   formatter: OpenSSLFormatter
   * });
   * ```
   */
  constructor(cipherParams?: CipherParamsCfg);
  /**
   * Factory method to create cipher params
   *
   * @param cipherParams - The cipher parameters
   * @returns A new CipherParams instance
   * @static
   */
  static create(cipherParams?: CipherParamsCfg): CipherParams;
  static create<T extends CipherParams>(this: new (...args: any[]) => T, ...args: any[]): T;
  /**
   * Converts this cipher params object to a string.
   *
   * @param formatter - The formatting strategy to use
   * @returns The stringified cipher params
   * @throws Error if neither the formatter nor the default formatter is set
   * @example
   * ```javascript
   * const string = cipherParams.toString();
   * const string = cipherParams.toString(OpenSSLFormatter);
   * ```
   */
  toString(formatter?: Format): string;
}
/**
 * OpenSSL formatting strategy.
 * Formats cipher params in OpenSSL-compatible format.
 */
declare const OpenSSLFormatter: Format;
/**
 * A cipher wrapper that returns ciphertext as a serializable cipher params object.
 * Handles the serialization and deserialization of cipher operations.
 */
declare class SerializableCipher extends Base {
  /** Configuration options */
  static cfg: {
    format: Format;
  };
  /**
   * Encrypts a message.
   *
   * @param cipher - The cipher algorithm to use
   * @param message - The message to encrypt
   * @param key - The key
   * @param cfg - Configuration options to use for this operation
   * @returns A cipher params object
   * @static
   * @example
   * ```javascript
   * const ciphertextParams = SerializableCipher.encrypt(AESAlgo, message, key);
   * const ciphertextParams = SerializableCipher.encrypt(AESAlgo, message, key, { iv: iv });
   * ```
   */
  static encrypt(cipher: typeof Cipher, message: WordArray | string, key: WordArray | string, cfg?: CipherCfg): CipherParams;
  /**
   * Decrypts serialized ciphertext.
   *
   * @param cipher - The cipher algorithm to use
   * @param ciphertext - The ciphertext to decrypt
   * @param key - The key
   * @param cfg - Configuration options to use for this operation
   * @returns The plaintext
   * @static
   * @example
   * ```javascript
   * const plaintext = SerializableCipher.decrypt(AESAlgo, formattedCiphertext, key, { iv: iv });
   * const plaintext = SerializableCipher.decrypt(AESAlgo, ciphertextParams, key, { iv: iv });
   * ```
   */
  static decrypt(cipher: typeof Cipher, ciphertext: CipherParams | CipherParamsCfg | string, key: WordArray | string, cfg?: CipherCfg): WordArray;
  /**
   * Converts serialized ciphertext to CipherParams.
   *
   * @param ciphertext - The ciphertext
   * @param format - The formatting strategy to use to parse serialized ciphertext
   * @returns The unserialized ciphertext
   * @static
   * @private
   */
  protected static _parse(ciphertext: CipherParams | CipherParamsCfg | string, format?: Format): CipherParams;
}
/**
 * OpenSSL key derivation function.
 * Derives a key and IV from a password using the OpenSSL method.
 */
declare const OpenSSLKdf: Kdf;
/**
 * A serializable cipher wrapper that derives the key from a password.
 * Returns ciphertext as a serializable cipher params object.
 */
declare class PasswordBasedCipher extends SerializableCipher {
  /** Configuration options */
  static cfg: {
    format: Format;
  } & {
    kdf: Kdf;
  };
  /**
   * Encrypts a message using a password.
   *
   * @param cipher - The cipher algorithm to use
   * @param message - The message to encrypt
   * @param password - The password
   * @param cfg - Configuration options to use for this operation
   * @returns A cipher params object
   * @static
   * @example
   * ```javascript
   * const ciphertextParams = PasswordBasedCipher.encrypt(AESAlgo, message, 'password');
   * ```
   */
  static encrypt(cipher: typeof Cipher, message: WordArray | string, password: string, cfg?: CipherCfg): CipherParams;
  /**
   * Decrypts serialized ciphertext using a password.
   *
   * @param cipher - The cipher algorithm to use
   * @param ciphertext - The ciphertext to decrypt
   * @param password - The password
   * @param cfg - Configuration options to use for this operation
   * @returns The plaintext
   * @static
   * @example
   * ```javascript
   * const plaintext = PasswordBasedCipher.decrypt(AESAlgo, formattedCiphertext, 'password');
   * ```
   */
  static decrypt(cipher: typeof Cipher, ciphertext: CipherParams | CipherParamsCfg | string, password: string, cfg?: CipherCfg): WordArray;
}
//#endregion
export { BlockCipher, BlockCipherMode, CBC, Cipher, CipherCfg, CipherObj, CipherParams, Format, OpenSSLFormatter, OpenSSLKdf, Padding, PasswordBasedCipher, Pkcs7, SerializableCipher, StreamCipher };
//# sourceMappingURL=cipher-core.d.mts.map