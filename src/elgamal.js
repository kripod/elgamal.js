import { BigInteger as BigInt } from 'jsbn';
import DecryptedValue from './models/decrypted-value';
import EncryptedValue from './models/encrypted-value';
import * as Errors from './errors';
import * as Utils from './utils';

/**
 * Provides methods for the ElGamal cryptosystem.
 */
export default class ElGamal {
  /**
   * Safe prime number.
   * @type {BigInt}
   * @memberof ElGamal
   */
  p;

  /**
   * Generator.
   * @type {BigInt}
   * @memberof ElGamal
   */
  g;

  /**
   * Public key.
   * @type {BigInt}
   * @memberof ElGamal
   */
  y;

  /**
   * Private key.
   * @type {BigInt}
   * @memberof ElGamal
   */
  x;

  static async generateAsync(primeBits = 2048) {
    let q;
    let p;
    do {
      q = await Utils.getBigPrimeAsync(primeBits - 1);
      p = q.shiftLeft(1).add(BigInt.ONE);
    } while (!p.isProbablePrime()); // Ensure that p is a prime

    let g;
    do {
      // Avoid g=2 because of Bleichenbacher's attack
      g = await Utils.getRandomBigIntAsync(new BigInt('3'), p);
    } while (
      g.modPowInt(2, p).equals(BigInt.ONE) ||
      g.modPow(q, p).equals(BigInt.ONE) ||
      // g|p-1
      p.subtract(BigInt.ONE).remainder(g).equals(BigInt.ZERO) ||
      // g^(-1)|p-1 (evades Khadir's attack)
      p.subtract(BigInt.ONE).remainder(g.modInverse(p)).equals(BigInt.ZERO)
    );

    // Generate private key
    const x = await Utils.getRandomBigIntAsync(
      Utils.BIG_TWO,
      p.subtract(BigInt.ONE)
    );

    // Generate public key
    const y = g.modPow(x, p);

    return new ElGamal(p, g, y, x);
  }

  /**
   * Creates a new ElGamal instance.
   * @param {BigInt|string|number} p Safe prime number.
   * @param {BigInt|string|number} g Generator.
   * @param {BigInt|string|number} y Public key.
   * @param {BigInt|string|number} x Private key.
   */
  constructor(p, g, y, x) {
    this.p = Utils.parseBigInt(p);
    this.g = Utils.parseBigInt(g);
    this.y = Utils.parseBigInt(y);
    this.x = Utils.parseBigInt(x);
  }

  /**
   * Encrypts a message.
   * @param {string|BigInt|number} m Piece of data to be encrypted, which must
   * be numerically smaller than `p`.
   * @param {BigInt|string|number} [k] A secret number, chosen randomly in the
   * closed range `[1, p-2]`.
   * @returns {EncryptedValue}
   */
  async encryptAsync(m, k) {
    const tmpKey = Utils.parseBigInt(k) || await Utils.getRandomBigIntAsync(
      BigInt.ONE,
      this.p.subtract(BigInt.ONE)
    );
    const mBi = new DecryptedValue(m).bi;
    const p = this.p;

    const a = this.g.modPow(tmpKey, p);
    const b = this.y.modPow(tmpKey, p).multiply(mBi).remainder(p);

    return new EncryptedValue(a, b);
  }

  /**
   * Decrypts a message.
   * @param {EncryptedValue} m Piece of data to be decrypted.
   * @throws {MissingPrivateKeyError}
   * @returns {DecryptedValue}
   */
  async decryptAsync(m) {
    // TODO: Use a custom error object
    if (!this.x) throw new Errors.MissingPrivateKeyError();

    const p = this.p;
    const r = await Utils.getRandomBigIntAsync(
      Utils.BIG_TWO,
      this.p.subtract(BigInt.ONE)
    );

    const aBlind = this.g.modPow(r, p).multiply(m.a).remainder(p);
    const ax = aBlind.modPow(this.x, p);

    const plaintextBlind = ax.modInverse(p).multiply(m.b).remainder(p);
    const plaintext = this.y.modPow(r, p).multiply(plaintextBlind).remainder(p);

    return new DecryptedValue(plaintext);
  }
}
