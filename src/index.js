import { BigInteger } from 'jsbn';
import * as Utils from './utils';

export default class ElGamal {
  /**
   * Safe prime number.
   * @type {BigInteger}
   * @memberof ElGamal
   */
  p;

  /**
   * Generator.
   * @type {BigInteger}
   * @memberof ElGamal
   */
  g;

  /**
   * Public key.
   * @type {BigInteger}
   * @memberof ElGamal
   */
  y;

  /**
   * Private key.
   * @type {BigInteger}
   * @memberof ElGamal
   */
  x;

  static async generateAsync(primeBits = 2048) {
    let q;
    let p;
    do {
      q = await Utils.getBigPrimeAsync(primeBits - 1);
      p = q.shiftLeft(1).add(BigInteger.ONE);
    } while (!p.isProbablePrime()); // Ensure that p is a prime

    let g;
    do { // eslint-disable-line no-constant-condition
      // Avoid g = 2 because of Bleichenbacher's attack
      g = await Utils.getRandomBigIntegerAsync(new BigInteger('3'), p);

      if (g.modPowInt(2, p).equals(BigInteger.ONE)) continue;
      if (g.modPow(q, p).equals(BigInteger.ONE)) continue;

      // Discard g if it divides p - 1
      if (p.subtract(BigInteger.ONE).remainder(g).equals(BigInteger.ZERO)) {
        continue;
      }

      // Discard g if g^(-1) divides p - 1 because of Khadir's attack
      const gInv = g.modInverse(p);
      if (p.subtract(BigInteger.ONE).remainder(gInv).equals(BigInteger.ZERO)) {
        continue;
      }

      break;
    } while (true);

    // Generate private key
    const x = await Utils.getRandomBigIntegerAsync(
      Utils.BIG_TWO,
      p.subtract(BigInteger.ONE)
    );

    // Generate public key
    const y = g.modPow(x, p);

    return new ElGamal(p, g, y, x);
  }

  /**
   * Creates a new ElGamal instance.
   * @param {BigInteger} p Safe prime number.
   * @param {BigInteger} g Generator.
   * @param {BigInteger} y Public key.
   * @param {BigInteger} x Private key.
   */
  constructor(p, g, y, x) {
    this.p = p;
    this.g = g;
    this.y = y;
    this.x = x;
  }

  /**
   * Encrypts a message.
   * @param {string|BigInteger} m Piece of data to be encrypted, which must be
   * numerically smaller than `p`.
   * @param {BigInteger} [k] A secret number, chosen randomly in the closed
   * range `[1, p - 2]`.
   */
  async encryptAsync(m, k) {
    const tmpKey = k || await Utils.getRandomBigIntegerAsync(
      BigInteger.ONE,
      this.p.subtract(BigInteger.ONE)
    );
    const p = this.p;

    let mBi = m;
    if (typeof m === 'string') {
      // Convert `m` to BigInteger
      mBi = new BigInteger(new Buffer(m).toString('hex'), 16);
    }

    const a = this.g.modPow(tmpKey, p);
    const b = this.y.modPow(tmpKey, p).multiply(mBi).remainder(p);

    // TODO: Make the result convertable (to a string)
    return { a, b };
  }

  /**
   * Decrypts a message.
   * @param {string|BigInteger} m Piece of data to be decrypted.
   * @returns {string|BigInteger}
   */
  async decryptAsync(m) {
    // TODO: Use a custom error object
    if (!this.x) throw new Error('Private key not available.');

    const p = this.p;
    const r = await Utils.getRandomBigIntegerAsync(
      2,
      this.p.subtract(BigInteger.ONE)
    );

    const aBlind = this.g.modPow(r, p).multiply(m.a).remainder(p);
    const ax = aBlind.modPow(this.x, p);

    const plaintextBlind = ax.modInverse(p).multiply(m.b).remainder(p);
    const plaintext = this.y.modPow(r, p).multiply(plaintextBlind).remainder(p);

    return plaintext;
  }
}
