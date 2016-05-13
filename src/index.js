import { BigInteger } from 'jsbn';
import _ from 'lodash';
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

    console.log(`q: ${q}`);
    console.log(`p: ${p}`);

    let g;
    do { // eslint-disable-line no-constant-condition
      // Avoid g = 2 because of Bleichenbacher's attack
      g = await Utils.getRandomBigIntegerAsync(new BigInteger('3'), p);
      console.log(`g: ${g}`);

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
    this.x = x;

    // Generate public key
    this.y = g.modPow(x, p);
  }

  /**
   * Encrypts a message.
   * @param {string|number} m Piece of data to be encrypted, which must be
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

    if (_.isString(m)) {
      // TODO: Convert m from string to BigInteger if necessary
    }

    const a = this.g.modPow(tmpKey, p);
    const b = this.y.modPow(tmpKey, p).multiply(m).remainder(p);

    // TODO: Make the result convertable (to a string)
    return { a, b };
  }
}
