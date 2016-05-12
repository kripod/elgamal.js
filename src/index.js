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
   * Private key.
   * @type {BigInteger}
   * @memberof ElGamal
   */
  x;

  /**
   * Public key.
   * @type {BigInteger}
   * @memberof ElGamal
   */
  y;

  static async generateAsync(primeBits = 2048) {
    let q;
    let p;
    // TODO: Make this loop faster
    do {
      q = await Utils.getBigPrimeAsync(primeBits - 1);
      p = q.shiftLeft(BigInteger.ONE).add(BigInteger.ONE);
    } while (!p.isProbablePrime()); // Ensure that p is a prime

    console.log(`q: ${q}`);
    console.log(`p: ${p}`);

    let g;
    do {
      // Avoid g = 2 because of Bleichenbacher's attack
      g = await Utils.getRandomBigIntegerAsync(new BigInteger('3'), p);
      console.log(`g: ${g}`);

      if (g.modPowInt(new BigInteger('2'), p).equals(BigInteger.ONE)) continue;
      if (g.modPow(q, p).equals(BigInteger.ONE)) continue;

      // Discard g if it divides p - 1
      if (p.subtract(BigInteger.ONE).remainder(g).equals(BigInteger.ZERO)) {
        continue;
      }

      // Discard g if g^(-1) divides p - 1 because of Khadir's attack
      // TODO: Check whether the implementation below is correct
      const gInv = g.modInverse(p);
      if (p.subtract(BigInteger.ONE).remainder(gInv).equals(BigInteger.ZERO)) {
        continue;
      }

      break;
    } while (true);

    // Generate private key
    const x = await Utils.getRandomBigIntegerAsync(
      new BigInteger('2'),
      p.subtract(BigInteger.ONE)
    );

    return new ElGamal(p, g, x);
  }

  /**
   * @param {BigInteger} p Safe prime number.
   * @param {BigInteger} g Generator.
   * @param {BigInteger} x Private key.
   */
  constructor(p, g, x) {
    // Generate public key
    this.y = g.modPow(x, p);
  }
}
