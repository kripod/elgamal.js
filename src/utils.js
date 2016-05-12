import Promise from 'bluebird';
import crypto from 'crypto';
import { BigInteger } from 'jsbn';
import { prime } from 'node-forge';

Promise.promisifyAll(crypto);
Promise.promisifyAll(prime);

/**
 * Returns a random prime BigInteger value.
 * @param {number} bits Number of bits in the output.
 * @returns {BigInteger}
 */
export async function getBigPrimeAsync(bits) {
  const bi = await prime.generateProbablePrimeAsync(bits);
  return new BigInteger(bi.toString());
}

/**
 * Returns a random BigInteger in the given range.
 * @param {BigInteger} min Minimum value (included).
 * @param {BigInteger} max Maximum value (excluded).
 */
export async function getRandomBigIntegerAsync(min, max) {
  const range = max.subtract(min).subtract(BigInteger.ONE);

  // Generate random bytes with the length of the range
  const buf = await crypto.randomBytesAsync(range.bitLength() >> 3);

  // Offset the result by the minimum value
  const bi = new BigInteger(buf.toString('hex'), 16).add(min);

  // Ensure that the generated value satisfies the given range
  return bi.compareTo(max) < 0 ? bi : getRandomBigIntegerAsync(min, max);
}
