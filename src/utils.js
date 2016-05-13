import Promise from 'bluebird';
import crypto from 'crypto';
import { BigInteger } from 'jsbn';

Promise.promisifyAll(crypto);

export const BIG_TWO = new BigInteger('2');

/**
 * Returns a random BigInteger with the given amount of bits.
 * @param {BigInteger} bits Number of bits in the output.
 * @returns {BigInteger}
 */
export async function getRandomNbitBigIntegerAsync(bits) {
  // Generate random bytes with the length of the range
  const buf = await crypto.randomBytesAsync(Math.ceil(bits / 8));
  const bi = new BigInteger(buf.toString('hex'), 16);

  // Trim the result if necessary and then ensure that the highest bit is set
  const trimLength = bi.bitLength() - bits;
  return bi.shiftRight(trimLength > 0 ? trimLength : 0).setBit(bits - 1);
}

/**
 * Returns a random BigInteger in the given range.
 * @param {BigInteger} min Minimum value (included).
 * @param {BigInteger} max Maximum value (excluded).
 * @returns {BigInteger}
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

/**
 * Returns a random prime BigInteger value.
 * @param {number} bits Number of bits in the output.
 * @returns {BigInteger}
 */
export async function getBigPrimeAsync(bits) {
  // Generate a random odd number with the given length
  let bi = (await getRandomNbitBigIntegerAsync(bits)).or(BigInteger.ONE);

  while (!bi.isProbablePrime()) {
    bi = bi.add(BIG_TWO);

    // Sanity check for correct bit length
    if (bi.bitLength() !== bits) {
      return getBigPrimeAsync(bits);
    }
  }

  return bi;
}
