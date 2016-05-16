import Promise from 'bluebird';
import crypto from 'crypto';
import { BigInteger as BigInt } from 'jsbn';

Promise.promisifyAll(crypto);

export const BIG_TWO = new BigInt('2');

/**
 * Returns a random BigInt with the given amount of bits.
 * @param {BigInt} bits Number of bits in the output.
 * @returns {BigInt}
 */
export async function getRandomNbitBigIntAsync(bits) {
  // Generate random bytes with the length of the range
  const buf = await crypto.randomBytesAsync(Math.ceil(bits / 8));
  const bi = new BigInt(buf.toString('hex'), 16);

  // Trim the result if necessary and then ensure that the highest bit is set
  const trimLength = bi.bitLength() - bits;
  return bi.shiftRight(trimLength > 0 ? trimLength : 0).setBit(bits - 1);
}

/**
 * Returns a random BigInt in the given range.
 * @param {BigInt} min Minimum value (included).
 * @param {BigInt} max Maximum value (excluded).
 * @returns {BigInt}
 */
export async function getRandomBigIntAsync(min, max) {
  const range = max.subtract(min).subtract(BigInt.ONE);

  // Generate random bytes with the length of the range
  const buf = await crypto.randomBytesAsync(range.bitLength() >> 3);

  // Offset the result by the minimum value
  const bi = new BigInt(buf.toString('hex'), 16).add(min);

  // Ensure that the generated value satisfies the given range
  return bi.compareTo(max) < 0 ? bi : getRandomBigIntAsync(min, max);
}

/**
 * Returns a random prime BigInt value.
 * @param {number} bits Number of bits in the output.
 * @returns {BigInt}
 */
export async function getBigPrimeAsync(bits) {
  // Generate a random odd number with the given length
  let bi = (await getRandomNbitBigIntAsync(bits)).or(BigInt.ONE);

  while (!bi.isProbablePrime()) {
    bi = bi.add(BIG_TWO);

    // Sanity check for correct bit length
    if (bi.bitLength() !== bits) {
      return getBigPrimeAsync(bits);
    }
  }

  return bi;
}

/**
 * Parses a BigInt.
 * @param {BigInt|string|number} obj Object to be parsed.
 * @returns {BigInt}
 */
export function parseBigInt(obj) {
  return obj instanceof BigInt ? obj : new BigInt(`${obj}`);
}
