/**
 * Stores a value which was decrypted by the ElGamal algorithm.
 */
export default class DecryptedValue {
  /**
   * Decrypted message stored as a BigInt.
   * @type BigInt
   * @memberof DecryptedValue
   */
  m;

  constructor(m) {
    this.m = m;
  }
}
