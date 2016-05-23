/**
 * Stores an ElGamal-encrypted value.
 */
export default class EncryptedValue {
  /**
   * @type BigInt
   * @memberof EncryptedValue
   */
  a;

  /**
   * @type BigInt
   * @memberof EncryptedValue
   */
  b;

  constructor(a, b) {
    this.a = a;
    this.b = b;
  }

  /**
   * Performs homomorphic multiplication of the current and the given value.
   * @param {EncryptedValue} encryptedValue Value to multiply the current value
   * with.
   * @returns {EncryptedValue}
   */
  multiply(encryptedValue) {
    return new EncryptedValue(
      this.a.multiply(encryptedValue.a),
      this.b.multiply(encryptedValue.b)
    );
  }
}
