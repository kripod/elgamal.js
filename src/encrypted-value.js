/**
 * Stores an ElGamal-encrypted value.
 */
export default class EncryptedValue {
  a;
  b;

  constructor(a, b) {
    this.a = a;
    this.b = b;
  }
}
