import ErrorBase from 'es6-error';

/**
 * An error which gets thrown when an attempt is made to decrypt data without
 * specifying a private key.
 */
export class MissingPrivateKeyError extends ErrorBase {
  constructor() {
    super('No private key was specified for data decryption.');
  }
}
