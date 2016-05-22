# elgamal.js

ElGamal cryptosystem for JavaScript based on the implementation of
[PyCrypto](https://github.com/dlitz/pycrypto).

[![Version (npm)](https://img.shields.io/npm/v/elgamal.svg)](https://npmjs.com/package/elgamal)
[![Build Status](https://img.shields.io/travis/kripod/elgamal.js/master.svg)](https://travis-ci.org/kripod/elgamal.js)
[![Code Coverage](https://img.shields.io/codecov/c/github/kripod/elgamal.js/master.svg)](https://codecov.io/gh/kripod/elgamal.js)
[![Gitter](https://img.shields.io/gitter/room/kripod/elgamal.js.svg)](https://gitter.im/kripod/elgamal.js)

## Getting started

In order to access the provided cryptographic functions, an instance of ElGamal
should be generated or initialized with custom parameters.

``` js
import ElGamal from 'elgamal';

const eg = await ElGamal.generateAsync(); // Recommended way of initialization
const egCustom = new ElGamal(prime, generator, publicKey, privateKey);
```

### Encryption and decryption

```js
const secret = 'The quick brown fox jumps over the lazy dog';
const encrypted = await eg.encryptAsync(secret);
const decrypted = await eg.decryptAsync(encrypted);

console.log(decrypted.toString() === secret); // true
```
