import { BigInteger as BigInt } from 'jsbn';
import test from 'tape';
import ElGamal from './../src';
import * as Errors from './../src/errors';

/* eslint-disable max-len */
const testVectors = {
  256: {
    p: 'ba4caeaaed8cbe952afd2126c63eb3b345d65c2a0a73d2a3ad4138b6d09bd933',
    g: '05',
    y: '60d063600eced7c7c55146020e7a31c4476e9793beaed420fec9e77604cae4ef',
    x: '1d391ba2ee3c37fe1ba175a69b2c73a11238ad77675932',
    k: 'f5893c5bab4131264066f57ab3d8ad89e391a0b68a68a1',
    m: '48656c6c6f207468657265',
    a: '32bfd5f487966cea9e9356715788c491ec515e4ed48b58f0f00971e93aaa5ec7',
    b: '7be8fbff317c93e82fcef9bd515284ba506603fea25d01c0cb874a31f315ee68',
  },
  512: {
    p: 'f1b18ae9f7b4e08fda9a04832f4e919d89462fd31bf12f92791a93519f75076d6ce3942689cdff2f344caff0f82d01864f69f3aecf566c774cbacf728b81a227',
    g: '07',
    y: '688628c676e4f05d630e1be39d0066178ca7aa83836b645de5add359b4825a12b02ef4252e4e6fa9bec1db0be90f6d7c8629cabb6e531f472b2664868156e20c',
    x: '14e60b1bdfd33436c0da8a22fdc14a2ccdbbed0627ce68',
    k: '38dbf14e1f319bda9bab33eeeadcaf6b2ea5250577ace7',
    m: '48656c6c6f207468657265',
    a: '290f8530c2cc312ec46178724f196f308ad4c523ceabb001facb0506bfed676083fe0f27ac688b5c749ab3cb8a80cd6f7094dba421fb19442f5a413e06a9772b',
    b: '1d69aaad1dc50493fb1b8e8721d621d683f3bf1321be21bc4a43e11b40c9d4d9c80de3aac2ab60d31782b16b61112e68220889d53c4c3136ee6f6ce61f8a23a0',
  },
};
/* eslint-enable max-len */

// Evaluate every specified test vector
for (const [bits, vector] of Object.entries(testVectors)) {
  test(`${bits}-bit key generation`, async (t) => {
    const eg = await ElGamal.generateAsync(bits);

    t.equal(eg.p.bitLength(), parseInt(bits, 10));
    t.end();
  });

  const eg = new ElGamal(
    new BigInt(vector.p, 16),
    new BigInt(vector.g, 16),
    new BigInt(vector.y, 16),
    new BigInt(vector.x, 16)
  );

  test(`${bits}-bit BigInt encryption`, async (t) => {
    const encrypted = await eg.encryptAsync(
      new BigInt(vector.m, 16),
      new BigInt(vector.k, 16)
    );

    t.equal(encrypted.a.toString(16), vector.a);
    t.equal(encrypted.b.toString(16), vector.b);
    t.end();
  });

  test(`${bits}-bit BigInt decryption`, async (t) => {
    const decrypted = await eg.decryptAsync({
      a: new BigInt(vector.a, 16),
      b: new BigInt(vector.b, 16),
    });

    t.equal(decrypted.bi.toString(16), vector.m);
    t.end();
  });
}

test('random ElGamal instance creation', async (t) => {
  const eg = await ElGamal.generateAsync();

  test('string conversion', async (tt) => {
    const secret = 'The quick brown fox jumps over the lazy dog';

    const encrypted = await eg.encryptAsync(secret);
    const decrypted = await eg.decryptAsync(encrypted);

    tt.equal(decrypted.toString(), secret);
    tt.end();
  });

  test('number conversion', async (tt) => {
    const secret = 42;

    const encrypted = await eg.encryptAsync(secret);
    const decrypted = await eg.decryptAsync(encrypted);

    tt.equal(decrypted.bi.intValue(), secret);
    tt.end();
  });

  test('homomorphic multiplication', async (tt) => {
    const m1 = new BigInt('43684365279967565');
    const m2 = new BigInt('80916417872157521');
    const m1m2 = m1.multiply(m2);

    const e1 = await eg.encryptAsync(m1);
    const e2 = await eg.encryptAsync(m2);
    const e1e2 = e1.multiply(e2);
    const decrypted = await eg.decryptAsync(e1e2);

    tt.ok(decrypted.bi.equals(m1m2));
    tt.end();
  });

  t.end();
});

test('error handling', async (t) => {
  const secret = new BigInt('42');

  const vector = Object.values(testVectors)[0];
  const eg = new ElGamal(
    new BigInt(vector.p, 16),
    new BigInt(vector.g, 16),
    new BigInt(vector.y, 16)
  );

  const encrypted = await eg.encryptAsync(secret);

  try {
    await eg.decryptAsync(encrypted);
    t.fail();
  } catch (e) {
    t.assert(e instanceof Errors.MissingPrivateKeyError);
  }
  t.end();
});
