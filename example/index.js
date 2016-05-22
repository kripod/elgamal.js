import { BigInteger as BigInt } from 'jsbn';
import ElGamal from './../src';

async function run() {
  console.time('example');

  const eg = await ElGamal.generateAsync();

  const secret = 'The quick brown fox jumps over the lazy dog';
  const encrypted = await eg.encryptAsync(secret);
  const decrypted = await eg.decryptAsync(encrypted);

  console.log(decrypted.toString() === secret);

  console.timeEnd('example');
}

run();
