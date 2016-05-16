import { BigInteger as BigInt } from 'jsbn';
import ElGamal from './../src';

async function run() {
  console.time('example');

  const eg = await ElGamal.generateAsync(2048);
  // console.log(eg);

  const encrypted = await eg.encryptAsync(new BigInt('672631631884797268'));
  console.log(encrypted);

  const decrypted = await eg.decryptAsync(encrypted);
  console.log(decrypted.toString());

  console.timeEnd('example');
}

run();
