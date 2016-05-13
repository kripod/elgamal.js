import { BigInteger } from 'jsbn';
import ElGamal from './../src';

async function run() {
  console.time('example');

  const eg = await ElGamal.generateAsync(2048);
  console.log(eg);

  const obj = await eg.encryptAsync(new BigInteger('672631631884797268976048'));
  console.log(obj);

  console.timeEnd('example');
}

run();
