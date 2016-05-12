import ElGamal from './../src';
import forge from 'node-forge';
import { BigInteger } from 'jsbn';

/*
// 55212756559928793179526928356344250630685495376116389993318240227888367461537
const bi = new BigInteger('55212756559928793179526928356344250630685495376116389993318240227888367461537');
console.log(bi.toString());
console.log(bi.shiftLeft(1).add(BigInteger.ONE).toString());
*/

async function run() {
  console.time('example');
  const eg = await ElGamal.generateAsync(256);
  console.timeEnd('example');
}

run();
