import { BigInteger } from 'jsbn';
import ElGamal from './../src';

async function run() {
  console.time('example');

  /*
  const eg = await ElGamal.generateAsync(2048);
  // console.log(eg);

  const encrypted = await eg.encryptAsync(new BigInteger('672631631884797268'));
  console.log(encrypted);

  const decrypted = await eg.decryptAsync(encrypted);
  console.log(decrypted.toString());
  */

  const eg = new ElGamal(
    new BigInteger('BA4CAEAAED8CBE952AFD2126C63EB3B345D65C2A0A73D2A3AD4138B6D09BD933', 16),
    new BigInteger('05', 16),
    new BigInteger('60D063600ECED7C7C55146020E7A31C4476E9793BEAED420FEC9E77604CAE4EF', 16),
    new BigInteger('1D391BA2EE3C37FE1BA175A69B2C73A11238AD77675932', 16)
  );

  console.log(eg);

  const encrypted = await eg.encryptAsync(
    new BigInteger('48656C6C6F207468657265', 16),
    new BigInteger('F5893C5BAB4131264066F57AB3D8AD89E391A0B68A68A1', 16)
  );

  // Assert equality
  console.log(encrypted.a.toString());
  console.log(new BigInteger('32BFD5F487966CEA9E9356715788C491EC515E4ED48B58F0F00971E93AAA5EC7', 16).toString());
  console.log(encrypted.b.toString());
  console.log(new BigInteger('7BE8FBFF317C93E82FCEF9BD515284BA506603FEA25D01C0CB874A31F315EE68', 16).toString());

  console.timeEnd('example');
}

run();
