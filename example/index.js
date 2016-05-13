import ElGamal from './../src';

async function run() {
  console.time('example');
  const eg = await ElGamal.generateAsync(2048);
  console.timeEnd('example');
}

run();
