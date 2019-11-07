const crypto = require('crypto');
const original = require('./original');
const rlbox = require('./rlbox');

const Benchmark = require('benchmark');
Benchmark.options.delay = 5;
Benchmark.options.initCount = 10;

{
  Benchmark.options.minSamples = 1000;
  const suite = new Benchmark.Suite('genSaltSync');
  suite.add('rlbox-genSaltSync', () => {
    rlbox.genSaltSync();
  })
  .add('original-genSaltSync', () => {
    original.genSaltSync();
  })
  .on('cycle', (event) => {
    console.log(String(event.target));
  })
  .on('complete', function () {
    console.log(`DONE: ${this[1].name}/${this[0].name} = ${(this[1].hz/this[0].hz)}`);
  })
  .run({ async: false });
}

{
  Benchmark.options.minSamples = 100; // Hashing is pretty slow
  const suite = new Benchmark.Suite('hashSync');
  // generate sensible random password
  const hash = crypto.randomFillSync(Buffer.alloc(32)).toString('hex');
  const salt = original.genSaltSync();
  suite.add('rlbox-hashSync', () => {
    rlbox.hashSync(hash, salt);
  })
  .add('original-hashSync', () => {
    original.hashSync(hash, salt);
  })
  .on('cycle', (event) => {
    console.log(String(event.target));
  })
  .on('complete', function () {
    console.log(`DONE: ${this[1].name}/${this[0].name} = ${(this[1].hz/this[0].hz)}`);
  })
  .run({ async: false });
}

{
  Benchmark.options.minSamples = 1000;
  const suite = new Benchmark.Suite('genSalt');
  suite.add('rlbox-genSalt', {
    defer: true,
    fn: (d) => { rlbox.genSalt(() => { d.resolve(); }); }
  })
  .add('original-genSalt', {
    defer: true,
    fn: (d) => { original.genSalt(() => { d.resolve(); }); }
  })
  .on('cycle', (event) => {
    console.log(String(event.target));
  })
  .on('complete', function () {
    console.log(`DONE: ${this[1].name}/${this[0].name} = ${(this[1].hz/this[0].hz)}`);
  })
  .run({ async: false });
}

{
  Benchmark.options.minSamples = 100; // Hashing is pretty slow
  const suite = new Benchmark.Suite('hash');
  // generate sensible random password
  const hash = crypto.randomFillSync(Buffer.alloc(32)).toString('hex');
  const salt = original.genSaltSync();
  suite.add('rlbox-hash', { 
    defer: true,
    fn: (d) => { rlbox.hash(hash, salt, () => { d.resolve(); }); }
  })
  .add('original-hash', { 
    defer: true,
    fn: (d) => { original.hash(hash, salt, () => { d.resolve(); }); }
  })
  .on('cycle', (event) => {
    console.log(String(event.target));
  })
  .on('complete', function () {
    console.log(`DONE: ${this[1].name}/${this[0].name} = ${(this[1].hz/this[0].hz)}`);
  })
  .run({ async: true });
}
