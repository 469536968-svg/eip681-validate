// test.mjs — zero-dep test runner for the validator + parser.
// Ground truth is the EIP-681 spec and the four canonical EIP-55 vectors,
// never our own output.
import assert from 'node:assert/strict';
import { validate } from './validate.mjs';
import { toChecksumAddress, isChecksumAddress, parse } from './eip681.mjs';

let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); pass++; console.log('  ok   ' + name); }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + e.message); }
};

console.log('\nEIP-55 canonical vectors (from the spec)');
const V55 = [
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
  '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
];
for (const v of V55) {
  t('checksum is valid: ' + v.slice(0, 10) + '...', () => {
    assert.equal(isChecksumAddress(v), true);
    assert.equal(toChecksumAddress(v.toLowerCase()), v);
  });
}
t('checksum rejects a single flipped case', () => {
  const bad = '0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
  assert.equal(isChecksumAddress(bad), false);
});

console.log('\nvalidator: clean URIs must pass');
const CLEAN = [
  'ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1',
  'ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1?value=1000000000000000000',
  'ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@8453/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000',
];
for (const u of CLEAN) {
  t('ok: ' + u.slice(0, 62), () => {
    const r = validate(u);
    assert.equal(r.errors, 0, JSON.stringify(r.issues));
    assert.equal(r.ok, true);
    assert.ok(r.canonical, 'canonical form expected for a clean URI');
  });
}

console.log('\nvalidator: must catch real mispayment bugs');
t('missing @chainId on an ERC-20 transfer is an ERROR', () => {
  const r = validate('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000');
  assert.equal(r.ok, false);
  assert.ok(r.issues.some((i) => i.code === 'missing-chain-id' && i.severity === 'error'));
});

t('value/uint256 disagreeing is an ERROR', () => {
  const r = validate('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&value=100&uint256=999');
  assert.ok(r.issues.some((i) => i.code === 'value-uint256-conflict'), JSON.stringify(r.issues));
});

t('scientific notation is flagged', () => {
  const r = validate('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1?value=1e18');
  assert.ok(r.issues.some((i) => i.code === 'value-scientific-notation'));
});

t('unknown parameter is flagged', () => {
  const r = validate('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1?memo=hi');
  assert.ok(r.issues.some((i) => i.code === 'unknown-parameter' && /memo/.test(i.message)));
});

t('duplicate parameter is flagged', () => {
  const r = validate('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1?value=1&value=2');
  assert.ok(r.issues.some((i) => i.code === 'duplicate-parameter'));
});

t('mixed-case but wrong checksum is an ERROR', () => {
  const r = validate('ethereum:0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1');
  assert.ok(r.issues.some((i) => i.code === 'target-checksum-invalid' && i.severity === 'error'),
    JSON.stringify(r.issues));
});

t('zero address is rejected', () => {
  const r = validate('ethereum:0x0000000000000000000000000000000000000000@1');
  assert.equal(r.ok, false);
});

t('wrong scheme is rejected', () => {
  const r = validate('bitcoin:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1');
  assert.equal(r.ok, false);
});

t('empty input never throws', () => {
  assert.equal(validate('').ok, false);
  assert.equal(validate(null).ok, false);
  assert.equal(validate(undefined).ok, false);
});

t('garbage never throws', () => {
  for (const g of ['not a uri', 'ethereum:', 'ethereum:0xzz@1', ':::', 'ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@notanumber']) {
    const r = validate(g);
    assert.equal(typeof r.ok, 'boolean');
  }
});

console.log('\nvalidator: canonical output round-trips');
t('canonical re-validates clean', () => {
  const r = validate('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000');
  assert.ok(r.canonical);
  const again = validate(r.canonical);
  assert.equal(again.errors, 0, JSON.stringify(again.issues));
});

console.log('\nparser: BigInt amount math is exact');
t('1e18 token units is exact', () => {
  const p = parse('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000000000000000');
  assert.equal(p.amount, 1000000000000000000n);
});
t('uint256 max does not lose precision', () => {
  const max = '115792089237316195423570985008687907853269984665640564039457584007913129639935';
  const p = parse('ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed@1/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=' + max);
  assert.equal(p.amount, BigInt(max));
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
