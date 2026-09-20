// validate.mjs — EIP-681 conformance report.
//
// Design: eip681.mjs::parse() is the parser (permissive, returns errors[]).
// validate() is the *conformance layer* on top: it surfaces the parser's own
// findings AND adds the interop rules that bite in practice — the ones that
// make one wallet pay and another wallet silently do something else.
//
// Pure. No network. No dependencies.
import { parse, isChecksumAddress, SCHEME, ERC20_TRANSFER } from './eip681.mjs';

const KNOWN_PARAMS = new Set([
  'value', 'uint256', 'gas', 'gasLimit',
  // EIP-681 registers these for the ERC-20 transfer shorthand:
  'address',
]);

const SEVERITY = { error: 'error', warn: 'warn', info: 'info' };

function mk(code, severity, message, hint) {
  return { code, severity, message, ...(hint ? { hint } : {}) };
}

function text(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'bigint') return v.toString();
  return String(v);
}

/**
 * @param {string} uri
 * @returns {{ok:boolean,input:string,errors:number,warnings:number,
 *            issues:Array<{code:string,severity:string,message:string,hint?:string}>,
 *            canonical:string|null, parsed:object|null}}
 */
export function validate(uri) {
  const issues = [];

  if (typeof uri !== 'string' || uri.trim() === '') {
    return finalize(String(uri ?? ''), [
      mk('empty', 'error', 'Empty input: nothing to validate.'),
    ], null, null);
  }

  // parse() never throws; it reports into .errors / .warnings.
  const p = parse(uri);

  // 1. parser findings (authoritative — this is the same code that runs on-chain logic)
  for (const e of p.errors || []) {
    issues.push(mk(e.code || 'parse-error', 'error', e.message || String(e)));
  }
  // The parser also notices a missing chain id, but this layer owns that rule
  // (severity depends on whether the URI is a token transfer). Drop the
  // parser's copy so the report says it once.
  const OWNED = new Set(['no-chain-id']);
  for (const w of p.warnings || []) {
    if (OWNED.has(w.code)) continue;
    issues.push(mk(w.code || 'parse-warning', 'warn', w.message || String(w)));
  }

  // If the URI did not even parse into a target, deeper rules are noise.
  if (!p.target) return finalize(uri, issues, null, p);

  // 2. interop rules the parser intentionally does not enforce
  const isToken = p.functionName === ERC20_TRANSFER || p.isTokenTransfer === true;

  // 2a. chainId presence. For a bare token address this is the #1 mispayment
  //     cause: the same address exists on many chains, and the payer's wallet
  //     picks the network, not the link.
  if (p.chainId === null || p.chainId === undefined) {
    issues.push(mk(
      'missing-chain-id',
      isToken ? 'error' : 'warn',
      'No @chainId in the URI.',
      isToken
        ? 'A token address without a chain is ambiguous; the payer may sign on the wrong network and the transfer becomes irrecoverable.'
        : 'Without @chainId the wallet must guess (usually mainnet, sometimes prompts). Pin it explicitly.',
    ));
  }

  // 2b. value + uint256 together. EIP-681 defines uint256 as an alias of value;
  //     emitting both means two different wallets can send two different amounts.
  const valueText = text(p.params?.value);
  const uintText = text(p.params?.uint256);
  if (valueText !== null && uintText !== null && valueText !== uintText) {
    issues.push(mk(
      'value-uint256-conflict',
      'error',
      `Both "value"=${valueText} and "uint256"=${uintText} are present and differ.`,
      'uint256 is an alias of value in EIP-681. Conflicting copies make the payable amount parser-dependent.',
    ));
  }

  // 2c. scientific notation. Common in JS/TS callers because 1e18 is idiomatic
  //     there, but the spec says decimal integer. Our parser accepts it, so we
  //     downgrade to warn: the URI still works here, but strict parsers reject it.
  if (valueText !== null && /[eE][+-]?\d+/.test(valueText)) {
    issues.push(mk(
      'value-scientific-notation',
      'warn',
      `value="${valueText}" uses scientific notation.`,
      'Spec form is a decimal integer in wei. Use 1000000000000000000 instead of 1e18 for portability.',
    ));
  }

  // 2d. unknown parameters. Silently ignored by wallets, so a link that "works"
  //     in the author's client can carry meaning nobody else reads.
  for (const k of Object.keys(p.params || {})) {
    if (!KNOWN_PARAMS.has(k)) {
      issues.push(mk(
        'unknown-parameter',
        'warn',
        `Parameter "${k}" is not in EIP-681.`,
        'Unknown params are ignored by most wallets. Never use them to carry the amount or recipient.',
      ));
    }
  }

  // 2e. duplicate keys. Precedence is undefined; parsers disagree.
  const q = uri.indexOf('?');
  if (q !== -1) {
    const counts = new Map();
    for (const pair of uri.slice(q + 1).split('&')) {
      const k = decodeURIComponent((pair.split('=')[0] || '').trim());
      if (k) counts.set(k, (counts.get(k) || 0) + 1);
    }
    for (const [k, n] of counts) {
      if (n > 1) {
        issues.push(mk(
          'duplicate-parameter',
          'warn',
          `Parameter "${k}" appears ${n} times.`,
          'Which copy wins is undefined across wallets.',
        ));
      }
    }
  }

  // 2f. EIP-55 on the target. parse() warns on a bad checksum, but a mixed-case
  //     address that fails EIP-55 is a high-signal sign of a hand-edited link
  //     and most strict wallets refuse it outright — promote to error.
  if (typeof p.target === 'string' && p.target.startsWith('0x')) {
    const body = p.target.slice(2);
    const mixed = body !== body.toLowerCase() && body !== body.toUpperCase();
    if (mixed && !isChecksumAddress(p.target)) {
      issues.push(mk(
        'target-checksum-invalid',
        'error',
        `Target ${p.target} is mixed-case but fails the EIP-55 checksum.`,
        'Strict wallets reject this. Either lowercase it or emit the correct checksum.',
      ));
    }
  }

  return finalize(uri, issues, p.canonical ?? null, p);
}

function finalize(input, issues, canonical, parsed) {
  const errors = issues.filter((i) => i.severity === 'error').length;
  const warnings = issues.filter((i) => i.severity === 'warn').length;
  return {
    ok: errors === 0,
    input,
    errors,
    warnings,
    issues,
    // A canonical form is only safe to emit when nothing is wrong.
    canonical: errors === 0 ? canonical : null,
    parsed: parsed ? summarize(parsed) : null,
  };
}

function summarize(p) {
  return {
    scheme: p.scheme ?? null,
    target: p.target ?? null,
    chainId: p.chainId ?? null,
    functionName: p.functionName ?? null,
    isTokenTransfer: p.isTokenTransfer === true,
    recipient: p.recipient ?? null,
    amount: text(p.amount),
    params: Object.fromEntries(
      Object.entries(p.params || {}).map(([k, v]) => [k, text(v)]),
    ),
  };
}

export { KNOWN_PARAMS, SCHEME, SEVERITY };
export default { validate, KNOWN_PARAMS, SEVERITY };
