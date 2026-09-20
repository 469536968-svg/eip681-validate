// eip681.mjs — strict EIP-681 payment-request URI parser, validator and formatter.
// Zero dependencies. Pure ES module. Runs in Node >= 18 and in browsers.
//
// Why this exists: the token-transfer form of EIP-681 is easy to emit and easy to
// get subtly wrong. A URI that names an ERC-20 contract but omits `uint256` is
// parsed by some wallets as an *open-ended* transfer the user fills in, and by
// others as a fixed transfer of zero. A URI with no chain id is ambiguous the
// moment the same contract address exists on two chains. This module refuses to
// guess: it reports errors for malformed input and warnings for every input that
// is technically valid but dangerous to hand to a third-party parser.
//
// Spec: https://eips.ethereum.org/EIPS/eip-681

export const SCHEME = 'ethereum';
export const ERC20_TRANSFER = 'transfer';

const ADDRESS_RE = /^(pay-)?(0x[0-9a-fA-F]{40})$/;
const CHAIN_DEC_RE = /^[0-9]+$/;
const CHAIN_HEX_RE = /^0x[0-9a-fA-F]+$/;
const FUNCTION_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const UINT_RE = /^[0-9]+(?:e[0-9]+)?$/i;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

function err(code, message) { return { code, message }; }
function warn(code, message) { return { code, message }; }

/**
 * Parse an amount like "1000", "1e18", "0x2a" into a bigint of base units.
 * EIP-681 permits decimal integers and scientific notation; the hex form is a
 * common extension, so it is accepted but flagged by the caller, not here.
 * Returns { ok, value, errors }.
 */
export function parseAmount(raw) {
  const errors = [];
  if (typeof raw !== 'string' || raw === '') {
    return { ok: false, value: null, errors: [err('amount-empty', 'amount is empty')] };
  }
  const hex = /^0x[0-9a-fA-F]+$/.test(raw);
  if (hex) return { ok: true, value: BigInt(raw), errors: [] };
  if (!UINT_RE.test(raw)) {
    return { ok: false, value: null, errors: [err('amount-invalid', `amount is not a non-negative integer or scientific notation: ${raw}`)] };
  }
  const [mantissa, exp] = raw.toLowerCase().split('e');
  let v = BigInt(mantissa);
  if (exp !== undefined) v *= 10n ** BigInt(exp);
  return { ok: true, value: v, errors };
}

/** EIP-55 checksum. Kept local so the module has no dependencies. */
const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROT = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
];
const MASK64 = 0xffffffffffffffffn;

function rotl64(x, n) {
  if (n === 0) return x & MASK64;
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

export function keccak256(bytes) {
  const rate = 136; // 1088 bits
  const st = [];
  for (let i = 0; i < 25; i++) st.push(0n);

  const padLen = rate - (bytes.length % rate);
  const padded = new Uint8Array(bytes.length + padLen);
  padded.set(bytes);
  padded[bytes.length] = 0x01;
  padded[padded.length - 1] = 0x80;

  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++) lane |= BigInt(padded[off + i * 8 + b]) << BigInt(8 * b);
      st[i] ^= lane;
    }
    // Keccak-f[1600]: 24 rounds
    for (let round = 0; round < 24; round++) {
      // theta
      const c = [], d = [];
      for (let x = 0; x < 5; x++) c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
      for (let x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) st[x + 5 * y] ^= d[x];
      // rho + pi
      const b = new Array(25);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y], KECCAK_ROT[x][y]);
      }
      // chi
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
        st[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y] & MASK64) & b[(x + 2) % 5 + 5 * y]);
      }
      // iota
      st[0] ^= KECCAK_RC[round];
    }
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = st[i];
    for (let b = 0; b < 8; b++) { out[i * 8 + b] = Number(lane & 0xffn); lane >>= 8n; }
  }
  return out;
}

/** EIP-55 mixed-case checksum of a 20-byte address. */
export function toChecksumAddress(addr) {
  const lower = addr.toLowerCase().replace(/^0x/, '');
  const hash = keccak256(new TextEncoder().encode(lower));
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    const nibble = (hash[Math.floor(i / 2)] >> (i % 2 === 0 ? 4 : 0)) & 0x0f;
    out += nibble >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

/** True when addr is a correct EIP-55 checksum (or all-lowercase/all-uppercase). */
export function isChecksumAddress(addr) {
  const body = addr.replace(/^0x/, '');
  if (!/^[0-9a-fA-F]{40}$/.test(body)) return false;
  if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
  return toChecksumAddress(addr) === '0x' + body;
}

/**
 * Parse an EIP-681 URI.
 * Returns:
 *   {
 *     ok: boolean,              // no errors (warnings may still be present)
 *     scheme, target, chainId, functionName, params,
 *     isTokenTransfer, recipient, amount (bigint|null),
 *     errors: [{code,message}], warnings: [{code,message}],
 *     canonical: string|null
 *   }
 */
export function parse(uri) {
  const errors = [];
  const warnings = [];
  const out = {
    ok: false, scheme: null, target: null, chainId: null, functionName: null,
    params: {}, isTokenTransfer: false, recipient: null, amount: null,
    errors, warnings, canonical: null,
  };

  if (typeof uri !== 'string' || uri.trim() === '') {
    errors.push(err('empty', 'URI is empty'));
    return out;
  }
  const raw = uri.trim();
  const colon = raw.indexOf(':');
  if (colon < 0) {
    errors.push(err('no-scheme', 'URI has no scheme; expected "ethereum:"'));
    return out;
  }
  const scheme = raw.slice(0, colon);
  if (scheme.toLowerCase() !== SCHEME) {
    errors.push(err('bad-scheme', `unsupported scheme "${scheme}"; EIP-681 uses "${SCHEME}"`));
    return out;
  }
  out.scheme = scheme.toLowerCase();

  let rest = raw.slice(colon + 1);
  let query = '';
  const q = rest.indexOf('?');
  if (q >= 0) { query = rest.slice(q + 1); rest = rest.slice(0, q); }

  let head = rest, fn = '';
  const slash = rest.indexOf('/');
  if (slash >= 0) { head = rest.slice(0, slash); fn = rest.slice(slash + 1); }

  // --- target [@chainId] ---
  let targetRaw = head, chainRaw = null;
  const at = head.indexOf('@');
  if (at >= 0) { targetRaw = head.slice(0, at); chainRaw = head.slice(at + 1); }

  if (targetRaw === '') {
    errors.push(err('no-target', 'URI has no target address'));
  } else {
    const m = ADDRESS_RE.exec(targetRaw);
    if (!m) {
      errors.push(err('bad-address', `target is not a 20-byte hex address: ${targetRaw}`));
    } else {
      if (m[1]) warnings.push(warn('pay-prefix', 'the deprecated "pay-" address prefix is present; plain addresses are preferred'));
      out.target = m[2];
      if (!isChecksumAddress(out.target)) {
        warnings.push(warn('bad-checksum', `target has an invalid EIP-55 checksum: ${out.target}`));
      }
      if (out.target.toLowerCase() === ZERO_ADDRESS) {
        errors.push(err('zero-address', 'target is the zero address; funds sent to it are unrecoverable'));
      }
    }
  }

  if (chainRaw !== null) {
    if (chainRaw === '') {
      errors.push(err('empty-chain-id', 'chain id is empty after "@"'));
    } else if (CHAIN_DEC_RE.test(chainRaw)) {
      out.chainId = Number(chainRaw);
      if (!Number.isSafeInteger(out.chainId)) {
        errors.push(err('chain-id-overflow', `chain id is not a safe integer: ${chainRaw}`));
        out.chainId = null;
      }
    } else if (CHAIN_HEX_RE.test(chainRaw)) {
      out.chainId = Number(BigInt(chainRaw));
      warnings.push(warn('hex-chain-id', 'chain id is hex; decimal is the canonical form'));
    } else {
      errors.push(err('bad-chain-id', `chain id is neither decimal nor hex: ${chainRaw}`));
    }
  } else {
    warnings.push(warn('no-chain-id', 'no chain id (@) present; the same address can exist on multiple chains, so a wallet may pick the wrong one'));
  }

  // --- /functionName ---
  if (slash >= 0) {
    if (fn === '') {
      errors.push(err('empty-function', 'trailing "/" with no function name'));
    } else if (!FUNCTION_RE.test(fn)) {
      errors.push(err('bad-function', `function name is not a bare identifier: ${fn}`));
    } else {
      out.functionName = fn;
    }
  }

  // --- query params ---
  if (query !== '') {
    for (const part of query.split('&')) {
      if (part === '') {
        errors.push(err('empty-param', 'query string contains an empty parameter'));
        continue;
      }
      const eq = part.indexOf('=');
      const keyRaw = eq < 0 ? part : part.slice(0, eq);
      const valRaw = eq < 0 ? '' : part.slice(eq + 1);
      const key = keyRaw.toLowerCase();
      if (key === '') { errors.push(err('empty-param-name', 'a parameter has no name')); continue; }
      if (Object.prototype.hasOwnProperty.call(out.params, key)) {
        errors.push(err('duplicate-param', `parameter "${key}" appears more than once; parsers disagree on which wins`));
        continue;
      }
      out.params[key] = decodeURIComponent(valRaw.replace(/\+/g, ' '));
    }
  }

  const isTransfer = out.functionName !== null && out.functionName.toLowerCase() === ERC20_TRANSFER;
  out.isTokenTransfer = isTransfer;

  if (Object.prototype.hasOwnProperty.call(out.params, 'address')) {
    const to = out.params.address;
    if (!/^0x[0-9a-fA-F]{40}$/.test(to)) {
      errors.push(err('bad-recipient', `recipient is not a 20-byte hex address: ${to}`));
    } else {
      out.recipient = to;
      if (!isChecksumAddress(to)) {
        warnings.push(warn('recipient-bad-checksum', `recipient has an invalid EIP-55 checksum: ${to}`));
      }
      if (to.toLowerCase() === ZERO_ADDRESS) {
        errors.push(err('recipient-zero', 'recipient is the zero address; funds sent to it are unrecoverable'));
      }
    }
  }

  if (isTransfer) {
    // Token transfer form: target is the ERC-20 contract, parameters are
    // address + uint256. A bare `value` here is intentionally rejected: the
    // number would mean base units of the token to some parsers and native
    // currency to others.
    if (!out.params.address) {
      errors.push(err('token-no-recipient', 'token transfer has no "address" parameter; the recipient is unspecified'));
    }
    if (!Object.prototype.hasOwnProperty.call(out.params, 'uint256')) {
      // Valid per the grammar, but hazardous: a partial parser can read this as
      // an open-ended transfer the user authorises manually.
      warnings.push(warn('token-no-amount', 'token transfer omits "uint256"; partial parsers may treat this as an open-ended transfer to be filled in by the user'));
    }
    if (Object.prototype.hasOwnProperty.call(out.params, 'value')) {
      errors.push(err('token-value-ambiguous', 'token transfer also carries "value", which is ambiguous between native and token units'));
    }
    if (out.params.uint256 !== undefined) {
      const a = parseAmount(out.params.uint256);
      if (!a.ok) errors.push(...a.errors);
      else {
        out.amount = a.value;
        if (a.value === 0n) warnings.push(warn('token-amount-zero', 'token amount is zero'));
        if (/^0x/i.test(out.params.uint256)) warnings.push(warn('hex-amount', 'amount is hex; decimal is the canonical form for uint256'));
      }
    }
  } else if (Object.prototype.hasOwnProperty.call(out.params, 'uint256')) {
    errors.push(err('uint256-without-transfer', '"uint256" is only meaningful on a /transfer function'));
  }

  if (!isTransfer && out.params.value !== undefined) {
    const a = parseAmount(out.params.value);
    if (!a.ok) errors.push(...a.errors);
    else {
      out.amount = a.value;
      if (a.value === 0n) warnings.push(warn('value-zero', 'native amount is zero'));
      if (/^0x/i.test(out.params.value)) warnings.push(warn('hex-amount', 'amount is hex; decimal is the canonical form'));
    }
  }

  // unknown params left in place; they are legal extensions per the spec
  out.ok = errors.length === 0;
  try { out.canonical = out.ok ? format(out) : null; } catch { out.canonical = null; }
  return out;
}

/** Serialise a parsed URI back to a canonical EIP-681 string. */
export function format(v) {
  if (!v || !v.target) throw new Error('format() needs a parsed value with a target');
  let s = SCHEME + ':' + v.target;
  if (v.chainId !== null && v.chainId !== undefined) s += '@' + v.chainId;
  if (v.functionName) s += '/' + v.functionName;
  const keys = Object.keys(v.params || {});
  if (keys.length) {
    // deterministic ordering: address, uint256, value, then the rest sorted
    const order = ['address', 'uint256', 'value'];
    keys.sort((a, b) => {
      const ia = order.indexOf(a), ib = order.indexOf(b);
      if (ia >= 0 || ib >= 0) return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      return a < b ? -1 : a > b ? 1 : 0;
    });
    s += '?' + keys.map(k => `${k}=${encodeURIComponent(v.params[k])}`).join('&');
  }
  return s;
}

/** Convenience: build an ERC-20 transfer request. */
export function erc20Transfer({ chainId, token, to, amount }) {
  const errors = [];
  if (!/^0x[0-9a-fA-F]{40}$/.test(token || '')) errors.push(err('token', `token is not an address: ${token}`));
  if (!/^0x[0-9a-fA-F]{40}$/.test(to || '')) errors.push(err('to', `recipient is not an address: ${to}`));
  let amt = amount;
  if (typeof amt === 'bigint') amt = amt.toString();
  if (typeof amt === 'number') amt = String(amt);
  if (!amt || !parseAmount(String(amt)).ok) errors.push(err('amount', `amount is not a valid base-unit integer: ${amount}`));
  if (errors.length) return { ok: false, errors, uri: null };
  return {
    ok: true, errors: [],
    uri: format({ scheme: SCHEME, target: token, chainId, functionName: ERC20_TRANSFER, params: { address: to, uint256: String(amt) } }),
  };
}

/** Convenience: build a native-currency transfer request. */
export function nativeTransfer({ chainId, to, wei }) {
  const errors = [];
  if (!/^0x[0-9a-fA-F]{40}$/.test(to || '')) errors.push(err('to', `recipient is not an address: ${to}`));
  let amt = typeof wei === 'bigint' ? wei.toString() : String(wei ?? '');
  if (!amt || !parseAmount(amt).ok) errors.push(err('wei', `amount is not a valid wei integer: ${wei}`));
  if (errors.length) return { ok: false, errors, uri: null };
  return {
    ok: true, errors: [],
    uri: format({ scheme: SCHEME, target: to, chainId, functionName: null, params: { value: amt } }),
  };
}

export default { parse, format, parseAmount, keccak256, toChecksumAddress, isChecksumAddress, erc20Transfer, nativeTransfer, SCHEME, ERC20_TRANSFER };
