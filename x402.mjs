// x402.mjs — minimal, dependency-free x402 payment gate for USDC on Base.
//
// What is implemented, precisely (no overclaiming):
//   * 402 response shaped per the x402 spec: { x402Version, accepts:[...] }
//   * Payment presentation via the `X-PAYMENT` header (base64 JSON).
//   * Scheme "usdc-base-tx": the payer submits the hash of an already-broadcast
//     USDC transfer on Base. We verify it server-side against the chain:
//       - transaction receipt exists and status == 1
//       - receipt contains a USDC Transfer log to `payTo`
//       - summed transfer value >= price
//       - tx hash has not been consumed before (replay protection, persisted)
//
// What is NOT implemented: EIP-3009 `transferWithAuthorization` signature
// recovery (the "exact" scheme). That needs secp256k1 recovery, which we do not
// vendor here. A payer using that flow will get a clear 501 telling them which
// scheme to use instead — we would rather return an explicit error than accept
// a signature we cannot verify.

import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const BASE_CHAIN_ID = 8453;
export const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

const DEFAULT_RPC = process.env.BASE_RPC_URL || 'https://mainnet.base.org';

function b64decode(s) {
  return JSON.parse(Buffer.from(String(s), 'base64').toString('utf8'));
}

function pad64(hexNo0x) {
  return hexNo0x.toLowerCase().padStart(64, '0');
}

function topicToAddress(topic) {
  const h = String(topic).replace(/^0x/, '');
  return '0x' + h.slice(-40);
}

/**
 * Build the 402 challenge body for a given resource.
 * @param {{resource:string, description:string, priceAtomic:string, payTo:string}} o
 */
export function paymentRequired(o) {
  return {
    x402Version: 1,
    error: 'Payment required',
    accepts: [
      {
        scheme: 'usdc-base-tx',
        network: 'base',
        asset: USDC_BASE,
        payTo: o.payTo,
        maxAmountRequired: String(o.priceAtomic),
        resource: o.resource,
        description: o.description,
        mimeType: 'application/json',
        maxTimeoutSeconds: 900,
        extra: {
          chainId: BASE_CHAIN_ID,
          assetDecimals: 6,
          assetSymbol: 'USDC',
          note:
            'Broadcast a USDC transfer on Base to payTo, then retry with header ' +
            'X-PAYMENT = base64(JSON {"txHash":"0x..."}).',
        },
      },
    ],
  };
}

/** Replay-protection store. Tiny JSON file; fine for a single-node service. */
export class SpentStore {
  constructor(file) {
    this.file = file;
    this.seen = new Set();
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (Array.isArray(raw)) raw.forEach((h) => this.seen.add(String(h).toLowerCase()));
    } catch { /* first run */ }
  }
  has(h) { return this.seen.has(String(h).toLowerCase()); }
  add(h) {
    this.seen.add(String(h).toLowerCase());
    const list = [...this.seen].slice(-20000);
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(list));
  }
}

/**
 * Ask the chain for a receipt and decide whether it satisfies the price.
 * Returns { paid:boolean, reason:string, observed?:string }
 */
export async function verifyTxPayment({ txHash, payTo, priceAtomic, rpcUrl = DEFAULT_RPC }) {
  if (typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
    return { paid: false, reason: 'malformed txHash' };
  }

  let receipt;
  try {
    const r = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [txHash],
      }),
      signal: AbortSignal.timeout(12000),
    });
    if (!r.ok) return { paid: false, reason: `rpc http ${r.status}` };
    const j = await r.json();
    receipt = j.result;
  } catch (e) {
    return { paid: false, reason: `rpc unreachable: ${e.message}`, rpcDown: true };
  }

  if (!receipt) return { paid: false, reason: 'no receipt for txHash (not mined?)' };
  if (receipt.status !== '0x1') return { paid: false, reason: 'tx reverted' };

  const want = BigInt(priceAtomic);
  const wantTo = String(payTo).toLowerCase();
  let credited = 0n;

  for (const log of receipt.logs || []) {
    if (String(log.address).toLowerCase() !== USDC_BASE.toLowerCase()) continue;
    if (String(log.topics?.[0]).toLowerCase() !== TRANSFER_TOPIC) continue;
    const to = topicToAddress(log.topics[2]);
    if (to !== wantTo) continue;
    credited += BigInt('0x' + String(log.data).replace(/^0x/, ''));
  }

  if (credited < want) {
    return {
      paid: false,
      reason: `underpaid: saw ${credited} atomic USDC to ${payTo}, need ${want}`,
      observed: credited.toString(),
    };
  }
  return { paid: true, reason: 'ok', observed: credited.toString() };
}

/**
 * Parse and check the X-PAYMENT header shape.
 * Returns { ok:true, txHash } or { ok:false, status, body }
 */
export function readPaymentHeader(headerValue) {
  if (!headerValue) {
    return { ok: false, status: 402, reason: 'missing X-PAYMENT' };
  }
  let payload;
  try { payload = b64decode(headerValue); }
  catch { return { ok: false, status: 400, reason: 'X-PAYMENT is not base64 JSON' }; }

  if (payload.scheme === 'exact') {
    return {
      ok: false,
      status: 501,
      reason:
        'scheme "exact" (EIP-3009 transferWithAuthorization) is not supported by this ' +
        'server: we cannot verify the signature. Use scheme "usdc-base-tx" with a txHash.',
    };
  }
  if (payload.scheme && payload.scheme !== 'usdc-base-tx') {
    return { ok: false, status: 400, reason: `unknown scheme "${payload.scheme}"` };
  }
  const txHash = payload.txHash || payload.payload?.txHash;
  if (!txHash) return { ok: false, status: 400, reason: 'X-PAYMENT missing txHash' };
  return { ok: true, txHash };
}

/** Deterministic id for a resource+client pair, used only for logs. */
export function requestId(req) {
  const ip = (req.socket?.remoteAddress || 'unknown') + ':' + (req.headers['user-agent'] || '');
  return createHash('sha256').update(ip).digest('hex').slice(0, 12) || randomUUID();
}

export default {
  paymentRequired, verifyTxPayment, readPaymentHeader, SpentStore,
  USDC_BASE, BASE_CHAIN_ID, requestId,
};
