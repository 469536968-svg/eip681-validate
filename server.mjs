// server.mjs — EIP-681 conformance checker, HTTP API.
//
// Zero dependencies (node: builtins only). Binds 127.0.0.1 by default;
// put a tunnel in front of it to expose publicly.
//
// POST /v1/validate   { "uri": "ethereum:0x...@8453?value=1" }
//   -> 200 { ok, errors, warnings, issues[], canonical, parsed }
//   -> 400 on malformed request body
//
// GET  /v1/validate?uri=...    same, convenient for browsers/curl
// GET  /health                 liveness + version
// GET  /                       tiny usage page
//
// Design notes:
//  - The response is the *whole* report, not a boolean. The point of the
//    service is the "why", which is what a wallet integrator actually needs.
//  - Every response is deterministic and offline: no external calls, so the
//    service cannot leak the URIs it is given, and cannot fail due to a
//    third party. That is also the privacy claim.
import http from 'node:http';
import { validate } from './validate.mjs';

const VERSION = '1.0.0';
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const MAX_BODY = 64 * 1024;
const MAX_URI = 4096;

const json = (res, code, obj) => {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
};

function runValidation(uri) {
  if (typeof uri !== 'string') {
    return { status: 400, body: { error: 'missing_field', message: 'Provide "uri" as a string.' } };
  }
  if (uri.length > MAX_URI) {
    return { status: 413, body: { error: 'uri_too_long', message: `Max ${MAX_URI} characters.` } };
  }
  const report = validate(uri);
  return { status: 200, body: { service: 'eip681-validate', version: VERSION, ...report } };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > MAX_BODY) { reject(new Error('body_too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const USAGE = `eip681-validate ${VERSION}
EIP-681 URI conformance checker.

  GET  /health
  GET  /v1/validate?uri=<urlencoded>
  POST /v1/validate   {"uri":"ethereum:0x...@8453?value=1"}

Returns { ok, errors, warnings, issues[], canonical, parsed }.
Stateless. No logging of URIs. No outbound network.
`;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, { ok: true, service: 'eip681-validate', version: VERSION });
  }

  if (req.method === 'GET' && url.pathname === '/v1/validate') {
    const uri = url.searchParams.get('uri');
    if (uri === null) {
      return json(res, 400, { error: 'missing_query', message: 'Add ?uri=<eip681 uri>' });
    }
    const { status, body } = runValidation(uri);
    return json(res, status, body);
  }

  if (req.method === 'POST' && url.pathname === '/v1/validate') {
    let raw;
    try { raw = await readBody(req); }
    catch { return json(res, 413, { error: 'body_too_large' }); }
    let payload;
    try { payload = JSON.parse(raw || '{}'); }
    catch { return json(res, 400, { error: 'invalid_json' }); }
    const { status, body } = runValidation(payload.uri);
    return json(res, status, body);
  }

  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end(USAGE);
  }

  json(res, 404, { error: 'not_found' });
});

server.listen(PORT, HOST, () => {
  console.log(`eip681-validate ${VERSION} listening on http://${HOST}:${PORT}`);
});

export { server };
