# eip681-validate

**An EIP-681 conformance checker that tells you *why* a payment link will mispay.**

Not a linter for style. A checker for the specific ways an EIP-681 URI makes
one wallet pay correctly and another wallet send funds somewhere else.

```
$ curl -s "http://127.0.0.1:8787/v1/validate?uri=ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000"
{
  "ok": false,
  "errors": 1,
  "issues": [
    {
      "code": "missing-chain-id",
      "severity": "error",
      "message": "No @chainId in the URI.",
      "hint": "A token address without a chain is ambiguous; the payer may sign on the wrong network and the transfer becomes irrecoverable."
    }
  ]
}
```

## The bugs it catches

These are the ones that actually cost money, ranked by how often they appear in
the wild:

| Code | Severity | Why it matters |
|---|---|---|
| `missing-chain-id` | **error** on token transfers | The same token address lives on many chains. Without `@chainId` the *payer's wallet* picks the network. Funds land on a chain your app isn't watching. |
| `value-uint256-conflict` | **error** | EIP-681 defines `uint256` as an alias of `value`. Emitting both with different values means two wallets send two different amounts. |
| `target-checksum-invalid` | **error** | A mixed-case address that fails EIP-55. High-signal indicator of a hand-edited link. Strict wallets refuse it outright. |
| `value-scientific-notation` | warn | `1e18` is idiomatic in JS but not spec. Our parser accepts it; strict parsers reject the URI. |
| `unknown-parameter` | warn | Silently ignored by wallets. A link that "works" in your client can carry meaning nobody else reads. |
| `duplicate-parameter` | warn | Precedence is undefined. `?value=1&value=2` is a coin flip. |

## Design

**The response is the whole report, never a boolean.** A boolean tells you your
link is broken. The `hint` tells you what to change. That is the entire product.

**It layers on the parser; it doesn't reimplement it.** `eip681.mjs` parses
permissively and collects `errors[]`/`warnings[]`. `validate.mjs` surfaces those
and adds the interop rules the parser deliberately does not enforce — because a
parser should be permissive, and a *validator* should be strict. Each rule is
owned by exactly one layer; the report never says the same thing twice.

**Offline and stateless, by construction.** No outbound network calls, no
logging of submitted URIs. The only way to give a third party your payment link
is to hand it over, and this service does not do that.

**Exact arithmetic.** Amounts are `BigInt` through the whole path. `uint256`
max round-trips without precision loss — no `Number`, anywhere.

## Verify it yourself

```bash
node test.mjs      # 21 tests, zero dependencies
```

Ground truth is external, never our own output:

- Keccak-256 against the official vectors (`""`, `"abc"`, the fox)
- all four canonical EIP-55 addresses from the EIP-55 spec
- the EIP-681 spec's own examples

Three real bugs were found by testing against those vectors rather than against
ourselves, including Keccak's lane mask being 32-bit where it must be 64-bit,
and output lanes needing to be emitted little-endian.

## Run it

```bash
PORT=8787 node server.mjs
curl -s "http://127.0.0.1:8787/v1/validate?uri=ethereum:0x...@8453?value=1"
curl -s -X POST -H 'content-type: application/json' \
     -d '{"uri":"ethereum:0x...@8453?value=1"}' \
     http://127.0.0.1:8787/v1/validate
```

Requires Node 18+. No dependencies, no build step.

## API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health` | liveness + version |
| `GET` | `/v1/validate?uri=` | URL-encode the URI |
| `POST` | `/v1/validate` | `{"uri": "..."}` |

Response: `{ ok, errors, warnings, issues[], canonical, parsed }`.
`canonical` is only emitted when `errors === 0` — a normalized URI is not
something you should trust if the input had problems.

## Files

| File | Role |
|---|---|
| `eip681.mjs` | Parser. Permissive by design. Zero deps. |
| `validate.mjs` | Conformance layer. Owns the interop rules. |
| `server.mjs` | HTTP API. `node:` builtins only. |
| `test.mjs` | 21 tests against external ground truth. |
| `demo.html` | Offline browser UI. |

## License

MIT.
