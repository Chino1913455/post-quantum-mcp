# Post-Quantum MCP

A [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI
agents and applications **NIST-standardized post-quantum cryptography** — key
encapsulation, digital signatures, hybrid encryption, secure randomness, and
key management — built on the audited [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
library.

> **"Harvest now, decrypt later" is a present threat.** Data encrypted with
> classical RSA/ECC today can be stored by an adversary and decrypted once a
> cryptographically-relevant quantum computer exists. The NIST PQC standards
> (FIPS 203/204/205, finalized 2024) are the mitigation. This server makes them
> a drop-in tool for any MCP-capable agent.

> 🔎 **Companion:** [`pqc-scan`](https://github.com/Chino1913455/pqc-scan) finds the
> quantum-vulnerable crypto in your codebase and flags harvest-now-decrypt-later
> risk. Use it to discover *what* to migrate — then use this server to *do* it.

## What's inside (and what isn't)

Every exposed tool is backed by a real, standards-compliant implementation —
there are **no mock or simulated operations** on the surface.

| Family | Algorithm | Standard | Tools |
|--------|-----------|----------|-------|
| KEM | Kyber / **ML-KEM** | FIPS 203 | `kyber-keygen`, `kyber-encapsulate`, `kyber-decapsulate` |
| Signature | Dilithium / **ML-DSA** | FIPS 204 | `dilithium-keygen`, `dilithium-sign`, `dilithium-verify` |
| Signature | SPHINCS+ / **SLH-DSA** | FIPS 205 | `sphincs-keygen`, `sphincs-sign`, `sphincs-verify` |
| Signature | Falcon / **FN-DSA** | (draft) | `falcon-keygen`, `falcon-sign`, `falcon-verify` |
| Encryption | ML-KEM-768 + AES-256-GCM | hybrid | `hybrid-encrypt`, `hybrid-decrypt` |
| Randomness | OS CSPRNG (+ optional HW entropy) | SP 800-90A/B | `secure-random`, `random-validate` |
| Key mgmt | AES-256-GCM store, KDFs | — | `store-key`, `retrieve-key`, `list-stored-keys`, `key-derive` |
| Advisory | Security level / threat model | — | `analyze-security` |
| Performance | Real measured benchmarks | — | `benchmark-algorithm` |
| **Hybrid** | X25519+ML-KEM-768 (X-Wing), Ed25519+ML-DSA-65 | hybrid | `hybrid-kem-*`, `hybrid-sign`, `hybrid-verify` |
| **Agent** | identity, attestations, E2E channels | — | `agent-create-identity`, `agent-attest`, `agent-channel-*` |
| **Supply chain** | quantum-safe code/SBOM signing | — | `sign-artifact`, `verify-artifact` |
| **Advisory** | PQC migration plan + HNDL risk | — | `assess-migration` |
| **Custody** | Shamir t-of-n key splitting + quorum signing | — | `threshold-split-key`, `threshold-reconstruct-key`, `threshold-sign` |
| **Tokens** | quantum-safe JWT-style auth tokens | — | `jwt-sign`, `jwt-verify` |
| **Documents** | multi-recipient PQ encryption | — | `encrypt-document`, `decrypt-document` |
| **PKI** | quantum-safe certificates | — | `issue-certificate`, `verify-certificate` |

**Honesty notes:**
- `secure-random` is a cryptographically-secure **CSPRNG** (hardware-seeded
  DRBG) — the correct source for PQC key material. It is **not** a quantum/true
  RNG unless a hardware entropy source is present; it reports its actual source.
- Experimental research primitives (threshold signatures, lattice ZK proofs,
  MPC, IBE, homomorphic voting) live in the source tree but are **not exposed**
  by this server and are not part of the supported surface.
- These implementations have **not** undergone a formal third-party security
  audit. The underlying `@noble/post-quantum` primitives are independently
  audited; the MCP wrapper around them is not. Use accordingly.

## What makes this different

The NIST algorithms are commodity. The edge is in what AI agents and real
deployments actually need:

- **Hybrid by default (X-Wing).** `hybrid-kem-*` and `hybrid-sign` combine
  classical X25519/Ed25519 with ML-KEM/ML-DSA, so you stay secure if *either*
  breaks — the construction Cloudflare/AWS/Apple/Signal actually ship.
  Verifying a hybrid signature requires *both* halves to pass.
- **Agent-native identity & messaging.** `agent-create-identity` mints a
  portable quantum-safe identity; `agent-attest` produces tamper-evident signed
  records of an agent's actions; `agent-channel-*` establishes an end-to-end
  encrypted channel between two agents via a hybrid KEM handshake.
- **Quantum-safe supply chain.** `sign-artifact` / `verify-artifact` produce
  in-toto-style hybrid signatures over a software/SBOM digest — signatures that
  must outlive the quantum transition.
- **Crypto-agility advisor.** `assess-migration` turns a crypto inventory into a
  prioritized migration plan with explicit harvest-now-decrypt-later risk.

## Install & configure

```bash
npm install
npm run build
```

Add to an MCP client (e.g. Claude Desktop `claude_desktop_config.json`):

```jsonc
{
  "mcpServers": {
    "post-quantum": {
      "command": "node",
      "args": ["/absolute/path/to/post-quantum-mcp/dist/index.js"],
      "env": {
        // Required ONLY if you use encrypted key storage (store-key/retrieve-key):
        "KEY_ENCRYPTION_SECRET": "<a strong secret, >= 16 chars>"
      }
    }
  }
}
```

| Env var | Default | Purpose |
|---------|---------|---------|
| `KEY_ENCRYPTION_SECRET` | *(unset → encrypted storage refused)* | Master secret for at-rest key encryption. Fails closed if unset. |
| `KEY_STORE_PATH` | `./keys` | Directory for the encrypted key store. |
| `LOG_LEVEL` | `info` | winston log level. |

## Use cases

### 1. Quantum-safe key exchange (ML-KEM)
Establish a shared secret resistant to quantum attack:
```
kyber-keygen { "parameterSet": "kyber768" }          -> publicKey, privateKey
kyber-encapsulate { "publicKey": "<pk>" }            -> ciphertext, sharedSecret
kyber-decapsulate { "privateKey": "<sk>",
                    "ciphertext": "<ct>" }            -> sharedSecret  (matches)
```

### 2. Quantum-safe document signing (ML-DSA / SLH-DSA / Falcon)
Sign and verify with a quantum-resistant signature:
```
dilithium-keygen { "parameterSet": "dilithium3" }    -> publicKey, privateKey
dilithium-sign  { "privateKey": "<sk>",
                  "message": "ship v1.0.0" }          -> signature
dilithium-verify { "publicKey": "<pk>",
                   "message": "ship v1.0.0",
                   "signature": "<sig>" }             -> { valid: true }
```
`verify` is **total**: a forged, truncated, or wrong-length signature returns
`{ valid: false }` — it never throws on attacker-controlled input.

### 3. Encrypt data so only the holder of a PQ key can read it
```
hybrid-encrypt { "publicKey": "<kyber-pk>",
                 "data": "classified payload" }       -> encapsulatedKey,
                                                          encryptedData, iv, authTag
hybrid-decrypt { "privateKey": "<kyber-sk>",
                 "encryptedData": { ...above... } }    -> decryptedData
```
ML-KEM-768 wraps an AES-256-GCM content key. Tampering with any field fails the
GCM authentication tag.

### 4. Generate and certify secure randomness
```
secure-random  { "bytes": 32, "format": "hex" }       -> random + source + health
random-validate { "bytes": 65536 }                    -> NIST SP 800-22 results
```
`secure-random` health-tests its output (SP 800-90B) and reports whether it came
from the OS CSPRNG or a conditioned hardware source. `random-validate` runs the
NIST SP 800-22 statistical battery on supplied or freshly-drawn bytes.

### 5. Choose the right algorithm for a threat model
```
analyze-security { "algorithm": "kyber", "parameterSet": "kyber1024",
                   "threatModel": "future-10y" }       -> NIST level, bit security,
                                                          quantum threat assessment
benchmark-algorithm { "algorithm": "all", "operations": 100 }
                                                       -> real keygen/sign/verify
                                                          timings per algorithm
```

### 6. Derive and store keys
```
key-derive  { "masterKey": "<base64>", "info": "session-2026",
              "algorithm": "hkdf-sha256", "length": 32 }   -> derivedKey
store-key   { "keyId": "signing-key", "keyData": "<base64>" }   (AES-256-GCM at rest)
retrieve-key { "keyId": "signing-key" }
```
KDFs: `shake256`, `hkdf-sha256`, `pbkdf2`, `scrypt` (all real, Node stdlib).

## Deployment

Two transports, selected by `MCP_TRANSPORT`:

- **stdio** (default) — for local MCP clients (Claude Desktop, IDEs); see the config above.
- **HTTP** — for hosting as a service (stateless JSON-RPC, 8 MiB request cap):

```bash
MCP_TRANSPORT=http PORT=3000 node dist/index.js   # POST JSON-RPC to http://host:3000/mcp
```

With Docker (runs as a non-root user):

```bash
docker build -t post-quantum-mcp .
docker run -p 3000:3000 -e KEY_ENCRYPTION_SECRET=your-strong-secret post-quantum-mcp
```

## Development

```bash
npm run build        # tsc + copy wasm
npm test             # full suite (NIST core, entropy, NTT, hybrid, failure cases)
npm run test:coverage
```

The lattice polynomial arithmetic uses a Number-Theoretic Transform (`getNTT`)
that is verified bit-for-bit against schoolbook convolution — an O(n log n)
speedup (~14x at n=256) with no change to results.

## License

MIT — see [LICENSE](./LICENSE).
