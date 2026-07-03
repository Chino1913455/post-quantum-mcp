import { Logger } from 'winston';
import NodeCache from 'node-cache';
import * as crypto from 'crypto';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import * as sampling from './entropy/sampling.js';
import { b64, ub } from './canonical.js';

/**
 * Shamir t-of-n custody of post-quantum private keys.
 *
 * This is the SOUND, useful counterpart to "threshold signing": rather than a
 * naive (and academically unsound) attempt to combine Dilithium partial
 * signatures, it splits a real private key into n shares such that:
 *   - any t shares reconstruct the key exactly (Lagrange over GF(2^8)),
 *   - any t-1 shares reveal ZERO information (Shamir is information-theoretic),
 *   - reconstruction is verified against a digest commitment (tamper-evident).
 *
 * `thresholdSign` reconstructs the key from a quorum, signs with the REAL
 * @noble ML-DSA (producing a standard FIPS-204 signature any verifier accepts),
 * then zeroizes the reconstructed key.
 *
 * SECURITY MODEL — read this: the key IS briefly reassembled in memory at
 * signing time. This protects key custody at rest (no single party holds the
 * key; a quorum is required to act) and enables quorum recovery. It is NOT a
 * "the key never exists in one place" threshold signature. For that, a
 * purpose-built scheme (e.g. threshold-Raccoon) is required — see the
 * deprecated, experimental threshold-signatures.ts.
 */

// ── Constant-time GF(2^8) arithmetic (AES field, 0x11b) ─────────────────────
// No table lookups and no data-dependent branches: table-index and branch
// timing can leak secret key bytes to a (potentially AI/ML-assisted)
// side-channel adversary. Since split/reconstruct run over REAL private-key
// material, the field arithmetic is fully branchless.

const gadd = (a: number, b: number): number => a ^ b; // add = subtract = XOR

/** Branchless GF(2^8) multiply (Russian-peasant), constant-time in both inputs. */
function gmul(a: number, b: number): number {
  let p = 0;
  let x = a & 0xff;
  let y = b & 0xff;
  for (let i = 0; i < 8; i++) {
    p ^= -(y & 1) & x; // conditionally xor x into the product
    const hi = -((x >> 7) & 1); // all-ones if top bit set
    x = (x << 1) & 0xff;
    x ^= 0x1b & hi; // reduce modulo the AES polynomial
    y >>= 1;
  }
  return p & 0xff;
}

/** GF(2^8) inverse via a^254 (Fermat), fully unrolled — constant-time. */
function ginv(a: number): number {
  const a2 = gmul(a, a);
  const a4 = gmul(a2, a2);
  const a8 = gmul(a4, a4);
  const a16 = gmul(a8, a8);
  const a32 = gmul(a16, a16);
  const a64 = gmul(a32, a32);
  const a128 = gmul(a64, a64);
  return gmul(gmul(gmul(gmul(gmul(gmul(a2, a4), a8), a16), a32), a64), a128);
}

/** Split one byte into n shares of a degree-(t-1) polynomial. Returns y at x=1..n. */
function splitByte(secret: number, n: number, t: number): number[] {
  const coeffs = new Uint8Array(t);
  coeffs[0] = secret;
  const rnd = sampling.randomBytes(t - 1);
  for (let i = 1; i < t; i++) coeffs[i] = rnd[i - 1];
  const ys: number[] = [];
  for (let x = 1; x <= n; x++) {
    let y = 0;
    for (let i = t - 1; i >= 0; i--) y = gadd(gmul(y, x), coeffs[i]); // Horner
    ys.push(y);
  }
  return ys;
}

/** Reconstruct the constant term (x=0) from t points via Lagrange over GF(256). */
function reconstructByte(xs: number[], ys: number[]): number {
  let secret = 0;
  for (let i = 0; i < xs.length; i++) {
    let num = 1;
    let den = 1;
    for (let j = 0; j < xs.length; j++) {
      if (i === j) continue;
      num = gmul(num, xs[j]); // (0 - x_j) == x_j in GF(2^8)
      den = gmul(den, gadd(xs[i], xs[j])); // (x_i - x_j) == x_i ^ x_j
    }
    secret = gadd(secret, gmul(ys[i], gmul(num, ginv(den))));
  }
  return secret;
}

const DSA = { dilithium2: ml_dsa44, dilithium3: ml_dsa65, dilithium5: ml_dsa87 } as const;

export class ThresholdCustodyHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  private json(obj: any) {
    return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
  }

  /** Split a secret (any key bytes) into n shares; any t reconstruct it. */
  async splitKey(params: any) {
    const { secret, n, threshold } = params ?? {};
    if (!Number.isInteger(n) || !Number.isInteger(threshold) || threshold < 2 || threshold > n || n > 255) {
      throw new Error('Require 2 <= threshold <= n <= 255');
    }
    const data = ub(secret);
    if (data.length === 0) throw new Error('secret must be non-empty');

    // Per-byte sharing; share i holds one byte from each byte-polynomial.
    const shareBytes: Uint8Array[] = Array.from({ length: n }, () => new Uint8Array(data.length));
    for (let pos = 0; pos < data.length; pos++) {
      const ys = splitByte(data[pos], n, threshold);
      for (let s = 0; s < n; s++) shareBytes[s][pos] = ys[s];
    }

    const commitment = crypto.createHash('sha256').update(Buffer.from(data)).digest('hex');
    const shares = shareBytes.map((bytes, i) => ({ index: i + 1, value: b64(bytes) }));

    this.logger.info(`Split a ${data.length}-byte secret into ${threshold}-of-${n} shares`);
    return this.json({
      scheme: 'shamir-gf256',
      n,
      threshold,
      shares,
      commitment,
      note: 'Distribute shares to distinct holders. Any t reconstruct; any t-1 reveal nothing. Keep the commitment to verify reconstruction.',
    });
  }

  private reconstruct(shares: any[], threshold: number): Uint8Array {
    if (!Array.isArray(shares) || shares.length < threshold) {
      throw new Error(`Need at least ${threshold} shares, got ${shares?.length ?? 0}`);
    }
    const subset = shares.slice(0, threshold);
    const xs = subset.map((s: any) => s.index);
    const vals = subset.map((s: any) => ub(s.value));
    const len = vals[0].length;
    if (!vals.every((v) => v.length === len)) throw new Error('shares have inconsistent length');

    const out = new Uint8Array(len);
    for (let pos = 0; pos < len; pos++) {
      out[pos] = reconstructByte(xs, vals.map((v) => v[pos]));
    }
    return out;
  }

  /** Reconstruct the secret from a quorum of shares; verify against the commitment. */
  async reconstructKey(params: any) {
    const { shares, threshold, commitment } = params ?? {};
    const secret = this.reconstruct(shares, threshold);
    const digest = crypto.createHash('sha256').update(Buffer.from(secret)).digest('hex');
    const verified = commitment ? digest === commitment : undefined;
    if (commitment && !verified) {
      throw new Error('Reconstruction does not match the commitment — shares are wrong or tampered');
    }
    this.logger.info('Reconstructed secret from quorum of shares');
    return this.json({ secret: b64(secret), digest, verified });
  }

  /**
   * Quorum-sign: reconstruct an ML-DSA key from t shares, produce a REAL
   * FIPS-204 signature, then zeroize the reconstructed key.
   */
  async thresholdSign(params: any) {
    const { shares, threshold, message, algorithm = 'dilithium3', format = 'base64' } = params ?? {};
    const dsa = (DSA as any)[algorithm];
    if (!dsa) throw new Error(`Unsupported algorithm: ${algorithm}. Supported: dilithium2, dilithium3, dilithium5`);

    const secretKey = this.reconstruct(shares, threshold);
    const msg = new Uint8Array(Buffer.from(message, 'utf8'));
    try {
      const signature = dsa.sign(msg, secretKey);
      this.logger.info(`Quorum-signed with ${algorithm} (${threshold} shares)`);
      return this.json({
        algorithm: 'ml-dsa',
        parameterSet: algorithm,
        signature: Buffer.from(signature).toString(format === 'hex' ? 'hex' : 'base64'),
        signatureSize: signature.length,
        note: 'Standard FIPS-204 signature: verify with dilithium-verify. Key was reconstructed in memory then zeroized.',
        implementation: '@noble/post-quantum (FIPS 204)',
      });
    } finally {
      secretKey.fill(0); // best-effort zeroize
    }
  }
}
