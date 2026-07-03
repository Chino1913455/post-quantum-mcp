import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { hybridSign, hybridVerify } from './hybrid-pqc.js';
import { utf8, decFmt } from './canonical.js';

/**
 * Quantum-safe authentication tokens (PQ-JWT).
 *
 * A JWT-shaped token (`header.payload.signature`, base64url) signed with a
 * post-quantum scheme so that bearer tokens, API keys, and session assertions
 * survive the quantum transition. Default scheme is hybrid (Ed25519+ML-DSA-65).
 *
 * Note: PQ signatures are large, so tokens are multi-kilobyte — that is the
 * honest cost of quantum resistance, not a bug.
 */
const b64url = (u: Uint8Array): string => Buffer.from(u).toString('base64url');
const fromB64url = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));

export class PQJwtHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  private json(obj: any) {
    return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
  }

  async sign(params: any) {
    const { privateKey, claims = {}, algorithm = 'hybrid', expiresInSeconds, format = 'base64' } = params ?? {};
    const now = Math.floor(Date.now() / 1000);
    const payload: any = { ...claims, iat: now };
    if (expiresInSeconds) payload.exp = now + Number(expiresInSeconds);

    const alg = algorithm === 'hybrid' ? 'HYBRID-ED25519-MLDSA65' : 'ML-DSA-65';
    const header = { alg, typ: 'PQJWT' };
    const signingInput = b64url(utf8(JSON.stringify(header))) + '.' + b64url(utf8(JSON.stringify(payload)));

    const sk = decFmt(privateKey, format);
    const sig = algorithm === 'hybrid' ? hybridSign(sk, utf8(signingInput)) : ml_dsa65.sign(utf8(signingInput), sk);
    const token = signingInput + '.' + b64url(sig);

    this.logger.info(`Issued PQ-JWT (${alg})`);
    return this.json({ token, algorithm: alg, issuedAt: now, expiresAt: payload.exp ?? null, tokenBytes: token.length });
  }

  async verify(params: any) {
    const { publicKey, token, algorithm = 'hybrid', format = 'base64' } = params ?? {};
    const parts = String(token).split('.');
    if (parts.length !== 3) return this.json({ valid: false, reason: 'malformed token' });

    const signingInput = parts[0] + '.' + parts[1];
    let signatureValid = false;
    try {
      const pk = decFmt(publicKey, format);
      const sig = fromB64url(parts[2]);
      signatureValid = algorithm === 'hybrid'
        ? hybridVerify(pk, utf8(signingInput), sig).valid
        : ml_dsa65.verify(sig, utf8(signingInput), pk);
    } catch (error) {
      this.logger.warn(`PQ-JWT verification rejected malformed input: ${error instanceof Error ? error.message : String(error)}`);
      signatureValid = false;
    }

    let claims: any = {};
    try {
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
      return this.json({ valid: false, reason: 'unparseable payload' });
    }

    const now = Math.floor(Date.now() / 1000);
    const expired = typeof claims.exp === 'number' ? now >= claims.exp : false;
    const notYetValid = typeof claims.nbf === 'number' ? now < claims.nbf : false;

    return this.json({
      valid: signatureValid && !expired && !notYetValid,
      signatureValid,
      expired,
      notYetValid,
      claims,
    });
  }
}
