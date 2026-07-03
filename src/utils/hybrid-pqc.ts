import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import * as sampling from './entropy/sampling.js';

/**
 * Hybrid (classical + post-quantum) primitives — the way PQC is actually
 * deployed in production (Cloudflare, AWS, Apple, Signal PQXDH). A hybrid scheme
 * stays secure as long as EITHER component holds, hedging against both a quantum
 * break of X25519/Ed25519 AND a classical/structural break of the newer lattice
 * schemes (which are far less battle-tested).
 *
 *  - Hybrid KEM:        X25519 + ML-KEM-768, combined per the X-Wing construction
 *                       (draft-connolly-cfrg-xwing-kem).
 *  - Hybrid signatures: Ed25519 + ML-DSA-65; verification requires BOTH to pass.
 *
 * Wire format:
 *  - KEM public  = x25519_pub(32) || mlkem_pub      KEM secret = x25519_sec(32) || mlkem_sec
 *  - KEM ct      = mlkem_ct || x25519_ct(32)
 *  - Sig public  = ed25519_pub(32) || mldsa_pub     Sig secret = ed25519_seed(32) || mldsa_sec
 *  - Signature   = ed25519_sig(64) || mldsa_sig
 *
 * The pure functions below are the canonical implementation; the MCP handler and
 * the agent-identity / code-signing modules all build on them (no duplication).
 */

export const X_LEN = 32;
export const ED_SIG_LEN = 64;
const XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]); // "\.//^\"

export function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function xWingCombine(ssM: Uint8Array, ssX: Uint8Array, ctX: Uint8Array, pkX: Uint8Array): Uint8Array {
  return sha3_256(concatBytes(XWING_LABEL, ssM, ssX, ctX, pkX));
}

// ── Pure hybrid KEM (X-Wing) ────────────────────────────────────────────────

export function hybridKemKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const xSec = sampling.randomBytes(X_LEN);
  const xPub = x25519.getPublicKey(xSec);
  const mlkem = ml_kem768.keygen();
  return {
    publicKey: concatBytes(xPub, mlkem.publicKey),
    secretKey: concatBytes(xSec, mlkem.secretKey),
  };
}

export function hybridKemEncapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  const xPub = publicKey.subarray(0, X_LEN);
  const mPub = publicKey.subarray(X_LEN);
  const ephSec = sampling.randomBytes(X_LEN);
  const ctX = x25519.getPublicKey(ephSec);
  const ssX = x25519.getSharedSecret(ephSec, xPub);
  const { cipherText: ctM, sharedSecret: ssM } = ml_kem768.encapsulate(mPub);
  return {
    ciphertext: concatBytes(ctM, ctX),
    sharedSecret: xWingCombine(ssM, ssX, ctX, xPub),
  };
}

export function hybridKemDecapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const xSec = secretKey.subarray(0, X_LEN);
  const mSec = secretKey.subarray(X_LEN);
  const ctX = ciphertext.subarray(ciphertext.length - X_LEN);
  const ctM = ciphertext.subarray(0, ciphertext.length - X_LEN);
  const ssM = ml_kem768.decapsulate(ctM, mSec);
  const ssX = x25519.getSharedSecret(xSec, ctX);
  const xPub = x25519.getPublicKey(xSec);
  return xWingCombine(ssM, ssX, ctX, xPub);
}

// ── Pure hybrid signatures (Ed25519 + ML-DSA-65) ────────────────────────────

export function hybridSignKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const edSeed = sampling.randomBytes(X_LEN);
  const edPub = ed25519.getPublicKey(edSeed);
  const mldsa = ml_dsa65.keygen();
  return {
    publicKey: concatBytes(edPub, mldsa.publicKey),
    secretKey: concatBytes(edSeed, mldsa.secretKey),
  };
}

export function hybridSign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  const edSeed = secretKey.subarray(0, X_LEN);
  const mSec = secretKey.subarray(X_LEN);
  return concatBytes(ed25519.sign(message, edSeed), ml_dsa65.sign(message, mSec));
}

/** Total verify: malformed input yields { valid: false }, never throws. */
export function hybridVerify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): { edValid: boolean; pqValid: boolean; valid: boolean } {
  let edValid = false;
  let pqValid = false;
  try {
    const edPub = publicKey.subarray(0, X_LEN);
    const mPub = publicKey.subarray(X_LEN);
    const edSig = signature.subarray(0, ED_SIG_LEN);
    const mSig = signature.subarray(ED_SIG_LEN);
    edValid = ed25519.verify(edSig, message, edPub);
    pqValid = ml_dsa65.verify(mSig, message, mPub);
  } catch {
    edValid = false;
    pqValid = false;
  }
  return { edValid, pqValid, valid: edValid && pqValid };
}

// ── I/O helpers + MCP handler ───────────────────────────────────────────────

function enc(data: Uint8Array, format: string): string {
  return Buffer.from(data).toString(format === 'hex' ? 'hex' : 'base64');
}
function dec(s: string, format: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, format === 'hex' ? 'hex' : 'base64'));
}

export class HybridPQCHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  async kemKeygen(params: any) {
    const { format = 'base64' } = params ?? {};
    const kp = hybridKemKeypair();
    this.logger.info('Hybrid KEM (X-Wing) key pair generated');
    return this.json({
      scheme: 'x-wing',
      kem: 'X25519 + ML-KEM-768',
      publicKey: enc(kp.publicKey, format),
      privateKey: enc(kp.secretKey, format),
      classical: 'x25519',
      postQuantum: 'ml-kem-768 (FIPS 203)',
      generated: new Date().toISOString(),
    });
  }

  async kemEncapsulate(params: any) {
    const { publicKey, format = 'base64' } = params ?? {};
    const { ciphertext, sharedSecret } = hybridKemEncapsulate(dec(publicKey, format));
    this.logger.info('Hybrid KEM encapsulation completed');
    return this.json({
      scheme: 'x-wing',
      sharedSecret: enc(sharedSecret, format),
      ciphertext: enc(ciphertext, format),
      sharedSecretSize: sharedSecret.length,
      ciphertextSize: ciphertext.length,
    });
  }

  async kemDecapsulate(params: any) {
    const { privateKey, ciphertext, format = 'base64' } = params ?? {};
    const sharedSecret = hybridKemDecapsulate(dec(privateKey, format), dec(ciphertext, format));
    this.logger.info('Hybrid KEM decapsulation completed');
    return this.json({ scheme: 'x-wing', sharedSecret: enc(sharedSecret, format), sharedSecretSize: sharedSecret.length, success: true });
  }

  async signKeygen(params: any) {
    const { format = 'base64' } = params ?? {};
    const kp = hybridSignKeypair();
    this.logger.info('Hybrid signature key pair generated');
    return this.json({
      scheme: 'hybrid-sign',
      signature: 'Ed25519 + ML-DSA-65',
      publicKey: enc(kp.publicKey, format),
      privateKey: enc(kp.secretKey, format),
      classical: 'ed25519',
      postQuantum: 'ml-dsa-65 (FIPS 204)',
      generated: new Date().toISOString(),
    });
  }

  async sign(params: any) {
    const { privateKey, message, format = 'base64' } = params ?? {};
    const sig = hybridSign(dec(privateKey, format), new Uint8Array(Buffer.from(message, 'utf8')));
    this.logger.info('Hybrid signature created');
    return this.json({ scheme: 'hybrid-sign', signature: enc(sig, format), signatureSize: sig.length });
  }

  async verify(params: any) {
    const { publicKey, message, signature, format = 'base64' } = params ?? {};
    let r = { edValid: false, pqValid: false, valid: false };
    try {
      r = hybridVerify(dec(publicKey, format), new Uint8Array(Buffer.from(message, 'utf8')), dec(signature, format));
    } catch (error) {
      this.logger.warn(`Hybrid verification rejected malformed input: ${error instanceof Error ? error.message : String(error)}`);
    }
    this.logger.info(`Hybrid verification: ${r.valid}`);
    return this.json({
      scheme: 'hybrid-sign',
      valid: r.valid,
      components: { ed25519: r.edValid, 'ml-dsa-65': r.pqValid },
      timestamp: new Date().toISOString(),
    });
  }

  private json(obj: any) {
    return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
  }
}
