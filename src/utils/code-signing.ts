import { Logger } from 'winston';
import NodeCache from 'node-cache';
import * as crypto from 'crypto';
import { hybridSign, hybridVerify } from './hybrid-pqc.js';
import { b64, ub, utf8, stableStringify } from './canonical.js';

/**
 * Quantum-safe code / SBOM / artifact signing.
 *
 * Supply-chain integrity (signing releases, container images, SBOMs) is among
 * the highest-demand security use cases, and signatures must outlive the
 * quantum transition: a firmware image signed today may be verified for 15+
 * years. This produces a hybrid (Ed25519 + ML-DSA-65) signature over a
 * deterministic envelope binding the artifact digest, timestamp, and metadata —
 * an in-toto-style attestation.
 */
export class CodeSigningHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  private json(obj: any) {
    return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
  }

  private digestOf(artifact: string | undefined, digest: string | undefined, algo: string): string {
    if (digest) return digest.toLowerCase();
    if (artifact !== undefined && artifact !== null) {
      return crypto.createHash(algo).update(Buffer.from(String(artifact), 'utf8')).digest('hex');
    }
    throw new Error('Provide either "artifact" (content to hash) or "digest" (precomputed hex).');
  }

  /** Sign an artifact (or its digest) and return a verifiable envelope. */
  async signArtifact(params: any) {
    const { privateKey, artifact, digest, digestAlgorithm = 'sha256', metadata = {} } = params ?? {};
    const artifactDigest = this.digestOf(artifact, digest, digestAlgorithm);

    // The signed envelope binds digest + provenance. `signature` is NOT part of it.
    const envelope = {
      artifactDigest,
      digestAlgorithm,
      scheme: 'Ed25519+ML-DSA-65',
      signedAt: new Date().toISOString(),
      metadata,
    };
    const signature = hybridSign(ub(privateKey), utf8(stableStringify(envelope)));
    this.logger.info(`Signed artifact ${artifactDigest.slice(0, 16)}…`);
    return this.json({ ...envelope, signature: b64(signature) });
  }

  /**
   * Verify a signed artifact. Pass back the full object returned by
   * sign-artifact as `signedArtifact`; optionally pass `artifact` to also
   * confirm the content still hashes to the signed digest.
   */
  async verifyArtifact(params: any) {
    const { publicKey, signedArtifact, artifact } = params ?? {};
    if (!signedArtifact || typeof signedArtifact !== 'object') {
      throw new Error('verify-artifact: "signedArtifact" (the sign-artifact output) is required');
    }
    const { signature, ...envelope } = signedArtifact;

    let digestMatch = true;
    if (artifact !== undefined && artifact !== null) {
      const recomputed = crypto
        .createHash(envelope.digestAlgorithm || 'sha256')
        .update(Buffer.from(String(artifact), 'utf8'))
        .digest('hex');
      digestMatch = recomputed === envelope.artifactDigest;
    }

    let r = { edValid: false, pqValid: false, valid: false };
    try {
      r = hybridVerify(ub(publicKey), utf8(stableStringify(envelope)), ub(signature));
    } catch (error) {
      this.logger.warn(`Artifact verification rejected malformed input: ${error instanceof Error ? error.message : String(error)}`);
    }

    const valid = r.valid && digestMatch;
    this.logger.info(`Artifact verification: ${valid} (sig=${r.valid}, digest=${digestMatch})`);
    return this.json({
      valid,
      signatureValid: r.valid,
      digestMatch,
      components: { ed25519: r.edValid, 'ml-dsa-65': r.pqValid },
      artifactDigest: envelope.artifactDigest,
    });
  }
}
