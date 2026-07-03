import { Logger } from 'winston';
import NodeCache from 'node-cache';
import * as crypto from 'crypto';
import { hybridSign, hybridVerify } from './hybrid-pqc.js';
import { b64, ub, utf8, stableStringify } from './canonical.js';

/**
 * Post-quantum PKI: issue and verify quantum-safe certificates.
 *
 * A certificate binds a subject identity to a (hybrid) public key, signed by an
 * issuer (a CA, or itself for a self-signed root) using a hybrid Ed25519 +
 * ML-DSA-65 signature. The format is a deterministic JSON document (not X.509
 * ASN.1 — interop with classical PKI would require ASN.1 encoding), suitable for
 * agent/service identity within a PQ trust domain.
 */
export class PQCertificateHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  private json(obj: any) {
    return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
  }

  /**
   * Issue a certificate. Self-signed if `issuer`/`issuerPrivateKey` reference
   * the subject; otherwise signed by a CA's hybrid signing key.
   */
  async issue(params: any) {
    const {
      subject,
      subjectPublicKey,
      issuerPrivateKey,
      issuer,
      issuerPublicKey,
      validityDays = 365,
      isCA = false,
    } = params ?? {};
    if (!subject || !subjectPublicKey || !issuerPrivateKey) {
      throw new Error('issue-certificate requires subject, subjectPublicKey, issuerPrivateKey');
    }

    const now = Date.now();
    const certificate = {
      version: 1,
      serialNumber: crypto.randomBytes(16).toString('hex'),
      subject,
      subjectPublicKey,
      issuer: issuer ?? subject,
      issuerPublicKey: issuerPublicKey ?? subjectPublicKey,
      notBefore: new Date(now).toISOString(),
      notAfter: new Date(now + Number(validityDays) * 86400000).toISOString(),
      isCA: Boolean(isCA),
      sigScheme: 'Ed25519+ML-DSA-65',
    };

    const signature = hybridSign(ub(issuerPrivateKey), utf8(stableStringify(certificate)));
    this.logger.info(`Issued certificate for "${subject}" (serial ${certificate.serialNumber.slice(0, 8)}…)`);
    return this.json({
      certificate,
      signature: b64(signature),
      selfSigned: certificate.issuer === certificate.subject,
    });
  }

  /**
   * Verify a certificate's signature and validity window. Optionally check it
   * was issued by a given CA certificate (one-level chain).
   */
  async verify(params: any) {
    const { certificate, signature, issuerPublicKey, caCertificate } = params ?? {};
    if (!certificate || !signature) throw new Error('verify-certificate requires certificate and signature');

    const verifyKey = issuerPublicKey ?? caCertificate?.subjectPublicKey ?? certificate.issuerPublicKey;
    let sig = { valid: false } as { valid: boolean };
    try {
      sig = hybridVerify(ub(verifyKey), utf8(stableStringify(certificate)), ub(signature));
    } catch (error) {
      this.logger.warn(`Certificate verification rejected malformed input: ${error instanceof Error ? error.message : String(error)}`);
    }

    const now = Date.now();
    const notBefore = Date.parse(certificate.notBefore);
    const notAfter = Date.parse(certificate.notAfter);
    const expired = now > notAfter;
    const notYetValid = now < notBefore;
    const timeValid = !expired && !notYetValid;

    // One-level chain: if a CA cert is supplied, the issuer must match it and it must be a CA.
    let chainValid = true;
    if (caCertificate) {
      chainValid = caCertificate.isCA === true && certificate.issuer === caCertificate.subject;
    }

    return this.json({
      valid: sig.valid && timeValid && chainValid,
      signatureValid: sig.valid,
      timeValid,
      expired,
      notYetValid,
      chainValid,
      subject: certificate.subject,
      serialNumber: certificate.serialNumber,
    });
  }
}
