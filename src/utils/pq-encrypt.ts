import { Logger } from 'winston';
import NodeCache from 'node-cache';
import * as crypto from 'crypto';
import { hybridKemEncapsulate, hybridKemDecapsulate } from './hybrid-pqc.js';
import { b64, decFmt } from './canonical.js';

/**
 * Quantum-safe document / multi-recipient encryption (a PQ "envelope", like
 * age/PGP but hybrid-post-quantum).
 *
 * A random AES-256-GCM content key encrypts the payload once; that content key
 * is then wrapped separately for each recipient using a hybrid X-Wing KEM. Any
 * one recipient can decrypt; recipients learn nothing about each other's keys.
 * Works on arbitrary bytes (files, documents, blobs) supplied as base64.
 */
function deriveWrapKey(sharedSecret: Uint8Array): Buffer {
  return crypto.createHash('sha256').update(Buffer.from(sharedSecret)).digest();
}

export class PQEncryptHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  private json(obj: any) {
    return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
  }

  /** Encrypt base64 data to one or more hybrid-KEM public keys. */
  async encryptDocument(params: any) {
    const { recipients, data, format = 'base64' } = params ?? {};
    if (!Array.isArray(recipients) || recipients.length === 0) {
      throw new Error('encrypt-document: "recipients" must be a non-empty array of hybrid KEM public keys');
    }

    const contentKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', contentKey, iv);
    const ct = Buffer.concat([cipher.update(Buffer.from(String(data), 'base64')), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const wrapped = recipients.map((pk: string) => {
      const { ciphertext, sharedSecret } = hybridKemEncapsulate(decFmt(pk, format));
      const wk = deriveWrapKey(sharedSecret);
      const wiv = crypto.randomBytes(12);
      const wc = crypto.createCipheriv('aes-256-gcm', wk, wiv);
      const wrappedKey = Buffer.concat([wc.update(contentKey), wc.final()]);
      return {
        kemCiphertext: b64(ciphertext),
        wrappedKey: wrappedKey.toString('base64'),
        wrapIv: wiv.toString('base64'),
        wrapTag: wc.getAuthTag().toString('base64'),
      };
    });

    this.logger.info(`Encrypted document for ${recipients.length} recipient(s)`);
    return this.json({
      scheme: 'x-wing + aes-256-gcm (multi-recipient envelope)',
      ciphertext: ct.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      recipients: wrapped,
      recipientCount: wrapped.length,
    });
  }

  /** Decrypt an envelope with a hybrid-KEM private key (finds the matching recipient). */
  async decryptDocument(params: any) {
    const { privateKey, envelope, format = 'base64' } = params ?? {};
    if (!envelope || !Array.isArray(envelope.recipients)) {
      throw new Error('decrypt-document: "envelope" with a recipients array is required');
    }
    const sk = decFmt(privateKey, format);

    let contentKey: Buffer | null = null;
    for (const r of envelope.recipients) {
      try {
        const ss = hybridKemDecapsulate(sk, decFmt(r.kemCiphertext, 'base64'));
        const wk = deriveWrapKey(ss);
        const wd = crypto.createDecipheriv('aes-256-gcm', wk, Buffer.from(r.wrapIv, 'base64'));
        wd.setAuthTag(Buffer.from(r.wrapTag, 'base64'));
        contentKey = Buffer.concat([wd.update(Buffer.from(r.wrappedKey, 'base64')), wd.final()]);
        break; // the GCM tag verified — this entry is ours
      } catch {
        // not our recipient entry; try the next
      }
    }
    if (!contentKey) throw new Error('Not a recipient: no wrapped content key could be unwrapped with this key');

    const d = crypto.createDecipheriv('aes-256-gcm', contentKey, Buffer.from(envelope.iv, 'base64'));
    d.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
    const pt = Buffer.concat([d.update(Buffer.from(envelope.ciphertext, 'base64')), d.final()]);

    this.logger.info('Decrypted document envelope');
    return this.json({ data: pt.toString('base64'), success: true });
  }
}
