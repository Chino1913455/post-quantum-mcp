import { Logger } from 'winston';
import NodeCache from 'node-cache';
import * as crypto from 'crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

// Real hybrid encryption: ML-KEM (quantum-resistant KEM) + AES-256-GCM (symmetric)
// This is the recommended approach for quantum-safe encryption in transit

export class HybridCryptoHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache
  ) {}

  async encrypt(params: any) {
    const { publicKey, data, algorithm = 'kyber-aes', format = 'base64' } = params;

    try {
      const pk = this.parseInput(publicKey, format);
      const plaintext = Buffer.from(data, 'utf8');

      // Real ML-KEM encapsulation — produces quantum-resistant shared secret
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(new Uint8Array(pk));

      // Derive symmetric key from shared secret using HKDF-like construction
      const symmetricKey = crypto.createHash('sha256').update(Buffer.from(sharedSecret)).digest();
      const iv = crypto.randomBytes(12); // 96-bit IV for GCM

      // Encrypt data with AES-256-GCM using the KEM-derived key
      const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
      const encrypted = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
      ]);
      const authTag = cipher.getAuthTag();

      const ctBuf = Buffer.from(cipherText);

      const result = {
        algorithm,
        encapsulatedKey: this.formatOutput(ctBuf, format),
        encapsulatedKeySize: ctBuf.length,
        encryptedData: this.formatOutput(encrypted, format),
        iv: this.formatOutput(iv, format),
        authTag: this.formatOutput(authTag, format),
        kemAlgorithm: 'ml-kem-768',
        symmetricAlgorithm: 'aes-256-gcm',
        implementation: '@noble/post-quantum (FIPS 203) + Node.js AES-256-GCM',
        timestamp: new Date().toISOString()
      };

      this.logger.info(`Hybrid encryption completed: ML-KEM-768 + AES-256-GCM (${encrypted.length}B ciphertext)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('Hybrid encryption failed:', error);
      throw error;
    }
  }

  async decrypt(params: any) {
    const { privateKey, encryptedData, algorithm = 'kyber-aes', format = 'base64' } = params;

    try {
      const encData = typeof encryptedData === 'string'
        ? JSON.parse(encryptedData)
        : encryptedData;

      const sk = this.parseInput(privateKey, format);
      const kemCiphertext = this.parseInput(encData.encapsulatedKey, format);
      const ciphertext = this.parseInput(encData.encryptedData, format);
      const iv = this.parseInput(encData.iv, format);
      const authTag = this.parseInput(encData.authTag, format);

      // Real ML-KEM decapsulation — recovers quantum-resistant shared secret
      const sharedSecret = ml_kem768.decapsulate(new Uint8Array(kemCiphertext), new Uint8Array(sk));

      // Derive symmetric key from shared secret (same derivation as encrypt)
      const symmetricKey = crypto.createHash('sha256').update(Buffer.from(sharedSecret)).digest();

      // Decrypt data with AES-256-GCM
      const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
      decipher.setAuthTag(authTag);

      const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);

      const result = {
        decryptedData: decrypted.toString('utf8'),
        algorithm,
        kemAlgorithm: 'ml-kem-768',
        symmetricAlgorithm: 'aes-256-gcm',
        success: true,
        implementation: '@noble/post-quantum (FIPS 203) + Node.js AES-256-GCM',
        timestamp: new Date().toISOString()
      };

      this.logger.info(`Hybrid decryption completed: ML-KEM-768 + AES-256-GCM`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('Hybrid decryption failed:', error);
      throw error;
    }
  }

  private formatOutput(data: Buffer, format: string): string {
    return format === 'hex' ? data.toString('hex') : data.toString('base64');
  }

  private parseInput(data: string, format: string): Buffer {
    return Buffer.from(data, format === 'hex' ? 'hex' : 'base64');
  }
}
