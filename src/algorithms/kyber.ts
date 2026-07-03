import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

// Real ML-KEM (Kyber) implementation using @noble/post-quantum
// FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism

const KEM_INSTANCES = {
  'kyber512': ml_kem512,
  'ml-kem-512': ml_kem512,
  'kyber768': ml_kem768,
  'ml-kem-768': ml_kem768,
  'kyber1024': ml_kem1024,
  'ml-kem-1024': ml_kem1024,
} as const;

type KyberParameterSet = keyof typeof KEM_INSTANCES;

export class KyberHandler {
  constructor(
    private logger: Logger,
    private cache: NodeCache
  ) {}

  async generateKeyPair(params: any) {
    const { parameterSet = 'kyber768', format = 'base64' } = params;

    try {
      const cacheKey = `kyber-keypair-${parameterSet}`;
      const cached = this.cache.get(cacheKey);
      if (cached && process.env.ENABLE_KEY_CACHE === 'true') {
        this.logger.debug('Returning cached key pair');
        return { content: [{ type: 'text', text: JSON.stringify(cached) }] };
      }

      const kem = KEM_INSTANCES[parameterSet as KyberParameterSet];
      if (!kem) {
        throw new Error(`Unsupported parameter set: ${parameterSet}. Supported: ${Object.keys(KEM_INSTANCES).join(', ')}`);
      }

      // Real ML-KEM key generation — lattice-based, quantum-resistant
      const keys = kem.keygen();
      const publicKey = Buffer.from(keys.publicKey);
      const privateKey = Buffer.from(keys.secretKey);

      const result = {
        algorithm: 'ml-kem',
        parameterSet,
        publicKey: this.formatOutput(publicKey, format),
        privateKey: this.formatOutput(privateKey, format),
        publicKeySize: publicKey.length,
        privateKeySize: privateKey.length,
        securityLevel: this.getSecurityLevel(parameterSet),
        implementation: '@noble/post-quantum (FIPS 203)',
        generated: new Date().toISOString()
      };

      if (process.env.ENABLE_KEY_CACHE === 'true') {
        this.cache.set(cacheKey, result, 300);
      }

      this.logger.info(`Generated ML-KEM key pair: ${parameterSet} (${publicKey.length}B pub, ${privateKey.length}B sec)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('ML-KEM key generation failed:', error);
      throw error;
    }
  }

  async encapsulate(params: any) {
    const { publicKey, parameterSet = 'kyber768', format = 'base64' } = params;

    try {
      const pk = this.parseInput(publicKey, format);

      const kem = KEM_INSTANCES[parameterSet as KyberParameterSet];
      if (!kem) {
        throw new Error(`Unsupported parameter set: ${parameterSet}`);
      }

      // Real ML-KEM encapsulation — produces ciphertext + shared secret
      const { cipherText, sharedSecret } = kem.encapsulate(new Uint8Array(pk));

      const ctBuf = Buffer.from(cipherText);
      const ssBuf = Buffer.from(sharedSecret);

      const result = {
        sharedSecret: this.formatOutput(ssBuf, format),
        ciphertext: this.formatOutput(ctBuf, format),
        ciphertextSize: ctBuf.length,
        sharedSecretSize: ssBuf.length,
        algorithm: 'ml-kem',
        parameterSet,
        implementation: '@noble/post-quantum (FIPS 203)'
      };

      this.logger.info(`ML-KEM encapsulation completed: ${parameterSet} (${ctBuf.length}B ciphertext)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('ML-KEM encapsulation failed:', error);
      throw error;
    }
  }

  async decapsulate(params: any) {
    const { privateKey, ciphertext, parameterSet = 'kyber768', format = 'base64' } = params;

    try {
      const sk = this.parseInput(privateKey, format);
      const ct = this.parseInput(ciphertext, format);

      const kem = KEM_INSTANCES[parameterSet as KyberParameterSet];
      if (!kem) {
        throw new Error(`Unsupported parameter set: ${parameterSet}`);
      }

      // Real ML-KEM decapsulation — recovers shared secret from ciphertext + secret key
      const sharedSecret = kem.decapsulate(new Uint8Array(ct), new Uint8Array(sk));
      const ssBuf = Buffer.from(sharedSecret);

      const result = {
        sharedSecret: this.formatOutput(ssBuf, format),
        sharedSecretSize: ssBuf.length,
        algorithm: 'ml-kem',
        parameterSet,
        success: true,
        implementation: '@noble/post-quantum (FIPS 203)'
      };

      this.logger.info(`ML-KEM decapsulation completed: ${parameterSet}`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('ML-KEM decapsulation failed:', error);
      throw error;
    }
  }

  private formatOutput(data: Buffer, format: string): string {
    switch (format) {
      case 'hex':
        return data.toString('hex');
      case 'base64':
        return data.toString('base64');
      default:
        return data.toString('base64');
    }
  }

  private parseInput(data: string, format: string): Buffer {
    switch (format) {
      case 'hex':
        return Buffer.from(data, 'hex');
      case 'base64':
        return Buffer.from(data, 'base64');
      default:
        return Buffer.from(data, 'base64');
    }
  }

  private getSecurityLevel(parameterSet: string): number {
    const levels: Record<string, number> = {
      'kyber512': 1, 'ml-kem-512': 1,   // NIST Level 1 (~AES-128)
      'kyber768': 3, 'ml-kem-768': 3,   // NIST Level 3 (~AES-192)
      'kyber1024': 5, 'ml-kem-1024': 5  // NIST Level 5 (~AES-256)
    };
    return levels[parameterSet] || 3;
  }
}
