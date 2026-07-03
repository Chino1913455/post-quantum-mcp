import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

// Real ML-DSA (Dilithium) implementation using @noble/post-quantum
// FIPS 204 — Module-Lattice-Based Digital Signature Algorithm

const DSA_INSTANCES = {
  'dilithium2': ml_dsa44,
  'ml-dsa-44': ml_dsa44,
  'dilithium3': ml_dsa65,
  'ml-dsa-65': ml_dsa65,
  'dilithium5': ml_dsa87,
  'ml-dsa-87': ml_dsa87,
} as const;

type DilithiumParameterSet = keyof typeof DSA_INSTANCES;

export class DilithiumHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache
  ) {}

  async generateKeyPair(params: any) {
    const { parameterSet = 'dilithium3', format = 'base64' } = params;

    try {
      const dsa = DSA_INSTANCES[parameterSet as DilithiumParameterSet];
      if (!dsa) {
        throw new Error(`Unsupported parameter set: ${parameterSet}. Supported: ${Object.keys(DSA_INSTANCES).join(', ')}`);
      }

      // Real ML-DSA key generation — lattice-based signatures, quantum-resistant
      const keys = dsa.keygen();
      const publicKey = Buffer.from(keys.publicKey);
      const privateKey = Buffer.from(keys.secretKey);

      const result = {
        algorithm: 'ml-dsa',
        parameterSet,
        publicKey: this.formatOutput(publicKey, format),
        privateKey: this.formatOutput(privateKey, format),
        publicKeySize: publicKey.length,
        privateKeySize: privateKey.length,
        securityLevel: this.getSecurityLevel(parameterSet),
        implementation: '@noble/post-quantum (FIPS 204)',
        generated: new Date().toISOString()
      };

      this.logger.info(`Generated ML-DSA key pair: ${parameterSet} (${publicKey.length}B pub, ${privateKey.length}B sec)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('ML-DSA key generation failed:', error);
      throw error;
    }
  }

  async sign(params: any) {
    const { privateKey, message, format = 'base64' } = params;

    try {
      const sk = this.parseInput(privateKey, format);
      const msg = new Uint8Array(Buffer.from(message, 'utf8'));

      // Determine parameter set from secret key size
      const dsa = this.dsaFromSecretKeySize(sk.length);

      // Real ML-DSA signing — deterministic lattice-based signature
      const signature = dsa.sign(msg, Uint8Array.from(sk));
      const sigBuf = Buffer.from(signature);

      const result = {
        signature: this.formatOutput(sigBuf, format),
        signatureSize: sigBuf.length,
        algorithm: 'ml-dsa',
        messageLength: msg.length,
        implementation: '@noble/post-quantum (FIPS 204)'
      };

      this.logger.info(`ML-DSA signing completed (${sigBuf.length}B signature)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('ML-DSA signing failed:', error);
      throw error;
    }
  }

  async verify(params: any) {
    const { publicKey, message, signature, format = 'base64' } = params;

    const msg = new Uint8Array(Buffer.from(message, 'utf8'));
    let isValid = false;
    let signatureSize = 0;
    try {
      const pk = this.parseInput(publicKey, format);
      const sig = this.parseInput(signature, format);
      signatureSize = sig.length;
      // Determine parameter set from public key size.
      const dsa = this.dsaFromPublicKeySize(pk.length);
      isValid = dsa.verify(Uint8Array.from(sig), msg, Uint8Array.from(pk));
    } catch (error) {
      // A malformed/wrong-length signature or key is NOT a valid signature.
      // A verifier must fail safely (return false), never throw on bad input.
      this.logger.warn(`ML-DSA verification rejected malformed input: ${error instanceof Error ? error.message : String(error)}`);
      isValid = false;
    }

    const result = {
      valid: isValid,
      algorithm: 'ml-dsa',
      messageLength: msg.length,
      signatureSize,
      implementation: '@noble/post-quantum (FIPS 204)',
      timestamp: new Date().toISOString()
    };

    this.logger.info(`ML-DSA verification completed: ${isValid}`);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }

  private dsaFromSecretKeySize(size: number) {
    // ML-DSA secret key sizes: ml_dsa44=2560, ml_dsa65=4032, ml_dsa87=4896
    if (size <= 2560) return ml_dsa44;
    if (size <= 4032) return ml_dsa65;
    return ml_dsa87;
  }

  private dsaFromPublicKeySize(size: number) {
    // ML-DSA public key sizes: ml_dsa44=1312, ml_dsa65=1952, ml_dsa87=2592
    if (size <= 1312) return ml_dsa44;
    if (size <= 1952) return ml_dsa65;
    return ml_dsa87;
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
      'dilithium2': 2, 'ml-dsa-44': 2,  // NIST Level 2 (~128-bit)
      'dilithium3': 3, 'ml-dsa-65': 3,  // NIST Level 3 (~192-bit)
      'dilithium5': 5, 'ml-dsa-87': 5   // NIST Level 5 (~256-bit)
    };
    return levels[parameterSet] || 3;
  }
}
