import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { falcon512, falcon1024 } from '@noble/post-quantum/falcon.js';

// Real Falcon implementation using @noble/post-quantum
// FN-DSA — FFT over NTRU Lattice Digital Signature Algorithm (NIST Round 3 finalist)

const FALCON_INSTANCES = {
  'falcon512': falcon512,
  'falcon-512': falcon512,
  'fn-dsa-512': falcon512,
  'falcon1024': falcon1024,
  'falcon-1024': falcon1024,
  'fn-dsa-1024': falcon1024,
} as const;

type FalconParameterSet = keyof typeof FALCON_INSTANCES;

export class FalconHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache
  ) {}

  async generateKeyPair(params: any) {
    const { parameterSet = 'falcon512', format = 'base64' } = params;

    try {
      const fal = FALCON_INSTANCES[parameterSet as FalconParameterSet];
      if (!fal) {
        throw new Error(`Unsupported parameter set: ${parameterSet}. Supported: ${Object.keys(FALCON_INSTANCES).join(', ')}`);
      }

      // Real Falcon key generation — NTRU lattice-based, compact signatures
      const keys = fal.keygen();
      const publicKey = Buffer.from(keys.publicKey);
      const privateKey = Buffer.from(keys.secretKey);

      const result = {
        algorithm: 'falcon',
        parameterSet,
        publicKey: this.formatOutput(publicKey, format),
        privateKey: this.formatOutput(privateKey, format),
        publicKeySize: publicKey.length,
        privateKeySize: privateKey.length,
        securityLevel: this.getSecurityLevel(parameterSet),
        implementation: '@noble/post-quantum (Falcon/FN-DSA)',
        generated: new Date().toISOString()
      };

      this.logger.info(`Generated Falcon key pair: ${parameterSet} (${publicKey.length}B pub, ${privateKey.length}B sec)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('Falcon key generation failed:', error);
      throw error;
    }
  }

  async sign(params: any) {
    const { privateKey, message, parameterSet = 'falcon512', format = 'base64' } = params;

    try {
      const sk = this.parseInput(privateKey, format);
      const msg = new Uint8Array(Buffer.from(message, 'utf8'));

      const fal = FALCON_INSTANCES[parameterSet as FalconParameterSet];
      if (!fal) {
        throw new Error(`Unsupported parameter set: ${parameterSet}`);
      }

      // Real Falcon signing — FFT-based Gaussian sampling over NTRU lattice
      // @noble API is sign(message, secretKey) — order matters.
      const signature = fal.sign(msg, new Uint8Array(sk));
      const sigBuf = Buffer.from(signature);

      const result = {
        signature: this.formatOutput(sigBuf, format),
        signatureSize: sigBuf.length,
        algorithm: 'falcon',
        parameterSet,
        messageLength: msg.length,
        implementation: '@noble/post-quantum (Falcon/FN-DSA)'
      };

      this.logger.info(`Falcon signing completed: ${parameterSet} (${sigBuf.length}B signature)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('Falcon signing failed:', error);
      throw error;
    }
  }

  async verify(params: any) {
    const { publicKey, message, signature, parameterSet = 'falcon512', format = 'base64' } = params;

    const fal = FALCON_INSTANCES[parameterSet as FalconParameterSet];
    if (!fal) {
      throw new Error(`Unsupported parameter set: ${parameterSet}`);
    }

    const msg = new Uint8Array(Buffer.from(message, 'utf8'));
    let isValid = false;
    let signatureSize = 0;
    try {
      const pk = this.parseInput(publicKey, format);
      const sig = this.parseInput(signature, format);
      signatureSize = sig.length;
      // @noble API is verify(signature, message, publicKey) — order matters.
      isValid = fal.verify(new Uint8Array(sig), msg, new Uint8Array(pk));
    } catch (error) {
      // A malformed/wrong-length signature or key is NOT a valid signature.
      // A verifier must fail safely (return false), never throw on bad input.
      this.logger.warn(`Falcon verification rejected malformed input: ${error instanceof Error ? error.message : String(error)}`);
      isValid = false;
    }

    const result = {
      valid: isValid,
      algorithm: 'falcon',
      parameterSet,
      messageLength: msg.length,
      signatureSize,
      implementation: '@noble/post-quantum (Falcon/FN-DSA)',
      timestamp: new Date().toISOString()
    };

    this.logger.info(`Falcon verification completed: ${isValid}`);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }

  private formatOutput(data: Buffer, format: string): string {
    return format === 'hex' ? data.toString('hex') : data.toString('base64');
  }

  private parseInput(data: string, format: string): Buffer {
    return Buffer.from(data, format === 'hex' ? 'hex' : 'base64');
  }

  private getSecurityLevel(parameterSet: string): number {
    const levels: Record<string, number> = {
      'falcon512': 1, 'falcon-512': 1, 'fn-dsa-512': 1,    // NIST Level 1
      'falcon1024': 5, 'falcon-1024': 5, 'fn-dsa-1024': 5   // NIST Level 5
    };
    return levels[parameterSet] || 1;
  }
}
