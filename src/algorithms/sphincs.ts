import { Logger } from 'winston';
import NodeCache from 'node-cache';
import {
  slh_dsa_sha2_128f, slh_dsa_sha2_128s,
  slh_dsa_sha2_192f, slh_dsa_sha2_192s,
  slh_dsa_sha2_256f, slh_dsa_sha2_256s,
  slh_dsa_shake_128f, slh_dsa_shake_128s,
  slh_dsa_shake_192f, slh_dsa_shake_192s,
  slh_dsa_shake_256f, slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';

// Real SLH-DSA (SPHINCS+) implementation using @noble/post-quantum
// FIPS 205 — Stateless Hash-Based Digital Signature Algorithm

const SLH_INSTANCES: Record<string, typeof slh_dsa_sha2_128f> = {
  // SHA2 variants
  'sphincs-sha2-128f': slh_dsa_sha2_128f,
  'slh-dsa-sha2-128f': slh_dsa_sha2_128f,
  'sphincs-sha2-128s': slh_dsa_sha2_128s,
  'slh-dsa-sha2-128s': slh_dsa_sha2_128s,
  'sphincs-sha2-192f': slh_dsa_sha2_192f,
  'slh-dsa-sha2-192f': slh_dsa_sha2_192f,
  'sphincs-sha2-192s': slh_dsa_sha2_192s,
  'slh-dsa-sha2-192s': slh_dsa_sha2_192s,
  'sphincs-sha256-192s': slh_dsa_sha2_192s, // Legacy alias
  'sphincs-sha2-256f': slh_dsa_sha2_256f,
  'slh-dsa-sha2-256f': slh_dsa_sha2_256f,
  'sphincs-sha2-256s': slh_dsa_sha2_256s,
  'slh-dsa-sha2-256s': slh_dsa_sha2_256s,
  // SHAKE variants
  'sphincs-shake-128f': slh_dsa_shake_128f,
  'slh-dsa-shake-128f': slh_dsa_shake_128f,
  'sphincs-shake-128s': slh_dsa_shake_128s,
  'slh-dsa-shake-128s': slh_dsa_shake_128s,
  'sphincs-shake-192f': slh_dsa_shake_192f,
  'slh-dsa-shake-192f': slh_dsa_shake_192f,
  'sphincs-shake-192s': slh_dsa_shake_192s,
  'slh-dsa-shake-192s': slh_dsa_shake_192s,
  'sphincs-shake-256f': slh_dsa_shake_256f,
  'slh-dsa-shake-256f': slh_dsa_shake_256f,
  'sphincs-shake-256s': slh_dsa_shake_256s,
  'slh-dsa-shake-256s': slh_dsa_shake_256s,
  // Legacy aliases
  'sphincs-sha256-128s': slh_dsa_sha2_128s,
  'sphincs-sha256-256s': slh_dsa_sha2_256s,
};

export class SphincsPlusHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache
  ) {}

  async generateKeyPair(params: any) {
    const { parameterSet = 'sphincs-sha2-192s', format = 'base64' } = params;

    try {
      const slh = SLH_INSTANCES[parameterSet];
      if (!slh) {
        throw new Error(`Unsupported parameter set: ${parameterSet}. Supported: ${Object.keys(SLH_INSTANCES).join(', ')}`);
      }

      // Real SLH-DSA key generation — hash-based, stateless, quantum-resistant
      const keys = slh.keygen();
      const publicKey = Buffer.from(keys.publicKey);
      const privateKey = Buffer.from(keys.secretKey);

      const result = {
        algorithm: 'slh-dsa',
        parameterSet,
        publicKey: this.formatOutput(publicKey, format),
        privateKey: this.formatOutput(privateKey, format),
        publicKeySize: publicKey.length,
        privateKeySize: privateKey.length,
        securityLevel: this.getSecurityLevel(parameterSet),
        implementation: '@noble/post-quantum (FIPS 205)',
        generated: new Date().toISOString()
      };

      this.logger.info(`Generated SLH-DSA key pair: ${parameterSet} (${publicKey.length}B pub, ${privateKey.length}B sec)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('SLH-DSA key generation failed:', error);
      throw error;
    }
  }

  async sign(params: any) {
    const { privateKey, message, parameterSet = 'sphincs-sha2-192s', format = 'base64' } = params;

    try {
      const sk = this.parseInput(privateKey, format);
      const msg = new Uint8Array(Buffer.from(message, 'utf8'));

      const slh = SLH_INSTANCES[parameterSet];
      if (!slh) {
        throw new Error(`Unsupported parameter set: ${parameterSet}`);
      }

      // Real SLH-DSA signing — Merkle tree + WOTS+ hash-based signature
      // @noble API is sign(message, secretKey) — order matters.
      const signature = slh.sign(msg, new Uint8Array(sk));
      const sigBuf = Buffer.from(signature);

      const result = {
        signature: this.formatOutput(sigBuf, format),
        signatureSize: sigBuf.length,
        algorithm: 'slh-dsa',
        parameterSet,
        messageLength: msg.length,
        implementation: '@noble/post-quantum (FIPS 205)'
      };

      this.logger.info(`SLH-DSA signing completed: ${parameterSet} (${sigBuf.length}B signature)`);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('SLH-DSA signing failed:', error);
      throw error;
    }
  }

  async verify(params: any) {
    const { publicKey, message, signature, parameterSet = 'sphincs-sha2-192s', format = 'base64' } = params;

    const slh = SLH_INSTANCES[parameterSet];
    if (!slh) {
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
      isValid = slh.verify(new Uint8Array(sig), msg, new Uint8Array(pk));
    } catch (error) {
      // A malformed/wrong-length signature or key is NOT a valid signature.
      // A verifier must fail safely (return false), never throw on bad input.
      this.logger.warn(`SLH-DSA verification rejected malformed input: ${error instanceof Error ? error.message : String(error)}`);
      isValid = false;
    }

    const result = {
      valid: isValid,
      algorithm: 'slh-dsa',
      parameterSet,
      messageLength: msg.length,
      signatureSize,
      implementation: '@noble/post-quantum (FIPS 205)',
      timestamp: new Date().toISOString()
    };

    this.logger.info(`SLH-DSA verification completed: ${isValid}`);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }

  private formatOutput(data: Buffer, format: string): string {
    return format === 'hex' ? data.toString('hex') : data.toString('base64');
  }

  private parseInput(data: string, format: string): Buffer {
    return Buffer.from(data, format === 'hex' ? 'hex' : 'base64');
  }

  private getSecurityLevel(parameterSet: string): number {
    if (parameterSet.includes('128')) return 1;
    if (parameterSet.includes('192')) return 3;
    if (parameterSet.includes('256')) return 5;
    return 3;
  }
}
