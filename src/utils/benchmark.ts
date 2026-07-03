import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128f } from '@noble/post-quantum/slh-dsa.js';
import { falcon512, falcon1024 } from '@noble/post-quantum/falcon.js';

interface BenchmarkResult {
  algorithm: string;
  parameterSet: string;
  operation: string;
  iterations: number;
  averageMs: number;
  minMs: number;
  maxMs: number;
  opsPerSec: number;
}

/**
 * Real performance benchmarks for the NIST post-quantum algorithms, measured by
 * running the actual @noble/post-quantum primitives (not simulated delays).
 */
export class BenchmarkHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  async benchmark(params: any) {
    const { algorithm = 'all', operations = 100 } = params ?? {};
    const iterations = Math.max(1, Math.min(10_000, operations));

    try {
      const algos =
        algorithm === 'all'
          ? ['kyber', 'dilithium', 'sphincs', 'falcon']
          : [algorithm];

      const results: BenchmarkResult[] = [];
      for (const alg of algos) {
        const suite = this.buildSuite(alg);
        for (const [operation, fn] of Object.entries(suite.ops)) {
          results.push(this.time(alg, suite.parameterSet, operation, iterations, fn));
        }
      }

      const summary = {
        results,
        note: 'Measured against @noble/post-quantum (real operations, not simulated).',
        timestamp: new Date().toISOString(),
        system: { platform: process.platform, arch: process.arch, nodeVersion: process.version },
      };

      this.logger.info(`Benchmark completed for ${algos.join(', ')} (${iterations} iters)`);
      return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
    } catch (error) {
      this.logger.error('Benchmark failed:', error);
      throw error;
    }
  }

  private time(
    algorithm: string,
    parameterSet: string,
    operation: string,
    iterations: number,
    fn: () => void,
  ): BenchmarkResult {
    // Warm-up to stabilize JIT before measuring.
    for (let i = 0; i < Math.min(10, iterations); i++) fn();

    let min = Infinity;
    let max = 0;
    let total = 0;
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      fn();
      const ms = Number(process.hrtime.bigint() - start) / 1e6;
      total += ms;
      if (ms < min) min = ms;
      if (ms > max) max = ms;
    }
    const avg = total / iterations;
    return {
      algorithm,
      parameterSet,
      operation,
      iterations,
      averageMs: round(avg),
      minMs: round(min),
      maxMs: round(max),
      opsPerSec: Math.round(1000 / avg),
    };
  }

  /** Build the set of real operations to benchmark for an algorithm. */
  private buildSuite(algorithm: string): { parameterSet: string; ops: Record<string, () => void> } {
    const msg = new TextEncoder().encode('post-quantum benchmark message');
    switch (algorithm) {
      case 'kyber': {
        const kem = ml_kem768;
        const kp = kem.keygen();
        const { cipherText } = kem.encapsulate(kp.publicKey);
        return {
          parameterSet: 'ml-kem-768',
          ops: {
            keygen: () => void kem.keygen(),
            encapsulate: () => void kem.encapsulate(kp.publicKey),
            decapsulate: () => void kem.decapsulate(cipherText, kp.secretKey),
          },
        };
      }
      case 'dilithium': {
        const dsa = ml_dsa65;
        const kp = dsa.keygen();
        const sig = dsa.sign(msg, kp.secretKey);
        return {
          parameterSet: 'ml-dsa-65',
          ops: {
            keygen: () => void dsa.keygen(),
            sign: () => void dsa.sign(msg, kp.secretKey),
            verify: () => void dsa.verify(sig, msg, kp.publicKey),
          },
        };
      }
      case 'sphincs': {
        const slh = slh_dsa_sha2_128f; // fast variant keeps the benchmark practical
        const kp = slh.keygen();
        const sig = slh.sign(msg, kp.secretKey);
        return {
          parameterSet: 'slh-dsa-sha2-128f',
          ops: {
            keygen: () => void slh.keygen(),
            sign: () => void slh.sign(msg, kp.secretKey),
            verify: () => void slh.verify(sig, msg, kp.publicKey),
          },
        };
      }
      case 'falcon': {
        const fal = falcon512;
        const kp = fal.keygen();
        const sig = fal.sign(msg, kp.secretKey);
        return {
          parameterSet: 'falcon-512',
          ops: {
            keygen: () => void fal.keygen(),
            sign: () => void fal.sign(msg, kp.secretKey),
            verify: () => void fal.verify(sig, msg, kp.publicKey),
          },
        };
      }
      default:
        throw new Error(
          `Unsupported benchmark algorithm: ${algorithm}. Supported: kyber, dilithium, sphincs, falcon, all`,
        );
    }
  }
}

// referenced to keep parameter-set imports meaningful for future tiers
void ml_kem512;
void ml_kem1024;
void ml_dsa44;
void ml_dsa87;
void falcon1024;

function round(x: number): number {
  return Math.round(x * 1000) / 1000;
}
