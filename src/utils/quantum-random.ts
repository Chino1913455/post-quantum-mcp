import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { entropyService } from './entropy/index.js';
import { runAllTests } from './entropy/nist-sp800-22.js';
import { bytesToBits } from './entropy/extractor.js';

/**
 * Secure random byte generator.
 *
 * Honest model: by default this is the OS CSPRNG (a hardware-seeded DRBG) —
 * which is the cryptographically correct source for post-quantum key material.
 * If a raw hardware entropy source is present (e.g. Linux /dev/hwrng) it is
 * health-tested (SP 800-90B) and conditioned (Toeplitz extraction) and used
 * instead. The response always reports the actual `source` so callers are never
 * misled: it does NOT claim "quantum/true" randomness unless real hardware
 * entropy backed it.
 *
 * (Renamed from the prior "quantum-random" handler, which overclaimed by
 * labelling crypto.randomBytes output as quantum and mixed in Date.now() —
 * cosmetic noise that added no entropy. Both have been removed.)
 */
export class SecureRandomHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  async generate(params: any) {
    const { bytes = 32, format = 'hex', healthTest = true } = params ?? {};

    if (!Number.isInteger(bytes) || bytes < 1 || bytes > 1_048_576) {
      throw new Error('bytes must be an integer between 1 and 1048576');
    }

    const result = entropyService.generate(bytes, { healthTest });
    const buf = Buffer.from(result.bytes);

    let output: string;
    switch (format) {
      case 'base64':
        output = buf.toString('base64');
        break;
      case 'integer':
        output = BigInt('0x' + (buf.toString('hex') || '0')).toString();
        break;
      case 'hex':
      default:
        output = buf.toString('hex');
        break;
    }

    const payload = {
      random: output,
      bytes,
      format,
      source: result.source,
      conditioned: result.conditioned,
      algorithm:
        result.source === 'os-csprng'
          ? 'OS CSPRNG (hardware-seeded DRBG)'
          : 'OS hardware RNG, Toeplitz-conditioned + SP 800-90B health-tested',
      // Sample statistic, not a security guarantee: for small `bytes` it is
      // expected to be below 8 bits/byte due to small-sample bias.
      sampleShannonBitsPerByte: this.shannonBitsPerByte(buf),
      health: result.health,
      note: 'CSPRNG output is suitable for post-quantum key material. Not quantum/true randomness unless source is a hardware entropy device.',
      generated: new Date().toISOString(),
    };

    this.logger.info(`Generated ${bytes} secure random bytes from ${result.source}`);
    return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
  }

  /**
   * Validate a byte sequence against the NIST SP 800-22 statistical suite.
   * Accepts supplied `data` (hex/base64) or generates a fresh sample.
   */
  async validate(params: any) {
    const { data, bytes = 4096, format = 'hex' } = params ?? {};

    let buf: Buffer;
    let origin: string;
    if (typeof data === 'string' && data.length > 0) {
      buf = Buffer.from(data, format === 'base64' ? 'base64' : 'hex');
      origin = 'supplied';
    } else {
      if (!Number.isInteger(bytes) || bytes < 16 || bytes > 1_048_576) {
        throw new Error('bytes must be an integer between 16 and 1048576');
      }
      buf = Buffer.from(entropyService.generate(bytes, { healthTest: false }).bytes);
      origin = 'generated';
    }

    const bits = bytesToBits(new Uint8Array(buf));
    const tests = runAllTests(bits);
    const passedCount = tests.filter((t) => t.passed).length;

    const payload = {
      origin,
      sampleBytes: buf.length,
      sampleBits: bits.length,
      significanceLevel: 0.01,
      testsRun: tests.length,
      testsPassed: passedCount,
      overallPass: passedCount === tests.length,
      results: tests,
      suite: 'NIST SP 800-22 (practical subset)',
    };

    this.logger.info(`SP 800-22 validation: ${passedCount}/${tests.length} passed (${origin})`);
    return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
  }

  /** Shannon entropy of the byte distribution (bits/byte). Sanity statistic. */
  private shannonBitsPerByte(buffer: Buffer): number {
    const freq: Record<number, number> = {};
    for (const b of buffer) freq[b] = (freq[b] || 0) + 1;
    const len = buffer.length;
    let h = 0;
    for (const c of Object.values(freq)) {
      const p = c / len;
      h -= p * Math.log2(p);
    }
    return Math.round(h * 1000) / 1000;
  }
}

/** Back-compat alias for the prior handler name. */
export { SecureRandomHandler as QuantumRandomHandler };
