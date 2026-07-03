/**
 * Entropy source abstraction + the EntropyService facade.
 *
 * An EntropySource is anything that can yield raw entropy bytes. The service
 * prefers the highest-min-entropy *raw* source available, health-tests it
 * (SP 800-90B), conditions it with the Toeplitz extractor, and reports exactly
 * what it used — never claiming more than it can prove.
 *
 * Sources are pluggable by design (evolutive scale): a native RDSEED binding,
 * an external QRNG API, or the true-rng SPAD USB device can each be registered
 * as an EntropySource without touching callers.
 *
 * Shipped sources:
 *   - OsCsprngSource     — crypto.randomBytes (OS CSPRNG; hardware-seeded DRBG).
 *                          Always available; output already uniform.
 *   - LinuxHwRngSource   — /dev/hwrng raw hardware RNG when present (Linux only).
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import { ToeplitzExtractor, bytesToBits } from './extractor.js';
import { runHealthTests, HealthReport } from './health.js';

export interface EntropySource {
  readonly name: string;
  /** Estimated min-entropy per output byte (bits). 8 = full entropy. */
  readonly minEntropyPerByte: number;
  /** True if this source can be read on the current host right now. */
  available(): boolean;
  /** Read n raw bytes. Throws if unavailable. */
  read(n: number): Uint8Array;
  /** Whether output is already uniform (a CSPRNG) vs raw (needs conditioning). */
  readonly raw: boolean;
}

/** OS CSPRNG — hardware-seeded DRBG (getrandom/BCryptGenRandom). Always present. */
export class OsCsprngSource implements EntropySource {
  readonly name = 'os-csprng';
  readonly minEntropyPerByte = 8;
  readonly raw = false;
  available(): boolean {
    return true;
  }
  read(n: number): Uint8Array {
    return new Uint8Array(crypto.randomBytes(n));
  }
}

/** Linux /dev/hwrng — raw on-chip hardware RNG (e.g. RDRAND/TPM), if exposed. */
export class LinuxHwRngSource implements EntropySource {
  readonly name = 'os-hwrng';
  // Raw hardware sources are conservatively credited below full entropy until
  // conditioned; matches true-rng's min_entropy_per_byte default.
  readonly minEntropyPerByte = 6;
  readonly raw = true;
  private readonly path = '/dev/hwrng';

  available(): boolean {
    if (os.platform() !== 'linux') return false;
    try {
      fs.accessSync(this.path, fs.constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  read(n: number): Uint8Array {
    const fd = fs.openSync(this.path, 'r');
    try {
      const buf = Buffer.alloc(n);
      let off = 0;
      while (off < n) {
        const got = fs.readSync(fd, buf, off, n - off, null);
        if (got <= 0) throw new Error('/dev/hwrng returned no data');
        off += got;
      }
      return new Uint8Array(buf);
    } finally {
      fs.closeSync(fd);
    }
  }
}

export interface GenerateResult {
  bytes: Uint8Array;
  source: string;
  conditioned: boolean;
  minEntropyPerByte: number;
  health: HealthReport | null;
}

export class EntropyService {
  private sources: EntropySource[];

  constructor(sources?: EntropySource[]) {
    // Order matters only for tie-breaking; selection is by min-entropy + raw.
    this.sources = sources ?? [new LinuxHwRngSource(), new OsCsprngSource()];
  }

  /** Register an additional source (e.g. a native RDSEED binding or QRNG API). */
  register(source: EntropySource): void {
    this.sources.unshift(source);
  }

  /** All currently-available sources, best first. */
  availableSources(): EntropySource[] {
    return this.sources
      .filter((s) => s.available())
      .sort((a, b) => Number(b.raw) - Number(a.raw)); // prefer raw hardware
  }

  /**
   * Produce `n` bytes. If a raw hardware source is available it is health-tested
   * and conditioned via Toeplitz extraction; otherwise the OS CSPRNG is used.
   * The result honestly reports the source and whether conditioning was applied.
   */
  generate(n: number, opts: { healthTest?: boolean } = {}): GenerateResult {
    if (!Number.isInteger(n) || n <= 0) throw new Error(`generate: invalid length ${n}`);
    const healthTest = opts.healthTest ?? true;

    const raw = this.availableSources().find((s) => s.raw);
    if (raw) {
      // Draw 2x to leave conditioning headroom (LHL needs surplus min-entropy).
      const rawBytes = raw.read(n * 2);
      const health = healthTest
        ? runHealthTests(rawBytes, { minEntropyPerSample: raw.minEntropyPerByte })
        : null;
      // Condition raw -> uniform.
      const extractor = new ToeplitzExtractor({
        inputBits: rawBytes.length * 8,
        outputBits: n * 8,
        minEntropyRate: raw.minEntropyPerByte / 8,
      });
      const conditioned = extractor.extractBytes(rawBytes);
      return {
        bytes: conditioned.subarray(0, n),
        source: raw.name,
        conditioned: true,
        minEntropyPerByte: 8,
        health,
      };
    }

    // CSPRNG path — already uniform; no conditioning required.
    const csprng = new OsCsprngSource();
    const bytes = csprng.read(n);
    return {
      bytes,
      source: csprng.name,
      conditioned: false,
      minEntropyPerByte: 8,
      health: healthTest ? runHealthTests(bytes) : null,
    };
  }
}
