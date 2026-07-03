import { Logger } from 'winston';
import NodeCache from 'node-cache';

/**
 * Crypto-agility advisor: turns an inventory of an existing system's
 * cryptography into a prioritized post-quantum migration plan, with explicit
 * "harvest now, decrypt later" (HNDL) risk scoring.
 *
 * HNDL is the urgent part: data whose confidentiality must outlive the arrival
 * of a cryptographically-relevant quantum computer (CRQC) is ALREADY at risk if
 * it is exchanged today under a quantum-vulnerable key-exchange — an adversary
 * can record the ciphertext now and decrypt it later. Signatures do not have
 * this property (a forgery is only useful in the future), so they are urgent
 * for long-lived artifacts (firmware, roots of trust) but not retroactively.
 */

type Category = 'key-exchange' | 'signature' | 'symmetric' | 'hash' | 'unknown';

interface AlgoInfo {
  category: Category;
  quantumVulnerable: boolean;
  reason: string;
  recommend: string;
}

// Estimated window until a CRQC is plausible. Deliberately conservative; the
// point of HNDL is that you must beat this horizon, not predict it exactly.
const CRQC_HORIZON_YEARS = 12;

const KB: Record<string, AlgoInfo> = {
  // Public-key key-exchange / encryption — broken by Shor; HNDL-relevant.
  rsa: { category: 'key-exchange', quantumVulnerable: true, reason: "Shor's algorithm factors RSA moduli", recommend: 'Hybrid X-Wing (X25519 + ML-KEM-768)' },
  'rsa-oaep': { category: 'key-exchange', quantumVulnerable: true, reason: "Shor's algorithm factors RSA moduli", recommend: 'Hybrid X-Wing (X25519 + ML-KEM-768)' },
  ecdh: { category: 'key-exchange', quantumVulnerable: true, reason: "Shor's algorithm solves ECDLP", recommend: 'Hybrid X-Wing (X25519 + ML-KEM-768)' },
  ecdhe: { category: 'key-exchange', quantumVulnerable: true, reason: "Shor's algorithm solves ECDLP", recommend: 'Hybrid X-Wing (X25519 + ML-KEM-768)' },
  x25519: { category: 'key-exchange', quantumVulnerable: true, reason: "Shor's algorithm solves ECDLP", recommend: 'Hybrid X-Wing (X25519 + ML-KEM-768)' },
  dh: { category: 'key-exchange', quantumVulnerable: true, reason: "Shor's algorithm solves the DLP", recommend: 'Hybrid X-Wing (X25519 + ML-KEM-768)' },
  dhe: { category: 'key-exchange', quantumVulnerable: true, reason: "Shor's algorithm solves the DLP", recommend: 'Hybrid X-Wing (X25519 + ML-KEM-768)' },

  // Signatures — broken by Shor; urgent for long-lived artifacts.
  'rsa-pss': { category: 'signature', quantumVulnerable: true, reason: "Shor's algorithm factors RSA moduli", recommend: 'Hybrid Ed25519 + ML-DSA-65 (or SLH-DSA for firmware/long-term)' },
  ecdsa: { category: 'signature', quantumVulnerable: true, reason: "Shor's algorithm solves ECDLP", recommend: 'Hybrid Ed25519 + ML-DSA-65 (or SLH-DSA for firmware/long-term)' },
  ed25519: { category: 'signature', quantumVulnerable: true, reason: "Shor's algorithm solves ECDLP", recommend: 'Hybrid Ed25519 + ML-DSA-65' },
  dsa: { category: 'signature', quantumVulnerable: true, reason: "Shor's algorithm solves the DLP", recommend: 'Hybrid Ed25519 + ML-DSA-65' },

  // Symmetric — Grover only halves the security level.
  'aes-128': { category: 'symmetric', quantumVulnerable: true, reason: 'Grover halves brute-force cost to ~2^64', recommend: 'AES-256' },
  'aes-256': { category: 'symmetric', quantumVulnerable: false, reason: '~128-bit post-quantum security under Grover', recommend: 'No change needed' },
  '3des': { category: 'symmetric', quantumVulnerable: true, reason: 'Already deprecated (Sweet32) and weakened by Grover', recommend: 'AES-256 immediately' },
  rc4: { category: 'symmetric', quantumVulnerable: true, reason: 'Classically broken regardless of quantum', recommend: 'AES-256-GCM immediately' },

  // Hashes — Grover affects preimage; collisions less so.
  md5: { category: 'hash', quantumVulnerable: true, reason: 'Classically broken (collisions)', recommend: 'SHA-256 / SHA-3 immediately' },
  'sha-1': { category: 'hash', quantumVulnerable: true, reason: 'Classically broken (collisions)', recommend: 'SHA-256 / SHA-3 immediately' },
  'sha-256': { category: 'hash', quantumVulnerable: false, reason: '~128-bit post-quantum preimage security under Grover', recommend: 'Use SHA-384/SHA-3 where 256-bit PQ security is required' },
  'sha-384': { category: 'hash', quantumVulnerable: false, reason: '~192-bit post-quantum preimage security', recommend: 'No change needed' },
  'sha-512': { category: 'hash', quantumVulnerable: false, reason: '~256-bit post-quantum preimage security', recommend: 'No change needed' },
  'sha3-256': { category: 'hash', quantumVulnerable: false, reason: '~128-bit post-quantum preimage security', recommend: 'No change needed' },
};

function normalize(name: string): string {
  return String(name).toLowerCase().replace(/\s+/g, '').replace('crystals-', '').replace(/_/g, '-');
}

/**
 * Resolve an algorithm name to a KB entry, with a family fallback for
 * size/curve-suffixed asymmetric names (rsa-2048 -> rsa, ecdsa-p256 -> ecdsa).
 * Symmetric/hash names are NOT fuzzy-matched because the size is the whole point
 * (aes-128 vs aes-256).
 */
function lookup(key: string): AlgoInfo | undefined {
  if (KB[key]) return KB[key];
  for (const fam of ['rsa-pss', 'rsa-oaep', 'rsa', 'ecdsa', 'ecdhe', 'ecdh', 'ed25519', 'dsa', 'dhe', 'dh']) {
    if (key.startsWith(fam)) return KB[fam];
  }
  return undefined;
}

export class CryptoAgilityHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  async assess(params: any) {
    const {
      currentAlgorithms = [],
      dataSensitivity = 'medium',
      dataLifetimeYears = 10,
    } = params ?? {};

    if (!Array.isArray(currentAlgorithms) || currentAlgorithms.length === 0) {
      throw new Error('assess-migration: "currentAlgorithms" must be a non-empty array of algorithm names');
    }

    const findings = currentAlgorithms.map((raw: string) => {
      const key = normalize(raw);
      const info = lookup(key) ?? {
        category: 'unknown' as Category,
        quantumVulnerable: false,
        reason: 'Not in knowledge base — review manually',
        recommend: 'Manual review',
      };
      const urgency = this.urgency(info, dataLifetimeYears, dataSensitivity);
      return { algorithm: raw, category: info.category, quantumVulnerable: info.quantumVulnerable, reason: info.reason, recommendation: info.recommend, urgency };
    });

    // HNDL applies to confidentiality exchanged today under vulnerable key-exchange.
    const hasVulnerableKex = findings.some((f) => f.category === 'key-exchange' && f.quantumVulnerable);
    const dataOutlivesCRQC = dataLifetimeYears >= CRQC_HORIZON_YEARS;
    const hndlRisk = !hasVulnerableKex
      ? 'none'
      : dataOutlivesCRQC
        ? this.bump('high', dataSensitivity)
        : 'medium';

    const order = { critical: 0, high: 1, medium: 2, low: 3, none: 4 } as Record<string, number>;
    const plan = findings
      .filter((f) => f.urgency !== 'none')
      .sort((a, b) => order[a.urgency] - order[b.urgency])
      .map((f, i) => ({ step: i + 1, action: `Migrate ${f.algorithm} → ${f.recommendation}`, urgency: f.urgency }));

    this.logger.info(`Crypto-agility assessment: ${findings.length} algos, HNDL risk=${hndlRisk}`);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          summary: {
            algorithmsAssessed: findings.length,
            quantumVulnerable: findings.filter((f) => f.quantumVulnerable).length,
            harvestNowDecryptLaterRisk: hndlRisk,
            crqcHorizonYears: CRQC_HORIZON_YEARS,
            dataLifetimeYears,
            dataSensitivity,
          },
          findings,
          recommendedPlan: plan,
          note: 'HNDL risk reflects confidentiality of data exchanged TODAY under quantum-vulnerable key exchange. Signatures are urgent for long-lived artifacts but not retroactively exploitable.',
        }, null, 2),
      }],
    };
  }

  private urgency(info: AlgoInfo, lifetime: number, sensitivity: string): string {
    if (!info.quantumVulnerable) return 'none';
    if (info.category === 'symmetric' || info.category === 'hash') {
      return info.recommend.includes('immediately') ? 'high' : 'low';
    }
    if (info.category === 'key-exchange') {
      // HNDL: vulnerable now if the data must stay secret past the CRQC horizon.
      return lifetime >= CRQC_HORIZON_YEARS ? this.bump('high', sensitivity) : 'medium';
    }
    // signatures
    return lifetime >= CRQC_HORIZON_YEARS ? 'high' : 'medium';
  }

  private bump(level: string, sensitivity: string): string {
    if ((sensitivity === 'critical' || sensitivity === 'high') && level === 'high') return 'critical';
    return level;
  }
}
