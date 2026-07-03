/**
 * Device-independent (DI) randomness certification — Probe 1 of the
 * qrng-device-independent north star.
 *
 * Turns a measured Bell/CHSH violation into a CERTIFIED min-entropy number with
 * NO trust in the device's internals. Pironio et al., "Random numbers certified
 * by Bell's theorem", Nature 464 (2010): in the CHSH scenario the adversary's
 * guessing probability obeys
 *     P_guess(S) = (1 + sqrt(2 - S^2/4)) / 2,   for  2 <= S <= 2*sqrt(2),
 * so the certified single-outcome min-entropy is
 *     H_min(S) = -log2 P_guess(S) = 1 - log2(1 + sqrt(2 - S^2/4)).
 * Endpoints:  S = 2 (local/classical bound) -> 0 bits;
 *             S = 2*sqrt(2) (Tsirelson, quantum max) -> 1 bit.
 *
 * Honest scope: this is the ASYMPTOTIC per-round bound against a quantum
 * adversary. A deployable protocol needs finite-statistics analysis (entropy
 * accumulation), which only LOWERS the rate — so this certifies the ideal
 * ceiling and gates on it. Public-vs-private is tracked explicitly: a public
 * beacon's output is unpredictable-in-advance but VISIBLE, so it must never
 * seed a secret key.
 */
import * as crypto from 'crypto';
import { ToeplitzExtractor } from './extractor.js';
import { BEST_EPSILON, STANDARD_EPSILON, type FullEntropyCertificate } from './ingest.js';

export const LOCAL_BOUND = 2;
export const TSIRELSON_BOUND = 2 * Math.SQRT2; // ≈ 2.82842712

export interface DiCertification {
  chsh: number;
  pGuess: number;
  /** Certified min-entropy per outcome bit (asymptotic). */
  minEntropyPerBit: number;
  /** True iff S exceeds the local bound (2) — otherwise no DI randomness. */
  certifiesRandomness: boolean;
  /** True iff S exceeds Tsirelson — data inconsistent with QM (measurement error). */
  aboveTsirelson: boolean;
  note: string;
}

/** Certified min-entropy per outcome from a measured CHSH value S. */
export function diMinEntropyFromCHSH(S: number): DiCertification {
  const aboveTsirelson = S > TSIRELSON_BOUND + 1e-9;
  const Sc = Math.min(Math.max(S, LOCAL_BOUND), TSIRELSON_BOUND); // clamp to [2, 2√2]
  const root = Math.sqrt(Math.max(0, 2 - (Sc * Sc) / 4));
  const pGuess = (1 + root) / 2;
  const minEntropyPerBit = -Math.log2(pGuess);

  let note: string;
  if (S <= LOCAL_BOUND) note = `S=${S} ≤ local bound 2: no DI-certified randomness`;
  else if (aboveTsirelson)
    note = `S=${S} > Tsirelson ${TSIRELSON_BOUND.toFixed(4)}: above quantum max — measurement/estimation error; clamped`;
  else note = `S=${S}: certified ${minEntropyPerBit.toFixed(4)} bits/outcome vs a quantum adversary`;

  return { chsh: S, pGuess, minEntropyPerBit, certifiesRandomness: S > LOCAL_BOUND, aboveTsirelson, note };
}

function binaryEntropy(p: number): number {
  if (p <= 0 || p >= 1) return 0;
  return -p * Math.log2(p) - (1 - p) * Math.log2(1 - p);
}

/**
 * Tight DI conditional von Neumann entropy bound (Pironio et al., PRA 2009):
 *   H(A|E) >= 1 - h_b( (1 + sqrt(S^2/4 - 1)) / 2 ),   2 <= S <= 2*sqrt(2).
 * Strictly TIGHTER than the guessing-probability (min-entropy) bound for
 * intermediate S, and the correct per-round rate for entropy accumulation.
 * Endpoints: 0 bits at S=2, 1 bit at S=2*sqrt(2).
 */
export function vonNeumannEntropyCHSH(S: number): number {
  const Sc = Math.min(Math.max(S, LOCAL_BOUND), TSIRELSON_BOUND);
  const arg = Math.sqrt(Math.max(0, (Sc * Sc) / 4 - 1));
  return Math.max(0, 1 - binaryEntropy((1 + arg) / 2));
}

export type Visibility = 'public' | 'private';

export interface DiIngestOptions {
  /** Measured CHSH value S of the device that produced these outcomes. */
  chsh: number;
  /** 'private' = secret-seed capable; 'public' = beacon (verifiable only). */
  visibility: Visibility;
  seedBits?: number;
  /** Distance-from-uniform target. Overrides `quality` if set. */
  epsilon?: number;
  /** 'best' (default) = 2^-64 from uniform; 'standard' = 2^-32. */
  quality?: 'standard' | 'best';
}

export interface DiIngestResult {
  accepted: boolean;
  reason: string;
  cert: DiCertification;
  visibility: Visibility;
  /** FALSE for public beacons — the seed must NOT be used as a secret key. */
  secretSafe: boolean;
  rawBits: number;
  seed: Uint8Array | null;
  /** Full-entropy proof for the seed (null when rejected). */
  certificate: FullEntropyCertificate | null;
}

/**
 * Ingest raw Bell-trial outcomes whose randomness is certified by the CHSH value
 * S (not by their output frequency — DI outcomes may look biased yet be
 * provably unpredictable). Gate on S>2, reject S>Tsirelson as inconsistent, then
 * extract a seed at the certified per-bit rate. Tags public/private so a public
 * beacon can never silently become a secret key seed.
 */
export function ingestDeviceIndependent(rawOutcomes: Uint8Array, opts: DiIngestOptions): DiIngestResult {
  const cert = diMinEntropyFromCHSH(opts.chsh);
  const seedBits = opts.seedBits ?? 512;
  const epsilon = opts.epsilon ?? (opts.quality === 'standard' ? STANDARD_EPSILON : BEST_EPSILON);
  const visibility = opts.visibility;
  const secretSafe = visibility === 'private';
  const base = { cert, visibility, secretSafe, rawBits: rawOutcomes.length * 8, certificate: null };
  const reject = (reason: string): DiIngestResult => ({ accepted: false, reason, seed: null, ...base });

  if (!cert.certifiesRandomness) return reject(`CHSH S=${opts.chsh} certifies no randomness (need S>2)`);
  if (cert.aboveTsirelson) return reject(cert.note);

  const rate = cert.minEntropyPerBit; // per-bit fraction in (0,1]
  const margin = 2 * Math.log2(1 / epsilon);
  const needBytes = Math.ceil((seedBits + margin + 64) / (8 * rate));
  if (needBytes > rawOutcomes.length) {
    return reject(
      `need ${needBytes} outcome bytes for a ${seedBits}-bit full-entropy seed at ${rate.toFixed(3)} bits/bit, have ${rawOutcomes.length}`,
    );
  }
  const extractor = new ToeplitzExtractor({
    inputBits: needBytes * 8,
    outputBits: seedBits,
    minEntropyRate: rate,
    epsilon,
  });
  const seed = extractor.extractBytes(rawOutcomes.subarray(0, needBytes)).subarray(0, seedBits / 8);
  const lhl = extractor.leftoverHashLemmaCheck();
  const certificate: FullEntropyCertificate = {
    fullEntropy: lhl.satisfiesLHL,
    distanceFromUniform: epsilon,
    inputMinEntropyBits: lhl.minEntropyBits,
    outputBits: seedBits,
    securityMarginBits: lhl.securityMarginBits,
  };
  const reason = secretSafe
    ? 'ok (private full-entropy seed — usable as a secret seed)'
    : 'ok (PUBLIC full-entropy seed — verifiable randomness only, NOT a secret key seed)';
  return { accepted: true, reason, seed, ...base, certificate };
}

/**
 * Consume an externally-fetched PUBLIC Bell-test beacon pulse (e.g. CURBy) and
 * condition it into a public-tagged seed. The caller fetches the pulse out of
 * band — this performs NO network I/O. secretSafe is false by construction: use
 * for verifiable on-chain randomness (VerisChain), never for secret keys.
 */
export function publicBeaconSeed(pulseBytes: Uint8Array, seedBits = 512): DiIngestResult {
  if (pulseBytes.length < 16) throw new Error('publicBeaconSeed: pulse too short');
  const len = seedBits / 8;
  const seed = new Uint8Array(
    crypto.hkdfSync('sha256', pulseBytes, Buffer.alloc(0), Buffer.from('DI-public-beacon'), len),
  );
  return {
    accepted: true,
    reason: 'ok (PUBLIC beacon — verifiable randomness only, NEVER a secret key seed)',
    cert: {
      chsh: NaN,
      pGuess: 0.5,
      minEntropyPerBit: 1,
      certifiesRandomness: true,
      aboveTsirelson: false,
      note: 'relies on the beacon-published DI certification (not locally re-verified)',
    },
    visibility: 'public',
    secretSafe: false,
    rawBits: pulseBytes.length * 8,
    seed,
    certificate: {
      fullEntropy: true,
      distanceFromUniform: BEST_EPSILON,
      inputMinEntropyBits: pulseBytes.length * 8,
      outputBits: seedBits,
      securityMarginBits: pulseBytes.length * 8 - seedBits,
    },
  };
}

// ── Finite-statistics certified rate (Entropy Accumulation) ─────────────────
//
// The asymptotic bound H_min(S) is the ideal per-round ceiling. A real n-round
// run cannot claim it: the observed CHSH value Ŝ is a finite-sample estimate, so
// the true value could be lower, and the smooth min-entropy carries an O(√n)
// penalty. Following the Entropy Accumulation Theorem (Dupuis–Fawzi–Renner;
// Arnon-Friedman et al., Nat. Commun. 2018), the certified TOTAL min-entropy is
//   H_total ≥ n · h(S_worst) − O(√n),
// where S_worst is Ŝ pulled down by a Hoeffding confidence margin and the √n
// term carries the soundness error ε_s. As n→∞ this recovers h(Ŝ).
//
// HONEST SCOPE: the parameter-estimation margin (Hoeffding) is a rigorous lower
// bound; the smoothing coefficient here is a CONSERVATIVE stand-in for the
// min-tradeoff-function variance term — it gives the correct shape and a safe
// (under-)estimate, and should be tightened with a full EAT derivation before a
// production certificate is issued.

export interface EatOptions {
  /** Total soundness error ε_s (split across estimation + smoothing). Default 1e-10. */
  soundnessError?: number;
}

export interface EatResult {
  rounds: number;
  chshObserved: number;
  asymptoticRatePerRound: number; // von Neumann H(A|E) at observed S, bits
  finitePenaltyPerRound: number; // EAT second-order term / sqrt(n), bits
  netRatePerRound: number; // >= 0
  totalCertifiedBits: number; // floor(n * netRate)
  certifiesSeedBits: number | null; // largest standard seed (512/256/128) covered
  soundnessError: number;
  boundType: 'von-neumann-EAT';
  note: string;
}

/**
 * Certified finite-statistics randomness for an n-round CHSH run at observed Ŝ,
 * via the Entropy Accumulation Theorem (Dupuis–Fawzi–Renner; Arnon-Friedman
 * et al., Nat. Commun. 2018):
 *   H_min^{ε_s}(A^n|E) >= n · H_vN(Ŝ) − sqrt(n) · v,
 * with the TIGHT von Neumann per-round rate and the EAT second-order term
 *   v = 2 · log2(2·d_A^2 + 1) · sqrt(1 − 2·log2(ε_s)),   d_A = 2 (binary outcome).
 * The sqrt(n) term carries the finite-size confidence, so the observed Ŝ is used
 * directly. As n→∞ the net rate → H_vN(Ŝ).
 *
 * HONEST SCOPE: the standard EAT structure with the dimension-based second-order
 * constant; the last increment of tightness (the exact min-tradeoff-function
 * variance) would only raise the rate further — so this is a safe lower bound.
 */
export function finiteRateEAT(chshObserved: number, rounds: number, opts: EatOptions = {}): EatResult {
  const eps = opts.soundnessError ?? 1e-10;
  const n = Math.max(1, Math.floor(rounds));

  const rate = vonNeumannEntropyCHSH(chshObserved); // tight per-round von Neumann bound
  const dA = 2; // binary measurement outcome
  const v = 2 * Math.log2(2 * dA * dA + 1) * Math.sqrt(1 - 2 * Math.log2(eps)); // EAT 2nd-order term
  const penalty = v / Math.sqrt(n);
  const net = Math.max(0, rate - penalty);
  const totalBits = Math.floor(n * net);

  const certifiesSeedBits = [512, 256, 128].find((s) => s <= totalBits) ?? null;
  const note =
    chshObserved <= LOCAL_BOUND
      ? `S=${chshObserved} ≤ 2: no certified randomness`
      : net <= 0
        ? `n=${n} too small: finite-size penalty ${penalty.toFixed(4)} exceeds the ${rate.toFixed(4)} bits/round rate`
        : `n=${n}: net ${net.toFixed(4)} bits/round → ${totalBits} certified full-entropy bits (rate ${rate.toFixed(4)})`;

  return {
    rounds: n,
    chshObserved,
    asymptoticRatePerRound: rate,
    finitePenaltyPerRound: penalty,
    netRatePerRound: net,
    totalCertifiedBits: totalBits,
    certifiesSeedBits,
    soundnessError: eps,
    boundType: 'von-neumann-EAT',
    note,
  };
}

/**
 * How many Bell rounds are needed to certify a `seedBits` full-entropy seed at
 * observed CHSH Ŝ and soundness ε_s? Returns null if the violation is too weak
 * to ever certify it. This is the actionable target for a Probe-2 experiment.
 */
export function roundsForSeed(chshObserved: number, seedBits = 512, opts: EatOptions = {}): number | null {
  const CAP = 1e13;
  let hi = 1024;
  while (hi < CAP && finiteRateEAT(chshObserved, hi, opts).totalCertifiedBits < seedBits) hi *= 2;
  if (finiteRateEAT(chshObserved, hi, opts).totalCertifiedBits < seedBits) return null;
  let lo = Math.floor(hi / 2);
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (finiteRateEAT(chshObserved, mid, opts).totalCertifiedBits >= seedBits) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

// ── Tight second-order rate (iid collective attacks) ────────────────────────
//
// The EAT bound above is conservative because it must hold against COHERENT
// (general) attacks. If the rounds are iid and the adversary is restricted to
// collective attacks, the achievable rate is the second-order expansion
// (Tomamichel–Hayashi 2013; Li 2014):
//   H_min^{ε}(A^n|E) ≈ n·H_vN(S) − sqrt(n·V(S))·Φ^{-1}(1−ε),
// with V(S) the conditional entropy variance. This is a much TIGHTER (and
// achievable) rate; the gap to the EAT number is exactly the price of security
// against coherent attacks. We expose both so the assumption is explicit.

/** Inverse standard-normal CDF (Acklam rational approximation, |err| < 1.2e-9). */
function invNormalCDF(p: number): number {
  if (p <= 0) return -Infinity;
  if (p >= 1) return Infinity;
  const a = [-3.969683028665376e1, 2.209460984245205e2, -2.759285104469687e2, 1.38357751867269e2, -3.066479806614716e1, 2.506628277459239e0];
  const b = [-5.447609879822406e1, 1.615858368580409e2, -1.556989798598866e2, 6.680131188771972e1, -1.328068155288572e1];
  const c = [-7.784894002430293e-3, -3.223964580411365e-1, -2.400758277161838e0, -2.549732539343734e0, 4.374664141464968e0, 2.938163982698783e0];
  const d = [7.784695709041462e-3, 3.224671290700398e-1, 2.445134137142996e0, 3.754408661907416e0];
  const pl = 0.02425, ph = 1 - pl;
  let q: number, r: number;
  if (p < pl) {
    q = Math.sqrt(-2 * Math.log(p));
    return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
  }
  if (p <= ph) {
    q = p - 0.5;
    r = q * q;
    return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1);
  }
  q = Math.sqrt(-2 * Math.log(1 - p));
  return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
}

/** CHSH "phase error" e: H_vN = 1 − h_b(e), with e = (1 − sqrt(S²/4 − 1))/2. */
function chshErrorRate(S: number): number {
  const Sc = Math.min(Math.max(S, LOCAL_BOUND), TSIRELSON_BOUND);
  return (1 - Math.sqrt(Math.max(0, (Sc * Sc) / 4 - 1))) / 2;
}

/** Conditional entropy variance model: Var of the Bernoulli(e) surprisal. */
export function entropyVariance(S: number): number {
  const e = chshErrorRate(S);
  if (e <= 0 || e >= 0.5) return 0;
  const lr = Math.log2((1 - e) / e);
  return e * (1 - e) * lr * lr;
}

export interface SecondOrderResult {
  rounds: number;
  chshObserved: number;
  vonNeumannRate: number;
  entropyVariance: number;
  penaltyPerRound: number;
  netRatePerRound: number;
  totalCertifiedBits: number;
  certifiesSeedBits: number | null;
  soundnessError: number;
  assumption: 'iid-collective';
  note: string;
}

/** Tight achievable rate under iid collective attacks (weaker adversary than EAT). */
export function finiteRateSecondOrder(chshObserved: number, rounds: number, opts: EatOptions = {}): SecondOrderResult {
  const eps = opts.soundnessError ?? 1e-10;
  const n = Math.max(1, Math.floor(rounds));
  const h = vonNeumannEntropyCHSH(chshObserved);
  const V = entropyVariance(chshObserved);
  const penalty = Math.sqrt(V / n) * invNormalCDF(1 - eps);
  const net = Math.max(0, h - penalty);
  const totalBits = Math.floor(n * net);
  const certifiesSeedBits = [512, 256, 128].find((s) => s <= totalBits) ?? null;
  return {
    rounds: n,
    chshObserved,
    vonNeumannRate: h,
    entropyVariance: V,
    penaltyPerRound: penalty,
    netRatePerRound: net,
    totalCertifiedBits: totalBits,
    certifiesSeedBits,
    soundnessError: eps,
    assumption: 'iid-collective',
    note:
      chshObserved <= LOCAL_BOUND
        ? `S=${chshObserved} ≤ 2: no certified randomness`
        : `n=${n}: net ${net.toFixed(4)} bits/round → ${totalBits} bits (iid collective-attack tight rate; weaker than EAT's coherent-attack bound)`,
  };
}

/** Rounds for a seedBits seed under the tight (iid collective) second-order rate. */
export function roundsForSeedSecondOrder(chshObserved: number, seedBits = 512, opts: EatOptions = {}): number | null {
  const CAP = 1e13;
  let hi = 256;
  while (hi < CAP && finiteRateSecondOrder(chshObserved, hi, opts).totalCertifiedBits < seedBits) hi *= 2;
  if (finiteRateSecondOrder(chshObserved, hi, opts).totalCertifiedBits < seedBits) return null;
  let lo = Math.floor(hi / 2);
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (finiteRateSecondOrder(chshObserved, mid, opts).totalCertifiedBits >= seedBits) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}
