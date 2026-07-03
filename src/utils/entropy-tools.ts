/**
 * MCP tool handlers exposing the entropy-assessment + device-independent
 * randomness stack. Turns the proven `entropy/` library into callable tools:
 *   - entropy-assess     : SP 800-90B min-entropy (MCV) + Shannon + full-entropy check
 *   - entropy-ingest     : measure -> gate -> condition -> full-entropy seed + certificate
 *   - di-certify         : certified min-entropy + tight von Neumann rate from CHSH S
 *   - di-finite-rate     : finite-statistics certified rate (entropy accumulation)
 *   - di-rounds-for-seed : Bell rounds needed to certify a full-entropy seed
 */
import {
  minEntropyMCV,
  verifyFullEntropy,
  ingestExternalEntropy,
  diMinEntropyFromCHSH,
  vonNeumannEntropyCHSH,
  finiteRateEAT,
  roundsForSeed,
  finiteRateSecondOrder,
  roundsForSeedSecondOrder,
} from './entropy/index.js';

type Fmt = 'hex' | 'base64';

function decode(data: string, format: Fmt): Uint8Array {
  return new Uint8Array(Buffer.from(data, format));
}

function mcp(payload: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }] };
}

function round(x: number, dp = 4): number {
  const f = Math.pow(10, dp);
  return Math.round(x * f) / f;
}

export const entropyToolsHandler = {
  /** Assess raw entropy: conservative min-entropy (input measure) + full-entropy check. */
  async assess(args: any) {
    const fmt: Fmt = args?.format ?? 'hex';
    const bytes = decode(String(args?.data ?? ''), fmt);
    if (bytes.length < 256) throw new Error('entropy-assess: provide >= 256 bytes of raw samples');
    const { hMin, pMax } = minEntropyMCV(bytes);
    const full = verifyFullEntropy(bytes);
    return mcp({
      bytes: bytes.length,
      minEntropyPerByte: round(hMin),
      pMax: round(pMax, 6),
      shannonPerByte: full.shannonPerByte,
      nearUniform: full.nearUniform,
      note: 'min-entropy is the conservative worst-case INPUT measure; Shannon≈8 + nearUniform indicates the source is essentially full-entropy.',
    });
  },

  /** Gate + condition raw entropy into a full-entropy seed with an LHL certificate. */
  async ingest(args: any) {
    const fmt: Fmt = args?.format ?? 'hex';
    const bytes = decode(String(args?.data ?? ''), fmt);
    const res = ingestExternalEntropy(bytes, { quality: args?.quality, seedBits: args?.seedBits });
    return mcp({
      accepted: res.accepted,
      reason: res.reason,
      measuredMinEntropyPerByte: res.measuredMinEntropyPerByte,
      certificate: res.certificate,
      seedHex: res.seed ? Buffer.from(res.seed).toString('hex') : null,
    });
  },

  /** Device-independent: certified min-entropy + tight von Neumann rate from CHSH S. */
  async diCertify(args: any) {
    const S = Number(args?.chsh);
    const g = diMinEntropyFromCHSH(S);
    return mcp({
      chsh: S,
      guessingMinEntropyPerBit: round(g.minEntropyPerBit),
      vonNeumannEntropyPerBit: round(vonNeumannEntropyCHSH(S)),
      certifiesRandomness: g.certifiesRandomness,
      aboveTsirelson: g.aboveTsirelson,
      note: g.note,
    });
  },

  /** Finite-statistics certified rate for n CHSH rounds — both adversary models. */
  async diFiniteRate(args: any) {
    const S = Number(args?.chsh);
    const n = Number(args?.rounds);
    const opts = { soundnessError: args?.soundnessError };
    const eat = finiteRateEAT(S, n, opts);
    const tight = finiteRateSecondOrder(S, n, opts);
    return mcp({
      chsh: S,
      rounds: n,
      coherentAttacks_EAT: { netRatePerRound: eat.netRatePerRound, totalCertifiedBits: eat.totalCertifiedBits },
      iidCollective_tight: { netRatePerRound: tight.netRatePerRound, totalCertifiedBits: tight.totalCertifiedBits },
      note: 'EAT = conservative lower bound (general/coherent attacks); tight = achievable under iid collective attacks. The gap is the price of coherent-attack security.',
    });
  },

  /** Bell rounds to certify a full-entropy seed — both adversary models. */
  async diRoundsForSeed(args: any) {
    const S = Number(args?.chsh);
    const seedBits = args?.seedBits ?? 512;
    const opts = { soundnessError: args?.soundnessError };
    return mcp({
      chsh: S,
      seedBits,
      roundsCoherent_EAT: roundsForSeed(S, seedBits, opts),
      roundsIidCollective_tight: roundsForSeedSecondOrder(S, seedBits, opts),
    });
  },
};
