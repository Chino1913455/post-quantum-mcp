/**
 * Entropy & secure-randomness toolkit for @veris/post-quantum-mcp.
 *
 *  - sampling:  CSPRNG primitives (the only sanctioned randomness in the pkg)
 *  - sources:   pluggable entropy sources + EntropyService facade
 *  - extractor: Toeplitz universal-hash conditioner (Leftover Hash Lemma)
 *  - health:    SP 800-90B online health tests (RCT/APT) + true-rng panel
 *  - nist:      SP 800-22 statistical test suite (batch quality validation)
 *
 * Provenance: extractor, health panel, and NIST suite are ported from the
 * VerisSuite `true-rng` research project (quantum_rng_design.py), with the
 * Toeplitz seed corrected to draw from a CSPRNG.
 */
export * as sampling from './sampling.js';
export * from './sources.js';
export { ToeplitzExtractor } from './extractor.js';
export {
  runHealthTests,
  repetitionCountTest,
  adaptiveProportionTest,
  quickHealthPanel,
  type HealthReport,
  type HealthTest,
} from './health.js';
export { runAllTests as runNistTests, type NistTestResult } from './nist-sp800-22.js';
export {
  minEntropyMCV,
  ingestExternalEntropy,
  verifyFullEntropy,
  registerValidatedSource,
  HmacDrbg,
  BufferEntropySource,
  STANDARD_EPSILON,
  BEST_EPSILON,
  type IngestOptions,
  type IngestResult,
  type FullEntropyCertificate,
} from './ingest.js';
export {
  diMinEntropyFromCHSH,
  vonNeumannEntropyCHSH,
  ingestDeviceIndependent,
  publicBeaconSeed,
  finiteRateEAT,
  roundsForSeed,
  finiteRateSecondOrder,
  roundsForSeedSecondOrder,
  entropyVariance,
  LOCAL_BOUND,
  TSIRELSON_BOUND,
  type DiCertification,
  type DiIngestOptions,
  type DiIngestResult,
  type Visibility,
  type EatOptions,
  type EatResult,
  type SecondOrderResult,
} from './di.js';

import { EntropyService } from './sources.js';

/** Shared process-wide entropy service (default sources). */
export const entropyService = new EntropyService();
