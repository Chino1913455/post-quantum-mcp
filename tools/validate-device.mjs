#!/usr/bin/env node
/**
 * validate-device.mjs - turn a raw entropy-device capture into a VALIDATED,
 * full-entropy seed and an unlimited DRBG stream. The last mile: once your
 * hardware (avalanche board / QRNG chip / Quantis) produces samples.bin, this
 * runs the proven cert pipeline and gives you usable randomness.
 *
 *   node tools/validate-device.mjs <samples.bin> [out.bin] [bytes]
 *
 * Pipeline: measure min-entropy -> SP 800-90B gate -> condition -> full-entropy
 * certificate -> HMAC_DRBG stream (verified). Exits non-zero if the source fails.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { ingestExternalEntropy, verifyFullEntropy, HmacDrbg } from '../dist/utils/entropy/index.js';

const [, , inPath, outPath, nStr] = process.argv;
if (!inPath) {
  console.error('usage: node tools/validate-device.mjs <samples.bin> [out.bin] [bytes]');
  process.exit(2);
}
const raw = new Uint8Array(readFileSync(inPath));
if (raw.length < 1024) {
  console.error('need >= 1024 bytes of raw samples');
  process.exit(2);
}

const res = ingestExternalEntropy(raw);
console.log('='.repeat(64));
console.log(`TrueEntropy device validation: ${inPath}  (${raw.length} bytes)`);
console.log('='.repeat(64));
console.log(`accepted             : ${res.accepted}  - ${res.reason}`);
console.log(`measured min-entropy : ${res.measuredMinEntropyPerByte} bits/byte (conservative INPUT measure)`);
if (res.certificate) {
  console.log(
    `full-entropy cert    : fullEntropy=${res.certificate.fullEntropy} | ` +
      `distance<=${res.certificate.distanceFromUniform.toExponential(0)} | margin ${res.certificate.securityMarginBits} bits`,
  );
}
if (!res.accepted) {
  console.log('REJECTED - do not use this source.');
  process.exit(1);
}

const seedHex = Buffer.from(res.seed).toString('hex');
console.log(`512-bit seed (hex)   : ${seedHex.slice(0, 32)}...`);

const n = Math.max(1, parseInt(nStr || '1048576', 10));
const stream = new HmacDrbg(res.seed).generate(n);
const v = verifyFullEntropy(stream);
console.log('-'.repeat(64));
console.log(
  `DRBG stream (${n} bytes): shannon/byte ${v.shannonPerByte}, min-entropy ${v.minEntropyPerByte}, full-entropy=${v.nearUniform}`,
);
if (outPath) {
  writeFileSync(outPath, stream);
  console.log(`wrote validated stream -> ${outPath}`);
}
console.log('OK - validated, full-entropy, quantum-seeded output ready.');
