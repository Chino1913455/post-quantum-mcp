import * as crypto from 'crypto';

/**
 * Constant-time primitives.
 *
 * Side-channel (timing / cache) leakage is the place where ML/AI-assisted
 * attackers are genuinely strong against otherwise-sound cryptography: a model
 * trained on timing or power traces can recover secret-dependent branches and
 * table indices. These helpers are branchless and perform no secret-dependent
 * control flow or memory access, so the time taken does not depend on secret
 * values.
 *
 * All operate on 32-bit-safe integers; callers mask to the needed width.
 */

/** All-ones mask (-1) if bit's LSB is 1, else 0. */
export const ctMask = (bit: number): number => -(bit & 1) | 0;

/** Constant-time select: mask all-ones -> a, mask 0 -> b. */
export const ctSelect = (mask: number, a: number, b: number): number => ((a & mask) | (b & ~mask)) | 0;

/** All-ones mask if a === b, else 0 (for values in 0..0xffff). */
export function ctEqMask(a: number, b: number): number {
  const x = (a ^ b) & 0xffff; // 0 iff equal
  return (x - 1) >> 31; // -1 (all ones) iff x === 0, else 0
}

/** All-ones mask if a === 0, else 0 (for values in 0..0xffff). */
export const ctIsZeroMask = (a: number): number => ctEqMask(a, 0);

/** 1 if a >= b, else 0 (constant-time; a,b non-negative and < 2^30). */
export const ctGE = (a: number, b: number): number => ((b - a - 1) >> 31) & 1;

/**
 * Timing-safe buffer equality (wraps Node's constant-time comparison). Returns
 * false for length mismatch without leaking which byte differed.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
