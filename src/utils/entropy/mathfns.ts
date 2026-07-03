/**
 * Numerical special functions for the statistical randomness tests.
 *
 * Implements log-gamma (Lanczos), the complementary error function, and the
 * regularized incomplete gamma functions P(a,x)/Q(a,x) via series + continued
 * fraction (the classic Numerical Recipes `gammp`/`gammq` split), plus binomial
 * tail helpers used by the SP 800-90B Adaptive Proportion Test cutoff.
 *
 * These back the p-value computations in nist-sp800-22.ts and the critical
 * binomial cutoff in health.ts. Accuracy is ~1e-7 (erfc) / ~1e-10 (igam) over
 * the ranges used — far tighter than the 0.01 thresholds that consume them.
 */

const LANCZOS_G = 7;
const LANCZOS_C = [
  0.99999999999980993, 676.5203681218851, -1259.1392167224028,
  771.32342877765313, -176.61502916214059, 12.507343278686905,
  -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
];

/** Natural log of the gamma function (Lanczos approximation). */
export function lgamma(x: number): number {
  if (x < 0.5) {
    // Reflection formula: Γ(x)Γ(1-x) = π / sin(πx)
    return Math.log(Math.PI / Math.sin(Math.PI * x)) - lgamma(1 - x);
  }
  x -= 1;
  let a = LANCZOS_C[0];
  const t = x + LANCZOS_G + 0.5;
  for (let i = 1; i < LANCZOS_G + 2; i++) a += LANCZOS_C[i] / (x + i);
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}

/**
 * Complementary error function erfc(x) = 1 - erf(x).
 * Numerical Recipes `erfcc` rational/Chebyshev approximation (|err| < 1.2e-7).
 */
export function erfc(x: number): number {
  const z = Math.abs(x);
  const t = 1 / (1 + 0.5 * z);
  // Horner evaluation of the Chebyshev polynomial in t.
  const poly =
    -1.26551223 +
    t * (1.00002368 +
    t * (0.37409196 +
    t * (0.09678418 +
    t * (-0.18628806 +
    t * (0.27886807 +
    t * (-1.13520398 +
    t * (1.48851587 +
    t * (-0.82215223 +
    t * 0.17087277))))))));
  const tau = t * Math.exp(-z * z + poly);
  return x >= 0 ? tau : 2 - tau;
}

/** Error function. */
export function erf(x: number): number {
  return 1 - erfc(x);
}

/** Standard normal CDF Φ(z). */
export function normalCdf(z: number): number {
  return 0.5 * erfc(-z / Math.SQRT2);
}

const IGAM_MAX_ITER = 200;
const IGAM_EPS = 1e-14;

/** Regularized lower incomplete gamma P(a,x) via series expansion. */
function gser(a: number, x: number): number {
  if (x <= 0) return 0;
  let ap = a;
  let sum = 1 / a;
  let del = sum;
  for (let n = 0; n < IGAM_MAX_ITER; n++) {
    ap += 1;
    del *= x / ap;
    sum += del;
    if (Math.abs(del) < Math.abs(sum) * IGAM_EPS) break;
  }
  return sum * Math.exp(-x + a * Math.log(x) - lgamma(a));
}

/** Regularized upper incomplete gamma Q(a,x) via continued fraction. */
function gcf(a: number, x: number): number {
  const FPMIN = 1e-300;
  let b = x + 1 - a;
  let c = 1 / FPMIN;
  let d = 1 / b;
  let h = d;
  for (let i = 1; i < IGAM_MAX_ITER; i++) {
    const an = -i * (i - a);
    b += 2;
    d = an * d + b;
    if (Math.abs(d) < FPMIN) d = FPMIN;
    c = b + an / c;
    if (Math.abs(c) < FPMIN) c = FPMIN;
    d = 1 / d;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < IGAM_EPS) break;
  }
  return Math.exp(-x + a * Math.log(x) - lgamma(a)) * h;
}

/** Regularized lower incomplete gamma P(a,x). */
export function igam(a: number, x: number): number {
  if (x < 0 || a <= 0) return NaN;
  if (x < a + 1) return gser(a, x);
  return 1 - gcf(a, x);
}

/** Regularized upper incomplete gamma Q(a,x) = 1 - P(a,x). */
export function igamc(a: number, x: number): number {
  if (x < 0 || a <= 0) return NaN;
  if (x < a + 1) return 1 - gser(a, x);
  return gcf(a, x);
}

/** log( C(n,k) ) via log-gamma. */
export function logChoose(n: number, k: number): number {
  if (k < 0 || k > n) return -Infinity;
  return lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1);
}

/**
 * Smallest integer c such that P[Bin(n,p) <= c] >= target.
 * Used to derive the SP 800-90B Adaptive Proportion Test cutoff.
 */
export function critBinom(n: number, p: number, target: number): number {
  const logP = Math.log(p);
  const logQ = Math.log1p(-p);
  let cdf = 0;
  for (let k = 0; k <= n; k++) {
    cdf += Math.exp(logChoose(n, k) + k * logP + (n - k) * logQ);
    if (cdf >= target) return k;
  }
  return n;
}
