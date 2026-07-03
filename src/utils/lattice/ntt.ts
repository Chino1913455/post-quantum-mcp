/**
 * Negacyclic Number Theoretic Transform (NTT) for fast polynomial
 * multiplication in Z_q[X]/(X^n + 1).
 *
 * This is a *no-compromise* speedup: it computes the EXACT same product as the
 * schoolbook O(n^2) convolution (verified bit-for-bit against it in the tests),
 * but in O(n log n). It changes nothing about the algebra, so security and
 * correctness are unaffected — only speed.
 *
 * Applicability: requires n a power of two and 2n | (q-1) so that a primitive
 * 2n-th root of unity exists mod q. For the lattice modules q = 12289
 * (12288 = 2^12 * 3), so NTT is available for n up to 2048. When the parameters
 * are not NTT-friendly, `usable` is false and callers fall back to schoolbook.
 *
 * Construction: the ψ-twisted variant — pre-multiply by ψ^i, run a length-n
 * cyclic NTT with ω = ψ^2, point-multiply, inverse-NTT, post-multiply by
 * ψ^{-i}·n^{-1}. ψ is a primitive 2n-th root of unity (ψ^n ≡ -1 mod q).
 */

function modpow(base: number, exp: number, q: number): number {
  base = ((base % q) + q) % q;
  let r = 1;
  while (exp > 0) {
    if (exp & 1) r = (r * base) % q;
    base = (base * base) % q;
    exp = Math.floor(exp / 2);
  }
  return r;
}

/** Modular inverse mod a prime q via Fermat's little theorem. */
function modinvPrime(a: number, q: number): number {
  return modpow(a, q - 2, q);
}

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}

/** Find a primitive 2n-th root of unity ψ mod q (ψ^n ≡ -1), or 0 if none. */
function findPsi(n: number, q: number): number {
  const exp = (q - 1) / (2 * n);
  const negOne = q - 1;
  for (let h = 2; h < q; h++) {
    const psi = modpow(h, exp, q);
    if (modpow(psi, n, q) === negOne) return psi;
  }
  return 0;
}

export class NegacyclicNTT {
  readonly n: number;
  readonly q: number;
  readonly usable: boolean;

  private psiPow: number[] = [];
  private psiInvPow: number[] = [];
  private omega = 0;
  private omegaInv = 0;
  private nInv = 0;

  constructor(n: number, q: number) {
    this.n = n;
    this.q = q;
    if (!isPowerOfTwo(n) || (q - 1) % (2 * n) !== 0) {
      this.usable = false;
      return;
    }
    const psi = findPsi(n, q);
    if (psi === 0) {
      this.usable = false;
      return;
    }
    const psiInv = modinvPrime(psi, q);
    this.psiPow = new Array(n);
    this.psiInvPow = new Array(n);
    let p = 1;
    let pInv = 1;
    for (let i = 0; i < n; i++) {
      this.psiPow[i] = p;
      this.psiInvPow[i] = pInv;
      p = (p * psi) % q;
      pInv = (pInv * psiInv) % q;
    }
    this.omega = (psi * psi) % q; // primitive n-th root
    this.omegaInv = modinvPrime(this.omega, q);
    this.nInv = modinvPrime(n, q);
    this.usable = true;
  }

  /** In-place iterative Cooley–Tukey NTT (inverse=true applies INTT + 1/n). */
  private transform(a: number[], inverse: boolean): void {
    const { n, q } = this;
    // bit-reversal permutation
    for (let i = 1, j = 0; i < n; i++) {
      let bit = n >> 1;
      for (; j & bit; bit >>= 1) j ^= bit;
      j ^= bit;
      if (i < j) {
        const t = a[i];
        a[i] = a[j];
        a[j] = t;
      }
    }
    const root = inverse ? this.omegaInv : this.omega;
    for (let len = 2; len <= n; len <<= 1) {
      const wLen = modpow(root, n / len, q);
      const half = len >> 1;
      for (let i = 0; i < n; i += len) {
        let w = 1;
        for (let k = 0; k < half; k++) {
          const u = a[i + k];
          const v = (a[i + k + half] * w) % q;
          a[i + k] = (u + v) % q;
          a[i + k + half] = (u - v + q) % q;
          w = (w * wLen) % q;
        }
      }
    }
    if (inverse) {
      for (let i = 0; i < n; i++) a[i] = (a[i] * this.nInv) % q;
    }
  }

  /** Negacyclic product of a and b in Z_q[X]/(X^n+1). */
  multiply(a: number[], b: number[]): number[] {
    const { n, q } = this;
    const fa = new Array(n);
    const fb = new Array(n);
    for (let i = 0; i < n; i++) {
      fa[i] = ((((a[i] % q) + q) % q) * this.psiPow[i]) % q;
      fb[i] = ((((b[i] % q) + q) % q) * this.psiPow[i]) % q;
    }
    this.transform(fa, false);
    this.transform(fb, false);
    const fc = new Array(n);
    for (let i = 0; i < n; i++) fc[i] = (fa[i] * fb[i]) % q;
    this.transform(fc, true);
    const c = new Array(n);
    for (let i = 0; i < n; i++) c[i] = (fc[i] * this.psiInvPow[i]) % q;
    return c;
  }
}

// Cache instances by (n, q) — root-of-unity precomputation is reused across calls.
const cache = new Map<string, NegacyclicNTT>();

export function getNTT(n: number, q: number): NegacyclicNTT {
  const key = `${n}:${q}`;
  let inst = cache.get(key);
  if (!inst) {
    inst = new NegacyclicNTT(n, q);
    cache.set(key, inst);
  }
  return inst;
}
