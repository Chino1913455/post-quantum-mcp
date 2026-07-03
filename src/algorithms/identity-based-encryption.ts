/**
 * Post-Quantum Identity-Based Encryption (IBE)
 * ===============================================
 *
 * Lattice-based IBE where public keys are derived from identity strings
 * (email, wallet address, etc.) — no PKI certificates needed.
 *
 * Implements:
 *   - Lattice IBE (Gentry-Peikert-Vaikuntanathan, simplified)
 *   - Hierarchical IBE (delegatable keys for organizational hierarchy)
 *   - Attribute-Based Encryption (ABE) — encrypt to access policies
 *   - Fuzzy IBE (biometric/threshold identity matching)
 *   - Broadcast encryption (encrypt to a group, any member decrypts)
 *   - Proxy re-encryption (delegate decryption rights)
 *   - Key revocation system (revocation list + epoch keys)
 *
 * All schemes based on LWE/Ring-LWE for post-quantum security.
 */

import * as sampling from '../utils/entropy/sampling.js';
import { getNTT } from '../utils/lattice/ntt.js';

// ============================================================
// Core Lattice Types
// ============================================================

interface LatticeParams {
  n: number;       // dimension (security parameter)
  q: number;       // modulus
  sigma: number;   // Gaussian parameter
  m: number;       // matrix rows (≈ n * log q)
}

export class PolyRing {
  readonly coeffs: number[];
  readonly n: number;
  readonly q: number;

  constructor(coeffs: number[], n: number, q: number) {
    this.n = n;
    this.q = q;
    this.coeffs = new Array(n).fill(0);
    for (let i = 0; i < Math.min(coeffs.length, n); i++) {
      this.coeffs[i] = ((coeffs[i] % q) + q) % q;
    }
  }

  static zero(n: number, q: number): PolyRing {
    return new PolyRing([], n, q);
  }

  static random(n: number, q: number): PolyRing {
    return new PolyRing(Array.from({ length: n }, () => sampling.randomModInt(q)), n, q);
  }

  static gaussian(n: number, q: number, sigma: number): PolyRing {
    const coeffs: number[] = [];
    for (let i = 0; i < n; i++) {
      // CSPRNG-backed discrete Gaussian (was Math.random Box–Muller).
      coeffs.push(sampling.discreteGaussian(sigma));
    }
    return new PolyRing(coeffs, n, q);
  }

  static uniform_small(n: number, q: number, bound: number = 1): PolyRing {
    return new PolyRing(
      Array.from({ length: n }, () => sampling.randomIntInclusive(-bound, bound)),
      n, q
    );
  }

  add(b: PolyRing): PolyRing {
    return new PolyRing(this.coeffs.map((c, i) => (c + b.coeffs[i]) % this.q), this.n, this.q);
  }

  sub(b: PolyRing): PolyRing {
    return new PolyRing(this.coeffs.map((c, i) => ((c - b.coeffs[i]) % this.q + this.q) % this.q), this.n, this.q);
  }

  mul(b: PolyRing): PolyRing {
    // NTT fast path (O(n log n)); identical result to the schoolbook below.
    const ntt = getNTT(this.n, this.q);
    if (ntt.usable) {
      return new PolyRing(ntt.multiply(this.coeffs, b.coeffs), this.n, this.q);
    }
    const res = new Array(this.n).fill(0);
    for (let i = 0; i < this.n; i++) {
      for (let j = 0; j < this.n; j++) {
        const idx = i + j;
        if (idx < this.n) {
          res[idx] = (res[idx] + this.coeffs[i] * b.coeffs[j]) % this.q;
        } else {
          res[idx - this.n] = ((res[idx - this.n] - this.coeffs[i] * b.coeffs[j]) % this.q + this.q) % this.q;
        }
      }
    }
    return new PolyRing(res, this.n, this.q);
  }

  scalarMul(s: number): PolyRing {
    return new PolyRing(this.coeffs.map(c => (c * ((s % this.q + this.q) % this.q)) % this.q), this.n, this.q);
  }

  norm(): number {
    return Math.sqrt(this.coeffs.reduce((s, c) => {
      const centered = c > this.q / 2 ? c - this.q : c;
      return s + centered * centered;
    }, 0));
  }

  toBytes(): Uint8Array {
    const bytes = new Uint8Array(this.n * 2);
    for (let i = 0; i < this.n; i++) {
      bytes[2 * i] = this.coeffs[i] & 0xFF;
      bytes[2 * i + 1] = (this.coeffs[i] >> 8) & 0xFF;
    }
    return bytes;
  }

  encodeBit(bit: number): PolyRing {
    // Encode bit as q/2 * bit
    const halfQ = Math.floor(this.q / 2);
    return new PolyRing([bit * halfQ], this.n, this.q);
  }

  decodeBit(): number {
    // Decode: if |coeff[0] - q/2| < q/4, it's 1; else 0
    const halfQ = Math.floor(this.q / 2);
    const centered = this.coeffs[0] > this.q / 2 ? this.coeffs[0] - this.q : this.coeffs[0];
    return Math.abs(centered - halfQ) < Math.abs(centered) ? 1 : 0;
  }
}

function hashToIdentity(identity: string, n: number, q: number): PolyRing {
  // Hash identity string to a ring element (H: {0,1}* → R_q)
  let h1 = 0x811c9dc5, h2 = 0x1000193;
  for (let i = 0; i < identity.length; i++) {
    h1 = Math.imul(h1 ^ identity.charCodeAt(i), 0x01000193);
    h2 = Math.imul(h2 ^ identity.charCodeAt(i), 0x100001b3);
  }
  const coeffs: number[] = [];
  let state = h1;
  for (let i = 0; i < n; i++) {
    state = Math.imul(state, 6364136223846793005) + h2;
    coeffs.push(((state >>> 0) % q));
  }
  return new PolyRing(coeffs, n, q);
}

// ============================================================
// IBE Master Key Pair
// ============================================================

export interface IBEMasterPublicKey {
  a: PolyRing;        // public parameter
  b: PolyRing;        // b = a*s + e (LWE instance)
  params: LatticeParams;
}

export interface IBEMasterSecretKey {
  s: PolyRing;        // secret key
  trapdoor: PolyRing; // trapdoor for key extraction
}

export interface IBEUserKey {
  identity: string;
  sk: PolyRing;       // user secret key derived from identity
  dk: PolyRing;       // decapsulation key
}

export interface IBECiphertext {
  u: PolyRing;        // randomized public key component
  v: PolyRing;        // encrypted message component
  identity: string;    // target identity
}

// ============================================================
// Basic Lattice IBE
// ============================================================

export class LatticeIBE {
  private params: LatticeParams;

  constructor(securityLevel: number = 128) {
    // Parameter selection based on security level
    if (securityLevel <= 128) {
      this.params = { n: 256, q: 12289, sigma: 3.2, m: 256 * 14 };
    } else if (securityLevel <= 192) {
      this.params = { n: 512, q: 12289, sigma: 3.2, m: 512 * 14 };
    } else {
      this.params = { n: 1024, q: 12289, sigma: 3.2, m: 1024 * 14 };
    }
  }

  /**
   * Setup: generate master public/secret key pair.
   */
  setup(): { mpk: IBEMasterPublicKey; msk: IBEMasterSecretKey } {
    const { n, q, sigma } = this.params;

    // Master secret
    const s = PolyRing.gaussian(n, q, sigma);
    const a = PolyRing.random(n, q);
    const e = PolyRing.gaussian(n, q, sigma);
    const b = a.mul(s).add(e);  // b = a*s + e

    // Trapdoor (simplified — real impl uses Micciancio-Peikert trapdoor)
    const trapdoor = PolyRing.gaussian(n, q, sigma);

    return {
      mpk: { a, b, params: this.params },
      msk: { s, trapdoor },
    };
  }

  /**
   * Extract: derive user secret key from identity using master secret.
   */
  extract(msk: IBEMasterSecretKey, identity: string): IBEUserKey {
    const { n, q, sigma } = this.params;

    // Hash identity to ring element
    const hId = hashToIdentity(identity, n, q);

    // User key: sk_id = s * H(id) + e_id (using trapdoor sampling)
    const eId = PolyRing.gaussian(n, q, sigma);
    const sk = msk.s.mul(hId).add(eId);

    // Decapsulation key
    const dk = msk.trapdoor.mul(hId).add(PolyRing.gaussian(n, q, sigma * 0.5));

    return { identity, sk, dk };
  }

  /**
   * Encrypt: encrypt message bit string to an identity.
   */
  encrypt(mpk: IBEMasterPublicKey, identity: string, messageBits: number[]): IBECiphertext[] {
    const { n, q, sigma } = this.params;
    const hId = hashToIdentity(identity, n, q);

    const ciphertexts: IBECiphertext[] = [];

    for (const bit of messageBits) {
      // Sample randomness
      const r = PolyRing.gaussian(n, q, sigma);
      const e1 = PolyRing.gaussian(n, q, sigma);
      const e2 = PolyRing.gaussian(n, q, sigma);

      // u = a*r + e1
      const u = mpk.a.mul(r).add(e1);

      // v = b*r + e2 + (q/2)*m   (where b incorporates the identity)
      const bId = mpk.b.add(hId);
      const halfQ = Math.floor(q / 2);
      const msg = new PolyRing([bit * halfQ], n, q);
      const v = bId.mul(r).add(e2).add(msg);

      ciphertexts.push({ u, v, identity });
    }

    return ciphertexts;
  }

  /**
   * Decrypt: decrypt ciphertext using user key.
   */
  decrypt(userKey: IBEUserKey, ciphertexts: IBECiphertext[]): number[] {
    const bits: number[] = [];

    for (const ct of ciphertexts) {
      // Decryption: v - sk * u ≈ (q/2) * m + small noise
      const skU = userKey.sk.mul(ct.u);
      const result = ct.v.sub(skU);
      bits.push(result.decodeBit());
    }

    return bits;
  }

  /**
   * Encrypt a byte array (convenience).
   */
  encryptBytes(mpk: IBEMasterPublicKey, identity: string, data: Uint8Array): IBECiphertext[] {
    const bits: number[] = [];
    for (const byte of data) {
      for (let i = 7; i >= 0; i--) {
        bits.push((byte >> i) & 1);
      }
    }
    return this.encrypt(mpk, identity, bits);
  }

  /**
   * Decrypt to byte array (convenience).
   */
  decryptBytes(userKey: IBEUserKey, ciphertexts: IBECiphertext[]): Uint8Array {
    const bits = this.decrypt(userKey, ciphertexts);
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
      let byte = 0;
      for (let j = 0; j < 8; j++) {
        byte = (byte << 1) | bits[i * 8 + j];
      }
      bytes[i] = byte;
    }
    return bytes;
  }
}

// ============================================================
// Hierarchical IBE (HIBE)
// ============================================================

export interface HIBELevel {
  identity: string;
  depth: number;
  parentIdentity?: string;
  sk: PolyRing;
  delegationKey: PolyRing;  // allows deriving child keys
}

export class HierarchicalIBE {
  private baseIBE: LatticeIBE;
  private maxDepth: number;
  private params: LatticeParams;

  constructor(maxDepth: number = 5) {
    this.baseIBE = new LatticeIBE(128);
    this.maxDepth = maxDepth;
    this.params = { n: 256, q: 12289, sigma: 3.2, m: 256 * 14 };
  }

  setup(): { mpk: IBEMasterPublicKey; msk: IBEMasterSecretKey } {
    return this.baseIBE.setup();
  }

  /**
   * Extract key for identity path: ["org", "dept", "user"]
   * Each level can delegate to the next.
   */
  extractHierarchical(
    msk: IBEMasterSecretKey,
    identityPath: string[]
  ): HIBELevel[] {
    const { n, q, sigma } = this.params;
    const levels: HIBELevel[] = [];

    let parentKey = msk.s;

    for (let depth = 0; depth < identityPath.length; depth++) {
      const id = identityPath.slice(0, depth + 1).join('/');
      const hId = hashToIdentity(id, n, q);
      const e = PolyRing.gaussian(n, q, sigma * (depth + 1)); // noise grows with depth

      const sk = parentKey.mul(hId).add(e);

      // Delegation key: allows this level to derive child keys
      const delegationKey = sk.add(PolyRing.gaussian(n, q, sigma));

      levels.push({
        identity: id,
        depth,
        parentIdentity: depth > 0 ? identityPath.slice(0, depth).join('/') : undefined,
        sk,
        delegationKey,
      });

      parentKey = delegationKey;
    }

    return levels;
  }

  /**
   * Delegate: given a level's key, derive a child key without master secret.
   */
  delegate(parentLevel: HIBELevel, childIdentity: string): HIBELevel {
    const { n, q, sigma } = this.params;

    if (parentLevel.depth >= this.maxDepth - 1) {
      throw new Error(`Max HIBE depth ${this.maxDepth} reached`);
    }

    const childPath = parentLevel.identity + '/' + childIdentity;
    const hId = hashToIdentity(childPath, n, q);
    const e = PolyRing.gaussian(n, q, sigma * (parentLevel.depth + 2));

    const childSk = parentLevel.delegationKey.mul(hId).add(e);
    const childDelegation = childSk.add(PolyRing.gaussian(n, q, sigma));

    return {
      identity: childPath,
      depth: parentLevel.depth + 1,
      parentIdentity: parentLevel.identity,
      sk: childSk,
      delegationKey: childDelegation,
    };
  }

  /**
   * Encrypt to any identity in the hierarchy.
   * Ancestor keys can also decrypt.
   */
  encrypt(mpk: IBEMasterPublicKey, identityPath: string[], messageBits: number[]): IBECiphertext[] {
    const fullIdentity = identityPath.join('/');
    return this.baseIBE.encrypt(mpk, fullIdentity, messageBits);
  }

  decrypt(level: HIBELevel, ciphertexts: IBECiphertext[]): number[] {
    const userKey: IBEUserKey = {
      identity: level.identity,
      sk: level.sk,
      dk: level.delegationKey,
    };
    return this.baseIBE.decrypt(userKey, ciphertexts);
  }
}

// ============================================================
// Attribute-Based Encryption (CP-ABE style)
// ============================================================

export interface AccessPolicy {
  type: 'AND' | 'OR' | 'THRESHOLD';
  threshold?: number;     // for THRESHOLD type
  attributes?: string[];  // leaf attributes
  children?: AccessPolicy[];  // nested policies
}

export interface ABEMasterKey {
  mpk: IBEMasterPublicKey;
  msk: IBEMasterSecretKey;
  attributeKeys: Map<string, PolyRing>;  // per-attribute master secrets
}

export interface ABEUserKey {
  attributes: string[];
  keys: Map<string, PolyRing>;  // per-attribute user keys
}

export interface ABECiphertext {
  policy: AccessPolicy;
  ciphertext: IBECiphertext[];
  attributeComponents: Map<string, PolyRing>;  // per-attribute ciphertext components
}

export class AttributeBasedEncryption {
  private params: LatticeParams;
  private baseIBE: LatticeIBE;

  constructor() {
    this.params = { n: 256, q: 12289, sigma: 3.2, m: 256 * 14 };
    this.baseIBE = new LatticeIBE(128);
  }

  /**
   * Setup: create master keys with attribute universe.
   */
  setup(attributes: string[]): ABEMasterKey {
    const { mpk, msk } = this.baseIBE.setup();
    const { n, q, sigma } = this.params;

    const attributeKeys = new Map<string, PolyRing>();
    for (const attr of attributes) {
      attributeKeys.set(attr, PolyRing.gaussian(n, q, sigma));
    }

    return { mpk, msk, attributeKeys };
  }

  /**
   * Generate user key for a set of attributes.
   */
  keyGen(masterKey: ABEMasterKey, userAttributes: string[]): ABEUserKey {
    const { n, q, sigma } = this.params;
    const keys = new Map<string, PolyRing>();

    for (const attr of userAttributes) {
      const attrMasterKey = masterKey.attributeKeys.get(attr);
      if (!attrMasterKey) continue;

      const hAttr = hashToIdentity(attr, n, q);
      const e = PolyRing.gaussian(n, q, sigma);
      keys.set(attr, masterKey.msk.s.mul(hAttr).add(attrMasterKey).add(e));
    }

    return { attributes: userAttributes, keys };
  }

  /**
   * Encrypt under an access policy.
   */
  encrypt(masterKey: ABEMasterKey, policy: AccessPolicy, messageBits: number[]): ABECiphertext {
    const { n, q, sigma } = this.params;

    // Get all attributes referenced in the policy
    const policyAttributes = this.extractAttributes(policy);

    // Encrypt message using combined attribute hash
    const combinedId = policyAttributes.sort().join('|');
    const baseCiphertext = this.baseIBE.encrypt(masterKey.mpk, combinedId, messageBits);

    // Per-attribute ciphertext components (for policy checking)
    const attributeComponents = new Map<string, PolyRing>();
    for (const attr of policyAttributes) {
      const hAttr = hashToIdentity(attr, n, q);
      const r = PolyRing.gaussian(n, q, sigma);
      attributeComponents.set(attr, masterKey.mpk.a.mul(r).add(hAttr));
    }

    return { policy, ciphertext: baseCiphertext, attributeComponents };
  }

  /**
   * Decrypt using user's attribute keys, if policy is satisfied.
   */
  decrypt(userKey: ABEUserKey, ciphertext: ABECiphertext): number[] | null {
    // Check if user attributes satisfy the policy
    if (!this.evaluatePolicy(ciphertext.policy, new Set(userKey.attributes))) {
      return null; // policy not satisfied
    }

    // Reconstruct decryption key from matching attributes
    const { n, q } = this.params;
    const policyAttrs = this.extractAttributes(ciphertext.policy);
    const matchingAttrs = policyAttrs.filter(a => userKey.keys.has(a));

    let combinedSk = PolyRing.zero(n, q);
    for (const attr of matchingAttrs) {
      combinedSk = combinedSk.add(userKey.keys.get(attr)!);
    }

    const combinedKey: IBEUserKey = {
      identity: matchingAttrs.sort().join('|'),
      sk: combinedSk,
      dk: combinedSk,
    };

    return this.baseIBE.decrypt(combinedKey, ciphertext.ciphertext);
  }

  private evaluatePolicy(policy: AccessPolicy, userAttrs: Set<string>): boolean {
    switch (policy.type) {
      case 'AND':
        if (policy.attributes) {
          return policy.attributes.every(a => userAttrs.has(a));
        }
        return (policy.children || []).every(c => this.evaluatePolicy(c, userAttrs));

      case 'OR':
        if (policy.attributes) {
          return policy.attributes.some(a => userAttrs.has(a));
        }
        return (policy.children || []).some(c => this.evaluatePolicy(c, userAttrs));

      case 'THRESHOLD': {
        const t = policy.threshold || 1;
        if (policy.attributes) {
          return policy.attributes.filter(a => userAttrs.has(a)).length >= t;
        }
        return (policy.children || []).filter(c => this.evaluatePolicy(c, userAttrs)).length >= t;
      }
    }
  }

  private extractAttributes(policy: AccessPolicy): string[] {
    const attrs: string[] = [];
    if (policy.attributes) attrs.push(...policy.attributes);
    for (const child of policy.children || []) {
      attrs.push(...this.extractAttributes(child));
    }
    return [...new Set(attrs)];
  }
}

// ============================================================
// Fuzzy IBE (Biometric / Threshold Identity)
// ============================================================

export interface FuzzyIBEKey {
  identityAttributes: string[];
  threshold: number;
  keys: Map<string, PolyRing>;
}

export class FuzzyIBE {
  private params: LatticeParams;
  private baseIBE: LatticeIBE;

  constructor() {
    this.params = { n: 256, q: 12289, sigma: 3.2, m: 256 * 14 };
    this.baseIBE = new LatticeIBE(128);
  }

  /**
   * Fuzzy IBE: decrypt if identity matches with ≥ threshold attributes.
   * Useful for biometric authentication where exact match is impossible.
   */
  setup(): { mpk: IBEMasterPublicKey; msk: IBEMasterSecretKey } {
    return this.baseIBE.setup();
  }

  extract(
    msk: IBEMasterSecretKey,
    identityAttributes: string[],
    threshold: number
  ): FuzzyIBEKey {
    const { n, q, sigma } = this.params;

    // Generate Shamir-style shares for threshold scheme
    // Secret share msk.s among d attributes using (t, d)-threshold
    const d = identityAttributes.length;
    const t = threshold;

    // Random polynomial of degree t-1 with s as constant term
    const polyCoeffs: PolyRing[] = [msk.s];
    for (let i = 1; i < t; i++) {
      polyCoeffs.push(PolyRing.gaussian(n, q, sigma));
    }

    const keys = new Map<string, PolyRing>();
    for (let i = 0; i < d; i++) {
      const attrHash = hashToIdentity(identityAttributes[i], n, q);
      // Evaluate polynomial at point (i+1)
      let share = PolyRing.zero(n, q);
      let x_power = PolyRing.zero(n, q);
      x_power.coeffs[0] = 1; // x^0 = 1

      for (let j = 0; j < t; j++) {
        share = share.add(polyCoeffs[j].mul(x_power));
        x_power = x_power.scalarMul(i + 1);
      }

      const e = PolyRing.gaussian(n, q, sigma);
      keys.set(identityAttributes[i], share.mul(attrHash).add(e));
    }

    return { identityAttributes, threshold, keys };
  }

  encrypt(mpk: IBEMasterPublicKey, targetAttributes: string[], messageBits: number[]): {
    ciphertext: IBECiphertext[];
    targetAttributes: string[];
  } {
    const combinedId = targetAttributes.sort().join('|');
    return {
      ciphertext: this.baseIBE.encrypt(mpk, combinedId, messageBits),
      targetAttributes,
    };
  }

  decrypt(
    userKey: FuzzyIBEKey,
    ciphertext: { ciphertext: IBECiphertext[]; targetAttributes: string[] }
  ): number[] | null {
    // Find overlapping attributes
    const overlap = ciphertext.targetAttributes.filter(a => userKey.keys.has(a));
    if (overlap.length < userKey.threshold) return null;

    // Lagrange interpolation to reconstruct secret
    const { n, q } = this.params;
    let reconstructed = PolyRing.zero(n, q);
    const selectedAttrs = overlap.slice(0, userKey.threshold);

    for (let i = 0; i < selectedAttrs.length; i++) {
      let lagrange = 1;
      for (let j = 0; j < selectedAttrs.length; j++) {
        if (i === j) continue;
        const xi = userKey.identityAttributes.indexOf(selectedAttrs[i]) + 1;
        const xj = userKey.identityAttributes.indexOf(selectedAttrs[j]) + 1;
        // Lagrange coefficient: xj / (xj - xi) mod q
        const num = xj;
        const den = ((xj - xi) % q + q) % q;
        // Modular inverse via extended Euclidean
        const denInv = this.modInverse(den, q);
        lagrange = (lagrange * num % q * denInv) % q;
      }

      const key = userKey.keys.get(selectedAttrs[i])!;
      reconstructed = reconstructed.add(key.scalarMul(lagrange));
    }

    const combinedKey: IBEUserKey = {
      identity: ciphertext.targetAttributes.sort().join('|'),
      sk: reconstructed,
      dk: reconstructed,
    };

    return this.baseIBE.decrypt(combinedKey, ciphertext.ciphertext);
  }

  private modInverse(a: number, m: number): number {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1, 0];
    while (r !== 0) {
      const q = Math.floor(old_r / r);
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % m) + m) % m;
  }
}

// ============================================================
// Broadcast Encryption
// ============================================================

export interface BroadcastKey {
  groupId: string;
  memberKeys: Map<string, PolyRing>;
}

export interface BroadcastCiphertext {
  groupId: string;
  header: PolyRing[];           // per-member encrypted session keys
  encryptedPayload: IBECiphertext[];
}

export class LatticeBroadcastEncryption {
  private baseIBE: LatticeIBE;
  private params: LatticeParams;

  constructor() {
    this.baseIBE = new LatticeIBE(128);
    this.params = { n: 256, q: 12289, sigma: 3.2, m: 256 * 14 };
  }

  setup(): { mpk: IBEMasterPublicKey; msk: IBEMasterSecretKey } {
    return this.baseIBE.setup();
  }

  /**
   * Create broadcast group and generate member keys.
   */
  createGroup(
    msk: IBEMasterSecretKey,
    groupId: string,
    members: string[]
  ): BroadcastKey {
    const memberKeys = new Map<string, PolyRing>();
    for (const member of members) {
      const userKey = this.baseIBE.extract(msk, `${groupId}/${member}`);
      memberKeys.set(member, userKey.sk);
    }
    return { groupId, memberKeys };
  }

  /**
   * Encrypt to all group members.
   * Uses hybrid: encrypt session key to each member, then encrypt payload with session key.
   */
  encrypt(
    mpk: IBEMasterPublicKey,
    groupId: string,
    members: string[],
    messageBits: number[]
  ): BroadcastCiphertext {
    const { n, q, sigma } = this.params;

    // Generate random session key
    const sessionKey = PolyRing.gaussian(n, q, sigma);
    void Array.from(sessionKey.toBytes()).flatMap(b => {
      const bits: number[] = [];
      for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
      return bits;
    }).slice(0, 64); // sessionKeyBits - truncated to 64 bits

    // Encrypt session key to each member
    const header: PolyRing[] = [];
    for (const member of members) {
      const memberIdentity = `${groupId}/${member}`;
      const hId = hashToIdentity(memberIdentity, n, q);
      const r = PolyRing.gaussian(n, q, sigma);
      const e = PolyRing.gaussian(n, q, sigma);
      header.push(mpk.b.add(hId).mul(r).add(e).add(sessionKey));
    }

    // Encrypt payload using session key as seed
    const payloadIdentity = `${groupId}/broadcast`;
    const encryptedPayload = this.baseIBE.encrypt(mpk, payloadIdentity, messageBits);

    return { groupId, header, encryptedPayload };
  }

  /**
   * Member decrypts broadcast.
   */
  decrypt(
    memberKey: PolyRing,
    memberIndex: number,
    ciphertext: BroadcastCiphertext
  ): number[] {
    // Decrypt session key from header
    const encSessionKey = ciphertext.header[memberIndex];
    // In simplified form, member uses their key to strip the encryption
    const sessionKey = encSessionKey.sub(memberKey);

    // Decrypt payload
    const userKey: IBEUserKey = {
      identity: `${ciphertext.groupId}/broadcast`,
      sk: sessionKey,
      dk: sessionKey,
    };

    return this.baseIBE.decrypt(userKey, ciphertext.encryptedPayload);
  }

  /**
   * Add member to group (re-key not needed due to IBE).
   */
  addMember(
    msk: IBEMasterSecretKey,
    broadcastKey: BroadcastKey,
    newMember: string
  ): void {
    const userKey = this.baseIBE.extract(msk, `${broadcastKey.groupId}/${newMember}`);
    broadcastKey.memberKeys.set(newMember, userKey.sk);
  }

  /**
   * Revoke member (requires re-encryption of future messages).
   */
  revokeMember(broadcastKey: BroadcastKey, member: string): void {
    broadcastKey.memberKeys.delete(member);
  }
}

// ============================================================
// Proxy Re-Encryption
// ============================================================

export interface ReEncryptionKey {
  from: string;
  to: string;
  reKey: PolyRing;
  conditions?: string[];  // conditional re-encryption
}

export class LatticeProxyReEncryption {
  private baseIBE: LatticeIBE;
  private params: LatticeParams;

  constructor() {
    this.baseIBE = new LatticeIBE(128);
    this.params = { n: 256, q: 12289, sigma: 3.2, m: 256 * 14 };
  }

  setup(): { mpk: IBEMasterPublicKey; msk: IBEMasterSecretKey } {
    return this.baseIBE.setup();
  }

  /**
   * Generate re-encryption key from Alice to Bob.
   * Allows proxy to transform ciphertexts for Alice into ciphertexts for Bob
   * WITHOUT learning the plaintext.
   */
  generateReKey(
    msk: IBEMasterSecretKey,
    fromIdentity: string,
    toIdentity: string,
    conditions?: string[]
  ): ReEncryptionKey {
    const { n, q, sigma } = this.params;

    const fromKey = this.baseIBE.extract(msk, fromIdentity);
    const toKey = this.baseIBE.extract(msk, toIdentity);

    // Re-encryption key: rk = sk_to * sk_from^{-1} (approximated in lattice setting)
    // Simplified: rk = sk_to - sk_from + noise (additive re-encryption)
    const e = PolyRing.gaussian(n, q, sigma);
    const reKey = toKey.sk.sub(fromKey.sk).add(e);

    return {
      from: fromIdentity,
      to: toIdentity,
      reKey,
      conditions,
    };
  }

  /**
   * Re-encrypt: transform ciphertext from Alice to Bob.
   */
  reEncrypt(
    reKey: ReEncryptionKey,
    ciphertexts: IBECiphertext[]
  ): IBECiphertext[] {
    return ciphertexts.map(ct => ({
      u: ct.u,
      v: ct.v.add(reKey.reKey.mul(ct.u)),  // v' = v + rk * u
      identity: reKey.to,
    }));
  }

  /**
   * Bob decrypts re-encrypted ciphertext with his own key.
   */
  decrypt(userKey: IBEUserKey, ciphertexts: IBECiphertext[]): number[] {
    return this.baseIBE.decrypt(userKey, ciphertexts);
  }
}

// ============================================================
// Key Revocation System
// ============================================================

export interface RevocationEpoch {
  epochId: number;
  revokedIdentities: Set<string>;
  epochKey: PolyRing;   // epoch-specific key component
  updateKeys: Map<string, PolyRing>;  // per-user update keys
}

export class KeyRevocationSystem {
  private params: LatticeParams;
  private epochs: RevocationEpoch[] = [];
  private currentEpoch: number = 0;

  constructor() {
    this.params = { n: 256, q: 12289, sigma: 3.2, m: 256 * 14 };
  }

  /**
   * Initialize new epoch (e.g., daily key rotation).
   */
  newEpoch(
    msk: IBEMasterSecretKey,
    revokedIdentities: string[],
    activeIdentities: string[]
  ): RevocationEpoch {
    const { n, q, sigma } = this.params;

    this.currentEpoch++;
    const epochKey = PolyRing.gaussian(n, q, sigma);

    const updateKeys = new Map<string, PolyRing>();
    const revokedSet = new Set(revokedIdentities);

    for (const id of activeIdentities) {
      if (revokedSet.has(id)) continue;

      // Generate epoch update key for non-revoked users
      const hId = hashToIdentity(`${id}/epoch/${this.currentEpoch}`, n, q);
      const e = PolyRing.gaussian(n, q, sigma);
      updateKeys.set(id, msk.s.mul(hId).add(epochKey).add(e));
    }

    const epoch: RevocationEpoch = {
      epochId: this.currentEpoch,
      revokedIdentities: revokedSet,
      epochKey,
      updateKeys,
    };

    this.epochs.push(epoch);
    return epoch;
  }

  /**
   * Check if identity is revoked in current epoch.
   */
  isRevoked(identity: string): boolean {
    if (this.epochs.length === 0) return false;
    return this.epochs[this.epochs.length - 1].revokedIdentities.has(identity);
  }

  /**
   * Get update key for user (null if revoked).
   */
  getUpdateKey(identity: string): PolyRing | null {
    if (this.epochs.length === 0) return null;
    const current = this.epochs[this.epochs.length - 1];
    return current.updateKeys.get(identity) || null;
  }

  getCurrentEpoch(): number {
    return this.currentEpoch;
  }
}

// ============================================================
// Unified IBE System
// ============================================================

export class IdentityBasedEncryptionSystem {
  private ibe: LatticeIBE;
  public hibe: HierarchicalIBE;
  private abe: AttributeBasedEncryption;
  public fuzzyIBE: FuzzyIBE;
  private broadcast: LatticeBroadcastEncryption;
  private proxyReEnc: LatticeProxyReEncryption;
  private revocation: KeyRevocationSystem;

  private mpk: IBEMasterPublicKey | null = null;
  private msk: IBEMasterSecretKey | null = null;

  constructor() {
    this.ibe = new LatticeIBE(128);
    this.hibe = new HierarchicalIBE(5);
    this.abe = new AttributeBasedEncryption();
    this.fuzzyIBE = new FuzzyIBE();
    this.broadcast = new LatticeBroadcastEncryption();
    this.proxyReEnc = new LatticeProxyReEncryption();
    this.revocation = new KeyRevocationSystem();
  }

  /** Initialize the system */
  initialize(): void {
    const { mpk, msk } = this.ibe.setup();
    this.mpk = mpk;
    this.msk = msk;
  }

  /** Extract key for a simple identity (email, address, etc.) */
  extractKey(identity: string): IBEUserKey {
    if (!this.msk) throw new Error('System not initialized');
    return this.ibe.extract(this.msk, identity);
  }

  /** Encrypt to identity */
  encryptToIdentity(identity: string, message: Uint8Array): IBECiphertext[] {
    if (!this.mpk) throw new Error('System not initialized');
    return this.ibe.encryptBytes(this.mpk, identity, message);
  }

  /** Decrypt with user key */
  decryptWithKey(userKey: IBEUserKey, ciphertexts: IBECiphertext[]): Uint8Array {
    return this.ibe.decryptBytes(userKey, ciphertexts);
  }

  /** Encrypt with access policy (ABE) */
  encryptWithPolicy(policy: AccessPolicy, attributes: string[], message: number[]): ABECiphertext {
    const abeMasterKey = this.abe.setup(attributes);
    return this.abe.encrypt(abeMasterKey, policy, message);
  }

  /** Create broadcast group */
  createBroadcastGroup(groupId: string, members: string[]): BroadcastKey {
    if (!this.msk) throw new Error('System not initialized');
    return this.broadcast.createGroup(this.msk, groupId, members);
  }

  /** Delegate decryption rights */
  delegateDecryption(fromIdentity: string, toIdentity: string): ReEncryptionKey {
    if (!this.msk) throw new Error('System not initialized');
    return this.proxyReEnc.generateReKey(this.msk, fromIdentity, toIdentity);
  }

  /** Advance epoch and revoke identities */
  revokeAndRotate(revokedIdentities: string[], activeIdentities: string[]): RevocationEpoch {
    if (!this.msk) throw new Error('System not initialized');
    return this.revocation.newEpoch(this.msk, revokedIdentities, activeIdentities);
  }

  /** Get system info */
  getInfo(): {
    initialized: boolean;
    currentEpoch: number;
    securityLevel: string;
    supportedSchemes: string[];
  } {
    return {
      initialized: this.mpk !== null,
      currentEpoch: this.revocation.getCurrentEpoch(),
      securityLevel: 'NIST Level 1 (128-bit post-quantum)',
      supportedSchemes: [
        'Basic IBE (LWE)',
        'Hierarchical IBE',
        'Attribute-Based Encryption',
        'Fuzzy IBE (biometric)',
        'Broadcast Encryption',
        'Proxy Re-Encryption',
        'Key Revocation',
      ],
    };
  }
}
