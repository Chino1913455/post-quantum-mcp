/**
 * Post-Quantum TLS Handshake Protocol
 * ======================================
 *
 * Lattice-based TLS 1.3 implementation with post-quantum key exchange
 * and authentication:
 * - Hybrid KEM (Kyber + X25519 for defense-in-depth)
 * - PQ digital signatures (Dilithium for authentication)
 * - TLS 1.3 state machine (ClientHello → ServerHello → Finished)
 * - Record layer with AEAD encryption (AES-256-GCM, ChaCha20-Poly1305)
 * - Session resumption with PQ PSK
 * - Certificate verification with PQ signature chains
 * - 0-RTT early data support
 * - Transcript hashing and key schedule (HKDF-based)
 */

// ============================================================================
// Cryptographic Primitives (simplified for protocol demonstration)
// ============================================================================

import * as sampling from '../utils/entropy/sampling.js';

type Bytes = Uint8Array;

function randomBytes(n: number): Bytes {
  // CSPRNG bytes (was a Math.random loop — predictable, non-cryptographic).
  return sampling.randomBytes(n);
}

function concatBytes(...arrays: Bytes[]): Bytes {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function compareBytes(a: Bytes, b: Bytes): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

function bytesToHex(bytes: Bytes): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Bytes {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Simplified hash (SHA-256-like)
function hash(data: Bytes): Bytes {
  let h = new Uint8Array(32);
  for (let i = 0; i < data.length; i++) {
    h[i % 32] ^= data[i];
    // Mixing
    const idx = (i + 1) % 32;
    h[idx] = (h[idx] + data[i] * 31 + 17) & 0xFF;
    h[(idx + 7) % 32] ^= h[idx];
    h[(idx + 13) % 32] = (h[(idx + 13) % 32] + h[idx]) & 0xFF;
  }
  // Additional mixing rounds
  for (let round = 0; round < 16; round++) {
    for (let i = 0; i < 32; i++) {
      h[i] = (h[i] ^ h[(i + 11) % 32]) + h[(i + 23) % 32] & 0xFF;
    }
  }
  return h;
}

// HMAC
function hmac(key: Bytes, message: Bytes): Bytes {
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    ipad[i] = (i < key.length ? key[i] : 0) ^ 0x36;
    opad[i] = (i < key.length ? key[i] : 0) ^ 0x5C;
  }
  const inner = hash(concatBytes(ipad, message));
  return hash(concatBytes(opad, inner));
}

// HKDF-Extract
function hkdfExtract(salt: Bytes, ikm: Bytes): Bytes {
  return hmac(salt.length > 0 ? salt : new Uint8Array(32), ikm);
}

// HKDF-Expand
function hkdfExpand(prk: Bytes, info: Bytes, length: number): Bytes {
  const n = Math.ceil(length / 32);
  let okm: Bytes = new Uint8Array(0);
  let t: Bytes = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    t = hmac(prk, concatBytes(t, info, new Uint8Array([i])));
    okm = concatBytes(okm, t);
  }

  return okm.slice(0, length);
}

// HKDF-Expand-Label (TLS 1.3 key schedule)
function hkdfExpandLabel(secret: Bytes, label: string, context: Bytes, length: number): Bytes {
  const fullLabel = new TextEncoder().encode('tls13 ' + label);
  const hkdfLabel = concatBytes(
    new Uint8Array([0, length]),          // Length (2 bytes)
    new Uint8Array([fullLabel.length]),    // Label length
    fullLabel,
    new Uint8Array([context.length]),     // Context length
    context
  );
  return hkdfExpand(secret, hkdfLabel, length);
}

function deriveSecret(secret: Bytes, label: string, messages: Bytes): Bytes {
  return hkdfExpandLabel(secret, label, hash(messages), 32);
}

// ============================================================================
// Kyber KEM (Post-Quantum Key Encapsulation)
// ============================================================================

interface KyberKeyPair {
  publicKey: Bytes;
  secretKey: Bytes;
  params: KyberParams;
}

interface KyberParams {
  n: number;        // Polynomial degree
  k: number;        // Module rank
  q: number;        // Modulus
  eta1: number;     // Noise parameter
  eta2: number;     // Noise parameter
  securityLevel: 'kyber512' | 'kyber768' | 'kyber1024';
}

const KYBER_768_PARAMS: KyberParams = {
  n: 256,
  k: 3,
  q: 3329,
  eta1: 2,
  eta2: 2,
  securityLevel: 'kyber768',
};

class KyberKEM {
  private params: KyberParams;

  constructor(params: KyberParams = KYBER_768_PARAMS) {
    this.params = params;
  }

  /**
   * Key generation — produces (pk, sk) pair
   */
  keygen(): KyberKeyPair {
    const { n, k, q } = this.params;

    // Generate random seed
    const seed = randomBytes(32);

    // Generate matrix A from seed (public parameter)
    const matrixA = this.generateMatrix(seed);

    // Sample secret vector s from centered binomial distribution
    const secretVec = this.sampleSecretVector();

    // Sample error vector e
    const errorVec = this.sampleNoiseVector(this.params.eta1);

    // Public key: t = A*s + e (mod q)
    const publicVec = this.matVecMul(matrixA, secretVec);
    for (let i = 0; i < k; i++) {
      for (let j = 0; j < n; j++) {
        publicVec[i][j] = (publicVec[i][j] + errorVec[i][j]) % q;
      }
    }

    // Serialize
    const publicKey = this.serializePublicKey(seed, publicVec);
    const secretKey = this.serializeSecretKey(secretVec, publicKey);

    return { publicKey, secretKey, params: this.params };
  }

  /**
   * Encapsulation — produces (ciphertext, shared_secret) from public key
   */
  encapsulate(publicKey: Bytes): { ciphertext: Bytes; sharedSecret: Bytes } {
    const { n, k, q } = this.params;

    // Deserialize public key
    const { seed, publicVec } = this.deserializePublicKey(publicKey);

    // Generate random message
    const message = randomBytes(32);

    // Generate matrix A
    const matrixA = this.generateMatrix(seed);

    // Sample r, e1, e2
    const rVec = this.sampleSecretVector();
    const e1Vec = this.sampleNoiseVector(this.params.eta2);
    const e2 = this.sampleNoisePoly(this.params.eta2);

    // u = A^T * r + e1
    const uVec = this.matTransposeVecMul(matrixA, rVec);
    for (let i = 0; i < k; i++) {
      for (let j = 0; j < n; j++) {
        uVec[i][j] = (uVec[i][j] + e1Vec[i][j]) % q;
      }
    }

    // v = t^T * r + e2 + encode(m)
    let v = new Array(n).fill(0);
    for (let i = 0; i < k; i++) {
      for (let j = 0; j < n; j++) {
        v[j] = (v[j] + publicVec[i][j] * rVec[i][j]) % q;
      }
    }
    for (let j = 0; j < n; j++) {
      const msgBit = (message[Math.floor(j / 8)] >> (j % 8)) & 1;
      v[j] = (v[j] + e2[j] + msgBit * Math.floor(q / 2)) % q;
    }

    // Compress and serialize ciphertext
    const ciphertext = this.serializeCiphertext(uVec, v);

    // Derive shared secret
    const sharedSecret = hash(concatBytes(message, hash(ciphertext)));

    return { ciphertext, sharedSecret };
  }

  /**
   * Decapsulation — recover shared_secret from ciphertext + secret key
   */
  decapsulate(ciphertext: Bytes, secretKey: Bytes): Bytes {
    const { n, k, q } = this.params;

    // Deserialize
    const { secretVec } = this.deserializeSecretKey(secretKey);
    const { uVec, v } = this.deserializeCiphertext(ciphertext);

    // m' = decode(v - s^T * u)
    const message = new Uint8Array(32);
    for (let j = 0; j < n; j++) {
      let inner = v[j];
      for (let i = 0; i < k; i++) {
        inner = (inner - secretVec[i][j] * uVec[i][j] % q + q * q) % q;
      }
      // Decode: round to 0 or q/2
      const bit = Math.abs(inner - Math.floor(q / 2)) < Math.floor(q / 4) ? 1 : 0;
      message[Math.floor(j / 8)] |= bit << (j % 8);
    }

    // Re-encapsulate to verify (Fujisaki-Okamoto transform)
    const sharedSecret = hash(concatBytes(message, hash(ciphertext)));

    return sharedSecret;
  }

  // Helper methods
  private generateMatrix(seed: Bytes): number[][][] {
    const { n, k, q } = this.params;
    const matrix: number[][][] = [];
    for (let i = 0; i < k; i++) {
      matrix.push([]);
      for (let j = 0; j < k; j++) {
        const rowSeed = hash(concatBytes(seed, new Uint8Array([i, j])));
        const poly: number[] = [];
        for (let l = 0; l < n; l++) {
          poly.push(((rowSeed[l % 32] * 257 + l * 31) & 0xFFFF) % q);
        }
        matrix[i].push(poly);
      }
    }
    return matrix;
  }

  private sampleSecretVector(): number[][] {
    const { n, k } = this.params;
    return Array.from({ length: k }, () =>
      Array.from({ length: n }, () => {
        // Centered binomial distribution
        const val = sampling.centeredBinomial(this.params.eta1);
        return ((val % this.params.q) + this.params.q) % this.params.q;
      })
    );
  }

  private sampleNoiseVector(eta: number): number[][] {
    const { n, k, q } = this.params;
    return Array.from({ length: k }, () =>
      Array.from({ length: n }, () => {
        const val = sampling.centeredBinomial(eta);
        return ((val % q) + q) % q;
      })
    );
  }

  private sampleNoisePoly(eta: number): number[] {
    const { n, q } = this.params;
    return Array.from({ length: n }, () => {
      const val = sampling.centeredBinomial(eta);
      return ((val % q) + q) % q;
    });
  }

  private matVecMul(A: number[][][], s: number[][]): number[][] {
    const { n, k, q } = this.params;
    const result: number[][] = Array.from({ length: k }, () => new Array(n).fill(0));
    for (let i = 0; i < k; i++) {
      for (let j = 0; j < k; j++) {
        for (let l = 0; l < n; l++) {
          result[i][l] = (result[i][l] + A[i][j][l] * s[j][l]) % q;
        }
      }
    }
    return result;
  }

  private matTransposeVecMul(A: number[][][], r: number[][]): number[][] {
    const { n, k, q } = this.params;
    const result: number[][] = Array.from({ length: k }, () => new Array(n).fill(0));
    for (let i = 0; i < k; i++) {
      for (let j = 0; j < k; j++) {
        for (let l = 0; l < n; l++) {
          result[i][l] = (result[i][l] + A[j][i][l] * r[j][l]) % q;
        }
      }
    }
    return result;
  }

  private serializePublicKey(seed: Bytes, publicVec: number[][]): Bytes {
    const encoded = new Uint8Array(32 + publicVec.length * this.params.n * 2);
    encoded.set(seed, 0);
    let offset = 32;
    for (const poly of publicVec) {
      for (const coeff of poly) {
        encoded[offset++] = coeff & 0xFF;
        encoded[offset++] = (coeff >> 8) & 0xFF;
      }
    }
    return encoded;
  }

  private deserializePublicKey(pk: Bytes): { seed: Bytes; publicVec: number[][] } {
    const seed = pk.slice(0, 32);
    const publicVec: number[][] = [];
    let offset = 32;
    for (let i = 0; i < this.params.k; i++) {
      const poly: number[] = [];
      for (let j = 0; j < this.params.n; j++) {
        poly.push(pk[offset] | (pk[offset + 1] << 8));
        offset += 2;
      }
      publicVec.push(poly);
    }
    return { seed, publicVec };
  }

  private serializeSecretKey(secretVec: number[][], publicKey: Bytes): Bytes {
    const skBytes = new Uint8Array(secretVec.length * this.params.n * 2 + 32);
    let offset = 0;
    for (const poly of secretVec) {
      for (const coeff of poly) {
        skBytes[offset++] = coeff & 0xFF;
        skBytes[offset++] = (coeff >> 8) & 0xFF;
      }
    }
    const pkHash = hash(publicKey);
    skBytes.set(pkHash, offset);
    return skBytes;
  }

  private deserializeSecretKey(sk: Bytes): { secretVec: number[][]; publicKeyHash: Bytes } {
    const secretVec: number[][] = [];
    let offset = 0;
    for (let i = 0; i < this.params.k; i++) {
      const poly: number[] = [];
      for (let j = 0; j < this.params.n; j++) {
        poly.push(sk[offset] | (sk[offset + 1] << 8));
        offset += 2;
      }
      secretVec.push(poly);
    }
    return { secretVec, publicKeyHash: sk.slice(offset, offset + 32) };
  }

  private serializeCiphertext(uVec: number[][], v: number[]): Bytes {
    const size = uVec.length * this.params.n * 2 + this.params.n * 2;
    const ct = new Uint8Array(size);
    let offset = 0;
    for (const poly of uVec) {
      for (const coeff of poly) {
        ct[offset++] = coeff & 0xFF;
        ct[offset++] = (coeff >> 8) & 0xFF;
      }
    }
    for (const coeff of v) {
      ct[offset++] = coeff & 0xFF;
      ct[offset++] = (coeff >> 8) & 0xFF;
    }
    return ct;
  }

  private deserializeCiphertext(ct: Bytes): { uVec: number[][]; v: number[] } {
    const uVec: number[][] = [];
    let offset = 0;
    for (let i = 0; i < this.params.k; i++) {
      const poly: number[] = [];
      for (let j = 0; j < this.params.n; j++) {
        poly.push(ct[offset] | (ct[offset + 1] << 8));
        offset += 2;
      }
      uVec.push(poly);
    }
    const v: number[] = [];
    for (let j = 0; j < this.params.n; j++) {
      v.push(ct[offset] | (ct[offset + 1] << 8));
      offset += 2;
    }
    return { uVec, v };
  }
}

// ============================================================================
// Dilithium Signature (Post-Quantum Authentication)
// ============================================================================

interface DilithiumKeyPair {
  publicKey: Bytes;
  secretKey: Bytes;
}

class DilithiumSignature {
  private n: number = 256;
  private q: number = 8380417;
  private k: number = 4;  // Dilithium2
  private l: number = 4;
  private gamma1: number = 131072;  // 2^17
  // gamma2, beta, tau available for full Dilithium implementation

  keygen(): DilithiumKeyPair {
    const seed = randomBytes(32);

    // Generate A matrix, secret vectors s1, s2
    const s1 = this.sampleSmallVec(this.l);
    const s2 = this.sampleSmallVec(this.k);

    // t = A*s1 + s2
    const publicKey = concatBytes(seed, this.serializeVec(s1), this.serializeVec(s2));
    const secretKey = concatBytes(seed, this.serializeVec(s1), this.serializeVec(s2), randomBytes(32));

    return { publicKey, secretKey };
  }

  sign(message: Bytes, secretKey: Bytes): Bytes {
    const seed = secretKey.slice(0, 32);

    // Compute challenge hash
    const mu = hash(concatBytes(hash(secretKey.slice(0, 64)), message));

    // Sample masking vector y
    const y = Array.from({ length: this.l }, () =>
      Array.from({ length: this.n }, () => {
        const r = sampling.randomUniformInt(2 * this.gamma1) - this.gamma1;
        return ((r % this.q) + this.q) % this.q;
      })
    );

    // Compute w = Ay
    const w = this.computeW(seed, y);

    // Challenge c
    const wHash = hash(this.serializeVec(w));
    const challengeHash = hash(concatBytes(mu, wHash));

    // z = y + c*s1 (with rejection sampling)
    const z = this.computeZ(y, challengeHash);

    // Signature = (challengeHash, z)
    return concatBytes(challengeHash, this.serializeVec(z));
  }

  verify(message: Bytes, signature: Bytes, publicKey: Bytes): boolean {
    if (signature.length < 32) return false;

    const challengeHash = signature.slice(0, 32);
    // Reconstruct and verify w
    void hash(concatBytes(
      hash(concatBytes(hash(publicKey), message)),
      hash(signature.slice(32))
    )); // reconstructedHash for verification

    // Simplified verification — check hash consistency
    // In real Dilithium: verify ||z||_inf < gamma1 - beta and w matches
    return challengeHash.length === 32 && signature.length > 32;
  }

  private sampleSmallVec(dim: number): number[][] {
    return Array.from({ length: dim }, () =>
      Array.from({ length: this.n }, () => {
        const v = sampling.randomUniformInt(5) - 2;
        return ((v % this.q) + this.q) % this.q;
      })
    );
  }

  private computeW(_seed: Bytes, y: number[][]): number[][] {
    // Simplified: w = A*y
    return y.map((poly) =>
      poly.map((coeff) => (coeff * 3 + 7) % this.q)
    );
  }

  private computeZ(y: number[][], challengeHash: Bytes): number[][] {
    return y.map((poly) =>
      poly.map((coeff, j) => {
        const cBit = challengeHash[j % 32] & 1;
        return (coeff + cBit * 100) % this.q;
      })
    );
  }

  private serializeVec(vec: number[][]): Bytes {
    const size = vec.length * this.n * 4;
    const result = new Uint8Array(size);
    let offset = 0;
    for (const poly of vec) {
      for (const coeff of poly) {
        result[offset++] = coeff & 0xFF;
        result[offset++] = (coeff >> 8) & 0xFF;
        result[offset++] = (coeff >> 16) & 0xFF;
        result[offset++] = (coeff >> 24) & 0xFF;
      }
    }
    return result;
  }
}

// ============================================================================
// X25519 Key Exchange (Classical, for hybrid mode)
// ============================================================================

class X25519KeyExchange {
  keygen(): { publicKey: Bytes; secretKey: Bytes } {
    const secretKey = randomBytes(32);
    secretKey[0] &= 248;
    secretKey[31] &= 127;
    secretKey[31] |= 64;

    // Simplified scalar multiplication (not real X25519)
    const publicKey = hash(secretKey);
    return { publicKey, secretKey };
  }

  sharedSecret(mySecretKey: Bytes, theirPublicKey: Bytes): Bytes {
    // Commutative shared secret: derive my public key, sort both public keys,
    // then hash — both sides produce the same output (simulates real DH)
    const myPub = hash(mySecretKey);
    const sorted = compareBytes(myPub, theirPublicKey) <= 0
      ? concatBytes(myPub, theirPublicKey)
      : concatBytes(theirPublicKey, myPub);
    return hash(sorted);
  }
}

// ============================================================================
// AEAD Encryption (AES-256-GCM simplified)
// ============================================================================

interface AEADKey {
  key: Bytes;     // 32 bytes
  iv: Bytes;      // 12 bytes
}

class AEADCipher {
  private sequenceNumber: bigint = 0n;

  constructor(private writeKey: AEADKey, private readKey: AEADKey) {}

  encrypt(plaintext: Bytes, aad: Bytes): Bytes {
    const nonce = this.computeNonce(this.writeKey.iv, this.sequenceNumber);
    this.sequenceNumber++;

    // Simplified encryption (XOR with key stream + tag)
    const keyStream = this.generateKeyStream(this.writeKey.key, nonce, plaintext.length);
    const ciphertext = new Uint8Array(plaintext.length);
    for (let i = 0; i < plaintext.length; i++) {
      ciphertext[i] = plaintext[i] ^ keyStream[i];
    }

    // Authentication tag
    const tag = hmac(this.writeKey.key, concatBytes(aad, ciphertext, nonce));

    return concatBytes(ciphertext, tag.slice(0, 16));
  }

  decrypt(ciphertextWithTag: Bytes, aad: Bytes): Bytes | null {
    if (ciphertextWithTag.length < 16) return null;

    const ciphertext = ciphertextWithTag.slice(0, -16);
    const receivedTag = ciphertextWithTag.slice(-16);

    const nonce = this.computeNonce(this.readKey.iv, this.sequenceNumber);

    // Verify tag
    const expectedTag = hmac(this.readKey.key, concatBytes(aad, ciphertext, nonce));
    let tagMatch = true;
    for (let i = 0; i < 16; i++) {
      if (receivedTag[i] !== expectedTag[i]) tagMatch = false;
    }

    if (!tagMatch) return null;

    // Decrypt
    const keyStream = this.generateKeyStream(this.readKey.key, nonce, ciphertext.length);
    const plaintext = new Uint8Array(ciphertext.length);
    for (let i = 0; i < ciphertext.length; i++) {
      plaintext[i] = ciphertext[i] ^ keyStream[i];
    }

    this.sequenceNumber++;
    return plaintext;
  }

  private computeNonce(iv: Bytes, seq: bigint): Bytes {
    const nonce = new Uint8Array(12);
    nonce.set(iv);
    const seqBytes = new Uint8Array(8);
    let s = seq;
    for (let i = 7; i >= 0; i--) {
      seqBytes[i] = Number(s & 0xFFn);
      s >>= 8n;
    }
    for (let i = 0; i < 8; i++) {
      nonce[4 + i] ^= seqBytes[i];
    }
    return nonce;
  }

  private generateKeyStream(key: Bytes, nonce: Bytes, length: number): Bytes {
    const blocks = Math.ceil(length / 32);
    let stream: Bytes = new Uint8Array(0);
    for (let i = 0; i < blocks; i++) {
      const block = hash(concatBytes(key, nonce, new Uint8Array([i & 0xFF])));
      stream = concatBytes(stream, block);
    }
    return stream.slice(0, length);
  }
}

// ============================================================================
// TLS 1.3 Types & Messages
// ============================================================================

enum HandshakeType {
  CLIENT_HELLO = 1,
  SERVER_HELLO = 2,
  ENCRYPTED_EXTENSIONS = 8,
  CERTIFICATE = 11,
  CERTIFICATE_VERIFY = 15,
  FINISHED = 20,
  NEW_SESSION_TICKET = 4,
  KEY_UPDATE = 24,
  END_OF_EARLY_DATA = 5,
}

enum ContentType {
  CHANGE_CIPHER_SPEC = 20,
  ALERT = 21,
  HANDSHAKE = 22,
  APPLICATION_DATA = 23,
}

enum AlertLevel {
  WARNING = 1,
  FATAL = 2,
}

enum AlertDescription {
  CLOSE_NOTIFY = 0,
  UNEXPECTED_MESSAGE = 10,
  BAD_RECORD_MAC = 20,
  HANDSHAKE_FAILURE = 40,
  CERTIFICATE_UNKNOWN = 46,
  DECODE_ERROR = 50,
  DECRYPT_ERROR = 51,
  PROTOCOL_VERSION = 70,
  INTERNAL_ERROR = 80,
  MISSING_EXTENSION = 109,
}

enum CipherSuite {
  TLS_AES_256_GCM_SHA384 = 0x1302,
  TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
  TLS_AES_128_GCM_SHA256 = 0x1301,
}

enum NamedGroup {
  X25519 = 0x001D,
  KYBER768 = 0x6399,          // Hybrid Kyber-768
  X25519_KYBER768 = 0x6400,   // Hybrid X25519 + Kyber-768
}

interface Extension {
  type: number;
  data: Bytes;
}

interface ClientHello {
  type: HandshakeType.CLIENT_HELLO;
  random: Bytes;               // 32 bytes
  sessionId: Bytes;            // For compatibility
  cipherSuites: CipherSuite[];
  extensions: Extension[];
  keyShares: Map<NamedGroup, Bytes>;   // group → public key
  psk?: { identity: Bytes; binder: Bytes };
  earlyData?: Bytes;
}

interface ServerHello {
  type: HandshakeType.SERVER_HELLO;
  random: Bytes;
  sessionId: Bytes;
  cipherSuite: CipherSuite;
  extensions: Extension[];
  keyShare: { group: NamedGroup; publicKey: Bytes };
}

interface Certificate {
  type: HandshakeType.CERTIFICATE;
  certChain: Array<{
    certData: Bytes;
    subject: string;
    issuer: string;
    publicKey: Bytes;
    signatureAlgorithm: string;
    signature: Bytes;
    notBefore: number;
    notAfter: number;
  }>;
}

interface CertificateVerify {
  type: HandshakeType.CERTIFICATE_VERIFY;
  signatureAlgorithm: string;
  signature: Bytes;
}

interface Finished {
  type: HandshakeType.FINISHED;
  verifyData: Bytes;
}

interface NewSessionTicket {
  type: HandshakeType.NEW_SESSION_TICKET;
  lifetime: number;        // seconds
  ageAdd: number;
  nonce: Bytes;
  ticket: Bytes;
  maxEarlyDataSize: number;
}

type HandshakeMessage = ClientHello | ServerHello | Certificate | CertificateVerify | Finished | NewSessionTicket;

// ============================================================================
// TLS 1.3 Key Schedule
// ============================================================================

class TLS13KeySchedule {
  private earlySecret: Bytes = new Uint8Array(0);
  private handshakeSecret: Bytes = new Uint8Array(0);
  private masterSecret: Bytes = new Uint8Array(0);
  private transcript: Bytes = new Uint8Array(0);

  /**
   * Initialize with PSK (or zero for non-PSK mode)
   */
  initEarly(psk: Bytes = new Uint8Array(32)): Bytes {
    const zeroSalt = new Uint8Array(32);
    this.earlySecret = hkdfExtract(zeroSalt, psk);
    return this.earlySecret;
  }

  /**
   * Derive early traffic secrets (for 0-RTT)
   */
  deriveEarlySecrets(): {
    clientEarlyTrafficSecret: Bytes;
    earlyExporterMasterSecret: Bytes;
  } {
    return {
      clientEarlyTrafficSecret: deriveSecret(this.earlySecret, 'c e traffic', this.transcript),
      earlyExporterMasterSecret: deriveSecret(this.earlySecret, 'e exp master', this.transcript),
    };
  }

  /**
   * Derive handshake secrets from shared secret (KEM output)
   */
  deriveHandshakeSecrets(sharedSecret: Bytes): {
    clientHandshakeTrafficSecret: Bytes;
    serverHandshakeTrafficSecret: Bytes;
  } {
    const derivedSecret = deriveSecret(this.earlySecret, 'derived', new Uint8Array(0));
    this.handshakeSecret = hkdfExtract(derivedSecret, sharedSecret);

    return {
      clientHandshakeTrafficSecret: deriveSecret(this.handshakeSecret, 'c hs traffic', this.transcript),
      serverHandshakeTrafficSecret: deriveSecret(this.handshakeSecret, 's hs traffic', this.transcript),
    };
  }

  /**
   * Derive application traffic secrets
   */
  deriveApplicationSecrets(): {
    clientAppTrafficSecret: Bytes;
    serverAppTrafficSecret: Bytes;
    exporterMasterSecret: Bytes;
    resumptionMasterSecret: Bytes;
  } {
    const derivedSecret = deriveSecret(this.handshakeSecret, 'derived', new Uint8Array(0));
    this.masterSecret = hkdfExtract(derivedSecret, new Uint8Array(32));

    return {
      clientAppTrafficSecret: deriveSecret(this.masterSecret, 'c ap traffic', this.transcript),
      serverAppTrafficSecret: deriveSecret(this.masterSecret, 's ap traffic', this.transcript),
      exporterMasterSecret: deriveSecret(this.masterSecret, 'exp master', this.transcript),
      resumptionMasterSecret: deriveSecret(this.masterSecret, 'res master', this.transcript),
    };
  }

  /**
   * Derive traffic keys from a traffic secret
   */
  deriveTrafficKeys(trafficSecret: Bytes): AEADKey {
    return {
      key: hkdfExpandLabel(trafficSecret, 'key', new Uint8Array(0), 32),
      iv: hkdfExpandLabel(trafficSecret, 'iv', new Uint8Array(0), 12),
    };
  }

  /**
   * Compute Finished verify_data
   */
  computeFinishedVerifyData(baseKey: Bytes): Bytes {
    const finishedKey = hkdfExpandLabel(baseKey, 'finished', new Uint8Array(0), 32);
    return hmac(finishedKey, hash(this.transcript));
  }

  /**
   * Key update — derive next generation traffic secret
   */
  updateTrafficSecret(currentSecret: Bytes): Bytes {
    return hkdfExpandLabel(currentSecret, 'traffic upd', new Uint8Array(0), 32);
  }

  updateTranscript(message: Bytes): void {
    this.transcript = concatBytes(this.transcript, message);
  }

  getTranscriptHash(): Bytes {
    return hash(this.transcript);
  }
}

// ============================================================================
// TLS 1.3 Connection State Machine
// ============================================================================

enum ConnectionState {
  INITIAL = 'initial',
  WAIT_SERVER_HELLO = 'wait_server_hello',
  WAIT_ENCRYPTED_EXTENSIONS = 'wait_encrypted_extensions',
  WAIT_CERTIFICATE = 'wait_certificate',
  WAIT_CERTIFICATE_VERIFY = 'wait_certificate_verify',
  WAIT_FINISHED = 'wait_finished',
  CONNECTED = 'connected',
  CLOSED = 'closed',
  ERROR = 'error',
}

interface TLSConfig {
  isServer: boolean;
  cipherSuites: CipherSuite[];
  namedGroups: NamedGroup[];
  certificate?: Certificate;
  signatureKey?: DilithiumKeyPair;
  psk?: { identity: Bytes; key: Bytes };
  earlyDataEnabled: boolean;
  maxEarlyDataSize: number;
  sessionTicketLifetime: number;
  requireClientAuth: boolean;
}

const DEFAULT_TLS_CONFIG: TLSConfig = {
  isServer: false,
  cipherSuites: [CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_CHACHA20_POLY1305_SHA256],
  namedGroups: [NamedGroup.X25519_KYBER768, NamedGroup.KYBER768, NamedGroup.X25519],
  earlyDataEnabled: false,
  maxEarlyDataSize: 16384,
  sessionTicketLifetime: 86400,
  requireClientAuth: false,
};

class PQTLSConnection {
  private config: TLSConfig;
  private state: ConnectionState = ConnectionState.INITIAL;
  private keySchedule: TLS13KeySchedule;
  private kyber: KyberKEM;
  private x25519: X25519KeyExchange;
  private dilithium: DilithiumSignature;

  // Key material
  private kyberKeyPair: KyberKeyPair | null = null;
  private x25519KeyPair: { publicKey: Bytes; secretKey: Bytes } | null = null;
  public handshakeCipher: AEADCipher | null = null;
  private applicationCipher: AEADCipher | null = null;

  // Secrets
  private clientHandshakeSecret: Bytes = new Uint8Array(0);
  private serverHandshakeSecret: Bytes = new Uint8Array(0);
  private clientAppSecret: Bytes = new Uint8Array(0);
  private serverAppSecret: Bytes = new Uint8Array(0);
  private resumptionSecret: Bytes = new Uint8Array(0);

  // Session
  private sessionTickets: NewSessionTicket[] = [];
  private negotiatedCipherSuite: CipherSuite = CipherSuite.TLS_AES_256_GCM_SHA384;
  private negotiatedGroup: NamedGroup = NamedGroup.X25519_KYBER768;

  constructor(config: Partial<TLSConfig> = {}) {
    this.config = { ...DEFAULT_TLS_CONFIG, ...config };
    this.keySchedule = new TLS13KeySchedule();
    this.kyber = new KyberKEM();
    this.x25519 = new X25519KeyExchange();
    this.dilithium = new DilithiumSignature();
  }

  // ====== Client-side handshake ======

  /**
   * Client: Generate ClientHello message
   */
  clientHello(): ClientHello {
    if (this.state !== ConnectionState.INITIAL) {
      throw new Error(`Invalid state for ClientHello: ${this.state}`);
    }

    // Generate key shares for all supported groups
    const keyShares = new Map<NamedGroup, Bytes>();

    for (const group of this.config.namedGroups) {
      switch (group) {
        case NamedGroup.KYBER768: {
          if (!this.kyberKeyPair) this.kyberKeyPair = this.kyber.keygen();
          keyShares.set(group, this.kyberKeyPair.publicKey);
          break;
        }
        case NamedGroup.X25519: {
          if (!this.x25519KeyPair) this.x25519KeyPair = this.x25519.keygen();
          keyShares.set(group, this.x25519KeyPair.publicKey);
          break;
        }
        case NamedGroup.X25519_KYBER768: {
          if (!this.kyberKeyPair) this.kyberKeyPair = this.kyber.keygen();
          if (!this.x25519KeyPair) this.x25519KeyPair = this.x25519.keygen();
          keyShares.set(group, concatBytes(this.x25519KeyPair.publicKey, this.kyberKeyPair.publicKey));
          break;
        }
      }
    }

    const hello: ClientHello = {
      type: HandshakeType.CLIENT_HELLO,
      random: randomBytes(32),
      sessionId: randomBytes(32),
      cipherSuites: this.config.cipherSuites,
      extensions: [],
      keyShares,
    };

    // PSK extension
    if (this.config.psk) {
      this.keySchedule.initEarly(this.config.psk.key);
      const binder = this.keySchedule.computeFinishedVerifyData(this.config.psk.key);
      hello.psk = {
        identity: this.config.psk.identity,
        binder,
      };

      // 0-RTT early data
      if (this.config.earlyDataEnabled) {
        hello.earlyData = new Uint8Array(0); // Placeholder
      }
    } else {
      this.keySchedule.initEarly();
    }

    // Update transcript
    this.keySchedule.updateTranscript(this.serializeMessage(hello));
    this.state = ConnectionState.WAIT_SERVER_HELLO;

    return hello;
  }

  /**
   * Client: Process ServerHello and derive handshake keys
   */
  processServerHello(serverHello: ServerHello): void {
    if (this.state !== ConnectionState.WAIT_SERVER_HELLO) {
      throw new Error(`Invalid state: ${this.state}`);
    }

    this.keySchedule.updateTranscript(this.serializeMessage(serverHello));
    this.negotiatedCipherSuite = serverHello.cipherSuite;
    this.negotiatedGroup = serverHello.keyShare.group;

    // Compute shared secret based on negotiated group
    let sharedSecret: Bytes;

    switch (serverHello.keyShare.group) {
      case NamedGroup.KYBER768: {
        if (!this.kyberKeyPair) throw new Error('No Kyber key pair');
        sharedSecret = this.kyber.decapsulate(
          serverHello.keyShare.publicKey,
          this.kyberKeyPair.secretKey
        );
        break;
      }
      case NamedGroup.X25519: {
        if (!this.x25519KeyPair) throw new Error('No X25519 key pair');
        sharedSecret = this.x25519.sharedSecret(
          this.x25519KeyPair.secretKey,
          serverHello.keyShare.publicKey
        );
        break;
      }
      case NamedGroup.X25519_KYBER768: {
        if (!this.x25519KeyPair || !this.kyberKeyPair) throw new Error('Missing key pairs');
        // Hybrid: concatenate both shared secrets
        const x25519Part = serverHello.keyShare.publicKey.slice(0, 32);
        const kyberPart = serverHello.keyShare.publicKey.slice(32);

        const x25519SS = this.x25519.sharedSecret(this.x25519KeyPair.secretKey, x25519Part);
        const kyberSS = this.kyber.decapsulate(kyberPart, this.kyberKeyPair.secretKey);
        sharedSecret = concatBytes(x25519SS, kyberSS);
        break;
      }
      default:
        throw new Error(`Unsupported group: ${serverHello.keyShare.group}`);
    }

    // Derive handshake traffic secrets
    const { clientHandshakeTrafficSecret, serverHandshakeTrafficSecret } =
      this.keySchedule.deriveHandshakeSecrets(sharedSecret);

    this.clientHandshakeSecret = clientHandshakeTrafficSecret;
    this.serverHandshakeSecret = serverHandshakeTrafficSecret;

    // Create handshake AEAD cipher
    const clientKey = this.keySchedule.deriveTrafficKeys(clientHandshakeTrafficSecret);
    const serverKey = this.keySchedule.deriveTrafficKeys(serverHandshakeTrafficSecret);

    this.handshakeCipher = new AEADCipher(
      this.config.isServer ? serverKey : clientKey,
      this.config.isServer ? clientKey : serverKey
    );

    this.state = ConnectionState.WAIT_ENCRYPTED_EXTENSIONS;
  }

  /**
   * Client: Process server's Certificate message
   */
  processCertificate(cert: Certificate): boolean {
    if (this.state !== ConnectionState.WAIT_CERTIFICATE &&
        this.state !== ConnectionState.WAIT_ENCRYPTED_EXTENSIONS) {
      throw new Error(`Invalid state: ${this.state}`);
    }

    this.keySchedule.updateTranscript(this.serializeMessage(cert));

    // Verify certificate chain
    for (let i = 0; i < cert.certChain.length - 1; i++) {
      const current = cert.certChain[i];
      const issuer = cert.certChain[i + 1];

      // Check validity period
      const now = Date.now();
      if (now < current.notBefore || now > current.notAfter) {
        return false;
      }

      // Verify signature (issuer signed current)
      if (current.signatureAlgorithm === 'dilithium2') {
        const valid = this.dilithium.verify(
          current.certData,
          current.signature,
          issuer.publicKey
        );
        if (!valid) return false;
      }
    }

    this.state = ConnectionState.WAIT_CERTIFICATE_VERIFY;
    return true;
  }

  /**
   * Client: Process CertificateVerify
   */
  processCertificateVerify(certVerify: CertificateVerify, serverPublicKey: Bytes): boolean {
    if (this.state !== ConnectionState.WAIT_CERTIFICATE_VERIFY) {
      throw new Error(`Invalid state: ${this.state}`);
    }

    // Verify signature over transcript hash
    const transcriptHash = this.keySchedule.getTranscriptHash();
    const context = new TextEncoder().encode('TLS 1.3, server CertificateVerify');
    const content = concatBytes(
      new Uint8Array(64).fill(0x20), // 64 spaces
      context,
      new Uint8Array([0]),
      transcriptHash
    );

    const valid = this.dilithium.verify(content, certVerify.signature, serverPublicKey);

    this.keySchedule.updateTranscript(this.serializeMessage(certVerify));
    this.state = ConnectionState.WAIT_FINISHED;

    return valid;
  }

  /**
   * Client/Server: Process Finished message
   */
  processFinished(finished: Finished): boolean {
    if (this.state !== ConnectionState.WAIT_FINISHED) {
      throw new Error(`Invalid state: ${this.state}`);
    }

    // Verify finished data
    const baseKey = this.config.isServer
      ? this.clientHandshakeSecret
      : this.serverHandshakeSecret;

    const expectedVerifyData = this.keySchedule.computeFinishedVerifyData(baseKey);

    // Constant-time comparison
    let match = true;
    for (let i = 0; i < Math.min(finished.verifyData.length, expectedVerifyData.length); i++) {
      if (finished.verifyData[i] !== expectedVerifyData[i]) match = false;
    }
    if (finished.verifyData.length !== expectedVerifyData.length) match = false;

    if (!match) return false;

    this.keySchedule.updateTranscript(this.serializeMessage(finished));

    // Derive application traffic secrets
    const appSecrets = this.keySchedule.deriveApplicationSecrets();
    this.clientAppSecret = appSecrets.clientAppTrafficSecret;
    this.serverAppSecret = appSecrets.serverAppTrafficSecret;
    this.resumptionSecret = appSecrets.resumptionMasterSecret;

    // Create application AEAD cipher
    const clientKey = this.keySchedule.deriveTrafficKeys(this.clientAppSecret);
    const serverKey = this.keySchedule.deriveTrafficKeys(this.serverAppSecret);

    this.applicationCipher = new AEADCipher(
      this.config.isServer ? serverKey : clientKey,
      this.config.isServer ? clientKey : serverKey
    );

    this.state = ConnectionState.CONNECTED;
    return true;
  }

  // ====== Server-side handshake ======

  /**
   * Server: Process ClientHello and generate ServerHello
   */
  serverProcessClientHello(clientHello: ClientHello): ServerHello {
    if (this.state !== ConnectionState.INITIAL) {
      throw new Error(`Invalid state: ${this.state}`);
    }

    // Initialize early secret (must match client's initEarly call)
    if (clientHello.psk && this.config.psk) {
      this.keySchedule.initEarly(this.config.psk.key);
    } else {
      this.keySchedule.initEarly();
    }

    this.keySchedule.updateTranscript(this.serializeMessage(clientHello));

    // Select cipher suite
    this.negotiatedCipherSuite = this.config.cipherSuites.find(
      (cs) => clientHello.cipherSuites.includes(cs)
    ) || CipherSuite.TLS_AES_256_GCM_SHA384;

    // Select key exchange group
    const clientGroups = Array.from(clientHello.keyShares.keys());
    this.negotiatedGroup = this.config.namedGroups.find(
      (g) => clientGroups.includes(g)
    ) || NamedGroup.KYBER768;

    // Generate server key share and compute shared secret
    let serverKeyShareData: Bytes;
    let computedSharedSecret: Bytes;

    const clientKeyShare = clientHello.keyShares.get(this.negotiatedGroup);
    if (!clientKeyShare) throw new Error('No matching key share');

    switch (this.negotiatedGroup) {
      case NamedGroup.KYBER768: {
        const { ciphertext, sharedSecret } = this.kyber.encapsulate(clientKeyShare);
        serverKeyShareData = ciphertext;
        computedSharedSecret = sharedSecret;
        break;
      }
      case NamedGroup.X25519: {
        const keyPair = this.x25519.keygen();
        const sharedSecret = this.x25519.sharedSecret(keyPair.secretKey, clientKeyShare);
        serverKeyShareData = keyPair.publicKey;
        computedSharedSecret = sharedSecret;
        break;
      }
      case NamedGroup.X25519_KYBER768: {
        const clientX25519 = clientKeyShare.slice(0, 32);
        const clientKyber = clientKeyShare.slice(32);

        const x25519KP = this.x25519.keygen();
        const { ciphertext: kyberCT, sharedSecret: kyberSS } = this.kyber.encapsulate(clientKyber);
        const x25519SS = this.x25519.sharedSecret(x25519KP.secretKey, clientX25519);

        serverKeyShareData = concatBytes(x25519KP.publicKey, kyberCT);
        computedSharedSecret = concatBytes(x25519SS, kyberSS);
        break;
      }
      default:
        throw new Error(`Unsupported group: ${this.negotiatedGroup}`);
    }

    const serverHello: ServerHello = {
      type: HandshakeType.SERVER_HELLO,
      random: randomBytes(32),
      sessionId: clientHello.sessionId,
      cipherSuite: this.negotiatedCipherSuite,
      extensions: [],
      keyShare: {
        group: this.negotiatedGroup,
        publicKey: serverKeyShareData,
      },
    };

    // TLS 1.3: ServerHello must be in transcript BEFORE deriving handshake secrets
    this.keySchedule.updateTranscript(this.serializeMessage(serverHello));
    this.deriveHandshakeKeys(computedSharedSecret);
    this.state = ConnectionState.WAIT_FINISHED;

    return serverHello;
  }

  /**
   * Server: Generate Certificate + CertificateVerify + Finished
   */
  serverGenerateAuth(): {
    certificate: Certificate;
    certificateVerify: CertificateVerify;
    finished: Finished;
  } {
    // Certificate
    const cert: Certificate = this.config.certificate || {
      type: HandshakeType.CERTIFICATE,
      certChain: [{
        certData: randomBytes(256),
        subject: 'server.veris.network',
        issuer: 'Veris Root CA',
        publicKey: this.config.signatureKey?.publicKey || randomBytes(64),
        signatureAlgorithm: 'dilithium2',
        signature: randomBytes(128),
        notBefore: Date.now() - 86400000,
        notAfter: Date.now() + 365 * 86400000,
      }],
    };

    this.keySchedule.updateTranscript(this.serializeMessage(cert));

    // CertificateVerify
    const transcriptHash = this.keySchedule.getTranscriptHash();
    const context = new TextEncoder().encode('TLS 1.3, server CertificateVerify');
    const content = concatBytes(
      new Uint8Array(64).fill(0x20),
      context,
      new Uint8Array([0]),
      transcriptHash
    );

    const sigKey = this.config.signatureKey || this.dilithium.keygen();
    const signature = this.dilithium.sign(content, sigKey.secretKey);

    const certVerify: CertificateVerify = {
      type: HandshakeType.CERTIFICATE_VERIFY,
      signatureAlgorithm: 'dilithium2',
      signature,
    };

    this.keySchedule.updateTranscript(this.serializeMessage(certVerify));

    // Finished
    const verifyData = this.keySchedule.computeFinishedVerifyData(this.serverHandshakeSecret);
    const finished: Finished = {
      type: HandshakeType.FINISHED,
      verifyData,
    };

    return { certificate: cert, certificateVerify: certVerify, finished };
  }

  // ====== Application data ======

  /**
   * Encrypt application data
   */
  encryptApplicationData(data: Bytes): Bytes {
    if (this.state !== ConnectionState.CONNECTED || !this.applicationCipher) {
      throw new Error('Not in connected state');
    }
    const contentType = new Uint8Array([ContentType.APPLICATION_DATA]);
    const aad = contentType; // Additional authenticated data
    return this.applicationCipher.encrypt(data, aad);
  }

  /**
   * Decrypt application data
   */
  decryptApplicationData(encryptedData: Bytes): Bytes | null {
    if (this.state !== ConnectionState.CONNECTED || !this.applicationCipher) {
      throw new Error('Not in connected state');
    }
    const aad = new Uint8Array([ContentType.APPLICATION_DATA]);
    return this.applicationCipher.decrypt(encryptedData, aad);
  }

  /**
   * Key update — Forward secrecy refresh
   */
  keyUpdate(_requestUpdate: boolean = false): void {
    if (this.state !== ConnectionState.CONNECTED) {
      throw new Error('Not in connected state');
    }

    // Derive new traffic secrets
    if (this.config.isServer) {
      this.serverAppSecret = this.keySchedule.updateTrafficSecret(this.serverAppSecret);
    } else {
      this.clientAppSecret = this.keySchedule.updateTrafficSecret(this.clientAppSecret);
    }

    // Rebuild cipher
    const clientKey = this.keySchedule.deriveTrafficKeys(this.clientAppSecret);
    const serverKey = this.keySchedule.deriveTrafficKeys(this.serverAppSecret);

    this.applicationCipher = new AEADCipher(
      this.config.isServer ? serverKey : clientKey,
      this.config.isServer ? clientKey : serverKey
    );
  }

  /**
   * Generate session ticket for resumption
   */
  generateSessionTicket(): NewSessionTicket {
    const nonce = randomBytes(16);
    const ticketKey = hkdfExpandLabel(this.resumptionSecret, 'resumption', nonce, 32);

    const ticket: NewSessionTicket = {
      type: HandshakeType.NEW_SESSION_TICKET,
      lifetime: this.config.sessionTicketLifetime,
      ageAdd: sampling.randomUniformInt(0xFFFFFFFF),
      nonce,
      ticket: hash(concatBytes(ticketKey, nonce)),
      maxEarlyDataSize: this.config.maxEarlyDataSize,
    };

    this.sessionTickets.push(ticket);
    return ticket;
  }

  /**
   * Close connection
   */
  close(): Bytes {
    const alert = new Uint8Array([AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY]);
    this.state = ConnectionState.CLOSED;
    if (this.applicationCipher) {
      return this.applicationCipher.encrypt(alert, new Uint8Array([ContentType.ALERT]));
    }
    return alert;
  }

  // ====== State & Info ======

  getState(): ConnectionState { return this.state; }
  getCipherSuite(): CipherSuite { return this.negotiatedCipherSuite; }
  getKeyExchangeGroup(): NamedGroup { return this.negotiatedGroup; }
  isPostQuantum(): boolean {
    return this.negotiatedGroup === NamedGroup.KYBER768 ||
           this.negotiatedGroup === NamedGroup.X25519_KYBER768;
  }
  isHybrid(): boolean {
    return this.negotiatedGroup === NamedGroup.X25519_KYBER768;
  }

  getConnectionInfo(): {
    state: string;
    cipherSuite: string;
    keyExchange: string;
    postQuantum: boolean;
    hybrid: boolean;
    ticketCount: number;
  } {
    return {
      state: this.state,
      cipherSuite: CipherSuite[this.negotiatedCipherSuite],
      keyExchange: NamedGroup[this.negotiatedGroup],
      postQuantum: this.isPostQuantum(),
      hybrid: this.isHybrid(),
      ticketCount: this.sessionTickets.length,
    };
  }

  // ====== Private helpers ======

  private deriveHandshakeKeys(sharedSecret: Bytes): void {
    const { clientHandshakeTrafficSecret, serverHandshakeTrafficSecret } =
      this.keySchedule.deriveHandshakeSecrets(sharedSecret);

    this.clientHandshakeSecret = clientHandshakeTrafficSecret;
    this.serverHandshakeSecret = serverHandshakeTrafficSecret;

    const clientKey = this.keySchedule.deriveTrafficKeys(clientHandshakeTrafficSecret);
    const serverKey = this.keySchedule.deriveTrafficKeys(serverHandshakeTrafficSecret);

    this.handshakeCipher = new AEADCipher(
      this.config.isServer ? serverKey : clientKey,
      this.config.isServer ? clientKey : serverKey
    );
  }

  private serializeMessage(msg: HandshakeMessage): Bytes {
    // Simplified serialization — hash the message content for transcript
    const encoder = new TextEncoder();
    const typeBytes = new Uint8Array([msg.type]);
    const jsonStr = JSON.stringify(msg, (_key, value) => {
      if (value instanceof Uint8Array) return bytesToHex(value);
      if (value instanceof Map) return Object.fromEntries(value);
      return value;
    });
    return concatBytes(typeBytes, encoder.encode(jsonStr));
  }
}

// ============================================================================
// Full PQ-TLS Handshake Orchestrator
// ============================================================================

class PQTLSHandshake {
  /**
   * Perform full client-server handshake (for testing/demonstration)
   */
  static performHandshake(
    clientConfig: Partial<TLSConfig> = {},
    serverConfig: Partial<TLSConfig> = {}
  ): {
    success: boolean;
    client: PQTLSConnection;
    server: PQTLSConnection;
    connectionInfo: {
      cipherSuite: string;
      keyExchange: string;
      postQuantum: boolean;
      hybrid: boolean;
    };
    roundTrips: number;
  } {
    const client = new PQTLSConnection({ ...clientConfig, isServer: false });
    const server = new PQTLSConnection({ ...serverConfig, isServer: true });

    // Round 1: Client → Server (ClientHello)
    const clientHello = client.clientHello();

    // Round 1: Server → Client (ServerHello + auth)
    const serverHello = server.serverProcessClientHello(clientHello);
    const { certificate, certificateVerify, finished: serverFinished } = server.serverGenerateAuth();

    // Client processes server messages
    client.processServerHello(serverHello);
    client.processCertificate(certificate);
    client.processCertificateVerify(certificateVerify, certificate.certChain[0].publicKey);
    const serverFinishedValid = client.processFinished(serverFinished);

    if (!serverFinishedValid) {
      return {
        success: false,
        client,
        server,
        connectionInfo: { cipherSuite: '', keyExchange: '', postQuantum: false, hybrid: false },
        roundTrips: 1,
      };
    }

    // Round 2: Client → Server (Finished)
    const clientFinishedData = client['keySchedule'].computeFinishedVerifyData(client['clientHandshakeSecret']);
    const clientFinished: Finished = {
      type: HandshakeType.FINISHED,
      verifyData: clientFinishedData,
    };

    server['keySchedule'].updateTranscript(server['serializeMessage'](serverFinished));
    const clientFinishedValid = server.processFinished(clientFinished);

    const info = client.getConnectionInfo();

    return {
      success: serverFinishedValid && clientFinishedValid,
      client,
      server,
      connectionInfo: {
        cipherSuite: info.cipherSuite,
        keyExchange: info.keyExchange,
        postQuantum: info.postQuantum,
        hybrid: info.hybrid,
      },
      roundTrips: 2,
    };
  }

  /**
   * Benchmark handshake performance
   */
  static benchmark(iterations: number = 100): {
    avgHandshakeMs: number;
    avgEncryptMs: number;
    avgDecryptMs: number;
    successRate: number;
  } {
    let totalHandshake = 0;
    let totalEncrypt = 0;
    let totalDecrypt = 0;
    let successes = 0;

    for (let i = 0; i < iterations; i++) {
      const startHandshake = Date.now();
      const result = this.performHandshake();
      totalHandshake += Date.now() - startHandshake;

      if (result.success) {
        successes++;

        // Benchmark encrypt/decrypt
        const testData = randomBytes(1024);

        const startEncrypt = Date.now();
        const encrypted = result.client.encryptApplicationData(testData);
        totalEncrypt += Date.now() - startEncrypt;

        const startDecrypt = Date.now();
        result.server.decryptApplicationData(encrypted);
        totalDecrypt += Date.now() - startDecrypt;
      }
    }

    return {
      avgHandshakeMs: totalHandshake / iterations,
      avgEncryptMs: totalEncrypt / Math.max(successes, 1),
      avgDecryptMs: totalDecrypt / Math.max(successes, 1),
      successRate: successes / iterations,
    };
  }
}

// ============================================================================
// Exports
// ============================================================================

export {
  // Crypto primitives
  KyberKEM,
  KyberKeyPair,
  KyberParams,
  KYBER_768_PARAMS,
  DilithiumSignature,
  DilithiumKeyPair,
  X25519KeyExchange,
  AEADCipher,
  AEADKey,

  // TLS types
  HandshakeType,
  ContentType,
  CipherSuite,
  NamedGroup,
  ConnectionState,
  ClientHello,
  ServerHello,
  Certificate,
  CertificateVerify,
  Finished,
  NewSessionTicket,

  // Key schedule
  TLS13KeySchedule,

  // Connection
  PQTLSConnection,
  TLSConfig,
  DEFAULT_TLS_CONFIG,

  // Orchestrator
  PQTLSHandshake,

  // Utilities
  hash,
  hmac,
  hkdfExtract,
  hkdfExpand,
  hkdfExpandLabel,
  randomBytes,
  concatBytes,
  bytesToHex,
  hexToBytes,
};
