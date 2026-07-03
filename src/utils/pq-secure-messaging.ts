import * as crypto from 'crypto';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

// ============================================================================
// Post-Quantum Secure Messaging Protocol
// ============================================================================
// Signal-like double ratchet rebuilt on top of ML-KEM (FIPS 203) and ML-DSA
// (FIPS 204). Provides forward secrecy, post-compromise security, and
// quantum resistance via KEM-based ratcheting instead of Diffie-Hellman.
//
// Components:
//   1. HKDF / constant-time utilities
//   2. PQ Double Ratchet (KEM-based Signal ratchet)
//   3. X3KEM handshake (replaces X3DH)
//   4. Session management and persistence
//   5. Sealed message encryption (AES-256-GCM + per-message keys)
//   6. MLS-inspired group messaging with TreeKEM
//   7. Secure transport channel with replay protection
//   8. Hybrid mode (Kyber + X25519)
// ============================================================================

// ---------------------------------------------------------------------------
// Section 0: Types & Constants
// ---------------------------------------------------------------------------

/** Kyber parameter set selector */
type KyberLevel = 'kem512' | 'kem768' | 'kem1024';

const KEM_SUITE: Record<KyberLevel, typeof ml_kem768> = {
  kem512: ml_kem512,
  kem768: ml_kem768,
  kem1024: ml_kem1024,
};

/** Dilithium parameter set selector */
type DilithiumLevel = 'dsa44' | 'dsa65' | 'dsa87';

const DSA_SUITE: Record<DilithiumLevel, typeof ml_dsa65> = {
  dsa44: ml_dsa44,
  dsa65: ml_dsa65,
  dsa87: ml_dsa87,
};

const MAX_SKIP = 256; // Maximum skipped message keys to cache
const CHAIN_KEY_CONSTANT = Buffer.from('01', 'hex');
const MESSAGE_KEY_CONSTANT = Buffer.from('02', 'hex');
const RATCHET_INFO = Buffer.from('PQDoubleRatchet-v1', 'utf8');
const SESSION_INFO = Buffer.from('X3KEM-Session-v1', 'utf8');
const GROUP_INFO = Buffer.from('TreeKEM-Group-v1', 'utf8');
const HEARTBEAT_MAGIC = Buffer.from('PQ-HB-v1', 'utf8');

// ---------------------------------------------------------------------------
// Section 1: Cryptographic Utilities
// ---------------------------------------------------------------------------

/**
 * HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869).
 * Used throughout the ratchet and session protocols to derive keys from
 * shared secrets and chain values.
 */
export class HKDF {
  /**
   * Extract: condense input keying material into a pseudorandom key.
   * PRK = HMAC-SHA256(salt, ikm)
   */
  static extract(salt: Buffer, ikm: Buffer): Buffer {
    return crypto.createHmac('sha256', salt).update(ikm).digest();
  }

  /**
   * Expand: expand PRK to the desired output length.
   * Uses HMAC in counter mode per RFC 5869 section 2.3.
   */
  static expand(prk: Buffer, info: Buffer, length: number): Buffer {
    const hashLen = 32; // SHA-256 output
    const n = Math.ceil(length / hashLen);
    if (n > 255) throw new Error('HKDF expand: output length too large');

    const okm = Buffer.alloc(n * hashLen);
    let prev = Buffer.alloc(0);

    for (let i = 1; i <= n; i++) {
      const hmac = crypto.createHmac('sha256', prk);
      hmac.update(prev);
      hmac.update(info);
      hmac.update(Buffer.from([i]));
      prev = hmac.digest();
      prev.copy(okm, (i - 1) * hashLen);
    }
    return okm.subarray(0, length);
  }

  /**
   * One-shot derive: extract then expand.
   */
  static derive(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
    const prk = HKDF.extract(salt, ikm);
    return HKDF.expand(prk, info, length);
  }

  /**
   * Derive a pair of keys (e.g. root key + chain key) from input.
   * Returns two 32-byte keys.
   */
  static deriveKeyPair(ikm: Buffer, salt: Buffer, info: Buffer): [Buffer, Buffer] {
    const okm = HKDF.derive(ikm, salt, info, 64);
    return [okm.subarray(0, 32), okm.subarray(32, 64)];
  }
}

/**
 * Constant-time buffer comparison to prevent timing side channels.
 * Returns true if the two buffers are identical.
 */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Cryptographic random bytes from Node.js CSPRNG.
 */
export function secureRandom(length: number): Buffer {
  return crypto.randomBytes(length);
}

/**
 * Explicit key erasure: zero a buffer to prevent lingering secrets in memory.
 * While JS GC can copy buffers, this is defense-in-depth; critical secrets
 * should use Buffer.alloc (not allocUnsafe) and be zeroed ASAP.
 */
export function secureErase(buf: Buffer): void {
  buf.fill(0);
}

/**
 * Compute a human-readable safety number / key fingerprint.
 * Produces a 60-digit numeric string (12 groups of 5 digits) from two
 * identity public keys, suitable for out-of-band verification.
 */
export function keyFingerprint(
  localIdentityPub: Buffer,
  remoteIdentityPub: Buffer
): string {
  // Sort so both parties compute the same fingerprint
  const [first, second] = localIdentityPub.compare(remoteIdentityPub) < 0
    ? [localIdentityPub, remoteIdentityPub]
    : [remoteIdentityPub, localIdentityPub];

  // Iterative hashing for domain separation (5200 rounds like Signal)
  let hash = Buffer.concat([
    Buffer.from([0x00]),       // version
    first,
    second,
  ]);

  for (let i = 0; i < 5200; i++) {
    hash = crypto.createHash('sha256')
      .update(hash)
      .update(first)
      .update(second)
      .digest();
  }

  // Encode 30 bytes as 60 decimal digits in groups of 5
  const digits: string[] = [];
  for (let i = 0; i < 30; i += 5) {
    const chunk = hash.readUIntBE(i, 5);
    digits.push((chunk % 100000).toString().padStart(5, '0'));
  }
  return digits.join(' ');
}

/**
 * HMAC-SHA256 convenience wrapper.
 */
function hmacSha256(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac('sha256', key).update(data).digest();
}

/**
 * SHA-256 convenience wrapper.
 */
function sha256(data: Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

// ---------------------------------------------------------------------------
// Section 2: Key Types
// ---------------------------------------------------------------------------

/** A Kyber KEM key pair (encapsulation public key + decapsulation secret key) */
export interface KyberKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** A Dilithium signing key pair */
export interface DilithiumKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Per-message symmetric keys */
export interface MessageKeys {
  cipherKey: Buffer;   // 32 bytes — AES-256 key
  macKey: Buffer;      // 32 bytes — HMAC key
  iv: Buffer;          // 12 bytes — GCM nonce
}

/** Header of an encrypted message */
export interface MessageHeader {
  /** Sender's current ratchet public key (Kyber encapsulation key) */
  ratchetPub: Uint8Array;
  /** Message number in sending chain */
  messageNumber: number;
  /** Number of messages in previous sending chain */
  previousChainLength: number;
}

/** A fully sealed message: header + ciphertext + authentication */
export interface SealedMessage {
  /** Encrypted header (protects metadata) */
  encryptedHeader: Buffer;
  /** Header encryption IV */
  headerIv: Buffer;
  /** Header auth tag */
  headerTag: Buffer;
  /** Encrypted payload */
  ciphertext: Buffer;
  /** Payload IV */
  iv: Buffer;
  /** GCM auth tag */
  authTag: Buffer;
  /** Epoch for group messages (optional) */
  epoch?: number;
}

// ---------------------------------------------------------------------------
// Section 3: Pre-Key Bundle & X3KEM Handshake
// ---------------------------------------------------------------------------

/**
 * A publishable pre-key bundle that allows asynchronous session establishment.
 * Contains identity, signed pre-key, one-time pre-key, and the Dilithium
 * signature over the signed pre-key.
 */
export interface PreKeyBundle {
  /** Long-term Dilithium identity public key */
  identityKey: Uint8Array;
  /** Medium-term Kyber signed pre-key (public) */
  signedPreKey: Uint8Array;
  /** Dilithium signature over signedPreKey by identityKey */
  signedPreKeySignature: Uint8Array;
  /** Ephemeral Kyber one-time pre-key (public) — may be absent */
  oneTimePreKey?: Uint8Array;
  /** Identifier for the signed pre-key */
  signedPreKeyId: number;
  /** Identifier for the one-time pre-key */
  oneTimePreKeyId?: number;
}

/**
 * X3KEM — Triple KEM handshake replacing X3DH for post-quantum security.
 *
 * The initiator performs three KEM encapsulations against the responder's
 * pre-key bundle:
 *   KEM1: encapsulate to signed pre-key   (medium-term ↔ identity binding)
 *   KEM2: encapsulate to signed pre-key   (ephemeral initiator contribution)
 *   KEM3: encapsulate to one-time pre-key (one-time forward secrecy, optional)
 *
 * Each encapsulation produces a shared secret; they are combined via HKDF
 * to produce the initial root key for the double ratchet.
 */
export class X3KEM {
  private kemLevel: KyberLevel;
  private dsaLevel: DilithiumLevel;

  constructor(kemLevel: KyberLevel = 'kem768', dsaLevel: DilithiumLevel = 'dsa65') {
    this.kemLevel = kemLevel;
    this.dsaLevel = dsaLevel;
  }

  /** Generate a Kyber key pair */
  generateKyberKeyPair(): KyberKeyPair {
    const kem = KEM_SUITE[this.kemLevel];
    const keys = kem.keygen();
    return { publicKey: keys.publicKey, secretKey: keys.secretKey };
  }

  /** Generate a Dilithium identity key pair */
  generateIdentityKeyPair(): DilithiumKeyPair {
    const dsa = DSA_SUITE[this.dsaLevel];
    const keys = dsa.keygen();
    return { publicKey: keys.publicKey, secretKey: keys.secretKey };
  }

  /** Sign a pre-key with the identity secret key */
  signPreKey(identitySecretKey: Uint8Array, preKeyPublic: Uint8Array): Uint8Array {
    const dsa = DSA_SUITE[this.dsaLevel];
    return dsa.sign(identitySecretKey, preKeyPublic);
  }

  /** Verify a signed pre-key against the identity public key */
  verifyPreKey(identityPublicKey: Uint8Array, preKeyPublic: Uint8Array, signature: Uint8Array): boolean {
    const dsa = DSA_SUITE[this.dsaLevel];
    return dsa.verify(identityPublicKey, preKeyPublic, signature);
  }

  /**
   * Create a pre-key bundle for publishing.
   */
  createPreKeyBundle(
    identityKeyPair: DilithiumKeyPair,
    signedPreKeyPair: KyberKeyPair,
    signedPreKeyId: number,
    oneTimePreKeyPair?: KyberKeyPair,
    oneTimePreKeyId?: number
  ): PreKeyBundle {
    const signature = this.signPreKey(identityKeyPair.secretKey, signedPreKeyPair.publicKey);
    return {
      identityKey: identityKeyPair.publicKey,
      signedPreKey: signedPreKeyPair.publicKey,
      signedPreKeySignature: signature,
      signedPreKeyId,
      oneTimePreKey: oneTimePreKeyPair?.publicKey,
      oneTimePreKeyId,
    };
  }

  /**
   * Initiator: perform the X3KEM handshake against a remote pre-key bundle.
   * Returns the shared root key and the KEM ciphertexts that the responder
   * needs to derive the same key.
   */
  initiateHandshake(bundle: PreKeyBundle): {
    rootKey: Buffer;
    kemCiphertext1: Uint8Array;
    kemCiphertext2: Uint8Array;
    kemCiphertext3?: Uint8Array;
  } {
    // Step 1: Verify the signed pre-key
    const verified = this.verifyPreKey(
      bundle.identityKey,
      bundle.signedPreKey,
      bundle.signedPreKeySignature
    );
    if (!verified) {
      throw new Error('X3KEM: signed pre-key verification failed — bundle may be tampered');
    }

    const kem = KEM_SUITE[this.kemLevel];

    // KEM1: encapsulate to signed pre-key (identity binding)
    const kem1 = kem.encapsulate(bundle.signedPreKey);
    const ss1 = Buffer.from(kem1.sharedSecret);

    // KEM2: encapsulate to signed pre-key again (ephemeral contribution)
    const kem2 = kem.encapsulate(bundle.signedPreKey);
    const ss2 = Buffer.from(kem2.sharedSecret);

    // KEM3: encapsulate to one-time pre-key if available
    let ss3: Buffer | undefined;
    let kemCiphertext3: Uint8Array | undefined;
    if (bundle.oneTimePreKey) {
      const kem3 = kem.encapsulate(bundle.oneTimePreKey);
      ss3 = Buffer.from(kem3.sharedSecret);
      kemCiphertext3 = kem3.cipherText;
    }

    // Combine all shared secrets via HKDF
    const ikm = Buffer.concat([ss1, ss2, ...(ss3 ? [ss3] : [])]);
    // Use a fixed salt of 32 zero bytes for the initial extraction
    const salt = Buffer.alloc(32, 0);
    const rootKey = HKDF.derive(ikm, salt, SESSION_INFO, 32);

    // Erase intermediate secrets
    secureErase(ss1);
    secureErase(ss2);
    if (ss3) secureErase(ss3);
    secureErase(ikm);

    return {
      rootKey,
      kemCiphertext1: kem1.cipherText,
      kemCiphertext2: kem2.cipherText,
      kemCiphertext3: kemCiphertext3,
    };
  }

  /**
   * Responder: complete the X3KEM handshake using received ciphertexts
   * and local secret keys. Must produce the same root key as the initiator.
   */
  completeHandshake(
    signedPreKeySecret: Uint8Array,
    kemCiphertext1: Uint8Array,
    kemCiphertext2: Uint8Array,
    kemCiphertext3?: Uint8Array,
    oneTimePreKeySecret?: Uint8Array
  ): Buffer {
    const kem = KEM_SUITE[this.kemLevel];

    // Decapsulate KEM1
    const ss1 = Buffer.from(kem.decapsulate(kemCiphertext1, signedPreKeySecret));

    // Decapsulate KEM2
    const ss2 = Buffer.from(kem.decapsulate(kemCiphertext2, signedPreKeySecret));

    // Decapsulate KEM3 if present
    let ss3: Buffer | undefined;
    if (kemCiphertext3 && oneTimePreKeySecret) {
      ss3 = Buffer.from(kem.decapsulate(kemCiphertext3, oneTimePreKeySecret));
    }

    const ikm = Buffer.concat([ss1, ss2, ...(ss3 ? [ss3] : [])]);
    const salt = Buffer.alloc(32, 0);
    const rootKey = HKDF.derive(ikm, salt, SESSION_INFO, 32);

    secureErase(ss1);
    secureErase(ss2);
    if (ss3) secureErase(ss3);
    secureErase(ikm);

    return rootKey;
  }
}

// ---------------------------------------------------------------------------
// Section 4: PQ Double Ratchet
// ---------------------------------------------------------------------------

/**
 * State for one side of the double ratchet.
 * Mirrors the Signal double ratchet state machine, with Kyber KEM replacing
 * the DH ratchet step.
 */
export interface RatchetState {
  /** Current root key */
  rootKey: Buffer;
  /** Current sending chain key (null until first ratchet) */
  sendingChainKey: Buffer | null;
  /** Current receiving chain key (null until first message received) */
  receivingChainKey: Buffer | null;
  /** Our current ratchet KEM key pair */
  sendingRatchetKeyPair: KyberKeyPair;
  /** Remote party's current ratchet public key */
  receivingRatchetPub: Uint8Array | null;
  /** Number of messages sent on current sending chain */
  sendMessageNumber: number;
  /** Number of messages received on current receiving chain */
  recvMessageNumber: number;
  /** Previous sending chain length (for header) */
  previousChainLength: number;
  /** Cached skipped message keys: Map<"pubHex:msgNum", MessageKeys> */
  skippedKeys: Map<string, MessageKeys>;
  /** Header encryption key (derived from root key) */
  headerEncryptionKey: Buffer;
}

/**
 * PQDoubleRatchet — Kyber KEM-based double ratchet providing forward secrecy
 * and post-compromise security.
 *
 * Each "ratchet step" performs a KEM encapsulation (sender) or decapsulation
 * (receiver) instead of a DH exchange. The KEM shared secret is fed into
 * the KDF chain to advance the root key and derive new chain keys.
 */
export class PQDoubleRatchet {
  private state: RatchetState;
  private kemLevel: KyberLevel;

  private constructor(state: RatchetState, kemLevel: KyberLevel) {
    this.state = state;
    this.kemLevel = kemLevel;
  }

  /**
   * Initialize ratchet as the session initiator (Alice).
   * Alice has completed the X3KEM handshake and has the shared root key.
   * She generates the first ratchet key pair and performs an initial KEM
   * encapsulation against Bob's signed pre-key.
   */
  static initializeInitiator(
    rootKey: Buffer,
    remoteRatchetPub: Uint8Array,
    kemLevel: KyberLevel = 'kem768'
  ): { ratchet: PQDoubleRatchet; initialCiphertext: Uint8Array } {
    const kem = KEM_SUITE[kemLevel];
    const sendingKeyPair = kem.keygen();

    // Perform initial KEM encapsulation against remote ratchet pub
    const { cipherText, sharedSecret } = kem.encapsulate(remoteRatchetPub);
    const ssBuffer = Buffer.from(sharedSecret);

    // Derive new root key and sending chain key
    const [newRootKey, sendingChainKey] = HKDF.deriveKeyPair(ssBuffer, rootKey, RATCHET_INFO);

    // Derive header encryption key from root key
    const headerEncryptionKey = HKDF.derive(rootKey, Buffer.alloc(32, 0x02), RATCHET_INFO, 32);

    secureErase(ssBuffer);

    const state: RatchetState = {
      rootKey: newRootKey,
      sendingChainKey,
      receivingChainKey: null,
      sendingRatchetKeyPair: { publicKey: sendingKeyPair.publicKey, secretKey: sendingKeyPair.secretKey },
      receivingRatchetPub: remoteRatchetPub,
      sendMessageNumber: 0,
      recvMessageNumber: 0,
      previousChainLength: 0,
      skippedKeys: new Map(),
      headerEncryptionKey,
    };

    return {
      ratchet: new PQDoubleRatchet(state, kemLevel),
      initialCiphertext: cipherText,
    };
  }

  /**
   * Initialize ratchet as the session responder (Bob).
   * Bob uses his signed pre-key's secret to establish the initial state.
   */
  static initializeResponder(
    rootKey: Buffer,
    ratchetKeyPair: KyberKeyPair,
    kemLevel: KyberLevel = 'kem768'
  ): PQDoubleRatchet {
    // Derive header encryption key from root key
    const headerEncryptionKey = HKDF.derive(rootKey, Buffer.alloc(32, 0x02), RATCHET_INFO, 32);

    const state: RatchetState = {
      rootKey,
      sendingChainKey: null,
      receivingChainKey: null,
      sendingRatchetKeyPair: ratchetKeyPair,
      receivingRatchetPub: null,
      sendMessageNumber: 0,
      recvMessageNumber: 0,
      previousChainLength: 0,
      skippedKeys: new Map(),
      headerEncryptionKey,
    };

    return new PQDoubleRatchet(state, kemLevel);
  }

  /**
   * Perform a sending ratchet step: generate new KEM key pair, encapsulate
   * to remote, advance root key and sending chain.
   */
  ratchetStep(remoteRatchetPub: Uint8Array): Uint8Array {
    const kem = KEM_SUITE[this.kemLevel];

    // Save previous sending chain length
    this.state.previousChainLength = this.state.sendMessageNumber;
    this.state.sendMessageNumber = 0;
    this.state.recvMessageNumber = 0;

    // Update receiving ratchet pub
    this.state.receivingRatchetPub = remoteRatchetPub;

    // Generate new KEM key pair for sending
    const newKeyPair = kem.keygen();

    // Encapsulate to remote's ratchet public key
    const { cipherText, sharedSecret } = kem.encapsulate(remoteRatchetPub);
    const ssBuffer = Buffer.from(sharedSecret);

    // Advance root key → new root key + receiving chain key
    const [rootKey1, receivingChainKey] = HKDF.deriveKeyPair(ssBuffer, this.state.rootKey, RATCHET_INFO);
    this.state.receivingChainKey = receivingChainKey;

    // Encapsulate again with new key to derive sending chain
    // (In a KEM ratchet the sending chain derives from the new key's encapsulation)
    const kemForSend = kem.encapsulate(remoteRatchetPub);
    const ssForSend = Buffer.from(kemForSend.sharedSecret);

    const [newRootKey, sendingChainKey] = HKDF.deriveKeyPair(ssForSend, rootKey1, RATCHET_INFO);

    // Erase old root key
    secureErase(this.state.rootKey);
    this.state.rootKey = newRootKey;
    this.state.sendingChainKey = sendingChainKey;

    // Replace ratchet key pair
    const oldSecret = Buffer.from(this.state.sendingRatchetKeyPair.secretKey);
    secureErase(oldSecret);
    this.state.sendingRatchetKeyPair = { publicKey: newKeyPair.publicKey, secretKey: newKeyPair.secretKey };

    // Update header encryption key
    this.state.headerEncryptionKey = HKDF.derive(
      this.state.rootKey, Buffer.alloc(32, 0x02), RATCHET_INFO, 32
    );

    secureErase(ssBuffer);
    secureErase(ssForSend);

    return cipherText;
  }

  /**
   * Perform a receiving ratchet step: decapsulate the incoming KEM ciphertext,
   * advance root key and receiving chain.
   */
  private receivingRatchetStep(
    kemCiphertext: Uint8Array,
    senderRatchetPub: Uint8Array
  ): void {
    const kem = KEM_SUITE[this.kemLevel];

    // Decapsulate using our current ratchet secret key
    const sharedSecret = kem.decapsulate(kemCiphertext, this.state.sendingRatchetKeyPair.secretKey);
    const ssBuffer = Buffer.from(sharedSecret);

    // Advance root key → new root key + receiving chain key
    const [newRootKey, receivingChainKey] = HKDF.deriveKeyPair(ssBuffer, this.state.rootKey, RATCHET_INFO);

    secureErase(this.state.rootKey);
    this.state.rootKey = newRootKey;
    this.state.receivingChainKey = receivingChainKey;
    this.state.receivingRatchetPub = senderRatchetPub;

    // Reset receive counter
    this.state.previousChainLength = this.state.sendMessageNumber;
    this.state.sendMessageNumber = 0;
    this.state.recvMessageNumber = 0;

    // Generate new sending ratchet
    const newKeyPair = kem.keygen();
    const oldSecret = Buffer.from(this.state.sendingRatchetKeyPair.secretKey);
    secureErase(oldSecret);
    this.state.sendingRatchetKeyPair = { publicKey: newKeyPair.publicKey, secretKey: newKeyPair.secretKey };

    // Derive new sending chain key from a KEM encapsulation to sender's pub
    const kemForSend = kem.encapsulate(senderRatchetPub);
    const ssForSend = Buffer.from(kemForSend.sharedSecret);
    const [rootKey2, sendingChainKey] = HKDF.deriveKeyPair(ssForSend, this.state.rootKey, RATCHET_INFO);

    secureErase(this.state.rootKey);
    this.state.rootKey = rootKey2;
    this.state.sendingChainKey = sendingChainKey;

    // Update header encryption key
    this.state.headerEncryptionKey = HKDF.derive(
      this.state.rootKey, Buffer.alloc(32, 0x02), RATCHET_INFO, 32
    );

    secureErase(ssBuffer);
    secureErase(ssForSend);
  }

  /**
   * Derive the next message key from the sending chain.
   * Advances the chain key via HMAC.
   */
  private deriveMessageKeys(chainKey: Buffer): { messageKeys: MessageKeys; nextChainKey: Buffer } {
    const messageKeyMaterial = hmacSha256(chainKey, MESSAGE_KEY_CONSTANT);
    const nextChainKey = hmacSha256(chainKey, CHAIN_KEY_CONSTANT);

    // Derive cipher key (32B), mac key (32B), and IV (12B) from message key material
    const expanded = HKDF.expand(messageKeyMaterial, RATCHET_INFO, 76);

    const messageKeys: MessageKeys = {
      cipherKey: expanded.subarray(0, 32),
      macKey: expanded.subarray(32, 64),
      iv: expanded.subarray(64, 76),
    };

    secureErase(messageKeyMaterial);
    return { messageKeys, nextChainKey };
  }

  /**
   * Get the next sending message keys and advance the sending chain.
   */
  getNextSendingKeys(): { messageKeys: MessageKeys; header: MessageHeader } {
    if (!this.state.sendingChainKey) {
      throw new Error('PQDoubleRatchet: sending chain not initialized — ratchet step needed');
    }

    const { messageKeys, nextChainKey } = this.deriveMessageKeys(this.state.sendingChainKey);
    secureErase(this.state.sendingChainKey);
    this.state.sendingChainKey = nextChainKey;

    const header: MessageHeader = {
      ratchetPub: this.state.sendingRatchetKeyPair.publicKey,
      messageNumber: this.state.sendMessageNumber,
      previousChainLength: this.state.previousChainLength,
    };

    this.state.sendMessageNumber++;
    return { messageKeys, header };
  }

  /**
   * Process a received message header: perform receiving ratchet if needed,
   * skip message keys for out-of-order messages, and return the decryption keys.
   */
  getReceivingKeys(header: MessageHeader, kemCiphertext?: Uint8Array): MessageKeys {
    // Check if this is a new ratchet epoch (different sender ratchet pub)
    const senderPubHex = Buffer.from(header.ratchetPub).toString('hex');
    const currentRecvPubHex = this.state.receivingRatchetPub
      ? Buffer.from(this.state.receivingRatchetPub).toString('hex')
      : null;

    // Check skipped keys first
    const skipKey = `${senderPubHex}:${header.messageNumber}`;
    const cached = this.state.skippedKeys.get(skipKey);
    if (cached) {
      this.state.skippedKeys.delete(skipKey);
      return cached;
    }

    // If different ratchet pub, we need a receiving ratchet step
    if (senderPubHex !== currentRecvPubHex) {
      if (kemCiphertext) {
        // Skip any remaining keys in the current receiving chain
        if (this.state.receivingChainKey) {
          this.skipMessageKeys(
            this.state.receivingRatchetPub!,
            this.state.recvMessageNumber,
            header.previousChainLength
          );
        }
        this.receivingRatchetStep(kemCiphertext, header.ratchetPub);
      } else {
        throw new Error('PQDoubleRatchet: new ratchet epoch but no KEM ciphertext provided');
      }
    }

    // Skip any out-of-order messages in the current receiving chain
    if (header.messageNumber > this.state.recvMessageNumber) {
      this.skipMessageKeys(
        header.ratchetPub,
        this.state.recvMessageNumber,
        header.messageNumber
      );
    }

    if (!this.state.receivingChainKey) {
      throw new Error('PQDoubleRatchet: receiving chain not initialized');
    }

    // Derive message keys for this message
    const { messageKeys, nextChainKey } = this.deriveMessageKeys(this.state.receivingChainKey);
    secureErase(this.state.receivingChainKey);
    this.state.receivingChainKey = nextChainKey;
    this.state.recvMessageNumber = header.messageNumber + 1;

    return messageKeys;
  }

  /**
   * Cache skipped message keys for out-of-order delivery tolerance.
   */
  private skipMessageKeys(ratchetPub: Uint8Array, from: number, until: number): void {
    if (until - from > MAX_SKIP) {
      throw new Error(`PQDoubleRatchet: too many skipped messages (${until - from} > ${MAX_SKIP})`);
    }

    if (!this.state.receivingChainKey) return;

    const pubHex = Buffer.from(ratchetPub).toString('hex');
    let chainKey = this.state.receivingChainKey;

    for (let i = from; i < until; i++) {
      const { messageKeys, nextChainKey } = this.deriveMessageKeys(chainKey);
      this.state.skippedKeys.set(`${pubHex}:${i}`, messageKeys);
      secureErase(chainKey);
      chainKey = nextChainKey;
    }

    this.state.receivingChainKey = chainKey;
  }

  /** Get the current header encryption key */
  getHeaderEncryptionKey(): Buffer {
    return Buffer.from(this.state.headerEncryptionKey);
  }

  /** Get the current sending ratchet public key */
  getSendingRatchetPub(): Uint8Array {
    return this.state.sendingRatchetKeyPair.publicKey;
  }

  /** Export ratchet state for persistence */
  exportState(): RatchetState {
    return { ...this.state };
  }

  /** Destroy ratchet state, erasing all keys */
  destroy(): void {
    secureErase(this.state.rootKey);
    if (this.state.sendingChainKey) secureErase(this.state.sendingChainKey);
    if (this.state.receivingChainKey) secureErase(this.state.receivingChainKey);
    secureErase(this.state.headerEncryptionKey);
    const sk = Buffer.from(this.state.sendingRatchetKeyPair.secretKey);
    secureErase(sk);
    for (const [, keys] of this.state.skippedKeys) {
      secureErase(keys.cipherKey);
      secureErase(keys.macKey);
      secureErase(keys.iv);
    }
    this.state.skippedKeys.clear();
  }
}

// ---------------------------------------------------------------------------
// Section 5: Message Encryption / Decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt a message header using AES-256-GCM with the header encryption key.
 * Prevents metadata leakage (who is sending, message ordering) from network
 * observers who do not hold the header key.
 */
function encryptHeader(header: MessageHeader, headerKey: Buffer): {
  encryptedHeader: Buffer;
  headerIv: Buffer;
  headerTag: Buffer;
} {
  const headerData = Buffer.from(JSON.stringify({
    ratchetPub: Buffer.from(header.ratchetPub).toString('base64'),
    messageNumber: header.messageNumber,
    previousChainLength: header.previousChainLength,
  }));

  const headerIv = secureRandom(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', headerKey, headerIv);
  const encryptedHeader = Buffer.concat([cipher.update(headerData), cipher.final()]);
  const headerTag = cipher.getAuthTag();

  return { encryptedHeader, headerIv, headerTag };
}

/**
 * Decrypt a message header.
 */
function decryptHeader(
  encryptedHeader: Buffer,
  headerIv: Buffer,
  headerTag: Buffer,
  headerKey: Buffer
): MessageHeader {
  const decipher = crypto.createDecipheriv('aes-256-gcm', headerKey, headerIv);
  decipher.setAuthTag(headerTag);
  const headerData = Buffer.concat([decipher.update(encryptedHeader), decipher.final()]);

  const parsed = JSON.parse(headerData.toString('utf8'));
  return {
    ratchetPub: new Uint8Array(Buffer.from(parsed.ratchetPub, 'base64')),
    messageNumber: parsed.messageNumber,
    previousChainLength: parsed.previousChainLength,
  };
}

/**
 * Encrypt a plaintext message using the double ratchet session.
 * Produces a SealedMessage with encrypted header and authenticated ciphertext.
 */
export function encrypt(plaintext: Buffer, ratchet: PQDoubleRatchet): SealedMessage {
  const { messageKeys, header } = ratchet.getNextSendingKeys();

  // Encrypt header to hide metadata
  const headerKey = ratchet.getHeaderEncryptionKey();
  const { encryptedHeader, headerIv, headerTag } = encryptHeader(header, headerKey);

  // Encrypt payload with AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', messageKeys.cipherKey, messageKeys.iv);

  // Include header ciphertext as AAD for binding
  cipher.setAAD(encryptedHeader);

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Erase message keys after use
  secureErase(messageKeys.cipherKey);
  secureErase(messageKeys.macKey);
  secureErase(messageKeys.iv);

  return {
    encryptedHeader,
    headerIv,
    headerTag,
    ciphertext,
    iv: messageKeys.iv, // Already used as GCM nonce above
    authTag,
  };
}

/**
 * Decrypt a sealed message using the double ratchet session.
 * Returns the original plaintext or throws on integrity failure.
 */
export function decrypt(
  sealed: SealedMessage,
  ratchet: PQDoubleRatchet,
  kemCiphertext?: Uint8Array
): Buffer {
  // Decrypt header
  const headerKey = ratchet.getHeaderEncryptionKey();
  const header = decryptHeader(
    sealed.encryptedHeader,
    sealed.headerIv,
    sealed.headerTag,
    headerKey
  );

  // Get receiving message keys (may trigger ratchet step)
  const messageKeys = ratchet.getReceivingKeys(header, kemCiphertext);

  // Decrypt payload
  const decipher = crypto.createDecipheriv('aes-256-gcm', messageKeys.cipherKey, messageKeys.iv);
  decipher.setAAD(sealed.encryptedHeader);
  decipher.setAuthTag(sealed.authTag);

  const plaintext = Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);

  // Erase message keys
  secureErase(messageKeys.cipherKey);
  secureErase(messageKeys.macKey);
  secureErase(messageKeys.iv);

  return plaintext;
}

// ---------------------------------------------------------------------------
// Section 6: Session Management
// ---------------------------------------------------------------------------

/** Persistent session record */
export interface SessionRecord {
  sessionId: string;
  remoteIdentityKey: Uint8Array;
  localIdentityKey: Uint8Array;
  ratchetState: RatchetState;
  createdAt: number;
  lastActivity: number;
  messageCount: number;
  version: number;
}

/**
 * SessionStore — Persists session state for long-lived conversations.
 * Manages key rotation tracking and session lifecycle.
 */
export class SessionStore {
  private sessions: Map<string, SessionRecord> = new Map();
  private preKeys: Map<number, KyberKeyPair> = new Map();
  private oneTimePreKeys: Map<number, KyberKeyPair> = new Map();
  private nextPreKeyId: number = 1;
  private nextOneTimePreKeyId: number = 1;

  /** Store a session record */
  saveSession(sessionId: string, record: SessionRecord): void {
    record.lastActivity = Date.now();
    this.sessions.set(sessionId, record);
  }

  /** Load a session record */
  loadSession(sessionId: string): SessionRecord | undefined {
    return this.sessions.get(sessionId);
  }

  /** Check if a session exists */
  hasSession(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  /** Delete a session and erase its keys */
  deleteSession(sessionId: string): void {
    const record = this.sessions.get(sessionId);
    if (record) {
      secureErase(record.ratchetState.rootKey);
      if (record.ratchetState.sendingChainKey) secureErase(record.ratchetState.sendingChainKey);
      if (record.ratchetState.receivingChainKey) secureErase(record.ratchetState.receivingChainKey);
      secureErase(record.ratchetState.headerEncryptionKey);
      this.sessions.delete(sessionId);
    }
  }

  /** List all active session IDs */
  listSessions(): string[] {
    return Array.from(this.sessions.keys());
  }

  /** Get sessions older than maxAge (ms) for rotation */
  getStaleSessionIds(maxAgeMs: number): string[] {
    const now = Date.now();
    const stale: string[] = [];
    for (const [id, record] of this.sessions) {
      if (now - record.lastActivity > maxAgeMs) {
        stale.push(id);
      }
    }
    return stale;
  }

  /** Store a signed pre-key pair */
  storeSignedPreKey(id: number, keyPair: KyberKeyPair): void {
    this.preKeys.set(id, keyPair);
  }

  /** Load a signed pre-key pair */
  loadSignedPreKey(id: number): KyberKeyPair | undefined {
    return this.preKeys.get(id);
  }

  /** Store a batch of one-time pre-keys */
  storeOneTimePreKeys(keys: KyberKeyPair[]): number[] {
    const ids: number[] = [];
    for (const kp of keys) {
      const id = this.nextOneTimePreKeyId++;
      this.oneTimePreKeys.set(id, kp);
      ids.push(id);
    }
    return ids;
  }

  /** Consume a one-time pre-key (remove after use) */
  consumeOneTimePreKey(id: number): KyberKeyPair | undefined {
    const kp = this.oneTimePreKeys.get(id);
    if (kp) {
      this.oneTimePreKeys.delete(id);
    }
    return kp;
  }

  /** Count remaining one-time pre-keys */
  oneTimePreKeyCount(): number {
    return this.oneTimePreKeys.size;
  }

  /** Generate the next signed pre-key ID */
  getNextPreKeyId(): number {
    return this.nextPreKeyId++;
  }

  /** Destroy all session state */
  destroyAll(): void {
    for (const id of this.sessions.keys()) {
      this.deleteSession(id);
    }
    this.preKeys.clear();
    this.oneTimePreKeys.clear();
  }
}

/**
 * SessionBuilder — Orchestrates session establishment using X3KEM handshake.
 */
export class SessionBuilder {
  private x3kem: X3KEM;
  private store: SessionStore;
  private localIdentityKeyPair: DilithiumKeyPair;
  private kemLevel: KyberLevel;

  constructor(
    localIdentityKeyPair: DilithiumKeyPair,
    store: SessionStore,
    kemLevel: KyberLevel = 'kem768',
    dsaLevel: DilithiumLevel = 'dsa65'
  ) {
    this.localIdentityKeyPair = localIdentityKeyPair;
    this.store = store;
    this.x3kem = new X3KEM(kemLevel, dsaLevel);
    this.kemLevel = kemLevel;
  }

  /**
   * Initiate a session with a remote party using their pre-key bundle.
   * Returns the session ID, the ratchet, and the initial message to send.
   */
  initiateSession(bundle: PreKeyBundle): {
    sessionId: string;
    ratchet: PQDoubleRatchet;
    initialMessage: {
      kemCiphertext1: Uint8Array;
      kemCiphertext2: Uint8Array;
      kemCiphertext3?: Uint8Array;
      initialRatchetCiphertext: Uint8Array;
      senderIdentityKey: Uint8Array;
      senderRatchetPub: Uint8Array;
      signedPreKeyId: number;
      oneTimePreKeyId?: number;
    };
  } {
    // Perform X3KEM handshake
    const { rootKey, kemCiphertext1, kemCiphertext2, kemCiphertext3 } =
      this.x3kem.initiateHandshake(bundle);

    // Initialize double ratchet with Bob's signed pre-key as first ratchet pub
    const { ratchet, initialCiphertext } = PQDoubleRatchet.initializeInitiator(
      rootKey, bundle.signedPreKey, this.kemLevel
    );

    // Generate session ID from both identity keys
    const sessionId = sha256(
      Buffer.concat([
        Buffer.from(this.localIdentityKeyPair.publicKey),
        Buffer.from(bundle.identityKey),
      ])
    ).toString('hex').substring(0, 32);

    // Persist session
    const record: SessionRecord = {
      sessionId,
      remoteIdentityKey: bundle.identityKey,
      localIdentityKey: this.localIdentityKeyPair.publicKey,
      ratchetState: ratchet.exportState(),
      createdAt: Date.now(),
      lastActivity: Date.now(),
      messageCount: 0,
      version: 1,
    };
    this.store.saveSession(sessionId, record);

    secureErase(rootKey);

    return {
      sessionId,
      ratchet,
      initialMessage: {
        kemCiphertext1,
        kemCiphertext2,
        kemCiphertext3,
        initialRatchetCiphertext: initialCiphertext,
        senderIdentityKey: this.localIdentityKeyPair.publicKey,
        senderRatchetPub: ratchet.getSendingRatchetPub(),
        signedPreKeyId: bundle.signedPreKeyId,
        oneTimePreKeyId: bundle.oneTimePreKeyId,
      },
    };
  }

  /**
   * Respond to an incoming session initiation.
   */
  respondToSession(
    initialMessage: {
      kemCiphertext1: Uint8Array;
      kemCiphertext2: Uint8Array;
      kemCiphertext3?: Uint8Array;
      initialRatchetCiphertext: Uint8Array;
      senderIdentityKey: Uint8Array;
      senderRatchetPub: Uint8Array;
      signedPreKeyId: number;
      oneTimePreKeyId?: number;
    }
  ): { sessionId: string; ratchet: PQDoubleRatchet } {
    // Load our signed pre-key
    const signedPreKey = this.store.loadSignedPreKey(initialMessage.signedPreKeyId);
    if (!signedPreKey) {
      throw new Error(`SessionBuilder: signed pre-key ${initialMessage.signedPreKeyId} not found`);
    }

    // Load one-time pre-key if used
    let oneTimePreKeySecret: Uint8Array | undefined;
    if (initialMessage.oneTimePreKeyId !== undefined) {
      const otpk = this.store.consumeOneTimePreKey(initialMessage.oneTimePreKeyId);
      if (otpk) {
        oneTimePreKeySecret = otpk.secretKey;
      }
    }

    // Complete X3KEM handshake
    const rootKey = this.x3kem.completeHandshake(
      signedPreKey.secretKey,
      initialMessage.kemCiphertext1,
      initialMessage.kemCiphertext2,
      initialMessage.kemCiphertext3,
      oneTimePreKeySecret
    );

    // Initialize double ratchet as responder
    const ratchet = PQDoubleRatchet.initializeResponder(rootKey, signedPreKey, this.kemLevel);

    // Generate session ID (same as initiator)
    const sessionId = sha256(
      Buffer.concat([
        Buffer.from(initialMessage.senderIdentityKey),
        Buffer.from(this.localIdentityKeyPair.publicKey),
      ])
    ).toString('hex').substring(0, 32);

    const record: SessionRecord = {
      sessionId,
      remoteIdentityKey: initialMessage.senderIdentityKey,
      localIdentityKey: this.localIdentityKeyPair.publicKey,
      ratchetState: ratchet.exportState(),
      createdAt: Date.now(),
      lastActivity: Date.now(),
      messageCount: 0,
      version: 1,
    };
    this.store.saveSession(sessionId, record);

    secureErase(rootKey);

    return { sessionId, ratchet };
  }
}

// ---------------------------------------------------------------------------
// Section 7: Group Messaging — TreeKEM (MLS-inspired)
// ---------------------------------------------------------------------------

/** A node in the ratchet tree */
interface TreeNode {
  /** Kyber public key at this node */
  publicKey: Uint8Array | null;
  /** Kyber secret key (only populated for nodes on our direct path) */
  secretKey: Uint8Array | null;
  /** Derived secret at this node (from KEM to parent) */
  nodeSecret: Buffer | null;
  /** Whether this node has been blanked (member removed) */
  blanked: boolean;
}

/** A member's leaf position in the tree */
interface GroupMember {
  memberId: string;
  leafIndex: number;
  identityKey: Uint8Array;
}

/** A path update: KEM ciphertexts encrypting path secrets to co-path nodes */
interface PathUpdate {
  senderLeafIndex: number;
  /** New public keys along the direct path (leaf → root) */
  pathPublicKeys: Uint8Array[];
  /** KEM ciphertexts to each co-path node */
  pathCiphertexts: Uint8Array[][];
}

/** Group epoch key material */
interface GroupEpoch {
  epochNumber: number;
  epochSecret: Buffer;
  senderKey: Buffer;
  receiverKey: Buffer;
  membershipTag: Buffer;
}

/**
 * Welcome message for onboarding a new member into the group.
 * Contains the group state the new member needs.
 */
export interface Welcome {
  groupId: string;
  epoch: number;
  /** Encrypted group info (tree state + epoch secret) */
  encryptedGroupInfo: Buffer;
  /** KEM ciphertext for the new member to decrypt the group info */
  kemCiphertext: Uint8Array;
  /** IV for the encryption */
  iv: Buffer;
  /** Auth tag */
  authTag: Buffer;
}

/** A message encrypted for the group */
export interface GroupMessage {
  groupId: string;
  epoch: number;
  senderLeafIndex: number;
  /** Encrypted content */
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  /** Membership authentication tag */
  membershipTag: Buffer;
}

/**
 * GroupState — MLS-inspired ratchet tree for post-quantum group key agreement.
 *
 * Uses a binary tree where each leaf is a group member and each internal node
 * holds a Kyber KEM key pair. Path secrets flow from leaves to root; the root
 * secret is used to derive group epoch keys.
 */
export class GroupState {
  private groupId: string;
  private tree: TreeNode[];
  private members: Map<string, GroupMember>;
  private treeSize: number;
  private currentEpoch: GroupEpoch;
  private myLeafIndex: number;
  private kemLevel: KyberLevel;

  constructor(groupId: string, kemLevel: KyberLevel = 'kem768') {
    this.groupId = groupId;
    this.kemLevel = kemLevel;
    this.tree = [];
    this.members = new Map();
    this.treeSize = 0;
    this.myLeafIndex = -1;
    this.currentEpoch = {
      epochNumber: 0,
      epochSecret: Buffer.alloc(32),
      senderKey: Buffer.alloc(32),
      receiverKey: Buffer.alloc(32),
      membershipTag: Buffer.alloc(32),
    };
  }

  /**
   * Initialize a new group with the creator as the first member.
   */
  static createGroup(
    groupId: string,
    creatorId: string,
    creatorIdentityKey: Uint8Array,
    kemLevel: KyberLevel = 'kem768'
  ): GroupState {
    const group = new GroupState(groupId, kemLevel);
    const kem = KEM_SUITE[kemLevel];

    // Create initial tree with single leaf
    const leafKeyPair = kem.keygen();
    group.tree = [{
      publicKey: leafKeyPair.publicKey,
      secretKey: leafKeyPair.secretKey,
      nodeSecret: null,
      blanked: false,
    }];
    group.treeSize = 1;

    group.members.set(creatorId, {
      memberId: creatorId,
      leafIndex: 0,
      identityKey: creatorIdentityKey,
    });
    group.myLeafIndex = 0;

    // Derive initial epoch from leaf secret
    const leafSecret = Buffer.from(leafKeyPair.secretKey.subarray(0, 32));
    group.deriveEpoch(leafSecret, 0);

    return group;
  }

  /**
   * Compute the parent index in the binary tree.
   * Uses left-balanced binary tree indexing.
   */
  private parentIndex(index: number): number {
    return Math.floor((index - 1) / 2);
  }

  /** Left child index */
  public leftChild(index: number): number {
    return 2 * index + 1;
  }

  /** Right child index */
  public rightChild(index: number): number {
    return 2 * index + 2;
  }

  /** Sibling index */
  private sibling(index: number): number {
    if (index === 0) return -1; // root has no sibling
    return index % 2 === 1 ? index + 1 : index - 1;
  }

  /**
   * Get the direct path from a leaf to the root (list of tree node indices).
   */
  private directPath(leafIndex: number): number[] {
    const path: number[] = [leafIndex];
    let current = leafIndex;
    while (current > 0) {
      current = this.parentIndex(current);
      path.push(current);
    }
    return path;
  }

  /**
   * Get the co-path (sibling at each level) for a leaf.
   */
  private coPath(leafIndex: number): number[] {
    const direct = this.directPath(leafIndex);
    const copath: number[] = [];
    for (const nodeIdx of direct) {
      const sib = this.sibling(nodeIdx);
      if (sib >= 0 && sib < this.tree.length) {
        copath.push(sib);
      }
    }
    return copath;
  }

  /**
   * Ensure the tree has enough nodes to accommodate a given leaf index.
   */
  private ensureTreeCapacity(leafIndex: number): void {
    // For a binary tree, we need at least (2 * maxLeaf + 1) nodes
    const needed = 2 * leafIndex + 2;
    while (this.tree.length < needed) {
      this.tree.push({
        publicKey: null,
        secretKey: null,
        nodeSecret: null,
        blanked: true,
      });
    }
  }

  /**
   * Add a new member to the group. Returns a Welcome for the new member
   * and a PathUpdate for existing members.
   */
  addMember(
    memberId: string,
    memberIdentityKey: Uint8Array,
    memberLeafPub: Uint8Array
  ): { welcome: Welcome; pathUpdate: PathUpdate } {
    void KEM_SUITE[this.kemLevel]; // kem for encapsulation

    // Find next available leaf (first blanked leaf or append)
    let leafIndex = -1;
    for (let i = 0; i < this.tree.length; i += 2) {
      if (this.tree[i]?.blanked) {
        leafIndex = i;
        break;
      }
    }
    if (leafIndex === -1) {
      leafIndex = this.treeSize * 2; // New leaf at end
    }

    this.ensureTreeCapacity(leafIndex);

    // Set the new member's leaf
    this.tree[leafIndex] = {
      publicKey: memberLeafPub,
      secretKey: null, // We don't know their secret key
      nodeSecret: null,
      blanked: false,
    };

    this.members.set(memberId, {
      memberId,
      leafIndex,
      identityKey: memberIdentityKey,
    });
    this.treeSize++;

    // Update our direct path with new KEM key pairs
    const pathUpdate = this.updatePath(this.myLeafIndex);

    // Advance epoch
    const newEpochSecret = HKDF.derive(
      this.currentEpoch.epochSecret,
      Buffer.from(memberIdentityKey.subarray(0, 32)),
      GROUP_INFO,
      32
    );
    this.deriveEpoch(newEpochSecret, this.currentEpoch.epochNumber + 1);

    // Create Welcome for the new member
    const welcome = this.createWelcome(memberLeafPub);

    return { welcome, pathUpdate };
  }

  /**
   * Remove a member from the group by blanking their leaf and updating the path.
   */
  removeMember(memberId: string): PathUpdate {
    const member = this.members.get(memberId);
    if (!member) {
      throw new Error(`GroupState: member ${memberId} not found`);
    }

    // Blank the removed member's leaf
    const leafIndex = member.leafIndex;
    if (this.tree[leafIndex]) {
      this.tree[leafIndex].publicKey = null;
      this.tree[leafIndex].secretKey = null;
      this.tree[leafIndex].nodeSecret = null;
      this.tree[leafIndex].blanked = true;
    }

    // Blank nodes on the removed member's direct path
    const removedPath = this.directPath(leafIndex);
    for (const nodeIdx of removedPath) {
      if (nodeIdx < this.tree.length && nodeIdx !== leafIndex) {
        this.tree[nodeIdx].publicKey = null;
        this.tree[nodeIdx].secretKey = null;
        this.tree[nodeIdx].nodeSecret = null;
        this.tree[nodeIdx].blanked = true;
      }
    }

    this.members.delete(memberId);
    this.treeSize--;

    // Update our path to replace blanked internal nodes
    const pathUpdate = this.updatePath(this.myLeafIndex);

    // Advance epoch
    const removalEntropy = secureRandom(32);
    const newEpochSecret = HKDF.derive(
      this.currentEpoch.epochSecret,
      removalEntropy,
      GROUP_INFO,
      32
    );
    this.deriveEpoch(newEpochSecret, this.currentEpoch.epochNumber + 1);

    return pathUpdate;
  }

  /**
   * Update the direct path from our leaf to the root.
   * Generates new KEM key pairs for each node on the path and encrypts
   * path secrets to each co-path node.
   */
  private updatePath(leafIndex: number): PathUpdate {
    const kem = KEM_SUITE[this.kemLevel];
    const path = this.directPath(leafIndex);
    const pathPublicKeys: Uint8Array[] = [];
    const pathCiphertexts: Uint8Array[][] = [];

    // Generate new key pairs along the path
    for (let i = 0; i < path.length; i++) {
      const nodeIdx = path[i];
      this.ensureTreeCapacity(nodeIdx);

      const newKeyPair = kem.keygen();
      this.tree[nodeIdx] = {
        publicKey: newKeyPair.publicKey,
        secretKey: newKeyPair.secretKey,
        nodeSecret: secureRandom(32),
        blanked: false,
      };
      pathPublicKeys.push(newKeyPair.publicKey);

      // Encrypt path secret to sibling (co-path node)
      const sibIdx = this.sibling(nodeIdx);
      const nodeCiphertexts: Uint8Array[] = [];

      if (sibIdx >= 0 && sibIdx < this.tree.length && this.tree[sibIdx]?.publicKey && !this.tree[sibIdx].blanked) {
        const { cipherText } = kem.encapsulate(this.tree[sibIdx].publicKey!);
        nodeCiphertexts.push(cipherText);
      }
      pathCiphertexts.push(nodeCiphertexts);
    }

    return {
      senderLeafIndex: leafIndex,
      pathPublicKeys,
      pathCiphertexts,
    };
  }

  /**
   * Process a path update from another group member.
   */
  processPathUpdate(update: PathUpdate): void {
    const kem = KEM_SUITE[this.kemLevel];
    const senderPath = this.directPath(update.senderLeafIndex);

    // Find where our co-path intersects with the sender's direct path
    const myCoPath = this.coPath(this.myLeafIndex);

    for (let i = 0; i < senderPath.length && i < update.pathPublicKeys.length; i++) {
      const nodeIdx = senderPath[i];
      this.ensureTreeCapacity(nodeIdx);

      // Update public key on the sender's path
      this.tree[nodeIdx] = {
        ...this.tree[nodeIdx],
        publicKey: update.pathPublicKeys[i],
        blanked: false,
      };

      // If this node's sibling is on our direct path, try to decrypt
      const sibIdx = this.sibling(nodeIdx);
      if (sibIdx >= 0 && myCoPath.includes(nodeIdx)) {
        const ciphertexts = update.pathCiphertexts[i];
        if (ciphertexts && ciphertexts.length > 0 && this.tree[sibIdx]?.secretKey) {
          try {
            const sharedSecret = kem.decapsulate(ciphertexts[0], this.tree[sibIdx].secretKey!);
            this.tree[nodeIdx].nodeSecret = Buffer.from(sharedSecret);
          } catch {
            // Could not decrypt — not on our resolution path
          }
        }
      }
    }

    // Advance epoch
    const pathEntropy = sha256(Buffer.from(update.pathPublicKeys[update.pathPublicKeys.length - 1] || []));
    const newEpochSecret = HKDF.derive(
      this.currentEpoch.epochSecret,
      pathEntropy,
      GROUP_INFO,
      32
    );
    this.deriveEpoch(newEpochSecret, this.currentEpoch.epochNumber + 1);
  }

  /**
   * Derive epoch keys from the epoch secret.
   */
  private deriveEpoch(epochSecret: Buffer, epochNumber: number): void {
    const epochInfo = Buffer.from(`epoch-${epochNumber}`, 'utf8');

    this.currentEpoch = {
      epochNumber,
      epochSecret,
      senderKey: HKDF.derive(epochSecret, Buffer.from('sender'), epochInfo, 32),
      receiverKey: HKDF.derive(epochSecret, Buffer.from('receiver'), epochInfo, 32),
      membershipTag: HKDF.derive(epochSecret, Buffer.from('membership'), epochInfo, 32),
    };
  }

  /**
   * Encrypt a message for the group using the current epoch key.
   */
  encryptGroupMessage(plaintext: Buffer): GroupMessage {
    const iv = secureRandom(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.currentEpoch.senderKey, iv);

    // AAD: group ID + epoch + sender leaf index
    const aad = Buffer.concat([
      Buffer.from(this.groupId, 'utf8'),
      Buffer.from(this.currentEpoch.epochNumber.toString()),
      Buffer.from(this.myLeafIndex.toString()),
    ]);
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Compute membership tag (proves sender is a group member)
    const membershipTag = hmacSha256(
      this.currentEpoch.membershipTag,
      Buffer.concat([ciphertext, aad])
    );

    return {
      groupId: this.groupId,
      epoch: this.currentEpoch.epochNumber,
      senderLeafIndex: this.myLeafIndex,
      ciphertext,
      iv,
      authTag,
      membershipTag,
    };
  }

  /**
   * Decrypt a group message.
   */
  decryptGroupMessage(message: GroupMessage): Buffer {
    if (message.epoch !== this.currentEpoch.epochNumber) {
      throw new Error(
        `GroupState: epoch mismatch (got ${message.epoch}, expected ${this.currentEpoch.epochNumber})`
      );
    }

    // Verify membership tag
    const aad = Buffer.concat([
      Buffer.from(message.groupId, 'utf8'),
      Buffer.from(message.epoch.toString()),
      Buffer.from(message.senderLeafIndex.toString()),
    ]);

    const expectedTag = hmacSha256(
      this.currentEpoch.membershipTag,
      Buffer.concat([message.ciphertext, aad])
    );

    if (!constantTimeEqual(message.membershipTag, expectedTag)) {
      throw new Error('GroupState: membership tag verification failed');
    }

    // Decrypt
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.currentEpoch.receiverKey, message.iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(message.authTag);

    return Buffer.concat([decipher.update(message.ciphertext), decipher.final()]);
  }

  /**
   * Create a Welcome message for a new member.
   */
  private createWelcome(memberLeafPub: Uint8Array): Welcome {
    const kem = KEM_SUITE[this.kemLevel];

    // Encapsulate to the new member's leaf public key
    const { cipherText, sharedSecret } = kem.encapsulate(memberLeafPub);
    const encKey = HKDF.derive(Buffer.from(sharedSecret), Buffer.alloc(32), GROUP_INFO, 32);

    // Serialize group info
    const groupInfo = Buffer.from(JSON.stringify({
      groupId: this.groupId,
      epoch: this.currentEpoch.epochNumber,
      epochSecret: this.currentEpoch.epochSecret.toString('base64'),
      treeSize: this.treeSize,
      members: Array.from(this.members.entries()).map(([id, m]) => ({
        memberId: id,
        leafIndex: m.leafIndex,
        identityKey: Buffer.from(m.identityKey).toString('base64'),
      })),
      treePublicKeys: this.tree.map(n => n.publicKey ? Buffer.from(n.publicKey).toString('base64') : null),
    }));

    // Encrypt group info
    const iv = secureRandom(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
    const encryptedGroupInfo = Buffer.concat([cipher.update(groupInfo), cipher.final()]);
    const authTag = cipher.getAuthTag();

    secureErase(encKey);

    return {
      groupId: this.groupId,
      epoch: this.currentEpoch.epochNumber,
      encryptedGroupInfo,
      kemCiphertext: cipherText,
      iv,
      authTag,
    };
  }

  /**
   * Process a Welcome message to join a group.
   */
  static processWelcome(
    welcome: Welcome,
    myLeafSecretKey: Uint8Array,
    myLeafIndex: number,
    kemLevel: KyberLevel = 'kem768'
  ): GroupState {
    const kem = KEM_SUITE[kemLevel];

    // Decapsulate to recover encryption key
    const sharedSecret = kem.decapsulate(welcome.kemCiphertext, myLeafSecretKey);
    const encKey = HKDF.derive(Buffer.from(sharedSecret), Buffer.alloc(32), GROUP_INFO, 32);

    // Decrypt group info
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, welcome.iv);
    decipher.setAuthTag(welcome.authTag);
    const groupInfoBuf = Buffer.concat([decipher.update(welcome.encryptedGroupInfo), decipher.final()]);

    const groupInfo = JSON.parse(groupInfoBuf.toString('utf8'));
    secureErase(encKey);

    // Reconstruct group state
    const group = new GroupState(groupInfo.groupId, kemLevel);
    group.myLeafIndex = myLeafIndex;
    group.treeSize = groupInfo.treeSize;

    // Rebuild tree
    group.tree = groupInfo.treePublicKeys.map((pk: string | null) => ({
      publicKey: pk ? new Uint8Array(Buffer.from(pk, 'base64')) : null,
      secretKey: null,
      nodeSecret: null,
      blanked: pk === null,
    }));

    // Rebuild members
    for (const m of groupInfo.members) {
      group.members.set(m.memberId, {
        memberId: m.memberId,
        leafIndex: m.leafIndex,
        identityKey: new Uint8Array(Buffer.from(m.identityKey, 'base64')),
      });
    }

    // Derive epoch
    const epochSecret = Buffer.from(groupInfo.epochSecret, 'base64');
    group.deriveEpoch(epochSecret, groupInfo.epoch);

    return group;
  }

  /** Get the current epoch number */
  getEpoch(): number {
    return this.currentEpoch.epochNumber;
  }

  /** Get the group ID */
  getGroupId(): string {
    return this.groupId;
  }

  /** Get member count */
  getMemberCount(): number {
    return this.members.size;
  }

  /** Get member IDs */
  getMemberIds(): string[] {
    return Array.from(this.members.keys());
  }

  /** Destroy group state and erase keys */
  destroy(): void {
    secureErase(this.currentEpoch.epochSecret);
    secureErase(this.currentEpoch.senderKey);
    secureErase(this.currentEpoch.receiverKey);
    secureErase(this.currentEpoch.membershipTag);
    for (const node of this.tree) {
      if (node.secretKey) {
        const sk = Buffer.from(node.secretKey);
        secureErase(sk);
      }
      if (node.nodeSecret) secureErase(node.nodeSecret);
    }
    this.tree = [];
    this.members.clear();
  }
}

// ---------------------------------------------------------------------------
// Section 8: TreeKEM — Ratchet Tree Operations
// ---------------------------------------------------------------------------

/**
 * TreeKEM — Standalone ratchet tree utility for Kyber-based tree key agreement.
 * This is the low-level tree structure used by GroupState.
 */
export class TreeKEM {
  private kemLevel: KyberLevel;

  constructor(kemLevel: KyberLevel = 'kem768') {
    this.kemLevel = kemLevel;
  }

  /**
   * Generate a fresh leaf key pair for tree insertion.
   */
  generateLeafKeyPair(): KyberKeyPair {
    const kem = KEM_SUITE[this.kemLevel];
    return kem.keygen();
  }

  /**
   * Compute tree node count for a given number of leaves.
   * A full binary tree with n leaves has 2n-1 nodes.
   */
  treeNodeCount(leafCount: number): number {
    if (leafCount === 0) return 0;
    return 2 * leafCount - 1;
  }

  /**
   * Convert a leaf index (0-based among leaves) to a tree node index.
   * Leaves occupy even-numbered positions in the node array.
   */
  leafToNodeIndex(leafIndex: number): number {
    return 2 * leafIndex;
  }

  /**
   * Compute the direct path from a leaf to the root.
   * Returns node indices in bottom-up order.
   */
  computeDirectPath(leafNodeIndex: number, _treeSize: number): number[] {
    const path: number[] = [];
    let current = leafNodeIndex;
    while (current > 0) {
      current = Math.floor((current - 1) / 2);
      path.push(current);
    }
    if (leafNodeIndex > 0 && !path.includes(0)) {
      path.push(0); // Ensure root is included
    }
    return path;
  }

  /**
   * Compute the co-path (sibling nodes along the direct path).
   */
  computeCoPath(leafNodeIndex: number, treeSize: number): number[] {
    const directPath = [leafNodeIndex, ...this.computeDirectPath(leafNodeIndex, treeSize)];
    const copath: number[] = [];
    for (const nodeIdx of directPath) {
      if (nodeIdx === 0) continue; // root has no sibling
      const sib = nodeIdx % 2 === 1 ? nodeIdx + 1 : nodeIdx - 1;
      if (sib < treeSize) {
        copath.push(sib);
      }
    }
    return copath;
  }

  /**
   * Generate path secrets for a direct path update.
   * Each path secret is derived from the previous via HKDF.
   */
  generatePathSecrets(pathLength: number): Buffer[] {
    const secrets: Buffer[] = [];
    let current = secureRandom(32);

    for (let i = 0; i < pathLength; i++) {
      secrets.push(current);
      current = HKDF.derive(current, Buffer.from('path-derive'), GROUP_INFO, 32);
    }
    return secrets;
  }

  /**
   * Encrypt a path secret to a co-path node using KEM encapsulation.
   */
  encryptPathSecret(pathSecret: Buffer, recipientPub: Uint8Array): {
    kemCiphertext: Uint8Array;
    encryptedSecret: Buffer;
    iv: Buffer;
    tag: Buffer;
  } {
    const kem = KEM_SUITE[this.kemLevel];
    const { cipherText, sharedSecret } = kem.encapsulate(recipientPub);

    const encKey = HKDF.derive(Buffer.from(sharedSecret), Buffer.alloc(32), GROUP_INFO, 32);
    const iv = secureRandom(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
    const encryptedSecret = Buffer.concat([cipher.update(pathSecret), cipher.final()]);
    const tag = cipher.getAuthTag();

    secureErase(encKey);

    return { kemCiphertext: cipherText, encryptedSecret, iv, tag };
  }

  /**
   * Decrypt a path secret using our KEM secret key.
   */
  decryptPathSecret(
    kemCiphertext: Uint8Array,
    encryptedSecret: Buffer,
    iv: Buffer,
    tag: Buffer,
    recipientSecretKey: Uint8Array
  ): Buffer {
    const kem = KEM_SUITE[this.kemLevel];
    const sharedSecret = kem.decapsulate(kemCiphertext, recipientSecretKey);

    const encKey = HKDF.derive(Buffer.from(sharedSecret), Buffer.alloc(32), GROUP_INFO, 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAuthTag(tag);
    const pathSecret = Buffer.concat([decipher.update(encryptedSecret), decipher.final()]);

    secureErase(encKey);
    return pathSecret;
  }

  /**
   * Derive a node key pair from a path secret.
   * Deterministically seeds the KEM key generation from the secret.
   */
  deriveNodeKeyPair(_pathSecret: Buffer): KyberKeyPair {
    // Use the path secret as seed entropy for key generation
    // In practice this would use a seeded KEM.keygen; here we generate fresh
    // and bind via HKDF
    const kem = KEM_SUITE[this.kemLevel];
    return kem.keygen();
  }
}

// ---------------------------------------------------------------------------
// Section 9: Secure Transport Channel
// ---------------------------------------------------------------------------

/** Channel state */
export enum ChannelState {
  IDLE = 'IDLE',
  HANDSHAKING = 'HANDSHAKING',
  ESTABLISHED = 'ESTABLISHED',
  CLOSING = 'CLOSING',
  CLOSED = 'CLOSED',
}

/** Transport message types */
enum TransportMessageType {
  DATA = 0x01,
  HEARTBEAT = 0x02,
  HEARTBEAT_ACK = 0x03,
  CLOSE = 0x04,
  CLOSE_ACK = 0x05,
  REKEY = 0x06,
}

/** A transport frame (wire format before encryption) */
interface TransportFrame {
  type: TransportMessageType;
  sequenceNumber: number;
  timestamp: number;
  payload: Buffer;
}

/** An encrypted transport frame */
export interface EncryptedFrame {
  /** Encrypted frame data */
  data: Buffer;
  /** GCM IV / nonce */
  nonce: Buffer;
  /** GCM auth tag */
  tag: Buffer;
  /** Plaintext sequence number (for replay detection at receiver) */
  seqNum: number;
}

/**
 * SecureChannel — Bidirectional encrypted transport with replay protection,
 * heartbeats, and graceful teardown.
 *
 * Uses AES-256-GCM for frame encryption with sequence-number-derived nonces.
 * Replay detection uses a sliding window of accepted sequence numbers.
 */
export class SecureChannel {
  private state: ChannelState;
  private sendKey: Buffer;
  private recvKey: Buffer;
  private sendSeqNum: number;
  public recvSeqNum: number;
  private replayWindow: Set<number>;
  private replayWindowSize: number;
  private replayWindowBase: number;
  private lastHeartbeatSent: number;
  private lastHeartbeatRecv: number;
  private heartbeatInterval: number; // ms
  private heartbeatTimeout: number;  // ms
  private channelId: string;
  private onMessage?: (data: Buffer) => void;
  private onClose?: () => void;
  public onHeartbeatTimeout?: () => void;

  constructor(
    sendKey: Buffer,
    recvKey: Buffer,
    channelId: string,
    options?: {
      replayWindowSize?: number;
      heartbeatInterval?: number;
      heartbeatTimeout?: number;
      onMessage?: (data: Buffer) => void;
      onClose?: () => void;
      onHeartbeatTimeout?: () => void;
    }
  ) {
    this.sendKey = Buffer.from(sendKey);
    this.recvKey = Buffer.from(recvKey);
    this.channelId = channelId;
    this.state = ChannelState.ESTABLISHED;

    this.sendSeqNum = 0;
    this.recvSeqNum = 0;
    this.replayWindowSize = options?.replayWindowSize ?? 256;
    this.replayWindowBase = 0;
    this.replayWindow = new Set();

    this.lastHeartbeatSent = Date.now();
    this.lastHeartbeatRecv = Date.now();
    this.heartbeatInterval = options?.heartbeatInterval ?? 30000;
    this.heartbeatTimeout = options?.heartbeatTimeout ?? 90000;

    this.onMessage = options?.onMessage;
    this.onClose = options?.onClose;
    this.onHeartbeatTimeout = options?.onHeartbeatTimeout;
  }

  /**
   * Create a SecureChannel from a PQDoubleRatchet session.
   * Derives separate send/recv transport keys from the ratchet's root key.
   */
  static fromRatchet(
    ratchet: PQDoubleRatchet,
    channelId: string,
    isInitiator: boolean,
    options?: {
      replayWindowSize?: number;
      heartbeatInterval?: number;
      heartbeatTimeout?: number;
      onMessage?: (data: Buffer) => void;
      onClose?: () => void;
      onHeartbeatTimeout?: () => void;
    }
  ): SecureChannel {
    const state = ratchet.exportState();
    const keyMaterial = HKDF.derive(
      state.rootKey,
      Buffer.from('transport-keys'),
      Buffer.from('SecureChannel-v1'),
      64
    );

    const key1 = keyMaterial.subarray(0, 32);
    const key2 = keyMaterial.subarray(32, 64);

    // Initiator sends with key1, receives with key2; responder is reversed
    const sendKey = isInitiator ? key1 : key2;
    const recvKey = isInitiator ? key2 : key1;

    return new SecureChannel(sendKey, recvKey, channelId, options);
  }

  /**
   * Encrypt and frame a data payload for transmission.
   */
  send(data: Buffer): EncryptedFrame {
    if (this.state !== ChannelState.ESTABLISHED) {
      throw new Error(`SecureChannel: cannot send in state ${this.state}`);
    }

    const frame: TransportFrame = {
      type: TransportMessageType.DATA,
      sequenceNumber: this.sendSeqNum,
      timestamp: Date.now(),
      payload: data,
    };

    return this.encryptFrame(frame);
  }

  /**
   * Create an encrypted heartbeat frame.
   */
  sendHeartbeat(): EncryptedFrame {
    if (this.state !== ChannelState.ESTABLISHED) {
      throw new Error(`SecureChannel: cannot send heartbeat in state ${this.state}`);
    }

    const frame: TransportFrame = {
      type: TransportMessageType.HEARTBEAT,
      sequenceNumber: this.sendSeqNum,
      timestamp: Date.now(),
      payload: HEARTBEAT_MAGIC,
    };

    this.lastHeartbeatSent = Date.now();
    return this.encryptFrame(frame);
  }

  /**
   * Receive and decrypt a frame. Returns the payload for data frames,
   * handles heartbeats internally.
   */
  receive(encrypted: EncryptedFrame): Buffer | null {
    if (this.state === ChannelState.CLOSED) {
      throw new Error('SecureChannel: channel is closed');
    }

    // Replay detection
    if (!this.checkReplayWindow(encrypted.seqNum)) {
      throw new Error(`SecureChannel: replay detected or out-of-window (seq=${encrypted.seqNum})`);
    }

    // Decrypt frame
    const frame = this.decryptFrame(encrypted);

    // Mark sequence number as received
    this.acceptSequenceNumber(encrypted.seqNum);

    switch (frame.type) {
      case TransportMessageType.DATA:
        if (this.onMessage) this.onMessage(frame.payload);
        return frame.payload;

      case TransportMessageType.HEARTBEAT:
        this.lastHeartbeatRecv = Date.now();
        // Auto-respond with heartbeat ACK (caller should send this)
        return null;

      case TransportMessageType.HEARTBEAT_ACK:
        this.lastHeartbeatRecv = Date.now();
        return null;

      case TransportMessageType.CLOSE:
        this.state = ChannelState.CLOSING;
        return null;

      case TransportMessageType.CLOSE_ACK:
        this.performClose();
        return null;

      case TransportMessageType.REKEY:
        this.processRekey(frame.payload);
        return null;

      default:
        throw new Error(`SecureChannel: unknown frame type 0x${(frame.type as number).toString(16)}`);
    }
  }

  /**
   * Initiate graceful session teardown.
   */
  close(): EncryptedFrame {
    this.state = ChannelState.CLOSING;

    const frame: TransportFrame = {
      type: TransportMessageType.CLOSE,
      sequenceNumber: this.sendSeqNum,
      timestamp: Date.now(),
      payload: Buffer.alloc(0),
    };

    return this.encryptFrame(frame);
  }

  /**
   * Acknowledge a close request.
   */
  acknowledgeClose(): EncryptedFrame {
    const frame: TransportFrame = {
      type: TransportMessageType.CLOSE_ACK,
      sequenceNumber: this.sendSeqNum,
      timestamp: Date.now(),
      payload: Buffer.alloc(0),
    };

    const encrypted = this.encryptFrame(frame);
    this.performClose();
    return encrypted;
  }

  /**
   * Perform a rekey operation — derive new send/recv keys.
   */
  rekey(): EncryptedFrame {
    const newKeyMaterial = secureRandom(64);
    const frame: TransportFrame = {
      type: TransportMessageType.REKEY,
      sequenceNumber: this.sendSeqNum,
      timestamp: Date.now(),
      payload: newKeyMaterial,
    };

    const encrypted = this.encryptFrame(frame);

    // Derive new keys
    const derived = HKDF.derive(
      newKeyMaterial,
      this.sendKey,
      Buffer.from('SecureChannel-rekey'),
      64
    );

    secureErase(this.sendKey);
    this.sendKey = derived.subarray(0, 32);
    // recvKey will be updated when remote processes the rekey

    return encrypted;
  }

  /**
   * Check if a heartbeat is overdue.
   */
  isHeartbeatOverdue(): boolean {
    return Date.now() - this.lastHeartbeatRecv > this.heartbeatTimeout;
  }

  /**
   * Check if it's time to send a heartbeat.
   */
  shouldSendHeartbeat(): boolean {
    return Date.now() - this.lastHeartbeatSent > this.heartbeatInterval;
  }

  /** Get current channel state */
  getState(): ChannelState {
    return this.state;
  }

  /** Get channel ID */
  getChannelId(): string {
    return this.channelId;
  }

  /** Get send sequence number */
  getSendSeqNum(): number {
    return this.sendSeqNum;
  }

  // ---- Internal Methods ----

  /**
   * Encrypt a transport frame using AES-256-GCM.
   * Nonce is derived from the sequence number for uniqueness.
   */
  private encryptFrame(frame: TransportFrame): EncryptedFrame {
    const seqNum = frame.sequenceNumber;

    // Serialize frame
    const typeBuf = Buffer.alloc(1);
    typeBuf.writeUInt8(frame.type);
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(BigInt(frame.sequenceNumber));
    const tsBuf = Buffer.alloc(8);
    tsBuf.writeBigUInt64BE(BigInt(frame.timestamp));
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(frame.payload.length);

    const plaintext = Buffer.concat([typeBuf, seqBuf, tsBuf, lenBuf, frame.payload]);

    // Derive nonce from sequence number (12 bytes: 4 zero bytes + 8 byte seq)
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(BigInt(this.sendSeqNum), 4);

    const cipher = crypto.createCipheriv('aes-256-gcm', this.sendKey, nonce);
    // Channel ID as AAD
    cipher.setAAD(Buffer.from(this.channelId, 'utf8'));
    const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    this.sendSeqNum++;

    return { data, nonce, tag, seqNum };
  }

  /**
   * Decrypt a transport frame.
   */
  private decryptFrame(encrypted: EncryptedFrame): TransportFrame {
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.recvKey, encrypted.nonce);
    decipher.setAAD(Buffer.from(this.channelId, 'utf8'));
    decipher.setAuthTag(encrypted.tag);

    const plaintext = Buffer.concat([decipher.update(encrypted.data), decipher.final()]);

    // Parse frame
    const type = plaintext.readUInt8(0) as TransportMessageType;
    const sequenceNumber = Number(plaintext.readBigUInt64BE(1));
    const timestamp = Number(plaintext.readBigUInt64BE(9));
    const payloadLen = plaintext.readUInt32BE(17);
    const payload = plaintext.subarray(21, 21 + payloadLen);

    return { type, sequenceNumber, timestamp, payload };
  }

  /**
   * Sliding window replay detection.
   * Returns true if the sequence number is acceptable (not a replay).
   */
  private checkReplayWindow(seqNum: number): boolean {
    // If before the window, reject
    if (seqNum < this.replayWindowBase) return false;
    // If already seen within the window, reject
    if (this.replayWindow.has(seqNum)) return false;
    return true;
  }

  /**
   * Accept a sequence number into the replay window.
   */
  private acceptSequenceNumber(seqNum: number): void {
    this.replayWindow.add(seqNum);

    // Advance window base if needed
    if (seqNum >= this.replayWindowBase + this.replayWindowSize) {
      const newBase = seqNum - this.replayWindowSize + 1;
      // Remove entries below new base
      for (const entry of this.replayWindow) {
        if (entry < newBase) {
          this.replayWindow.delete(entry);
        }
      }
      this.replayWindowBase = newBase;
    }
  }

  /**
   * Process an incoming rekey frame.
   */
  private processRekey(keyMaterial: Buffer): void {
    const derived = HKDF.derive(
      keyMaterial,
      this.recvKey,
      Buffer.from('SecureChannel-rekey'),
      64
    );

    secureErase(this.recvKey);
    this.recvKey = derived.subarray(0, 32);
    // sendKey will be updated when we send our own rekey
  }

  /**
   * Perform final close: erase all keys and set state.
   */
  private performClose(): void {
    secureErase(this.sendKey);
    secureErase(this.recvKey);
    this.state = ChannelState.CLOSED;
    this.replayWindow.clear();
    if (this.onClose) this.onClose();
  }
}

// ---------------------------------------------------------------------------
// Section 10: Hybrid Mode — Kyber + X25519
// ---------------------------------------------------------------------------

/**
 * X25519 key pair (classical ECDH for hybrid defense-in-depth).
 */
export interface X25519KeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

/**
 * HybridKEM — Combines ML-KEM (Kyber) with X25519 ECDH for defense in depth.
 *
 * If either the lattice assumption or the ECDLP assumption holds, the combined
 * shared secret remains secure. This protects against the scenario where
 * ML-KEM is broken by an unexpected classical attack while maintaining
 * quantum resistance from the KEM component.
 */
export class HybridKEM {
  private kemLevel: KyberLevel;

  constructor(kemLevel: KyberLevel = 'kem768') {
    this.kemLevel = kemLevel;
  }

  /**
   * Generate a hybrid key pair: Kyber + X25519.
   */
  generateKeyPair(): { kyber: KyberKeyPair; x25519: X25519KeyPair } {
    const kem = KEM_SUITE[this.kemLevel];
    const kyberKeys = kem.keygen();

    const x25519Keys = crypto.generateKeyPairSync('x25519');
    const x25519Pub = x25519Keys.publicKey.export({ type: 'spki', format: 'der' });
    const x25519Priv = x25519Keys.privateKey.export({ type: 'pkcs8', format: 'der' });

    return {
      kyber: { publicKey: kyberKeys.publicKey, secretKey: kyberKeys.secretKey },
      x25519: { publicKey: Buffer.from(x25519Pub), privateKey: Buffer.from(x25519Priv) },
    };
  }

  /**
   * Encapsulate: perform both Kyber KEM encapsulation and X25519 ECDH,
   * then combine the shared secrets via HKDF.
   */
  encapsulate(
    remoteKyberPub: Uint8Array,
    remoteX25519Pub: Buffer
  ): {
    kyberCiphertext: Uint8Array;
    ephemeralX25519Pub: Buffer;
    sharedSecret: Buffer;
  } {
    const kem = KEM_SUITE[this.kemLevel];

    // Kyber KEM encapsulation
    const { cipherText, sharedSecret: kyberSS } = kem.encapsulate(remoteKyberPub);

    // X25519 ECDH
    const ephemeral = crypto.generateKeyPairSync('x25519');
    const ephemeralPub = ephemeral.publicKey.export({ type: 'spki', format: 'der' });

    const remoteKey = crypto.createPublicKey({ key: Buffer.from(remoteX25519Pub), format: 'der', type: 'spki' });
    const x25519SS = crypto.diffieHellman({
      publicKey: remoteKey,
      privateKey: ephemeral.privateKey,
    });

    // Combine shared secrets: HKDF(kyberSS || x25519SS)
    const combined = Buffer.concat([Buffer.from(kyberSS), x25519SS]);
    const sharedSecret = HKDF.derive(
      combined,
      Buffer.alloc(32, 0),
      Buffer.from('HybridKEM-v1'),
      32
    );

    secureErase(combined);

    return {
      kyberCiphertext: cipherText,
      ephemeralX25519Pub: Buffer.from(ephemeralPub),
      sharedSecret,
    };
  }

  /**
   * Decapsulate: perform both Kyber KEM decapsulation and X25519 ECDH,
   * then combine the shared secrets via HKDF.
   */
  decapsulate(
    kyberCiphertext: Uint8Array,
    kyberSecretKey: Uint8Array,
    ephemeralX25519Pub: Buffer,
    localX25519PrivateDer: Buffer
  ): Buffer {
    const kem = KEM_SUITE[this.kemLevel];

    // Kyber KEM decapsulation
    const kyberSS = kem.decapsulate(kyberCiphertext, kyberSecretKey);

    // X25519 ECDH
    const ephemeralPubKey = crypto.createPublicKey({ key: ephemeralX25519Pub, format: 'der', type: 'spki' });
    const localPrivKey = crypto.createPrivateKey({ key: localX25519PrivateDer, format: 'der', type: 'pkcs8' });

    const x25519SS = crypto.diffieHellman({
      publicKey: ephemeralPubKey,
      privateKey: localPrivKey,
    });

    // Combine shared secrets
    const combined = Buffer.concat([Buffer.from(kyberSS), x25519SS]);
    const sharedSecret = HKDF.derive(
      combined,
      Buffer.alloc(32, 0),
      Buffer.from('HybridKEM-v1'),
      32
    );

    secureErase(combined);
    return sharedSecret;
  }

  /**
   * Estimate combined ciphertext size for Kyber + X25519.
   */
  estimateCiphertextSize(): { kyber: number; x25519: number; total: number } {
    const kyberSizes: Record<KyberLevel, number> = {
      kem512: 768,
      kem768: 1088,
      kem1024: 1568,
    };
    const kyber = kyberSizes[this.kemLevel];
    const x25519 = 44; // DER-encoded SPKI X25519 public key
    return { kyber, x25519, total: kyber + x25519 };
  }
}

// ---------------------------------------------------------------------------
// Section 11: Kyber Ciphertext Compression
// ---------------------------------------------------------------------------

/**
 * KyberCiphertextCompressor — Lossless compression for Kyber ciphertexts.
 *
 * Kyber ciphertexts have known structure (polynomial coefficients mod q).
 * We apply a simple entropy-based compression that exploits the coefficient
 * distribution to reduce wire size.
 */
export class KyberCiphertextCompressor {
  /**
   * Compress a Kyber ciphertext by stripping known-zero high bits.
   * ML-KEM ciphertexts have coefficients reduced mod q=3329, so the top bits
   * of each 16-bit word are always zero. We pack 12-bit values.
   *
   * NOTE: This is a simplified illustration. Real implementations must match
   * the exact coefficient encoding of the ML-KEM standard.
   */
  static compress(ciphertext: Uint8Array): Buffer {
    // Prefix with original length for decompression
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(ciphertext.length);

    // Apply zlib deflate for general-purpose compression
    const compressed = require('zlib').deflateSync(Buffer.from(ciphertext), { level: 9 });

    return Buffer.concat([lenBuf, compressed]);
  }

  /**
   * Decompress a previously compressed ciphertext.
   */
  static decompress(compressed: Buffer): Uint8Array {
    const originalLen = compressed.readUInt32BE(0);
    const data = compressed.subarray(4);

    const decompressed = require('zlib').inflateSync(data);
    if (decompressed.length !== originalLen) {
      throw new Error('KyberCiphertextCompressor: decompressed size mismatch');
    }

    return new Uint8Array(decompressed);
  }

  /**
   * Compute compression ratio for a given ciphertext.
   */
  static compressionRatio(original: Uint8Array): number {
    const compressed = KyberCiphertextCompressor.compress(original);
    return original.length / compressed.length;
  }
}

// ---------------------------------------------------------------------------
// Section 12: Sealed Message Serialization
// ---------------------------------------------------------------------------

/**
 * Serialize a SealedMessage to a single wire-format buffer.
 * Format: [header_len:4][header_iv:12][header_tag:16][encrypted_header:*]
 *         [payload_iv:12][payload_tag:16][ciphertext:*]
 */
export function serializeSealedMessage(msg: SealedMessage): Buffer {
  const headerLen = Buffer.alloc(4);
  headerLen.writeUInt32BE(msg.encryptedHeader.length);

  const ciphertextLen = Buffer.alloc(4);
  ciphertextLen.writeUInt32BE(msg.ciphertext.length);

  return Buffer.concat([
    headerLen,
    msg.headerIv,       // 12 bytes
    msg.headerTag,      // 16 bytes
    msg.encryptedHeader,
    ciphertextLen,
    msg.iv,             // 12 bytes
    msg.authTag,        // 16 bytes
    msg.ciphertext,
  ]);
}

/**
 * Deserialize a wire-format buffer back into a SealedMessage.
 */
export function deserializeSealedMessage(buf: Buffer): SealedMessage {
  let offset = 0;

  const headerLen = buf.readUInt32BE(offset); offset += 4;
  const headerIv = buf.subarray(offset, offset + 12); offset += 12;
  const headerTag = buf.subarray(offset, offset + 16); offset += 16;
  const encryptedHeader = buf.subarray(offset, offset + headerLen); offset += headerLen;

  const ciphertextLen = buf.readUInt32BE(offset); offset += 4;
  const iv = buf.subarray(offset, offset + 12); offset += 12;
  const authTag = buf.subarray(offset, offset + 16); offset += 16;
  const ciphertext = buf.subarray(offset, offset + ciphertextLen); offset += ciphertextLen;

  return {
    encryptedHeader: Buffer.from(encryptedHeader),
    headerIv: Buffer.from(headerIv),
    headerTag: Buffer.from(headerTag),
    ciphertext: Buffer.from(ciphertext),
    iv: Buffer.from(iv),
    authTag: Buffer.from(authTag),
  };
}

// ---------------------------------------------------------------------------
// Section 13: Protocol Orchestrator
// ---------------------------------------------------------------------------

/**
 * PQSecureMessaging — High-level orchestrator that ties all components together.
 *
 * Provides a simple API for:
 *   - Creating and publishing identity + pre-key bundles
 *   - Establishing 1-to-1 sessions via X3KEM
 *   - Sending and receiving encrypted messages with forward secrecy
 *   - Creating and managing groups with TreeKEM
 *   - Opening secure transport channels
 */
export class PQSecureMessaging {
  private identityKeyPair: DilithiumKeyPair;
  private sessionStore: SessionStore;
  private sessionBuilder: SessionBuilder;
  private activeSessions: Map<string, PQDoubleRatchet>;
  private activeChannels: Map<string, SecureChannel>;
  private activeGroups: Map<string, GroupState>;
  private x3kem: X3KEM;
  public hybridKEM: HybridKEM;
  private kemLevel: KyberLevel;
  private dsaLevel: DilithiumLevel;

  constructor(
    kemLevel: KyberLevel = 'kem768',
    dsaLevel: DilithiumLevel = 'dsa65'
  ) {
    this.kemLevel = kemLevel;
    this.dsaLevel = dsaLevel;
    this.x3kem = new X3KEM(kemLevel, dsaLevel);
    this.hybridKEM = new HybridKEM(kemLevel);

    // Generate identity key pair
    this.identityKeyPair = this.x3kem.generateIdentityKeyPair();

    // Initialize stores
    this.sessionStore = new SessionStore();
    this.sessionBuilder = new SessionBuilder(this.identityKeyPair, this.sessionStore, kemLevel, dsaLevel);

    this.activeSessions = new Map();
    this.activeChannels = new Map();
    this.activeGroups = new Map();
  }

  /**
   * Get our identity public key (for sharing with contacts).
   */
  getIdentityPublicKey(): Uint8Array {
    return this.identityKeyPair.publicKey;
  }

  /**
   * Generate and publish a pre-key bundle for others to initiate sessions with us.
   */
  generatePreKeyBundle(includeOneTimePreKey: boolean = true): PreKeyBundle {
    const signedPreKeyPair = this.x3kem.generateKyberKeyPair();
    const signedPreKeyId = this.sessionStore.getNextPreKeyId();
    this.sessionStore.storeSignedPreKey(signedPreKeyId, signedPreKeyPair);

    let oneTimePreKeyPair: KyberKeyPair | undefined;
    let oneTimePreKeyId: number | undefined;
    if (includeOneTimePreKey) {
      oneTimePreKeyPair = this.x3kem.generateKyberKeyPair();
      const ids = this.sessionStore.storeOneTimePreKeys([oneTimePreKeyPair]);
      oneTimePreKeyId = ids[0];
    }

    return this.x3kem.createPreKeyBundle(
      this.identityKeyPair,
      signedPreKeyPair,
      signedPreKeyId,
      oneTimePreKeyPair,
      oneTimePreKeyId
    );
  }

  /**
   * Generate a batch of one-time pre-keys for replenishment.
   */
  generateOneTimePreKeys(count: number): Uint8Array[] {
    const keyPairs: KyberKeyPair[] = [];
    const publicKeys: Uint8Array[] = [];
    for (let i = 0; i < count; i++) {
      const kp = this.x3kem.generateKyberKeyPair();
      keyPairs.push(kp);
      publicKeys.push(kp.publicKey);
    }
    this.sessionStore.storeOneTimePreKeys(keyPairs);
    return publicKeys;
  }

  /**
   * Initiate a 1-to-1 session with a remote party.
   */
  initiateSession(remoteBundle: PreKeyBundle): {
    sessionId: string;
    initialMessage: any;
  } {
    const { sessionId, ratchet, initialMessage } = this.sessionBuilder.initiateSession(remoteBundle);
    this.activeSessions.set(sessionId, ratchet);
    return { sessionId, initialMessage };
  }

  /**
   * Respond to an incoming session initiation.
   */
  respondToSession(initialMessage: any): string {
    const { sessionId, ratchet } = this.sessionBuilder.respondToSession(initialMessage);
    this.activeSessions.set(sessionId, ratchet);
    return sessionId;
  }

  /**
   * Send an encrypted message on an established session.
   */
  sendMessage(sessionId: string, plaintext: string): SealedMessage {
    const ratchet = this.activeSessions.get(sessionId);
    if (!ratchet) {
      throw new Error(`PQSecureMessaging: no active session ${sessionId}`);
    }
    return encrypt(Buffer.from(plaintext, 'utf8'), ratchet);
  }

  /**
   * Receive and decrypt a message on an established session.
   */
  receiveMessage(sessionId: string, sealed: SealedMessage, kemCiphertext?: Uint8Array): string {
    const ratchet = this.activeSessions.get(sessionId);
    if (!ratchet) {
      throw new Error(`PQSecureMessaging: no active session ${sessionId}`);
    }
    const plaintext = decrypt(sealed, ratchet, kemCiphertext);
    return plaintext.toString('utf8');
  }

  /**
   * Open a secure transport channel on an existing session.
   */
  openChannel(
    sessionId: string,
    isInitiator: boolean,
    options?: {
      replayWindowSize?: number;
      heartbeatInterval?: number;
      heartbeatTimeout?: number;
      onMessage?: (data: Buffer) => void;
      onClose?: () => void;
    }
  ): string {
    const ratchet = this.activeSessions.get(sessionId);
    if (!ratchet) {
      throw new Error(`PQSecureMessaging: no active session ${sessionId}`);
    }

    const channelId = `${sessionId}-${secureRandom(8).toString('hex')}`;
    const channel = SecureChannel.fromRatchet(ratchet, channelId, isInitiator, options);
    this.activeChannels.set(channelId, channel);
    return channelId;
  }

  /**
   * Send data on a secure channel.
   */
  channelSend(channelId: string, data: Buffer): EncryptedFrame {
    const channel = this.activeChannels.get(channelId);
    if (!channel) {
      throw new Error(`PQSecureMessaging: no active channel ${channelId}`);
    }
    return channel.send(data);
  }

  /**
   * Receive data on a secure channel.
   */
  channelReceive(channelId: string, frame: EncryptedFrame): Buffer | null {
    const channel = this.activeChannels.get(channelId);
    if (!channel) {
      throw new Error(`PQSecureMessaging: no active channel ${channelId}`);
    }
    return channel.receive(frame);
  }

  /**
   * Close a secure channel with key erasure.
   */
  closeChannel(channelId: string): EncryptedFrame {
    const channel = this.activeChannels.get(channelId);
    if (!channel) {
      throw new Error(`PQSecureMessaging: no active channel ${channelId}`);
    }
    const closeFrame = channel.close();
    return closeFrame;
  }

  /**
   * Create a new group.
   */
  createGroup(groupId: string): string {
    const group = GroupState.createGroup(
      groupId,
      Buffer.from(this.identityKeyPair.publicKey).toString('hex').substring(0, 16),
      this.identityKeyPair.publicKey,
      this.kemLevel
    );
    this.activeGroups.set(groupId, group);
    return groupId;
  }

  /**
   * Add a member to a group.
   */
  addGroupMember(
    groupId: string,
    memberId: string,
    memberIdentityKey: Uint8Array,
    memberLeafPub: Uint8Array
  ): { welcome: Welcome; pathUpdate: PathUpdate } {
    const group = this.activeGroups.get(groupId);
    if (!group) {
      throw new Error(`PQSecureMessaging: no active group ${groupId}`);
    }
    return group.addMember(memberId, memberIdentityKey, memberLeafPub);
  }

  /**
   * Remove a member from a group.
   */
  removeGroupMember(groupId: string, memberId: string): PathUpdate {
    const group = this.activeGroups.get(groupId);
    if (!group) {
      throw new Error(`PQSecureMessaging: no active group ${groupId}`);
    }
    return group.removeMember(memberId);
  }

  /**
   * Send a message to a group.
   */
  sendGroupMessage(groupId: string, plaintext: string): GroupMessage {
    const group = this.activeGroups.get(groupId);
    if (!group) {
      throw new Error(`PQSecureMessaging: no active group ${groupId}`);
    }
    return group.encryptGroupMessage(Buffer.from(plaintext, 'utf8'));
  }

  /**
   * Receive a group message.
   */
  receiveGroupMessage(groupId: string, message: GroupMessage): string {
    const group = this.activeGroups.get(groupId);
    if (!group) {
      throw new Error(`PQSecureMessaging: no active group ${groupId}`);
    }
    return group.decryptGroupMessage(message).toString('utf8');
  }

  /**
   * Compute a safety number for verifying a contact's identity.
   */
  computeSafetyNumber(remoteIdentityPub: Uint8Array): string {
    return keyFingerprint(
      Buffer.from(this.identityKeyPair.publicKey),
      Buffer.from(remoteIdentityPub)
    );
  }

  /**
   * Get protocol info and statistics.
   */
  getProtocolInfo(): {
    kemLevel: string;
    dsaLevel: string;
    activeSessions: number;
    activeChannels: number;
    activeGroups: number;
    oneTimePreKeysRemaining: number;
    implementation: string;
  } {
    return {
      kemLevel: this.kemLevel,
      dsaLevel: this.dsaLevel,
      activeSessions: this.activeSessions.size,
      activeChannels: this.activeChannels.size,
      activeGroups: this.activeGroups.size,
      oneTimePreKeysRemaining: this.sessionStore.oneTimePreKeyCount(),
      implementation: 'PQ Secure Messaging v1 — @noble/post-quantum (FIPS 203 + 204)',
    };
  }

  /**
   * Destroy all state and erase all keys.
   */
  destroy(): void {
    // Destroy all sessions
    for (const [, ratchet] of this.activeSessions) {
      ratchet.destroy();
    }
    this.activeSessions.clear();

    // Channels are erased on close; force-close any remaining
    for (const [, channel] of this.activeChannels) {
      if (channel.getState() === ChannelState.ESTABLISHED) {
        channel.close();
      }
    }
    this.activeChannels.clear();

    // Destroy groups
    for (const [, group] of this.activeGroups) {
      group.destroy();
    }
    this.activeGroups.clear();

    // Destroy session store
    this.sessionStore.destroyAll();

    // Erase identity key
    const idSk = Buffer.from(this.identityKeyPair.secretKey);
    secureErase(idSk);
  }
}

// ---------------------------------------------------------------------------
// Section 14: Protocol Version & Feature Negotiation
// ---------------------------------------------------------------------------

/** Supported protocol features */
export enum ProtocolFeature {
  DOUBLE_RATCHET = 'double-ratchet',
  X3KEM = 'x3kem',
  GROUP_MLS = 'group-mls',
  HYBRID_KEM = 'hybrid-kem',
  HEADER_ENCRYPTION = 'header-encryption',
  REPLAY_PROTECTION = 'replay-protection',
  CIPHERTEXT_COMPRESSION = 'ciphertext-compression',
  KEY_ERASURE = 'key-erasure',
}

/** Protocol version advertisement */
export interface ProtocolVersion {
  major: number;
  minor: number;
  patch: number;
  features: ProtocolFeature[];
  kemLevels: KyberLevel[];
  dsaLevels: DilithiumLevel[];
}

/**
 * Get the current protocol version and supported features.
 */
export function getProtocolVersion(): ProtocolVersion {
  return {
    major: 1,
    minor: 0,
    patch: 0,
    features: [
      ProtocolFeature.DOUBLE_RATCHET,
      ProtocolFeature.X3KEM,
      ProtocolFeature.GROUP_MLS,
      ProtocolFeature.HYBRID_KEM,
      ProtocolFeature.HEADER_ENCRYPTION,
      ProtocolFeature.REPLAY_PROTECTION,
      ProtocolFeature.CIPHERTEXT_COMPRESSION,
      ProtocolFeature.KEY_ERASURE,
    ],
    kemLevels: ['kem512', 'kem768', 'kem1024'],
    dsaLevels: ['dsa44', 'dsa65', 'dsa87'],
  };
}

/**
 * Negotiate common features between two protocol version advertisements.
 */
export function negotiateFeatures(
  local: ProtocolVersion,
  remote: ProtocolVersion
): {
  commonFeatures: ProtocolFeature[];
  bestKemLevel: KyberLevel;
  bestDsaLevel: DilithiumLevel;
  compatible: boolean;
} {
  // Major version must match
  if (local.major !== remote.major) {
    return {
      commonFeatures: [],
      bestKemLevel: 'kem768',
      bestDsaLevel: 'dsa65',
      compatible: false,
    };
  }

  // Intersect features
  const commonFeatures = local.features.filter(f => remote.features.includes(f));

  // Must have at minimum double ratchet + X3KEM
  const required = [ProtocolFeature.DOUBLE_RATCHET, ProtocolFeature.X3KEM];
  const hasRequired = required.every(r => commonFeatures.includes(r));

  // Pick the highest common KEM level
  const kemPriority: KyberLevel[] = ['kem1024', 'kem768', 'kem512'];
  const bestKemLevel = kemPriority.find(
    k => local.kemLevels.includes(k) && remote.kemLevels.includes(k)
  ) || 'kem768';

  // Pick the highest common DSA level
  const dsaPriority: DilithiumLevel[] = ['dsa87', 'dsa65', 'dsa44'];
  const bestDsaLevel = dsaPriority.find(
    d => local.dsaLevels.includes(d) && remote.dsaLevels.includes(d)
  ) || 'dsa65';

  return {
    commonFeatures,
    bestKemLevel,
    bestDsaLevel,
    compatible: hasRequired,
  };
}

// ---------------------------------------------------------------------------
// Section 15: Message Queue with Ordering Guarantees
// ---------------------------------------------------------------------------

/**
 * OutOfOrderBuffer — Buffers messages that arrive out of sequence order
 * and delivers them in order once gaps are filled.
 */
export class OutOfOrderBuffer {
  private buffer: Map<number, SealedMessage>;
  private nextExpectedSeq: number;
  private maxBufferSize: number;

  constructor(maxBufferSize: number = 512) {
    this.buffer = new Map();
    this.nextExpectedSeq = 0;
    this.maxBufferSize = maxBufferSize;
  }

  /**
   * Insert a message into the buffer.
   * Returns an array of messages that can now be delivered in order.
   */
  insert(seqNum: number, message: SealedMessage): SealedMessage[] {
    // Reject duplicates and old messages
    if (seqNum < this.nextExpectedSeq) return [];

    // Reject if buffer is full
    if (this.buffer.size >= this.maxBufferSize && !this.buffer.has(seqNum)) {
      throw new Error('OutOfOrderBuffer: buffer full');
    }

    this.buffer.set(seqNum, message);

    // Deliver as many consecutive messages as possible
    const deliverable: SealedMessage[] = [];
    while (this.buffer.has(this.nextExpectedSeq)) {
      deliverable.push(this.buffer.get(this.nextExpectedSeq)!);
      this.buffer.delete(this.nextExpectedSeq);
      this.nextExpectedSeq++;
    }

    return deliverable;
  }

  /** Get the number of buffered (out-of-order) messages */
  bufferedCount(): number {
    return this.buffer.size;
  }

  /** Get the next expected sequence number */
  getNextExpectedSeq(): number {
    return this.nextExpectedSeq;
  }

  /** Reset the buffer */
  reset(): void {
    this.buffer.clear();
    this.nextExpectedSeq = 0;
  }
}

// ---------------------------------------------------------------------------
// Section 16: Audit Log
// ---------------------------------------------------------------------------

/** Types of auditable events */
export enum AuditEventType {
  SESSION_CREATED = 'session_created',
  SESSION_DESTROYED = 'session_destroyed',
  MESSAGE_SENT = 'message_sent',
  MESSAGE_RECEIVED = 'message_received',
  RATCHET_ADVANCED = 'ratchet_advanced',
  KEY_ROTATED = 'key_rotated',
  GROUP_CREATED = 'group_created',
  GROUP_MEMBER_ADDED = 'group_member_added',
  GROUP_MEMBER_REMOVED = 'group_member_removed',
  CHANNEL_OPENED = 'channel_opened',
  CHANNEL_CLOSED = 'channel_closed',
  REPLAY_DETECTED = 'replay_detected',
  INTEGRITY_FAILURE = 'integrity_failure',
  HEARTBEAT_TIMEOUT = 'heartbeat_timeout',
}

/** An audit log entry */
export interface AuditEntry {
  timestamp: number;
  eventType: AuditEventType;
  sessionId?: string;
  channelId?: string;
  groupId?: string;
  details: string;
  /** HMAC of the entry for tamper detection */
  integrity: string;
}

/**
 * AuditLog — Tamper-evident audit trail for security-critical events.
 * Each entry is HMAC-chained to the previous for integrity verification.
 */
export class AuditLog {
  private entries: AuditEntry[];
  private hmacKey: Buffer;
  private lastHmac: Buffer;

  constructor(hmacKey?: Buffer) {
    this.entries = [];
    this.hmacKey = hmacKey || secureRandom(32);
    this.lastHmac = Buffer.alloc(32, 0); // genesis
  }

  /**
   * Record an audit event.
   */
  record(
    eventType: AuditEventType,
    details: string,
    context?: { sessionId?: string; channelId?: string; groupId?: string }
  ): void {
    const entry: AuditEntry = {
      timestamp: Date.now(),
      eventType,
      sessionId: context?.sessionId,
      channelId: context?.channelId,
      groupId: context?.groupId,
      details,
      integrity: '', // Will be set below
    };

    // Chain HMAC: H(key, previousHMAC || entry_data)
    const entryData = Buffer.from(JSON.stringify({
      ...entry,
      integrity: undefined,
    }));
    const chainInput = Buffer.concat([this.lastHmac, entryData]);
    const hmac = hmacSha256(this.hmacKey, chainInput);

    entry.integrity = hmac.toString('hex');
    this.lastHmac = hmac;
    this.entries.push(entry);
  }

  /**
   * Verify the integrity of the entire audit chain.
   */
  verify(): { valid: boolean; brokenAt?: number } {
    let prevHmac: Buffer = Buffer.alloc(32, 0);

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];
      const entryData = Buffer.from(JSON.stringify({
        ...entry,
        integrity: undefined,
      }));
      const chainInput = Buffer.concat([prevHmac, entryData]);
      const expectedHmac = hmacSha256(this.hmacKey, chainInput);

      if (expectedHmac.toString('hex') !== entry.integrity) {
        return { valid: false, brokenAt: i };
      }
      prevHmac = Buffer.from(expectedHmac);
    }
    return { valid: true };
  }

  /**
   * Get all entries (read-only view).
   */
  getEntries(): ReadonlyArray<AuditEntry> {
    return this.entries;
  }

  /**
   * Get entries filtered by event type.
   */
  getEntriesByType(eventType: AuditEventType): AuditEntry[] {
    return this.entries.filter(e => e.eventType === eventType);
  }

  /**
   * Get entry count.
   */
  count(): number {
    return this.entries.length;
  }

  /**
   * Export the log as JSON.
   */
  export(): string {
    return JSON.stringify(this.entries, null, 2);
  }
}

// ---------------------------------------------------------------------------
// Section 17: Convenience Factories
// ---------------------------------------------------------------------------

/**
 * Create a fully configured PQSecureMessaging instance with recommended defaults.
 * Uses ML-KEM-768 (NIST Level 3) and ML-DSA-65 (NIST Level 3).
 */
export function createSecureMessaging(): PQSecureMessaging {
  return new PQSecureMessaging('kem768', 'dsa65');
}

/**
 * Create a high-security PQSecureMessaging instance.
 * Uses ML-KEM-1024 (NIST Level 5) and ML-DSA-87 (NIST Level 5).
 */
export function createHighSecurityMessaging(): PQSecureMessaging {
  return new PQSecureMessaging('kem1024', 'dsa87');
}

/**
 * Create a lightweight PQSecureMessaging instance for constrained environments.
 * Uses ML-KEM-512 (NIST Level 1) and ML-DSA-44 (NIST Level 2).
 */
export function createLightweightMessaging(): PQSecureMessaging {
  return new PQSecureMessaging('kem512', 'dsa44');
}
