import { Logger } from 'winston';
import NodeCache from 'node-cache';
import * as crypto from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3.js';
import {
  hybridSignKeypair, hybridSign, hybridVerify,
  hybridKemKeypair, hybridKemEncapsulate, hybridKemDecapsulate,
  concatBytes,
} from './hybrid-pqc.js';
import { b64, ub, utf8, stableStringify } from './canonical.js';

/**
 * Agent-native quantum-safe identity, attestations, and channels.
 *
 * The differentiator for an MCP-resident crypto server: its users are AI agents.
 * This gives each agent a portable hybrid identity, lets it issue tamper-evident
 * signed attestations of its actions (e.g. "agent X authorized payment Y at T"),
 * and lets two agents establish an end-to-end encrypted channel using a hybrid
 * (X-Wing) KEM handshake. All signatures are hybrid (Ed25519 + ML-DSA-65).
 */
export class AgentIdentityHandler {
  constructor(
    private logger: Logger,
    _cache: NodeCache,
  ) {}

  private json(obj: any) {
    return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
  }

  /** Mint a new agent identity: hybrid signing + hybrid KEM key material. */
  async createIdentity(_params: any) {
    const sig = hybridSignKeypair();
    const kem = hybridKemKeypair();
    const agentId = Buffer.from(sha3_256(concatBytes(sig.publicKey, kem.publicKey)))
      .toString('hex')
      .slice(0, 32);
    this.logger.info(`Created agent identity ${agentId}`);
    return this.json({
      agentId,
      sigPublicKey: b64(sig.publicKey),
      kemPublicKey: b64(kem.publicKey),
      secretBundle: { sigPrivateKey: b64(sig.secretKey), kemPrivateKey: b64(kem.secretKey) },
      schemes: { signature: 'Ed25519+ML-DSA-65', kem: 'X-Wing (X25519+ML-KEM-768)' },
      created: new Date().toISOString(),
    });
  }

  /** Issue a signed, timestamped attestation of an action. */
  async attest(params: any) {
    const { sigPrivateKey, agentId = '', action } = params ?? {};
    if (action === undefined) throw new Error('attest: "action" is required');
    const attestation = {
      agentId,
      action,
      timestamp: new Date().toISOString(),
      nonce: b64(new Uint8Array(crypto.randomBytes(16))),
    };
    const signature = hybridSign(ub(sigPrivateKey), utf8(stableStringify(attestation)));
    this.logger.info(`Signed attestation for agent ${agentId || '(anon)'}`);
    return this.json({ attestation, signature: b64(signature), scheme: 'Ed25519+ML-DSA-65' });
  }

  /** Verify an attestation against an agent's signing public key. */
  async verifyAttestation(params: any) {
    const { sigPublicKey, attestation, signature } = params ?? {};
    let r = { edValid: false, pqValid: false, valid: false };
    try {
      r = hybridVerify(ub(sigPublicKey), utf8(stableStringify(attestation)), ub(signature));
    } catch (error) {
      this.logger.warn(`Attestation verification rejected malformed input: ${error instanceof Error ? error.message : String(error)}`);
    }
    return this.json({ valid: r.valid, components: { ed25519: r.edValid, 'ml-dsa-65': r.pqValid }, attestation });
  }

  /** Initiator: open a channel to a peer's KEM public key (X-Wing encapsulation). */
  async channelOpen(params: any) {
    const { peerKemPublicKey } = params ?? {};
    const { ciphertext, sharedSecret } = hybridKemEncapsulate(ub(peerKemPublicKey));
    return this.json({
      ciphertext: b64(ciphertext),
      channelKey: b64(sharedSecret),
      note: 'Send ciphertext to the peer; keep channelKey secret. Use agent-channel-message to encrypt/decrypt.',
    });
  }

  /** Responder: accept a channel using the KEM private key + the initiator ciphertext. */
  async channelAccept(params: any) {
    const { kemPrivateKey, ciphertext } = params ?? {};
    const sharedSecret = hybridKemDecapsulate(ub(kemPrivateKey), ub(ciphertext));
    return this.json({ channelKey: b64(sharedSecret) });
  }

  /** AES-256-GCM over a channel key. direction = encrypt | decrypt. */
  async channelMessage(params: any) {
    const { direction, channelKey, data, iv, authTag } = params ?? {};
    const key = Buffer.from(ub(channelKey));
    if (key.length !== 32) throw new Error('channelKey must be 32 bytes');

    if (direction === 'encrypt') {
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
      const ct = Buffer.concat([cipher.update(Buffer.from(String(data), 'utf8')), cipher.final()]);
      return this.json({
        direction,
        ciphertext: ct.toString('base64'),
        iv: nonce.toString('base64'),
        authTag: cipher.getAuthTag().toString('base64'),
      });
    }
    if (direction === 'decrypt') {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
      decipher.setAuthTag(Buffer.from(authTag, 'base64'));
      const pt = Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]);
      return this.json({ direction, plaintext: pt.toString('utf8') });
    }
    throw new Error("direction must be 'encrypt' or 'decrypt'");
  }
}
