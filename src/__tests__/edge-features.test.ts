/**
 * Tests for the differentiating edge features:
 * agent identity + attestations + E2E channels, code/SBOM signing,
 * and the crypto-agility advisor. Includes the failure cases for each.
 */
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { AgentIdentityHandler } from '../utils/agent-identity';
import { CodeSigningHandler } from '../utils/code-signing';
import { CryptoAgilityHandler } from '../utils/crypto-agility';

const log = (): Logger => ({ info: jest.fn(), error: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any);
const body = (r: any) => JSON.parse(r.content[0].text);
let cache: NodeCache;
beforeEach(() => { cache = new NodeCache(); });

describe('Agent identity, attestations & channels', () => {
  let h: AgentIdentityHandler;
  beforeEach(() => { h = new AgentIdentityHandler(log(), cache); });

  it('creates an identity with an id, hybrid sign + KEM keys', async () => {
    const id = body(await h.createIdentity({}));
    expect(id.agentId).toMatch(/^[0-9a-f]{32}$/);
    expect(id.sigPublicKey).toBeDefined();
    expect(id.kemPublicKey).toBeDefined();
    expect(id.secretBundle.sigPrivateKey).toBeDefined();
  });

  it('attest -> verify is valid; tampering and wrong key are rejected', async () => {
    const id = body(await h.createIdentity({}));
    const att = body(await h.attest({ sigPrivateKey: id.secretBundle.sigPrivateKey, agentId: id.agentId, action: { type: 'authorize-payment', amount: 100 } }));
    const ok = body(await h.verifyAttestation({ sigPublicKey: id.sigPublicKey, attestation: att.attestation, signature: att.signature }));
    expect(ok.valid).toBe(true);

    const tampered = { ...att.attestation, action: { type: 'authorize-payment', amount: 999999 } };
    const bad = body(await h.verifyAttestation({ sigPublicKey: id.sigPublicKey, attestation: tampered, signature: att.signature }));
    expect(bad.valid).toBe(false);

    const other = body(await h.createIdentity({}));
    const wrongKey = body(await h.verifyAttestation({ sigPublicKey: other.sigPublicKey, attestation: att.attestation, signature: att.signature }));
    expect(wrongKey.valid).toBe(false);
  });

  it('establishes a shared channel key and round-trips an encrypted message', async () => {
    const peer = body(await h.createIdentity({}));
    const opened = body(await h.channelOpen({ peerKemPublicKey: peer.kemPublicKey }));
    const accepted = body(await h.channelAccept({ kemPrivateKey: peer.secretBundle.kemPrivateKey, ciphertext: opened.ciphertext }));
    expect(accepted.channelKey).toBe(opened.channelKey);

    const enc = body(await h.channelMessage({ direction: 'encrypt', channelKey: opened.channelKey, data: 'hello agent' }));
    const dec = body(await h.channelMessage({ direction: 'decrypt', channelKey: accepted.channelKey, data: enc.ciphertext, iv: enc.iv, authTag: enc.authTag }));
    expect(dec.plaintext).toBe('hello agent');
  });

  it('rejects a tampered channel ciphertext (AEAD)', async () => {
    const peer = body(await h.createIdentity({}));
    const opened = body(await h.channelOpen({ peerKemPublicKey: peer.kemPublicKey }));
    const enc = body(await h.channelMessage({ direction: 'encrypt', channelKey: opened.channelKey, data: 'secret' }));
    const ct = Buffer.from(enc.ciphertext, 'base64');
    ct[0] ^= 0xff;
    await expect(h.channelMessage({ direction: 'decrypt', channelKey: opened.channelKey, data: ct.toString('base64'), iv: enc.iv, authTag: enc.authTag })).rejects.toThrow();
  });
});

describe('Quantum-safe code/SBOM signing', () => {
  let cs: CodeSigningHandler;
  let agents: AgentIdentityHandler;
  let signer: any;
  beforeEach(async () => {
    cs = new CodeSigningHandler(log(), cache);
    agents = new AgentIdentityHandler(log(), cache);
    signer = body(await agents.createIdentity({}));
  });

  it('signs an artifact and verifies it (signature + digest)', async () => {
    const signed = body(await cs.signArtifact({ privateKey: signer.secretBundle.sigPrivateKey, artifact: 'v1.0.0 release bytes', metadata: { project: 'pqmcp' } }));
    expect(signed.artifactDigest).toMatch(/^[0-9a-f]{64}$/);
    const ok = body(await cs.verifyArtifact({ publicKey: signer.sigPublicKey, signedArtifact: signed, artifact: 'v1.0.0 release bytes' }));
    expect(ok.valid).toBe(true);
    expect(ok.digestMatch).toBe(true);
  });

  it('detects a modified artifact (digest mismatch)', async () => {
    const signed = body(await cs.signArtifact({ privateKey: signer.secretBundle.sigPrivateKey, artifact: 'original' }));
    const res = body(await cs.verifyArtifact({ publicKey: signer.sigPublicKey, signedArtifact: signed, artifact: 'modified' }));
    expect(res.valid).toBe(false);
    expect(res.digestMatch).toBe(false);
  });

  it('rejects verification under the wrong public key', async () => {
    const signed = body(await cs.signArtifact({ privateKey: signer.secretBundle.sigPrivateKey, digest: 'a'.repeat(64) }));
    const other = body(await agents.createIdentity({}));
    const res = body(await cs.verifyArtifact({ publicKey: other.sigPublicKey, signedArtifact: signed }));
    expect(res.valid).toBe(false);
    expect(res.signatureValid).toBe(false);
  });
});

describe('Crypto-agility advisor', () => {
  let ca: CryptoAgilityHandler;
  beforeEach(() => { ca = new CryptoAgilityHandler(log(), cache); });

  it('flags HNDL risk for long-lived data under vulnerable key exchange', async () => {
    const r = body(await ca.assess({ currentAlgorithms: ['RSA-2048', 'ECDH', 'AES-128', 'SHA-256'], dataSensitivity: 'high', dataLifetimeYears: 25 }));
    expect(r.summary.quantumVulnerable).toBeGreaterThanOrEqual(3);
    expect(['high', 'critical']).toContain(r.summary.harvestNowDecryptLaterRisk);
    expect(r.recommendedPlan.length).toBeGreaterThan(0);
    // RSA key exchange should map to a hybrid X-Wing recommendation.
    const rsa = r.findings.find((f: any) => /rsa/i.test(f.algorithm));
    expect(rsa.recommendation).toMatch(/X-Wing/);
  });

  it('treats AES-256 / SHA-384 as quantum-safe (no HNDL when no vulnerable KEX)', async () => {
    const r = body(await ca.assess({ currentAlgorithms: ['AES-256', 'SHA-384'], dataLifetimeYears: 30 }));
    expect(r.summary.harvestNowDecryptLaterRisk).toBe('none');
    expect(r.summary.quantumVulnerable).toBe(0);
  });

  it('rejects an empty algorithm list', async () => {
    await expect(ca.assess({ currentAlgorithms: [] })).rejects.toThrow();
  });
});
