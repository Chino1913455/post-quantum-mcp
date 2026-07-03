#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

import { createLogger, format, transports } from 'winston';
import NodeCache from 'node-cache';

// Import all post-quantum algorithm handlers
import { KyberHandler } from './algorithms/kyber.js';
import { DilithiumHandler } from './algorithms/dilithium.js';
import { SphincsPlusHandler } from './algorithms/sphincs.js';
import { FalconHandler } from './algorithms/falcon.js';

// Utility handlers
import { HybridCryptoHandler } from './utils/hybrid.js';
import { KeyManagementHandler } from './utils/keymanagement.js';
import { QuantumRandomHandler } from './utils/quantum-random.js';
import { BenchmarkHandler } from './utils/benchmark.js';
import { SecurityAnalyzer } from './utils/security-analyzer.js';
import { HybridPQCHandler } from './utils/hybrid-pqc.js';
import { AgentIdentityHandler } from './utils/agent-identity.js';
import { CodeSigningHandler } from './utils/code-signing.js';
import { CryptoAgilityHandler } from './utils/crypto-agility.js';
import { ThresholdCustodyHandler } from './utils/threshold-custody.js';
import { PQJwtHandler } from './utils/pq-jwt.js';
import { PQEncryptHandler } from './utils/pq-encrypt.js';
import { PQCertificateHandler } from './utils/pq-certificate.js';
import { entropyToolsHandler } from './utils/entropy-tools.js';

// Configure logger
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.splat(),
    format.json()
  ),
  // MCP speaks JSON-RPC over stdout; ALL logs MUST go to stderr or they corrupt
  // the protocol stream. File logging is opt-in (LOG_FILE) so running via npx
  // does not write log files into the user's working directory.
  transports: [
    new transports.Console({
      stderrLevels: ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'],
      format: format.combine(format.colorize(), format.simple()),
    }),
    ...(process.env.LOG_FILE ? [new transports.File({ filename: process.env.LOG_FILE })] : []),
  ],
});

// Initialize cache for performance
const cache = new NodeCache({
  stdTTL: 600, // 10 minutes default TTL
  checkperiod: 120, // Check for expired keys every 2 minutes
});

// Algorithm handlers
const kyberHandler = new KyberHandler(logger, cache);
const dilithiumHandler = new DilithiumHandler(logger, cache);
const sphincsHandler = new SphincsPlusHandler(logger, cache);
const falconHandler = new FalconHandler(logger, cache);
// Utility handlers
const hybridHandler = new HybridCryptoHandler(logger, cache);
const keyMgmtHandler = new KeyManagementHandler(logger, cache);
const quantumRngHandler = new QuantumRandomHandler(logger, cache);
const benchmarkHandler = new BenchmarkHandler(logger, cache);
const securityAnalyzer = new SecurityAnalyzer(logger, cache);
const hybridPqc = new HybridPQCHandler(logger, cache);
const agentIdentity = new AgentIdentityHandler(logger, cache);
const codeSigning = new CodeSigningHandler(logger, cache);
const cryptoAgility = new CryptoAgilityHandler(logger, cache);
const thresholdCustody = new ThresholdCustodyHandler(logger, cache);
const pqJwt = new PQJwtHandler(logger, cache);
const pqEncrypt = new PQEncryptHandler(logger, cache);
const pqCert = new PQCertificateHandler(logger, cache);

// Define all available tools
const TOOLS = {
  // Key Encapsulation Mechanisms (KEMs)
  'kyber-keygen': {
    description: 'Generate Kyber (CRYSTALS-Kyber) key pair',
    inputSchema: z.object({
      parameterSet: z.enum(['kyber512', 'kyber768', 'kyber1024']).optional().default('kyber768'),
      format: z.enum(['base64', 'hex', 'raw']).optional().default('base64'),
    }),
  },
  'kyber-encapsulate': {
    description: 'Encapsulate a shared secret using Kyber public key',
    inputSchema: z.object({
      publicKey: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'kyber-decapsulate': {
    description: 'Decapsulate a shared secret using Kyber private key',
    inputSchema: z.object({
      privateKey: z.string(),
      ciphertext: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },

  // Digital Signatures
  'dilithium-keygen': {
    description: 'Generate Dilithium (CRYSTALS-Dilithium) key pair',
    inputSchema: z.object({
      parameterSet: z
        .enum(['dilithium2', 'dilithium3', 'dilithium5'])
        .optional()
        .default('dilithium3'),
      format: z.enum(['base64', 'hex', 'raw']).optional().default('base64'),
    }),
  },
  'dilithium-sign': {
    description: 'Sign a message using Dilithium',
    inputSchema: z.object({
      privateKey: z.string(),
      message: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'dilithium-verify': {
    description: 'Verify a Dilithium signature',
    inputSchema: z.object({
      publicKey: z.string(),
      message: z.string(),
      signature: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },

  'sphincs-keygen': {
    description: 'Generate SPHINCS+ key pair',
    inputSchema: z.object({
      parameterSet: z
        .enum(['sphincs-sha256-128s', 'sphincs-sha256-192s', 'sphincs-sha256-256s'])
        .optional()
        .default('sphincs-sha256-192s'),
      format: z.enum(['base64', 'hex', 'raw']).optional().default('base64'),
    }),
  },
  'sphincs-sign': {
    description: 'Sign a message using SPHINCS+',
    inputSchema: z.object({
      privateKey: z.string(),
      message: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'sphincs-verify': {
    description: 'Verify a SPHINCS+ signature',
    inputSchema: z.object({
      publicKey: z.string(),
      message: z.string(),
      signature: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },

  'falcon-keygen': {
    description: 'Generate Falcon key pair',
    inputSchema: z.object({
      parameterSet: z.enum(['falcon512', 'falcon1024']).optional().default('falcon512'),
      format: z.enum(['base64', 'hex', 'raw']).optional().default('base64'),
    }),
  },
  'falcon-sign': {
    description: 'Sign a message using Falcon',
    inputSchema: z.object({
      privateKey: z.string(),
      message: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'falcon-verify': {
    description: 'Verify a Falcon signature',
    inputSchema: z.object({
      publicKey: z.string(),
      message: z.string(),
      signature: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },

  // Utility Tools
  'hybrid-encrypt': {
    description: 'Hybrid encryption combining post-quantum KEM with symmetric encryption',
    inputSchema: z.object({
      publicKey: z.string(),
      data: z.string(),
      algorithm: z.enum(['kyber-aes']).optional().default('kyber-aes'),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'hybrid-decrypt': {
    description: 'Hybrid decryption',
    inputSchema: z.object({
      privateKey: z.string(),
      encryptedData: z.string(),
      algorithm: z.enum(['kyber-aes']).optional().default('kyber-aes'),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },

  'secure-random': {
    description:
      'Generate cryptographically secure random bytes from the OS CSPRNG (hardware-seeded), or from a raw hardware entropy source (conditioned + SP 800-90B health-tested) when available. Reports the actual entropy source used.',
    inputSchema: z.object({
      bytes: z.number().min(1).max(1048576).optional().default(32),
      format: z.enum(['base64', 'hex', 'integer']).optional().default('hex'),
      healthTest: z.boolean().optional().default(true),
    }),
  },

  'quantum-random': {
    description:
      'DEPRECATED alias for secure-random. Output is a CSPRNG/hardware-seeded DRBG, not quantum randomness unless a hardware entropy source is present.',
    inputSchema: z.object({
      bytes: z.number().min(1).max(1048576).optional().default(32),
      format: z.enum(['base64', 'hex', 'integer']).optional().default('hex'),
      healthTest: z.boolean().optional().default(true),
    }),
  },

  'random-validate': {
    description:
      'Validate a byte sequence against the NIST SP 800-22 statistical test suite (practical subset). Supply data (hex/base64) or generate a fresh sample.',
    inputSchema: z.object({
      data: z.string().optional(),
      bytes: z.number().min(16).max(1048576).optional().default(4096),
      format: z.enum(['base64', 'hex']).optional().default('hex'),
    }),
  },

  'benchmark-algorithm': {
    description: 'Benchmark post-quantum algorithm performance',
    inputSchema: z.object({
      algorithm: z.enum(['kyber', 'dilithium', 'sphincs', 'falcon', 'all']),
      operations: z.number().min(1).max(1000).optional().default(100),
      includeMemory: z.boolean().optional().default(true),
    }),
  },

  'analyze-security': {
    description: 'Analyze security parameters and quantum resistance',
    inputSchema: z.object({
      algorithm: z.string(),
      parameterSet: z.string().optional(),
      threatModel: z
        .enum(['current', 'future-5y', 'future-10y', 'future-20y'])
        .optional()
        .default('future-10y'),
    }),
  },

  'key-derive': {
    description: 'Derive keys using post-quantum KDF',
    inputSchema: z.object({
      masterKey: z.string(),
      info: z.string(),
      length: z.number().min(16).max(512).optional().default(32),
      algorithm: z
        .enum(['shake256', 'hkdf-sha256', 'pbkdf2', 'scrypt'])
        .optional()
        .default('shake256'),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },

  'store-key': {
    description: 'Store post-quantum keys securely',
    inputSchema: z.object({
      keyId: z.string(),
      keyData: z.string(),
      metadata: z.record(z.string()).optional(),
      encryption: z.boolean().optional().default(true),
    }),
  },

  'retrieve-key': {
    description: 'Retrieve stored post-quantum keys',
    inputSchema: z.object({
      keyId: z.string(),
      decrypt: z.boolean().optional().default(true),
    }),
  },

  'list-stored-keys': {
    description: 'List all stored key IDs and metadata',
    inputSchema: z.object({
      filter: z
        .object({
          algorithm: z.string().optional(),
          createdAfter: z.string().optional(),
          createdBefore: z.string().optional(),
        })
        .optional(),
    }),
  },

  // ── Entropy assessment & device-independent randomness ──
  'entropy-assess': {
    description: 'Assess raw entropy: SP 800-90B min-entropy (MCV) + Shannon + full-entropy check',
    inputSchema: z.object({
      data: z.string().describe('raw sample bytes, hex or base64'),
      format: z.enum(['hex', 'base64']).optional().default('hex'),
    }),
  },
  'entropy-ingest': {
    description: 'Gate + condition raw entropy into a full-entropy seed (measure→gate→condition→LHL certificate)',
    inputSchema: z.object({
      data: z.string(),
      format: z.enum(['hex', 'base64']).optional().default('hex'),
      seedBits: z.number().int().positive().optional().default(512),
      quality: z.enum(['standard', 'best']).optional(),
    }),
  },
  'di-certify': {
    description: 'Device-independent: certified min-entropy + tight von Neumann rate from a CHSH value S',
    inputSchema: z.object({ chsh: z.number() }),
  },
  'di-finite-rate': {
    description: 'DI finite-statistics certified rate (entropy accumulation) for n CHSH rounds at observed S',
    inputSchema: z.object({
      chsh: z.number(),
      rounds: z.number().int().positive(),
      soundnessError: z.number().positive().optional(),
    }),
  },
  'di-rounds-for-seed': {
    description: 'DI: how many Bell rounds to certify a full-entropy seed at observed CHSH S',
    inputSchema: z.object({
      chsh: z.number(),
      seedBits: z.number().int().positive().optional().default(512),
      soundnessError: z.number().positive().optional(),
    }),
  },

  // ── Hybrid (classical + post-quantum) ──
  'hybrid-kem-keygen': {
    description: 'Generate a hybrid X-Wing (X25519 + ML-KEM-768) KEM key pair',
    inputSchema: z.object({ format: z.enum(['base64', 'hex']).optional().default('base64') }),
  },
  'hybrid-kem-encapsulate': {
    description: 'Encapsulate a shared secret to a hybrid X-Wing public key',
    inputSchema: z.object({
      publicKey: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'hybrid-kem-decapsulate': {
    description: 'Decapsulate a hybrid X-Wing shared secret',
    inputSchema: z.object({
      privateKey: z.string(),
      ciphertext: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'hybrid-sign-keygen': {
    description: 'Generate a hybrid (Ed25519 + ML-DSA-65) signature key pair',
    inputSchema: z.object({ format: z.enum(['base64', 'hex']).optional().default('base64') }),
  },
  'hybrid-sign': {
    description: 'Sign a message with a hybrid Ed25519 + ML-DSA-65 key',
    inputSchema: z.object({
      privateKey: z.string(),
      message: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'hybrid-verify': {
    description: 'Verify a hybrid signature (both Ed25519 AND ML-DSA-65 must pass)',
    inputSchema: z.object({
      publicKey: z.string(),
      message: z.string(),
      signature: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },

  // ── Agent identity, attestations, channels ──
  'agent-create-identity': {
    description: 'Mint a quantum-safe agent identity (hybrid signing + KEM keys)',
    inputSchema: z.object({}),
  },
  'agent-attest': {
    description: 'Issue a hybrid-signed, timestamped attestation of an agent action',
    inputSchema: z.object({
      sigPrivateKey: z.string(),
      agentId: z.string().optional(),
      action: z.any(),
    }),
  },
  'agent-verify-attestation': {
    description: 'Verify an agent action attestation',
    inputSchema: z.object({
      sigPublicKey: z.string(),
      attestation: z.record(z.any()),
      signature: z.string(),
    }),
  },
  'agent-channel-open': {
    description: 'Open an end-to-end channel to a peer agent (X-Wing encapsulation)',
    inputSchema: z.object({ peerKemPublicKey: z.string() }),
  },
  'agent-channel-accept': {
    description: 'Accept an end-to-end channel from an initiator ciphertext',
    inputSchema: z.object({ kemPrivateKey: z.string(), ciphertext: z.string() }),
  },
  'agent-channel-message': {
    description: 'Encrypt or decrypt a message over an established channel key (AES-256-GCM)',
    inputSchema: z.object({
      direction: z.enum(['encrypt', 'decrypt']),
      channelKey: z.string(),
      data: z.string(),
      iv: z.string().optional(),
      authTag: z.string().optional(),
    }),
  },

  // ── Quantum-safe code / SBOM signing ──
  'sign-artifact': {
    description:
      'Hybrid-sign a software artifact / SBOM (or its digest) into a verifiable envelope',
    inputSchema: z.object({
      privateKey: z.string(),
      artifact: z.string().optional(),
      digest: z.string().optional(),
      digestAlgorithm: z.string().optional().default('sha256'),
      metadata: z.record(z.any()).optional(),
    }),
  },
  'verify-artifact': {
    description: 'Verify a signed artifact envelope (optionally re-hashing the artifact)',
    inputSchema: z.object({
      publicKey: z.string(),
      signedArtifact: z.record(z.any()),
      artifact: z.string().optional(),
    }),
  },

  // ── Crypto-agility advisor ──
  'assess-migration': {
    description:
      'Assess current cryptography and produce a prioritized PQC migration plan + harvest-now-decrypt-later risk',
    inputSchema: z.object({
      currentAlgorithms: z.array(z.string()),
      dataSensitivity: z.enum(['low', 'medium', 'high', 'critical']).optional().default('medium'),
      dataLifetimeYears: z.number().optional().default(10),
    }),
  },

  // ── Shamir t-of-n custody of post-quantum keys ──
  'threshold-split-key': {
    description:
      'Split a private key into n Shamir shares; any t reconstruct, any t-1 reveal nothing',
    inputSchema: z.object({
      secret: z.string(),
      n: z.number().min(2).max(255),
      threshold: z.number().min(2).max(255),
    }),
  },
  'threshold-reconstruct-key': {
    description: 'Reconstruct a key from a quorum of shares (verified against the commitment)',
    inputSchema: z.object({
      shares: z.array(z.object({ index: z.number(), value: z.string() })),
      threshold: z.number(),
      commitment: z.string().optional(),
    }),
  },
  'threshold-sign': {
    description:
      'Quorum-sign: reconstruct an ML-DSA key from t shares and produce a real FIPS-204 signature',
    inputSchema: z.object({
      shares: z.array(z.object({ index: z.number(), value: z.string() })),
      threshold: z.number(),
      message: z.string(),
      algorithm: z
        .enum(['dilithium2', 'dilithium3', 'dilithium5'])
        .optional()
        .default('dilithium3'),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },

  // ── Applications: tokens, document encryption, PKI ──
  'jwt-sign': {
    description: 'Issue a quantum-safe JWT-style token (hybrid or ML-DSA signature)',
    inputSchema: z.object({
      privateKey: z.string(),
      claims: z.record(z.any()).optional(),
      algorithm: z.enum(['hybrid', 'ml-dsa']).optional().default('hybrid'),
      expiresInSeconds: z.number().optional(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'jwt-verify': {
    description: 'Verify a quantum-safe JWT-style token (signature + exp/nbf)',
    inputSchema: z.object({
      publicKey: z.string(),
      token: z.string(),
      algorithm: z.enum(['hybrid', 'ml-dsa']).optional().default('hybrid'),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'encrypt-document': {
    description: 'Encrypt data to one or more hybrid-KEM recipients (multi-recipient PQ envelope)',
    inputSchema: z.object({
      recipients: z.array(z.string()),
      data: z.string(),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'decrypt-document': {
    description: 'Decrypt a PQ document envelope with your hybrid-KEM private key',
    inputSchema: z.object({
      privateKey: z.string(),
      envelope: z.record(z.any()),
      format: z.enum(['base64', 'hex']).optional().default('base64'),
    }),
  },
  'issue-certificate': {
    description: 'Issue a quantum-safe certificate (self-signed or CA-signed, hybrid signature)',
    inputSchema: z.object({
      subject: z.string(),
      subjectPublicKey: z.string(),
      issuerPrivateKey: z.string(),
      issuer: z.string().optional(),
      issuerPublicKey: z.string().optional(),
      validityDays: z.number().optional().default(365),
      isCA: z.boolean().optional().default(false),
    }),
  },
  'verify-certificate': {
    description:
      'Verify a quantum-safe certificate (signature, validity window, optional CA chain)',
    inputSchema: z.object({
      certificate: z.record(z.any()),
      signature: z.string(),
      issuerPublicKey: z.string().optional(),
      caCertificate: z.record(z.any()).optional(),
    }),
  },
};

// Build a fresh MCP server instance. Factory so stdio uses a single instance
// and stateless HTTP can build one per request.
function buildServer(): Server {
  const server = new Server(
    {
      name: 'post-quantum-mcp',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Handle list tools request
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: Object.entries(TOOLS).map(([name, config]) => ({
        name,
        description: config.description,
        inputSchema: config.inputSchema,
      })),
    };
  });

  // Handle tool execution
  server.setRequestHandler(CallToolRequestSchema, async request => {
    const { name, arguments: args } = request.params;

    logger.info(`Executing tool: ${name}`, { args });

    try {
      // Route to appropriate handler based on tool name
      switch (name) {
        // Kyber operations
        case 'kyber-keygen':
          return await kyberHandler.generateKeyPair(args);
        case 'kyber-encapsulate':
          return await kyberHandler.encapsulate(args);
        case 'kyber-decapsulate':
          return await kyberHandler.decapsulate(args);

        // Dilithium operations
        case 'dilithium-keygen':
          return await dilithiumHandler.generateKeyPair(args);
        case 'dilithium-sign':
          return await dilithiumHandler.sign(args);
        case 'dilithium-verify':
          return await dilithiumHandler.verify(args);

        // SPHINCS+ operations
        case 'sphincs-keygen':
          return await sphincsHandler.generateKeyPair(args);
        case 'sphincs-sign':
          return await sphincsHandler.sign(args);
        case 'sphincs-verify':
          return await sphincsHandler.verify(args);

        // Falcon operations
        case 'falcon-keygen':
          return await falconHandler.generateKeyPair(args);
        case 'falcon-sign':
          return await falconHandler.sign(args);
        case 'falcon-verify':
          return await falconHandler.verify(args);

        // Utility operations
        case 'hybrid-encrypt':
          return await hybridHandler.encrypt(args);
        case 'hybrid-decrypt':
          return await hybridHandler.decrypt(args);
        case 'secure-random':
        case 'quantum-random':
          return await quantumRngHandler.generate(args);
        case 'random-validate':
          return await quantumRngHandler.validate(args);

        // Entropy assessment & device-independent randomness
        case 'entropy-assess':
          return await entropyToolsHandler.assess(args);
        case 'entropy-ingest':
          return await entropyToolsHandler.ingest(args);
        case 'di-certify':
          return await entropyToolsHandler.diCertify(args);
        case 'di-finite-rate':
          return await entropyToolsHandler.diFiniteRate(args);
        case 'di-rounds-for-seed':
          return await entropyToolsHandler.diRoundsForSeed(args);
        case 'benchmark-algorithm':
          return await benchmarkHandler.benchmark(args);
        case 'analyze-security':
          return await securityAnalyzer.analyze(args);
        case 'key-derive':
          return await keyMgmtHandler.deriveKey(args);
        case 'store-key':
          return await keyMgmtHandler.storeKey(args);
        case 'retrieve-key':
          return await keyMgmtHandler.retrieveKey(args);
        case 'list-stored-keys':
          return await keyMgmtHandler.listKeys(args);

        // Hybrid (classical + post-quantum)
        case 'hybrid-kem-keygen':
          return await hybridPqc.kemKeygen(args);
        case 'hybrid-kem-encapsulate':
          return await hybridPqc.kemEncapsulate(args);
        case 'hybrid-kem-decapsulate':
          return await hybridPqc.kemDecapsulate(args);
        case 'hybrid-sign-keygen':
          return await hybridPqc.signKeygen(args);
        case 'hybrid-sign':
          return await hybridPqc.sign(args);
        case 'hybrid-verify':
          return await hybridPqc.verify(args);

        // Agent identity / attestations / channels
        case 'agent-create-identity':
          return await agentIdentity.createIdentity(args);
        case 'agent-attest':
          return await agentIdentity.attest(args);
        case 'agent-verify-attestation':
          return await agentIdentity.verifyAttestation(args);
        case 'agent-channel-open':
          return await agentIdentity.channelOpen(args);
        case 'agent-channel-accept':
          return await agentIdentity.channelAccept(args);
        case 'agent-channel-message':
          return await agentIdentity.channelMessage(args);

        // Code / SBOM signing
        case 'sign-artifact':
          return await codeSigning.signArtifact(args);
        case 'verify-artifact':
          return await codeSigning.verifyArtifact(args);

        // Crypto-agility advisor
        case 'assess-migration':
          return await cryptoAgility.assess(args);

        // Shamir t-of-n key custody
        case 'threshold-split-key':
          return await thresholdCustody.splitKey(args);
        case 'threshold-reconstruct-key':
          return await thresholdCustody.reconstructKey(args);
        case 'threshold-sign':
          return await thresholdCustody.thresholdSign(args);

        // Applications: tokens, document encryption, PKI
        case 'jwt-sign':
          return await pqJwt.sign(args);
        case 'jwt-verify':
          return await pqJwt.verify(args);
        case 'encrypt-document':
          return await pqEncrypt.encryptDocument(args);
        case 'decrypt-document':
          return await pqEncrypt.decryptDocument(args);
        case 'issue-certificate':
          return await pqCert.issue(args);
        case 'verify-certificate':
          return await pqCert.verify(args);

        default:
          throw new McpError(ErrorCode.MethodNotFound, `Tool not found: ${name}`);
      }
    } catch (error) {
      logger.error(`Tool execution failed: ${name}`, { error, args });

      if (error instanceof McpError) {
        throw error;
      }

      throw new McpError(
        ErrorCode.InternalError,
        `Tool execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  });

  return server;
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, shutting down gracefully...');
  cache.flushAll();
  process.exit(0);
});

// Start the server: stdio by default, HTTP when MCP_TRANSPORT=http.
async function main() {
  if ((process.env.MCP_TRANSPORT || '').toLowerCase() === 'http') {
    const { StreamableHTTPServerTransport } =
      await import('@modelcontextprotocol/sdk/server/streamableHttp.js');
    const http = await import('node:http');
    const port = parseInt(process.env.PORT || '3000', 10);
    const routePath = process.env.MCP_HTTP_PATH || '/mcp';
    const MAX_BODY = 8 * 1024 * 1024; // 8 MiB request cap (DoS guard)

    const httpServer = http.createServer((req, res) => {
      if (req.method === 'GET' && (req.url === '/health' || req.url === '/healthz')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', tools: Object.keys(TOOLS).length }));
        return;
      }
      if (req.url !== routePath || req.method !== 'POST') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Not found. POST JSON-RPC to ${routePath}` }));
        return;
      }
      let size = 0;
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => {
        size += c.length;
        if (size > MAX_BODY) {
          res.writeHead(413).end('Payload too large');
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', async () => {
        try {
          const raw = Buffer.concat(chunks).toString('utf8');
          const body = raw ? JSON.parse(raw) : undefined;
          const srv = buildServer();
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
            enableJsonResponse: true,
          });
          res.on('close', () => {
            transport.close();
            srv.close();
          });
          await srv.connect(transport);
          await transport.handleRequest(req, res, body);
        } catch (err) {
          logger.error('HTTP request failed:', err);
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'internal error' }));
          }
        }
      });
    });
    httpServer.listen(port, () =>
      logger.info(`Post-Quantum MCP Server (HTTP) on :${port}${routePath}`)
    );
  } else {
    const server = buildServer();
    await server.connect(new StdioServerTransport());
    logger.info('Post-Quantum MCP Server started successfully (stdio)');
  }
}

main().catch(error => {
  logger.error('Failed to start server:', error);
  process.exit(1);
});
