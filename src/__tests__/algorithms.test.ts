import { jest, describe, it, expect, beforeEach, afterEach, test } from "@jest/globals";
import { KyberHandler } from '../algorithms/kyber';
import { DilithiumHandler } from '../algorithms/dilithium';
import { Logger } from 'winston';
import NodeCache from 'node-cache';

describe('Post-Quantum Algorithms', () => {
  let logger: Logger;
  let cache: NodeCache;
  
  beforeEach(() => {
    logger = {
      info: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    } as any;
    
    cache = new NodeCache();
  });
  
  afterEach(() => {
    cache.flushAll();
  });
  
  describe('KyberHandler', () => {
    let kyberHandler: KyberHandler;
    
    beforeEach(() => {
      kyberHandler = new KyberHandler(logger, cache);
    });
    
    test('should generate key pair', async () => {
      const result = await kyberHandler.generateKeyPair({
        parameterSet: 'kyber768',
        format: 'base64'
      });
      
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe('text');
      
      const data = JSON.parse(result.content[0].text);
      expect(['kyber', 'ml-kem']).toContain(data.algorithm);
      expect(['kyber768', 'ml-kem-768']).toContain(data.parameterSet);
      expect(data.publicKey).toBeDefined();
      expect(data.privateKey).toBeDefined();
    });
    
    test('should encapsulate shared secret', async () => {
      const keyPair = await kyberHandler.generateKeyPair({
        parameterSet: 'kyber768',
        format: 'base64'
      });
      
      const keyData = JSON.parse(keyPair.content[0].text);
      
      const result = await kyberHandler.encapsulate({
        publicKey: keyData.publicKey,
        format: 'base64'
      });
      
      expect(result.content).toBeDefined();
      const encapData = JSON.parse(result.content[0].text);
      expect(encapData.sharedSecret).toBeDefined();
      expect(encapData.ciphertext).toBeDefined();
    });
  });
  
  describe('DilithiumHandler', () => {
    let dilithiumHandler: DilithiumHandler;
    
    beforeEach(() => {
      dilithiumHandler = new DilithiumHandler(logger, cache);
    });
    
    test('should generate key pair', async () => {
      const result = await dilithiumHandler.generateKeyPair({
        parameterSet: 'dilithium3',
        format: 'base64'
      });
      
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(['dilithium', 'ml-dsa']).toContain(data.algorithm);
      expect(['dilithium3', 'ml-dsa-65']).toContain(data.parameterSet);
    });
    
    test('should sign and verify message', async () => {
      const keyPair = await dilithiumHandler.generateKeyPair({
        parameterSet: 'dilithium3',
        format: 'base64'
      });
      
      const keyData = JSON.parse(keyPair.content[0].text);
      const message = 'Test message for signing';
      
      const signResult = await dilithiumHandler.sign({
        privateKey: keyData.privateKey,
        message,
        format: 'base64'
      });
      
      const signData = JSON.parse(signResult.content[0].text);
      
      const verifyResult = await dilithiumHandler.verify({
        publicKey: keyData.publicKey,
        message,
        signature: signData.signature,
        format: 'base64'
      });
      
      const verifyData = JSON.parse(verifyResult.content[0].text);
      expect(verifyData.valid).toBe(true);
    });
  });
});
