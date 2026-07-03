import { Logger } from 'winston';
import NodeCache from 'node-cache';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';

export class KeyManagementHandler {
  private keyStorePath: string;
  
  constructor(
    private logger: Logger,
    private cache: NodeCache
  ) {
    this.keyStorePath = process.env.KEY_STORE_PATH || './keys';
    this.initKeyStore();
  }

  private async initKeyStore() {
    try {
      await fs.mkdir(this.keyStorePath, { recursive: true });
    } catch (error) {
      this.logger.error('Failed to initialize key store:', error);
    }
  }

  async storeKey(params: any) {
    const { keyId, keyData, metadata = {}, encryption = true } = params;
    
    try {
      const keyInfo = {
        id: keyId,
        data: keyData,
        metadata: {
          ...metadata,
          created: new Date().toISOString(),
          encrypted: encryption
        }
      };
      
      let finalData = keyData;
      
      if (encryption) {
        // Encrypt key data before storage
        const encryptionKey = this.deriveEncryptionKey(keyId);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
        
        const encrypted = Buffer.concat([
          cipher.update(Buffer.from(keyData, 'base64')),
          cipher.final()
        ]);
        const authTag = cipher.getAuthTag();
        
        finalData = {
          encrypted: encrypted.toString('base64'),
          iv: iv.toString('base64'),
          authTag: authTag.toString('base64')
        };
      }
      
      keyInfo.data = finalData;
      
      // Store to file
      const filePath = path.join(this.keyStorePath, `${keyId}.json`);
      await fs.writeFile(filePath, JSON.stringify(keyInfo, null, 2));
      
      // Cache the key info
      this.cache.set(`key-${keyId}`, keyInfo);
      
      this.logger.info(`Stored key: ${keyId}`);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            keyId,
            stored: new Date().toISOString(),
            encrypted: encryption
          }, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('Key storage failed:', error);
      throw error;
    }
  }

  async retrieveKey(params: any) {
    const { keyId, decrypt = true } = params;
    
    try {
      // Check cache first
      let keyInfo = this.cache.get<any>(`key-${keyId}`);
      
      if (!keyInfo) {
        // Load from file
        const filePath = path.join(this.keyStorePath, `${keyId}.json`);
        const data = await fs.readFile(filePath, 'utf8');
        keyInfo = JSON.parse(data);
        
        // Cache it
        this.cache.set(`key-${keyId}`, keyInfo);
      }
      
      let keyData = keyInfo.data;
      
      if (keyInfo.metadata.encrypted && decrypt) {
        // Decrypt key data
        const encryptionKey = this.deriveEncryptionKey(keyId);
        const { encrypted, iv, authTag } = keyData;
        
        const decipher = crypto.createDecipheriv(
          'aes-256-gcm',
          encryptionKey,
          Buffer.from(iv, 'base64')
        );
        decipher.setAuthTag(Buffer.from(authTag, 'base64'));
        
        const decrypted = Buffer.concat([
          decipher.update(Buffer.from(encrypted, 'base64')),
          decipher.final()
        ]);
        
        keyData = decrypted.toString('base64');
      }
      
      const result = {
        keyId,
        keyData,
        metadata: keyInfo.metadata
      };
      
      this.logger.info(`Retrieved key: ${keyId}`);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('Key retrieval failed:', error);
      throw error;
    }
  }

  async listKeys(params: any) {
    const { filter = {} } = params;
    
    try {
      const files = await fs.readdir(this.keyStorePath);
      const keys = [];
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const filePath = path.join(this.keyStorePath, file);
          const data = await fs.readFile(filePath, 'utf8');
          const keyInfo = JSON.parse(data);
          
          // Apply filters
          if (filter.algorithm && keyInfo.metadata.algorithm !== filter.algorithm) {
            continue;
          }
          if (filter.createdAfter && new Date(keyInfo.metadata.created) < new Date(filter.createdAfter)) {
            continue;
          }
          if (filter.createdBefore && new Date(keyInfo.metadata.created) > new Date(filter.createdBefore)) {
            continue;
          }
          
          keys.push({
            keyId: keyInfo.id,
            metadata: keyInfo.metadata
          });
        }
      }
      
      this.logger.info(`Listed ${keys.length} keys`);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            keys,
            count: keys.length
          }, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('Key listing failed:', error);
      throw error;
    }
  }

  async deriveKey(params: any) {
    const { masterKey, info, length = 32, algorithm = 'shake256', format = 'base64' } = params;
    
    try {
      const master = Buffer.from(masterKey, format);
      const salt = Buffer.from(info, 'utf8');
      
      let derivedKey: Buffer;
      
      switch (algorithm) {
        case 'shake256': {
          // SHAKE256 XOF key derivation.
          const hash = crypto.createHash('shake256', { outputLength: length });
          hash.update(master);
          hash.update(salt);
          derivedKey = hash.digest();
          break;
        }
        case 'hkdf-sha256':
          // RFC 5869 HKDF-Expand/Extract over SHA-256.
          derivedKey = Buffer.from(
            crypto.hkdfSync('sha256', master, salt, Buffer.alloc(0), length),
          );
          break;
        case 'pbkdf2':
          // PBKDF2-HMAC-SHA256, 200k iterations.
          derivedKey = crypto.pbkdf2Sync(master, salt, 200_000, length, 'sha256');
          break;
        case 'scrypt':
          // scrypt (memory-hard).
          derivedKey = crypto.scryptSync(master, salt, length);
          break;
        default:
          throw new Error(
            `Unsupported algorithm: ${algorithm}. Supported: shake256, hkdf-sha256, pbkdf2, scrypt`,
          );
      }
      
      const result = {
        derivedKey: derivedKey.toString(format === 'hex' ? 'hex' : 'base64'),
        algorithm,
        keyLength: length,
        timestamp: new Date().toISOString()
      };
      
      this.logger.info(`Derived key using ${algorithm}`);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      this.logger.error('Key derivation failed:', error);
      throw error;
    }
  }

  private deriveEncryptionKey(keyId: string): Buffer {
    // Fail closed: never fall back to a hardcoded/default secret for at-rest
    // key encryption (CWE-798). The operator MUST provide a real secret.
    const secret = process.env.KEY_ENCRYPTION_SECRET;
    if (!secret || secret.length < 16) {
      throw new Error(
        'KEY_ENCRYPTION_SECRET must be set (>=16 chars) to store/retrieve encrypted keys. ' +
          'Refusing to use a default secret.',
      );
    }
    return crypto.pbkdf2Sync(secret, keyId, 200_000, 32, 'sha256');
  }
}
