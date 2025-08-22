/**
 * Unit tests for JWT cryptographic utility functions
 * These tests focus on the core crypto functionality used in JWT operations
 */

import { TextEncoder, TextDecoder } from 'util';

// Setup globals for Node.js environment
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');

// JWT Crypto utility functions
export const jwtCrypto = {
  /**
   * Base64 URL encode data
   * @param {string|ArrayBuffer} data - Data to encode
   * @returns {string} Base64 URL encoded string
   */
  base64UrlEncode: (data) => {
    if (typeof data === 'string') {
      data = new TextEncoder().encode(data);
    }
    return btoa(String.fromCharCode(...new Uint8Array(data)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  },

  /**
   * Base64 URL decode string
   * @param {string} str - Base64 URL encoded string
   * @returns {string} Decoded string
   */
  base64UrlDecode: (str) => {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
      str += '=';
    }
    return decodeURIComponent(atob(str).split('').map(c => 
      '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
    ).join(''));
  },

  /**
   * Base64 URL decode to ArrayBuffer
   * @param {string} str - Base64 URL encoded string
   * @returns {ArrayBuffer} Decoded ArrayBuffer
   */
  base64UrlDecodeToArrayBuffer: (str) => {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
      str += '=';
    }
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  },

  /**
   * Get algorithm from JWK
   * @param {Object} jwk - JSON Web Key
   * @returns {string} Algorithm name
   */
  getAlgorithmFromKey: (jwk) => {
    if (!jwk) return 'none';
    
    if (jwk.kty === 'RSA') {
      if (jwk.use === 'enc' || (jwk.key_ops && jwk.key_ops.includes('encrypt'))) {
        return 'RS256'; // Default for RSA
      }
      return jwk.alg || 'RS256';
    }
    
    if (jwk.kty === 'EC') {
      if (jwk.use === 'enc' || (jwk.key_ops && jwk.key_ops.includes('deriveKey'))) {
        return 'ES256'; // Default for EC
      }
      return jwk.alg || (jwk.crv === 'P-384' ? 'ES384' : jwk.crv === 'P-521' ? 'ES512' : 'ES256');
    }
    
    return 'none';
  },

  /**
   * Get crypto algorithm parameters for Web Crypto API
   * @param {string} algorithm - JWT algorithm (RS256, ES256, etc.)
   * @param {string} keyType - Key type (RSA, EC)
   * @returns {Object} Algorithm parameters for Web Crypto API
   */
  getCryptoAlgorithm: (algorithm, keyType, jwk = {}) => {
    if (keyType === 'RSA') {
      const keyAlgorithm = algorithm.startsWith('PS') ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5';
      const hash = algorithm.includes('384') ? 'SHA-384' : 
                   algorithm.includes('512') ? 'SHA-512' : 'SHA-256';
      
      if (algorithm.startsWith('PS')) {
        const saltLength = algorithm.includes('384') ? 48 : 
                          algorithm.includes('512') ? 64 : 32;
        return { 
          importAlg: { name: keyAlgorithm, hash },
          signAlg: { name: keyAlgorithm, saltLength }
        };
      }
      
      return { 
        importAlg: { name: keyAlgorithm, hash },
        signAlg: keyAlgorithm
      };
    }
    
    if (keyType === 'EC') {
      const hash = algorithm.includes('384') ? 'SHA-384' : 
                   algorithm.includes('512') ? 'SHA-512' : 'SHA-256';
      const curve = jwk.crv || (algorithm.includes('384') ? 'P-384' : algorithm.includes('512') ? 'P-521' : 'P-256');
      return {
        importAlg: { name: 'ECDSA', namedCurve: curve },
        signAlg: { name: 'ECDSA', hash }
      };
    }
    
    throw new Error(`Unsupported key type: ${keyType}`);
  },

  /**
   * Parse JWT without verification
   * @param {string} jwt - JWT token
   * @returns {Object} Parsed JWT parts
   */
  parseJwt: (jwt) => {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
    }

    try {
      const header = JSON.parse(jwtCrypto.base64UrlDecode(parts[0]));
      const payload = JSON.parse(jwtCrypto.base64UrlDecode(parts[1]));
      
      return {
        header,
        payload,
        signature: parts[2],
        raw: parts
      };
    } catch (error) {
      throw new Error(`Failed to parse JWT: ${error.message}`);
    }
  },

  /**
   * Validate JWT structure and claims
   * @param {Object} parsedJwt - Parsed JWT from parseJwt
   * @returns {Object} Validation result
   */
  validateJwtClaims: (parsedJwt) => {
    const { header, payload } = parsedJwt;
    const now = Math.floor(Date.now() / 1000);
    const issues = [];
    const warnings = [];

    // Validate header
    if (!header.alg) {
      issues.push('Missing algorithm in header');
    }
    if (!header.typ || header.typ !== 'JWT') {
      warnings.push('Missing or invalid typ claim in header');
    }

    // Validate timing claims
    if (payload.exp && payload.exp < now) {
      issues.push(`Token expired at ${new Date(payload.exp * 1000).toISOString()}`);
    }
    if (payload.nbf && payload.nbf > now) {
      issues.push(`Token not valid before ${new Date(payload.nbf * 1000).toISOString()}`);
    }
    if (payload.iat && payload.iat > now + 300) { // 5 minute clock skew tolerance
      warnings.push('Token issued in the future');
    }

    // Validate required claims
    if (!payload.sub && !payload.iss) {
      warnings.push('Missing subject (sub) and issuer (iss) claims');
    }

    return {
      valid: issues.length === 0,
      issues,
      warnings,
      claims: {
        expired: payload.exp && payload.exp < now,
        notYetValid: payload.nbf && payload.nbf > now,
        timeToExpiry: payload.exp ? payload.exp - now : null
      }
    };
  }
};

describe('JWT Crypto Utilities', () => {
  describe('Base64 URL Encoding/Decoding', () => {
    test('should encode and decode strings correctly', () => {
      const testCases = [
        'Hello World',
        'Test string with special chars: @#$%^&*()',
        '{"typ":"JWT","alg":"RS256"}',
        '{"sub":"1234567890","name":"John Doe","iat":1516239022}',
        '', // empty string
        'a', // single character
        '🎉', // emoji
      ];

      testCases.forEach(input => {
        const encoded = jwtCrypto.base64UrlEncode(input);
        const decoded = jwtCrypto.base64UrlDecode(encoded);
        
        expect(decoded).toBe(input);
        expect(encoded).not.toContain('+');
        expect(encoded).not.toContain('/');
        expect(encoded).not.toContain('=');
      });
    });

    test('should handle ArrayBuffer input', () => {
      const testData = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = jwtCrypto.base64UrlEncode(testData.buffer);
      
      expect(encoded).toBe('SGVsbG8');
      expect(jwtCrypto.base64UrlDecode(encoded)).toBe('Hello');
    });

    test('should decode to ArrayBuffer correctly', () => {
      const input = 'SGVsbG8'; // "Hello" in base64url
      const buffer = jwtCrypto.base64UrlDecodeToArrayBuffer(input);
      const view = new Uint8Array(buffer);
      
      expect(view).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    test('should handle padding edge cases', () => {
      const testCases = [
        'YW55IGNhcm5hbCBwbGVhc3VyZQ', // no padding
        'YW55IGNhcm5hbCBwbGVhc3Vy',   // 1 pad
        'YW55IGNhcm5hbCBwbGVhc3U',    // 2 pads
      ];

      testCases.forEach(encoded => {
        expect(() => jwtCrypto.base64UrlDecode(encoded)).not.toThrow();
        expect(() => jwtCrypto.base64UrlDecodeToArrayBuffer(encoded)).not.toThrow();
      });
    });
  });

  describe('Algorithm Detection', () => {
    test('should detect RSA algorithms correctly', () => {
      const testCases = [
        { jwk: { kty: 'RSA' }, expected: 'RS256' },
        { jwk: { kty: 'RSA', alg: 'RS384' }, expected: 'RS384' },
        { jwk: { kty: 'RSA', alg: 'RS512' }, expected: 'RS512' },
        { jwk: { kty: 'RSA', alg: 'PS256' }, expected: 'PS256' },
        { jwk: { kty: 'RSA', use: 'enc' }, expected: 'RS256' },
        { jwk: { kty: 'RSA', key_ops: ['encrypt'] }, expected: 'RS256' },
      ];

      testCases.forEach(({ jwk, expected }) => {
        expect(jwtCrypto.getAlgorithmFromKey(jwk)).toBe(expected);
      });
    });

    test('should detect EC algorithms correctly', () => {
      const testCases = [
        { jwk: { kty: 'EC', crv: 'P-256' }, expected: 'ES256' },
        { jwk: { kty: 'EC', crv: 'P-384' }, expected: 'ES384' },
        { jwk: { kty: 'EC', crv: 'P-521' }, expected: 'ES512' },
        { jwk: { kty: 'EC', crv: 'P-256', alg: 'ES256' }, expected: 'ES256' },
        { jwk: { kty: 'EC', use: 'enc' }, expected: 'ES256' },
      ];

      testCases.forEach(({ jwk, expected }) => {
        expect(jwtCrypto.getAlgorithmFromKey(jwk)).toBe(expected);
      });
    });

    test('should handle edge cases', () => {
      expect(jwtCrypto.getAlgorithmFromKey(null)).toBe('none');
      expect(jwtCrypto.getAlgorithmFromKey(undefined)).toBe('none');
      expect(jwtCrypto.getAlgorithmFromKey({})).toBe('none');
      expect(jwtCrypto.getAlgorithmFromKey({ kty: 'oct' })).toBe('none');
    });
  });

  describe('Crypto Algorithm Parameters', () => {
    test('should generate correct RSA parameters', () => {
      const testCases = [
        {
          algorithm: 'RS256',
          keyType: 'RSA',
          expected: {
            importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            signAlg: 'RSASSA-PKCS1-v1_5'
          }
        },
        {
          algorithm: 'RS384',
          keyType: 'RSA',
          expected: {
            importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
            signAlg: 'RSASSA-PKCS1-v1_5'
          }
        },
        {
          algorithm: 'PS256',
          keyType: 'RSA',
          expected: {
            importAlg: { name: 'RSA-PSS', hash: 'SHA-256' },
            signAlg: { name: 'RSA-PSS', saltLength: 32 }
          }
        },
        {
          algorithm: 'PS384',
          keyType: 'RSA',
          expected: {
            importAlg: { name: 'RSA-PSS', hash: 'SHA-384' },
            signAlg: { name: 'RSA-PSS', saltLength: 48 }
          }
        }
      ];

      testCases.forEach(({ algorithm, keyType, expected }) => {
        const result = jwtCrypto.getCryptoAlgorithm(algorithm, keyType);
        expect(result).toEqual(expected);
      });
    });

    test('should throw for unsupported key types', () => {
      expect(() => jwtCrypto.getCryptoAlgorithm('HS256', 'oct')).toThrow('Unsupported key type: oct');
    });
  });

  describe('JWT Parsing', () => {
    test('should parse valid JWT correctly', () => {
      // Create a test JWT (header.payload.signature)
      const header = { alg: 'RS256', typ: 'JWT' };
      const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
      
      const encodedHeader = jwtCrypto.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = jwtCrypto.base64UrlEncode(JSON.stringify(payload));
      const signature = 'test-signature';
      
      const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;
      
      const parsed = jwtCrypto.parseJwt(jwt);
      
      expect(parsed.header).toEqual(header);
      expect(parsed.payload).toEqual(payload);
      expect(parsed.signature).toBe(signature);
      expect(parsed.raw).toEqual([encodedHeader, encodedPayload, signature]);
    });

    test('should handle malformed JWTs', () => {
      const testCases = [
        'invalid',
        'header.payload', // missing signature
        'header.payload.signature.extra', // too many parts
        'invalid-base64.payload.signature',
        'header.invalid-json.signature'
      ];

      testCases.forEach(jwt => {
        expect(() => jwtCrypto.parseJwt(jwt)).toThrow();
      });
    });
  });

  describe('JWT Claims Validation', () => {
    const baseTime = Math.floor(Date.now() / 1000);

    test('should validate timing claims correctly', () => {
      const testCases = [
        {
          name: 'valid token',
          jwt: {
            header: { alg: 'RS256', typ: 'JWT' },
            payload: { 
              sub: 'user123',
              iat: baseTime - 100,
              exp: baseTime + 3600,
              nbf: baseTime - 50
            }
          },
          expectedValid: true
        },
        {
          name: 'expired token',
          jwt: {
            header: { alg: 'RS256', typ: 'JWT' },
            payload: { 
              sub: 'user123',
              exp: baseTime - 100
            }
          },
          expectedValid: false
        },
        {
          name: 'not yet valid token',
          jwt: {
            header: { alg: 'RS256', typ: 'JWT' },
            payload: { 
              sub: 'user123',
              nbf: baseTime + 100
            }
          },
          expectedValid: false
        }
      ];

      testCases.forEach(({ name, jwt, expectedValid }) => {
        const result = jwtCrypto.validateJwtClaims(jwt);
        expect(result.valid).toBe(expectedValid);
        
        if (name === 'expired token') {
          expect(result.claims.expired).toBe(true);
        }
        if (name === 'not yet valid token') {
          expect(result.claims.notYetValid).toBe(true);
        }
      });
    });

    test('should validate header claims', () => {
      const jwt = {
        header: { typ: 'JWT' }, // missing alg
        payload: { sub: 'user123' }
      };

      const result = jwtCrypto.validateJwtClaims(jwt);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain('Missing algorithm in header');
    });

    test('should generate warnings for missing claims', () => {
      const jwt = {
        header: { alg: 'RS256' }, // missing typ
        payload: {} // missing sub and iss
      };

      const result = jwtCrypto.validateJwtClaims(jwt);
      expect(result.warnings).toContain('Missing or invalid typ claim in header');
      expect(result.warnings).toContain('Missing subject (sub) and issuer (iss) claims');
    });

    test('should calculate time to expiry', () => {
      const jwt = {
        header: { alg: 'RS256', typ: 'JWT' },
        payload: { 
          sub: 'user123',
          exp: baseTime + 1800 // 30 minutes from now
        }
      };

      const result = jwtCrypto.validateJwtClaims(jwt);
      expect(result.claims.timeToExpiry).toBeCloseTo(1800, -1); // Within 10 seconds
    });
  });

  describe('Real-world JWT Examples', () => {
    test('should handle standard JWT structure', () => {
      const header = {
        alg: 'RS256',
        typ: 'JWT',
        kid: 'rsa-key-1'
      };
      
      const payload = {
        iss: 'https://example.com',
        sub: 'user@example.com',
        aud: 'https://api.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        nbf: Math.floor(Date.now() / 1000),
        jti: 'unique-token-id',
        scope: 'read write',
        roles: ['user', 'admin']
      };
      
      const encodedHeader = jwtCrypto.base64UrlEncode(JSON.stringify(header));
      const encodedPayload = jwtCrypto.base64UrlEncode(JSON.stringify(payload));
      const jwt = `${encodedHeader}.${encodedPayload}.signature`;
      
      const parsed = jwtCrypto.parseJwt(jwt);
      expect(parsed.header).toEqual(header);
      expect(parsed.payload).toEqual(payload);
      
      const validation = jwtCrypto.validateJwtClaims(parsed);
      expect(validation.valid).toBe(true);
      expect(validation.issues).toHaveLength(0);
    });
  });
});