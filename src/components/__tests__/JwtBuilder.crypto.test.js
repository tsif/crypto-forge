import { TextEncoder, TextDecoder } from 'util';

// Mock Web Crypto API for testing
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Mock crypto.subtle
const mockCrypto = {
  subtle: {
    importKey: jest.fn(),
    exportKey: jest.fn(),
    sign: jest.fn(),
    verify: jest.fn(),
    generateKey: jest.fn()
  }
};

global.crypto = mockCrypto;
global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');

// Import the functions we want to test by extracting them from the component
// Since they're inside the component, we'll create standalone versions for testing

// Base64 URL encoding/decoding functions
const base64UrlEncode = (data) => {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  return btoa(String.fromCharCode(...new Uint8Array(data)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

const base64UrlDecode = (str) => {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  return decodeURIComponent(atob(str).split('').map(c => 
    '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
  ).join(''));
};

const base64UrlDecodeToArrayBuffer = (str) => {
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
};

// Algorithm detection function
const getAlgorithmFromKey = (jwk) => {
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
};

// JWT creation function
const createJwtToken = async (header, payload, jwk, algorithm) => {
  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  if (algorithm === 'none') {
    return `${signingInput}.`;
  }

  // Import the key for signing
  let cryptoKey;
  if (jwk.kty === 'RSA') {
    const keyAlgorithm = algorithm.startsWith('PS') ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5';
    const hash = algorithm.includes('384') ? 'SHA-384' : algorithm.includes('512') ? 'SHA-512' : 'SHA-256';
    
    cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: keyAlgorithm, hash },
      false,
      ['sign']
    );
  } else if (jwk.kty === 'EC') {
    cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDSA', namedCurve: jwk.crv },
      false,
      ['sign']
    );
  }

  // Sign the JWT
  const signature = await crypto.subtle.sign(
    jwk.kty === 'RSA' 
      ? (algorithm.startsWith('PS') ? { name: 'RSA-PSS', saltLength: 32 } : 'RSASSA-PKCS1-v1_5')
      : { name: 'ECDSA', hash: algorithm.includes('384') ? 'SHA-384' : algorithm.includes('512') ? 'SHA-512' : 'SHA-256' },
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );

  const encodedSignature = base64UrlEncode(signature);
  return `${signingInput}.${encodedSignature}`;
};

// JWT verification function
const verifyJwtSignature = async (parts, header, jwk) => {
  const signingInput = `${parts[0]}.${parts[1]}`;
  const signature = base64UrlDecodeToArrayBuffer(parts[2]);

  let cryptoKey;
  if (jwk.kty === 'RSA') {
    const keyAlgorithm = header.alg.startsWith('PS') ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5';
    const hash = header.alg.includes('384') ? 'SHA-384' : header.alg.includes('512') ? 'SHA-512' : 'SHA-256';
    
    cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: keyAlgorithm, hash },
      false,
      ['verify']
    );
  } else if (jwk.kty === 'EC') {
    cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDSA', namedCurve: jwk.crv },
      false,
      ['verify']
    );
  }

  return await crypto.subtle.verify(
    jwk.kty === 'RSA' 
      ? (header.alg.startsWith('PS') ? { name: 'RSA-PSS', saltLength: 32 } : 'RSASSA-PKCS1-v1_5')
      : { name: 'ECDSA', hash: header.alg.includes('384') ? 'SHA-384' : header.alg.includes('512') ? 'SHA-512' : 'SHA-256' },
    cryptoKey,
    signature,
    new TextEncoder().encode(signingInput)
  );
};

describe('JWT Builder Crypto Functions', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Base64 URL Encoding/Decoding', () => {
    test('base64UrlEncode should encode strings correctly', () => {
      const input = 'Hello World';
      const result = base64UrlEncode(input);
      
      // Should not contain +, /, or = characters
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
      expect(result).not.toContain('=');
      
      // Should be reversible
      const decoded = base64UrlDecode(result);
      expect(decoded).toBe(input);
    });

    test('base64UrlEncode should encode ArrayBuffer correctly', () => {
      const input = new Uint8Array([72, 101, 108, 108, 111]).buffer; // "Hello"
      const result = base64UrlEncode(input);
      
      expect(result).toBe('SGVsbG8');
    });

    test('base64UrlDecode should decode correctly', () => {
      const input = 'SGVsbG8gV29ybGQ'; // "Hello World" in base64url
      const result = base64UrlDecode(input);
      
      expect(result).toBe('Hello World');
    });

    test('base64UrlDecodeToArrayBuffer should return ArrayBuffer', () => {
      const input = 'SGVsbG8'; // "Hello" in base64url
      const result = base64UrlDecodeToArrayBuffer(input);
      
      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(new Uint8Array(result)).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    test('should handle padding correctly', () => {
      const testCases = [
        'SGVsbG8',     // no padding needed
        'SGVsbG9o',    // 1 padding
        'SGVsbG9oZQ',  // 2 padding
      ];

      testCases.forEach(encoded => {
        expect(() => base64UrlDecode(encoded)).not.toThrow();
        expect(() => base64UrlDecodeToArrayBuffer(encoded)).not.toThrow();
      });
    });
  });

  describe('Algorithm Detection', () => {
    test('should return correct algorithm for RSA keys', () => {
      const rsaKey = { kty: 'RSA', alg: 'RS256' };
      expect(getAlgorithmFromKey(rsaKey)).toBe('RS256');
    });

    test('should return default RS256 for RSA keys without alg', () => {
      const rsaKey = { kty: 'RSA' };
      expect(getAlgorithmFromKey(rsaKey)).toBe('RS256');
    });

    test('should return correct algorithm for EC keys', () => {
      const ecKey = { kty: 'EC', crv: 'P-256' };
      expect(getAlgorithmFromKey(ecKey)).toBe('ES256');
      
      const ecKey384 = { kty: 'EC', crv: 'P-384' };
      expect(getAlgorithmFromKey(ecKey384)).toBe('ES384');
      
      const ecKey521 = { kty: 'EC', crv: 'P-521' };
      expect(getAlgorithmFromKey(ecKey521)).toBe('ES512');
    });

    test('should return none for null/undefined keys', () => {
      expect(getAlgorithmFromKey(null)).toBe('none');
      expect(getAlgorithmFromKey(undefined)).toBe('none');
    });

    test('should handle encryption use keys', () => {
      const encKey = { kty: 'RSA', use: 'enc' };
      expect(getAlgorithmFromKey(encKey)).toBe('RS256');
      
      const encKeyOps = { kty: 'RSA', key_ops: ['encrypt'] };
      expect(getAlgorithmFromKey(encKeyOps)).toBe('RS256');
    });
  });

  describe('JWT Creation', () => {
    const mockSignature = new ArrayBuffer(64);
    const mockCryptoKey = { type: 'private' };

    beforeEach(() => {
      mockCrypto.subtle.importKey.mockResolvedValue(mockCryptoKey);
      mockCrypto.subtle.sign.mockResolvedValue(mockSignature);
    });

    test('should create unsigned JWT for none algorithm', async () => {
      const header = { alg: 'none', typ: 'JWT' };
      const payload = { sub: '1234567890', name: 'John Doe' };
      
      const jwt = await createJwtToken(header, payload, null, 'none');
      
      const parts = jwt.split('.');
      expect(parts).toHaveLength(3);
      expect(parts[2]).toBe(''); // No signature for none algorithm
      
      // Verify header and payload are correctly encoded
      expect(JSON.parse(base64UrlDecode(parts[0]))).toEqual(header);
      expect(JSON.parse(base64UrlDecode(parts[1]))).toEqual(payload);
    });

    test('should create signed JWT for RSA key', async () => {
      const header = { alg: 'RS256', typ: 'JWT' };
      const payload = { sub: '1234567890', name: 'John Doe' };
      const rsaKey = { kty: 'RSA', n: 'test', e: 'AQAB' };
      
      const jwt = await createJwtToken(header, payload, rsaKey, 'RS256');
      
      const parts = jwt.split('.');
      expect(parts).toHaveLength(3);
      expect(parts[2]).toBeTruthy(); // Should have signature
      
      // Verify crypto.subtle calls
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'jwk',
        rsaKey,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['sign']
      );
      
      expect(mockCrypto.subtle.sign).toHaveBeenCalledWith(
        'RSASSA-PKCS1-v1_5',
        mockCryptoKey,
        expect.any(Object)
      );
    });

    test('should create signed JWT for EC key', async () => {
      const header = { alg: 'ES256', typ: 'JWT' };
      const payload = { sub: '1234567890', name: 'John Doe' };
      const ecKey = { kty: 'EC', crv: 'P-256', x: 'test', y: 'test' };
      
      const jwt = await createJwtToken(header, payload, ecKey, 'ES256');
      
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'jwk',
        ecKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign']
      );
      
      expect(mockCrypto.subtle.sign).toHaveBeenCalledWith(
        { name: 'ECDSA', hash: 'SHA-256' },
        mockCryptoKey,
        expect.any(Object)
      );
    });

    test('should handle different hash algorithms', async () => {
      const rsaKey = { kty: 'RSA', n: 'test', e: 'AQAB' };
      
      // Test RS384
      await createJwtToken({ alg: 'RS384' }, {}, rsaKey, 'RS384');
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'jwk',
        rsaKey,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
        false,
        ['sign']
      );
      
      // Test RS512
      await createJwtToken({ alg: 'RS512' }, {}, rsaKey, 'RS512');
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'jwk',
        rsaKey,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
        false,
        ['sign']
      );
    });

    test('should handle PSS algorithms', async () => {
      const rsaKey = { kty: 'RSA', n: 'test', e: 'AQAB' };
      
      await createJwtToken({ alg: 'PS256' }, {}, rsaKey, 'PS256');
      
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'jwk',
        rsaKey,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        false,
        ['sign']
      );
      
      expect(mockCrypto.subtle.sign).toHaveBeenCalledWith(
        { name: 'RSA-PSS', saltLength: 32 },
        mockCryptoKey,
        expect.any(Object)
      );
    });
  });

  describe('JWT Verification', () => {
    const mockCryptoKey = { type: 'public' };

    beforeEach(() => {
      mockCrypto.subtle.importKey.mockResolvedValue(mockCryptoKey);
      mockCrypto.subtle.verify.mockResolvedValue(true);
    });

    test('should verify RSA JWT signature', async () => {
      const parts = ['header', 'payload', 'signature'];
      const header = { alg: 'RS256' };
      const rsaKey = { kty: 'RSA', n: 'test', e: 'AQAB' };
      
      const result = await verifyJwtSignature(parts, header, rsaKey);
      
      expect(result).toBe(true);
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'jwk',
        rsaKey,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      );
      
      expect(mockCrypto.subtle.verify).toHaveBeenCalledWith(
        'RSASSA-PKCS1-v1_5',
        mockCryptoKey,
        expect.any(Object),
        expect.any(Object)
      );
    });

    test('should verify EC JWT signature', async () => {
      const parts = ['header', 'payload', 'signature'];
      const header = { alg: 'ES256' };
      const ecKey = { kty: 'EC', crv: 'P-256', x: 'test', y: 'test' };
      
      const result = await verifyJwtSignature(parts, header, ecKey);
      
      expect(result).toBe(true);
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'jwk',
        ecKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );
      
      expect(mockCrypto.subtle.verify).toHaveBeenCalledWith(
        { name: 'ECDSA', hash: 'SHA-256' },
        mockCryptoKey,
        expect.any(Object),
        expect.any(Object)
      );
    });

    test('should handle verification failure', async () => {
      mockCrypto.subtle.verify.mockResolvedValue(false);
      
      const parts = ['header', 'payload', 'signature'];
      const header = { alg: 'RS256' };
      const rsaKey = { kty: 'RSA', n: 'test', e: 'AQAB' };
      
      const result = await verifyJwtSignature(parts, header, rsaKey);
      
      expect(result).toBe(false);
    });

    test('should handle different EC curves', async () => {
      const parts = ['header', 'payload', 'signature'];
      
      // Test P-384
      await verifyJwtSignature(parts, { alg: 'ES384' }, { kty: 'EC', crv: 'P-384' });
      expect(mockCrypto.subtle.verify).toHaveBeenCalledWith(
        { name: 'ECDSA', hash: 'SHA-384' },
        mockCryptoKey,
        expect.any(Object),
        expect.any(Object)
      );
      
      // Test P-521
      await verifyJwtSignature(parts, { alg: 'ES512' }, { kty: 'EC', crv: 'P-521' });
      expect(mockCrypto.subtle.verify).toHaveBeenCalledWith(
        { name: 'ECDSA', hash: 'SHA-512' },
        mockCryptoKey,
        expect.any(Object),
        expect.any(Object)
      );
    });
  });

  describe('Integration Tests', () => {
    test('should create and parse valid JWT structure', async () => {
      const header = { alg: 'none', typ: 'JWT', kid: 'test-key' };
      const payload = { 
        sub: '1234567890', 
        name: 'John Doe', 
        iat: 1516239022,
        exp: 1516239022 + 3600
      };
      
      const jwt = await createJwtToken(header, payload, null, 'none');
      const parts = jwt.split('.');
      
      expect(parts).toHaveLength(3);
      
      const decodedHeader = JSON.parse(base64UrlDecode(parts[0]));
      const decodedPayload = JSON.parse(base64UrlDecode(parts[1]));
      
      expect(decodedHeader).toEqual(header);
      expect(decodedPayload).toEqual(payload);
    });

    test('should handle empty payload', async () => {
      const header = { alg: 'none', typ: 'JWT' };
      const payload = {};
      
      const jwt = await createJwtToken(header, payload, null, 'none');
      const parts = jwt.split('.');
      
      const decodedPayload = JSON.parse(base64UrlDecode(parts[1]));
      expect(decodedPayload).toEqual({});
    });

    test('should handle complex nested payload', async () => {
      const header = { alg: 'none', typ: 'JWT' };
      const payload = {
        sub: '1234567890',
        name: 'John Doe',
        roles: ['admin', 'user'],
        permissions: {
          read: true,
          write: false,
          admin: true
        },
        metadata: {
          created: '2024-01-01',
          updated: '2024-01-02'
        }
      };
      
      const jwt = await createJwtToken(header, payload, null, 'none');
      const parts = jwt.split('.');
      
      const decodedPayload = JSON.parse(base64UrlDecode(parts[1]));
      expect(decodedPayload).toEqual(payload);
    });
  });

  describe('Error Handling', () => {
    test('should handle crypto.subtle.importKey errors', async () => {
      mockCrypto.subtle.importKey.mockRejectedValue(new Error('Invalid key'));
      
      const header = { alg: 'RS256', typ: 'JWT' };
      const payload = { sub: 'test' };
      const invalidKey = { kty: 'RSA', n: 'invalid' };
      
      await expect(createJwtToken(header, payload, invalidKey, 'RS256'))
        .rejects.toThrow('Invalid key');
    });

    test('should handle crypto.subtle.sign errors', async () => {
      mockCrypto.subtle.importKey.mockResolvedValue({ type: 'private' });
      mockCrypto.subtle.sign.mockRejectedValue(new Error('Signing failed'));
      
      const header = { alg: 'RS256', typ: 'JWT' };
      const payload = { sub: 'test' };
      const key = { kty: 'RSA', n: 'test', e: 'AQAB' };
      
      await expect(createJwtToken(header, payload, key, 'RS256'))
        .rejects.toThrow('Signing failed');
    });

    test('should handle crypto.subtle.verify errors', async () => {
      mockCrypto.subtle.importKey.mockResolvedValue({ type: 'public' });
      mockCrypto.subtle.verify.mockRejectedValue(new Error('Verification failed'));
      
      const parts = ['header', 'payload', 'signature'];
      const header = { alg: 'RS256' };
      const key = { kty: 'RSA', n: 'test', e: 'AQAB' };
      
      await expect(verifyJwtSignature(parts, header, key))
        .rejects.toThrow('Verification failed');
    });
  });
});