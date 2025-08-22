# JWT Crypto Tests

This directory contains comprehensive unit tests for the Web Crypto API functionality used in JWT operations.

## Test Files

### `jwtCrypto.test.js`
Tests for JWT cryptographic utility functions including:
- **Base64 URL Encoding/Decoding**: Tests for proper base64url encoding without padding
- **Algorithm Detection**: Tests for detecting correct algorithms from JWK keys
- **Crypto Algorithm Parameters**: Tests for generating correct Web Crypto API parameters
- **JWT Parsing**: Tests for parsing JWT tokens into header/payload/signature
- **JWT Claims Validation**: Tests for validating timing claims and required fields
- **Error Handling**: Tests for proper error handling in various scenarios

### `JwtBuilder.crypto.test.js`
Integration tests for the JWT Builder component's crypto functionality:
- **JWT Creation**: Tests for creating signed and unsigned JWTs
- **JWT Verification**: Tests for verifying JWT signatures
- **Key Import/Export**: Tests for Web Crypto API key operations
- **Algorithm Support**: Tests for RSA and EC algorithms (RS256, ES256, PS256, etc.)

## Running Tests

### Run All Tests
```bash
npm test
```

### Run Only Crypto Tests
```bash
npm run test:crypto
```

### Run Tests with Coverage
```bash
npm run test:coverage
```

### Run Tests in Watch Mode
```bash
npm test -- --watch
```

### Run Specific Test File
```bash
npm test jwtCrypto.test.js
```

## Test Coverage

The tests cover:

### ✅ Base64 URL Operations
- String encoding/decoding
- ArrayBuffer handling
- Padding edge cases
- Special characters and emojis

### ✅ Algorithm Detection
- RSA key algorithm detection (RS256, RS384, RS512, PS256, PS384, PS512)
- EC key algorithm detection (ES256, ES384, ES512) 
- Curve-based algorithm selection (P-256, P-384, P-521)
- Key usage and key_ops handling

### ✅ JWT Structure
- Header/payload encoding
- Signature handling
- Multi-part JWT parsing
- Malformed JWT handling

### ✅ Cryptographic Operations
- Key import with correct parameters
- Signing with various algorithms
- Signature verification
- Error handling for invalid keys

### ✅ Claims Validation
- Timing claims (exp, nbf, iat)
- Required claims validation
- Security warnings
- Clock skew tolerance

### ✅ Real-world Scenarios
- Standard JWT structures
- Complex nested payloads
- Various header claims (kid, x5t, etc.)
- Integration with Web Crypto API

## Mock Setup

The tests use mocked Web Crypto API for consistent testing:
- `crypto.subtle.importKey`
- `crypto.subtle.exportKey` 
- `crypto.subtle.sign`
- `crypto.subtle.verify`

Node.js compatibility is provided through:
- `TextEncoder`/`TextDecoder` polyfills
- `atob`/`btoa` implementations using Buffer

## Test Data

Tests use realistic JWT examples including:
- Standard header claims (alg, typ, kid)
- Common payload claims (iss, sub, aud, exp, iat, nbf)
- Complex nested objects
- Various key formats (RSA, EC with different curves)

## Security Considerations

Tests verify proper handling of:
- Invalid/malformed JWTs
- Expired tokens
- Not-yet-valid tokens
- Missing required claims
- Weak algorithms
- Key import failures
- Signature verification failures

## Browser Compatibility

The crypto utilities are tested for compatibility with:
- Modern browsers supporting Web Crypto API
- Node.js environments (with polyfills)
- Various JWT libraries and standards