# Claude Assistant Context

This document provides essential context for AI assistants working on the CryptoForge (key-wizard) project.

## Project Overview

CryptoForge is a client-side cryptographic toolkit built with React that provides:
- JWK/JWKS generation for RSA and EC keys
- PEM/JWK format conversion
- JWT verification with x5c certificate extraction
- X.509 certificate validation and parsing
- Key strength analysis

**Core Principle**: All cryptographic operations run locally in the browser using the Web Crypto API. No data is transmitted to any server.

## Key Technical Details

### Architecture

- **Framework**: React (functional components with hooks)
- **Crypto**: Web Crypto API (browser-native)
- **Styling**: CSS with custom properties for theming
- **State Management**: React useState/useEffect hooks
- **Build Tool**: Create React App

### Important Design Decisions

1. **Verify-Only JWT**: The JWT Builder component has create functionality but is currently set to `verifyOnly={true}` mode. The create code remains dormant for potential future use.

2. **Security First**: Never log or transmit private keys. All operations are client-side.

3. **Font Size Toggle**: Uses CSS variables with `data-font-size` attribute on document element for accessibility.

4. **Theme System**: Dark/light themes using CSS custom properties, stored in localStorage.

5. **Fixed Footer**: Desktop-only footer with security notes, requires 280px bottom padding on body.

## Component Structure

```
src/
├── components/
│   ├── Controls.js           # Key generation controls
│   ├── OutputCard.js         # Display generated keys/certs
│   ├── PemConverter.js       # PEM to JWK conversion
│   ├── JwtBuilder.js         # JWT verify (+ dormant create)
│   ├── KeyValidator.js       # Single JWK validation
│   ├── JwksValidator.js      # JWKS validation
│   ├── CertificateValidator.js # X.509 parsing
│   ├── KeyStrengthAnalyzer.js  # NIST compliance checks
│   ├── SegmentedControl.js  # Tab navigation
│   ├── ThemeToggle.js       # Dark/light mode
│   └── FontSizeToggle.js    # Text size control
├── utils/
│   ├── cryptoUtils.js       # Core crypto operations
│   ├── asn1Parser.js        # ASN.1 parsing for certs
│   └── certChainValidator.js # Certificate chain validation
└── App.js                    # Main app logic & state

```

## Critical Functions

### cryptoUtils.js
- `jwkThumbprint()` - Generates RFC 7638 thumbprints
- `privateKeyId()` - Creates unique IDs for private keys
- `analyzeKeyStrength()` - NIST SP 800-57 compliance checks
- `pemToDer()` / `derToPem()` - Format conversion
- `tryImportRSA()` / `tryImportEC()` - Key import with fallbacks

### JwtBuilder.js
- `extractKeyFromX5c()` - Auto-extracts public keys from JWT x5c headers
- `verifyJwt()` - Validates JWT signatures
- Supports RS256/384/512, ES256/384/512 algorithms

### App.js
- `extractPublicKeyFromCertificate()` - ASN.1 parsing for cert public keys
- State persistence for validation tabs
- Key generation with proper algorithm selection (RSA-OAEP for encryption)

## Common Tasks & Commands

```bash
# Development
npm start          # Start dev server on port 3000
npm run build      # Production build
npm test           # Run tests

# Linting (check for warnings)
npm run build      # Shows ESLint warnings
```

## Known Issues & Workarounds

1. **Textarea Height**: CSS has default `min-height: 160px`. Override with inline styles and `rows` attribute.

2. **JWKS Duplicate IDs**: Private/public keys need different IDs. Use `privateKeyId()` for private keys.

3. **RSA Bit Calculation**: Must decode base64url and count actual bits, not string length.

4. **Encryption Keys**: Must use RSA-OAEP for RSA encryption, ECDH for EC key agreement.

## Testing Checklist

When making changes, always test:

- [ ] Key generation (RSA/EC, various sizes/curves)
- [ ] PEM/JWK conversion both directions
- [ ] Certificate PEM extraction
- [ ] JWT verification with manual and x5c keys
- [ ] JWKS validation with keypairs
- [ ] Theme switching persistence
- [ ] Font size toggle functionality
- [ ] Mobile responsiveness
- [ ] Footer clearance on all tabs

## Security Considerations

1. **Never** add network requests for crypto operations
2. **Never** log private key material
3. **Never** store keys beyond session
4. **Always** validate input formats before crypto operations
5. **Always** use Web Crypto API, not custom implementations

## State Management Patterns

```javascript
// Tab state persistence pattern
const [validatorState, setValidatorState] = useState({
  input: '',
  result: null
});

// Pass to child components as props
<KeyValidator 
  input={validatorState.input}
  setInput={(input) => setValidatorState(prev => ({ ...prev, input }))}
/>
```

## Styling Patterns

```css
/* Theme variables */
:root {
  --ink: #1a1a1a;
  --card: #ffffff;
  /* ... */
}

[data-theme="dark"] {
  --ink: #e5e5e5;
  --card: #1f1f1f;
  /* ... */
}

/* Font size variables */
[data-font-size="large"] {
  --base-font-size: 18px;
  /* ... */
}
```

## Performance Tips

1. Batch state updates when possible
2. Use `useCallback` for expensive operations
3. Avoid unnecessary re-renders with proper dependency arrays
4. Keep bundle size minimal (currently ~67KB gzipped)

## Future Enhancement Ideas

- JWT create functionality (code exists, currently disabled)
- Additional key formats (PKCS#1, etc.)
- Batch operations
- Key rotation workflows
- Advanced certificate chain validation
- WebAuthn key support

## Browser Compatibility

- Requires modern browsers with Web Crypto API
- Chrome 37+, Firefox 34+, Safari 11+, Edge 79+
- No IE11 support

## Deployment Notes

- Static site, can deploy to any static host
- No backend required
- No environment variables needed
- Build outputs to `build/` directory

## Contact & Resources

- Security issues: See SECURITY.md
- Contributing: See CONTRIBUTING.md
- License: MIT (see LICENSE file)

---

*Last updated: 2025*
*Remember: This is a security-sensitive application. Always prioritize security over features.*