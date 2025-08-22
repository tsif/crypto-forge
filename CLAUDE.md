# Claude Assistant Context

This document provides essential context for AI assistants working on the CryptoForge (key-wizard) project.

## Project Overview

CryptoForge is a comprehensive client-side cryptographic toolkit built with React that provides:
- JWK/JWKS generation for RSA and EC keys with strength analysis
- JWT creation and verification with custom headers (kid, x5t, x5t#S256, x5u)
- PEM/JWK bidirectional format conversion
- X.509 certificate generation and validation
- Certificate chain validation with comprehensive checks
- Key strength analysis with NIST compliance
- Smart key validation with educational feedback

**Core Principle**: All cryptographic operations run locally in the browser using the Web Crypto API. No data is transmitted to any server.

## Key Technical Details

### Architecture

- **Framework**: React 18 (functional components with hooks)
- **Crypto**: Web Crypto API (browser-native)
- **Styling**: CSS with custom properties for theming
- **State Management**: React useState/useEffect hooks with persistence
- **Build Tool**: Create React App
- **Testing**: Jest with Web Crypto API mocks
- **Deployment**: GitHub Actions to GitHub Pages (on PR merge)

### Important Design Decisions

1. **JWT Builder Modes**: Full create/verify functionality with sub-tabs. Create mode is desktop-only for better UX.

2. **State Persistence**: Verify JWT state persists across tab switches. Create JWT state is local.

3. **Security First**: Never log or transmit private keys. All operations are client-side.

4. **Mobile Responsive**: Simplified UI on mobile (≤768px), JWT creation hidden on mobile.

5. **Font Size Toggle**: Accessibility feature with CSS variables and localStorage persistence.

6. **Theme System**: Dark/light themes using CSS custom properties, stored in localStorage.

7. **Fixed Footer**: Desktop-only footer with security notes, requires 280px bottom padding.

8. **Auto Key Detection**: Automatically detects key types and suggests appropriate algorithms.

## Component Structure

```
src/
├── components/
│   ├── Controls.js              # Key generation controls
│   ├── OutputCard.js            # Display generated keys/certs with copy
│   ├── PemConverter.js          # PEM to JWK conversion
│   ├── JwtBuilder.js            # JWT create & verify with custom headers
│   ├── KeyValidator.js          # Single JWK validation
│   ├── SmartKeyValidator.js     # Multi-format key validation
│   ├── JwksValidator.js         # JWKS validation
│   ├── CertificateValidator.js  # X.509 parsing & chain validation
│   ├── CertificateGenerator.js  # X.509 certificate creation
│   ├── KeyStrengthAnalyzer.js   # NIST compliance checks
│   ├── JwtExpirationCalculator.js # JWT timing utilities
│   ├── SegmentedControl.js      # Tab navigation with mobile labels
│   ├── ThemeToggle.js           # Dark/light mode
│   ├── FontSizeToggle.js        # Text size control
│   ├── Toast.js                 # User notifications
│   ├── Spinner.js               # Loading indicator
│   ├── ExplainButton.js         # Educational tooltips
│   ├── CommonMistakesWarning.js # Security guidance
│   └── __tests__/               # Component tests
├── utils/
│   ├── cryptoUtils.js           # Core crypto operations
│   ├── asn1Parser.js            # ASN.1 parsing for certs
│   ├── certChainValidator.js    # Certificate chain validation
│   └── __tests__/               # Utility tests
│       └── jwtCrypto.test.js    # Web Crypto API tests
└── App.js                        # Main app logic & state
```

## Critical Functions

### cryptoUtils.js
- `jwkThumbprint()` - Generates RFC 7638 thumbprints
- `privateKeyId()` - Creates unique IDs for private keys
- `analyzeKeyStrength()` - NIST SP 800-57 compliance checks
- `pemToDer()` / `derToPem()` - Format conversion
- `tryImportRSA()` / `tryImportEC()` - Key import with fallbacks

### JwtBuilder.js
- `createJwtToken()` - Creates signed JWTs with custom headers
- `verifyJwtSignature()` - Validates JWT signatures
- `extractKeyFromX5c()` - Auto-extracts public keys from JWT x5c headers
- `base64UrlEncode()` / `base64UrlDecode()` - JWT encoding utilities
- Supports RS256/384/512, ES256/384/512, PS256/384/512 algorithms
- Auto-fetches keys from URLs ending in .json

### CertificateGenerator.js
- `generateCertificate()` - Creates self-signed X.509 certificates
- `createX509Extensions()` - Adds extensions (basicConstraints, keyUsage, etc.)
- Customizable validity periods and certificate attributes

### CertificateValidator.js
- `parseCertificateChain()` - Parses multiple PEM certificates
- `validateChain()` - Validates certificate chain ordering and constraints
- Checks expiration, signature algorithms, CA constraints

### App.js
- `extractPublicKeyFromCertificate()` - ASN.1 parsing for cert public keys
- State persistence for all validation tabs
- Key generation with proper algorithm selection (RSA-OAEP for encryption)
- `getAvailableKeys()` - Provides keys to JWT Builder from other tabs

## Common Tasks & Commands

```bash
# Development
npm start              # Start dev server on port 3000
npm run build          # Production build
npm test               # Run all tests
npm run test:crypto    # Run crypto-specific tests
npm run test:coverage  # Generate coverage report

# Deployment (automatic on PR merge)
# GitHub Actions deploys to: https://dtsiflit.github.io/key-wizard
```

## State Management Patterns

```javascript
// Tab state persistence pattern
const [jwtBuilderState, setJwtBuilderState] = useState({
  activeSubTab: 'create',
  selectedKeyId: '',
  headerClaims: { typ: 'JWT' },
  payloadClaims: { /* ... */ },
  customClaims: '{}',
  generatedJwt: ''
});

// Verify state persists, create state is local
const state = localState.activeSubTab === 'verify' 
  ? { ...localState, ...jwtVerifyState }
  : localState;

// Mobile detection pattern
const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
```

## Styling Patterns

```css
/* Theme variables */
:root {
  --ink: #111;
  --card: #ffffff;
  --base-font-size: 14px;
}

[data-theme="dark"] {
  --ink: #e5e5e5;
  --card: #1a1a1a;
}

/* Font size variables */
[data-font-size="large"] {
  --base-font-size: 18px;
}

/* Mobile responsiveness */
@media (max-width: 768px) {
  .desktop-only { display: none !important; }
  .mobile-only { display: block; }
}
```

## Testing Strategy

### Unit Tests
- Base64 URL encoding/decoding
- Algorithm detection from JWK
- JWT parsing and validation
- Claims validation (exp, nbf, iat)
- Web Crypto API mocking

### Integration Tests
- JWT creation with various algorithms
- Signature verification
- Key import/export
- Certificate chain validation

### Test Files
- `src/utils/__tests__/jwtCrypto.test.js` - Core crypto utilities
- `src/components/__tests__/JwtBuilder.crypto.test.js` - JWT operations

## Security Considerations

1. **Never** add network requests for crypto operations (except fetching public keys)
2. **Never** log private key material
3. **Never** store keys beyond session
4. **Always** validate input formats before crypto operations
5. **Always** use Web Crypto API, not custom implementations
6. **Always** check certificate expiration and constraints
7. **Never** trust x5c chains without validation

## Known Issues & Workarounds

1. **Textarea Styling**: Single-row textareas use `height: 40px` with `resize: vertical`

2. **JWKS Duplicate IDs**: Private/public keys need different IDs. Use `privateKeyId()` for private keys.

3. **RSA Bit Calculation**: Must decode base64url and count actual bits, not string length.

4. **Encryption Keys**: Must use RSA-OAEP for RSA encryption, ECDH for EC key agreement.

5. **Mobile Segmented Control**: Uses shorter labels and responsive breakpoints.

6. **JWT State**: Verify mode uses persistent state, Create mode uses local state.

## Testing Checklist

When making changes, always test:

- [ ] Key generation (RSA 2048/3072/4096, EC P-256/384/521)
- [ ] JWT creation with custom headers (kid, x5t, etc.)
- [ ] JWT verification with manual and x5c keys
- [ ] URL-based key fetching (.json endpoints)
- [ ] PEM/JWK conversion both directions
- [ ] Certificate generation with custom attributes
- [ ] Certificate chain validation
- [ ] JWKS validation with keypairs
- [ ] Theme switching persistence
- [ ] Font size toggle functionality
- [ ] Mobile responsiveness (hide JWT create)
- [ ] Segmented control on various screen sizes
- [ ] State persistence across tab switches

## Performance Tips

1. Batch state updates when possible
2. Use `useCallback` for expensive operations
3. Avoid unnecessary re-renders with proper dependency arrays
4. Keep bundle size minimal (currently ~80KB gzipped)
5. Lazy load educational components
6. Use CSS transforms for animations

## Future Enhancement Ideas

- [ ] JWE (JSON Web Encryption) support
- [ ] EdDSA/Ed25519 support
- [ ] Batch key operations
- [ ] Key rotation workflows
- [ ] OCSP/CRL checking
- [ ] WebAuthn key support
- [ ] Export/import key archives
- [ ] JWT decode history

## Browser Compatibility

- Requires modern browsers with Web Crypto API
- Chrome 37+, Firefox 34+, Safari 11+, Edge 79+
- No IE11 support
- Mobile Safari 11+ for iOS
- Chrome Mobile 37+ for Android

## Deployment Notes

- **Production URL**: https://dtsiflit.github.io/key-wizard
- **Deployment**: Automatic via GitHub Actions on PR merge to main
- **Build**: Static site, no backend required
- **Environment**: No environment variables needed
- **Output**: Build outputs to `build/` directory
- **Pages Config**: Set to deploy from GitHub Actions

## CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
- Triggers on PR merge to main (not direct push)
- Runs tests with coverage
- Builds with PUBLIC_URL for GitHub Pages
- Deploys to github-pages environment
```

## Contact & Resources

- Repository: https://github.com/dtsiflit/key-wizard
- Live App: https://dtsiflit.github.io/key-wizard
- Security issues: See SECURITY.md
- Contributing: See CONTRIBUTING.md
- License: MIT (see LICENSE file)

---

*Last updated: December 2024*
*Remember: This is a security-sensitive application. Always prioritize security over features.*
*JWT create functionality is desktop-only by design for better UX.*