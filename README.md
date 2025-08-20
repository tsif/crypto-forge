# CryptoForge — Your Complete Key & Certificate Toolkit

A comprehensive web-based cryptographic toolkit for generating, converting, validating, and analyzing keys and certificates. All operations run securely in your browser using the Web Crypto API.

![CryptoForge Screenshot](https://via.placeholder.com/800x400/2a2a2a/ffffff?text=CryptoForge+Screenshot)

## 🚀 Features

### Key Generation
- **RSA Keys**: 2048, 3072, 4096-bit support with SHA-256/384/512 hashing
- **Elliptic Curve Keys**: P-256, P-384, P-521 curves (NIST standard)  
- **Multiple Output Formats**: JWK, JWKS, PEM (SPKI/PKCS#8), OpenSSH
- **Automatic Key Parameters**: kid (thumbprint), alg, use, key_ops

### Format Conversion
- **PEM ↔ JWK Conversion**: Bidirectional conversion between formats
- **OpenSSH Export**: Generate SSH-compatible public keys
- **JWKS Generation**: Create JSON Web Key Sets for public distribution
- **Auto-Detection**: Supports both RSA and EC keys automatically

### Validation & Analysis
- **JWK Validation**: Validate individual JSON Web Keys
- **JWKS Validation**: Validate entire JSON Web Key Sets with security analysis
- **Certificate Validation**: Parse and validate X.509 certificates
- **Certificate Chain Validation**: Analyze complete certificate chains
- **Key Strength Analysis**: NIST-compliant security recommendations

### Security Features
- **Real-time Input Validation**: Visual feedback for malformed inputs
- **Security Timeline**: Shows when keys need replacement (based on NIST SP 800-57)
- **Chain Analysis**: Certificate chain structure and validity verification
- **Proper ASN.1 Parsing**: Accurate X.509 certificate field extraction
- **Private Key Detection**: Warns about private keys in public JWKS

## 🛠️ Technology Stack

- **Frontend**: React 18 with Hooks
- **Cryptography**: Web Crypto API (browser-native)
- **ASN.1 Parsing**: Custom lightweight parser for X.509 certificates
- **Styling**: CSS Custom Properties with light/dark theme support
- **Build System**: Create React App

## 📦 Installation

### Prerequisites
- Node.js 16+ 
- npm or yarn

### Setup
```bash
# Clone the repository
git clone https://github.com/your-username/cryptoforge.git
cd cryptoforge

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build
```

The application will be available at `http://localhost:3000`.

## 🎯 Usage

### Generate Keys
1. Select **Generate Keys** tab
2. Choose algorithm (RSA or EC) and parameters
3. Click **Generate keypair**
4. Copy or download keys in your preferred format

### Convert PEM to JWK
1. Select **PEM → JWK / JWKS** tab
2. Paste PEM-formatted key (PUBLIC KEY or PRIVATE KEY)
3. Click **Convert PEM**
4. Get JWK, JWKS, and OpenSSH formats

### Validate Keys
1. Select **Validate JWK** tab for individual keys
2. Select **Validate JWKS** tab for key sets
3. Paste the key/keyset JSON
4. View validation results and security analysis

### Analyze Certificates
1. Select **Validate Certificate** tab
2. Paste single certificate or certificate chain
3. View detailed certificate analysis and chain validation

## 🔒 Security Features

### Key Strength Analysis
Based on **NIST SP 800-57 Part 1 Rev 5**:

| Key Type | Security Level | Valid Through |
|----------|----------------|---------------|
| RSA 2048-bit | Acceptable | 2030 |
| RSA 3072-bit | Good | 2030+ |
| RSA 7680-bit | Excellent | 2030+ |
| EC P-256 | Good | 2030+ |
| EC P-384 | Excellent | 2030+ |
| EC P-521 | Excellent | 2040+ |

### Security Validations
- **JWKS Security**: Detects private keys in public key sets
- **Certificate Chain**: Validates issuer/subject relationships
- **Algorithm Strength**: Identifies weak signature algorithms
- **Expiration Checking**: Warns about expired or not-yet-valid certificates

## 🏗️ Architecture

### Components
- **`Controls`**: Key generation parameters and controls
- **`OutputCard`**: Reusable component for displaying generated content
- **`PemConverter`**: PEM to JWK conversion interface
- **`KeyValidator`**: Individual JWK validation
- **`JwksValidator`**: JWKS document validation
- **`CertificateValidator`**: X.509 certificate and chain analysis
- **`KeyStrengthAnalyzer`**: Security analysis display
- **`SegmentedControl`**: Tab navigation interface

### Utilities
- **`cryptoUtils.js`**: Core cryptographic operations and conversions
- **`asn1Parser.js`**: ASN.1/DER parsing for X.509 certificates
- **`certChainValidator.js`**: Certificate chain validation logic

## 🔧 API Reference

### Key Generation
```javascript
// Generate RSA key pair
const keyPair = await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: 'SHA-256'
  },
  true,
  ['sign', 'verify']
);
```

### Format Conversion
```javascript
// Convert JWK to OpenSSH format
const opensshKey = jwkToOpenSSH(publicJwk, 'comment');

// Convert PEM to JWK
const { der, label } = pemToDer(pemString);
const jwk = await crypto.subtle.exportKey('jwk', importedKey);
```

## 🎨 Customization

### Theme Support
The application supports automatic light/dark theme switching based on system preferences:

```css
:root {
  --bg: #f7f7fb;
  --card: #ffffff;
  --ink: #111;
}

[data-theme="dark"] {
  --bg: #0a0a0a;
  --card: #1a1a1a;
  --ink: #e5e5e5;
}
```

### Adding New Algorithms
To add support for new algorithms:

1. Update `algForSelection()` in `cryptoUtils.js`
2. Add algorithm-specific key generation logic
3. Update the `analyzeKeyStrength()` function
4. Add UI controls in the `Controls` component

## 📝 Certificate Chain Example

```
-----BEGIN CERTIFICATE-----
[End Entity Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Intermediate CA Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Root CA Certificate]
-----END CERTIFICATE-----
```

The validator will:
- Parse each certificate individually
- Verify the chain structure (End Entity → Intermediate → Root)
- Check subject/issuer relationships
- Validate certificate validity periods
- Identify weak signature algorithms

## ⚠️ Security Notes

- **Local Processing**: All operations run in your browser - no data is sent to servers
- **Private Key Handling**: Private keys should never be shared in JWKS documents
- **Certificate Verification**: Always verify certificate chains and CRL status separately
- **Algorithm Recommendations**: Follow NIST guidelines for algorithm selection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NIST SP 800-57**: Key management recommendations
- **RFC 7517**: JSON Web Key (JWK) specification  
- **RFC 7518**: JSON Web Algorithms (JWA) specification
- **ITU-T X.690**: ASN.1 encoding rules
- **Web Crypto API**: Browser-native cryptographic operations

## 📞 Support

For support, questions, or feature requests:
- Create an issue on GitHub
- Check the existing documentation
- Review the security notes for best practices

---

**Built for developers. Use at your own risk.**

© 2025 • CryptoForge Toolkit