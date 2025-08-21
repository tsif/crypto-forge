import React, { useState } from 'react';

function ExplainButton({ concept, title, compact = false, position = 'left' }) {
  const [showExplanation, setShowExplanation] = useState(false);

  // Educational content for different concepts
  const explanations = {
    'rsa': {
      title: 'RSA Algorithm',
      content: `RSA is a public-key cryptosystem widely used for secure data transmission. It uses two mathematically linked keys:
      
      • Public Key: Can be shared openly, used for encryption and signature verification
      • Private Key: Must be kept secret, used for decryption and signing
      
      Key Sizes:
      • 2048-bit: Minimum recommended for new systems
      • 3072-bit: Good security level (~128-bit equivalent)
      • 4096-bit: High security but slower performance
      
      Common Uses: SSL/TLS certificates, email encryption, digital signatures`
    },
    'ec': {
      title: 'Elliptic Curve Cryptography (ECC)',
      content: `ECC provides the same security as RSA with smaller key sizes, making it faster and more efficient.
      
      Popular Curves:
      • P-256: 128-bit security, widely supported
      • P-384: 192-bit security, high security applications  
      • P-521: 256-bit security, maximum security
      
      Advantages:
      • Smaller keys = faster operations
      • Lower power consumption
      • Same security with less bandwidth
      
      Common Uses: Mobile devices, IoT, modern TLS, cryptocurrencies`
    },
    'key-use': {
      title: 'Key Usage Types',
      content: `Different cryptographic operations require different key configurations:
      
      Signature (sig):
      • Used for: Digital signatures, authentication
      • Operations: Sign data, verify signatures
      • Example: JWT signing, code signing certificates
      
      Encryption (enc):
      • Used for: Data encryption, key exchange
      • Operations: Encrypt/decrypt data, key agreement
      • Example: TLS key exchange, file encryption
      
      ⚠️ Important: Never use the same key for both signing and encryption - this can compromise security!`
    },
    'jwt': {
      title: 'JSON Web Tokens (JWT)',
      content: `JWTs are a compact way to securely transmit information between parties as JSON objects.
      
      Structure: header.payload.signature
      • Header: Algorithm and token type
      • Payload: Claims (data about user/session)
      • Signature: Ensures token hasn't been tampered with
      
      Security:
      • Always verify signatures before trusting claims
      • Check expiration (exp) and not-before (nbf) times
      • Use strong algorithms (RS256, ES256, not HS256 with weak secrets)
      
      Common Mistakes: Using symmetric keys in public applications, not validating expiration`
    },
    'jwk': {
      title: 'JSON Web Key (JWK)',
      content: `JWK is a JSON format for representing cryptographic keys in a standardized way.
      
      Key Components:
      • kty: Key type (RSA, EC, oct)
      • use: Intended use (sig, enc)
      • alg: Algorithm (RS256, ES256, etc.)
      • kid: Key ID for identification
      
      RSA Keys: Include n (modulus) and e (exponent)
      EC Keys: Include crv (curve), x and y coordinates
      
      Best Practice: Use different keys for signing and encryption, include 'use' and 'alg' parameters`
    },
    'pem': {
      title: 'PEM Format',
      content: `Privacy-Enhanced Mail (PEM) is a Base64 encoding format for certificates and keys.
      
      Structure:
      • -----BEGIN [TYPE]----- header
      • Base64 encoded data (64 chars per line)  
      • -----END [TYPE]----- footer
      
      Common Types:
      • PRIVATE KEY: Private key in PKCS#8 format
      • PUBLIC KEY: Public key in X.509 SubjectPublicKeyInfo
      • CERTIFICATE: X.509 certificate
      • RSA PRIVATE KEY: RSA key in PKCS#1 format
      
      Usage: Widely supported by tools like OpenSSL, web servers, and programming libraries`
    },
    'certificate-chain': {
      title: 'Certificate Chain',
      content: `A certificate chain establishes trust from an end-entity certificate to a trusted root CA.
      
      Chain Components:
      • End-Entity (Leaf): The actual certificate (website, user, etc.)
      • Intermediate CA: Issues end-entity certificates
      • Root CA: Self-signed, pre-trusted by browsers/OS
      
      Validation Process:
      1. Verify each certificate signature using issuer's public key
      2. Check validity periods (not expired, not before date)
      3. Verify certificate purposes match intended use
      4. Ensure root CA is trusted
      
      Best Practice: Include intermediate certificates when deploying SSL certificates`
    }
  };

  const explanation = explanations[concept];
  if (!explanation) {
    return null;
  }

  const buttonStyle = compact ? {
    padding: '2px 6px',
    fontSize: '11px',
    border: '1px solid var(--line)',
    background: 'var(--input-bg)',
    color: 'var(--muted)',
    borderRadius: '4px',
    cursor: 'pointer',
    marginLeft: '4px'
  } : {
    padding: '4px 8px',
    fontSize: '12px',
    border: '1px solid #3b82f6',
    background: '#3b82f610',
    color: '#3b82f6',
    borderRadius: '6px',
    cursor: 'pointer',
    fontWeight: '500'
  };

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        onClick={() => setShowExplanation(!showExplanation)}
        style={buttonStyle}
        onMouseEnter={(e) => e.target.style.background = compact ? 'var(--btn-hover)' : '#3b82f620'}
        onMouseLeave={(e) => e.target.style.background = compact ? 'var(--input-bg)' : '#3b82f610'}
      >
        {compact ? '?' : '💡 Explain This'}
      </button>

      {showExplanation && (
        <div style={{
          position: 'absolute',
          top: '100%',
          [position]: 0,
          marginTop: '4px',
          background: 'var(--card)',
          border: '1px solid var(--line)',
          borderRadius: '12px',
          padding: '16px',
          minWidth: '320px',
          maxWidth: '420px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
          zIndex: 1001,
          fontSize: '13px',
          lineHeight: '1.5'
        }}>
          {/* Close button */}
          <button
            onClick={() => setShowExplanation(false)}
            style={{
              position: 'absolute',
              top: '8px',
              right: '8px',
              background: 'none',
              border: 'none',
              color: 'var(--muted)',
              cursor: 'pointer',
              fontSize: '16px',
              padding: '4px'
            }}
          >
            ×
          </button>

          <h4 style={{ 
            margin: '0 0 12px 0', 
            fontSize: '16px', 
            color: '#3b82f6',
            paddingRight: '20px'
          }}>
            {title || explanation.title}
          </h4>
          
          <div style={{ 
            color: 'var(--ink)',
            whiteSpace: 'pre-line'
          }}>
            {explanation.content}
          </div>

          {/* Arrow pointer */}
          <div style={{
            position: 'absolute',
            top: '-6px',
            [position]: '12px',
            width: '12px',
            height: '12px',
            background: 'var(--card)',
            border: '1px solid var(--line)',
            borderRight: 'none',
            borderBottom: 'none',
            transform: 'rotate(45deg)'
          }} />
        </div>
      )}
    </div>
  );
}

export default ExplainButton;