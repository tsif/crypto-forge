import React, { useState } from 'react';
import * as cryptoUtils from '../utils/cryptoUtils';
import Spinner from './Spinner';
import KeyStrengthAnalyzer from './KeyStrengthAnalyzer';

function KeyValidator() {
  const [keyInput, setKeyInput] = useState('');
  const [validationResult, setValidationResult] = useState(null);
  const [isValidating, setIsValidating] = useState(false);
  const [inputError, setInputError] = useState(null);

  const validateInput = (input) => {
    if (!input.trim()) {
      setInputError(null);
      return;
    }

    try {
      const parsed = JSON.parse(input.trim());
      if (!parsed.kty) {
        setInputError('Missing required "kty" (key type) parameter');
        return;
      }
      if (parsed.kty !== 'RSA' && parsed.kty !== 'EC') {
        setInputError('Unsupported key type. Only RSA and EC keys are supported');
        return;
      }
      if (parsed.kty === 'EC' && !parsed.crv) {
        setInputError('EC keys must have "crv" (curve) parameter');
        return;
      }
      setInputError(null);
    } catch (e) {
      setInputError('Invalid JSON format');
    }
  };

  const handleInputChange = (e) => {
    const value = e.target.value;
    setKeyInput(value);
    validateInput(value);
  };


  const validateKey = async () => {
    setIsValidating(true);
    setValidationResult(null);

    try {
      // Parse the JWK JSON
      let jwk;
      try {
        jwk = JSON.parse(keyInput.trim());
      } catch (e) {
        setValidationResult({
          valid: false,
          error: 'Invalid JSON format. Please paste a valid JWK (JSON Web Key).'
        });
        return;
      }

      // Check if it's a valid JWK structure
      if (!jwk.kty) {
        setValidationResult({
          valid: false,
          error: 'Invalid JWK: missing "kty" (key type) parameter.'
        });
        return;
      }

      const isPrivate = jwk.d !== undefined; // Private keys have 'd' parameter
      const keyType = jwk.kty;

      // Try to import the JWK
      let cryptoKey;
      let algorithm;
      
      try {
        if (keyType === 'RSA') {
          // Determine if it's an encryption or signing key
          const isEncryptionKey = jwk.use === 'enc' || 
            (jwk.key_ops && (jwk.key_ops.includes('encrypt') || jwk.key_ops.includes('decrypt') || 
             jwk.key_ops.includes('wrapKey') || jwk.key_ops.includes('unwrapKey')));
          
          // Try different RSA algorithms based on key usage
          const rsaAlgs = isEncryptionKey ?
            [{ name: 'RSA-OAEP', hash: 'SHA-256' }, { name: 'RSA-OAEP', hash: 'SHA-384' }, { name: 'RSA-OAEP', hash: 'SHA-512' }] :
            [{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, { name: 'RSA-PSS', hash: 'SHA-256' }];
          
          for (const alg of rsaAlgs) {
            try {
              // Use key_ops from JWK if available
              let usages = [];
              if (jwk.key_ops && Array.isArray(jwk.key_ops) && jwk.key_ops.length > 0) {
                // Use the key_ops from the JWK, filtering to valid Web Crypto operations
                const validOps = ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
                usages = jwk.key_ops.filter(op => validOps.includes(op));
              } 
              
              if (usages.length === 0) {
                // Fallback to defaults based on algorithm and key type
                usages = alg.name === 'RSA-OAEP' ? 
                  (isPrivate ? ['decrypt'] : ['encrypt']) : 
                  (isPrivate ? ['sign'] : ['verify']);
              }
              
              cryptoKey = await crypto.subtle.importKey('jwk', jwk, alg, false, usages);
              algorithm = alg;
              break;
            } catch (e) {
              continue;
            }
          }
        } else if (keyType === 'EC') {
          // Try EC with the curve from JWK
          const curve = jwk.crv;
          if (!curve) {
            throw new Error('EC key missing curve parameter');
          }
          
          // Determine if it's ECDH or ECDSA based on use or key_ops
          // Note: For public keys, we also check if there are any deriveKey/deriveBits in key_ops
          // even though public keys can't perform these operations (they're just metadata)
          const isKeyAgreement = jwk.use === 'enc' || 
            (jwk.key_ops && (jwk.key_ops.includes('deriveKey') || jwk.key_ops.includes('deriveBits'))) ||
            (jwk.alg && jwk.alg.startsWith('ECDH'));
          
          if (isKeyAgreement) {
            // ECDH for key agreement
            algorithm = { name: 'ECDH', namedCurve: curve };
            
            let usages = [];
            
            // For ECDH, public keys don't have usages in Web Crypto API
            // Only private keys can perform deriveKey/deriveBits
            if (isPrivate) {
              if (jwk.key_ops && Array.isArray(jwk.key_ops) && jwk.key_ops.length > 0) {
                const validOps = ['deriveKey', 'deriveBits'];
                usages = jwk.key_ops.filter(op => validOps.includes(op));
              }
              
              if (usages.length === 0) {
                usages = ['deriveKey', 'deriveBits'];
              }
            } else {
              // Public ECDH keys have no usages in Web Crypto API
              usages = [];
            }
            
            cryptoKey = await crypto.subtle.importKey('jwk', jwk, algorithm, false, usages);
          } else {
            // ECDSA for signing
            algorithm = { name: 'ECDSA', namedCurve: curve };
            
            let usages = [];
            if (jwk.key_ops && Array.isArray(jwk.key_ops) && jwk.key_ops.length > 0) {
              const validOps = ['sign', 'verify'];
              usages = jwk.key_ops.filter(op => validOps.includes(op));
            }
            
            if (usages.length === 0) {
              usages = isPrivate ? ['sign'] : ['verify'];
            }
            
            cryptoKey = await crypto.subtle.importKey('jwk', jwk, algorithm, false, usages);
          }
        } else {
          throw new Error(`Unsupported key type: ${keyType}`);
        }

        if (!cryptoKey) {
          throw new Error('Failed to import key with any supported algorithm');
        }
      } catch (importError) {
        setValidationResult({
          valid: false,
          error: `Failed to import JWK: ${importError.message}`
        });
        return;
      }
      
      // Extract key details
      let details = {
        valid: true,
        keyType,
        isPrivate,
        algorithm: algorithm.name,
        jwk: {
          kty: jwk.kty,
          alg: jwk.alg,
          use: jwk.use,
          key_ops: jwk.key_ops,
          kid: jwk.kid
        }
      };

      if (keyType === 'RSA') {
        // Calculate modulus length for RSA
        const modulusLength = jwk.n ? Math.ceil((jwk.n.replace(/[^A-Za-z0-9+/]/g, '').length * 6) / 8) : null;
        details.rsaDetails = {
          modulusLength,
          hash: algorithm.hash,
          publicExponent: jwk.e
        };
      } else if (keyType === 'EC') {
        details.ecDetails = {
          curve: jwk.crv,
          x: jwk.x ? jwk.x.substring(0, 10) + '...' : undefined,
          y: jwk.y ? jwk.y.substring(0, 10) + '...' : undefined
        };
      }

      // Add thumbprint
      const publicJwk = isPrivate ? cryptoUtils.derivePublicFromPrivateJwk(jwk) : jwk;
      details.thumbprint = await cryptoUtils.jwkThumbprint(publicJwk);
      details.publicJwkObject = publicJwk;

      setValidationResult(details);
    } catch (error) {
      setValidationResult({
        valid: false,
        error: error.message || 'An error occurred while validating the key.'
      });
    } finally {
      setIsValidating(false);
    }
  };

  const handleClear = () => {
    setKeyInput('');
    setValidationResult(null);
    setInputError(null);
  };

  return (
    <>
      <section className="card" style={{ marginTop: '12px' }}>
        <h2>Validate JWK</h2>
        <p className="muted">
          Paste a <strong>JWK (JSON Web Key)</strong> to validate it. 
          Works for both RSA and EC keys. The validator will check the key's validity and display its properties.
        </p>
        <div className="actions" style={{ marginTop: '8px' }}>
          <button 
            className="btn primary" 
            onClick={validateKey} 
            disabled={isValidating || !keyInput.trim()}
          >
            {isValidating && <Spinner size={16} />}
            Validate JWK
          </button>
          <button 
            className="btn" 
            onClick={handleClear}
          >
            Clear
          </button>
        </div>
        <div className="space"></div>
        <div className={`field ${inputError ? 'field-error' : (keyInput.trim() && !inputError ? 'field-success' : '')}`}>
          <textarea 
            value={keyInput}
            onChange={handleInputChange}
            placeholder={`{\n  "kty": "RSA",\n  "n": "...",\n  "e": "AQAB",\n  "d": "...",\n  "alg": "RS256",\n  "use": "sig"\n}\n\nor\n\n{\n  "kty": "EC",\n  "crv": "P-256",\n  "x": "...",\n  "y": "...",\n  "d": "...",\n  "alg": "ES256",\n  "use": "sig"\n}`}
            style={{ minHeight: '200px' }}
          />
          {inputError && (
            <div className="error-message">
              ⚠ {inputError}
            </div>
          )}
        </div>
      </section>

      {validationResult && (
        <section className="card outputs-animated" style={{ marginTop: '12px' }}>
          <h3 style={{ marginBottom: '12px' }}>Validation Result</h3>
          
          {validationResult.valid ? (
            <div className="validation-success">
              <div className="badge" style={{ 
                background: 'var(--badge-bg)', 
                color: '#10b981',
                border: '1px solid #10b981',
                marginBottom: '12px',
                display: 'inline-block'
              }}>
                ✓ Valid Key
              </div>
              
              <div className="validation-details" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div className="field">
                  <strong style={{ minWidth: '120px', display: 'inline-block' }}>Type:</strong>
                  <span>{validationResult.keyType}</span>
                </div>
                <div className="field">
                  <strong style={{ minWidth: '120px', display: 'inline-block' }}>Key Nature:</strong>
                  <span>{validationResult.isPrivate ? 'Private Key' : 'Public Key'}</span>
                </div>
                <div className="field">
                  <strong style={{ minWidth: '120px', display: 'inline-block' }}>Algorithm:</strong>
                  <span>{validationResult.algorithm}</span>
                </div>
                
                {validationResult.jwk.alg && (
                  <div className="field">
                    <strong style={{ minWidth: '120px', display: 'inline-block' }}>JWK Algorithm:</strong>
                    <span>{validationResult.jwk.alg}</span>
                  </div>
                )}
                
                {validationResult.jwk.use && (
                  <div className="field">
                    <strong style={{ minWidth: '120px', display: 'inline-block' }}>Key Use:</strong>
                    <span>{validationResult.jwk.use} ({validationResult.jwk.use === 'sig' ? 'Signature' : 'Encryption'})</span>
                  </div>
                )}
                
                {validationResult.jwk.key_ops && (
                  <div className="field">
                    <strong style={{ minWidth: '120px', display: 'inline-block' }}>Key Operations:</strong>
                    <span>{Array.isArray(validationResult.jwk.key_ops) ? validationResult.jwk.key_ops.join(', ') : validationResult.jwk.key_ops}</span>
                  </div>
                )}
                
                {validationResult.jwk.kid && (
                  <div className="field">
                    <strong style={{ minWidth: '120px', display: 'inline-block' }}>Key ID:</strong>
                    <span style={{ 
                      fontFamily: 'ui-monospace, monospace', 
                      fontSize: '12px',
                      wordBreak: 'break-all'
                    }}>
                      {validationResult.jwk.kid}
                    </span>
                  </div>
                )}
                
                {validationResult.rsaDetails && (
                  <>
                    <div className="field">
                      <strong style={{ minWidth: '120px', display: 'inline-block' }}>Modulus:</strong>
                      <span>{validationResult.rsaDetails.modulusLength} bits</span>
                    </div>
                    <div className="field">
                      <strong style={{ minWidth: '120px', display: 'inline-block' }}>Hash:</strong>
                      <span>{validationResult.rsaDetails.hash}</span>
                    </div>
                    <div className="field">
                      <strong style={{ minWidth: '120px', display: 'inline-block' }}>Public Exponent:</strong>
                      <span>{validationResult.rsaDetails.publicExponent}</span>
                    </div>
                  </>
                )}
                
                {validationResult.ecDetails && (
                  <>
                    <div className="field">
                      <strong style={{ minWidth: '120px', display: 'inline-block' }}>Curve:</strong>
                      <span>{validationResult.ecDetails.curve}</span>
                    </div>
                    {validationResult.ecDetails.x && (
                      <div className="field">
                        <strong style={{ minWidth: '120px', display: 'inline-block' }}>X Coordinate:</strong>
                        <span style={{ fontFamily: 'ui-monospace, monospace', fontSize: '12px' }}>
                          {validationResult.ecDetails.x}
                        </span>
                      </div>
                    )}
                    {validationResult.ecDetails.y && (
                      <div className="field">
                        <strong style={{ minWidth: '120px', display: 'inline-block' }}>Y Coordinate:</strong>
                        <span style={{ fontFamily: 'ui-monospace, monospace', fontSize: '12px' }}>
                          {validationResult.ecDetails.y}
                        </span>
                      </div>
                    )}
                  </>
                )}
                
                <div className="field">
                  <strong style={{ minWidth: '120px', display: 'inline-block' }}>Thumbprint:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '12px',
                    wordBreak: 'break-all'
                  }}>
                    {validationResult.thumbprint}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div className="validation-error">
              <div className="badge" style={{ 
                background: 'var(--badge-bg)', 
                color: '#ef4444',
                border: '1px solid #ef4444',
                marginBottom: '12px',
                display: 'inline-block'
              }}>
                ✗ Invalid Key
              </div>
              <p className="muted">{validationResult.error}</p>
            </div>
          )}
        </section>
      )}

      {validationResult && validationResult.valid && validationResult.publicJwkObject && (
        <section className="card outputs-animated" style={{ marginTop: '12px' }}>
          <KeyStrengthAnalyzer jwk={validationResult.publicJwkObject} />
        </section>
      )}
    </>
  );
}

export default KeyValidator;