import React, { useState } from 'react';
import * as cryptoUtils from '../utils/cryptoUtils';
import Spinner from './Spinner';
import KeyStrengthAnalyzer from './KeyStrengthAnalyzer';

function JwksValidator({ jwksInput = '', setJwksInput, validationResult = null, setValidationResult }) {
  // Use props if provided, otherwise fall back to local state for backward compatibility
  const [localJwksInput, setLocalJwksInput] = useState('');
  const [localValidationResult, setLocalValidationResult] = useState(null);
  
  const input = setJwksInput ? jwksInput : localJwksInput;
  const setInput = setJwksInput || setLocalJwksInput;
  const result = setValidationResult ? validationResult : localValidationResult;
  const setResult = setValidationResult || setLocalValidationResult;
  
  const [isValidating, setIsValidating] = useState(false);
  const [inputError, setInputError] = useState(null);

  const validateJwksInput = (input) => {
    if (!input.trim()) {
      setInputError(null);
      return;
    }

    try {
      const parsed = JSON.parse(input.trim());
      if (!parsed.keys) {
        setInputError('JWKS must have a "keys" array');
        return;
      }
      if (!Array.isArray(parsed.keys)) {
        setInputError('"keys" must be an array');
        return;
      }
      if (parsed.keys.length === 0) {
        setInputError('JWKS must contain at least one key');
        return;
      }
      setInputError(null);
    } catch (e) {
      setInputError('Invalid JSON format');
    }
  };

  const handleInputChange = (e) => {
    const value = e.target.value;
    setInput(value);
    validateJwksInput(value);
  };

  const validateJwks = async () => {
    setIsValidating(true);
    setResult(null);

    try {
      // Parse the JWKS JSON
      let jwks;
      try {
        jwks = JSON.parse(input.trim());
      } catch (e) {
        setResult({
          valid: false,
          error: 'Invalid JSON format. Please paste a valid JWKS (JSON Web Key Set).'
        });
        return;
      }

      // Validate JWKS structure
      if (!jwks.keys) {
        setResult({
          valid: false,
          error: 'Invalid JWKS: missing "keys" array.'
        });
        return;
      }

      if (!Array.isArray(jwks.keys)) {
        setResult({
          valid: false,
          error: 'Invalid JWKS: "keys" must be an array.'
        });
        return;
      }

      if (jwks.keys.length === 0) {
        setResult({
          valid: false,
          error: 'Invalid JWKS: must contain at least one key.'
        });
        return;
      }

      // Validate each key in the set
      const keyResults = [];
      const keyIds = new Set();
      const publicKeys = new Set();
      let hasPrivateKeys = false;
      let errors = [];
      let warnings = [];

      for (let i = 0; i < jwks.keys.length; i++) {
        const jwk = jwks.keys[i];
        const keyResult = {
          index: i,
          valid: false,
          jwk: jwk,
          error: null,
          keyType: jwk.kty,
          isPrivate: jwk.d !== undefined,
          keyId: jwk.kid,
          algorithm: jwk.alg,
          use: jwk.use,
          keyOps: jwk.key_ops
        };

        try {
          // Basic JWK validation
          if (!jwk.kty) {
            keyResult.error = 'Missing "kty" (key type) parameter';
            keyResults.push(keyResult);
            continue;
          }

          if (jwk.kty !== 'RSA' && jwk.kty !== 'EC') {
            keyResult.error = `Unsupported key type: ${jwk.kty}`;
            keyResults.push(keyResult);
            continue;
          }

          // Check for private keys in JWKS
          if (jwk.d) {
            hasPrivateKeys = true;
          }

          // Check for duplicate key IDs
          if (jwk.kid) {
            if (keyIds.has(jwk.kid)) {
              warnings.push(`Duplicate key ID "${jwk.kid}" found at index ${i}`);
            } else {
              keyIds.add(jwk.kid);
            }
          } else {
            warnings.push(`Key at index ${i} missing "kid" (key ID) - recommended for key identification`);
          }

          // Try to import the key to validate it
          let cryptoKey;
          let algorithm;
          
          if (jwk.kty === 'RSA') {
            // Determine key usage from JWK
            const isEncryptionKey = jwk.use === 'enc' || 
              (jwk.key_ops && (jwk.key_ops.includes('encrypt') || jwk.key_ops.includes('decrypt') || 
               jwk.key_ops.includes('wrapKey') || jwk.key_ops.includes('unwrapKey')));
            
            const rsaAlgs = isEncryptionKey ? 
              [{ name: 'RSA-OAEP', hash: 'SHA-256' }, { name: 'RSA-OAEP', hash: 'SHA-384' }, { name: 'RSA-OAEP', hash: 'SHA-512' }] :
              [{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, { name: 'RSA-PSS', hash: 'SHA-256' }];
            
            for (const alg of rsaAlgs) {
              try {
                // Use the key_ops from the JWK if available, otherwise use defaults
                let usages = [];
                if (jwk.key_ops && Array.isArray(jwk.key_ops)) {
                  // Filter to only include valid Web Crypto operations
                  const validOps = ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
                  usages = jwk.key_ops.filter(op => validOps.includes(op));
                } else {
                  // Default based on algorithm and private/public
                  usages = alg.name === 'RSA-OAEP' ? 
                    (keyResult.isPrivate ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey']) : 
                    (keyResult.isPrivate ? ['sign'] : ['verify']);
                }
                
                if (usages.length === 0) {
                  // If no valid usages, try with minimal set
                  usages = alg.name === 'RSA-OAEP' ? 
                    (keyResult.isPrivate ? ['decrypt'] : ['encrypt']) : 
                    (keyResult.isPrivate ? ['sign'] : ['verify']);
                }
                
                cryptoKey = await crypto.subtle.importKey('jwk', jwk, alg, false, usages);
                algorithm = alg;
                break;
              } catch (e) {
                continue;
              }
            }
          } else if (jwk.kty === 'EC') {
            const curve = jwk.crv;
            if (!curve) {
              keyResult.error = 'EC key missing "crv" (curve) parameter';
              keyResults.push(keyResult);
              continue;
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
              try {
                let usages = [];
                
                // For ECDH, public keys don't have usages in Web Crypto API
                // Only private keys can perform deriveKey/deriveBits
                if (keyResult.isPrivate) {
                  if (jwk.key_ops && Array.isArray(jwk.key_ops)) {
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
              } catch (e) {
                keyResult.error = `Failed to import ECDH key: ${e.message}`;
                keyResults.push(keyResult);
                continue;
              }
            } else {
              // ECDSA for signing
              algorithm = { name: 'ECDSA', namedCurve: curve };
              try {
                let usages = [];
                if (jwk.key_ops && Array.isArray(jwk.key_ops)) {
                  const validOps = ['sign', 'verify'];
                  usages = jwk.key_ops.filter(op => validOps.includes(op));
                } else {
                  usages = keyResult.isPrivate ? ['sign'] : ['verify'];
                }
                
                if (usages.length === 0) {
                  usages = keyResult.isPrivate ? ['sign'] : ['verify'];
                }
                
                cryptoKey = await crypto.subtle.importKey('jwk', jwk, algorithm, false, usages);
              } catch (e) {
                keyResult.error = `Failed to import ECDSA key: ${e.message}`;
                keyResults.push(keyResult);
                continue;
              }
            }
          }

          if (!cryptoKey) {
            keyResult.error = 'Failed to import key with any supported algorithm';
            keyResults.push(keyResult);
            continue;
          }

          // Key successfully imported - generate thumbprint to check for duplicates
          const publicJwk = keyResult.isPrivate ? cryptoUtils.derivePublicFromPrivateJwk(jwk) : jwk;
          const thumbprint = await cryptoUtils.jwkThumbprint(publicJwk);
          
          if (publicKeys.has(thumbprint)) {
            warnings.push(`Duplicate public key found at index ${i} (same key material as another key)`);
          } else {
            publicKeys.add(thumbprint);
          }

          keyResult.valid = true;
          keyResult.thumbprint = thumbprint;
          keyResult.publicJwkObject = publicJwk;
          keyResult.algorithm = algorithm.name;

        } catch (e) {
          keyResult.error = e.message || 'Unknown validation error';
        }

        keyResults.push(keyResult);
      }

      // JWKS-level validations
      if (hasPrivateKeys) {
        errors.push('SECURITY WARNING: JWKS contains private keys. Private keys should NEVER be included in a JWKS intended for public distribution.');
      }

      // Check for recommended fields
      const missingAlgCount = keyResults.filter(k => k.valid && !k.algorithm).length;
      if (missingAlgCount > 0) {
        warnings.push(`${missingAlgCount} key(s) missing "alg" parameter - recommended for algorithm identification`);
      }

      const missingUseCount = keyResults.filter(k => k.valid && !k.use).length;
      if (missingUseCount > 0) {
        warnings.push(`${missingUseCount} key(s) missing "use" parameter - recommended to specify "sig" or "enc"`);
      }

      // Summary
      const validKeys = keyResults.filter(k => k.valid);
      const invalidKeys = keyResults.filter(k => !k.valid);
      
      setResult({
        valid: invalidKeys.length === 0,
        keyCount: jwks.keys.length,
        validKeys: validKeys.length,
        invalidKeys: invalidKeys.length,
        hasPrivateKeys,
        uniqueKeyIds: keyIds.size,
        uniquePublicKeys: publicKeys.size,
        keyResults,
        errors,
        warnings,
        jwksObject: jwks
      });

    } catch (error) {
      setResult({
        valid: false,
        error: error.message || 'An error occurred while validating the JWKS.'
      });
    } finally {
      setIsValidating(false);
    }
  };

  const handleClear = () => {
    setInput('');
    setResult(null);
    setInputError(null);
  };

  return (
    <>
      <section className="card" style={{ marginTop: '12px' }}>
        <h2>Validate JWKS</h2>
        <p className="muted">
          Paste a <strong>JWKS (JSON Web Key Set)</strong> to validate it. 
          Validates the entire key set structure, checks each key, and identifies potential security issues.
        </p>
        <div className="actions" style={{ marginTop: '8px' }}>
          <button 
            className="btn primary" 
            onClick={validateJwks} 
            disabled={isValidating || !input.trim()}
          >
            {isValidating && <Spinner size={16} />}
            Validate JWKS
          </button>
          <button 
            className="btn" 
            onClick={handleClear}
          >
            Clear
          </button>
        </div>
        <div className="space"></div>
        <div className={`field ${inputError ? 'field-error' : (input.trim() && !inputError ? 'field-success' : '')}`}>
          <textarea 
            value={input}
            onChange={handleInputChange}
            placeholder={`{\n  "keys": [\n    {\n      "kty": "RSA",\n      "n": "...",\n      "e": "AQAB",\n      "kid": "key1",\n      "alg": "RS256",\n      "use": "sig"\n    },\n    {\n      "kty": "EC",\n      "crv": "P-256",\n      "x": "...",\n      "y": "...",\n      "kid": "key2",\n      "alg": "ES256",\n      "use": "sig"\n    }\n  ]\n}`}
            style={{ minHeight: '200px' }}
          />
          {inputError && (
            <div className="error-message">
              ⚠ {inputError}
            </div>
          )}
        </div>
      </section>

      {result && (
        <section className="card outputs-animated" style={{ marginTop: '12px' }}>
          <h3 style={{ marginBottom: '12px' }}>JWKS Validation Result</h3>
          
          {result.valid ? (
            <div className="validation-success">
              <div className="badge" style={{ 
                background: 'var(--badge-bg)', 
                color: '#10b981',
                border: '1px solid #10b981',
                marginBottom: '12px',
                display: 'inline-block'
              }}>
                ✓ Valid JWKS
              </div>
              
              <div style={{ marginBottom: '16px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '12px', marginBottom: '12px' }}>
                  <div style={{ textAlign: 'center', background: 'var(--input-bg)', padding: '8px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '18px', fontWeight: '600', color: 'var(--ink)' }}>{result.keyCount}</div>
                    <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Total Keys</div>
                  </div>
                  <div style={{ textAlign: 'center', background: 'var(--input-bg)', padding: '8px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '18px', fontWeight: '600', color: '#10b981' }}>{result.validKeys}</div>
                    <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Valid</div>
                  </div>
                  <div style={{ textAlign: 'center', background: 'var(--input-bg)', padding: '8px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '18px', fontWeight: '600', color: result.invalidKeys > 0 ? '#ef4444' : 'var(--muted)' }}>{result.invalidKeys}</div>
                    <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Invalid</div>
                  </div>
                  <div style={{ textAlign: 'center', background: 'var(--input-bg)', padding: '8px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '18px', fontWeight: '600', color: 'var(--ink)' }}>{result.uniqueKeyIds}</div>
                    <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Unique IDs</div>
                  </div>
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
                ✗ Invalid JWKS
              </div>
              <p className="muted">{result.error}</p>
            </div>
          )}

          {/* Errors */}
          {result.errors && result.errors.length > 0 && (
            <div style={{ marginBottom: '12px' }}>
              <h4 style={{ color: '#ef4444', fontSize: '14px', margin: '0 0 8px 0' }}>Security Issues</h4>
              {result.errors.map((error, index) => (
                <div key={index} style={{ 
                  color: '#ef4444', 
                  marginBottom: '4px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '4px',
                  fontSize: '12px'
                }}>
                  <span style={{ minWidth: '12px' }}>●</span>
                  <span>{error}</span>
                </div>
              ))}
            </div>
          )}

          {/* Warnings */}
          {result.warnings && result.warnings.length > 0 && (
            <div style={{ marginBottom: '12px' }}>
              <h4 style={{ color: '#f59e0b', fontSize: '14px', margin: '0 0 8px 0' }}>Recommendations</h4>
              {result.warnings.map((warning, index) => (
                <div key={index} style={{ 
                  color: '#f59e0b', 
                  marginBottom: '4px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '4px',
                  fontSize: '12px'
                }}>
                  <span style={{ minWidth: '12px' }}>●</span>
                  <span>{warning}</span>
                </div>
              ))}
            </div>
          )}

          {/* Individual Key Results */}
          {result.keyResults && (
            <div>
              <h4 style={{ fontSize: '14px', margin: '16px 0 8px 0' }}>Individual Key Analysis</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {result.keyResults.map((keyResult, index) => (
                  <div key={index} style={{ 
                    background: 'var(--input-bg)', 
                    border: `1px solid ${keyResult.valid ? '#10b981' : '#ef4444'}`,
                    borderRadius: '6px', 
                    padding: '8px',
                    fontSize: '12px'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontWeight: '600' }}>
                        Key {index + 1}: {keyResult.keyType} {keyResult.isPrivate ? '(Private)' : '(Public)'}
                      </span>
                      <span style={{ 
                        color: keyResult.valid ? '#10b981' : '#ef4444',
                        fontSize: '11px',
                        fontWeight: '500'
                      }}>
                        {keyResult.valid ? '✓ Valid' : '✗ Invalid'}
                      </span>
                    </div>
                    {keyResult.keyId && (
                      <div style={{ color: 'var(--muted)', marginBottom: '2px' }}>
                        ID: {keyResult.keyId}
                      </div>
                    )}
                    {keyResult.error && (
                      <div style={{ color: '#ef4444', marginBottom: '4px' }}>
                        Error: {keyResult.error}
                      </div>
                    )}
                    {keyResult.valid && keyResult.thumbprint && (
                      <div style={{ color: 'var(--muted)', fontFamily: 'ui-monospace, monospace', fontSize: '10px' }}>
                        Thumbprint: {keyResult.thumbprint}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* Security Analysis for first valid key */}
      {result && result.keyResults && (
        result.keyResults
          .filter(kr => kr.valid && kr.publicJwkObject)
          .slice(0, 1) // Show analysis for first valid key only
          .map((keyResult, index) => (
            <section key={index} className="card outputs-animated" style={{ marginTop: '12px' }}>
              <h4 style={{ fontSize: '14px', marginBottom: '12px' }}>Security Analysis (Key 1)</h4>
              <KeyStrengthAnalyzer jwk={keyResult.publicJwkObject} />
            </section>
          ))
      )}
    </>
  );
}

export default JwksValidator;