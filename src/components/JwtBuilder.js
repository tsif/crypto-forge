import React, { useState } from 'react';
import Spinner from './Spinner';
import OutputCard from './OutputCard';

function JwtBuilder({ 
  verifyOnly = false,
  availableKeys = [], 
  jwtBuilderState = {}, 
  setJwtBuilderState,
  jwtVerifyState = {},
  setJwtVerifyState,
  showToast,
  setMessage 
}) {
  // Use props if provided, otherwise fall back to local state
  const [localState, setLocalState] = useState({
    activeSubTab: verifyOnly ? 'verify' : 'create',
    // Create JWT state
    selectedKeyId: '',
    customKey: '',
    headerClaims: { typ: 'JWT' },
    payloadClaims: { 
      iss: '', 
      aud: '', 
      sub: '', 
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000)
    },
    customClaims: '{}',
    generatedJwt: '',
    // Verify JWT state
    jwtToVerify: '',
    verificationKey: '',
    verificationResult: null,
    x5cExtracted: null
  });

  const state = verifyOnly ? (setJwtVerifyState ? jwtVerifyState : localState) : (setJwtBuilderState ? jwtBuilderState : localState);
  const setState = verifyOnly ? (setJwtVerifyState || setLocalState) : (setJwtBuilderState || setLocalState);

  const [busy, setBusy] = useState(false);

  // Get available keys from generate and PEM conversion tabs
  const getAvailableKeys = () => {
    const keys = [];
    
    // Add a separator and instruction
    if (availableKeys.length > 0) {
      keys.push({ id: '', label: '-- Select a generated key --', disabled: true });
      keys.push(...availableKeys);
    }
    
    keys.push({ id: 'custom', label: 'Use custom key (paste below)' });
    return keys;
  };

  const updateState = (updates) => {
    setState(prev => ({ ...prev, ...updates }));
  };

  const getSelectedKey = () => {
    if (state.selectedKeyId === 'custom') {
      try {
        return JSON.parse(state.customKey);
      } catch {
        return null;
      }
    }
    
    const selected = availableKeys.find(k => k.id === state.selectedKeyId);
    return selected ? selected.jwk : null;
  };

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

  const createJwt = async () => {
    setBusy(true);
    setMessage('');

    try {
      const selectedKey = getSelectedKey();
      if (!selectedKey) {
        throw new Error('Please select or provide a valid key');
      }

      const algorithm = getAlgorithmFromKey(selectedKey);
      if (algorithm === 'none') {
        throw new Error('Unable to determine algorithm for selected key');
      }

      // Build header
      const header = {
        alg: algorithm,
        ...state.headerClaims
      };

      // Build payload
      let customClaimsObj = {};
      try {
        if (state.customClaims.trim()) {
          customClaimsObj = JSON.parse(state.customClaims);
        }
      } catch (e) {
        throw new Error('Custom claims must be valid JSON');
      }

      const payload = {
        ...state.payloadClaims,
        ...customClaimsObj
      };

      // Create JWT
      const jwt = await createJwtToken(header, payload, selectedKey, algorithm);
      
      updateState({ generatedJwt: jwt });
      setMessage('JWT created successfully');
    } catch (error) {
      setMessage(`Error: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

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

  const decodeJwt = async () => {
    setBusy(true);
    setMessage('');

    try {
      if (!state.jwtToVerify.trim()) {
        throw new Error('Please provide a JWT to decode');
      }

      const parts = state.jwtToVerify.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
      }

      // Decode header and payload (no signature verification)
      const header = JSON.parse(base64UrlDecode(parts[0]));
      const payload = JSON.parse(base64UrlDecode(parts[1]));

      // Check if payload has standard claims and provide human-readable info
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        // Standard registered claims
        iss: payload.iss ? `Issuer: ${payload.iss}` : null,
        sub: payload.sub ? `Subject: ${payload.sub}` : null,
        aud: payload.aud ? `Audience: ${Array.isArray(payload.aud) ? payload.aud.join(', ') : payload.aud}` : null,
        exp: payload.exp ? {
          raw: payload.exp,
          date: new Date(payload.exp * 1000).toISOString(),
          expired: payload.exp < now,
          timeLeft: payload.exp - now
        } : null,
        nbf: payload.nbf ? {
          raw: payload.nbf,
          date: new Date(payload.nbf * 1000).toISOString(),
          active: payload.nbf <= now
        } : null,
        iat: payload.iat ? {
          raw: payload.iat,
          date: new Date(payload.iat * 1000).toISOString()
        } : null,
        jti: payload.jti ? `JWT ID: ${payload.jti}` : null
      };

      // Get x5c certificate info if present
      let x5cInfo = null;
      if (header.x5c && Array.isArray(header.x5c)) {
        x5cInfo = {
          chainLength: header.x5c.length,
          firstCert: header.x5c[0] ? header.x5c[0].substring(0, 50) + '...' : null
        };
      }

      updateState({
        verificationResult: {
          mode: 'decode-only',
          valid: null, // Not applicable for decode-only
          header,
          payload,
          claims,
          x5cInfo,
          rawParts: parts,
          decodedAt: new Date().toISOString()
        }
      });

      if (showToast) {
        showToast('✓ JWT decoded successfully');
      }

    } catch (error) {
      updateState({
        verificationResult: {
          mode: 'decode-only',
          error: error.message,
          header: null,
          payload: null
        }
      });

      if (showToast) {
        showToast(`✗ JWT decode failed: ${error.message}`);
      }
    } finally {
      setBusy(false);
    }
  };

  const verifyJwt = async () => {
    setBusy(true);
    setMessage('');

    try {
      if (!state.jwtToVerify.trim()) {
        throw new Error('Please provide a JWT to verify');
      }

      const parts = state.jwtToVerify.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
      }

      // Decode header and payload
      const header = JSON.parse(base64UrlDecode(parts[0]));
      const payload = JSON.parse(base64UrlDecode(parts[1]));

      // Verify signature if algorithm is not 'none'
      let signatureValid = false;
      let verificationError = null;

      if (header.alg === 'none') {
        signatureValid = parts[2] === '';
      } else {
        try {
          if (!state.verificationKey.trim()) {
            throw new Error('Verification key is required for signed JWTs');
          }

          const verifyKey = JSON.parse(state.verificationKey);
          signatureValid = await verifyJwtSignature(parts, header, verifyKey);
        } catch (e) {
          verificationError = e.message;
        }
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      const isExpired = payload.exp && payload.exp < now;
      const isNotYetValid = payload.nbf && payload.nbf > now;

      const result = {
        mode: 'verify',
        valid: signatureValid && !isExpired && !isNotYetValid,
        header,
        payload,
        signatureValid,
        isExpired,
        isNotYetValid,
        verificationError,
        timing: {
          issued: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
          expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
          notBefore: payload.nbf ? new Date(payload.nbf * 1000).toISOString() : null
        }
      };

      updateState({ verificationResult: result });
      setMessage(result.valid ? 'JWT verified successfully' : 'JWT verification failed');
    } catch (error) {
      updateState({ 
        verificationResult: { 
          mode: 'verify',
          valid: false, 
          error: error.message 
        } 
      });
      setMessage(`Error: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

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

  // Utility functions
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

  // Extract public key from x5c certificate chain in JWT header
  const extractKeyFromX5c = async (jwtToken) => {
    try {
      const parts = jwtToken.split('.');
      if (parts.length !== 3) return null;
      
      const header = JSON.parse(base64UrlDecode(parts[0]));
      
      if (!header.x5c || !Array.isArray(header.x5c) || header.x5c.length === 0) {
        return null;
      }
      
      // Get the first certificate from the chain
      const certBase64 = header.x5c[0];
      
      // Convert base64 to DER
      const binaryString = atob(certBase64);
      const certDer = new ArrayBuffer(binaryString.length);
      const certView = new Uint8Array(certDer);
      for (let i = 0; i < binaryString.length; i++) {
        certView[i] = binaryString.charCodeAt(i);
      }
      
      // Use the same certificate parsing logic from App.js
      const extractPublicKeyFromCertificate = (certDer) => {
        const view = new DataView(certDer);
        let offset = 0;
        
        // Parse outer SEQUENCE
        if (view.getUint8(offset) !== 0x30) throw new Error('Invalid certificate: expected SEQUENCE');
        offset++;
        
        // Skip length of outer sequence
        parseLength(view, offset);
        offset += getLengthBytes(view, offset);
        
        // Parse tbsCertificate SEQUENCE
        if (view.getUint8(offset) !== 0x30) throw new Error('Invalid certificate: expected tbsCertificate SEQUENCE');
        offset++;
        
        parseLength(view, offset);
        offset += getLengthBytes(view, offset);
        
        // Skip version (optional, context tag [0])
        if (view.getUint8(offset) === 0xa0) {
          offset++;
          const versionLength = parseLength(view, offset);
          offset += getLengthBytes(view, offset) + versionLength;
        }
        
        // Skip serialNumber (INTEGER)
        if (view.getUint8(offset) !== 0x02) throw new Error('Invalid certificate: expected serialNumber INTEGER');
        offset++;
        const serialLength = parseLength(view, offset);
        offset += getLengthBytes(view, offset) + serialLength;
        
        // Skip signature (SEQUENCE)
        if (view.getUint8(offset) !== 0x30) throw new Error('Invalid certificate: expected signature SEQUENCE');
        offset++;
        const sigLength = parseLength(view, offset);
        offset += getLengthBytes(view, offset) + sigLength;
        
        // Skip issuer (SEQUENCE)
        if (view.getUint8(offset) !== 0x30) throw new Error('Invalid certificate: expected issuer SEQUENCE');
        offset++;
        const issuerLength = parseLength(view, offset);
        offset += getLengthBytes(view, offset) + issuerLength;
        
        // Skip validity (SEQUENCE)
        if (view.getUint8(offset) !== 0x30) throw new Error('Invalid certificate: expected validity SEQUENCE');
        offset++;
        const validityLength = parseLength(view, offset);
        offset += getLengthBytes(view, offset) + validityLength;
        
        // Skip subject (SEQUENCE)
        if (view.getUint8(offset) !== 0x30) throw new Error('Invalid certificate: expected subject SEQUENCE');
        offset++;
        const subjectLength = parseLength(view, offset);
        offset += getLengthBytes(view, offset) + subjectLength;
        
        // Now we should be at subjectPublicKeyInfo (SEQUENCE)
        if (view.getUint8(offset) !== 0x30) throw new Error('Invalid certificate: expected subjectPublicKeyInfo SEQUENCE');
        const spkiStart = offset;
        offset++;
        
        const spkiLength = parseLength(view, offset);
        offset += getLengthBytes(view, offset);
        
        // Extract the complete SubjectPublicKeyInfo
        return certDer.slice(spkiStart, spkiStart + 1 + getLengthBytes(view, spkiStart + 1) + spkiLength);
      };
      
      // Helper functions for ASN.1 parsing
      const parseLength = (view, offset) => {
        const firstByte = view.getUint8(offset);
        if ((firstByte & 0x80) === 0) {
          return firstByte;
        } else {
          const lengthBytes = firstByte & 0x7f;
          let length = 0;
          for (let i = 1; i <= lengthBytes; i++) {
            length = (length << 8) | view.getUint8(offset + i);
          }
          return length;
        }
      };
      
      const getLengthBytes = (view, offset) => {
        const firstByte = view.getUint8(offset);
        if ((firstByte & 0x80) === 0) {
          return 1;
        } else {
          return 1 + (firstByte & 0x7f);
        }
      };
      
      // Extract public key from certificate
      const publicKeyDer = extractPublicKeyFromCertificate(certDer);
      
      // Try to import as RSA first, then EC
      let imported = null;
      let keyType = null;
      
      try {
        imported = await crypto.subtle.importKey(
          'spki',
          publicKeyDer,
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          true,
          ['verify']
        );
        keyType = 'RSA';
      } catch {
        try {
          imported = await crypto.subtle.importKey(
            'spki', 
            publicKeyDer,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
          );
          keyType = 'EC';
        } catch {
          try {
            imported = await crypto.subtle.importKey(
              'spki',
              publicKeyDer, 
              { name: 'ECDSA', namedCurve: 'P-384' },
              true,
              ['verify']
            );
            keyType = 'EC';
          } catch {
            imported = await crypto.subtle.importKey(
              'spki',
              publicKeyDer,
              { name: 'ECDSA', namedCurve: 'P-521' },
              true, 
              ['verify']
            );
            keyType = 'EC';
          }
        }
      }
      
      if (!imported) return null;
      
      // Export as JWK
      const jwk = await crypto.subtle.exportKey('jwk', imported);
      
      return {
        jwk: JSON.stringify(jwk, null, 2),
        keyType,
        source: 'x5c certificate chain'
      };
      
    } catch (error) {
      console.warn('Failed to extract key from x5c:', error);
      return null;
    }
  };

  const clearAll = () => {
    updateState({
      selectedKeyId: '',
      customKey: '',
      headerClaims: { typ: 'JWT' },
      payloadClaims: { 
        iss: '', 
        aud: '', 
        sub: '', 
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        nbf: Math.floor(Date.now() / 1000)
      },
      customClaims: '{}',
      generatedJwt: '',
      jwtToVerify: '',
      verificationKey: '',
      verificationResult: null,
      x5cExtracted: null
    });
  };

  return (
    <>
      <section className="card" style={{ marginTop: '12px' }}>
        <h2>{verifyOnly ? 'JWT Verifier' : 'JWT Builder'}</h2>
        <p className="muted">
          {verifyOnly 
            ? 'Verify JSON Web Tokens using your generated keys or custom keys. Supports RSA and EC algorithms with proper signature verification.'
            : 'Create and verify JSON Web Tokens using your generated keys or custom keys. Supports RSA and EC algorithms with proper signature verification.'
          }
        </p>
        
        {/* Sub-tab navigation - only show if not verify-only */}
        {!verifyOnly && (
          <div className="segmented-control" style={{ marginTop: '16px' }}>
            <button
              className={`segment ${state.activeSubTab === 'create' ? 'active' : ''}`}
              onClick={() => updateState({ activeSubTab: 'create' })}
            >
              Create JWT
            </button>
            <button
              className={`segment ${state.activeSubTab === 'verify' ? 'active' : ''}`}
              onClick={() => updateState({ activeSubTab: 'verify' })}
            >
            Verify JWT
          </button>
          </div>
        )}
      </section>

      {!verifyOnly && state.activeSubTab === 'create' && (
        <>
          <section className="card" style={{ marginTop: '12px' }}>
            <h3>Create JWT</h3>
            
            {/* Key Selection */}
            <div className="field">
              <label>Signing Key</label>
              <select 
                value={state.selectedKeyId} 
                onChange={(e) => updateState({ selectedKeyId: e.target.value })}
              >
                <option value="">-- Select a key --</option>
                {getAvailableKeys().map(key => (
                  <option key={key.id} value={key.id} disabled={key.disabled}>
                    {key.label}
                  </option>
                ))}
              </select>
            </div>

            {state.selectedKeyId === 'custom' && (
              <div className="field">
                <label>Custom Key (JWK JSON)</label>
                <textarea
                  value={state.customKey}
                  onChange={(e) => updateState({ customKey: e.target.value })}
                  placeholder='{"kty":"RSA","n":"...","e":"AQAB","d":"..."}'
                  style={{ minHeight: '100px' }}
                />
              </div>
            )}

            {/* Header Claims */}
            <div className="field">
              <label>Header Claims</label>
              <div className="row">
                <input
                  type="text"
                  placeholder="typ"
                  value={state.headerClaims.typ || ''}
                  onChange={(e) => updateState({ 
                    headerClaims: { ...state.headerClaims, typ: e.target.value }
                  })}
                />
              </div>
            </div>

            {/* Standard Payload Claims */}
            <div className="field">
              <label>Standard Claims</label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px' }}>
                <input
                  type="text"
                  placeholder="iss (issuer)"
                  value={state.payloadClaims.iss || ''}
                  onChange={(e) => updateState({ 
                    payloadClaims: { ...state.payloadClaims, iss: e.target.value }
                  })}
                />
                <input
                  type="text"
                  placeholder="aud (audience)"
                  value={state.payloadClaims.aud || ''}
                  onChange={(e) => updateState({ 
                    payloadClaims: { ...state.payloadClaims, aud: e.target.value }
                  })}
                />
                <input
                  type="text"
                  placeholder="sub (subject)"
                  value={state.payloadClaims.sub || ''}
                  onChange={(e) => updateState({ 
                    payloadClaims: { ...state.payloadClaims, sub: e.target.value }
                  })}
                />
                <input
                  type="number"
                  placeholder="exp (expires)"
                  value={state.payloadClaims.exp || ''}
                  onChange={(e) => updateState({ 
                    payloadClaims: { ...state.payloadClaims, exp: parseInt(e.target.value) || 0 }
                  })}
                />
                <input
                  type="number"
                  placeholder="iat (issued at)"
                  value={state.payloadClaims.iat || ''}
                  onChange={(e) => updateState({ 
                    payloadClaims: { ...state.payloadClaims, iat: parseInt(e.target.value) || 0 }
                  })}
                />
                <input
                  type="number"
                  placeholder="nbf (not before)"
                  value={state.payloadClaims.nbf || ''}
                  onChange={(e) => updateState({ 
                    payloadClaims: { ...state.payloadClaims, nbf: parseInt(e.target.value) || 0 }
                  })}
                />
              </div>
            </div>

            {/* Custom Claims */}
            <div className="field">
              <label>Custom Claims (JSON)</label>
              <textarea
                value={state.customClaims}
                onChange={(e) => updateState({ customClaims: e.target.value })}
                placeholder='{"custom_claim": "value", "role": "admin"}'
                style={{ minHeight: '80px' }}
              />
            </div>

            <div className="actions">
              <button 
                className="btn primary" 
                onClick={createJwt}
                disabled={busy}
              >
                {busy && <Spinner size={16} />}
                Create JWT
              </button>
              <button className="btn" onClick={clearAll}>
                Clear All
              </button>
            </div>
          </section>

          {state.generatedJwt && (
            <section className="outputs grid grid-1 outputs-animated" style={{ marginTop: '12px' }}>
              <OutputCard
                title="Generated JWT"
                value={state.generatedJwt}
                filename="token.jwt"
                setMessage={setMessage}
                showToast={showToast}
              />
            </section>
          )}
        </>
      )}

      {(verifyOnly || state.activeSubTab === 'verify') && (
        <>
          <section className="card" style={{ marginTop: '12px' }}>
            <h3>Verify JWT</h3>
            
            {/* Shared textarea styling for consistent width */}
            {(() => {
              const textareaStyle = { 
                minHeight: '120px', 
                height: '120px',
                maxHeight: 'none',
                width: '100%', 
                boxSizing: 'border-box',
                resize: 'vertical',
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace'
              };
              
              const fieldStyle = {
                display: 'flex',
                flexDirection: 'column',
                width: '100%'
              };
              
              const labelContainerStyle = {
                display: 'flex',
                alignItems: 'center',
                marginBottom: '8px',
                minHeight: '24px' // Ensure consistent label height
              };
              
              return (
                <>
                  <div className="field" style={fieldStyle}>
                    <div style={labelContainerStyle}>
                      <label style={{ margin: 0 }}>JWT to Verify</label>
                    </div>
                    <textarea
                      value={state.jwtToVerify}
                      onChange={async (e) => {
                        const jwtValue = e.target.value;
                        updateState({ jwtToVerify: jwtValue });
                        
                        // Try to extract key from x5c if present
                        if (jwtValue.trim()) {
                          const extractedKey = await extractKeyFromX5c(jwtValue);
                          if (extractedKey) {
                            updateState({ 
                              verificationKey: extractedKey.jwk,
                              x5cExtracted: extractedKey 
                            });
                            if (showToast) {
                              showToast(`✓ Auto-extracted ${extractedKey.keyType} public key from x5c certificate chain`);
                            }
                          } else {
                            // Clear x5c extraction info if no x5c found
                            updateState({ x5cExtracted: null });
                          }
                        }
                      }}
                      placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature"
                      style={{...textareaStyle}}
                      rows="2"
                    />
                  </div>

                  <div className="field" style={{ ...fieldStyle, marginTop: '16px' }}>
                    <div style={labelContainerStyle}>
                      <label style={{ margin: 0 }}>Verification Key (Public Key JWK)</label>
                      {state.x5cExtracted && (
                        <span style={{ color: '#10b981', fontSize: '12px', marginLeft: '8px' }}>
                          ✓ Auto-extracted from x5c
                        </span>
                      )}
                    </div>
                    <textarea
                      value={state.verificationKey}
                      onChange={(e) => updateState({ verificationKey: e.target.value, x5cExtracted: null })}
                      placeholder='{"kty":"RSA","n":"...","e":"AQAB"}'
                      style={{...textareaStyle}}
                      rows="2"
                    />
                  </div>
                </>
              );
            })()}

            <div className="actions" style={{ marginTop: '20px' }}>
              <button 
                className="btn primary" 
                onClick={decodeJwt}
                disabled={busy}
                style={{ marginRight: '8px' }}
              >
                {busy && <Spinner size={16} />}
                Decode JWT
              </button>
              <button 
                className="btn" 
                onClick={verifyJwt}
                disabled={busy}
                style={{ marginRight: '8px' }}
              >
                {busy && <Spinner size={16} />}
                Verify JWT
              </button>
              <button className="btn" onClick={clearAll}>
                Clear All
              </button>
            </div>
          </section>

          {state.verificationResult && (
            <section className="card outputs-animated" style={{ marginTop: '12px' }}>
              <h3>
                {state.verificationResult.mode === 'decode-only' ? 'JWT Decode Result' : 'Verification Result'}
              </h3>
              
              {state.verificationResult.error ? (
                <div className="validation-error">
                  <div className="badge" style={{ 
                    background: 'var(--badge-bg)', 
                    color: '#ef4444',
                    border: '1px solid #ef4444',
                    marginBottom: '12px',
                    display: 'inline-block'
                  }}>
                    ✗ Error
                  </div>
                  <p className="muted">{state.verificationResult.error}</p>
                </div>
              ) : (
                <>
                  {state.verificationResult.mode === 'decode-only' ? (
                    <div className="validation-success">
                      <div className="badge" style={{ 
                        background: 'var(--badge-bg)', 
                        color: '#3b82f6',
                        border: '1px solid #3b82f6',
                        marginBottom: '12px',
                        display: 'inline-block'
                      }}>
                        ℹ JWT Decoded (Not Verified)
                      </div>
                      {state.verificationResult.decodedAt && (
                        <p className="muted" style={{ fontSize: '12px', marginTop: '8px' }}>
                          Decoded at: {new Date(state.verificationResult.decodedAt).toLocaleString()}
                        </p>
                      )}
                    </div>
                  ) : (
                    <div className="validation-success">
                      <div className="badge" style={{ 
                        background: 'var(--badge-bg)', 
                        color: state.verificationResult.valid ? '#10b981' : '#ef4444',
                        border: `1px solid ${state.verificationResult.valid ? '#10b981' : '#ef4444'}`,
                        marginBottom: '12px',
                        display: 'inline-block'
                      }}>
                        {state.verificationResult.valid ? '✓ Valid JWT' : '✗ Invalid JWT'}
                      </div>
                    </div>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '12px', marginBottom: '16px' }}>
                    <div style={{ background: 'var(--input-bg)', padding: '12px', borderRadius: '8px', overflow: 'hidden' }}>
                      <h4 style={{ margin: '0 0 8px 0', fontSize: '14px' }}>Header</h4>
                      <pre style={{ 
                        margin: 0, 
                        fontSize: '12px', 
                        whiteSpace: 'pre-wrap', 
                        wordBreak: 'break-all',
                        overflowWrap: 'break-word',
                        overflow: 'auto',
                        maxHeight: '200px'
                      }}>
                        {JSON.stringify(state.verificationResult.header, null, 2)}
                      </pre>
                    </div>
                    <div style={{ background: 'var(--input-bg)', padding: '12px', borderRadius: '8px', overflow: 'hidden' }}>
                      <h4 style={{ margin: '0 0 8px 0', fontSize: '14px' }}>Payload</h4>
                      <pre style={{ 
                        margin: 0, 
                        fontSize: '12px', 
                        whiteSpace: 'pre-wrap', 
                        wordBreak: 'break-all',
                        overflowWrap: 'break-word',
                        overflow: 'auto',
                        maxHeight: '200px'
                      }}>
                        {JSON.stringify(state.verificationResult.payload, null, 2)}
                      </pre>
                    </div>
                  </div>

                  {/* Verification-specific displays */}
                  {state.verificationResult.mode === 'verify' && (
                    <>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                        <div style={{ background: 'var(--input-bg)', padding: '8px', borderRadius: '6px', textAlign: 'center' }}>
                          <div style={{ fontSize: '16px', fontWeight: '600', color: state.verificationResult.signatureValid ? '#10b981' : '#ef4444' }}>
                            {state.verificationResult.signatureValid ? '✓' : '✗'}
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Signature</div>
                        </div>
                        <div style={{ background: 'var(--input-bg)', padding: '8px', borderRadius: '6px', textAlign: 'center' }}>
                          <div style={{ fontSize: '16px', fontWeight: '600', color: state.verificationResult.isExpired ? '#ef4444' : '#10b981' }}>
                            {state.verificationResult.isExpired ? '✗' : '✓'}
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Not Expired</div>
                        </div>
                        <div style={{ background: 'var(--input-bg)', padding: '8px', borderRadius: '6px', textAlign: 'center' }}>
                          <div style={{ fontSize: '16px', fontWeight: '600', color: state.verificationResult.isNotYetValid ? '#ef4444' : '#10b981' }}>
                            {state.verificationResult.isNotYetValid ? '✗' : '✓'}
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Valid Now</div>
                        </div>
                      </div>

                      {state.verificationResult.timing && (
                        <div style={{ marginTop: '12px', background: 'var(--input-bg)', padding: '12px', borderRadius: '8px' }}>
                          <h4 style={{ margin: '0 0 8px 0', fontSize: '14px' }}>Timing</h4>
                          <div style={{ fontSize: '12px', color: 'var(--muted)' }}>
                            {state.verificationResult.timing.issued && (
                              <div>Issued: {state.verificationResult.timing.issued}</div>
                            )}
                            {state.verificationResult.timing.expires && (
                              <div>Expires: {state.verificationResult.timing.expires}</div>
                            )}
                            {state.verificationResult.timing.notBefore && (
                              <div>Not Before: {state.verificationResult.timing.notBefore}</div>
                            )}
                          </div>
                        </div>
                      )}
                    </>
                  )}

                  {/* Decode-only specific displays */}
                  {state.verificationResult.mode === 'decode-only' && (
                    <>
                      {state.verificationResult.claims && (
                        <div style={{ marginTop: '12px', background: 'var(--input-bg)', padding: '12px', borderRadius: '8px' }}>
                          <h4 style={{ margin: '0 0 8px 0', fontSize: '14px' }}>Standard Claims</h4>
                          <div style={{ fontSize: '12px', color: 'var(--muted)' }}>
                            {state.verificationResult.claims.iss && <div>{state.verificationResult.claims.iss}</div>}
                            {state.verificationResult.claims.sub && <div>{state.verificationResult.claims.sub}</div>}
                            {state.verificationResult.claims.aud && <div>{state.verificationResult.claims.aud}</div>}
                            {state.verificationResult.claims.jti && <div>{state.verificationResult.claims.jti}</div>}
                            {state.verificationResult.claims.exp && (
                              <div style={{ color: state.verificationResult.claims.exp.expired ? '#ef4444' : '#10b981' }}>
                                Expires: {state.verificationResult.claims.exp.date}
                                {state.verificationResult.claims.exp.expired ? ' (EXPIRED)' : ''}
                              </div>
                            )}
                            {state.verificationResult.claims.nbf && (
                              <div style={{ color: state.verificationResult.claims.nbf.active ? '#10b981' : '#f59e0b' }}>
                                Not Before: {state.verificationResult.claims.nbf.date}
                                {!state.verificationResult.claims.nbf.active ? ' (NOT YET ACTIVE)' : ''}
                              </div>
                            )}
                            {state.verificationResult.claims.iat && (
                              <div>Issued At: {state.verificationResult.claims.iat.date}</div>
                            )}
                          </div>
                        </div>
                      )}

                      {state.verificationResult.x5cInfo && (
                        <div style={{ marginTop: '12px', background: 'var(--input-bg)', padding: '12px', borderRadius: '8px' }}>
                          <h4 style={{ margin: '0 0 8px 0', fontSize: '14px' }}>X.509 Certificate Chain (x5c)</h4>
                          <div style={{ fontSize: '12px', color: 'var(--muted)' }}>
                            <div>Chain Length: {state.verificationResult.x5cInfo.chainLength} certificate(s)</div>
                            {state.verificationResult.x5cInfo.firstCert && (
                              <div style={{ 
                                fontFamily: 'monospace', 
                                marginTop: '4px',
                                wordBreak: 'break-all'
                              }}>
                                First Certificate: {state.verificationResult.x5cInfo.firstCert}
                              </div>
                            )}
                            <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '4px' }}>
                              💡 Use "Verify JWT" to automatically extract and use these certificates
                            </div>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </>
              )}
            </section>
          )}
        </>
      )}
    </>
  );
}

export default JwtBuilder;