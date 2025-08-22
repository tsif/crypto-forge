import React, { useState, useEffect } from 'react';
import Controls from './components/Controls';
import OutputCard from './components/OutputCard';
import PemConverter from './components/PemConverter';
import JwtBuilder from './components/JwtBuilder';
import KeyValidator from './components/KeyValidator';
import JwksValidator from './components/JwksValidator';
import CertificateValidator from './components/CertificateValidator';
import CertificateGenerator from './components/CertificateGenerator';
import SegmentedControl from './components/SegmentedControl';
import ThemeToggle from './components/ThemeToggle';
import FontSizeToggle from './components/FontSizeToggle';
import Toast from './components/Toast';
import KeyStrengthAnalyzer from './components/KeyStrengthAnalyzer';
import ScrollIndicator from './components/ScrollIndicator';
import * as cryptoUtils from './utils/cryptoUtils';
import './App.css';

function App() {
  const [algorithm, setAlgorithm] = useState('EC');
  const [rsaBits, setRsaBits] = useState('2048');
  const [rsaHash, setRsaHash] = useState('SHA-256');
  const [ecCurve, setEcCurve] = useState('P-256');
  const [keyUse, setKeyUse] = useState('sig');
  const [message, setMessage] = useState('Keys generated in your browser.');
  const [busy, setBusy] = useState(false);
  const [activeTab, setActiveTab] = useState('generate');
  
  // Toast state
  const [toast, setToast] = useState({ show: false, message: '' });
  
  // Theme state with system preference detection
  const [theme, setTheme] = useState(() => {
    // Check localStorage first
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
      return savedTheme;
    }
    // Otherwise check system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }
    return 'light';
  });

  // Font size state with localStorage persistence
  const [fontSize, setFontSize] = useState(() => {
    const savedFontSize = localStorage.getItem('fontSize');
    return savedFontSize || 'default';
  });

  // Apply theme on mount and when it changes
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

  // Apply font size on mount and when it changes
  useEffect(() => {
    document.documentElement.setAttribute('data-font-size', fontSize);
    localStorage.setItem('fontSize', fontSize);
  }, [fontSize]);

  // Listen for system theme changes
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e) => {
      // Only update if no saved preference
      if (!localStorage.getItem('theme')) {
        setTheme(e.matches ? 'dark' : 'light');
      }
    };
    
    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', handleChange);
      return () => mediaQuery.removeEventListener('change', handleChange);
    }
  }, []);

  const toggleTheme = () => {
    setTheme(prevTheme => prevTheme === 'light' ? 'dark' : 'light');
  };

  const toggleFontSize = () => {
    setFontSize(prevSize => prevSize === 'default' ? 'large' : 'default');
  };

  const showToast = (message) => {
    setToast({ show: true, message });
  };

  const hideToast = () => {
    setToast({ show: false, message: '' });
  };
  
  const [outputs, setOutputs] = useState({
    privateJwk: '',
    publicJwk: '',
    jwksPair: '',
    jwksPublic: '',
    publicPem: '',
    privatePem: '',
    openssh: '',
    publicJwkObject: null
  });

  // State for scroll indicator
  const [showScrollIndicator, setShowScrollIndicator] = useState(false);

  const [pemConversionOutputs, setPemConversionOutputs] = useState({
    privateJwk: '',
    publicJwk: '',
    jwksPair: '',
    jwksPublic: '',
    publicPem: '',
    privatePem: '',
    openssh: '',
    publicJwkObject: null
  });

  const [pemConversionError, setPemConversionError] = useState(null);
  
  // Input states for persistence across tab switches
  const [pemInput, setPemInput] = useState('');
  
  // Validation states for persistence
  const [keyValidatorState, setKeyValidatorState] = useState({
    keyInput: '',
    validationResult: null
  });
  
  const [jwksValidatorState, setJwksValidatorState] = useState({
    jwksInput: '',
    validationResult: null
  });
  
  const [certValidatorState, setCertValidatorState] = useState({
    certInput: '',
    validationResult: null
  });
  
  const [jwtVerifyState, setJwtVerifyState] = useState({
    jwtToVerify: '',
    verificationKey: '',
    verificationResult: null,
    x5cExtracted: null
  });

  const getAlg = () => {
    if (algorithm === 'RSA') {
      if (keyUse === 'enc') {
        // RSA-OAEP algorithms for encryption
        return {
          'SHA-256': 'RSA-OAEP-256',
          'SHA-384': 'RSA-OAEP-384',
          'SHA-512': 'RSA-OAEP-512'
        }[rsaHash] || 'RSA-OAEP';
      }
      return cryptoUtils.algForSelection('RSA', rsaHash);
    }
    // For EC, algorithm doesn't change with use (ECDH doesn't have standard JWA alg values)
    return cryptoUtils.algForSelection('EC', ecCurve);
  };

  // Extract public key from X.509 certificate DER
  const extractPublicKeyFromCertificate = (certDer) => {
    // Parse X.509 certificate to extract SubjectPublicKeyInfo
    // X.509 Certificate structure:
    // Certificate ::= SEQUENCE {
    //   tbsCertificate       TBSCertificate,
    //   signatureAlgorithm   AlgorithmIdentifier,
    //   signatureValue       BIT STRING  
    // }
    // TBSCertificate ::= SEQUENCE {
    //   ...
    //   subjectPublicKeyInfo SubjectPublicKeyInfo,
    //   ...
    // }
    
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
      // Short form
      return firstByte;
    } else {
      // Long form
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
      return 1; // Short form uses 1 byte
    } else {
      return 1 + (firstByte & 0x7f); // Long form uses 1 + n bytes
    }
  };

  // Get available keys for JWT Builder
  const getAvailableKeys = () => {
    const keys = [];

    // Add keys from key generation
    if (outputs.publicJwkObject) {
      const keyDesc = `Generated ${outputs.publicJwkObject.kty} ${
        outputs.publicJwkObject.kty === 'RSA' 
          ? `${outputs.publicJwkObject.n ? Math.ceil(atob(outputs.publicJwkObject.n.replace(/-/g, '+').replace(/_/g, '/')).length * 8) : 'Unknown'}-bit`
          : outputs.publicJwkObject.crv
      } (${outputs.publicJwkObject.use || 'sig'})`;
      
      // Add both public and private keys if available
      if (outputs.privateJwk) {
        try {
          const privateJwk = JSON.parse(outputs.privateJwk);
          keys.push({
            id: `generated-private-${Date.now()}`,
            label: `${keyDesc} - Private Key`,
            jwk: privateJwk,
            type: 'private'
          });
        } catch (e) {
          // Ignore parse errors
        }
      }
      
      keys.push({
        id: `generated-public-${Date.now()}`,
        label: `${keyDesc} - Public Key`,
        jwk: outputs.publicJwkObject,
        type: 'public'
      });
    }

    // Add keys from PEM conversion
    if (pemConversionOutputs.publicJwkObject) {
      const keyDesc = `Converted ${pemConversionOutputs.publicJwkObject.kty} ${
        pemConversionOutputs.publicJwkObject.kty === 'RSA' 
          ? `${pemConversionOutputs.publicJwkObject.n ? Math.ceil(atob(pemConversionOutputs.publicJwkObject.n.replace(/-/g, '+').replace(/_/g, '/')).length * 8) : 'Unknown'}-bit`
          : pemConversionOutputs.publicJwkObject.crv
      } (${pemConversionOutputs.publicJwkObject.use || 'sig'})`;
      
      // Add both public and private keys if available
      if (pemConversionOutputs.privateJwk) {
        try {
          const privateJwk = JSON.parse(pemConversionOutputs.privateJwk);
          keys.push({
            id: `converted-private-${Date.now()}`,
            label: `${keyDesc} - Private Key`,
            jwk: privateJwk,
            type: 'private'
          });
        } catch (e) {
          // Ignore parse errors
        }
      }
      
      keys.push({
        id: `converted-public-${Date.now()}`,
        label: `${keyDesc} - Public Key`,
        jwk: pemConversionOutputs.publicJwkObject,
        type: 'public'
      });
    }

    return keys;
  };

  const clearOutputs = () => {
    setOutputs({
      privateJwk: '',
      publicJwk: '',
      jwksPair: '',
      jwksPublic: '',
      publicPem: '',
      privatePem: '',
      openssh: '',
      publicJwkObject: null
    });
    setMessage('');
    setShowScrollIndicator(false);
  };

  const clearPemOutputs = () => {
    setPemConversionOutputs({
      privateJwk: '',
      publicJwk: '',
      jwksPair: '',
      jwksPublic: '',
      publicPem: '',
      privatePem: '',
      openssh: '',
      publicJwkObject: null
    });
    setPemConversionError(null);
    setPemInput('');
  };

  const generateKeys = async () => {
    setBusy(true);
    setMessage('');
    
    try {
      const isRSA = algorithm === 'RSA';
      const isEncryption = keyUse === 'enc';
      let keyPair;
      
      if (isRSA) {
        if (isEncryption) {
          // Use RSA-OAEP for encryption
          keyPair = await crypto.subtle.generateKey(
            {
              name: 'RSA-OAEP',
              modulusLength: parseInt(rsaBits, 10),
              publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
              hash: rsaHash
            },
            true,
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
          );
        } else {
          // Use RSASSA-PKCS1-v1_5 for signing
          keyPair = await crypto.subtle.generateKey(
            {
              name: 'RSASSA-PKCS1-v1_5',
              modulusLength: parseInt(rsaBits, 10),
              publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
              hash: rsaHash
            },
            true,
            ['sign', 'verify']
          );
        }
      } else {
        // EC keys - ECDSA for signing, ECDH for key agreement (not direct encryption)
        if (isEncryption) {
          keyPair = await crypto.subtle.generateKey(
            {
              name: 'ECDH',
              namedCurve: ecCurve
            },
            true,
            ['deriveKey', 'deriveBits']
          );
        } else {
          keyPair = await crypto.subtle.generateKey(
            {
              name: 'ECDSA',
              namedCurve: ecCurve
            },
            true,
            ['sign', 'verify']
          );
        }
      }

      const jwkPriv = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      const jwkPub = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

      const kid = await cryptoUtils.jwkThumbprint(jwkPub);
      const kidPrivate = await cryptoUtils.privateKeyId(jwkPriv); // Unique ID for private key
      const alg = getAlg();

      // Add 'use' parameter
      // Note: key_ops are already set correctly by Web Crypto API export
      const keyParamsPublic = { kid, alg, use: keyUse };
      const keyParamsPrivate = { kid: kidPrivate, alg, use: keyUse };
      
      // For ECDH keys used for encryption, we need to handle the alg differently
      if (!isRSA && isEncryption) {
        // ECDH doesn't have standard JWA algorithm identifiers for direct use
        // Set alg to indicate the curve-based ECDH
        keyParamsPublic.alg = 'ECDH-ES';
        keyParamsPrivate.alg = 'ECDH-ES';
      }
      
      Object.assign(jwkPriv, keyParamsPrivate);
      Object.assign(jwkPub, keyParamsPublic);

      // Export keys to PEM format
      const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

      // Generate OpenSSH format
      const opensshKey = cryptoUtils.jwkToOpenSSH(jwkPub, 'cryptoforge-generated');

      setOutputs({
        privateJwk: cryptoUtils.prettyJson(jwkPriv),
        publicJwk: cryptoUtils.prettyJson(jwkPub),
        jwksPair: JSON.stringify({ keys: [jwkPub, jwkPriv] }, null, 2),
        jwksPublic: JSON.stringify({ keys: [jwkPub] }, null, 2),
        publicPem: cryptoUtils.derToPem(spki, 'PUBLIC KEY'),
        privatePem: cryptoUtils.derToPem(pkcs8, 'PRIVATE KEY'),
        openssh: opensshKey,
        publicJwkObject: jwkPub
      });

      setMessage('Keys generated in your browser.');
      
      // Show scroll indicator to help user find the generated keys
      setShowScrollIndicator(true);
    } catch (e) {
      console.error(e);
      setMessage('Error: ' + (e && e.message ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  };

  const handlePemConversion = async (pemText) => {
    setBusy(true);
    setMessage('');
    setPemConversionError(null);
    
    try {
      const { der, label } = cryptoUtils.pemToDer(pemText);
      const format = /PUBLIC KEY/.test(label) ? 'spki' : 
                   /^PRIVATE KEY$/.test(label) ? 'pkcs8' : 
                   /RSA PRIVATE KEY/.test(label) ? 'pkcs1' :
                   /CERTIFICATE/.test(label) ? 'x509' : null;
      
      if (!format) throw new Error('PEM must be PUBLIC KEY, PRIVATE KEY, RSA PRIVATE KEY, or CERTIFICATE.');
      
      const isPrivate = format === 'pkcs8' || format === 'pkcs1';
      const isCertificate = format === 'x509';
      
      let imported, family, publicKeyDer;
      
      if (isCertificate) {
        // Extract public key from certificate
        try {
          publicKeyDer = extractPublicKeyFromCertificate(der);
          
          // Try to import the extracted public key
          imported = await cryptoUtils.tryImportRSA('spki', publicKeyDer, false);
          family = 'RSA';
          
          if (!imported) {
            imported = await cryptoUtils.tryImportEC('spki', publicKeyDer, false);
            family = 'EC';
          }
          
          if (!imported) throw new Error('Failed to extract or import public key from certificate.');
        } catch (e) {
          throw new Error(`Failed to process certificate: ${e.message}`);
        }
      } else {
        // Handle regular key PEMs
        imported = await cryptoUtils.tryImportRSA(format, der, isPrivate);
        family = 'RSA';
        
        if (!imported) {
          imported = await cryptoUtils.tryImportEC(format, der, isPrivate);
          family = 'EC';
        }
        
        if (!imported) throw new Error('Failed to import key. Unsupported algorithm or malformed PEM.');
      }

      const jwk = await crypto.subtle.exportKey('jwk', imported.key);
      const jwkPriv = isPrivate ? jwk : null;
      const jwkPub = isPrivate ? cryptoUtils.derivePublicFromPrivateJwk(jwk) : jwk;

      const kid = await cryptoUtils.jwkThumbprint(jwkPub);
      const inferredAlg = family === 'RSA' ? 'RS256' : 
        (jwkPub.crv === 'P-384' ? 'ES384' : (jwkPub.crv === 'P-521' ? 'ES512' : 'ES256'));

      // Infer 'use' based on the key type
      const inferredUse = (family === 'RSA' && imported.name === 'RSA-OAEP') ? 'enc' : 'sig';

      if (jwkPriv) {
        const kidPrivate = await cryptoUtils.privateKeyId(jwkPriv); // Unique ID for private key
        jwkPriv.kid = kidPrivate;
        jwkPriv.alg = inferredAlg;
        jwkPriv.use = inferredUse;
        // key_ops already included from the native export
      }
      
      jwkPub.kid = kid;
      jwkPub.alg = inferredAlg;
      jwkPub.use = inferredUse;
      // key_ops already included from the native export

      let pubPemOut = '';
      let privPemOut = '';
      
      if (isPrivate) {
        privPemOut = cryptoUtils.derToPem(der, 'PRIVATE KEY');
        const pubKey = await crypto.subtle.importKey(
          'jwk',
          jwkPub,
          family === 'RSA' ? 
            { name: imported.name || 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } : 
            { name: 'ECDSA', namedCurve: jwkPub.crv },
          true,
          (family === 'RSA' && imported.name === 'RSA-OAEP') ? ['encrypt'] : ['verify']
        );
        const spki = await crypto.subtle.exportKey('spki', pubKey);
        pubPemOut = cryptoUtils.derToPem(spki, 'PUBLIC KEY');
      } else if (isCertificate) {
        // For certificates, use the extracted public key DER
        pubPemOut = cryptoUtils.derToPem(publicKeyDer, 'PUBLIC KEY');
      } else {
        pubPemOut = cryptoUtils.derToPem(der, 'PUBLIC KEY');
      }

      // Generate OpenSSH format for public key
      const opensshKey = cryptoUtils.jwkToOpenSSH(jwkPub, 'cryptoforge-converted');

      setPemConversionOutputs({
        privateJwk: jwkPriv ? cryptoUtils.prettyJson(jwkPriv) : '',
        publicJwk: cryptoUtils.prettyJson(jwkPub),
        jwksPair: jwkPriv ? 
          JSON.stringify({ keys: [jwkPub, jwkPriv] }, null, 2) : 
          JSON.stringify({ keys: [jwkPub] }, null, 2),
        jwksPublic: JSON.stringify({ keys: [jwkPub] }, null, 2),
        publicPem: pubPemOut,
        privatePem: privPemOut,
        openssh: opensshKey,
        publicJwkObject: jwkPub
      });

      setMessage(isCertificate ? 'Certificate processed - public key extracted successfully.' : 'PEM converted successfully.');
    } catch (e) {
      console.error(e);
      setPemConversionError(e.message || String(e));
      setMessage('Error: ' + (e && e.message ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <nav className="navbar">
        <div className="nav-container">
          <div className="nav-content">
            <h1>CryptoForge — Your Complete Key & Certificate Toolkit</h1>
            <p className="nav-subtitle">
              Generate keypairs, convert between JWK/PEM formats, verify JWTs, validate keys, and decode X.509 certificates. 
              All cryptographic operations run securely in your browser.
            </p>
          </div>
          <div className="nav-actions">
            <FontSizeToggle fontSize={fontSize} toggleFontSize={toggleFontSize} />
            <ThemeToggle theme={theme} toggleTheme={toggleTheme} />
            <a className="muted link mobile-only" href="#notes">Security notes</a>
          </div>
        </div>
      </nav>
      
      <div className="container">
        <SegmentedControl activeTab={activeTab} onTabChange={setActiveTab} />

        {activeTab === 'generate' && (
          <>
            <Controls
              algorithm={algorithm}
              setAlgorithm={setAlgorithm}
              rsaBits={rsaBits}
              setRsaBits={setRsaBits}
              rsaHash={rsaHash}
              setRsaHash={setRsaHash}
              ecCurve={ecCurve}
              setEcCurve={setEcCurve}
              keyUse={keyUse}
              setKeyUse={setKeyUse}
              alg={getAlg()}
              onGenerate={generateKeys}
              onClear={clearOutputs}
              busy={busy}
              message={message}
            />

            {(outputs.privateJwk || outputs.publicJwk) && (
              <section className="outputs grid grid-2 outputs-animated" style={{ marginTop: '12px' }}>
                <OutputCard
                  title="Private JWK"
                  value={outputs.privateJwk}
                  filename="private.jwk.json"
                  setMessage={setMessage}
                  showToast={showToast}
                />
                <OutputCard
                  title="Public JWK"
                  value={outputs.publicJwk}
                  filename="public.jwk.json"
                  setMessage={setMessage}
                  showToast={showToast}
                />
                <OutputCard
                  title="JWK Set (Keypair)"
                  value={outputs.jwksPair}
                  filename="jwks-keypair.json"
                  setMessage={setMessage}
                  showToast={showToast}
                />
                <OutputCard
                  title="JWK Set (Public only)"
                  value={outputs.jwksPublic}
                  filename="jwks-public.json"
                  setMessage={setMessage}
                  showToast={showToast}
                />
                <OutputCard
                  title="Public Key (SPKI PEM)"
                  value={outputs.publicPem}
                  filename="public.pem"
                  setMessage={setMessage}
                  showToast={showToast}
                />
                <OutputCard
                  title="Private Key (PKCS#8 PEM)"
                  value={outputs.privatePem}
                  filename="private.pem"
                  setMessage={setMessage}
                  showToast={showToast}
                />
                <OutputCard
                  title="Public Key (OpenSSH)"
                  value={outputs.openssh}
                  filename="id_rsa.pub"
                  setMessage={setMessage}
                  showToast={showToast}
                />
              </section>
            )}

            {outputs.publicJwkObject && (
              <section className="card outputs-animated" style={{ marginTop: '12px' }}>
                <KeyStrengthAnalyzer jwk={outputs.publicJwkObject} />
              </section>
            )}
          </>
        )}

        {activeTab === 'pem-convert' && (
          <PemConverter 
            onConvert={handlePemConversion} 
            busy={busy} 
            outputs={pemConversionOutputs}
            setMessage={setMessage}
            onClearOutputs={clearPemOutputs}
            error={pemConversionError}
            showToast={showToast}
            pemInput={pemInput}
            setPemInput={setPemInput}
          />
        )}

        {activeTab === 'jwt-verify' && (
          <JwtBuilder 
            verifyOnly={true}
            availableKeys={getAvailableKeys()}
            jwtVerifyState={jwtVerifyState}
            setJwtVerifyState={setJwtVerifyState}
            showToast={showToast}
            setMessage={setMessage}
          />
        )}
        {activeTab === 'certificate-generator' && (
          <CertificateGenerator
            availableKeys={getAvailableKeys()}
            setMessage={setMessage}
            showToast={showToast}
          />
        )}

        {activeTab === 'validate-jwk' && (
          <KeyValidator 
            keyInput={keyValidatorState.keyInput}
            setKeyInput={(input) => setKeyValidatorState(prev => ({ ...prev, keyInput: input }))}
            validationResult={keyValidatorState.validationResult}
            setValidationResult={(result) => setKeyValidatorState(prev => ({ ...prev, validationResult: result }))}
          />
        )}

        {activeTab === 'validate-jwks' && (
          <JwksValidator 
            jwksInput={jwksValidatorState.jwksInput}
            setJwksInput={(input) => setJwksValidatorState(prev => ({ ...prev, jwksInput: input }))}
            validationResult={jwksValidatorState.validationResult}
            setValidationResult={(result) => setJwksValidatorState(prev => ({ ...prev, validationResult: result }))}
          />
        )}

        {activeTab === 'validate-cert' && (
          <CertificateValidator 
            certInput={certValidatorState.certInput}
            setCertInput={(input) => setCertValidatorState(prev => ({ ...prev, certInput: input }))}
            validationResult={certValidatorState.validationResult}
            setValidationResult={(result) => setCertValidatorState(prev => ({ ...prev, validationResult: result }))}
          />
        )}

      <section id="notes" className="stack mobile-only" style={{ marginTop: '8px' }}>
        <h2>Notes & safety</h2>
        <ul className="muted" style={{ paddingLeft: '18px', margin: 0 }}>
          <li>Keys are generated <em>locally</em> in your browser using the Web Crypto API. No data is sent anywhere by this page.</li>
          <li>Public PEMs are <code>SubjectPublicKeyInfo</code> (<code>BEGIN PUBLIC KEY</code>). Private PEMs are PKCS#8 (<code>BEGIN PRIVATE KEY</code>).</li>
          <li><strong>Never</strong> publish a JWKS that contains private keys. The "JWK Set (Keypair)" is for local testing only.</li>
          <li>Certificate validation parses X.509 structure and displays properties. <strong>Always verify</strong> certificate chain and CRL status separately.</li>
          <li>Imported PEMs and certificates are auto-detected (RSA or EC). For RSA, RSASSA-PKCS1-v1_5, RSA-PSS, or RSA-OAEP are accepted. For EC, P‑256/P‑384/P‑521 are supported.</li>
          <li>The <code>alg</code> on imported keys is inferred (e.g., RS256 for RSA; ES256/384/512 for EC) and may not match the original usage.</li>
        </ul>
      </section>
      </div>
      
      <footer className="security-footer desktop-only">
        <div className="security-content">
          <h3>Notes & safety</h3>
          <ul className="security-list">
            <li>Keys are generated <em>locally</em> in your browser using the Web Crypto API. No data is sent anywhere by this page.</li>
            <li>Public PEMs are <code>SubjectPublicKeyInfo</code> (<code>BEGIN PUBLIC KEY</code>). Private PEMs are PKCS#8 (<code>BEGIN PRIVATE KEY</code>).</li>
            <li><strong>Never</strong> publish a JWKS that contains private keys. The "JWK Set (Keypair)" is for local testing only.</li>
            <li>Certificate validation parses X.509 structure and displays properties. <strong>Always verify</strong> certificate chain and CRL status separately.</li>
            <li>JWT verification supports RSA and EC algorithms. Public keys are auto-extracted from <code>x5c</code> certificate chains when present in JWT headers.</li>
            <li>Imported PEMs and certificates are auto-detected (RSA or EC). For RSA, RSASSA-PKCS1-v1_5, RSA-PSS, or RSA-OAEP are accepted. For EC, P‑256/P‑384/P‑521 are supported.</li>
            <li>The <code>alg</code> on imported keys is inferred (e.g., RS256 for RSA; ES256/384/512 for EC) and may not match the original usage.</li>
          </ul>
          <div className="security-footer-copyright">
            © {new Date().getFullYear()} • Built for developers. Use at your own risk.
          </div>
        </div>
      </footer>
      
      <Toast 
        message={toast.message} 
        show={toast.show} 
        onClose={hideToast} 
      />
      
      <ScrollIndicator 
        show={showScrollIndicator && activeTab === 'generate' && (outputs.privateJwk || outputs.publicJwk)}
        message="Scroll down to view generated keys"
      />
    </>
  );
}

export default App;