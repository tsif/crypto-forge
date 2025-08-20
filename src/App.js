import React, { useState, useEffect } from 'react';
import Controls from './components/Controls';
import OutputCard from './components/OutputCard';
import PemConverter from './components/PemConverter';
import KeyValidator from './components/KeyValidator';
import ThemeToggle from './components/ThemeToggle';
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

  // Apply theme on mount and when it changes
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

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
  
  const [outputs, setOutputs] = useState({
    privateJwk: '',
    publicJwk: '',
    jwksPair: '',
    jwksPublic: '',
    publicPem: '',
    privatePem: ''
  });

  const [pemConversionOutputs, setPemConversionOutputs] = useState({
    privateJwk: '',
    publicJwk: '',
    jwksPair: '',
    jwksPublic: '',
    publicPem: '',
    privatePem: ''
  });

  const [pemConversionError, setPemConversionError] = useState(null);

  const getAlg = () => {
    if (algorithm === 'RSA') {
      return cryptoUtils.algForSelection('RSA', rsaHash);
    }
    return cryptoUtils.algForSelection('EC', ecCurve);
  };

  const clearOutputs = () => {
    setOutputs({
      privateJwk: '',
      publicJwk: '',
      jwksPair: '',
      jwksPublic: '',
      publicPem: '',
      privatePem: ''
    });
    setMessage('');
  };

  const clearPemOutputs = () => {
    setPemConversionOutputs({
      privateJwk: '',
      publicJwk: '',
      jwksPair: '',
      jwksPublic: '',
      publicPem: '',
      privatePem: ''
    });
    setPemConversionError(null);
  };

  const generateKeys = async () => {
    setBusy(true);
    setMessage('');
    
    try {
      const isRSA = algorithm === 'RSA';
      let keyPair;
      
      if (isRSA) {
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

      const jwkPriv = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      const jwkPub = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

      const kid = await cryptoUtils.jwkThumbprint(jwkPub);
      const alg = getAlg();

      // Add 'use' parameter (keep native key_ops from Web Crypto API)
      const keyParams = { kid, alg, use: keyUse };
      
      Object.assign(jwkPriv, keyParams);
      Object.assign(jwkPub, keyParams);

      const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

      setOutputs({
        privateJwk: cryptoUtils.prettyJson(jwkPriv),
        publicJwk: cryptoUtils.prettyJson(jwkPub),
        jwksPair: JSON.stringify({ keys: [jwkPub, jwkPriv] }, null, 2),
        jwksPublic: JSON.stringify({ keys: [jwkPub] }, null, 2),
        publicPem: cryptoUtils.derToPem(spki, 'PUBLIC KEY'),
        privatePem: cryptoUtils.derToPem(pkcs8, 'PRIVATE KEY')
      });

      setMessage('Keys generated in your browser.');
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
      const format = /PUBLIC KEY/.test(label) ? 'spki' : /PRIVATE KEY/.test(label) ? 'pkcs8' : null;
      
      if (!format) throw new Error('PEM must be PUBLIC KEY or PRIVATE KEY.');
      
      const isPrivate = format === 'pkcs8';
      
      let imported = await cryptoUtils.tryImportRSA(format, der, isPrivate);
      let family = 'RSA';
      
      if (!imported) {
        imported = await cryptoUtils.tryImportEC(format, der, isPrivate);
        family = 'EC';
      }
      
      if (!imported) throw new Error('Failed to import key. Unsupported algorithm or malformed PEM.');

      const jwk = await crypto.subtle.exportKey('jwk', imported.key);
      const jwkPriv = isPrivate ? jwk : null;
      const jwkPub = isPrivate ? cryptoUtils.derivePublicFromPrivateJwk(jwk) : jwk;

      const kid = await cryptoUtils.jwkThumbprint(jwkPub);
      const inferredAlg = family === 'RSA' ? 'RS256' : 
        (jwkPub.crv === 'P-384' ? 'ES384' : (jwkPub.crv === 'P-521' ? 'ES512' : 'ES256'));

      // Infer 'use' based on the key type
      const inferredUse = (family === 'RSA' && imported.name === 'RSA-OAEP') ? 'enc' : 'sig';

      if (jwkPriv) {
        jwkPriv.kid = kid;
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
      } else {
        pubPemOut = cryptoUtils.derToPem(der, 'PUBLIC KEY');
      }

      setPemConversionOutputs({
        privateJwk: jwkPriv ? cryptoUtils.prettyJson(jwkPriv) : '',
        publicJwk: cryptoUtils.prettyJson(jwkPub),
        jwksPair: jwkPriv ? 
          JSON.stringify({ keys: [jwkPub, jwkPriv] }, null, 2) : 
          JSON.stringify({ keys: [jwkPub] }, null, 2),
        jwksPublic: JSON.stringify({ keys: [jwkPub] }, null, 2),
        publicPem: pubPemOut,
        privatePem: privPemOut
      });

      setMessage('PEM converted successfully.');
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
            <h1>Key Wizard — JWK ⇄ PEM</h1>
            <p className="nav-subtitle">
              Generate RSA or EC keypairs and convert between JWK/JWKS and PEM (SPKI / PKCS#8). 
              Everything runs in your browser.
            </p>
          </div>
          <div className="nav-actions">
            <ThemeToggle theme={theme} toggleTheme={toggleTheme} />
            <a className="muted link mobile-only" href="#notes">Security notes</a>
          </div>
        </div>
      </nav>
      
      <div className="container">

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
          />
          <OutputCard
            title="Public JWK"
            value={outputs.publicJwk}
            filename="public.jwk.json"
            setMessage={setMessage}
          />
          <OutputCard
            title="JWK Set (Keypair)"
            value={outputs.jwksPair}
            filename="jwks-keypair.json"
            setMessage={setMessage}
          />
          <OutputCard
            title="JWK Set (Public only)"
            value={outputs.jwksPublic}
            filename="jwks-public.json"
            setMessage={setMessage}
          />
          <OutputCard
            title="Public Key (SPKI PEM)"
            value={outputs.publicPem}
            filename="public.pem"
            setMessage={setMessage}
          />
          <OutputCard
            title="Private Key (PKCS#8 PEM)"
            value={outputs.privatePem}
            filename="private.pem"
            setMessage={setMessage}
          />
        </section>
      )}

      <PemConverter 
        onConvert={handlePemConversion} 
        busy={busy} 
        outputs={pemConversionOutputs}
        setMessage={setMessage}
        onClearOutputs={clearPemOutputs}
        error={pemConversionError}
      />

      <KeyValidator />

      <section id="notes" className="stack mobile-only" style={{ marginTop: '8px' }}>
        <h2>Notes & safety</h2>
        <ul className="muted" style={{ paddingLeft: '18px', margin: 0 }}>
          <li>Keys are generated <em>locally</em> in your browser using the Web Crypto API. No data is sent anywhere by this page.</li>
          <li>Public PEMs are <code>SubjectPublicKeyInfo</code> (<code>BEGIN PUBLIC KEY</code>). Private PEMs are PKCS#8 (<code>BEGIN PRIVATE KEY</code>).</li>
          <li><strong>Never</strong> publish a JWKS that contains private keys. The "JWK Set (Keypair)" is for local testing only.</li>
          <li>Imported PEMs are auto-detected (RSA or EC). For RSA, RSASSA-PKCS1-v1_5, RSA-PSS, or RSA-OAEP are accepted. For EC, P‑256/P‑384/P‑521 are supported.</li>
          <li>The <code>alg</code> on imported keys is inferred (e.g., RS256 for RSA; ES256/384/512 for EC) and may not match the original usage.</li>
        </ul>
      </section>

        <div className="footer">
          © {new Date().getFullYear()} • Built for developers. Use at your own risk.
        </div>
      </div>
      
      <footer className="security-footer desktop-only">
        <div className="security-content">
          <h3>Notes & safety</h3>
          <ul className="security-list">
            <li>Keys are generated <em>locally</em> in your browser using the Web Crypto API. No data is sent anywhere by this page.</li>
            <li>Public PEMs are <code>SubjectPublicKeyInfo</code> (<code>BEGIN PUBLIC KEY</code>). Private PEMs are PKCS#8 (<code>BEGIN PRIVATE KEY</code>).</li>
            <li><strong>Never</strong> publish a JWKS that contains private keys. The "JWK Set (Keypair)" is for local testing only.</li>
            <li>Imported PEMs are auto-detected (RSA or EC). For RSA, RSASSA-PKCS1-v1_5, RSA-PSS, or RSA-OAEP are accepted. For EC, P‑256/P‑384/P‑521 are supported.</li>
            <li>The <code>alg</code> on imported keys is inferred (e.g., RS256 for RSA; ES256/384/512 for EC) and may not match the original usage.</li>
          </ul>
          <div className="security-footer-copyright">
            © {new Date().getFullYear()} • Built for developers. Use at your own risk.
          </div>
        </div>
      </footer>
    </>
  );
}

export default App;