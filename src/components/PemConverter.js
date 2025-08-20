import React, { useState } from 'react';
import OutputCard from './OutputCard';

function PemConverter({ onConvert, busy, outputs, setMessage, onClearOutputs, error }) {
  const [pemInput, setPemInput] = useState('');

  const handleFileChange = async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const text = await file.text();
    setPemInput(text);
  };

  const handleConvert = () => {
    onConvert(pemInput);
  };

  const handleClear = () => {
    setPemInput('');
    if (onClearOutputs) {
      onClearOutputs();
    }
  };

  const hasOutputs = outputs && (outputs.publicJwk || outputs.privateJwk);

  return (
    <>
      <section className="card" style={{ marginTop: '12px' }}>
        <h2>PEM → JWK / JWKS</h2>
        <p className="muted">
          Paste or upload a <strong>PUBLIC KEY</strong> (SPKI) or <strong>PRIVATE KEY</strong> (PKCS#8) PEM to convert. 
          Works for RSA and EC keys. If the private key is provided, a corresponding public JWK and SPKI PEM will be derived.
        </p>
        <div className="actions" style={{ marginTop: '8px' }}>
          <input 
            type="file" 
            accept=".pem,.key,.txt" 
            onChange={handleFileChange}
          />
          <button 
            className="btn primary" 
            onClick={handleConvert} 
            disabled={busy || !pemInput.trim()}
          >
            Convert PEM
          </button>
          <button 
            className="btn" 
            onClick={handleClear}
          >
            Clear Input
          </button>
        </div>
        <div className="space"></div>
        <textarea 
          value={pemInput}
          onChange={(e) => setPemInput(e.target.value)}
          placeholder={`-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----`}
        />
      </section>

      {hasOutputs && (
        <section className="outputs grid grid-2 outputs-animated" style={{ marginTop: '12px' }}>
          {outputs.privateJwk && (
            <OutputCard
              title="Converted Private JWK"
              value={outputs.privateJwk}
              filename="converted-private.jwk.json"
              setMessage={setMessage}
            />
          )}
          <OutputCard
            title="Converted Public JWK"
            value={outputs.publicJwk}
            filename="converted-public.jwk.json"
            setMessage={setMessage}
          />
          <OutputCard
            title="Converted JWK Set"
            value={outputs.jwksPair}
            filename="converted-jwks.json"
            setMessage={setMessage}
          />
          <OutputCard
            title="Converted JWK Set (Public only)"
            value={outputs.jwksPublic}
            filename="converted-jwks-public.json"
            setMessage={setMessage}
          />
          <OutputCard
            title="Converted Public Key (SPKI PEM)"
            value={outputs.publicPem}
            filename="converted-public.pem"
            setMessage={setMessage}
          />
          {outputs.privatePem && (
            <OutputCard
              title="Converted Private Key (PKCS#8 PEM)"
              value={outputs.privatePem}
              filename="converted-private.pem"
              setMessage={setMessage}
            />
          )}
        </section>
      )}

      {error && (
        <section className="card outputs-animated" style={{ marginTop: '12px' }}>
          <div className="validation-error">
            <div className="badge" style={{ 
              background: 'var(--badge-bg)', 
              color: '#ef4444',
              border: '1px solid #ef4444',
              marginBottom: '12px',
              display: 'inline-block'
            }}>
              ✗ Invalid PEM
            </div>
            <p className="muted">{error}</p>
          </div>
        </section>
      )}
    </>
  );
}

export default PemConverter;