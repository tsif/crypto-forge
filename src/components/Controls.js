import React from 'react';
import Spinner from './Spinner';

function Controls({
  algorithm,
  setAlgorithm,
  rsaBits,
  setRsaBits,
  rsaHash,
  setRsaHash,
  ecCurve,
  setEcCurve,
  keyUse,
  setKeyUse,
  alg,
  onGenerate,
  onClear,
  busy,
  message
}) {
  const isRSA = algorithm === 'RSA';

  return (
    <section className="controls card">
      <h2>Generate Keys</h2>
      <div className="controls-grid">
        <div className="field">
          <label htmlFor="kind">Algorithm</label>
          <select 
            id="kind" 
            value={algorithm} 
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            <option value="RSA">RSA</option>
            <option value="EC">EC (ECDSA)</option>
          </select>
        </div>

        {isRSA && (
          <>
            <div className="field">
              <label htmlFor="rsaBits">Modulus</label>
              <select 
                id="rsaBits" 
                value={rsaBits} 
                onChange={(e) => setRsaBits(e.target.value)}
              >
                <option value="2048">2048</option>
                <option value="3072">3072</option>
                <option value="4096">4096</option>
              </select>
            </div>

            <div className="field">
              <label htmlFor="rsaHash">Hash</label>
              <select 
                id="rsaHash" 
                value={rsaHash} 
                onChange={(e) => setRsaHash(e.target.value)}
              >
                <option>SHA-256</option>
                <option>SHA-384</option>
                <option>SHA-512</option>
              </select>
            </div>
          </>
        )}

        {!isRSA && (
          <div className="field">
            <label htmlFor="ecCurve">Curve</label>
            <select 
              id="ecCurve" 
              value={ecCurve} 
              onChange={(e) => setEcCurve(e.target.value)}
            >
              <option>P-256</option>
              <option>P-384</option>
              <option>P-521</option>
            </select>
          </div>
        )}

        <div className="field">
          <label htmlFor="keyUse">Key Use</label>
          <select 
            id="keyUse" 
            value={keyUse} 
            onChange={(e) => setKeyUse(e.target.value)}
          >
            <option value="sig">Signature (sig)</option>
            <option value="enc">Encryption (enc)</option>
          </select>
        </div>

        <div className="field">
          <label>alg</label>
          <div className="badge">{alg}</div>
        </div>
      </div>

      <div className="actions">
        <button 
          className="btn primary" 
          onClick={onGenerate} 
          disabled={busy}
        >
          {busy && <Spinner size={16} />}
          Generate keypair
        </button>
        <button 
          className="btn" 
          onClick={onClear}
        >
          Clear
        </button>
        <span className="muted">{message}</span>
      </div>
    </section>
  );
}

export default Controls;