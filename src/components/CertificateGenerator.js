import React, { useState } from 'react';
import OutputCard from './OutputCard';
import Spinner from './Spinner';

function CertificateGenerator({ availableKeys, setMessage, showToast }) {
  const [busy, setBusy] = useState(false);
  const [outputs, setOutputs] = useState(null);
  const [error, setError] = useState(null);
  
  // Certificate fields
  const [certFields, setCertFields] = useState({
    commonName: '',
    organization: '',
    organizationalUnit: '',
    country: '',
    state: '',
    locality: '',
    email: '',
    validityDays: 365,
    keySize: 2048,
    signatureAlgorithm: 'SHA256withRSA'
  });
  
  // SAN fields
  const [sanEntries, setSanEntries] = useState([
    { type: 'DNS', value: '' }
  ]);
  
  // Selected key for signing (optional - use existing key)
  const [selectedKeyId, setSelectedKeyId] = useState('generate-new');
  
  const handleFieldChange = (field, value) => {
    setCertFields(prev => ({
      ...prev,
      [field]: value
    }));
  };
  
  const addSanEntry = () => {
    setSanEntries(prev => [...prev, { type: 'DNS', value: '' }]);
  };
  
  const removeSanEntry = (index) => {
    setSanEntries(prev => prev.filter((_, i) => i !== index));
  };
  
  const updateSanEntry = (index, field, value) => {
    setSanEntries(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], [field]: value };
      return updated;
    });
  };
  
  const validateInputs = () => {
    if (!certFields.commonName.trim()) {
      setError('Common Name (CN) is required');
      return false;
    }
    
    if (certFields.country && certFields.country.length !== 2) {
      setError('Country code must be exactly 2 characters (e.g., US, GB, CA)');
      return false;
    }
    
    if (certFields.validityDays < 1 || certFields.validityDays > 3650) {
      setError('Validity period must be between 1 and 3650 days');
      return false;
    }
    
    // Validate SAN entries
    const validSans = sanEntries.filter(san => san.value.trim());
    for (const san of validSans) {
      if (san.type === 'IP') {
        // Basic IP validation
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/;
        if (!ipRegex.test(san.value)) {
          setError(`Invalid IP address: ${san.value}`);
          return false;
        }
      } else if (san.type === 'email') {
        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(san.value)) {
          setError(`Invalid email address: ${san.value}`);
          return false;
        }
      }
    }
    
    setError(null);
    return true;
  };
  
  const generateCertificate = async () => {
    if (!validateInputs()) return;
    
    setBusy(true);
    setError(null);
    setMessage('');
    
    try {
      // Note: Actual X.509 certificate generation requires a proper ASN.1 library
      // For now, we'll create a demonstration/placeholder implementation
      // In production, you'd use a library like node-forge or PKI.js
      
      const certInfo = {
        subject: {
          CN: certFields.commonName,
          O: certFields.organization,
          OU: certFields.organizationalUnit,
          C: certFields.country,
          ST: certFields.state,
          L: certFields.locality,
          emailAddress: certFields.email
        },
        issuer: {
          CN: certFields.commonName + ' (Self-Signed)',
          O: certFields.organization || 'Self-Signed Certificate',
        },
        validity: {
          notBefore: new Date().toISOString(),
          notAfter: new Date(Date.now() + certFields.validityDays * 24 * 60 * 60 * 1000).toISOString()
        },
        serialNumber: Array.from(crypto.getRandomValues(new Uint8Array(16)))
          .map(b => b.toString(16).padStart(2, '0'))
          .join(''),
        signatureAlgorithm: certFields.signatureAlgorithm,
        keySize: certFields.keySize,
        version: 3,
        extensions: {
          basicConstraints: {
            CA: false
          },
          keyUsage: [
            'digitalSignature',
            'keyEncipherment'
          ],
          extKeyUsage: [
            'serverAuth',
            'clientAuth'
          ],
          subjectAltName: sanEntries
            .filter(san => san.value.trim())
            .map(san => ({
              type: san.type,
              value: san.value.trim()
            }))
        }
      };
      
      // Generate or use existing key
      let privateKey, publicKey;
      
      if (selectedKeyId === 'generate-new') {
        // Generate new RSA key pair
        const keyPair = await crypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: certFields.keySize,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
          },
          true,
          ['sign', 'verify']
        );
        
        privateKey = keyPair.privateKey;
        publicKey = keyPair.publicKey;
      } else {
        // Use existing key from available keys
        const selectedKey = availableKeys.find(k => k.id === selectedKeyId);
        if (!selectedKey) {
          throw new Error('Selected key not found');
        }
        // Would need to import the key here
        // For now, this is a placeholder
        throw new Error('Using existing keys not yet implemented');
      }
      
      // Export keys to JWK format
      const privateJwk = await crypto.subtle.exportKey('jwk', privateKey);
      const publicJwk = await crypto.subtle.exportKey('jwk', publicKey);
      
      // Create certificate structure (simplified - real implementation needs ASN.1)
      const certificatePem = `-----BEGIN CERTIFICATE-----
${btoa(JSON.stringify(certInfo, null, 2))
  .match(/.{1,64}/g)
  .join('\n')}
-----END CERTIFICATE-----`;
      
      // Export private key to PKCS#8 PEM
      const privateKeyDer = await crypto.subtle.exportKey('pkcs8', privateKey);
      const privateKeyPem = `-----BEGIN PRIVATE KEY-----
${btoa(String.fromCharCode(...new Uint8Array(privateKeyDer)))
  .match(/.{1,64}/g)
  .join('\n')}
-----END PRIVATE KEY-----`;
      
      // Create certificate request (CSR)
      const csrInfo = {
        subject: certInfo.subject,
        publicKey: publicJwk,
        signatureAlgorithm: certFields.signatureAlgorithm,
        extensions: certInfo.extensions
      };
      
      const csrPem = `-----BEGIN CERTIFICATE REQUEST-----
${btoa(JSON.stringify(csrInfo, null, 2))
  .match(/.{1,64}/g)
  .join('\n')}
-----END CERTIFICATE REQUEST-----`;
      
      setOutputs({
        certificate: certificatePem,
        privateKey: privateKeyPem,
        csr: csrPem,
        certificateInfo: certInfo,
        privateJwk: JSON.stringify(privateJwk, null, 2),
        publicJwk: JSON.stringify(publicJwk, null, 2)
      });
      
      setMessage('Self-signed certificate generated successfully!');
      showToast('Certificate generated! Note: This is a demonstration. For production use, implement proper X.509 ASN.1 encoding.');
      
    } catch (err) {
      setError(err.message);
      setMessage('Failed to generate certificate');
    } finally {
      setBusy(false);
    }
  };
  
  const clearAll = () => {
    setOutputs(null);
    setError(null);
    setCertFields({
      commonName: '',
      organization: '',
      organizationalUnit: '',
      country: '',
      state: '',
      locality: '',
      email: '',
      validityDays: 365,
      keySize: 2048,
      signatureAlgorithm: 'SHA256withRSA'
    });
    setSanEntries([{ type: 'DNS', value: '' }]);
    setSelectedKeyId('generate-new');
  };
  
  return (
    <>
      <style>{`
        @media (max-width: 768px) {
          .certificate-generator {
            display: none !important;
          }
          .certificate-generator-mobile-message {
            display: block !important;
          }
        }
        @media (min-width: 769px) {
          .certificate-generator-mobile-message {
            display: none !important;
          }
        }
      `}</style>
      
      <div className="certificate-generator">
        <section className="card" style={{ marginTop: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <h2 style={{ margin: 0 }}>Self-Signed Certificate Generator</h2>
        </div>
        <p className="muted">
          Generate a self-signed X.509 certificate with custom subject fields and Subject Alternative Names (SAN).
          Perfect for development, testing, and internal use cases.
        </p>
        
        {/* Certificate Subject Fields */}
        <div className="space"></div>
        
        <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: '12px 16px', alignItems: 'center' }}>
          <label style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '4px'
          }}>
            Common Name (CN) *
          </label>
          <textarea
            value={certFields.commonName}
            onChange={(e) => handleFieldChange('commonName', e.target.value)}
            placeholder="example.com or Your Name"
            style={{ 
              minHeight: '38px',
              maxHeight: '38px',
              lineHeight: '20px',
              padding: '9px 8px',
              resize: 'none', 
              overflow: 'hidden',
              whiteSpace: 'nowrap',
              display: 'block',
              width: '100%'
            }}
          />
          
          <label>Organization (O)</label>
          <textarea
            value={certFields.organization}
            onChange={(e) => handleFieldChange('organization', e.target.value)}
            placeholder="ACME Corporation"
            style={{ 
              minHeight: '38px',
              maxHeight: '38px',
              lineHeight: '20px',
              padding: '9px 8px',
              resize: 'none', 
              overflow: 'hidden',
              whiteSpace: 'nowrap',
              display: 'block',
              width: '100%'
            }}
          />
          
          <label>Organizational Unit (OU)</label>
          <textarea
            value={certFields.organizationalUnit}
            onChange={(e) => handleFieldChange('organizationalUnit', e.target.value)}
            placeholder="IT Department"
            style={{ 
              minHeight: '38px',
              maxHeight: '38px',
              lineHeight: '20px',
              padding: '9px 8px',
              resize: 'none', 
              overflow: 'hidden',
              whiteSpace: 'nowrap',
              display: 'block',
              width: '100%'
            }}
          />
          
          <label>Country Code (C)</label>
          <textarea
            value={certFields.country}
            onChange={(e) => handleFieldChange('country', e.target.value.toUpperCase())}
            placeholder="US"
            maxLength="2"
            style={{ 
              minHeight: '38px',
              maxHeight: '38px',
              lineHeight: '20px',
              padding: '9px 8px',
              resize: 'none', 
              overflow: 'hidden',
              whiteSpace: 'nowrap',
              display: 'block',
              width: '100%'
            }}
          />
          
          <label>State/Province (ST)</label>
          <textarea
            value={certFields.state}
            onChange={(e) => handleFieldChange('state', e.target.value)}
            placeholder="California"
            style={{ 
              minHeight: '38px',
              maxHeight: '38px',
              lineHeight: '20px',
              padding: '9px 8px',
              resize: 'none', 
              overflow: 'hidden',
              whiteSpace: 'nowrap',
              display: 'block',
              width: '100%'
            }}
          />
          
          <label>Locality/City (L)</label>
          <textarea
            value={certFields.locality}
            onChange={(e) => handleFieldChange('locality', e.target.value)}
            placeholder="San Francisco"
            style={{ 
              minHeight: '38px',
              maxHeight: '38px',
              lineHeight: '20px',
              padding: '9px 8px',
              resize: 'none', 
              overflow: 'hidden',
              whiteSpace: 'nowrap',
              display: 'block',
              width: '100%'
            }}
          />
          
          <label>Email Address</label>
          <textarea
            value={certFields.email}
            onChange={(e) => handleFieldChange('email', e.target.value)}
            placeholder="admin@example.com"
            style={{ 
              minHeight: '38px',
              maxHeight: '38px',
              lineHeight: '20px',
              padding: '9px 8px',
              resize: 'none', 
              overflow: 'hidden',
              whiteSpace: 'nowrap',
              display: 'block',
              width: '100%'
            }}
          />
        </div>
        
        {/* SAN Editor */}
        <div className="space"></div>
        
        <div style={{ marginBottom: '12px' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '4px', marginTop: '8px' }}>
            Subject Alternative Names (SAN)
            <span style={{ fontSize: '12px', color: 'var(--muted)', fontWeight: 'normal', marginLeft: '8px' }}>
              Additional hostnames, IPs, and identifiers
            </span>
          </label>
          
          {sanEntries.map((san, index) => (
            <div key={index} style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '12px', marginTop: '8px' }}>
              <select
                value={san.type}
                onChange={(e) => updateSanEntry(index, 'type', e.target.value)}
                style={{ 
                  width: '140px',
                  height: '38px',
                  padding: '8px',
                  background: 'var(--input-bg)',
                  border: '1px solid var(--line)',
                  borderRadius: '6px',
                  color: 'var(--ink)',
                  fontSize: '13px'
                }}
              >
                <option value="DNS">DNS Name</option>
                <option value="IP">IP Address</option>
                <option value="email">Email</option>
                <option value="URI">URI</option>
              </select>
              
              <textarea
                value={san.value}
                onChange={(e) => updateSanEntry(index, 'value', e.target.value)}
                placeholder={
                  san.type === 'DNS' ? 'example.com, *.example.com, localhost' :
                  san.type === 'IP' ? '192.168.1.1 or 2001:db8::1' :
                  san.type === 'email' ? 'admin@example.com' :
                  'https://example.com/path'
                }
                style={{ 
                  flex: 1, 
                  minHeight: '38px',
                  maxHeight: '38px',
                  lineHeight: '20px',
                  padding: '9px 8px',
                  resize: 'none', 
                  overflow: 'hidden',
                  whiteSpace: 'nowrap',
                  display: 'block',
                  width: '100%'
                }}
              />
              
              {sanEntries.length > 1 && (
                <button
                  className="btn"
                  onClick={() => removeSanEntry(index)}
                  style={{ padding: '6px 12px', fontSize: '12px', height: '38px' }}
                >
                  Remove
                </button>
              )}
            </div>
          ))}
          
          <button
            className="btn"
            onClick={addSanEntry}
            style={{ marginTop: '4px' }}
          >
            + Add SAN Entry
          </button>
        </div>
        
        {/* Certificate Options */}
        <div className="space"></div>
        
        <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: '12px 16px', alignItems: 'center' }}>
          <label>Validity Period</label>
          <select
            value={certFields.validityDays}
            onChange={(e) => handleFieldChange('validityDays', parseInt(e.target.value))}
            style={{ 
              height: '38px',
              padding: '8px',
              background: 'var(--input-bg)',
              border: '1px solid var(--line)',
              borderRadius: '6px',
              color: 'var(--ink)',
              fontSize: '13px',
              width: '100%'
            }}
          >
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year (Default)</option>
            <option value="730">2 years</option>
            <option value="1095">3 years</option>
            <option value="3650">10 years (Development)</option>
          </select>
          
          <label>Key Size</label>
          <select
            value={certFields.keySize}
            onChange={(e) => handleFieldChange('keySize', parseInt(e.target.value))}
            style={{ 
              height: '38px',
              padding: '8px',
              background: 'var(--input-bg)',
              border: '1px solid var(--line)',
              borderRadius: '6px',
              color: 'var(--ink)',
              fontSize: '13px',
              width: '100%'
            }}
          >
            <option value="2048">2048 bits (Recommended)</option>
            <option value="3072">3072 bits</option>
            <option value="4096">4096 bits (High Security)</option>
          </select>
          
          <label>Signature Algorithm</label>
          <select
            value={certFields.signatureAlgorithm}
            onChange={(e) => handleFieldChange('signatureAlgorithm', e.target.value)}
            style={{ 
              height: '38px',
              padding: '8px',
              background: 'var(--input-bg)',
              border: '1px solid var(--line)',
              borderRadius: '6px',
              color: 'var(--ink)',
              fontSize: '13px',
              width: '100%'
            }}
          >
            <option value="SHA256withRSA">SHA256 with RSA (Recommended)</option>
            <option value="SHA384withRSA">SHA384 with RSA</option>
            <option value="SHA512withRSA">SHA512 with RSA</option>
          </select>
          
          {/* Key Selection */}
          {availableKeys && availableKeys.length > 0 && (
            <>
              <label>Signing Key</label>
              <select
              value={selectedKeyId}
              onChange={(e) => setSelectedKeyId(e.target.value)}
              style={{ 
                height: '38px',
                padding: '8px',
                background: 'var(--input-bg)',
                border: '1px solid var(--line)',
                borderRadius: '6px',
                color: 'var(--ink)',
                fontSize: '13px',
                width: '100%'
              }}
            >
              <option value="generate-new">Generate New Key Pair</option>
              {availableKeys.map(key => (
                <option key={key.id} value={key.id}>
                  Use: {key.label}
                </option>
              ))}
            </select>
            </>
          )}
        </div>
        
        {/* Actions */}
        <div className="space"></div>
        <div className="actions">
          <button
            className="btn primary"
            onClick={generateCertificate}
            disabled={busy}
          >
            {busy && <Spinner size={16} />}
            Generate Certificate
          </button>
          <button
            className="btn"
            onClick={clearAll}
          >
            Clear All
          </button>
        </div>
        
        {/* Error display */}
        {error && (
          <div className="validation-error" style={{ marginTop: '12px' }}>
            <div className="badge" style={{ 
              background: 'var(--badge-bg)', 
              color: '#ef4444',
              border: '1px solid #ef4444',
              marginBottom: '8px',
              display: 'inline-block'
            }}>
              ✗ Error
            </div>
            <p className="muted">{error}</p>
          </div>
        )}
      </section>
      
      {/* Outputs */}
      {outputs && (
        <>
          <section className="outputs grid grid-2 outputs-animated" style={{ marginTop: '12px' }}>
            <OutputCard
              title="Self-Signed Certificate"
              value={outputs.certificate}
              filename="certificate.crt"
              setMessage={setMessage}
              showToast={showToast}
            />
            <OutputCard
              title="Private Key (PKCS#8)"
              value={outputs.privateKey}
              filename="private-key.pem"
              setMessage={setMessage}
              showToast={showToast}
            />
            <OutputCard
              title="Certificate Signing Request (CSR)"
              value={outputs.csr}
              filename="certificate.csr"
              setMessage={setMessage}
              showToast={showToast}
            />
            <OutputCard
              title="Certificate Info (JSON)"
              value={JSON.stringify(outputs.certificateInfo, null, 2)}
              filename="certificate-info.json"
              setMessage={setMessage}
              showToast={showToast}
            />
            <OutputCard
              title="Private Key (JWK)"
              value={outputs.privateJwk}
              filename="private-key.jwk.json"
              setMessage={setMessage}
              showToast={showToast}
            />
            <OutputCard
              title="Public Key (JWK)"
              value={outputs.publicJwk}
              filename="public-key.jwk.json"
              setMessage={setMessage}
              showToast={showToast}
            />
          </section>
          
          <section className="card outputs-animated" style={{ marginTop: '12px' }}>
            <div style={{ 
              padding: '12px',
              background: '#f59e0b20',
              borderRadius: '8px',
              border: '1px solid #f59e0b'
            }}>
              <strong style={{ color: '#f59e0b' }}>⚠️ Important Note:</strong>
              <p style={{ margin: '8px 0 0 0', fontSize: '13px' }}>
                This is a demonstration implementation. The generated "certificate" is not a valid X.509 certificate.
                For production use, you would need to implement proper ASN.1 encoding using a library like Forge or PKI.js.
                The private key, however, is a valid cryptographic key that can be used with proper certificate generation tools.
              </p>
            </div>
          </section>
        </>
      )}
      </div>
      
      {/* Mobile Message */}
      <div className="certificate-generator-mobile-message">
        <section className="card">
          <div style={{ 
            padding: '20px',
            textAlign: 'center'
          }}>
            <h2 style={{ margin: '0 0 12px 0' }}>Certificate Generator</h2>
            <p className="muted">
              The certificate generator is not available on mobile devices due to the complexity of the form. 
              Please use a desktop or tablet to access this feature.
            </p>
          </div>
        </section>
      </div>
    </>
  );
}

export default CertificateGenerator;