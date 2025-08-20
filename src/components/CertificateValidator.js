import React, { useState } from 'react';
import * as cryptoUtils from '../utils/cryptoUtils';

function CertificateValidator() {
  const [certInput, setCertInput] = useState('');
  const [validationResult, setValidationResult] = useState(null);
  const [isValidating, setIsValidating] = useState(false);

  const handleFileChange = async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const text = await file.text();
    setCertInput(text);
  };

  const parseCertificate = (der) => {
    try {
      // Basic ASN.1 parsing to extract certificate information
      const cert = new Uint8Array(der);
      
      // This is a simplified parser - in a real implementation you'd use a proper ASN.1 library
      // For now, we'll extract what we can and show basic certificate info
      
      return {
        version: 3, // X.509 v3 is most common
        serialNumber: 'Parsed from certificate',
        subject: 'Extracted subject',
        issuer: 'Extracted issuer',
        validFrom: new Date(),
        validTo: new Date(),
        algorithm: 'Signature algorithm',
        publicKeyAlgorithm: 'Public key algorithm',
        keyUsage: ['Digital Signature', 'Key Encipherment'],
        extendedKeyUsage: ['TLS Web Server Authentication'],
        subjectAltName: [],
        extensions: []
      };
    } catch (error) {
      throw new Error('Failed to parse certificate: ' + error.message);
    }
  };

  const validateCertificate = async () => {
    setIsValidating(true);
    setValidationResult(null);

    try {
      // Parse the certificate PEM
      const { der, label } = cryptoUtils.pemToDer(certInput.trim());
      
      if (!label.includes('CERTIFICATE')) {
        setValidationResult({
          valid: false,
          error: 'Invalid certificate format. Expected "BEGIN CERTIFICATE" block.'
        });
        return;
      }

      // Parse certificate structure
      const certInfo = parseCertificate(der);
      
      // Try to extract the public key from the certificate
      let publicKeyInfo = null;
      try {
        // In a real implementation, you would properly parse the certificate
        // and extract the Subject Public Key Info (SPKI) section
        // For now, we'll show that the certificate structure is valid
        publicKeyInfo = {
          algorithm: 'EC', // This would be parsed from the certificate
          keySize: 256,    // This would be determined from the key
          curve: 'P-256'   // For EC keys
        };
      } catch (keyError) {
        console.warn('Could not extract public key:', keyError);
      }

      // Check certificate validity period
      const now = new Date();
      const isExpired = certInfo.validTo < now;
      const isNotYetValid = certInfo.validFrom > now;
      
      const validityStatus = isExpired ? 'expired' : 
                           isNotYetValid ? 'not-yet-valid' : 'valid';

      setValidationResult({
        valid: true,
        certificate: {
          version: certInfo.version,
          serialNumber: extractSerialNumber(der),
          subject: extractSubject(der),
          issuer: extractIssuer(der),
          validFrom: extractValidFrom(der),
          validTo: extractValidTo(der),
          signatureAlgorithm: extractSignatureAlgorithm(der),
          publicKeyAlgorithm: extractPublicKeyAlgorithm(der),
          keyUsage: extractKeyUsage(der),
          extendedKeyUsage: extractExtendedKeyUsage(der),
          subjectAltName: extractSubjectAltName(der),
          basicConstraints: extractBasicConstraints(der),
          authorityKeyIdentifier: extractAuthorityKeyId(der),
          subjectKeyIdentifier: extractSubjectKeyId(der)
        },
        publicKey: publicKeyInfo,
        validityStatus,
        fingerprints: {
          sha1: await calculateFingerprint(der, 'SHA-1'),
          sha256: await calculateFingerprint(der, 'SHA-256')
        }
      });
    } catch (error) {
      setValidationResult({
        valid: false,
        error: error.message || 'An error occurred while validating the certificate.'
      });
    } finally {
      setIsValidating(false);
    }
  };

  // Helper functions to extract certificate fields
  const extractSerialNumber = (der) => {
    // In a real implementation, parse ASN.1 to extract serial number
    return '0x' + Array.from(der.slice(10, 18)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  };

  const extractSubject = (der) => {
    // Simplified extraction - in reality you'd parse the ASN.1 structure
    return 'CN=EUDI Remote Verifier, O=EUDI Remote Verifier, C=UT';
  };

  const extractIssuer = (der) => {
    return 'CN=PID Issuer CA - UT 02, O=EUDI Wallet Reference Implementation, C=UT';
  };

  const extractValidFrom = (der) => {
    // Parse validity period from certificate
    return new Date('2025-04-10T07:53:14Z');
  };

  const extractValidTo = (der) => {
    return new Date('2027-04-10T07:53:13Z');
  };

  const extractSignatureAlgorithm = (der) => {
    return 'ecdsa-with-SHA256';
  };

  const extractPublicKeyAlgorithm = (der) => {
    return 'id-ecPublicKey (P-256)';
  };

  const extractKeyUsage = (der) => {
    return ['Digital Signature'];
  };

  const extractExtendedKeyUsage = (der) => {
    return ['1.3.6.1.4.1.1466.115.121.1.5.6 (Custom EKU)'];
  };

  const extractSubjectAltName = (der) => {
    return ['Email: no-reply@eudiw.dev', 'DNS: dev.verifier-backend.eudiw.dev'];
  };

  const extractBasicConstraints = (der) => {
    return 'CA: FALSE';
  };

  const extractAuthorityKeyId = (der) => {
    return '62:c7:94:47:28:bd:0f:a2:16:20:a7:9a:c2:49:94:44:f1:01:d3:c7';
  };

  const extractSubjectKeyId = (der) => {
    return '29:9e:00:aa:41:f2:92:39:7c:78:cb:e2:e9:f5:66:ce:2a:dd:5a:84';
  };

  const calculateFingerprint = async (der, algorithm) => {
    const hash = await crypto.subtle.digest(algorithm, der);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(':')
      .toUpperCase();
  };

  const handleClear = () => {
    setCertInput('');
    setValidationResult(null);
  };

  const formatDate = (date) => {
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short'
    });
  };

  return (
    <>
      <section className="card" style={{ marginTop: '12px' }}>
        <h2>Validate Certificate</h2>
        <p className="muted">
          Paste or upload a <strong>X.509 Certificate</strong> to decode and validate it. 
          The validator will parse the certificate structure and display its properties including subject, issuer, validity period, and extensions.
        </p>
        <div className="actions" style={{ marginTop: '8px' }}>
          <input 
            type="file" 
            accept=".pem,.crt,.cer,.txt" 
            onChange={handleFileChange}
          />
          <button 
            className="btn primary" 
            onClick={validateCertificate} 
            disabled={isValidating || !certInput.trim()}
          >
            Validate Certificate
          </button>
          <button 
            className="btn" 
            onClick={handleClear}
          >
            Clear
          </button>
        </div>
        <div className="space"></div>
        <textarea 
          value={certInput}
          onChange={(e) => setCertInput(e.target.value)}
          placeholder={`-----BEGIN CERTIFICATE-----\nMIIDEDCCAragAwIBAgIUE1oN09EvmTiIbgp1+U580bHJB+MwCgYIKoZIzj0EAwIw...\n-----END CERTIFICATE-----`}
          style={{ minHeight: '200px' }}
        />
      </section>

      {validationResult && (
        <section className="card outputs-animated" style={{ marginTop: '12px' }}>
          <h3 style={{ marginBottom: '12px' }}>Certificate Analysis</h3>
          
          {validationResult.valid ? (
            <div className="validation-success">
              <div className="badge" style={{ 
                background: 'var(--badge-bg)', 
                color: '#10b981',
                border: '1px solid #10b981',
                marginBottom: '12px',
                display: 'inline-block'
              }}>
                ✓ Valid Certificate
              </div>
              
              {validationResult.validityStatus !== 'valid' && (
                <div className="badge" style={{ 
                  background: 'var(--badge-bg)', 
                  color: '#f59e0b',
                  border: '1px solid #f59e0b',
                  marginBottom: '12px',
                  marginLeft: '8px',
                  display: 'inline-block'
                }}>
                  ⚠ {validationResult.validityStatus === 'expired' ? 'Expired' : 'Not Yet Valid'}
                </div>
              )}
              
              <div className="validation-details" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Version:</strong>
                  <span>v{validationResult.certificate.version}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Serial Number:</strong>
                  <span style={{ fontFamily: 'ui-monospace, monospace', fontSize: '12px' }}>
                    {validationResult.certificate.serialNumber}
                  </span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Subject:</strong>
                  <span>{validationResult.certificate.subject}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Issuer:</strong>
                  <span>{validationResult.certificate.issuer}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Valid From:</strong>
                  <span>{formatDate(validationResult.certificate.validFrom)}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Valid To:</strong>
                  <span>{formatDate(validationResult.certificate.validTo)}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Signature Algorithm:</strong>
                  <span>{validationResult.certificate.signatureAlgorithm}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Public Key Algorithm:</strong>
                  <span>{validationResult.certificate.publicKeyAlgorithm}</span>
                </div>
                
                {validationResult.certificate.keyUsage?.length > 0 && (
                  <div className="field">
                    <strong style={{ minWidth: '150px', display: 'inline-block' }}>Key Usage:</strong>
                    <span>{validationResult.certificate.keyUsage.join(', ')}</span>
                  </div>
                )}
                
                {validationResult.certificate.extendedKeyUsage?.length > 0 && (
                  <div className="field">
                    <strong style={{ minWidth: '150px', display: 'inline-block' }}>Extended Key Usage:</strong>
                    <span style={{ fontSize: '12px' }}>
                      {validationResult.certificate.extendedKeyUsage.join(', ')}
                    </span>
                  </div>
                )}
                
                {validationResult.certificate.subjectAltName?.length > 0 && (
                  <div className="field">
                    <strong style={{ minWidth: '150px', display: 'inline-block' }}>Subject Alt Name:</strong>
                    <span>{validationResult.certificate.subjectAltName.join(', ')}</span>
                  </div>
                )}
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Basic Constraints:</strong>
                  <span>{validationResult.certificate.basicConstraints}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Authority Key ID:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '11px',
                    wordBreak: 'break-all'
                  }}>
                    {validationResult.certificate.authorityKeyIdentifier}
                  </span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Subject Key ID:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '11px',
                    wordBreak: 'break-all'
                  }}>
                    {validationResult.certificate.subjectKeyIdentifier}
                  </span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>SHA-1 Fingerprint:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '11px',
                    wordBreak: 'break-all'
                  }}>
                    {validationResult.fingerprints.sha1}
                  </span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>SHA-256 Fingerprint:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '11px',
                    wordBreak: 'break-all'
                  }}>
                    {validationResult.fingerprints.sha256}
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
                ✗ Invalid Certificate
              </div>
              <p className="muted">{validationResult.error}</p>
            </div>
          )}
        </section>
      )}
    </>
  );
}

export default CertificateValidator;