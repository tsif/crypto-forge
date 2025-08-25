import React, { useState } from 'react';
import * as cryptoUtils from '../utils/cryptoUtils';
import Spinner from './Spinner';
import { ASN1Parser, parseOid, parseTime, parseString, parseInteger, parseBitString, parseDN } from '../utils/asn1Parser';
import { CertificateChainValidator } from '../utils/certChainValidator';
import CertificateChainViewer from './CertificateChainViewer';

function CertificateValidator({ certInput = '', setCertInput, validationResult = null, setValidationResult }) {
  // Use props if provided, otherwise fall back to local state for backward compatibility
  const [localCertInput, setLocalCertInput] = useState('');
  const [localValidationResult, setLocalValidationResult] = useState(null);
  
  const input = setCertInput ? certInput : localCertInput;
  const setInput = setCertInput || setLocalCertInput;
  const result = setValidationResult ? validationResult : localValidationResult;
  const setResult = setValidationResult || setLocalValidationResult;
  
  const [isValidating, setIsValidating] = useState(false);
  const [inputError, setInputError] = useState(null);

  const validateCertInput = (input) => {
    if (!input.trim()) {
      setInputError(null);
      return;
    }

    const trimmed = input.trim();
    const hasBegin = /-----BEGIN CERTIFICATE-----/.test(trimmed);
    const hasEnd = /-----END CERTIFICATE-----/.test(trimmed);
    
    if (!hasBegin && !hasEnd) {
      setInputError('Certificate must be in PEM format with "-----BEGIN CERTIFICATE-----" header');
      return;
    }
    
    if (!hasBegin) {
      setInputError('Missing certificate header (-----BEGIN CERTIFICATE-----)');
      return;
    }
    
    if (!hasEnd) {
      setInputError('Missing certificate footer (-----END CERTIFICATE-----)');
      return;
    }

    setInputError(null);
  };

  const handleInputChange = (e) => {
    const value = e.target.value;
    setInput(value);
    validateCertInput(value);
  };

  const handleFileChange = async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const text = await file.text();
    setInput(text);
    validateCertInput(text);
  };

  const parseCertificate = (der) => {
    try {
      const parser = new ASN1Parser(der);
      const cert = parser.parseObject();
      
      if (!cert.isSequence()) {
        throw new Error('Certificate must be a SEQUENCE');
      }
      
      const certChildren = parser.parseSequence(cert);
      if (certChildren.length < 3) {
        throw new Error('Invalid certificate structure');
      }
      
      const tbsCertificate = certChildren[0]; // TBSCertificate
      const signatureAlgorithm = certChildren[1]; // AlgorithmIdentifier
      // const signatureValue = certChildren[2]; // BIT STRING - unused but part of cert structure
      
      // Parse TBSCertificate
      const tbsParser = new ASN1Parser(tbsCertificate.content);
      const tbsChildren = tbsParser.parseAll();
      
      let tbsIndex = 0;
      
      // Version (optional, default v1)
      let version = 1;
      if (tbsChildren[tbsIndex] && tbsChildren[tbsIndex].isContext(0)) {
        const versionParser = new ASN1Parser(tbsChildren[tbsIndex].content);
        const versionObj = versionParser.parseObject();
        if (versionObj.isInteger()) {
          version = parseInteger(versionObj.content) + 1; // ASN.1 is 0-based
        }
        tbsIndex++;
      }
      
      // Serial Number
      const serialNumberObj = tbsChildren[tbsIndex++];
      let serialNumber = 'Unknown';
      if (serialNumberObj && serialNumberObj.isInteger()) {
        serialNumber = '0x' + Array.from(serialNumberObj.content)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('').toUpperCase();
      }
      
      // Signature Algorithm (skip for now)
      tbsIndex++;
      
      // Issuer
      const issuerObj = tbsChildren[tbsIndex++];
      let issuer = 'Unknown Issuer';
      if (issuerObj && issuerObj.isSequence()) {
        issuer = parseDN(issuerObj);
      }
      
      // Validity
      const validityObj = tbsChildren[tbsIndex++];
      let validFrom = new Date();
      let validTo = new Date();
      if (validityObj && validityObj.isSequence()) {
        const validityParser = new ASN1Parser(validityObj.content);
        const validityChildren = validityParser.parseAll();
        if (validityChildren.length >= 2) {
          const notBefore = validityChildren[0];
          const notAfter = validityChildren[1];
          
          if (notBefore.isUtcTime()) {
            validFrom = parseTime(notBefore.content, false);
          } else if (notBefore.isGeneralizedTime()) {
            validFrom = parseTime(notBefore.content, true);
          }
          
          if (notAfter.isUtcTime()) {
            validTo = parseTime(notAfter.content, false);
          } else if (notAfter.isGeneralizedTime()) {
            validTo = parseTime(notAfter.content, true);
          }
        }
      }
      
      // Subject
      const subjectObj = tbsChildren[tbsIndex++];
      let subject = 'Unknown Subject';
      if (subjectObj && subjectObj.isSequence()) {
        subject = parseDN(subjectObj);
      }
      
      // Subject Public Key Info
      const spkiObj = tbsChildren[tbsIndex++];
      let publicKeyAlgorithm = 'Unknown';
      if (spkiObj && spkiObj.isSequence()) {
        const spkiParser = new ASN1Parser(spkiObj.content);
        const spkiChildren = spkiParser.parseAll();
        if (spkiChildren.length >= 1) {
          const algObj = spkiChildren[0];
          if (algObj.isSequence()) {
            const algParser = new ASN1Parser(algObj.content);
            const oidObj = algParser.parseObject();
            if (oidObj.isOid()) {
              publicKeyAlgorithm = parseOid(oidObj.content);
            }
          }
        }
      }
      
      // Extensions (optional)
      let keyUsage = [];
      let extendedKeyUsage = [];
      let subjectAltName = [];
      let basicConstraints = 'N/A';
      let authorityKeyId = 'N/A';
      let subjectKeyId = 'N/A';
      
      if (tbsIndex < tbsChildren.length && tbsChildren[tbsIndex].isContext(3)) {
        const extensionsObj = tbsChildren[tbsIndex];
        const extensionsParser = new ASN1Parser(extensionsObj.content);
        const extensionsSeq = extensionsParser.parseObject();
        
        if (extensionsSeq.isSequence()) {
          const extensionsSeqParser = new ASN1Parser(extensionsSeq.content);
          const extensions = extensionsSeqParser.parseAll();
          
          for (const ext of extensions) {
            if (ext.isSequence()) {
              const extParser = new ASN1Parser(ext.content);
              const extChildren = extParser.parseAll();
              
              if (extChildren.length >= 2) {
                const oidObj = extChildren[0];
                let critical = false;
                let valueObj;
                
                if (extChildren.length === 3) {
                  // critical = extChildren[1].tag.tagNumber === 1; // BOOLEAN - unused but parsed
                  valueObj = extChildren[2];
                } else {
                  valueObj = extChildren[1];
                }
                
                if (oidObj.isOid() && valueObj.isOctetString()) {
                  const oid = parseOid(oidObj.content);
                  
                  switch (oid) {
                    default:
                      // Handle unknown extensions
                      break;
                    case 'keyUsage':
                      // Parse key usage bit string
                      const kuParser = new ASN1Parser(valueObj.content);
                      const kuBitString = kuParser.parseObject();
                      if (kuBitString.isBitString()) {
                        const bits = parseBitString(kuBitString.content);
                        if (bits.length > 0) {
                          const usages = [];
                          const kuNames = [
                            'Digital Signature', 'Non Repudiation', 'Key Encipherment',
                            'Data Encipherment', 'Key Agreement', 'Key Cert Sign',
                            'CRL Sign', 'Encipher Only', 'Decipher Only'
                          ];
                          for (let i = 0; i < Math.min(9, bits.length * 8); i++) {
                            const byteIndex = Math.floor(i / 8);
                            const bitIndex = 7 - (i % 8);
                            if (bits[byteIndex] & (1 << bitIndex)) {
                              usages.push(kuNames[i]);
                            }
                          }
                          keyUsage = usages;
                        }
                      }
                      break;
                    case 'subjectAltName':
                      // Parse subject alt name
                      const sanParser = new ASN1Parser(valueObj.content);
                      const sanSeq = sanParser.parseObject();
                      if (sanSeq.isSequence()) {
                        const sanSeqParser = new ASN1Parser(sanSeq.content);
                        const sanItems = sanSeqParser.parseAll();
                        const altNames = [];
                        for (const item of sanItems) {
                          if (item.tag.tagClass === 2) { // Context-specific
                            const value = parseString(item.content);
                            const typeNames = ['', 'Email', 'DNS', 'x400', 'DN', 'EDI', 'URI', 'IP', 'RegID'];
                            const typeName = typeNames[item.tag.tagNumber] || `Type${item.tag.tagNumber}`;
                            altNames.push(`${typeName}: ${value}`);
                          }
                        }
                        subjectAltName = altNames;
                      }
                      break;
                    case 'basicConstraints':
                      const bcParser = new ASN1Parser(valueObj.content);
                      const bcSeq = bcParser.parseObject();
                      if (bcSeq.isSequence()) {
                        const bcSeqParser = new ASN1Parser(bcSeq.content);
                        const bcChildren = bcSeqParser.parseAll();
                        let isCA = false;
                        if (bcChildren.length > 0 && bcChildren[0].tag.tagNumber === 1) {
                          isCA = bcChildren[0].content[0] !== 0;
                        }
                        basicConstraints = isCA ? 'CA: TRUE' : 'CA: FALSE';
                      }
                      break;
                  }
                }
              }
            }
          }
        }
      }
      
      // Parse signature algorithm
      let signatureAlgorithmName = 'Unknown';
      if (signatureAlgorithm.isSequence()) {
        const sigAlgParser = new ASN1Parser(signatureAlgorithm.content);
        const sigOidObj = sigAlgParser.parseObject();
        if (sigOidObj.isOid()) {
          signatureAlgorithmName = parseOid(sigOidObj.content);
        }
      }
      
      return {
        version,
        serialNumber,
        subject,
        issuer,
        validFrom,
        validTo,
        signatureAlgorithm: signatureAlgorithmName,
        publicKeyAlgorithm,
        keyUsage,
        extendedKeyUsage,
        subjectAltName,
        basicConstraints,
        authorityKeyIdentifier: authorityKeyId,
        subjectKeyIdentifier: subjectKeyId
      };
    } catch (error) {
      throw new Error('Failed to parse certificate: ' + error.message);
    }
  };

  const validateCertificate = async () => {
    setIsValidating(true);
    setResult(null);

    try {
      const inputText = input.trim();
      
      // Check if this is a certificate chain (multiple certificates)
      const certBlocks = inputText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      
      if (!certBlocks || certBlocks.length === 0) {
        setResult({
          valid: false,
          error: 'Invalid certificate format. Expected "BEGIN CERTIFICATE" block.'
        });
        return;
      }

      if (certBlocks.length > 1) {
        // Handle certificate chain
        const chainValidator = new CertificateChainValidator();
        const certificates = chainValidator.parseCertificateChain(inputText);
        const chainValidation = chainValidator.validateChain();
        
        // Determine overall chain validity status based on all certificates
        let overallValidityStatus = 'valid';
        const now = new Date();
        
        for (const cert of certificates.filter(c => !c.error)) {
          if (cert.validTo && cert.validTo < now) {
            overallValidityStatus = 'expired';
            break;
          } else if (cert.validFrom && cert.validFrom > now) {
            overallValidityStatus = 'not-yet-valid';
            break;
          }
        }
        
        setResult({
          valid: chainValidation.valid,
          isChain: true,
          chainValidation,
          certificates,
          validityStatus: overallValidityStatus,
          fingerprints: certificates.length > 0 && certificates[0].der ? {
            sha1: await calculateFingerprint(certificates[0].der, 'SHA-1'),
            sha256: await calculateFingerprint(certificates[0].der, 'SHA-256')
          } : null
        });
        return;
      }

      // Single certificate validation (existing logic)
      const { der, label } = cryptoUtils.pemToDer(inputText);
      
      if (!label.includes('CERTIFICATE')) {
        setResult({
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

      setResult({
        valid: true,
        isChain: false,
        certificate: certInfo,
        publicKey: publicKeyInfo,
        validityStatus,
        fingerprints: {
          sha1: await calculateFingerprint(der, 'SHA-1'),
          sha256: await calculateFingerprint(der, 'SHA-256')
        }
      });
    } catch (error) {
      setResult({
        valid: false,
        error: error.message || 'An error occurred while validating the certificate.'
      });
    } finally {
      setIsValidating(false);
    }
  };


  const calculateFingerprint = async (der, algorithm) => {
    const hash = await crypto.subtle.digest(algorithm, der);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(':')
      .toUpperCase();
  };

  const handleClear = () => {
    setInput('');
    setResult(null);
    setInputError(null);
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
          Paste or upload <strong>X.509 Certificate(s)</strong> to decode and validate. 
          Supports single certificates or certificate chains. The validator will parse certificate structure and perform basic chain validation.
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
            disabled={isValidating || !input.trim()}
          >
            {isValidating && <Spinner size={16} />}
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
        <div className={`field ${inputError ? 'field-error' : (input.trim() && !inputError ? 'field-success' : '')}`}>
          <textarea 
            value={input}
            onChange={handleInputChange}
            placeholder={`-----BEGIN CERTIFICATE-----\nMIIDEDCCAragAwIBAgIUE1oN09EvmTiIbgp1+U580bHJB+MwCgYIKoZIzj0EAwIw...\n-----END CERTIFICATE-----`}
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
          <h3 style={{ marginBottom: '12px' }}>
            {result.isChain ? 'Certificate Chain Analysis' : 'Certificate Analysis'}
          </h3>
          
          {result.valid ? (
            <div className="validation-success">
              <div className="badge" style={{ 
                background: 'var(--badge-bg)', 
                color: '#10b981',
                border: '1px solid #10b981',
                marginBottom: '12px',
                display: 'inline-block'
              }}>
                ✓ {result.isChain ? 'Valid Certificate Chain' : 'Valid Certificate'}
              </div>
              
              {result.validityStatus !== 'valid' && (
                <div className="badge" style={{ 
                  background: 'var(--badge-bg)', 
                  color: '#f59e0b',
                  border: '1px solid #f59e0b',
                  marginBottom: '12px',
                  marginLeft: '8px',
                  display: 'inline-block'
                }}>
                  ⚠ {result.validityStatus === 'expired' ? 'Expired' : 'Not Yet Valid'}
                </div>
              )}
              
              {result.isChain ? (
                /* Certificate Chain Display */
                <div>
                  {/* Chain Summary */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '12px', marginBottom: '16px' }}>
                    <div style={{ textAlign: 'center', background: 'var(--input-bg)', padding: '8px', borderRadius: '6px' }}>
                      <div style={{ fontSize: '18px', fontWeight: '600', color: 'var(--ink)' }}>{result.chainValidation.chainLength}</div>
                      <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Total Certificates</div>
                    </div>
                    <div style={{ textAlign: 'center', background: 'var(--input-bg)', padding: '8px', borderRadius: '6px' }}>
                      <div style={{ fontSize: '18px', fontWeight: '600', color: '#10b981' }}>{result.chainValidation.validCertificates}</div>
                      <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Valid</div>
                    </div>
                    <div style={{ textAlign: 'center', background: 'var(--input-bg)', padding: '8px', borderRadius: '6px' }}>
                      <div style={{ fontSize: '18px', fontWeight: '600', color: result.chainValidation.invalidCertificates > 0 ? '#ef4444' : 'var(--muted)' }}>{result.chainValidation.invalidCertificates}</div>
                      <div style={{ fontSize: '12px', color: 'var(--muted)' }}>Invalid</div>
                    </div>
                  </div>

                  {/* Chain Issues */}
                  {result.chainValidation.issues.length > 0 && (
                    <div style={{ marginBottom: '12px' }}>
                      <h4 style={{ color: '#ef4444', fontSize: '14px', margin: '0 0 8px 0' }}>Chain Issues</h4>
                      {result.chainValidation.issues.map((issue, index) => (
                        <div key={index} style={{ 
                          color: '#ef4444', 
                          marginBottom: '4px',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '4px',
                          fontSize: '12px'
                        }}>
                          <span style={{ minWidth: '12px' }}>●</span>
                          <span>{issue}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Chain Warnings */}
                  {result.chainValidation.warnings.length > 0 && (
                    <div style={{ marginBottom: '12px' }}>
                      <h4 style={{ color: '#f59e0b', fontSize: '14px', margin: '0 0 8px 0' }}>Chain Warnings</h4>
                      {result.chainValidation.warnings.map((warning, index) => (
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

                  {/* Certificate Chain Visualization */}
                  <div style={{ marginBottom: '24px' }}>
                    <CertificateChainViewer certificates={result.certificates.filter(cert => !cert.error)} />
                  </div>

                  {/* Individual Certificates */}
                  <div>
                    <h4 style={{ fontSize: '14px', margin: '16px 0 8px 0' }}>Certificate Details</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {result.certificates.map((cert, index) => (
                        <div key={index} style={{ 
                          background: 'var(--input-bg)', 
                          border: `1px solid ${cert.error ? '#ef4444' : '#10b981'}`,
                          borderRadius: '6px', 
                          padding: '8px',
                          fontSize: '12px'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                            <span style={{ fontWeight: '600' }}>
                              Certificate {index + 1}
                              {cert.basicConstraints === 'CA: TRUE' && cert.subject === cert.issuer && ' (Root CA)'}
                              {cert.basicConstraints === 'CA: TRUE' && cert.subject !== cert.issuer && ' (Intermediate CA)'}
                              {cert.basicConstraints === 'CA: FALSE' && ' (End Entity)'}
                            </span>
                            <span style={{ 
                              color: cert.error ? '#ef4444' : '#10b981',
                              fontSize: '11px',
                              fontWeight: '500'
                            }}>
                              {cert.error ? '✗ Invalid' : '✓ Valid'}
                            </span>
                          </div>
                          {cert.error ? (
                            <div style={{ color: '#ef4444' }}>{cert.error}</div>
                          ) : (
                            <>
                              <div style={{ color: 'var(--muted)', marginBottom: '2px' }}>
                                Subject: {cert.subject}
                              </div>
                              <div style={{ color: 'var(--muted)', marginBottom: '2px' }}>
                                Issuer: {cert.issuer}
                              </div>
                              <div style={{ color: 'var(--muted)' }}>
                                Valid: {cert.validFrom?.toLocaleDateString()} - {cert.validTo?.toLocaleDateString()}
                              </div>
                            </>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                /* Single Certificate Display */
                <>
                  {/* Single Certificate Visualization */}
                  <div style={{ marginBottom: '24px' }}>
                    <CertificateChainViewer certificates={[result.certificate]} />
                  </div>
                  
                  <div className="validation-details" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div className="field">
                    <strong style={{ minWidth: '150px', display: 'inline-block' }}>Version:</strong>
                    <span>v{result.certificate.version}</span>
                  </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Serial Number:</strong>
                  <span style={{ fontFamily: 'ui-monospace, monospace', fontSize: '12px' }}>
                    {result.certificate.serialNumber}
                  </span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Subject:</strong>
                  <span>{result.certificate.subject}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Issuer:</strong>
                  <span>{result.certificate.issuer}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Valid From:</strong>
                  <span>{formatDate(result.certificate.validFrom)}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Valid To:</strong>
                  <span>{formatDate(result.certificate.validTo)}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Signature Algorithm:</strong>
                  <span>{result.certificate.signatureAlgorithm}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Public Key Algorithm:</strong>
                  <span>{result.certificate.publicKeyAlgorithm}</span>
                </div>
                
                {result.certificate.keyUsage?.length > 0 && (
                  <div className="field">
                    <strong style={{ minWidth: '150px', display: 'inline-block' }}>Key Usage:</strong>
                    <span>{result.certificate.keyUsage.join(', ')}</span>
                  </div>
                )}
                
                {result.certificate.extendedKeyUsage?.length > 0 && (
                  <div className="field">
                    <strong style={{ minWidth: '150px', display: 'inline-block' }}>Extended Key Usage:</strong>
                    <span style={{ fontSize: '12px' }}>
                      {result.certificate.extendedKeyUsage.join(', ')}
                    </span>
                  </div>
                )}
                
                {result.certificate.subjectAltName?.length > 0 && (
                  <div className="field">
                    <strong style={{ minWidth: '150px', display: 'inline-block' }}>Subject Alt Name:</strong>
                    <span>{result.certificate.subjectAltName.join(', ')}</span>
                  </div>
                )}
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Basic Constraints:</strong>
                  <span>{result.certificate.basicConstraints}</span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Authority Key ID:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '11px',
                    wordBreak: 'break-all'
                  }}>
                    {result.certificate.authorityKeyIdentifier}
                  </span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>Subject Key ID:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '11px',
                    wordBreak: 'break-all'
                  }}>
                    {result.certificate.subjectKeyIdentifier}
                  </span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>SHA-1 Fingerprint:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '11px',
                    wordBreak: 'break-all'
                  }}>
                    {result.fingerprints.sha1}
                  </span>
                </div>
                
                <div className="field">
                  <strong style={{ minWidth: '150px', display: 'inline-block' }}>SHA-256 Fingerprint:</strong>
                  <span style={{ 
                    fontFamily: 'ui-monospace, monospace', 
                    fontSize: '11px',
                    wordBreak: 'break-all'
                  }}>
                    {result.fingerprints.sha256}
                  </span>
                </div>
                </div>
                </>
              )}
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
              <p className="muted">{result.error}</p>
            </div>
          )}
        </section>
      )}
    </>
  );
}

export default CertificateValidator;