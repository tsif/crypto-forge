import React, { useState } from 'react';

function CertificateChainViewer({ certificates = [] }) {
  const [expandedCerts, setExpandedCerts] = useState(new Set([0])); // Expand first cert by default
  
  if (!certificates || certificates.length === 0) {
    return null;
  }

  const toggleExpanded = (index) => {
    const newExpanded = new Set(expandedCerts);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedCerts(newExpanded);
  };

  const getCertificateLevel = (index) => {
    // Determine hierarchy level based on issuer/subject relationships
    if (index === 0) return 'leaf'; // End-entity certificate
    if (index === certificates.length - 1) return 'root'; // Root CA
    return 'intermediate'; // Intermediate CA
  };

  const getCertificateIcon = (level) => {
    // Using single-color geometric shapes instead of emojis
    switch (level) {
      case 'root':
        return '●'; // Root CA - solid circle
      case 'intermediate':
        return '◆'; // Intermediate CA - diamond
      case 'leaf':
        return '▲'; // End-entity/leaf certificate - triangle
      default:
        return '■'; // Square fallback
    }
  };

  const getCertificateColor = (level) => {
    switch (level) {
      case 'root':
        return '#10b981'; // Green for trusted root
      case 'intermediate':
        return '#3b82f6'; // Blue for intermediate
      case 'leaf':
        return '#8b5cf6'; // Purple for leaf
      default:
        return '#6b7280';
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return null;
    try {
      const date = new Date(dateStr);
      // Check if date is valid
      if (isNaN(date.getTime())) return null;
      return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric' 
      });
    } catch {
      return null;
    }
  };

  const getValidityStatus = (cert) => {
    // Return null if no validity information is available (don't show a badge)
    if (!cert.validity || !cert.validity.notBefore || !cert.validity.notAfter) {
      return null;
    }
    
    const now = new Date();
    const notBefore = new Date(cert.validity.notBefore);
    const notAfter = new Date(cert.validity.notAfter);
    
    if (now < notBefore) {
      return { status: 'Not Yet Valid', color: '#f59e0b' };
    } else if (now > notAfter) {
      return { status: 'Expired', color: '#ef4444' };
    } else {
      const daysRemaining = Math.floor((notAfter - now) / (1000 * 60 * 60 * 24));
      if (daysRemaining < 30) {
        return { status: `Expiring Soon (${daysRemaining} days)`, color: '#f59e0b' };
      }
      return { status: 'Valid', color: '#10b981' };
    }
  };

  const renderCertificateNode = (cert, index) => {
    const level = getCertificateLevel(index);
    const icon = getCertificateIcon(level);
    const color = getCertificateColor(level);
    const isExpanded = expandedCerts.has(index);
    const validity = getValidityStatus(cert);
    
    return (
      <div key={index} className="cert-node" style={{ marginLeft: `${index * 24}px` }}>
        {/* Simple vertical connection line for non-root certificates */}
        {index > 0 && (
          <div className="cert-connection" style={{
            position: 'absolute',
            left: `${index * 24 + 10}px`,
            top: '-20px',
            width: '2px',
            height: '20px',
            background: 'var(--line)'
          }} />
        )}
        
        {/* Certificate card */}
        <div 
          className="cert-card"
          style={{
            background: 'var(--input-bg)',
            border: `2px solid ${color}`,
            borderRadius: '12px',
            padding: '12px',
            marginBottom: '16px',
            position: 'relative',
            cursor: 'pointer',
            transition: 'all 0.2s ease'
          }}
          onClick={() => toggleExpanded(index)}
        >
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '20px', color: color, fontWeight: 'bold' }}>{icon}</span>
            <div style={{ flex: 1 }}>
              <div style={{ 
                fontWeight: '600', 
                fontSize: '14px',
                color: color,
                marginBottom: '4px'
              }}>
                {level === 'root' && 'Root CA'}
                {level === 'intermediate' && `Intermediate CA ${index}`}
                {level === 'leaf' && 'End-Entity Certificate'}
              </div>
              <div style={{ fontSize: '13px', color: 'var(--muted)' }}>
                {cert.subject?.CN || cert.subject?.O || cert.subject?.OU || 
                 cert.commonName || cert.organizationName || cert.organizationalUnitName ||
                 (cert.subject && typeof cert.subject === 'string' ? cert.subject : 'Certificate')}
              </div>
            </div>
            {validity && (
              <div style={{ 
                fontSize: '12px', 
                padding: '2px 8px',
                borderRadius: '4px',
                background: validity.color + '20',
                color: validity.color,
                fontWeight: '500'
              }}>
                {validity.status}
              </div>
            )}
            <div style={{
              transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
              transition: 'transform 0.2s ease',
              color: 'var(--muted)'
            }}>
              ▼
            </div>
          </div>

          {/* Expanded details */}
          {isExpanded && (
            <div style={{ 
              marginTop: '12px', 
              paddingTop: '12px', 
              borderTop: '1px solid var(--line)' 
            }}>
              <div style={{ display: 'grid', gap: '8px', fontSize: '12px' }}>
                {/* Subject */}
                <div>
                  <strong style={{ color: 'var(--muted)' }}>Subject:</strong>
                  <div style={{ marginLeft: '12px', marginTop: '4px' }}>
                    {/* Handle different subject formats */}
                    {cert.subject?.CN && <div>CN: {cert.subject.CN}</div>}
                    {cert.subject?.O && <div>O: {cert.subject.O}</div>}
                    {cert.subject?.OU && <div>OU: {cert.subject.OU}</div>}
                    {cert.subject?.C && <div>C: {cert.subject.C}</div>}
                    {cert.commonName && !cert.subject?.CN && <div>CN: {cert.commonName}</div>}
                    {cert.organizationName && !cert.subject?.O && <div>O: {cert.organizationName}</div>}
                    {cert.organizationalUnitName && !cert.subject?.OU && <div>OU: {cert.organizationalUnitName}</div>}
                    {cert.countryName && !cert.subject?.C && <div>C: {cert.countryName}</div>}
                    {/* If subject is a string, display it directly */}
                    {cert.subject && typeof cert.subject === 'string' && <div>{cert.subject}</div>}
                    {/* Fallback if no subject info found */}
                    {!cert.subject && !cert.commonName && !cert.organizationName && (
                      <div style={{ fontStyle: 'italic', color: 'var(--muted)' }}>No subject information available</div>
                    )}
                  </div>
                </div>

                {/* Issuer */}
                <div>
                  <strong style={{ color: 'var(--muted)' }}>Issuer:</strong>
                  <div style={{ marginLeft: '12px', marginTop: '4px' }}>
                    {cert.issuer?.CN && <div>CN: {cert.issuer.CN}</div>}
                    {cert.issuer?.O && <div>O: {cert.issuer.O}</div>}
                    {cert.issuer?.OU && <div>OU: {cert.issuer.OU}</div>}
                    {cert.issuer?.C && <div>C: {cert.issuer.C}</div>}
                    {cert.issuerName && !cert.issuer?.CN && <div>CN: {cert.issuerName}</div>}
                    {cert.issuer && typeof cert.issuer === 'string' && <div>{cert.issuer}</div>}
                    {!cert.issuer && !cert.issuerName && (
                      <div style={{ fontStyle: 'italic', color: 'var(--muted)' }}>No issuer information available</div>
                    )}
                  </div>
                </div>

                {/* Validity Period - only show if we have valid dates */}
                {(formatDate(cert.validity?.notBefore) || formatDate(cert.validity?.notAfter)) && (
                  <div>
                    <strong style={{ color: 'var(--muted)' }}>Validity Period:</strong>
                    <div style={{ marginLeft: '12px', marginTop: '4px' }}>
                      {formatDate(cert.validity?.notBefore) && (
                        <div>Not Before: {formatDate(cert.validity?.notBefore)}</div>
                      )}
                      {formatDate(cert.validity?.notAfter) && (
                        <div>Not After: {formatDate(cert.validity?.notAfter)}</div>
                      )}
                    </div>
                  </div>
                )}

                {/* Key Info */}
                {cert.publicKey && (
                  <div>
                    <strong style={{ color: 'var(--muted)' }}>Public Key:</strong>
                    <div style={{ marginLeft: '12px', marginTop: '4px' }}>
                      <div>Algorithm: {cert.publicKey.algorithm || 'Unknown'}</div>
                      {cert.publicKey.keySize && <div>Key Size: {cert.publicKey.keySize} bits</div>}
                      {cert.publicKey.curve && <div>Curve: {cert.publicKey.curve}</div>}
                    </div>
                  </div>
                )}

                {/* Serial Number */}
                {cert.serialNumber && (
                  <div>
                    <strong style={{ color: 'var(--muted)' }}>Serial Number:</strong>
                    <div style={{ 
                      marginLeft: '12px', 
                      marginTop: '4px',
                      fontFamily: 'monospace',
                      fontSize: '11px',
                      wordBreak: 'break-all'
                    }}>
                      {cert.serialNumber}
                    </div>
                  </div>
                )}

                {/* Signature Algorithm */}
                {cert.signatureAlgorithm && (
                  <div>
                    <strong style={{ color: 'var(--muted)' }}>Signature Algorithm:</strong>
                    <div style={{ marginLeft: '12px', marginTop: '4px' }}>
                      {cert.signatureAlgorithm}
                    </div>
                  </div>
                )}

                {/* Key Usages */}
                {cert.keyUsage && cert.keyUsage.length > 0 && (
                  <div>
                    <strong style={{ color: 'var(--muted)' }}>Key Usage:</strong>
                    <div style={{ marginLeft: '12px', marginTop: '4px' }}>
                      {cert.keyUsage.join(', ')}
                    </div>
                  </div>
                )}

                {/* Extended Key Usage */}
                {cert.extKeyUsage && cert.extKeyUsage.length > 0 && (
                  <div>
                    <strong style={{ color: 'var(--muted)' }}>Extended Key Usage:</strong>
                    <div style={{ marginLeft: '12px', marginTop: '4px' }}>
                      {cert.extKeyUsage.map(usage => {
                        // Map OIDs to human-readable names
                        const usageNames = {
                          '1.3.6.1.5.5.7.3.1': 'Server Authentication',
                          '1.3.6.1.5.5.7.3.2': 'Client Authentication',
                          '1.3.6.1.5.5.7.3.3': 'Code Signing',
                          '1.3.6.1.5.5.7.3.4': 'Email Protection',
                          '1.3.6.1.5.5.7.3.8': 'Time Stamping'
                        };
                        return usageNames[usage] || usage;
                      }).join(', ')}
                    </div>
                  </div>
                )}

                {/* SAN */}
                {cert.san && cert.san.length > 0 && (
                  <div>
                    <strong style={{ color: 'var(--muted)' }}>Subject Alternative Names:</strong>
                    <div style={{ 
                      marginLeft: '12px', 
                      marginTop: '4px',
                      maxHeight: '60px',
                      overflowY: 'auto'
                    }}>
                      {cert.san.join(', ')}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="certificate-chain-viewer">
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        gap: '8px',
        marginBottom: '16px'
      }}>
        <h3 style={{ margin: 0 }}>Certificate Chain Visualization</h3>
        <span style={{ 
          fontSize: '12px', 
          color: 'var(--muted)',
          background: 'var(--input-bg)',
          padding: '2px 8px',
          borderRadius: '4px'
        }}>
          {certificates.length} {certificates.length === 1 ? 'certificate' : 'certificates'}
        </span>
      </div>

      <div style={{ 
        background: 'var(--card)',
        borderRadius: '12px',
        padding: '20px',
        position: 'relative'
      }}>
        {/* Legend */}
        <div style={{ 
          display: 'flex', 
          gap: '16px',
          marginBottom: '20px',
          fontSize: '12px',
          flexWrap: 'wrap'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ color: '#8b5cf6', fontWeight: 'bold' }}>▲</span>
            <span style={{ color: '#8b5cf6' }}>End-Entity</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ color: '#3b82f6', fontWeight: 'bold' }}>◆</span>
            <span style={{ color: '#3b82f6' }}>Intermediate CA</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ color: '#10b981', fontWeight: 'bold' }}>●</span>
            <span style={{ color: '#10b981' }}>Root CA</span>
          </div>
        </div>

        {/* Certificate chain */}
        <div style={{ position: 'relative' }}>
          {certificates.map((cert, index) => renderCertificateNode(cert, index))}
        </div>

        {/* Trust indicator */}
        {certificates.length > 0 && (
          <div style={{
            marginTop: '20px',
            padding: '12px',
            background: 'var(--input-bg)',
            borderRadius: '8px',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <span style={{ color: 'var(--muted)', fontWeight: 'bold' }}>●</span>
            <span style={{ color: 'var(--muted)' }}>
              Click on certificates to expand/collapse details. 
              Chain validation shows the trust path from end-entity to root CA.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

export default CertificateChainViewer;