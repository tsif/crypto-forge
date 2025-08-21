import React from 'react';

function CommonMistakesWarning({ algorithm, keyUse, rsaBits, curve, context = 'generation' }) {
  const warnings = [];
  const tips = [];

  // Check for common mistakes based on parameters
  if (context === 'generation') {
    // RSA key size warnings
    if (algorithm === 'RSA') {
      if (parseInt(rsaBits) < 2048) {
        warnings.push({
          type: 'security',
          title: 'Weak RSA Key Size',
          message: `${rsaBits}-bit RSA keys are vulnerable to attack. Use at least 2048-bit for new systems.`,
          severity: 'high'
        });
      } else if (parseInt(rsaBits) === 2048) {
        tips.push({
          type: 'recommendation',
          title: 'Consider Stronger RSA Key',
          message: 'For long-term security, consider 3072-bit or 4096-bit RSA keys.'
        });
      }
    }

    // EC curve warnings
    if (algorithm === 'EC') {
      if (curve === 'secp256k1') {
        tips.push({
          type: 'info',
          title: 'Non-Standard Curve',
          message: 'secp256k1 is mainly used in Bitcoin. For general use, P-256 is more widely supported.'
        });
      }
    }

    // Key usage context warnings
    if (keyUse === 'enc') {
      tips.push({
        type: 'security',
        title: 'Encryption Key Usage',
        message: 'Never use encryption keys for signing operations. Generate separate keys for different purposes.'
      });
    }
  }

  // JWT-specific warnings
  if (context === 'jwt') {
    warnings.push({
      type: 'security',
      title: 'JWT Security Checklist',
      message: 'Always verify signatures, check expiration times, and use strong algorithms (RS256/ES256).',
      severity: 'medium'
    });

    tips.push({
      type: 'best-practice',
      title: 'JWT Best Practices',
      message: 'Keep JWTs small, use short expiration times, and never store sensitive data in public claims.'
    });
  }

  // Certificate-specific warnings
  if (context === 'certificate') {
    tips.push({
      type: 'security',
      title: 'Certificate Validation',
      message: 'Always verify the entire certificate chain, check validity periods, and validate the certificate purpose.'
    });
  }

  // JWKS warnings
  if (context === 'jwks') {
    warnings.push({
      type: 'security',
      title: 'JWKS Security',
      message: 'Validate JWKS endpoints with HTTPS, implement key rotation, and cache keys appropriately.',
      severity: 'medium'
    });
  }

  // General crypto warnings
  const generalWarnings = [
    {
      condition: true,
      warning: {
        type: 'best-practice',
        title: 'Key Management',
        message: 'Store private keys securely, use hardware security modules for production, and implement proper key rotation.'
      }
    }
  ];

  // Add conditional general warnings
  generalWarnings.forEach(({ condition, warning }) => {
    if (condition) {
      tips.push(warning);
    }
  });

  if (warnings.length === 0 && tips.length === 0) {
    return null;
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return '#dc2626';
      case 'medium': return '#d97706';
      case 'low': return '#16a34a';
      default: return '#6b7280';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'security': return '🛡️';
      case 'recommendation': return '💡';
      case 'best-practice': return '✨';
      case 'info': return 'ℹ️';
      default: return '•';
    }
  };

  return (
    <div style={{ marginTop: '12px' }}>
      {/* High priority warnings */}
      {warnings.map((warning, index) => (
        <div
          key={`warning-${index}`}
          style={{
            background: getSeverityColor(warning.severity) + '10',
            border: `1px solid ${getSeverityColor(warning.severity)}30`,
            borderRadius: '8px',
            padding: '12px',
            marginBottom: '8px'
          }}
        >
          <div style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '8px'
          }}>
            <span style={{ 
              fontSize: '16px',
              flexShrink: 0,
              marginTop: '2px'
            }}>
              ⚠️
            </span>
            <div style={{ flex: 1 }}>
              <div style={{
                fontWeight: '600',
                fontSize: '13px',
                color: getSeverityColor(warning.severity),
                marginBottom: '4px'
              }}>
                {warning.title}
              </div>
              <div style={{
                fontSize: '12px',
                color: 'var(--ink)',
                lineHeight: '1.4'
              }}>
                {warning.message}
              </div>
            </div>
          </div>
        </div>
      ))}

      {/* Tips and recommendations */}
      {tips.map((tip, index) => (
        <div
          key={`tip-${index}`}
          style={{
            background: '#3b82f608',
            border: '1px solid #3b82f620',
            borderRadius: '8px',
            padding: '10px',
            marginBottom: index < tips.length - 1 ? '8px' : '0'
          }}
        >
          <div style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '8px'
          }}>
            <span style={{ 
              fontSize: '14px',
              flexShrink: 0,
              marginTop: '1px'
            }}>
              {getTypeIcon(tip.type)}
            </span>
            <div style={{ flex: 1 }}>
              <div style={{
                fontWeight: '600',
                fontSize: '12px',
                color: '#3b82f6',
                marginBottom: '4px'
              }}>
                {tip.title}
              </div>
              <div style={{
                fontSize: '11px',
                color: 'var(--ink)',
                lineHeight: '1.4'
              }}>
                {tip.message}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default CommonMistakesWarning;