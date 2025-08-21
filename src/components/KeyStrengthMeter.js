import React from 'react';

function KeyStrengthMeter({ keyType, keySize, curve, showRecommendations = true }) {
  
  // Analyze key strength based on type and parameters
  const analyzeKeyStrength = () => {
    if (!keyType) {
      return { strength: 0, level: 'unknown', color: '#9ca3af', description: 'Unknown key type' };
    }

    const type = keyType.toUpperCase();
    
    if (type === 'RSA') {
      if (!keySize) return { strength: 0, level: 'unknown', color: '#9ca3af', description: 'Key size unknown' };
      
      if (keySize < 1024) {
        return { 
          strength: 10, 
          level: 'very-weak', 
          color: '#dc2626', 
          description: 'Cryptographically broken',
          recommendation: 'Use at least 2048-bit RSA keys'
        };
      } else if (keySize < 2048) {
        return { 
          strength: 25, 
          level: 'weak', 
          color: '#ea580c', 
          description: 'Deprecated and vulnerable',
          recommendation: 'Upgrade to 2048-bit or higher RSA keys'
        };
      } else if (keySize === 2048) {
        return { 
          strength: 70, 
          level: 'acceptable', 
          color: '#d97706', 
          description: 'Minimum acceptable for new systems',
          recommendation: 'Consider 3072-bit or 4096-bit for higher security'
        };
      } else if (keySize === 3072) {
        return { 
          strength: 85, 
          level: 'good', 
          color: '#16a34a', 
          description: 'Good security level (~128-bit equivalent)',
          recommendation: 'Excellent choice for most applications'
        };
      } else if (keySize >= 4096) {
        return { 
          strength: 95, 
          level: 'excellent', 
          color: '#059669', 
          description: 'Very high security (~150-bit equivalent)',
          recommendation: 'Maximum security, but slower performance'
        };
      }
    } else if (type === 'EC' || type === 'ECDSA' || type === 'ECDH') {
      if (!curve) return { strength: 0, level: 'unknown', color: '#9ca3af', description: 'Curve unknown' };
      
      switch (curve.toUpperCase()) {
        case 'P-256':
        case 'SECP256R1':
        case 'PRIME256V1':
          return { 
            strength: 80, 
            level: 'good', 
            color: '#16a34a', 
            description: 'Good security (~128-bit equivalent)',
            recommendation: 'Widely supported and secure'
          };
        case 'P-384':
        case 'SECP384R1':
          return { 
            strength: 90, 
            level: 'excellent', 
            color: '#059669', 
            description: 'High security (~192-bit equivalent)',
            recommendation: 'Excellent for high-security applications'
          };
        case 'P-521':
        case 'SECP521R1':
          return { 
            strength: 95, 
            level: 'excellent', 
            color: '#059669', 
            description: 'Very high security (~256-bit equivalent)',
            recommendation: 'Maximum security with good performance'
          };
        case 'SECP256K1':
          return { 
            strength: 75, 
            level: 'acceptable', 
            color: '#d97706', 
            description: 'Bitcoin curve, less standardized',
            recommendation: 'Consider P-256 for general use'
          };
        default:
          return { 
            strength: 50, 
            level: 'unknown', 
            color: '#9ca3af', 
            description: 'Non-standard or unknown curve'
          };
      }
    } else if (type === 'SYMMETRIC' || type === 'AES' || type === 'HMAC') {
      if (!keySize) return { strength: 0, level: 'unknown', color: '#9ca3af', description: 'Key size unknown' };
      
      if (keySize < 128) {
        return { 
          strength: 20, 
          level: 'weak', 
          color: '#dc2626', 
          description: 'Insufficient for modern use',
          recommendation: 'Use at least 128-bit symmetric keys'
        };
      } else if (keySize === 128) {
        return { 
          strength: 80, 
          level: 'good', 
          color: '#16a34a', 
          description: 'Standard security level',
          recommendation: 'Good for most applications'
        };
      } else if (keySize === 192) {
        return { 
          strength: 85, 
          level: 'good', 
          color: '#16a34a', 
          description: 'High security level',
          recommendation: 'Strong security with good performance'
        };
      } else if (keySize >= 256) {
        return { 
          strength: 95, 
          level: 'excellent', 
          color: '#059669', 
          description: 'Very high security level',
          recommendation: 'Maximum security for symmetric encryption'
        };
      }
    }

    return { 
      strength: 50, 
      level: 'unknown', 
      color: '#9ca3af', 
      description: 'Cannot assess key strength'
    };
  };

  const analysis = analyzeKeyStrength();
  
  // Get security level badge text
  const getLevelText = (level) => {
    switch (level) {
      case 'very-weak': return 'VERY WEAK';
      case 'weak': return 'WEAK';
      case 'acceptable': return 'ACCEPTABLE';
      case 'good': return 'GOOD';
      case 'excellent': return 'EXCELLENT';
      default: return 'UNKNOWN';
    }
  };

  // Get additional security context
  const getSecurityContext = () => {
    if (keyType?.toUpperCase() === 'RSA' && keySize) {
      return {
        title: 'RSA Key Security',
        details: [
          `${keySize}-bit RSA key`,
          `Factorization difficulty: ~2^${Math.log2(keySize * 4).toFixed(0)}`,
          `NIST recommendation: ${keySize >= 2048 ? '✓ Compliant' : '✗ Non-compliant'}`
        ]
      };
    } else if ((keyType?.toUpperCase() === 'EC' || keyType?.toUpperCase() === 'ECDSA') && curve) {
      const bitEquivalent = curve.includes('256') ? '128' : 
                           curve.includes('384') ? '192' : 
                           curve.includes('521') ? '256' : '?';
      return {
        title: 'Elliptic Curve Security',
        details: [
          `${curve} curve`,
          `Security equivalent: ~${bitEquivalent}-bit symmetric`,
          `FIPS 186-4: ${['P-256', 'P-384', 'P-521'].includes(curve) ? '✓ Approved' : '? Check compliance'}`
        ]
      };
    }
    return null;
  };

  const securityContext = getSecurityContext();

  if (!keyType) {
    return null;
  }

  return (
    <div style={{
      background: 'var(--input-bg)',
      border: '1px solid var(--line)',
      borderRadius: '12px',
      padding: '16px',
      marginTop: '12px'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        marginBottom: '12px'
      }}>
        <h4 style={{ margin: 0, fontSize: '16px' }}>Key Strength Analysis</h4>
        <div style={{
          background: analysis.color + '15',
          color: analysis.color,
          padding: '4px 8px',
          borderRadius: '6px',
          fontSize: '12px',
          fontWeight: '600'
        }}>
          {getLevelText(analysis.level)}
        </div>
      </div>

      {/* Strength meter bar */}
      <div style={{ marginBottom: '12px' }}>
        <div style={{
          width: '100%',
          height: '8px',
          background: 'var(--card)',
          borderRadius: '4px',
          overflow: 'hidden',
          position: 'relative'
        }}>
          <div style={{
            width: `${analysis.strength}%`,
            height: '100%',
            background: analysis.color,
            borderRadius: '4px',
            transition: 'width 0.5s ease, background 0.3s ease'
          }} />
        </div>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: '11px',
          color: 'var(--muted)',
          marginTop: '4px'
        }}>
          <span>Weak</span>
          <span>Strong</span>
        </div>
      </div>

      {/* Description */}
      <p style={{
        margin: '0 0 12px 0',
        fontSize: '14px',
        color: 'var(--ink)'
      }}>
        {analysis.description}
      </p>

      {/* Security context details */}
      {securityContext && (
        <div style={{
          background: 'var(--card)',
          padding: '10px',
          borderRadius: '8px',
          marginBottom: '12px'
        }}>
          <h5 style={{ margin: '0 0 6px 0', fontSize: '13px', color: 'var(--muted)' }}>
            {securityContext.title}
          </h5>
          {securityContext.details.map((detail, index) => (
            <div key={index} style={{ fontSize: '12px', color: 'var(--ink)', marginBottom: '2px' }}>
              • {detail}
            </div>
          ))}
        </div>
      )}

      {/* Recommendations */}
      {showRecommendations && analysis.recommendation && (
        <div style={{
          background: '#3b82f610',
          border: '1px solid #3b82f630',
          borderRadius: '8px',
          padding: '10px'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            marginBottom: '4px'
          }}>
            <span style={{ color: '#3b82f6', fontSize: '14px' }}>●</span>
            <span style={{ fontSize: '13px', fontWeight: '600', color: '#3b82f6' }}>
              Recommendation
            </span>
          </div>
          <div style={{ fontSize: '12px', color: 'var(--ink)' }}>
            {analysis.recommendation}
          </div>
        </div>
      )}
    </div>
  );
}

export default KeyStrengthMeter;