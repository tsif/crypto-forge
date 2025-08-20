import React from 'react';
import * as cryptoUtils from '../utils/cryptoUtils';

function KeyStrengthAnalyzer({ jwk }) {
  if (!jwk) return null;

  const analysis = cryptoUtils.analyzeKeyStrength(jwk);

  const getLevelColor = (level) => {
    switch (level) {
      case 'excellent': return '#10b981';
      case 'good': return '#059669';
      case 'acceptable': return '#f59e0b';
      case 'weak': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getLevelIcon = (level) => {
    switch (level) {
      case 'excellent': return '●';
      case 'good': return '●';
      case 'acceptable': return '●';
      case 'weak': return '●';
      default: return '●';
    }
  };

  return (
    <div className="key-strength-analyzer">
      <h4 style={{ margin: '0 0 12px 0', fontSize: '14px' }}>Security Analysis</h4>
      
      {/* Strength Badge */}
      <div className="strength-badge" style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '6px 12px',
        background: 'var(--badge-bg)',
        border: `1px solid ${getLevelColor(analysis.level)}`,
        borderRadius: '999px',
        fontSize: '12px',
        fontWeight: '500',
        color: getLevelColor(analysis.level),
        marginBottom: '12px'
      }}>
        <span>{getLevelIcon(analysis.level)}</span>
        <span>{analysis.strength}</span>
        <span style={{ color: 'var(--muted)', marginLeft: '4px' }}>
          ({analysis.securityBits} bits)
        </span>
      </div>

      {/* Details */}
      <div className="analysis-details" style={{ fontSize: '12px' }}>
        {/* Recommendations */}
        {analysis.recommendations.length > 0 && (
          <div style={{ marginBottom: '8px' }}>
            {analysis.recommendations.map((rec, index) => (
              <div key={index} style={{ 
                color: 'var(--ink)', 
                marginBottom: '4px',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '4px'
              }}>
                <span style={{ color: '#10b981', minWidth: '12px' }}>●</span>
                <span>{rec}</span>
              </div>
            ))}
          </div>
        )}

        {/* Warnings */}
        {analysis.warnings.length > 0 && (
          <div style={{ marginBottom: '8px' }}>
            {analysis.warnings.map((warning, index) => (
              <div key={index} style={{ 
                color: '#ef4444', 
                marginBottom: '4px',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '4px'
              }}>
                <span style={{ color: '#ef4444', minWidth: '12px' }}>●</span>
                <span>{warning}</span>
              </div>
            ))}
          </div>
        )}

        {/* Technical Details */}
        <div style={{ 
          background: 'var(--input-bg)', 
          padding: '8px', 
          borderRadius: '6px',
          border: '1px solid var(--line)',
          marginTop: '8px'
        }}>
          <div style={{ fontWeight: '500', marginBottom: '4px', color: 'var(--ink)' }}>
            Technical Details:
          </div>
          <div style={{ color: 'var(--muted)' }}>
            <div>Algorithm: {analysis.algorithm}</div>
            {analysis.details.modulusLength && (
              <div>Modulus: {analysis.details.modulusLength} bits</div>
            )}
            {analysis.details.curve && (
              <div>Curve: {analysis.details.curve}</div>
            )}
            {analysis.details.publicExponent && (
              <div>Public Exponent: {analysis.details.publicExponent}</div>
            )}
          </div>
        </div>

        {/* Security Timeline */}
        <div style={{ 
          background: 'var(--input-bg)', 
          padding: '8px', 
          borderRadius: '6px',
          border: '1px solid var(--line)',
          marginTop: '8px'
        }}>
          <div style={{ fontWeight: '500', marginBottom: '4px', color: 'var(--ink)' }}>
            Security Timeline:
          </div>
          <div style={{ color: 'var(--muted)' }}>
            {analysis.securityBits >= 256 && (
              <div><span style={{ color: '#10b981' }}>●</span> Secure through 2040+</div>
            )}
            {analysis.securityBits >= 192 && analysis.securityBits < 256 && (
              <div><span style={{ color: '#10b981' }}>●</span> Secure through 2030+</div>
            )}
            {analysis.securityBits >= 128 && analysis.securityBits < 192 && (
              <div><span style={{ color: '#f59e0b' }}>●</span> Secure through 2030</div>
            )}
            {analysis.securityBits >= 112 && analysis.securityBits < 128 && (
              <div><span style={{ color: '#f59e0b' }}>●</span> Should replace by 2030</div>
            )}
            {analysis.securityBits < 112 && analysis.securityBits > 0 && (
              <div><span style={{ color: '#ef4444' }}>●</span> <span style={{ color: '#ef4444' }}>Replace immediately</span></div>
            )}
            {analysis.securityBits === 0 && (
              <div><span style={{ color: '#ef4444' }}>●</span> <span style={{ color: '#ef4444' }}>Not secure</span></div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default KeyStrengthAnalyzer;