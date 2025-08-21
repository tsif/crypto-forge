import React, { useState, useRef, useEffect } from 'react';

function CopyDropdown({ value, setMessage, showToast }) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Format conversion functions
  const formatters = {
    'Original Text': (text) => text,
    'Base64': (text) => {
      try {
        return btoa(unescape(encodeURIComponent(text)));
      } catch (e) {
        throw new Error('Failed to encode as Base64');
      }
    },
    'Base64URL': (text) => {
      try {
        return btoa(unescape(encodeURIComponent(text)))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '');
      } catch (e) {
        throw new Error('Failed to encode as Base64URL');
      }
    },
    'Hex': (text) => {
      try {
        return Array.from(new TextEncoder().encode(text))
          .map(byte => byte.toString(16).padStart(2, '0'))
          .join('');
      } catch (e) {
        throw new Error('Failed to encode as Hex');
      }
    },
    'Hex (Spaced)': (text) => {
      try {
        return Array.from(new TextEncoder().encode(text))
          .map(byte => byte.toString(16).padStart(2, '0').toUpperCase())
          .join(' ');
      } catch (e) {
        throw new Error('Failed to encode as spaced Hex');
      }
    },
    'URI Encoded': (text) => {
      try {
        return encodeURIComponent(text);
      } catch (e) {
        throw new Error('Failed to URI encode');
      }
    },
    'JSON Escaped': (text) => {
      try {
        return JSON.stringify(text);
      } catch (e) {
        throw new Error('Failed to JSON escape');
      }
    }
  };

  // Add PEM format for specific content types
  const isPemLike = (text) => {
    return text.includes('-----BEGIN') || 
           (text.startsWith('{') && (text.includes('"kty"') || text.includes('"x5c"'))) ||
           /^[A-Za-z0-9+/=]+$/.test(text.replace(/\s/g, ''));
  };

  const getPemFormat = (text) => {
    // If it's already PEM formatted, return as-is
    if (text.includes('-----BEGIN')) {
      return text;
    }
    
    // If it's a JWK, try to format as PEM-like structure
    if (text.startsWith('{') && text.includes('"kty"')) {
      try {
        const jwk = JSON.parse(text);
        if (jwk.kty === 'RSA') {
          return `-----BEGIN RSA PUBLIC KEY-----\n${text}\n-----END RSA PUBLIC KEY-----`;
        } else if (jwk.kty === 'EC') {
          return `-----BEGIN EC PUBLIC KEY-----\n${text}\n-----END EC PUBLIC KEY-----`;
        }
      } catch (e) {
        // Fall through to base64 handling
      }
    }
    
    // If it looks like base64, format as generic PEM
    if (/^[A-Za-z0-9+/=]+$/.test(text.replace(/\s/g, ''))) {
      const cleaned = text.replace(/\s/g, '');
      const formatted = cleaned.match(/.{1,64}/g)?.join('\n') || cleaned;
      return `-----BEGIN DATA-----\n${formatted}\n-----END DATA-----`;
    }
    
    return text;
  };

  // Add PEM format if content looks appropriate
  if (isPemLike(value)) {
    formatters['PEM Format'] = getPemFormat;
  }

  const handleCopy = async (format) => {
    try {
      const formatter = formatters[format];
      const formattedValue = formatter(value || '');
      await navigator.clipboard.writeText(formattedValue);
      
      if (showToast) {
        showToast(`✓ Copied as ${format}`);
      } else if (setMessage) {
        setMessage(`Copied as ${format}`);
      }
    } catch (err) {
      const errorMsg = `Copy failed: ${err.message}`;
      if (showToast) {
        showToast(`✗ ${errorMsg}`);
      } else if (setMessage) {
        setMessage(errorMsg);
      }
    } finally {
      setIsOpen(false);
    }
  };

  return (
    <div className="copy-dropdown" ref={dropdownRef} style={{ position: 'relative', display: 'inline-block' }}>
      <button 
        className="btn"
        onClick={() => setIsOpen(!isOpen)}
        style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '4px',
          minWidth: '80px',
          justifyContent: 'center'
        }}
      >
        Copy as
        <span style={{ 
          transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
          transition: 'transform 0.2s ease',
          fontSize: '12px'
        }}>
          ▼
        </span>
      </button>
      
      {isOpen && (
        <div style={{
          position: 'absolute',
          top: '100%',
          right: 0,
          background: 'var(--card)',
          border: '1px solid var(--line)',
          borderRadius: '8px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
          zIndex: 1000,
          minWidth: '140px',
          marginTop: '4px',
          overflow: 'hidden'
        }}>
          {Object.keys(formatters).map((format, index) => (
            <button
              key={format}
              onClick={() => handleCopy(format)}
              style={{
                width: '100%',
                padding: '8px 12px',
                border: 'none',
                background: 'transparent',
                color: 'var(--ink)',
                fontSize: '13px',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'background 0.2s ease',
                borderBottom: index < Object.keys(formatters).length - 1 ? '1px solid var(--line)' : 'none'
              }}
              onMouseEnter={(e) => e.target.style.background = 'var(--input-bg)'}
              onMouseLeave={(e) => e.target.style.background = 'transparent'}
            >
              {format}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default CopyDropdown;