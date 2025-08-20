import React from 'react';

function FontSizeToggle({ fontSize, toggleFontSize }) {
  return (
    <button
      className="theme-toggle font-size-toggle"
      onClick={toggleFontSize}
      aria-label={`Switch to ${fontSize === 'default' ? 'large' : 'default'} font size`}
      title={`Switch to ${fontSize === 'default' ? 'large' : 'default'} font size`}
    >
      <span style={{ 
        display: 'flex',
        alignItems: 'center',
        gap: '4px',
        fontSize: '14px',
        transition: 'all 0.2s ease'
      }}>
        <span style={{ fontWeight: 'bold' }}>F</span>
        <span style={{ fontSize: '12px', opacity: 0.8 }}>
          {fontSize === 'default' ? 'Default' : 'Large'}
        </span>
      </span>
    </button>
  );
}

export default FontSizeToggle;