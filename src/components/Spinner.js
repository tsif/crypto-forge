import React from 'react';

function Spinner({ size = 16 }) {
  return (
    <div 
      className="spinner" 
      style={{ 
        width: size, 
        height: size,
        display: 'inline-block',
        marginRight: '8px'
      }}
    >
    </div>
  );
}

export default Spinner;