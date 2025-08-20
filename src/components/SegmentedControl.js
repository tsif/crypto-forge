import React from 'react';

function SegmentedControl({ activeTab, onTabChange }) {
  const tabs = [
    { id: 'generate', label: 'Generate Keys' },
    { id: 'pem-convert', label: 'PEM → JWK / JWKS' },
    { id: 'validate-jwk', label: 'Validate JWK' },
    { id: 'validate-cert', label: 'Validate Certificate' }
  ];

  return (
    <div className="segmented-control">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`segment ${activeTab === tab.id ? 'active' : ''}`}
          onClick={() => onTabChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export default SegmentedControl;