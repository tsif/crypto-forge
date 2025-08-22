import React from 'react';

function SegmentedControl({ activeTab, onTabChange }) {
  const tabs = [
    { id: 'generate', label: 'Generate Keys' },
    { id: 'jwt-verify', label: 'Verify JWT' },
    { id: 'pem-convert', label: 'PEM → JWK / JWKS' },
    { id: 'certificate-generator', label: 'Generate Certificate' },
    { id: 'validate-keys', label: 'Validate Keys' },
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