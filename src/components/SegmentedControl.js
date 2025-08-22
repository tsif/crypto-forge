import React, { useState, useEffect } from 'react';

function SegmentedControl({ activeTab, onTabChange }) {
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const checkScreenSize = () => {
      setIsMobile(window.innerWidth <= 768);
    };

    checkScreenSize();
    window.addEventListener('resize', checkScreenSize);
    return () => window.removeEventListener('resize', checkScreenSize);
  }, []);

  const tabs = [
    { id: 'generate', label: 'Generate Keys', mobileLabel: 'Generate' },
    { id: 'jwt-verify', label: 'Verify JWT', mobileLabel: 'Verify JWT' },
    { id: 'pem-convert', label: 'PEM → JWK / JWKS', mobileLabel: 'Convert' },
    { id: 'certificate-generator', label: 'Generate Certificate', mobileLabel: 'Gen Cert' },
    { id: 'validate-keys', label: 'Validate Keys', mobileLabel: 'Val Keys' },
    { id: 'validate-cert', label: 'Validate Certificate', mobileLabel: 'Val Cert' }
  ];

  return (
    <div className="segmented-control">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`segment ${activeTab === tab.id ? 'active' : ''}`}
          onClick={() => onTabChange(tab.id)}
        >
          {isMobile ? tab.mobileLabel : tab.label}
        </button>
      ))}
    </div>
  );
}

export default SegmentedControl;