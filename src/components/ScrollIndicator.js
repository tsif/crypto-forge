import React, { useState, useEffect } from 'react';

function ScrollIndicator({ show, message = "Scroll down to view generated keys" }) {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (show) {
      // Small delay to ensure the indicator appears after content is rendered
      const timer = setTimeout(() => {
        setIsVisible(true);
      }, 500);

      // Hide after 5 seconds or when user scrolls
      const hideTimer = setTimeout(() => {
        setIsVisible(false);
      }, 5000);

      const handleScroll = () => {
        setIsVisible(false);
      };

      window.addEventListener('scroll', handleScroll, { once: true });

      return () => {
        clearTimeout(timer);
        clearTimeout(hideTimer);
        window.removeEventListener('scroll', handleScroll);
      };
    } else {
      setIsVisible(false);
    }
  }, [show]);

  if (!isVisible) {
    return null;
  }

  return (
    <div style={{
      position: 'fixed',
      bottom: '30px',
      right: '30px',
      background: 'var(--card)',
      border: '1px solid var(--line)',
      borderRadius: '12px',
      padding: '12px 16px',
      boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
      zIndex: 1000,
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      animation: 'scrollIndicatorFadeIn 0.3s ease-out forwards, scrollIndicatorPulse 2s ease-in-out infinite',
      maxWidth: '280px'
    }}>
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        color: 'var(--muted)',
        fontSize: '16px',
        animation: 'scrollIndicatorBounce 1.5s ease-in-out infinite'
      }}>
        ↓
      </div>
      <div style={{
        fontSize: '13px',
        color: 'var(--ink)',
        fontWeight: '500'
      }}>
        {message}
      </div>
      <button
        onClick={() => setIsVisible(false)}
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--muted)',
          cursor: 'pointer',
          fontSize: '16px',
          padding: '0 4px',
          marginLeft: '4px'
        }}
        title="Dismiss"
      >
        ×
      </button>

      <style>{`
        @keyframes scrollIndicatorFadeIn {
          from {
            opacity: 0;
            transform: translateY(10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        
        @keyframes scrollIndicatorPulse {
          0%, 100% {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
          }
          50% {
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.2);
          }
        }
        
        @keyframes scrollIndicatorBounce {
          0%, 20%, 50%, 80%, 100% {
            transform: translateY(0);
          }
          40% {
            transform: translateY(-4px);
          }
          60% {
            transform: translateY(-2px);
          }
        }
        
        @media (max-width: 768px) {
          /* Position indicator better on mobile */
          .scroll-indicator {
            bottom: 20px;
            right: 20px;
            max-width: 240px;
            font-size: 12px;
          }
        }
      `}</style>
    </div>
  );
}

export default ScrollIndicator;