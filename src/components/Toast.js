import React, { useEffect } from 'react';

function Toast({ message, show, onClose }) {
  useEffect(() => {
    if (show) {
      const timer = setTimeout(() => {
        onClose();
      }, 2000); // Hide after 2 seconds
      
      return () => clearTimeout(timer);
    }
  }, [show, onClose]);

  if (!show) return null;

  return (
    <div className="toast">
      <span>{message}</span>
    </div>
  );
}

export default Toast;