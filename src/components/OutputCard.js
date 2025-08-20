import React from 'react';

function OutputCard({ title, value, filename, setMessage, showToast }) {
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value || '');
      if (showToast) {
        showToast('Copied!');
      } else {
        setMessage('Copied to clipboard.');
      }
    } catch (err) {
      if (showToast) {
        showToast('Copy failed');
      } else {
        setMessage('Copy failed.');
      }
    }
  };

  return (
    <div className="card">
      <div className="titlebar">
        <strong>{title}</strong>
        <button className="btn" onClick={handleCopy}>Copy</button>
      </div>
      <textarea value={value} readOnly />
    </div>
  );
}

export default OutputCard;