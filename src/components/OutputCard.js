import React from 'react';

function OutputCard({ title, value, filename, setMessage }) {
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value || '');
      setMessage('Copied to clipboard.');
    } catch (err) {
      setMessage('Copy failed.');
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