import React from 'react';
import CopyDropdown from './CopyDropdown';

function OutputCard({ title, value, filename, setMessage, showToast }) {
  return (
    <div className="card">
      <div className="titlebar">
        <strong>{title}</strong>
        <CopyDropdown value={value} setMessage={setMessage} showToast={showToast} />
      </div>
      <textarea value={value} readOnly />
    </div>
  );
}

export default OutputCard;