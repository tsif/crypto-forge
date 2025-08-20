import React from 'react';

function ThemeToggle({ theme, toggleTheme }) {
  return (
    <button className="theme-toggle" onClick={toggleTheme} aria-label="Toggle theme">
      <span className="theme-toggle-icon">
        {theme === 'light' ? (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
            <circle cx="8" cy="8" r="4"/>
            <circle cx="8" cy="1" r="1"/>
            <circle cx="8" cy="15" r="1"/>
            <circle cx="15" cy="8" r="1"/>
            <circle cx="1" cy="8" r="1"/>
            <circle cx="13.7" cy="2.3" r="1"/>
            <circle cx="2.3" cy="13.7" r="1"/>
            <circle cx="13.7" cy="13.7" r="1"/>
            <circle cx="2.3" cy="2.3" r="1"/>
          </svg>
        ) : (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
            <path d="M6 .278a.768.768 0 0 1 .08.858 7.208 7.208 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277.527 0 1.04-.055 1.533-.16a.787.787 0 0 1 .81.316.733.733 0 0 1-.031.893A8.349 8.349 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.752.752 0 0 1 6 .278z"/>
          </svg>
        )}
      </span>
      <span>{theme === 'light' ? 'Light' : 'Dark'}</span>
    </button>
  );
}

export default ThemeToggle;