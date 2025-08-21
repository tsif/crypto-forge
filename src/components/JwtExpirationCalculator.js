import React, { useState, useEffect } from 'react';

function JwtExpirationCalculator({ exp, nbf, iat }) {
  const [currentTime, setCurrentTime] = useState(Math.floor(Date.now() / 1000));

  // Update current time every second
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(Math.floor(Date.now() / 1000));
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  // Calculate time differences
  const timeToExpiration = exp ? exp - currentTime : null;
  const timeFromIssuance = iat ? currentTime - iat : null;
  const timeToActivation = nbf ? nbf - currentTime : null;

  // Format duration in human-readable format
  const formatDuration = (seconds) => {
    if (!seconds) return null;
    
    const absSeconds = Math.abs(seconds);
    const isNegative = seconds < 0;
    
    const days = Math.floor(absSeconds / 86400);
    const hours = Math.floor((absSeconds % 86400) / 3600);
    const minutes = Math.floor((absSeconds % 3600) / 60);
    const secs = absSeconds % 60;
    
    let parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);
    
    const formatted = parts.slice(0, 2).join(' '); // Show up to 2 units
    return isNegative ? `-${formatted}` : formatted;
  };

  // Get status info
  const getExpirationStatus = () => {
    if (!exp) return null;
    
    if (timeToExpiration <= 0) {
      return { status: 'expired', color: '#ef4444', text: 'EXPIRED' };
    } else if (timeToExpiration < 300) { // Less than 5 minutes
      return { status: 'critical', color: '#ef4444', text: 'CRITICAL' };
    } else if (timeToExpiration < 3600) { // Less than 1 hour
      return { status: 'warning', color: '#f59e0b', text: 'EXPIRING SOON' };
    } else if (timeToExpiration < 86400) { // Less than 1 day
      return { status: 'caution', color: '#f59e0b', text: 'EXPIRES TODAY' };
    } else {
      return { status: 'valid', color: '#10b981', text: 'VALID' };
    }
  };

  const getActivationStatus = () => {
    if (!nbf) return null;
    
    if (timeToActivation > 0) {
      return { status: 'not-active', color: '#f59e0b', text: 'NOT YET ACTIVE' };
    } else {
      return { status: 'active', color: '#10b981', text: 'ACTIVE' };
    }
  };

  const expirationStatus = getExpirationStatus();
  const activationStatus = getActivationStatus();

  // Progress bar calculation
  const getProgressPercentage = () => {
    if (!exp || !iat) return 0;
    
    const totalLifetime = exp - iat;
    const elapsed = currentTime - iat;
    const percentage = Math.min(Math.max((elapsed / totalLifetime) * 100, 0), 100);
    
    return percentage;
  };

  const progressPercentage = getProgressPercentage();

  if (!exp && !nbf && !iat) {
    return null;
  }

  return (
    <div style={{
      background: 'var(--input-bg)',
      border: '1px solid var(--line)',
      borderRadius: '12px',
      padding: '16px',
      marginTop: '16px'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '16px'
      }}>
        <h4 style={{ margin: 0, fontSize: '16px' }}>JWT Timing Analysis</h4>
        <div style={{
          fontSize: '11px',
          color: 'var(--muted)',
          background: 'var(--card)',
          padding: '2px 6px',
          borderRadius: '4px',
          fontFamily: 'monospace'
        }}>
          Live: {new Date(currentTime * 1000).toLocaleTimeString()}
        </div>
      </div>

      {/* Status badges */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '8px',
        marginBottom: '16px'
      }}>
        {expirationStatus && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            background: expirationStatus.color + '15',
            color: expirationStatus.color,
            padding: '4px 8px',
            borderRadius: '6px',
            fontSize: '12px',
            fontWeight: '600'
          }}>
            <div 
              className={expirationStatus.status === 'critical' ? 'jwt-pulse' : ''}
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: expirationStatus.color
              }} 
            />
            {expirationStatus.text}
          </div>
        )}
        
        {activationStatus && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            background: activationStatus.color + '15',
            color: activationStatus.color,
            padding: '4px 8px',
            borderRadius: '6px',
            fontSize: '12px',
            fontWeight: '600'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: activationStatus.color
            }} />
            {activationStatus.text}
          </div>
        )}
      </div>

      {/* Lifetime progress bar */}
      {exp && iat && (
        <div style={{ marginBottom: '16px' }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '6px'
          }}>
            <span style={{ fontSize: '12px', color: 'var(--muted)' }}>Token Lifetime</span>
            <span style={{ fontSize: '12px', color: 'var(--muted)' }}>
              {progressPercentage.toFixed(1)}% elapsed
            </span>
          </div>
          <div style={{
            width: '100%',
            height: '8px',
            background: 'var(--card)',
            borderRadius: '4px',
            overflow: 'hidden'
          }}>
            <div style={{
              width: `${progressPercentage}%`,
              height: '100%',
              background: progressPercentage > 90 ? '#ef4444' : 
                         progressPercentage > 75 ? '#f59e0b' : '#10b981',
              borderRadius: '4px',
              transition: 'width 0.3s ease, background 0.3s ease'
            }} />
          </div>
        </div>
      )}

      {/* Time details grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
        gap: '12px',
        fontSize: '13px'
      }}>
        {iat && (
          <div style={{
            background: 'var(--card)',
            padding: '10px',
            borderRadius: '8px',
            textAlign: 'center'
          }}>
            <div style={{ color: '#6b7280', marginBottom: '4px' }}>Issued At</div>
            <div style={{ fontWeight: '600', marginBottom: '2px' }}>
              {new Date(iat * 1000).toLocaleDateString()}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
              {new Date(iat * 1000).toLocaleTimeString()}
            </div>
            {timeFromIssuance !== null && (
              <div style={{ 
                fontSize: '11px', 
                color: '#3b82f6', 
                marginTop: '4px',
                fontWeight: '500'
              }}>
                {formatDuration(timeFromIssuance)} ago
              </div>
            )}
          </div>
        )}

        {nbf && (
          <div style={{
            background: 'var(--card)',
            padding: '10px',
            borderRadius: '8px',
            textAlign: 'center'
          }}>
            <div style={{ color: '#6b7280', marginBottom: '4px' }}>Not Before</div>
            <div style={{ fontWeight: '600', marginBottom: '2px' }}>
              {new Date(nbf * 1000).toLocaleDateString()}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
              {new Date(nbf * 1000).toLocaleTimeString()}
            </div>
            {timeToActivation !== null && (
              <div style={{ 
                fontSize: '11px', 
                color: timeToActivation > 0 ? '#f59e0b' : '#10b981',
                marginTop: '4px',
                fontWeight: '500'
              }}>
                {timeToActivation > 0 
                  ? `Activates in ${formatDuration(timeToActivation)}`
                  : `Active for ${formatDuration(-timeToActivation)}`
                }
              </div>
            )}
          </div>
        )}

        {exp && (
          <div style={{
            background: 'var(--card)',
            padding: '10px',
            borderRadius: '8px',
            textAlign: 'center'
          }}>
            <div style={{ color: '#6b7280', marginBottom: '4px' }}>Expires At</div>
            <div style={{ fontWeight: '600', marginBottom: '2px' }}>
              {new Date(exp * 1000).toLocaleDateString()}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
              {new Date(exp * 1000).toLocaleTimeString()}
            </div>
            {timeToExpiration !== null && (
              <div style={{ 
                fontSize: '11px', 
                color: timeToExpiration <= 0 ? '#ef4444' : 
                       timeToExpiration < 3600 ? '#f59e0b' : '#10b981',
                marginTop: '4px',
                fontWeight: '500'
              }}>
                {timeToExpiration <= 0 
                  ? `Expired ${formatDuration(-timeToExpiration)} ago`
                  : `Expires in ${formatDuration(timeToExpiration)}`
                }
              </div>
            )}
          </div>
        )}
      </div>

      {/* Quick reference */}
      <div style={{
        marginTop: '12px',
        padding: '8px',
        background: 'var(--card)',
        borderRadius: '6px',
        fontSize: '11px',
        color: 'var(--muted)',
        textAlign: 'center'
      }}>
        Unix timestamps: {iat && `iat=${iat}`} {nbf && `nbf=${nbf}`} {exp && `exp=${exp}`}
      </div>

      <style>{`
        @keyframes jwt-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        .jwt-pulse {
          animation: jwt-pulse 1s infinite;
        }
      `}</style>
    </div>
  );
}

export default JwtExpirationCalculator;