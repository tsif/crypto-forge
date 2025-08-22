import React, { useState, useEffect } from 'react';
import KeyValidator from './KeyValidator';
import JwksValidator from './JwksValidator';

function SmartKeyValidator({ 
  keyValidatorState,
  setKeyValidatorState,
  jwksValidatorState,
  setJwksValidatorState
}) {
  const [detectedType, setDetectedType] = useState('jwk'); // default to JWK
  const [currentInput, setCurrentInput] = useState('');

  // Auto-detect input type
  const detectInputType = (input) => {
    if (!input.trim()) {
      return 'jwk'; // Default to JWK for empty input
    }
    
    try {
      const parsed = JSON.parse(input);
      
      // Check if it's a JWKS (has 'keys' array)
      if (parsed.keys && Array.isArray(parsed.keys)) {
        return 'jwks';
      }
      
      // Check if it's a JWK (has required JWK properties like 'kty')
      if (parsed.kty) {
        return 'jwk';
      }
      
      // Check if it's an array of JWKs
      if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].kty) {
        return 'jwks'; // Treat as JWKS
      }
      
      // Default to JWK if we can't determine
      return 'jwk';
    } catch (e) {
      // If JSON is invalid, default to JWK
      return 'jwk';
    }
  };

  // Monitor input changes to detect type
  useEffect(() => {
    const jwkInput = keyValidatorState.keyInput;
    const jwksInput = jwksValidatorState.jwksInput;
    
    // Use whichever input has content, or the most recently updated one
    const activeInput = jwkInput || jwksInput || currentInput;
    
    if (activeInput !== currentInput) {
      setCurrentInput(activeInput);
      const type = detectInputType(activeInput);
      setDetectedType(type);
    }
  }, [keyValidatorState.keyInput, jwksValidatorState.jwksInput, currentInput]);

  // Sync inputs between validators based on detected type
  const handleInputChange = (newInput, sourceType) => {
    setCurrentInput(newInput);
    const detectedInputType = detectInputType(newInput);
    setDetectedType(detectedInputType);
    
    if (detectedInputType === 'jwk') {
      // Update JWK validator and clear JWKS
      setKeyValidatorState(prev => ({ ...prev, keyInput: newInput }));
      if (jwksValidatorState.jwksInput !== '') {
        setJwksValidatorState(prev => ({ ...prev, jwksInput: '', validationResult: null }));
      }
    } else {
      // Update JWKS validator and clear JWK
      setJwksValidatorState(prev => ({ ...prev, jwksInput: newInput }));
      if (keyValidatorState.keyInput !== '') {
        setKeyValidatorState(prev => ({ ...prev, keyInput: '', validationResult: null }));
      }
    }
  };

  return (
    <>
      {detectedType === 'jwk' ? (
        <KeyValidator 
          keyInput={currentInput}
          setKeyInput={(input) => handleInputChange(input, 'jwk')}
          validationResult={keyValidatorState.validationResult}
          setValidationResult={(result) => setKeyValidatorState(prev => ({ ...prev, validationResult: result }))}
        />
      ) : (
        <JwksValidator 
          jwksInput={currentInput}
          setJwksInput={(input) => handleInputChange(input, 'jwks')}
          validationResult={jwksValidatorState.validationResult}
          setValidationResult={(result) => setJwksValidatorState(prev => ({ ...prev, validationResult: result }))}
        />
      )}
    </>
  );
}

export default SmartKeyValidator;