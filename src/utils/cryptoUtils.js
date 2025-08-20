const textEncoder = new TextEncoder();

export function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

export function base64ToBuf(b64) {
  const bin = atob(b64);
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes.buffer;
}

export function base64UrlFromBuf(buf) {
  return bufToBase64(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function derToPem(der, label) {
  const b64 = bufToBase64(der);
  const wrapped = b64.replace(/(.{64})/g, "$1\n");
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

export function pemToDer(pem) {
  const match = pem
    .replace(/\r/g, "")
    .match(/-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/);
  
  if (!match) {
    throw new Error("Invalid PEM. Expected BEGIN/END blocks.");
  }
  
  const label = match[1].trim();
  const b64 = match[2].replace(/\s+/g, "");
  return { der: base64ToBuf(b64), label };
}

export function prettyJson(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort(), 2);
}

export function download(filename, text) {
  const blob = new Blob([text], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function jwkThumbprint(jwk) {
  let json = "";
  if (jwk.kty === 'RSA') {
    json = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  } else if (jwk.kty === 'EC') {
    json = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  } else {
    throw new Error('Unsupported kty for thumbprint');
  }
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(json));
  return base64UrlFromBuf(digest);
}

const RSA_HASHES = ['SHA-256', 'SHA-384', 'SHA-512'];
const EC_CURVES = ['P-256', 'P-384', 'P-521'];

export function algForSelection(kind, hashOrCurve) {
  if (kind === 'RSA') {
    return {
      'SHA-256': 'RS256',
      'SHA-384': 'RS384',
      'SHA-512': 'RS512'
    }[hashOrCurve] || 'RS256';
  }
  if (kind === 'EC') {
    return {
      'P-256': 'ES256',
      'P-384': 'ES384',
      'P-521': 'ES512'
    }[hashOrCurve] || 'ES256';
  }
}

export async function tryImportRSA(format, der, isPrivate) {
  for (const name of ['RSASSA-PKCS1-v1_5', 'RSA-PSS', 'RSA-OAEP']) {
    for (const hash of RSA_HASHES) {
      try {
        const usages = name === 'RSA-OAEP' ? 
          (isPrivate ? ['decrypt'] : ['encrypt']) : 
          (isPrivate ? ['sign'] : ['verify']);
        
        const key = await crypto.subtle.importKey(
          format,
          der,
          name === 'RSA-OAEP' ? { name, hash } : { name, hash },
          true,
          usages
        );
        return { key, name, hash };
      } catch (e) {
        // Continue trying other combinations
      }
    }
  }
  return null;
}

export async function tryImportEC(format, der, isPrivate) {
  for (const curve of EC_CURVES) {
    try {
      const key = await crypto.subtle.importKey(
        format,
        der,
        { name: 'ECDSA', namedCurve: curve },
        true,
        isPrivate ? ['sign'] : ['verify']
      );
      return { key, curve };
    } catch (e) {
      // Continue trying other curves
    }
  }
  return null;
}

export function derivePublicFromPrivateJwk(jwk) {
  if (jwk.kty === 'RSA') {
    const { kty, n, e } = jwk;
    return { kty, n, e };
  }
  if (jwk.kty === 'EC') {
    const { kty, crv, x, y } = jwk;
    return { kty, crv, x, y };
  }
  throw new Error('Unsupported kty');
}

// OpenSSH format utilities
export function writeUint32(value) {
  const buf = new ArrayBuffer(4);
  const view = new DataView(buf);
  view.setUint32(0, value, false); // big endian
  return new Uint8Array(buf);
}

export function writeString(str) {
  const strBytes = textEncoder.encode(str);
  const lenBytes = writeUint32(strBytes.length);
  const result = new Uint8Array(lenBytes.length + strBytes.length);
  result.set(lenBytes, 0);
  result.set(strBytes, lenBytes.length);
  return result;
}

export function writeMpint(bytes) {
  // Remove leading zeros
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) {
    start++;
  }
  
  // If empty or high bit is set, need to add zero byte
  const needZero = bytes.length === start || bytes[start] & 0x80;
  const actualBytes = bytes.slice(start);
  const mpintBytes = needZero ? 
    new Uint8Array([0, ...actualBytes]) : 
    actualBytes;
  
  const lenBytes = writeUint32(mpintBytes.length);
  const result = new Uint8Array(lenBytes.length + mpintBytes.length);
  result.set(lenBytes, 0);
  result.set(mpintBytes, lenBytes.length);
  return result;
}

export function jwkToOpenSSH(jwk, comment = '') {
  let keyData;
  let keyType;
  
  if (jwk.kty === 'RSA') {
    keyType = 'ssh-rsa';
    
    // Decode base64url encoded components
    const n = new Uint8Array(base64ToBuf(jwk.n.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - jwk.n.length % 4) % 4)));
    const e = new Uint8Array(base64ToBuf(jwk.e.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - jwk.e.length % 4) % 4)));
    
    // Build SSH key data structure
    const typeBytes = writeString(keyType);
    const eBytes = writeMpint(e);
    const nBytes = writeMpint(n);
    
    keyData = new Uint8Array(typeBytes.length + eBytes.length + nBytes.length);
    keyData.set(typeBytes, 0);
    keyData.set(eBytes, typeBytes.length);
    keyData.set(nBytes, typeBytes.length + eBytes.length);
    
  } else if (jwk.kty === 'EC') {
    // Map JWK curve names to SSH curve names
    const curveMap = {
      'P-256': 'nistp256',
      'P-384': 'nistp384', 
      'P-521': 'nistp521'
    };
    
    const sshCurve = curveMap[jwk.crv];
    if (!sshCurve) {
      throw new Error(`Unsupported EC curve: ${jwk.crv}`);
    }
    
    keyType = `ecdsa-sha2-${sshCurve}`;
    
    // Decode coordinates
    const x = new Uint8Array(base64ToBuf(jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - jwk.x.length % 4) % 4)));
    const y = new Uint8Array(base64ToBuf(jwk.y.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - jwk.y.length % 4) % 4)));
    
    // Build uncompressed point (0x04 prefix + x + y)
    const point = new Uint8Array(1 + x.length + y.length);
    point[0] = 0x04;
    point.set(x, 1);
    point.set(y, 1 + x.length);
    
    // Build SSH key data structure
    const typeBytes = writeString(keyType);
    const curveBytes = writeString(sshCurve);
    const pointBytes = writeString(point);
    
    keyData = new Uint8Array(typeBytes.length + curveBytes.length + pointBytes.length);
    keyData.set(typeBytes, 0);
    keyData.set(curveBytes, typeBytes.length);
    keyData.set(pointBytes, typeBytes.length + curveBytes.length);
    
  } else {
    throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
  
  // Base64 encode the key data
  const b64Key = bufToBase64(keyData);
  
  // Format as OpenSSH public key
  return `${keyType} ${b64Key}${comment ? ' ' + comment : ''}`;
}

// Key strength analysis
export function analyzeKeyStrength(jwk) {
  const analysis = {
    algorithm: jwk.kty,
    strength: 'unknown',
    level: 'unknown', // 'weak', 'acceptable', 'good', 'excellent'
    recommendations: [],
    warnings: [],
    securityBits: 0,
    details: {}
  };

  if (jwk.kty === 'RSA') {
    // Calculate modulus length
    const modulusLength = jwk.n ? 
      Math.ceil((jwk.n.replace(/[^A-Za-z0-9+/]/g, '').length * 6) / 8) : 0;
    
    analysis.details = {
      modulusLength,
      publicExponent: jwk.e
    };

    // Security strength based on NIST SP 800-57 Part 1 Rev 5
    if (modulusLength >= 15360) {
      analysis.strength = `${modulusLength}-bit RSA`;
      analysis.level = 'excellent';
      analysis.securityBits = 256;
      analysis.recommendations.push('Excellent: This key provides the highest level of security for the foreseeable future');
    } else if (modulusLength >= 7680) {
      analysis.strength = `${modulusLength}-bit RSA`;
      analysis.level = 'excellent'; 
      analysis.securityBits = 192;
      analysis.recommendations.push('Excellent: This key provides very strong security through 2030 and beyond');
    } else if (modulusLength >= 3072) {
      analysis.strength = `${modulusLength}-bit RSA`;
      analysis.level = 'good';
      analysis.securityBits = 128;
      analysis.recommendations.push('Good: This key provides strong security through 2030');
    } else if (modulusLength >= 2048) {
      analysis.strength = `${modulusLength}-bit RSA`;
      analysis.level = 'acceptable';
      analysis.securityBits = 112;
      analysis.recommendations.push('Acceptable: This key provides adequate security but should be replaced by 2030');
      analysis.warnings.push('Consider upgrading to 3072-bit RSA or EC P-256 for better security');
    } else if (modulusLength >= 1024) {
      analysis.strength = `${modulusLength}-bit RSA`;
      analysis.level = 'weak';
      analysis.securityBits = 80;
      analysis.warnings.push('DEPRECATED: This key size is considered weak and should not be used');
      analysis.warnings.push('Upgrade to at least 2048-bit RSA immediately');
    } else {
      analysis.strength = `${modulusLength}-bit RSA`;
      analysis.level = 'weak';
      analysis.securityBits = 0;
      analysis.warnings.push('INSECURE: This key size provides no meaningful security');
    }

    // Check public exponent
    if (jwk.e === 'AQAB') { // 65537
      analysis.recommendations.push('Uses standard public exponent (65537)');
    } else if (jwk.e === 'Aw') { // 3
      analysis.warnings.push('Uses small public exponent (3) - acceptable but 65537 is preferred');
    } else {
      analysis.warnings.push('Uses non-standard public exponent');
    }

  } else if (jwk.kty === 'EC') {
    const curve = jwk.crv;
    analysis.details = {
      curve,
      coordinates: {
        x: jwk.x ? jwk.x.substring(0, 12) + '...' : undefined,
        y: jwk.y ? jwk.y.substring(0, 12) + '...' : undefined
      }
    };

    // Security strength based on NIST SP 800-57
    switch (curve) {
      case 'P-256':
        analysis.strength = 'NIST P-256 (secp256r1)';
        analysis.level = 'good';
        analysis.securityBits = 128;
        analysis.recommendations.push('Good: Widely supported curve with strong security through 2030');
        analysis.recommendations.push('Equivalent security to 3072-bit RSA');
        break;
      case 'P-384':
        analysis.strength = 'NIST P-384 (secp384r1)';
        analysis.level = 'excellent';
        analysis.securityBits = 192;
        analysis.recommendations.push('Excellent: Provides very strong security through 2030 and beyond');
        analysis.recommendations.push('Equivalent security to 7680-bit RSA');
        break;
      case 'P-521':
        analysis.strength = 'NIST P-521 (secp521r1)';
        analysis.level = 'excellent';
        analysis.securityBits = 256;
        analysis.recommendations.push('Excellent: Provides the highest level of security for the foreseeable future');
        analysis.recommendations.push('Equivalent security to 15360-bit RSA');
        break;
      case 'secp256k1':
        analysis.strength = 'secp256k1 (Bitcoin curve)';
        analysis.level = 'good';
        analysis.securityBits = 128;
        analysis.recommendations.push('Good: Popular in cryptocurrency applications');
        analysis.warnings.push('Less widely supported than NIST curves in enterprise environments');
        break;
      default:
        analysis.strength = `Unknown curve: ${curve}`;
        analysis.level = 'unknown';
        analysis.warnings.push('Curve not recognized - security cannot be assessed');
    }
  }

  // Algorithm-specific recommendations
  if (jwk.alg) {
    switch (jwk.alg) {
      case 'RS256':
      case 'RS384': 
      case 'RS512':
        analysis.recommendations.push(`Uses RSASSA-PKCS1-v1_5 signature algorithm (${jwk.alg})`);
        break;
      case 'PS256':
      case 'PS384':
      case 'PS512':
        analysis.recommendations.push(`Uses RSA-PSS signature algorithm (${jwk.alg}) - preferred over PKCS1`);
        break;
      case 'ES256':
      case 'ES384':
      case 'ES512':
        analysis.recommendations.push(`Uses ECDSA signature algorithm (${jwk.alg})`);
        break;
      default:
        if (jwk.alg.startsWith('RS') || jwk.alg.startsWith('PS')) {
          analysis.warnings.push(`Non-standard RSA algorithm: ${jwk.alg}`);
        } else if (jwk.alg.startsWith('ES')) {
          analysis.warnings.push(`Non-standard ECDSA algorithm: ${jwk.alg}`);
        }
    }
  }

  // Key usage recommendations
  if (jwk.use === 'sig') {
    analysis.recommendations.push('Designated for signature operations only (good practice)');
  } else if (jwk.use === 'enc') {
    analysis.recommendations.push('Designated for encryption operations only (good practice)');
  }

  return analysis;
}