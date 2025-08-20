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