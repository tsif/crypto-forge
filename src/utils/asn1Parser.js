// Lightweight ASN.1 parser for X.509 certificate parsing
// Based on ITU-T X.690 ASN.1 encoding rules

class ASN1Parser {
  constructor(data) {
    this.data = new Uint8Array(data);
    this.pos = 0;
  }

  // Read one byte
  readByte() {
    if (this.pos >= this.data.length) {
      throw new Error('Unexpected end of data');
    }
    return this.data[this.pos++];
  }

  // Parse tag
  parseTag() {
    const firstByte = this.readByte();
    const isConstructed = (firstByte & 0x20) !== 0;
    const tagClass = (firstByte & 0xC0) >> 6;
    let tagNumber = firstByte & 0x1F;

    // Handle multi-byte tags
    if (tagNumber === 0x1F) {
      tagNumber = 0;
      let byte;
      do {
        byte = this.readByte();
        tagNumber = (tagNumber << 7) | (byte & 0x7F);
      } while ((byte & 0x80) !== 0);
    }

    return { tagClass, isConstructed, tagNumber };
  }

  // Parse length
  parseLength() {
    let firstByte = this.readByte();
    
    if ((firstByte & 0x80) === 0) {
      // Short form
      return firstByte;
    } else {
      // Long form
      const lengthBytes = firstByte & 0x7F;
      if (lengthBytes === 0) {
        throw new Error('Indefinite length not supported');
      }
      if (lengthBytes > 4) {
        throw new Error('Length too long');
      }
      
      let length = 0;
      for (let i = 0; i < lengthBytes; i++) {
        length = (length << 8) | this.readByte();
      }
      return length;
    }
  }

  // Parse ASN.1 object
  parseObject() {
    const startPos = this.pos;
    const tag = this.parseTag();
    const length = this.parseLength();
    const contentStart = this.pos;
    
    if (this.pos + length > this.data.length) {
      throw new Error('Invalid length');
    }

    const content = this.data.slice(this.pos, this.pos + length);
    this.pos += length;

    return {
      tag,
      length,
      content,
      startPos,
      contentStart,
      endPos: this.pos,
      // Helper methods
      isSequence: () => tag.tagNumber === 16 && tag.isConstructed,
      isSet: () => tag.tagNumber === 17 && tag.isConstructed,
      isOctetString: () => tag.tagNumber === 4 && !tag.isConstructed,
      isBitString: () => tag.tagNumber === 3 && !tag.isConstructed,
      isInteger: () => tag.tagNumber === 2 && !tag.isConstructed,
      isOid: () => tag.tagNumber === 6 && !tag.isConstructed,
      isUtcTime: () => tag.tagNumber === 23 && !tag.isConstructed,
      isGeneralizedTime: () => tag.tagNumber === 24 && !tag.isConstructed,
      isPrintableString: () => tag.tagNumber === 19 && !tag.isConstructed,
      isUtf8String: () => tag.tagNumber === 12 && !tag.isConstructed,
      isIA5String: () => tag.tagNumber === 22 && !tag.isConstructed,
      isContext: (num) => tag.tagClass === 2 && tag.tagNumber === num
    };
  }

  // Parse sequence children
  parseSequence(obj) {
    if (!obj.isSequence()) {
      throw new Error('Not a sequence');
    }

    const children = [];
    const parser = new ASN1Parser(obj.content);
    
    while (parser.pos < parser.data.length) {
      children.push(parser.parseObject());
    }
    
    return children;
  }

  // Parse all objects at current level
  parseAll() {
    const objects = [];
    while (this.pos < this.data.length) {
      objects.push(this.parseObject());
    }
    return objects;
  }
}

// OID mappings for common certificate fields
const OID_MAP = {
  '2.5.4.3': 'CN',           // Common Name
  '2.5.4.6': 'C',            // Country
  '2.5.4.7': 'L',            // Locality
  '2.5.4.8': 'ST',           // State/Province
  '2.5.4.10': 'O',           // Organization
  '2.5.4.11': 'OU',          // Organizational Unit
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.2.1': 'ecPublicKey',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10045.3.1.7': 'secp256r1',
  '1.3.132.0.34': 'secp384r1',
  '1.3.132.0.35': 'secp521r1',
  '2.5.29.15': 'keyUsage',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.35': 'authorityKeyIdentifier',
  '2.5.29.14': 'subjectKeyIdentifier',
  '2.5.29.37': 'extendedKeyUsage',
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection'
};

// Utility functions
export function parseOid(content) {
  if (content.length === 0) return '';
  
  const result = [];
  let value = content[0];
  result.push(Math.floor(value / 40));
  result.push(value % 40);
  
  let current = 0;
  for (let i = 1; i < content.length; i++) {
    const byte = content[i];
    current = (current << 7) | (byte & 0x7F);
    
    if ((byte & 0x80) === 0) {
      result.push(current);
      current = 0;
    }
  }
  
  const oidString = result.join('.');
  return OID_MAP[oidString] || oidString;
}

export function parseTime(content, isGeneralized = false) {
  const timeStr = new TextDecoder('ascii').decode(content);
  
  if (isGeneralized) {
    // GeneralizedTime: YYYYMMDDHHMMSSZ
    const match = timeStr.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/);
    if (match) {
      const [, year, month, day, hour, minute, second] = match;
      return new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}Z`);
    }
  } else {
    // UTCTime: YYMMDDHHMMSSZ (YY >= 50 means 19xx, else 20xx)
    const match = timeStr.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/);
    if (match) {
      let [, year, month, day, hour, minute, second] = match;
      year = parseInt(year) >= 50 ? `19${year}` : `20${year}`;
      return new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}Z`);
    }
  }
  
  return new Date(); // fallback
}

export function parseString(content) {
  return new TextDecoder('utf-8').decode(content);
}

export function parseInteger(content) {
  let result = 0;
  for (let i = 0; i < Math.min(content.length, 8); i++) {
    result = (result << 8) | content[i];
  }
  return result;
}

export function parseBitString(content) {
  if (content.length === 0) return new Uint8Array();
  const unusedBits = content[0];
  return content.slice(1);
}

// Parse DN (Distinguished Name)
export function parseDN(dnSeq) {
  const parser = new ASN1Parser(dnSeq.content);
  const dnComponents = [];
  
  try {
    while (parser.pos < parser.data.length) {
      const rdnSet = parser.parseObject();
      if (rdnSet.isSet()) {
        const rdnParser = new ASN1Parser(rdnSet.content);
        while (rdnParser.pos < rdnParser.data.length) {
          const attrSeq = rdnParser.parseObject();
          if (attrSeq.isSequence()) {
            const attrParser = new ASN1Parser(attrSeq.content);
            const oid = attrParser.parseObject();
            const value = attrParser.parseObject();
            
            if (oid.isOid()) {
              const attrName = parseOid(oid.content);
              const attrValue = parseString(value.content);
              dnComponents.push(`${attrName}=${attrValue}`);
            }
          }
        }
      }
    }
  } catch (e) {
    // If parsing fails, return what we have
  }
  
  return dnComponents.join(', ');
}

export { ASN1Parser };