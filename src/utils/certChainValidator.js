// Basic certificate chain validation utilities
import { ASN1Parser, parseOid, parseTime, parseString, parseInteger, parseBitString, parseDN } from './asn1Parser';

export class CertificateChainValidator {
  constructor() {
    this.certificates = [];
  }

  // Parse multiple PEM certificates from input
  parseCertificateChain(pemChain) {
    const certificates = [];
    const pemBlocks = pemChain.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    
    if (!pemBlocks) {
      throw new Error('No valid certificate blocks found');
    }

    for (let i = 0; i < pemBlocks.length; i++) {
      try {
        const pemBlock = pemBlocks[i];
        const base64Data = pemBlock
          .replace(/-----BEGIN CERTIFICATE-----/, '')
          .replace(/-----END CERTIFICATE-----/, '')
          .replace(/\s+/g, '');
        
        const der = this.base64ToBuf(base64Data);
        const certInfo = this.parseCertificateFromDER(der, i);
        
        certificates.push({
          index: i,
          pem: pemBlock,
          der: der,
          ...certInfo
        });
      } catch (error) {
        certificates.push({
          index: i,
          error: `Certificate ${i + 1}: ${error.message}`,
          pem: pemBlocks[i]
        });
      }
    }

    this.certificates = certificates;
    return certificates;
  }

  // Basic chain validation
  validateChain() {
    if (this.certificates.length === 0) {
      return { valid: false, error: 'No certificates to validate' };
    }

    const validCerts = this.certificates.filter(cert => !cert.error);
    if (validCerts.length === 0) {
      return { valid: false, error: 'No valid certificates in chain' };
    }

    const results = {
      valid: true,
      chainLength: this.certificates.length,
      validCertificates: validCerts.length,
      invalidCertificates: this.certificates.length - validCerts.length,
      issues: [],
      warnings: [],
      endEntity: null,
      intermediates: [],
      rootCA: null
    };

    // Identify certificate roles
    for (const cert of validCerts) {
      if (cert.basicConstraints?.includes('CA: TRUE')) {
        if (cert.subject === cert.issuer) {
          results.rootCA = cert;
        } else {
          results.intermediates.push(cert);
        }
      } else {
        if (!results.endEntity) {
          results.endEntity = cert;
        } else {
          results.warnings.push('Multiple end-entity certificates found');
        }
      }
    }

    // Basic chain structure validation
    if (!results.endEntity) {
      results.issues.push('No end-entity certificate found (should have CA: FALSE)');
    }

    if (validCerts.length > 1 && !results.rootCA && results.intermediates.length === 0) {
      results.warnings.push('Chain appears incomplete - no CA certificates found');
    }

    // Check certificate validity periods
    const now = new Date();
    for (const cert of validCerts) {
      if (cert.validTo < now) {
        results.issues.push(`Certificate ${cert.index + 1} has expired (${cert.subject})`);
      }
      if (cert.validFrom > now) {
        results.issues.push(`Certificate ${cert.index + 1} is not yet valid (${cert.subject})`);
      }
    }

    // Check subject/issuer relationships
    if (validCerts.length > 1) {
      const chainOrder = this.orderCertificateChain(validCerts);
      if (chainOrder.length !== validCerts.length) {
        results.warnings.push('Could not establish complete certificate chain order');
      } else {
        // Validate issuer/subject chain
        for (let i = 0; i < chainOrder.length - 1; i++) {
          const cert = chainOrder[i];
          const issuer = chainOrder[i + 1];
          
          if (cert.issuer !== issuer.subject) {
            results.issues.push(`Certificate ${cert.index + 1} issuer does not match certificate ${issuer.index + 1} subject`);
          }
        }
      }
    }

    // Check for weak signature algorithms
    for (const cert of validCerts) {
      if (cert.signatureAlgorithm) {
        if (cert.signatureAlgorithm.includes('md5') || cert.signatureAlgorithm.includes('sha1')) {
          results.issues.push(`Certificate ${cert.index + 1} uses weak signature algorithm: ${cert.signatureAlgorithm}`);
        }
      }
    }

    results.valid = results.issues.length === 0;
    return results;
  }

  // Attempt to order certificates in a chain
  orderCertificateChain(certificates) {
    const ordered = [];
    const remaining = [...certificates];

    // Find end-entity certificate (not a CA)
    let current = remaining.find(cert => !cert.basicConstraints?.includes('CA: TRUE'));
    if (!current) {
      // If no clear end-entity, start with any certificate
      current = remaining[0];
    }

    while (current && remaining.length > 0) {
      ordered.push(current);
      remaining.splice(remaining.indexOf(current), 1);

      // Find the issuer of the current certificate
      current = remaining.find(cert => cert.subject === current.issuer);
    }

    return ordered;
  }

  // Helper method to parse certificate from DER
  parseCertificateFromDER(der, index) {
    const parser = new ASN1Parser(der);
    const cert = parser.parseObject();
    
    if (!cert.isSequence()) {
      throw new Error('Certificate must be a SEQUENCE');
    }
    
    const certChildren = parser.parseSequence(cert);
    if (certChildren.length < 3) {
      throw new Error('Invalid certificate structure');
    }
    
    const tbsCertificate = certChildren[0];
    const signatureAlgorithm = certChildren[1];
    
    // Parse TBSCertificate
    const tbsParser = new ASN1Parser(tbsCertificate.content);
    const tbsChildren = tbsParser.parseAll();
    
    let tbsIndex = 0;
    
    // Version (optional, default v1)
    let version = 1;
    if (tbsChildren[tbsIndex] && tbsChildren[tbsIndex].isContext(0)) {
      const versionParser = new ASN1Parser(tbsChildren[tbsIndex].content);
      const versionObj = versionParser.parseObject();
      if (versionObj.isInteger()) {
        version = parseInteger(versionObj.content) + 1;
      }
      tbsIndex++;
    }
    
    // Serial Number
    const serialNumberObj = tbsChildren[tbsIndex++];
    let serialNumber = 'Unknown';
    if (serialNumberObj && serialNumberObj.isInteger()) {
      serialNumber = '0x' + Array.from(serialNumberObj.content)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('').toUpperCase();
    }
    
    // Skip signature algorithm
    tbsIndex++;
    
    // Issuer
    const issuerObj = tbsChildren[tbsIndex++];
    let issuer = 'Unknown Issuer';
    if (issuerObj && issuerObj.isSequence()) {
      issuer = parseDN(issuerObj);
    }
    
    // Validity
    const validityObj = tbsChildren[tbsIndex++];
    let validFrom = new Date();
    let validTo = new Date();
    if (validityObj && validityObj.isSequence()) {
      const validityParser = new ASN1Parser(validityObj.content);
      const validityChildren = validityParser.parseAll();
      if (validityChildren.length >= 2) {
        const notBefore = validityChildren[0];
        const notAfter = validityChildren[1];
        
        if (notBefore.isUtcTime()) {
          validFrom = parseTime(notBefore.content, false);
        } else if (notBefore.isGeneralizedTime()) {
          validFrom = parseTime(notBefore.content, true);
        }
        
        if (notAfter.isUtcTime()) {
          validTo = parseTime(notAfter.content, false);
        } else if (notAfter.isGeneralizedTime()) {
          validTo = parseTime(notAfter.content, true);
        }
      }
    }
    
    // Subject
    const subjectObj = tbsChildren[tbsIndex++];
    let subject = 'Unknown Subject';
    if (subjectObj && subjectObj.isSequence()) {
      subject = parseDN(subjectObj);
    }
    
    // Extensions - look for Basic Constraints
    let basicConstraints = 'CA: FALSE'; // default
    
    if (tbsIndex + 1 < tbsChildren.length && tbsChildren[tbsIndex + 1] && tbsChildren[tbsIndex + 1].isContext(3)) {
      const extensionsObj = tbsChildren[tbsIndex + 1];
      const extensionsParser = new ASN1Parser(extensionsObj.content);
      const extensionsSeq = extensionsParser.parseObject();
      
      if (extensionsSeq.isSequence()) {
        const extensionsSeqParser = new ASN1Parser(extensionsSeq.content);
        const extensions = extensionsSeqParser.parseAll();
        
        for (const ext of extensions) {
          if (ext.isSequence()) {
            const extParser = new ASN1Parser(ext.content);
            const extChildren = extParser.parseAll();
            
            if (extChildren.length >= 2) {
              const oidObj = extChildren[0];
              let valueObj = extChildren[extChildren.length - 1];
              
              if (oidObj.isOid() && valueObj.isOctetString()) {
                const oid = parseOid(oidObj.content);
                
                if (oid === 'basicConstraints') {
                  const bcParser = new ASN1Parser(valueObj.content);
                  const bcSeq = bcParser.parseObject();
                  if (bcSeq.isSequence()) {
                    const bcSeqParser = new ASN1Parser(bcSeq.content);
                    const bcChildren = bcSeqParser.parseAll();
                    let isCA = false;
                    if (bcChildren.length > 0 && bcChildren[0].tag.tagNumber === 1) {
                      isCA = bcChildren[0].content[0] !== 0;
                    }
                    basicConstraints = isCA ? 'CA: TRUE' : 'CA: FALSE';
                  }
                  break;
                }
              }
            }
          }
        }
      }
    }
    
    // Parse signature algorithm
    let signatureAlgorithmName = 'Unknown';
    if (signatureAlgorithm.isSequence()) {
      const sigAlgParser = new ASN1Parser(signatureAlgorithm.content);
      const sigOidObj = sigAlgParser.parseObject();
      if (sigOidObj.isOid()) {
        signatureAlgorithmName = parseOid(sigOidObj.content);
      }
    }
    
    return {
      version,
      serialNumber,
      subject,
      issuer,
      validFrom,
      validTo,
      signatureAlgorithm: signatureAlgorithmName,
      basicConstraints
    };
  }

  // Helper method to convert base64 to buffer
  base64ToBuf(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes.buffer;
  }
}