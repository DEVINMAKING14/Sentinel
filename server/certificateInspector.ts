import tls from 'tls';
import { TlsCertificateAnalysis, Finding } from './types';
import { SsrfValidationResult, validateUrlForSsrf } from './ssrf';

export interface CertificateInspectionResult {
  certificate: TlsCertificateAnalysis;
  findings: Finding[];
}

/**
 * Perform a real TLS socket probe against the given hostname.
 */
export async function inspectTlsCertificate(
  domain: string,
  port = 443,
  initialValidation?: SsrfValidationResult,
): Promise<CertificateInspectionResult> {
  const findings: Finding[] = [];
  const notes: string[] = [];
  let trustScore = 100;

  // SSRF validation before establishing TLS socket
  const urlHost = domain.includes(':') ? `[${domain}]` : domain;
  const ssrfCheck = initialValidation || await validateUrlForSsrf(`https://${urlHost}:${port}`);
  if (!ssrfCheck.safe) {
    findings.push({
      id: 'tls-ssrf-blocked',
      category: 'SSL_TLS',
      severity: 'CRITICAL',
      title: 'TLS Probe Aborted: Restricted Network Destination',
      technicalDetails: ssrfCheck.reason || 'Target domain resolves to private or loopback infrastructure.',
      evidence: domain,
      impact: 'Prevents SSRF probes against internal enterprise services.',
      remediation: 'Inspect DNS configurations for anomalous internal host mapping.',
    });

    return {
      certificate: {
        valid: false,
        subject: {},
        issuer: {},
        validFrom: '',
        validTo: '',
        daysRemaining: 0,
        isExpired: true,
        subjectAltNames: [],
        hostnameMatch: false,
        isSelfSigned: false,
        trustScore: 0,
        notes: ['SSRF protection stopped connection.'],
      },
      findings,
    };
  }

  return new Promise(resolve => {
    const socket = tls.connect(
      {
        host: domain,
        port,
        servername: domain,
        rejectUnauthorized: false, // We inspect invalid/expired/self-signed certs directly
        timeout: 6000,
        lookup: (_hostname, options, callback) => {
          const pinned = ssrfCheck.resolvedAddresses?.[0];
          if (!pinned) {
            const error = new Error('No validated address is available for this TLS connection.');
            if (options.all) callback(error, []);
            else callback(error, '', 0);
            return;
          }
          if (options.all) callback(null, [pinned]);
          else callback(null, pinned.address, pinned.family);
        },
      },
      () => {
        try {
          const rawCert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol() || undefined;
          const cipherInfo = socket.getCipher();
          const cipher = cipherInfo ? `${cipherInfo.name} (${cipherInfo.version})` : undefined;

          if (!rawCert || Object.keys(rawCert).length === 0) {
            socket.destroy();
            resolve({
              certificate: createEmptyAnalysis(false, 'No peer certificate presented by server.'),
              findings: [
                {
                  id: 'tls-no-cert',
                  category: 'SSL_TLS',
                  severity: 'HIGH',
                  title: 'No SSL/TLS Certificate Presented',
                  technicalDetails: 'Target server closed TLS handshake without returning an X.509 server certificate.',
                  evidence: `Host: ${domain}:${port}`,
                  impact: 'Client traffic cannot be cryptographically encrypted or verified.',
                  remediation: 'Provision and configure a valid TLS certificate on the web listener.',
                },
              ],
            });
            return;
          }

          // Parse certificate details
          const validFrom = rawCert.valid_from;
          const validTo = rawCert.valid_to;
          const validToDate = new Date(validTo);
          const now = new Date();
          const msRemaining = validToDate.getTime() - now.getTime();
          const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));
          const isExpired = daysRemaining < 0;

          // Helper to normalize multi-value or single string certificate attributes
          const toSingleString = (val: string | string[] | undefined): string | undefined => {
            if (!val) return undefined;
            return Array.isArray(val) ? val.join(', ') : val;
          };

          // Parse Subject and Issuer
          const subject = {
            commonName: toSingleString(rawCert.subject?.CN),
            organization: toSingleString(rawCert.subject?.O),
            country: toSingleString(rawCert.subject?.C),
          };
          const issuer = {
            commonName: toSingleString(rawCert.issuer?.CN),
            organization: toSingleString(rawCert.issuer?.O),
            country: toSingleString(rawCert.issuer?.C),
          };

          // Parse SANs
          const rawSans = rawCert.subjectaltname || '';
          const subjectAltNames = rawSans
            ? rawSans.split(',').map(s => s.trim().replace(/^DNS:/i, ''))
            : [];

          // Hostname match check
          const hostnameMatch = checkHostnameMatch(domain, subject.commonName, subjectAltNames);

          // Self-signed check
          const isSelfSigned = Boolean(
            (rawCert.fingerprint && rawCert.fingerprint === rawCert.issuerCertificate?.fingerprint) ||
            (subject.commonName && subject.commonName === issuer.commonName && subject.organization === issuer.organization)
          );

          // Key size
          const keyBits = rawCert.bits;
          const pubKeyType = rawCert.asn1Curve ? `EC (${rawCert.asn1Curve})` : 'RSA';

          // Check TLS protocol version
          if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
            trustScore -= 30;
            findings.push({
              id: 'tls-deprecated-version',
              category: 'SSL_TLS',
              severity: 'HIGH',
              title: `Deprecated TLS Version Negotiated (${protocol})`,
              technicalDetails: `Server negotiated an obsolete TLS protocol version: ${protocol}. Deprecated by RFC 8996 due to known cryptographic weaknesses.`,
              evidence: `Protocol: ${protocol}`,
              impact: 'Prone to cipher suite downgrade and chosen-ciphertext attacks.',
              remediation: 'Disable TLS 1.0 and 1.1; enforce TLS 1.2 and TLS 1.3 only.',
            });
          }

          // Check expiration
          if (isExpired) {
            trustScore -= 50;
            findings.push({
              id: 'tls-cert-expired',
              category: 'SSL_TLS',
              severity: 'CRITICAL',
              title: 'SSL/TLS Certificate Has Expired',
              technicalDetails: `Certificate expired on ${validTo} (${Math.abs(daysRemaining)} days ago).`,
              evidence: `Valid To: ${validTo}`,
              impact: 'Browsers display security interstitial block screens; trust anchor is broken.',
              remediation: 'Immediately renew and deploy a valid certificate via your Certificate Authority.',
            });
          } else if (daysRemaining < 14) {
            trustScore -= 15;
            notes.push(`Certificate expires soon: ${daysRemaining} days remaining.`);
            findings.push({
              id: 'tls-cert-expiring-soon',
              category: 'SSL_TLS',
              severity: 'MEDIUM',
              title: 'SSL/TLS Certificate Imminently Expiring',
              technicalDetails: `Certificate expires in ${daysRemaining} days.`,
              evidence: `Valid To: ${validTo}`,
              impact: 'Risk of unexpected service outage or certificate interstitial warnings.',
              remediation: 'Trigger automated ACME certificate renewal process.',
            });
          }

          // Check self-signed
          if (isSelfSigned) {
            trustScore -= 45;
            findings.push({
              id: 'tls-self-signed',
              category: 'SSL_TLS',
              severity: 'CRITICAL',
              title: 'Self-Signed SSL/TLS Certificate Detected',
              technicalDetails: 'The certificate was signed by itself and is not anchored to a trusted Root CA in public trust stores.',
              evidence: `Subject: ${subject.commonName} | Issuer: ${issuer.commonName}`,
              impact: 'Vulnerable to active Man-in-the-Middle intercept; browser warning alerts end users.',
              remediation: 'Obtain an authentic certificate issued by a recognized public or enterprise CA.',
            });
          }

          // Check hostname mismatch
          if (!hostnameMatch) {
            trustScore -= 40;
            findings.push({
              id: 'tls-hostname-mismatch',
              category: 'SSL_TLS',
              severity: 'CRITICAL',
              title: 'SSL/TLS Hostname Mismatch',
              technicalDetails: `Target domain '${domain}' does not match certificate Common Name '${subject.commonName}' or Subject Alternative Names.`,
              evidence: `Target: ${domain} | Cert CN: ${subject.commonName || 'N/A'} | SANs: ${subjectAltNames.slice(0, 3).join(', ')}`,
              impact: 'Browsers reject connection with ERR_CERT_COMMON_NAME_INVALID.',
              remediation: 'Ensure SAN list includes all active domain and subdomain aliases.',
            });
          }

          // Check weak key size
          if (pubKeyType.startsWith('RSA') && keyBits && keyBits < 2048) {
            trustScore -= 25;
            findings.push({
              id: 'tls-weak-key-size',
              category: 'SSL_TLS',
              severity: 'HIGH',
              title: `Weak RSA Public Key Length (${keyBits} bits)`,
              technicalDetails: 'Key sizes below 2048 bits are considered cryptographically vulnerable to factorisation.',
              evidence: `Key size: ${keyBits} bits`,
              impact: 'Private key may be factored given sufficient computational capabilities.',
              remediation: 'Generate a new private key with at least RSA 2048 bits or ECDSA P-256.',
            });
          }

          // Note about phishing with valid certs
          notes.push('Crucial: A valid TLS certificate provides cryptographic transport privacy, but does NOT verify that the website owner is benevolent or authentic.');

          socket.destroy();

          const finalScore = Math.max(0, Math.min(100, trustScore));

          resolve({
            certificate: {
              valid: !isExpired && !isSelfSigned && hostnameMatch,
              subject,
              issuer,
              validFrom,
              validTo,
              daysRemaining,
              isExpired,
              subjectAltNames,
              hostnameMatch,
              isSelfSigned,
              signatureAlgorithm: (rawCert as any).sigalg || (rawCert as any).signatureAlgorithm || 'sha256WithRSAEncryption',
              publicKeyAlgorithm: pubKeyType,
              keySizeBits: keyBits,
              cipher,
              protocol,
              trustScore: finalScore,
              notes,
            },
            findings,
          });
        } catch (err: unknown) {
          socket.destroy();
          const errMsg = err instanceof Error ? err.message : String(err);
          resolve({
            certificate: createEmptyAnalysis(false, `Parsing error: ${errMsg}`),
            findings: [],
          });
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        certificate: createEmptyAnalysis(false, 'TLS handshake timed out.'),
        findings: [
          {
            id: 'tls-handshake-timeout',
            category: 'SSL_TLS',
            severity: 'INFORMATIONAL',
            title: 'TLS Socket Handshake Timeout',
            technicalDetails: 'Server did not complete TLS negotiation within the 6000ms threshold.',
            evidence: `Domain: ${domain}`,
            impact: 'Cannot evaluate TLS parameters.',
            remediation: 'Check firewall egress and listener status.',
          },
        ],
      });
    });

    socket.on('error', err => {
      socket.destroy();
      resolve({
        certificate: createEmptyAnalysis(false, `TLS connection error: ${err.message}`),
        findings: [
          {
            id: 'tls-socket-error',
            category: 'SSL_TLS',
            severity: 'INFORMATIONAL',
            title: 'TLS Socket Connection Refused / Error',
            technicalDetails: err.message,
            evidence: `Domain: ${domain}`,
            impact: 'HTTPS endpoint could not be inspected over port 443.',
            remediation: 'Verify whether service is listening on port 443.',
          },
        ],
      });
    });
  });
}

function checkHostnameMatch(domain: string, cn?: string, sans: string[] = []): boolean {
  const normDomain = domain.toLowerCase();

  // Test against Common Name
  if (cn && matchesPattern(normDomain, cn.toLowerCase())) {
    return true;
  }

  // Test against SANs
  for (const san of sans) {
    if (matchesPattern(normDomain, san.toLowerCase())) {
      return true;
    }
  }

  return false;
}

function matchesPattern(domain: string, pattern: string): boolean {
  if (domain === pattern) return true;
  if (pattern.startsWith('*.')) {
    const rootPattern = pattern.slice(2);
    const domainParts = domain.split('.');
    if (domainParts.length > 2) {
      const domainRoot = domainParts.slice(1).join('.');
      return domainRoot === rootPattern;
    }
  }
  return false;
}

function createEmptyAnalysis(valid: boolean, note: string): TlsCertificateAnalysis {
  return {
    valid,
    subject: {},
    issuer: {},
    validFrom: '',
    validTo: '',
    daysRemaining: 0,
    isExpired: false,
    subjectAltNames: [],
    hostnameMatch: false,
    isSelfSigned: false,
    trustScore: 0,
    notes: [note],
  };
}
