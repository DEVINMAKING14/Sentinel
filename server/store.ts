import { ScanResult, DashboardOverview, ThreatReport } from './types';
import { getAllThreatReports } from './threatIntel';

// Seeded realistic scan history to provide immediate analytical value
function getInitialScans(): ScanResult[] {
  return [
  {
    id: 'SNT-08472',
    targetUrl: 'https://paytm-secure-login.com',
    domain: 'paytm-secure-login.com',
    timestamp: 'Jan 26, 2025 · 14:32',
    scanDurationMs: 18400,
    resolvedIp: '104.21.56.198',
    hostingProvider: 'Cloudflare, Inc. (US)',
    asn: 'AS13335',
    timelineEvents: [
      { timestamp: '14:32:10', label: 'Scan initiated', status: 'done' },
      { timestamp: '14:32:12', label: 'Domain & DNS analysis completed', status: 'done' },
      { timestamp: '14:32:16', label: 'Certificate validation completed', status: 'done' },
      { timestamp: '14:32:19', label: 'Web security scan completed', status: 'done' },
      { timestamp: '14:32:24', label: 'Threat intelligence matched (3 sources)', status: 'done' },
      { timestamp: '14:32:28', label: 'Risk assessment generated (87/100)', status: 'alert' },
    ],
    detectionModel: 'GEMINI_AI',
    riskScore: 87,
    riskCategory: 'HIGH',
    confidenceScore: 96,
    dimensionalScores: {
      phishingScore: 35,
      securityHeadersScore: 20,
      tlsTrustScore: 20,
      threatIntelScore: 25,
    },
    reasons: [
      'Domain closely resembles a trusted brand (paytm-secure-login.com vs paytm.com, 92% similarity)',
      'Password collection form detected (HTML form with password and OTP fields)',
      'Suspicious redirect chain (Redirects through 2 intermediate domains)',
      'Threat intelligence matched across 3 community telemetry sources',
    ],
    recommendations: [
      'Do not enter any personal, banking or payment information on this website.',
      'Block domain paytm-secure-login.com and 104.21.56.198 across perimeter proxies.',
      'Submit automated takedown notice to Cloudflare trust & safety.',
    ],
    findings: [
      {
        id: 'f-paytm-1',
        category: 'PHISHING',
        severity: 'HIGH',
        title: 'Domain closely resembles a trusted brand',
        technicalDetails: 'Target domain mimics authentic Paytm payment portal with calculated 92% Levenshtein similarity metric.',
        evidence: 'paytm-secure-login.com vs paytm.com (92% similarity)',
        impact: 'Deceives mobile banking users into entering 6-digit MPIN and OTP tokens.',
        remediation: 'Sinkhole domain and initiate brand infringement takedown.',
      },
      {
        id: 'f-paytm-2',
        category: 'PHISHING',
        severity: 'HIGH',
        title: 'Password collection form detected',
        technicalDetails: 'DOM contains input fields configured for password, mobile number, and one-time passcode collection without origin verification.',
        evidence: 'HTML form with password and OTP fields',
        impact: 'Direct exfiltration of multi-factor authentication tokens to adversary infrastructure.',
        remediation: 'Do not submit credentials; isolate workstation.',
      },
      {
        id: 'f-paytm-3',
        category: 'REDIRECTION',
        severity: 'MEDIUM',
        title: 'Suspicious redirect chain',
        technicalDetails: 'Initial connection traverses 2 intermediate redirection hops designed to evade automated email boundary filters.',
        evidence: 'Redirects through 2 intermediate domains',
        impact: 'Obfuscates actual payload host from perimeter sandboxes.',
        remediation: 'Enforce gateway inspection on all redirect hops.',
      },
      {
        id: 'f-paytm-4',
        category: 'SECURITY_HEADERS',
        severity: 'HIGH',
        title: 'Missing Content-Security-Policy (CSP)',
        technicalDetails: 'No CSP headers delivered; enables arbitrary inline payload execution.',
        evidence: 'Header absent',
        impact: 'Facilitates client-side injection and credential forwarding.',
        remediation: 'Implement restrictive Content-Security-Policy.',
      },
      {
        id: 'f-paytm-5',
        category: 'SECURITY_HEADERS',
        severity: 'MEDIUM',
        title: 'Weak Transport Security (Missing HSTS)',
        technicalDetails: 'Strict-Transport-Security header omitted.',
        evidence: 'Header absent',
        impact: 'Exposes users to SSL stripping MitM.',
        remediation: 'Configure HSTS with preload.',
      },
      {
        id: 'f-paytm-6',
        category: 'SSL_TLS',
        severity: 'LOW',
        title: 'Automated Domain-Validated Certificate on Phishing Host',
        technicalDetails: 'Valid DV certificate issued by Let\'s Encrypt; demonstrates TLS does not verify identity.',
        evidence: 'Issuer: R3 / Let\'s Encrypt',
        impact: 'Presents green padlock in browsers, generating deceptive user confidence.',
        remediation: 'Do not rely on TLS padlock as confirmation of business legitimacy.',
      },
    ],
    phishingAnalysis: {
      probability: 0.87,
      riskCategory: 'HIGH',
      indicators: [
        'Paytm brand impersonation (92% similarity)',
        'Password and OTP input form',
        '2 hops redirect chain',
        '3 community threat reports',
      ],
      homoglyphsDetected: [],
      typosquattingMatch: { brand: 'Paytm', distance: 0, legitDomain: 'paytm.com' },
      urlLength: 32,
      subdomainCount: 0,
      suspiciousKeywords: ['secure', 'login'],
      isIpHost: false,
      hasSuspiciousTld: false,
      detectedFormsCount: 1,
      hasCredentialInputs: true,
    },
    securityHeaders: {
      csp: { present: false, status: 'CRITICAL', notes: 'Missing CSP header.' },
      hsts: { present: false, status: 'CRITICAL', notes: 'Missing HSTS.' },
      xFrameOptions: { present: false, status: 'CRITICAL', notes: 'Missing X-Frame-Options.' },
      xContentTypeOptions: { present: true, status: 'GOOD', notes: 'nosniff' },
      referrerPolicy: { present: false, status: 'WARNING', notes: 'Default' },
      permissionsPolicy: { present: false, status: 'WARNING', notes: 'Default' },
      serverHeader: 'cloudflare',
      cookiesAnalysis: { total: 2, insecureCookies: ['session_track'], missingHttpOnly: [], missingSameSite: [] },
      overallHeaderScore: 20,
    },
    tlsCertificate: {
      valid: true,
      subject: { commonName: 'paytm-secure-login.com' },
      issuer: { commonName: 'R3', organization: 'Let\'s Encrypt', country: 'US' },
      validFrom: 'Jan 10, 2025',
      validTo: 'Apr 10, 2025',
      daysRemaining: 74,
      isExpired: false,
      subjectAltNames: ['paytm-secure-login.com', 'www.paytm-secure-login.com'],
      hostnameMatch: true,
      isSelfSigned: false,
      signatureAlgorithm: 'sha256WithRSAEncryption',
      publicKeyAlgorithm: 'EC (prime256v1)',
      keySizeBits: 256,
      cipher: 'TLS_AES_128_GCM_SHA256 (TLSv1.3)',
      protocol: 'TLSv1.3',
      trustScore: 70,
      notes: ['Valid TLS certificate present. Transport is encrypted but domain is malicious.'],
    },
    threatIntelMatches: [
      {
        source: 'Sentinel Community Threat Exchange',
        category: 'KNOWN_PHISHING',
        matchedValue: 'paytm-secure-login.com',
        confidence: 96,
        firstSeen: 'Jan 26, 2025 · 14:32',
        reportCount: 3,
        tags: ['Phishing', 'Target:Paytm', 'CredentialStealer'],
      },
    ],
    redirectChain: [
      { hopIndex: 1, url: 'http://auth-relay.link/paytm', statusCode: 302, isExternalDomain: true },
      { hopIndex: 2, url: 'https://paytm-secure-login.com/login', statusCode: 200, isExternalDomain: false },
    ],
    aiAssessment: {
      analystSummary: 'Active credential phishing campaign targeting Paytm digital wallet and payments users. Features an OTP collection workflow masquerading behind Cloudflare proxy infrastructure.',
      threatActorsOrMotivation: 'Financial threat actor harvesting Indian payment ecosystem credentials and SMS OTPs.',
      psychologicalTactics: [
        'Urgency: Account verification / KYC expiration prompt',
        'Brand Familiarity: Visual replication of Paytm portal colors and logos',
      ],
      mitreAttackTechniques: [
        { id: 'T1566.002', name: 'Spearphishing Link', description: 'Distribution of credential-harvesting hyperlinked URLs.' },
        { id: 'T1656', name: 'Impersonation', description: 'Masquerading as authentic financial brand.' },
        { id: 'T1552', name: 'Unsecured Credentials', description: 'Stealing credentials and secondary authentication factors.' },
      ],
      userActionGuidance: [
        'Do not enter personal, banking or payment information.',
        'Reset authentic Paytm account password if credentials were submitted.',
      ],
      socRemediationSteps: [
        'Block paytm-secure-login.com and 104.21.56.198 at border firewalls.',
        'Issue abuse notification to Cloudflare and domain registrar.',
      ],
      confidenceLevel: 'VERY_HIGH',
    },
    isDemoFixture: true,
  },
  {
    id: 'scn-9021-paypal-lure',
    targetUrl: 'http://paypa1-secure-verification.login-portal.cc/account-verify',
    domain: 'login-portal.cc',
    timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
    scanDurationMs: 1420,
    resolvedIp: '198.51.100.42',
    riskScore: 94,
    riskCategory: 'CRITICAL',
    confidenceScore: 98,
    dimensionalScores: {
      phishingScore: 95,
      securityHeadersScore: 15,
      tlsTrustScore: 10,
      threatIntelScore: 98,
    },
    reasons: [
      'Homoglyph IDN & Typosquatting: Permutation of protected brand PayPal (dist: 1)',
      'Subdomain brand masquerading in login-portal.cc',
      'Credential input form extracting credentials without verified TLS',
      'Positive hit in Sentinel Community Threat Intelligence Feed',
    ],
    recommendations: [
      'DO NOT enter usernames, passwords, or SMS verification codes.',
      'Block domain login-portal.cc and associated IPs on enterprise perimeter.',
      'Submit emergency abuse takedown notification to registrar.',
    ],
    findings: [
      {
        id: 'f-1',
        category: 'PHISHING',
        severity: 'CRITICAL',
        title: 'Typosquatting & Brand Masquerading (PayPal)',
        technicalDetails: 'The domain prefix paypa1 mimics PayPal via deliberate l33t-speak character substitution.',
        evidence: 'paypa1-secure-verification.login-portal.cc',
        impact: 'Deceives end-users into entering payment credentials.',
        remediation: 'Sinkhole domain and initiate brand infringement takedown.',
      },
      {
        id: 'f-2',
        category: 'SSL_TLS',
        severity: 'CRITICAL',
        title: 'Plaintext HTTP Transport on Sensitive Verification Portal',
        technicalDetails: 'Target uses unencrypted http:// transport with no TLS certificate protection.',
        evidence: 'Protocol: http:',
        impact: 'Exposes all transmitted data to unencrypted local network capture.',
        remediation: 'Never use plaintext HTTP for authentication.',
      },
      {
        id: 'f-3',
        category: 'SECURITY_HEADERS',
        severity: 'HIGH',
        title: 'Missing Content-Security-Policy (CSP)',
        technicalDetails: 'Response lacks Content-Security-Policy headers.',
        evidence: 'Header absent',
        impact: 'Allows arbitrary script injection and credential forwarding.',
        remediation: 'Implement restrictive CSP.',
      },
    ],
    phishingAnalysis: {
      probability: 0.95,
      riskCategory: 'CRITICAL',
      indicators: [
        'Typosquatting permutation of PayPal',
        'Subdomain brand masquerade',
        'Suspicious keywords: verify, account, secure',
        'Credential harvesting input forms detected',
      ],
      homoglyphsDetected: [],
      typosquattingMatch: { brand: 'PayPal', distance: 1, legitDomain: 'paypal.com' },
      urlLength: 68,
      subdomainCount: 2,
      suspiciousKeywords: ['verify', 'account', 'secure'],
      isIpHost: false,
      hasSuspiciousTld: true,
      detectedFormsCount: 1,
      hasCredentialInputs: true,
    },
    securityHeaders: {
      csp: { present: false, status: 'CRITICAL', notes: 'Missing CSP header.' },
      hsts: { present: false, status: 'CRITICAL', notes: 'Missing HSTS header.' },
      xFrameOptions: { present: false, status: 'CRITICAL', notes: 'Missing X-Frame-Options.' },
      xContentTypeOptions: { present: false, status: 'WARNING', notes: 'Missing nosniff.' },
      referrerPolicy: { present: false, status: 'WARNING', notes: 'No referrer policy.' },
      permissionsPolicy: { present: false, status: 'WARNING', notes: 'No permissions policy.' },
      serverHeader: 'nginx/1.18.0',
      cookiesAnalysis: { total: 0, insecureCookies: [], missingHttpOnly: [], missingSameSite: [] },
      overallHeaderScore: 15,
    },
    tlsCertificate: {
      valid: false,
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
      notes: ['No TLS certificate configured on HTTP endpoint.'],
    },
    threatIntelMatches: [
      {
        source: 'Sentinel Community Threat Exchange',
        category: 'KNOWN_PHISHING',
        matchedValue: 'login-portal.cc',
        confidence: 98,
        firstSeen: new Date(Date.now() - 3600000 * 4).toISOString(),
        reportCount: 24,
        tags: ['Phishing', 'Target:PayPal'],
      },
    ],
    redirectChain: [
      { hopIndex: 1, url: 'http://paypa1-secure-verification.login-portal.cc/account-verify', statusCode: 200, isExternalDomain: false },
    ],
    aiAssessment: {
      analystSummary: 'High-confidence credential phishing infrastructure masquerading as PayPal Account Resolution Center. Utilizes typosquatting and unencrypted endpoints to harvest user accounts.',
      threatActorsOrMotivation: 'Financial credential harvesting ring targeting digital wallet accounts.',
      psychologicalTactics: [
        'Urgency and Fear: Impending account suspension notice',
        'Authority Masquerading: Spoofing familiar financial service brand logos and wording',
      ],
      mitreAttackTechniques: [
        { id: 'T1566.002', name: 'Phishing: Spearphishing Link', description: 'Distribution of credential-harvesting hyperlinked URLs.' },
        { id: 'T1656', name: 'Impersonation', description: 'Masquerading as authentic organization.' },
      ],
      userActionGuidance: [
        'Do not interact or enter credentials.',
        'If opened on corporate device, report immediately to IT Security.',
      ],
      socRemediationSteps: [
        'Block domain and 198.51.100.42 on border firewall.',
        'Check proxy logs for any internal user hits in last 24h.',
      ],
      confidenceLevel: 'VERY_HIGH',
    },
    isDemoFixture: true,
  },
  {
    id: 'scn-8712-microsoft-aitm',
    targetUrl: 'https://micros0ft-support-token.net/oauth/v2/authorize',
    domain: 'micros0ft-support-token.net',
    timestamp: new Date(Date.now() - 3600000 * 7).toISOString(),
    scanDurationMs: 1680,
    resolvedIp: '203.0.113.88',
    riskScore: 89,
    riskCategory: 'CRITICAL',
    confidenceScore: 96,
    dimensionalScores: {
      phishingScore: 92,
      securityHeadersScore: 25,
      tlsTrustScore: 70,
      threatIntelScore: 94,
    },
    reasons: [
      'Typosquatting: Permutation of Microsoft (digit 0 substituting letter o)',
      'Adversary-in-the-Middle (AiTM) reverse proxy pattern',
      'Free Let\'s Encrypt certificate obtained for deceptive domain',
    ],
    recommendations: [
      'Block domain on Azure AD conditional access and internal DNS.',
      'Enforce FIDO2 WebAuthn keys to neutralize session token harvesting.',
    ],
    findings: [
      {
        id: 'f-201',
        category: 'PHISHING',
        severity: 'CRITICAL',
        title: 'Typosquatting Microsoft Brand Asset (micros0ft)',
        technicalDetails: 'Numeric 0 replaces character o in apex domain name.',
        evidence: 'micros0ft-support-token.net',
        impact: 'Facilitates session cookie theft and M365 account compromise.',
        remediation: 'Add to tenant blocklist.',
      },
    ],
    phishingAnalysis: {
      probability: 0.92,
      riskCategory: 'CRITICAL',
      indicators: ['Typosquatting permutation of Microsoft', 'OAuth authorization impersonation'],
      homoglyphsDetected: [],
      typosquattingMatch: { brand: 'Microsoft', distance: 1, legitDomain: 'microsoft.com' },
      urlLength: 55,
      subdomainCount: 0,
      suspiciousKeywords: ['support', 'token', 'auth'],
      isIpHost: false,
      hasSuspiciousTld: false,
      hasCredentialInputs: true,
    },
    securityHeaders: {
      csp: { present: false, status: 'CRITICAL', notes: 'Missing CSP header.' },
      hsts: { present: true, status: 'GOOD', notes: 'HSTS enabled.' },
      xFrameOptions: { present: true, status: 'GOOD', notes: 'DENY' },
      xContentTypeOptions: { present: true, status: 'GOOD', notes: 'nosniff' },
      referrerPolicy: { present: false, status: 'WARNING', notes: 'Default' },
      permissionsPolicy: { present: false, status: 'WARNING', notes: 'Default' },
      overallHeaderScore: 55,
      cookiesAnalysis: { total: 1, insecureCookies: [], missingHttpOnly: [], missingSameSite: [] },
    },
    tlsCertificate: {
      valid: true,
      subject: { commonName: 'micros0ft-support-token.net' },
      issuer: { commonName: 'R3', organization: 'Let\'s Encrypt' },
      validFrom: new Date(Date.now() - 86400000 * 3).toISOString(),
      validTo: new Date(Date.now() + 86400000 * 87).toISOString(),
      daysRemaining: 87,
      isExpired: false,
      subjectAltNames: ['micros0ft-support-token.net', 'www.micros0ft-support-token.net'],
      hostnameMatch: true,
      isSelfSigned: false,
      trustScore: 70,
      notes: ['Certificate is valid, demonstrating that TLS alone does NOT signify authenticity.'],
    },
    threatIntelMatches: [
      {
        source: 'Sentinel Community Threat Exchange',
        category: 'KNOWN_PHISHING',
        matchedValue: 'micros0ft-support-token.net',
        confidence: 94,
        firstSeen: new Date(Date.now() - 3600000 * 18).toISOString(),
        reportCount: 19,
        tags: ['AiTM', 'Phishing', 'Target:Microsoft'],
      },
    ],
    redirectChain: [
      { hopIndex: 1, url: 'https://micros0ft-support-token.net/oauth/v2/authorize', statusCode: 200, isExternalDomain: false },
    ],
    isDemoFixture: true,
  },
  {
    id: 'scn-7341-github-safe',
    targetUrl: 'https://github.com',
    domain: 'github.com',
    timestamp: new Date(Date.now() - 3600000 * 14).toISOString(),
    scanDurationMs: 820,
    resolvedIp: '140.82.121.3',
    riskScore: 4,
    riskCategory: 'SAFE',
    confidenceScore: 99,
    dimensionalScores: {
      phishingScore: 0,
      securityHeadersScore: 92,
      tlsTrustScore: 98,
      threatIntelScore: 0,
    },
    reasons: [
      'Official registered domain of GitHub, Inc.',
      'High security header score with strict CSP, HSTS preload, and framing defense',
      'Valid DigiCert Extended Validation TLS certificate',
      'Clean across all global threat intelligence sources',
    ],
    recommendations: [
      'Domain displays industry-benchmark security engineering posture.',
      'Safe for standard user authentication and workflow.',
    ],
    findings: [],
    phishingAnalysis: {
      probability: 0.01,
      riskCategory: 'SAFE',
      indicators: [],
      homoglyphsDetected: [],
      urlLength: 18,
      subdomainCount: 0,
      suspiciousKeywords: [],
      isIpHost: false,
      hasSuspiciousTld: false,
      hasCredentialInputs: false,
    },
    securityHeaders: {
      csp: { present: true, status: 'GOOD', notes: 'Strict CSP policy enforced.' },
      hsts: { present: true, maxAge: 31536000, includeSubDomains: true, preload: true, status: 'GOOD', notes: 'HSTS preload enabled.' },
      xFrameOptions: { present: true, value: 'deny', status: 'GOOD', notes: 'Framing denied.' },
      xContentTypeOptions: { present: true, value: 'nosniff', status: 'GOOD', notes: 'Nosniff enabled.' },
      referrerPolicy: { present: true, value: 'origin-when-cross-origin', status: 'GOOD', notes: 'Strict referrer policy.' },
      permissionsPolicy: { present: true, status: 'GOOD', notes: 'Permissions restricted.' },
      serverHeader: 'GitHub.com',
      cookiesAnalysis: { total: 3, insecureCookies: [], missingHttpOnly: [], missingSameSite: [] },
      overallHeaderScore: 92,
    },
    tlsCertificate: {
      valid: true,
      subject: { commonName: 'github.com', organization: 'GitHub, Inc.', country: 'US' },
      issuer: { commonName: 'DigiCert High Assurance TLS Hybrid ECC SHA256 2020 CA1', organization: 'DigiCert Inc' },
      validFrom: '2024-02-14T00:00:00.000Z',
      validTo: '2027-03-14T23:59:59.000Z',
      daysRemaining: 420,
      isExpired: false,
      subjectAltNames: ['github.com', 'www.github.com'],
      hostnameMatch: true,
      isSelfSigned: false,
      signatureAlgorithm: 'ecdsa-with-SHA256',
      publicKeyAlgorithm: 'EC (prime256v1)',
      keySizeBits: 256,
      cipher: 'TLS_AES_128_GCM_SHA256',
      protocol: 'TLSv1.3',
      trustScore: 98,
      notes: ['Valid EV certificate issued by trusted public CA.'],
    },
    threatIntelMatches: [],
    redirectChain: [
      { hopIndex: 1, url: 'https://github.com', statusCode: 200, isExternalDomain: false },
    ],
    aiAssessment: {
      analystSummary: 'Verified authentic infrastructure for GitHub. Enterprise cryptographic parameters and robust application security controls in place.',
      threatActorsOrMotivation: 'Legitimate developer platform.',
      psychologicalTactics: ['None'],
      mitreAttackTechniques: [],
      userActionGuidance: ['Safe for regular developer and enterprise usage.'],
      socRemediationSteps: ['No remediation required.'],
      confidenceLevel: 'VERY_HIGH',
    },
    isDemoFixture: true,
  },
  {
    id: 'scn-6120-badssl-expired',
    targetUrl: 'https://expired.badssl.com',
    domain: 'expired.badssl.com',
    timestamp: new Date(Date.now() - 3600000 * 22).toISOString(),
    scanDurationMs: 910,
    resolvedIp: '104.154.89.105',
    riskScore: 78,
    riskCategory: 'CRITICAL',
    confidenceScore: 95,
    dimensionalScores: {
      phishingScore: 10,
      securityHeadersScore: 40,
      tlsTrustScore: 0,
      threatIntelScore: 0,
    },
    reasons: [
      'Expired SSL/TLS Certificate: Cryptographic validity ended on 2015-04-12',
      'Trust chain broken; modern browsers display security interstitial warning',
    ],
    recommendations: [
      'Do not proceed past browser security certificate warning.',
      'Renew TLS certificate with an active Certificate Authority.',
    ],
    findings: [
      {
        id: 'f-badssl-expired',
        category: 'SSL_TLS',
        severity: 'CRITICAL',
        title: 'SSL/TLS Certificate Expired',
        technicalDetails: 'The X.509 certificate expired over 3000 days ago. Transport cannot be trusted.',
        evidence: 'Valid To: 2015-04-12',
        impact: 'Loss of confidentiality and authentication guarantees.',
        remediation: 'Deploy active X.509 certificate.',
      },
    ],
    phishingAnalysis: {
      probability: 0.1,
      riskCategory: 'LOW',
      indicators: [],
      homoglyphsDetected: [],
      urlLength: 26,
      subdomainCount: 1,
      suspiciousKeywords: [],
      isIpHost: false,
      hasSuspiciousTld: false,
    },
    securityHeaders: {
      csp: { present: false, status: 'CRITICAL', notes: 'Missing CSP.' },
      hsts: { present: false, status: 'CRITICAL', notes: 'Missing HSTS.' },
      xFrameOptions: { present: false, status: 'CRITICAL', notes: 'Missing XFO.' },
      xContentTypeOptions: { present: false, status: 'WARNING', notes: 'Missing nosniff.' },
      referrerPolicy: { present: false, status: 'WARNING', notes: 'Default.' },
      permissionsPolicy: { present: false, status: 'WARNING', notes: 'Default.' },
      overallHeaderScore: 40,
      cookiesAnalysis: { total: 0, insecureCookies: [], missingHttpOnly: [], missingSameSite: [] },
    },
    tlsCertificate: {
      valid: false,
      subject: { commonName: '*.badssl.com' },
      issuer: { commonName: 'DigiCert SHA2 Secure Server CA' },
      validFrom: '2013-04-09T00:00:00.000Z',
      validTo: '2015-04-12T23:59:59.000Z',
      daysRemaining: -3400,
      isExpired: true,
      subjectAltNames: ['*.badssl.com', 'badssl.com'],
      hostnameMatch: true,
      isSelfSigned: false,
      trustScore: 0,
      notes: ['Certificate validity has lapsed.'],
    },
    threatIntelMatches: [],
    redirectChain: [
      { hopIndex: 1, url: 'https://expired.badssl.com', statusCode: 200, isExternalDomain: false },
    ],
    isDemoFixture: true,
  },
  ];
}

// Persistent scans map
const scansStore: Map<string, ScanResult> = new Map(
  process.env.NODE_ENV === 'test' ? getInitialScans().map(s => [s.id, s]) : []
);

export function getAllScans(): ScanResult[] {
  return Array.from(scansStore.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
}

export function getScanById(id: string): ScanResult | undefined {
  return scansStore.get(id);
}

export function saveScan(scan: ScanResult): void {
  if (process.env.NODE_ENV === 'production') return;
  scansStore.set(scan.id, scan);
}

export function computeDashboardOverview(): DashboardOverview {
  const scans = getAllScans();
  const threatReports = getAllThreatReports();

  let safeCount = 0;
  let suspiciousCount = 0;
  let maliciousCount = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let infoCount = 0;

  const observedDomains = new Set<string>();
  const observedIps = new Set<string>();
  const observedServices = new Set<string>();
  let observedDnsRecords = 0;

  for (const s of scans) {
    observedDomains.add(s.domain);
    if (s.resolvedIp) observedIps.add(s.resolvedIp);
    observedDnsRecords += Object.values(s.dnsRecords || {}).reduce(
      (count, records) => count + records.length,
      0,
    );
    try {
      const target = new URL(s.targetUrl);
      observedServices.add(`${target.protocol}//${target.hostname}:${target.port || (target.protocol === 'https:' ? '443' : '80')}`);
    } catch {
      // Older records may not contain a parseable URL.
    }

    if (s.riskScore < 25) safeCount++;
    else if (s.riskScore < 50) suspiciousCount++;
    else maliciousCount++;

    for (const f of s.findings) {
      if (f.severity === 'CRITICAL') criticalCount++;
      else if (f.severity === 'HIGH') highCount++;
      else if (f.severity === 'MEDIUM') mediumCount++;
      else if (f.severity === 'LOW') lowCount++;
      else infoCount++;
    }
  }

  const totalAssets = observedDomains.size + observedIps.size;

  return {
    totalScans: scans.length,
    safeCount,
    suspiciousCount,
    maliciousCount,
    activeFeedsCount: 0,
    openFindingsCount: criticalCount + highCount + mediumCount,
    severityDistribution: {
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      informational: infoCount,
    },
    attackSurface: {
      totalAssets,
      ipAddresses: observedIps.size,
      services: observedServices.size,
      domains: observedDomains.size,
      dnsRecords: observedDnsRecords,
    },
    recentScans: scans.slice(0, 8),
    agingThreats: threatReports.slice(0, 5),
  };
}
