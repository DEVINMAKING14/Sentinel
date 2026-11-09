import { PhishingAnalysis, Finding, RiskSeverity, RiskLevel } from './types';
import net from 'net';

// Common Cyrillic / Greek homoglyph mappings
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', // Cyrillic Small Letter A
  '\u0410': 'A', // Cyrillic Capital Letter A
  '\u0441': 'c', // Cyrillic Small Letter Es
  '\u0421': 'C', // Cyrillic Capital Letter Es
  '\u0435': 'e', // Cyrillic Small Letter Ie
  '\u0415': 'E', // Cyrillic Capital Letter Ie
  '\u043E': 'o', // Cyrillic Small Letter O
  '\u041E': 'O', // Cyrillic Capital Letter O
  '\u0440': 'p', // Cyrillic Small Letter Er
  '\u0420': 'P', // Cyrillic Capital Letter Er
  '\u0455': 's', // Cyrillic Small Letter Dze
  '\u0445': 'x', // Cyrillic Small Letter Ha
  '\u0425': 'X', // Cyrillic Capital Letter Ha
  '\u0443': 'y', // Cyrillic Small Letter U
  '\u0456': 'i', // Cyrillic Small Letter Byelorussian-Ukrainian I
  '\u03B1': 'a', // Greek Small Letter Alpha
  '\u03BF': 'o', // Greek Small Letter Omicron
  '\u03BD': 'v', // Greek Small Letter Nu
  '\u03C1': 'p', // Greek Small Letter Rho
};

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'buzz', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'cam',
  'click', 'icu', 'rest', 'sbs', 'bond', 'quest', 'monster', 'hair', 'cfd',
]);

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'account-update', 'secure',
  'security-alert', 'banking', 'billing', 'invoice', 'support', 'password',
  'credential', 'suspend', 'suspended', 'auth', 'authorize', 'wallet',
  'confirm', 'session', 'recover', 'recruitment', 'payroll', 'urgent-action',
];

export function analyzePhishingIndicators(targetUrl: string, htmlContent?: string): {
  analysis: PhishingAnalysis;
  findings: Finding[];
} {
  const findings: Finding[] = [];
  const indicators: string[] = [];
  let riskScorePoints = 0;

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return {
      analysis: {
        probability: 0,
        riskCategory: 'SAFE',
        indicators: [],
        homoglyphsDetected: [],
        urlLength: targetUrl.length,
        subdomainCount: 0,
        suspiciousKeywords: [],
        isIpHost: false,
        hasSuspiciousTld: false,
      },
      findings: [],
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = targetUrl.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();

  // 1. Homoglyph Detection
  const homoglyphsDetected: { char: string; codePoint: string; replaces: string }[] = [];
  for (const char of hostname) {
    if (HOMOGLYPH_MAP[char]) {
      homoglyphsDetected.push({
        char,
        codePoint: `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`,
        replaces: HOMOGLYPH_MAP[char],
      });
    }
  }

  if (homoglyphsDetected.length > 0) {
    riskScorePoints += 45;
    const details = homoglyphsDetected
      .map(h => `'${h.char}' (${h.codePoint} replacing Latin '${h.replaces}')`)
      .join(', ');
    indicators.push(`Homoglyph Internationalized Domain Name (IDN) spoofing: ${details}`);
    findings.push({
      id: 'phish-homoglyph-idn',
      category: 'PHISHING',
      severity: 'CRITICAL',
      title: 'Homoglyph / Punycode Domain Impersonation Detected',
      technicalDetails: `The domain name uses non-Latin Unicode characters that visually emulate standard Latin characters: ${details}`,
      evidence: `Hostname: ${hostname} (Detected characters: ${details})`,
      impact: 'Victims visually believe they are navigating to a legitimate corporate portal while their credentials are harvested by an imposter domain.',
      remediation: 'Immediately block this domain at DNS and proxy layers. Never enter credentials.',
    });
  }

  // 2. IP as Hostname
  const isIpHost = net.isIP(hostname) !== 0;
  if (isIpHost) {
    riskScorePoints += 30;
    indicators.push(`Host is configured directly as a raw IP address (${hostname})`);
    findings.push({
      id: 'phish-ip-host',
      category: 'PHISHING',
      severity: 'HIGH',
      title: 'Direct IP Hostname In URL',
      technicalDetails: 'Legitimate corporate services register registered domain names. Direct IP addresses are predominantly utilized in opportunistic phishing or botnet command-and-control servers.',
      evidence: `Target: ${targetUrl}`,
      impact: 'Bypasses domain reputation databases and hides the origin identity behind disposable cloud IP allocations.',
      remediation: 'Deny connections to direct IP web endpoints unless formally authorized on internal development lists.',
    });
  }

  // 3. Typosquatting and Brand Impersonation
  const domainParts = hostname.split('.');
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';
  const sld = domainParts.length > 1 ? domainParts[domainParts.length - 2] : hostname;
  const typosquattingMatch: undefined = undefined;

  // 4. Suspicious Keywords
  const matchedKeywords: string[] = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (fullUrl.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  if (matchedKeywords.length > 0) {
    const points = Math.min(25, matchedKeywords.length * 8);
    riskScorePoints += points;
    indicators.push(`Suspicious phishing keywords found: ${matchedKeywords.join(', ')}`);
    if (matchedKeywords.length >= 2) {
      findings.push({
        id: 'phish-suspicious-keywords',
        category: 'PHISHING',
        severity: matchedKeywords.length >= 3 ? 'HIGH' : 'MEDIUM',
        title: 'High-Risk Phishing Keywords in URL Path and Domain',
        technicalDetails: `URL contains tokens characteristically linked to credential verification and banking scams: ${matchedKeywords.join(', ')}`,
        evidence: `URL Path: ${pathname}`,
        impact: 'Creates psychological urgency and masquerades as an account security verification gateway.',
        remediation: 'Verify whether the request was legitimately initiated by checking official notification channels directly.',
      });
    }
  }

  // 5. URL Length & Subdomain Density
  const urlLength = targetUrl.length;
  if (urlLength > 100) {
    riskScorePoints += 15;
    indicators.push(`Excessively long URL (${urlLength} characters)`);
    findings.push({
      id: 'phish-url-length',
      category: 'PHISHING',
      severity: 'LOW',
      title: 'Abnormal URL Length',
      technicalDetails: `URL length of ${urlLength} exceeds typical benign navigation thresholds, frequently utilized to conceal malicious payloads or tracking tokens from user viewports.`,
      evidence: `Length: ${urlLength} chars`,
      impact: 'Obscures destination in mobile browser address bars.',
      remediation: 'Inspect complete query parameters before interaction.',
    });
  }

  const subdomainCount = Math.max(0, domainParts.length - 2);
  if (subdomainCount >= 3) {
    riskScorePoints += 15;
    indicators.push(`Elevated subdomain depth (${subdomainCount} subdomains)`);
    findings.push({
      id: 'phish-subdomain-depth',
      category: 'PHISHING',
      severity: 'MEDIUM',
      title: 'Excessive Subdomain Fragmentation',
      technicalDetails: `Host contains ${subdomainCount} subdomains, a technique widely used in automated bulletproof hosting and dynamic phishing kits.`,
      evidence: `Hostname: ${hostname}`,
      impact: 'Bypasses single-level domain filters and hides the true apex entity.',
      remediation: 'Analyze DNS authority records and WHOIS registration details.',
    });
  }

  // 6. Suspicious TLD
  const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  if (hasSuspiciousTld) {
    riskScorePoints += 20;
    indicators.push(`Registered under high-abuse TLD ('.${tld}')`);
    findings.push({
      id: 'phish-suspicious-tld',
      category: 'PHISHING',
      severity: 'MEDIUM',
      title: `High-Risk Top-Level Domain (TLD) Detected (.${tld})`,
      technicalDetails: `The top-level domain '.${tld}' exhibits high spam, fraud, and disposable registration activity across global threat intelligence feeds.`,
      evidence: `TLD: .${tld}`,
      impact: 'High prevalence of disposable, low-cost registration vectors favored by threat actors.',
      remediation: 'Enforce heightened endpoint inspection on traffic traversing elevated-risk TLDs.',
    });
  }

  // 7. HTML Content Analysis if available
  let detectedFormsCount = 0;
  let hasCredentialInputs = false;

  if (htmlContent) {
    const formMatches = htmlContent.match(/<form[\s\S]*?<\/form>/gi) || [];
    detectedFormsCount = formMatches.length;

    const hasPasswordInput = /<input[^>]+type=["']password["']/i.test(htmlContent);
    const hasCardInput = /(card|cvv|expiry|ssn|social-security|credit-card)/i.test(htmlContent);

    hasCredentialInputs = hasPasswordInput || hasCardInput;
    if (hasCredentialInputs && riskScorePoints > 0) {
      riskScorePoints += 20;
      indicators.push('Sensitive input fields were observed alongside other URL risk indicators');
      findings.push({
        id: 'phish-credential-harvesting-form',
        category: 'PHISHING',
        severity: 'HIGH',
        source: 'Retrieved HTML content inspection',
        title: 'Sensitive Input Fields on a URL with Risk Indicators',
        technicalDetails: 'The retrieved page contains password or payment-related input fields and the submitted URL also triggered phishing heuristics.',
        evidence: `Forms found: ${detectedFormsCount}, password fields present: ${hasPasswordInput}, payment-related fields present: ${hasCardInput}`,
        impact: 'Sensitive data may be requested on a URL that has other suspicious characteristics.',
        remediation: 'Verify the hostname through an independently trusted source before entering information.',
      });
    }
  }

  // Calculate normalized probability (0 to 1)
  const probability = Math.min(0.99, riskScorePoints / 100);

  let riskCategory: RiskLevel = 'SAFE';
  if (probability >= 0.75) riskCategory = 'CRITICAL';
  else if (probability >= 0.50) riskCategory = 'HIGH';
  else if (probability >= 0.25) riskCategory = 'MEDIUM';
  else if (probability >= 0.10) riskCategory = 'LOW';

  return {
    analysis: {
      probability,
      riskCategory,
      indicators,
      homoglyphsDetected,
      typosquattingMatch,
      urlLength,
      subdomainCount,
      suspiciousKeywords: matchedKeywords,
      isIpHost,
      hasSuspiciousTld,
      detectedFormsCount,
      hasCredentialInputs,
    },
    findings,
  };
}
