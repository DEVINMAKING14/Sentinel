import { RiskLevel, Finding, PhishingAnalysis, SecurityHeaderAssessment, TlsCertificateAnalysis, ThreatIntelligenceMatch } from './types';

export interface UnifiedScoreOutput {
  riskScore: number;
  riskCategory: RiskLevel;
  confidenceScore: number;
  dimensionalScores: {
    phishingScore: number;
    securityHeadersScore: number;
    tlsTrustScore: number;
    threatIntelScore: number;
  };
  reasons: string[];
  recommendations: string[];
}

export interface ScoreEvidenceAvailability {
  securityHeaders: boolean;
  tlsCertificate: boolean;
  threatIntelligence: boolean;
}

export function computeUnifiedRiskScore(
  phishing: PhishingAnalysis,
  securityHeaders: SecurityHeaderAssessment,
  tlsCert: TlsCertificateAnalysis,
  threatMatches: ThreatIntelligenceMatch[],
  findings: Finding[],
  availability: ScoreEvidenceAvailability = {
    securityHeaders: true,
    tlsCertificate: true,
    threatIntelligence: true,
  },
): UnifiedScoreOutput {
  // 1. Phishing risk component (0 - 100)
  const phishingRisk = Math.round(phishing.probability * 100);

  // 2. Security headers risk component (0 - 100)
  // Higher header score means better security, so risk = 100 - headerScore
  const securityRisk = Math.max(0, 100 - securityHeaders.overallHeaderScore);

  // 3. TLS Certificate risk component (0 - 100)
  // Higher trust score means safer TLS, so risk = 100 - trustScore
  const tlsRisk = Math.max(0, 100 - tlsCert.trustScore);

  // 4. Threat Intelligence risk component (0 - 100)
  let threatIntelRisk = 0;
  if (threatMatches.length > 0) {
    const highestConfidence = Math.max(...threatMatches.map(m => m.confidence));
    threatIntelRisk = highestConfidence;
  }

  // Configured weights: Phishing 35%, Security 20%, TLS 20%, Threat Intel 25%
  const WEIGHT_PHISHING = 0.35;
  const WEIGHT_SECURITY = 0.20;
  const WEIGHT_TLS = 0.20;
  const WEIGHT_INTEL = 0.25;

  const evidence = [
    { risk: phishingRisk, weight: WEIGHT_PHISHING, available: true },
    { risk: securityRisk, weight: WEIGHT_SECURITY, available: availability.securityHeaders },
    { risk: tlsRisk, weight: WEIGHT_TLS, available: availability.tlsCertificate },
    { risk: threatIntelRisk, weight: WEIGHT_INTEL, available: availability.threatIntelligence },
  ];
  const availableWeight = evidence.reduce((total, item) => total + (item.available ? item.weight : 0), 0);
  let weightedRisk = availableWeight > 0
    ? evidence.reduce((total, item) => total + (item.available ? item.risk * item.weight : 0), 0) / availableWeight
    : 0;

  const finalScore = Math.min(100, Math.max(0, Math.round(weightedRisk)));

  // Risk Classification
  let riskCategory: RiskLevel = 'SAFE';
  if (finalScore >= 75) riskCategory = 'CRITICAL';
  else if (finalScore >= 50) riskCategory = 'HIGH';
  else if (finalScore >= 25) riskCategory = 'MEDIUM';
  else if (finalScore >= 10) riskCategory = 'LOW';

  // Confidence Score Calculation (Data Source completeness)
  const finalConfidence = Math.round(availableWeight * 100);

  // Transparent Reasons extraction
  const reasons: string[] = [];
  if (phishing.homoglyphsDetected.length > 0) {
    reasons.push('Homoglyph IDN attack: Non-Latin characters spoofing legitimate ASCII brand letters');
  }
  if (phishing.typosquattingMatch) {
    reasons.push(`Domain mimics protected brand '${phishing.typosquattingMatch.brand}' (edit distance: ${phishing.typosquattingMatch.distance})`);
  }
  if (threatMatches.length > 0) {
    reasons.push(`Positive threat intelligence hit: Flagged in ${threatMatches[0].source}`);
  }
  if (phishing.hasCredentialInputs) {
    reasons.push('Credential harvesting or credit card entry fields detected on untrusted host');
  }
  if (tlsCert.isExpired) {
    reasons.push('Expired SSL/TLS certificate breaks cryptographic chain of trust');
  }
  if (tlsCert.isSelfSigned) {
    reasons.push('Self-signed TLS certificate not anchored in public CA trust store');
  }
  if (!tlsCert.hostnameMatch && tlsCert.subject.commonName) {
    reasons.push(`Hostname mismatch: Cert issued for '${tlsCert.subject.commonName}'`);
  }
  if (!securityHeaders.csp.present) {
    reasons.push('Missing Content Security Policy exposes users to client-side script injection');
  }
  if (!securityHeaders.hsts.present) {
    reasons.push('Missing HSTS transport enforcement permits plaintext downgrade attacks');
  }
  if (reasons.length === 0) {
    reasons.push('No phishing indicators were found in the submitted URL. This is not a guarantee that the website is safe.');
  }

  // Tailored Actionable Recommendations
  const recommendations: string[] = [];
  if (finalScore >= 75) {
    recommendations.push('DO NOT enter usernames, passwords, 2FA tokens, or financial payment details.');
    recommendations.push('Immediately add domain and associated IP address to corporate firewall and DNS sinkhole blocklists.');
    recommendations.push('Submit indicator of compromise (IoC) to threat intelligence exchange and registrar abuse team.');
  } else if (finalScore >= 50) {
    recommendations.push('Exercise extreme caution. Cross-reference URL with official organization documentation.');
    recommendations.push('Inspect domain spelling meticulously before submitting sensitive data.');
    recommendations.push('Verify whether internal email gateway quarantined correlated incoming messages.');
  } else if (finalScore >= 25) {
    recommendations.push('Remediate missing web security headers (implement CSP, enable HSTS with preload).');
    recommendations.push('Ensure session cookies are transmitted with HttpOnly and Secure flags.');
  } else {
    recommendations.push('No URL-based phishing indicators were detected; verify the destination before entering sensitive information.');
    recommendations.push('Continue standard security posture monitoring.');
  }

  return {
    riskScore: finalScore,
    riskCategory,
    confidenceScore: finalConfidence,
    dimensionalScores: {
      phishingScore: phishingRisk,
      securityHeadersScore: securityHeaders.overallHeaderScore,
      tlsTrustScore: tlsCert.trustScore,
      threatIntelScore: threatIntelRisk,
    },
    reasons,
    recommendations,
  };
}
