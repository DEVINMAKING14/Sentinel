import { ThreatReport, ThreatIntelligenceMatch, Finding } from './types';
import { randomUUID } from 'crypto';

// Pre-seeded high-fidelity threat intelligence feed with realistic verified and unverified threat campaigns
function getInitialThreatReports(): ThreatReport[] {
  return [
  {
    id: 'ioc-rep-8091',
    url: 'http://paypa1-secure-verification.login-portal.cc/account-verify',
    domain: 'login-portal.cc',
    threatType: 'PHISHING',
    targetedBrand: 'PayPal',
    submittedAt: new Date(Date.now() - 3600000 * 4).toISOString(),
    submittedBy: 'analyst_roberts@sentinel-sec.io',
    evidenceNotes: 'Credential harvesting kit masquerading as PayPal account suspension notification. Steals SMS 2FA codes.',
    verificationsCount: 24,
    disputesCount: 0,
    status: 'VERIFIED',
    reputationScore: 98,
  },
  {
    id: 'ioc-rep-7943',
    url: 'https://micros0ft-support-token.net/oauth/v2/authorize',
    domain: 'micros0ft-support-token.net',
    threatType: 'BRAND_IMPERSONATION',
    targetedBrand: 'Microsoft',
    submittedAt: new Date(Date.now() - 3600000 * 18).toISOString(),
    submittedBy: 'soc_tier2@enterprise-defense.com',
    evidenceNotes: 'Typosquatted domain deploying Evilginx2 reverse-proxy adversary-in-the-middle (AiTM) authentication interception.',
    verificationsCount: 19,
    disputesCount: 1,
    status: 'VERIFIED',
    reputationScore: 94,
  },
  {
    id: 'ioc-rep-6520',
    url: 'https://chase-security-resolution.online/verify-debit',
    domain: 'chase-security-resolution.online',
    threatType: 'PAYMENT_FRAUD',
    targetedBrand: 'Chase Bank',
    submittedAt: new Date(Date.now() - 3600000 * 42).toISOString(),
    submittedBy: 'fraud_ops@fintech-coalition.org',
    evidenceNotes: 'Extracts full 16-digit debit card numbers, CVVs, PIN numbers, and mother maiden names.',
    verificationsCount: 38,
    disputesCount: 0,
    status: 'VERIFIED',
    reputationScore: 99,
  },
  {
    id: 'ioc-rep-5412',
    url: 'http://careers-remote-apply.work/google-engineering-offer',
    domain: 'careers-remote-apply.work',
    threatType: 'BRAND_IMPERSONATION',
    targetedBrand: 'Google',
    submittedAt: new Date(Date.now() - 3600000 * 72).toISOString(),
    submittedBy: 'community_hunter',
    evidenceNotes: 'Fake recruitment scam sending fraudulent employment offer letters requiring check-cashing advance fees.',
    verificationsCount: 12,
    disputesCount: 2,
    status: 'VERIFIED',
    reputationScore: 88,
  },
  {
    id: 'ioc-rep-4301',
    url: 'https://binance-wallet-sync-defi.top/connect-wallet',
    domain: 'binance-wallet-sync-defi.top',
    threatType: 'CREDENTIAL_HARVESTING',
    targetedBrand: 'Binance',
    submittedAt: new Date(Date.now() - 3600000 * 96).toISOString(),
    submittedBy: 'crypto_sentinel',
    evidenceNotes: 'Wallet drainer smart-contract phishing site stealing BIP-39 mnemonic seed phrases.',
    verificationsCount: 45,
    disputesCount: 0,
    status: 'VERIFIED',
    reputationScore: 99,
  },
  ];
}

// In-memory threat reports store
const threatReportsStore: Map<string, ThreatReport> = new Map(
  process.env.NODE_ENV === 'test' ? getInitialThreatReports().map(r => [r.id, r]) : []
);

export function getAllThreatReports(): ThreatReport[] {
  return Array.from(threatReportsStore.values()).sort(
    (a, b) => new Date(b.submittedAt).getTime() - new Date(a.submittedAt).getTime()
  );
}

export function submitThreatReport(report: Omit<ThreatReport, 'id' | 'submittedAt' | 'verificationsCount' | 'disputesCount' | 'status' | 'reputationScore'>): ThreatReport {
  const newReport: ThreatReport = {
    ...report,
    id: `ioc-rep-${randomUUID()}`,
    submittedAt: new Date().toISOString(),
    verificationsCount: 1,
    disputesCount: 0,
    status: 'PENDING',
    reputationScore: 70,
  };

  threatReportsStore.set(newReport.id, newReport);
  return newReport;
}

export function verifyThreatReport(reportId: string, isAffirmative: boolean): ThreatReport | null {
  const report = threatReportsStore.get(reportId);
  if (!report) return null;

  if (isAffirmative) {
    report.verificationsCount += 1;
    report.reputationScore = Math.min(100, report.reputationScore + 5);
    if (report.verificationsCount >= 3) {
      report.status = 'VERIFIED';
    }
  } else {
    report.disputesCount += 1;
    report.reputationScore = Math.max(0, report.reputationScore - 10);
    if (report.disputesCount >= 3 && report.disputesCount > report.verificationsCount) {
      report.status = 'DISPUTED';
    }
  }

  return report;
}

export function lookupThreatIntelligence(targetUrl: string, domain: string): {
  matches: ThreatIntelligenceMatch[];
  findings: Finding[];
} {
  const matches: ThreatIntelligenceMatch[] = [];
  const findings: Finding[] = [];
  const normUrl = targetUrl.toLowerCase();
  const normDomain = domain.toLowerCase();

  // Search in threat reports
  for (const report of threatReportsStore.values()) {
    const reportDomain = report.domain.toLowerCase();
    const reportUrl = report.url.toLowerCase();

    if (normUrl === reportUrl || normDomain === reportDomain || normDomain.endsWith(`.${reportDomain}`)) {
      matches.push({
        source: 'Sentinel Community Threat Exchange',
        category: report.status === 'VERIFIED' ? 'KNOWN_PHISHING' : 'COMMUNITY_REPORTED',
        matchedValue: report.domain,
        confidence: report.reputationScore,
        firstSeen: report.submittedAt,
        reportCount: report.verificationsCount,
        tags: [report.threatType, report.targetedBrand ? `Target:${report.targetedBrand}` : 'General'],
      });

      findings.push({
        id: `threat-match-${report.id}`,
        category: 'THREAT_INTEL',
        severity: report.status === 'VERIFIED' ? 'CRITICAL' : 'HIGH',
        source: 'Sentinel Community Threat Exchange',
        title: `Positive Threat Intelligence Match (${report.threatType})`,
        technicalDetails: `Domain matches reported malicious entry in threat database. Target brand: ${report.targetedBrand || 'N/A'}. Reporter notes: ${report.evidenceNotes}`,
        evidence: `Threat Report ID: ${report.id} (${report.verificationsCount} peer verifications, confidence: ${report.reputationScore}%)`,
        impact: 'High risk of immediate financial, credential, or malware victimization.',
        remediation: 'Block URL at perimeter egress proxies and notify endpoint security operations center.',
      });
      break;
    }
  }

  return { matches, findings };
}
