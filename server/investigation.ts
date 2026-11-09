import { randomUUID } from 'crypto';
import { collectDnsRecords, normalizeTargetUrl, resolveHostingAndAsn, SsrfValidationResult, validateUrlForSsrf } from './ssrf';
import { analyzePhishingIndicators } from './phishingEngine';
import { scanWebsiteSecurity } from './securityScanner';
import { inspectTlsCertificate } from './certificateInspector';
import { lookupThreatIntelligence } from './threatIntel';
import { computeUnifiedRiskScore } from './riskScorer';
import { analyzeThreatWithGemini } from './aiAnalyzer';
import { Finding, ScanResult, TlsCertificateAnalysis } from './types';

type DnsRecords = NonNullable<ScanResult['dnsRecords']>;

export class InvestigationError extends Error {
  constructor(message: string, readonly statusCode: number) {
    super(message);
    this.name = 'InvestigationError';
  }
}

export interface InvestigationDependencies {
  validateUrl?: typeof validateUrlForSsrf;
  collectDns?: typeof collectDnsRecords;
  scanHttp?: typeof scanWebsiteSecurity;
  inspectTls?: typeof inspectTlsCertificate;
  resolveHosting?: typeof resolveHostingAndAsn;
}

const emptyDnsRecords: DnsRecords = { A: [], AAAA: [], MX: [], NS: [], TXT: [] };

function unavailableCertificate(note: string): TlsCertificateAnalysis {
  return {
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
    notes: [note],
  };
}

function withFindingSource(findings: Finding[], source: string): Finding[] {
  return findings.map(finding => ({ ...finding, source: finding.source || source }));
}

function formatTime(date: Date): string {
  return date.toTimeString().split(' ')[0];
}

export async function investigateSubmittedUrl(
  submittedUrl: string,
  dependencies: InvestigationDependencies = {},
): Promise<ScanResult> {
  const startedAt = Date.now();
  const norm = normalizeTargetUrl(submittedUrl);
  if (!norm.valid) {
    throw new InvestigationError(norm.error || 'Invalid website address.', 400);
  }

  const scanId = `SNT-${randomUUID()}`;
  const parsedUrl = new URL(norm.normalizedUrl);
  const validate = dependencies.validateUrl || validateUrlForSsrf;
  const check = await validate(norm.normalizedUrl);
  const isDnsFailure = Boolean(
    check.reason?.startsWith('DNS lookup failed:') ||
    check.reason?.startsWith('Could not resolve domain:'),
  );
  if (!check.safe && !isDnsFailure) {
    throw new InvestigationError(check.reason || 'Destination is blocked by SSRF protection.', 400);
  }

  let dnsRecords = emptyDnsRecords;
  let dnsMessage: string | undefined;
  try {
    dnsRecords = await (dependencies.collectDns || collectDnsRecords)(norm.domain);
  } catch (error) {
    dnsMessage = error instanceof Error ? error.message : String(error);
  }
  const dnsCompletedAt = Date.now();

  let httpCompletedAt = Date.now();
  const headerScanPromise = (dependencies.scanHttp || scanWebsiteSecurity)(norm.normalizedUrl, check)
    .then(result => {
      httpCompletedAt = Date.now();
      return result;
    });
  let tlsCompletedAt = Date.now();
  const certificatePromise = parsedUrl.protocol === 'https:' && check.safe
    ? (dependencies.inspectTls || inspectTlsCertificate)(
        norm.domain,
        parsedUrl.port ? Number(parsedUrl.port) : 443,
        check,
      )
    : Promise.resolve({
        certificate: unavailableCertificate(
          parsedUrl.protocol === 'http:'
            ? 'TLS was not attempted because the submitted URL uses HTTP.'
            : check.reason || 'TLS is unavailable because the hostname did not resolve.',
        ),
        findings: [],
      });
  const observedCertificatePromise = certificatePromise.then(result => {
    tlsCompletedAt = Date.now();
    return result;
  });

  const [httpScan, tlsResult] = await Promise.all([headerScanPromise, observedCertificatePromise]);
  const phishing = analyzePhishingIndicators(norm.normalizedUrl, httpScan.bodySnippet);
  const threatIntel = lookupThreatIntelligence(norm.normalizedUrl, norm.domain);
  const certificateRetrieved = Boolean(tlsResult.certificate.validFrom);
  const tlsUnavailableMessage = certificateRetrieved
    ? undefined
    : tlsResult.certificate.notes[0] || 'No TLS certificate was retrieved.';
  const dnsRecordsFound = Object.values(dnsRecords).some(records => records.length > 0);
  const dnsStatus = check.safe && !dnsMessage
    ? 'completed' as const
    : check.safe || dnsRecordsFound
      ? 'partial' as const
      : 'unavailable' as const;
  const dnsUnavailableMessage = dnsMessage || (isDnsFailure ? check.reason : undefined);

  const findings = [
    ...withFindingSource(phishing.findings, 'Submitted URL and retrieved page-content heuristics'),
    ...withFindingSource(httpScan.findings, 'Observed HTTP response and redirect chain'),
    ...withFindingSource(tlsResult.findings, 'Observed TLS handshake and certificate'),
    ...withFindingSource(threatIntel.findings, 'Sentinel Community Threat Exchange'),
  ];
  if (parsedUrl.protocol === 'http:') {
    findings.push({
      id: `${scanId}-plaintext-http`,
      category: 'SSL_TLS',
      severity: 'HIGH',
      source: 'Submitted URL scheme',
      title: 'Submitted URL uses unencrypted HTTP',
      technicalDetails: 'The submitted URL uses HTTP, so its request and response are not protected by TLS.',
      evidence: norm.normalizedUrl,
      impact: 'Data exchanged with this endpoint may be observable or modified in transit.',
      remediation: 'Use the HTTPS version if the website provides one.',
    });
  }

  const risk = computeUnifiedRiskScore(
    phishing.analysis,
    httpScan.headers,
    tlsResult.certificate,
    threatIntel.matches,
    findings,
    {
      securityHeaders: httpScan.headersAvailable,
      tlsCertificate: certificateRetrieved || parsedUrl.protocol === 'http:',
      threatIntelligence: true,
    },
  );
  const riskCompletedAt = Date.now();

  const aiAssessment = await analyzeThreatWithGemini(
    submittedUrl,
    norm.domain,
    phishing.analysis,
    tlsResult.certificate,
    findings,
    risk.riskScore,
  );
  const aiCompletedAt = Date.now();
  const hosting = await (dependencies.resolveHosting || resolveHostingAndAsn)(
    check.resolvedIp,
    httpScan.finalStatusCode > 0 ? httpScan.headers.serverHeader : undefined,
  );
  const timestamp = new Date(startedAt).toISOString();
  const timelineEventsWithTimes = [
    { at: startedAt, label: 'Investigation started', status: 'done' },
    {
      at: dnsCompletedAt,
      label: `DNS ${dnsStatus}${dnsUnavailableMessage ? `: ${dnsUnavailableMessage}` : ''}`,
      status: dnsStatus === 'completed' ? 'done' : 'info',
    },
    {
      at: httpCompletedAt,
      label: `HTTP ${httpScan.status}${httpScan.message ? `: ${httpScan.message}` : ''}`,
      status: httpScan.status === 'completed' ? 'done' : 'info',
    },
    {
      at: tlsCompletedAt,
      label: `TLS ${certificateRetrieved ? 'completed' : 'unavailable'}${tlsUnavailableMessage ? `: ${tlsUnavailableMessage}` : ''}`,
      status: certificateRetrieved ? 'done' : 'info',
    },
    {
      at: riskCompletedAt,
      label: `Risk assessment calculated (${risk.riskScore}/100)`,
      status: risk.riskScore >= 50 ? 'alert' : 'done',
    },
    {
      at: aiCompletedAt,
      label: `AI analysis ${aiAssessment ? 'completed' : 'unavailable'}`,
      status: aiAssessment ? 'done' : 'info',
    },
  ] satisfies {
    at: number;
    label: string;
    status: 'done' | 'alert' | 'info';
  }[];
  timelineEventsWithTimes.sort((a, b) => a.at - b.at);
  const timelineEvents: NonNullable<ScanResult['timelineEvents']> = timelineEventsWithTimes
    .map(({ at, ...event }) => ({ timestamp: formatTime(new Date(at)), ...event }));

  return {
    id: scanId,
    submittedUrl,
    targetUrl: norm.normalizedUrl,
    domain: norm.domain,
    timestamp,
    scanDurationMs: Date.now() - startedAt,
    resolvedIp: check.resolvedIp,
    dnsRecords,
    modules: {
      dns: { status: dnsStatus, message: dnsUnavailableMessage },
      http: { status: httpScan.status, message: httpScan.message },
      tls: {
        status: certificateRetrieved ? 'completed' : 'unavailable',
        message: tlsUnavailableMessage,
      },
      phishing: { status: 'completed' },
      threatIntel: {
        status: 'completed',
        message: threatIntel.matches.length
          ? 'Matched against submitted community threat reports.'
          : 'No community threat report matched; no external threat feeds are configured.',
      },
      ai: {
        status: aiAssessment ? 'completed' : 'unavailable',
        message: aiAssessment ? undefined : process.env.GEMINI_API_KEY
          ? 'AI assessment is unavailable; see server logs for the provider error.'
          : 'Gemini analysis is not configured.',
      },
    },
    hostingProvider: hosting.hostingProvider,
    asn: hosting.asn,
    timelineEvents,
    detectionModel: aiAssessment ? 'GEMINI_AI' : 'RULE_BASED',
    riskScore: risk.riskScore,
    riskCategory: risk.riskCategory,
    confidenceScore: risk.confidenceScore,
    dimensionalScores: risk.dimensionalScores,
    reasons: risk.reasons,
    recommendations: risk.recommendations,
    findings,
    phishingAnalysis: phishing.analysis,
    securityHeaders: httpScan.headers,
    tlsCertificate: tlsResult.certificate,
    threatIntelMatches: threatIntel.matches,
    redirectChain: httpScan.redirectChain,
    aiAssessment,
    isDemoFixture: false,
  };
}
