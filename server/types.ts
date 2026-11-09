export type RiskSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';

export interface Finding {
  id: string;
  category: 'PHISHING' | 'SECURITY_HEADERS' | 'SSL_TLS' | 'THREAT_INTEL' | 'REDIRECTION';
  severity: RiskSeverity;
  source?: string;
  title: string;
  technicalDetails: string;
  evidence: string;
  impact: string;
  remediation: string;
}

export interface PhishingAnalysis {
  probability: number; // 0 to 1
  riskCategory: RiskLevel;
  indicators: string[];
  homoglyphsDetected: { char: string; codePoint: string; replaces: string }[];
  typosquattingMatch?: { brand: string; distance: number; legitDomain: string };
  urlLength: number;
  subdomainCount: number;
  suspiciousKeywords: string[];
  isIpHost: boolean;
  hasSuspiciousTld: boolean;
  detectedFormsCount?: number;
  hasCredentialInputs?: boolean;
}

export interface SecurityHeaderAssessment {
  csp: { present: boolean; value?: string; status: 'GOOD' | 'WARNING' | 'CRITICAL'; notes: string };
  hsts: { present: boolean; value?: string; maxAge?: number; includeSubDomains?: boolean; preload?: boolean; status: 'GOOD' | 'WARNING' | 'CRITICAL'; notes: string };
  xFrameOptions: { present: boolean; value?: string; status: 'GOOD' | 'WARNING' | 'CRITICAL'; notes: string };
  xContentTypeOptions: { present: boolean; value?: string; status: 'GOOD' | 'WARNING'; notes: string };
  referrerPolicy: { present: boolean; value?: string; status: 'GOOD' | 'WARNING'; notes: string };
  permissionsPolicy: { present: boolean; value?: string; status: 'GOOD' | 'WARNING'; notes: string };
  serverHeader?: string;
  xPoweredBy?: string;
  cookiesAnalysis: {
    total: number;
    insecureCookies: string[];
    missingHttpOnly: string[];
    missingSameSite: string[];
  };
  overallHeaderScore: number; // 0 to 100
}

export interface TlsCertificateAnalysis {
  valid: boolean;
  subject: {
    commonName?: string;
    organization?: string;
    country?: string;
  };
  issuer: {
    commonName?: string;
    organization?: string;
    country?: string;
  };
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  isExpired: boolean;
  subjectAltNames: string[];
  hostnameMatch: boolean;
  isSelfSigned: boolean;
  signatureAlgorithm?: string;
  publicKeyAlgorithm?: string;
  keySizeBits?: number;
  cipher?: string;
  protocol?: string;
  trustScore: number; // 0 to 100
  notes: string[];
}

export interface ThreatIntelligenceMatch {
  source: string;
  category: 'KNOWN_PHISHING' | 'MALWARE' | 'SUSPICIOUS_REDIRECT' | 'COMMUNITY_REPORTED' | 'CLEAN';
  matchedValue: string;
  confidence: number;
  firstSeen?: string;
  reportCount?: number;
  tags: string[];
}

export interface RedirectHop {
  hopIndex: number;
  url: string;
  statusCode: number;
  isExternalDomain: boolean;
}

export interface AiThreatAssessment {
  analystSummary: string;
  threatActorsOrMotivation: string;
  psychologicalTactics: string[];
  mitreAttackTechniques: { id: string; name: string; description: string }[];
  userActionGuidance: string[];
  socRemediationSteps: string[];
  confidenceLevel: 'VERY_HIGH' | 'HIGH' | 'MODERATE' | 'LOW';
}

export interface ScanResult {
  id: string;
  submittedUrl?: string;
  targetUrl: string;
  domain: string;
  timestamp: string;
  scanDurationMs: number;
  resolvedIp?: string;
  dnsRecords?: {
    A: string[];
    AAAA: string[];
    MX: { priority: number; exchange: string }[];
    NS: string[];
    TXT: string[];
  };
  modules?: {
    dns: { status: 'completed' | 'partial' | 'unavailable'; message?: string };
    http: { status: 'completed' | 'partial' | 'unavailable'; message?: string };
    tls: { status: 'completed' | 'unavailable'; message?: string };
    phishing: { status: 'completed' };
    threatIntel: { status: 'completed'; message: string };
    ai: { status: 'completed' | 'unavailable'; message?: string };
  };
  riskScore: number; // 0 to 100
  riskCategory: RiskLevel;
  confidenceScore: number; // 0 to 100
  dimensionalScores: {
    phishingScore: number; // 35% weight
    securityHeadersScore: number; // 20% weight
    tlsTrustScore: number; // 20% weight
    threatIntelScore: number; // 25% weight
  };
  reasons: string[];
  recommendations: string[];
  findings: Finding[];
  phishingAnalysis: PhishingAnalysis;
  securityHeaders: SecurityHeaderAssessment;
  tlsCertificate: TlsCertificateAnalysis;
  threatIntelMatches: ThreatIntelligenceMatch[];
  redirectChain: RedirectHop[];
  aiAssessment?: AiThreatAssessment;
  hostingProvider?: string;
  asn?: string;
  timelineEvents?: { timestamp: string; label: string; status: 'done' | 'alert' | 'info' }[];
  detectionModel?: 'RULE_BASED' | 'HYBRID_ML' | 'GEMINI_AI';
  isDemoFixture?: boolean;
}

export interface ThreatReport {
  id: string;
  url: string;
  domain: string;
  threatType: 'PHISHING' | 'MALWARE' | 'BRAND_IMPERSONATION' | 'CREDENTIAL_HARVESTING' | 'PAYMENT_FRAUD';
  targetedBrand?: string;
  submittedAt: string;
  submittedBy: string;
  evidenceNotes: string;
  verificationsCount: number;
  disputesCount: number;
  status: 'PENDING' | 'VERIFIED' | 'DISPUTED';
  reputationScore: number;
}

export interface DashboardOverview {
  totalScans: number;
  safeCount: number;
  suspiciousCount: number;
  maliciousCount: number;
  activeFeedsCount: number;
  openFindingsCount: number;
  severityDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  attackSurface: {
    totalAssets: number;
    ipAddresses: number;
    services: number;
    domains: number;
    dnsRecords: number;
  };
  recentScans: ScanResult[];
  agingThreats: ThreatReport[];
}
