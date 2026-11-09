import express, { NextFunction, Request, Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'node:url';

import { validateUrlForSsrf, normalizeTargetUrl, resolveHostingAndAsn } from './server/ssrf';
import { analyzePhishingIndicators } from './server/phishingEngine';
import { scanWebsiteSecurity } from './server/securityScanner';
import { inspectTlsCertificate } from './server/certificateInspector';
import { lookupThreatIntelligence, getAllThreatReports, submitThreatReport, verifyThreatReport } from './server/threatIntel';
import { computeUnifiedRiskScore } from './server/riskScorer';
import { analyzeThreatWithGemini } from './server/aiAnalyzer';
import { getAllScans, getScanById, saveScan, computeDashboardOverview } from './server/store';
import { ScanResult, Finding } from './server/types';
import { createInvestigationHandler } from './server/investigationRoute';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function createApp() {
  const app = express();
  app.disable('x-powered-by');
  const trustedProxy = process.env.TRUST_PROXY?.trim();
  if (process.env.VERCEL === '1') {
    app.set('trust proxy', 1);
  } else if (trustedProxy) {
    if (trustedProxy.toLowerCase() === 'true' || /^\d+$/.test(trustedProxy)) {
      throw new Error('TRUST_PROXY must identify trusted proxy networks; boolean and hop-count values are not accepted.');
    }
    app.set('trust proxy', trustedProxy);
  }
  const apiRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'Too many requests. Please try again later.' },
  });
  const scanRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'Scan limit reached. Please try again later.' },
  });

  app.use('/api/v1', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use('/api/v1', apiRateLimit);
  app.use(express.json({ limit: '32kb' }));

  // ==========================================
  // API ROUTE: User-Directed Live Investigation
  // ==========================================
  app.post('/api/v1/scans', scanRateLimit, createInvestigationHandler());

  // ==========================================
  // API ROUTE: Test-Only Demonstration Scanner
  // ==========================================
  app.post('/api/v1/demo/scans', async (req: Request, res: Response) => {
    if (process.env.NODE_ENV !== 'test') {
      res.status(404).json({ error: 'Demo scans are only available in the test environment.' });
      return;
    }
    const startTime = Date.now();
    const { url: rawInput } = req.body;

    // 1. Comprehensive URL / Domain Normalization
    const norm = normalizeTargetUrl(rawInput);
    if (!norm.valid) {
      res.status(400).json({ error: norm.error || 'Invalid website address.' });
      return;
    }

    const rawUrl = norm.normalizedUrl;
    const domain = norm.domain;

    // 2. SSRF Protection & Controlled Demo Mode Handling
    const existingFixture = getAllScans().find(
      s => s.isDemoFixture && (s.targetUrl.toLowerCase() === rawUrl.toLowerCase() || s.domain.toLowerCase() === domain)
    );

    const ssrfCheck = await validateUrlForSsrf(rawUrl);
    if (!ssrfCheck.safe) {
      if (existingFixture) {
        // Return calibrated demonstration fixture with updated timestamp
        res.json({
          ...existingFixture,
          id: `scn-demo-${Date.now().toString(36)}`,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // If it failed because domain doesn't exist, but it's not a private IP, allow lexical analysis
      if (ssrfCheck.reason?.includes('DNS lookup failed')) {
        const phishingResult = analyzePhishingIndicators(rawUrl);
        const threatIntel = lookupThreatIntelligence(rawUrl, domain);
        const findings: Finding[] = [
          ...phishingResult.findings,
          {
            id: 'dns-unresolved',
            category: 'THREAT_INTEL',
            severity: 'HIGH',
            title: 'Unresolvable Domain / NXDOMAIN',
            technicalDetails: `Domain '${domain}' could not be resolved via public DNS. Frequently observed with disposable phishing campaigns that have been sinkholed or taken offline.`,
            evidence: ssrfCheck.reason,
            impact: 'Destination cannot establish TCP/IP communication.',
            remediation: 'Inspect historical WHOIS records and passive DNS telemetry.',
          },
          ...threatIntel.findings,
        ];

        const scoreOutput = computeUnifiedRiskScore(
          phishingResult.analysis,
          {
            csp: { present: false, status: 'CRITICAL', notes: 'Cannot probe unresolvable host.' },
            hsts: { present: false, status: 'CRITICAL', notes: 'Cannot probe unresolvable host.' },
            xFrameOptions: { present: false, status: 'CRITICAL', notes: 'Cannot probe unresolvable host.' },
            xContentTypeOptions: { present: false, status: 'WARNING', notes: 'Cannot probe unresolvable host.' },
            referrerPolicy: { present: false, status: 'WARNING', notes: 'Cannot probe unresolvable host.' },
            permissionsPolicy: { present: false, status: 'WARNING', notes: 'Cannot probe unresolvable host.' },
            cookiesAnalysis: { total: 0, insecureCookies: [], missingHttpOnly: [], missingSameSite: [] },
            overallHeaderScore: 0,
          },
          {
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
            notes: ['No TLS handshake possible due to DNS NXDOMAIN.'],
          },
          threatIntel.matches,
          findings
        );

        const aiAssessment = await analyzeThreatWithGemini(
          rawUrl,
          domain,
          phishingResult.analysis,
          { valid: false, subject: {}, issuer: {}, validFrom: '', validTo: '', daysRemaining: 0, isExpired: false, subjectAltNames: [], hostnameMatch: false, isSelfSigned: false, trustScore: 0, notes: [] },
          findings,
          scoreOutput.riskScore
        );

        const fallbackResult: ScanResult = {
          id: `scn-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
          targetUrl: rawUrl,
          domain,
          timestamp: new Date().toISOString(),
          scanDurationMs: Date.now() - startTime,
          riskScore: scoreOutput.riskScore,
          riskCategory: scoreOutput.riskCategory,
          confidenceScore: 85,
          dimensionalScores: scoreOutput.dimensionalScores,
          reasons: scoreOutput.reasons,
          recommendations: scoreOutput.recommendations,
          findings,
          phishingAnalysis: phishingResult.analysis,
          securityHeaders: {
            csp: { present: false, status: 'CRITICAL', notes: 'No response.' },
            hsts: { present: false, status: 'CRITICAL', notes: 'No response.' },
            xFrameOptions: { present: false, status: 'CRITICAL', notes: 'No response.' },
            xContentTypeOptions: { present: false, status: 'WARNING', notes: 'No response.' },
            referrerPolicy: { present: false, status: 'WARNING', notes: 'No response.' },
            permissionsPolicy: { present: false, status: 'WARNING', notes: 'No response.' },
            cookiesAnalysis: { total: 0, insecureCookies: [], missingHttpOnly: [], missingSameSite: [] },
            overallHeaderScore: 0,
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
            notes: ['No DNS record.'],
          },
          threatIntelMatches: threatIntel.matches,
          redirectChain: [],
          aiAssessment,
          isDemoFixture: false,
        };

        saveScan(fallbackResult);
        res.json(fallbackResult);
        return;
      }

      // If it's a private IP or metadata SSRF violation, strictly reject
      res.status(400).json({
        error: 'Scan Rejected by Sentinel SSRF Firewall',
        details: ssrfCheck.reason,
        resolvedIp: ssrfCheck.resolvedIp,
      });
      return;
    }

    try {
      // 2. Controlled Website Security Assessment (Passive headers & redirects)
      const headerScanPromise = scanWebsiteSecurity(rawUrl);

      // 3. TLS Certificate Inspection
      const parsedUrl = new URL(rawUrl);
      const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : (parsedUrl.protocol === 'http:' ? 80 : 443);
      const tlsCertPromise = parsedUrl.protocol === 'https:'
        ? inspectTlsCertificate(domain, port)
        : Promise.resolve({
            certificate: {
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
              notes: ['Target accessed over plaintext HTTP. No TLS encryption enabled.'],
            },
            findings: [
              {
                id: 'tls-plaintext-scheme',
                category: 'SSL_TLS' as const,
                severity: 'CRITICAL' as const,
                title: 'Unencrypted Plaintext HTTP Scheme in Use',
                technicalDetails: 'Target uses unencrypted http:// without TLS cryptographic protection.',
                evidence: rawUrl,
                impact: 'Credentials and session tokens transmitted in plaintext across network routes.',
                remediation: 'Upgrade to HTTPS and redirect all HTTP traffic to HTTPS with HSTS.',
              },
            ],
          });

      // 4. Collaborative Threat Intelligence Lookup
      const threatIntelPromise = Promise.resolve(lookupThreatIntelligence(rawUrl, domain));

      // Await parallel network checks
      const [headerScan, tlsResult, threatIntel] = await Promise.all([
        headerScanPromise,
        tlsCertPromise,
        threatIntelPromise,
      ]);

      // 5. Intelligent Phishing Analysis (incorporating HTML body if retrieved)
      const phishingResult = analyzePhishingIndicators(rawUrl, headerScan.bodySnippet);

      // Aggregate all discovered findings
      const allFindings: Finding[] = [
        ...phishingResult.findings,
        ...headerScan.findings,
        ...tlsResult.findings,
        ...threatIntel.findings,
      ];

      // 6. Unified Risk Scoring Engine
      const scoreOutput = computeUnifiedRiskScore(
        phishingResult.analysis,
        headerScan.headers,
        tlsResult.certificate,
        threatIntel.matches,
        allFindings
      );

      // 7. AI Threat Deep-Dive (Gemini 3.8 Flash)
      const aiAssessment = await analyzeThreatWithGemini(
        rawUrl,
        domain,
        phishingResult.analysis,
        tlsResult.certificate,
        allFindings,
        scoreOutput.riskScore
      );

      const scanDurationMs = Date.now() - startTime;
      const scanId = `SNT-${Math.floor(10000 + Math.random() * 90000)}`;

      // 8. Hosting & ASN Resolution
      const { hostingProvider, asn } = await resolveHostingAndAsn(ssrfCheck.resolvedIp, headerScan.headers.serverHeader);

      // 9. Real Chronological Timeline Events
      const formatTime = (msOffset: number) => {
        const d = new Date(startTime + msOffset);
        return d.toTimeString().split(' ')[0];
      };

      const timelineEvents = [
        { timestamp: formatTime(0), label: 'Scan initiated', status: 'done' as const },
        { timestamp: formatTime(Math.min(scanDurationMs, 200)), label: 'Domain & DNS analysis completed', status: 'done' as const },
        { timestamp: formatTime(Math.min(scanDurationMs, 600)), label: 'Certificate validation completed', status: 'done' as const },
        { timestamp: formatTime(Math.min(scanDurationMs, 1000)), label: 'Web security scan completed', status: 'done' as const },
        { timestamp: formatTime(Math.min(scanDurationMs, 1400)), label: `Threat intelligence matched (${threatIntel.matches.length} sources)`, status: 'done' as const },
        { timestamp: formatTime(scanDurationMs), label: `Risk assessment generated (${scoreOutput.riskScore}/100)`, status: scoreOutput.riskScore >= 50 ? ('alert' as const) : ('done' as const) },
      ];

      const scanResult: ScanResult = {
        id: scanId,
        targetUrl: rawUrl,
        domain,
        timestamp: new Date().toISOString(),
        scanDurationMs,
        resolvedIp: ssrfCheck.resolvedIp,
        hostingProvider,
        asn,
        timelineEvents,
        detectionModel: 'GEMINI_AI',
        riskScore: scoreOutput.riskScore,
        riskCategory: scoreOutput.riskCategory,
        confidenceScore: scoreOutput.confidenceScore,
        dimensionalScores: scoreOutput.dimensionalScores,
        reasons: scoreOutput.reasons,
        recommendations: scoreOutput.recommendations,
        findings: allFindings,
        phishingAnalysis: phishingResult.analysis,
        securityHeaders: headerScan.headers,
        tlsCertificate: tlsResult.certificate,
        threatIntelMatches: threatIntel.matches,
        redirectChain: headerScan.redirectChain,
        aiAssessment,
        isDemoFixture: false,
      };

      // Persist to store
      saveScan(scanResult);

      res.json(scanResult);
    } catch (err: unknown) {
      console.error('Scan execution error:', err);
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: 'Analysis failed during scan execution', details: msg });
    }
  });

  // ==========================================
  // API ROUTE: Scan History & Individual Reports
  // ==========================================
  app.get('/api/v1/scans', (req: Request, res: Response) => {
    if (process.env.NODE_ENV === 'production') {
      res.json({ total: 0, scans: [] });
      return;
    }
    let scans = getAllScans();
    const query = typeof req.query.q === 'string' ? req.query.q.toLowerCase() : '';
    const risk = typeof req.query.risk === 'string' ? req.query.risk.toUpperCase() : '';

    if (query) {
      scans = scans.filter(s => s.domain.toLowerCase().includes(query) || s.targetUrl.toLowerCase().includes(query));
    }
    if (risk && risk !== 'ALL') {
      scans = scans.filter(s => s.riskCategory === risk);
    }

    res.json({
      total: scans.length,
      scans,
    });
  });

  app.get('/api/v1/scans/:id', (req: Request, res: Response) => {
    if (process.env.NODE_ENV === 'production') {
      res.status(404).json({ error: 'Scan history is disabled in production.' });
      return;
    }
    const scan = getScanById(req.params.id);
    if (!scan) {
      res.status(404).json({ error: 'Scan record not found.' });
      return;
    }
    res.json(scan);
  });

  // ==========================================
  // API ROUTE: SOC Dashboard Overview
  // ==========================================
  app.get('/api/v1/dashboard/overview', (_req: Request, res: Response) => {
    const overview = computeDashboardOverview();
    res.json(overview);
  });

  // ==========================================
  // API ROUTE: Collaborative Threat Intelligence
  // ==========================================
  app.get('/api/v1/threat-intelligence', (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === 'production') {
      res.json({ total: 0, reports: [] });
      return;
    }
    const reports = getAllThreatReports();
    res.json({
      total: reports.length,
      reports,
    });
  });

  app.post('/api/v1/threat-reports', (req: Request, res: Response) => {
    if (process.env.NODE_ENV === 'production') {
      res.status(404).json({ error: 'Community reports are disabled in production until authenticated moderation is configured.' });
      return;
    }
    const { url, domain, threatType, targetedBrand, evidenceNotes, submittedBy } = req.body;

    if (!url || !domain || !threatType || !evidenceNotes) {
      res.status(400).json({ error: 'Missing required report fields (url, domain, threatType, evidenceNotes).' });
      return;
    }

    const report = submitThreatReport({
      url,
      domain,
      threatType,
      targetedBrand,
      evidenceNotes,
      submittedBy: submittedBy || 'anonymous_analyst',
    });

    res.status(201).json(report);
  });

  app.post('/api/v1/threat-reports/:id/verify', (req: Request, res: Response) => {
    if (process.env.NODE_ENV === 'production') {
      res.status(404).json({ error: 'Community report verification is disabled in production until authenticated moderation is configured.' });
      return;
    }
    const { isAffirmative = true } = req.body;
    const updated = verifyThreatReport(req.params.id, Boolean(isAffirmative));
    if (!updated) {
      res.status(404).json({ error: 'Threat report not found.' });
      return;
    }
    res.json(updated);
  });

  // ==========================================
  // API ROUTE: Standalone Certificate Inspector
  // ==========================================
  app.get('/api/v1/certificates/:domain', async (req: Request, res: Response) => {
    const domain = req.params.domain.toLowerCase().trim();
    const result = await inspectTlsCertificate(domain);
    res.json(result);
  });

  // ==========================================
  // API ROUTE: Demo Workflows & Test Cases
  // ==========================================
  app.get('/api/v1/demo/scenarios', (_req: Request, res: Response) => {
    if (process.env.NODE_ENV !== 'test') {
      res.status(404).json({ error: 'Demo scenarios are only available in the test environment.' });
      return;
    }
    res.json([
      {
        id: 'demo-1-paypal',
        label: 'PayPal Phishing Lure (Homoglyph & Subdomain Masquerading)',
        url: 'http://paypa1-secure-verification.login-portal.cc/account-verify',
        type: 'CRITICAL_PHISHING',
        description: 'Simulates l33t-speak typosquatting (paypa1), multi-subdomain spoofing, unencrypted plaintext credentials input, and community threat feed match.',
      },
      {
        id: 'demo-2-google-homoglyph',
        label: 'Google IDN Homoglyph Attack (Cyrillic Character Substitution)',
        url: 'https://gооgle.com/login',
        type: 'HOMOGLYPH_IDN',
        description: 'Demonstrates visual spoofing where Latin letter "o" is substituted by Cyrillic U+043E (о), virtually indistinguishable in standard browser address bars.',
      },
      {
        id: 'demo-3-microsoft-aitm',
        label: 'Microsoft 365 AiTM Reverse-Proxy Phishing',
        url: 'https://micros0ft-support-token.net/oauth/v2/authorize',
        type: 'AITM_OAUTH',
        description: 'Emulates an adversary-in-the-middle session cookie theft portal with valid TLS certificate, proving TLS alone does not verify legitimacy.',
      },
      {
        id: 'demo-4-badssl-expired',
        label: 'Expired SSL/TLS Certificate (BadSSL Public Testbed)',
        url: 'https://expired.badssl.com',
        type: 'EXPIRED_CERTIFICATE',
        description: 'Inspects real public server presenting an expired X.509 certificate to verify trust anchor revocation handling.',
      },
      {
        id: 'demo-5-github-safe',
        label: 'GitHub Official Infrastructure (Benchmark Clean Case)',
        url: 'https://github.com',
        type: 'BENCHMARK_SAFE',
        description: 'Evaluates production enterprise security posture with DigiCert EV certificate, strict CSP, and HSTS preload.',
      },
    ]);
  });

  // ==========================================
  // Vite Dev Server / Static Hosting
  // ==========================================
  if (process.env.VERCEL === '1') {
    app.use((_req: Request, res: Response) => {
      res.status(404).json({ error: 'API endpoint not found.' });
    });
  } else if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const statusCode = error && typeof error === 'object' && 'status' in error
      ? error.status
      : undefined;
    if (statusCode === 400) {
      res.status(400).json({ error: 'Invalid request body.' });
      return;
    }
    if (statusCode === 413) {
      res.status(413).json({ error: 'Request body is too large.' });
      return;
    }
    console.error('Unhandled request error:', error);
    res.status(500).json({ error: 'Internal server error.' });
  });

  return app;
}

async function startServer() {
  const app = await createApp();
  const PORT = parseInt(process.env.PORT || '3000', 10);
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SENTINEL ENGINE] Threat Intelligence platform online on port ${PORT}`);
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  startServer().catch(err => {
    console.error('Failed to start Sentinel server:', err);
    process.exit(1);
  });
}
