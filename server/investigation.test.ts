import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import { once } from 'node:events';
import { test } from 'node:test';
import { getScanById, saveScan } from './store';
import { investigateSubmittedUrl, InvestigationError } from './investigation';
import { isPrivateOrReservedIp, normalizeTargetUrl, validateUrlForSsrf } from './ssrf';
import { HeaderScanResult } from './securityScanner';
import { TlsCertificateAnalysis } from './types';
import { createInvestigationHandler } from './investigationRoute';
import { restoreVercelApiPath } from './vercelPath';

process.env.GEMINI_API_KEY = '';

function headers(serverHeader?: string): HeaderScanResult['headers'] {
  const missing = (notes: string) => ({ present: false, status: 'WARNING' as const, notes });
  return {
    csp: missing('Not returned by controlled test response.'),
    hsts: missing('Not returned by controlled test response.'),
    xFrameOptions: missing('Not returned by controlled test response.'),
    xContentTypeOptions: missing('Not returned by controlled test response.'),
    referrerPolicy: missing('Not returned by controlled test response.'),
    permissionsPolicy: missing('Not returned by controlled test response.'),
    serverHeader,
    cookiesAnalysis: { total: 0, insecureCookies: [], missingHttpOnly: [], missingSameSite: [] },
    overallHeaderScore: 0,
  };
}

function certificate(domain: string): TlsCertificateAnalysis {
  return {
    valid: true,
    subject: { commonName: domain },
    issuer: { commonName: 'Controlled Test CA' },
    validFrom: '2025-01-01T00:00:00.000Z',
    validTo: '2030-01-01T00:00:00.000Z',
    daysRemaining: 1200,
    isExpired: false,
    subjectAltNames: [domain],
    hostnameMatch: true,
    isSelfSigned: false,
    trustScore: 100,
    notes: ['Certificate returned by controlled test fixture.'],
  };
}

function httpResult(url: string, serverHeader: string): HeaderScanResult {
  return {
    headers: headers(serverHeader),
    redirectChain: [{ hopIndex: 1, url, statusCode: 200, isExternalDomain: false }],
    findings: [],
    bodySnippet: '<html><body><form><input type="password"></form></body></html>',
    finalStatusCode: 200,
    headersAvailable: true,
    status: 'completed',
  };
}

const controlledHosting = async () => ({
  hostingProvider: 'Controlled test address',
  asn: 'Not configured in test',
});

test('normalizes arbitrary hostnames without a supported-domain allowlist', () => {
  const inputs = [
    'https://google.com/search?q=sentinel',
    'amazon.in/products',
    'https://mynew-domain.example.edu/path',
    'https://xn--bcher-kva.example/',
  ];

  for (const input of inputs) {
    const normalized = normalizeTargetUrl(input);
    assert.equal(normalized.valid, true, input);
    assert.ok(normalized.domain);
  }
});

test('passes each submitted host through live modules and stores independent unique results', async () => {
  const submittedUrls = [
    'https://google.com/search?q=sentinel',
    'amazon.in/products',
    'https://newly-registered.example.edu/portal',
  ];
  const httpTargets: string[] = [];
  const tlsTargets: string[] = [];
  const results = [];

  for (const submittedUrl of submittedUrls) {
    const result = await investigateSubmittedUrl(submittedUrl, {
      validateUrl: async url => ({
        safe: true,
        resolvedIp: '203.0.113.19',
        resolvedAddresses: [{ address: '203.0.113.19', family: 4 }],
      }),
      collectDns: async hostname => ({
        A: [`198.51.100.${hostname.length}`],
        AAAA: [],
        MX: [],
        NS: [`ns.${hostname}`],
        TXT: [],
      }),
      resolveHosting: controlledHosting,
      scanHttp: async url => {
        httpTargets.push(url);
        return httpResult(url, `controlled-${new URL(url).hostname}`);
      },
      inspectTls: async (domain) => {
        tlsTargets.push(domain);
        return { certificate: certificate(domain), findings: [] };
      },
    });
    saveScan(result);
    results.push(result);
  }

  assert.equal(new Set(results.map(result => result.id)).size, submittedUrls.length);
  results.forEach((result, index) => {
    const expected = normalizeTargetUrl(submittedUrls[index]);
    assert.equal(result.submittedUrl, submittedUrls[index]);
    assert.equal(result.targetUrl, expected.normalizedUrl);
    assert.equal(result.domain, expected.domain);
    assert.equal(result.id.startsWith('SNT-'), true);
    assert.equal(result.dnsRecords?.NS[0], `ns.${expected.domain}`);
    assert.equal(result.securityHeaders.serverHeader, `controlled-${expected.domain}`);
    assert.equal(result.modules?.http.status, 'completed');
    assert.equal(result.modules?.tls.status, 'completed');
    assert.ok(result.findings.every(finding => Boolean(finding.source)));
    assert.equal(getScanById(result.id)?.domain, expected.domain);
  });
  assert.deepEqual(httpTargets, results.map(result => result.targetUrl));
  assert.deepEqual(tlsTargets, results.map(result => result.domain));
});

test('processes separate user submissions through the HTTP API and persists each response by scan ID', async () => {
  const app = express();
  app.use(express.json());
  app.post('/api/v1/scans', createInvestigationHandler({
    validateUrl: async url => ({
      safe: true,
      resolvedIp: `203.0.113.${new URL(url).hostname.length}`,
      resolvedAddresses: [{ address: '203.0.113.23', family: 4 }],
    }),
    collectDns: async hostname => ({
      A: [`198.51.100.${hostname.length}`],
      AAAA: [],
      MX: [],
      NS: [],
      TXT: [],
    }),
    resolveHosting: controlledHosting,
    scanHttp: async url => httpResult(url, `api-fixture-${new URL(url).hostname}`),
    inspectTls: async domain => ({ certificate: certificate(domain), findings: [] }),
  }));
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');

  try {
    const submittedUrls = [
      'https://first-customer.example.test/one',
      'https://different-customer.example.edu/two',
    ];
    const responses = await Promise.all(submittedUrls.map(url => fetch(
      `http://127.0.0.1:${address.port}/api/v1/scans`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url }),
      },
    )));
    const results = await Promise.all(responses.map(response => response.json()));

    assert.ok(responses.every(response => response.ok));
    assert.equal(new Set(results.map(result => result.id)).size, 2);
    results.forEach((result, index) => {
      const domain = new URL(submittedUrls[index]).hostname;
      assert.equal(result.submittedUrl, submittedUrls[index]);
      assert.equal(result.domain, domain);
      assert.equal(result.securityHeaders.serverHeader, `api-fixture-${domain}`);
      assert.equal(getScanById(result.id)?.targetUrl, result.targetUrl);
    });
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('does not retain scans in production mode', async () => {
  const result = await investigateSubmittedUrl('https://private-customer.example.test/assessment', {
    validateUrl: async () => ({
      safe: true,
      resolvedIp: '203.0.113.24',
      resolvedAddresses: [{ address: '203.0.113.24', family: 4 }],
    }),
    collectDns: async () => ({ A: [], AAAA: [], MX: [], NS: [], TXT: [] }),
    resolveHosting: controlledHosting,
    scanHttp: async url => httpResult(url, 'controlled-fixture'),
    inspectTls: async domain => ({ certificate: certificate(domain), findings: [] }),
  });
  const previousNodeEnv = process.env.NODE_ENV;

  try {
    process.env.NODE_ENV = 'production';
    saveScan(result);
    assert.equal(getScanById(result.id), undefined);
  } finally {
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
  }
});

test('creates a Vercel-compatible API app without opening a standalone listener', async () => {
  const previousVercel = process.env.VERCEL;
  const previousNodeEnv = process.env.NODE_ENV;
  process.env.VERCEL = '1';
  process.env.NODE_ENV = 'production';

  let server: http.Server | undefined;
  try {
    const { createApp } = await import('../server');
    const app = await createApp();
    server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();
    assert.ok(address && typeof address !== 'string');

    const historyResponse = await fetch(`http://127.0.0.1:${address.port}/api/v1/scans`);
    assert.equal(historyResponse.status, 200);
    assert.deepEqual(await historyResponse.json(), { total: 0, scans: [] });

    const privateTargetResponse = await fetch(`http://127.0.0.1:${address.port}/api/v1/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'http://127.0.0.1' }),
    });
    assert.equal(privateTargetResponse.status, 400);
    assert.equal(typeof (await privateTargetResponse.json()).error, 'string');
  } finally {
    if (server?.listening) {
      server.close();
      await once(server, 'close');
    }
    if (previousVercel === undefined) delete process.env.VERCEL;
    else process.env.VERCEL = previousVercel;
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
  }
});

test('restores Vercel-rewritten API paths and preserves caller query parameters', () => {
  const request = { url: '/api/index?__sentinel_path=v1%2Fscans&q=customer&risk=ALL' };
  restoreVercelApiPath(request);
  assert.equal(request.url, '/api/v1/scans?q=customer&risk=ALL');
});

test('runs a real HTTP inspection against a controlled local website with the validated IP pinned', async () => {
  let observedHost = '';
  let requestCount = 0;
  const server = http.createServer((request, response) => {
    requestCount++;
    observedHost = request.headers.host || '';
    response.writeHead(200, {
      'content-type': 'text/html',
      'server': 'controlled-fixture',
      'x-content-type-options': 'nosniff',
    });
    response.end('<form><input type="password"></form>');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');

  try {
    const submittedUrl = `http://customer-defined-${Date.now()}.example.test:${address.port}/login/verify`;
    const result = await investigateSubmittedUrl(submittedUrl, {
      validateUrl: async () => ({
        safe: true,
        resolvedIp: '127.0.0.1',
        resolvedAddresses: [{ address: '127.0.0.1', family: 4 }],
      }),
      collectDns: async () => ({
        A: ['127.0.0.1'],
        AAAA: [],
        MX: [],
        NS: [],
        TXT: [],
      }),
      resolveHosting: controlledHosting,
    });

    assert.equal(requestCount, 1, JSON.stringify({ modules: result.modules, findings: result.findings }));
    assert.equal(observedHost, new URL(submittedUrl).host);
    assert.equal(result.submittedUrl, submittedUrl);
    assert.equal(result.domain, new URL(submittedUrl).hostname);
    assert.equal(result.securityHeaders.serverHeader, 'controlled-fixture');
    assert.equal(result.redirectChain[0].url, result.targetUrl);
    assert.equal(result.modules?.http.status, 'completed');
    assert.ok(result.phishingAnalysis.detectedFormsCount);
    assert.ok(result.findings.some(finding => finding.source === 'Retrieved HTML content inspection'));
    assert.ok(result.findings.some(finding => finding.title.includes('Content-Security-Policy')));
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('reports DNS failure without inventing web or certificate findings', async () => {
  const result = await investigateSubmittedUrl('https://unregistered-host.invalid/path', {
    validateUrl: async () => ({ safe: false, reason: 'DNS lookup failed: controlled NXDOMAIN' }),
    collectDns: async () => ({ A: [], AAAA: [], MX: [], NS: [], TXT: [] }),
    resolveHosting: controlledHosting,
  });

  assert.equal(result.modules?.dns.status, 'unavailable');
  assert.equal(result.modules?.http.status, 'unavailable');
  assert.equal(result.modules?.tls.status, 'unavailable');
  assert.equal(result.modules?.dns.message, 'DNS lookup failed: controlled NXDOMAIN');
  assert.equal(result.resolvedIp, undefined);
  assert.equal(result.findings.length, 0);
});

test('reports an unavailable web endpoint without treating missing response headers as findings', async () => {
  const closedServer = http.createServer();
  closedServer.listen(0, '127.0.0.1');
  await once(closedServer, 'listening');
  const address = closedServer.address();
  assert.ok(address && typeof address !== 'string');
  closedServer.close();
  await once(closedServer, 'close');

  const result = await investigateSubmittedUrl(`http://unavailable-${Date.now()}.example.test:${address.port}/`, {
    validateUrl: async () => ({
      safe: true,
      resolvedIp: '127.0.0.1',
      resolvedAddresses: [{ address: '127.0.0.1', family: 4 }],
    }),
    collectDns: async () => ({ A: [], AAAA: [], MX: [], NS: [], TXT: [] }),
    resolveHosting: controlledHosting,
  });

  assert.equal(result.modules?.http.status, 'unavailable');
  assert.ok(result.findings.some(finding => finding.id === 'sec-connection-error'));
  assert.ok(!result.findings.some(finding => finding.id === 'sec-missing-csp'));
});

test('reports the certificate actually returned by the TLS module, including certificate issues', async () => {
  const submittedUrl = 'https://certificate-case.example.test:8443/account';
  const canonicalDomain = 'certificate-case.example.test';
  const invalidCertificate = {
    ...certificate(canonicalDomain),
    valid: false,
    isExpired: true,
    daysRemaining: -3,
    trustScore: 0,
    notes: ['Certificate expired three days ago.'],
  };
  let observedDomain = '';
  let observedPort: number | undefined;
  const result = await investigateSubmittedUrl(submittedUrl, {
    validateUrl: async () => ({
      safe: true,
      resolvedIp: '203.0.113.21',
      resolvedAddresses: [{ address: '203.0.113.21', family: 4 }],
    }),
    collectDns: async () => ({ A: ['203.0.113.21'], AAAA: [], MX: [], NS: [], TXT: [] }),
    resolveHosting: controlledHosting,
    scanHttp: async url => httpResult(url, 'controlled-tls-fixture'),
    inspectTls: async (domain, port) => {
      observedDomain = domain;
      observedPort = port;
      return {
        certificate: invalidCertificate,
        findings: [{
          id: 'controlled-expired-certificate',
          category: 'SSL_TLS',
          severity: 'HIGH',
          title: 'Certificate expired',
          technicalDetails: 'The test certificate is expired.',
          evidence: 'Controlled TLS fixture',
          impact: 'Certificate trust is unavailable.',
          remediation: 'Renew the test certificate.',
        }],
      };
    },
  });

  assert.equal(observedDomain, canonicalDomain);
  assert.equal(observedPort, 8443);
  assert.equal(result.modules?.tls.status, 'completed');
  assert.equal(result.tlsCertificate.isExpired, true);
  assert.ok(result.findings.some(finding => finding.source === 'Observed TLS handshake and certificate'));
});

test('rejects malformed inputs and private IP destinations', async () => {
  await assert.rejects(
    investigateSubmittedUrl('not a valid URL/%'),
    error => error instanceof InvestigationError && error.statusCode === 400,
  );
  const privateIp = await validateUrlForSsrf('http://127.0.0.1/');
  assert.equal(privateIp.safe, false);
  await assert.rejects(
    investigateSubmittedUrl('http://127.0.0.1/'),
    error => error instanceof InvestigationError && error.statusCode === 400,
  );
});

test('blocks private, reserved, mapped, and documentation IP ranges while permitting public addresses', () => {
  for (const address of [
    '127.0.0.1',
    '10.0.0.2',
    '172.20.1.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '198.51.100.10',
    '203.0.113.10',
    '::1',
    'fc00::1',
    'fe80::1',
    '2001:db8::1',
    '::ffff:127.0.0.1',
  ]) {
    assert.equal(isPrivateOrReservedIp(address), true, address);
  }
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
  assert.equal(isPrivateOrReservedIp('2606:4700:4700::1111'), false);
});

test('blocks a redirect to a private destination before making a second request', async () => {
  let requestCount = 0;
  const server = http.createServer((_request, response) => {
    requestCount++;
    response.writeHead(302, { location: 'http://127.0.0.1:9/private' });
    response.end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');

  try {
    const result = await investigateSubmittedUrl(
      `http://redirect-check-${Date.now()}.example.test:${address.port}/`,
      {
        validateUrl: async () => ({
          safe: true,
          resolvedIp: '127.0.0.1',
          resolvedAddresses: [{ address: '127.0.0.1', family: 4 }],
        }),
        collectDns: async () => ({ A: [], AAAA: [], MX: [], NS: [], TXT: [] }),
        resolveHosting: controlledHosting,
      },
    );

    assert.equal(requestCount, 1, JSON.stringify({ modules: result.modules, findings: result.findings }));
    assert.equal(result.modules?.http.status, 'partial');
    assert.ok(result.findings.some(finding => finding.id === 'sec-redirect-restricted'));
    assert.equal(result.redirectChain.length, 1);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('marks automated-request blocking as partial instead of reporting absent headers', async () => {
  const server = http.createServer((_request, response) => {
    response.writeHead(403);
    response.end('Automated requests are denied');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');

  try {
    const result = await investigateSubmittedUrl(`http://blocked-${Date.now()}.example.test:${address.port}/`, {
      validateUrl: async () => ({
        safe: true,
        resolvedIp: '127.0.0.1',
        resolvedAddresses: [{ address: '127.0.0.1', family: 4 }],
      }),
      collectDns: async () => ({ A: [], AAAA: [], MX: [], NS: [], TXT: [] }),
      resolveHosting: controlledHosting,
    });
    assert.equal(result.modules?.http.status, 'partial');
    assert.match(result.modules?.http.message || '', /HTTP 403/);
    assert.ok(!result.findings.some(finding => finding.id === 'sec-missing-csp'));
  } finally {
    server.close();
    await once(server, 'close');
  }
});
