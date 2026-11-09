import http from 'http';
import https from 'https';
import { SecurityHeaderAssessment, RedirectHop, Finding } from './types';
import { SsrfValidationResult, validateUrlForSsrf } from './ssrf';

export interface HeaderScanResult {
  headers: SecurityHeaderAssessment;
  redirectChain: RedirectHop[];
  findings: Finding[];
  bodySnippet?: string;
  finalStatusCode: number;
  headersAvailable: boolean;
  status: 'completed' | 'partial' | 'unavailable';
  message?: string;
}

/**
 * Perform safe HTTP request adhering strictly to SSRF limits, 5s timeout, and redirect tracing.
 */
export async function scanWebsiteSecurity(
  initialUrl: string,
  initialValidation?: SsrfValidationResult,
): Promise<HeaderScanResult> {
  const redirectChain: RedirectHop[] = [];
  const findings: Finding[] = [];
  let currentUrl = initialUrl;
  let hops = 0;
  const MAX_HOPS = 5;

  let finalHeaders: http.IncomingHttpHeaders = {};
  let finalStatusCode = 0;
  let bodyAccumulator = '';
  let moduleMessage: string | undefined;

  while (hops < MAX_HOPS) {
    // 1. SSRF Check on current hop
    const ssrfCheck = hops === 0 && initialValidation
      ? initialValidation
      : await validateUrlForSsrf(currentUrl);
    if (!ssrfCheck.safe) {
      moduleMessage = ssrfCheck.reason || 'Destination could not be safely resolved.';
      if (hops > 0) {
        findings.push({
          id: 'sec-redirect-restricted',
          category: 'REDIRECTION',
          severity: 'INFORMATIONAL',
          source: 'HTTP redirect inspection',
          title: 'Redirect to a restricted destination was blocked',
          technicalDetails: moduleMessage,
          evidence: `Blocked redirect target: ${currentUrl}`,
          impact: 'The scanner stopped before connecting to a private or reserved address.',
          remediation: 'Review the observed redirect target before following it in a browser.',
        });
      }
      break;
    }

    try {
      const response = await executeSingleHop(currentUrl, ssrfCheck);
      finalHeaders = response.headers;
      finalStatusCode = response.statusCode;

      const currentDomain = new URL(currentUrl).hostname;
      const initialDomain = new URL(initialUrl).hostname;
      const isExternal = currentDomain !== initialDomain;

      redirectChain.push({
        hopIndex: hops + 1,
        url: currentUrl,
        statusCode: response.statusCode,
        isExternalDomain: isExternal,
      });

      if (response.body) {
        bodyAccumulator = response.body.slice(0, 50000); // 50KB snippet for content inspection
      }

      // Check if redirect
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers['location']) {
        const nextLoc = Array.isArray(response.headers['location'])
          ? response.headers['location'][0]
          : response.headers['location'];
        const nextUrl = new URL(nextLoc, currentUrl);
        const resolvedNextUrl = nextUrl.toString();

        if (nextUrl.username || nextUrl.password) {
          moduleMessage = 'Redirect target contained embedded credentials and was not followed.';
          findings.push({
            id: `sec-redirect-credentials-${hops}`,
            category: 'REDIRECTION',
            severity: 'INFORMATIONAL',
            source: 'HTTP redirect inspection',
            title: 'Redirect containing embedded credentials was blocked',
            technicalDetails: moduleMessage,
            evidence: `${currentUrl} -> ${resolvedNextUrl}`,
            impact: 'The scanner does not follow destinations with embedded authentication details.',
            remediation: 'Review the redirect target before opening it.',
          });
          break;
        }

        if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
          moduleMessage = `Redirect used a disallowed protocol: ${nextUrl.protocol}`;
          findings.push({
            id: `sec-redirect-protocol-${hops}`,
            category: 'REDIRECTION',
            severity: 'INFORMATIONAL',
            source: 'HTTP redirect inspection',
            title: 'Redirect to a disallowed protocol was blocked',
            technicalDetails: moduleMessage,
            evidence: `${currentUrl} -> ${resolvedNextUrl}`,
            impact: 'The scanner only follows HTTP and HTTPS destinations.',
            remediation: 'Review the redirect destination manually.',
          });
          break;
        }

        if (nextUrl.hostname !== initialDomain) {
          findings.push({
            id: `sec-external-redirect-${hops}`,
            category: 'REDIRECTION',
            severity: 'HIGH',
            source: 'HTTP redirect inspection',
            title: 'Cross-Domain Redirection Observed',
            technicalDetails: `The URL silently redirected from origin '${initialDomain}' to an external domain '${new URL(resolvedNextUrl).hostname}'.`,
            evidence: `${currentUrl} -> ${resolvedNextUrl}`,
            impact: 'Open redirects and sneaky forwarding chains are utilized to evade email scanners and spoof legitimate brands.',
            remediation: 'Validate redirect target against an allowlist before following cross-domain hops.',
          });
        }

        currentUrl = resolvedNextUrl;
        hops++;
      } else {
        // Final destination reached
        break;
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      moduleMessage = errMsg;
      findings.push({
        id: 'sec-connection-error',
        category: 'SECURITY_HEADERS',
        severity: 'INFORMATIONAL',
        source: 'HTTP response inspection',
        title: 'HTTP Probe Handshake Alert',
        technicalDetails: `Automated HTTP inspection encountered an error: ${errMsg}`,
        evidence: `Target: ${currentUrl}`,
        impact: 'Target server may be unreachable, rejecting programmatic crawlers, or utilizing rate-limiting.',
        remediation: 'Verify destination accessibility from an isolated browser sandbox.',
      });
      break;
    }
  }

  // Analyze the extracted headers
  const automatedRequestBlocked = [401, 403, 429].includes(finalStatusCode);
  const headerAssessment = finalStatusCode > 0 && !automatedRequestBlocked
    ? evaluateHeaders(finalHeaders, findings)
    : createUnavailableHeaders();

  return {
    headers: headerAssessment,
    redirectChain,
    findings,
    bodySnippet: automatedRequestBlocked ? undefined : bodyAccumulator,
    finalStatusCode,
    headersAvailable: finalStatusCode > 0 && !automatedRequestBlocked,
    status: finalStatusCode === 0
      ? 'unavailable'
      : moduleMessage || finalStatusCode === 403 || finalStatusCode === 429
        ? 'partial'
        : 'completed',
    message: moduleMessage || (finalStatusCode === 403 || finalStatusCode === 429
      ? `The website returned HTTP ${finalStatusCode}; automated access may be restricted.`
      : undefined),
  };
}

function executeSingleHop(targetUrl: string, validation: SsrfValidationResult): Promise<{
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;

    const req = client.request(
      targetUrl,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelSecurityScanner/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Connection': 'close',
        },
        timeout: 5000,
        lookup: (_hostname, options, callback) => {
          const pinned = validation.resolvedAddresses?.[0];
          if (!pinned) {
            const error = new Error('No validated address is available for this connection.');
            if (options.all) callback(error, []);
            else callback(error, '', 0);
            return;
          }
          if (options.all) callback(null, [pinned]);
          else callback(null, pinned.address, pinned.family);
        },
        // We reject unauthorized by default, but let's allow self-signed to capture real findings
        rejectUnauthorized: false,
      },
      res => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', chunk => {
          data += chunk;
          // Guard against payload flood
          if (data.length > 100000) {
            req.destroy();
            resolve({
              statusCode: res.statusCode || 200,
              headers: res.headers,
              body: data,
            });
          }

        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 200,
            headers: res.headers,
            body: data,
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out after 5000ms'));
    });

    req.on('error', err => {
      reject(err);
    });

    req.end();
  });
}

function createUnavailableHeaders(): SecurityHeaderAssessment {
  const notes = 'No HTTP response was received; security headers were not assessed.';
  return {
    csp: { present: false, status: 'WARNING', notes },
    hsts: { present: false, status: 'WARNING', notes },
    xFrameOptions: { present: false, status: 'WARNING', notes },
    xContentTypeOptions: { present: false, status: 'WARNING', notes },
    referrerPolicy: { present: false, status: 'WARNING', notes },
    permissionsPolicy: { present: false, status: 'WARNING', notes },
    cookiesAnalysis: { total: 0, insecureCookies: [], missingHttpOnly: [], missingSameSite: [] },
    overallHeaderScore: 0,
  };
}

function evaluateHeaders(
  headers: http.IncomingHttpHeaders,
  findings: Finding[]
): SecurityHeaderAssessment {
  let score = 100;

  // Normalize header keys to lowercase
  const getHeader = (name: string): string | undefined => {
    const val = headers[name.toLowerCase()];
    if (!val) return undefined;
    return Array.isArray(val) ? val.join('; ') : val;
  };

  // 1. Content Security Policy (CSP)
  const cspVal = getHeader('content-security-policy');
  const csp: SecurityHeaderAssessment['csp'] = {
    present: !!cspVal,
    value: cspVal,
    status: 'GOOD',
    notes: 'CSP header enforces authorized sources for scripts, images, and network calls.',
  };
  if (!cspVal) {
    score -= 25;
    csp.status = 'CRITICAL';
    csp.notes = 'Missing Content-Security-Policy header. Site is vulnerable to Cross-Site Scripting (XSS) and code injection.';
    findings.push({
      id: 'sec-missing-csp',
      category: 'SECURITY_HEADERS',
      severity: 'HIGH',
      title: 'Missing Content-Security-Policy (CSP)',
      technicalDetails: 'No Content-Security-Policy header detected in server HTTP response.',
      evidence: 'Header absent',
      impact: 'Enables execution of malicious client-side JavaScript, cross-site scripting (XSS), and data exfiltration.',
      remediation: 'Implement a strict CSP policy restricting default-src, script-src, object-src, and frame-ancestors.',
    });
  } else if (cspVal.includes('unsafe-inline') || cspVal.includes('unsafe-eval') || cspVal.includes('*')) {
    score -= 10;
    csp.status = 'WARNING';
    csp.notes = 'CSP includes permissive directives such as unsafe-inline, unsafe-eval, or wildcards.';
    findings.push({
      id: 'sec-weak-csp',
      category: 'SECURITY_HEADERS',
      severity: 'MEDIUM',
      title: 'Weak / Permissive Content-Security-Policy Directives',
      technicalDetails: 'CSP contains unsafe-inline or wildcard definitions that substantially weaken XSS defenses.',
      evidence: cspVal.slice(0, 120),
      impact: 'Adversaries can bypass CSP restrictions if an injection vector exists.',
      remediation: 'Refactor client scripts to use cryptographic nonces or SHA-256 hashes instead of unsafe-inline.',
    });
  }

  // 2. HTTP Strict Transport Security (HSTS)
  const hstsVal = getHeader('strict-transport-security');
  const hsts: SecurityHeaderAssessment['hsts'] = {
    present: !!hstsVal,
    value: hstsVal,
    status: 'GOOD',
    notes: 'HSTS is properly enforcing secure transport over HTTPS.',
  };
  if (!hstsVal) {
    score -= 20;
    hsts.status = 'CRITICAL';
    hsts.notes = 'Missing Strict-Transport-Security header. Users are vulnerable to SSL stripping and protocol downgrade attacks.';
    findings.push({
      id: 'sec-missing-hsts',
      category: 'SECURITY_HEADERS',
      severity: 'HIGH',
      title: 'Missing HTTP Strict Transport Security (HSTS)',
      technicalDetails: 'The web application does not transmit the Strict-Transport-Security header.',
      evidence: 'Header absent',
      impact: 'Vulnerable to Man-in-the-Middle (MitM) attacks, SSL stripping, and insecure plaintext fallback.',
      remediation: 'Enforce HSTS with a minimum max-age of 31536000 (1 year), includeSubDomains, and preload.',
    });
  } else {
    const maxAgeMatch = hstsVal.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    hsts.maxAge = maxAge;
    hsts.includeSubDomains = /includesubdomains/i.test(hstsVal);
    hsts.preload = /preload/i.test(hstsVal);

    if (maxAge < 15552000) {
      score -= 5;
      hsts.status = 'WARNING';
      hsts.notes = `HSTS max-age is set to ${maxAge} seconds (< 6 months recommended threshold).`;
    }
  }

  // 3. X-Frame-Options (Clickjacking defense)
  const xfoVal = getHeader('x-frame-options');
  const xFrameOptions: SecurityHeaderAssessment['xFrameOptions'] = {
    present: !!xfoVal,
    value: xfoVal,
    status: 'GOOD',
    notes: 'Framing restriction configured against clickjacking attacks.',
  };
  if (!xfoVal && (!cspVal || !cspVal.includes('frame-ancestors'))) {
    score -= 15;
    xFrameOptions.status = 'CRITICAL';
    xFrameOptions.notes = 'No X-Frame-Options or CSP frame-ancestors detected. Application can be framed in an attacker iframe.';
    findings.push({
      id: 'sec-missing-xfo',
      category: 'SECURITY_HEADERS',
      severity: 'MEDIUM',
      title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
      technicalDetails: 'Neither X-Frame-Options nor CSP frame-ancestors directives are declared.',
      evidence: 'Header absent',
      impact: 'Enables clickjacking attacks where hidden framing tricks users into performing unintended actions.',
      remediation: 'Set X-Frame-Options to DENY or SAMEORIGIN, or configure frame-ancestors \'none\' in CSP.',
    });
  }

  // 4. X-Content-Type-Options
  const xctoVal = getHeader('x-content-type-options');
  const xContentTypeOptions: SecurityHeaderAssessment['xContentTypeOptions'] = {
    present: !!xctoVal,
    value: xctoVal,
    status: xctoVal?.toLowerCase() === 'nosniff' ? 'GOOD' : 'WARNING',
    notes: xctoVal ? 'MIME-sniffing protection enabled.' : 'Missing nosniff header.',
  };
  if (!xctoVal) {
    score -= 10;
    findings.push({
      id: 'sec-missing-xcto',
      category: 'SECURITY_HEADERS',
      severity: 'LOW',
      title: 'Missing X-Content-Type-Options: nosniff',
      technicalDetails: 'Without nosniff, older browsers may inspect file contents and execute files disguised as non-executable types.',
      evidence: 'Header absent',
      impact: 'MIME-type confusion can lead to cross-site scripting when serving user-generated uploads.',
      remediation: 'Add header: X-Content-Type-Options: nosniff to all responses.',
    });
  }

  // 5. Referrer-Policy
  const refVal = getHeader('referrer-policy');
  const referrerPolicy: SecurityHeaderAssessment['referrerPolicy'] = {
    present: !!refVal,
    value: refVal,
    status: refVal ? 'GOOD' : 'WARNING',
    notes: refVal ? `Referrer policy: ${refVal}` : 'Default browser referrer policy in effect.',
  };
  if (!refVal) {
    score -= 5;
  }

  // 6. Permissions-Policy
  const permVal = getHeader('permissions-policy');
  const permissionsPolicy: SecurityHeaderAssessment['permissionsPolicy'] = {
    present: !!permVal,
    value: permVal,
    status: permVal ? 'GOOD' : 'WARNING',
    notes: permVal ? 'Hardware features restricted.' : 'Permissions policy not configured.',
  };

  // 7. Server Banner / Technology Disclosures
  const serverHeader = getHeader('server');
  const xPoweredBy = getHeader('x-powered-by');

  if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
    score -= 5;
    findings.push({
      id: 'sec-server-version-leak',
      category: 'SECURITY_HEADERS',
      severity: 'LOW',
      title: 'Server Version Information Disclosure',
      technicalDetails: `Server header reveals precise version numbers: '${serverHeader}'`,
      evidence: `Server: ${serverHeader}`,
      impact: 'Aids attackers in fingerprinting known CVE vulnerabilities associated with specific software revisions.',
      remediation: 'Configure web server (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx) to suppress version details.',
    });
  }

  if (xPoweredBy) {
    score -= 5;
    findings.push({
      id: 'sec-xpowered-by-leak',
      category: 'SECURITY_HEADERS',
      severity: 'LOW',
      title: 'Technology Fingerprint Disclosed via X-Powered-By',
      technicalDetails: `Server returns application runtime identifier: '${xPoweredBy}'`,
      evidence: `X-Powered-By: ${xPoweredBy}`,
      impact: 'Provides reconnaissance data for targeted exploits against the backend stack.',
      remediation: 'Disable the X-Powered-By header in application server framework settings.',
    });
  }

  // 8. Cookies Analysis
  const rawSetCookie = headers['set-cookie'];
  const cookiesList = Array.isArray(rawSetCookie) ? rawSetCookie : (rawSetCookie ? [rawSetCookie] : []);
  const insecureCookies: string[] = [];
  const missingHttpOnly: string[] = [];
  const missingSameSite: string[] = [];

  for (const c of cookiesList) {
    const cookieName = c.split('=')[0]?.trim() || 'unknown';
    if (!/secure/i.test(c)) insecureCookies.push(cookieName);
    if (!/httponly/i.test(c)) missingHttpOnly.push(cookieName);
    if (!/samesite/i.test(c)) missingSameSite.push(cookieName);
  }

  if (insecureCookies.length > 0) {
    score -= 10;
    findings.push({
      id: 'sec-insecure-cookies',
      category: 'SECURITY_HEADERS',
      severity: 'MEDIUM',
      title: 'Cookies Missing Secure Flag',
      technicalDetails: `Cookies transmitted without the Secure directive: ${insecureCookies.join(', ')}`,
      evidence: `Cookies: ${insecureCookies.join(', ')}`,
      impact: 'Cookies can be intercepted in plaintext if transmitted over unencrypted HTTP channels.',
      remediation: 'Append ; Secure to all session and tracking cookies.',
    });
  }

  const overallScore = Math.max(0, Math.min(100, score));

  return {
    csp,
    hsts,
    xFrameOptions,
    xContentTypeOptions,
    referrerPolicy,
    permissionsPolicy,
    serverHeader,
    xPoweredBy,
    cookiesAnalysis: {
      total: cookiesList.length,
      insecureCookies,
      missingHttpOnly,
      missingSameSite,
    },
    overallHeaderScore: overallScore,
  };
}
