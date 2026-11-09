import dns from 'dns';
import net from 'net';

/**
 * Validates whether an IP address is in a private, loopback, or metadata range.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip) return true;

  // IPv4 checks
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(p => parseInt(p, 10));
    if (parts.length !== 4 || parts.some(isNaN)) return true;

    // 0.0.0.0/8 (Broadcast/Current network)
    if (parts[0] === 0) return true;
    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true;
    // 10.0.0.0/8 (Private)
    if (parts[0] === 10) return true;
    // 172.16.0.0/12 (Private)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // IANA special-purpose, private, loopback and documentation networks
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 192 && parts[1] === 0 && (parts[2] === 0 || parts[2] === 2)) return true;
    if (parts[0] === 192 && parts[1] === 88 && parts[2] === 99) return true;
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true;
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true;
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true;
    // 169.254.0.0/16 (Link Local & AWS/GCP Metadata 169.254.169.254)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 100.64.0.0/10 (Carrier-grade NAT)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    // 224.0.0.0/4 (Multicast)
    if (parts[0] >= 224) return true;

    return false;
  }

  // IPv6 checks
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    const mappedIpv4 = normalized.match(/^(?:::ffff:|0:0:0:0:0:ffff:)(\d+\.\d+\.\d+\.\d+)$/);
    if (mappedIpv4) return isPrivateOrReservedIp(mappedIpv4[1]);
    const firstHextet = parseInt(normalized.split(':')[0] || '0', 16);
    // Loopback
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
    // Unspecified
    if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true;
    // Unique local address (fc00::/7)
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    // Link local (fe80::/10)
    if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true;

    // Only global-unicast IPv6 space (2000::/3) is eligible for outbound scans.
    if (firstHextet < 0x2000 || firstHextet > 0x3fff) return true;
    // Documentation prefix (2001:db8::/32).
    return normalized.startsWith('2001:db8:');
  }

  return true;
}

export interface SsrfValidationResult {
  safe: boolean;
  reason?: string;
  resolvedIp?: string;
  resolvedAddresses?: { address: string; family: number }[];
}

/**
 * Resolves a hostname and verifies it is not pointing to an internal or restricted network.
 */
export async function validateUrlForSsrf(inputUrl: string): Promise<SsrfValidationResult> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(inputUrl);
  } catch {
    return { safe: false, reason: 'Invalid URL format' };
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return { safe: false, reason: `Disallowed protocol: ${parsedUrl.protocol}. Only http and https are permitted.` };
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Explicit blocked hosts
  const blockedHosts = [
    'localhost',
    'metadata.google.internal',
    'metadata',
    'instance-data',
    'internal',
  ];

  if (blockedHosts.includes(hostname) || hostname.endsWith('.internal') || hostname.endsWith('.local')) {
    return { safe: false, reason: `Host '${hostname}' is an internal domain name.` };
  }

  // Check if hostname itself is directly an IP
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      return { safe: false, reason: `IP address ${hostname} belongs to private or metadata space. Access blocked.`, resolvedIp: hostname };
    }
    return { safe: true, resolvedIp: hostname, resolvedAddresses: [{ address: hostname, family: net.isIP(hostname) }] };
  }

  // DNS resolution
  try {
    const addresses = await dns.promises.lookup(hostname, { all: true, verbatim: true });
    if (!addresses || addresses.length === 0) {
      return { safe: false, reason: `Could not resolve domain: ${hostname}` };
    }

    for (const addr of addresses) {
      if (isPrivateOrReservedIp(addr.address)) {
        return {
          safe: false,
          reason: `Resolved IP ${addr.address} for '${hostname}' resolves to a private or restricted network.`,
          resolvedIp: addr.address,
        };
      }
    }

    return {
      safe: true,
      resolvedIp: addresses[0].address,
      resolvedAddresses: addresses.map(({ address, family }) => ({ address, family })),
    };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    return { safe: false, reason: `DNS lookup failed: ${errorMsg}` };
  }
}

/**
 * Normalizes user input into a validated, standard URL and hostname.
 */
export function normalizeTargetUrl(input: string): {
  normalizedUrl: string;
  domain: string;
  protocol: string;
  valid: boolean;
  error?: string;
} {
  if (!input || typeof input !== 'string') {
    return { normalizedUrl: '', domain: '', protocol: '', valid: false, error: 'Target URL or domain cannot be empty.' };
  }

  let cleaned = input.trim();

  // Strip control characters or whitespace
  if (/[\s\r\n\t]/.test(cleaned)) {
    return { normalizedUrl: '', domain: '', protocol: '', valid: false, error: 'URL contains disallowed whitespace or control characters.' };
  }

  // Prepend https:// if protocol is omitted
  if (!cleaned.startsWith('http://') && !cleaned.startsWith('https://')) {
    if (cleaned.startsWith('//')) {
      cleaned = `https:${cleaned}`;
    } else {
      cleaned = `https://${cleaned}`;
    }
  }

  let parsed: URL;
  try {
    parsed = new URL(cleaned);
  } catch {
    return { normalizedUrl: '', domain: '', protocol: '', valid: false, error: 'Malformed URL. Please enter a valid domain or web address.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      normalizedUrl: '',
      domain: '',
      protocol: parsed.protocol,
      valid: false,
      error: `Unsupported protocol '${parsed.protocol}'. Sentinel only evaluates http:// and https:// destinations.`,
    };
  }

  if (parsed.username || parsed.password) {
    return { normalizedUrl: '', domain: '', protocol: parsed.protocol, valid: false, error: 'URLs containing embedded credentials are not allowed.' };
  }

  const domain = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!domain || domain.length > 253) {
    return { normalizedUrl: '', domain: '', protocol: '', valid: false, error: 'Invalid hostname format.' };
  }

  return {
    normalizedUrl: parsed.toString(),
    domain,
    protocol: parsed.protocol,
    valid: true,
  };
}

/**
 * Infers hosting organization and autonomous system number (ASN) from IP or reverse DNS
 */
export async function resolveHostingAndAsn(ip?: string, serverBanner?: string): Promise<{ hostingProvider: string; asn: string }> {
  if (!ip) return { hostingProvider: 'Unavailable (no resolved IP)', asn: 'Unavailable' };
  try {
    const hostnames = await dns.promises.reverse(ip);
    if (hostnames.length > 0) {
      return {
        hostingProvider: `Reverse DNS: ${hostnames[0]}`,
        asn: 'Unknown (no ASN lookup configured)',
      };
    }
  } catch {
    // A PTR record is optional and its absence does not invalidate the address.
  }
  return {
    hostingProvider: serverBanner ? `Server banner: ${serverBanner}` : 'Unknown (no PTR record)',
    asn: 'Unknown (no ASN lookup configured)',
  };
}

export async function collectDnsRecords(hostname: string): Promise<{
  A: string[];
  AAAA: string[];
  MX: { priority: number; exchange: string }[];
  NS: string[];
  TXT: string[];
}> {
  const read = async <T>(query: () => Promise<T>): Promise<T | []> => {
    try {
      return await query();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENODATA' || code === 'ENOTFOUND' || code === 'ESERVFAIL' || code === 'ETIMEOUT') return [];
      throw error;
    }
  };

  const [A, AAAA, MX, NS, TXT] = await Promise.all([
    read(() => dns.promises.resolve4(hostname)),
    read(() => dns.promises.resolve6(hostname)),
    read(() => dns.promises.resolveMx(hostname)),
    read(() => dns.promises.resolveNs(hostname)),
    read(() => dns.promises.resolveTxt(hostname)),
  ]);
  return {
    A: A as string[],
    AAAA: AAAA as string[],
    MX: MX as { priority: number; exchange: string }[],
    NS: NS as string[],
    TXT: (TXT as string[][]).map(parts => parts.join('')),
  };
}
