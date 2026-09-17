// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — IP & Network Utilities
// ═══════════════════════════════════════════════════════════════

import dns from 'dns/promises';
import { execFile } from 'child_process';
import os from 'os';
import { promisify } from 'util';
import { AppError } from '../middleware/errorHandler.js';

const execFileAsync = promisify(execFile);

// ────────────────────────────────────────────────────────────────
// 1. IP CONVERTER (IPv4 <-> Decimal, Hex, Binary, Octal)
// ────────────────────────────────────────────────────────────────

/**
 * Parse any valid IPv4 representation (dotted-decimal, integer, hex, binary, octal)
 * and return standard 32-bit unsigned integer.
 */
function parseIPv4ToUint32(input) {
  if (typeof input !== 'string' && typeof input !== 'number') {
    throw new AppError('IP input must be a string or number.', 400, 'INVALID_INPUT');
  }

  const str = String(input).trim();

  // 1) Dotted Decimal: 192.168.1.1
  const dottedMatch = str.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (dottedMatch) {
    const octets = dottedMatch.slice(1, 5).map(Number);
    for (const oct of octets) {
      if (oct < 0 || oct > 255) {
        throw new AppError(`Invalid octet value ${oct}. Must be 0-255.`, 400, 'INVALID_OCTET');
      }
    }
    return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  }

  // 2) Hexadecimal: 0xC0A80101 or C0A80101
  if (/^(0x)?[0-9a-fA-F]{1,8}$/.test(str)) {
    const cleanHex = str.replace(/^0x/i, '');
    const num = parseInt(cleanHex, 16);
    if (isNaN(num) || num < 0 || num > 0xFFFFFFFF) {
      throw new AppError('Hexadecimal value out of 32-bit IPv4 range.', 400, 'OUT_OF_RANGE');
    }
    return num >>> 0;
  }

  // 3) Binary: 11000000101010000000000100000001 or dotted binary
  const cleanBinary = str.replace(/\./g, '');
  if (/^[01]{1,32}$/.test(cleanBinary)) {
    const num = parseInt(cleanBinary, 2);
    if (!isNaN(num)) return num >>> 0;
  }

  // 4) Octal dotted: 0300.0250.0001.0001
  const octalDotted = str.match(/^0([0-7]{1,3})\.0([0-7]{1,3})\.0([0-7]{1,3})\.0([0-7]{1,3})$/);
  if (octalDotted) {
    const octets = octalDotted.slice(1, 5).map((s) => parseInt(s, 8));
    return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  }

  // 5) Pure Decimal integer: 3232235777
  if (/^\d{1,10}$/.test(str)) {
    const num = Number(str);
    if (num >= 0 && num <= 4294967295) {
      return num >>> 0;
    }
  }

  throw new AppError(
    'Unrecognized IPv4 format. Provide dotted-decimal (192.168.1.1), decimal integer (3232235777), hex (0xC0A80101), or binary.',
    400,
    'INVALID_IPV4_FORMAT'
  );
}

/**
 * Determine IP Class and Scope
 */
function getIPClassAndScope(uint32) {
  const firstOctet = (uint32 >>> 24) & 255;
  const secondOctet = (uint32 >>> 16) & 255;

  let ipClass = 'Unknown';
  if (firstOctet >= 1 && firstOctet <= 126) ipClass = 'Class A';
  else if (firstOctet === 127) ipClass = 'Class A (Loopback)';
  else if (firstOctet >= 128 && firstOctet <= 191) ipClass = 'Class B';
  else if (firstOctet >= 192 && firstOctet <= 223) ipClass = 'Class C';
  else if (firstOctet >= 224 && firstOctet <= 239) ipClass = 'Class D (Multicast)';
  else if (firstOctet >= 240 && firstOctet <= 255) ipClass = 'Class E (Reserved)';

  let scope = 'Public Internet';
  let isPrivate = false;

  // RFC 1918 Private Ranges
  if (firstOctet === 10) {
    scope = 'Private (RFC 1918 - 10.0.0.0/8)';
    isPrivate = true;
  } else if (firstOctet === 172 && secondOctet >= 16 && secondOctet <= 31) {
    scope = 'Private (RFC 1918 - 172.16.0.0/12)';
    isPrivate = true;
  } else if (firstOctet === 192 && secondOctet === 168) {
    scope = 'Private (RFC 1918 - 192.168.0.0/16)';
    isPrivate = true;
  } else if (firstOctet === 127) {
    scope = 'Loopback (127.0.0.0/8)';
    isPrivate = true;
  } else if (firstOctet === 169 && secondOctet === 254) {
    scope = 'Link-Local / APIPA (169.254.0.0/16)';
    isPrivate = true;
  } else if (firstOctet === 0) {
    scope = 'Current network (RFC 1122 - 0.0.0.0/8)';
  } else if (firstOctet >= 224 && firstOctet <= 239) {
    scope = 'Multicast (RFC 5771 - 224.0.0.0/4)';
  } else if (firstOctet >= 240) {
    scope = 'Reserved / Experimental (240.0.0.0/4)';
  }

  return { ipClass, scope, isPrivate };
}

/**
 * Convert IPv4 to all common representation formats
 */
export function convertIP(input) {
  const uint32 = parseIPv4ToUint32(input);

  const oct1 = (uint32 >>> 24) & 255;
  const oct2 = (uint32 >>> 16) & 255;
  const oct3 = (uint32 >>> 8) & 255;
  const oct4 = uint32 & 255;

  const dotDecimal = `${oct1}.${oct2}.${oct3}.${oct4}`;
  const decimal = uint32;
  const hex = '0x' + uint32.toString(16).toUpperCase().padStart(8, '0');
  const hexDotted = [oct1, oct2, oct3, oct4].map((o) => '0x' + o.toString(16).padStart(2, '0')).join('.');
  
  const binOctets = [oct1, oct2, oct3, oct4].map((o) => o.toString(2).padStart(8, '0'));
  const binaryDotted = binOctets.join('.');
  const binaryFlat = binOctets.join('');

  const octOctets = [oct1, oct2, oct3, oct4].map((o) => '0' + o.toString(8).padStart(3, '0'));
  const octalDotted = octOctets.join('.');

  const ipv6Mapped = `::ffff:${dotDecimal}`;
  const ipv6Hex = `::ffff:${oct1.toString(16).padStart(2, '0')}${oct2.toString(16).padStart(2, '0')}:${oct3.toString(16).padStart(2, '0')}${oct4.toString(16).padStart(2, '0')}`;
  const reverseDns = `${oct4}.${oct3}.${oct2}.${oct1}.in-addr.arpa`;

  const { ipClass, scope, isPrivate } = getIPClassAndScope(uint32);

  return {
    dotDecimal,
    decimal,
    hex,
    hexDotted,
    binaryDotted,
    binaryFlat,
    octalDotted,
    ipv6Mapped,
    ipv6Hex,
    reverseDns,
    ipClass,
    scope,
    isPrivate,
  };
}

// ────────────────────────────────────────────────────────────────
// 2. SUBNET CALCULATOR (CIDR -> Network, Broadcast, Hosts, Range)
// ────────────────────────────────────────────────────────────────

export function calculateSubnet(cidrInput) {
  if (!cidrInput || typeof cidrInput !== 'string') {
    throw new AppError('CIDR string is required (e.g. 192.168.1.0/24).', 400, 'INVALID_CIDR');
  }

  const parts = cidrInput.trim().split('/');
  if (parts.length !== 2) {
    throw new AppError('Invalid CIDR format. Expected format: IP/PREFIX (e.g. 10.0.0.0/24)', 400, 'INVALID_CIDR');
  }

  const ipStr = parts[0].trim();
  const prefixStr = parts[1].trim();
  const prefix = Number(prefixStr);

  if (isNaN(prefix) || prefix < 0 || prefix > 32 || !Number.isInteger(prefix)) {
    throw new AppError('Prefix length must be an integer between 0 and 32.', 400, 'INVALID_PREFIX');
  }

  const ipUint = parseIPv4ToUint32(ipStr);

  // Subnet mask uint32
  const maskUint = prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - prefix)) >>> 0);
  const wildcardUint = (~maskUint) >>> 0;

  // Network address
  const networkUint = (ipUint & maskUint) >>> 0;

  // Broadcast address
  const broadcastUint = (networkUint | wildcardUint) >>> 0;

  // Helpers to string
  const uintToDotted = (u) => `${(u >>> 24) & 255}.${(u >>> 16) & 255}.${(u >>> 8) & 255}.${u & 255}`;
  const uintToBinaryDotted = (u) => [
    (u >>> 24) & 255,
    (u >>> 16) & 255,
    (u >>> 8) & 255,
    u & 255
  ].map((o) => o.toString(2).padStart(8, '0')).join('.');

  const networkIP = uintToDotted(networkUint);
  const broadcastIP = uintToDotted(broadcastUint);
  const subnetMask = uintToDotted(maskUint);
  const wildcardMask = uintToDotted(wildcardUint);
  const binaryMask = uintToBinaryDotted(maskUint);

  const totalHosts = Math.pow(2, 32 - prefix);
  let usableHosts = 0;
  let usableRangeStart = 'N/A';
  let usableRangeEnd = 'N/A';

  if (prefix === 32) {
    usableHosts = 1;
    usableRangeStart = networkIP;
    usableRangeEnd = networkIP;
  } else if (prefix === 31) {
    // RFC 3021: Point-to-Point links
    usableHosts = 2;
    usableRangeStart = networkIP;
    usableRangeEnd = broadcastIP;
  } else {
    usableHosts = Math.max(0, totalHosts - 2);
    usableRangeStart = uintToDotted(networkUint + 1);
    usableRangeEnd = uintToDotted(broadcastUint - 1);
  }

  const { ipClass, scope, isPrivate } = getIPClassAndScope(networkUint);

  return {
    inputCidr: `${uintToDotted(ipUint)}/${prefix}`,
    ipAddress: uintToDotted(ipUint),
    prefix,
    networkIP,
    broadcastIP,
    subnetMask,
    wildcardMask,
    binaryMask,
    totalHosts,
    usableHosts,
    usableRangeStart,
    usableRangeEnd,
    usableRange: usableHosts > 0 ? `${usableRangeStart} — ${usableRangeEnd}` : 'None',
    ipClass,
    scope,
    isPrivate,
  };
}

// ────────────────────────────────────────────────────────────────
// 3. PING UTILITY (Latency, Packet Loss, Reachability)
// ────────────────────────────────────────────────────────────────

const HOSTNAME_SAFE_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_REGEX = /^[0-9a-fA-F:]+$/;

function isPrivateOrRestrictedIP(ipStr) {
  if (!IPV4_REGEX.test(ipStr)) return false;
  const parts = ipStr.split('.').map(Number);
  const oct1 = parts[0];
  const oct2 = parts[1];

  if (oct1 === 127) return true; // Loopback
  if (oct1 === 10) return true; // RFC 1918 Private
  if (oct1 === 172 && oct2 >= 16 && oct2 <= 31) return true; // RFC 1918 Private
  if (oct1 === 192 && oct2 === 168) return true; // RFC 1918 Private
  if (oct1 === 169 && oct2 === 254) return true; // Link-local / Cloud metadata (AWS/GCP)
  if (oct1 === 0) return true; // 0.0.0.0/8
  if (oct1 >= 224) return true; // Multicast / Reserved

  return false;
}

export async function pingHost(targetHost, count = 4) {
  if (!targetHost || typeof targetHost !== 'string') {
    throw new AppError('Host or IP is required for ping.', 400, 'INVALID_HOST');
  }

  const cleanHost = targetHost.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  if (!IPV4_REGEX.test(cleanHost) && !HOSTNAME_SAFE_REGEX.test(cleanHost) && !IPV6_REGEX.test(cleanHost)) {
    throw new AppError('Invalid target host. Only valid domain names or IP addresses allowed.', 400, 'SECURITY_VALIDATION_ERROR');
  }

  // Security Check: Block private IP ranges, loopback, and cloud metadata targets
  if (cleanHost === 'localhost' || cleanHost === '::1' || cleanHost === '0.0.0.0' || isPrivateOrRestrictedIP(cleanHost)) {
    throw new AppError('Pinging private, internal, or loopback network addresses is restricted for security.', 403, 'RESTRICTED_TARGET');
  }

  // If target is a hostname, verify resolved IP does not point to internal/private targets
  if (HOSTNAME_SAFE_REGEX.test(cleanHost) && !IPV4_REGEX.test(cleanHost)) {
    try {
      const resolved = await dns.lookup(cleanHost);
      if (resolved && isPrivateOrRestrictedIP(resolved.address)) {
        throw new AppError('Target resolves to a private or restricted internal network address.', 403, 'RESTRICTED_TARGET');
      }
    } catch (dnsErr) {
      if (dnsErr instanceof AppError) throw dnsErr;
      // If DNS resolution fails, ping will handle host unreachable error
    }
  }

  const isWin = os.platform() === 'win32';
  const pingCount = Math.min(Math.max(Number(count) || 4, 1), 6);

  // Safe argument array passed to execFile (prevents command injection)
  const args = isWin
    ? ['-n', String(pingCount), '-w', '2000', cleanHost]
    : ['-c', String(pingCount), '-W', '2', cleanHost];

  try {
    const { stdout, stderr } = await execFileAsync('ping', args, {
      timeout: 10000,
      maxBuffer: 1024 * 512,
    });

    return parsePingOutput(cleanHost, stdout, isWin);
  } catch (err) {
    // If ping command exited with non-zero (packet loss / unreachable), stdout is often still populated
    if (err.stdout) {
      return parsePingOutput(cleanHost, err.stdout, isWin);
    }

    return {
      host: cleanHost,
      alive: false,
      packetsTransmitted: pingCount,
      packetsReceived: 0,
      packetLossPercent: 100,
      minLatency: null,
      avgLatency: null,
      maxLatency: null,
      rawOutput: err.message || 'Host unreachable or ping timed out.',
      error: 'Ping request failed or host is unreachable.',
    };
  }
}

/**
 * Parse standard Windows / Linux ping terminal output
 */
function parsePingOutput(host, rawOutput, isWin) {
  let packetsTransmitted = 0;
  let packetsReceived = 0;
  let packetLossPercent = 100;
  let minLatency = null;
  let avgLatency = null;
  let maxLatency = null;

  if (isWin) {
    // Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)
    const packetsMatch = rawOutput.match(/Sent = (\d+), Received = (\d+), Lost = (\d+)\s*\((\d+)%\s*loss\)/i);
    if (packetsMatch) {
      packetsTransmitted = Number(packetsMatch[1]);
      packetsReceived = Number(packetsMatch[2]);
      packetLossPercent = Number(packetsMatch[4]);
    }

    // Minimum = 14ms, Maximum = 16ms, Average = 15ms
    const rttMatch = rawOutput.match(/Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms/i);
    if (rttMatch) {
      minLatency = Number(rttMatch[1]);
      maxLatency = Number(rttMatch[2]);
      avgLatency = Number(rttMatch[3]);
    }
  } else {
    // Linux: 4 packets transmitted, 4 received, 0% packet loss, time 3004ms
    const packetsMatch = rawOutput.match(/(\d+)\s+packets transmitted,\s+(\d+)\s+received.*?(?:,\s+(\d+)%\s+packet loss)?/i);
    if (packetsMatch) {
      packetsTransmitted = Number(packetsMatch[1]);
      packetsReceived = Number(packetsMatch[2]);
      packetLossPercent = packetsMatch[3] !== undefined ? Number(packetsMatch[3]) : (packetsReceived === 0 ? 100 : 0);
    }

    // rtt min/avg/max/mdev = 14.123/15.456/16.789/0.912 ms
    const rttMatch = rawOutput.match(/rtt min\/avg\/max\/mdev\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)/i);
    if (rttMatch) {
      minLatency = parseFloat(rttMatch[1]);
      avgLatency = parseFloat(rttMatch[2]);
      maxLatency = parseFloat(rttMatch[3]);
    }
  }

  const alive = packetsReceived > 0;

  return {
    host,
    alive,
    packetsTransmitted,
    packetsReceived,
    packetLossPercent,
    minLatency,
    avgLatency,
    maxLatency,
    rawOutput: rawOutput.trim(),
  };
}

// ────────────────────────────────────────────────────────────────
// 4. DNS RECORDS LOOKUP (A, AAAA, MX, TXT, NS, CNAME, SOA)
// ────────────────────────────────────────────────────────────────

export async function resolveAllDNS(domainInput) {
  if (!domainInput || typeof domainInput !== 'string') {
    throw new AppError('Domain name is required for DNS lookup.', 400, 'INVALID_DOMAIN');
  }

  let cleanDomain = domainInput.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  if (!HOSTNAME_SAFE_REGEX.test(cleanDomain)) {
    throw new AppError('Invalid domain name format.', 400, 'INVALID_DOMAIN');
  }

  // Execute all DNS queries in parallel with Promise.allSettled
  const [aRes, aaaaRes, mxRes, txtRes, nsRes, cnameRes, soaRes] = await Promise.allSettled([
    dns.resolve4(cleanDomain),
    dns.resolve6(cleanDomain),
    dns.resolveMx(cleanDomain),
    dns.resolveTxt(cleanDomain),
    dns.resolveNs(cleanDomain),
    dns.resolveCname(cleanDomain),
    dns.resolveSoa(cleanDomain),
  ]);

  const records = {
    A: aRes.status === 'fulfilled' ? aRes.value : [],
    AAAA: aaaaRes.status === 'fulfilled' ? aaaaRes.value : [],
    MX: mxRes.status === 'fulfilled' ? mxRes.value.sort((a, b) => a.priority - b.priority) : [],
    TXT: txtRes.status === 'fulfilled' ? txtRes.value.map((chunk) => chunk.join(' ')) : [],
    NS: nsRes.status === 'fulfilled' ? nsRes.value : [],
    CNAME: cnameRes.status === 'fulfilled' ? cnameRes.value : [],
    SOA: soaRes.status === 'fulfilled' ? soaRes.value : null,
  };

  const totalRecordsFound =
    records.A.length +
    records.AAAA.length +
    records.MX.length +
    records.TXT.length +
    records.NS.length +
    records.CNAME.length +
    (records.SOA ? 1 : 0);

  return {
    domain: cleanDomain,
    queryTimestamp: new Date().toISOString(),
    totalRecordsFound,
    records,
  };
}
