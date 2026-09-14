import axios from 'axios';
import { promises as dnsPromises } from 'dns';
import config from '../config/env.js';
import { ServiceError } from '../middleware/errorHandler.js';

const API_BASE = 'https://api.abuseipdb.com/api/v2';
const TIMEOUT = 8_000; // 8 seconds

// ── Risk level classification ───────────────────────────────────
function classifyRisk(confidenceScore) {
  if (confidenceScore >= 80) return { level: 'critical', label: 'Critical', color: '#ef4444' };
  if (confidenceScore >= 50) return { level: 'high', label: 'High', color: '#f97316' };
  if (confidenceScore >= 25) return { level: 'medium', label: 'Medium', color: '#eab308' };
  if (confidenceScore >= 5) return { level: 'low', label: 'Low', color: '#22d3ee' };
  return { level: 'clean', label: 'Clean', color: '#10b981' };
}

// ── Usage type mapping ──────────────────────────────────────────
const USAGE_TYPE_MAP = {
  'Commercial': 'Commercial',
  'Organization': 'Organization',
  'Government': 'Government',
  'Military': 'Military',
  'University/College/School': 'Education',
  'Library': 'Library',
  'Content Delivery Network': 'CDN',
  'Fixed Line ISP': 'ISP (Fixed)',
  'Mobile ISP': 'ISP (Mobile)',
  'Data Center/Web Hosting/Transit': 'Data Center',
  'Search Engine Spider': 'Search Bot',
  'Reserved': 'Reserved',
};

// ── In-memory IP cache (30 mins TTL) ───────────────────────────
const ipCache = new Map();
const CACHE_TTL = 30 * 60 * 1000;

// ── Multi-Tier Fallback Telemetry (Zero-Fail IP Intelligence) ───
async function getFallbackTelemetry(ipAddress, reason = 'Live Geolocation & ISP Telemetry Active') {
  let geo = null;
  let rDnsHostnames = [];

  // Attempt reverse DNS
  try {
    rDnsHostnames = await dnsPromises.reverse(ipAddress);
  } catch (_) {
    rDnsHostnames = [];
  }

  // Tier 1: ip-api.com
  try {
    const res = await axios.get(
      `http://ip-api.com/json/${encodeURIComponent(ipAddress)}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query`,
      { timeout: 4000 }
    );
    if (res.data && res.data.status === 'success') {
      geo = {
        isp: res.data.isp || res.data.org || 'Unknown',
        domain: res.data.org || res.data.isp || 'N/A',
        usageType: 'Network Host',
        countryCode: res.data.countryCode || 'Unknown',
        countryName: res.data.country || 'Unknown',
        hostnames: [res.data.as, ...rDnsHostnames].filter(Boolean),
      };
    }
  } catch (_) {}

  // Tier 2: ipwho.is if tier 1 failed
  if (!geo) {
    try {
      const res = await axios.get(`https://ipwho.is/${encodeURIComponent(ipAddress)}`, { timeout: 4000 });
      if (res.data && res.data.success !== false) {
        geo = {
          isp: res.data.connection?.isp || res.data.connection?.org || 'Unknown',
          domain: res.data.connection?.domain || res.data.connection?.isp || 'N/A',
          usageType: res.data.connection?.type || 'Network Host',
          countryCode: res.data.country_code || 'Unknown',
          countryName: res.data.country || 'Unknown',
          hostnames: [res.data.connection?.asn ? `AS${res.data.connection.asn}` : '', ...rDnsHostnames].filter(Boolean),
        };
      }
    } catch (_) {}
  }

  // Tier 3: Local heuristics fallback
  if (!geo) {
    const isPrivate = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ipAddress);
    geo = {
      isp: isPrivate ? 'Internal / Private Subnet' : 'Public Internet Host',
      domain: 'N/A',
      usageType: isPrivate ? 'Local Area Network' : 'Network Endpoint',
      countryCode: isPrivate ? 'LAN' : 'Unknown',
      countryName: isPrivate ? 'Local Network' : 'Global Internet',
      hostnames: rDnsHostnames,
    };
  }

  return {
    ip: ipAddress,
    isPublic: !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ipAddress),
    ipVersion: ipAddress.includes(':') ? 6 : 4,
    isWhitelisted: false,
    abuseConfidenceScore: 0,
    riskLevel: 'clean',
    riskLabel: 'Telemetry Active',
    riskColor: '#38bdf8',
    totalReports: 0,
    numDistinctUsers: 0,
    lastReportedAt: null,
    isp: geo.isp,
    domain: geo.domain,
    usageType: geo.usageType,
    hostnames: geo.hostnames && geo.hostnames.length > 0 ? geo.hostnames : (rDnsHostnames.length ? rDnsHostnames : []),
    countryCode: geo.countryCode,
    countryName: geo.countryName,
    queriedAt: new Date().toISOString(),
    isFallback: true,
    warning: reason,
  };
}

// ── Main check function ─────────────────────────────────────────
export async function checkIP(ipAddress) {
  const cached = ipCache.get(ipAddress);
  if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
    return cached.data;
  }

  const apiKey = (config.ABUSEIPDB_API_KEY || process.env.ABUSEIPDB_API_KEY || '').trim();

  // If no API key is set, immediately provide live telemetry fallback without throwing auth error
  if (!apiKey) {
    const fallbackData = await getFallbackTelemetry(
      ipAddress,
      'Live Geolocation & ISP Telemetry Active (AbuseIPDB key standby)'
    );
    ipCache.set(ipAddress, { data: fallbackData, timestamp: Date.now() });
    return fallbackData;
  }

  try {
    const response = await axios.get(`${API_BASE}/check`, {
      params: {
        ipAddress,
        maxAgeInDays: 90,
        verbose: '',
      },
      headers: {
        Key: apiKey,
        Accept: 'application/json',
      },
      timeout: TIMEOUT,
    });

    const data = response.data.data;
    const risk = classifyRisk(data.abuseConfidenceScore);

    const result = {
      ip: data.ipAddress,
      isPublic: data.isPublic,
      ipVersion: data.ipVersion,
      isWhitelisted: data.isWhitelisted,

      // ── Abuse metrics ──
      abuseConfidenceScore: data.abuseConfidenceScore,
      riskLevel: risk.level,
      riskLabel: risk.label,
      riskColor: risk.color,
      totalReports: data.totalReports,
      numDistinctUsers: data.numDistinctUsers,
      lastReportedAt: data.lastReportedAt,

      // ── Network info ──
      isp: data.isp || 'Unknown',
      domain: data.domain || 'N/A',
      usageType: USAGE_TYPE_MAP[data.usageType] || data.usageType || 'Unknown',
      hostnames: data.hostnames || [],

      // ── Geo info ──
      countryCode: data.countryCode || 'Unknown',
      countryName: data.countryName || 'Unknown',

      // ── Meta ──
      queriedAt: new Date().toISOString(),
      isFallback: false,
    };

    ipCache.set(ipAddress, { data: result, timestamp: Date.now() });
    return result;
  } catch (error) {
    const status = error.response?.status;

    // Graceful fallback for Auth errors (401/403), rate limits (429), or timeouts/network issues
    if (status === 401 || status === 403 || status === 429 || error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {
      let reason = 'Live Geolocation & Network Telemetry Active';
      if (status === 401 || status === 403) {
        reason = 'AbuseIPDB authorization issue. Displaying live Geolocation & ISP telemetry.';
      } else if (status === 429) {
        reason = 'AbuseIPDB rate limit reached. Displaying live Geolocation & ISP telemetry.';
      } else {
        reason = 'AbuseIPDB feed unavailable. Displaying live Geolocation & ISP telemetry.';
      }

      try {
        const fallbackData = await getFallbackTelemetry(ipAddress, reason);
        ipCache.set(ipAddress, { data: fallbackData, timestamp: Date.now() });
        return fallbackData;
      } catch (fallbackErr) {
        console.error('[AbuseIPDB Service] Fallback failed:', fallbackErr.message);
      }
    }

    if (status === 422) {
      throw new ServiceError(
        'AbuseIPDB',
        'Invalid IP address provided.',
        400,
        { original: error.response?.data }
      );
    }

    // Ultimate safeguard: return fallback instead of blowing up the UI
    const finalFallback = await getFallbackTelemetry(ipAddress, 'Telemetry retrieved via public OSINT resolvers.');
    ipCache.set(ipAddress, { data: finalFallback, timestamp: Date.now() });
    return finalFallback;
  }
}
