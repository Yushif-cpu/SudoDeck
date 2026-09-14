import axios from 'axios';
import config from '../config/env.js';
import { ServiceError } from '../middleware/errorHandler.js';

const API_BASE = 'https://api.abuseipdb.com/api/v2';
const TIMEOUT = 10_000; // 10 seconds

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

// ── Main check function ─────────────────────────────────────────
export async function checkIP(ipAddress) {
  const cached = ipCache.get(ipAddress);
  if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
    return cached.data;
  }

  try {
    const response = await axios.get(`${API_BASE}/check`, {
      params: {
        ipAddress,
        maxAgeInDays: 90,
        verbose: '',
      },
      headers: {
        Key: config.ABUSEIPDB_API_KEY,
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
    };

    ipCache.set(ipAddress, { data: result, timestamp: Date.now() });
    return result;
  } catch (error) {
    if (error.response?.status === 429) {
      // Graceful fallback to free IP telemetry so UI doesn't break
      try {
        const fallbackRes = await axios.get(`http://ip-api.com/json/${encodeURIComponent(ipAddress)}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query`, {
          timeout: 4000,
        });
        const geo = fallbackRes.data;
        if (geo && geo.status === 'success') {
          const fallbackData = {
            ip: ipAddress,
            isPublic: true,
            ipVersion: ipAddress.includes(':') ? 6 : 4,
            isWhitelisted: false,
            abuseConfidenceScore: 0,
            riskLevel: 'clean',
            riskLabel: 'Quota Exceeded (Telemetry Active)',
            riskColor: '#f59e0b',
            totalReports: 0,
            numDistinctUsers: 0,
            lastReportedAt: null,
            isp: geo.isp || geo.org || 'Unknown',
            domain: geo.org || 'N/A',
            usageType: 'Network Host',
            hostnames: [geo.as || ''].filter(Boolean),
            countryCode: geo.countryCode || 'Unknown',
            countryName: geo.country || 'Unknown',
            queriedAt: new Date().toISOString(),
            warning: 'AbuseIPDB daily API limit reached. Displaying fallback Geolocation & ISP telemetry.',
          };
          ipCache.set(ipAddress, { data: fallbackData, timestamp: Date.now() });
          return fallbackData;
        }
      } catch (fallbackErr) {
        // Continue to throwing standard rate limit error
      }

      throw new ServiceError(
        'AbuseIPDB',
        'AbuseIPDB rate limit exceeded. Try again later.',
        429,
        { retryAfter: error.response.headers?.['retry-after'] }
      );
    }
    if (error.response?.status === 422) {
      throw new ServiceError(
        'AbuseIPDB',
        'Invalid IP address provided.',
        400,
        { original: error.response.data }
      );
    }
    throw error; // let global handler catch it
  }
}

