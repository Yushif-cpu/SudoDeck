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
  if (confidenceScore >= 5)  return { level: 'low', label: 'Low', color: '#22d3ee' };
  return { level: 'clean', label: 'Clean', color: '#10b981' };
}

// ── Usage type mapping ──────────────────────────────────────────
const USAGE_TYPE_MAP = {
  'Commercial':           'Commercial',
  'Organization':         'Organization',
  'Government':           'Government',
  'Military':             'Military',
  'University/College/School': 'Education',
  'Library':              'Library',
  'Content Delivery Network': 'CDN',
  'Fixed Line ISP':       'ISP (Fixed)',
  'Mobile ISP':           'ISP (Mobile)',
  'Data Center/Web Hosting/Transit': 'Data Center',
  'Search Engine Spider':  'Search Bot',
  'Reserved':             'Reserved',
};

// ── Main check function ─────────────────────────────────────────
export async function checkIP(ipAddress) {
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

    return {
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
  } catch (error) {
    if (error.response?.status === 429) {
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

