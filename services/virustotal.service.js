import axios from 'axios';
import config from '../config/env.js';
import { ServiceError } from '../middleware/errorHandler.js';

const API_BASE = 'https://www.virustotal.com/api/v3';
const TIMEOUT = 15_000; // 15 seconds

// ── Threat score calculation ────────────────────────────────────
function calculateThreatScore(stats) {
  const total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
  if (total === 0) return 0;
  // Weighted: malicious=100%, suspicious=60%
  return Math.round(((stats.malicious * 100 + stats.suspicious * 60) / total));
}

function classifyThreat(score) {
  if (score >= 60) return { level: 'malicious', label: 'Malicious', color: '#ef4444' };
  if (score >= 30) return { level: 'suspicious', label: 'Suspicious', color: '#f97316' };
  if (score >= 10) return { level: 'low_risk', label: 'Low Risk', color: '#eab308' };
  return { level: 'clean', label: 'Clean', color: '#10b981' };
}

// ── File hash lookup ────────────────────────────────────────────
export async function checkFileHash(sha256Hash) {
  try {
    const response = await axios.get(`${API_BASE}/files/${sha256Hash}`, {
      headers: {
        'x-apikey': config.VIRUSTOTAL_API_KEY,
        Accept: 'application/json',
      },
      timeout: TIMEOUT,
    });

    const attrs = response.data.data.attributes;
    const stats = attrs.last_analysis_stats || {};
    const threatScore = calculateThreatScore(stats);
    const threat = classifyThreat(threatScore);

    return {
      found: true,
      hash: {
        sha256: attrs.sha256,
        sha1: attrs.sha1,
        md5: attrs.md5,
      },

      // ── Detection summary ──
      detectionStats: {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        undetected: stats.undetected || 0,
        harmless: stats.harmless || 0,
        timeout: stats.timeout || 0,
        total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0),
      },
      threatScore,
      threatLevel: threat.level,
      threatLabel: threat.label,
      threatColor: threat.color,

      // ── File info ──
      fileName: attrs.meaningful_name || attrs.names?.[0] || 'Unknown',
      fileType: attrs.type_description || attrs.magic || 'Unknown',
      fileSize: attrs.size || 0,
      fileSizeFormatted: formatBytes(attrs.size || 0),

      // ── Threat details ──
      popularThreatName: attrs.popular_threat_classification?.suggested_threat_label || null,
      threatCategory: attrs.popular_threat_classification?.popular_threat_category?.[0]?.value || null,
      tags: attrs.tags || [],

      // ── Scan info ──
      lastAnalysisDate: attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      firstSubmissionDate: attrs.first_submission_date
        ? new Date(attrs.first_submission_date * 1000).toISOString()
        : null,
      timesSubmitted: attrs.times_submitted || 0,

      // ── Engine results (top detections) ──
      topDetections: extractTopDetections(attrs.last_analysis_results),

      queriedAt: new Date().toISOString(),
    };
  } catch (error) {
    if (error.response?.status === 404) {
      return {
        found: false,
        hash: { sha256: sha256Hash },
        message: 'File not found in VirusTotal database. It may be clean or previously unsubmitted.',
        queriedAt: new Date().toISOString(),
      };
    }
    if (error.response?.status === 429) {
      throw new ServiceError(
        'VirusTotal',
        'VirusTotal API rate limit exceeded. Try again later.',
        429
      );
    }
    throw error;
  }
}

// ── Domain lookup ───────────────────────────────────────────────
export async function checkDomain(domain) {
  try {
    const response = await axios.get(`${API_BASE}/domains/${domain}`, {
      headers: {
        'x-apikey': config.VIRUSTOTAL_API_KEY,
        Accept: 'application/json',
      },
      timeout: TIMEOUT,
    });

    const attrs = response.data.data.attributes;
    const stats = attrs.last_analysis_stats || {};
    const totalEngines = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0);
    const threatScore = totalEngines > 0
      ? Math.round(((stats.malicious || 0) * 100 + (stats.suspicious || 0) * 60) / totalEngines)
      : 0;
    const threat = classifyThreat(threatScore);

    return {
      found: true,
      domain,

      // ── Reputation ──
      reputation: attrs.reputation || 0,
      threatScore,
      threatLevel: threat.level,
      threatLabel: threat.label,
      threatColor: threat.color,

      // ── Detection stats ──
      detectionStats: {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        undetected: stats.undetected || 0,
        harmless: stats.harmless || 0,
        total: totalEngines,
      },

      // ── Domain info ──
      registrar: attrs.registrar || 'Unknown',
      creationDate: attrs.creation_date
        ? new Date(attrs.creation_date * 1000).toISOString()
        : null,
      lastUpdateDate: attrs.last_update_date
        ? new Date(attrs.last_update_date * 1000).toISOString()
        : null,
      lastDnsRecords: (attrs.last_dns_records || []).map((r) => ({
        type: r.type,
        value: r.value,
        ttl: r.ttl,
      })),

      // ── Categories ──
      categories: attrs.categories || {},
      totalVotes: attrs.total_votes || { harmless: 0, malicious: 0 },

      // ── WHOIS ──
      whoisInfo: extractWhois(attrs.whois || ''),

      // ── Analysis ──
      lastAnalysisDate: attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,

      queriedAt: new Date().toISOString(),
    };
  } catch (error) {
    if (error.response?.status === 404) {
      return {
        found: false,
        domain,
        message: 'Domain not found in VirusTotal database.',
        queriedAt: new Date().toISOString(),
      };
    }
    if (error.response?.status === 429) {
      throw new ServiceError(
        'VirusTotal',
        'VirusTotal API rate limit exceeded. Try again later.',
        429
      );
    }
    throw error;
  }
}

// ── Helpers ─────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

function extractTopDetections(results) {
  if (!results) return [];
  return Object.entries(results)
    .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
    .slice(0, 10)
    .map(([engine, v]) => ({
      engine,
      category: v.category,
      result: v.result,
    }));
}

function extractWhois(whoisRaw) {
  if (!whoisRaw) return {};
  const fields = {};
  const patterns = {
    registrant: /Registrant\s*(?:Organization|Name):\s*(.+)/i,
    adminEmail: /Admin\s*Email:\s*(.+)/i,
    nameServers: /Name\s*Server:\s*(.+)/gi,
    expiryDate: /(?:Expiry|Expiration)\s*Date:\s*(.+)/i,
  };
  for (const [key, regex] of Object.entries(patterns)) {
    if (key === 'nameServers') {
      const matches = [...whoisRaw.matchAll(regex)];
      fields[key] = matches.map((m) => m[1].trim().toLowerCase());
    } else {
      const match = whoisRaw.match(regex);
      if (match) fields[key] = match[1].trim();
    }
  }
  return fields;
}
