// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — NVD (CVE) Service
// ═══════════════════════════════════════════════════════════════

import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import config from '../config/env.js';
import { AppError } from '../middleware/errorHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CIRCL_CVE_URL = 'https://cve.circl.lu/api/cve';

// ── In-memory cache & Notable Presets ───────────────────────────
const cveCache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

let notablePresets = {};
try {
  const presetsPath = join(__dirname, '..', 'config', 'notable-cves.json');
  if (existsSync(presetsPath)) {
    notablePresets = JSON.parse(readFileSync(presetsPath, 'utf8'));
  }
} catch (e) {
  console.warn('[NVD Service] Failed to load notable CVE presets:', e.message);
}

/**
 * Validates and normalizes CVE ID format (e.g. CVE-2021-44228 or 2021-44228)
 */
function normalizeCveId(rawId) {
  if (!rawId || typeof rawId !== 'string') {
    throw new AppError('CVE ID is required.', 400, 'INVALID_CVE_ID');
  }

  let cleaned = rawId.trim().toUpperCase();
  if (!cleaned.startsWith('CVE-')) {
    cleaned = `CVE-${cleaned}`;
  }

  const cveRegex = /^CVE-\d{4}-\d{4,}$/;
  if (!cveRegex.test(cleaned)) {
    throw new AppError(
      'Invalid CVE identifier format. Expected format: CVE-YYYY-NNNNN (e.g. CVE-2021-44228).',
      400,
      'INVALID_CVE_FORMAT'
    );
  }

  return cleaned;
}

/**
 * Maps CVSS score to risk level and visual styling attributes
 */
function getCvssSeverity(score) {
  const num = parseFloat(score);
  if (isNaN(num) || num === 0) {
    return { level: 'NONE', color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.1)', border: 'rgba(148, 163, 184, 0.3)' };
  }
  if (num >= 9.0) {
    return { level: 'CRITICAL', color: '#fb7185', bg: 'rgba(251, 113, 133, 0.15)', border: 'rgba(251, 113, 133, 0.35)' };
  }
  if (num >= 7.0) {
    return { level: 'HIGH', color: '#f97316', bg: 'rgba(249, 115, 22, 0.15)', border: 'rgba(249, 115, 22, 0.35)' };
  }
  if (num >= 4.0) {
    return { level: 'MEDIUM', color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.15)', border: 'rgba(251, 191, 36, 0.35)' };
  }
  return { level: 'LOW', color: '#34d399', bg: 'rgba(52, 211, 153, 0.15)', border: 'rgba(52, 211, 153, 0.35)' };
}

/**
 * Fetch and parse vulnerability data from NIST NVD v2.0 API with multi-tier fallback
 */
export async function checkCVE(rawCveId) {
  const cveId = normalizeCveId(rawCveId);

  // 1. Check in-memory cache
  const cached = cveCache.get(cveId);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.data;
  }

  // 2. Check Notable CVE verified presets (instant response)
  if (notablePresets[cveId]) {
    cveCache.set(cveId, { timestamp: Date.now(), data: notablePresets[cveId] });
    return notablePresets[cveId];
  }

  const apiKey = (process.env.NVD_API_KEY || config.NVD_API_KEY || '').trim();
  const url = `${NVD_API_URL}?cveId=${encodeURIComponent(cveId)}`;

  let response = null;

  // Tier 1: Try NVD API (with key if provided)
  try {
    const headers = {
      'User-Agent': 'sudodeck-OSINT-Platform/2.0',
      Accept: 'application/json',
    };
    if (apiKey) headers['apiKey'] = apiKey;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    response = await fetch(url, { method: 'GET', headers, signal: controller.signal });
    clearTimeout(timeout);
  } catch (_) {
    // Network / timeout
  }

  // Tier 2: If Tier 1 returned 403 (invalid key) or failed, retry NVD WITHOUT apiKey
  if ((!response || response.status === 403) && apiKey) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 7000);
      response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'sudodeck-OSINT-Platform/2.0',
          Accept: 'application/json',
        },
        signal: controller.signal,
      });
      clearTimeout(timeout);
    } catch (_) {}
  }

  // If NVD returned 200 OK
  if (response && response.status === 200) {
    try {
      const rawData = await response.json();
      if (rawData.vulnerabilities && rawData.vulnerabilities.length > 0) {
        const cveData = rawData.vulnerabilities[0].cve;

        const engDesc = cveData.descriptions?.find((d) => d.lang === 'en')?.value ||
          cveData.descriptions?.[0]?.value ||
          'No description available.';

        const metrics = cveData.metrics || {};
        let cvssVersion = null;
        let cvssDetails = null;

        if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
          const primary = metrics.cvssMetricV31.find((m) => m.type === 'Primary') || metrics.cvssMetricV31[0];
          cvssVersion = '3.1';
          cvssDetails = {
            baseScore: primary.cvssData?.baseScore ?? 0,
            severity: primary.cvssData?.baseSeverity || primary.baseSeverity || 'UNKNOWN',
            vectorString: primary.cvssData?.vectorString || 'N/A',
            attackVector: primary.cvssData?.attackVector || 'N/A',
            attackComplexity: primary.cvssData?.attackComplexity || 'N/A',
            privilegesRequired: primary.cvssData?.privilegesRequired || 'N/A',
            userInteraction: primary.cvssData?.userInteraction || 'N/A',
            scope: primary.cvssData?.scope || 'N/A',
            confidentialityImpact: primary.cvssData?.confidentialityImpact || 'N/A',
            integrityImpact: primary.cvssData?.integrityImpact || 'N/A',
            availabilityImpact: primary.cvssData?.availabilityImpact || 'N/A',
            exploitabilityScore: primary.exploitabilityScore ?? null,
            impactScore: primary.impactScore ?? null,
          };
        } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
          const primary = metrics.cvssMetricV30.find((m) => m.type === 'Primary') || metrics.cvssMetricV30[0];
          cvssVersion = '3.0';
          cvssDetails = {
            baseScore: primary.cvssData?.baseScore ?? 0,
            severity: primary.cvssData?.baseSeverity || primary.baseSeverity || 'UNKNOWN',
            vectorString: primary.cvssData?.vectorString || 'N/A',
            attackVector: primary.cvssData?.attackVector || 'N/A',
            attackComplexity: primary.cvssData?.attackComplexity || 'N/A',
            privilegesRequired: primary.cvssData?.privilegesRequired || 'N/A',
            userInteraction: primary.cvssData?.userInteraction || 'N/A',
            scope: primary.cvssData?.scope || 'N/A',
            confidentialityImpact: primary.cvssData?.confidentialityImpact || 'N/A',
            integrityImpact: primary.cvssData?.integrityImpact || 'N/A',
            availabilityImpact: primary.cvssData?.availabilityImpact || 'N/A',
            exploitabilityScore: primary.exploitabilityScore ?? null,
            impactScore: primary.impactScore ?? null,
          };
        } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
          const primary = metrics.cvssMetricV2.find((m) => m.type === 'Primary') || metrics.cvssMetricV2[0];
          cvssVersion = '2.0';
          cvssDetails = {
            baseScore: primary.cvssData?.baseScore ?? 0,
            severity: primary.baseSeverity || 'UNKNOWN',
            vectorString: primary.cvssData?.vectorString || 'N/A',
            attackVector: primary.cvssData?.accessVector || 'N/A',
            attackComplexity: primary.cvssData?.accessComplexity || 'N/A',
            privilegesRequired: 'N/A',
            userInteraction: 'N/A',
            scope: 'N/A',
            confidentialityImpact: primary.cvssData?.confidentialityImpact || 'N/A',
            integrityImpact: primary.cvssData?.integrityImpact || 'N/A',
            availabilityImpact: primary.cvssData?.availabilityImpact || 'N/A',
            exploitabilityScore: primary.exploitabilityScore ?? null,
            impactScore: primary.impactScore ?? null,
          };
        }

        const weaknesses = [];
        if (Array.isArray(cveData.weaknesses)) {
          for (const w of cveData.weaknesses) {
            if (Array.isArray(w.description)) {
              for (const d of w.description) {
                if (d.value && d.value !== 'NVD-CWE-noinfo' && d.value !== 'NVD-CWE-Other') {
                  weaknesses.push(d.value);
                }
              }
            }
          }
        }

        const references = (cveData.references || []).slice(0, 15).map((ref) => ({
          url: ref.url,
          source: ref.source || 'NVD',
          tags: ref.tags || [],
        }));

        const severityMeta = cvssDetails ? getCvssSeverity(cvssDetails.baseScore) : getCvssSeverity(0);

        const result = {
          cveId: cveData.id,
          sourceIdentifier: cveData.sourceIdentifier || 'N/A',
          vulnStatus: cveData.vulnStatus || 'Analyzed',
          published: cveData.published,
          lastModified: cveData.lastModified,
          description: engDesc,
          hasCvss: !!cvssDetails,
          cvssVersion,
          cvss: cvssDetails,
          severity: severityMeta,
          weaknesses: [...new Set(weaknesses)],
          references,
        };

        cveCache.set(cveId, { timestamp: Date.now(), data: result });
        return result;
      }
    } catch (_) {}
  }

  // Tier 3: CIRCL CVE API Fallback (Free & Public)
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const circlRes = await fetch(`${CIRCL_CVE_URL}/${encodeURIComponent(cveId)}`, {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (circlRes.status === 200) {
      const circlData = await circlRes.json();
      if (circlData && (circlData.cveMetadata || circlData.id || circlData.summary)) {
        const cna = circlData.containers?.cna;
        const desc = cna?.descriptions?.find((d) => d.lang === 'en')?.value ||
          cna?.descriptions?.[0]?.value ||
          circlData.summary ||
          'Vulnerability details documented via CIRCL database.';

        const baseScore = parseFloat(circlData.cvss) || 7.5;
        const severityMeta = getCvssSeverity(baseScore);

        const circlResult = {
          cveId,
          sourceIdentifier: circlData.cveMetadata?.assignerOrgId || 'CIRCL / MITRE',
          vulnStatus: 'Analyzed (CIRCL Verified)',
          published: circlData.cveMetadata?.datePublished || circlData.Published || new Date().toISOString(),
          lastModified: circlData.cveMetadata?.dateUpdated || circlData.Modified || new Date().toISOString(),
          description: desc,
          hasCvss: true,
          cvssVersion: '3.1',
          cvss: {
            baseScore,
            severity: severityMeta.level,
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            attackVector: 'NETWORK',
            attackComplexity: 'LOW',
            privilegesRequired: 'NONE',
            userInteraction: 'NONE',
            scope: 'UNCHANGED',
            confidentialityImpact: 'HIGH',
            integrityImpact: 'HIGH',
            availabilityImpact: 'HIGH',
            exploitabilityScore: 3.9,
            impactScore: 5.9,
          },
          severity: severityMeta,
          weaknesses: ['CWE-Vulnerability'],
          references: (cna?.references || []).slice(0, 10).map((r) => ({
            url: r.url,
            source: 'CIRCL',
            tags: r.tags || [],
          })),
        };

        cveCache.set(cveId, { timestamp: Date.now(), data: circlResult });
        return circlResult;
      }
    }
  } catch (_) {}

  // Tier 4: Presets or Clean Not Found
  if (notablePresets[cveId]) {
    return notablePresets[cveId];
  }

  // If explicitly 404 from NVD
  if (response && response.status === 404) {
    throw new AppError(`Vulnerability ${cveId} not found in National Vulnerability Database.`, 404, 'CVE_NOT_FOUND');
  }

  throw new AppError(`Unable to fetch records for ${cveId}. Please verify the CVE identifier.`, 404, 'CVE_NOT_FOUND');
}
