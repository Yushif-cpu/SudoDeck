// ═══════════════════════════════════════════════════════════════
//  SudoDeck OSINT — Subdomain & Resource Discovery Service
//  Aggregates Certificate Transparency (crt.sh) and HackerTarget
// ═══════════════════════════════════════════════════════════════

import axios from 'axios';

/**
 * Sanitize and validate target domain input
 * @param {string} input - Raw user input (e.g. "https://example.com/test")
 * @returns {string|null} Clean root domain or null if invalid
 */
export function sanitizeDomain(input) {
  if (!input || typeof input !== 'string') return null;

  let domain = input.trim().toLowerCase();
  // Strip protocols
  domain = domain.replace(/^[a-zA-Z]+:\/\//, '');
  // Strip paths, query strings, fragments, and ports
  domain = domain.split('/')[0].split('?')[0].split('#')[0].split(':')[0].trim();

  // Strip leading wildcards if user entered *.example.com
  domain = domain.replace(/^\*\./, '');

  // Standard domain regex validation
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain) ? domain : null;
}

/**
 * Query crt.sh for SSL Certificate Transparency logs
 * @param {string} domain - Clean target domain
 * @returns {Promise<{ success: boolean, count: number, error?: string, results: Map<string, { ip?: string, sources: Set<string> }> }>}
 */
async function fetchFromCrtSh(domain) {
  const sourceName = 'crt.sh';
  const resultMap = new Map();

  try {
    const response = await axios.get(`https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`, {
      timeout: 12000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SudoDeck-Recon/2.0',
        'Accept': 'application/json, text/plain, */*',
      },
    });

    if (Array.isArray(response.data)) {
      for (const entry of response.data) {
        if (!entry || !entry.name_value) continue;

        // name_value can contain multiple domain names separated by newline
        const rawNames = entry.name_value.split('\n');
        for (let name of rawNames) {
          name = name.trim().toLowerCase();
          // Remove wildcard prefix
          name = name.replace(/^\*\./, '');

          // Verify it belongs to target domain
          if (name === domain || name.endsWith(`.${domain}`)) {
            if (!resultMap.has(name)) {
              resultMap.set(name, { sources: new Set([sourceName]) });
            } else {
              resultMap.get(name).sources.add(sourceName);
            }
          }
        }
      }
    }

    return {
      success: true,
      count: resultMap.size,
      results: resultMap,
    };
  } catch (err) {
    const isTimeout = err.code === 'ECONNABORTED' || err.message?.includes('timeout');
    return {
      success: false,
      count: 0,
      error: isTimeout ? 'crt.sh request timed out' : (err.message || 'crt.sh error'),
      results: resultMap,
    };
  }
}

/**
 * Query HackerTarget Host Search API
 * @param {string} domain - Clean target domain
 * @returns {Promise<{ success: boolean, count: number, error?: string, results: Map<string, { ip?: string, sources: Set<string> }> }>}
 */
async function fetchFromHackerTarget(domain) {
  const sourceName = 'HackerTarget';
  const resultMap = new Map();

  try {
    const response = await axios.get(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, {
      timeout: 9000,
      headers: {
        'User-Agent': 'SudoDeck-Recon/2.0',
      },
    });

    const rawText = typeof response.data === 'string' ? response.data : '';

    if (
      rawText.includes('API count exceeded') ||
      rawText.includes('error check your search parameter') ||
      rawText.includes('No records')
    ) {
      return {
        success: false,
        count: 0,
        error: rawText.split('\n')[0].trim() || 'HackerTarget rate limit or search parameter issue',
        results: resultMap,
      };
    }

    const lines = rawText.split('\n');
    for (const line of lines) {
      const parts = line.trim().split(',');
      if (parts.length >= 1 && parts[0]) {
        let host = parts[0].trim().toLowerCase();
        host = host.replace(/^\*\./, '');
        const ip = parts[1] ? parts[1].trim() : undefined;

        if (host === domain || host.endsWith(`.${domain}`)) {
          if (!resultMap.has(host)) {
            resultMap.set(host, { ip, sources: new Set([sourceName]) });
          } else {
            const item = resultMap.get(host);
            item.sources.add(sourceName);
            if (!item.ip && ip) item.ip = ip;
          }
        }
      }
    }

    return {
      success: true,
      count: resultMap.size,
      results: resultMap,
    };
  } catch (err) {
    const isTimeout = err.code === 'ECONNABORTED' || err.message?.includes('timeout');
    return {
      success: false,
      count: 0,
      error: isTimeout ? 'HackerTarget request timed out' : (err.message || 'HackerTarget error'),
      results: resultMap,
    };
  }
}

/**
 * Main subdomain and resource discovery function
 * @param {string} rawDomain - User-supplied domain string
 * @returns {Promise<object>} Unified discovery payload
 */
export async function discoverSubdomains(rawDomain) {
  const startTime = Date.now();
  const domain = sanitizeDomain(rawDomain);

  if (!domain) {
    throw new Error('Invalid target domain format. Example: target.com or security-intel.org');
  }

  // Execute both reconnaissance engines concurrently
  const [crtOutcome, htOutcome] = await Promise.all([
    fetchFromCrtSh(domain),
    fetchFromHackerTarget(domain),
  ]);

  if (!crtOutcome.success && !htOutcome.success) {
    throw new Error(`Reconnaissance sources failed: crt.sh (${crtOutcome.error || 'error'}), HackerTarget (${htOutcome.error || 'error'})`);
  }

  // Merge results
  const aggregatedMap = new Map();

  // Merge crt.sh
  if (crtOutcome.results) {
    for (const [sub, data] of crtOutcome.results.entries()) {
      if (!aggregatedMap.has(sub)) {
        aggregatedMap.set(sub, { ip: data.ip, sources: new Set(data.sources) });
      } else {
        data.sources.forEach((s) => aggregatedMap.get(sub).sources.add(s));
      }
    }
  }

  // Merge HackerTarget
  if (htOutcome.results) {
    for (const [sub, data] of htOutcome.results.entries()) {
      if (!aggregatedMap.has(sub)) {
        aggregatedMap.set(sub, { ip: data.ip, sources: new Set(data.sources) });
      } else {
        const item = aggregatedMap.get(sub);
        data.sources.forEach((s) => item.sources.add(s));
        if (!item.ip && data.ip) item.ip = data.ip;
      }
    }
  }

  // Convert to clean array and sort logically
  const subdomains = Array.from(aggregatedMap.entries())
    .map(([subdomain, details]) => ({
      subdomain,
      ip: details.ip || null,
      sources: Array.from(details.sources),
    }))
    .sort((a, b) => {
      // Shorter domain depth first, then alphabetical
      const depthA = a.subdomain.split('.').length;
      const depthB = b.subdomain.split('.').length;
      if (depthA !== depthB) return depthA - depthB;
      return a.subdomain.localeCompare(b.subdomain);
    });

  return {
    success: true,
    target: domain,
    total: subdomains.length,
    durationMs: Date.now() - startTime,
    subdomains,
    sourcesStatus: {
      crtSh: {
        success: crtOutcome.success,
        count: crtOutcome.count,
        error: crtOutcome.error,
      },
      hackerTarget: {
        success: htOutcome.success,
        count: htOutcome.count,
        error: htOutcome.error,
      },
    },
  };
}
