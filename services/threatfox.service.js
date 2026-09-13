import axios from 'axios';

const THREATFOX_RECENT_URL = 'https://threatfox.abuse.ch/export/json/recent/';
const TIMEOUT_MS = 15000;

// In-memory cache to prevent spamming ThreatFox feed and ensure fast response
let cache = {
  data: null,
  timestamp: 0,
  ttl: 2 * 60 * 1000, // 2 minutes
};

/**
 * Fetch and parse recent malicious IPs from ThreatFox (Abuse.ch)
 * @param {number} limit Number of IPs to return
 * @returns {Promise<Array>} List of parsed malicious IP records
 */
export async function fetchRecentMaliciousIPs(limit = 24) {
  const now = Date.now();

  // Return cached feed if still fresh
  if (cache.data && now - cache.timestamp < cache.ttl) {
    return cache.data.slice(0, limit);
  }

  const response = await axios.get(THREATFOX_RECENT_URL, {
    timeout: TIMEOUT_MS,
    headers: {
      'User-Agent': 'sudodeck-OSINT/1.0',
      Accept: 'application/json',
    },
  });

  const rawData = response.data;
  const list = [];
  const seenIps = new Set();

  if (rawData && typeof rawData === 'object') {
    for (const key of Object.keys(rawData)) {
      const entries = rawData[key];
      if (!Array.isArray(entries)) continue;

      for (const item of entries) {
        if (!item.ioc_value) continue;

        const isIpType = item.ioc_type === 'ip:port' || item.ioc_type === 'ip';
        const ipMatch = item.ioc_value.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);

        if (isIpType || ipMatch) {
          const ip = ipMatch ? ipMatch[1] : item.ioc_value.split(':')[0];
          const port = item.ioc_value.includes(':') ? item.ioc_value.split(':')[1] : null;

          if (!seenIps.has(ip)) {
            seenIps.add(ip);

            const threatDesc = formatThreatType(item.threat_type);
            list.push({
              ip,
              port,
              ioc: item.ioc_value,
              malware: item.malware_printable || item.malware || 'Unknown Malware',
              malwareKey: item.malware || 'unknown',
              threatType: item.threat_type || 'malicious_host',
              threatTypeLabel: threatDesc,
              confidence: item.confidence_level !== undefined ? item.confidence_level : 100,
              firstSeen: item.first_seen_utc || null,
              lastSeen: item.last_seen_utc || item.first_seen_utc || null,
              reporter: item.reporter || 'ThreatFox Community',
              tags: item.tags
                ? typeof item.tags === 'string'
                  ? item.tags.split(',').map((t) => t.trim()).filter(Boolean)
                  : item.tags
                : [],
            });
          }
        }
      }
    }
  }

  // Sort by lastSeen descending (newest first)
  list.sort((a, b) => new Date(b.lastSeen || b.firstSeen || 0) - new Date(a.lastSeen || a.firstSeen || 0));

  cache = {
    data: list,
    timestamp: now,
    ttl: 2 * 60 * 1000,
  };

  return list.slice(0, limit);
}

/**
 * Format threat type slug into human-readable label
 */
function formatThreatType(type) {
  if (!type) return 'Malicious Host';
  const map = {
    botnet_cc: 'Botnet C2',
    payload_delivery: 'Payload Delivery',
    c2: 'Command & Control',
    ransomware: 'Ransomware',
    phishing: 'Phishing Host',
    cryptominer: 'Crypto Miner',
    malware_sample: 'Malware Host',
  };
  return map[type] || type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
