// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — MAC Vendors Service
// ═══════════════════════════════════════════════════════════════

import config from '../config/env.js';
import { AppError } from '../middleware/errorHandler.js';

const MACVENDORS_BASE_URL = 'https://api.macvendors.com';

// In-memory cache to reduce external latency and avoid rate-limiting
const macCache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// Verified prominent vendor presets for instantaneous lookup & offline resilience
const VENDOR_PRESETS = {
  '00:00:0C': { vendor: 'Cisco Systems, Inc', country: 'United States', category: 'Enterprise Networking' },
  '00:01:42': { vendor: 'Cisco Systems, Inc', country: 'United States', category: 'Enterprise Networking' },
  '00:1A:2B': { vendor: 'Ayecom Technology Co., Ltd.', country: 'Taiwan', category: 'Telecommunications' },
  '00:17:F2': { vendor: 'Apple, Inc.', country: 'United States', category: 'Consumer Electronics' },
  '00:1B:63': { vendor: 'Apple, Inc.', country: 'United States', category: 'Consumer Electronics' },
  'B8:27:EB': { vendor: 'Raspberry Pi Foundation', country: 'United Kingdom', category: 'Single Board Computers' },
  'DC:A6:32': { vendor: 'Raspberry Pi Trading Ltd', country: 'United Kingdom', category: 'Single Board Computers' },
  '00:1B:21': { vendor: 'Intel Corporate', country: 'United States', category: 'Semiconductor / Network Adapters' },
  '00:50:56': { vendor: 'VMware, Inc.', country: 'United States', category: 'Virtualization & Cloud' },
  '00:0C:29': { vendor: 'VMware, Inc.', country: 'United States', category: 'Virtualization & Cloud' },
  '24:6F:28': { vendor: 'Espressif Inc.', country: 'China', category: 'IoT / Microcontrollers (ESP32/ESP8266)' },
  '3C:71:BF': { vendor: 'Espressif Inc.', country: 'China', category: 'IoT / Microcontrollers (ESP32/ESP8266)' },
  '08:00:27': { vendor: 'PCS Systemtechnik GmbH (Oracle VirtualBox)', country: 'Germany', category: 'Virtual Machine' },
  '00:15:5D': { vendor: 'Microsoft Corporation (Hyper-V)', country: 'United States', category: 'Virtual Machine / OS' },
  '54:60:09': { vendor: 'Google, Inc.', country: 'United States', category: 'Consumer Hardware' },
};

/**
 * Normalizes, validates and extracts granular components from a raw MAC address
 */
export function parseAndNormalizeMac(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    throw new AppError('MAC address is required.', 400, 'MISSING_MAC');
  }

  // Remove all non-hex characters (colons, hyphens, dots, spaces)
  const cleanedHex = rawInput.trim().replace(/[^a-fA-F0-9]/g, '').toUpperCase();

  if (cleanedHex.length !== 6 && cleanedHex.length !== 12) {
    throw new AppError(
      `Invalid MAC address or OUI prefix: "${rawInput}". Must contain exactly 6 hex characters (OUI) or 12 hex characters (Full MAC).`,
      400,
      'INVALID_MAC_FORMAT'
    );
  }

  // Format standard representations
  const isFullMac = cleanedHex.length === 12;
  const ouiHex = cleanedHex.substring(0, 6);
  const ouiColon = `${ouiHex.slice(0, 2)}:${ouiHex.slice(2, 4)}:${ouiHex.slice(4, 6)}`;
  const ouiHyphen = `${ouiHex.slice(0, 2)}-${ouiHex.slice(2, 4)}-${ouiHex.slice(4, 6)}`;

  let standardColon = ouiColon;
  let standardHyphen = ouiHyphen;
  let ciscoDot = `${ouiHex.slice(0, 4)}.${ouiHex.slice(4, 6)}`;
  let nicBytes = null;

  if (isFullMac) {
    const nicHex = cleanedHex.substring(6);
    nicBytes = `${nicHex.slice(0, 2)}:${nicHex.slice(2, 4)}:${nicHex.slice(4, 6)}`;
    standardColon = `${ouiColon}:${nicBytes}`;
    standardHyphen = `${ouiHyphen}-${nicHex.slice(0, 2)}-${nicHex.slice(2, 4)}-${nicHex.slice(4, 6)}`;
    ciscoDot = `${cleanedHex.slice(0, 4)}.${cleanedHex.slice(4, 8)}.${cleanedHex.slice(8, 12)}`.toLowerCase();
  }

  // Analyze network characteristics from the first octet
  const firstByte = parseInt(cleanedHex.substring(0, 2), 16);
  const isMulticast = (firstByte & 0x01) !== 0;
  const isLocallyAdministered = (firstByte & 0x02) !== 0;

  // Decimal and Binary representation
  let decimalValue = null;
  try {
    decimalValue = BigInt(`0x${cleanedHex}`).toString(10);
  } catch (_) {}

  return {
    rawInput: rawInput.trim(),
    cleanedHex,
    isFullMac,
    oui: {
      hex: ouiHex,
      colon: ouiColon,
      hyphen: ouiHyphen,
    },
    nicBytes,
    formats: {
      colon: standardColon,
      hyphen: standardHyphen,
      cisco: ciscoDot,
      raw: cleanedHex,
      decimal: decimalValue,
    },
    characteristics: {
      castType: isMulticast ? 'Multicast' : 'Unicast',
      castDescription: isMulticast
        ? 'Group address / Multicast traffic target'
        : 'Individual device / Point-to-point transmission',
      administrationType: isLocallyAdministered ? 'LAA (Locally Administered)' : 'UAA (Universally Administered)',
      administrationDescription: isLocallyAdministered
        ? 'Privately assigned or randomized MAC (MAC Spoofing / Private Wi-Fi)'
        : 'Globally unique IEEE OUI enforced by hardware manufacturer',
    },
  };
}

/**
 * Performs MAC Vendor lookup via api.macvendors.com with Bearer token authentication
 */
export async function lookupMacVendor(rawMac) {
  const parsed = parseAndNormalizeMac(rawMac);
  const cacheKey = parsed.oui.colon;

  // 1. Check in-memory cache
  const cached = macCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return {
      ...parsed,
      vendor: cached.vendor,
      isCached: true,
      found: cached.found !== false,
      details: cached.details || null,
    };
  }

  // 2. Check local presets (instant response)
  const preset = VENDOR_PRESETS[parsed.oui.colon];
  if (preset) {
    const resultData = {
      ...parsed,
      vendor: preset.vendor,
      isCached: false,
      found: true,
      details: {
        country: preset.country,
        category: preset.category,
      },
    };
    macCache.set(cacheKey, { timestamp: Date.now(), vendor: preset.vendor, found: true, details: resultData.details });
    return resultData;
  }

  // 3. Request external API
  const token = (process.env.MACVENDORS_API_TOKEN || config.MACVENDORS_API_TOKEN || '').trim();
  const headers = {
    'User-Agent': 'sudodeck-OSINT-Platform/2.0',
    Accept: 'application/json, text/plain, */*',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const targetQuery = parsed.oui.colon;
  const url = `${MACVENDORS_BASE_URL}/${encodeURIComponent(targetQuery)}`;

  let response;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    response = await fetch(url, {
      method: 'GET',
      headers,
      signal: controller.signal,
    });
    clearTimeout(timeout);
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new AppError('MAC Vendors API request timed out. Please try again.', 504, 'MAC_API_TIMEOUT');
    }
    throw new AppError(`Network error querying MAC Vendors API: ${err.message}`, 502, 'MAC_API_NETWORK_ERROR');
  }

  if (response.status === 404) {
    const notFoundResult = {
      ...parsed,
      vendor: 'Vendor Not Registered in IEEE Database',
      isCached: false,
      found: false,
      details: null,
    };
    macCache.set(cacheKey, { timestamp: Date.now(), vendor: notFoundResult.vendor, found: false });
    return notFoundResult;
  }

  if (response.status === 401 || response.status === 403) {
    throw new AppError('MACVendors API authentication failed. Please check MACVENDORS_API_TOKEN.', 401, 'MAC_AUTH_ERROR');
  }

  if (response.status === 429) {
    throw new AppError('MACVendors API rate limit reached. Please wait a moment and try again.', 429, 'MAC_RATE_LIMIT');
  }

  if (!response.ok) {
    throw new AppError(`MACVendors API returned HTTP ${response.status}: ${response.statusText}`, response.status, 'MAC_API_ERROR');
  }

  // Result can be plain text string or JSON
  const rawText = await response.text();
  let vendorName = rawText.trim();

  try {
    const json = JSON.parse(rawText);
    if (json.vendor) vendorName = json.vendor;
    else if (json.company) vendorName = json.company;
  } catch (_) {
    // rawText is already clean string
  }

  const finalResult = {
    ...parsed,
    vendor: vendorName || 'Unknown Manufacturer',
    isCached: false,
    found: true,
    details: null,
  };

  macCache.set(cacheKey, { timestamp: Date.now(), vendor: finalResult.vendor, found: true });
  return finalResult;
}
