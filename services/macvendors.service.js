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
  // Cisco & Enterprise
  '00:00:0C': { vendor: 'Cisco Systems, Inc', country: 'United States', category: 'Enterprise Networking' },
  '00:01:42': { vendor: 'Cisco Systems, Inc', country: 'United States', category: 'Enterprise Networking' },
  '00:01:C7': { vendor: 'Cisco Systems, Inc', country: 'United States', category: 'Enterprise Networking' },
  '00:01:C9': { vendor: 'Cisco Systems, Inc', country: 'United States', category: 'Enterprise Networking' },
  // Apple
  '00:17:F2': { vendor: 'Apple, Inc.', country: 'United States', category: 'Consumer Electronics' },
  '00:1B:63': { vendor: 'Apple, Inc.', country: 'United States', category: 'Consumer Electronics' },
  'F0:18:98': { vendor: 'Apple, Inc.', country: 'United States', category: 'Consumer Electronics' },
  'AC:DE:48': { vendor: 'Apple, Inc.', country: 'United States', category: 'Consumer Electronics' },
  '3C:07:54': { vendor: 'Apple, Inc.', country: 'United States', category: 'Consumer Electronics' },
  // Raspberry Pi
  'B8:27:EB': { vendor: 'Raspberry Pi Foundation', country: 'United Kingdom', category: 'Single Board Computers' },
  'DC:A6:32': { vendor: 'Raspberry Pi Trading Ltd', country: 'United Kingdom', category: 'Single Board Computers' },
  'E4:5F:01': { vendor: 'Raspberry Pi Trading Ltd', country: 'United Kingdom', category: 'Single Board Computers' },
  '28:CD:C1': { vendor: 'Raspberry Pi Trading Ltd', country: 'United Kingdom', category: 'Single Board Computers' },
  // Intel / Network
  '00:1B:21': { vendor: 'Intel Corporate', country: 'United States', category: 'Semiconductor / Network Adapters' },
  '00:15:00': { vendor: 'Intel Corporate', country: 'United States', category: 'Semiconductor / Network Adapters' },
  '00:1E:67': { vendor: 'Intel Corporate', country: 'United States', category: 'Semiconductor / Network Adapters' },
  // Virtualization
  '00:50:56': { vendor: 'VMware, Inc.', country: 'United States', category: 'Virtualization & Cloud' },
  '00:0C:29': { vendor: 'VMware, Inc.', country: 'United States', category: 'Virtualization & Cloud' },
  '00:05:69': { vendor: 'VMware, Inc.', country: 'United States', category: 'Virtualization & Cloud' },
  '08:00:27': { vendor: 'PCS Systemtechnik GmbH (Oracle VirtualBox)', country: 'Germany', category: 'Virtual Machine' },
  '00:15:5D': { vendor: 'Microsoft Corporation (Hyper-V)', country: 'United States', category: 'Virtual Machine / OS' },
  '52:54:00': { vendor: 'QEMU / KVM Virtual Machine', country: 'Open Source', category: 'Virtual Machine' },
  // IoT & Microcontrollers
  '24:6F:28': { vendor: 'Espressif Inc.', country: 'China', category: 'IoT / Microcontrollers (ESP32/ESP8266)' },
  '3C:71:BF': { vendor: 'Espressif Inc.', country: 'China', category: 'IoT / Microcontrollers (ESP32/ESP8266)' },
  '84:0D:8E': { vendor: 'Espressif Inc.', country: 'China', category: 'IoT / Microcontrollers (ESP32/ESP8266)' },
  'A4:CF:12': { vendor: 'Espressif Inc.', country: 'China', category: 'IoT / Microcontrollers (ESP32/ESP8266)' },
  // Big Tech
  '54:60:09': { vendor: 'Google, Inc.', country: 'United States', category: 'Consumer Hardware' },
  'D8:6C:63': { vendor: 'Google, Inc.', country: 'United States', category: 'Consumer Hardware' },
  'FC:65:DE': { vendor: 'Amazon Technologies Inc.', country: 'United States', category: 'IoT & Smart Home' },
  '44:65:0D': { vendor: 'Amazon Technologies Inc.', country: 'United States', category: 'IoT & Smart Home' },
  // Networking Hardware
  '00:1A:2B': { vendor: 'Ayecom Technology Co., Ltd.', country: 'Taiwan', category: 'Telecommunications' },
  '00:14:D1': { vendor: 'TRENDnet, Inc.', country: 'United States', category: 'Networking Equipment' },
  '00:18:E7': { vendor: 'Cameo Communications, Inc.', country: 'Taiwan', category: 'Networking' },
  '50:C7:BF': { vendor: 'TP-Link Corporation Limited', country: 'China', category: 'Networking & Routers' },
  'E8:48:B8': { vendor: 'TP-Link Corporation Limited', country: 'China', category: 'Networking & Routers' },
  '24:A4:3C': { vendor: 'Ubiquiti Networks, Inc.', country: 'United States', category: 'Enterprise Wi-Fi & Switches' },
  '04:18:D6': { vendor: 'Ubiquiti Networks, Inc.', country: 'United States', category: 'Enterprise Wi-Fi & Switches' },
  '48:8F:5A': { vendor: 'MikroTik', country: 'Latvia', category: 'Routers & Wireless' },
  // PC Vendors
  '00:14:22': { vendor: 'Dell Inc.', country: 'United States', category: 'Computers & Servers' },
  'B8:AC:6F': { vendor: 'Dell Inc.', country: 'United States', category: 'Computers & Servers' },
  '3C:D9:2B': { vendor: 'HP Inc.', country: 'United States', category: 'Personal Systems & Printers' },
  '00:21:5A': { vendor: 'HP Inc.', country: 'United States', category: 'Personal Systems & Printers' },
  '00:23:7D': { vendor: 'Samsung Electronics Co., Ltd.', country: 'South Korea', category: 'Consumer Electronics' },
  '50:01:D9': { vendor: 'Samsung Electronics Co., Ltd.', country: 'South Korea', category: 'Consumer Electronics' },
  '00:26:55': { vendor: 'Huawei Technologies Co., Ltd', country: 'China', category: 'Telecommunications' },
  '00:1E:10': { vendor: 'Huawei Technologies Co., Ltd', country: 'China', category: 'Telecommunications' },
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
 * Performs MAC Vendor lookup with multi-tier fallback (Zero authentication failure)
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

  // 3. Multi-tier query engine
  let vendorName = null;
  let vendorDetails = null;
  const token = (process.env.MACVENDORS_API_TOKEN || config.MACVENDORS_API_TOKEN || '').trim();
  const targetQuery = parsed.oui.colon;

  // Tier 1: api.macvendors.com (with token if configured)
  try {
    const headers = {
      'User-Agent': 'sudodeck-OSINT-Platform/2.0',
      Accept: 'application/json, text/plain, */*',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(`${MACVENDORS_BASE_URL}/${encodeURIComponent(targetQuery)}`, {
      method: 'GET',
      headers,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.status === 200) {
      const raw = await res.text();
      try {
        const j = JSON.parse(raw);
        vendorName = j.vendor || j.company || raw.trim();
      } catch (_) {
        vendorName = raw.trim();
      }
    } else if (res.status === 404) {
      // Confirmed not registered
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
  } catch (_) {
    // Continue to next tier on timeout or auth failure
  }

  // Tier 2: api.macvendors.com without token (if token caused 401/403 or failed)
  if (!vendorName && token) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(`${MACVENDORS_BASE_URL}/${encodeURIComponent(targetQuery)}`, {
        method: 'GET',
        headers: { 'User-Agent': 'sudodeck-OSINT-Platform/2.0' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (res.status === 200) {
        vendorName = (await res.text()).trim();
      }
    } catch (_) {}
  }

  // Tier 3: api.maclookup.app (free public mirror)
  if (!vendorName) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(`https://api.maclookup.app/v2/macs/${encodeURIComponent(targetQuery)}`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (res.status === 200) {
        const j = await res.json();
        if (j && j.company) {
          vendorName = j.company;
          vendorDetails = {
            country: j.country || null,
            address: j.address || null,
          };
        }
      }
    } catch (_) {}
  }

  // Final check: if vendor found or unknown
  if (vendorName) {
    const finalResult = {
      ...parsed,
      vendor: vendorName,
      isCached: false,
      found: true,
      details: vendorDetails,
    };
    macCache.set(cacheKey, { timestamp: Date.now(), vendor: finalResult.vendor, found: true, details: vendorDetails });
    return finalResult;
  }

  // Unregistered or private MAC
  const fallbackResult = {
    ...parsed,
    vendor: parsed.characteristics.administrationType.includes('LAA')
      ? 'Locally Administered / Randomized MAC (No IEEE OUI)'
      : 'Unknown Manufacturer (Unindexed OUI)',
    isCached: false,
    found: false,
    details: null,
  };

  macCache.set(cacheKey, { timestamp: Date.now(), vendor: fallbackResult.vendor, found: false });
  return fallbackResult;
}
