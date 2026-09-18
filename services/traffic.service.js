// ═══════════════════════════════════════════════════════════════
//  Web Traffic & Audience Intelligence Service (Similarweb + Supabase)
// ═══════════════════════════════════════════════════════════════

import axios from 'axios';
import config from '../config/env.js';
import { supabase } from './supabase.service.js';
import { reserveTrafficCall } from './traffic-budget.js';

/**
 * Clean & normalize domain name
 * @param {string} rawDomain
 * @returns {string}
 */
export function normalizeDomain(rawDomain) {
  if (!rawDomain || typeof rawDomain !== 'string') return '';
  let cleaned = rawDomain.trim().toLowerCase();
  cleaned = cleaned.replace(/^[a-zA-Z]+:\/\//, '');
  cleaned = cleaned.split('/')[0];
  cleaned = cleaned.split('?')[0];
  cleaned = cleaned.split('#')[0];
  cleaned = cleaned.split(':')[0];
  cleaned = cleaned.replace(/^\*\./, '');
  return cleaned;
}

/**
 * Format duration in seconds to mm:ss or hh:mm:ss
 */
function formatDurationSeconds(sec) {
  if (typeof sec === 'string' && sec.includes(':')) return sec;
  const s = Math.round(Number(sec));
  if (isNaN(s) || s <= 0) return 'N/A';
  const mins = Math.floor(s / 60);
  const remSec = s % 60;
  return `${String(mins).padStart(2, '0')}:${String(remSec).padStart(2, '0')}`;
}

/**
 * Normalize raw Similarweb Scraper dataset item into structured metrics
 */
function normalizeTrafficPayload(rawItem, domain) {
  if (!rawItem || typeof rawItem !== 'object') {
    return { domain };
  }

  // Monthly visits
  let totalVisits = rawItem.visits || rawItem.totalVisits;
  if (!totalVisits && rawItem.estimatedMonthlyVisits && typeof rawItem.estimatedMonthlyVisits === 'object') {
    const vals = Object.values(rawItem.estimatedMonthlyVisits);
    if (vals.length > 0) totalVisits = vals[vals.length - 1];
  }

  // Bounce rate
  let bounceRate = rawItem.bounceRate || rawItem.bounce_rate;
  if (bounceRate !== null && bounceRate !== undefined && bounceRate !== '') {
    if (typeof bounceRate === 'string' && bounceRate.includes('%')) {
      const p = parseFloat(bounceRate.replace('%', ''));
      bounceRate = !isNaN(p) ? `${p.toFixed(1)}%` : bounceRate.trim();
    } else {
      const num = Number(bounceRate);
      if (!isNaN(num)) {
        bounceRate = num <= 1 && num > 0 ? `${(num * 100).toFixed(1)}%` : `${num.toFixed(1)}%`;
      }
    }
  }

  // Duration
  let duration = rawItem.avgVisitDuration;
  if (!duration && rawItem.timeOnSite) {
    duration = formatDurationSeconds(rawItem.timeOnSite);
  }

  // Countries
  const topCountries = [];
  const rawShares = rawItem.topCountryShares || rawItem.topCountries || [];
  if (Array.isArray(rawShares)) {
    rawShares.forEach((c) => {
      topCountries.push({
        countryCode: c.CountryCode || c.countryCode || c.code || 'N/A',
        countryName: c.CountryName || c.countryName || c.CountryCode || 'N/A',
        share: typeof c.Value === 'number' ? c.Value : (typeof c.share === 'number' ? c.share : 0),
      });
    });
  }

  // Traffic Sources
  const rawSources = rawItem.trafficSources || {};
  const trafficSources = {};
  if (typeof rawSources === 'object') {
    Object.entries(rawSources).forEach(([k, v]) => {
      let share = typeof v === 'number' ? v : parseFloat(v) || 0;
      trafficSources[k] = share;
    });
  }

  return {
    ...rawItem,
    domain: rawItem.domain || domain,
    title: rawItem.title || '',
    description: rawItem.description || '',
    category: rawItem.category || '',
    globalRank: rawItem.globalRank || rawItem.rank || null,
    countryRank: rawItem.countryRank || null,
    categoryRank: rawItem.categoryRank || null,
    totalVisits: totalVisits || 'N/A',
    bounceRate: bounceRate || 'N/A',
    pagesPerVisit: rawItem.pagesPerVisit ? Number(rawItem.pagesPerVisit).toFixed(1) : 'N/A',
    avgVisitDuration: duration || 'N/A',
    trafficSources,
    topCountries,
  };
}

/**
 * Fetch domain traffic intelligence:
 * 1. Check Supabase 'domain_traffic' table for cached data.
 * 2. If absent, call Apify Similarweb Scraper (curious_coder~similarweb-scraper with fallback).
 * 3. Cache/Upsert result to Supabase and return to client.
 */
export async function getDomainTraffic(domain, forceFresh = false) {
  const cleanDomain = normalizeDomain(domain);
  if (!cleanDomain) {
    throw new Error('Düzgün domen adı tələb olunur (məs: github.com)');
  }

  // 1. Supabase Cache Check (if not force-refresh)
  if (!forceFresh && supabase) {
    try {
      const { data: cachedRow, error: cacheErr } = await supabase
        .from('domain_traffic')
        .select('*')
        .eq('domain', cleanDomain)
        .maybeSingle();

      if (cachedRow && cachedRow.traffic_data) {
        return {
          success: true,
          cached: true,
          source: 'supabase_cache',
          cachedAt: cachedRow.updated_at || cachedRow.cached_at || cachedRow.created_at,
          domain: cleanDomain,
          data: cachedRow.traffic_data,
        };
      }
    } catch (err) {
      console.warn(`[TrafficService] Supabase cache read warning for ${cleanDomain}:`, err.message);
    }
  }

  // 2. Apify Similarweb Scraper API Call
  const apifyToken = config.APIFY_API_TOKEN || process.env.APIFY_API_TOKEN;
  if (!apifyToken) {
    throw new Error('APIFY_API_TOKEN mühit dəyişənlərində (.env) təyin edilməyib.');
  }

  if (!reserveTrafficCall(cleanDomain, forceFresh)) {
    const error = new Error('Traffic refresh limit reached. Try again later.');
    error.statusCode = 429;
    throw error;
  }

  // Primary: curious_coder~similarweb-scraper, fallback: tri_angle~similarweb-scraper
  const candidateActors = [
    'curious_coder~similarweb-scraper',
    'tri_angle~similarweb-scraper',
  ];

  let scraperItems = [];
  let lastErrorMsg = '';

  for (const actor of candidateActors) {
    try {
      const apifyEndpoint = `https://api.apify.com/v2/acts/${actor}/run-sync-get-dataset-items`;
      const apifyRes = await axios.post(
        apifyEndpoint,
        {
          domains: [cleanDomain],
          limit: 5,
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'SudoDeck-ThreatIntel/2.0',
            Authorization: `Bearer ${apifyToken}`,
          },
          timeout: 90000, // 90s timeout
        }
      );

      scraperItems = Array.isArray(apifyRes.data)
        ? apifyRes.data
        : (apifyRes.data?.items || []);

      if (scraperItems && scraperItems.length > 0) {
        break; // Successfully got data
      }
    } catch (error) {
      lastErrorMsg = error.response?.data?.error?.message || error.response?.data?.message || error.message;
      console.warn(`[TrafficService] Apify actor ${actor} attempt notice:`, lastErrorMsg);
    }
  }

  if (!scraperItems || scraperItems.length === 0) {
    throw new Error(
      lastErrorMsg
        ? `Similarweb kəşfiyyat xətası: ${lastErrorMsg}`
        : `"${cleanDomain}" domeni üçün Similarweb-də ictimai trafik məlumatı tapılmadı.`
    );
  }

  // Find exact domain match or fallback to first record
  const rawResult = scraperItems.find((item) => {
    const itemDomain = (item.domain || item.url || item.target || '').toLowerCase();
    return itemDomain.includes(cleanDomain);
  }) || scraperItems[0];

  // Normalize data for consistent frontend consumption
  const normalizedData = normalizeTrafficPayload(rawResult, cleanDomain);

  // 3. Upsert to Supabase
  let savedToSupabase = false;
  if (supabase) {
    try {
      const now = new Date().toISOString();
      const { error: upsertErr } = await supabase
        .from('domain_traffic')
        .upsert(
          {
            domain: cleanDomain,
            traffic_data: normalizedData,
            cached_at: now,
            updated_at: now,
          },
          { onConflict: 'domain' }
        );

      if (!upsertErr) {
        savedToSupabase = true;
      } else {
        console.warn(`[TrafficService] Supabase upsert note: ${upsertErr.message}`);
      }
    } catch (err) {
      console.warn(`[TrafficService] Supabase upsert exception:`, err.message);
    }
  }

  return {
    success: true,
    cached: false,
    savedToSupabase,
    source: 'apify_similarweb_live',
    fetchedAt: new Date().toISOString(),
    domain: cleanDomain,
    data: normalizedData,
  };
}

export default {
  normalizeDomain,
  getDomainTraffic,
};
