// @ts-nocheck
import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { reserveTrafficCall } from '../../../services/traffic-budget.js';

// Environment variables
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || '';
const supabaseKey =
  process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
  process.env.SUPABASE_KEY ||
  '';
const apifyToken = process.env.APIFY_API_TOKEN || '';

// Initialize Supabase Client
const supabase = (supabaseUrl && supabaseKey)
  ? createClient(supabaseUrl, supabaseKey)
  : null;

// Domain sanitization and cleaning
function sanitizeDomain(input: string): string | null {
  if (!input || typeof input !== 'string') return null;

  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^[a-zA-Z]+:\/\//, ''); // strip http/https
  domain = domain.split('/')[0].split('?')[0].split('#')[0].split(':')[0].trim();
  domain = domain.replace(/^\*\./, ''); // strip wildcard

  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain) ? domain : null;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => null);
    const rawDomain = body?.domain || body?.target;
    const forceFresh = Boolean(body?.forceFresh || body?.refresh);

    if (!rawDomain) {
      return NextResponse.json(
        { success: false, error: 'Target domain is required (e.g., google.com).' },
        { status: 400 }
      );
    }

    const domain = sanitizeDomain(rawDomain);
    if (!domain) {
      return NextResponse.json(
        { success: false, error: 'Please enter a valid domain format (e.g., example.com).' },
        { status: 400 }
      );
    }

    // 1. Supabase Cache Check
    if (!forceFresh && supabase) {
      try {
        const { data: cachedRow, error: cacheErr } = await supabase
          .from('domain_traffic')
          .select('*')
          .eq('domain', domain)
          .maybeSingle();

        if (cachedRow && cachedRow.traffic_data) {
          return NextResponse.json({
            success: true,
            cached: true,
            source: 'supabase_cache',
            cachedAt: cachedRow.updated_at || cachedRow.cached_at,
            domain,
            data: cachedRow.traffic_data,
          });
        }
      } catch (err) {
        console.warn(`[API /check-traffic] Supabase cache read notice:`, err);
      }
    }

    // 2. Apify Similarweb Scraper API Request
    if (!apifyToken) {
      return NextResponse.json(
        { success: false, error: 'APIFY_API_TOKEN is not configured in .env' },
        { status: 500 }
      );
    }

    if (!reserveTrafficCall(domain, forceFresh)) {
      return NextResponse.json({ success: false, error: 'Traffic refresh limit reached. Try again later.' }, { status: 429 });
    }

    const apifyUrl = 'https://api.apify.com/v2/acts/curious_coder~similarweb-scraper/run-sync-get-dataset-items';

    const apifyResponse = await fetch(apifyUrl, {
      method: 'POST',
      signal: AbortSignal.timeout(90000),
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apifyToken}`,
      },
      body: JSON.stringify({
        domains: [domain],
        limit: 10,
      }),
    });

    if (!apifyResponse.ok) {
      return NextResponse.json(
        {
          success: false,
          error: 'Traffic provider is temporarily unavailable.',
        },
        { status: 502 }
      );
    }

    const rawData = await apifyResponse.json();
    const items = Array.isArray(rawData) ? rawData : (rawData?.items || []);

    if (!items || items.length === 0) {
      return NextResponse.json(
        {
          success: false,
          error: `No public Similarweb traffic records found for "${domain}".`,
        },
        { status: 404 }
      );
    }

    // Select domain match or first item
    const trafficResult =
      items.find((item) => {
        const itemDomain = (item.domain || item.url || item.target || '').toLowerCase();
        return itemDomain.includes(domain);
      }) || items[0];

    // 3. Upsert to Supabase
    let savedToSupabase = false;
    if (supabase) {
      try {
        const now = new Date().toISOString();
        const { error: upsertErr } = await supabase
          .from('domain_traffic')
          .upsert(
            {
              domain,
              traffic_data: trafficResult,
              cached_at: now,
              updated_at: now,
            },
            { onConflict: 'domain' }
          );

        if (!upsertErr) {
          savedToSupabase = true;
        } else {
          console.warn(`[API /check-traffic] Supabase upsert notice:`, upsertErr.message);
        }
      } catch (err) {
        console.warn(`[API /check-traffic] Supabase connection notice:`, err);
      }
    }

    return NextResponse.json({
      success: true,
      cached: false,
      savedToSupabase,
      source: 'apify_similarweb_live',
      fetchedAt: new Date().toISOString(),
      domain,
      data: trafficResult,
    });
  } catch (error: any) {
    console.error('[API /check-traffic Error]:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Internal server error occurred.',
      },
      { status: 500 }
    );
  }
}
