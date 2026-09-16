// @ts-nocheck
import { NextRequest, NextResponse } from 'next/server';

export interface SubdomainItem {
  subdomain: string;
  ip?: string;
  sources: ('crt.sh' | 'HackerTarget')[];
}

export interface DiscoveryResponse {
  target: string;
  total: number;
  durationMs: number;
  subdomains: SubdomainItem[];
  sourcesStatus: {
    crtSh: { success: boolean; count: number; error?: string };
    hackerTarget: { success: boolean; count: number; error?: string };
  };
}

// Domain sanitization and regex validation
function sanitizeDomain(input: string): string | null {
  if (!input || typeof input !== 'string') return null;

  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^[a-zA-Z]+:\/\//, '');
  domain = domain.split('/')[0].split('?')[0].split('#')[0].split(':')[0].trim();
  domain = domain.replace(/^\*\./, '');

  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain) ? domain : null;
}

export async function POST(req: NextRequest) {
  const startTime = Date.now();

  try {
    const body = await req.json().catch(() => null);
    if (!body || !body.domain) {
      return NextResponse.json(
        { error: 'Target domain is required. Please provide a valid domain name.' },
        { status: 400 }
      );
    }

    const domain = sanitizeDomain(body.domain);
    if (!domain) {
      return NextResponse.json(
        { error: 'Invalid domain format. Example: target.com or security-intel.org' },
        { status: 400 }
      );
    }

    const subdomainsMap = new Map<string, { ip?: string; sources: Set<'crt.sh' | 'HackerTarget'> }>();

    // 1. Source: crt.sh (Certificate Transparency Log)
    const fetchCrtSh = async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);

      try {
        const response = await fetch(
          `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`,
          {
            signal: controller.signal,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SudoDeck-Recon/2.0',
              'Accept': 'application/json',
            },
            next: { revalidate: 0 },
          }
        );

        if (!response.ok) {
          throw new Error(`crt.sh responded with HTTP ${response.status}`);
        }

        const data: Array<{ name_value?: string }> = await response.json();
        let addedCount = 0;

        if (Array.isArray(data)) {
          for (const entry of data) {
            if (!entry.name_value) continue;

            const names = entry.name_value.split('\n');
            for (let name of names) {
              name = name.trim().toLowerCase();
              name = name.replace(/^\*\./, '');

              if (name === domain || name.endsWith(`.${domain}`)) {
                if (!subdomainsMap.has(name)) {
                  subdomainsMap.set(name, { sources: new Set(['crt.sh']) });
                } else {
                  subdomainsMap.get(name)!.sources.add('crt.sh');
                }
                addedCount++;
              }
            }
          }
        }

        return { success: true, count: addedCount };
      } catch (err: any) {
        const isAbort = err.name === 'AbortError';
        return {
          success: false,
          count: 0,
          error: isAbort ? 'crt.sh request timed out' : (err.message || 'crt.sh error'),
        };
      } finally {
        clearTimeout(timeoutId);
      }
    };

    // 2. Source: HackerTarget Host Search API
    const fetchHackerTarget = async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 9000);

      try {
        const response = await fetch(
          `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
          {
            signal: controller.signal,
            headers: {
              'User-Agent': 'SudoDeck-Recon/2.0',
            },
            next: { revalidate: 0 },
          }
        );

        if (!response.ok) {
          throw new Error(`HackerTarget responded with HTTP ${response.status}`);
        }

        const rawText = await response.text();
        let addedCount = 0;

        if (
          rawText.includes('API count exceeded') ||
          rawText.includes('error check your search parameter') ||
          rawText.includes('No records')
        ) {
          return {
            success: false,
            count: 0,
            error: rawText.split('\n')[0].trim() || 'HackerTarget rate limit or search parameter issue',
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
              if (!subdomainsMap.has(host)) {
                subdomainsMap.set(host, { ip, sources: new Set(['HackerTarget']) });
              } else {
                const item = subdomainsMap.get(host)!;
                item.sources.add('HackerTarget');
                if (!item.ip && ip) item.ip = ip;
              }
              addedCount++;
            }
          }
        }

        return { success: true, count: addedCount };
      } catch (err: any) {
        const isAbort = err.name === 'AbortError';
        return {
          success: false,
          count: 0,
          error: isAbort ? 'HackerTarget request timed out' : (err.message || 'HackerTarget error'),
        };
      } finally {
        clearTimeout(timeoutId);
      }
    };

    const [crtResult, htResult] = await Promise.all([fetchCrtSh(), fetchHackerTarget()]);

    if (!crtResult.success && !htResult.success) {
      return NextResponse.json(
        {
          error: 'External reconnaissance sources failed.',
          details: { crtSh: crtResult.error, hackerTarget: htResult.error },
        },
        { status: 502 }
      );
    }

    const subdomains: SubdomainItem[] = Array.from(subdomainsMap.entries())
      .map(([subdomain, details]) => ({
        subdomain,
        ip: details.ip,
        sources: Array.from(details.sources),
      }))
      .sort((a, b) => a.subdomain.localeCompare(b.subdomain));

    const responsePayload: DiscoveryResponse = {
      target: domain,
      total: subdomains.length,
      durationMs: Date.now() - startTime,
      subdomains,
      sourcesStatus: {
        crtSh: crtResult,
        hackerTarget: htResult,
      },
    };

    return NextResponse.json(responsePayload, { status: 200 });
  } catch (error: any) {
    return NextResponse.json(
      { error: 'Internal server error.', details: error.message },
      { status: 500 }
    );
  }
}
