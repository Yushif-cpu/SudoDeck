// @ts-nocheck
'use client';

import React, { useState } from 'react';

export interface TrafficData {
  domain?: string;
  globalRank?: number | string;
  countryRank?: { rank?: number | string; country?: string };
  categoryRank?: { rank?: number | string; category?: string };
  totalVisits?: number | string;
  bounceRate?: string | number;
  pagesPerVisit?: number | string;
  avgVisitDuration?: string | number;
  trafficSources?: {
    direct?: number;
    search?: number;
    social?: number;
    referral?: number;
    mail?: number;
    paid?: number;
  };
  topCountries?: Array<{
    countryCode?: string;
    countryName?: string;
    share?: number;
  }>;
  [key: string]: any;
}

export interface TrafficApiResponse {
  success: boolean;
  cached: boolean;
  source?: string;
  cachedAt?: string;
  fetchedAt?: string;
  domain: string;
  data: TrafficData;
  error?: string;
}

export default function TrafficForm() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [forceFresh, setForceFresh] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<TrafficApiResponse | null>(null);
  const [copied, setCopied] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!clean || loading) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/check-traffic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: clean, forceFresh }),
      });

      const data: TrafficApiResponse = await res.json();
      if (!res.ok || !data.success) {
        const errObj = data?.error;
        let msg = 'Failed to retrieve website traffic data.';
        if (typeof errObj === 'string') {
          msg = errObj;
        } else if (errObj && typeof errObj === 'object') {
          msg = (errObj as any).message || JSON.stringify(errObj);
        }
        throw new Error(msg);
      }

      setResult(data);
    } catch (err: any) {
      setError(err?.message || 'Network communication error occurred.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyJson = () => {
    if (!result) return;
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const tData = result?.data || {};

  return (
    <div className="w-full max-w-5xl mx-auto px-4 py-8">
      {/* Header Banner */}
      <div className="mb-8 text-center sm:text-left flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Web Traffic & Audience Intelligence
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Analyze target domain visitor volume, global rankings, bounce rates, and traffic sources in real time.
          </p>
        </div>
      </div>

      {/* Input Search Form */}
      <div className="bg-surface-850/80 border border-slate-800 rounded-2xl p-4 sm:p-6 shadow-2xl backdrop-blur-sm mb-8">
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
            </div>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="Enter target domain (e.g., github.com, amazon.com, bbc.com)..."
              disabled={loading}
              className="w-full pl-11 pr-4 py-3 bg-surface-900 border border-slate-700/80 rounded-xl text-white placeholder-slate-500 text-sm focus:outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20 font-mono transition-all disabled:opacity-60"
            />
          </div>

          <div className="flex items-center gap-2">
            <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none bg-surface-900 px-3 py-3 border border-slate-800 rounded-xl hover:border-slate-700 transition">
              <input
                type="checkbox"
                checked={forceFresh}
                onChange={(e) => setForceFresh(e.target.checked)}
                className="w-4 h-4 rounded text-emerald-500 focus:ring-0 focus:ring-offset-0 bg-slate-800 border-slate-700 cursor-pointer"
              />
              <span className="whitespace-nowrap">Bypass Cache (Force fresh)</span>
            </label>

            <button
              type="submit"
              disabled={loading || !domain.trim()}
              className="px-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-surface-900 font-bold text-sm rounded-xl transition-all shadow-lg shadow-emerald-500/20 flex items-center justify-center gap-2 shrink-0 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-surface-900" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                  </svg>
                  <span>Analyze Traffic</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Quick Example Tags */}
        <div className="mt-3 flex items-center gap-2 flex-wrap text-xs text-slate-500">
          <span>Examples:</span>
          {['github.com', 'openai.com', 'cloudflare.com', 'hackerone.com'].map((ex) => (
            <button
              key={ex}
              type="button"
              onClick={() => setDomain(ex)}
              className="px-2 py-0.5 rounded bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-emerald-400 font-mono transition"
            >
              {ex}
            </button>
          ))}
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-4 mb-8 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm flex items-start gap-3 animate-fade-in">
          <svg className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="flex-1">
            <span className="font-bold">Error:</span> {error}
          </div>
        </div>
      )}

      {/* Result Display */}
      {result && result.success && (
        <div className="space-y-6 animate-fade-in">
          {/* Status & Cache Banner */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-surface-850 border border-slate-800">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold font-mono">
                {result.domain.charAt(0).toUpperCase()}
              </div>
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span>{result.domain}</span>
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  {result.cachedAt ? `Cached at: ${new Date(result.cachedAt).toLocaleString()}` : `Queried: ${new Date().toLocaleTimeString()}`}
                </p>
              </div>
            </div>

            <button
              onClick={handleCopyJson}
              className="px-3 py-1.5 rounded-lg bg-surface-800 hover:bg-surface-700 text-slate-300 text-xs font-mono flex items-center gap-1.5 border border-slate-700 transition"
            >
              {copied ? 'Copied!' : 'Copy JSON'}
            </button>
          </div>

          {/* Metric Cards Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-surface-850 border border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Global Rank</div>
              <div className="text-xl sm:text-2xl font-black text-white font-mono mt-1">
                {tData.globalRank ? `#${Number(tData.globalRank).toLocaleString()}` : (tData.rank || 'N/A')}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">Similarweb Global Rank</div>
            </div>

            <div className="p-4 rounded-xl bg-surface-850 border border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Monthly Visits</div>
              <div className="text-xl sm:text-2xl font-black text-emerald-400 font-mono mt-1">
                {tData.totalVisits || tData.visits || tData.estimatedMonthlyVisits || 'N/A'}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">Estimated Monthly Traffic</div>
            </div>

            <div className="p-4 rounded-xl bg-surface-850 border border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Bounce Rate</div>
              <div className="text-xl sm:text-2xl font-black text-amber-400 font-mono mt-1">
                {tData.bounceRate ? (
                  (() => {
                    const b = tData.bounceRate;
                    if (typeof b === 'string' && b.includes('%')) {
                      const p = parseFloat(b.replace('%', ''));
                      return !isNaN(p) ? `${p.toFixed(1)}%` : b;
                    }
                    const num = Number(b);
                    if (!isNaN(num)) {
                      return num <= 1 && num > 0 ? `${(num * 100).toFixed(1)}%` : `${num.toFixed(1)}%`;
                    }
                    return String(b);
                  })()
                ) : 'N/A'}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">Single-page exit percentage</div>
            </div>

            <div className="p-4 rounded-xl bg-surface-850 border border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Avg. Duration</div>
              <div className="text-xl sm:text-2xl font-black text-cyan-400 font-mono mt-1">
                {tData.avgVisitDuration || tData.timeOnSite || 'N/A'}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">Avg. Session Duration</div>
            </div>
          </div>

          {/* Details & Raw Inspector */}
          <div className="p-5 rounded-2xl bg-surface-850 border border-slate-800">
            <h4 className="text-sm font-bold text-white mb-3 font-mono flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
              RAW TELEMETRY & TRAFFIC DETAILS
            </h4>
            <div className="overflow-x-auto">
              <pre className="p-4 rounded-xl bg-surface-900 border border-slate-800/80 text-xs font-mono text-slate-300 max-h-96 overflow-y-auto custom-scroll">
                {JSON.stringify(tData, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
