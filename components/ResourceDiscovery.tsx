// @ts-nocheck
'use client';

import React, { useState } from 'react';

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

export default function ResourceDiscovery() {
  const [domain, setDomain] = useState('');
  const [filterQuery, setFilterQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DiscoveryResponse | null>(null);
  const [copiedItem, setCopiedItem] = useState<string | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim() || loading) return;

    setLoading(true);
    setError(null);
    setFilterQuery('');

    try {
      const res = await fetch('/api/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'An error occurred during subdomain discovery');
      }

      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Network communication error occurred.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, isAll: boolean = false) => {
    navigator.clipboard.writeText(text);
    if (isAll) {
      setCopiedAll(true);
      setTimeout(() => setCopiedAll(false), 2000);
    } else {
      setCopiedItem(text);
      setTimeout(() => setCopiedItem(null), 1800);
    }
  };

  const filteredSubdomains = (result?.subdomains || []).filter((item) =>
    item.subdomain.toLowerCase().includes(filterQuery.toLowerCase()) ||
    (item.ip && item.ip.includes(filterQuery))
  );

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* SudoDeck Attack Utilities Hero Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900/90 via-slate-900/80 to-slate-950/90 border border-amber-500/30 p-6 md:p-8 shadow-2xl backdrop-blur-xl">
        <div className="absolute -top-16 -right-16 w-48 h-48 bg-amber-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl md:text-3xl font-black tracking-tight text-white flex items-center gap-3">
              Subdomain & Resource Finder
            </h1>
            <p className="text-slate-400 text-xs md:text-sm mt-1 max-w-2xl leading-relaxed">
              Passive asset reconnaissance and attack surface enumeration powered by Certificate Transparency (crt.sh) logs and HackerTarget DNS host search.
            </p>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSearch} className="mt-6 flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500 font-mono text-xs">
              TARGET://
            </div>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="e.g., tesla.com or github.com"
              disabled={loading}
              className="w-full pl-24 pr-4 py-3.5 rounded-xl bg-slate-950/90 border border-slate-700/80 hover:border-slate-600 focus:border-amber-400/80 focus:ring-2 focus:ring-amber-400/20 text-white font-mono text-sm placeholder:text-slate-600 transition-all outline-none"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold text-sm tracking-wide transition-all shadow-lg shadow-amber-500/20 hover:shadow-amber-500/40 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shrink-0 cursor-pointer"
          >
            {loading ? (
              <>
                <svg className="animate-spin h-4 w-4 text-slate-950" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                <span>Discovering...</span>
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <span>Launch Discovery</span>
              </>
            )}
          </button>
        </form>

        {error && (
          <div className="mt-4 p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-rose-500" />
            <span>[ERROR]: {error}</span>
          </div>
        )}
      </div>

      {/* Terminal View */}
      {result && (
        <div className="rounded-2xl bg-[#090d16] border border-slate-800 shadow-2xl overflow-hidden font-mono">
          <div className="bg-[#0e1424] px-4 py-3 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
                <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
                <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
              </div>
              <span className="text-xs text-slate-400 font-bold ml-2">
                RECON_TERMINAL // {result.target}
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 font-bold">
                {result.total} SUBDOMAINS
              </span>
              <span className="text-[10px] text-slate-500 hidden sm:inline">
                ({result.durationMs}ms)
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => copyToClipboard(result.subdomains.map((s) => s.subdomain).join('\n'), true)}
                className="px-2.5 py-1 text-[11px] rounded-lg bg-slate-800/90 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {copiedAll ? '✓ Copied All!' : 'Copy All Subdomains'}
              </button>
            </div>
          </div>

          <div className="bg-[#0c1220]/90 px-4 py-2.5 border-b border-slate-800/60 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-3 text-[11px]">
              <span className="text-slate-400 flex items-center gap-1">
                crt.sh:
                <strong className={result.sourcesStatus.crtSh.success ? 'text-emerald-400' : 'text-rose-400'}>
                  {result.sourcesStatus.crtSh.success ? `${result.sourcesStatus.crtSh.count} found` : 'Failed'}
                </strong>
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-slate-400 flex items-center gap-1">
                HackerTarget:
                <strong className={result.sourcesStatus.hackerTarget.success ? 'text-emerald-400' : 'text-rose-400'}>
                  {result.sourcesStatus.hackerTarget.success ? `${result.sourcesStatus.hackerTarget.count} found` : 'Failed'}
                </strong>
              </span>
            </div>

            <div className="w-full sm:w-56">
              <input
                type="text"
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                placeholder="Filter subdomains (e.g., api, vpn)..."
                className="w-full px-2.5 py-1 text-xs rounded-md bg-slate-900 border border-slate-700 text-slate-200 focus:border-amber-400 outline-none"
              />
            </div>
          </div>

          <div className="p-3 max-h-[460px] overflow-y-auto divide-y divide-slate-800/40 custom-scroll">
            {filteredSubdomains.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                No subdomains matching your filter criteria.
              </div>
            ) : (
              filteredSubdomains.map((item, idx) => (
                <div
                  key={idx}
                  className="py-2.5 px-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-lg hover:bg-slate-800/40 transition-colors group"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="text-slate-600 text-[10px] select-none w-6 text-right">
                      {idx + 1}.
                    </span>
                    <a
                      href={`https://${item.subdomain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-amber-300/90 group-hover:text-amber-200 font-semibold truncate hover:underline"
                    >
                      {item.subdomain}
                    </a>
                    {item.ip && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shrink-0">
                        {item.ip}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
                    {item.sources.map((src) => (
                      <span
                        key={src}
                        className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider border ${
                          src === 'crt.sh'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            : 'bg-purple-500/10 text-purple-400 border-purple-500/20'
                        }`}
                      >
                        {src}
                      </span>
                    ))}

                    <button
                      onClick={() => copyToClipboard(item.subdomain)}
                      title="Copy subdomain"
                      className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors opacity-70 group-hover:opacity-100 cursor-pointer text-[10px]"
                    >
                      {copiedItem === item.subdomain ? '✓' : 'Copy'}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="bg-[#0a0f1d] px-4 py-2 border-t border-slate-800/80 text-[11px] text-slate-500 flex items-center justify-between">
            <span>SudoDeck Passive Recon Engine v2.0</span>
            <span>Showing: {filteredSubdomains.length} / {result.total}</span>
          </div>
        </div>
      )}
    </div>
  );
}
