// @ts-nocheck
'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { payloadsData, csrfPayloadsData, commandPayloadsData, PayloadItem } from './payloadsData';

export { payloadsData, csrfPayloadsData, commandPayloadsData, type PayloadItem };

export interface SecurityPayload {
  id: string | number;
  category: 'XSS' | 'SQLi' | 'Traversal' | 'CSRF' | 'Command';
  title?: string;
  payload?: string;
  value?: string;
  description?: string;
  source?: string;
}

export default function PayloadManager() {
  const [payloads, setPayloads] = useState<SecurityPayload[]>(payloadsData);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | number | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadPayloads() {
      try {
        const res = await fetch('/api/payloads');
        if (!res.ok) return;
        const json = await res.json();
        if (json.payloads && json.payloads.length > 0) {
          setPayloads(json.payloads);
        }
      } catch (err: any) {
        // Silently retain preloaded payloadsData on fetch failure
      }
    }
    loadPayloads();
  }, []);

  const filteredPayloads = useMemo(() => {
    return payloads.filter((item) => {
      const matchesCategory =
        selectedCategory === 'all' ||
        item.category.toLowerCase() === selectedCategory.toLowerCase();

      const q = searchQuery.toLowerCase().trim();
      const val = (item.value || item.payload || '').toLowerCase();
      const title = (item.title || `${item.category} Vector #${item.id}`).toLowerCase();
      const desc = (item.description || '').toLowerCase();
      const cat = (item.category || '').toLowerCase();

      const matchesSearch =
        !q ||
        val.includes(q) ||
        title.includes(q) ||
        desc.includes(q) ||
        cat.includes(q);

      return matchesCategory && matchesSearch;
    });
  }, [payloads, selectedCategory, searchQuery]);

  const handleCopy = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1800);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1800);
    }
  };

  const categoryCounts = useMemo(() => {
    return {
      all: payloads.length,
      xss: payloads.filter((p) => p.category === 'XSS').length,
      sqli: payloads.filter((p) => p.category === 'SQLi').length,
      traversal: payloads.filter((p) => p.category === 'Traversal').length,
      csrf: payloads.filter((p) => p.category === 'CSRF').length,
      command: payloads.filter((p) => p.category === 'Command').length,
    };
  }, [payloads]);

  return (
    <div className="w-full max-w-6xl mx-auto px-4 py-8 font-sans text-slate-100">
      {/* Top Breadcrumb */}
      <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-6">
        <a href="/" className="text-slate-400 hover:text-emerald-400 transition-colors flex items-center gap-1">
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          <span>Hub</span>
        </a>
        <span className="text-slate-600">/</span>
        <span className="text-amber-400 font-semibold uppercase tracking-wider">SECURITY PAYLOAD MANAGER</span>
      </div>

      {/* Header Banner */}
      <div className="mb-8 border-b border-slate-800/80 pb-6">
        <div className="flex items-center gap-2 text-xs font-mono text-amber-400 mb-2 tracking-wider uppercase">
          <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
          ATTACK UTILITIES // SECURITY PAYLOAD MANAGER
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
          <span>Payload Catalogue & Testing Suite</span>
        </h1>
        <p className="text-sm text-slate-400 mt-2 max-w-3xl leading-relaxed">
          Curated defensive injection test vectors, directory traversal probes, and input validation test strings for security auditing and sanitization benchmarking.
        </p>
      </div>

      {/* Controls Bar: Category Tabs & Search */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 mb-6">
        {/* Category Filter Tabs */}
        <div className="flex items-center gap-1.5 p-1 bg-surface-900 border border-slate-800 rounded-xl overflow-x-auto">
          <button
            type="button"
            onClick={() => setSelectedCategory('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              selectedCategory === 'all'
                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                : 'text-slate-400 hover:text-white hover:bg-surface-800'
            }`}
          >
            All Vectors ({categoryCounts.all})
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('xss')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              selectedCategory === 'xss'
                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                : 'text-slate-400 hover:text-white hover:bg-surface-800'
            }`}
          >
            XSS ({categoryCounts.xss})
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('sqli')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              selectedCategory === 'sqli'
                ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40'
                : 'text-slate-400 hover:text-white hover:bg-surface-800'
            }`}
          >
            SQL Injection ({categoryCounts.sqli})
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('traversal')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              selectedCategory === 'traversal'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                : 'text-slate-400 hover:text-white hover:bg-surface-800'
            }`}
          >
            Traversal ({categoryCounts.traversal})
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('csrf')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              selectedCategory === 'csrf'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white hover:bg-surface-800'
            }`}
          >
            CSRF ({categoryCounts.csrf})
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('command')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
              selectedCategory === 'command'
                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                : 'text-slate-400 hover:text-white hover:bg-surface-800'
            }`}
          >
            Command Injection ({categoryCounts.command})
          </button>
        </div>

        {/* Live Search Input */}
        <div className="relative min-w-[260px] sm:w-80">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search payload, title or tag..."
            className="w-full pl-9 pr-4 py-2 bg-surface-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500/60 transition-colors font-mono"
          />
          <span className="absolute left-3 top-2.5 text-slate-500 text-xs">🔍</span>
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-2 text-slate-400 hover:text-white text-xs"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* Terminal-Styled Payload List Container */}
      <div className="rounded-2xl border border-slate-800/80 bg-[#070b14] shadow-2xl overflow-hidden">
        {/* Terminal Header */}
        <div className="px-5 py-3.5 bg-surface-900/90 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-rose-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
            <span className="ml-3 text-xs font-mono text-slate-400">
              PAYLOAD_CATALOGUE // {selectedCategory.toUpperCase()} ({filteredPayloads.length} items)
            </span>
          </div>
          <div className="text-[11px] font-mono text-slate-500 hidden sm:block">
            UTF-8 // SEC_AUDIT_ENABLED
          </div>
        </div>

        {/* Terminal Body with Scrollable List */}
        <div className="p-4 max-h-[620px] overflow-y-auto space-y-3 font-mono">
          {loading ? (
            <div className="py-16 text-center text-slate-500 text-xs">
              <span className="inline-block w-4 h-4 border-2 border-amber-500 border-t-transparent rounded-full animate-spin mr-2"></span>
              Synchronizing test vectors from live repositories...
            </div>
          ) : error ? (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
              Error: {error}
            </div>
          ) : filteredPayloads.length === 0 ? (
            <div className="py-16 text-center text-slate-500 text-xs">
              No matching payloads found for "{searchQuery || selectedCategory}".
            </div>
          ) : (
            filteredPayloads.map((item) => {
              const isCopied = copiedId === item.id;
              const isXss = item.category === 'XSS';
              const isSqli = item.category === 'SQLi';
              const isTrav = item.category === 'Traversal';
              const isCmd = item.category === 'Command';

              const badgeColor = isXss
                ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                : isSqli
                ? 'bg-purple-500/20 text-purple-400 border-purple-500/40'
                : isTrav
                ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                : isCmd
                ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40';

              const payloadText = item.value || item.payload || '';
              const payloadTitle = item.title || `${item.category} Test Vector #${item.id}`;
              const payloadSource = item.source || 'SecLists / PayloadAllTheThings';

              return (
                <div
                  key={item.id}
                  className="group relative p-4 rounded-xl bg-surface-900/60 border border-slate-800/80 hover:border-amber-500/40 hover:bg-surface-850/80 transition-all"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider border ${badgeColor}`}>
                        {item.category}
                      </span>
                      <span className="text-xs font-semibold text-slate-200">
                        {payloadTitle}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-slate-500 px-1.5 py-0.5 rounded bg-surface-800">
                        {payloadSource}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy(item.id, payloadText)}
                        className={`text-xs px-2.5 py-1 rounded-lg font-mono transition-all flex items-center gap-1.5 ${
                          isCopied
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'bg-surface-800 text-slate-300 border border-slate-700 hover:text-amber-400 hover:border-amber-500/40'
                        }`}
                      >
                        {isCopied ? '✓ Copied' : '📋 Copy'}
                      </button>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-surface-950 border border-slate-900/80 text-xs text-amber-300 font-mono break-all selection:bg-amber-500/30">
                    {payloadText}
                  </div>

                  {item.description && (
                    <p className="text-[11px] text-slate-400 mt-2 font-sans leading-relaxed">
                      {item.description}
                    </p>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Terminal Footer */}
        <div className="px-5 py-3 bg-surface-900/90 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between font-mono">
          <span>Displaying {filteredPayloads.length} of {payloads.length} total test vectors</span>
          <span className="text-slate-400">Press Copy to grab raw string</span>
        </div>
      </div>
    </div>
  );
}
