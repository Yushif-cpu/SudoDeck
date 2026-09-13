// ═══════════════════════════════════════════════════════════════
//  ThreatIntel — Dedicated NVD CVE Scanner Frontend Application
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initCveSearch();
  initQuickPills();
  checkUrlParams();
});

// ── Toast Notifications ─────────────────────────────────────────
function showToast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icons = {
    success: 'check-circle-2',
    error: 'alert-circle',
    warning: 'alert-triangle',
    info: 'info',
  };

  toast.innerHTML = `
    <i data-lucide="${icons[type] || 'info'}" class="w-5 h-5 flex-shrink-0"></i>
    <span class="text-sm font-medium flex-1">${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);
  lucide.createIcons({ nodes: [toast] });

  setTimeout(() => {
    toast.style.animation = 'slideOutRight 0.3s ease-out forwards';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Copy to Clipboard ───────────────────────────────────────────
window.copyToClipboard = function(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.innerHTML;
    btn.classList.add('copied');
    btn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5"></i> Copied`;
    lucide.createIcons({ nodes: [btn] });
    showToast('Copied to clipboard', 'success', 2000);
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = original;
      lucide.createIcons({ nodes: [btn] });
    }, 2000);
  });
};

function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(str || '').replace(/[&<>"']/g, (m) => map[m]);
}

function formatDate(isoStr) {
  if (!isoStr) return 'N/A';
  const d = new Date(isoStr);
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

// ── Skeleton Loader ─────────────────────────────────────────────
function showSkeleton(container) {
  container.innerHTML = `
    <div class="card p-6 animate-fade-in space-y-6">
      <div class="flex items-center justify-between">
        <div class="space-y-2">
          <div class="skeleton h-7 w-64 rounded-lg"></div>
          <div class="skeleton h-4 w-40 rounded"></div>
        </div>
        <div class="skeleton h-10 w-28 rounded-xl"></div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="skeleton h-32 rounded-xl"></div>
        <div class="skeleton h-32 rounded-xl md:col-span-2"></div>
      </div>
      <div class="skeleton h-24 rounded-xl"></div>
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div class="skeleton h-16 rounded-lg"></div>
        <div class="skeleton h-16 rounded-lg"></div>
        <div class="skeleton h-16 rounded-lg"></div>
        <div class="skeleton h-16 rounded-lg"></div>
      </div>
    </div>
  `;
}

// ── Search & API Request ────────────────────────────────────────
let isSearching = false;

async function performCveSearch(rawCveId) {
  const cveId = (rawCveId || '').trim();
  if (!cveId) return;

  const form = document.getElementById('cve-search-form');
  const input = document.getElementById('cve-input');
  const submitBtn = document.getElementById('cve-submit-btn');
  const resultsContainer = document.getElementById('cve-results');
  const pills = document.querySelectorAll('.quick-cve-pill');

  if (input) input.value = cveId;

  // Visual active indication on pills
  pills.forEach((p) => {
    const pCve = (p.getAttribute('data-cve') || p.dataset.cve || '').toUpperCase();
    const isMatch = pCve === cveId.toUpperCase();
    p.classList.toggle('!border-rose-500', isMatch);
    p.classList.toggle('!bg-rose-500/20', isMatch);
    p.classList.toggle('shadow-lg', isMatch);
  });

  if (isSearching) return;
  isSearching = true;

  const originalBtn = submitBtn ? submitBtn.innerHTML : '';
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<div class="spinner"></div><span>Scanning NVD...</span>`;
  }

  showSkeleton(resultsContainer);

  try {
    const res = await fetch('/api/check-cve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cveId }),
    });

    const data = await res.json();

    if (!res.ok || !data.success) {
      const errMsg = data.error?.message || data.error || `NVD query failed (${res.status})`;
      throw new Error(errMsg);
    }

    if (window.ThreatIntelHistory) {
      window.ThreatIntelHistory.add('cve', data.data.cveId || cveId);
      if (typeof window.renderRecentCves === 'function') window.renderRecentCves();
    }

    renderCveResult(data.data);

    // Update browser URL without reload for direct sharing
    try {
      const newUrl = `${window.location.pathname}?id=${encodeURIComponent(data.data.cveId)}`;
      window.history.pushState({ cve: data.data.cveId }, '', newUrl);
    } catch (_) {}

  } catch (err) {
    resultsContainer.innerHTML = `
      <div class="card p-8 border-rose-500/40 bg-rose-500/5 animate-fade-in text-center max-w-2xl mx-auto">
        <div class="w-14 h-14 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center mx-auto mb-4">
          <i data-lucide="alert-triangle" class="w-7 h-7 text-rose-400"></i>
        </div>
        <h3 class="text-base font-bold text-rose-300">Vulnerability Investigation Failed</h3>
        <p class="text-xs text-slate-300 mt-2 leading-relaxed">${escapeHtml(err.message)}</p>
        <div class="mt-5 flex items-center justify-center gap-2">
          <button type="button" class="btn-secondary !text-xs !py-1.5 !px-4" onclick="document.getElementById('cve-input').focus()">
            Modify Identifier
          </button>
          <button type="button" class="btn-primary !text-xs !py-1.5 !px-4 !bg-rose-600 hover:!bg-rose-500" onclick="performCveSearch('${escapeHtml(cveId)}')">
            <i data-lucide="rotate-cw" class="w-3.5 h-3.5"></i> Retry
          </button>
        </div>
      </div>
    `;
    try {
      lucide.createIcons({ nodes: [resultsContainer] });
    } catch (_) {}
  } finally {
    isSearching = false;
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtn || `<i data-lucide="radar" class="w-4 h-4"></i><span>Inspect CVE</span>`;
      try {
        lucide.createIcons({ nodes: [submitBtn] });
      } catch (_) {}
    }
  }
}

window.performCveSearch = performCveSearch;

function initCveSearch() {
  const form = document.getElementById('cve-search-form');
  const input = document.getElementById('cve-input');
  const clearBtn = document.getElementById('btn-clear-cve');
  const recentContainer = document.getElementById('recent-cves-container');
  const recentList = document.getElementById('recent-cves-list');
  const clearHistoryBtn = document.getElementById('btn-clear-cve-history');

  window.renderRecentCves = function() {
    if (!recentContainer || !recentList || !window.ThreatIntelHistory) return;
    const history = window.ThreatIntelHistory.get('cve', 6);
    if (history.length === 0) {
      recentContainer.classList.add('hidden');
      recentList.innerHTML = '';
      return;
    }
    recentContainer.classList.remove('hidden');
    recentList.innerHTML = history.map(item => `
      <button type="button" class="recent-chip" data-cve="${escapeHtml(item)}">
        <i data-lucide="history" class="w-3 h-3 text-slate-500"></i>
        <span>${escapeHtml(item)}</span>
      </button>
    `).join('');
    if (window.lucide) lucide.createIcons({ nodes: [recentList] });

    recentList.querySelectorAll('.recent-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        performCveSearch(btn.dataset.cve);
      });
    });
  };

  window.renderRecentCves();

  if (input && clearBtn) {
    input.addEventListener('input', () => {
      if (input.value.trim().length > 0) {
        clearBtn.classList.remove('hidden');
      } else {
        clearBtn.classList.add('hidden');
      }
    });

    clearBtn.addEventListener('click', () => {
      input.value = '';
      clearBtn.classList.add('hidden');
      input.focus();
    });
  }

  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
      if (window.ThreatIntelHistory) {
        window.ThreatIntelHistory.clear('cve');
        window.renderRecentCves();
        showToast('Recent CVE history cleared', 'info');
      }
    });
  }

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const cveId = input ? input.value.trim() : '';
      if (cveId) {
        performCveSearch(cveId);
      }
    });
  }
}

function initQuickPills() {
  const pills = document.querySelectorAll('.quick-cve-pill');
  pills.forEach((pill) => {
    pill.addEventListener('click', (e) => {
      e.preventDefault();
      const cve = pill.getAttribute('data-cve') || pill.dataset.cve;
      if (cve) {
        performCveSearch(cve.trim());
      }
    });
  });
}

function checkUrlParams() {
  const params = new URLSearchParams(window.location.search);
  const cveParam = params.get('id') || params.get('cve') || params.get('cveId') || params.get('q');
  if (cveParam) {
    performCveSearch(cveParam.trim());
  }
}

window.addEventListener('popstate', (e) => {
  if (e.state && e.state.cve) {
    performCveSearch(e.state.cve);
  }
});

// ── Render Vulnerability Result ─────────────────────────────────
function renderCveResult(data) {
  if (!data) return;
  const container = document.getElementById('cve-results');
  if (!container) return;

  const cvss = data.cvss || {};
  const severity = data.severity || {
    level: 'UNKNOWN',
    color: '#94a3b8',
    bg: 'rgba(148, 163, 184, 0.1)',
    border: 'rgba(148, 163, 184, 0.3)',
  };
  const score = (cvss.baseScore !== undefined && cvss.baseScore !== null)
    ? Number(cvss.baseScore).toFixed(1)
    : 'N/A';

  // Metrics helper
  const getMetricBadge = (val, highIsDangerous = true) => {
    if (!val || val === 'N/A') return `<span class="text-slate-500 text-xs font-mono">N/A</span>`;
    const v = String(val).toUpperCase();
    let isCrit = v === 'HIGH' || v === 'NETWORK' || v === 'CHANGED' || v === 'NONE';
    if (!highIsDangerous) isCrit = !isCrit;
    return `<span class="font-mono text-xs font-bold ${isCrit ? 'text-rose-400' : 'text-slate-300'}">${escapeHtml(val)}</span>`;
  };

  const weaknesses = Array.isArray(data.weaknesses) ? data.weaknesses : [];
  const references = Array.isArray(data.references) ? data.references : [];

  container.innerHTML = `
    <!-- Top Header Banner -->
    <div class="card p-6 animate-fade-in border-slate-700/80 bg-gradient-to-r from-surface-800 via-surface-700/60 to-surface-800 shadow-xl">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div class="flex flex-wrap items-center gap-2.5">
            <h2 class="text-2xl font-mono font-extrabold text-white tracking-wide">${escapeHtml(data.cveId)}</h2>
            <span
              class="px-3 py-1 rounded-full text-xs font-black tracking-wider uppercase border shadow-sm"
              style="color: ${severity.color || '#94a3b8'}; background: ${severity.bg || 'transparent'}; border-color: ${severity.border || '#94a3b8'};"
            >
              ${escapeHtml(severity.level || 'UNKNOWN')}
            </span>
            <span class="px-2.5 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">
              ${escapeHtml(data.vulnStatus || 'Analyzed')}
            </span>
          </div>
          <p class="text-xs text-slate-400 mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1">
            <span>Published: <strong class="text-slate-300">${formatDate(data.published)}</strong></span>
            <span>Last Modified: <strong class="text-slate-300">${formatDate(data.lastModified)}</strong></span>
            <span>Assigner: <strong class="text-slate-300">${escapeHtml(data.sourceIdentifier || 'N/A')}</strong></span>
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-2">
          <button
            type="button"
            class="btn-secondary !text-xs !py-2 !px-3.5 flex items-center gap-1.5"
            onclick="copyToClipboard('${escapeHtml(data.cveId)}', this)"
          >
            <i data-lucide="copy" class="w-3.5 h-3.5"></i> Copy ID
          </button>
          <a
            href="/gtfobins"
            class="btn-secondary !text-xs !py-2 !px-3.5 flex items-center gap-1.5 text-amber-400 border-amber-500/30 hover:bg-amber-500/10 transition-colors"
            title="Search Unix privilege escalation vectors on GTFOBins"
          >
            <i data-lucide="terminal" class="w-3.5 h-3.5 text-amber-400"></i>
            <span>GTFOBins</span>
          </a>
          <a
            href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(data.cveId)}"
            target="_blank"
            rel="noopener noreferrer"
            class="btn-primary !text-xs !py-2 !px-3.5 !bg-surface-700 !border-slate-600 hover:!bg-surface-600 flex items-center gap-1.5"
          >
            <span>NIST Official</span>
            <i data-lucide="external-link" class="w-3.5 h-3.5 text-slate-400"></i>
          </a>
        </div>
      </div>
    </div>

    <!-- CVSS Scoreboard & Impact Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in">

      <!-- CVSS Score Card -->
      <div class="card p-6 border-slate-700/60 flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-4">
            <span class="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <i data-lucide="activity" class="w-4 h-4 text-rose-400"></i>
              CVSS ${escapeHtml(data.cvssVersion || '3.1')} Base Score
            </span>
            <span class="text-[10px] font-mono text-slate-500 uppercase">Severity Matrix</span>
          </div>

          <div class="flex items-baseline gap-3 my-2">
            <span class="font-mono text-5xl font-black" style="color: ${severity.color || '#94a3b8'}">${score}</span>
            <span class="text-slate-500 text-lg font-medium">/ 10.0</span>
          </div>

          <!-- Score Progress Bar -->
          <div class="w-full h-2.5 bg-surface-900 rounded-full overflow-hidden border border-slate-700/40 my-3">
            <div
              class="h-full rounded-full transition-all duration-700"
              style="width: ${(parseFloat(score) || 0) * 10}%; background: ${severity.color || '#94a3b8'}"
            ></div>
          </div>
        </div>

        <div class="pt-4 border-t border-slate-800/80 space-y-2 text-xs">
          <div class="flex items-center justify-between">
            <span class="text-slate-400">Exploitability Score:</span>
            <span class="font-mono font-bold text-white">${cvss.exploitabilityScore != null ? cvss.exploitabilityScore : 'N/A'}</span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-slate-400">Impact Score:</span>
            <span class="font-mono font-bold text-white">${cvss.impactScore != null ? cvss.impactScore : 'N/A'}</span>
          </div>
        </div>
      </div>

      <!-- CVSS Vector & Attack Parameters (2 Columns) -->
      <div class="lg:col-span-2 card p-6 border-slate-700/60">
        <div class="flex items-center justify-between mb-4">
          <span class="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <i data-lucide="crosshair" class="w-4 h-4 text-cyan-400"></i>
            CVSS Vector & Attack Vector Analysis
          </span>
          <button
            type="button"
            class="text-xs text-slate-400 hover:text-white flex items-center gap-1"
            onclick="copyToClipboard('${escapeHtml(cvss.vectorString || '')}', this)"
          >
            <i data-lucide="copy" class="w-3 h-3"></i> Copy Vector
          </button>
        </div>

        <!-- Raw Vector Banner -->
        <div class="net-val-box !py-2 !px-3 mb-4 bg-surface-900/90">
          <code class="font-mono text-xs text-cyan-300 break-all">${escapeHtml(cvss.vectorString || 'N/A')}</code>
        </div>

        <!-- 8 Core Metrics Grid -->
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
          <div class="vector-chip">
            <span class="text-[10px] uppercase font-bold text-slate-500">Attack Vector (AV)</span>
            ${getMetricBadge(cvss.attackVector)}
          </div>
          <div class="vector-chip">
            <span class="text-[10px] uppercase font-bold text-slate-500">Complexity (AC)</span>
            ${getMetricBadge(cvss.attackComplexity, false)}
          </div>
          <div class="vector-chip">
            <span class="text-[10px] uppercase font-bold text-slate-500">Privileges (PR)</span>
            ${getMetricBadge(cvss.privilegesRequired, false)}
          </div>
          <div class="vector-chip">
            <span class="text-[10px] uppercase font-bold text-slate-500">User Interaction (UI)</span>
            ${getMetricBadge(cvss.userInteraction, false)}
          </div>
          <div class="vector-chip">
            <span class="text-[10px] uppercase font-bold text-slate-500">Scope (S)</span>
            ${getMetricBadge(cvss.scope)}
          </div>
          <div class="vector-chip">
            <span class="text-[10px] uppercase font-bold text-slate-500">Confidentiality (C)</span>
            ${getMetricBadge(cvss.confidentialityImpact)}
          </div>
          <div class="vector-chip">
            <span class="text-[10px] uppercase font-bold text-slate-500">Integrity (I)</span>
            ${getMetricBadge(cvss.integrityImpact)}
          </div>
          <div class="vector-chip">
            <span class="text-[10px] uppercase font-bold text-slate-500">Availability (A)</span>
            ${getMetricBadge(cvss.availabilityImpact)}
          </div>
        </div>
      </div>

    </div>

    <!-- Detailed Vulnerability Description -->
    <div class="card p-6 animate-fade-in border-slate-700/60">
      <h3 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
        <i data-lucide="file-text" class="w-4 h-4 text-emerald-400"></i>
        Vulnerability Executive Summary
      </h3>
      <p class="text-sm text-slate-300 leading-relaxed font-sans font-normal whitespace-pre-wrap">
        ${escapeHtml(data.description || 'No description available.')}
      </p>
    </div>

    <!-- Weaknesses (CWE) -->
    ${weaknesses.length > 0 ? `
      <div class="card p-6 animate-fade-in border-slate-700/60">
        <h3 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
          <i data-lucide="shield-x" class="w-4 h-4 text-amber-400"></i>
          Common Weakness Enumeration (CWE)
        </h3>
        <div class="flex flex-wrap gap-2">
          ${weaknesses.map((cwe) => {
            const clean = String(cwe || '').replace('CWE-', '');
            return `
            <a
              href="https://cwe.mitre.org/data/definitions/${encodeURIComponent(clean)}.html"
              target="_blank"
              rel="noopener noreferrer"
              class="net-val-box !py-1.5 !px-3 flex items-center gap-2 hover:border-amber-500/50 group"
            >
              <span class="font-mono text-xs font-bold text-amber-300">${escapeHtml(cwe)}</span>
              <i data-lucide="external-link" class="w-3 h-3 text-slate-600 group-hover:text-amber-400"></i>
            </a>
            `;
          }).join('')}
        </div>
      </div>
    ` : ''}

    <!-- Official References & Advisories -->
    ${references.length > 0 ? `
      <div class="card p-6 animate-fade-in border-slate-700/60">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <i data-lucide="link" class="w-4 h-4 text-violet-400"></i>
            Official Security Advisories, Patches & Exploit Proofs
          </h3>
          <span class="text-xs text-slate-500">${references.length} Sources</span>
        </div>

        <div class="divide-y divide-slate-800/80 max-h-96 overflow-y-auto pr-2">
          ${references.map((ref) => {
            const url = (ref && ref.url) ? ref.url : '#';
            const tags = Array.isArray(ref?.tags) ? ref.tags : [];
            return `
            <div class="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
              <div class="flex-1 min-w-0">
                <a
                  href="${escapeHtml(url)}"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="font-mono text-slate-300 hover:text-cyan-400 transition-colors break-all flex items-center gap-1.5"
                >
                  <span class="truncate">${escapeHtml(url)}</span>
                  <i data-lucide="external-link" class="w-3 h-3 flex-shrink-0 text-slate-500"></i>
                </a>
              </div>
              <div class="flex items-center gap-1.5 flex-wrap flex-shrink-0">
                ${tags.length > 0 ? tags.map((tag) => `
                  <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-surface-700 text-slate-400 border border-slate-700">
                    ${escapeHtml(tag)}
                  </span>
                `).join('') : '<span class="text-[10px] text-slate-600">Advisory</span>'}
              </div>
            </div>
            `;
          }).join('')}
        </div>
      </div>
    ` : ''}
  `;

  try {
    lucide.createIcons({ nodes: [container] });
  } catch (_) {
    try {
      lucide.createIcons();
    } catch (e) {}
  }
}
