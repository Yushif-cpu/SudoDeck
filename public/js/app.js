// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — Frontend Application
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initClock();
  initTabs();
  initIPForm();
  initFileForm();
  initHashForm();
  initDomainForm();
  initQuickButtons();
  initDragAndDrop();
  loadReportedIPs();
  initReportedIPsRefresh();
  initUtilsModule();
  initEmailHeaderModule();
  initUniversalSearch();
});

// ═══════════════════════════════════════════════════════════════
//  UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════

// ── Live Clock ──────────────────────────────────────────────────
function initClock() {
  const el = document.getElementById('live-clock');
  if (!el) return;
  const tick = () => {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
  };
  tick();
  setInterval(tick, 1000);
}

// ── Toast Notifications ─────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
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
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.innerHTML;
    btn.classList.add('copied');
    btn.innerHTML = `<i data-lucide="check" class="w-3 h-3"></i> Copied`;
    lucide.createIcons({ nodes: [btn] });
    showToast('Copied to clipboard', 'success', 2000);
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = original;
      lucide.createIcons({ nodes: [btn] });
    }, 2000);
  });
}

// ── Escape HTML ─────────────────────────────────────────────────
function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(str).replace(/[&<>"']/g, (m) => map[m]);
}

// ── Format date ─────────────────────────────────────────────────
function formatDate(isoStr) {
  if (!isoStr) return 'N/A';
  const d = new Date(isoStr);
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) +
    ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

// ── Format bytes ────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

// ── Loading skeleton ────────────────────────────────────────────
function showSkeleton(container) {
  container.innerHTML = `
    <div class="card p-6 animate-fade-in">
      <div class="flex items-center gap-4 mb-6">
        <div class="skeleton w-16 h-16 rounded-2xl"></div>
        <div class="flex-1 space-y-2">
          <div class="skeleton h-5 w-48"></div>
          <div class="skeleton h-3 w-32"></div>
        </div>
      </div>
      <div class="space-y-3">
        <div class="skeleton h-3 w-full"></div>
        <div class="skeleton h-3 w-3/4"></div>
        <div class="skeleton h-8 w-full rounded-lg"></div>
      </div>
      <div class="grid grid-cols-2 gap-3 mt-6">
        <div class="skeleton h-20 rounded-lg"></div>
        <div class="skeleton h-20 rounded-lg"></div>
        <div class="skeleton h-20 rounded-lg"></div>
        <div class="skeleton h-20 rounded-lg"></div>
      </div>
    </div>
  `;
}

// ── Set button loading state ────────────────────────────────────
function setButtonLoading(btn, loading) {
  if (loading) {
    btn.disabled = true;
    btn._originalHTML = btn.innerHTML;
    btn.innerHTML = `<div class="spinner"></div><span>Analyzing...</span>`;
  } else {
    btn.disabled = false;
    if (btn._originalHTML) btn.innerHTML = btn._originalHTML;
    lucide.createIcons({ nodes: [btn] });
  }
}

// ── API request helper ──────────────────────────────────────────
async function apiRequest(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...options.headers,
    },
  });

  const data = await res.json();

  if (!res.ok || !data.success) {
    const errMsg = data.error?.message || data.error || `Request failed (${res.status})`;
    throw new Error(errMsg);
  }

  return data;
}

// ═══════════════════════════════════════════════════════════════
//  TAB NAVIGATION & PORTAL ROUTING
// ═══════════════════════════════════════════════════════════════
function switchToTab(tabName) {
  if (tabName === 'file') {
    window.location.href = '/siem#file';
    return;
  }
  if (tabName === 'email') {
    window.location.href = '/siem#email';
    return;
  }

  const btns = document.querySelectorAll('.tab-btn');
  const targetBtn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);

  btns.forEach((b) => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });

  if (targetBtn) {
    targetBtn.classList.add('active');
    targetBtn.setAttribute('aria-selected', 'true');
  }

  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.add('hidden'));
  const panel = document.getElementById(`panel-${tabName}`);
  if (panel) {
    panel.classList.remove('hidden');
    panel.classList.add('animate-fade-in');
    if (window.lucide) lucide.createIcons();
  }

  // Isolate special modules from live threat feed (utils and email hide it, home and others show it)
  const reportedSection = document.getElementById('reported-ips-section');
  if (reportedSection) {
    if (tabName === 'utils' || tabName === 'email') {
      reportedSection.classList.add('hidden');
    } else {
      reportedSection.classList.remove('hidden');
    }
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}
window.switchToTab = switchToTab;

function initTabs() {
  const btns = document.querySelectorAll('.tab-btn[data-tab]');
  btns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      if (!tabName) return;
      switchToTab(tabName);
      history.pushState(null, '', tabName === 'home' ? '/' : `/#${tabName}`);
    });
  });

  // Global click delegator for any button or link with [data-switch-tab]
  document.addEventListener('click', (e) => {
    const trigger = e.target.closest('[data-switch-tab]');
    if (trigger) {
      e.preventDefault();
      const tab = trigger.getAttribute('data-switch-tab');
      if (tab) {
        switchToTab(tab);
        history.pushState(null, '', tab === 'home' ? '/' : `/#${tab}`);
      }
    }
  });

  // Brand Logo and Name click in Header/Footer -> Always return to Home smoothly on index.html!
  const brandLogos = document.querySelectorAll('#brand-logo-link, .brand-home-link');
  brandLogos.forEach((logo) => {
    logo.addEventListener('click', (e) => {
      if (window.location.pathname === '/' || window.location.pathname.endsWith('index.html')) {
        e.preventDefault();
        switchToTab('home');
        history.pushState(null, '', '/');
      }
    });
  });

  // Handle Hash change dynamically (e.g. clicking /#ip anywhere)
  window.addEventListener('hashchange', () => {
    const hash = window.location.hash ? window.location.hash.replace('#', '') : null;
    if (hash === 'file') {
      window.location.href = '/siem#file';
      return;
    }
    if (hash === 'email') {
      window.location.href = '/siem#email';
      return;
    }
    if (hash && document.getElementById(`panel-${hash}`)) {
      switchToTab(hash);
    } else if (!hash) {
      switchToTab('home');
    }
  });

  // Handle URL parameters or Hash on initial load
  const urlParams = new URLSearchParams(window.location.search);
  const paramTab = urlParams.get('tab');
  const hashTab = window.location.hash ? window.location.hash.replace('#', '') : null;
  const targetTab = paramTab || hashTab;

  if (targetTab === 'file') {
    window.location.href = '/siem#file';
    return;
  }
  if (targetTab === 'email') {
    window.location.href = '/siem#email';
    return;
  }

  if (targetTab && document.getElementById(`panel-${targetTab}`)) {
    switchToTab(targetTab);
  } else {
    // Default is always Home!
    switchToTab('home');
  }
}

// ═══════════════════════════════════════════════════════════════
//  UNIVERSAL SMART SEARCH (HOME HUB)
// ═══════════════════════════════════════════════════════════════
function initUniversalSearch() {
  const form = document.getElementById('universal-search-form');
  const input = document.getElementById('universal-search-input');
  if (!form || !input) return;

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const query = input.value.trim();
    if (!query) return;

    // 1. CVE detection (e.g. CVE-2024-3094)
    if (/^CVE-\d{4}-\d{4,}$/i.test(query)) {
      window.location.href = `/cve?query=${encodeURIComponent(query)}`;
      return;
    }

    // 2. MAC address detection (e.g. 00:1A:2B:3C:4D:5E or 001A2B3C4D5E)
    if (/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(query) || /^[0-9A-Fa-f]{12}$/.test(query)) {
      window.location.href = `/mac?query=${encodeURIComponent(query)}`;
      return;
    }

    // 3. IP address detection (IPv4 / IPv6)
    const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(query);
    const isIPv6 = query.includes(':') && /^[0-9a-fA-F:]+$/.test(query);
    if (isIPv4 || isIPv6) {
      switchToTab('ip');
      const ipInput = document.getElementById('ip-input');
      const ipForm = document.getElementById('ip-form');
      if (ipInput) ipInput.value = query;
      if (ipForm) ipForm.dispatchEvent(new Event('submit', { cancelable: true }));
      return;
    }

    // 4. File Hash detection (MD5 = 32 hex, SHA-1 = 40 hex, SHA-256 = 64 hex)
    if (/^[a-fA-F0-9]{32}$/.test(query) || /^[a-fA-F0-9]{40}$/.test(query) || /^[a-fA-F0-9]{64}$/.test(query)) {
      window.location.href = `/siem?hash=${encodeURIComponent(query)}#file`;
      return;
    }

    // 5. Domain detection (contains dot and valid domain suffix)
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(query)) {
      switchToTab('domain');
      const domainInput = document.getElementById('domain-input');
      const domainForm = document.getElementById('domain-form');
      if (domainInput) domainInput.value = query;
      if (domainForm) domainForm.dispatchEvent(new Event('submit', { cancelable: true }));
      return;
    }

    // Fallback: Default to IP search
    switchToTab('ip');
    const fallbackInput = document.getElementById('ip-input');
    if (fallbackInput) fallbackInput.value = query;
  });

  // Universal quick buttons
  document.querySelectorAll('.universal-quick-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const val = btn.dataset.value;
      if (val && input) {
        input.value = val;
        form.dispatchEvent(new Event('submit', { cancelable: true }));
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════
//  IP REPUTATION MODULE
// ═══════════════════════════════════════════════════════════════
function initIPForm() {
  const form = document.getElementById('ip-form');
  const ipInput = document.getElementById('ip-input');
  const clearBtn = document.getElementById('btn-clear-ip');
  const recentContainer = document.getElementById('recent-ips-container');
  const recentList = document.getElementById('recent-ips-list');
  const clearHistoryBtn = document.getElementById('btn-clear-ip-history');

  // Render recent searches
  const renderRecent = () => {
    if (!recentContainer || !recentList || !window.ThreatIntelHistory) return;
    const history = window.ThreatIntelHistory.get('ip', 6);
    if (history.length === 0) {
      recentContainer.classList.add('hidden');
      recentList.innerHTML = '';
      return;
    }
    recentContainer.classList.remove('hidden');
    recentList.innerHTML = history.map(ip => `
      <button type="button" class="recent-chip" data-ip="${escapeHtml(ip)}">
        <i data-lucide="history" class="w-3 h-3 text-slate-500"></i>
        <span>${escapeHtml(ip)}</span>
      </button>
    `).join('');
    if (window.lucide) lucide.createIcons({ nodes: [recentList] });

    recentList.querySelectorAll('.recent-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        if (ipInput) ipInput.value = btn.dataset.ip;
        form.dispatchEvent(new Event('submit'));
      });
    });
  };

  renderRecent();

  // Clear button toggle
  if (ipInput && clearBtn) {
    ipInput.addEventListener('input', () => {
      if (ipInput.value.trim().length > 0) {
        clearBtn.classList.remove('hidden');
      } else {
        clearBtn.classList.add('hidden');
      }
    });

    clearBtn.addEventListener('click', () => {
      ipInput.value = '';
      clearBtn.classList.add('hidden');
      ipInput.focus();
    });
  }

  // Clear history button
  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
      if (window.ThreatIntelHistory) {
        window.ThreatIntelHistory.clear('ip');
        renderRecent();
        showToast('Recent IP history cleared', 'info');
      }
    });
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = (ipInput?.value || '').trim();
    if (!ip) return;

    const btn = document.getElementById('ip-submit');
    const results = document.getElementById('ip-results');

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      const data = await apiRequest('/api/check-ip', {
        method: 'POST',
        body: JSON.stringify({ ip }),
      });

      if (window.ThreatIntelHistory) {
        window.ThreatIntelHistory.add('ip', ip);
        renderRecent();
      }

      renderIPResults(results, data.data);
      showToast('IP analysis complete', 'success');
    } catch (err) {
      renderError(results, err.message);
      showToast(err.message, 'error');
    } finally {
      setButtonLoading(btn, false);
    }
  });

  // Cross-Tool / URL Query auto-search
  const urlParams = new URLSearchParams(window.location.search);
  const qIp = urlParams.get('ip');
  if (qIp && ipInput) {
    ipInput.value = qIp.trim();
    if (clearBtn) clearBtn.classList.remove('hidden');
    setTimeout(() => {
      form.dispatchEvent(new Event('submit'));
    }, 150);
  }
}

function renderIPResults(container, d) {
  const riskClasses = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    clean: 'badge-clean',
  };
  const riskGradients = {
    critical: 'from-rose-500 to-red-600',
    high: 'from-orange-500 to-amber-600',
    medium: 'from-yellow-500 to-amber-500',
    low: 'from-cyan-500 to-blue-500',
    clean: 'from-emerald-500 to-teal-500',
  };
  const riskTextColors = {
    critical: 'text-rose-400',
    high: 'text-orange-400',
    medium: 'text-amber-400',
    low: 'text-blue-400',
    clean: 'text-emerald-400',
  };
  const riskBorderColors = {
    critical: 'border-rose-500/30 bg-rose-500/10',
    high: 'border-orange-500/30 bg-orange-500/10',
    medium: 'border-amber-500/30 bg-amber-500/10',
    low: 'border-blue-500/30 bg-blue-500/10',
    clean: 'border-emerald-500/30 bg-emerald-500/10',
  };

  container.innerHTML = `
    <div class="space-y-4 animate-fade-in w-full">
      <!-- ── 1. Main Risk Score & Target IP Card ── -->
      <div class="card p-6 border-slate-800/80 bg-surface-850 shadow-xl space-y-4">
        ${d.warning ? `
          <div class="px-3.5 py-2.5 rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-xs text-cyan-200 flex items-center gap-2 animate-fade-in">
            <i data-lucide="info" class="w-4 h-4 text-cyan-400 shrink-0"></i>
            <span class="font-mono text-[11px]">${escapeHtml(d.warning)}</span>
          </div>
        ` : ''}
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div class="flex items-center gap-4">
            <div class="w-16 h-16 rounded-2xl ${riskBorderColors[d.riskLevel] || riskBorderColors.clean} border flex flex-col items-center justify-center flex-shrink-0 shadow-inner">
              <span class="text-2xl font-extrabold font-mono text-white leading-none">${d.abuseConfidenceScore}</span>
              <span class="text-[9px] font-mono text-slate-400 uppercase mt-0.5">/ 100</span>
            </div>
            <div>
              <div class="flex items-center gap-2.5 flex-wrap">
                <h3 class="text-xl font-bold text-white font-mono tracking-wide">${escapeHtml(d.ip)}</h3>
                <button
                  type="button"
                  class="btn-secondary !text-xs !py-1 !px-2.5 flex items-center gap-1.5 transition-all"
                  onclick="copyToClipboard('${escapeHtml(d.ip)}', this)"
                >
                  <i data-lucide="copy" class="w-3.5 h-3.5 text-slate-400"></i>
                  <span>Copy</span>
                </button>
                <span class="badge ${riskClasses[d.riskLevel] || 'badge-clean'} font-mono">${escapeHtml(d.riskLabel)}</span>
              </div>
              <div class="flex items-center gap-2 mt-1.5 text-xs text-slate-400 font-mono flex-wrap">
                <span>IPv${d.ipVersion || '4'}</span>
                <span>•</span>
                <span class="${d.isPublic ? 'text-cyan-400' : 'text-amber-400'}">${d.isPublic ? 'Public IP' : 'Private IP'}</span>
                <span>•</span>
                <span>${d.isWhitelisted ? '<span class="text-emerald-400 font-semibold">Whitelisted Safe</span>' : 'Not Whitelisted'}</span>
              </div>
            </div>
          </div>

          <div class="sm:text-right border-t sm:border-t-0 border-slate-800/80 pt-3 sm:pt-0">
            <span class="text-[10px] uppercase font-bold text-slate-500 tracking-wider block font-mono">Location & Country</span>
            <div class="text-sm font-semibold text-white flex items-center sm:justify-end gap-1.5 mt-0.5">
              <i data-lucide="map-pin" class="w-3.5 h-3.5 text-cyan-400"></i>
              <span>${escapeHtml(d.countryName || 'Unknown')} (${escapeHtml(d.countryCode || 'N/A')})</span>
            </div>
          </div>
        </div>

        <!-- Score Meter Bar -->
        <div class="pt-3 border-t border-slate-800/80">
          <div class="flex items-center justify-between text-xs font-mono mb-1.5">
            <span class="text-slate-400">Abuse Confidence Score</span>
            <span class="font-bold ${riskTextColors[d.riskLevel] || 'text-emerald-400'}">${d.abuseConfidenceScore}% Confidence</span>
          </div>
          <div class="w-full h-2.5 bg-surface-900 rounded-full overflow-hidden p-0.5 border border-slate-800">
            <div
              class="h-full rounded-full transition-all duration-700 bg-gradient-to-r ${riskGradients[d.riskLevel] || riskGradients.clean}"
              style="width: ${Math.max(d.abuseConfidenceScore, 3)}%"
            ></div>
          </div>
        </div>
      </div>

      <!-- ── 2. Telemetry Key Metrics (4 Cards) ── -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div class="card p-3.5 bg-surface-900/90 border-slate-800/80">
          <div class="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <i data-lucide="flag" class="w-3.5 h-3.5 text-rose-400"></i>
            <span class="font-mono text-[11px]">Total Reports</span>
          </div>
          <span class="text-lg font-bold font-mono text-white">${d.totalReports.toLocaleString()}</span>
        </div>

        <div class="card p-3.5 bg-surface-900/90 border-slate-800/80">
          <div class="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <i data-lucide="users" class="w-3.5 h-3.5 text-amber-400"></i>
            <span class="font-mono text-[11px]">Reporters</span>
          </div>
          <span class="text-lg font-bold font-mono text-white">${d.numDistinctUsers.toLocaleString()}</span>
        </div>

        <div class="card p-3.5 bg-surface-900/90 border-slate-800/80">
          <div class="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <i data-lucide="building" class="w-3.5 h-3.5 text-cyan-400"></i>
            <span class="font-mono text-[11px]">ISP / Organization</span>
          </div>
          <span class="text-xs font-semibold text-white truncate block font-mono" title="${escapeHtml(d.isp || 'N/A')}">${escapeHtml(d.isp || 'N/A')}</span>
        </div>

        <div class="card p-3.5 bg-surface-900/90 border-slate-800/80">
          <div class="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <i data-lucide="globe" class="w-3.5 h-3.5 text-emerald-400"></i>
            <span class="font-mono text-[11px]">Domain</span>
          </div>
          <span class="text-xs font-semibold text-white truncate block font-mono" title="${escapeHtml(d.domain || 'N/A')}">${escapeHtml(d.domain || 'N/A')}</span>
        </div>
      </div>

      <!-- ── 3. Structured Network Details Card ── -->
      <div class="card p-5 border-slate-800/80 bg-surface-850 space-y-3">
        <div class="flex items-center justify-between border-b border-slate-800 pb-2.5">
          <div class="flex items-center gap-2">
            <i data-lucide="network" class="w-4 h-4 text-cyan-400"></i>
            <h4 class="text-xs font-bold text-white uppercase tracking-wider">Network & Infrastructure Details</h4>
          </div>
          <span class="text-[10px] font-mono text-slate-500">AbuseIPDB Verified</span>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 font-mono text-xs">
          <div class="p-2.5 rounded-xl bg-surface-900/80 border border-slate-800">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Usage Type</span>
            <span class="text-slate-200 font-semibold truncate block mt-0.5">${escapeHtml(d.usageType || 'N/A')}</span>
          </div>

          <div class="p-2.5 rounded-xl bg-surface-900/80 border border-slate-800">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Domain Name</span>
            <span class="text-cyan-300 font-semibold truncate block mt-0.5">${escapeHtml(d.domain || 'N/A')}</span>
          </div>

          <div class="p-2.5 rounded-xl bg-surface-900/80 border border-slate-800">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Whitelist Status</span>
            <span class="font-semibold block mt-0.5 ${d.isWhitelisted ? 'text-emerald-400' : 'text-slate-400'}">
              ${d.isWhitelisted ? '✓ Whitelisted Safe' : '✗ Not Whitelisted'}
            </span>
          </div>

          <div class="p-2.5 rounded-xl bg-surface-900/80 border border-slate-800 sm:col-span-2 lg:col-span-3">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Reverse DNS Hostnames</span>
            <span class="text-indigo-300 font-semibold break-all block mt-0.5">${escapeHtml(d.hostnames?.join(', ') || 'None reported')}</span>
          </div>

          <div class="p-2.5 rounded-xl bg-surface-900/80 border border-slate-800">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Last Reported</span>
            <span class="text-slate-300 block mt-0.5">${formatDate(d.lastReportedAt)}</span>
          </div>

          <div class="p-2.5 rounded-xl bg-surface-900/80 border border-slate-800 sm:col-span-1 lg:col-span-2">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Queried At</span>
            <span class="text-slate-400 block mt-0.5">${formatDate(d.queriedAt)}</span>
          </div>
        </div>
      </div>

      <!-- ── 4. Raw JSON Inspection ── -->
      ${renderJsonToggle(d, 'ip')}
    </div>
  `;

  lucide.createIcons({ nodes: [container] });
}

// ═══════════════════════════════════════════════════════════════
//  FILE HASH ANALYSIS MODULE
// ═══════════════════════════════════════════════════════════════
function initFileForm() {
  const form = document.getElementById('file-form');
  const fileInput = document.getElementById('file-input');
  const fileInfo = document.getElementById('file-info');
  const fileName = document.getElementById('file-name');
  const fileSize = document.getElementById('file-size');

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      const f = fileInput.files[0];
      fileName.textContent = f.name;
      fileSize.textContent = formatBytes(f.size);
      fileInfo.classList.remove('hidden');
    }
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!fileInput.files.length) {
      showToast('Please select a file to analyze', 'warning');
      return;
    }

    const btn = document.getElementById('file-submit');
    const results = document.getElementById('file-results');
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      const data = await apiRequest('/api/check-file', {
        method: 'POST',
        body: formData,
      });
      renderFileResults(results, data);
      showToast('File analysis complete', 'success');
    } catch (err) {
      renderError(results, err.message);
      showToast(err.message, 'error');
    } finally {
      setButtonLoading(btn, false);
    }
  });
}

function initHashForm() {
  const form = document.getElementById('hash-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const hash = document.getElementById('hash-input').value.trim();
    if (!hash) {
      showToast('Please enter a SHA-256 hash', 'warning');
      return;
    }

    const btn = document.getElementById('hash-submit');
    const results = document.getElementById('file-results');

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      const data = await apiRequest('/api/check-hash', {
        method: 'POST',
        body: JSON.stringify({ hash }),
      });
      renderFileResults(results, data);
      showToast('Hash lookup complete', 'success');
    } catch (err) {
      renderError(results, err.message);
      showToast(err.message, 'error');
    } finally {
      setButtonLoading(btn, false);
    }
  });
}

function renderFileResults(container, response) {
  const d = response.data;

  if (!d.found) {
    container.innerHTML = `
      <div class="card p-8 text-center animate-fade-in">
        <div class="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4">
          <i data-lucide="shield-check" class="w-8 h-8 text-emerald-400"></i>
        </div>
        <h3 class="text-lg font-bold text-white mb-2">Not Found in Database</h3>
        <p class="text-sm text-slate-400 mb-4">${escapeHtml(d.message || 'This file hash was not found in the VirusTotal database.')}</p>
        <div class="inline-flex items-center gap-2 px-4 py-2 bg-surface-700/60 rounded-lg font-mono text-xs text-slate-400 break-all">
          ${escapeHtml(d.hash?.sha256 || response.hash)}
          <button class="copy-btn ml-2" onclick="copyToClipboard('${escapeHtml(d.hash?.sha256 || response.hash)}', this)">
            <i data-lucide="copy" class="w-3 h-3"></i>
          </button>
        </div>
      </div>
    `;
    lucide.createIcons({ nodes: [container] });
    return;
  }

  const stats = d.detectionStats;
  const total = stats.total || 1;
  const malPct = ((stats.malicious / total) * 100).toFixed(1);
  const susPct = ((stats.suspicious / total) * 100).toFixed(1);
  const cleanPct = ((stats.harmless / total) * 100).toFixed(1);
  const undPct = ((stats.undetected / total) * 100).toFixed(1);

  const threatClasses = {
    malicious: 'badge-malicious',
    suspicious: 'badge-suspicious',
    low_risk: 'badge-medium',
    clean: 'badge-clean',
  };
  const threatGradients = {
    malicious: 'from-red-500 to-rose-600',
    suspicious: 'from-orange-500 to-amber-600',
    low_risk: 'from-yellow-500 to-amber-500',
    clean: 'from-emerald-500 to-green-600',
  };

  container.innerHTML = `
    ${d.warning ? `
      <div class="px-4 py-2.5 rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-xs text-cyan-200 flex items-center gap-2 mb-4 animate-fade-in">
        <i data-lucide="info" class="w-4 h-4 text-cyan-400 shrink-0"></i>
        <span class="font-mono text-[11px]">${escapeHtml(d.warning)}</span>
      </div>
    ` : ''}
    <!-- Threat Score Header -->
    <div class="card p-6 animate-slide-up">
      <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-5">
        <div class="flex items-center gap-4">
          <div class="w-14 h-14 rounded-2xl bg-gradient-to-br ${threatGradients[d.threatLevel] || threatGradients.clean} flex items-center justify-center shadow-lg">
            <span class="text-xl font-bold text-white">${d.threatScore}</span>
          </div>
          <div>
            <h3 class="text-base font-bold text-white">${escapeHtml(d.fileName)}</h3>
            <div class="flex items-center gap-2 mt-1">
              <span class="badge ${threatClasses[d.threatLevel] || 'badge-clean'}">${escapeHtml(d.threatLabel)}</span>
              <span class="text-xs text-slate-500">${escapeHtml(d.fileType)}</span>
            </div>
          </div>
        </div>
        <div class="text-right">
          <p class="text-xs text-slate-500">Detection Ratio</p>
          <p class="text-xl font-bold text-white">${stats.malicious}<span class="text-slate-500">/${total}</span></p>
        </div>
      </div>

      <!-- Detection Bar -->
      <div class="mb-3">
        <div class="flex justify-between text-xs text-slate-500 mb-1.5">
          <span>Detection Breakdown</span>
          <span>${stats.malicious + stats.suspicious} flagged of ${total}</span>
        </div>
        <div class="detection-bar">
          <div class="bg-rose-500" style="width: ${malPct}%" title="Malicious: ${stats.malicious}"></div>
          <div class="bg-orange-500" style="width: ${susPct}%" title="Suspicious: ${stats.suspicious}"></div>
          <div class="bg-slate-600" style="width: ${undPct}%" title="Undetected: ${stats.undetected}"></div>
          <div class="bg-emerald-500" style="width: ${cleanPct}%" title="Harmless: ${stats.harmless}"></div>
        </div>
        <div class="flex gap-4 mt-2">
          <span class="flex items-center gap-1.5 text-xs"><span class="w-2 h-2 rounded-full bg-rose-500"></span> Malicious (${stats.malicious})</span>
          <span class="flex items-center gap-1.5 text-xs"><span class="w-2 h-2 rounded-full bg-orange-500"></span> Suspicious (${stats.suspicious})</span>
          <span class="flex items-center gap-1.5 text-xs"><span class="w-2 h-2 rounded-full bg-emerald-500"></span> Clean (${stats.harmless})</span>
          <span class="flex items-center gap-1.5 text-xs"><span class="w-2 h-2 rounded-full bg-slate-600"></span> Undetected (${stats.undetected})</span>
        </div>
      </div>
    </div>

    <!-- Hash Info -->
    <div class="card p-6 animate-slide-up" style="animation-delay: 0.1s">
      <h4 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
        <i data-lucide="hash" class="w-4 h-4 text-violet-400"></i>
        Hash Values
      </h4>
      ${hashRow('SHA-256', d.hash.sha256)}
      ${hashRow('SHA-1', d.hash.sha1)}
      ${hashRow('MD5', d.hash.md5)}
    </div>

    <!-- File Details -->
    <div class="card p-6 animate-slide-up" style="animation-delay: 0.15s">
      <h4 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
        <i data-lucide="file-text" class="w-4 h-4 text-blue-400"></i>
        File Details
      </h4>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3">
        ${detailRow('File Size', d.fileSizeFormatted)}
        ${detailRow('File Type', d.fileType)}
        ${detailRow('Threat Name', d.popularThreatName || 'N/A')}
        ${detailRow('Category', d.threatCategory || 'N/A')}
        ${detailRow('Times Submitted', d.timesSubmitted)}
        ${detailRow('First Submission', formatDate(d.firstSubmissionDate))}
        ${detailRow('Last Analysis', formatDate(d.lastAnalysisDate))}
      </div>
      ${d.tags?.length ? `
        <div class="mt-4 pt-3 border-t border-slate-700/30">
          <p class="text-xs text-slate-500 mb-2">Tags</p>
          <div class="flex flex-wrap gap-1.5">
            ${d.tags.map(t => `<span class="text-xs px-2 py-0.5 rounded-md bg-surface-700/60 border border-slate-700/40 text-slate-400">${escapeHtml(t)}</span>`).join('')}
          </div>
        </div>
      ` : ''}
    </div>

    <!-- Top Detections -->
    ${d.topDetections?.length ? `
      <div class="card p-6 animate-slide-up" style="animation-delay: 0.2s">
        <h4 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <i data-lucide="alert-triangle" class="w-4 h-4 text-rose-400"></i>
          Top Detections (${d.topDetections.length})
        </h4>
        <div class="space-y-2">
          ${d.topDetections.map(det => `
            <div class="flex items-center justify-between py-2 px-3 rounded-lg bg-surface-900/40 border border-slate-800/40">
              <span class="text-xs font-medium text-slate-300">${escapeHtml(det.engine)}</span>
              <div class="flex items-center gap-2">
                <span class="text-xs font-mono ${det.category === 'malicious' ? 'text-rose-400' : 'text-orange-400'}">${escapeHtml(det.result || det.category)}</span>
                <span class="badge ${det.category === 'malicious' ? 'badge-malicious' : 'badge-suspicious'}">${det.category}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    ` : ''}

    ${renderJsonToggle(d, 'file')}
  `;

  lucide.createIcons({ nodes: [container] });
}

// ═══════════════════════════════════════════════════════════════
//  DOMAIN INTELLIGENCE MODULE
// ═══════════════════════════════════════════════════════════════
function initDomainForm() {
  const form = document.getElementById('domain-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = document.getElementById('domain-input').value.trim();
    if (!domain) return;

    const btn = document.getElementById('domain-submit');
    const results = document.getElementById('domain-results');

    setButtonLoading(btn, true);
    showSkeleton(results);

    try {
      const data = await apiRequest('/api/check-domain', {
        method: 'POST',
        body: JSON.stringify({ domain }),
      });
      renderDomainResults(results, data.data);
      showToast('Domain analysis complete', 'success');
    } catch (err) {
      renderError(results, err.message);
      showToast(err.message, 'error');
    } finally {
      setButtonLoading(btn, false);
    }
  });
}

function renderDomainResults(container, d) {
  if (!d.found) {
    container.innerHTML = `
      <div class="card p-8 text-center animate-fade-in">
        <div class="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center mx-auto mb-4">
          <i data-lucide="search-x" class="w-8 h-8 text-amber-400"></i>
        </div>
        <h3 class="text-lg font-bold text-white mb-2">Domain Not Found</h3>
        <p class="text-sm text-slate-400">${escapeHtml(d.message || 'No data available for this domain.')}</p>
      </div>
    `;
    lucide.createIcons({ nodes: [container] });
    return;
  }

  const stats = d.detectionStats;
  const total = stats.total || 1;
  const threatClasses = {
    malicious: 'badge-malicious',
    suspicious: 'badge-suspicious',
    low_risk: 'badge-medium',
    clean: 'badge-clean',
  };
  const threatGradients = {
    malicious: 'from-red-500 to-rose-600',
    suspicious: 'from-orange-500 to-amber-600',
    low_risk: 'from-yellow-500 to-amber-500',
    clean: 'from-emerald-500 to-green-600',
  };

  // Categories
  const catEntries = Object.entries(d.categories || {});
  const catHtml = catEntries.length > 0
    ? catEntries.map(([src, cat]) => `
        <span class="text-xs px-2.5 py-1 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-300" title="${escapeHtml(src)}">${escapeHtml(cat)}</span>
      `).join('')
    : '<span class="text-xs text-slate-500">No categories</span>';

  // DNS records
  const dnsHtml = (d.lastDnsRecords || []).length > 0
    ? d.lastDnsRecords.map(rec => {
        const typeColors = { A: 'bg-emerald-500/20 text-emerald-300', AAAA: 'bg-cyan-500/20 text-cyan-300', MX: 'bg-violet-500/20 text-violet-300', NS: 'bg-blue-500/20 text-blue-300', TXT: 'bg-amber-500/20 text-amber-300', SOA: 'bg-rose-500/20 text-rose-300', CNAME: 'bg-orange-500/20 text-orange-300' };
        const color = typeColors[rec.type] || 'bg-slate-500/20 text-slate-300';
        return `
          <div class="dns-tag">
            <span class="dns-tag-type ${color}">${escapeHtml(rec.type)}</span>
            <span class="font-mono text-slate-300 truncate" title="${escapeHtml(rec.value)}">${escapeHtml(rec.value)}</span>
            ${rec.ttl ? `<span class="text-slate-600 text-xs">TTL: ${rec.ttl}</span>` : ''}
          </div>
        `;
      }).join('')
    : '<span class="text-xs text-slate-500">No DNS records available</span>';

  container.innerHTML = `
    ${d.warning ? `
      <div class="px-4 py-2.5 rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-xs text-cyan-200 flex items-center gap-2 mb-4 animate-fade-in">
        <i data-lucide="info" class="w-4 h-4 text-cyan-400 shrink-0"></i>
        <span class="font-mono text-[11px]">${escapeHtml(d.warning)}</span>
      </div>
    ` : ''}
    <!-- Threat Score Header -->
    <div class="card p-6 animate-slide-up">
      <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-5">
        <div class="flex items-center gap-4">
          <div class="w-14 h-14 rounded-2xl bg-gradient-to-br ${threatGradients[d.threatLevel] || threatGradients.clean} flex items-center justify-center shadow-lg">
            <i data-lucide="globe" class="w-7 h-7 text-white"></i>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-lg font-bold text-white">${escapeHtml(d.domain)}</h3>
              <button class="copy-btn" onclick="copyToClipboard('${escapeHtml(d.domain)}', this)">
                <i data-lucide="copy" class="w-3 h-3"></i> Copy
              </button>
            </div>
            <div class="flex items-center gap-2 mt-1">
              <span class="badge ${threatClasses[d.threatLevel] || 'badge-clean'}">${escapeHtml(d.threatLabel)}</span>
              <span class="text-xs text-slate-500">Reputation: ${d.reputation}</span>
            </div>
          </div>
        </div>
        <div class="text-right">
          <p class="text-xs text-slate-500">Flagged Engines</p>
          <p class="text-xl font-bold text-white">${stats.malicious + stats.suspicious}<span class="text-slate-500">/${total}</span></p>
        </div>
      </div>

      <!-- Detection Bar -->
      <div class="detection-bar mb-2">
        <div class="bg-rose-500" style="width: ${((stats.malicious / total) * 100).toFixed(1)}%"></div>
        <div class="bg-orange-500" style="width: ${((stats.suspicious / total) * 100).toFixed(1)}%"></div>
        <div class="bg-slate-600" style="width: ${((stats.undetected / total) * 100).toFixed(1)}%"></div>
        <div class="bg-emerald-500" style="width: ${((stats.harmless / total) * 100).toFixed(1)}%"></div>
      </div>
      <div class="flex gap-4">
        <span class="flex items-center gap-1.5 text-xs"><span class="w-2 h-2 rounded-full bg-rose-500"></span> Malicious (${stats.malicious})</span>
        <span class="flex items-center gap-1.5 text-xs"><span class="w-2 h-2 rounded-full bg-emerald-500"></span> Clean (${stats.harmless})</span>
      </div>
    </div>

    <!-- Stats Grid -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 animate-slide-up" style="animation-delay: 0.1s">
      <div class="stat-card">
        <div class="flex items-center gap-2 mb-2">
          <i data-lucide="building-2" class="w-4 h-4 text-blue-400"></i>
          <span class="text-xs text-slate-500">Registrar</span>
        </div>
        <p class="text-xs font-semibold text-white truncate" title="${escapeHtml(d.registrar)}">${escapeHtml(d.registrar)}</p>
      </div>
      <div class="stat-card">
        <div class="flex items-center gap-2 mb-2">
          <i data-lucide="calendar" class="w-4 h-4 text-emerald-400"></i>
          <span class="text-xs text-slate-500">Created</span>
        </div>
        <p class="text-xs font-semibold text-white">${d.creationDate ? formatDate(d.creationDate) : 'N/A'}</p>
      </div>
      <div class="stat-card">
        <div class="flex items-center gap-2 mb-2">
          <i data-lucide="thumbs-up" class="w-4 h-4 text-emerald-400"></i>
          <span class="text-xs text-slate-500">Clean Votes</span>
        </div>
        <p class="text-xl font-bold text-white">${d.totalVotes?.harmless || 0}</p>
      </div>
      <div class="stat-card">
        <div class="flex items-center gap-2 mb-2">
          <i data-lucide="thumbs-down" class="w-4 h-4 text-rose-400"></i>
          <span class="text-xs text-slate-500">Mal. Votes</span>
        </div>
        <p class="text-xl font-bold text-white">${d.totalVotes?.malicious || 0}</p>
      </div>
    </div>

    <!-- Categories -->
    <div class="card p-6 animate-slide-up" style="animation-delay: 0.15s">
      <h4 class="text-sm font-semibold text-white mb-3 flex items-center gap-2">
        <i data-lucide="tag" class="w-4 h-4 text-blue-400"></i>
        Categories
      </h4>
      <div class="flex flex-wrap gap-2">${catHtml}</div>
    </div>

    <!-- DNS Records -->
    <div class="card p-6 animate-slide-up" style="animation-delay: 0.2s">
      <h4 class="text-sm font-semibold text-white mb-3 flex items-center gap-2">
        <i data-lucide="server" class="w-4 h-4 text-cyan-400"></i>
        DNS Records (${d.lastDnsRecords?.length || 0})
      </h4>
      <div class="flex flex-wrap gap-2">${dnsHtml}</div>
    </div>

    <!-- WHOIS -->
    ${Object.keys(d.whoisInfo || {}).length > 0 ? `
      <div class="card p-6 animate-slide-up" style="animation-delay: 0.25s">
        <h4 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <i data-lucide="file-text" class="w-4 h-4 text-violet-400"></i>
          WHOIS Information
        </h4>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3">
          ${d.whoisInfo.registrant ? detailRow('Registrant', d.whoisInfo.registrant) : ''}
          ${d.whoisInfo.adminEmail ? detailRow('Admin Email', d.whoisInfo.adminEmail) : ''}
          ${d.whoisInfo.expiryDate ? detailRow('Expiry Date', d.whoisInfo.expiryDate) : ''}
          ${d.whoisInfo.nameServers?.length ? detailRow('Name Servers', d.whoisInfo.nameServers.join(', ')) : ''}
        </div>
      </div>
    ` : ''}

    ${renderJsonToggle(d, 'domain')}
  `;

  lucide.createIcons({ nodes: [container] });
}

// ═══════════════════════════════════════════════════════════════
//  SHARED RENDER HELPERS
// ═══════════════════════════════════════════════════════════════

function detailRow(label, value) {
  return `
    <div class="flex justify-between py-2 border-b border-slate-800/40">
      <span class="text-xs text-slate-500">${escapeHtml(label)}</span>
      <span class="text-xs text-slate-300 font-medium text-right max-w-[60%] truncate" title="${escapeHtml(String(value))}">${escapeHtml(String(value))}</span>
    </div>
  `;
}

function hashRow(label, value) {
  if (!value) return '';
  return `
    <div class="flex items-center justify-between py-2.5 border-b border-slate-800/30 gap-2">
      <span class="text-xs text-slate-500 font-medium shrink-0">${label}</span>
      <div class="flex items-center gap-2 min-w-0">
        <span class="text-xs font-mono text-slate-400 truncate">${escapeHtml(value)}</span>
        <button class="copy-btn shrink-0" onclick="copyToClipboard('${escapeHtml(value)}', this)">
          <i data-lucide="copy" class="w-3 h-3"></i>
        </button>
      </div>
    </div>
  `;
}

function renderJsonToggle(data, id) {
  const jsonStr = JSON.stringify(data, null, 2);
  return `
    <div class="card p-4 animate-slide-up" style="animation-delay: 0.3s">
      <div class="json-toggle flex items-center justify-between" onclick="toggleJson('${id}')">
        <span class="text-xs font-medium text-slate-500 flex items-center gap-2">
          <i data-lucide="code-2" class="w-3.5 h-3.5"></i>
          Raw JSON Response
        </span>
        <i data-lucide="chevron-down" class="w-4 h-4 text-slate-600 transition-transform" id="json-chevron-${id}"></i>
      </div>
      <div class="json-content mt-3" id="json-body-${id}">
        <pre>${escapeHtml(jsonStr)}</pre>
      </div>
    </div>
  `;
}

function toggleJson(id) {
  const body = document.getElementById(`json-body-${id}`);
  const chevron = document.getElementById(`json-chevron-${id}`);
  body.classList.toggle('expanded');
  chevron.style.transform = body.classList.contains('expanded') ? 'rotate(180deg)' : '';
}
// Make it globally accessible
window.toggleJson = toggleJson;
window.copyToClipboard = copyToClipboard;

function renderError(container, message) {
  container.innerHTML = `
    <div class="card p-8 text-center animate-fade-in">
      <div class="w-16 h-16 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center mx-auto mb-4">
        <i data-lucide="alert-circle" class="w-8 h-8 text-rose-400"></i>
      </div>
      <h3 class="text-lg font-bold text-white mb-2">Analysis Failed</h3>
      <p class="text-sm text-slate-400">${escapeHtml(message)}</p>
    </div>
  `;
  lucide.createIcons({ nodes: [container] });
}

// ═══════════════════════════════════════════════════════════════
//  QUICK BUTTONS & DRAG-AND-DROP
// ═══════════════════════════════════════════════════════════════
function initQuickButtons() {
  document.querySelectorAll('.quick-ip-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.getElementById('ip-input').value = btn.dataset.ip;
      document.getElementById('ip-form').dispatchEvent(new Event('submit'));
    });
  });

  document.querySelectorAll('.quick-domain-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.getElementById('domain-input').value = btn.dataset.domain;
      document.getElementById('domain-form').dispatchEvent(new Event('submit'));
    });
  });

  document.querySelectorAll('.quick-hash-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const hashInput = document.getElementById('hash-input');
      if (hashInput) {
        hashInput.value = btn.dataset.hash;
        document.getElementById('hash-form').dispatchEvent(new Event('submit'));
      }
    });
  });
}

function initDragAndDrop() {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  if (!dropZone) return;

  ['dragenter', 'dragover'].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer?.files;
    if (files?.length > 0) {
      fileInput.files = files;
      fileInput.dispatchEvent(new Event('change'));
    }
  });
}

// ═══════════════════════════════════════════════════════════════
//  RECENTLY REPORTED IPs MODULE
// ═══════════════════════════════════════════════════════════════

// ── Country code → flag emoji ───────────────────────────────────
function countryFlag(countryCode) {
  if (!countryCode || countryCode === 'Unknown' || countryCode.length !== 2) return '🌐';
  const code = countryCode.toUpperCase();
  return String.fromCodePoint(
    ...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)
  );
}

// ── Relative time formatter ─────────────────────────────────────
function timeAgo(isoStr) {
  if (!isoStr) return 'N/A';
  const seconds = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000);
  if (seconds < 60)    return `${seconds}s ago`;
  if (seconds < 3600)  return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// ── Load and render reported IPs (ThreatFox abuse.ch feed) ─────
async function loadReportedIPs(silent = false) {
  const grid = document.getElementById('reported-ips-grid');
  const errorDiv = document.getElementById('reported-ips-error');
  const errorMsg = document.getElementById('reported-ips-error-msg');
  if (!grid) return;

  if (!silent && grid.children.length === 0) {
    grid.classList.remove('hidden');
    errorDiv.classList.add('hidden');
  }

  try {
    const response = await apiRequest('/api/recent-malicious-ips?limit=24');
    const ips = response.ips || response.data;

    if (!ips || ips.length === 0) {
      grid.innerHTML = `
        <div class="col-span-full text-center py-8">
          <p class="text-sm text-slate-500">No recently reported malicious IPs available in ThreatFox feed.</p>
        </div>
      `;
      return;
    }

    grid.classList.remove('hidden');
    errorDiv.classList.add('hidden');

    grid.innerHTML = ips.map((item, i) => {
      const isBotnet = item.threatType === 'botnet_cc';
      const isPayload = item.threatType === 'payload_delivery';

      const borderClass = isBotnet
        ? 'border-rose-500/30 hover:border-rose-500/60'
        : isPayload
        ? 'border-orange-500/30 hover:border-orange-500/60'
        : 'border-violet-500/30 hover:border-violet-500/60';

      const glowClass = isBotnet
        ? 'hover:shadow-rose-500/10'
        : isPayload
        ? 'hover:shadow-orange-500/10'
        : 'hover:shadow-violet-500/10';

      const badgeBg = isBotnet
        ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
        : isPayload
        ? 'bg-orange-500/15 text-orange-300 border-orange-500/30'
        : 'bg-violet-500/15 text-violet-300 border-violet-500/30';

      const iconName = isBotnet ? 'skull' : isPayload ? 'crosshair' : 'shield-alert';
      const iconColor = isBotnet ? 'text-rose-400' : isPayload ? 'text-orange-400' : 'text-violet-400';

      return `
        <div class="reported-ip-card bg-surface-800/75 border ${borderClass} rounded-xl p-3.5 transition-all duration-200 cursor-pointer hover:shadow-lg ${glowClass} animate-fade-in group flex flex-col justify-between"
             style="animation-delay: ${i * 25}ms"
             title="Click to analyze ${escapeHtml(item.ip)} in OSINT Platform"
             onclick="document.getElementById('ip-input').value='${escapeHtml(item.ip)}'; document.querySelectorAll('.tab-btn')[0].click(); document.getElementById('ip-form').dispatchEvent(new Event('submit'));">
          
          <!-- Top row: Threat Type Badge & Confidence / Time -->
          <div class="flex items-center justify-between gap-2 mb-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border shrink-0 ${badgeBg} flex items-center gap-1">
              <i data-lucide="${iconName}" class="w-3 h-3 shrink-0"></i>
              ${escapeHtml(item.threatTypeLabel || 'MALICIOUS')}
            </span>
            <div class="flex items-center gap-1.5 text-[11px] font-mono text-slate-400 shrink-0">
              <span class="text-[10px] font-bold text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800/40">
                ${item.confidence}% Conf.
              </span>
              <span class="text-slate-500 flex items-center gap-0.5">
                <i data-lucide="clock" class="w-3 h-3 text-slate-500"></i>
                ${timeAgo(item.lastSeen || item.firstSeen)}
              </span>
            </div>
          </div>

          <!-- Middle row: Full Uncut IP Address & Port (Never Truncated) -->
          <div class="flex items-center justify-between gap-2 my-1.5 py-2 px-3 rounded-lg bg-surface-900/90 border border-slate-700/60 group-hover:border-cyan-500/50 transition-colors">
            <div class="flex items-center gap-2 min-w-0">
              <span class="w-2 h-2 rounded-full bg-rose-500 animate-pulse-slow shrink-0"></span>
              <span class="text-sm sm:text-base font-mono font-bold text-white tracking-normal select-all whitespace-nowrap group-hover:text-cyan-300 transition-colors">
                ${escapeHtml(item.ip)}
              </span>
            </div>
            ${item.port ? `
              <span class="text-xs font-mono font-bold text-cyan-400 bg-surface-800 px-2 py-0.5 rounded border border-cyan-500/30 shrink-0" title="Port ${escapeHtml(item.port)}">
                :${escapeHtml(item.port)}
              </span>
            ` : ''}
          </div>

          <!-- Bottom row: Malware Family & Reporter -->
          <div class="flex items-center justify-between gap-2 pt-1 text-xs">
            <div class="flex items-center gap-1.5 min-w-0">
              <i data-lucide="bug" class="w-3.5 h-3.5 text-rose-400 shrink-0"></i>
              <span class="font-bold text-rose-300 truncate" title="Malware: ${escapeHtml(item.malware)}">
                ${escapeHtml(item.malware)}
              </span>
            </div>
            <span class="flex items-center gap-1 text-[11px] font-mono text-slate-400 shrink-0 truncate max-w-[110px]" title="Reported by ${escapeHtml(item.reporter)}">
              <i data-lucide="user-check" class="w-3 h-3 text-slate-500 shrink-0"></i>
              ${escapeHtml(item.reporter)}
            </span>
          </div>

        </div>
      `;
    }).join('');

    lucide.createIcons({ nodes: [grid] });

  } catch (err) {
    if (!silent) {
      grid.classList.add('hidden');
      errorDiv.classList.remove('hidden');
      errorMsg.textContent = err.message || 'Failed to load ThreatFox malicious IPs feed.';
    }
  }
}

// ── Refresh button & Live background interval ───────────────────
function initReportedIPsRefresh() {
  const btn = document.getElementById('refresh-reported-ips');
  if (btn) {
    btn.addEventListener('click', () => {
      const grid = document.getElementById('reported-ips-grid');
      grid.classList.remove('hidden');
      grid.innerHTML = `
        <div class="skeleton h-28 rounded-xl"></div>
        <div class="skeleton h-28 rounded-xl"></div>
        <div class="skeleton h-28 rounded-xl"></div>
        <div class="skeleton h-28 rounded-xl"></div>
        <div class="skeleton h-28 rounded-xl hidden sm:block"></div>
        <div class="skeleton h-28 rounded-xl hidden sm:block"></div>
        <div class="skeleton h-28 rounded-xl hidden lg:block"></div>
        <div class="skeleton h-28 rounded-xl hidden lg:block"></div>
      `;
      loadReportedIPs(false);
      showToast('Refreshing ThreatFox live feed...', 'info', 2000);
    });
  }

  // Live background polling every 60 seconds without page reload
  if (window._threatFoxInterval) {
    clearInterval(window._threatFoxInterval);
  }
  window._threatFoxInterval = setInterval(() => {
    loadReportedIPs(true);
  }, 60000);
}

// ═══════════════════════════════════════════════════════════════
//  IP & NETWORK UTILITIES MODULE
// ═══════════════════════════════════════════════════════════════

function initUtilsModule() {
  initUtilSubtabs();
  initConvertModule();
  initSubnetModule();
  initPingModule();
  initDnsModule();
}

// ── Sub-Tabs Navigation ─────────────────────────────────────────
function initUtilSubtabs() {
  const btns = document.querySelectorAll('.util-subtab-btn');
  btns.forEach((btn) => {
    btn.addEventListener('click', () => {
      btns.forEach((b) => {
        b.classList.remove('active');
        b.classList.add('text-slate-400');
        b.setAttribute('aria-selected', 'false');
      });
      btn.classList.add('active');
      btn.classList.remove('text-slate-400');
      btn.setAttribute('aria-selected', 'true');

      document.querySelectorAll('.util-subpanel').forEach((p) => p.classList.add('hidden'));
      const targetPanel = document.getElementById(`subpanel-${btn.dataset.subtab}`);
      if (targetPanel) {
        targetPanel.classList.remove('hidden');
        targetPanel.classList.add('animate-fade-in');
        if (window.lucide) lucide.createIcons();
      }
    });
  });
}

// ────────────────────────────────────────────────────────────────
// 1. CONVERT IP MODULE
// ────────────────────────────────────────────────────────────────

function initConvertModule() {
  const form = document.getElementById('convert-form');
  const input = document.getElementById('convert-input');
  const submitBtn = document.getElementById('convert-submit');
  const resultsContainer = document.getElementById('convert-results');
  const quickPills = document.querySelectorAll('#subpanel-convert .quick-pill');

  if (!form) return;

  quickPills.forEach((pill) => {
    pill.addEventListener('click', () => {
      input.value = pill.dataset.value;
      form.dispatchEvent(new Event('submit'));
    });
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const val = input.value.trim();
    if (!val) return;

    setButtonLoading(submitBtn, true);
    showSkeleton(resultsContainer);

    try {
      const res = await apiRequest('/api/utils/convert-ip', {
        method: 'POST',
        body: JSON.stringify({ ip: val }),
      });
      renderConvertResults(res.data);
    } catch (err) {
      resultsContainer.innerHTML = `
        <div class="card p-6 border-rose-500/30 bg-rose-500/5 animate-fade-in">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center flex-shrink-0">
              <i data-lucide="alert-circle" class="w-5 h-5 text-rose-400"></i>
            </div>
            <div>
              <h4 class="text-sm font-semibold text-rose-400">Conversion Failed</h4>
              <p class="text-xs text-slate-400 mt-0.5">${escapeHtml(err.message)}</p>
            </div>
          </div>
        </div>
      `;
      lucide.createIcons({ nodes: [resultsContainer] });
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}

function renderConvertResults(data) {
  const container = document.getElementById('convert-results');

  container.innerHTML = `
    <!-- Summary Header Card -->
    <div class="card p-5 animate-fade-in border-cyan-500/30 bg-gradient-to-r from-surface-800 via-surface-700/60 to-surface-800">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
            <i data-lucide="binary" class="w-5 h-5 text-cyan-400"></i>
          </div>
          <div>
            <h3 class="text-base font-mono font-bold text-white">${escapeHtml(data.dotDecimal)}</h3>
            <p class="text-xs text-slate-400">${escapeHtml(data.reverseDns)}</p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <span class="px-2.5 py-1 rounded-md text-xs font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
            ${escapeHtml(data.ipClass)}
          </span>
          <span class="px-2.5 py-1 rounded-md text-xs font-semibold ${data.isPrivate ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30' : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'}">
            ${escapeHtml(data.scope)}
          </span>
        </div>
      </div>
    </div>

    <!-- Representations Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5 animate-fade-in">

      <!-- Dotted Decimal -->
      <div class="net-val-box">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Dotted Decimal</span>
          <button type="button" class="btn-copy text-[11px] text-slate-400 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(data.dotDecimal)}', this)">
            <i data-lucide="copy" class="w-3 h-3"></i> Copy
          </button>
        </div>
        <p class="font-mono text-sm font-bold text-cyan-300 break-all">${escapeHtml(data.dotDecimal)}</p>
      </div>

      <!-- Integer (Decimal) -->
      <div class="net-val-box">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Decimal Integer (Uint32)</span>
          <button type="button" class="btn-copy text-[11px] text-slate-400 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(String(data.decimal))}', this)">
            <i data-lucide="copy" class="w-3 h-3"></i> Copy
          </button>
        </div>
        <p class="font-mono text-sm font-bold text-emerald-300 break-all">${escapeHtml(String(data.decimal))}</p>
      </div>

      <!-- Hexadecimal -->
      <div class="net-val-box">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Hexadecimal (0x)</span>
          <button type="button" class="btn-copy text-[11px] text-slate-400 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(data.hex)}', this)">
            <i data-lucide="copy" class="w-3 h-3"></i> Copy
          </button>
        </div>
        <p class="font-mono text-sm font-bold text-violet-300 break-all">${escapeHtml(data.hex)}</p>
        <p class="font-mono text-[11px] text-slate-500 mt-1">${escapeHtml(data.hexDotted)}</p>
      </div>

      <!-- Binary (Dotted & Flat) -->
      <div class="net-val-box">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Binary (32-bit)</span>
          <button type="button" class="btn-copy text-[11px] text-slate-400 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(data.binaryDotted)}', this)">
            <i data-lucide="copy" class="w-3 h-3"></i> Copy
          </button>
        </div>
        <p class="font-mono text-xs font-bold text-amber-300 break-all leading-relaxed">${escapeHtml(data.binaryDotted)}</p>
      </div>

      <!-- Octal -->
      <div class="net-val-box">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Octal Representation</span>
          <button type="button" class="btn-copy text-[11px] text-slate-400 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(data.octalDotted)}', this)">
            <i data-lucide="copy" class="w-3 h-3"></i> Copy
          </button>
        </div>
        <p class="font-mono text-sm font-bold text-rose-300 break-all">${escapeHtml(data.octalDotted)}</p>
      </div>

      <!-- IPv6 Mapped -->
      <div class="net-val-box">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">IPv4-Mapped IPv6</span>
          <button type="button" class="btn-copy text-[11px] text-slate-400 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(data.ipv6Mapped)}', this)">
            <i data-lucide="copy" class="w-3 h-3"></i> Copy
          </button>
        </div>
        <p class="font-mono text-sm font-bold text-sky-300 break-all">${escapeHtml(data.ipv6Mapped)}</p>
        <p class="font-mono text-[11px] text-slate-500 mt-1">${escapeHtml(data.ipv6Hex)}</p>
      </div>

    </div>
  `;

  lucide.createIcons({ nodes: [container] });
}

// ────────────────────────────────────────────────────────────────
// 2. SUBNET CALCULATOR MODULE
// ────────────────────────────────────────────────────────────────

function initSubnetModule() {
  const form = document.getElementById('subnet-form');
  const input = document.getElementById('subnet-input');
  const submitBtn = document.getElementById('subnet-submit');
  const resultsContainer = document.getElementById('subnet-results');
  const quickPills = document.querySelectorAll('#subpanel-subnet .quick-pill');

  if (!form) return;

  quickPills.forEach((pill) => {
    pill.addEventListener('click', () => {
      input.value = pill.dataset.value;
      form.dispatchEvent(new Event('submit'));
    });
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const val = input.value.trim();
    if (!val) return;

    setButtonLoading(submitBtn, true);
    showSkeleton(resultsContainer);

    try {
      const res = await apiRequest('/api/utils/subnet', {
        method: 'POST',
        body: JSON.stringify({ cidr: val }),
      });
      renderSubnetResults(res.data);
    } catch (err) {
      resultsContainer.innerHTML = `
        <div class="card p-6 border-rose-500/30 bg-rose-500/5 animate-fade-in">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center flex-shrink-0">
              <i data-lucide="alert-circle" class="w-5 h-5 text-rose-400"></i>
            </div>
            <div>
              <h4 class="text-sm font-semibold text-rose-400">Subnet Calculation Failed</h4>
              <p class="text-xs text-slate-400 mt-0.5">${escapeHtml(err.message)}</p>
            </div>
          </div>
        </div>
      `;
      lucide.createIcons({ nodes: [resultsContainer] });
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}

function renderSubnetResults(data) {
  const container = document.getElementById('subnet-results');

  container.innerHTML = `
    <!-- Top Highlights Grid -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 animate-fade-in">
      <div class="card p-4 border-slate-700/60 bg-surface-800/80">
        <p class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Network IP</p>
        <p class="font-mono text-sm font-bold text-cyan-400 mt-1 truncate">${escapeHtml(data.networkIP)}</p>
        <p class="text-[10px] text-slate-500 mt-0.5">Prefix /${data.prefix}</p>
      </div>

      <div class="card p-4 border-slate-700/60 bg-surface-800/80">
        <p class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Broadcast IP</p>
        <p class="font-mono text-sm font-bold text-rose-400 mt-1 truncate">${escapeHtml(data.broadcastIP)}</p>
        <p class="text-[10px] text-slate-500 mt-0.5">End of Block</p>
      </div>

      <div class="card p-4 border-slate-700/60 bg-surface-800/80">
        <p class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Total Addresses</p>
        <p class="font-mono text-sm font-bold text-white mt-1">${data.totalHosts.toLocaleString()}</p>
        <p class="text-[10px] text-slate-500 mt-0.5">2^${32 - data.prefix} IPs</p>
      </div>

      <div class="card p-4 border-slate-700/60 bg-surface-800/80">
        <p class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Usable Hosts</p>
        <p class="font-mono text-sm font-bold text-emerald-400 mt-1">${data.usableHosts.toLocaleString()}</p>
        <p class="text-[10px] text-slate-500 mt-0.5">Allocatable</p>
      </div>
    </div>

    <!-- Detailed Parameters Card -->
    <div class="card p-6 animate-fade-in">
      <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
        <i data-lucide="layers" class="w-4 h-4 text-emerald-400"></i>
        Subnet Specification Breakdown
      </h4>

      <div class="divide-y divide-slate-800/80">

        <div class="py-2.5 flex items-center justify-between">
          <span class="text-xs text-slate-400">Usable IP Range</span>
          <div class="flex items-center gap-2">
            <span class="font-mono text-xs font-bold text-emerald-300">${escapeHtml(data.usableRange)}</span>
            <button type="button" class="btn-copy text-xs text-slate-400 hover:text-white" onclick="copyToClipboard('${escapeHtml(data.usableRange)}', this)">
              <i data-lucide="copy" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </div>

        <div class="py-2.5 flex items-center justify-between">
          <span class="text-xs text-slate-400">Subnet Mask</span>
          <div class="flex items-center gap-2">
            <span class="font-mono text-xs text-slate-200">${escapeHtml(data.subnetMask)}</span>
            <button type="button" class="btn-copy text-xs text-slate-400 hover:text-white" onclick="copyToClipboard('${escapeHtml(data.subnetMask)}', this)">
              <i data-lucide="copy" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </div>

        <div class="py-2.5 flex items-center justify-between">
          <span class="text-xs text-slate-400">Wildcard Mask</span>
          <span class="font-mono text-xs text-slate-400">${escapeHtml(data.wildcardMask)}</span>
        </div>

        <div class="py-2.5 flex items-center justify-between">
          <span class="text-xs text-slate-400">Binary Subnet Mask</span>
          <span class="font-mono text-[11px] text-amber-400/90">${escapeHtml(data.binaryMask)}</span>
        </div>

        <div class="py-2.5 flex items-center justify-between">
          <span class="text-xs text-slate-400">IP Classification & Scope</span>
          <div class="flex items-center gap-1.5">
            <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">${escapeHtml(data.ipClass)}</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${data.isPrivate ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}">
              ${escapeHtml(data.scope)}
            </span>
          </div>
        </div>

      </div>
    </div>
  `;

  lucide.createIcons({ nodes: [container] });
}

// ────────────────────────────────────────────────────────────────
// 3. PING / LATENCY MODULE
// ────────────────────────────────────────────────────────────────

function initPingModule() {
  const form = document.getElementById('ping-form');
  const input = document.getElementById('ping-input');
  const countSelect = document.getElementById('ping-count');
  const submitBtn = document.getElementById('ping-submit');
  const resultsContainer = document.getElementById('ping-results');
  const quickPills = document.querySelectorAll('#subpanel-ping .quick-pill');

  if (!form) return;

  quickPills.forEach((pill) => {
    pill.addEventListener('click', () => {
      input.value = pill.dataset.value;
      form.dispatchEvent(new Event('submit'));
    });
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const host = input.value.trim();
    if (!host) return;

    const count = Number(countSelect.value) || 4;

    setButtonLoading(submitBtn, true);
    showSkeleton(resultsContainer);

    try {
      const res = await apiRequest('/api/utils/ping', {
        method: 'POST',
        body: JSON.stringify({ host, count }),
      });
      renderPingResults(res.data);
    } catch (err) {
      resultsContainer.innerHTML = `
        <div class="card p-6 border-rose-500/30 bg-rose-500/5 animate-fade-in">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center flex-shrink-0">
              <i data-lucide="alert-circle" class="w-5 h-5 text-rose-400"></i>
            </div>
            <div>
              <h4 class="text-sm font-semibold text-rose-400">Ping Execution Failed</h4>
              <p class="text-xs text-slate-400 mt-0.5">${escapeHtml(err.message)}</p>
            </div>
          </div>
        </div>
      `;
      lucide.createIcons({ nodes: [resultsContainer] });
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}

function renderPingResults(data) {
  const container = document.getElementById('ping-results');
  const isAlive = data.alive;

  container.innerHTML = `
    <!-- Host Status Banner -->
    <div class="card p-5 animate-fade-in ${isAlive ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'}">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3.5">
          <div class="w-11 h-11 rounded-xl flex items-center justify-center ${isAlive ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'}">
            <i data-lucide="${isAlive ? 'check-circle-2' : 'x-circle'}" class="w-6 h-6"></i>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-base font-mono font-bold text-white">${escapeHtml(data.host)}</h3>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${isAlive ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'}">
                ${isAlive ? 'Online / Reachable' : 'Unreachable / Dead'}
              </span>
            </div>
            <p class="text-xs text-slate-400 mt-0.5">
              ${data.packetsReceived} of ${data.packetsTransmitted} packets received (${data.packetLossPercent}% loss)
            </p>
          </div>
        </div>

        ${isAlive && data.avgLatency !== null ? `
          <div class="text-right hidden sm:block">
            <p class="text-xs text-slate-500 uppercase font-semibold">Avg Round-Trip</p>
            <p class="font-mono text-lg font-bold text-emerald-400">${data.avgLatency} ms</p>
          </div>
        ` : ''}
      </div>
    </div>

    <!-- Latency Stats (if host answered) -->
    ${isAlive ? `
      <div class="grid grid-cols-3 gap-3 animate-fade-in">
        <div class="card p-4 border-slate-700/60 bg-surface-800/80 text-center">
          <p class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Min Latency</p>
          <p class="font-mono text-base font-bold text-cyan-300 mt-1">${data.minLatency !== null ? data.minLatency + ' ms' : 'N/A'}</p>
        </div>
        <div class="card p-4 border-slate-700/60 bg-surface-800/80 text-center">
          <p class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Avg Latency</p>
          <p class="font-mono text-base font-bold text-emerald-300 mt-1">${data.avgLatency !== null ? data.avgLatency + ' ms' : 'N/A'}</p>
        </div>
        <div class="card p-4 border-slate-700/60 bg-surface-800/80 text-center">
          <p class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Max Latency</p>
          <p class="font-mono text-base font-bold text-rose-300 mt-1">${data.maxLatency !== null ? data.maxLatency + ' ms' : 'N/A'}</p>
        </div>
      </div>
    ` : ''}

    <!-- Raw Terminal Output -->
    <div class="card p-5 animate-fade-in">
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <i data-lucide="terminal" class="w-4 h-4 text-cyan-400"></i>
          ICMP Echo Console Output
        </h4>
        <button type="button" class="btn-copy text-xs text-slate-400 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(data.rawOutput.replace(/\r?\n/g, '\\n'))}', this)">
          <i data-lucide="copy" class="w-3.5 h-3.5"></i> Copy Raw
        </button>
      </div>

      <div class="soc-terminal">
        <div class="soc-terminal-header">
          <div class="terminal-dot bg-rose-500"></div>
          <div class="terminal-dot bg-amber-500"></div>
          <div class="terminal-dot bg-emerald-500"></div>
          <span class="text-[10px] text-slate-500 ml-2 font-mono">ping -c ${data.packetsTransmitted} ${escapeHtml(data.host)}</span>
        </div>
        <pre class="whitespace-pre-wrap font-mono text-xs text-slate-300">${escapeHtml(data.rawOutput)}</pre>
      </div>
    </div>
  `;

  lucide.createIcons({ nodes: [container] });
}

// ────────────────────────────────────────────────────────────────
// 4. DNS RECORD LOOKUP MODULE
// ────────────────────────────────────────────────────────────────

function initDnsModule() {
  const form = document.getElementById('dns-form');
  const input = document.getElementById('dns-input');
  const submitBtn = document.getElementById('dns-submit');
  const resultsContainer = document.getElementById('dns-results');
  const quickPills = document.querySelectorAll('#subpanel-dns .quick-pill');

  if (!form) return;

  quickPills.forEach((pill) => {
    pill.addEventListener('click', () => {
      input.value = pill.dataset.value;
      form.dispatchEvent(new Event('submit'));
    });
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = input.value.trim();
    if (!domain) return;

    setButtonLoading(submitBtn, true);
    showSkeleton(resultsContainer);

    try {
      const res = await apiRequest('/api/utils/dns', {
        method: 'POST',
        body: JSON.stringify({ domain }),
      });
      renderDnsResults(res.data);
    } catch (err) {
      resultsContainer.innerHTML = `
        <div class="card p-6 border-rose-500/30 bg-rose-500/5 animate-fade-in">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center flex-shrink-0">
              <i data-lucide="alert-circle" class="w-5 h-5 text-rose-400"></i>
            </div>
            <div>
              <h4 class="text-sm font-semibold text-rose-400">DNS Resolution Failed</h4>
              <p class="text-xs text-slate-400 mt-0.5">${escapeHtml(err.message)}</p>
            </div>
          </div>
        </div>
      `;
      lucide.createIcons({ nodes: [resultsContainer] });
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}

function renderDnsResults(data) {
  const container = document.getElementById('dns-results');
  const rec = data.records;

  container.innerHTML = `
    <!-- Header Banner -->
    <div class="card p-5 animate-fade-in border-violet-500/30 bg-gradient-to-r from-surface-800 via-surface-700/60 to-surface-800">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
            <i data-lucide="globe" class="w-5 h-5 text-violet-400"></i>
          </div>
          <div>
            <h3 class="text-base font-mono font-bold text-white">${escapeHtml(data.domain)}</h3>
            <p class="text-xs text-slate-400">Resolved at ${formatDate(data.queryTimestamp)}</p>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <span class="px-3 py-1 rounded-md text-xs font-semibold bg-violet-500/15 text-violet-300 border border-violet-500/30">
            ${data.totalRecordsFound} Active Records Found
          </span>
        </div>
      </div>
    </div>

    <!-- DNS Record Sections -->
    <div class="space-y-4 animate-fade-in">

      <!-- A Records (IPv4) -->
      <div class="card p-5">
        <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">A</span>
            IPv4 Address Records
          </span>
          <span class="text-xs text-slate-500">${rec.A.length} found</span>
        </h4>
        ${rec.A.length > 0 ? `
          <div class="flex flex-wrap gap-2">
            ${rec.A.map((ip) => `
              <div class="net-val-box !py-1.5 !px-3 flex items-center gap-2">
                <span class="font-mono text-xs text-cyan-300 font-semibold">${escapeHtml(ip)}</span>
                <button type="button" class="text-slate-500 hover:text-white" onclick="copyToClipboard('${escapeHtml(ip)}', this)">
                  <i data-lucide="copy" class="w-3 h-3"></i>
                </button>
              </div>
            `).join('')}
          </div>
        ` : '<p class="text-xs text-slate-600 italic">No IPv4 (A) records discovered.</p>'}
      </div>

      <!-- AAAA Records (IPv6) -->
      <div class="card p-5">
        <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">AAAA</span>
            IPv6 Address Records
          </span>
          <span class="text-xs text-slate-500">${rec.AAAA.length} found</span>
        </h4>
        ${rec.AAAA.length > 0 ? `
          <div class="flex flex-wrap gap-2">
            ${rec.AAAA.map((ip6) => `
              <div class="net-val-box !py-1.5 !px-3 flex items-center gap-2">
                <span class="font-mono text-xs text-emerald-300 font-semibold">${escapeHtml(ip6)}</span>
                <button type="button" class="text-slate-500 hover:text-white" onclick="copyToClipboard('${escapeHtml(ip6)}', this)">
                  <i data-lucide="copy" class="w-3 h-3"></i>
                </button>
              </div>
            `).join('')}
          </div>
        ` : '<p class="text-xs text-slate-600 italic">No IPv6 (AAAA) records discovered.</p>'}
      </div>

      <!-- MX Records (Mail Exchanger) -->
      <div class="card p-5">
        <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">MX</span>
            Mail Exchange Records
          </span>
          <span class="text-xs text-slate-500">${rec.MX.length} found</span>
        </h4>
        ${rec.MX.length > 0 ? `
          <div class="divide-y divide-slate-800/80">
            ${rec.MX.map((mx) => `
              <div class="py-2 flex items-center justify-between text-xs">
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    PRI ${mx.priority}
                  </span>
                  <span class="font-mono text-slate-200">${escapeHtml(mx.exchange)}</span>
                </div>
                <button type="button" class="text-slate-500 hover:text-white" onclick="copyToClipboard('${escapeHtml(mx.exchange)}', this)">
                  <i data-lucide="copy" class="w-3 h-3"></i>
                </button>
              </div>
            `).join('')}
          </div>
        ` : '<p class="text-xs text-slate-600 italic">No MX mail servers configured.</p>'}
      </div>

      <!-- TXT Records (SPF, DKIM, Domain Verification) -->
      <div class="card p-5">
        <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">TXT</span>
            Descriptive & Policy Records (SPF / DKIM)
          </span>
          <span class="text-xs text-slate-500">${rec.TXT.length} found</span>
        </h4>
        ${rec.TXT.length > 0 ? `
          <div class="space-y-2">
            ${rec.TXT.map((txt) => `
              <div class="net-val-box !p-2.5 flex items-start justify-between gap-3">
                <code class="font-mono text-xs text-slate-300 break-all leading-relaxed">${escapeHtml(txt)}</code>
                <button type="button" class="text-slate-500 hover:text-white flex-shrink-0 mt-0.5" onclick="copyToClipboard('${escapeHtml(txt)}', this)">
                  <i data-lucide="copy" class="w-3.5 h-3.5"></i>
                </button>
              </div>
            `).join('')}
          </div>
        ` : '<p class="text-xs text-slate-600 italic">No TXT records discovered.</p>'}
      </div>

      <!-- NS Records (Nameservers) -->
      <div class="card p-5">
        <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-violet-500/15 text-violet-400 border border-violet-500/30">NS</span>
            Authoritative Name Servers
          </span>
          <span class="text-xs text-slate-500">${rec.NS.length} found</span>
        </h4>
        ${rec.NS.length > 0 ? `
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            ${rec.NS.map((ns) => `
              <div class="net-val-box !py-2 !px-3 flex items-center justify-between">
                <span class="font-mono text-xs text-violet-300 font-semibold">${escapeHtml(ns)}</span>
                <button type="button" class="text-slate-500 hover:text-white" onclick="copyToClipboard('${escapeHtml(ns)}', this)">
                  <i data-lucide="copy" class="w-3 h-3"></i>
                </button>
              </div>
            `).join('')}
          </div>
        ` : '<p class="text-xs text-slate-600 italic">No authoritative NS records found.</p>'}
      </div>

      <!-- SOA Record -->
      ${rec.SOA ? `
        <div class="card p-5">
          <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-700 text-slate-300 border border-slate-600">SOA</span>
            Start of Authority Details
          </h4>
          <div class="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
            <div class="net-val-box !py-2 !px-3">
              <span class="text-[10px] uppercase text-slate-500 font-bold">Primary NS</span>
              <p class="font-mono text-xs text-slate-200 mt-0.5 truncate">${escapeHtml(rec.SOA.nsname)}</p>
            </div>
            <div class="net-val-box !py-2 !px-3">
              <span class="text-[10px] uppercase text-slate-500 font-bold">Hostmaster</span>
              <p class="font-mono text-xs text-slate-200 mt-0.5 truncate">${escapeHtml(rec.SOA.hostmaster)}</p>
            </div>
            <div class="net-val-box !py-2 !px-3">
              <span class="text-[10px] uppercase text-slate-500 font-bold">Serial</span>
              <p class="font-mono text-xs text-slate-200 mt-0.5">${rec.SOA.serial}</p>
            </div>
            <div class="net-val-box !py-2 !px-3">
              <span class="text-[10px] uppercase text-slate-500 font-bold">Refresh</span>
              <p class="font-mono text-xs text-slate-200 mt-0.5">${rec.SOA.refresh}s</p>
            </div>
            <div class="net-val-box !py-2 !px-3">
              <span class="text-[10px] uppercase text-slate-500 font-bold">Retry</span>
              <p class="font-mono text-xs text-slate-200 mt-0.5">${rec.SOA.retry}s</p>
            </div>
            <div class="net-val-box !py-2 !px-3">
              <span class="text-[10px] uppercase text-slate-500 font-bold">Expire / Min TTL</span>
              <p class="font-mono text-xs text-slate-200 mt-0.5">${rec.SOA.expire}s / ${rec.SOA.minttl}s</p>
            </div>
          </div>
        </div>
      ` : ''}

    </div>
  `;

  lucide.createIcons({ nodes: [container] });
}

// ═══════════════════════════════════════════════════════════════
//  EMAIL HEADER ANALYSIS MODULE
// ═══════════════════════════════════════════════════════════════

function initEmailHeaderModule() {
  const form = document.getElementById('email-header-form');
  const input = document.getElementById('email-header-input');
  const submitBtn = document.getElementById('email-header-submit');
  const clearBtn = document.getElementById('email-header-clear');
  const resultsContainer = document.getElementById('email-header-results');

  const legitBtn = document.getElementById('preset-legit-email');
  const spoofedBtn = document.getElementById('preset-spoofed-email');

  if (!form) return;

  // Clear button
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      input.value = '';
      input.focus();
    });
  }

  // Presets
  const LEGIT_SAMPLE = `Delivered-To: victim@company.com
Received: by 2002:a05:6512:2146:b0:4f7:d08e:1499 with SMTP id c6csp123456lfb;
        Sat, 12 Sep 2026 18:25:34 -0700 (PDT)
X-Received: by 2002:a17:907:738b:b0:a22:a5a1:5f87 with SMTP id c11-20020a170907738bb00a22a5a15f87mr10291419ejc.29;
        Sat, 12 Sep 2026 18:25:34 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@github.com header.s=s20150108;
       spf=pass (google.com: domain of noreply@github.com designates 192.30.252.204 as permitted sender) smtp.mailfrom=noreply@github.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com
Received-SPF: pass (google.com: domain of noreply@github.com designates 192.30.252.204 as permitted sender) client-ip=192.30.252.204;
Received: from smtp.github.com (out-16.mta.github.com. [192.30.252.204])
        by mx.google.com with ESMTPS id o18-20020a1709075752b00a29334547si5733157ejc.38.2026.09.12.18.25.33
        for <victim@company.com>;
        Sat, 12 Sep 2026 18:25:34 -0700 (PDT)
From: GitHub Security <noreply@github.com>
To: victim@company.com
Subject: [GitHub] Critical Security Advisory Notification
Date: Sat, 12 Sep 2026 18:25:32 -0700
Message-ID: <github/security-advisory/883921@github.com>
Return-Path: <noreply@github.com>`;

  const SPOOFED_SAMPLE = `Delivered-To: finance@corporate.com
Received: by 2002:a2e:9209:0:b0:2e1:14a0:5252 with SMTP id u9csp9948218;
        Sat, 12 Sep 2026 14:10:12 -0400 (EDT)
Authentication-Results: mx.corporate.com;
       dkim=none;
       spf=fail (corporate.com: domain of billing-notice@paypal.com does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=bounce@evil-phish-server.ru;
       dmarc=fail (p=REJECT) header.from=paypal.com
Received-SPF: fail (corporate.com: domain of paypal.com designates 185.220.101.5 as unauthorized sender) client-ip=185.220.101.5;
Received: from tor-exit-node.evil-phish-server.ru ([185.220.101.5])
        by mx.corporate.com with ESMTP id x82-corp-gateway.7712;
        Sat, 12 Sep 2026 14:10:10 -0400 (EDT)
From: "PayPal Security Support" <billing-notice@paypal.com>
To: finance@corporate.com
Reply-To: phisher-collector@evil-phish-server.ru
Subject: URGENT: Your PayPal Business Account is Suspended
Date: Sat, 12 Sep 2026 14:09:58 -0400
Message-ID: <20260912140958.9918237@fake-mailer>
Return-Path: <bounce@evil-phish-server.ru>`;

  if (legitBtn) {
    legitBtn.addEventListener('click', () => {
      input.value = LEGIT_SAMPLE;
      form.dispatchEvent(new Event('submit'));
    });
  }

  if (spoofedBtn) {
    spoofedBtn.addEventListener('click', () => {
      input.value = SPOOFED_SAMPLE;
      form.dispatchEvent(new Event('submit'));
    });
  }

  // Form submit
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const rawHeader = input.value.trim();
    if (!rawHeader) return;

    setButtonLoading(submitBtn, true);
    showSkeleton(resultsContainer);

    try {
      const res = await apiRequest('/api/analyze-header', {
        method: 'POST',
        body: JSON.stringify({ rawHeader }),
      });

      renderEmailHeaderResults(res.data);
    } catch (err) {
      resultsContainer.innerHTML = `
        <div class="card p-6 border-rose-500/30 bg-rose-500/5 animate-fade-in">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center flex-shrink-0">
              <i data-lucide="alert-circle" class="w-5 h-5 text-rose-400"></i>
            </div>
            <div>
              <h4 class="text-sm font-semibold text-rose-400">Header Parsing Failed</h4>
              <p class="text-xs text-slate-400 mt-0.5">${escapeHtml(err.message)}</p>
            </div>
          </div>
        </div>
      `;
      lucide.createIcons({ nodes: [resultsContainer] });
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}

function renderEmailHeaderResults(data) {
  const container = document.getElementById('email-header-results');
  const auth = data.authentication;
  const sec = data.securityChecks;
  const ov = data.overview;
  const hops = data.hops.hopsList || [];

  container.innerHTML = `
    <!-- Security Verdict & Authentication Scoreboard -->
    <div class="card p-5 animate-fade-in border-slate-700/80 bg-gradient-to-r from-surface-800 via-surface-700/50 to-surface-800 shadow-xl">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div class="flex items-center gap-3">
          <div class="w-11 h-11 rounded-xl flex items-center justify-center border" style="background: ${sec.verdictColor}15; border-color: ${sec.verdictColor}30;">
            <i data-lucide="${sec.riskScore >= 60 ? 'shield-alert' : sec.riskScore >= 25 ? 'shield-question' : 'shield-check'}" class="w-6 h-6" style="color: ${sec.verdictColor}"></i>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-base font-bold text-white tracking-tight">${escapeHtml(sec.verdict)}</h3>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono" style="color: ${sec.verdictColor}; background: ${sec.verdictColor}15; border: 1px solid ${sec.verdictColor}30">
                RISK: ${sec.riskScore}%
              </span>
            </div>
            <p class="text-xs text-slate-400 mt-0.5">
              ${data.rawHeaderCount} message headers processed • ${hops.length} network relay hops detected
            </p>
          </div>
        </div>

        ${data.hops.originatingIP ? `
          <div class="text-left sm:text-right">
            <span class="text-[10px] uppercase font-bold text-slate-500">Originating Sender IP</span>
            <p class="font-mono text-xs font-bold text-cyan-400">${escapeHtml(data.hops.originatingIP)}</p>
          </div>
        ` : ''}
      </div>

      <!-- 3 Core Auth Badges: SPF, DKIM, DMARC -->
      <div class="grid grid-cols-3 gap-3 pt-4">

        <!-- SPF -->
        <div class="net-val-box text-center !p-3">
          <span class="text-[10px] uppercase font-bold text-slate-400 tracking-wider block mb-1">SPF Auth</span>
          <span
            class="px-2.5 py-1 rounded-md text-xs font-bold font-mono uppercase inline-block border"
            style="color: ${auth.spf.badge.color}; background: ${auth.spf.badge.bg}; border-color: ${auth.spf.badge.border};"
          >
            ${escapeHtml(auth.spf.status)}
          </span>
          <p class="text-[10px] text-slate-500 mt-1 truncate" title="${escapeHtml(auth.spf.details)}">
            ${escapeHtml(auth.spf.details)}
          </p>
        </div>

        <!-- DKIM -->
        <div class="net-val-box text-center !p-3">
          <span class="text-[10px] uppercase font-bold text-slate-400 tracking-wider block mb-1">DKIM Sign</span>
          <span
            class="px-2.5 py-1 rounded-md text-xs font-bold font-mono uppercase inline-block border"
            style="color: ${auth.dkim.badge.color}; background: ${auth.dkim.badge.bg}; border-color: ${auth.dkim.badge.border};"
          >
            ${escapeHtml(auth.dkim.status)}
          </span>
          <p class="text-[10px] text-slate-500 mt-1 truncate">
            ${auth.dkim.domain ? 'd=' + escapeHtml(auth.dkim.domain) : (auth.dkim.signatureCount > 0 ? auth.dkim.signatureCount + ' signature(s)' : 'No signature')}
          </p>
        </div>

        <!-- DMARC -->
        <div class="net-val-box text-center !p-3">
          <span class="text-[10px] uppercase font-bold text-slate-400 tracking-wider block mb-1">DMARC Policy</span>
          <span
            class="px-2.5 py-1 rounded-md text-xs font-bold font-mono uppercase inline-block border"
            style="color: ${auth.dmarc.badge.color}; background: ${auth.dmarc.badge.bg}; border-color: ${auth.dmarc.badge.border};"
          >
            ${escapeHtml(auth.dmarc.status)}
          </span>
          <p class="text-[10px] text-slate-500 mt-1">
            ${auth.dmarc.policy ? 'p=' + escapeHtml(auth.dmarc.policy) : 'Policy: None'}
          </p>
        </div>

      </div>
    </div>

    <!-- Security Warning Alerts (if any) -->
    ${sec.flags.length > 0 ? `
      <div class="space-y-2 animate-fade-in">
        ${sec.flags.map((flag) => `
          <div class="card !p-3.5 border-${flag.type === 'CRITICAL' ? 'rose-500/40 bg-rose-500/10' : 'amber-500/40 bg-amber-500/10'} flex items-start gap-3">
            <i data-lucide="${flag.type === 'CRITICAL' ? 'alert-triangle' : 'alert-circle'}" class="w-4 h-4 flex-shrink-0 mt-0.5 ${flag.type === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'}"></i>
            <div>
              <h5 class="text-xs font-bold ${flag.type === 'CRITICAL' ? 'text-rose-300' : 'text-amber-300'}">${escapeHtml(flag.title)}</h5>
              <p class="text-[11px] text-slate-300 mt-0.5 leading-relaxed">${escapeHtml(flag.description)}</p>
            </div>
          </div>
        `).join('')}
      </div>
    ` : ''}

    <!-- Message Core Metadata Card -->
    <div class="card p-5 animate-fade-in">
      <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3.5 flex items-center justify-between">
        <span class="flex items-center gap-2">
          <i data-lucide="file-text" class="w-4 h-4 text-violet-400"></i>
          Message Header Envelope
        </span>
        <button type="button" class="text-xs text-slate-400 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(ov.subject)}', this)">
          <i data-lucide="copy" class="w-3 h-3"></i> Copy Subject
        </button>
      </h4>

      <div class="space-y-2 text-xs">
        <div class="net-val-box !p-2.5">
          <span class="text-[10px] uppercase font-bold text-slate-500 block">Subject</span>
          <span class="font-semibold text-slate-200 text-sm break-words">${escapeHtml(ov.subject)}</span>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <div class="net-val-box !p-2.5">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Sender (From)</span>
            <span class="font-mono text-cyan-300 font-semibold break-all">${escapeHtml(ov.from || 'N/A')}</span>
          </div>

          <div class="net-val-box !p-2.5">
            <div class="flex items-center justify-between">
              <span class="text-[10px] uppercase font-bold text-slate-500">Return-Path (Envelope)</span>
              ${ov.fromDomain && ov.returnPathDomain && ov.fromDomain !== ov.returnPathDomain ? `
                <span class="text-[9px] font-bold text-rose-400 uppercase bg-rose-500/10 px-1.5 py-0.2 rounded border border-rose-500/20">MISMATCH</span>
              ` : ''}
            </div>
            <span class="font-mono text-amber-300 font-semibold break-all">${escapeHtml(ov.returnPath || 'N/A')}</span>
          </div>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <div class="net-val-box !p-2.5">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Recipient (To)</span>
            <span class="font-mono text-slate-300 break-all">${escapeHtml(ov.to || 'N/A')}</span>
          </div>

          <div class="net-val-box !p-2.5">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Dispatch Date</span>
            <span class="font-mono text-slate-300">${escapeHtml(ov.date || 'N/A')}</span>
          </div>
        </div>

        ${ov.messageId ? `
          <div class="net-val-box !p-2.5">
            <span class="text-[10px] uppercase font-bold text-slate-500 block">Message-ID</span>
            <span class="font-mono text-[11px] text-slate-400 break-all">${escapeHtml(ov.messageId)}</span>
          </div>
        ` : ''}
      </div>
    </div>

    <!-- Received Relay Hops Chain -->
    <div class="card p-5 animate-fade-in">
      <div class="flex items-center justify-between mb-4">
        <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <i data-lucide="git-commit" class="w-4 h-4 text-cyan-400"></i>
          Received Relay Hops (Chronological Route)
        </h4>
        <span class="text-xs text-slate-500">${hops.length} Relays</span>
      </div>

      ${hops.length > 0 ? `
        <div class="relative pl-6 border-l-2 border-slate-700/60 space-y-4 my-2">
          ${hops.map((hop) => `
            <div class="relative group">
              <!-- Hop indicator dot -->
              <div class="absolute -left-[31px] top-1.5 w-4 h-4 rounded-full bg-surface-900 border-2 ${hop.hopNumber === 1 ? 'border-emerald-400' : 'border-cyan-400'} flex items-center justify-center shadow-md">
                <span class="w-1.5 h-1.5 rounded-full ${hop.hopNumber === 1 ? 'bg-emerald-400' : 'bg-cyan-400'}"></span>
              </div>

              <!-- Hop Card -->
              <div class="net-val-box !p-3">
                <div class="flex items-center justify-between gap-2 mb-1.5">
                  <div class="flex items-center gap-2">
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${hop.hopNumber === 1 ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30' : 'bg-surface-700 text-slate-300 border border-slate-700'}">
                      Hop #${hop.hopNumber} ${hop.hopNumber === 1 ? '(Origin)' : ''}
                    </span>
                    <span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                      ${escapeHtml(hop.protocol)}
                    </span>
                  </div>

                  ${hop.ip !== 'N/A' ? `
                    <button type="button" class="font-mono text-xs font-bold text-cyan-300 hover:text-white flex items-center gap-1" onclick="copyToClipboard('${escapeHtml(hop.ip)}', this)">
                      <i data-lucide="copy" class="w-3 h-3"></i> ${escapeHtml(hop.ip)}
                    </button>
                  ` : ''}
                </div>

                <div class="text-[11px] text-slate-300 space-y-0.5">
                  <p><span class="text-slate-500 font-medium">Sender Server:</span> <strong class="font-mono text-slate-200">${escapeHtml(hop.from)}</strong></p>
                  <p><span class="text-slate-500 font-medium">Received By:</span> <strong class="font-mono text-slate-400">${escapeHtml(hop.by)}</strong></p>
                </div>

                ${hop.timestamp !== 'N/A' ? `
                  <p class="text-[10px] text-slate-500 mt-2 flex items-center gap-1 font-mono">
                    <i data-lucide="clock" class="w-3 h-3"></i>
                    ${escapeHtml(hop.timestamp)}
                  </p>
                ` : ''}
              </div>
            </div>
          `).join('')}
        </div>
      ` : '<p class="text-xs text-slate-600 italic">No Received relay hops parsed from headers.</p>'}
    </div>
  `;

  lucide.createIcons({ nodes: [container] });
}

// ═══════════════════════════════════════════════════════════════
//  sudodeck — Contact CIRT Dispatch & PGP Actions
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  // PGP Copy Button
  const copyPgpBtn = document.getElementById('btn-copy-pgp');
  if (copyPgpBtn) {
    copyPgpBtn.addEventListener('click', () => {
      copyToClipboard('9B4E 72F1 A830 DC65 1904 449E F5A1 3302 9D77 B81C', copyPgpBtn);
    });
  }

  // Contact Form Submission
  const contactForm = document.getElementById('contact-form');
  if (contactForm) {
    contactForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-submit-contact');
      const name = document.getElementById('contact-name')?.value.trim();
      const email = document.getElementById('contact-email')?.value.trim();
      const category = document.getElementById('contact-category')?.value;
      const priority = document.getElementById('contact-priority')?.value;
      const subject = document.getElementById('contact-subject')?.value.trim();
      const message = document.getElementById('contact-message')?.value.trim();

      if (!name || !email || !subject || !message) {
        showToast('Please complete all required fields', 'warning');
        return;
      }

      const origHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i><span>Encrypting & Sending...</span>`;
      if (window.lucide) lucide.createIcons({ nodes: [btn] });

      try {
        const response = await fetch('/api/contact', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, category, priority, subject, message }),
        });
        const data = await response.json();

        const ticketId = data.ticketId || `SD-${Math.random().toString(36).substring(2, 8).toUpperCase()}-${Date.now().toString().slice(-4)}`;
        const refEl = document.getElementById('contact-ref-id');
        const alertEl = document.getElementById('contact-success-alert');

        if (refEl) refEl.textContent = ticketId;
        if (alertEl) {
          alertEl.classList.remove('hidden');
          if (window.lucide) lucide.createIcons({ nodes: [alertEl] });
        }

        contactForm.reset();
        showToast(`Transmission confirmed! Reference: ${ticketId}`, 'success', 5000);
      } catch (err) {
        showToast('Failed to dispatch message. Please try directly via email: soc@sudodeck.internal', 'error', 5000);
      } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
        if (window.lucide) lucide.createIcons({ nodes: [btn] });
      }
    });
  }

  // Smooth scroll if URL has #about or #contact
  if (window.location.hash) {
    const target = document.querySelector(window.location.hash);
    if (target) {
      setTimeout(() => {
        target.scrollIntoView({ behavior: 'smooth' });
      }, 300);
    }
  }
});


