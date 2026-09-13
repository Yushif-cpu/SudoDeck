// ═══════════════════════════════════════════════════════════════
//  ThreatIntel — Dedicated MAC & OUI Reconnaissance Frontend
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initMacSearch();
  initQuickPills();
  initInputHelpers();
  initRecentMacs();
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
  try {
    lucide.createIcons({ nodes: [toast] });
  } catch (_) {}

  setTimeout(() => {
    toast.style.animation = 'slideOutRight 0.3s ease-out forwards';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Copy to Clipboard ───────────────────────────────────────────
window.copyToClipboard = function(text, btn) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.innerHTML;
    btn.classList.add('copied');
    btn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i> <span class="text-emerald-300">Copied</span>`;
    try {
      lucide.createIcons({ nodes: [btn] });
    } catch (_) {}
    showToast(`Copied "${text}" to clipboard`, 'success', 2000);
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = original;
      try {
        lucide.createIcons({ nodes: [btn] });
      } catch (_) {}
    }, 2000);
  }).catch(() => {
    showToast('Failed to copy to clipboard', 'error');
  });
};

function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(str || '').replace(/[&<>"']/g, (m) => map[m]);
}

// ── Skeleton Loader ─────────────────────────────────────────────
function showSkeleton(container) {
  if (!container) return;
  container.innerHTML = `
    <div class="card p-6 animate-fade-in space-y-6">
      <div class="flex items-center justify-between">
        <div class="space-y-2">
          <div class="skeleton h-8 w-72 rounded-lg"></div>
          <div class="skeleton h-4 w-44 rounded"></div>
        </div>
        <div class="skeleton h-10 w-32 rounded-xl"></div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="skeleton h-36 rounded-xl"></div>
        <div class="skeleton h-36 rounded-xl"></div>
        <div class="skeleton h-36 rounded-xl"></div>
      </div>
      <div class="skeleton h-44 rounded-xl"></div>
    </div>
  `;
}

// ── Input Helpers ───────────────────────────────────────────────
function initInputHelpers() {
  const input = document.getElementById('mac-input');
  const clearBtn = document.getElementById('mac-clear-btn');
  if (!input || !clearBtn) return;

  input.addEventListener('input', () => {
    clearBtn.classList.toggle('hidden', !input.value.trim());
  });

  clearBtn.addEventListener('click', () => {
    input.value = '';
    clearBtn.classList.add('hidden');
    input.focus();
  });
}

// ── Search & API Integration ────────────────────────────────────
let isSearching = false;

async function performMacLookup(rawMac) {
  const mac = (rawMac || '').trim();
  if (!mac) return;

  const input = document.getElementById('mac-input');
  const submitBtn = document.getElementById('mac-submit-btn');
  const clearBtn = document.getElementById('mac-clear-btn');
  const resultsContainer = document.getElementById('mac-results');
  const pills = document.querySelectorAll('.quick-mac-pill');

  if (input) {
    input.value = mac;
    if (clearBtn) clearBtn.classList.remove('hidden');
  }

  // Visual active indication on preset pills
  const cleanCompare = mac.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  pills.forEach((p) => {
    const pillMac = (p.getAttribute('data-mac') || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();
    const isMatch = pillMac.length > 0 && cleanCompare.startsWith(pillMac.slice(0, 6));
    p.classList.toggle('!border-cyan-500', isMatch);
    p.classList.toggle('!bg-cyan-500/20', isMatch);
    p.classList.toggle('shadow-lg', isMatch);
  });

  if (isSearching) return;
  isSearching = true;

  const originalBtn = submitBtn ? submitBtn.innerHTML : '';
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<div class="spinner"></div><span>Querying Registry...</span>`;
  }

  showSkeleton(resultsContainer);

  try {
    const res = await fetch('/api/mac-lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac }),
    });

    const body = await res.json();

    if (!res.ok || !body.success) {
      const errMsg = body.error?.message || body.error || `MAC query failed (${res.status})`;
      throw new Error(errMsg);
    }

    renderMacResult(body.data || body);

    if (window.ThreatIntelHistory) {
      ThreatIntelHistory.add('mac', mac);
      renderRecentMacs();
    }

    // Update browser URL without full page reload
    try {
      const newUrl = `${window.location.pathname}?mac=${encodeURIComponent(mac)}`;
      window.history.pushState({ mac }, '', newUrl);
    } catch (_) {}

  } catch (err) {
    resultsContainer.innerHTML = `
      <div class="card p-8 border-rose-500/40 bg-rose-500/5 animate-fade-in text-center max-w-2xl mx-auto">
        <div class="w-14 h-14 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center mx-auto mb-4">
          <i data-lucide="alert-triangle" class="w-7 h-7 text-rose-400"></i>
        </div>
        <h3 class="text-base font-bold text-rose-300">MAC Address Investigation Failed</h3>
        <p class="text-xs text-slate-300 mt-2 leading-relaxed">${escapeHtml(err.message)}</p>
        <div class="mt-5 flex items-center justify-center gap-2">
          <button type="button" class="btn-secondary !text-xs !py-1.5 !px-4" onclick="document.getElementById('mac-input').focus()">
            Modify Address
          </button>
          <button type="button" class="btn-primary !text-xs !py-1.5 !px-4 !bg-cyan-600 hover:!bg-cyan-500" onclick="performMacLookup('${escapeHtml(mac)}')">
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
      submitBtn.innerHTML = originalBtn || `<i data-lucide="search" class="w-4 h-4"></i><span>Lookup MAC</span>`;
      try {
        lucide.createIcons({ nodes: [submitBtn] });
      } catch (_) {}
    }
  }
}

window.performMacLookup = performMacLookup;

function initMacSearch() {
  const form = document.getElementById('mac-search-form');
  const input = document.getElementById('mac-input');

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = input ? input.value.trim() : '';
      if (val) {
        performMacLookup(val);
      }
    });
  }
}

function initQuickPills() {
  const pills = document.querySelectorAll('.quick-mac-pill');
  pills.forEach((pill) => {
    pill.addEventListener('click', (e) => {
      e.preventDefault();
      const mac = pill.getAttribute('data-mac');
      if (mac) {
        performMacLookup(mac.trim());
      }
    });
  });
}

function checkUrlParams() {
  const params = new URLSearchParams(window.location.search);
  const macParam = params.get('mac') || params.get('q');
  if (macParam) {
    performMacLookup(macParam.trim());
  }
}

function renderRecentMacs() {
  const container = document.getElementById('recent-macs-container');
  const list = document.getElementById('recent-macs-list');
  if (!container || !list || !window.ThreatIntelHistory) return;

  const items = ThreatIntelHistory.get('mac');
  if (!items.length) {
    container.classList.add('hidden');
    list.innerHTML = '';
    return;
  }

  container.classList.remove('hidden');
  list.innerHTML = items.map((m) => `
    <button type="button" class="recent-chip" data-recent-mac="${escapeHtml(m)}">
      <i data-lucide="history" class="w-3 h-3 text-slate-500"></i>
      <span class="font-mono text-xs font-semibold text-slate-300 uppercase">${escapeHtml(m)}</span>
    </button>
  `).join('');

  list.querySelectorAll('[data-recent-mac]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetMac = btn.getAttribute('data-recent-mac');
      if (targetMac) performMacLookup(targetMac);
    });
  });

  try {
    lucide.createIcons({ nodes: [list] });
  } catch (_) {}
}

function initRecentMacs() {
  renderRecentMacs();
  const clearBtn = document.getElementById('btn-clear-mac-history');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (window.ThreatIntelHistory) {
        ThreatIntelHistory.clear('mac');
        renderRecentMacs();
        showToast('MAC search history cleared', 'info', 2000);
      }
    });
  }
}

window.addEventListener('popstate', (e) => {
  if (e.state && e.state.mac) {
    performMacLookup(e.state.mac);
  }
});

// ── Render Hardware Result ──────────────────────────────────────
function renderMacResult(data) {
  if (!data) return;
  const container = document.getElementById('mac-results');
  if (!container) return;

  const vendorName = data.vendor || 'Unknown Manufacturer';
  const isFound = data.found !== false;
  const oui = data.oui || {};
  const formats = data.formats || {};
  const char = data.characteristics || {};
  const details = data.details || {};

  const isMulticast = char.castType === 'Multicast';
  const isLocal = (char.administrationType || '').includes('LAA');

  container.innerHTML = `
    <!-- Top Identity Header Banner -->
    <div class="card p-6 animate-fade-in border-slate-700/80 bg-gradient-to-r from-surface-800 via-surface-700/50 to-surface-800 shadow-xl">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div class="flex flex-wrap items-center gap-2.5">
            <h2 class="text-2xl font-bold text-white tracking-tight">${escapeHtml(vendorName)}</h2>
            <span class="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold ${
              isFound
                ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
            }">
              ${isFound ? 'IEEE Registered OUI' : 'Unregistered / Private'}
            </span>
            ${data.isCached ? `
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-surface-700 text-slate-400 border border-slate-700">
                Cached Result
              </span>
            ` : ''}
          </div>
          <p class="text-xs text-slate-400 mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono">
            <span>OUI Prefix: <strong class="text-cyan-300 font-bold">${escapeHtml(oui.colon || 'N/A')}</strong></span>
            ${data.nicBytes ? `<span>Device NIC: <strong class="text-slate-200">${escapeHtml(data.nicBytes)}</strong></span>` : ''}
            ${details.country ? `<span>Origin: <strong class="text-slate-300 font-sans font-semibold">${escapeHtml(details.country)}</strong></span>` : ''}
          </p>
        </div>

        <div class="flex items-center gap-2">
          <button
            type="button"
            class="btn-secondary !text-xs !py-2 !px-3.5 flex items-center gap-1.5"
            onclick="copyToClipboard('${escapeHtml(formats.colon || data.rawInput)}', this)"
          >
            <i data-lucide="copy" class="w-3.5 h-3.5"></i> Copy Standard MAC
          </button>
          <a
            href="https://standards.ieee.org/products-programs/regauth/"
            target="_blank"
            rel="noopener noreferrer"
            class="btn-primary !text-xs !py-2 !px-3.5 !bg-surface-700 !border-slate-600 hover:!bg-surface-600 flex items-center gap-1.5"
          >
            <span>IEEE Registry</span>
            <i data-lucide="external-link" class="w-3.5 h-3.5 text-slate-400"></i>
          </a>
        </div>
      </div>
    </div>

    <!-- 3 Core Telemetry Cards -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 animate-fade-in">

      <!-- Card 1: Manufacturer Profile -->
      <div class="card p-5 border-slate-700/60 flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <i data-lucide="building-2" class="w-4 h-4 text-cyan-400"></i>
              Manufacturer Profile
            </span>
            <span class="text-[10px] font-mono text-cyan-400 uppercase font-bold">24-bit OUI</span>
          </div>

          <div class="space-y-3 text-xs mt-3">
            <div>
              <span class="text-slate-400 block text-[11px]">Organization / Vendor:</span>
              <span class="font-semibold text-white text-sm">${escapeHtml(vendorName)}</span>
            </div>
            <div>
              <span class="text-slate-400 block text-[11px]">Assigned OUI Block:</span>
              <code class="font-mono text-xs text-cyan-300 font-bold bg-surface-900 px-2 py-0.5 rounded border border-slate-700/50">${escapeHtml(oui.colon || 'N/A')}</code>
            </div>
            ${details.category ? `
              <div>
                <span class="text-slate-400 block text-[11px]">Hardware Class:</span>
                <span class="text-slate-200 font-medium">${escapeHtml(details.category)}</span>
              </div>
            ` : ''}
          </div>
        </div>

        <div class="pt-3 border-t border-slate-800/80 mt-4 text-[11px] text-slate-500">
          First 3 octets managed by IEEE Registration Authority
        </div>
      </div>

      <!-- Card 2: Transmission & Scope -->
      <div class="card p-5 border-slate-700/60 flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <i data-lucide="radio" class="w-4 h-4 text-emerald-400"></i>
              Frame Characteristics
            </span>
            <span class="text-[10px] font-mono text-slate-500 uppercase">Layer 2 Bits</span>
          </div>

          <div class="space-y-3 mt-3">
            <div>
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs text-slate-400">Cast Type (I/G bit):</span>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
                  isMulticast
                    ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                    : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                }">
                  ${escapeHtml(char.castType || 'Unicast')}
                </span>
              </div>
              <p class="text-[11px] text-slate-400 leading-tight">${escapeHtml(char.castDescription || '')}</p>
            </div>

            <div class="pt-2 border-t border-slate-800/60">
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs text-slate-400">Scope Type (U/L bit):</span>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
                  isLocal
                    ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                    : 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                }">
                  ${escapeHtml(char.administrationType || 'UAA')}
                </span>
              </div>
              <p class="text-[11px] text-slate-400 leading-tight">${escapeHtml(char.administrationDescription || '')}</p>
            </div>
          </div>
        </div>

        <div class="pt-3 border-t border-slate-800/80 mt-4 text-[11px] text-slate-500">
          Decoded from 1st byte LSBs (IEEE 802)
        </div>
      </div>

      <!-- Card 3: OUI / NIC Decomposition -->
      <div class="card p-5 border-slate-700/60 flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <i data-lucide="layers" class="w-4 h-4 text-violet-400"></i>
              Bit Decomposition
            </span>
            <span class="text-[10px] font-mono text-slate-500 uppercase">48-bit EUI-48</span>
          </div>

          <div class="space-y-3 mt-3">
            <div class="grid grid-cols-2 gap-2 text-center font-mono text-xs">
              <div class="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/25">
                <span class="text-[10px] uppercase text-cyan-400 block font-sans font-bold">OUI (24 bits)</span>
                <span class="text-cyan-200 font-bold">${escapeHtml(oui.colon || 'N/A')}</span>
              </div>
              <div class="p-2 rounded-lg bg-slate-800/80 border border-slate-700/60">
                <span class="text-[10px] uppercase text-slate-400 block font-sans font-bold">NIC (24 bits)</span>
                <span class="text-slate-200 font-bold">${escapeHtml(data.nicBytes || 'XX:XX:XX')}</span>
              </div>
            </div>

            <div class="text-xs space-y-1.5 pt-1">
              <div class="flex items-center justify-between text-slate-400">
                <span>Address Type:</span>
                <span class="text-white font-medium">${data.isFullMac ? 'Complete 48-bit MAC' : '24-bit OUI Prefix'}</span>
              </div>
              <div class="flex items-center justify-between text-slate-400">
                <span>Total Bits:</span>
                <span class="text-white font-mono font-medium">${data.isFullMac ? '48 bits (6 octets)' : '24 bits (3 octets)'}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="pt-3 border-t border-slate-800/80 mt-4 text-[11px] text-slate-500">
          Standard Ethernet Frame Hardware Target
        </div>
      </div>

    </div>

    <!-- Multi-format Representations & Fast Copy -->
    <div class="card p-6 animate-fade-in border-slate-700/60">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <i data-lucide="code" class="w-4 h-4 text-cyan-400"></i>
          Standard Format Representations
        </h3>
        <span class="text-xs text-slate-500">Click to Copy</span>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">

        <!-- Format 1: Standard Colon -->
        <div class="net-val-box flex items-center justify-between p-3 bg-surface-900/90 hover:border-cyan-500/40 transition-colors">
          <div class="min-w-0 pr-2">
            <span class="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Standard Colon (Linux/Unix)</span>
            <code class="font-mono text-xs text-cyan-300 truncate block mt-0.5">${escapeHtml(formats.colon || 'N/A')}</code>
          </div>
          <button
            type="button"
            class="p-1.5 rounded bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-white border border-slate-700/60 flex-shrink-0"
            title="Copy Colon Format"
            onclick="copyToClipboard('${escapeHtml(formats.colon || '')}', this)"
          >
            <i data-lucide="copy" class="w-3.5 h-3.5"></i>
          </button>
        </div>

        <!-- Format 2: Hyphen (Windows) -->
        <div class="net-val-box flex items-center justify-between p-3 bg-surface-900/90 hover:border-cyan-500/40 transition-colors">
          <div class="min-w-0 pr-2">
            <span class="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Hyphen (Windows Format)</span>
            <code class="font-mono text-xs text-slate-200 truncate block mt-0.5">${escapeHtml(formats.hyphen || 'N/A')}</code>
          </div>
          <button
            type="button"
            class="p-1.5 rounded bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-white border border-slate-700/60 flex-shrink-0"
            title="Copy Hyphen Format"
            onclick="copyToClipboard('${escapeHtml(formats.hyphen || '')}', this)"
          >
            <i data-lucide="copy" class="w-3.5 h-3.5"></i>
          </button>
        </div>

        <!-- Format 3: Cisco Dot -->
        <div class="net-val-box flex items-center justify-between p-3 bg-surface-900/90 hover:border-cyan-500/40 transition-colors">
          <div class="min-w-0 pr-2">
            <span class="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Cisco IOS (Dotted Triple)</span>
            <code class="font-mono text-xs text-slate-200 truncate block mt-0.5">${escapeHtml(formats.cisco || 'N/A')}</code>
          </div>
          <button
            type="button"
            class="p-1.5 rounded bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-white border border-slate-700/60 flex-shrink-0"
            title="Copy Cisco Format"
            onclick="copyToClipboard('${escapeHtml(formats.cisco || '')}', this)"
          >
            <i data-lucide="copy" class="w-3.5 h-3.5"></i>
          </button>
        </div>

        <!-- Format 4: Raw Hex -->
        <div class="net-val-box flex items-center justify-between p-3 bg-surface-900/90 hover:border-cyan-500/40 transition-colors">
          <div class="min-w-0 pr-2">
            <span class="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Raw Hexadecimal (No Delimiters)</span>
            <code class="font-mono text-xs text-slate-300 truncate block mt-0.5">${escapeHtml(formats.raw || 'N/A')}</code>
          </div>
          <button
            type="button"
            class="p-1.5 rounded bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-white border border-slate-700/60 flex-shrink-0"
            title="Copy Raw Hex"
            onclick="copyToClipboard('${escapeHtml(formats.raw || '')}', this)"
          >
            <i data-lucide="copy" class="w-3.5 h-3.5"></i>
          </button>
        </div>

        <!-- Format 5: Decimal / Integer -->
        <div class="net-val-box flex items-center justify-between p-3 bg-surface-900/90 hover:border-cyan-500/40 transition-colors sm:col-span-2 lg:col-span-2">
          <div class="min-w-0 pr-2">
            <span class="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Decimal Integer Representation (Database BigInt)</span>
            <code class="font-mono text-xs text-amber-300 truncate block mt-0.5">${escapeHtml(formats.decimal || 'N/A')}</code>
          </div>
          <button
            type="button"
            class="p-1.5 rounded bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-white border border-slate-700/60 flex-shrink-0"
            title="Copy Decimal Value"
            onclick="copyToClipboard('${escapeHtml(formats.decimal || '')}', this)"
          >
            <i data-lucide="copy" class="w-3.5 h-3.5"></i>
          </button>
        </div>

      </div>
    </div>
  `;

  try {
    lucide.createIcons({ nodes: [container] });
  } catch (_) {
    try {
      lucide.createIcons();
    } catch (e) {}
  }
}
