// ═══════════════════════════════════════════════════════════════
//  ThreatIntel — Custom GTFOBins Explorer Frontend Logic
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initGTFOBinsExplorer();
});

// ── State & Cache ───────────────────────────────────────────────
const state = {
  binaries: [],
  selectedBinary: null,
  searchQuery: '',
  activeCategory: 'all',
  isLoadingList: false,
  isLoadingDetail: false,
};

const binaryCache = new Map();

// ── Category Definitions & Metadata ────────────────────────────
const CATEGORY_META = {
  shell: {
    label: 'Shell',
    title: 'Interactive Shell Spawn',
    badgeClass: 'func-badge-shell',
    borderClass: 'border-purple-500/30',
    textClass: 'text-purple-400',
    bgClass: 'bg-purple-500/10',
    icon: 'terminal',
    desc: 'Spawns an interactive Unix shell session or command prompt.',
  },
  sudo: {
    label: 'Sudo',
    title: 'Sudo Execution / Root Bypass',
    badgeClass: 'func-badge-sudo',
    borderClass: 'border-rose-500/30',
    textClass: 'text-rose-400',
    bgClass: 'bg-rose-500/10',
    icon: 'shield-alert',
    desc: 'Executes commands with elevated superuser privileges if permitted in sudoers.',
  },
  suid: {
    label: 'SUID',
    title: 'SUID Privilege Escalation',
    badgeClass: 'func-badge-suid',
    borderClass: 'border-amber-500/30',
    textClass: 'text-amber-400',
    bgClass: 'bg-amber-500/10',
    icon: 'lock',
    desc: 'Bypasses privilege dropping and retains effective UID 0 capabilities.',
  },
  'file-read': {
    label: 'File Read',
    title: 'Arbitrary File Read',
    badgeClass: 'func-badge-file-read',
    borderClass: 'border-cyan-500/30',
    textClass: 'text-cyan-400',
    bgClass: 'bg-cyan-500/10',
    icon: 'file-text',
    desc: 'Reads, dumps, or exfiltrates contents of protected files (e.g. /etc/shadow).',
  },
  'file-write': {
    label: 'File Write',
    title: 'Arbitrary File Write / Overwrite',
    badgeClass: 'func-badge-file-write',
    borderClass: 'border-emerald-500/30',
    textClass: 'text-emerald-400',
    bgClass: 'bg-emerald-500/10',
    icon: 'file-edit',
    desc: 'Writes or appends arbitrary payload content to sensitive system files.',
  },
  'reverse-shell': {
    label: 'Reverse Shell',
    title: 'Network Reverse Shell',
    badgeClass: 'func-badge-reverse-shell',
    borderClass: 'border-pink-500/30',
    textClass: 'text-pink-400',
    bgClass: 'bg-pink-500/10',
    icon: 'radio',
    desc: 'Connects back to a remote listening socket providing interactive shell access.',
  },
};

// ── Toast Notifications ─────────────────────────────────────────
function showToast(message, type = 'info', duration = 2500) {
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
    <i data-lucide="${icons[type] || 'info'}" class="w-4 h-4 flex-shrink-0"></i>
    <span class="text-xs font-semibold flex-1">${escapeHtml(message)}</span>
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

// ── Copy Command Helper ─────────────────────────────────────────
function copyCommand(btn, codeText) {
  if (!codeText) return;
  navigator.clipboard.writeText(codeText.trim()).then(() => {
    const original = btn.innerHTML;
    btn.classList.add('!border-emerald-500/50', '!text-emerald-400');
    btn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i> <span class="font-bold text-emerald-300">Copied</span>`;
    try {
      lucide.createIcons({ nodes: [btn] });
    } catch (_) {}
    showToast('Command copied to clipboard', 'success', 2000);

    setTimeout(() => {
      btn.classList.remove('!border-emerald-500/50', '!text-emerald-400');
      btn.innerHTML = original;
      try {
        lucide.createIcons({ nodes: [btn] });
      } catch (_) {}
    }, 2000);
  }).catch(() => {
    showToast('Failed to copy command', 'error');
  });
}

function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(str || '').replace(/[&<>"']/g, (m) => map[m]);
}

// ── Initialization ──────────────────────────────────────────────
async function initGTFOBinsExplorer() {
  setupEventListeners();
  await fetchCatalog();

  // Check URL query or hash for direct binary selection (e.g. #bash or ?bin=bash or ?q=bash)
  const urlParams = new URLSearchParams(window.location.search);
  const directBinary = urlParams.get('bin') || urlParams.get('q') || window.location.hash.replace('#', '');
  if (directBinary) {
    selectBinary(directBinary);
  } else if (state.binaries.length > 0) {
    // Default select first or 'find'
    const defaultBin = state.binaries.find((b) => b.name === 'find') ? 'find' : state.binaries[0].name;
    selectBinary(defaultBin);
  }
}

// ── Event Listeners ─────────────────────────────────────────────
function setupEventListeners() {
  const searchInput = document.getElementById('gtfo-search-input');
  const searchClear = document.getElementById('gtfo-search-clear');
  const categoryBtns = document.querySelectorAll('.category-filter-btn');
  const resetFilterBtn = document.getElementById('reset-filter-btn');
  const listContainer = document.getElementById('binaries-list-container');
  const detailContent = document.getElementById('detail-content');

  // Search Input live filter
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      state.searchQuery = searchInput.value.trim().toLowerCase();
      if (searchClear) {
        searchClear.classList.toggle('hidden', state.searchQuery.length === 0);
      }
      renderBinariesList();
    });
  }

  // Clear search
  if (searchClear) {
    searchClear.addEventListener('click', () => {
      if (searchInput) {
        searchInput.value = '';
        searchInput.focus();
      }
      state.searchQuery = '';
      searchClear.classList.add('hidden');
      renderBinariesList();
    });
  }

  // Category filter tabs
  categoryBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      categoryBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      state.activeCategory = btn.dataset.category;
      renderBinariesList();
    });
  });

  // Reset filter
  if (resetFilterBtn) {
    resetFilterBtn.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      state.searchQuery = '';
      if (searchClear) searchClear.classList.add('hidden');

      categoryBtns.forEach((b) => b.classList.remove('active'));
      document.querySelector('.category-filter-btn[data-category="all"]')?.classList.add('active');
      state.activeCategory = 'all';

      renderBinariesList();
    });
  }

  // 1. Delegated click on sidebar binary list
  if (listContainer) {
    listContainer.addEventListener('click', (e) => {
      const item = e.target.closest('.binary-item');
      if (item && item.dataset.binary) {
        selectBinary(item.dataset.binary);
      }
    });

    listContainer.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        const item = e.target.closest('.binary-item');
        if (item && item.dataset.binary) {
          e.preventDefault();
          selectBinary(item.dataset.binary);
        }
      }
    });
  }

  // 2. Delegated click for Copy Buttons in details panel
  if (detailContent) {
    detailContent.addEventListener('click', (e) => {
      const copyBtn = e.target.closest('.copy-code-btn');
      if (copyBtn) {
        const block = copyBtn.closest('.command-block');
        const codeEl = block ? block.querySelector('.cmd-code-text') : null;
        if (codeEl) {
          copyCommand(copyBtn, codeEl.textContent);
        }
      }
    });
  }

  // 3. Quick select buttons anywhere on page
  document.addEventListener('click', (e) => {
    const quickBtn = e.target.closest('.quick-select-btn');
    if (quickBtn && quickBtn.dataset.binary) {
      selectBinary(quickBtn.dataset.binary);
    }
  });

  // 4. Listen to browser forward/back or hash changes
  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.replace('#', '').trim().toLowerCase();
    if (hash && hash !== state.selectedBinary) {
      selectBinary(hash, false);
    }
  });
}

// ── Fetch Binaries Catalog ──────────────────────────────────────
async function fetchCatalog() {
  const listContainer = document.getElementById('binaries-list-container');
  const countLabel = document.getElementById('binary-count-label');
  const statTotal = document.getElementById('stat-total-binaries');

  state.isLoadingList = true;

  try {
    const res = await fetch('/api/gtfobins');
    const data = await res.json();

    if (!res.ok || !data.success) {
      throw new Error(data.error?.message || 'Failed to fetch GTFOBins catalog');
    }

    state.binaries = data.binaries || [];
    if (statTotal) statTotal.textContent = data.total || state.binaries.length;

    renderBinariesList();
  } catch (err) {
    if (listContainer) {
      listContainer.innerHTML = `
        <div class="p-6 text-center text-xs text-rose-400">
          <i data-lucide="alert-triangle" class="w-6 h-6 mx-auto mb-2 text-rose-500"></i>
          <p class="font-semibold">Unable to load catalog</p>
          <p class="text-slate-500 text-[11px] mt-1">${escapeHtml(err.message)}</p>
          <button type="button" onclick="fetchCatalog()" class="btn-secondary !text-xs !py-1 !px-3 mt-3">
            Retry
          </button>
        </div>
      `;
      try {
        lucide.createIcons({ nodes: [listContainer] });
      } catch (_) {}
    }
  } finally {
    state.isLoadingList = false;
  }
}

// ── Render Binaries Sidebar List ────────────────────────────────
function renderBinariesList() {
  const listContainer = document.getElementById('binaries-list-container');
  const countLabel = document.getElementById('binary-count-label');
  if (!listContainer) return;

  const q = state.searchQuery;
  const cat = state.activeCategory;

  const filtered = state.binaries.filter((b) => {
    // Search text match
    const matchText = !q || b.name.toLowerCase().includes(q) || (b.description && b.description.toLowerCase().includes(q));
    // Category match
    const matchCat = cat === 'all' || (b.functions && b.functions.includes(cat));
    return matchText && matchCat;
  });

  if (countLabel) {
    countLabel.textContent = `${filtered.length} of ${state.binaries.length} binaries`;
  }

  if (filtered.length === 0) {
    listContainer.innerHTML = `
      <div class="p-8 text-center text-xs text-slate-500 space-y-2">
        <i data-lucide="search-x" class="w-6 h-6 mx-auto text-slate-600"></i>
        <p class="font-medium text-slate-400">No matching binaries found</p>
        <p class="text-[11px] text-slate-600">Try a different search keyword or capability filter.</p>
      </div>
    `;
    try {
      lucide.createIcons({ nodes: [listContainer] });
    } catch (_) {}
    return;
  }

  listContainer.innerHTML = filtered.map((b) => {
    const isActive = state.selectedBinary === b.name;
    return `
      <div
        class="binary-item p-2.5 rounded-xl border border-slate-800/80 bg-surface-900/60 hover:bg-surface-800 hover:border-slate-700/80 cursor-pointer ${isActive ? 'active' : ''}"
        data-binary="${escapeHtml(b.name)}"
        role="button"
        tabindex="0"
      >
        <div class="flex items-center justify-between gap-2 pointer-events-none">
          <span class="binary-name font-mono font-bold text-xs text-white tracking-wide">
            ${escapeHtml(b.name)}
          </span>
          <span class="text-[10px] font-mono text-slate-500">
            ${b.functionCount || (b.functions ? b.functions.length : 0)} funcs
          </span>
        </div>

        <p class="text-[11px] text-slate-400 truncate mt-0.5 pointer-events-none" title="${escapeHtml(b.description)}">
          ${escapeHtml(b.description)}
        </p>

        <!-- Function Mini Badges -->
        <div class="flex flex-wrap gap-1 mt-2 pointer-events-none">
          ${(b.functions || []).map((f) => {
            const meta = CATEGORY_META[f] || { label: f, badgeClass: 'bg-surface-800 text-slate-400' };
            return `<span class="func-badge ${meta.badgeClass}">${meta.label}</span>`;
          }).join('')}
        </div>
      </div>
    `;
  }).join('');
}

// ── Select and Load Binary Details ──────────────────────────────
window.selectBinary = async function(binaryName, updateHash = true) {
  if (!binaryName) return;
  const cleanName = binaryName.trim().toLowerCase();
  state.selectedBinary = cleanName;

  // Update active highlight in left list
  document.querySelectorAll('.binary-item').forEach((el) => {
    el.classList.toggle('active', el.dataset.binary === cleanName);
  });

  // Update URL hash
  if (updateHash && history.replaceState) {
    history.replaceState(null, '', `#${cleanName}`);
  }

  if (window.ThreatIntelHistory) {
    ThreatIntelHistory.add('gtfobins', cleanName);
  }

  const placeholder = document.getElementById('detail-placeholder');
  const detailContent = document.getElementById('detail-content');

  if (placeholder) placeholder.classList.add('hidden');
  if (detailContent) detailContent.classList.remove('hidden');

  // If in cache, render immediately without spinner or lag!
  if (binaryCache.has(cleanName)) {
    renderBinaryDetails(binaryCache.get(cleanName));
    return;
  }

  detailContent.innerHTML = `
    <div class="card p-8 text-center text-xs text-slate-400 border-slate-800 animate-fade-in">
      <div class="spinner mx-auto mb-3"></div>
      <p class="font-mono text-sm text-white">Loading specifications for <strong>${escapeHtml(cleanName)}</strong>...</p>
    </div>
  `;

  try {
    const res = await fetch(`/api/gtfobins/${encodeURIComponent(cleanName)}`);
    const data = await res.json();

    if (!res.ok || !data.success || !data.data) {
      throw new Error(data.error?.message || 'Binary specifications not found');
    }

    binaryCache.set(cleanName, data.data);
    renderBinaryDetails(data.data);
  } catch (err) {
    detailContent.innerHTML = `
      <div class="card p-8 text-center text-xs border-rose-500/30 bg-rose-500/5 text-rose-300">
        <i data-lucide="alert-circle" class="w-8 h-8 mx-auto mb-2 text-rose-400"></i>
        <h4 class="text-sm font-bold text-white">Failed to load binary details</h4>
        <p class="text-[11px] text-slate-400 mt-1">${escapeHtml(err.message)}</p>
      </div>
    `;
    try {
      lucide.createIcons({ nodes: [detailContent] });
    } catch (_) {}
  }
};

// ── Render Binary Details View ──────────────────────────────────
function renderBinaryDetails(binary) {
  const container = document.getElementById('detail-content');
  if (!container) return;

  const funcs = binary.functions || {};
  const funcKeys = Object.keys(funcs);

  container.innerHTML = `
    <!-- ── Binary Header Card ── -->
    <div class="card p-6 border-amber-500/30 bg-gradient-to-r from-surface-850 via-surface-800 to-surface-850 shadow-2xl space-y-4 animate-fade-in">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div class="flex items-center gap-3">
          <div class="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shadow-inner flex-shrink-0">
            <i data-lucide="terminal" class="w-6 h-6"></i>
          </div>
          <div>
            <div class="flex items-center gap-2.5 flex-wrap">
              <h2 class="text-2xl font-extrabold text-white font-mono tracking-tight">${escapeHtml(binary.name)}</h2>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-surface-750 text-slate-300 border border-slate-700">
                ${funcKeys.length} Capabilities
              </span>
            </div>
            <p class="text-xs text-slate-400 mt-1 leading-relaxed">
              ${escapeHtml(binary.description)}
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <a
            href="https://gtfobins.github.io/gtfobins/${encodeURIComponent(binary.name)}/"
            target="_blank"
            rel="noopener noreferrer"
            class="btn-secondary !text-xs !py-1.5 !px-3 flex items-center gap-1.5 hover:!border-amber-500/40"
            title="Open upstream GTFOBins project"
          >
            <span>Upstream Docs</span>
            <i data-lucide="external-link" class="w-3 h-3 text-slate-400"></i>
          </a>
        </div>
      </div>

      <!-- Quick Capability Tags Bar -->
      <div class="flex flex-wrap items-center gap-2 pt-1">
        <span class="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Available Exploits:</span>
        ${funcKeys.map((k) => {
          const meta = CATEGORY_META[k] || { label: k, badgeClass: 'bg-surface-800 text-slate-300' };
          return `
            <a href="#func-${k}" class="func-badge ${meta.badgeClass} hover:opacity-80 transition-opacity">
              <i data-lucide="${meta.icon || 'check'}" class="w-3 h-3"></i>
              <span>${meta.label}</span>
            </a>
          `;
        }).join('')}
      </div>
    </div>

    <!-- ── Functions Detail Stack ── -->
    <div class="space-y-4">
      ${funcKeys.map((funcKey) => {
        const meta = CATEGORY_META[funcKey] || {
          label: funcKey.toUpperCase(),
          title: funcKey.toUpperCase(),
          borderClass: 'border-slate-700',
          textClass: 'text-amber-400',
          bgClass: 'bg-surface-800',
          icon: 'terminal',
          desc: '',
        };
        const commands = funcs[funcKey] || [];

        return `
          <div id="func-${funcKey}" class="card p-5 border ${meta.borderClass} bg-surface-850/90 shadow-xl space-y-4 animate-fade-in">

            <!-- Card Category Header -->
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
              <div class="flex items-center gap-2.5">
                <div class="w-8 h-8 rounded-lg ${meta.bgClass} border ${meta.borderClass} flex items-center justify-center ${meta.textClass}">
                  <i data-lucide="${meta.icon}" class="w-4 h-4"></i>
                </div>
                <div>
                  <div class="flex items-center gap-2">
                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">${escapeHtml(meta.title)}</h3>
                    <span class="px-2 py-0.2 rounded text-[10px] font-mono font-bold ${meta.badgeClass}">
                      ${meta.label}
                    </span>
                  </div>
                  <p class="text-[11px] text-slate-400">${escapeHtml(meta.desc)}</p>
                </div>
              </div>

              <span class="text-[11px] font-mono text-slate-500 font-medium">
                ${commands.length} ${commands.length === 1 ? 'syntax' : 'syntaxes'}
              </span>
            </div>

            <!-- Command Snippets -->
            <div class="space-y-3.5">
              ${commands.map((cmd) => {
                const escapedCode = escapeHtml(cmd.code);

                return `
                  <div class="command-block space-y-2">
                    <div class="flex items-center justify-between">
                      <h4 class="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                        <i data-lucide="chevron-right" class="w-3.5 h-3.5 ${meta.textClass}"></i>
                        ${escapeHtml(cmd.title || 'Execution Vector')}
                      </h4>
                      <button
                        type="button"
                        class="btn-secondary !text-xs !py-1 !px-2.5 flex items-center gap-1.5 transition-all copy-code-btn"
                        title="Copy command to clipboard"
                      >
                        <i data-lucide="copy" class="w-3.5 h-3.5"></i>
                        <span>Copy</span>
                      </button>
                    </div>

                    <!-- Code Block -->
                    <div class="relative group">
                      <pre class="bg-surface-900 p-3.5 rounded-xl font-mono text-xs text-amber-300 border border-slate-800/90 overflow-x-auto select-all leading-relaxed whitespace-pre-wrap break-all shadow-inner"><code class="cmd-code-text">${escapedCode}</code></pre>
                    </div>

                    ${cmd.description ? `
                      <p class="text-[11px] text-slate-400 leading-snug pl-1">
                        ${escapeHtml(cmd.description)}
                      </p>
                    ` : ''}
                  </div>
                `;
              }).join('<div class="border-t border-slate-800/60 pt-3"></div>')}
            </div>

          </div>
        `;
      }).join('')}
    </div>
  `;

  try {
    lucide.createIcons({ nodes: [container] });
  } catch (_) {}
}
