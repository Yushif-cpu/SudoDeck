// ═══════════════════════════════════════════════════════════════
//  SudoDeck Security Payload Manager — Client Logic
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // ── Elements ───────────────────────────────────────────────────
  const payloadList = document.getElementById('payload-list');
  const searchInput = document.getElementById('search-input');
  const clearSearchBtn = document.getElementById('clear-search-btn');
  const copyAllBtn = document.getElementById('copy-all-visible-btn');
  const terminalCount = document.getElementById('terminal-count');
  const terminalActiveCat = document.getElementById('terminal-active-cat');
  const footerStatusText = document.getElementById('footer-status-text');

  const statTotal = document.getElementById('stat-total');
  const statXss = document.getElementById('stat-xss');
  const statSqli = document.getElementById('stat-sqli');
  const statTraversal = document.getElementById('stat-traversal');
  const statCsrf = document.getElementById('stat-csrf');
  const statCommand = document.getElementById('stat-command');

  const countTabAll = document.getElementById('count-tab-all');
  const countTabXss = document.getElementById('count-tab-xss');
  const countTabSqli = document.getElementById('count-tab-sqli');
  const countTabTraversal = document.getElementById('count-tab-traversal');
  const countTabCsrf = document.getElementById('count-tab-csrf');
  const countTabCommand = document.getElementById('count-tab-command');

  const categoryTabs = document.querySelectorAll('.category-tab');

  let allPayloads = [];
  let currentCategory = 'all';
  let currentSearch = '';

  // ── Fetch Payloads from Backend API ────────────────────────────
  async function fetchPayloads() {
    try {
      payloadList.innerHTML = `
        <div class="py-16 text-center text-slate-500 text-xs">
          <span class="inline-block w-4 h-4 border-2 border-amber-500 border-t-transparent rounded-full animate-spin mr-2"></span>
          Synchronizing test vectors from API & SecLists repositories...
        </div>
      `;

      const res = await fetch('/api/payloads');
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to load`);
      const data = await res.json();
      allPayloads = data.payloads || [];

      updateStats();
      renderPayloads();
    } catch (err) {
      payloadList.innerHTML = `
        <div class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          Failed to load payload catalog: ${escapeHtml(err.message)}
        </div>
      `;
    }
  }

  // ── Update Telemetry Counts ────────────────────────────────────
  function updateStats() {
    const total = allPayloads.length;
    const xss = allPayloads.filter(p => p.category === 'XSS').length;
    const sqli = allPayloads.filter(p => p.category === 'SQLi').length;
    const traversal = allPayloads.filter(p => p.category === 'Traversal').length;
    const csrf = allPayloads.filter(p => p.category === 'CSRF').length;
    const command = allPayloads.filter(p => p.category === 'Command').length;

    if (statTotal) statTotal.textContent = total;
    if (statXss) statXss.textContent = xss;
    if (statSqli) statSqli.textContent = sqli;
    if (statTraversal) statTraversal.textContent = traversal;
    if (statCsrf) statCsrf.textContent = csrf;
    if (statCommand) statCommand.textContent = command;

    if (countTabAll) countTabAll.textContent = total;
    if (countTabXss) countTabXss.textContent = xss;
    if (countTabSqli) countTabSqli.textContent = sqli;
    if (countTabTraversal) countTabTraversal.textContent = traversal;
    if (countTabCsrf) countTabCsrf.textContent = csrf;
    if (countTabCommand) countTabCommand.textContent = command;
  }

  // ── Filter and Render Payload List ─────────────────────────────
  function getFilteredPayloads() {
    return allPayloads.filter(p => {
      const matchesCat = currentCategory === 'all' || p.category.toLowerCase() === currentCategory.toLowerCase();
      const q = currentSearch.toLowerCase().trim();
      const matchesSearch = !q ||
        p.title.toLowerCase().includes(q) ||
        p.payload.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.category.toLowerCase().includes(q) ||
        p.source.toLowerCase().includes(q);
      return matchesCat && matchesSearch;
    });
  }

  function renderPayloads() {
    const filtered = getFilteredPayloads();

    if (terminalCount) terminalCount.textContent = filtered.length;
    if (terminalActiveCat) terminalActiveCat.textContent = currentCategory.toUpperCase();
    if (footerStatusText) {
      footerStatusText.textContent = `Displaying ${filtered.length} of ${allPayloads.length} total test vectors`;
    }

    if (filtered.length === 0) {
      payloadList.innerHTML = `
        <div class="py-16 text-center text-slate-500 text-xs">
          No matching test vectors found for "${escapeHtml(currentSearch || currentCategory)}".
        </div>
      `;
      return;
    }

    payloadList.innerHTML = filtered.map(item => {
      const isXss = item.category === 'XSS';
      const isSqli = item.category === 'SQLi';
      const isTrav = item.category === 'Traversal';
      const isCmd = item.category === 'Command';
      const badgeStyle = isXss
        ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
        : isSqli
        ? 'bg-purple-500/20 text-purple-400 border-purple-500/40'
        : isTrav
        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
        : isCmd
        ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
        : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40';

      return `
        <div class="p-4 rounded-xl bg-surface-900/70 border border-slate-800/80 hover:border-amber-500/40 hover:bg-surface-850/80 transition-all">
          <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div class="flex items-center gap-2">
              <span class="text-[10px] px-2 py-0.5 rounded font-bold border uppercase tracking-wider ${badgeStyle}">
                ${escapeHtml(item.category)}
              </span>
              <span class="text-xs font-semibold text-slate-200">
                ${escapeHtml(item.title)}
              </span>
            </div>
            <div class="flex items-center gap-2">
              <span class="text-[10px] text-slate-500 px-2 py-0.5 rounded bg-surface-800 border border-slate-800">
                ${escapeHtml(item.source)}
              </span>
              <button
                type="button"
                data-copy-payload="${escapeHtml(item.payload)}"
                class="copy-btn text-xs px-2.5 py-1 rounded-lg font-mono bg-surface-800 text-slate-300 border border-slate-700 hover:text-amber-400 hover:border-amber-500/40 transition-all flex items-center gap-1.5"
              >
                <i data-lucide="copy" class="w-3 h-3"></i>
                <span class="btn-lbl">Copy</span>
              </button>
            </div>
          </div>

          <div class="p-3 rounded-lg bg-surface-950 border border-slate-900/90 text-xs text-amber-300 font-mono break-all select-all selection:bg-amber-500/30">
            ${escapeHtml(item.payload)}
          </div>

          ${item.description ? `
            <p class="text-[11px] text-slate-400 mt-2 font-sans leading-relaxed">
              ${escapeHtml(item.description)}
            </p>
          ` : ''}
        </div>
      `;
    }).join('');

    // Attach copy button handlers
    payloadList.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const text = btn.getAttribute('data-copy-payload');
        const lbl = btn.querySelector('.btn-lbl');
        copyToClipboard(text, btn, lbl);
      });
    });

    if (window.lucide) {
      window.lucide.createIcons({ nodes: [payloadList] });
    }
  }

  // ── Copy Helper ────────────────────────────────────────────────
  async function copyToClipboard(text, button, labelEl) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedState(button, labelEl);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopiedState(button, labelEl);
    }
  }

  function setCopiedState(button, labelEl) {
    if (labelEl) labelEl.textContent = 'Copied!';
    button.classList.add('bg-emerald-500/20', 'text-emerald-300', 'border-emerald-500/40');
    button.classList.remove('bg-surface-800', 'text-slate-300', 'border-slate-700');

    setTimeout(() => {
      if (labelEl) labelEl.textContent = 'Copy';
      button.classList.remove('bg-emerald-500/20', 'text-emerald-300', 'border-emerald-500/40');
      button.classList.add('bg-surface-800', 'text-slate-300', 'border-slate-700');
    }, 1800);
  }

  // ── Tab Event Listeners ────────────────────────────────────────
  categoryTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      categoryTabs.forEach(t => {
        t.classList.remove('active', 'bg-amber-500/20', 'text-amber-400', 'border-amber-500/40');
        t.classList.add('text-slate-400', 'border-transparent');
      });

      tab.classList.add('active', 'bg-amber-500/20', 'text-amber-400', 'border-amber-500/40');
      tab.classList.remove('text-slate-400', 'border-transparent');

      currentCategory = tab.getAttribute('data-category') || 'all';
      renderPayloads();
    });
  });

  // ── Live Search Listener ───────────────────────────────────────
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      currentSearch = e.target.value;
      if (clearSearchBtn) {
        if (currentSearch) {
          clearSearchBtn.classList.remove('hidden');
        } else {
          clearSearchBtn.classList.add('hidden');
        }
      }
      renderPayloads();
    });
  }

  if (clearSearchBtn) {
    clearSearchBtn.addEventListener('click', () => {
      if (searchInput) {
        searchInput.value = '';
        currentSearch = '';
        clearSearchBtn.classList.add('hidden');
        renderPayloads();
        searchInput.focus();
      }
    });
  }

  // ── Copy All Filtered Vectors ──────────────────────────────────
  if (copyAllBtn) {
    copyAllBtn.addEventListener('click', () => {
      const filtered = getFilteredPayloads();
      if (filtered.length === 0) return;
      const combined = filtered.map(p => p.payload).join('\n');
      navigator.clipboard.writeText(combined).then(() => {
        const origText = copyAllBtn.querySelector('span').textContent;
        copyAllBtn.querySelector('span').textContent = 'Copied All!';
        setTimeout(() => {
          copyAllBtn.querySelector('span').textContent = origText;
        }, 1800);
      });
    });
  }




  // Helper: HTML entity escaping
  function escapeHtml(str) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(str || '').replace(/[&<>"']/g, m => map[m]);
  }

  // Initial fetch
  fetchPayloads();
});
