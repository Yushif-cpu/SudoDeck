// ═══════════════════════════════════════════════════════════════
//  SudoDeck OSINT — Subdomain & Resource Discovery Client Logic
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // ── Elements ───────────────────────────────────────────────────
  const form = document.getElementById('subdomain-form');
  const domainInput = document.getElementById('target-domain-input');
  const submitBtn = document.getElementById('submit-btn');
  const btnText = document.getElementById('btn-text');
  const btnSpinner = document.getElementById('btn-spinner');

  const statusCard = document.getElementById('status-card');
  const targetBadge = document.getElementById('res-target-domain');
  const totalCountBadge = document.getElementById('res-total-count');
  const durationBadge = document.getElementById('res-duration');
  const crtBadge = document.getElementById('res-crt-status');
  const htBadge = document.getElementById('res-ht-status');

  const terminalSection = document.getElementById('terminal-section');
  const terminalList = document.getElementById('terminal-subdomain-list');
  const terminalCount = document.getElementById('terminal-count');
  const terminalFilter = document.getElementById('terminal-filter-input');
  const terminalShowingCount = document.getElementById('terminal-showing-count');

  const copyAllBtn = document.getElementById('copy-all-btn');
  const exportTxtBtn = document.getElementById('export-txt-btn');
  const exportJsonBtn = document.getElementById('export-json-btn');
  const errorAlert = document.getElementById('error-alert');
  const errorMessage = document.getElementById('error-message');

  let currentSubdomains = [];
  let currentTarget = '';

  // ── Preset Quick Buttons ─────────────────────────────────────────
  document.querySelectorAll('[data-preset-domain]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const preset = btn.getAttribute('data-preset-domain');
      if (preset && domainInput) {
        domainInput.value = preset;
        domainInput.focus();
        triggerSearch(preset);
      }
    });
  });

  // ── Form Submission ──────────────────────────────────────────────
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const domain = domainInput.value.trim();
      if (!domain) {
        showError('Please enter a target domain name (e.g., example.com)');
        return;
      }
      triggerSearch(domain);
    });
  }

  // ── Trigger Discovery ────────────────────────────────────────────
  async function triggerSearch(domain) {
    hideError();
    setLoading(true);

    try {
      const response = await fetch('/api/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'An error occurred during subdomain discovery');
      }

      currentTarget = data.target || domain;
      currentSubdomains = Array.isArray(data.subdomains) ? data.subdomains : [];

      renderResults(data);
    } catch (err) {
      showError(err.message || 'Failed to connect to reconnaissance server.');
    } finally {
      setLoading(false);
    }
  }

  // ── Render Results ───────────────────────────────────────────────
  function renderResults(data) {
    if (statusCard) statusCard.classList.remove('hidden');
    if (terminalSection) terminalSection.classList.remove('hidden');

    if (targetBadge) targetBadge.textContent = data.target;
    if (totalCountBadge) totalCountBadge.textContent = `${data.total} subdomains`;
    if (durationBadge) durationBadge.textContent = `${data.durationMs}ms`;

    // crt.sh status
    if (crtBadge) {
      const crt = data.sourcesStatus?.crtSh;
      if (crt?.success) {
        crtBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30';
        crtBadge.textContent = `crt.sh: ${crt.count} found`;
      } else {
        crtBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30';
        crtBadge.textContent = 'crt.sh: Failed';
      }
    }

    // HackerTarget status
    if (htBadge) {
      const ht = data.sourcesStatus?.hackerTarget;
      if (ht?.success) {
        htBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/15 text-purple-400 border border-purple-500/30';
        htBadge.textContent = `HackerTarget: ${ht.count} found`;
      } else {
        htBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30';
        htBadge.textContent = 'HackerTarget: Failed';
      }
    }

    if (terminalCount) {
      terminalCount.textContent = `${data.total} SUBDOMAINS`;
    }

    if (terminalFilter) {
      terminalFilter.value = '';
    }

    renderList(currentSubdomains);

    terminalSection?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ── Render Subdomain List ────────────────────────────────────────
  function renderList(list) {
    if (!terminalList) return;

    if (terminalShowingCount) {
      terminalShowingCount.textContent = `Showing: ${list.length} / ${currentSubdomains.length}`;
    }

    if (list.length === 0) {
      terminalList.innerHTML = `
        <div class="py-16 text-center text-slate-500 font-mono text-xs">
          <i data-lucide="search-x" class="w-8 h-8 mx-auto mb-2 text-slate-600"></i>
          No subdomains matching your filter criteria.
        </div>
      `;
      if (window.lucide) window.lucide.createIcons();
      return;
    }

    terminalList.innerHTML = list.map((item, idx) => {
      const sourcesHtml = (item.sources || []).map((src) => {
        const isCrt = src === 'crt.sh';
        const colorCls = isCrt
          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
          : 'bg-purple-500/10 text-purple-400 border-purple-500/25';
        return `<span class="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold uppercase tracking-wider border ${colorCls}">${escapeHtml(src)}</span>`;
      }).join(' ');

      const ipHtml = item.ip
        ? `<span class="text-[10px] px-2 py-0.5 rounded font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shrink-0 select-all">${escapeHtml(item.ip)}</span>`
        : '';

      return `
        <div class="py-2.5 px-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 rounded-lg hover:bg-slate-800/40 transition-colors group">
          <div class="flex items-center gap-2.5 min-w-0 flex-1">
            <span class="text-slate-600 text-[11px] font-mono select-none w-7 text-right shrink-0">
              ${idx + 1}.
            </span>
            <a
              href="https://${encodeURIComponent(item.subdomain)}"
              target="_blank"
              rel="noopener noreferrer"
              class="text-xs sm:text-sm font-mono text-amber-300 group-hover:text-amber-200 font-semibold truncate hover:underline flex items-center gap-1.5"
              title="Open: https://${escapeHtml(item.subdomain)}"
            >
              <span>${escapeHtml(item.subdomain)}</span>
              <i data-lucide="external-link" class="w-3 h-3 opacity-50 group-hover:opacity-100 transition-opacity shrink-0"></i>
            </a>
            ${ipHtml}
          </div>

          <div class="flex items-center gap-2 self-end sm:self-auto shrink-0">
            ${sourcesHtml}
            <button
              type="button"
              data-copy-text="${escapeHtml(item.subdomain)}"
              class="copy-single-btn px-2 py-1 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-all cursor-pointer flex items-center gap-1 border border-slate-700"
              title="Copy subdomain"
            >
              <i data-lucide="copy" class="w-3 h-3"></i>
              <span>Copy</span>
            </button>
          </div>
        </div>
      `;
    }).join('');

    if (window.lucide) window.lucide.createIcons();

    // Attach single copy listeners
    terminalList.querySelectorAll('.copy-single-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const text = btn.getAttribute('data-copy-text');
        if (text) {
          navigator.clipboard.writeText(text);
          const original = btn.innerHTML;
          btn.innerHTML = `<span class="text-emerald-400 font-bold">✓ Copied</span>`;
          setTimeout(() => {
            btn.innerHTML = original;
            if (window.lucide) window.lucide.createIcons();
          }, 1500);
        }
      });
    });
  }

  // ── Filter Input Listener ────────────────────────────────────────
  if (terminalFilter) {
    terminalFilter.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      if (!q) {
        renderList(currentSubdomains);
        return;
      }
      const filtered = currentSubdomains.filter((item) =>
        item.subdomain.toLowerCase().includes(q) ||
        (item.ip && item.ip.includes(q)) ||
        (item.sources && item.sources.some((s) => s.toLowerCase().includes(q)))
      );
      renderList(filtered);
    });
  }

  // ── Copy All Button ──────────────────────────────────────────────
  if (copyAllBtn) {
    copyAllBtn.addEventListener('click', () => {
      if (currentSubdomains.length === 0) return;
      const text = currentSubdomains.map((s) => s.subdomain).join('\n');
      navigator.clipboard.writeText(text);
      const originalText = copyAllBtn.innerHTML;
      copyAllBtn.innerHTML = `<span>✓ Copied All!</span>`;
      setTimeout(() => {
        copyAllBtn.innerHTML = originalText;
      }, 2000);
    });
  }

  // ── Export TXT Button ────────────────────────────────────────────
  if (exportTxtBtn) {
    exportTxtBtn.addEventListener('click', () => {
      if (currentSubdomains.length === 0) return;
      const content = currentSubdomains.map((s) => s.subdomain).join('\n');
      downloadFile(content, `${currentTarget}_subdomains.txt`, 'text/plain');
    });
  }

  // ── Export JSON Button ───────────────────────────────────────────
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener('click', () => {
      if (currentSubdomains.length === 0) return;
      const content = JSON.stringify({
        target: currentTarget,
        exportedAt: new Date().toISOString(),
        total: currentSubdomains.length,
        subdomains: currentSubdomains,
      }, null, 2);
      downloadFile(content, `${currentTarget}_subdomains.json`, 'application/json');
    });
  }

  // ── Download Utility ─────────────────────────────────────────────
  function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── UI States ────────────────────────────────────────────────────
  function setLoading(isLoading) {
    if (!submitBtn) return;
    submitBtn.disabled = isLoading;
    if (isLoading) {
      btnSpinner?.classList.remove('hidden');
      btnText.textContent = 'Discovering...';
    } else {
      btnSpinner?.classList.add('hidden');
      btnText.textContent = 'Launch Discovery';
    }
  }

  function showError(msg) {
    if (errorAlert && errorMessage) {
      errorMessage.textContent = msg;
      errorAlert.classList.remove('hidden');
    }
  }

  function hideError() {
    if (errorAlert) {
      errorAlert.classList.add('hidden');
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
