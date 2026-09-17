// ══════════════════════════════════════════════════════════════════
//  SudoDeck — Social Media Footprint (Sherlock // Maigret OSINT)
// ══════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // DOM Elements
  const usernameInput = document.getElementById('sherlock-username-input');
  const btnRun = document.getElementById('btn-run-sherlock');
  const statsContainer = document.getElementById('sherlock-stats-container');
  const foundCountEl = document.getElementById('sherlock-found-count');
  const totalCountEl = document.getElementById('sherlock-total-count');
  const avgLatencyEl = document.getElementById('sherlock-avg-latency');
  const btnExport = document.getElementById('btn-export-results');
  const loadingHUD = document.getElementById('sherlock-loading');
  const loadingUsername = document.getElementById('sherlock-loading-username');
  const emptyPrompt = document.getElementById('sherlock-empty');
  const resultsGrid = document.getElementById('sherlock-results-grid');
  const demoTags = document.querySelectorAll('.btn-demo-tag');
  const tabs = document.querySelectorAll('.sherlock-tab');

  let currentResults = [];
  let currentFilter = 'all';

  // Helpers
  const setText = (el, text) => {
    if (el) el.textContent = text;
  };

  const setDisplay = (el, isVisible) => {
    if (!el) return;
    if (isVisible) {
      el.classList.remove('hidden');
    } else {
      el.classList.add('hidden');
    }
  };

  const copyToClipboard = (text, triggerBtn, successText = 'Copied!') => {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      if (!triggerBtn) return;
      const original = triggerBtn.textContent;
      triggerBtn.textContent = successText;
      triggerBtn.classList.add('text-[#00C897]', 'border-[#00C897]');
      setTimeout(() => {
        triggerBtn.textContent = original;
        triggerBtn.classList.remove('text-[#00C897]', 'border-[#00C897]');
      }, 2000);
    });
  };

  // Main Scan Execution
  const executeScan = async (rawTarget) => {
    const user = (rawTarget || '').trim().replace(/^@/, '');
    if (!user || user.length < 2) {
      if (usernameInput) usernameInput.focus();
      return;
    }

    if (usernameInput) usernameInput.value = user;

    // Update URL query string without reloading page
    const url = new URL(window.location);
    url.searchParams.set('u', user);
    window.history.replaceState({}, '', url);

    setDisplay(emptyPrompt, false);
    setDisplay(resultsGrid, false);
    setDisplay(statsContainer, false);
    setDisplay(loadingHUD, true);
    setText(loadingUsername, `@${user}`);

    try {
      const res = await fetch(`/api/sherlock?username=${encodeURIComponent(user)}`);
      const json = await res.json();

      if (json.success && json.data) {
        currentResults = json.data.results || [];
        setText(foundCountEl, json.data.totalFound || 0);
        setText(totalCountEl, json.data.totalScanned || 0);

        // Calculate avg latency
        if (currentResults.length > 0) {
          const totalMs = currentResults.reduce((acc, curr) => acc + (curr.responseTimeMs || 0), 0);
          const avg = Math.round(totalMs / currentResults.length);
          setText(avgLatencyEl, `~${avg}ms`);
        }

        updateTabCounts(currentResults);
        setDisplay(statsContainer, true);

        // Default to 'found' if any exist, else 'all'
        currentFilter = json.data.totalFound > 0 ? 'found' : 'all';
        updateActiveTabUI(currentFilter);
        renderCards(currentFilter);
      } else {
        setDisplay(emptyPrompt, true);
        setText(emptyPrompt, json.message || 'An error occurred during search.');
      }
    } catch (err) {
      console.error('Sherlock scan error:', err);
      setDisplay(emptyPrompt, true);
    } finally {
      setDisplay(loadingHUD, false);
    }
  };

  const updateTabCounts = (results) => {
    const counts = {
      all: results.length,
      found: results.filter(r => r.exists).length,
      Social: results.filter(r => r.category === 'Social').length,
      Developer: results.filter(r => r.category === 'Developer').length,
      Media: results.filter(r => r.category === 'Media').length,
      Gaming: results.filter(r => r.category === 'Gaming').length,
    };

    setText(document.getElementById('tab-count-all'), counts.all);
    setText(document.getElementById('tab-count-found'), counts.found);
    setText(document.getElementById('tab-count-social'), counts.Social);
    setText(document.getElementById('tab-count-developer'), counts.Developer);
    setText(document.getElementById('tab-count-media'), counts.Media);
    setText(document.getElementById('tab-count-gaming'), counts.Gaming);
  };

  const updateActiveTabUI = (activeFilter) => {
    tabs.forEach(tab => {
      if (tab.getAttribute('data-filter') === activeFilter) {
        tab.className = 'sherlock-tab px-3.5 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40 transition-colors';
      } else {
        tab.className = 'sherlock-tab px-3.5 py-1.5 rounded-lg bg-surface-850 text-slate-400 hover:text-white border border-slate-800 transition-colors';
      }
    });
  };

  const renderCards = (filter) => {
    if (!resultsGrid) return;
    resultsGrid.innerHTML = '';
    setDisplay(resultsGrid, true);

    let filtered = currentResults;
    if (filter === 'found') {
      filtered = currentResults.filter(r => r.exists);
    } else if (filter !== 'all') {
      filtered = currentResults.filter(r => r.category === filter);
    }

    if (filtered.length === 0) {
      resultsGrid.innerHTML = `
        <div class="col-span-full p-12 rounded-2xl bg-surface-900 border border-slate-800 text-center text-xs font-mono text-slate-400 space-y-2">
          <i data-lucide="filter-x" class="w-8 h-8 text-slate-600 mx-auto mb-1"></i>
          <div>No profiles found for this category or filter.</div>
        </div>
      `;
      if (window.lucide) window.lucide.createIcons({ root: resultsGrid });
      return;
    }

    filtered.forEach(item => {
      const card = document.createElement('div');
      const isFound = item.exists;

      card.className = `p-4 rounded-xl border transition-all duration-200 space-y-3 ${
        isFound
          ? 'bg-gradient-to-b from-surface-850 to-surface-900 border-emerald-500/40 shadow-[0_0_20px_rgba(16,185,129,0.12)]'
          : 'bg-surface-850/60 border-slate-800/80 opacity-75 hover:opacity-100'
      }`;

      card.innerHTML = `
        <div class="flex items-start justify-between gap-2">
          <div class="flex items-center gap-2.5">
            <div class="w-8 h-8 rounded-lg flex items-center justify-center ${
              isFound ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-slate-800 text-slate-500'
            }">
              <i data-lucide="${item.icon || 'globe'}" class="w-4 h-4"></i>
            </div>
            <div>
              <div class="text-xs font-bold text-white font-mono">${item.platform}</div>
              <div class="text-[10px] text-slate-400 font-mono">${item.category}</div>
            </div>
          </div>
          <span class="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold ${
            isFound
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 animate-pulse'
              : 'bg-slate-800 text-slate-500 border border-slate-700'
          }">
            ${isFound ? '🟢 FOUND' : 'NOT FOUND'}
          </span>
        </div>

        <div class="text-[11px] font-mono text-slate-400 truncate break-all bg-surface-900/60 px-2.5 py-1.5 rounded-lg border border-slate-800/60">
          ${item.url}
        </div>

        <div class="flex items-center gap-2 pt-1 font-mono text-xs">
          <a
            href="${item.url}"
            target="_blank"
            rel="noreferrer"
            class="flex-1 text-center py-2 px-3 rounded-lg font-bold transition-all text-xs flex items-center justify-center gap-1.5 ${
              isFound
                ? 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 shadow-sm'
                : 'bg-slate-800 hover:bg-slate-750 text-slate-400 hover:text-slate-200'
            }"
          >
            <span>Profile ↗</span>
          </a>
          <button
            type="button"
            class="btn-copy-card-url px-3 py-2 rounded-lg bg-surface-800 hover:bg-surface-750 text-slate-400 hover:text-white border border-slate-700 text-xs transition-colors"
            data-url="${item.url}"
          >
            Copy
          </button>
        </div>
      `;

      card.querySelector('.btn-copy-card-url').addEventListener('click', (e) => {
        copyToClipboard(e.currentTarget.getAttribute('data-url'), e.currentTarget, '✓');
      });

      resultsGrid.appendChild(card);
    });

    if (window.lucide) {
      window.lucide.createIcons({ root: resultsGrid });
    }
  };

  // Event Listeners
  if (btnRun && usernameInput) {
    btnRun.addEventListener('click', () => executeScan(usernameInput.value));
    usernameInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') executeScan(usernameInput.value);
    });
  }

  demoTags.forEach(tag => {
    tag.addEventListener('click', (e) => {
      const user = e.currentTarget.getAttribute('data-user');
      executeScan(user);
    });
  });

  tabs.forEach(tab => {
    tab.addEventListener('click', (e) => {
      const filter = e.currentTarget.getAttribute('data-filter');
      currentFilter = filter;
      updateActiveTabUI(filter);
      renderCards(filter);
    });
  });

  if (btnExport) {
    btnExport.addEventListener('click', () => {
      const found = currentResults.filter(r => r.exists);
      if (found.length === 0) {
        copyToClipboard('No profiles found.', btnExport, 'Empty!');
        return;
      }
      const text = found.map(f => `${f.platform}: ${f.url}`).join('\n');
      copyToClipboard(text, btnExport, 'Copied! ✓');
    });
  }

  // Check URL params on load (e.g. /social-footprint?u=by.orux)
  const urlParams = new URLSearchParams(window.location.search);
  const initialUser = urlParams.get('username') || urlParams.get('u');
  if (initialUser) {
    executeScan(initialUser);
  }
});
