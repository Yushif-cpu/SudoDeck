// ═══════════════════════════════════════════════════════════════
//  SudoDeck — Cyber Intelligence Live Newsfeed Client Logic
// ═══════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // State
  let newsArticles = [];
  let filteredArticles = [];
  let selectedCategory = 'all';
  let searchQuery = '';
  let pollInterval = null;
  let isFetching = false;
  const POLL_CYCLE_SECONDS = 30; // Real-time silent background sync every 30s

  // DOM Elements
  const newsGrid = document.getElementById('news-grid');
  const newsCountBadge = document.getElementById('news-count-badge');
  const searchInput = document.getElementById('news-search-input');
  const searchClearBtn = document.getElementById('news-search-clear');
  const lastUpdatedEl = document.getElementById('news-last-updated');
  const filterPills = document.querySelectorAll('.category-filter-pill');
  const emptyState = document.getElementById('news-empty-state');
  const loadingSkeleton = document.getElementById('news-loading-skeleton');

  // Relative Time in English
  function getRelativeTimeString(dateInput) {
    if (!dateInput) return 'Just now';
    const date = new Date(dateInput);
    if (isNaN(date.getTime())) return 'Just now';

    const now = new Date();
    const diffSeconds = Math.floor((now - date) / 1000);

    if (diffSeconds < 45) return 'Just now';
    if (diffSeconds < 90) return '1 min ago';
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)} mins ago`;
    if (diffSeconds < 7200) return '1 hour ago';
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)} hours ago`;
    if (diffSeconds < 172800) return 'Yesterday';
    return `${Math.floor(diffSeconds / 86400)} days ago`;
  }

  // Format exact local time
  function formatClockTime(dateInput) {
    const d = dateInput ? new Date(dateInput) : new Date();
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  // Fetch News from Backend with CORS-Proxy Fallback
  async function fetchNews(isSilent = false) {
    if (isFetching) return;
    isFetching = true;

    try {
      let data = null;

      // Primary: Node.js /api/news endpoint
      try {
        const response = await fetch('/api/news');
        if (response.ok) {
          const resJson = await response.json();
          if (resJson && resJson.success && Array.isArray(resJson.items)) {
            data = resJson;
          }
        }
      } catch (err) {
        console.warn('Backend /api/news failed, attempting client-side fallback...', err);
      }

      // Client-Side CORS Fallback if backend is unreachable
      if (!data) {
        try {
          const fallbackUrl = 'https://api.rss2json.com/v1/api.json?rss_url=https%3A%2F%2Fthehackernews.com%2Frss.xml';
          const fbRes = await fetch(fallbackUrl);
          if (fbRes.ok) {
            const fbJson = await fbRes.json();
            if (fbJson.status === 'ok' && Array.isArray(fbJson.items)) {
              data = {
                success: true,
                cached: false,
                lastSync: new Date().toISOString(),
                feedInfo: {
                  source: 'The Hacker News',
                  url: 'https://thehackernews.com/rss.xml',
                },
                items: fbJson.items.map((item) => ({
                  title: item.title,
                  link: item.link,
                  pubDate: item.pubDate,
                  isoDate: new Date(item.pubDate).toISOString(),
                  author: item.author || 'The Hacker News',
                  description: item.description ? item.description.replace(/<[^>]+>/g, '').trim().substring(0, 240) + '...' : '',
                  thumbnail: item.thumbnail || (item.enclosure && item.enclosure.link) || null,
                  categories: item.categories || [],
                  source: 'The Hacker News',
                })),
              };
            }
          }
        } catch (fbErr) {
          console.error('Fallback client proxy also failed:', fbErr);
        }
      }

      if (data && data.items && data.items.length > 0) {
        newsArticles = data.items;
        applyFilters();

        if (lastUpdatedEl) {
          lastUpdatedEl.textContent = formatClockTime(data.lastSync || new Date());
        }
      } else if (newsArticles.length === 0) {
        showErrorState('The newsfeed is currently unavailable. Retrying in background...');
      }
    } catch (error) {
      console.error('Fetch news error:', error);
      if (newsArticles.length === 0) {
        showErrorState('Failed to retrieve newsfeed data. Retrying in background...');
      }
    } finally {
      isFetching = false;
      if (loadingSkeleton) {
        loadingSkeleton.classList.add('hidden');
      }
    }
  }

  // Filter & Search Logic
  function applyFilters() {
    filteredArticles = newsArticles.filter((item) => {
      // Category check
      if (selectedCategory !== 'all') {
        const fullText = (item.title + ' ' + item.description + ' ' + (item.categories || []).join(' ')).toLowerCase();

        if (selectedCategory === 'vuln') {
          if (!fullText.includes('vulnerab') && !fullText.includes('flaw') && !fullText.includes('cve') && !fullText.includes('zero-day') && !fullText.includes('patch')) return false;
        } else if (selectedCategory === 'malware') {
          if (!fullText.includes('malware') && !fullText.includes('ransomware') && !fullText.includes('trojan') && !fullText.includes('spyware') && !fullText.includes('backdoor')) return false;
        } else if (selectedCategory === 'attacks') {
          if (!fullText.includes('attack') && !fullText.includes('breach') && !fullText.includes('hack') && !fullText.includes('phish') && !fullText.includes('campaign')) return false;
        } else if (selectedCategory === 'cloud') {
          if (!fullText.includes('cloud') && !fullText.includes('aws') && !fullText.includes('azure') && !fullText.includes('google') && !fullText.includes('passkey') && !fullText.includes('identity')) return false;
        }
      }

      // Search query check
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const inTitle = item.title && item.title.toLowerCase().includes(q);
        const inDesc = item.description && item.description.toLowerCase().includes(q);
        const inAuthor = item.author && item.author.toLowerCase().includes(q);
        const inCats = item.categories && item.categories.some((c) => c.toLowerCase().includes(q));
        if (!inTitle && !inDesc && !inAuthor && !inCats) return false;
      }

      return true;
    });

    renderNewsGrid();
  }

  // Render Grid
  function renderNewsGrid() {
    if (!newsGrid) return;

    if (newsCountBadge) {
      newsCountBadge.textContent = `${filteredArticles.length} Stories`;
    }

    if (filteredArticles.length === 0) {
      newsGrid.innerHTML = '';
      if (emptyState) emptyState.classList.remove('hidden');
      return;
    }

    if (emptyState) emptyState.classList.add('hidden');

    const html = filteredArticles
      .map((item) => {
        const relTime = getRelativeTimeString(item.isoDate || item.pubDate);
        const fallbackImg = `https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=600&q=80`;
        const imgSrc = item.thumbnail || fallbackImg;

        // Tags
        let tagsHtml = '';
        if (item.categories && item.categories.length > 0) {
          tagsHtml = item.categories
            .slice(0, 2)
            .map(
              (cat) =>
                `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700/60 truncate max-w-[120px]">${escapeHtml(
                  cat
                )}</span>`
            )
            .join('');
        }

        return `
          <article class="news-card flex flex-col justify-between group">
            <!-- Neon Top Accent Glow -->
            <div class="news-neon-glow"></div>

            <div>
              <!-- Thumbnail Banner with Fallback Protection -->
              <div class="news-thumbnail-wrap relative">
                <img
                  src="${escapeHtml(imgSrc)}"
                  alt="${escapeHtml(item.title)}"
                  loading="lazy"
                  onerror="this.onerror=null; this.src='https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=600&q=80';"
                  class="w-full h-full object-cover"
                />
                <div class="absolute inset-0 bg-gradient-to-t from-surface-900 via-transparent to-transparent opacity-80"></div>
                
                <!-- Badges over Image -->
                <div class="absolute top-3 left-3 right-3 flex items-center justify-between pointer-events-none">
                  <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-surface-900/90 backdrop-blur-md border border-emerald-500/40 text-[10px] font-mono font-bold text-emerald-400 shadow-md">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span>The Hacker News</span>
                  </div>
                  <span class="px-2 py-0.5 rounded-md bg-surface-900/85 backdrop-blur-md border border-slate-700/80 text-[10px] font-mono text-slate-300">
                    ${relTime}
                  </span>
                </div>
              </div>

              <!-- Content Body -->
              <div class="p-5">
                <div class="flex items-center gap-1.5 mb-2.5 flex-wrap">
                  ${tagsHtml}
                </div>

                <h3 class="text-base font-bold text-white group-hover:text-emerald-300 transition-colors leading-snug line-clamp-2 mb-2.5">
                  <a href="${escapeHtml(item.link)}" target="_blank" rel="noopener noreferrer" class="hover:underline focus:outline-none">
                    ${escapeHtml(item.title)}
                  </a>
                </h3>

                <p class="text-xs text-slate-400 leading-relaxed line-clamp-3">
                  ${escapeHtml(item.description || 'Click to read full coverage on source.')}
                </p>
              </div>
            </div>

            <!-- Card Footer -->
            <div class="px-5 pb-5 pt-2 flex items-center justify-between border-t border-slate-800/80 text-xs mt-2">
              <div class="flex items-center gap-1.5 text-[11px] text-slate-500 font-medium">
                <i data-lucide="clock" class="w-3.5 h-3.5 text-slate-400"></i>
                <span class="article-time-badge" data-date="${escapeHtml(item.isoDate || item.pubDate)}">${relTime}</span>
              </div>

              <a
                href="${escapeHtml(item.link)}"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 hover:text-emerald-200 text-xs font-semibold transition-all group/link"
              >
                <span>Read Full Article</span>
                <i data-lucide="external-link" class="w-3 h-3 group-hover/link:translate-x-0.5 transition-transform"></i>
              </a>
            </div>
          </article>
        `;
      })
      .join('');

    newsGrid.innerHTML = html;

    // Re-initialize Lucide Icons
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  }

  // Error state
  function showErrorState(msg) {
    if (!newsGrid) return;
    newsGrid.innerHTML = `
      <div class="col-span-full card p-8 text-center border-rose-500/30">
        <div class="w-12 h-12 rounded-2xl bg-rose-500/15 border border-rose-500/30 text-rose-400 flex items-center justify-center mx-auto mb-3.5">
          <i data-lucide="alert-circle" class="w-6 h-6"></i>
        </div>
        <h4 class="text-sm font-bold text-white mb-1.5">Live Feed Sync Interrupted</h4>
        <p class="text-xs text-slate-400 max-w-md mx-auto mb-4">${escapeHtml(msg)}</p>
        <button
          type="button"
          onclick="window.location.reload()"
          class="px-4 py-2 rounded-xl bg-surface-800 hover:bg-surface-700 border border-slate-700 text-xs font-semibold text-slate-200"
        >
          Reload Feed
        </button>
      </div>
    `;
    if (window.lucide) window.lucide.createIcons();
  }

  // Periodic Relative Time Refresh (every 10s)
  function refreshRelativeTimes() {
    const badges = document.querySelectorAll('.article-time-badge');
    badges.forEach((el) => {
      const d = el.getAttribute('data-date');
      if (d) {
        el.textContent = getRelativeTimeString(d);
      }
    });
  }

  // Escape HTML
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Event Listeners
  function initEventListeners() {
    // Search input
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.trim();
        if (searchClearBtn) {
          if (searchQuery) {
            searchClearBtn.classList.remove('hidden');
          } else {
            searchClearBtn.classList.add('hidden');
          }
        }
        applyFilters();
      });
    }

    // Search clear button
    if (searchClearBtn) {
      searchClearBtn.addEventListener('click', () => {
        if (searchInput) {
          searchInput.value = '';
          searchQuery = '';
          searchClearBtn.classList.add('hidden');
          searchInput.focus();
          applyFilters();
        }
      });
    }

    // Category pills
    filterPills.forEach((pill) => {
      pill.addEventListener('click', () => {
        filterPills.forEach((p) => {
          p.classList.remove('active', 'bg-emerald-500/20', 'text-emerald-300', 'border-emerald-500/40');
          p.classList.add('bg-surface-850', 'text-slate-400', 'border-slate-800');
        });

        pill.classList.remove('bg-surface-850', 'text-slate-400', 'border-slate-800');
        pill.classList.add('active', 'bg-emerald-500/20', 'text-emerald-300', 'border-emerald-500/40');

        selectedCategory = pill.getAttribute('data-category') || 'all';
        applyFilters();
      });
    });
  }

  // Setup Continuous Silent Real-Time Polling
  function startPolling() {
    // Initial fetch
    fetchNews(false);

    // Continuous real-time polling every 30 seconds
    pollInterval = setInterval(() => {
      fetchNews(true);
    }, POLL_CYCLE_SECONDS * 1000);

    // Relative Time updater every 10s
    setInterval(refreshRelativeTimes, 10000);
  }

  // DOM Content Loaded
  document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
    startPolling();
  });
})();
