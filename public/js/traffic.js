// ═══════════════════════════════════════════════════════════════
//  SudoDeck OSINT — Web Traffic & Audience Intelligence Client Logic
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // ── Elements ───────────────────────────────────────────────────
  const form = document.getElementById('traffic-form');
  const domainInput = document.getElementById('target-domain-input');
  const bypassCacheCheck = document.getElementById('bypass-cache-checkbox');
  const submitBtn = document.getElementById('submit-btn');
  const btnText = document.getElementById('btn-text');
  const btnSpinner = document.getElementById('btn-spinner');

  const statusCard = document.getElementById('status-card');
  const resDomain = document.getElementById('res-domain');
  const resTimestamp = document.getElementById('res-timestamp');

  const resultsSection = document.getElementById('results-section');
  const metricGlobalRank = document.getElementById('metric-global-rank');
  const metricVisits = document.getElementById('metric-visits');
  const metricBounceRate = document.getElementById('metric-bounce-rate');
  const metricDuration = document.getElementById('metric-duration');
  const metricPagesPerVisit = document.getElementById('metric-pages-per-visit');
  const metricCategory = document.getElementById('metric-category');

  const trafficSourcesContainer = document.getElementById('traffic-sources-list');
  const topCountriesContainer = document.getElementById('top-countries-list');
  const rawJsonPre = document.getElementById('raw-json-output');

  const copyJsonBtn = document.getElementById('copy-json-btn');
  const copyShareLinkBtn = document.getElementById('copy-share-btn');
  const errorAlert = document.getElementById('error-alert');
  const errorMessage = document.getElementById('error-message');

  let currentResultData = null;

  // ── Preset Quick Buttons ─────────────────────────────────────────
  document.querySelectorAll('[data-preset-domain]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const preset = btn.getAttribute('data-preset-domain');
      if (preset && domainInput) {
        domainInput.value = preset;
        domainInput.focus();
        triggerSearch(preset, false);
      }
    });
  });

  // ── URL Search Param Support (?domain=example.com) ─────────────
  const urlParams = new URLSearchParams(window.location.search);
  const initialDomain = urlParams.get('domain') || urlParams.get('target');
  if (initialDomain && domainInput) {
    domainInput.value = initialDomain;
    triggerSearch(initialDomain, urlParams.get('refresh') === 'true');
  }

  // ── Form Submission ──────────────────────────────────────────────
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const raw = domainInput.value.trim();
      if (!raw) {
        showError('Please enter a target domain name (e.g., github.com)');
        return;
      }
      const forceFresh = bypassCacheCheck ? bypassCacheCheck.checked : false;
      triggerSearch(raw, forceFresh);
    });
  }

  // ── Search Execution ─────────────────────────────────────────────
  async function triggerSearch(rawDomain, forceFresh = false) {
    hideError();
    const cleanDomain = cleanDomainString(rawDomain);
    if (!cleanDomain) {
      showError('Please enter a valid domain format (e.g., example.com)');
      return;
    }

    setLoading(true);
    if (resultsSection) resultsSection.classList.add('hidden');
    if (statusCard) statusCard.classList.add('hidden');

    try {
      const res = await fetch('/api/check-traffic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: cleanDomain,
          forceFresh: Boolean(forceFresh),
        }),
      });

      const responseData = await res.json();

      if (!res.ok || !responseData.success) {
        const errObj = responseData?.error;
        let msg = 'An error occurred while retrieving traffic data.';
        if (typeof errObj === 'string') {
          msg = errObj;
        } else if (errObj && typeof errObj === 'object') {
          msg = errObj.message || JSON.stringify(errObj);
        }
        throw new Error(msg);
      }

      currentResultData = responseData;
      renderResults(responseData);

      // Update URL query string without reloading page
      const newUrl = new URL(window.location);
      newUrl.searchParams.set('domain', cleanDomain);
      if (forceFresh) {
        newUrl.searchParams.set('refresh', 'true');
      } else {
        newUrl.searchParams.delete('refresh');
      }
      window.history.replaceState({}, '', newUrl);

    } catch (err) {
      const displayMsg = (err && typeof err === 'object') ? (err.message || JSON.stringify(err)) : String(err);
      showError(displayMsg);
    } finally {
      setLoading(false);
    }
  }

  // ── Helper: Format numbers ───────────────────────────────────────
  function formatNumber(num) {
    if (num === null || num === undefined || num === '') return 'N/A';
    if (typeof num === 'string') {
      const parsed = parseFloat(num.replace(/,/g, ''));
      if (!isNaN(parsed) && !num.includes('M') && !num.includes('K') && !num.includes('B') && !num.includes('%')) {
        return parsed.toLocaleString('en-US');
      }
      return num;
    }
    if (typeof num === 'number') {
      return num.toLocaleString('en-US');
    }
    return String(num);
  }

  function formatPercent(val) {
    if (val === null || val === undefined || val === '') return 'N/A';
    if (typeof val === 'string' && val.includes('%')) {
      const parsed = parseFloat(val.replace('%', ''));
      return !isNaN(parsed) ? `${parsed.toFixed(1)}%` : val.trim();
    }
    const num = Number(val);
    if (!isNaN(num)) {
      if (num <= 1 && num > 0) {
        return `${(num * 100).toFixed(1)}%`;
      }
      return `${num.toFixed(1)}%`;
    }
    return String(val);
  }

  function formatDuration(val) {
    if (val === null || val === undefined || val === '') return 'N/A';
    if (typeof val === 'string' && val.includes(':')) return val;
    const num = Number(val);
    if (!isNaN(num) && num > 0) {
      const s = Math.round(num);
      const mins = Math.floor(s / 60);
      const remSec = s % 60;
      return `${String(mins).padStart(2, '0')}:${String(remSec).padStart(2, '0')}`;
    }
    return String(val);
  }

  // ── Render Results ───────────────────────────────────────────────
  function renderResults(payload) {
    const { domain, cached, cachedAt, fetchedAt, data } = payload;
    const tData = data || {};

    // 1. Status Card
    if (resDomain) resDomain.textContent = domain;

    if (resTimestamp) {
      const timeStr = cachedAt || fetchedAt || new Date().toISOString();
      resTimestamp.textContent = `Updated: ${new Date(timeStr).toLocaleString('en-US', { hour12: true })}`;
    }

    if (statusCard) statusCard.classList.remove('hidden');

    // 2. Metrics
    const globalRankVal = tData.globalRank || tData.rank || tData.global_rank;
    if (metricGlobalRank) {
      metricGlobalRank.textContent = globalRankVal ? `#${formatNumber(globalRankVal)}` : 'N/A';
    }

    const visitsVal = tData.totalVisits || tData.visits || tData.estimatedMonthlyVisits || tData.total_visits;
    if (metricVisits) {
      metricVisits.textContent = visitsVal ? formatNumber(visitsVal) : 'N/A';
    }

    const bounceVal = tData.bounceRate || tData.bounce_rate;
    if (metricBounceRate) {
      metricBounceRate.textContent = formatPercent(bounceVal);
    }

    const durationVal = tData.avgVisitDuration || tData.timeOnSite || tData.avg_visit_duration;
    if (metricDuration) {
      metricDuration.textContent = formatDuration(durationVal);
    }

    const pagesVal = tData.pagesPerVisit || tData.pages_per_visit || tData.pageViewsPerVisit;
    if (metricPagesPerVisit) {
      if (pagesVal !== null && pagesVal !== undefined && pagesVal !== '') {
        const pNum = Number(pagesVal);
        metricPagesPerVisit.textContent = !isNaN(pNum) ? pNum.toFixed(1) : String(pagesVal);
      } else {
        metricPagesPerVisit.textContent = 'N/A';
      }
    }

    const catVal = tData.categoryRank?.category || tData.category || tData.industry || 'General Internet';
    const catRank = tData.categoryRank?.rank || tData.categoryRank;
    if (metricCategory) {
      metricCategory.textContent = catRank && typeof catRank !== 'object' ? `${catVal} (#${catRank})` : catVal;
    }

    // 3. Traffic Channels Breakdown
    renderTrafficSources(tData.trafficSources || tData.traffic_sources || tData.channels);

    // 4. Top Countries
    renderTopCountries(tData.topCountries || tData.top_countries || tData.topCountryShares || tData.geography);

    // 5. Raw JSON Output
    if (rawJsonPre) {
      rawJsonPre.textContent = JSON.stringify(payload, null, 2);
    }

    if (resultsSection) {
      resultsSection.classList.remove('hidden');
      resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    if (window.lucide) {
      window.lucide.createIcons();
    }
  }

  // ── Render Traffic Sources ───────────────────────────────────────
  function renderTrafficSources(sources) {
    if (!trafficSourcesContainer) return;
    trafficSourcesContainer.innerHTML = '';

    if (!sources || typeof sources !== 'object' || Object.keys(sources).length === 0) {
      trafficSourcesContainer.innerHTML = `
        <div class="py-6 text-center text-xs text-slate-500 font-mono">
          No channel acquisition breakdown available for this domain.
        </div>`;
      return;
    }

    const channelMap = {
      direct: { color: 'bg-emerald-500', text: 'text-emerald-400', label: 'Direct' },
      searchorganic: { color: 'bg-blue-500', text: 'text-blue-400', label: 'Organic Search' },
      searchpaid: { color: 'bg-blue-400', text: 'text-blue-300', label: 'Paid Search' },
      search: { color: 'bg-blue-500', text: 'text-blue-400', label: 'Search Engines' },
      socialorganic: { color: 'bg-cyan-500', text: 'text-cyan-400', label: 'Social Networks' },
      socialpaid: { color: 'bg-cyan-400', text: 'text-cyan-300', label: 'Paid Social' },
      social: { color: 'bg-cyan-500', text: 'text-cyan-400', label: 'Social Networks' },
      referrals: { color: 'bg-purple-500', text: 'text-purple-400', label: 'Referrals' },
      referral: { color: 'bg-purple-500', text: 'text-purple-400', label: 'Referrals' },
      mail: { color: 'bg-amber-500', text: 'text-amber-400', label: 'Email / Mail' },
      genai: { color: 'bg-teal-400', text: 'text-teal-300', label: 'AI Referrals' },
      displayads: { color: 'bg-pink-500', text: 'text-pink-400', label: 'Display Ads' },
      paid: { color: 'bg-rose-500', text: 'text-rose-400', label: 'Paid Advertising' },
      affiliate: { color: 'bg-indigo-500', text: 'text-indigo-400', label: 'Affiliate Network' },
    };

    Object.entries(sources).forEach(([channelKey, rawShare]) => {
      let sharePercent = 0;
      if (typeof rawShare === 'number') {
        sharePercent = rawShare <= 1 ? rawShare * 100 : rawShare;
      } else if (typeof rawShare === 'string') {
        sharePercent = parseFloat(rawShare.replace('%', '')) || 0;
      }

      if (sharePercent < 0.01) return; // Skip 0% items

      const normalizedKey = channelKey.toLowerCase().replace(/[^a-z]/g, '');
      const conf = channelMap[normalizedKey] || {
        color: 'bg-slate-500',
        text: 'text-slate-300',
        label: channelKey.toUpperCase(),
      };

      const row = document.createElement('div');
      row.className = 'space-y-1.5';
      row.innerHTML = `
        <div class="flex items-center justify-between text-xs">
          <span class="font-medium text-slate-300 flex items-center gap-2">
            <span class="w-2 h-2 rounded-full ${conf.color}"></span>
            ${escapeHtml(conf.label)}
          </span>
          <span class="font-mono font-bold ${conf.text}">${sharePercent.toFixed(1)}%</span>
        </div>
        <div class="w-full bg-surface-900 rounded-full h-2 overflow-hidden border border-slate-800">
          <div class="${conf.color} h-2 rounded-full transition-all duration-700 ease-out" style="width: ${Math.min(Math.max(sharePercent, 1), 100)}%"></div>
        </div>
      `;
      trafficSourcesContainer.appendChild(row);
    });
  }

  // ── Render Top Countries ─────────────────────────────────────────
  function renderTopCountries(countries) {
    if (!topCountriesContainer) return;
    topCountriesContainer.innerHTML = '';

    const list = Array.isArray(countries) ? countries : [];
    if (list.length === 0) {
      topCountriesContainer.innerHTML = `
        <div class="py-6 text-center text-xs text-slate-500 font-mono">
          No geographical traffic distribution detected.
        </div>`;
      return;
    }

    list.slice(0, 6).forEach((item) => {
      const code = item.countryCode || item.CountryCode || item.code || item.country || 'N/A';
      const name = item.countryName || item.CountryName || item.name || code;
      let share = 0;
      const rawVal = item.Value !== undefined ? item.Value : item.share;
      if (typeof rawVal === 'number') {
        share = rawVal <= 1 ? rawVal * 100 : rawVal;
      } else if (typeof rawVal === 'string') {
        share = parseFloat(rawVal.replace('%', '')) || 0;
      }

      const row = document.createElement('div');
      row.className = 'flex items-center justify-between p-2.5 rounded-lg bg-surface-900 border border-slate-800/80 text-xs';
      row.innerHTML = `
        <div class="flex items-center gap-2.5 min-w-0">
          <span class="px-1.5 py-0.5 rounded bg-surface-800 border border-slate-700 font-mono font-bold text-slate-300 text-[10px]">
            ${escapeHtml(String(code).toUpperCase())}
          </span>
          <span class="font-medium text-white truncate">${escapeHtml(name)}</span>
        </div>
        <span class="font-mono font-bold text-emerald-400 shrink-0">${share.toFixed(1)}%</span>
      `;
      topCountriesContainer.appendChild(row);
    });
  }

  // ── Utilities ────────────────────────────────────────────────────
  function cleanDomainString(input) {
    if (!input) return '';
    return input.trim().toLowerCase().replace(/^[a-zA-Z]+:\/\//, '').split('/')[0].split('?')[0].split('#')[0].split(':')[0];
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[char]);
  }

  function setLoading(state) {
    if (submitBtn) submitBtn.disabled = state;
    if (domainInput) domainInput.disabled = state;
    if (btnSpinner) btnSpinner.classList.toggle('hidden', !state);
    if (btnText) btnText.textContent = state ? 'Analyzing...' : 'Analyze Traffic';
  }

  function showError(msg) {
    const text = typeof msg === 'object' && msg !== null ? (msg.message || JSON.stringify(msg)) : String(msg);
    if (errorMessage) errorMessage.textContent = text;
    if (errorAlert) {
      errorAlert.classList.remove('hidden');
      errorAlert.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }

  function hideError() {
    if (errorAlert) errorAlert.classList.add('hidden');
  }

  // ── Copy buttons ─────────────────────────────────────────────────
  if (copyJsonBtn) {
    copyJsonBtn.addEventListener('click', () => {
      if (!currentResultData) return;
      navigator.clipboard.writeText(JSON.stringify(currentResultData, null, 2));
      const originalText = copyJsonBtn.innerHTML;
      copyJsonBtn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i> Copied!`;
      if (window.lucide) window.lucide.createIcons();
      setTimeout(() => {
        copyJsonBtn.innerHTML = originalText;
        if (window.lucide) window.lucide.createIcons();
      }, 2000);
    });
  }

  if (copyShareLinkBtn) {
    copyShareLinkBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(window.location.href);
      const originalText = copyShareLinkBtn.innerHTML;
      copyShareLinkBtn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5 text-cyan-400"></i> Link Copied!`;
      if (window.lucide) window.lucide.createIcons();
      setTimeout(() => {
        copyShareLinkBtn.innerHTML = originalText;
        if (window.lucide) window.lucide.createIcons();
      }, 2000);
    });
  }
});
