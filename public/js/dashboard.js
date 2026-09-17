// ═══════════════════════════════════════════════════════════════
//  SudoDeck Threat Intelligence Platform — User Dashboard Controller
// ═══════════════════════════════════════════════════════════════

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Lucide Icons
    if (window.lucide) lucide.createIcons();

    // 2. Load User Profile & State
    const user = window.SudoDeckAuth.getUser();
    let historyItems = window.SudoDeckAuth.getHistory();
    let billingData = window.SudoDeckAuth.getBilling();
    let apiKeys = window.SudoDeckAuth.getApiKeys();

    // 3. Populate Header & Profile Info
    renderUserProfile(user);
    renderBillingProfile(billingData);
    renderHistoryTable(historyItems);
    renderApiKeysTable(apiKeys);
    setupTabNavigation();
    setupHistoryFilters();
    setupBillingForm();
    setupQuickScanner();
    setupApiKeyGenerator();
    setupExportActions();

    // ── Render User Profile Header ─────────────────────────────────
    function renderUserProfile(u) {
      document.getElementById('user-display-name').textContent = u.name || 'Alex Vance';
      document.getElementById('user-email-badge').textContent = u.email || 'alex.vance@sudodeck.io';
      document.getElementById('user-phone-badge').textContent = u.phone || '+1 (555) 234-8901';
      document.getElementById('user-role-badge').textContent = u.role || 'Lead Threat Hunter';
      
      const avatarImg = document.getElementById('user-avatar-img');
      const avatarFallback = document.getElementById('user-avatar-fallback');
      if (u.avatar) {
        avatarImg.src = u.avatar;
        avatarImg.classList.remove('hidden');
        avatarFallback.classList.add('hidden');
      } else {
        avatarFallback.textContent = (u.name || 'AV').split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
        avatarFallback.classList.remove('hidden');
        avatarImg.classList.add('hidden');
      }

      // Quota bar
      const quota = u.apiQuota || { used: 420, total: 1000 };
      const pct = Math.min(100, Math.round((quota.used / quota.total) * 100));
      document.getElementById('quota-text').textContent = `${quota.used} / ${quota.total} queries`;
      document.getElementById('quota-bar').style.width = `${pct}%`;
      document.getElementById('quota-percent').textContent = `${pct}%`;

      // Stat Counters
      const totalCount = historyItems.length;
      const maliciousCount = historyItems.filter(i => i.verdict === 'Malicious' || i.verdict === 'Critical').length;
      const cleanCount = historyItems.filter(i => i.verdict === 'Clean' || i.verdict === 'Low' || i.verdict === 'Informational').length;
      
      document.getElementById('stat-total-scans').textContent = totalCount;
      document.getElementById('stat-malicious-count').textContent = maliciousCount;
      document.getElementById('stat-clean-count').textContent = cleanCount;
      document.getElementById('stat-api-keys').textContent = apiKeys.length;
    }

    // ── Tab Navigation ─────────────────────────────────────────────
    function setupTabNavigation() {
      const tabBtns = document.querySelectorAll('[data-dashboard-tab]');
      const tabPanes = document.querySelectorAll('[data-tab-pane]');

      // Check hash or default to 'history'
      const activeHash = window.location.hash.replace('#', '') || 'history';

      function activateTab(tabId) {
        tabBtns.forEach(btn => {
          const isTarget = btn.getAttribute('data-dashboard-tab') === tabId;
          if (isTarget) {
            btn.className = 'dashboard-tab-btn active flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs sm:text-sm font-semibold text-white bg-surface-800 border border-emerald-500/30 shadow-[0_0_15px_rgba(52,211,153,0.1)] transition-all';
          } else {
            btn.className = 'dashboard-tab-btn flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs sm:text-sm font-medium text-slate-400 hover:text-slate-200 hover:bg-surface-850 transition-all';
          }
        });

        tabPanes.forEach(pane => {
          if (pane.getAttribute('data-tab-pane') === tabId) {
            pane.classList.remove('hidden');
          } else {
            pane.classList.add('hidden');
          }
        });

        window.location.hash = tabId;
        if (window.lucide) lucide.createIcons();
      }

      tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          activateTab(btn.getAttribute('data-dashboard-tab'));
        });
      });

      // Activate initial
      activateTab(activeHash);
    }

    // ── Investigation History Table ────────────────────────────────
    function renderHistoryTable(items) {
      const tbody = document.getElementById('history-table-body');
      const countLabel = document.getElementById('history-count-badge');
      const emptyState = document.getElementById('history-empty-state');

      countLabel.textContent = `${items.length} Records`;

      if (items.length === 0) {
        tbody.innerHTML = '';
        emptyState.classList.remove('hidden');
        return;
      }

      emptyState.classList.add('hidden');

      tbody.innerHTML = items.map(item => {
        const timeAgo = formatTimeAgo(new Date(item.timestamp));
        const iconName = getToolIcon(item.type);
        const verdictBadge = getVerdictBadge(item.verdict, item.badgeColor);
        const toolUrl = getToolUrl(item.type, item.query);

        return `
          <tr class="border-b border-slate-800/80 hover:bg-surface-850/60 transition-colors group">
            <!-- Tool & Indicator -->
            <td class="py-3.5 px-4">
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 rounded-lg bg-surface-800 border border-slate-700/60 flex items-center justify-center text-emerald-400 shrink-0">
                  <i data-lucide="${iconName}" class="w-4 h-4"></i>
                </div>
                <div>
                  <div class="text-xs font-bold text-white flex items-center gap-2">
                    <span>${escapeHtml(item.tool || 'Analysis')}</span>
                    <span class="text-[10px] font-mono text-slate-500 uppercase">${escapeHtml(item.type || 'IOC')}</span>
                  </div>
                  <div class="text-xs font-mono text-emerald-400 font-semibold tracking-wide truncate max-w-xs sm:max-w-md">
                    ${escapeHtml(item.query)}
                  </div>
                </div>
              </div>
            </td>

            <!-- Verdict -->
            <td class="py-3.5 px-4 whitespace-nowrap">
              ${verdictBadge}
            </td>

            <!-- Summary Details -->
            <td class="py-3.5 px-4 hidden md:table-cell text-xs text-slate-400 max-w-xs lg:max-w-sm truncate">
              ${escapeHtml(item.details || 'Investigation complete')}
            </td>

            <!-- Timestamp -->
            <td class="py-3.5 px-4 whitespace-nowrap text-xs text-slate-400 font-mono">
              <div class="flex items-center gap-1.5" title="${item.timestamp}">
                <i data-lucide="clock" class="w-3 h-3 text-slate-500"></i>
                <span>${timeAgo}</span>
              </div>
            </td>

            <!-- Actions -->
            <td class="py-3.5 px-4 text-right whitespace-nowrap">
              <div class="flex items-center justify-end gap-1.5">
                <a
                  href="${toolUrl}"
                  class="p-1.5 rounded-lg bg-surface-800 hover:bg-emerald-500/20 text-slate-400 hover:text-emerald-400 border border-slate-700/60 transition-colors"
                  title="Re-run investigation in live tool"
                >
                  <i data-lucide="external-link" class="w-3.5 h-3.5"></i>
                </a>
                <button
                  type="button"
                  data-inspect-id="${item.id}"
                  class="p-1.5 rounded-lg bg-surface-800 hover:bg-cyan-500/20 text-slate-400 hover:text-cyan-400 border border-slate-700/60 transition-colors"
                  title="Inspect raw payload and JSON"
                >
                  <i data-lucide="code" class="w-3.5 h-3.5"></i>
                </button>
                <button
                  type="button"
                  data-delete-id="${item.id}"
                  class="p-1.5 rounded-lg bg-surface-800 hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 border border-slate-700/60 transition-colors"
                  title="Remove from history"
                >
                  <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                </button>
              </div>
            </td>
          </tr>
        `;
      }).join('');

      // Wire up action buttons
      tbody.querySelectorAll('[data-inspect-id]').forEach(btn => {
        btn.addEventListener('click', () => {
          const id = btn.getAttribute('data-inspect-id');
          const targetItem = historyItems.find(i => i.id === id);
          if (targetItem) openInspectModal(targetItem);
        });
      });

      tbody.querySelectorAll('[data-delete-id]').forEach(btn => {
        btn.addEventListener('click', () => {
          const id = btn.getAttribute('data-delete-id');
          historyItems = window.SudoDeckAuth.deleteHistoryItem(id);
          renderHistoryTable(historyItems);
          renderUserProfile(window.SudoDeckAuth.getUser());
          showToast('Investigation record removed from local history.');
        });
      });

      if (window.lucide) lucide.createIcons();
    }

    function getToolIcon(type) {
      switch (type) {
        case 'ip': return 'radar';
        case 'domain': return 'globe';
        case 'file': return 'file-search';
        case 'traffic': return 'bar-chart-3';
        case 'social': return 'user-check';
        case 'cve': return 'flame';
        case 'mac': return 'cpu';
        case 'gtfobins': return 'terminal';
        default: return 'search';
      }
    }

    function getToolUrl(type, query) {
      const q = encodeURIComponent(query || '');
      switch (type) {
        case 'ip': return `/#ip?q=${q}`;
        case 'domain': return `/#domain?q=${q}`;
        case 'file': return `/siem#file?q=${q}`;
        case 'traffic': return `/traffic?domain=${q}`;
        case 'social': return `/social-footprint?username=${q}`;
        case 'cve': return `/cve?query=${q}`;
        case 'mac': return `/mac?mac=${q}`;
        default: return '/';
      }
    }

    function getVerdictBadge(verdict, color) {
      const v = (verdict || 'Informational').toUpperCase();
      if (v === 'MALICIOUS' || v === 'CRITICAL') {
        return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/15 border border-rose-500/30 text-rose-400"><span class="w-1.5 h-1.5 rounded-full bg-rose-400"></span>${escapeHtml(verdict)}</span>`;
      }
      if (v === 'SUSPICIOUS' || v === 'HIGH' || v === 'MEDIUM') {
        return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/15 border border-amber-500/30 text-amber-400"><span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>${escapeHtml(verdict)}</span>`;
      }
      if (v === 'CLEAN' || v === 'LOW' || v === 'SAFE') {
        return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 border border-emerald-500/30 text-emerald-400"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>${escapeHtml(verdict)}</span>`;
      }
      return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/15 border border-cyan-500/30 text-cyan-400"><span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>${escapeHtml(verdict || 'Info')}</span>`;
    }

    // ── History Filter & Search ────────────────────────────────────
    function setupHistoryFilters() {
      const searchInput = document.getElementById('history-search');
      const toolFilter = document.getElementById('history-tool-filter');
      const verdictFilter = document.getElementById('history-verdict-filter');
      const clearBtn = document.getElementById('clear-history-btn');

      function filterData() {
        const term = (searchInput.value || '').toLowerCase().trim();
        const selectedTool = toolFilter.value;
        const selectedVerdict = verdictFilter.value;

        const filtered = historyItems.filter(item => {
          const matchTerm = !term || item.query.toLowerCase().includes(term) || (item.details && item.details.toLowerCase().includes(term));
          const matchTool = !selectedTool || item.type === selectedTool;
          const matchVerdict = !selectedVerdict || (selectedVerdict === 'malicious' ? (item.verdict === 'Malicious' || item.verdict === 'Critical') : selectedVerdict === 'clean' ? (item.verdict === 'Clean' || item.verdict === 'Safe') : (item.verdict === 'Suspicious' || item.verdict === 'Informational'));
          return matchTerm && matchTool && matchVerdict;
        });

        renderHistoryTable(filtered);
      }

      if (searchInput) searchInput.addEventListener('input', filterData);
      if (toolFilter) toolFilter.addEventListener('change', filterData);
      if (verdictFilter) verdictFilter.addEventListener('change', filterData);

      if (clearBtn) {
        clearBtn.addEventListener('click', () => {
          if (confirm('Are you sure you want to clear your local investigation history?')) {
            window.SudoDeckAuth.clearHistory();
            historyItems = [];
            renderHistoryTable([]);
            renderUserProfile(window.SudoDeckAuth.getUser());
            showToast('All investigation history cleared.');
          }
        });
      }
    }

    // ── Inspector Modal ────────────────────────────────────────────
    function openInspectModal(item) {
      const modal = document.getElementById('inspect-modal');
      const title = document.getElementById('inspect-title');
      const jsonView = document.getElementById('inspect-json-view');
      const rerunBtn = document.getElementById('inspect-rerun-btn');

      title.textContent = `${item.tool}: ${item.query}`;
      jsonView.textContent = JSON.stringify(item, null, 2);
      rerunBtn.href = getToolUrl(item.type, item.query);

      modal.classList.remove('hidden');
      if (window.lucide) lucide.createIcons();
    }

    const closeInspectModal = document.getElementById('close-inspect-modal');
    if (closeInspectModal) {
      closeInspectModal.addEventListener('click', () => {
        document.getElementById('inspect-modal').classList.add('hidden');
      });
    }

    // ── Billing Profile & Form ─────────────────────────────────────
    function renderBillingProfile(billing) {
      document.getElementById('billing-input-email').value = billing.email || '';
      document.getElementById('billing-input-phone').value = billing.phone || '';
      document.getElementById('billing-input-company').value = billing.company || '';
      document.getElementById('billing-input-taxid').value = billing.taxId || '';
      document.getElementById('billing-input-address').value = billing.address || '';

      // Plan card details
      document.getElementById('billing-plan-name').textContent = billing.planName || 'Pro Cyber Analyst';
      document.getElementById('billing-plan-price').textContent = billing.planPrice || '$29 / month';
      document.getElementById('billing-renewal-date').textContent = billing.renewalDate || 'October 14, 2026';

      // Card last4
      if (billing.paymentMethod) {
        document.getElementById('card-brand-name').textContent = billing.paymentMethod.brand;
        document.getElementById('card-last-digits').textContent = `•••• ${billing.paymentMethod.last4}`;
        document.getElementById('card-expiry').textContent = billing.paymentMethod.expiry;
      }

      // Render Invoices Table
      renderInvoicesTable(billing.invoices || []);
    }

    function renderInvoicesTable(invoices) {
      const tbody = document.getElementById('invoices-table-body');
      if (!tbody) return;

      tbody.innerHTML = invoices.map(inv => `
        <tr class="border-b border-slate-800/60 hover:bg-surface-850/40 text-xs">
          <td class="py-3 px-4 font-mono text-emerald-400 font-semibold">${escapeHtml(inv.id)}</td>
          <td class="py-3 px-4 text-slate-400 font-mono">${escapeHtml(inv.date)}</td>
          <td class="py-3 px-4 text-slate-300">${escapeHtml(inv.description)}</td>
          <td class="py-3 px-4 font-mono font-bold text-white">${escapeHtml(inv.amount)}</td>
          <td class="py-3 px-4">
            <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 border border-emerald-500/30 text-emerald-400">
              ${escapeHtml(inv.status)}
            </span>
          </td>
          <td class="py-3 px-4 text-right">
            <button
              type="button"
              data-download-invoice="${inv.id}"
              class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-surface-800 hover:bg-surface-750 text-slate-300 hover:text-white border border-slate-700/60 text-[11px] font-medium transition-all"
            >
              <i data-lucide="download" class="w-3 h-3 text-emerald-400"></i>
              <span>Receipt</span>
            </button>
          </td>
        </tr>
      `).join('');

      tbody.querySelectorAll('[data-download-invoice]').forEach(btn => {
        btn.addEventListener('click', () => {
          const invId = btn.getAttribute('data-download-invoice');
          openReceiptModal(invId);
        });
      });

      if (window.lucide) lucide.createIcons();
    }

    function setupBillingForm() {
      const form = document.getElementById('billing-form');
      if (!form) return;

      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const email = document.getElementById('billing-input-email').value.trim();
        const phone = document.getElementById('billing-input-phone').value.trim();
        const company = document.getElementById('billing-input-company').value.trim();
        const taxId = document.getElementById('billing-input-taxid').value.trim();
        const address = document.getElementById('billing-input-address').value.trim();

        if (!email) {
          showToast('Valid billing email is required.', false);
          return;
        }

        const updated = window.SudoDeckAuth.updateBilling({
          email,
          phone,
          company,
          taxId,
          address,
        });

        // Also update primary user profile email & phone
        const u = window.SudoDeckAuth.getUser();
        u.email = email;
        if (phone) u.phone = phone;
        window.SudoDeckAuth.setUser(u);
        renderUserProfile(u);

        showToast('Billing contact & dispatch parameters saved successfully!');
      });

      // Update Card Modal Trigger
      const updateCardBtn = document.getElementById('update-card-btn');
      const cardModal = document.getElementById('card-modal');
      const closeCardModal = document.getElementById('close-card-modal');
      const cardForm = document.getElementById('card-form');

      if (updateCardBtn) {
        updateCardBtn.addEventListener('click', () => cardModal.classList.remove('hidden'));
      }
      if (closeCardModal) {
        closeCardModal.addEventListener('click', () => cardModal.classList.add('hidden'));
      }
      if (cardForm) {
        cardForm.addEventListener('submit', (e) => {
          e.preventDefault();
          const cardNum = document.getElementById('new-card-number').value.replace(/\s/g, '');
          const cardExp = document.getElementById('new-card-exp').value;
          const cardHolder = document.getElementById('new-card-holder').value;
          const last4 = cardNum.slice(-4) || '9922';

          const billing = window.SudoDeckAuth.getBilling();
          billing.paymentMethod = {
            brand: cardNum.startsWith('4') ? 'Visa' : 'Mastercard',
            last4,
            expiry: cardExp || '12/29',
            holder: cardHolder || 'Operator',
          };
          window.SudoDeckAuth.updateBilling(billing);
          renderBillingProfile(billing);
          cardModal.classList.add('hidden');
          showToast('Payment method encrypted & updated!');
        });
      }
    }

    // ── Receipt Modal ──────────────────────────────────────────────
    function openReceiptModal(invId) {
      const billing = window.SudoDeckAuth.getBilling();
      const inv = (billing.invoices || []).find(i => i.id === invId) || {
        id: invId,
        date: new Date().toISOString().split('T')[0],
        amount: '$29.00',
        status: 'Paid',
      };

      document.getElementById('receipt-id').textContent = inv.id;
      document.getElementById('receipt-date').textContent = inv.date;
      document.getElementById('receipt-amount').textContent = inv.amount;
      document.getElementById('receipt-customer').textContent = `${billing.company || 'SudoDeck Labs'} (${billing.email})`;

      document.getElementById('receipt-modal').classList.remove('hidden');
      if (window.lucide) lucide.createIcons();
    }

    const closeReceiptModal = document.getElementById('close-receipt-modal');
    if (closeReceiptModal) {
      closeReceiptModal.addEventListener('click', () => {
        document.getElementById('receipt-modal').classList.add('hidden');
      });
    }

    // ── Quick Scanner Widget ───────────────────────────────────────
    function setupQuickScanner() {
      const form = document.getElementById('quick-scan-form');
      const input = document.getElementById('quick-scan-input');
      if (!form) return;

      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const val = (input.value || '').trim();
        if (!val) return;

        // Auto-detect type
        let targetUrl = `/#ip?q=${encodeURIComponent(val)}`;
        let toolType = 'ip';
        let toolTitle = 'IP Reputation';

        if (/^[0-9a-fA-F]{32,64}$/.test(val)) {
          targetUrl = `/siem#file?q=${encodeURIComponent(val)}`;
          toolType = 'file';
          toolTitle = 'File Hash Analysis';
        } else if (val.startsWith('CVE-') || val.startsWith('cve-')) {
          targetUrl = `/cve?query=${encodeURIComponent(val)}`;
          toolType = 'cve';
          toolTitle = 'CVE Vulnerability';
        } else if (/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(val)) {
          targetUrl = `/mac?mac=${encodeURIComponent(val)}`;
          toolType = 'mac';
          toolTitle = 'MAC & OUI Lookup';
        } else if (val.includes('.') && !val.includes('@')) {
          targetUrl = `/traffic?domain=${encodeURIComponent(val)}`;
          toolType = 'traffic';
          toolTitle = 'Web Traffic & Analytics';
        } else if (val.startsWith('@') || !val.includes('.')) {
          targetUrl = `/social-footprint?username=${encodeURIComponent(val.replace('@', ''))}`;
          toolType = 'social';
          toolTitle = 'Social Footprint';
        }

        // Add to history
        window.SudoDeckAuth.addHistoryItem({
          tool: toolTitle,
          type: toolType,
          query: val,
          verdict: 'Informational',
          details: 'Dispatched via SudoDeck Dashboard Quick Launcher',
        });

        window.location.href = targetUrl;
      });
    }

    // ── API Key Management ─────────────────────────────────────────
    function renderApiKeysTable(keys) {
      const tbody = document.getElementById('api-keys-table-body');
      if (!tbody) return;

      tbody.innerHTML = keys.map(k => `
        <tr class="border-b border-slate-800/60 hover:bg-surface-850/40 text-xs">
          <td class="py-3 px-4 font-semibold text-white">${escapeHtml(k.name)}</td>
          <td class="py-3 px-4 font-mono text-emerald-400 flex items-center gap-2">
            <span>${escapeHtml(k.keyMasked)}</span>
            <button type="button" data-copy-key="${k.key || k.keyMasked}" class="p-1 rounded hover:bg-surface-800 text-slate-400 hover:text-emerald-400" title="Copy Key">
              <i data-lucide="copy" class="w-3.5 h-3.5"></i>
            </button>
          </td>
          <td class="py-3 px-4 font-mono text-slate-400">${escapeHtml(k.created)}</td>
          <td class="py-3 px-4 font-mono text-slate-400">${escapeHtml(k.lastUsed)}</td>
          <td class="py-3 px-4 text-right">
            <button
              type="button"
              data-revoke-key="${k.id}"
              class="px-2 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-400 text-[11px] font-semibold transition-all"
            >
              Revoke
            </button>
          </td>
        </tr>
      `).join('');

      tbody.querySelectorAll('[data-copy-key]').forEach(btn => {
        btn.addEventListener('click', () => {
          navigator.clipboard.writeText(btn.getAttribute('data-copy-key'));
          showToast('API Key copied to secure clipboard.');
        });
      });

      tbody.querySelectorAll('[data-revoke-key]').forEach(btn => {
        btn.addEventListener('click', () => {
          const id = btn.getAttribute('data-revoke-key');
          if (confirm('Revoke this API Key immediately? Systems using it will lose access.')) {
            apiKeys = window.SudoDeckAuth.revokeApiKey(id);
            renderApiKeysTable(apiKeys);
            renderUserProfile(window.SudoDeckAuth.getUser());
            showToast('API Key revoked.');
          }
        });
      });

      if (window.lucide) lucide.createIcons();
    }

    function setupApiKeyGenerator() {
      const btn = document.getElementById('generate-api-key-btn');
      if (!btn) return;

      btn.addEventListener('click', () => {
        const name = prompt('Enter a label for this API Key (e.g., Incident Response CLI):', 'SOC Automated Feed');
        if (name !== null) {
          const newKey = window.SudoDeckAuth.addApiKey(name);
          apiKeys = window.SudoDeckAuth.getApiKeys();
          renderApiKeysTable(apiKeys);
          renderUserProfile(window.SudoDeckAuth.getUser());
          showToast(`Generated: ${newKey.name}`);
        }
      });
    }

    // ── Export History Actions ─────────────────────────────────────
    function setupExportActions() {
      const exportJsonBtn = document.getElementById('export-history-json');
      const exportCsvBtn = document.getElementById('export-history-csv');

      if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => {
          const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(historyItems, null, 2));
          const dl = document.createElement('a');
          dl.setAttribute('href', dataStr);
          dl.setAttribute('download', `sudodeck_history_${Date.now()}.json`);
          dl.click();
          showToast('History exported as JSON.');
        });
      }

      if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => {
          const headers = ['ID', 'Tool', 'Type', 'Query', 'Verdict', 'Score', 'Details', 'Timestamp'];
          const rows = historyItems.map(i => [
            i.id,
            `"${(i.tool || '').replace(/"/g, '""')}"`,
            i.type,
            `"${(i.query || '').replace(/"/g, '""')}"`,
            i.verdict,
            i.verdictScore || 0,
            `"${(i.details || '').replace(/"/g, '""')}"`,
            i.timestamp,
          ]);
          const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
          const dl = document.createElement('a');
          dl.setAttribute('href', encodeURI(csvContent));
          dl.setAttribute('download', `sudodeck_history_${Date.now()}.csv`);
          dl.click();
          showToast('History exported as CSV.');
        });
      }

      // Logout Action
      const logoutBtn = document.getElementById('dashboard-logout-btn');
      if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
          if (confirm('Terminate active SudoDeck terminal session and sign out?')) {
            window.SudoDeckAuth.logout();
          }
        });
      }
    }

    // ── Helpers ────────────────────────────────────────────────────
    function formatTimeAgo(date) {
      const diffMs = Date.now() - date.getTime();
      const mins = Math.floor(diffMs / (60 * 1000));
      if (mins < 1) return 'Just now';
      if (mins < 60) return `${mins}m ago`;
      const hours = Math.floor(mins / 60);
      if (hours < 24) return `${hours}h ago`;
      const days = Math.floor(hours / 24);
      return `${days}d ago`;
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function showToast(msg, isSuccess = true) {
      const toast = document.getElementById('dashboard-toast');
      const toastText = document.getElementById('dashboard-toast-text');
      if (!toast || !toastText) return;

      toastText.textContent = msg;
      toast.className = `fixed bottom-6 right-6 z-50 max-w-sm px-4 py-3 rounded-xl border ${isSuccess ? 'border-emerald-500/40' : 'border-rose-500/40'} bg-surface-850/95 text-white text-xs font-medium backdrop-blur-xl shadow-xl flex items-center gap-3 translate-y-0 opacity-100 transition-all duration-300`;
      setTimeout(() => {
        toast.className = toast.className.replace('translate-y-0 opacity-100', 'translate-y-24 opacity-0');
      }, 3500);
    }

  });
})();
