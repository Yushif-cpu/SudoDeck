// ═══════════════════════════════════════════════════════════════
//  ThreatIntel — Shared Navigation & Global Command Palette (Ctrl+K)
// ═══════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // ── 1. LocalStorage History Helper ────────────────────────────
  window.ThreatIntelHistory = {
    get(key, limit = 5) {
      try {
        const raw = localStorage.getItem(`threatintel_history_${key}`);
        return raw ? JSON.parse(raw).slice(0, limit) : [];
      } catch {
        return [];
      }
    },
    add(key, value) {
      if (!value || typeof value !== 'string') return;
      const val = value.trim();
      if (!val) return;
      try {
        let list = this.get(key, 20);
        list = list.filter(item => item.toLowerCase() !== val.toLowerCase());
        list.unshift(val);
        localStorage.setItem(`threatintel_history_${key}`, JSON.stringify(list.slice(0, 10)));
      } catch {
        // Ignore storage errors
      }
    },
    clear(key) {
      try {
        localStorage.removeItem(`threatintel_history_${key}`);
      } catch {}
    }
  };

  // ── 2. Command Palette Registry ───────────────────────────────
  const COMMAND_ITEMS = [
    // Navigation items
    {
      id: 'nav-ip',
      title: 'IP Reputation & Threat Intel',
      desc: 'Analyze IP reputation, malicious reports, geolocation, and ASN data',
      category: 'Threat & Recon',
      icon: 'radar',
      url: '/#ip',
      keywords: ['ip', 'abuseipdb', 'threat', 'reputation', 'asn', 'dns', 'scan']
    },
    {
      id: 'nav-mac',
      title: 'MAC Address & OUI Vendor Lookup',
      desc: 'Identify hardware vendor, IEEE OUI block, and MAC address details',
      category: 'Threat & Recon',
      icon: 'cpu',
      url: '/mac',
      keywords: ['mac', 'oui', 'hardware', 'vendor', 'ieee', 'ethernet', 'device']
    },
    {
      id: 'nav-domain',
      title: 'Domain Intelligence & WHOIS',
      desc: 'VirusTotal threat scans, DNS records, MX/TXT verification, and WHOIS registration',
      category: 'Threat & Recon',
      icon: 'globe',
      url: '/#domain',
      keywords: ['domain', 'whois', 'dns', 'virustotal', 'mx', 'txt', 'ns', 'url', 'hostname']
    },
    {
      id: 'nav-utils',
      title: 'IP & Subnet Utilities',
      desc: 'Interactive CIDR calculator, subnet masks, wildcard masks, usable bounds, and broadcast addresses',
      category: 'Threat & Recon',
      icon: 'network',
      url: '/#utils',
      keywords: ['subnet', 'cidr', 'mask', 'ip', 'network', 'broadcast', 'wildcard', 'dns', 'ping']
    },
    {
      id: 'nav-cve',
      title: 'CVE Vulnerability Scanner (NVD v2.0)',
      desc: 'Query national vulnerability database by CVE ID, software name, or keyword',
      category: 'Threat & Recon',
      icon: 'flame',
      url: '/cve',
      keywords: ['cve', 'nvd', 'vulnerability', 'exploit', 'security', 'advisory', 'patch']
    },
    {
      id: 'nav-siem-ua',
      title: 'User-Agent & HTTP Header Inspector',
      desc: 'Parse User-Agent strings, detect automated scanners, and audit HTTP security headers',
      category: 'SOC & SIEM',
      icon: 'globe',
      url: '/siem#headers',
      keywords: ['headers', 'user-agent', 'ua', 'http', 'csp', 'hsts', 'security headers', 'sqlmap', 'scanner']
    },
    {
      id: 'nav-siem-log',
      title: 'SIEM Log & Alert Formatter',
      desc: 'Format, syntax highlight, and beautify raw JSON, Syslog, and Windows Event logs',
      category: 'SOC & SIEM',
      icon: 'file-text',
      url: '/siem#formatter',
      keywords: ['siem', 'log', 'format', 'json', 'syslog', 'event', 'alert', 'parser']
    },
    {
      id: 'nav-siem-regex',
      title: 'SOC Regex Tester & Detection Builder',
      desc: 'Test regular expressions with real-time match groups, execution timer, and presets',
      category: 'SOC & SIEM',
      icon: 'regex',
      url: '/siem#regex',
      keywords: ['regex', 'regular expression', 'pattern', 'detection', 'rule', 'sigma', 'yara']
    },
    {
      id: 'nav-siem-email',
      title: 'Email Header Forensic Analyzer',
      desc: 'Parse RFC 822/5322 headers, inspect Received hops, SPF/DKIM/DMARC authentication verdicts',
      category: 'SOC & SIEM',
      icon: 'mail-search',
      url: '/siem#email',
      keywords: ['email', 'header', 'spf', 'dkim', 'dmarc', 'phishing', 'smtp', 'hops']
    },
    {
      id: 'nav-siem-file',
      title: 'File Hash & Malware Analyzer',
      desc: 'VirusTotal multi-engine malware scans, SHA-256 integrity lookup, and threat scores',
      category: 'SOC & SIEM',
      icon: 'file-search',
      url: '/siem#file',
      keywords: ['file', 'hash', 'sha256', 'md5', 'virustotal', 'malware', 'antivirus']
    },
    {
      id: 'nav-crypto-hash',
      title: 'Crypto Suite: Hash Generator & Analyzer',
      desc: 'Generate and inspect MD5, SHA-1, SHA-256, SHA-512, and file integrity checksums',
      category: 'Attack Utilities',
      icon: 'hash',
      url: '/crypto#hash',
      keywords: ['hash', 'md5', 'sha1', 'sha256', 'sha512', 'checksum', 'crypto']
    },
    {
      id: 'nav-crypto-jwt',
      title: 'Crypto Suite: JWT Token Decoder',
      desc: 'Inspect JWT header, payload, expiration timestamps, and signature structure',
      category: 'Attack Utilities',
      icon: 'key-round',
      url: '/crypto#jwt',
      keywords: ['jwt', 'token', 'decode', 'bearer', 'auth', 'claim', 'signature']
    },
    {
      id: 'nav-crypto-encoder',
      title: 'Crypto Suite: Multi-Encoder & Decoder',
      desc: 'Base64, URL encoding, Hexadecimal, Binary, and CyberChef-style conversions',
      category: 'Attack Utilities',
      icon: 'binary',
      url: '/crypto#convert',
      keywords: ['base64', 'hex', 'url', 'encode', 'decode', 'cyberchef', 'convert']
    },
    {
      id: 'nav-gtfobins',
      title: 'GTFOBins Unix PrivEsc & Bypass Explorer',
      desc: 'Search Unix binaries that can be exploited to bypass local security restrictions',
      category: 'Attack Utilities',
      icon: 'terminal',
      url: '/gtfobins',
      keywords: ['gtfobins', 'privesc', 'sudo', 'suid', 'privilege escalation', 'bypass', 'linux', 'unix']
    },
    {
      id: 'nav-wordlist',
      title: 'Automated Wordlist & Mutator Suite',
      desc: 'Generate and mutate password wordlists with leet-speak, case variants, suffixes, and custom patterns',
      category: 'Attack Utilities',
      icon: 'book-text',
      url: '/wordlist',
      keywords: ['wordlist', 'password', 'mutator', 'leet', 'bruteforce', 'dictionary', 'generator', 'mutation']
    },
    {
      id: 'nav-news',
      title: 'Cybersecurity News & Threat Wire (The Hacker News)',
      desc: 'Live real-time cybersecurity newsfeed, zero-day advisories, and APT campaign reports',
      category: 'Threat & Recon',
      icon: 'newspaper',
      url: '/news',
      keywords: ['news', 'the hacker news', 'feed', 'rss', 'live', 'wire', 'articles', 'intel', 'breach']
    },
    {
      id: 'nav-premium',
      title: 'Premium Tools Suite (Classified Arsenal)',
      desc: 'Exclusive high-grade red team operations and advanced autonomous SOC defense capabilities',
      category: 'Enterprise & Premium',
      icon: 'crown',
      url: '/premium',
      keywords: ['premium', 'tools', 'red team', 'pro', 'arsenal', 'exploit', 'darknet', 'c2', 'vip']
    },
    {
      id: 'nav-pricing',
      title: 'Pricing & Subscription Tiers',
      desc: 'Compare Community, Analyst Pro, and Enterprise SOC plans with transparent pricing',
      category: 'Enterprise & Premium',
      icon: 'credit-card',
      url: '/pricing',
      keywords: ['pricing', 'plans', 'subscription', 'price', 'cost', 'pro', 'enterprise', 'upgrade', 'billing']
    },
    {
      id: 'nav-about',
      title: 'About SudoDeck Intelligence Platform',
      desc: 'Platform mission, architectural pillars, telemetry metrics, and privacy architecture',
      category: 'Platform & Operations',
      icon: 'info',
      url: '/#about',
      keywords: ['about', 'mission', 'platform', 'sudodeck', 'architecture', 'privacy', 'telemetry', 'info']
    },
    {
      id: 'nav-contact',
      title: 'Contact Security Operations (CIRT)',
      desc: 'Submit incident dispatches, report vulnerabilities, or request enterprise support',
      category: 'Platform & Operations',
      icon: 'mail',
      url: '/#contact',
      keywords: ['contact', 'email', 'support', 'cirt', 'soc', 'pgp', 'incident', 'report', 'vulnerability']
    }
  ];

  // ── 3. Initialize Command Palette UI ──────────────────────────
  let paletteOpen = false;
  let selectedIndex = 0;
  let currentFilteredList = [];

  function injectCommandPalette() {
    if (document.getElementById('ti-command-palette-modal')) return;

    const modalHtml = `
      <div id="ti-command-palette-backdrop" class="fixed inset-0 bg-black/75 backdrop-blur-md z-[100] hidden items-start justify-center pt-[10vh] px-4 opacity-0 transition-opacity duration-200">
        <div id="ti-command-palette-modal" class="w-full max-w-2xl bg-surface-900 border border-slate-700/80 rounded-2xl shadow-2xl shadow-black/80 overflow-hidden transform scale-95 transition-transform duration-200 flex flex-col max-h-[75vh]">
          
          <!-- Search Input Header -->
          <div class="relative border-b border-slate-800/80 p-4 bg-surface-850/90 flex items-center gap-3">
            <i data-lucide="search" class="w-5 h-5 text-emerald-400 shrink-0"></i>
            <input
              type="text"
              id="ti-palette-input"
              class="w-full bg-transparent border-none outline-none text-white text-base placeholder-slate-400 font-sans focus:ring-0"
              placeholder="Search tools, actions, or enter an IP / CVE / MAC address..."
              autocomplete="off"
              spellcheck="false"
            />
            <button
              id="ti-palette-close"
              type="button"
              class="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-surface-700 transition-colors text-xs flex items-center gap-1 font-mono border border-slate-700/50"
            >
              <span>ESC</span>
            </button>
          </div>

          <!-- Quick Navigation / Smart Actions List -->
          <div id="ti-palette-results" class="overflow-y-auto p-2 space-y-1 flex-1 custom-scrollbar">
            <!-- Dynamically populated -->
          </div>

          <!-- Footer Bar -->
          <div class="border-t border-slate-800/80 px-4 py-2.5 bg-surface-900/90 flex items-center justify-between text-[11px] text-slate-400 font-mono">
            <div class="flex items-center gap-3">
              <span class="flex items-center gap-1">
                <kbd class="px-1.5 py-0.5 rounded bg-surface-800 border border-slate-700 text-slate-300">↑</kbd>
                <kbd class="px-1.5 py-0.5 rounded bg-surface-800 border border-slate-700 text-slate-300">↓</kbd>
                <span>Navigate</span>
              </span>
              <span class="flex items-center gap-1">
                <kbd class="px-1.5 py-0.5 rounded bg-surface-800 border border-slate-700 text-slate-300">↵</kbd>
                <span>Select</span>
              </span>
            </div>
            <div class="flex items-center gap-2">
              <span class="text-emerald-400 font-semibold">SudoDeck</span>
              <span>Quick Launcher</span>
            </div>
          </div>

        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);
    if (window.lucide) lucide.createIcons({ nodes: [document.getElementById('ti-command-palette-backdrop')] });

    // Event listeners for palette input & close
    const backdrop = document.getElementById('ti-command-palette-backdrop');
    const input = document.getElementById('ti-palette-input');
    const closeBtn = document.getElementById('ti-palette-close');

    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) closePalette();
    });

    closeBtn.addEventListener('click', closePalette);

    input.addEventListener('input', () => {
      renderPaletteResults(input.value.trim());
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        navigatePalette(1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        navigatePalette(-1);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        executeSelectedPaletteItem();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        closePalette();
      }
    });
  }

  function openPalette() {
    injectCommandPalette();
    const backdrop = document.getElementById('ti-command-palette-backdrop');
    const modal = document.getElementById('ti-command-palette-modal');
    const input = document.getElementById('ti-palette-input');

    backdrop.classList.remove('hidden');
    backdrop.classList.add('flex');
    setTimeout(() => {
      backdrop.classList.remove('opacity-0');
      backdrop.classList.add('opacity-100');
      modal.classList.remove('scale-95');
      modal.classList.add('scale-100');
      input.focus();
      input.value = '';
      renderPaletteResults('');
    }, 10);

    paletteOpen = true;
  }

  function closePalette() {
    const backdrop = document.getElementById('ti-command-palette-backdrop');
    const modal = document.getElementById('ti-command-palette-modal');
    if (!backdrop) return;

    backdrop.classList.remove('opacity-100');
    backdrop.classList.add('opacity-0');
    modal.classList.remove('scale-100');
    modal.classList.add('scale-95');

    setTimeout(() => {
      backdrop.classList.add('hidden');
      backdrop.classList.remove('flex');
    }, 200);

    paletteOpen = false;
  }

  // Smart Query Detection: Detect if query is an IP, CVE, MAC, or Binary
  function buildSmartActions(query) {
    const actions = [];
    const q = query.trim();
    if (!q) return actions;

    // 1. IP Check
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){1,7}:?([0-9a-fA-F]{1,4})?$/;
    if (ipRegex.test(q)) {
      actions.push({
        id: 'smart-ip',
        title: `Analyze IP Address: ${q}`,
        desc: `Inspect threat reputation, abuse reports, and ISP origin on IP Reputation page`,
        category: 'Instant Action',
        icon: 'zap',
        isSmart: true,
        url: `/?ip=${encodeURIComponent(q)}`
      });
    }

    // 2. CVE Check
    const cveRegex = /^(CVE-)?[0-9]{4}-[0-9]{4,}$/i;
    if (cveRegex.test(q)) {
      const cveId = q.toUpperCase().startsWith('CVE-') ? q.toUpperCase() : `CVE-${q.toUpperCase()}`;
      actions.push({
        id: 'smart-cve',
        title: `Search Vulnerability: ${cveId}`,
        desc: `Look up CVSS score, severity, and mitigation advisories in NVD v2.0`,
        category: 'Instant Action',
        icon: 'zap',
        isSmart: true,
        url: `/cve?q=${encodeURIComponent(cveId)}`
      });
    }

    // 3. MAC Check
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){2,5}([0-9A-Fa-f]{2})?$/;
    if (macRegex.test(q)) {
      actions.push({
        id: 'smart-mac',
        title: `Lookup MAC Vendor: ${q}`,
        desc: `Identify vendor manufacturer and IEEE OUI block allocation`,
        category: 'Instant Action',
        icon: 'zap',
        isSmart: true,
        url: `/mac?mac=${encodeURIComponent(q)}`
      });
    }

    // 4. GTFOBins Search
    if (/^[a-zA-Z0-9_\-]{2,20}$/.test(q) && !actions.length) {
      actions.push({
        id: 'smart-gtfobins',
        title: `GTFOBins Search: ${q}`,
        desc: `Check if '${q}' binary can be exploited for security bypass or sudo privesc`,
        category: 'Instant Action',
        icon: 'terminal',
        isSmart: true,
        url: `/gtfobins?q=${encodeURIComponent(q)}`
      });
    }

    return actions;
  }

  function renderPaletteResults(query) {
    const container = document.getElementById('ti-palette-results');
    if (!container) return;

    const smartActions = buildSmartActions(query);
    const qLower = query.toLowerCase();

    let items = COMMAND_ITEMS.filter(item => {
      if (!query) return true;
      if (item.title.toLowerCase().includes(qLower)) return true;
      if (item.desc.toLowerCase().includes(qLower)) return true;
      if (item.category.toLowerCase().includes(qLower)) return true;
      return item.keywords.some(k => k.includes(qLower));
    });

    currentFilteredList = [...smartActions, ...items];
    selectedIndex = 0;

    if (currentFilteredList.length === 0) {
      container.innerHTML = `
        <div class="p-8 text-center text-slate-500 font-sans">
          <i data-lucide="help-circle" class="w-8 h-8 mx-auto mb-2 text-slate-600"></i>
          <p class="text-sm font-medium text-slate-400">No matching commands or tools found.</p>
          <p class="text-xs text-slate-500 mt-1">Try searching for "IP", "CVE", "Hash", "JWT", or "Syslog".</p>
        </div>
      `;
      if (window.lucide) lucide.createIcons({ nodes: [container] });
      return;
    }

    container.innerHTML = currentFilteredList.map((item, index) => {
      const isSelected = index === selectedIndex;
      const isSmart = item.isSmart;
      const bgClass = isSelected
        ? isSmart ? 'bg-emerald-500/15 border-emerald-500/40 text-white' : 'bg-surface-750 border-slate-700/80 text-white'
        : 'bg-surface-850/50 border-transparent text-slate-300 hover:bg-surface-800';

      const iconColor = isSmart ? 'text-emerald-400' : 'text-indigo-400';

      return `
        <div
          class="ti-palette-item flex items-center justify-between p-3 rounded-xl border transition-all cursor-pointer ${bgClass}"
          data-index="${index}"
          data-url="${item.url}"
        >
          <div class="flex items-center gap-3 overflow-hidden">
            <div class="w-8 h-8 rounded-lg bg-surface-900 border border-slate-800 flex items-center justify-center shrink-0 ${iconColor}">
              <i data-lucide="${item.icon || 'arrow-right'}" class="w-4 h-4"></i>
            </div>
            <div class="truncate">
              <div class="text-xs font-bold text-white flex items-center gap-2">
                <span>${escapeHtml(item.title)}</span>
                ${isSmart ? '<span class="px-1.5 py-0.2 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Action</span>' : ''}
              </div>
              <p class="text-[11px] text-slate-400 truncate">${escapeHtml(item.desc)}</p>
            </div>
          </div>
          <div class="shrink-0 ml-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-900 border border-slate-800 text-slate-400">
              ${escapeHtml(item.category)}
            </span>
          </div>
        </div>
      `;
    }).join('');

    if (window.lucide) lucide.createIcons({ nodes: [container] });

    // Item click binding
    container.querySelectorAll('.ti-palette-item').forEach(el => {
      el.addEventListener('click', () => {
        const url = el.dataset.url;
        if (url) window.location.href = url;
      });
    });
  }

  function navigatePalette(direction) {
    if (currentFilteredList.length === 0) return;
    selectedIndex += direction;
    if (selectedIndex < 0) selectedIndex = currentFilteredList.length - 1;
    if (selectedIndex >= currentFilteredList.length) selectedIndex = 0;

    const items = document.querySelectorAll('.ti-palette-item');
    items.forEach((item, idx) => {
      if (idx === selectedIndex) {
        item.classList.add('bg-surface-750', 'border-slate-700/80');
        item.classList.remove('bg-surface-850/50', 'border-transparent');
        item.scrollIntoView({ block: 'nearest' });
      } else {
        item.classList.remove('bg-surface-750', 'border-slate-700/80');
        item.classList.add('bg-surface-850/50', 'border-transparent');
      }
    });
  }

  function executeSelectedPaletteItem() {
    if (currentFilteredList[selectedIndex]) {
      const url = currentFilteredList[selectedIndex].url;
      if (url) window.location.href = url;
    }
  }

  // Global Keyboard shortcut listener
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (paletteOpen) closePalette();
      else openPalette();
    }
  });

  // ── 4. Dropdowns & Mobile Navigation ──────────────────────────
  function initHeaderNavigation() {
    // Command Palette Trigger buttons across all pages (direct listeners)
    document.querySelectorAll('[data-action="open-command-palette"], #cmd-palette-btn, .cmd-palette-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        openPalette();
      });
    });

    // Global click delegation for command palette trigger
    document.addEventListener('click', (e) => {
      const trigger = e.target.closest('[data-action="open-command-palette"], #cmd-palette-btn, .cmd-palette-btn');
      if (trigger) {
        e.preventDefault();
        openPalette();
      }
    });

    // ── Mobile Navigation Toggle & Drawer Builder ───────────────
    const mobileBtn = document.getElementById('mobile-menu-btn') || 
                      document.getElementById('mobile-menu-toggle') || 
                      document.querySelector('[data-action="toggle-mobile-menu"]');
    const mobileDrawer = document.getElementById('mobile-menu-drawer');

    if (mobileBtn && mobileDrawer) {
      // Build the symmetrical categorized accordion mobile menu
      buildMobileMenuDrawer(mobileDrawer);

      mobileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isHidden = mobileDrawer.classList.contains('hidden');
        if (isHidden) {
          mobileDrawer.classList.remove('hidden');
          mobileBtn.setAttribute('aria-expanded', 'true');
          mobileBtn.innerHTML = '<i data-lucide="x" class="w-5 h-5 text-emerald-400"></i>';
        } else {
          mobileDrawer.classList.add('hidden');
          mobileBtn.setAttribute('aria-expanded', 'false');
          mobileBtn.innerHTML = '<i data-lucide="menu" class="w-5 h-5 text-slate-300"></i>';
        }
        if (window.lucide) window.lucide.createIcons();
      });

      // Close mobile drawer when clicking any link inside it
      mobileDrawer.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', () => {
          mobileDrawer.classList.add('hidden');
          if (mobileBtn) {
            mobileBtn.setAttribute('aria-expanded', 'false');
            mobileBtn.innerHTML = '<i data-lucide="menu" class="w-5 h-5 text-slate-300"></i>';
            if (window.lucide) window.lucide.createIcons();
          }
        });
      });

      // Close mobile drawer when clicking outside
      document.addEventListener('click', (e) => {
        if (!mobileDrawer.contains(e.target) && !mobileBtn.contains(e.target)) {
          if (!mobileDrawer.classList.contains('hidden')) {
            mobileDrawer.classList.add('hidden');
            mobileBtn.setAttribute('aria-expanded', 'false');
            mobileBtn.innerHTML = '<i data-lucide="menu" class="w-5 h-5 text-slate-300"></i>';
            if (window.lucide) window.lucide.createIcons();
          }
        }
      });
    }

    // ── Symmetrical & Grouped Mobile Menu Drawer Builder ───────────
    function buildMobileMenuDrawer(drawer) {
      if (!drawer) return;

      drawer.innerHTML = `
        <div class="p-3 space-y-3">
          <!-- Quick Nav Header Pills: News, Premium, Pricing -->
          <div class="grid grid-cols-3 gap-2 pb-1">
            <a href="/news" class="mobile-quick-pill group ${window.location.pathname === '/news' ? 'active' : ''}">
              <div class="w-7 h-7 rounded-lg bg-slate-800 border border-slate-700/80 flex items-center justify-center text-slate-300 group-hover:text-emerald-400 group-hover:border-emerald-500/40 transition-colors">
                <i data-lucide="newspaper" class="w-3.5 h-3.5"></i>
              </div>
              <span class="text-[11px] font-semibold text-slate-300 group-hover:text-white">News</span>
            </a>
            <a href="/premium" class="mobile-quick-pill group ${window.location.pathname === '/premium' ? 'active' : ''}">
              <div class="w-7 h-7 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 group-hover:border-amber-400 transition-colors">
                <i data-lucide="crown" class="w-3.5 h-3.5"></i>
              </div>
              <span class="text-[11px] font-semibold text-slate-300 group-hover:text-white">Premium</span>
            </a>
            <a href="/pricing" class="mobile-quick-pill group ${window.location.pathname === '/pricing' ? 'active' : ''}">
              <div class="w-7 h-7 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:border-emerald-400 transition-colors">
                <i data-lucide="credit-card" class="w-3.5 h-3.5"></i>
              </div>
              <span class="text-[11px] font-semibold text-slate-300 group-hover:text-white">Pricing</span>
            </a>
          </div>

          <!-- Section 1: Threat & Recon (Symmetrical Accordion) -->
          <div class="mobile-accordion-group rounded-2xl border border-slate-800 bg-surface-850/80 overflow-hidden shadow-sm">
            <button type="button" class="mobile-accordion-trigger w-full flex items-center justify-between p-3 text-left transition-colors hover:bg-surface-800/80 cursor-pointer" data-target="mob-threat-group">
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 flex items-center justify-center shrink-0">
                  <i data-lucide="radar" class="w-4 h-4"></i>
                </div>
                <div>
                  <div class="text-xs font-bold text-white tracking-wide">Threat & Recon</div>
                  <div class="text-[10px] font-mono text-emerald-400/80">5 intelligence modules</div>
                </div>
              </div>
              <i data-lucide="chevron-down" class="w-4 h-4 text-slate-400 transition-transform duration-200"></i>
            </button>
            <div id="mob-threat-group" class="mobile-accordion-content hidden border-t border-slate-800/80 bg-surface-900/60 p-2 space-y-1">
              <a href="/#ip" data-switch-tab="ip" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-emerald-500/15 border border-emerald-500/30 text-emerald-400">
                  <i data-lucide="shield-check" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-emerald-300 truncate">IP Reputation Check</div>
                  <div class="text-[10px] text-slate-400 truncate">AbuseIPDB, Geolocation & ASN</div>
                </div>
              </a>
              <a href="/#domain" data-switch-tab="domain" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-blue-500/15 border border-blue-500/30 text-blue-400">
                  <i data-lucide="globe" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-blue-300 truncate">Domain Intelligence</div>
                  <div class="text-[10px] text-slate-400 truncate">VirusTotal, DNS & WHOIS Engine</div>
                </div>
              </a>
              <a href="/#utils" data-switch-tab="utils" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-teal-500/15 border border-teal-500/30 text-teal-400">
                  <i data-lucide="network" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-teal-300 truncate">IP & Subnet Utilities</div>
                  <div class="text-[10px] text-slate-400 truncate">CIDR calculator & subnet masks</div>
                </div>
              </a>
              <a href="/mac" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-cyan-500/15 border border-cyan-500/30 text-cyan-400">
                  <i data-lucide="cpu" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-cyan-300 truncate">MAC & OUI Lookup</div>
                  <div class="text-[10px] text-slate-400 truncate">Hardware vendor & IEEE block</div>
                </div>
              </a>
              <a href="/cve" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-rose-500/15 border border-rose-500/30 text-rose-400">
                  <i data-lucide="flame" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-rose-300 truncate">CVE Scanner</div>
                  <div class="text-[10px] text-slate-400 truncate">NVD v2.0 CVSS advisories</div>
                </div>
              </a>
            </div>
          </div>

          <!-- Section 2: SIEM Utilities (Symmetrical Accordion) -->
          <div class="mobile-accordion-group rounded-2xl border border-slate-800 bg-surface-850/80 overflow-hidden shadow-sm">
            <button type="button" class="mobile-accordion-trigger w-full flex items-center justify-between p-3 text-left transition-colors hover:bg-surface-800/80 cursor-pointer" data-target="mob-siem-group">
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 rounded-xl bg-indigo-500/15 border border-indigo-500/30 text-indigo-400 flex items-center justify-center shrink-0">
                  <i data-lucide="layers" class="w-4 h-4"></i>
                </div>
                <div>
                  <div class="text-xs font-bold text-white tracking-wide">SIEM Utilities</div>
                  <div class="text-[10px] font-mono text-indigo-400/80">5 SOC tools & parsers</div>
                </div>
              </div>
              <i data-lucide="chevron-down" class="w-4 h-4 text-slate-400 transition-transform duration-200"></i>
            </button>
            <div id="mob-siem-group" class="mobile-accordion-content hidden border-t border-slate-800/80 bg-surface-900/60 p-2 space-y-1">
              <a href="/siem#formatter" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
                  <i data-lucide="file-code" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-indigo-300 truncate">Log & Alert Formatter</div>
                  <div class="text-[10px] text-slate-400 truncate">Windows Event & Syslog to JSON</div>
                </div>
              </a>
              <a href="/siem#regex" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
                  <i data-lucide="search-code" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-indigo-300 truncate">Detection Regex Tester</div>
                  <div class="text-[10px] text-slate-400 truncate">Test regex against threat logs</div>
                </div>
              </a>
              <a href="/siem#headers" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
                  <i data-lucide="scan-face" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-indigo-300 truncate">User-Agent & HTTP Headers</div>
                  <div class="text-[10px] text-slate-400 truncate">Analyze web client anomalies</div>
                </div>
              </a>
              <a href="/siem#email" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
                  <i data-lucide="mail-search" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-indigo-300 truncate">Email Header Analysis</div>
                  <div class="text-[10px] text-slate-400 truncate">SPF, DKIM, DMARC hop forensics</div>
                </div>
              </a>
              <a href="/siem#file" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
                  <i data-lucide="file-search" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-indigo-300 truncate">File Hash Analysis</div>
                  <div class="text-[10px] text-slate-400 truncate">VirusTotal multi-engine verdicts</div>
                </div>
              </a>
            </div>
          </div>

          <!-- Section 3: Attack Utilities (Symmetrical Accordion) -->
          <div class="mobile-accordion-group rounded-2xl border border-slate-800 bg-surface-850/80 overflow-hidden shadow-sm">
            <button type="button" class="mobile-accordion-trigger w-full flex items-center justify-between p-3 text-left transition-colors hover:bg-surface-800/80 cursor-pointer" data-target="mob-attack-group">
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 rounded-xl bg-amber-500/15 border border-amber-500/30 text-amber-400 flex items-center justify-center shrink-0">
                  <i data-lucide="crosshair" class="w-4 h-4"></i>
                </div>
                <div>
                  <div class="text-xs font-bold text-white tracking-wide">Attack Utilities</div>
                  <div class="text-[10px] font-mono text-amber-400/80">3 offensive security suites</div>
                </div>
              </div>
              <i data-lucide="chevron-down" class="w-4 h-4 text-slate-400 transition-transform duration-200"></i>
            </button>
            <div id="mob-attack-group" class="mobile-accordion-content hidden border-t border-slate-800/80 bg-surface-900/60 p-2 space-y-1">
              <a href="/crypto" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-purple-500/15 border border-purple-500/30 text-purple-400">
                  <i data-lucide="key-round" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-purple-300 truncate">Crypto & Hash Suite</div>
                  <div class="text-[10px] text-slate-400 truncate">Hash gen, JWT decode, Base64</div>
                </div>
              </a>
              <a href="/gtfobins" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-amber-500/15 border border-amber-500/30 text-amber-400">
                  <i data-lucide="terminal" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-amber-300 truncate">GTFOBins Explorer</div>
                  <div class="text-[10px] text-slate-400 truncate">Unix binaries sudo/suid bypass</div>
                </div>
              </a>
              <a href="/wordlist" class="mobile-menu-item group">
                <div class="mobile-menu-icon bg-emerald-500/15 border border-emerald-500/30 text-emerald-400">
                  <i data-lucide="book-text" class="w-4 h-4"></i>
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-xs font-semibold text-white group-hover:text-emerald-300 truncate">Wordlist Mutator</div>
                  <div class="text-[10px] text-slate-400 truncate">Generate & mutate password lists</div>
                </div>
              </a>
            </div>
          </div>

          <!-- Bottom Actions: About, Contact CIRT -->
          <div class="pt-2 border-t border-slate-800/80 grid grid-cols-2 gap-2">
            <a href="/#about" class="flex items-center justify-center gap-2 p-2.5 rounded-xl bg-surface-850 hover:bg-surface-800 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white transition-colors">
              <i data-lucide="info" class="w-3.5 h-3.5 text-slate-400"></i>
              <span>About</span>
            </a>
            <a href="/#contact" class="flex items-center justify-center gap-2 p-2.5 rounded-xl bg-surface-850 hover:bg-surface-800 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white transition-colors">
              <i data-lucide="mail" class="w-3.5 h-3.5 text-slate-400"></i>
              <span>Contact CIRT</span>
            </a>
          </div>
        </div>
      `;

      // Accordion Toggle handlers
      drawer.querySelectorAll('.mobile-accordion-trigger').forEach(trigger => {
        trigger.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          const targetId = trigger.getAttribute('data-target');
          const content = document.getElementById(targetId);
          const chevron = trigger.querySelector('[data-lucide="chevron-down"]');
          if (!content) return;

          const isHidden = content.classList.contains('hidden');
          if (isHidden) {
            content.classList.remove('hidden');
            if (chevron) chevron.classList.add('rotate-180');
          } else {
            content.classList.add('hidden');
            if (chevron) chevron.classList.remove('rotate-180');
          }
        });
      });

      // In index.html, support switching tabs on link click
      drawer.querySelectorAll('[data-switch-tab]').forEach(link => {
        link.addEventListener('click', (e) => {
          const tab = link.getAttribute('data-switch-tab');
          if (window.switchTab && (window.location.pathname === '/' || window.location.pathname === '')) {
            e.preventDefault();
            window.switchTab(tab);
            window.location.hash = tab;
            drawer.classList.add('hidden');
            const mBtn = document.getElementById('mobile-menu-btn') || document.getElementById('mobile-menu-toggle');
            if (mBtn) {
              mBtn.setAttribute('aria-expanded', 'false');
              mBtn.innerHTML = '<i data-lucide="menu" class="w-5 h-5 text-slate-300"></i>';
              if (window.lucide) window.lucide.createIcons();
            }
          }
        });
      });

      if (window.lucide) window.lucide.createIcons();
    }

    // Floating Back to Top Button (Mobile & Desktop)
    if (!document.getElementById('floating-back-to-top')) {
      const btt = document.createElement('button');
      btt.id = 'floating-back-to-top';
      btt.className = 'fixed bottom-5 right-5 z-40 p-2.5 rounded-xl bg-surface-800/90 hover:bg-surface-700 border border-slate-700/80 text-emerald-400 shadow-2xl backdrop-blur-md opacity-0 pointer-events-none transition-all duration-300 active:scale-90 flex items-center justify-center';
      btt.setAttribute('aria-label', 'Scroll to top');
      btt.innerHTML = '<i data-lucide="arrow-up" class="w-4 h-4"></i>';
      document.body.appendChild(btt);
      if (window.lucide) window.lucide.createIcons();

      window.addEventListener('scroll', () => {
        if (window.scrollY > 300) {
          btt.classList.remove('opacity-0', 'pointer-events-none');
          btt.classList.add('opacity-100', 'pointer-events-auto');
        } else {
          btt.classList.add('opacity-0', 'pointer-events-none');
          btt.classList.remove('opacity-100', 'pointer-events-auto');
        }
      }, { passive: true });

      btt.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
    }

    // Dropdown triggers
    const dropdownToggles = document.querySelectorAll('[data-dropdown-toggle]');
    dropdownToggles.forEach(toggle => {
      const menuId = toggle.dataset.dropdownToggle;
      const menu = document.getElementById(menuId);
      if (!menu) return;

      toggle.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = !menu.classList.contains('hidden');
        closeAllDropdowns();
        if (!isOpen) {
          menu.classList.remove('hidden');
          const chevron = toggle.querySelector('[data-lucide="chevron-down"]');
          if (chevron) chevron.classList.add('rotate-180');
          toggle.classList.add('dropdown-open');
        }
      });
    });

    document.addEventListener('click', () => {
      closeAllDropdowns();
    });
  }

  function closeAllDropdowns() {
    document.querySelectorAll('[data-dropdown-menu]').forEach(m => {
      m.classList.add('hidden');
    });
    document.querySelectorAll('[data-dropdown-toggle]').forEach(btn => {
      btn.classList.remove('dropdown-open');
      const chevron = btn.querySelector('[data-lucide="chevron-down"]');
      if (chevron) chevron.classList.remove('rotate-180');
    });
  }

  function escapeHtml(str) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(str || '').replace(/[&<>"']/g, m => map[m]);
  }

  // ── 6. Automated Favicon & Page Route Synchronizer ────────────
  // Silently warms page routes in background so Firefox & Chrome
  // automatically update their omnibox / history suggestion icons to >_
  function syncAllPageFavicons() {
    if (window._sudodeck_synced_favicons) return;
    window._sudodeck_synced_favicons = true;

    const routes = [
      '/',
      '/siem',
      '/crypto',
      '/gtfobins',
      '/cve',
      '/mac',
      '/wordlist',
      '/news',
      '/pricing',
      '/premium'
    ];

    setTimeout(() => {
      const container = document.createElement('div');
      container.style.cssText = 'position:absolute;width:1px;height:1px;top:-9999px;left:-9999px;opacity:0;pointer-events:none;overflow:hidden;';
      document.body.appendChild(container);

      let delay = 200;
      routes.forEach(route => {
        if (window.location.pathname === route) return;
        setTimeout(() => {
          const iframe = document.createElement('iframe');
          iframe.src = route;
          iframe.setAttribute('tabindex', '-1');
          iframe.setAttribute('aria-hidden', 'true');
          container.appendChild(iframe);
          setTimeout(() => iframe.remove(), 4000);
        }, delay);
        delay += 350;
      });
    }, 1200);
  }

  // ── 5. DOM Ready Bootstrap ─────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      injectCommandPalette();
      initHeaderNavigation();
      syncAllPageFavicons();
    });
  } else {
    injectCommandPalette();
    initHeaderNavigation();
    syncAllPageFavicons();
  }

  // Expose global methods
  window.ThreatIntelNav = {
    openCommandPalette: openPalette,
    closeCommandPalette: closePalette
  };

})();
