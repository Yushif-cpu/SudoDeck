// ═══════════════════════════════════════════════════════════════
//  SudoDeck Threat Intelligence Platform — Client-side Auth & Store
// ═══════════════════════════════════════════════════════════════

(function () {
  'use strict';

  const STORAGE_KEYS = {
    USER: 'sudodeck_auth_user',
    TOKEN: 'sudodeck_auth_token',
    HISTORY: 'sudodeck_investigation_history',
    BILLING: 'sudodeck_billing_data',
    API_KEYS: 'sudodeck_api_keys',
  };

  // Preloaded sample investigation history so the dashboard feels vibrant & realistic immediately
  const INITIAL_HISTORY = [
    {
      id: 'inv_9841',
      tool: 'IP Reputation',
      type: 'ip',
      query: '185.220.101.5',
      verdict: 'Malicious',
      verdictScore: 100,
      badgeColor: 'rose',
      details: 'AbuseIPDB 100% confidence • Tor Exit Node • Active C2 Cobalt Strike Beacon',
      timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
      raw: {
        ip: '185.220.101.5',
        country: 'Germany',
        isp: 'Zwiebelfreunde e.V.',
        abuseScore: 100,
        totalReports: 1420,
        asn: 'AS208323',
      },
    },
    {
      id: 'inv_9840',
      tool: 'Web Traffic & Analytics',
      type: 'traffic',
      query: 'cloudflare.com',
      verdict: 'Clean',
      verdictScore: 0,
      badgeColor: 'emerald',
      details: 'Global Rank #45 • 1.4B Monthly Visits • Low bounce rate (26.4%) • Legit CDN',
      timestamp: new Date(Date.now() - 55 * 60 * 1000).toISOString(),
      raw: {
        domain: 'cloudflare.com',
        globalRank: 45,
        monthlyVisits: '1,420,000,000',
        safetyVerdict: 'Verified Infrastructure',
      },
    },
    {
      id: 'inv_9839',
      tool: 'Domain Intelligence',
      type: 'domain',
      query: 'update-secure-auth24.top',
      verdict: 'Malicious',
      verdictScore: 88,
      badgeColor: 'rose',
      details: 'VirusTotal 14/89 security engines flagged as Phishing / Credential Harvester',
      timestamp: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
      raw: {
        domain: 'update-secure-auth24.top',
        registrar: 'NameCheap Inc.',
        created: '2026-08-12',
        maliciousCount: 14,
      },
    },
    {
      id: 'inv_9838',
      tool: 'Social Media Footprint',
      type: 'social',
      query: 'cyber_spectre99',
      verdict: 'Suspicious',
      verdictScore: 65,
      badgeColor: 'amber',
      details: '14 Active handles identified across Telegram, GitHub, Keybase, HackerOne & Reddit',
      timestamp: new Date(Date.now() - 7 * 3600 * 1000).toISOString(),
      raw: {
        username: 'cyber_spectre99',
        foundCount: 14,
        topPlatforms: ['GitHub', 'Telegram', 'HackerOne', 'Reddit'],
      },
    },
    {
      id: 'inv_9837',
      tool: 'File Hash Analysis',
      type: 'file',
      query: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      verdict: 'Clean',
      verdictScore: 0,
      badgeColor: 'emerald',
      details: 'VirusTotal 0/72 engines • Standard Zero-byte file digest • No threat detected',
      timestamp: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
      raw: {
        hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        type: 'SHA-256',
        verdict: 'Known Safe',
      },
    },
    {
      id: 'inv_9836',
      tool: 'CVE Vulnerability Scanner',
      type: 'cve',
      query: 'CVE-2024-21413',
      verdict: 'Critical',
      verdictScore: 98,
      badgeColor: 'rose',
      details: 'CVSS 9.8 Critical • Microsoft Outlook Moniker RCE / NTLM Hash Leak Vulnerability',
      timestamp: new Date(Date.now() - 48 * 3600 * 1000).toISOString(),
      raw: {
        cve: 'CVE-2024-21413',
        cvss: 9.8,
        severity: 'CRITICAL',
        epss: '84.2%',
      },
    },
    {
      id: 'inv_9835',
      tool: 'MAC & OUI Lookup',
      type: 'mac',
      query: '00:1A:2B:3C:4D:5E',
      verdict: 'Clean',
      verdictScore: 0,
      badgeColor: 'emerald',
      details: 'Vendor: Cisco Systems, Inc. • IEEE 24-bit OUI block • Unicast hardware address',
      timestamp: new Date(Date.now() - 72 * 3600 * 1000).toISOString(),
      raw: {
        mac: '00:1A:2B:3C:4D:5E',
        vendor: 'Cisco Systems, Inc.',
        prefix: '00:1A:2B',
      },
    }
  ];

  const DEFAULT_USER = {
    id: 'usr_cirt_9042',
    name: 'Alex Vance',
    email: 'alex.vance@sudodeck.io',
    phone: '+1 (555) 234-8901',
    organization: 'SecOps Incident Response Team',
    role: 'Lead Threat Hunter',
    plan: 'pro',
    securityClearance: 'Tier 3 (Enterprise)',
    joinedDate: '2025-11-14T08:30:00.000Z',
    twoFactorEnabled: true,
    avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
    apiQuota: {
      used: 420,
      total: 1000,
      resetHours: 14,
    },
  };

  const DEFAULT_BILLING = {
    email: 'alex.vance@sudodeck.io',
    phone: '+1 (555) 234-8901',
    company: 'SudoDeck Security Labs LLC',
    taxId: 'US-94827103',
    address: '100 Cyberway Blvd, Suite 400, Austin, TX 78701',
    country: 'United States',
    plan: 'pro',
    planName: 'Pro Cyber Analyst',
    planPrice: '$29 / month',
    renewalDate: 'October 14, 2026',
    paymentMethod: {
      brand: 'Mastercard',
      last4: '4821',
      expiry: '08/28',
      holder: 'Alex Vance',
    },
    invoices: [
      {
        id: 'INV-2026-091',
        date: '2026-09-01',
        description: 'SudoDeck Pro Analyst Subscription (Monthly)',
        amount: '$29.00',
        status: 'Paid',
        currency: 'USD',
      },
      {
        id: 'INV-2026-084',
        date: '2026-08-01',
        description: 'SudoDeck Pro Analyst Subscription (Monthly)',
        amount: '$29.00',
        status: 'Paid',
        currency: 'USD',
      },
      {
        id: 'INV-2026-077',
        date: '2026-07-01',
        description: 'SudoDeck Pro Analyst Subscription (Monthly)',
        amount: '$29.00',
        status: 'Paid',
        currency: 'USD',
      },
      {
        id: 'INV-2026-069',
        date: '2026-06-01',
        description: 'SudoDeck Pro Analyst Subscription (Monthly)',
        amount: '$29.00',
        status: 'Paid',
        currency: 'USD',
      },
    ],
  };

  const DEFAULT_API_KEYS = [
    {
      id: 'key_prod_89a1',
      name: 'Primary CLI & Automation Key',
      key: 'sd_live_98a48b1990c741e2b489aa0912fc88',
      keyMasked: 'sd_live_98a4••••••••••••88',
      created: '2026-02-10',
      lastUsed: '12 mins ago',
      status: 'active',
    },
    {
      id: 'key_siem_11b2',
      name: 'Splunk / SIEM Log Ingestion',
      key: 'sd_live_11b98a002cf711d9a277bc4490ef11',
      keyMasked: 'sd_live_11b9••••••••••••11',
      created: '2026-05-22',
      lastUsed: '2 hours ago',
      status: 'active',
    },
  ];

  window.SudoDeckAuth = {
    // ── Check if logged in ──────────────────────────────────────────
    isLoggedIn() {
      try {
        const u = localStorage.getItem(STORAGE_KEYS.USER);
        return !!u;
      } catch {
        return false;
      }
    },

    // ── Get User Profile ───────────────────────────────────────────
    getUser() {
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.USER);
        if (raw) return JSON.parse(raw);
      } catch {}
      // If none saved yet, return default demo profile
      return { ...DEFAULT_USER };
    },

    // ── Set User Profile ───────────────────────────────────────────
    setUser(userData) {
      try {
        const current = this.getUser();
        const merged = { ...current, ...userData };
        localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(merged));
        return merged;
      } catch {
        return userData;
      }
    },

    // ── Sign In ────────────────────────────────────────────────────
    async login(email, password) {
      const cleanEmail = String(email || '').trim();
      let user = {
        ...DEFAULT_USER,
        email: cleanEmail || DEFAULT_USER.email,
        name: cleanEmail ? cleanEmail.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : DEFAULT_USER.name,
      };

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: cleanEmail, password }),
        });
        const data = await res.json();
        if (data.success && data.user) {
          user = { ...DEFAULT_USER, ...data.user };
          if (data.token) localStorage.setItem(STORAGE_KEYS.TOKEN, data.token);
        }
      } catch (e) {
        console.warn('Network call failed, using client storage:', e);
      }

      localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));
      return { success: true, user };
    },

    // ── Sign Up ────────────────────────────────────────────────────
    async signup(name, email, phone, password) {
      const cleanEmail = String(email || '').trim();
      const cleanName = String(name || '').trim() || cleanEmail.split('@')[0];
      const cleanPhone = String(phone || '').trim();

      const user = {
        ...DEFAULT_USER,
        id: `usr_${Math.random().toString(36).substring(2, 9)}`,
        name: cleanName,
        email: cleanEmail,
        phone: cleanPhone || '+1 (555) 000-0000',
        joinedDate: new Date().toISOString(),
      };

      try {
        const res = await fetch('/api/auth/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: cleanName, email: cleanEmail, phone: cleanPhone, password }),
        });
        const data = await res.json();
        if (data.success && data.token) {
          localStorage.setItem(STORAGE_KEYS.TOKEN, data.token);
        }
      } catch (e) {
        console.warn('Signup network call notice:', e);
      }

      // Also update billing email and phone automatically
      const billing = this.getBilling();
      billing.email = cleanEmail;
      billing.phone = cleanPhone || billing.phone;
      this.updateBilling(billing);

      localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));
      return { success: true, user };
    },

    // ── Google OAuth Flow ──────────────────────────────────────────
    async loginWithGoogle() {
      // Simulates real Google OAuth popup / sign-in with rich profile
      const googleUser = {
        ...DEFAULT_USER,
        id: `usr_google_${Math.random().toString(36).substring(2, 8)}`,
        name: 'Alex Vance',
        email: 'alex.vance@gmail.com',
        avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
        provider: 'google',
      };

      try {
        const res = await fetch('/api/auth/google', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: googleUser.email, name: googleUser.name }),
        });
        const data = await res.json();
        if (data.success && data.token) {
          localStorage.setItem(STORAGE_KEYS.TOKEN, data.token);
        }
      } catch {}

      localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(googleUser));
      return { success: true, user: googleUser };
    },

    // ── Log Out ────────────────────────────────────────────────────
    logout() {
      try {
        localStorage.removeItem(STORAGE_KEYS.USER);
        localStorage.removeItem(STORAGE_KEYS.TOKEN);
      } catch {}
      window.location.href = '/login';
    },

    // ── Investigation History ──────────────────────────────────────
    getHistory() {
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.HISTORY);
        if (raw) return JSON.parse(raw);
      } catch {}
      // Initialize with default rich history
      localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(INITIAL_HISTORY));
      return INITIAL_HISTORY;
    },

    addHistoryItem(item) {
      if (!item || !item.query) return;
      try {
        const list = this.getHistory();
        const newItem = {
          id: `inv_${Date.now().toString(36)}`,
          tool: item.tool || 'Indicator Analysis',
          type: item.type || 'ip',
          query: String(item.query).trim(),
          verdict: item.verdict || 'Informational',
          verdictScore: item.verdictScore || 0,
          badgeColor: item.badgeColor || (item.verdict === 'Malicious' ? 'rose' : item.verdict === 'Suspicious' ? 'amber' : 'emerald'),
          details: item.details || 'Investigation recorded',
          timestamp: new Date().toISOString(),
          raw: item.raw || null,
        };
        // Avoid duplicate top item
        const filtered = list.filter(i => !(i.type === newItem.type && i.query.toLowerCase() === newItem.query.toLowerCase()));
        filtered.unshift(newItem);
        localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(filtered.slice(0, 100)));
        return newItem;
      } catch (err) {
        console.error('Failed to add history item:', err);
      }
    },

    deleteHistoryItem(id) {
      try {
        const list = this.getHistory();
        const updated = list.filter(i => i.id !== id);
        localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(updated));
        return updated;
      } catch {
        return [];
      }
    },

    clearHistory() {
      try {
        localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify([]));
      } catch {}
    },

    // ── Billing Profile ────────────────────────────────────────────
    getBilling() {
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.BILLING);
        if (raw) return JSON.parse(raw);
      } catch {}
      localStorage.setItem(STORAGE_KEYS.BILLING, JSON.stringify(DEFAULT_BILLING));
      return { ...DEFAULT_BILLING };
    },

    updateBilling(data) {
      try {
        const current = this.getBilling();
        const merged = { ...current, ...data };
        localStorage.setItem(STORAGE_KEYS.BILLING, JSON.stringify(merged));
        // Also sync with server endpoint asynchronously
        fetch('/api/user/billing', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(merged),
        }).catch(() => {});
        return merged;
      } catch {
        return data;
      }
    },

    // ── API Keys ───────────────────────────────────────────────────
    getApiKeys() {
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.API_KEYS);
        if (raw) return JSON.parse(raw);
      } catch {}
      localStorage.setItem(STORAGE_KEYS.API_KEYS, JSON.stringify(DEFAULT_API_KEYS));
      return [...DEFAULT_API_KEYS];
    },

    addApiKey(name) {
      const keys = this.getApiKeys();
      const randHex = Math.random().toString(16).substring(2, 10) + Math.random().toString(16).substring(2, 10);
      const fullKey = `sd_live_${randHex}`;
      const newKey = {
        id: `key_${Date.now().toString(36)}`,
        name: name ? String(name).trim() : 'Personal CLI Token',
        key: fullKey,
        keyMasked: `${fullKey.slice(0, 11)}••••••••••••${fullKey.slice(-4)}`,
        created: new Date().toISOString().split('T')[0],
        lastUsed: 'Just now',
        status: 'active',
      };
      keys.unshift(newKey);
      localStorage.setItem(STORAGE_KEYS.API_KEYS, JSON.stringify(keys));
      return newKey;
    },

    revokeApiKey(id) {
      const keys = this.getApiKeys().filter(k => k.id !== id);
      localStorage.setItem(STORAGE_KEYS.API_KEYS, JSON.stringify(keys));
      return keys;
    }
  };

})();
