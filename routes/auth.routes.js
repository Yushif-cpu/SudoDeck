// ═══════════════════════════════════════════════════════════════
//  SudoDeck Threat Intelligence Platform — Auth & User Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';

const router = Router();

// In-memory fallback / mock store for persistent demo session
const DEFAULT_DEMO_USER = {
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
  apiQuota: {
    used: 420,
    total: 1000,
    resetTime: '24h',
  },
  billing: {
    email: 'billing@sudodeck.io',
    phone: '+1 (555) 234-8901',
    company: 'SudoDeck Security Labs LLC',
    taxId: 'US-94827103',
    address: '100 Cyberway Blvd, Suite 400, Austin, TX 78701',
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
    ],
  },
  apiKeys: [
    {
      id: 'key_prod_89a1',
      name: 'Primary CLI & CI/CD Key',
      prefix: 'sd_live_98a...',
      keyMasked: 'sd_live_98a48b1990c741e2b4',
      created: '2026-02-10',
      lastUsed: '2 mins ago',
      status: 'active',
    },
    {
      id: 'key_siem_11b2',
      name: 'Splunk / SIEM Integration Webhook',
      prefix: 'sd_live_11b...',
      keyMasked: 'sd_live_11b98a002cf711d9a2',
      created: '2026-05-22',
      lastUsed: '1 hour ago',
      status: 'active',
    },
  ],
};

// ── GET /api/auth/me ─────────────────────────────────────────────
router.get('/auth/me', (req, res) => {
  return res.json({
    success: true,
    user: DEFAULT_DEMO_USER,
  });
});

// ── POST /api/auth/login ─────────────────────────────────────────
router.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Email and password credentials are required.',
    });
  }

  const cleanEmail = String(email).trim().toLowerCase();
  
  // Return successful authenticated session
  const user = {
    ...DEFAULT_DEMO_USER,
    email: cleanEmail,
    name: cleanEmail.includes('alex') ? DEFAULT_DEMO_USER.name : cleanEmail.split('@')[0].replace('.', ' ').replace(/^./, str => str.toUpperCase()),
  };

  const token = `sd_jwt_${Buffer.from(`${user.id}:${Date.now()}`).toString('base64')}`;

  return res.json({
    success: true,
    message: 'Authentication successful. Terminal session established.',
    token,
    user,
  });
});

// ── POST /api/auth/signup ────────────────────────────────────────
router.post('/auth/signup', (req, res) => {
  const { name, email, phone, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Email and secure password are required.',
    });
  }

  const cleanEmail = String(email).trim().toLowerCase();
  const cleanName = String(name || cleanEmail.split('@')[0]).trim();
  const cleanPhone = String(phone || '').trim();

  const user = {
    ...DEFAULT_DEMO_USER,
    id: `usr_${Math.random().toString(36).substring(2, 9)}`,
    name: cleanName,
    email: cleanEmail,
    phone: cleanPhone || '+1 (555) 000-0000',
    billing: {
      ...DEFAULT_DEMO_USER.billing,
      email: cleanEmail,
      phone: cleanPhone || DEFAULT_DEMO_USER.billing.phone,
    },
    joinedDate: new Date().toISOString(),
  };

  const token = `sd_jwt_${Buffer.from(`${user.id}:${Date.now()}`).toString('base64')}`;

  return res.json({
    success: true,
    message: 'User registered and security clearance granted.',
    token,
    user,
  });
});

// ── POST /api/auth/google ────────────────────────────────────────
router.post('/auth/google', (req, res) => {
  const { email, name, picture } = req.body || {};
  const userEmail = email ? String(email).trim().toLowerCase() : 'analyst.google@sudodeck.io';
  const userName = name ? String(name).trim() : 'Google SecOps User';

  const user = {
    ...DEFAULT_DEMO_USER,
    id: `usr_g_${Math.random().toString(36).substring(2, 9)}`,
    name: userName,
    email: userEmail,
    avatar: picture || null,
    provider: 'google',
    billing: {
      ...DEFAULT_DEMO_USER.billing,
      email: userEmail,
    },
  };

  const token = `sd_jwt_g_${Buffer.from(`${user.id}:${Date.now()}`).toString('base64')}`;

  return res.json({
    success: true,
    message: 'Google Single Sign-On authenticated successfully.',
    token,
    user,
  });
});

// ── POST /api/user/profile ───────────────────────────────────────
router.post('/user/profile', (req, res) => {
  const { name, email, phone, organization } = req.body || {};

  if (!email) {
    return res.status(400).json({
      success: false,
      error: 'Valid email address is mandatory.',
    });
  }

  return res.json({
    success: true,
    message: 'Profile records and identity parameters synchronized.',
    updated: {
      name: String(name || '').trim(),
      email: String(email).trim(),
      phone: String(phone || '').trim(),
      organization: String(organization || '').trim(),
      updatedAt: new Date().toISOString(),
    },
  });
});

// ── POST /api/user/billing ───────────────────────────────────────
router.post('/user/billing', (req, res) => {
  const { email, phone, company, taxId, address, plan } = req.body || {};

  if (!email) {
    return res.status(400).json({
      success: false,
      error: 'Billing contact email is required.',
    });
  }

  return res.json({
    success: true,
    message: 'Billing dispatch records and contact details saved.',
    billing: {
      email: String(email).trim(),
      phone: String(phone || '').trim(),
      company: String(company || '').trim(),
      taxId: String(taxId || '').trim(),
      address: String(address || '').trim(),
      plan: plan || 'pro',
      updatedAt: new Date().toISOString(),
    },
  });
});

// ── POST /api/user/api-keys/generate ─────────────────────────────
router.post('/user/api-keys/generate', (req, res) => {
  const { name } = req.body || {};
  const randomHex = Math.random().toString(16).substring(2, 10) + Math.random().toString(16).substring(2, 10);
  const fullKey = `sd_live_${randomHex}`;
  const keyObj = {
    id: `key_${Math.random().toString(36).substring(2, 8)}`,
    name: name ? String(name).trim() : 'Personal Investigation Key',
    prefix: `${fullKey.slice(0, 11)}...`,
    keyMasked: `${fullKey.slice(0, 16)}••••••••`,
    created: new Date().toISOString().split('T')[0],
    lastUsed: 'Never',
    status: 'active',
  };

  return res.json({
    success: true,
    message: 'New production API token generated. Save it securely.',
    key: fullKey,
    keyMetadata: keyObj,
  });
});

export default router;
