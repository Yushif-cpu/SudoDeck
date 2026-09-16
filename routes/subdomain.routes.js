// ═══════════════════════════════════════════════════════════════
//  SudoDeck OSINT — Subdomain & Resource Discovery Route
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import { discoverSubdomains } from '../services/subdomain.service.js';

const router = Router();

/**
 * POST /api/discover or POST /api/subdomain/discover
 * Request body: { domain: string }
 */
router.post('/discover', async (req, res, next) => {
  try {
    const { domain } = req.body || {};
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Target domain is required. Please provide a valid domain name (e.g., target.com).',
      });
    }

    const payload = await discoverSubdomains(domain);
    return res.json(payload);
  } catch (error) {
    if (error.message && error.message.includes('Invalid target domain')) {
      return res.status(400).json({
        success: false,
        error: error.message,
      });
    }
    return next(error);
  }
});

/**
 * GET /api/discover?domain=...
 */
router.get('/discover', async (req, res, next) => {
  try {
    const domain = req.query.domain;
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Target domain query parameter is required (e.g., /api/discover?domain=target.com)',
      });
    }

    const payload = await discoverSubdomains(String(domain));
    return res.json(payload);
  } catch (error) {
    if (error.message && error.message.includes('Invalid target domain')) {
      return res.status(400).json({
        success: false,
        error: error.message,
      });
    }
    return next(error);
  }
});

export default router;
