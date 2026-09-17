// ═══════════════════════════════════════════════════════════════
//  Web Traffic & Audience Intelligence Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import { getDomainTraffic, normalizeDomain } from '../services/traffic.service.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { trafficLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// Apply traffic rate limiter
router.use(trafficLimiter);

const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

// POST /api/check-traffic
router.post(
  '/check-traffic',
  asyncHandler(async (req, res) => {
    const rawDomain = req.body.domain || req.body.target;
    const forceFresh = Boolean(req.body.forceFresh || req.body.refresh);

    const domain = normalizeDomain(rawDomain);
    if (!domain || !DOMAIN_REGEX.test(domain)) {
      return res.status(400).json({
        success: false,
        error: 'Valid domain name is required (e.g. github.com)',
      });
    }

    const result = await getDomainTraffic(domain, forceFresh);
    return res.json(result);
  })
);

// GET /api/check-traffic?domain=github.com
router.get(
  '/check-traffic',
  asyncHandler(async (req, res) => {
    const rawDomain = req.query.domain || req.query.target;
    const forceFresh = req.query.refresh === 'true' || req.query.forceFresh === 'true';

    const domain = normalizeDomain(rawDomain);
    if (!domain || !DOMAIN_REGEX.test(domain)) {
      return res.status(400).json({
        success: false,
        error: 'Query parameter "domain" must be a valid domain name (e.g. ?domain=github.com)',
      });
    }

    const result = await getDomainTraffic(domain, forceFresh);
    return res.json(result);
  })
);

export default router;
