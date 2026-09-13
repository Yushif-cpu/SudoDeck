// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — IP & Network Utilities Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import {
  convertIP,
  calculateSubnet,
  pingHost,
  resolveAllDNS,
} from '../services/utils.service.js';
import { asyncHandler, AppError } from '../middleware/errorHandler.js';

const router = Router();

// ── POST /api/utils/convert-ip ──────────────────────────────────
router.post(
  '/convert-ip',
  asyncHandler(async (req, res) => {
    const { ip } = req.body;
    if (!ip && ip !== 0) {
      throw new AppError('IP address or integer is required (e.g. 192.168.1.1 or 3232235777).', 400, 'MISSING_FIELD');
    }

    const result = convertIP(ip);
    res.json({
      success: true,
      data: result,
    });
  })
);

// ── POST /api/utils/subnet ──────────────────────────────────────
router.post(
  '/subnet',
  asyncHandler(async (req, res) => {
    const { cidr } = req.body;
    if (!cidr) {
      throw new AppError('CIDR notation is required (e.g. 192.168.1.0/24).', 400, 'MISSING_FIELD');
    }

    const result = calculateSubnet(cidr);
    res.json({
      success: true,
      data: result,
    });
  })
);

// ── POST /api/utils/ping ────────────────────────────────────────
router.post(
  '/ping',
  asyncHandler(async (req, res) => {
    const { host, count } = req.body;
    if (!host) {
      throw new AppError('Target host or IP address is required for ping.', 400, 'MISSING_FIELD');
    }

    const result = await pingHost(host, count || 4);
    res.json({
      success: true,
      data: result,
    });
  })
);

// ── POST /api/utils/dns ─────────────────────────────────────────
router.post(
  '/dns',
  asyncHandler(async (req, res) => {
    const { domain } = req.body;
    if (!domain) {
      throw new AppError('Domain name is required for DNS record lookup.', 400, 'MISSING_FIELD');
    }

    const result = await resolveAllDNS(domain);
    res.json({
      success: true,
      data: result,
    });
  })
);

export default router;
