// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — MAC Lookup Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import { lookupMacVendor } from '../services/macvendors.service.js';
import { asyncHandler, AppError } from '../middleware/errorHandler.js';

const router = Router();

// ── POST /api/mac-lookup ────────────────────────────────────────
router.post(
  '/mac-lookup',
  asyncHandler(async (req, res) => {
    const rawMac = req.body.mac || req.body.macAddress;
    if (!rawMac) {
      throw new AppError('MAC address is required (e.g. 00:1A:2B:3C:4D:5E or 00-1A-2B).', 400, 'MISSING_MAC');
    }

    const result = await lookupMacVendor(rawMac);

    res.json({
      success: true,
      vendor: result.vendor,
      data: result,
    });
  })
);

export default router;
