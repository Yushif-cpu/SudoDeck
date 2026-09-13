// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — CVE Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import { checkCVE } from '../services/nvd.service.js';
import { asyncHandler, AppError } from '../middleware/errorHandler.js';

const router = Router();

// ── POST /api/check-cve ─────────────────────────────────────────
router.post(
  '/check-cve',
  asyncHandler(async (req, res) => {
    const { cveId } = req.body;
    if (!cveId) {
      throw new AppError('CVE identifier is required (e.g. CVE-2021-44228).', 400, 'MISSING_CVE_ID');
    }

    const result = await checkCVE(cveId);
    res.json({
      success: true,
      data: result,
    });
  })
);

export default router;
