// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — Email Header Analysis Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import { parseEmailHeaders } from '../services/emailHeader.service.js';
import { asyncHandler, AppError } from '../middleware/errorHandler.js';

const router = Router();

// ── POST /api/analyze-header ────────────────────────────────────
router.post(
  '/analyze-header',
  asyncHandler(async (req, res) => {
    const { rawHeader } = req.body;
    if (!rawHeader || typeof rawHeader !== 'string' || !rawHeader.trim()) {
      throw new AppError('Please provide raw email headers in rawHeader body field.', 400, 'MISSING_HEADER_CONTENT');
    }

    const result = parseEmailHeaders(rawHeader);
    res.json({
      success: true,
      data: result,
    });
  })
);

export default router;
