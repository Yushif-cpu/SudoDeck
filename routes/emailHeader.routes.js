// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — Email Header Analysis Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import { parseEmailHeaders, parseRfc2047Detailed } from '../services/emailHeader.service.js';
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

// ── POST /api/decode-subject ────────────────────────────────────
router.post(
  '/decode-subject',
  asyncHandler(async (req, res) => {
    const raw = req.body.subject || req.body.rawSubject || req.body.text || '';
    if (typeof raw !== 'string') {
      throw new AppError('Subject must be a string.', 400, 'INVALID_INPUT');
    }

    const result = parseRfc2047Detailed(raw);
    res.json({
      success: true,
      data: result,
    });
  })
);

export default router;

