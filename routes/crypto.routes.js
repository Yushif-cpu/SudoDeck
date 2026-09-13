// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — Crypto & Encoding Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import {
  processCryptoRequest,
  executeAllHashes,
  smartAnalyzeInput,
  ALGORITHM_REGISTRY,
} from '../services/crypto.service.js';
import { asyncHandler, AppError } from '../middleware/errorHandler.js';

const router = Router();

// ── GET /api/crypto/algorithms ──────────────────────────────────
router.get('/algorithms', (req, res) => {
  res.json({
    success: true,
    data: ALGORITHM_REGISTRY,
  });
});

// ── POST /api/crypto/process ────────────────────────────────────
router.post(
  '/process',
  asyncHandler(async (req, res) => {
    const { text, category, algorithm, mode, options } = req.body;

    if (text === undefined || text === null) {
      throw new AppError('Input text is required for transformation.', 400, 'MISSING_TEXT');
    }

    const result = processCryptoRequest({
      text,
      category,
      algorithm,
      mode,
      options,
    });

    res.json({
      success: true,
      data: result,
    });
  })
);

// ── POST /api/crypto/hash-all ───────────────────────────────────
router.post(
  '/hash-all',
  asyncHandler(async (req, res) => {
    const { text } = req.body;

    if (text === undefined || text === null) {
      throw new AppError('Input text is required to calculate hashes.', 400, 'MISSING_TEXT');
    }

    const result = executeAllHashes(text);

    res.json({
      success: true,
      data: result,
    });
  })
);

// ── POST /api/crypto/analyze (Smart Analyzer & Identifier) ─────
router.post(
  '/analyze',
  asyncHandler(async (req, res) => {
    const { text } = req.body;

    if (text === undefined || text === null) {
      throw new AppError('Input text is required for smart analysis.', 400, 'MISSING_TEXT');
    }

    const result = smartAnalyzeInput(text);

    res.json({
      success: true,
      data: result,
    });
  })
);

export default router;
