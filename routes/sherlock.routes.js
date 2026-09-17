// ══════════════════════════════════════════════════════════════════
//  SudoDeck — Sherlock / Maigret OSINT Routes
// ══════════════════════════════════════════════════════════════════

import { Router } from 'express';
import { runSherlockScan, PLATFORMS } from '../services/sherlock.service.js';
import { asyncHandler, AppError } from '../middleware/errorHandler.js';

const router = Router();

// GET /api/sherlock/platforms - List all supported platforms
router.get(
  '/platforms',
  asyncHandler(async (req, res) => {
    res.json({
      success: true,
      total: PLATFORMS.length,
      platforms: PLATFORMS.map((p) => ({
        name: p.name,
        category: p.category,
        icon: p.icon,
        exampleUrl: p.url.replace(/\{u\}/g, 'username'),
      })),
    });
  })
);

// GET /api/sherlock?username=xyz
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const username = req.query.username || req.query.u;
    if (!username || typeof username !== 'string' || username.trim().length < 2) {
      throw new AppError('A valid username (min 2 characters) is required (e.g. ?username=target).', 400, 'INVALID_USERNAME');
    }

    const data = await runSherlockScan(username);
    res.json({
      success: true,
      data,
    });
  })
);

// POST /api/sherlock
router.post(
  '/',
  asyncHandler(async (req, res) => {
    const { username } = req.body;
    if (!username || typeof username !== 'string' || username.trim().length < 2) {
      throw new AppError('A valid username (min 2 characters) is required.', 400, 'INVALID_USERNAME');
    }

    const data = await runSherlockScan(username);
    res.json({
      success: true,
      data,
    });
  })
);

export default router;
