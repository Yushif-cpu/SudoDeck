// ═══════════════════════════════════════════════════════════════
//  The Hacker News Feed API Routes
// ═══════════════════════════════════════════════════════════════

import express from 'express';
import { getHackerNewsFeed } from '../services/news.service.js';

const router = express.Router();

/**
 * GET /api/news
 * Returns real-time news articles from The Hacker News RSS feed
 */
router.get('/news', async (req, res, next) => {
  try {
    const force = req.query.force === 'true';
    const feed = await getHackerNewsFeed(force);
    return res.json(feed);
  } catch (error) {
    console.error('News Feed Route Error:', error.message);
    return res.status(502).json({
      success: false,
      error: 'Unable to synchronize live feed from The Hacker News.',
      details: error.message,
    });
  }
});

export default router;
