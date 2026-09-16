import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { getPayloads } from '../services/payloads.service.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// GET /api/payloads
router.get('/', async (req, res) => {
  try {
    const category = req.query.category || 'all';
    const query = req.query.q || '';
    const result = await getPayloads(category, query);
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
