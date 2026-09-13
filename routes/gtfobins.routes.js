// ═══════════════════════════════════════════════════════════════
//  ThreatIntel — GTFOBins Explorer Routes
// ═══════════════════════════════════════════════════════════════

import { Router } from 'express';
import { getGtfobinsList, getGtfobinsBinaryDetails } from '../services/gtfobins.service.js';

const router = Router();

/**
 * GET /api/gtfobins
 * Query parameters:
 *   - q / search: text filter for binary name or description
 *   - function / category: filter by function (e.g. 'shell', 'sudo', 'suid', 'file-read', 'file-write')
 */
router.get('/', (req, res) => {
  try {
    const data = getGtfobinsList(req.query);
    return res.json({
      success: true,
      ...data,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: {
        message: 'Failed to retrieve GTFOBins catalog',
        details: err.message,
      },
    });
  }
});

/**
 * GET /api/gtfobins/:binary
 * Returns detailed functions and terminal execution commands for a specific binary.
 */
router.get('/:binary', (req, res) => {
  try {
    const { binary } = req.params;
    const details = getGtfobinsBinaryDetails(binary);

    if (!details) {
      return res.status(404).json({
        success: false,
        error: {
          message: `Binary '${binary}' not found in GTFOBins internal catalog.`,
        },
      });
    }

    return res.json({
      success: true,
      data: details,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: {
        message: 'Failed to retrieve binary details',
        details: err.message,
      },
    });
  }
});

export default router;
