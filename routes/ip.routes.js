import { Router } from 'express';
import { checkIP } from '../services/abuseipdb.service.js';
import { validateIP } from '../middleware/validator.js';
import { asyncHandler } from '../middleware/errorHandler.js';

const router = Router();

router.post(
  '/check-ip',
  validateIP,
  asyncHandler(async (req, res) => {
    const { ip } = req.validatedInput;
    const result = await checkIP(ip);

    res.json({
      success: true,
      type: 'ip',
      data: result,
    });
  })
);

export default router;
