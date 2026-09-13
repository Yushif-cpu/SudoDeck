import { Router } from 'express';
import { checkDomain } from '../services/domain.service.js';
import { validateDomain } from '../middleware/validator.js';
import { asyncHandler } from '../middleware/errorHandler.js';

const router = Router();

router.post(
  '/check-domain',
  validateDomain,
  asyncHandler(async (req, res) => {
    const { domain } = req.validatedInput;
    const result = await checkDomain(domain);

    res.json({
      success: true,
      type: 'domain',
      data: result,
    });
  })
);

export default router;
