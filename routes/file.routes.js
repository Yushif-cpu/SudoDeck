import { Router } from 'express';
import crypto from 'crypto';
import multer from 'multer';
import { checkFileHash } from '../services/virustotal.service.js';
import { validateHash } from '../middleware/validator.js';
import { asyncHandler, AppError } from '../middleware/errorHandler.js';

const router = Router();

// Multer config — memory storage with 16MB limit (prevents OOM on concurrent uploads)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 16 * 1024 * 1024 }, // 16MB
});

// ── File upload + hash analysis ─────────────────────────────────
router.post(
  '/check-file',
  upload.single('file'),
  asyncHandler(async (req, res) => {
    if (!req.file) {
      throw new AppError('No file uploaded.', 400, 'VALIDATION_ERROR');
    }

    // Calculate SHA-256 hash from file buffer
    const sha256 = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

    const result = await checkFileHash(sha256);

    const safeOriginalName = (req.file.originalname || 'unknown')
      .replace(/[^\w.\- ()]/g, '_')
      .slice(0, 150);

    res.json({
      success: true,
      type: 'file',
      uploadedFile: {
        originalName: safeOriginalName,
        size: req.file.size,
        mimeType: req.file.mimetype,
      },
      hash: sha256,
      data: result,
    });
  })
);

// ── Direct hash lookup (no file upload needed) ──────────────────
router.post(
  '/check-hash',
  validateHash,
  asyncHandler(async (req, res) => {
    const { hash } = req.validatedInput;
    const result = await checkFileHash(hash);

    res.json({
      success: true,
      type: 'hash',
      hash,
      data: result,
    });
  })
);

export default router;
