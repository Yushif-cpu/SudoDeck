import rateLimit from 'express-rate-limit';

// ── General rate limiter (all routes) ───────────────────────────
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1500,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests. Please try again later.',
    },
  },
});

// ── Standard API limiter ────────────────────────────────────────
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'API_RATE_LIMIT_EXCEEDED',
      message: 'API rate limit exceeded. Maximum 500 requests per 15 minutes.',
    },
  },
});

// ── Heavy Recon & Multi-Query limiter (/api/sherlock, /api/discover) ──
export const heavyScanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 deep scans per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'SCAN_RATE_LIMIT_EXCEEDED',
      message: 'Scan frequency limit exceeded. Please wait a moment before initiating another deep scan.',
    },
  },
});

// ── Geocoding Proxy limiter (Complies with OSM Nominatim 1 req/sec policy) ──
export const geocodeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 geocode queries per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'GEOCODE_RATE_LIMIT_EXCEEDED',
      message: 'Geocoding rate limit exceeded. Please wait a few seconds.',
    },
  },
});

// ── Contact Form anti-spam limiter ──────────────────────────────
export const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 6, // 6 submissions per 15 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'CONTACT_RATE_LIMIT_EXCEEDED',
      message: 'Too many submissions from your address. Please try again later.',
    },
  },
});

// ── Web Traffic & Similarweb Apify Limiter (Protects paid compute units) ──
export const trafficLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 15, // Max 15 traffic queries per 5 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'TRAFFIC_RATE_LIMIT_EXCEEDED',
      message: 'Traffic intelligence rate limit exceeded. Please wait a few minutes before querying additional domains.',
    },
  },
});



