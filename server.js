// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — Server Entry Point
// ═══════════════════════════════════════════════════════════════

import dotenv from 'dotenv';
dotenv.config({ quiet: true });

import config from './config/env.js';
import express from 'express';
import axios from 'axios';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// ── Middleware ───────────────────────────────────────────────────
import {
  generalLimiter,
  apiLimiter,
  heavyScanLimiter,
  geocodeLimiter,
  contactLimiter,
} from './middleware/rateLimiter.js';
import { errorHandler } from './middleware/errorHandler.js';

// ── Routes ──────────────────────────────────────────────────────
import ipRoutes from './routes/ip.routes.js';
import fileRoutes from './routes/file.routes.js';
import domainRoutes from './routes/domain.routes.js';
import utilsRoutes from './routes/utils.routes.js';
import cveRoutes from './routes/cve.routes.js';
import emailHeaderRoutes from './routes/emailHeader.routes.js';
import macRoutes from './routes/mac.routes.js';
import cryptoRoutes from './routes/crypto.routes.js';
import gtfobinsRoutes from './routes/gtfobins.routes.js';
import newsRoutes from './routes/news.routes.js';
import subdomainRoutes from './routes/subdomain.routes.js';
import payloadsRoutes from './routes/payloads.routes.js';
import sherlockRoutes from './routes/sherlock.routes.js';
import trafficRoutes from './routes/traffic.routes.js';
import { fetchRecentMaliciousIPs } from './services/threatfox.service.js';

// ── Path setup ──────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Express app ─────────────────────────────────────────────────
const app = express();

// Enable reverse proxy support (Crucial for Coolify, Traefik, Docker, Cloudflare, Nginx)
app.set('trust proxy', 1);

// ── Security middleware ─────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://unpkg.com", "https://cdn.jsdelivr.net"],
      workerSrc: ["'self'", "blob:", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.tailwindcss.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'", "https://nominatim.openstreetmap.org", "https://tessdata.projectnaptha.com", "https://cdn.jsdelivr.net", "blob:", "data:", "https:"],
    },
  },
}));

const corsOptions = {
  origin: (origin, callback) => {
    // Allow non-browser agents (cURL, Postman, automated monitors, internal health checks)
    if (!origin) return callback(null, true);

    const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
    const envOrigins = process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)
      : [];

    // If wildcard or explicit whitelist is defined
    if (envOrigins.includes('*')) {
      return callback(null, true);
    }

    if (envOrigins.length > 0) {
      if (isLocal || envOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Cross-Origin Request Blocked by ThreatIntel CORS Policy'));
    }

    // Default for cloud & container deployments (Coolify, Render, VPS, local):
    // Allow the request origin so that frontend API calls from the assigned domain succeed
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(compression());
app.use(generalLimiter);
app.use(express.json({ limit: '1mb' }));

// ── Favicons & Root ──────────────────────────────────────────────
app.get('/favicon.ico', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.type('image/x-icon');
  res.sendFile(join(__dirname, 'public', 'favicon.ico'));
});

app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// ── Static files with dynamic cache control ─────────────────────
app.use(express.static(join(__dirname, 'public'), {
  etag: false,
  setHeaders: (res, path) => {
    if (path.endsWith('.html') || path.endsWith('.js') || path.endsWith('.css')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    } else if (path.includes('favicon')) {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=3600');
    }
  }
}));

// ── API routes ──────────────────────────────────────────────────
app.use('/api', apiLimiter);
app.use(['/api/discover', '/api/subdomain/discover'], heavyScanLimiter);
app.use('/api/sherlock', heavyScanLimiter, sherlockRoutes);
app.use('/api', ipRoutes);
app.use('/api', fileRoutes);
app.use('/api', domainRoutes);
app.use('/api', cveRoutes);
app.use('/api', emailHeaderRoutes);
app.use('/api', macRoutes);
app.use('/api/crypto', cryptoRoutes);
app.use('/api/gtfobins', gtfobinsRoutes);
app.use('/api/utils', utilsRoutes);
app.use('/api', newsRoutes);
app.use('/api', subdomainRoutes);
app.use('/api/subdomain', subdomainRoutes);
app.use('/api/payloads', payloadsRoutes);
app.use('/api', trafficRoutes);

// ── ThreatFox Live Malicious IPs Feed (Keyless & Free) ──────────
app.get('/api/recent-malicious-ips', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 24, 100);
    const ips = await fetchRecentMaliciousIPs(limit);
    return res.json({
      success: true,
      count: ips.length,
      ips,
    });
  } catch (error) {
    console.error('ThreatFox Feed Error:', error.message);
    return res.status(502).json({
      success: false,
      error: 'Failed to retrieve live ThreatFox malicious IP feed. Please try again later.',
      details: error.message,
    });
  }
});

// Backward-compatibility alias
app.get('/api/reported-ips', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 24, 100);
    const ips = await fetchRecentMaliciousIPs(limit);
    return res.json({
      success: true,
      count: ips.length,
      ips,
      data: ips,
    });
  } catch (error) {
    return res.status(502).json({
      success: false,
      error: 'Failed to retrieve live ThreatFox feed',
    });
  }
});

// ── OpenStreetMap (Nominatim) In-Memory Cache (Protects upstream rate-limits) ──
const geocodeCache = new Map();
const MAX_GEOCODE_CACHE = 500;
const GEOCODE_TTL_MS = 15 * 60 * 1000; // 15 minutes

function getCachedGeocode(key) {
  const item = geocodeCache.get(key);
  if (!item) return null;
  if (Date.now() - item.time > GEOCODE_TTL_MS) {
    geocodeCache.delete(key);
    return null;
  }
  return item.data;
}

function setCachedGeocode(key, data) {
  if (geocodeCache.size >= MAX_GEOCODE_CACHE) {
    const firstKey = geocodeCache.keys().next().value;
    geocodeCache.delete(firstKey);
  }
  geocodeCache.set(key, { data, time: Date.now() });
}

// ── OpenStreetMap (Nominatim) Geocoding Free Proxy ───────────────
app.get('/api/geocode', geocodeLimiter, async (req, res) => {
  const rawQuery = (req.query.q || '').trim();
  if (!rawQuery) {
    return res.status(400).json({ success: false, error: 'Search query (q parameter) is required.' });
  }
  if (rawQuery.length > 100) {
    return res.status(400).json({ success: false, error: 'Search query exceeds maximum limit of 100 characters.' });
  }
  const query = rawQuery.replace(/[<>'"`;()]/g, '');
  if (!query) {
    return res.status(400).json({ success: false, error: 'Valid alphanumeric search query required.' });
  }

  const limit = Math.min(parseInt(req.query.limit, 10) || 5, 10);
  const cacheKey = `geo:${query.toLowerCase()}:${limit}`;
  const cached = getCachedGeocode(cacheKey);
  if (cached) {
    return res.json({
      success: true,
      query,
      cached: true,
      results: cached,
    });
  }

  try {
    const osmResponse = await axios.get('https://nominatim.openstreetmap.org/search', {
      params: {
        q: query,
        format: 'json',
        addressdetails: 1,
        limit,
      },
      headers: {
        'User-Agent': 'SudoDeck-OSINT-Platform/2.0 (threat-intel-visual-recon)',
        'Accept-Language': 'en,az,ru',
      },
      timeout: 8000,
    });

    const results = osmResponse.data || [];
    setCachedGeocode(cacheKey, results);

    return res.json({
      success: true,
      query,
      results,
    });
  } catch (err) {
    console.warn('Nominatim geocode proxy notice:', err.message);
    return res.status(502).json({
      success: false,
      error: 'Nominatim geocoding service is temporarily unavailable.',
      details: err.message,
    });
  }
});

// ── OpenStreetMap (Nominatim) Reverse Geocoding Proxy ─────────────
app.get('/api/reverse-geocode', geocodeLimiter, async (req, res) => {
  const lat = parseFloat(req.query.lat);
  const lon = parseFloat(req.query.lon);
  if (isNaN(lat) || isNaN(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180) {
    return res.status(400).json({ success: false, error: 'Valid lat (-90 to 90) and lon (-180 to 180) coordinates are required.' });
  }

  const roundedLat = lat.toFixed(4);
  const roundedLon = lon.toFixed(4);
  const cacheKey = `rev:${roundedLat}:${roundedLon}`;
  const cached = getCachedGeocode(cacheKey);
  if (cached) {
    return res.json({
      success: true,
      cached: true,
      data: cached,
    });
  }

  try {
    const osmResponse = await axios.get('https://nominatim.openstreetmap.org/reverse', {
      params: {
        lat,
        lon,
        format: 'json',
        addressdetails: 1,
      },
      headers: {
        'User-Agent': 'SudoDeck-OSINT-Platform/2.0 (threat-intel-visual-recon)',
        'Accept-Language': 'en,az,ru',
      },
      timeout: 8000,
    });

    const data = osmResponse.data || {};
    setCachedGeocode(cacheKey, data);

    return res.json({
      success: true,
      data,
    });
  } catch (err) {
    console.warn('Nominatim reverse geocode notice:', err.message);
    return res.status(502).json({
      success: false,
      error: 'Nominatim reverse geocoding service is temporarily unavailable.',
      details: err.message,
    });
  }
});

// ── Health check ────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'operational',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// ── Contact / Inquiry submission endpoint ───────────────────────
app.post('/api/contact', contactLimiter, (req, res) => {
  const { name, email, category, priority, subject, message } = req.body || {};
  if (!name || !email || !message) {
    return res.status(400).json({
      success: false,
      error: 'Name, email, and message are required fields',
    });
  }

  const cleanEmail = String(email).trim();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(cleanEmail) || cleanEmail.length > 254) {
    return res.status(400).json({
      success: false,
      error: 'Please provide a valid email address.',
    });
  }

  const cleanName = String(name).trim().replace(/[<>]/g, '').slice(0, 100);
  const cleanSubject = String(subject || 'General Inquiry').trim().replace(/[<>]/g, '').slice(0, 200);
  const cleanMessage = String(message).trim().replace(/[<>]/g, '').slice(0, 5000);

  const ticketId = `SD-${Math.random().toString(36).substring(2, 8).toUpperCase()}-${Date.now().toString().slice(-4)}`;
  console.log(`[CIRT Contact] Received dispatch ${ticketId} from ${cleanEmail} (${priority || 'P3'}: ${cleanSubject})`);

  return res.json({
    success: true,
    message: 'Message dispatched securely to SudoDeck CIRT desk',
    ticketId,
    timestamp: new Date().toISOString(),
  });
});

// ── HTML Page delivery helper (Prevents stale favicon & layout caches) ──
function sendPage(res, filename) {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(join(__dirname, 'public', filename));
}

// ── Dedicated CVE page route ────────────────────────────────────
app.get('/cve', (req, res) => {
  sendPage(res, 'cve.html');
});

// ── Dedicated MAC Lookup page route ─────────────────────────────
app.get('/mac', (req, res) => {
  sendPage(res, 'mac.html');
});

// ── Dedicated Crypto Suite page route ───────────────────────────
app.get('/crypto', (req, res) => {
  sendPage(res, 'crypto.html');
});

// ── Dedicated GTFOBins Explorer page route ──────────────────────
app.get('/gtfobins', (req, res) => {
  sendPage(res, 'gtfobins.html');
});

// ── Dedicated Wordlist & Mutator Suite page route ───────────
app.get('/wordlist', (req, res) => {
  sendPage(res, 'wordlist.html');
});

// ── Dedicated SIEM Utilities page route ─────────────────────
app.get('/siem', (req, res) => {
  sendPage(res, 'siem.html');
});

// ── Dedicated Subdomain & Resource Discovery page route ───────────
app.get(['/subdomain', '/discover', '/subdomains'], (req, res) => {
  sendPage(res, 'subdomain.html');
});

// ── Dedicated Security Payload Manager page route ───────────
app.get(['/payloads', '/payload-manager', '/payload'], (req, res) => {
  sendPage(res, 'payloads.html');
});

// ── Dedicated Social Media Footprint (Sherlock/Maigret) route ──
app.get(['/social-footprint', '/social-recon', '/footprint', '/sherlock'], (req, res) => {
  sendPage(res, 'social-footprint.html');
});

// ── Dedicated Visual Recon & Image Geolocation route ────────
app.get(['/visual-recon', '/recon', '/image-recon', '/geolocation'], (req, res) => {
  sendPage(res, 'visual-recon.html');
});

// ── Dedicated Web Traffic & Similarweb Recon route ───────────
app.get(['/traffic', '/web-traffic', '/website-traffic'], (req, res) => {
  sendPage(res, 'traffic.html');
});

// ── Dedicated Security News Live Feed page route ───────────
app.get('/news', (req, res) => {
  sendPage(res, 'news.html');
});

// ── Dedicated Premium Tools page route ─────────────────────
app.get(['/premium', '/premium-tools'], (req, res) => {
  sendPage(res, 'premium.html');
});

// ── Dedicated Pricing page route ───────────────────────────
app.get('/pricing', (req, res) => {
  sendPage(res, 'pricing.html');
});


// ── SPA fallback ────────────────────────────────────────────────
app.get('{*path}', (req, res) => {
  sendPage(res, 'index.html');
});

// ── Global error handler (must be last) ─────────────────────────
app.use(errorHandler);

// ── Start server ────────────────────────────────────────────────
const server = app.listen(config.PORT, '0.0.0.0', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║  🛡️  OSINT Threat Intelligence Platform                  ║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log(`║  Status:  ONLINE                                        ║`);
  console.log(`║  URL:     http://localhost:${String(config.PORT).padEnd(29)}║`);
  console.log(`║  Mode:    ${config.IS_DEV ? 'Development' : 'Production '}                                 ║`);
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log('║  Endpoints:                                              ║');
  console.log('║    GET  /api/recent-malicious-ips ThreatFox Live Feed   ║');
  console.log('║    POST /api/check-ip            IP Reputation          ║');
  console.log('║    POST /api/check-file          File Hash (VirusTotal) ║');
  console.log('║    POST /api/check-hash          Direct Hash (VT)       ║');
  console.log('║    POST /api/check-domain        Domain Intel (VT)      ║');
  console.log('║    POST /api/crypto/analyze      Smart Analyzer & Detect║');
  console.log('║    POST /api/crypto/process      Crypto Transformations ║');
  console.log('║    GET  /api/gtfobins            GTFOBins Catalog API   ║');
  console.log('║    GET  /api/gtfobins/:binary    Binary Functions Spec  ║');
  console.log('║    GET  /gtfobins                GTFOBins Explorer Page ║');
  console.log('║    POST /api/check-traffic       Website Traffic Intel  ║');
  console.log('║    GET  /traffic                 Web Traffic Dashboard ║');
  console.log('║    GET  /api/health              Health Check           ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
});

// ── Graceful shutdown ───────────────────────────────────────────
function gracefulShutdown(signal) {
  console.log(`\n[${signal}] Shutting down gracefully...`);
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('Forced shutdown after timeout.');
    process.exit(1);
  }, 10_000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));