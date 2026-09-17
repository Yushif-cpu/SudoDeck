// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — Server Entry Point
// ═══════════════════════════════════════════════════════════════

import dotenv from 'dotenv';
dotenv.config();

import config from './config/env.js';
import express from 'express';
import axios from 'axios';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// ── Middleware ───────────────────────────────────────────────────
import { generalLimiter, apiLimiter } from './middleware/rateLimiter.js';
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
import { fetchRecentMaliciousIPs } from './services/threatfox.service.js';

// ── Path setup ──────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Express app ─────────────────────────────────────────────────
const app = express();

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
      connectSrc: ["'self'", "https://nominatim.openstreetmap.org", "https://tessdata.projectnaptha.com", "https://cdn.jsdelivr.net", "blob:", "data:"],
    },
  },
}));
app.use(cors());
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

// ── Static files with compression & caching ─────────────────────
app.use(express.static(join(__dirname, 'public'), {
  maxAge: '1h',
  etag: true,
  setHeaders: (res, path) => {
    if (path.includes('favicon')) {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    }
  }
}));

// ── API routes ──────────────────────────────────────────────────
app.use('/api', apiLimiter);
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

// ── OpenStreetMap (Nominatim) Geocoding Free Proxy ───────────────
app.get('/api/geocode', async (req, res) => {
  const query = (req.query.q || '').trim();
  if (!query) {
    return res.status(400).json({ success: false, error: 'Axtarış sorğusu (q parametri) mütləqdir.' });
  }

  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 5, 10);
    const osmResponse = await axios.get('https://nominatim.openstreetmap.org/search', {
      params: {
        q: query,
        format: 'json',
        addressdetails: 1,
        limit,
      },
      headers: {
        'User-Agent': 'SudoDeck-OSINT-Platform/2.0 (threat-intel-visual-recon)',
        'Accept-Language': 'az,en,ru',
      },
      timeout: 8000,
    });

    return res.json({
      success: true,
      query,
      results: osmResponse.data || [],
    });
  } catch (err) {
    console.warn('Nominatim geocode proxy notice:', err.message);
    return res.status(502).json({
      success: false,
      error: 'Nominatim geocoding xidməti müvəqqəti əlçatmazdır.',
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
app.post('/api/contact', (req, res) => {
  const { name, email, category, priority, subject, message } = req.body || {};
  if (!name || !email || !message) {
    return res.status(400).json({
      success: false,
      error: 'Name, email, and message are required fields',
    });
  }

  const ticketId = `SD-${Math.random().toString(36).substring(2, 8).toUpperCase()}-${Date.now().toString().slice(-4)}`;
  console.log(`[CIRT Contact] Received dispatch ${ticketId} from ${email} (${priority || 'P3'}: ${subject || 'No subject'})`);

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

// ── Dedicated Visual Recon & Image Geolocation route ────────
app.get(['/visual-recon', '/recon', '/image-recon', '/geolocation'], (req, res) => {
  sendPage(res, 'visual-recon.html');
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
  console.log('║    GET  /crypto                  Dedicated Crypto Suite ║');
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