import { AppError } from './errorHandler.js';

// ── Regex patterns ──────────────────────────────────────────────
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d)|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d))$/;
const DOMAIN_REGEX = /^(?!:\/\/)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const SHA256_REGEX = /^[a-fA-F0-9]{64}$/;

// ── Sanitization helpers ────────────────────────────────────────
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str
    .trim()
    .replace(/[<>'"]/g, '') // strip XSS vectors
    .substring(0, 2048);     // limit length
}

function extractDomain(input) {
  let cleaned = sanitizeString(input).toLowerCase();
  // Strip protocol if present
  cleaned = cleaned.replace(/^https?:\/\//, '');
  // Strip path, query, fragment
  cleaned = cleaned.split('/')[0];
  cleaned = cleaned.split('?')[0];
  cleaned = cleaned.split('#')[0];
  // Strip port
  cleaned = cleaned.split(':')[0];
  return cleaned;
}

// ── Validation middleware factories ─────────────────────────────

export function validateIP(req, res, next) {
  const rawIP = req.body.ip;
  if (!rawIP) {
    throw new AppError('IP address is required.', 400, 'VALIDATION_ERROR');
  }

  const ip = sanitizeString(rawIP);

  if (!IPV4_REGEX.test(ip) && !IPV6_REGEX.test(ip)) {
    throw new AppError(
      'Invalid IP address format. Provide a valid IPv4 or IPv6 address.',
      400,
      'INVALID_IP'
    );
  }

  req.validatedInput = { ip };
  next();
}

export function validateDomain(req, res, next) {
  const rawDomain = req.body.domain;
  if (!rawDomain) {
    throw new AppError('Domain name is required.', 400, 'VALIDATION_ERROR');
  }

  const domain = extractDomain(rawDomain);

  if (!DOMAIN_REGEX.test(domain)) {
    throw new AppError(
      'Invalid domain format. Provide a valid domain name (e.g., example.com).',
      400,
      'INVALID_DOMAIN'
    );
  }

  req.validatedInput = { domain };
  next();
}

export function validateHash(req, res, next) {
  const rawHash = req.body.hash;
  if (!rawHash) {
    // If no hash provided, it might be a file upload — skip hash validation
    return next();
  }

  const hash = sanitizeString(rawHash).toLowerCase();

  if (!SHA256_REGEX.test(hash)) {
    throw new AppError(
      'Invalid hash format. Provide a valid SHA-256 hash (64 hex characters).',
      400,
      'INVALID_HASH'
    );
  }

  req.validatedInput = { hash };
  next();
}
