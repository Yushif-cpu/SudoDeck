// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — Crypto & Encoding Service
// ═══════════════════════════════════════════════════════════════

import crypto from 'crypto';
import { AppError } from '../middleware/errorHandler.js';

// ── CRC32 Standard Lookup Table & Calculation ──────────────────
const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC_TABLE[i] = c;
}

function calculateCRC32(buffer) {
  let crc = 0 ^ (-1);
  for (let i = 0; i < buffer.length; i++) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[i]) & 0xFF];
  }
  return ((crc ^ (-1)) >>> 0).toString(16).padStart(8, '0');
}

// ── Pure JS MD4 Fallback (RFC 1320) ─────────────────────────────
function md4(buffer) {
  function rol(v, n) { return (v << n) | (v >>> (32 - n)); }
  function f(x, y, z) { return (x & y) | (~x & z); }
  function g(x, y, z) { return (x & y) | (x & z) | (y & z); }
  function h(x, y, z) { return x ^ y ^ z; }

  const len = buffer.length;
  const bitLen = len * 8;
  const padLen = (len % 64 < 56) ? (56 - (len % 64)) : (120 - (len % 64));
  const totalLen = len + padLen + 8;
  const padded = Buffer.alloc(totalLen);
  buffer.copy(padded);
  padded[len] = 0x80;
  padded.writeUInt32LE(bitLen & 0xffffffff, totalLen - 8);
  padded.writeUInt32LE(Math.floor(bitLen / 0x100000000), totalLen - 4);

  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;

  for (let i = 0; i < totalLen; i += 64) {
    const x = [];
    for (let j = 0; j < 16; j++) {
      x[j] = padded.readUInt32LE(i + j * 4);
    }

    const aa = a, bb = b, cc = c, dd = d;

    // Round 1
    const r1 = [3, 7, 11, 19];
    for (let j = 0; j < 16; j++) {
      const s = r1[j % 4];
      if (j % 4 === 0) a = rol(a + f(b, c, d) + x[j], s);
      else if (j % 4 === 1) d = rol(d + f(a, b, c) + x[j], s);
      else if (j % 4 === 2) c = rol(c + f(d, a, b) + x[j], s);
      else b = rol(b + f(c, d, a) + x[j], s);
    }

    // Round 2
    const r2 = [3, 5, 9, 13];
    const order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    for (let j = 0; j < 16; j++) {
      const s = r2[j % 4];
      const idx = order2[j];
      if (j % 4 === 0) a = rol(a + g(b, c, d) + x[idx] + 0x5a827999, s);
      else if (j % 4 === 1) d = rol(d + g(a, b, c) + x[idx] + 0x5a827999, s);
      else if (j % 4 === 2) c = rol(c + g(d, a, b) + x[idx] + 0x5a827999, s);
      else b = rol(b + g(c, d, a) + x[idx] + 0x5a827999, s);
    }

    // Round 3
    const r3 = [3, 9, 11, 15];
    const order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    for (let j = 0; j < 16; j++) {
      const s = r3[j % 4];
      const idx = order3[j];
      if (j % 4 === 0) a = rol(a + h(b, c, d) + x[idx] + 0x6ed9eba1, s);
      else if (j % 4 === 1) d = rol(d + h(a, b, c) + x[idx] + 0x6ed9eba1, s);
      else if (j % 4 === 2) c = rol(c + h(d, a, b) + x[idx] + 0x6ed9eba1, s);
      else b = rol(b + h(c, d, a) + x[idx] + 0x6ed9eba1, s);
    }

    a = (a + aa) >>> 0;
    b = (b + bb) >>> 0;
    c = (c + cc) >>> 0;
    d = (d + dd) >>> 0;
  }

  const out = Buffer.alloc(16);
  out.writeUInt32LE(a, 0);
  out.writeUInt32LE(b, 4);
  out.writeUInt32LE(c, 8);
  out.writeUInt32LE(d, 12);
  return out.toString('hex');
}

// ── Base32 (RFC 4648) ───────────────────────────────────────────
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  while (output.length % 8 !== 0) {
    output += '=';
  }
  return output;
}

function base32Decode(str) {
  const cleaned = str.toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    const val = B32_ALPHABET.indexOf(cleaned[i]);
    if (val === -1) continue;
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes).toString('utf8');
}

// ── Base85 (Ascii85) ────────────────────────────────────────────
function base85Encode(buffer) {
  let output = '<~';
  const pad = (4 - (buffer.length % 4)) % 4;
  const padded = Buffer.concat([buffer, Buffer.alloc(pad)]);

  for (let i = 0; i < padded.length; i += 4) {
    const val = padded.readUInt32BE(i);
    if (val === 0 && i < buffer.length && pad === 0) {
      output += 'z';
    } else {
      let b = '';
      let n = val;
      for (let j = 0; j < 5; j++) {
        b = String.fromCharCode((n % 85) + 33) + b;
        n = Math.floor(n / 85);
      }
      output += b;
    }
  }
  if (pad > 0) {
    output = output.slice(0, output.length - pad);
  }
  return output + '~>';
}

function base85Decode(inputStr) {
  let str = inputStr.trim();
  if (str.startsWith('<~')) str = str.slice(2);
  if (str.endsWith('~>')) str = str.slice(0, -2);
  str = str.replace(/\s+/g, '');

  let expanded = '';
  for (let i = 0; i < str.length; i++) {
    if (str[i] === 'z') expanded += '!!!!!';
    else expanded += str[i];
  }

  const pad = (5 - (expanded.length % 5)) % 5;
  expanded += 'u'.repeat(pad);

  const bytes = [];
  for (let i = 0; i < expanded.length; i += 5) {
    let val = 0;
    for (let j = 0; j < 5; j++) {
      val = val * 85 + (expanded.charCodeAt(i + j) - 33);
    }
    bytes.push((val >>> 24) & 0xff, (val >>> 16) & 0xff, (val >>> 8) & 0xff, val & 0xff);
  }

  const resBuf = Buffer.from(bytes);
  return resBuf.slice(0, resBuf.length - pad).toString('utf8');
}

// ── Morse Code Dictionary ───────────────────────────────────────
const MORSE_MAP = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.',
  G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..',
  M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.',
  S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-',
  Y: '-.--', Z: '--..', 1: '.----', 2: '..---', 3: '...--',
  4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..',
  9: '----.', 0: '-----', ' ': '/', '.': '.-.-.-', ',': '--..--',
  '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.',
  '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
  ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-',
  _: '..--.-', '"': '.-..-.', $: '...-..-', '@': '.--.-.',
};

const REVERSE_MORSE = Object.fromEntries(
  Object.entries(MORSE_MAP).map(([k, v]) => [v, k])
);

function toMorse(text) {
  return text
    .toUpperCase()
    .split('')
    .map((c) => MORSE_MAP[c] || c)
    .join(' ');
}

function fromMorse(code) {
  return code
    .trim()
    .split(/\s+/)
    .map((symbol) => {
      if (symbol === '/' || symbol === '|') return ' ';
      return REVERSE_MORSE[symbol] || symbol;
    })
    .join('');
}

// ── Classical Ciphers: Caesar, ROT13, Atbash, Vigenère ───────────
function rot13(text) {
  return text.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

function caesar(text, shift = 3, decode = false) {
  let s = parseInt(shift, 10) || 3;
  if (decode) s = (26 - (s % 26)) % 26;
  else s = (s % 26 + 26) % 26;

  return text.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + s) % 26) + base);
  });
}

function atbash(text) {
  return text.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code - 65));
    if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code - 97));
    return c;
  });
}

function vigenere(text, key = 'KEY', decode = false) {
  if (!key) return text;
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, '') || 'KEY';
  let keyIdx = 0;

  return text.replace(/[a-zA-Z]/g, (c) => {
    const isUpper = c <= 'Z';
    const base = isUpper ? 65 : 97;
    const charCode = c.charCodeAt(0) - base;
    const shift = cleanKey.charCodeAt(keyIdx % cleanKey.length) - 65;
    keyIdx++;

    const finalShift = decode ? (charCode - shift + 26) % 26 : (charCode + shift) % 26;
    return String.fromCharCode(finalShift + base);
  });
}

// ── Supported Algorithms Registry ───────────────────────────────
export const ALGORITHM_REGISTRY = {
  hashes: [
    { id: 'md5', name: 'MD5 (128-bit)', family: 'MD', bits: 128 },
    { id: 'md4', name: 'MD4 (128-bit)', family: 'MD', bits: 128 },
    { id: 'sha1', name: 'SHA-1 (160-bit)', family: 'SHA-1', bits: 160 },
    { id: 'sha224', name: 'SHA-224 (224-bit)', family: 'SHA-2', bits: 224 },
    { id: 'sha256', name: 'SHA-256 (256-bit)', family: 'SHA-2', bits: 256 },
    { id: 'sha384', name: 'SHA-384 (384-bit)', family: 'SHA-2', bits: 384 },
    { id: 'sha512', name: 'SHA-512 (512-bit)', family: 'SHA-2', bits: 512 },
    { id: 'sha512-256', name: 'SHA-512/256 (256-bit)', family: 'SHA-2', bits: 256 },
    { id: 'sha3-224', name: 'SHA3-224 (224-bit)', family: 'SHA-3', bits: 224 },
    { id: 'sha3-256', name: 'SHA3-256 (256-bit)', family: 'SHA-3', bits: 256 },
    { id: 'sha3-384', name: 'SHA3-384 (384-bit)', family: 'SHA-3', bits: 384 },
    { id: 'sha3-512', name: 'SHA3-512 (512-bit)', family: 'SHA-3', bits: 512 },
    { id: 'ripemd160', name: 'RIPEMD-160 (160-bit)', family: 'RIPEMD', bits: 160 },
    { id: 'blake2b512', name: 'BLAKE2b (512-bit)', family: 'BLAKE2', bits: 512 },
    { id: 'blake2s256', name: 'BLAKE2s (256-bit)', family: 'BLAKE2', bits: 256 },
    { id: 'crc32', name: 'CRC32 (32-bit Checksum)', family: 'Checksum', bits: 32 },
  ],
  encodings: [
    { id: 'base64', name: 'Base64', reversible: true },
    { id: 'base64url', name: 'Base64URL (URL-Safe)', reversible: true },
    { id: 'base32', name: 'Base32 (RFC 4648)', reversible: true },
    { id: 'base16', name: 'Base16 / Hexadecimal', reversible: true },
    { id: 'base85', name: 'Base85 / Ascii85', reversible: true },
    { id: 'url', name: 'URL Percent-Encoding', reversible: true },
    { id: 'binary', name: 'Binary (0101... 8-bit)', reversible: true },
    { id: 'octal', name: 'Octal (Base-8)', reversible: true },
    { id: 'decimal', name: 'Decimal (ASCII Codes)', reversible: true },
    { id: 'html', name: 'HTML Entities', reversible: true },
  ],
  ciphers: [
    { id: 'rot13', name: 'ROT13', hasOptions: false },
    { id: 'caesar', name: 'Caesar Cipher', hasOptions: true, optionType: 'shift', defaultOption: 3 },
    { id: 'morse', name: 'Morse Code', hasOptions: false },
    { id: 'atbash', name: 'Atbash Cipher', hasOptions: false },
    { id: 'vigenere', name: 'Vigenère Cipher', hasOptions: true, optionType: 'key', defaultOption: 'SECRET' },
  ],
};

/**
 * Executes a single cryptographic hashing operation
 */
export function executeHash(text, algorithm) {
  const buf = Buffer.from(text, 'utf8');
  const alg = (algorithm || 'sha256').toLowerCase().trim();

  let hex = '';
  if (alg === 'crc32') {
    hex = calculateCRC32(buf);
  } else if (alg === 'md4') {
    hex = md4(buf);
  } else {
    try {
      hex = crypto.createHash(alg).update(buf).digest('hex');
    } catch (err) {
      throw new AppError(`Algorithm "${algorithm}" is not supported by Node.js cryptographic provider: ${err.message}`, 400, 'UNSUPPORTED_ALGORITHM');
    }
  }

  const hashBuffer = Buffer.from(hex, 'hex');
  const base64 = hashBuffer.toString('base64');

  return {
    algorithm: alg.toUpperCase(),
    hex,
    base64,
    bytes: hex.length / 2,
    bits: (hex.length / 2) * 8,
  };
}

/**
 * Calculates a complete matrix of all major cryptographic hashes simultaneously
 */
export function executeAllHashes(text) {
  const buf = Buffer.from(text, 'utf8');
  const results = [];

  for (const item of ALGORITHM_REGISTRY.hashes) {
    try {
      const res = executeHash(text, item.id);
      results.push({
        id: item.id,
        name: item.name,
        family: item.family,
        bits: res.bits,
        hex: res.hex,
        base64: res.base64,
      });
    } catch (_) {
      // Gracefully skip unsupported algorithms in multi-hash table
    }
  }

  return {
    inputLength: text.length,
    inputBytes: buf.length,
    hashes: results,
  };
}

/**
 * Executes encoding or decoding transformation
 */
export function executeEncoding(text, algorithm, mode = 'encode') {
  const isDecode = mode === 'decode';
  const alg = (algorithm || 'base64').toLowerCase().trim();

  try {
    if (alg === 'base64') {
      if (isDecode) {
        return Buffer.from(text.trim(), 'base64').toString('utf8');
      }
      return Buffer.from(text, 'utf8').toString('base64');
    }

    if (alg === 'base64url') {
      if (isDecode) {
        let b64 = text.trim().replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        return Buffer.from(b64, 'base64').toString('utf8');
      }
      return Buffer.from(text, 'utf8').toString('base64url');
    }

    if (alg === 'base16' || alg === 'hex') {
      if (isDecode) {
        const cleanHex = text.replace(/[^0-9a-fA-F]/g, '');
        if (cleanHex.length % 2 !== 0) {
          throw new Error('Hex string must have an even number of characters.');
        }
        return Buffer.from(cleanHex, 'hex').toString('utf8');
      }
      return Buffer.from(text, 'utf8').toString('hex');
    }

    if (alg === 'base32') {
      return isDecode ? base32Decode(text) : base32Encode(Buffer.from(text, 'utf8'));
    }

    if (alg === 'base85' || alg === 'ascii85') {
      return isDecode ? base85Decode(text) : base85Encode(Buffer.from(text, 'utf8'));
    }

    if (alg === 'url') {
      return isDecode ? decodeURIComponent(text) : encodeURIComponent(text);
    }

    if (alg === 'binary') {
      if (isDecode) {
        const clean = text.replace(/[^01]/g, '');
        if (clean.length % 8 !== 0) {
          throw new Error('Binary string must be a multiple of 8 bits.');
        }
        const bytes = [];
        for (let i = 0; i < clean.length; i += 8) {
          bytes.push(parseInt(clean.slice(i, i + 8), 2));
        }
        return Buffer.from(bytes).toString('utf8');
      }
      return Array.from(Buffer.from(text, 'utf8'))
        .map((b) => b.toString(2).padStart(8, '0'))
        .join(' ');
    }

    if (alg === 'octal') {
      if (isDecode) {
        const parts = text.trim().split(/\s+/);
        const bytes = parts.map((p) => {
          const val = parseInt(p, 8);
          if (isNaN(val)) throw new Error(`Invalid octal value: "${p}"`);
          return val;
        });
        return Buffer.from(bytes).toString('utf8');
      }
      return Array.from(Buffer.from(text, 'utf8'))
        .map((b) => b.toString(8).padStart(3, '0'))
        .join(' ');
    }

    if (alg === 'decimal') {
      if (isDecode) {
        const parts = text.trim().split(/[\s,]+/);
        const bytes = parts.map((p) => {
          const val = parseInt(p, 10);
          if (isNaN(val) || val < 0 || val > 255) throw new Error(`Invalid byte decimal value: "${p}"`);
          return val;
        });
        return Buffer.from(bytes).toString('utf8');
      }
      return Array.from(Buffer.from(text, 'utf8')).join(' ');
    }

    if (alg === 'html') {
      if (isDecode) {
        return text
          .replace(/&amp;/g, '&')
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .replace(/&quot;/g, '"')
          .replace(/&#039;/g, "'")
          .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(code));
      }
      return text.replace(/[&<>"']/g, (m) => {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return map[m];
      });
    }

    throw new AppError(`Encoding algorithm "${algorithm}" is not supported.`, 400, 'UNSUPPORTED_ENCODING');
  } catch (err) {
    throw new AppError(`Decoding/Encoding error for ${algorithm}: ${err.message}`, 400, 'TRANSFORMATION_ERROR');
  }
}

/**
 * Executes a classical cipher transformation
 */
export function executeCipher(text, algorithm, mode = 'encode', options = {}) {
  const isDecode = mode === 'decode';
  const alg = (algorithm || 'rot13').toLowerCase().trim();

  if (alg === 'rot13') {
    return rot13(text);
  }

  if (alg === 'caesar') {
    const shift = parseInt(options.shift !== undefined ? options.shift : 3, 10);
    return caesar(text, shift, isDecode);
  }

  if (alg === 'morse') {
    return isDecode ? fromMorse(text) : toMorse(text);
  }

  if (alg === 'atbash') {
    return atbash(text);
  }

  if (alg === 'vigenere') {
    const key = String(options.key || 'SECRET');
    return vigenere(text, key, isDecode);
  }

  throw new AppError(`Cipher algorithm "${algorithm}" is not supported.`, 400, 'UNSUPPORTED_CIPHER');
}

/**
 * Main dispatcher for crypto processing requests
 */
export function processCryptoRequest({ text, category, algorithm, mode = 'encode', options = {} }) {
  if (text === undefined || text === null) {
    throw new AppError('Input text is required for processing.', 400, 'MISSING_TEXT');
  }

  const cat = (category || 'hashes').toLowerCase().trim();
  const startTime = process.hrtime.bigint();

  let output = '';
  let meta = {};

  if (cat === 'hashes' || cat === 'hash') {
    const hashRes = executeHash(text, algorithm);
    output = hashRes.hex;
    meta = hashRes;
  } else if (cat === 'encodings' || cat === 'encoding') {
    output = executeEncoding(text, algorithm, mode);
    meta = { mode, algorithm };
  } else if (cat === 'ciphers' || cat === 'cipher') {
    output = executeCipher(text, algorithm, mode, options);
    meta = { mode, algorithm, options };
  } else {
    throw new AppError(`Invalid category "${category}". Supported: hashes, encodings, ciphers.`, 400, 'INVALID_CATEGORY');
  }

  const endTime = process.hrtime.bigint();
  const executionMs = Number(endTime - startTime) / 1e6;

  return {
    category: cat,
    algorithm,
    output,
    inputLength: text.length,
    outputLength: output.length,
    executionTimeMs: Number(executionMs.toFixed(3)),
    meta,
  };
}

/**
 * Smart Analyzer & Identifier Engine
 * Inspects any arbitrary input and auto-detects hash signatures,
 * reversible encodings with instant decoded preview, and classical ciphers.
 */
export function smartAnalyzeInput(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return {
      input: '',
      inputLength: 0,
      inputBytes: 0,
      primaryType: 'None',
      hashCandidates: [],
      decodings: [],
      ciphers: [],
    };
  }

  const text = rawText.trim();
  const hashCandidates = [];
  const decodings = [];
  const ciphers = [];

  // 1. Check Hash Signature (Hex length / Unix formats)
  const isHexOnly = /^[0-9a-fA-F]+$/.test(text);
  const cleanHex = text.toLowerCase();

  if (isHexOnly) {
    const len = cleanHex.length;
    if (len === 8) {
      hashCandidates.push(
        { name: 'CRC32', family: 'Checksum', bits: 32, matchType: 'Hex Length Match (8 chars)', likelihood: 'High', hashcatMode: 'N/A', johnFormat: 'crc32', notes: 'Cyclic Redundancy Check 32-bit checksum' },
        { name: 'Adler-32', family: 'Checksum', bits: 32, matchType: 'Hex Length Match (8 chars)', likelihood: 'Medium', hashcatMode: 'N/A', johnFormat: 'adler32', notes: 'Zlib Adler-32 Checksum' }
      );
    } else if (len === 32) {
      hashCandidates.push(
        { name: 'MD5', family: 'MD', bits: 128, matchType: 'Hex Length Match (32 chars)', likelihood: 'Very High', hashcatMode: '0', johnFormat: 'raw-md5', notes: 'RFC 1321 Message Digest 5 (standard)' },
        { name: 'NTLM', family: 'Windows', bits: 128, matchType: 'Hex Length Match (32 chars)', likelihood: 'High', hashcatMode: '1000', johnFormat: 'nt', notes: 'Windows NT LAN Manager MD4-based hash' },
        { name: 'MD4', family: 'MD', bits: 128, matchType: 'Hex Length Match (32 chars)', likelihood: 'Medium', hashcatMode: '900', johnFormat: 'raw-md4', notes: 'RFC 1320 Message Digest 4' },
        { name: 'RIPEMD-128', family: 'RIPEMD', bits: 128, matchType: 'Hex Length Match (32 chars)', likelihood: 'Low', hashcatMode: 'N/A', johnFormat: 'ripemd-128', notes: 'RACE Integrity Primitives 128-bit' }
      );
    } else if (len === 40) {
      hashCandidates.push(
        { name: 'SHA-1', family: 'SHA-1', bits: 160, matchType: 'Hex Length Match (40 chars)', likelihood: 'Very High', hashcatMode: '100', johnFormat: 'raw-sha1', notes: 'FIPS 180-1 Secure Hash Algorithm 1' },
        { name: 'RIPEMD-160', family: 'RIPEMD', bits: 160, matchType: 'Hex Length Match (40 chars)', likelihood: 'High', hashcatMode: '6000', johnFormat: 'ripemd-160', notes: 'RIPEMD-160 (Used in Bitcoin addresses)' },
        { name: 'MySQL 4.1+', family: 'Database', bits: 160, matchType: 'Hex Length Match (40 chars)', likelihood: 'Medium', hashcatMode: '300', johnFormat: 'mysql-sha1', notes: 'MySQL password hash (double SHA1)' }
      );
    } else if (len === 56) {
      hashCandidates.push(
        { name: 'SHA-224', family: 'SHA-2', bits: 224, matchType: 'Hex Length Match (56 chars)', likelihood: 'Very High', hashcatMode: 'N/A', johnFormat: 'raw-sha224', notes: 'FIPS 180-4 SHA-2 224-bit digest' },
        { name: 'SHA3-224', family: 'SHA-3', bits: 224, matchType: 'Hex Length Match (56 chars)', likelihood: 'High', hashcatMode: '17300', johnFormat: 'raw-keccak-224', notes: 'FIPS 202 Keccak / SHA-3 224-bit digest' }
      );
    } else if (len === 64) {
      hashCandidates.push(
        { name: 'SHA-256', family: 'SHA-2', bits: 256, matchType: 'Hex Length Match (64 chars)', likelihood: 'Very High', hashcatMode: '1400', johnFormat: 'raw-sha256', notes: 'FIPS 180-4 SHA-2 256-bit (Industry standard)' },
        { name: 'SHA3-256', family: 'SHA-3', bits: 256, matchType: 'Hex Length Match (64 chars)', likelihood: 'High', hashcatMode: '17400', johnFormat: 'raw-sha3-256', notes: 'NIST FIPS 202 SHA-3 256-bit Keccak' },
        { name: 'BLAKE2s-256', family: 'BLAKE2', bits: 256, matchType: 'Hex Length Match (64 chars)', likelihood: 'Medium', hashcatMode: 'N/A', johnFormat: 'blake2s', notes: 'RFC 7693 BLAKE2s optimized 256-bit hash' }
      );
    } else if (len === 96) {
      hashCandidates.push(
        { name: 'SHA-384', family: 'SHA-2', bits: 384, matchType: 'Hex Length Match (96 chars)', likelihood: 'Very High', hashcatMode: '10800', johnFormat: 'raw-sha384', notes: 'FIPS 180-4 SHA-2 384-bit cryptographic digest' },
        { name: 'SHA3-384', family: 'SHA-3', bits: 384, matchType: 'Hex Length Match (96 chars)', likelihood: 'High', hashcatMode: '17500', johnFormat: 'raw-sha3-384', notes: 'NIST FIPS 202 SHA-3 384-bit Keccak' }
      );
    } else if (len === 128) {
      hashCandidates.push(
        { name: 'SHA-512', family: 'SHA-2', bits: 512, matchType: 'Hex Length Match (128 chars)', likelihood: 'Very High', hashcatMode: '1700', johnFormat: 'raw-sha512', notes: 'FIPS 180-4 SHA-2 512-bit military grade digest' },
        { name: 'SHA3-512', family: 'SHA-3', bits: 512, matchType: 'Hex Length Match (128 chars)', likelihood: 'High', hashcatMode: '17600', johnFormat: 'raw-sha3-512', notes: 'NIST FIPS 202 SHA-3 512-bit Keccak' },
        { name: 'Whirlpool', family: 'Whirlpool', bits: 512, matchType: 'Hex Length Match (128 chars)', likelihood: 'Medium', hashcatMode: '6100', johnFormat: 'whirlpool', notes: 'NESSIE ISO/IEC 10118-3 512-bit hash' },
        { name: 'BLAKE2b-512', family: 'BLAKE2', bits: 512, matchType: 'Hex Length Match (128 chars)', likelihood: 'Medium', hashcatMode: 'N/A', johnFormat: 'blake2b-512', notes: 'RFC 7693 BLAKE2b optimized 512-bit hash' }
      );
    }
  }

  // Unix password hash detection
  if (text.startsWith('$2a$') || text.startsWith('$2b$') || text.startsWith('$2y$')) {
    hashCandidates.push({ name: 'Bcrypt', family: 'Unix / Web', bits: 184, matchType: 'Prefix $2*$', likelihood: 'Very High', hashcatMode: '3200', johnFormat: 'bcrypt', notes: 'OpenBSD Blowfish-based adaptive password hash' });
  } else if (text.startsWith('$6$')) {
    hashCandidates.push({ name: 'SHA-512 Crypt', family: 'Unix', bits: 512, matchType: 'Prefix $6$', likelihood: 'Very High', hashcatMode: '1800', johnFormat: 'sha512crypt', notes: 'Linux /etc/shadow SHA-512 crypt' });
  } else if (text.startsWith('$5$')) {
    hashCandidates.push({ name: 'SHA-256 Crypt', family: 'Unix', bits: 256, matchType: 'Prefix $5$', likelihood: 'Very High', hashcatMode: '7400', johnFormat: 'sha256crypt', notes: 'Linux /etc/shadow SHA-256 crypt' });
  } else if (text.startsWith('$1$')) {
    hashCandidates.push({ name: 'MD5 Crypt', family: 'Unix', bits: 128, matchType: 'Prefix $1$', likelihood: 'Very High', hashcatMode: '500', johnFormat: 'md5crypt', notes: 'Classic Unix FreeBSD/Linux MD5 crypt' });
  } else if (text.startsWith('$argon2id$') || text.startsWith('$argon2i$')) {
    hashCandidates.push({ name: 'Argon2', family: 'Modern KDF', bits: 256, matchType: 'Prefix $argon2*$', likelihood: 'Very High', hashcatMode: 'N/A', johnFormat: 'argon2', notes: 'Password Hashing Competition winner' });
  }

  // 2. Decoders & Converters (Reversible)
  // A. Base64
  try {
    const isBase64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text);
    if (isBase64Pattern && text.length >= 4 && text.length % 4 === 0) {
      const decodedBuf = Buffer.from(text, 'base64');
      const decodedStr = decodedBuf.toString('utf8');
      const printableRatio = getPrintableRatio(decodedStr);
      const isDetected = printableRatio > 0.65 && decodedStr.length > 0 && decodedStr !== text;
      decodings.push({
        id: 'base64',
        name: 'Base64 (RFC 4648)',
        detected: isDetected,
        confidence: printableRatio > 0.85 ? 'High' : 'Medium',
        decoded: isDetected ? decodedStr : '',
        validUtf8: isDetected,
        notes: isDetected ? `Decoded into ${decodedStr.length} characters of readable UTF-8.` : 'Decodes to unprintable binary.',
      });
    } else {
      decodings.push({
        id: 'base64',
        name: 'Base64 (RFC 4648)',
        detected: false,
        confidence: 'Low',
        decoded: '',
        validUtf8: false,
        notes: 'Invalid Base64 padding or length.',
      });
    }
  } catch (_) {}

  // B. Hex (Base16)
  try {
    const rawNoSpaces = text.replace(/\s+/g, '');
    if (/^[0-9a-fA-F]+$/.test(rawNoSpaces) && rawNoSpaces.length >= 2 && rawNoSpaces.length % 2 === 0) {
      const decodedBuf = Buffer.from(rawNoSpaces, 'hex');
      const decodedStr = decodedBuf.toString('utf8');
      const printableRatio = getPrintableRatio(decodedStr);
      const isDetected = printableRatio > 0.65 && decodedStr.length > 0 && decodedStr !== text;
      decodings.push({
        id: 'hex',
        name: 'Hexadecimal (Base16)',
        detected: isDetected,
        confidence: printableRatio > 0.85 ? 'High' : 'Medium',
        decoded: isDetected ? decodedStr : '',
        validUtf8: isDetected,
        notes: isDetected ? `Decoded hex bytes into ${decodedStr.length} characters of readable UTF-8.` : 'Hex bytes decode to unprintable binary.',
      });
    } else {
      decodings.push({
        id: 'hex',
        name: 'Hexadecimal (Base16)',
        detected: false,
        confidence: 'Low',
        decoded: '',
        validUtf8: false,
        notes: 'Not a valid even-length hex stream.',
      });
    }
  } catch (_) {}

  // C. URL-Encoded (%XX)
  try {
    if (/%[0-9a-fA-F]{2}/.test(text)) {
      const decoded = decodeURIComponent(text.replace(/\+/g, ' '));
      const isDetected = decoded !== text;
      decodings.push({
        id: 'url',
        name: 'URL Percent-Encoding',
        detected: isDetected,
        confidence: 'High',
        decoded: isDetected ? decoded : '',
        validUtf8: true,
        notes: isDetected ? 'Decoded %XX percent entities to characters.' : 'No URL entities modified.',
      });
    } else {
      decodings.push({
        id: 'url',
        name: 'URL Percent-Encoding',
        detected: false,
        confidence: 'Low',
        decoded: '',
        validUtf8: false,
        notes: 'No URL %XX entities found.',
      });
    }
  } catch (_) {}

  // D. Binary (0s and 1s)
  try {
    const isBinWithSpaces = /^[01\s]+$/.test(text);
    if (isBinWithSpaces) {
      const bits = text.trim().split(/\s+/).filter(Boolean);
      if (bits.length > 0 && bits.every((b) => b.length === 8)) {
        const chars = bits.map((b) => String.fromCharCode(parseInt(b, 2))).join('');
        const ratio = getPrintableRatio(chars);
        const isDetected = ratio > 0.65 && chars.length > 0;
        decodings.push({
          id: 'binary',
          name: 'Binary (8-bit Bitstream)',
          detected: isDetected,
          confidence: 'High',
          decoded: isDetected ? chars : '',
          validUtf8: isDetected,
          notes: isDetected ? `Decoded ${bits.length} binary bytes into text.` : 'Binary bytes do not map to printable text.',
        });
      } else {
        decodings.push({
          id: 'binary',
          name: 'Binary (8-bit Bitstream)',
          detected: false,
          confidence: 'Low',
          decoded: '',
          validUtf8: false,
          notes: 'Binary bits not grouped into 8-bit octets.',
        });
      }
    } else {
      decodings.push({
        id: 'binary',
        name: 'Binary (8-bit Bitstream)',
        detected: false,
        confidence: 'Low',
        decoded: '',
        validUtf8: false,
        notes: 'Contains characters other than 0 and 1.',
      });
    }
  } catch (_) {}

  // E. Base32 (RFC 4648)
  try {
    const isB32 = /^[A-Z2-7=]+$/i.test(text);
    if (isB32 && text.length >= 8 && text.length % 8 === 0) {
      const decoded = base32Decode(text);
      const ratio = getPrintableRatio(decoded);
      const isDetected = ratio > 0.65 && decoded.length > 0 && decoded !== text;
      decodings.push({
        id: 'base32',
        name: 'Base32 (RFC 4648)',
        detected: isDetected,
        confidence: 'Medium',
        decoded: isDetected ? decoded : '',
        validUtf8: isDetected,
        notes: isDetected ? `Decoded Base32 payload into readable text.` : 'Base32 decodes to non-printable binary.',
      });
    } else {
      decodings.push({
        id: 'base32',
        name: 'Base32 (RFC 4648)',
        detected: false,
        confidence: 'Low',
        decoded: '',
        validUtf8: false,
        notes: 'Invalid Base32 length or alphabet.',
      });
    }
  } catch (_) {}

  // F. Morse Code
  try {
    if (/^[\.\-\s\/]+$/.test(text) && (text.includes('.') || text.includes('-'))) {
      const decoded = fromMorse(text);
      const isDetected = decoded && decoded.trim().length > 0 && !decoded.includes('???');
      decodings.push({
        id: 'morse',
        name: 'International Morse Code',
        detected: isDetected,
        confidence: 'High',
        decoded: isDetected ? decoded : '',
        validUtf8: true,
        notes: isDetected ? 'Decoded dots and dashes into standard Latin text.' : 'Morse sequences could not be mapped.',
      });
    } else {
      decodings.push({
        id: 'morse',
        name: 'International Morse Code',
        detected: false,
        confidence: 'Low',
        decoded: '',
        validUtf8: false,
        notes: 'No Morse dot/dash sequences found.',
      });
    }
  } catch (_) {}

  // G. HTML Entities
  try {
    if (/&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;/.test(text)) {
      const decoded = decodeHtml(text);
      const isDetected = decoded !== text;
      decodings.push({
        id: 'html',
        name: 'HTML Character Entities',
        detected: isDetected,
        confidence: 'High',
        decoded: isDetected ? decoded : '',
        validUtf8: true,
        notes: isDetected ? 'Decoded named or numeric HTML entities.' : 'No HTML entities altered.',
      });
    } else {
      decodings.push({
        id: 'html',
        name: 'HTML Character Entities',
        detected: false,
        confidence: 'Low',
        decoded: '',
        validUtf8: false,
        notes: 'No HTML entities found.',
      });
    }
  } catch (_) {}

  // 3. Classical Ciphers Previews
  // ROT13
  const rot13Val = rot13(text);
  ciphers.push({
    id: 'rot13',
    name: 'ROT13',
    family: 'Caesar Shift 13',
    transformed: rot13Val,
    notes: 'Symmetric 13-position alphabet rotation',
  });

  // Atbash
  const atbashVal = atbash(text);
  ciphers.push({
    id: 'atbash',
    name: 'Atbash Cipher',
    family: 'Hebrew Reverse Alphabet',
    transformed: atbashVal,
    notes: 'Symmetric reverse alphabet mapping (A ↔ Z)',
  });

  // Caesar Best Shift
  const caesarBest = findBestCaesarShift(text);
  if (caesarBest) {
    ciphers.push({
      id: 'caesar_best',
      name: `Caesar Cipher (Shift ${caesarBest.shift})`,
      family: 'Caesar Substitution',
      shift: caesarBest.shift,
      score: caesarBest.score,
      transformed: caesarBest.result,
      notes: `Optimal English letter frequency matching (Score: ${caesarBest.score})`,
    });
  }

  // Determine Primary Recommendation
  let primaryType = {
    type: 'unknown',
    title: 'Arbitrary Plaintext / Unknown String',
    confidence: 'Low',
    summary: 'The input does not match obvious cryptographic hashes, standard encoders, or known cipher patterns.',
  };

  if (hashCandidates.length > 0) {
    const top = hashCandidates[0];
    primaryType = {
      type: 'hash',
      title: `${top.name} Cryptographic Hash (${top.bits}-bit)`,
      confidence: top.likelihood === 'Very High' ? 'High' : 'Medium',
      summary: `Input precisely matches the ${top.matchType} signature of a ${top.name} one-way digest.`,
    };
  } else if (decodings.some((d) => d.detected && d.confidence === 'High')) {
    const top = decodings.find((d) => d.detected && d.confidence === 'High');
    primaryType = {
      type: 'encoder',
      title: `${top.name} Encoded Payload`,
      confidence: 'High',
      summary: `Payload successfully decoded into verified UTF-8 text via ${top.name}.`,
    };
  } else if (decodings.some((d) => d.detected)) {
    const top = decodings.find((d) => d.detected);
    primaryType = {
      type: 'encoder',
      title: `${top.name} Encoded Payload`,
      confidence: 'Medium',
      summary: `Payload identified as ${top.name} encoding.`,
    };
  } else if (caesarBest && caesarBest.score > 20 && caesarBest.shift !== 0 && caesarBest.shift !== 26) {
    primaryType = {
      type: 'cipher',
      title: `Potential Caesar Cipher (Shift +${caesarBest.shift})`,
      confidence: 'Medium',
      summary: `Payload exhibits strong English letter frequency when shifted by ${caesarBest.shift} positions.`,
    };
  }

  return {
    input: text,
    inputLength: text.length,
    inputBytes: Buffer.byteLength(text),
    isHexOnly,
    primaryType,
    hashCandidates,
    decodings,
    ciphers,
  };
}

function getPrintableRatio(str) {
  if (!str || str.length === 0) return 0;
  // If Unicode replacement character U+FFFD appears, it is invalid/corrupt UTF-8
  if (str.includes('\uFFFD')) return 0;

  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
      printable++;
    } else if (code >= 160 && code <= 0x052F) {
      // Valid European / Latin / Cyrillic UTF-8
      printable++;
    }
  }
  return printable / str.length;
}

function findBestCaesarShift(str) {
  const FREQ = {
    e: 12.02, t: 9.10, a: 8.12, o: 7.68, i: 7.31, n: 6.95, s: 6.28,
    r: 6.02, h: 5.92, d: 4.32, l: 3.98, u: 2.88, c: 2.71, m: 2.61,
    f: 2.30, y: 2.11, w: 2.09, g: 2.03, p: 1.82, b: 1.49, v: 1.11,
    k: 0.69, x: 0.17, q: 0.11, j: 0.10, z: 0.07,
  };

  let bestShift = 3;
  let bestScore = -1;
  let bestText = '';

  for (let shift = 1; shift <= 25; shift++) {
    const shifted = caesar(str, 26 - shift);
    let score = 0;
    const lower = shifted.toLowerCase();
    for (let i = 0; i < lower.length; i++) {
      if (FREQ[lower[i]]) score += FREQ[lower[i]];
    }
    if (score > bestScore) {
      bestScore = score;
      bestShift = shift;
      bestText = shifted;
    }
  }

  return {
    shift: bestShift,
    score: Math.round(bestScore),
    result: bestText,
  };
}
