import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env strictly from the root of the project (threat-intel-node/.env)
const envPath = resolve(__dirname, '..', '.env');
dotenv.config({ path: envPath });

// ── Required environment variables ──────────────────────────────
const REQUIRED_VARS = ['ABUSEIPDB_API_KEY', 'VIRUSTOTAL_API_KEY'];

const missing = REQUIRED_VARS.filter((key) => !process.env[key]);
if (missing.length > 0) {
  console.error('╔══════════════════════════════════════════════════════════╗');
  console.error('║  FATAL: Missing required environment variables          ║');
  console.error('╠══════════════════════════════════════════════════════════╣');
  missing.forEach((key) => {
    console.error(`║  ✗  ${key.padEnd(50)}║`);
  });
  console.error('╠══════════════════════════════════════════════════════════╣');
  console.error('║  Create a .env file with the required API keys.         ║');
  console.error('╚══════════════════════════════════════════════════════════╝');
  process.exit(1);
}

// ── Export validated config ──────────────────────────────────────
const config = Object.freeze({
  PORT: parseInt(process.env.PORT, 10) || 3000,
  ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY,
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY,
  NVD_API_KEY: process.env.NVD_API_KEY || '',
  MACVENDORS_API_TOKEN: process.env.MACVENDORS_API_TOKEN || '',
  NODE_ENV: process.env.NODE_ENV || 'development',
  IS_DEV: (process.env.NODE_ENV || 'development') === 'development',
});

export default config;
