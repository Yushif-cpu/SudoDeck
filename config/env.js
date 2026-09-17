import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env reliably from project root, current working directory, or parent directory
const possibleEnvPaths = [
  resolve(__dirname, '..', '.env'),
  resolve(process.cwd(), '.env'),
  resolve(process.cwd(), 'threat-intel-node', '.env'),
  resolve(__dirname, '..', '..', '.env'),
];
for (const p of possibleEnvPaths) {
  dotenv.config({ path: p });
}


// ── Environment variables check (Graceful degradation) ───────────
const RECOMMENDED_VARS = ['ABUSEIPDB_API_KEY', 'VIRUSTOTAL_API_KEY'];
const missing = RECOMMENDED_VARS.filter((key) => !process.env[key]);
if (missing.length > 0) {
  console.warn('╔══════════════════════════════════════════════════════════╗');
  console.warn('║  NOTICE: Running with partial/missing API keys           ║');
  console.warn('╠══════════════════════════════════════════════════════════╣');
  missing.forEach((key) => {
    console.warn(`║  !  ${key.padEnd(50)}║`);
  });
  console.warn('╠══════════════════════════════════════════════════════════╣');
  console.warn('║  Add keys in environment variables for live VT/AbuseIPDB ║');
  console.warn('╚══════════════════════════════════════════════════════════╝');
}

// ── Export validated config ──────────────────────────────────────
const config = Object.freeze({
  PORT: parseInt(process.env.PORT, 10) || 3000,
  ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY,
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY,
  NVD_API_KEY: process.env.NVD_API_KEY || '',
  MACVENDORS_API_TOKEN: process.env.MACVENDORS_API_TOKEN || '',
  APIFY_API_TOKEN: process.env.APIFY_API_TOKEN || '',
  SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://ecoxglivjqhrzwtgwrim.supabase.co',
  SUPABASE_KEY: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || 'sb_publishable_9Hy_lO637TmXg8xgQmuMkQ_Aia9Twwa',
  NODE_ENV: process.env.NODE_ENV || 'development',
  IS_DEV: (process.env.NODE_ENV || 'development') === 'development',
});

export default config;
