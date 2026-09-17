import fs from 'fs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env reliably ONLY if file actually exists on disk (suppresses noisy container warnings)
const possibleEnvPaths = [
  resolve(process.cwd(), '.env'),
  resolve(__dirname, '..', '.env'),
  resolve(process.cwd(), 'threat-intel-node', '.env'),
  resolve(__dirname, '..', '..', '.env'),
];

for (const p of possibleEnvPaths) {
  if (fs.existsSync(p)) {
    dotenv.config({ path: p, quiet: true });
    break; // First match is loaded, prevent multiple redundant injections
  }
}

// ── Environment variables check (Graceful degradation) ───────────
const RECOMMENDED_VARS = ['ABUSEIPDB_API_KEY', 'VIRUSTOTAL_API_KEY'];
const missing = RECOMMENDED_VARS.filter((key) => !process.env[key]);
if (missing.length > 0 && process.env.NODE_ENV === 'development') {
  console.info(`[Config] Operating in community feed mode (Optional keys not set: ${missing.join(', ')})`);
}

// ── Export validated config ──────────────────────────────────────
const config = Object.freeze({
  PORT: parseInt(process.env.PORT, 10) || 3000,
  ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY,
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY,
  NVD_API_KEY: process.env.NVD_API_KEY || '',
  MACVENDORS_API_TOKEN: process.env.MACVENDORS_API_TOKEN || '',
  APIFY_API_TOKEN: process.env.APIFY_API_TOKEN || '',
  SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || '',
  SUPABASE_KEY: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY || '',
  NODE_ENV: process.env.NODE_ENV || 'development',
  IS_DEV: (process.env.NODE_ENV || 'development') === 'development',
});

export default config;
