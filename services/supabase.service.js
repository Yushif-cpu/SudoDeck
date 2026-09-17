import { createClient } from '@supabase/supabase-js';
import config from '../config/env.js';

const supabaseUrl = config.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseKey = config.SUPABASE_KEY || process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || '';

// Initialize Supabase Client safely to prevent crash on serverless/cloud environments if keys are not provided
let client = null;

if (supabaseUrl && supabaseKey) {
  try {
    client = createClient(supabaseUrl, supabaseKey);
  } catch (err) {
    console.warn('[Supabase] Client initialization notice:', err.message);
    client = null;
  }
}

export const supabase = client;

export default supabase;
