import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://ecoxglivjqhrzwtgwrim.supabase.co';
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || 'sb_publishable_9Hy_lO637TmXg8xgQmuMkQ_Aia9Twwa';

export const supabase = createClient(supabaseUrl, supabaseKey);

export default supabase;
