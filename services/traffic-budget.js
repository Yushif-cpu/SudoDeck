// Process-local spending guard for paid Apify calls. Use an external shared store
// when deploying multiple workers or instances.
const WINDOW_MS = 60 * 60 * 1000;
const MAX_CALLS = 20;
const DOMAIN_COOLDOWN_MS = 10 * 60 * 1000;
const attempts = [];
const recentDomains = new Map();

export function reserveTrafficCall(domain, forceFresh = false) {
  const now = Date.now();
  while (attempts.length && attempts[0] <= now - WINDOW_MS) attempts.shift();
  for (const [name, time] of recentDomains) {
    if (time <= now - DOMAIN_COOLDOWN_MS) recentDomains.delete(name);
  }

  const key = `${forceFresh ? 'refresh' : 'normal'}:${domain}`;
  if (attempts.length >= MAX_CALLS || recentDomains.has(key)) return false;
  attempts.push(now);
  recentDomains.set(key, now);
  return true;
}
