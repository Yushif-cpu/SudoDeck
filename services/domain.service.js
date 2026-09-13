// Domain service — delegates to VirusTotal service for domain intelligence.
// This module exists as a clean abstraction layer so routes don't need to know
// which upstream API provides domain data. In the future, additional sources
// (Shodan, SecurityTrails, etc.) can be aggregated here.

import { checkDomain as vtCheckDomain } from './virustotal.service.js';

export async function checkDomain(domain) {
  return vtCheckDomain(domain);
}
