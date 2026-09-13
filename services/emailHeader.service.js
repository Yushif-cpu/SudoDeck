// ═══════════════════════════════════════════════════════════════
//  OSINT Threat Intelligence Platform — Email Header Parser Service
// ═══════════════════════════════════════════════════════════════

import { AppError } from '../middleware/errorHandler.js';

/**
 * Parses raw RFC 822 / RFC 5322 email headers
 */
export function parseEmailHeaders(rawHeader) {
  if (!rawHeader || typeof rawHeader !== 'string' || !rawHeader.trim()) {
    throw new AppError('Raw email header content is required.', 400, 'EMPTY_HEADER');
  }

  const lines = rawHeader.split(/\r?\n/);
  const headerMap = {}; // Lowercase key -> array of values
  let currentKey = null;

  for (const line of lines) {
    // Header continuation (folding)
    if (/^[\t ]+/.test(line) && currentKey) {
      const lastIndex = headerMap[currentKey].length - 1;
      headerMap[currentKey][lastIndex] += ' ' + line.trim();
    } else {
      const match = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
      if (match) {
        currentKey = match[1].toLowerCase();
        const value = match[2].trim();
        if (!headerMap[currentKey]) {
          headerMap[currentKey] = [];
        }
        headerMap[currentKey].push(value);
      } else if (!line.trim()) {
        // Empty line separates headers from body
        break;
      }
    }
  }

  if (Object.keys(headerMap).length === 0) {
    throw new AppError(
      'Could not parse any valid email headers. Please ensure you copied the raw email headers (e.g. Received, From, To, Subject).',
      400,
      'INVALID_HEADER_FORMAT'
    );
  }

  // 1. Core Metadata
  const from = getFirstHeader(headerMap, 'from');
  const to = getFirstHeader(headerMap, 'to');
  const subject = getFirstHeader(headerMap, 'subject') || '(No Subject)';
  const date = getFirstHeader(headerMap, 'date');
  const messageId = getFirstHeader(headerMap, 'message-id');
  const returnPath = getFirstHeader(headerMap, 'return-path');
  const replyTo = getFirstHeader(headerMap, 'reply-to');

  // Extract clean email addresses and domains
  const fromEmail = extractEmail(from);
  const returnPathEmail = extractEmail(returnPath);
  const fromDomain = extractDomain(fromEmail);
  const returnPathDomain = extractDomain(returnPathEmail);

  // 2. Authentication Analysis (SPF, DKIM, DMARC)
  const authResults = headerMap['authentication-results'] || [];
  const receivedSpf = headerMap['received-spf'] || [];
  const dkimSignatures = headerMap['dkim-signature'] || [];
  const dmarcHeaders = headerMap['dmarc-filter'] || headerMap['x-dmarc-info'] || [];

  const authStatus = extractAuthStatus(authResults, receivedSpf, dkimSignatures, dmarcHeaders);

  // 3. Received Hops Analysis (Relay Path)
  const rawReceived = headerMap['received'] || [];
  const hops = parseReceivedHops(rawReceived);

  // 4. Security Assessment & Spoofing Detection
  const securityChecks = performSecurityAssessment({
    fromEmail,
    returnPathEmail,
    fromDomain,
    returnPathDomain,
    authStatus,
    hops,
    headerMap,
  });

  return {
    overview: {
      from,
      fromEmail,
      fromDomain,
      to,
      subject,
      date,
      messageId,
      returnPath,
      returnPathEmail,
      returnPathDomain,
      replyTo,
    },
    authentication: authStatus,
    securityChecks,
    hops: {
      totalHops: hops.length,
      originatingIP: hops.length > 0 ? hops[0].ip : null,
      hopsList: hops,
    },
    rawHeaderCount: Object.keys(headerMap).length,
  };
}

// ── Helpers ─────────────────────────────────────────────────────

function getFirstHeader(map, key) {
  return map[key] && map[key].length > 0 ? map[key][0] : null;
}

function extractEmail(str) {
  if (!str) return null;
  const match = str.match(/<([^>]+)>/) || str.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1].toLowerCase().trim() : str.trim();
}

function extractDomain(email) {
  if (!email || !email.includes('@')) return null;
  return email.split('@')[1].toLowerCase().trim();
}

/**
 * Parse Authentication-Results / Received-SPF headers for SPF, DKIM, and DMARC
 */
function extractAuthStatus(authResultsList, receivedSpfList, dkimSignatures, dmarcHeaders) {
  const combinedAuth = authResultsList.join(' ');
  const combinedSpf = receivedSpfList.join(' ');
  const combinedDmarc = dmarcHeaders.join(' ');

  // 1) SPF
  let spfStatus = 'NONE';
  let spfReason = null;
  const spfMatch = combinedAuth.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i) ||
    combinedSpf.match(/^(pass|fail|softfail|neutral|none|temperror|permerror)/i);
  if (spfMatch) {
    spfStatus = spfMatch[1].toUpperCase();
  }

  // 2) DKIM
  let dkimStatus = dkimSignatures.length > 0 ? 'SIGNED' : 'NONE';
  let dkimDomain = null;
  const dkimMatch = combinedAuth.match(/dkim=(pass|fail|neutral|none|temperror|permerror)/i);
  if (dkimMatch) {
    dkimStatus = dkimMatch[1].toUpperCase();
  }
  const dkimDomainMatch = combinedAuth.match(/header\.d=([^\s;]+)/i) ||
    (dkimSignatures[0] && dkimSignatures[0].match(/d=([^\s;]+)/i));
  if (dkimDomainMatch) {
    dkimDomain = dkimDomainMatch[1];
  }

  // 3) DMARC
  let dmarcStatus = 'NONE';
  let dmarcPolicy = null;
  const dmarcMatch = combinedAuth.match(/dmarc=(pass|fail|bestguesspass|none|temperror|permerror)/i) ||
    combinedDmarc.match(/(pass|fail)/i);
  if (dmarcMatch) {
    dmarcStatus = dmarcMatch[1].toUpperCase();
  }
  const dmarcPolicyMatch = combinedAuth.match(/action=(none|quarantine|reject)/i) ||
    combinedAuth.match(/p=(none|quarantine|reject)/i);
  if (dmarcPolicyMatch) {
    dmarcPolicy = dmarcPolicyMatch[1].toUpperCase();
  }

  return {
    spf: {
      status: spfStatus,
      badge: getAuthBadge(spfStatus),
      details: combinedSpf || spfMatch?.[0] || 'No dedicated Received-SPF record found.',
    },
    dkim: {
      status: dkimStatus,
      badge: getAuthBadge(dkimStatus),
      domain: dkimDomain,
      signatureCount: dkimSignatures.length,
    },
    dmarc: {
      status: dmarcStatus,
      badge: getAuthBadge(dmarcStatus),
      policy: dmarcPolicy,
    },
  };
}

function getAuthBadge(status) {
  switch (status) {
    case 'PASS':
    case 'BESTGUESSPASS':
      return { level: 'PASS', color: '#34d399', bg: 'rgba(52, 211, 153, 0.15)', border: 'rgba(52, 211, 153, 0.3)' };
    case 'FAIL':
      return { level: 'FAIL', color: '#fb7185', bg: 'rgba(251, 113, 133, 0.15)', border: 'rgba(251, 113, 133, 0.3)' };
    case 'SOFTFAIL':
      return { level: 'SOFTFAIL', color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.15)', border: 'rgba(251, 191, 36, 0.3)' };
    case 'SIGNED':
      return { level: 'SIGNED', color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.15)', border: 'rgba(56, 189, 248, 0.3)' };
    default:
      return { level: status || 'UNKNOWN', color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.1)', border: 'rgba(148, 163, 184, 0.25)' };
  }
}

/**
 * Parse Received: headers into chronological hops (from origin to recipient)
 */
function parseReceivedHops(rawReceivedList) {
  // Received headers are added top-to-bottom, so the earliest hop is at the bottom.
  const reversedList = [...rawReceivedList].reverse();

  return reversedList.map((header, idx) => {
    // Extract FROM host/IP
    let fromHost = null;
    let fromIP = null;
    const fromMatch = header.match(/from\s+([^\s\(\[]+)(?:\s+[\(\[](?:[^\)\]]*?)([0-9a-fA-F:.]+)[\)\]])?/i);
    if (fromMatch) {
      fromHost = fromMatch[1].replace(/[\(\)\[\]]/g, '').trim();
      fromIP = fromMatch[2] || null;
    }

    // Direct IP match if fromIP is still null
    if (!fromIP) {
      const ipMatch = header.match(/\[([0-9a-fA-F:.]+)\]/);
      if (ipMatch) fromIP = ipMatch[1];
    }

    // Extract BY host
    let byHost = null;
    const byMatch = header.match(/by\s+([^\s\(\[]+)/i);
    if (byMatch) {
      byHost = byMatch[1].replace(/[\(\)\[\];]/g, '').trim();
    }

    // Extract PROTOCOL (with ESMTP / ESMTPS / etc.)
    let protocol = null;
    const withMatch = header.match(/with\s+([^\s;]+)/i);
    if (withMatch) {
      protocol = withMatch[1].trim();
    }

    // Extract timestamp after semicolon
    let timestamp = null;
    const timeMatch = header.match(/;\s*(.*)$/);
    if (timeMatch) {
      timestamp = timeMatch[1].trim();
    }

    return {
      hopNumber: idx + 1,
      from: fromHost || 'Unknown Sender Server',
      ip: fromIP || 'N/A',
      by: byHost || 'Unknown Relay',
      protocol: protocol || 'SMTP',
      timestamp: timestamp || 'N/A',
      raw: header.trim(),
    };
  });
}

/**
 * Evaluate security risks such as Spoofing, SPF Fail, and DMARC Violations
 */
function performSecurityAssessment({ fromDomain, returnPathDomain, authStatus, hops }) {
  const flags = [];
  let riskScore = 0; // 0 (Clean) to 100 (High Risk Spoof)

  // Check 1: From vs Return-Path Domain Alignment
  if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
    flags.push({
      type: 'WARNING',
      title: 'Domain Mismatch (Return-Path vs From)',
      description: `Sender header (${fromDomain}) does not match Return-Path envelope (${returnPathDomain}). Common indicator of marketing relays or potential email spoofing.`,
    });
    riskScore += 25;
  }

  // Check 2: SPF Status
  if (authStatus.spf.status === 'FAIL') {
    flags.push({
      type: 'CRITICAL',
      title: 'SPF Authentication Failed',
      description: 'The sending mail server IP is not authorized by the domain SPF record to send emails on its behalf.',
    });
    riskScore += 40;
  } else if (authStatus.spf.status === 'SOFTFAIL') {
    flags.push({
      type: 'WARNING',
      title: 'SPF SoftFail Detected',
      description: 'Sending IP is not explicitly listed in SPF (~all). Likely unauthorized or transitional mail relay.',
    });
    riskScore += 20;
  } else if (authStatus.spf.status === 'NONE') {
    flags.push({
      type: 'INFO',
      title: 'No SPF Verification Found',
      description: 'Could not verify SPF authentication in headers.',
    });
    riskScore += 10;
  }

  // Check 3: DMARC Status
  if (authStatus.dmarc.status === 'FAIL') {
    flags.push({
      type: 'CRITICAL',
      title: 'DMARC Verification Failed',
      description: 'The email failed domain-level DMARC alignment checks. High probability of fraudulent or spoofed message.',
    });
    riskScore += 40;
  }

  // Check 4: DKIM Status
  if (authStatus.dkim.status === 'FAIL') {
    flags.push({
      type: 'CRITICAL',
      title: 'DKIM Cryptographic Signature Invalid',
      description: 'DKIM signature could not be verified or was modified in transit.',
    });
    riskScore += 30;
  } else if (authStatus.dkim.status === 'NONE') {
    flags.push({
      type: 'INFO',
      title: 'No DKIM Signature Found',
      description: 'Message lacks cryptographic DKIM domain signatures.',
    });
    riskScore += 10;
  }

  let verdict = 'CLEAN';
  let verdictColor = '#34d399';
  if (riskScore >= 60) {
    verdict = 'SUSPICIOUS / SPOOFING RISK';
    verdictColor = '#fb7185';
  } else if (riskScore >= 25) {
    verdict = 'UNALIGNED / REVIEW NEEDED';
    verdictColor = '#fbbf24';
  }

  return {
    riskScore: Math.min(riskScore, 100),
    verdict,
    verdictColor,
    flags,
  };
}
