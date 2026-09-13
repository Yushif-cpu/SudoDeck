// ═══════════════════════════════════════════════════════════════
//  ThreatIntel — SIEM Utilities & Parsers Frontend Logic
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  initSiemUtilities();
});

// ── Sample Logs Database ────────────────────────────────────────
const SAMPLE_LOGS = {
  json_alert: JSON.stringify({
    timestamp: "2026-09-13T04:22:19.412093Z",
    flow_id: 1827462947261,
    event_type: "alert",
    src_ip: "192.168.1.145",
    src_port: 54212,
    dest_ip: "10.0.0.25",
    dest_port: 445,
    proto: "TCP",
    alert: {
      action: "allowed",
      gid: 1,
      signature_id: 2012034,
      rev: 8,
      signature: "ET EXPLOIT Possible EternalBlue SMB Remote Code Execution Attempt (CVE-2017-0144)",
      category: "Attempted Administrator Privilege Gain",
      severity: 1,
      metadata: {
        cve: ["CVE-2017-0144"],
        affected_product: "Windows_SMBv1",
        attack_target: "Client_and_Server",
        deployment: "Perimeter",
        signature_severity: "Major"
      }
    },
    host: "sec-sensor-edge-01"
  }, null, 2),

  syslog_rfc5424: `<34>1 2026-09-13T04:15:30.003Z border-fw-01 sshd 24192 ID47 [auth@32473 user="admin" src="198.51.100.44" port="4122"] Failed password for invalid user admin from 198.51.100.44 port 4122 ssh2`,

  windows_event: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-13T04:18:22.1245000Z"/>
    <EventRecordID>491024</EventRecordID>
    <Correlation/>
    <Execution ProcessID="688" ThreadID="1432"/>
    <Channel>Security</Channel>
    <Computer>DC01.corp.internal</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">svc_backup</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="LogonProcessName">NtLmSsp</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="WorkstationName">WORKSTATION-92</Data>
    <Data Name="IpAddress">10.0.10.88</Data>
    <Data Name="IpPort">51240</Data>
  </EventData>
</Event>`,

  cef_log: `CEF:0|Palo Alto Networks|PAN-OS|10.1.0|threat|file|8|deviceExternalId=001801000001 src=10.10.20.155 spt=51294 dst=203.0.113.88 dpt=443 proto=tcp act=blocked fileId=982142 fname=invoice_doc.exe msg="Malicious binary payload detected and quarantined by WildFire" cs1=Antivirus cs1Label=ThreatType cn1=99 cn1Label=ThreatID`,

  key_value: `time="2026-09-13 04:20:11" logid="0000000013" type="traffic" subtype="forward" level="warning" action="deny" policyid=4 srcip=192.168.40.110 srcport=49214 dstip=172.16.5.20 dstport=22 proto=6 service="SSH" reason="IP blacklist match" devname="FGT-CORP-FW"`
};

// ── Sample Regex Presets ─────────────────────────────────────────
const REGEX_PRESETS = {
  ipv4: {
    name: 'IPv4 Address',
    pattern: '\\b(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\\b',
    flags: 'g',
    desc: 'Matches valid IPv4 addresses (0.0.0.0 to 255.255.255.255)',
    sample: 'Connection failed from 192.168.1.105 and 10.0.0.1, external relay was 203.0.113.199.'
  },
  cve: {
    name: 'CVE Identifier',
    pattern: '\\bCVE-\\d{4}-\\d{4,7}\\b',
    flags: 'gi',
    desc: 'Matches Common Vulnerabilities and Exposures numbers',
    sample: 'Vulnerability scanner reported CVE-2021-44228 (Log4Shell) and CVE-2017-0144.'
  },
  hashes: {
    name: 'MD5 / SHA-256 Hash',
    pattern: '\\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})\\b',
    flags: 'g',
    desc: 'Matches 32-char MD5 or 64-char SHA-256 cryptographic hashes',
    sample: 'Threat hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, legacy md5: 5d41402abc4b2a76b9719d911017c592.'
  },
  email: {
    name: 'Email Address',
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    flags: 'gi',
    desc: 'Matches valid user@domain.tld email addresses',
    sample: 'Alert dispatched to soc-analyst@corp.internal and fallback sec-ops@external-partner.com.'
  },
  domain: {
    name: 'Domain / FQDN',
    pattern: '\\b(?=.{1,253}\\b)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,63}\\b',
    flags: 'gi',
    desc: 'Matches fully qualified domain names and hostnames',
    sample: 'C2 beaconing detected to api.telemetry-update.com and backup at ns1.threat-dns.net.'
  },
  url: {
    name: 'HTTP/HTTPS URL',
    pattern: 'https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_+.~#?&//=]*)',
    flags: 'gi',
    desc: 'Matches web URLs with protocol, path and query string',
    sample: 'Phishing email link: https://login.microsoft.online-verify.cc/auth?token=9281a&redirect=true'
  },
  winevent: {
    name: 'Windows Event ID',
    pattern: '(?:EventID>?\\s*[:=]\\s*|<EventID>)(\\d{4,5})(?:<\\/EventID>)?',
    flags: 'gi',
    desc: 'Extracts 4-5 digit Windows Security/System Event IDs',
    sample: '<EventID>4624</EventID> Logon Success, followed by EventID: 4672 privileged assigned.'
  },
  base64: {
    name: 'Base64 String',
    pattern: '(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    flags: 'g',
    desc: 'Matches base64 strings with minimum length (>= 32 chars)',
    sample: 'PowerShell -EncodedCommand VABoAGkAcwAgAGkAcwAgAGEAIABwAGEAeQBsAG8AYQBkACAAdABlAHMAdAA='
  }
};

// ── Application State ───────────────────────────────────────────
const state = {
  activeTab: 'formatter', // 'formatter' | 'regex' | 'headers'
  rawLog: '',
  formattedData: null,
  detectedFormat: 'unknown',
  regexPattern: '',
  regexFlags: 'gi',
  regexTestText: '',
  matches: [],
  // Headers & User-Agent state
  currentUA: '',
  parsedUA: null,
  rawHeaders: '',
  parsedHeaders: [],
  headersSearchTerm: '',
  activeHeaderFilter: 'all',
  securityAudit: null
};

// ── Initialization ──────────────────────────────────────────────
function initSiemUtilities() {
  setupTabs();
  setupFormatter();
  setupRegexTester();
  setupHeadersAnalyzer();
  setupGlobalActions();

  // Load initial defaults silently (NO toasts on page load / F5!)
  loadSampleLog('json_alert', true);
  loadRegexPreset('ipv4', true);
  loadSampleUA('win-chrome', true);
  loadHeadersPreset('hardened', true);

  // Restore active tab on page load (from URL hash or localStorage)
  const hash = window.location.hash ? window.location.hash.replace('#', '') : null;
  const savedTab = hash || localStorage.getItem('siem_active_tab') || 'formatter';
  if (['formatter', 'regex', 'headers'].includes(savedTab)) {
    switchTab(savedTab);
  }
}

// ── Tab Management & Persistence ────────────────────────────────
function switchTab(tabName) {
  if (!tabName) return;
  state.activeTab = tabName;
  localStorage.setItem('siem_active_tab', tabName);

  const tabButtons = document.querySelectorAll('.siem-nav-tab');
  const sections = {
    formatter: document.getElementById('section-formatter'),
    regex: document.getElementById('section-regex'),
    headers: document.getElementById('section-headers')
  };

  tabButtons.forEach(b => {
    const isActive = b.dataset.tab === tabName;
    b.classList.toggle('active', isActive);
    if (isActive) {
      b.classList.add('border-indigo-500', 'text-white', 'bg-surface-800/80');
      b.classList.remove('border-transparent', 'text-slate-400');
    } else {
      b.classList.remove('border-indigo-500', 'text-white', 'bg-surface-800/80');
      b.classList.add('border-transparent', 'text-slate-400');
    }
  });

  Object.keys(sections).forEach(k => {
    if (sections[k]) {
      sections[k].classList.toggle('hidden', k !== tabName);
    }
  });

  if (window.lucide) lucide.createIcons();
}

function setupTabs() {
  const tabButtons = document.querySelectorAll('.siem-nav-tab');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      switchTab(tabName);
      if (history.replaceState) {
        history.replaceState(null, '', '#' + tabName);
      } else {
        window.location.hash = tabName;
      }
    });
  });

  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.replace('#', '');
    if (['formatter', 'regex', 'headers'].includes(hash)) {
      switchTab(hash);
    }
  });
}

// ═══════════════════════════════════════════════════════════════
//  SECTION 1: LOG & ALERT FORMATTER LOGIC
// ═══════════════════════════════════════════════════════════════
function setupFormatter() {
  const inputEl = document.getElementById('raw-log-input');
  const formatBtn = document.getElementById('btn-format-log');
  const minifyBtn = document.getElementById('btn-minify-log');
  const clearBtn = document.getElementById('btn-clear-log');
  const sampleSelector = document.getElementById('select-sample-log');
  const copyFormattedBtn = document.getElementById('btn-copy-formatted');

  if (inputEl) {
    inputEl.addEventListener('input', () => {
      state.rawLog = inputEl.value;
      updateInputStats();
    });
  }

  if (formatBtn) {
    formatBtn.addEventListener('click', () => {
      processLogFormatting(false);
    });
  }

  if (minifyBtn) {
    minifyBtn.addEventListener('click', () => {
      processLogFormatting(true);
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (inputEl) inputEl.value = '';
      state.rawLog = '';
      state.formattedData = null;
      updateInputStats();
      clearFormattedOutput();
      showToast('Input cleared', 'info');
    });
  }

  if (sampleSelector) {
    sampleSelector.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val && SAMPLE_LOGS[val]) {
        loadSampleLog(val);
      }
    });
  }

  if (copyFormattedBtn) {
    copyFormattedBtn.addEventListener('click', () => {
      const codeEl = document.getElementById('formatted-code-output');
      if (codeEl && codeEl.textContent.trim()) {
        copyToClipboard(codeEl.textContent, copyFormattedBtn);
      } else {
        showToast('No formatted output to copy', 'warning');
      }
    });
  }
}

function loadSampleLog(key, silent = false) {
  const inputEl = document.getElementById('raw-log-input');
  if (SAMPLE_LOGS[key] && inputEl) {
    inputEl.value = SAMPLE_LOGS[key];
    state.rawLog = SAMPLE_LOGS[key];
    updateInputStats();
    processLogFormatting(false, silent);
    if (!silent) {
      showToast(`Loaded sample: ${key}`, 'success');
    }
  }
}

function updateInputStats() {
  const lenEl = document.getElementById('raw-log-length');
  const linesEl = document.getElementById('raw-log-lines');
  const text = state.rawLog || '';

  if (lenEl) lenEl.textContent = `${text.length.toLocaleString()} chars`;
  if (linesEl) {
    const lines = text ? text.split(/\r\n|\r|\n/).length : 0;
    linesEl.textContent = `${lines} ${lines === 1 ? 'line' : 'lines'}`;
  }
}

// ── Parser Engine ───────────────────────────────────────────────
function processLogFormatting(minify = false, silent = false) {
  const raw = (state.rawLog || '').trim();
  const outputCard = document.getElementById('formatted-output-card');
  const codeEl = document.getElementById('formatted-code-output');
  const badgeFormat = document.getElementById('badge-detected-format');
  const badgeFields = document.getElementById('badge-fields-count');
  const badgeTime = document.getElementById('badge-parse-time');
  const tableContainer = document.getElementById('parsed-fields-container');

  if (!raw) {
    if (!silent) {
      showToast('Please enter a log or alert to format', 'warning');
    }
    return;
  }

  const startTime = performance.now();
  let parsedObj = null;
  let detectedType = 'Plain Text';
  let formattedCode = '';
  let extractedFields = {};

  try {
    // 1. Check if valid JSON
    if ((raw.startsWith('{') && raw.endsWith('}')) || (raw.startsWith('[') && raw.endsWith(']'))) {
      parsedObj = JSON.parse(raw);
      detectedType = 'JSON Alert';
      extractedFields = extractKeySiemFields(parsedObj);
    }
    // 2. Check if XML / Windows Event Log
    else if (raw.startsWith('<') && raw.endsWith('>')) {
      parsedObj = parseXmlLikeLog(raw);
      detectedType = 'Windows Event / XML';
      extractedFields = extractKeySiemFields(parsedObj);
    }
    // 3. Check if CEF Log
    else if (raw.includes('CEF:')) {
      parsedObj = parseCefLog(raw);
      detectedType = 'CEF (Common Event Format)';
      extractedFields = extractKeySiemFields(parsedObj);
    }
    // 4. Check if Syslog RFC 5424 / 3164
    else if (/^<\d{1,3}>/.test(raw) || /(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+/.test(raw)) {
      parsedObj = parseSyslog(raw);
      detectedType = 'Syslog';
      extractedFields = extractKeySiemFields(parsedObj);
    }
    // 5. Check if Key-Value pairs (key=val or key="val")
    else if (/[a-zA-Z0-9_-]+=(?:"[^"]*"|'[^']*'|[^\s]+)/.test(raw)) {
      parsedObj = parseKeyValueLog(raw);
      detectedType = 'Key-Value / Firewall Log';
      extractedFields = extractKeySiemFields(parsedObj);
    }
    else {
      detectedType = 'Raw Text / Unstructured';
      parsedObj = { raw_message: raw };
      extractedFields = { raw_message: raw };
    }
  } catch (err) {
    // Fallback if JSON parse failed
    detectedType = 'Malformed JSON / Text';
    parsedObj = { error: err.message, raw_content: raw };
  }

  const elapsed = (performance.now() - startTime).toFixed(1);

  // Render highlighted output
  if (minify) {
    formattedCode = JSON.stringify(parsedObj);
    if (codeEl) codeEl.textContent = formattedCode;
  } else {
    formattedCode = JSON.stringify(parsedObj, null, 2);
    if (codeEl) {
      codeEl.innerHTML = syntaxHighlightJson(formattedCode);
    }
  }

  // Update Badges
  if (badgeFormat) {
    badgeFormat.textContent = detectedType;
    badgeFormat.className = `px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getBadgeStyleForFormat(detectedType)}`;
  }
  if (badgeFields) {
    const totalKeys = countDeepKeys(parsedObj);
    badgeFields.textContent = `${totalKeys} fields`;
  }
  if (badgeTime) {
    badgeTime.textContent = `${elapsed} ms`;
  }

  // Render Extracted Fields Summary
  renderParsedFieldsTable(extractedFields, tableContainer);

  if (outputCard) outputCard.classList.remove('hidden');
  if (!silent) {
    showToast(`Parsed as ${detectedType} (${elapsed}ms)`, 'success');
  }
}

function clearFormattedOutput() {
  const outputCard = document.getElementById('formatted-output-card');
  const codeEl = document.getElementById('formatted-code-output');
  const tableContainer = document.getElementById('parsed-fields-container');
  if (outputCard) outputCard.classList.add('hidden');
  if (codeEl) codeEl.innerHTML = '';
  if (tableContainer) tableContainer.innerHTML = '';
}

// ── Specific Parsers ────────────────────────────────────────────

// 1. CEF Parser: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
function parseCefLog(raw) {
  const parts = raw.split('|');
  if (parts.length < 7) {
    return parseKeyValueLog(raw);
  }

  const header = {
    cef_version: parts[0].replace(/.*?CEF:/i, '').trim(),
    device_vendor: parts[1],
    device_product: parts[2],
    device_version: parts[3],
    device_event_class_id: parts[4],
    name: parts[5],
    severity: parts[6]
  };

  const extensionRaw = parts.slice(7).join('|');
  const extension = parseKeyValueLog(extensionRaw);

  return {
    ...header,
    extension
  };
}

// 2. Syslog Parser
function parseSyslog(raw) {
  const result = {};
  // PRI: <34>
  const priMatch = raw.match(/^<(\d{1,3})>/);
  if (priMatch) {
    const pri = parseInt(priMatch[1], 10);
    result.pri = pri;
    result.facility = Math.floor(pri / 8);
    result.severity = pri % 8;
    result.severity_label = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Informational', 'Debug'][result.severity] || 'Unknown';
  }

  // Remainder
  const body = raw.replace(/^<\d{1,3}>/, '').trim();
  const tokenParts = body.split(/\s+/);

  // Check RFC 5424 timestamp
  if (tokenParts[0] && /\d{4}-\d{2}-\d{2}T/.test(tokenParts[0])) {
    result.timestamp = tokenParts[0];
    result.hostname = tokenParts[1] || '';
    result.app_name = tokenParts[2] || '';
    result.proc_id = tokenParts[3] || '';
    result.msg_id = tokenParts[4] || '';
    result.message = tokenParts.slice(5).join(' ');
  } else {
    // RFC 3164 (e.g. Sep 13 04:15:30)
    result.timestamp = tokenParts.slice(0, 3).join(' ');
    result.hostname = tokenParts[3] || '';
    result.message = tokenParts.slice(4).join(' ');
  }

  // If message has key-values inside, parse them too
  const innerKv = parseKeyValueLog(result.message || '');
  if (Object.keys(innerKv).length > 2) {
    result.extracted_attributes = innerKv;
  }

  return result;
}

// 3. Key-Value Parser (Fortinet, Palo Alto, AWS VPC flow)
function parseKeyValueLog(raw) {
  const obj = {};
  const regex = /([a-zA-Z0-9_\-.]+)=(?:"([^"]*)"|'([^']*)'|([^\s,]+))/g;
  let match;

  while ((match = regex.exec(raw)) !== null) {
    const key = match[1];
    const val = match[2] !== undefined ? match[2] : (match[3] !== undefined ? match[3] : match[4]);
    obj[key] = isNaN(val) ? val : (val.includes('.') ? parseFloat(val) : parseInt(val, 10));
  }

  return Object.keys(obj).length > 0 ? obj : { raw };
}

// 4. XML / Windows Event Log quick parser
function parseXmlLikeLog(raw) {
  const obj = {};

  // Extract EventID
  const eid = raw.match(/<EventID[^>]*>(\d+)<\/EventID>/i);
  if (eid) obj.event_id = parseInt(eid[1], 10);

  // Extract Provider
  const prov = raw.match(/<Provider\s+Name="([^"]+)"/i);
  if (prov) obj.provider_name = prov[1];

  // Extract Computer
  const comp = raw.match(/<Computer>([^<]+)<\/Computer>/i);
  if (comp) obj.computer = comp[1];

  // Extract TimeCreated
  const time = raw.match(/<TimeCreated\s+SystemTime="([^"]+)"/i);
  if (time) obj.timestamp = time[1];

  // Extract Channel
  const chan = raw.match(/<Channel>([^<]+)<\/Channel>/i);
  if (chan) obj.channel = chan[1];

  // Extract Data elements: <Data Name="Key">Value</Data>
  const dataMap = {};
  const dataRegex = /<Data\s+Name="([^"]+)">([^<]*)<\/Data>/gi;
  let dMatch;
  while ((dMatch = dataRegex.exec(raw)) !== null) {
    dataMap[dMatch[1]] = dMatch[2];
  }

  if (Object.keys(dataMap).length > 0) {
    obj.event_data = dataMap;
  }

  return obj;
}

// ── Key SIEM Field Extractor ────────────────────────────────────
function extractKeySiemFields(obj) {
  const summary = {};

  function search(node, prefix = '') {
    if (!node || typeof node !== 'object') return;

    for (const [key, val] of Object.entries(node)) {
      const lower = key.toLowerCase();

      // Timestamp
      if (!summary.timestamp && (lower.includes('time') || lower === 'ts' || lower === '@timestamp')) {
        if (typeof val === 'string' || typeof val === 'number') summary.timestamp = String(val);
      }

      // Source IP
      if (!summary.source_ip && (lower === 'src_ip' || lower === 'srcip' || lower === 'src' || lower === 'sourceip' || lower === 'ipaddress')) {
        if (typeof val === 'string') summary.source_ip = val;
      }

      // Source Port
      if (!summary.source_port && (lower === 'src_port' || lower === 'srcport' || lower === 'spt' || lower === 'ipport')) {
        summary.source_port = val;
      }

      // Dest IP
      if (!summary.dest_ip && (lower === 'dest_ip' || lower === 'dstip' || lower === 'dst' || lower === 'destinationip')) {
        if (typeof val === 'string') summary.dest_ip = val;
      }

      // Dest Port
      if (!summary.dest_port && (lower === 'dest_port' || lower === 'dstport' || lower === 'dpt')) {
        summary.dest_port = val;
      }

      // Event ID / Signature
      if (!summary.event_name && (lower === 'signature' || lower === 'event_name' || lower === 'msg' || lower === 'name')) {
        if (typeof val === 'string') summary.event_name = val;
      }
      if (!summary.event_id && (lower === 'event_id' || lower === 'eventid' || lower === 'signature_id' || lower === 'logid')) {
        summary.event_id = val;
      }

      // User / Account
      if (!summary.user && (lower === 'user' || lower === 'username' || lower === 'targetusername' || lower === 'src_user')) {
        if (typeof val === 'string' && val.trim()) summary.user = val;
      }

      // Host / Computer
      if (!summary.host && (lower === 'host' || lower === 'hostname' || lower === 'computer' || lower === 'devname')) {
        if (typeof val === 'string') summary.host = val;
      }

      // Action / Status
      if (!summary.action && (lower === 'action' || lower === 'act' || lower === 'status' || lower === 'result')) {
        if (typeof val === 'string' || typeof val === 'number') summary.action = String(val);
      }

      // Recurse
      if (typeof val === 'object') {
        search(val, `${prefix}${key}.`);
      }
    }
  }

  search(obj);
  return summary;
}

function renderParsedFieldsTable(fields, container) {
  if (!container) return;

  const entries = Object.entries(fields).filter(([_, v]) => v !== undefined && v !== null && v !== '');

  if (entries.length === 0) {
    container.innerHTML = `
      <div class="p-4 rounded-xl bg-surface-900 border border-slate-800 text-center text-xs text-slate-500">
        No standard SIEM identifiers (IPs, Event IDs, Users) detected automatically. Inspect raw JSON below.
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
      ${entries.map(([k, v]) => {
        const label = formatFieldLabel(k);
        const strVal = String(v);
        const isIp = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(strVal.trim());
        const isCve = /CVE-\d{4}-\d{4,7}/i.test(strVal);

        return `
          <div class="p-2.5 rounded-xl bg-surface-900/80 border border-slate-800/80 hover:border-slate-700 transition-colors flex flex-col justify-between">
            <div>
              <span class="text-[10px] uppercase font-mono font-bold text-slate-500 tracking-wider block">${escapeHtml(label)}</span>
              <span class="text-xs font-mono font-bold text-indigo-300 truncate block mt-0.5" title="${escapeHtml(strVal)}">
                ${escapeHtml(strVal)}
              </span>
            </div>
            ${isIp ? `
              <div class="pt-1.5 mt-1 border-t border-slate-800/60">
                <a href="/?ip=${encodeURIComponent(strVal.trim())}" class="inline-flex items-center gap-1 text-[10px] font-medium text-cyan-400 hover:text-cyan-300 transition-colors">
                  <i data-lucide="shield-check" class="w-3 h-3"></i>
                  <span>Check IP Intel</span>
                </a>
              </div>
            ` : ''}
            ${isCve ? `
              <div class="pt-1.5 mt-1 border-t border-slate-800/60">
                <a href="/cve?id=${encodeURIComponent(strVal.match(/CVE-\d{4}-\d{4,7}/i)[0])}" class="inline-flex items-center gap-1 text-[10px] font-medium text-rose-400 hover:text-rose-300 transition-colors">
                  <i data-lucide="flame" class="w-3 h-3"></i>
                  <span>Scan CVE</span>
                </a>
              </div>
            ` : ''}
          </div>
        `;
      }).join('')}
    </div>
  `;

  if (window.lucide) {
    try {
      lucide.createIcons({ nodes: [container] });
    } catch (_) {}
  }
}

function formatFieldLabel(key) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function getBadgeStyleForFormat(fmt) {
  switch (fmt) {
    case 'JSON Alert':
      return 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
    case 'Windows Event / XML':
      return 'bg-blue-500/10 border-blue-500/30 text-blue-400';
    case 'CEF (Common Event Format)':
      return 'bg-purple-500/10 border-purple-500/30 text-purple-400';
    case 'Syslog':
      return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
    case 'Key-Value / Firewall Log':
      return 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400';
    default:
      return 'bg-slate-700/30 border-slate-600 text-slate-300';
  }
}

function countDeepKeys(obj) {
  if (!obj || typeof obj !== 'object') return 1;
  let count = 0;
  for (const k in obj) {
    count += countDeepKeys(obj[k]);
  }
  return count;
}

// ── JSON Syntax Highlighting ────────────────────────────────────
function syntaxHighlightJson(jsonStr) {
  jsonStr = escapeHtml(jsonStr);
  return jsonStr.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
    (match) => {
      let cls = 'text-amber-300'; // number
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'text-indigo-400 font-semibold'; // key
        } else {
          cls = 'text-emerald-300'; // string
        }
      } else if (/true|false/.test(match)) {
        cls = 'text-purple-400 font-bold'; // boolean
      } else if (/null/.test(match)) {
        cls = 'text-slate-500 italic'; // null
      }
      return `<span class="${cls}">${match}</span>`;
    }
  );
}

// ═══════════════════════════════════════════════════════════════
//  SECTION 2: REGEX TESTER & DETECTION HELPER
// ═══════════════════════════════════════════════════════════════
function setupRegexTester() {
  const patternInput = document.getElementById('regex-pattern-input');
  const testTextInput = document.getElementById('regex-test-text');
  const flagCheckboxes = document.querySelectorAll('.regex-flag-cb');
  const presetSelector = document.getElementById('select-regex-preset');
  const generateRulesBtn = document.getElementById('btn-generate-siem-rules');

  function triggerRegexEvaluation() {
    state.regexPattern = patternInput ? patternInput.value : '';
    state.regexTestText = testTextInput ? testTextInput.value : '';

    // Collect flags
    let flags = '';
    flagCheckboxes.forEach(cb => {
      if (cb.checked) flags += cb.value;
    });
    state.regexFlags = flags;

    evaluateRegex();
  }

  if (patternInput) {
    patternInput.addEventListener('input', triggerRegexEvaluation);
  }

  if (testTextInput) {
    testTextInput.addEventListener('input', triggerRegexEvaluation);
  }

  flagCheckboxes.forEach(cb => {
    cb.addEventListener('change', triggerRegexEvaluation);
  });

  if (presetSelector) {
    presetSelector.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val && REGEX_PRESETS[val]) {
        loadRegexPreset(val);
      }
    });
  }

  // Quick Preset Click Buttons
  document.querySelectorAll('.btn-quick-regex').forEach(btn => {
    btn.addEventListener('click', () => {
      const presetKey = btn.dataset.preset;
      if (presetKey && REGEX_PRESETS[presetKey]) {
        loadRegexPreset(presetKey);
      }
    });
  });

  // SIEM Rule Generator Button
  if (generateRulesBtn) {
    generateRulesBtn.addEventListener('click', () => {
      generateSiemDetectionRules();
    });
  }
}

function loadRegexPreset(key, silent = false) {
  const preset = REGEX_PRESETS[key];
  if (!preset) return;

  const patternInput = document.getElementById('regex-pattern-input');
  const testTextInput = document.getElementById('regex-test-text');
  const flagCheckboxes = document.querySelectorAll('.regex-flag-cb');
  const presetDesc = document.getElementById('regex-preset-desc');

  if (patternInput) patternInput.value = preset.pattern;
  if (testTextInput && (!testTextInput.value || testTextInput.value.length < 50)) {
    testTextInput.value = preset.sample;
  }

  flagCheckboxes.forEach(cb => {
    cb.checked = preset.flags.includes(cb.value);
  });

  if (presetDesc) {
    presetDesc.textContent = `${preset.name} — ${preset.desc}`;
  }

  state.regexPattern = preset.pattern;
  state.regexFlags = preset.flags;
  state.regexTestText = testTextInput ? testTextInput.value : preset.sample;

  evaluateRegex();
  if (!silent) {
    showToast(`Loaded regex preset: ${preset.name}`, 'info');
  }
}

function evaluateRegex() {
  const pattern = state.regexPattern;
  const flags = state.regexFlags;
  const text = state.regexTestText;

  const highlightContainer = document.getElementById('regex-highlight-preview');
  const matchCountBadge = document.getElementById('badge-match-count');
  const matchExecBadge = document.getElementById('badge-match-time');
  const matchTableContainer = document.getElementById('regex-matches-table-container');
  const errorAlert = document.getElementById('regex-error-alert');

  if (errorAlert) errorAlert.classList.add('hidden');

  if (!pattern) {
    if (highlightContainer) highlightContainer.innerHTML = escapeHtml(text || 'Enter text and regex pattern above to preview matches...');
    if (matchCountBadge) matchCountBadge.textContent = '0 matches';
    if (matchTableContainer) matchTableContainer.innerHTML = '';
    return;
  }

  let regex;
  try {
    regex = new RegExp(pattern, flags);
  } catch (err) {
    if (errorAlert) {
      errorAlert.classList.remove('hidden');
      errorAlert.textContent = `Regex Syntax Error: ${err.message}`;
    }
    if (matchCountBadge) matchCountBadge.textContent = 'Syntax Error';
    return;
  }

  const startTime = performance.now();
  const matches = [];

  // If text is huge, avoid browser freeze
  const safeText = text.length > 100000 ? text.substring(0, 100000) : text;

  try {
    if (flags.includes('g')) {
      let m;
      let iterations = 0;
      while ((m = regex.exec(safeText)) !== null && iterations < 1000) {
        iterations++;
        matches.push({
          index: m.index,
          length: m[0].length,
          value: m[0],
          groups: m.slice(1)
        });
        if (m[0].length === 0) {
          regex.lastIndex++; // prevent infinite loop on zero-width match
        }
      }
    } else {
      const m = regex.exec(safeText);
      if (m) {
        matches.push({
          index: m.index,
          length: m[0].length,
          value: m[0],
          groups: m.slice(1)
        });
      }
    }
  } catch (evalErr) {
    if (errorAlert) {
      errorAlert.classList.remove('hidden');
      errorAlert.textContent = `Regex Execution Error: ${evalErr.message}`;
    }
    return;
  }

  const elapsed = (performance.now() - startTime).toFixed(2);
  state.matches = matches;

  // 1. Update Match Badges
  if (matchCountBadge) {
    matchCountBadge.textContent = `${matches.length} ${matches.length === 1 ? 'match' : 'matches'}`;
    matchCountBadge.className = matches.length > 0
      ? 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40'
      : 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700';
  }
  if (matchExecBadge) {
    matchExecBadge.textContent = `${elapsed} ms`;
  }

  // 2. Render Highlighted Text
  if (highlightContainer) {
    if (matches.length === 0) {
      highlightContainer.innerHTML = escapeHtml(safeText || '(No text provided)');
    } else {
      highlightContainer.innerHTML = buildHighlightedHtml(safeText, matches);
    }
  }

  // 3. Render Match Details Table
  renderMatchesTable(matches, matchTableContainer);
}

function buildHighlightedHtml(text, matches) {
  let result = '';
  let lastIndex = 0;

  // Sort matches by index
  const sorted = [...matches].sort((a, b) => a.index - b.index);

  sorted.forEach((m, idx) => {
    // text before match
    if (m.index > lastIndex) {
      result += escapeHtml(text.substring(lastIndex, m.index));
    }
    // matched text
    const matchVal = text.substring(m.index, m.index + m.length);
    result += `<mark class="regex-mark-match" title="Match #${idx + 1} (Offset ${m.index})">${escapeHtml(matchVal)}</mark>`;
    lastIndex = m.index + m.length;
  });

  // remaining text
  if (lastIndex < text.length) {
    result += escapeHtml(text.substring(lastIndex));
  }

  return result;
}

function renderMatchesTable(matches, container) {
  if (!container) return;

  if (matches.length === 0) {
    container.innerHTML = `
      <div class="p-6 text-center text-xs text-slate-500 space-y-1">
        <i data-lucide="search-x" class="w-6 h-6 mx-auto text-slate-600 mb-2"></i>
        <p class="font-medium text-slate-400">No regex matches found</p>
        <p class="text-[11px] text-slate-600">Check pattern syntax, case-sensitivity flags, or input sample text.</p>
      </div>
    `;
    if (window.lucide) lucide.createIcons({ nodes: [container] });
    return;
  }

  container.innerHTML = `
    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs text-slate-300">
        <thead class="bg-surface-950/80 text-[10px] uppercase font-mono font-bold text-slate-400 border-b border-slate-800">
          <tr>
            <th class="py-2.5 px-3">#</th>
            <th class="py-2.5 px-3">Match Value</th>
            <th class="py-2.5 px-3">Offset</th>
            <th class="py-2.5 px-3">Length</th>
            <th class="py-2.5 px-3">Groups</th>
            <th class="py-2.5 px-3 text-right">Action</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800/60 font-mono">
          ${matches.slice(0, 100).map((m, idx) => {
            const hasGroups = m.groups && m.groups.length > 0;
            return `
              <tr class="hover:bg-surface-800/50 transition-colors">
                <td class="py-2.5 px-3 text-indigo-400 font-bold">${idx + 1}</td>
                <td class="py-2.5 px-3 font-semibold text-white truncate max-w-xs" title="${escapeHtml(m.value)}">
                  <span class="px-1.5 py-0.5 rounded bg-surface-800 border border-slate-700/80 text-amber-300 select-all">
                    ${escapeHtml(m.value)}
                  </span>
                </td>
                <td class="py-2.5 px-3 text-slate-400 text-[11px]">${m.index}</td>
                <td class="py-2.5 px-3 text-slate-400 text-[11px]">${m.length}</td>
                <td class="py-2.5 px-3 text-[11px]">
                  ${hasGroups ? m.groups.map((g, gi) => `
                    <span class="inline-block px-1.5 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 mr-1 text-[10px]">
                      $${gi + 1}: ${escapeHtml(g || 'null')}
                    </span>
                  `).join('') : '<span class="text-slate-600 italic">none</span>'}
                </td>
                <td class="py-2.5 px-3 text-right">
                  <button
                    type="button"
                    class="btn-copy-table-match px-2 py-1 rounded text-[10px] bg-surface-800 hover:bg-surface-700 text-slate-300 hover:text-white border border-slate-700 transition-colors"
                    data-copy="${escapeHtml(m.value)}"
                  >
                    Copy
                  </button>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
      ${matches.length > 100 ? `
        <div class="p-2 text-center text-[10px] font-mono text-slate-500 bg-surface-950/60 border-t border-slate-800">
          Showing first 100 of ${matches.length} matches
        </div>
      ` : ''}
    </div>
  `;

  // Attach table copy listeners
  container.querySelectorAll('.btn-copy-table-match').forEach(btn => {
    btn.addEventListener('click', () => {
      copyToClipboard(btn.dataset.copy, btn);
    });
  });
}

// ── SIEM Query Rule Generator ───────────────────────────────────
function generateSiemDetectionRules() {
  const pattern = state.regexPattern.trim();
  const rulesModal = document.getElementById('siem-rules-modal');
  const modalContent = document.getElementById('siem-rules-modal-content');

  if (!pattern) {
    showToast('Enter a valid regex pattern first', 'warning');
    return;
  }

  // Splunk
  const splunkQuery = `index=* sourcetype=* | rex field=_raw "(?P<extracted_ioc>${pattern})"\n| stats count by extracted_ioc\n| sort - count`;

  // KQL / Elasticsearch
  const elasticQuery = `POST /*/_search\n{\n  "query": {\n    "regexp": {\n      "message": {\n        "value": "${pattern.replace(/\\/g, '\\\\')}",\n        "flags": "ALL",\n        "case_insensitive": true\n      }\n    }\n  }\n}`;

  // Sigma Rule YAML
  const sigmaYaml = `title: Custom IOC Detection via Regular Expression
id: ${generateUuid()}
status: experimental
description: Detects matches for pattern ${pattern}
author: sudodeck SIEM Suite
date: ${new Date().toISOString().split('T')[0]}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '${pattern.replace(/'/g, "''")}'
  condition: selection
falsepositives:
  - Unknown
level: medium`;

  // YARA Rule
  const yaraRule = `rule Detect_Regex_Pattern {\n    meta:\n        description = "Automated YARA rule for regex matching"\n        author = "sudodeck SIEM Utilities"\n        date = "${new Date().toISOString().split('T')[0]}"\n    strings:\n        $re1 = /${pattern}/\n    condition:\n        $re1\n}`;

  if (modalContent) {
    modalContent.innerHTML = `
      <div class="space-y-4">
        <!-- Splunk Card -->
        <div class="card p-4 bg-surface-900 border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold font-mono text-amber-400">Splunk SPL (rex Extraction)</span>
            <button class="btn-copy-rule btn-secondary !text-[11px] !py-1 !px-2.5" data-code="${escapeHtml(splunkQuery)}">
              Copy SPL
            </button>
          </div>
          <pre class="bg-surface-950 p-3 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto"><code>${escapeHtml(splunkQuery)}</code></pre>
        </div>

        <!-- Sigma Rule Card -->
        <div class="card p-4 bg-surface-900 border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold font-mono text-indigo-400">Sigma Detection Rule (YAML)</span>
            <button class="btn-copy-rule btn-secondary !text-[11px] !py-1 !px-2.5" data-code="${escapeHtml(sigmaYaml)}">
              Copy Sigma
            </button>
          </div>
          <pre class="bg-surface-950 p-3 rounded-lg text-xs font-mono text-emerald-400 overflow-x-auto"><code>${escapeHtml(sigmaYaml)}</code></pre>
        </div>

        <!-- Elasticsearch Query -->
        <div class="card p-4 bg-surface-900 border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold font-mono text-cyan-400">Elasticsearch DSL Regexp Query</span>
            <button class="btn-copy-rule btn-secondary !text-[11px] !py-1 !px-2.5" data-code="${escapeHtml(elasticQuery)}">
              Copy DSL
            </button>
          </div>
          <pre class="bg-surface-950 p-3 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto"><code>${escapeHtml(elasticQuery)}</code></pre>
        </div>

        <!-- YARA Rule Card -->
        <div class="card p-4 bg-surface-900 border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold font-mono text-rose-400">YARA String Rule</span>
            <button class="btn-copy-rule btn-secondary !text-[11px] !py-1 !px-2.5" data-code="${escapeHtml(yaraRule)}">
              Copy YARA
            </button>
          </div>
          <pre class="bg-surface-950 p-3 rounded-lg text-xs font-mono text-rose-300 overflow-x-auto"><code>${escapeHtml(yaraRule)}</code></pre>
        </div>
      </div>
    `;

    modalContent.querySelectorAll('.btn-copy-rule').forEach(btn => {
      btn.addEventListener('click', () => {
        copyToClipboard(btn.dataset.code, btn);
      });
    });
  }

  if (rulesModal) rulesModal.classList.remove('hidden');
}

// ── Global Helper Utilities ─────────────────────────────────────
function setupGlobalActions() {
  const modalClose = document.getElementById('btn-close-siem-modal');
  const rulesModal = document.getElementById('siem-rules-modal');

  if (modalClose && rulesModal) {
    modalClose.addEventListener('click', () => {
      rulesModal.classList.add('hidden');
    });
  }

  // Close modal when clicking outside
  if (rulesModal) {
    rulesModal.addEventListener('click', (e) => {
      if (e.target === rulesModal) {
        rulesModal.classList.add('hidden');
      }
    });
  }
}

// ═══════════════════════════════════════════════════════════════
//  SECTION 3: USER-AGENT & HTTP HEADER ANALYZER LOGIC
// ═══════════════════════════════════════════════════════════════

// ── Sample User-Agents Database ─────────────────────────────────
const SAMPLE_UAS = {
  'win-chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'mac-safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'iphone-safari': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  'android-chrome': 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36',
  'sqlmap': 'sqlmap/1.8.8#stable (https://sqlmap.org)',
  'nikto': 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)',
  'googlebot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'curl': 'curl/8.5.0'
};

// ── Sample HTTP Headers Database ────────────────────────────────
const SAMPLE_HEADERS = {
  hardened: `HTTP/2 200 OK
Date: Sun, 13 Sep 2026 04:30:00 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 1042
Connection: keep-alive
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; block-all-mixed-content
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate
Pragma: no-cache
Server: cloudflare`,

  vulnerable: `HTTP/1.1 200 OK
Date: Sun, 13 Sep 2026 04:30:00 GMT
Server: Apache/2.4.41 (Ubuntu) mod_ssl/2.4.41 OpenSSL/1.1.1f
X-Powered-By: PHP/7.4.3
X-AspNet-Version: 4.0.30319
Content-Type: text/html; charset=UTF-8
Content-Length: 4820
Connection: close
Access-Control-Allow-Origin: *
Set-Cookie: PHPSESSID=f87a39b2cd81a0e98213; path=/; HttpOnly`,

  cloudflare: `HTTP/2 200 OK
Date: Sun, 13 Sep 2026 04:30:00 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
CF-Ray: 8c34f9a12b3901a8-FRA
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: max-age=14400, public
CF-Cache-Status: HIT
Server: cloudflare`,

  request: `GET /api/v1/telemetry/events HTTP/1.1
Host: api.sudodeck.internal
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9,az;q=0.8
Accept-Encoding: gzip, deflate, br
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDN...
Cookie: session_token=soc_usr_98a72f10b2; preferences=dark_mode%3Dtrue
Sec-Ch-Ua: "Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin`
};

// ── Setup Headers Analyzer ──────────────────────────────────────
function setupHeadersAnalyzer() {
  const uaInput = document.getElementById('ua-input');
  const btnAnalyzeUa = document.getElementById('btn-analyze-ua');
  const btnMyUa = document.getElementById('btn-my-ua');
  const btnClearUa = document.getElementById('btn-clear-ua');
  const btnCopyUaJson = document.getElementById('btn-copy-ua-json');
  const uaChips = document.querySelectorAll('.ua-chip');

  const headersInput = document.getElementById('raw-headers-input');
  const selectPreset = document.getElementById('select-headers-preset');
  const btnAnalyzeHeaders = document.getElementById('btn-analyze-headers');
  const btnClearHeaders = document.getElementById('btn-clear-headers');
  const btnCopyHeadersJson = document.getElementById('btn-copy-headers-json');
  const btnCopyTableTsv = document.getElementById('btn-copy-table-tsv');
  const searchInput = document.getElementById('input-search-headers');
  const filterButtons = document.querySelectorAll('.header-filter-btn');

  // UA Input events
  if (uaInput) {
    uaInput.addEventListener('input', () => {
      state.currentUA = uaInput.value.trim();
      updateUaStats();
    });
  }

  if (btnAnalyzeUa) {
    btnAnalyzeUa.addEventListener('click', () => {
      runUaAnalysis();
    });
  }

  if (btnMyUa) {
    btnMyUa.addEventListener('click', () => {
      if (uaInput) {
        uaInput.value = navigator.userAgent;
        state.currentUA = navigator.userAgent;
        updateUaStats();
        runUaAnalysis();
        showToast('Current browser User-Agent loaded', 'info');
      }
    });
  }

  if (btnClearUa) {
    btnClearUa.addEventListener('click', () => {
      if (uaInput) uaInput.value = '';
      state.currentUA = '';
      state.parsedUA = null;
      updateUaStats();
      resetUaCards();
      showToast('User-Agent input cleared', 'info');
    });
  }

  if (btnCopyUaJson) {
    btnCopyUaJson.addEventListener('click', () => {
      if (!state.parsedUA) {
        showToast('Please analyze a User-Agent first', 'warning');
        return;
      }
      copyToClipboard(JSON.stringify(state.parsedUA, null, 2), btnCopyUaJson);
    });
  }

  uaChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const key = chip.dataset.ua;
      loadSampleUA(key);
    });
  });

  // Headers Input events
  if (headersInput) {
    headersInput.addEventListener('input', () => {
      state.rawHeaders = headersInput.value;
      updateHeadersStats();
    });
  }

  if (selectPreset) {
    selectPreset.addEventListener('change', () => {
      loadHeadersPreset(selectPreset.value);
    });
  }

  if (btnAnalyzeHeaders) {
    btnAnalyzeHeaders.addEventListener('click', () => {
      runHeadersAnalysis();
    });
  }

  if (btnClearHeaders) {
    btnClearHeaders.addEventListener('click', () => {
      if (headersInput) headersInput.value = '';
      state.rawHeaders = '';
      state.parsedHeaders = [];
      updateHeadersStats();
      resetHeadersResults();
      showToast('Headers input cleared', 'info');
    });
  }

  if (btnCopyHeadersJson) {
    btnCopyHeadersJson.addEventListener('click', () => {
      if (!state.parsedHeaders || state.parsedHeaders.length === 0) {
        showToast('No HTTP headers to copy', 'warning');
        return;
      }
      const obj = {};
      state.parsedHeaders.forEach(h => {
        if (obj[h.key]) {
          obj[h.key] = Array.isArray(obj[h.key]) ? [...obj[h.key], h.value] : [obj[h.key], h.value];
        } else {
          obj[h.key] = h.value;
        }
      });
      copyToClipboard(JSON.stringify(obj, null, 2), btnCopyHeadersJson);
    });
  }

  if (btnCopyTableTsv) {
    btnCopyTableTsv.addEventListener('click', () => {
      if (!state.parsedHeaders || state.parsedHeaders.length === 0) {
        showToast('No table data to copy', 'warning');
        return;
      }
      const tsvLines = ['Header\tCategory\tValue'];
      state.parsedHeaders.forEach(h => {
        tsvLines.push(`${h.key}\t${h.category}\t${h.value}`);
      });
      copyToClipboard(tsvLines.join('\n'), btnCopyTableTsv);
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      state.headersSearchTerm = searchInput.value.trim().toLowerCase();
      renderHeadersTable();
    });
  }

  filterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      filterButtons.forEach(b => {
        b.classList.remove('active', 'bg-indigo-600/20', 'text-indigo-300', 'border-indigo-500/40');
        b.classList.add('bg-surface-900', 'text-slate-400', 'border-slate-800');
      });
      btn.classList.add('active', 'bg-indigo-600/20', 'text-indigo-300', 'border-indigo-500/40');
      btn.classList.remove('bg-surface-900', 'text-slate-400', 'border-slate-800');

      state.activeHeaderFilter = btn.dataset.filter || 'all';
      renderHeadersTable();
    });
  });
}

// ── Sample Loaders ──────────────────────────────────────────────
function loadSampleUA(key, silent = false) {
  const ua = SAMPLE_UAS[key];
  if (!ua) return;

  const uaInput = document.getElementById('ua-input');
  if (uaInput) {
    uaInput.value = ua;
    state.currentUA = ua;
    updateUaStats();
    runUaAnalysis(silent);
  }
}

function loadHeadersPreset(key, silent = false) {
  const headers = SAMPLE_HEADERS[key];
  if (!headers) return;

  const headersInput = document.getElementById('raw-headers-input');
  if (headersInput) {
    headersInput.value = headers;
    state.rawHeaders = headers;
    updateHeadersStats();
    runHeadersAnalysis(silent);
  }
}

function updateUaStats() {
  const counter = document.getElementById('ua-length-counter');
  if (counter) {
    counter.textContent = `${(state.currentUA || '').length} characters`;
  }
}

function updateHeadersStats() {
  const text = state.rawHeaders || '';
  const lines = text ? text.split(/\r?\n/).filter(l => l.trim().length > 0) : [];
  
  const statLines = document.getElementById('headers-stat-lines');
  const statCount = document.getElementById('headers-stat-count');
  if (statLines) statLines.textContent = `${lines.length} lines`;
  if (statCount) statCount.textContent = `${lines.length} headers`;
}

// ── User-Agent Deep Parser Engine ───────────────────────────────
function runUaAnalysis(silent = false) {
  const ua = (state.currentUA || document.getElementById('ua-input')?.value || '').trim();
  if (!ua) {
    if (!silent) {
      showToast('Please enter a User-Agent string', 'warning');
    }
    return;
  }

  state.currentUA = ua;
  const parsed = parseUserAgent(ua);
  state.parsedUA = parsed;

  renderUaResults(parsed);
  if (!silent) {
    showToast('User-Agent successfully analyzed', 'success');
  }
}

function parseUserAgent(ua) {
  const result = {
    raw: ua,
    browser: { name: 'Unknown', version: '—', family: 'Unknown', isBot: false },
    os: { name: 'Unknown', version: '—', arch: 'Unknown' },
    device: { type: 'Desktop', brand: 'Generic', formFactor: 'Stationary' },
    engine: { name: 'Unknown', version: '—' },
    threat: null,
    tokens: []
  };

  // Extract parentheses tokens
  const parenMatches = ua.match(/\(([^)]+)\)/g) || [];
  parenMatches.forEach(p => {
    const cleaned = p.replace(/^\(|\)$/g, '');
    cleaned.split(';').forEach(token => {
      const trimmed = token.trim();
      if (trimmed) result.tokens.push(trimmed);
    });
  });

  // Extract slash product tokens
  const productMatches = ua.match(/([a-zA-Z0-9_\-]+)\/([0-9a-zA-Z\.\#\-_]+)/g) || [];
  productMatches.forEach(prod => {
    if (!result.tokens.includes(prod)) result.tokens.push(prod);
  });

  // 1. Check for Security Tools & Pentest Scanners
  if (/sqlmap/i.test(ua)) {
    const v = (ua.match(/sqlmap\/([0-9\.\#\w\-]+)/i) || [])[1] || 'Unknown';
    result.browser = { name: 'sqlmap (Exploitation Tool)', version: v, family: 'Security Scanner', isBot: true };
    result.device = { type: 'Security Tool', brand: 'Automated CLI', formFactor: 'Virtual Engine' };
    result.engine = { name: 'Python urllib / Socket', version: v };
    result.threat = {
      level: 'high',
      title: 'Malicious Pentest Tool Detected: sqlmap',
      desc: 'Automated SQL Injection and database takeover tool. In SIEM logs, this User-Agent should be flagged as an active attack attempt.'
    };
  } else if (/nikto/i.test(ua)) {
    const v = (ua.match(/Nikto\/([0-9\.]+)/i) || [])[1] || '2.5';
    result.browser = { name: 'Nikto Web Scanner', version: v, family: 'Vulnerability Scanner', isBot: true };
    result.device = { type: 'Security Tool', brand: 'CLI Scanner', formFactor: 'Virtual Engine' };
    result.engine = { name: 'Perl libwww', version: v };
    result.threat = {
      level: 'high',
      title: 'Vulnerability Scanner Detected: Nikto',
      desc: 'Automated web server scanner searching for known misconfigurations and security vulnerabilities.'
    };
  } else if (/gobuster/i.test(ua)) {
    const v = (ua.match(/gobuster\/([0-9\.]+)/i) || [])[1] || '3.x';
    result.browser = { name: 'Gobuster', version: v, family: 'Brute-force Scanner', isBot: true };
    result.device = { type: 'Security Tool', brand: 'CLI Tool', formFactor: 'Virtual Engine' };
    result.engine = { name: 'Go net/http', version: v };
    result.threat = {
      level: 'medium',
      title: 'Directory Brute-Forcer Detected: Gobuster',
      desc: 'High-speed Go-based brute-forcing tool used to discover hidden files, directories, and DNS subdomains.'
    };
  } else if (/nmap/i.test(ua)) {
    result.browser = { name: 'Nmap Scripting Engine (NSE)', version: '7.x', family: 'Network Recon', isBot: true };
    result.device = { type: 'Security Tool', brand: 'Nmap Project', formFactor: 'Virtual Engine' };
    result.engine = { name: 'Lua Socket', version: '7.x' };
    result.threat = {
      level: 'high',
      title: 'Network Reconnaissance Tool: Nmap NSE',
      desc: 'HTTP request initiated by Nmap Scripting Engine during automated network port and service scanning.'
    };
  } else if (/curl\//i.test(ua)) {
    const v = (ua.match(/curl\/([0-9\.]+)/i) || [])[1] || 'Unknown';
    result.browser = { name: 'curl', version: v, family: 'CLI HTTP Client', isBot: true };
    result.device = { type: 'CLI Client', brand: 'Command Line', formFactor: 'Automated Script' };
    result.engine = { name: 'libcurl', version: v };
    result.threat = {
      level: 'low',
      title: 'Command-Line Tool: curl',
      desc: 'Automated script or manual terminal HTTP request executed via curl.'
    };
  } else if (/Wget\//i.test(ua)) {
    const v = (ua.match(/Wget\/([0-9\.]+)/i) || [])[1] || 'Unknown';
    result.browser = { name: 'GNU Wget', version: v, family: 'CLI HTTP Client', isBot: true };
    result.device = { type: 'CLI Client', brand: 'GNU Project', formFactor: 'Automated Script' };
    result.engine = { name: 'Wget Engine', version: v };
    result.threat = {
      level: 'low',
      title: 'File Downloader: Wget',
      desc: 'Automated file retrieval or scraping utility executed via GNU Wget.'
    };
  } else if (/python-requests/i.test(ua)) {
    const v = (ua.match(/python-requests\/([0-9\.]+)/i) || [])[1] || 'Unknown';
    result.browser = { name: 'Python requests', version: v, family: 'Scripting Library', isBot: true };
    result.device = { type: 'Automated Bot', brand: 'Python Environment', formFactor: 'Script / Bot' };
    result.engine = { name: 'urllib3 / Python', version: v };
    result.threat = {
      level: 'medium',
      title: 'Python Script Request: python-requests',
      desc: 'Programmatic HTTP request sent by a Python script, not a standard web browser.'
    };
  } else if (/googlebot/i.test(ua)) {
    const v = (ua.match(/Googlebot\/([0-9\.]+)/i) || [])[1] || '2.1';
    result.browser = { name: 'Googlebot Crawler', version: v, family: 'Search Bot', isBot: true };
    result.device = { type: 'Search Crawler', brand: 'Google LLC', formFactor: 'Datacenter Bot' };
    result.engine = { name: 'Google WebKit', version: v };
    result.threat = {
      level: 'info',
      title: 'Search Crawler: Googlebot',
      desc: 'Official Google web crawler for search indexing. Verify IP origin against Google AS15169 to prevent spoofing.'
    };
  } else {
    // Standard User Browsers
    if (/Edg(?:e|A|iOS)?\/([0-9\.]+)/i.test(ua)) {
      const v = (ua.match(/Edg(?:e|A|iOS)?\/([0-9\.]+)/i) || [])[1];
      result.browser = { name: 'Microsoft Edge', version: v, family: 'Chromium / Blink', isBot: false };
      result.engine = { name: 'Blink', version: v };
    } else if (/(?:OPR|Opera)\/([0-9\.]+)/i.test(ua)) {
      const v = (ua.match(/(?:OPR|Opera)\/([0-9\.]+)/i) || [])[1];
      result.browser = { name: 'Opera', version: v, family: 'Chromium / Blink', isBot: false };
      result.engine = { name: 'Blink', version: v };
    } else if (/Vivaldi\/([0-9\.]+)/i.test(ua)) {
      const v = (ua.match(/Vivaldi\/([0-9\.]+)/i) || [])[1];
      result.browser = { name: 'Vivaldi', version: v, family: 'Chromium / Blink', isBot: false };
      result.engine = { name: 'Blink', version: v };
    } else if (/Brave/i.test(ua)) {
      result.browser = { name: 'Brave Browser', version: 'Brave Core', family: 'Chromium / Blink', isBot: false };
      result.engine = { name: 'Blink', version: 'Latest' };
    } else if (/SamsungBrowser\/([0-9\.]+)/i.test(ua)) {
      const v = (ua.match(/SamsungBrowser\/([0-9\.]+)/i) || [])[1];
      result.browser = { name: 'Samsung Internet', version: v, family: 'Chromium / Blink', isBot: false };
      result.engine = { name: 'Blink', version: v };
    } else if (/(?:Chrome|CriOS)\/([0-9\.]+)/i.test(ua)) {
      const v = (ua.match(/(?:Chrome|CriOS)\/([0-9\.]+)/i) || [])[1];
      result.browser = { name: 'Google Chrome', version: v, family: 'Chromium / Blink', isBot: false };
      result.engine = { name: 'Blink', version: v };
    } else if (/(?:Firefox|FxiOS)\/([0-9\.]+)/i.test(ua)) {
      const v = (ua.match(/(?:Firefox|FxiOS)\/([0-9\.]+)/i) || [])[1];
      result.browser = { name: 'Mozilla Firefox', version: v, family: 'Gecko', isBot: false };
      result.engine = { name: 'Gecko', version: v };
    } else if (/Version\/([0-9\.]+).*Safari/i.test(ua)) {
      const v = (ua.match(/Version\/([0-9\.]+)/i) || [])[1];
      result.browser = { name: 'Apple Safari', version: v, family: 'WebKit', isBot: false };
      result.engine = { name: 'WebKit', version: v };
    } else if (/MSIE ([0-9\.]+)/i.test(ua) || /Trident\/.*rv:([0-9\.]+)/i.test(ua)) {
      const v = (ua.match(/(?:MSIE |rv:)([0-9\.]+)/i) || [])[1];
      result.browser = { name: 'Internet Explorer', version: v, family: 'Trident', isBot: false };
      result.engine = { name: 'Trident', version: v };
    }
  }

  // 2. Detect Operating System (OS)
  if (/Windows NT 10\.0/i.test(ua)) {
    result.os = { name: 'Windows 11 / 10', version: 'NT 10.0', arch: /Win64|x64/i.test(ua) ? '64-bit (x64)' : '32-bit' };
    if (!result.threat) result.device = { type: 'Desktop PC', brand: 'Windows Workstation', formFactor: 'Desktop' };
  } else if (/Windows NT 6\.3/i.test(ua)) {
    result.os = { name: 'Windows 8.1', version: 'NT 6.3', arch: /Win64|x64/i.test(ua) ? '64-bit' : '32-bit' };
  } else if (/Windows NT 6\.1/i.test(ua)) {
    result.os = { name: 'Windows 7 (Legacy)', version: 'NT 6.1', arch: /Win64|x64/i.test(ua) ? '64-bit' : '32-bit' };
  } else if (/iPhone OS ([0-9_]+)/i.test(ua)) {
    const rawV = (ua.match(/iPhone OS ([0-9_]+)/i) || [])[1] || '';
    const v = rawV.replace(/_/g, '.');
    result.os = { name: 'iOS', version: v || 'Latest', arch: 'ARM64' };
    if (!result.threat) result.device = { type: 'Smartphone', brand: 'Apple iPhone', formFactor: 'Mobile Handheld' };
  } else if (/iPad; CPU OS ([0-9_]+)/i.test(ua)) {
    const rawV = (ua.match(/iPad; CPU OS ([0-9_]+)/i) || [])[1] || '';
    const v = rawV.replace(/_/g, '.');
    result.os = { name: 'iPadOS', version: v || 'Latest', arch: 'Apple Silicon' };
    if (!result.threat) result.device = { type: 'Tablet', brand: 'Apple iPad', formFactor: 'Tablet' };
  } else if (/Mac OS X ([0-9_]+)/i.test(ua)) {
    const rawV = (ua.match(/Mac OS X ([0-9_]+)/i) || [])[1] || '';
    const v = rawV.replace(/_/g, '.');
    let osName = 'macOS';
    if (v.startsWith('14')) osName = 'macOS Sonoma';
    else if (v.startsWith('13')) osName = 'macOS Ventura';
    else if (v.startsWith('12')) osName = 'macOS Monterey';
    else if (v.startsWith('11')) osName = 'macOS Big Sur';
    else if (v.startsWith('10.15')) osName = 'macOS Catalina';
    result.os = { name: osName, version: v, arch: /Intel/i.test(ua) ? 'Intel x86_64' : 'Apple Silicon / Universal' };
    if (!result.threat) result.device = { type: 'Desktop / Mac', brand: 'Apple Mac', formFactor: 'Desktop / Laptop' };
  } else if (/Android ([0-9\.]+)/i.test(ua)) {
    const v = (ua.match(/Android ([0-9\.]+)/i) || [])[1] || 'Latest';
    const model = (ua.match(/Android [^;]+; ([^;)]+)\)/i) || [])[1] || 'Generic Android';
    result.os = { name: 'Android OS', version: v, arch: 'ARM / AArch64' };
    const isMobile = /Mobile/i.test(ua);
    if (!result.threat) {
      result.device = {
        type: isMobile ? 'Smartphone' : 'Tablet',
        brand: model.trim(),
        formFactor: isMobile ? 'Mobile Handheld' : 'Tablet'
      };
    }
  } else if (/Linux/i.test(ua)) {
    let distro = 'Linux GNU';
    if (/Kali/i.test(ua)) distro = 'Kali Linux (Offensive Security)';
    else if (/Ubuntu/i.test(ua)) distro = 'Ubuntu Linux';
    else if (/Debian/i.test(ua)) distro = 'Debian Linux';
    else if (/Arch/i.test(ua)) distro = 'Arch Linux';
    result.os = { name: distro, version: 'Kernel Linux', arch: /x86_64|amd64/i.test(ua) ? 'x86_64 (64-bit)' : 'x86' };
    if (!result.threat) result.device = { type: 'Workstation / Server', brand: 'Linux Host', formFactor: 'Desktop / Server' };
  }

  return result;
}

function renderUaResults(data) {
  // Update Spec Cards
  const elBrowserName = document.getElementById('ua-browser-name');
  const elBrowserVersion = document.getElementById('ua-browser-version');
  const elBrowserFamily = document.getElementById('ua-browser-family');

  const elOsName = document.getElementById('ua-os-name');
  const elOsVersion = document.getElementById('ua-os-version');
  const elOsArch = document.getElementById('ua-os-arch');

  const elDeviceType = document.getElementById('ua-device-type');
  const elDeviceForm = document.getElementById('ua-device-form');
  const elDeviceBrand = document.getElementById('ua-device-brand');

  const elEngineName = document.getElementById('ua-engine-name');
  const elEngineVersion = document.getElementById('ua-engine-version');
  const elSecStatus = document.getElementById('ua-security-status');

  if (elBrowserName) elBrowserName.textContent = data.browser.name;
  if (elBrowserVersion) elBrowserVersion.textContent = `Versiya: ${data.browser.version}`;
  if (elBrowserFamily) elBrowserFamily.textContent = data.browser.family;

  if (elOsName) elOsName.textContent = data.os.name;
  if (elOsVersion) elOsVersion.textContent = `Version: ${data.os.version}`;
  if (elOsArch) elOsArch.textContent = data.os.arch;

  if (elDeviceType) elDeviceType.textContent = data.device.type;
  if (elDeviceForm) elDeviceForm.textContent = `Form: ${data.device.formFactor}`;
  if (elDeviceBrand) elDeviceBrand.textContent = data.device.brand;

  if (elEngineName) elEngineName.textContent = data.engine.name;
  if (elEngineVersion) elEngineVersion.textContent = `Version: ${data.engine.version}`;
  if (elSecStatus) {
    if (data.threat) {
      elSecStatus.innerHTML = `<span class="text-rose-400 font-bold">⚠️ ${data.threat.title.split(':')[0]}</span>`;
    } else {
      elSecStatus.innerHTML = `<span class="text-emerald-400 font-bold">✓ Standard User Browser</span>`;
    }
  }

  // Threat Banner
  const banner = document.getElementById('ua-threat-alert');
  if (banner) {
    if (data.threat) {
      banner.classList.remove('hidden');
      const colors = {
        high: 'bg-rose-500/10 border-rose-500/40 text-rose-300',
        medium: 'bg-amber-500/10 border-amber-500/40 text-amber-300',
        low: 'bg-indigo-500/10 border-indigo-500/40 text-indigo-300',
        info: 'bg-blue-500/10 border-blue-500/40 text-blue-300'
      };
      banner.className = `p-4 rounded-xl border transition-all animate-fade-in ${colors[data.threat.level] || colors.medium}`;
      banner.innerHTML = `
        <div class="flex items-start gap-3">
          <div class="mt-0.5 font-bold text-lg">⚠️</div>
          <div class="space-y-1">
            <h4 class="text-sm font-bold text-white">${escapeHtml(data.threat.title)}</h4>
            <p class="text-xs opacity-90">${escapeHtml(data.threat.desc)}</p>
          </div>
        </div>
      `;
    } else {
      banner.classList.add('hidden');
    }
  }

  // Tokens List
  const tokensContainer = document.getElementById('ua-tokens-list');
  if (tokensContainer) {
    if (data.tokens.length === 0) {
      tokensContainer.innerHTML = '<span class="text-xs text-slate-500">No tokens detected.</span>';
    } else {
      tokensContainer.innerHTML = data.tokens.map(t => `
        <span class="px-2 py-0.5 rounded text-[11px] font-mono bg-surface-800 text-slate-300 border border-slate-700/60 hover:border-indigo-500/40 transition-colors">
          ${escapeHtml(t)}
        </span>
      `).join('');
    }
  }

  if (window.lucide) lucide.createIcons();
}

function resetUaCards() {
  const defaults = {
    'ua-browser-name': 'Awaiting Input...',
    'ua-browser-version': 'Version: —',
    'ua-browser-family': '—',
    'ua-os-name': 'Awaiting Input...',
    'ua-os-version': 'Version: —',
    'ua-os-arch': '—',
    'ua-device-type': 'Awaiting Input...',
    'ua-device-form': 'Form: —',
    'ua-device-brand': '—',
    'ua-engine-name': 'Awaiting Input...',
    'ua-engine-version': 'Version: —',
    'ua-security-status': '—'
  };

  Object.keys(defaults).forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = defaults[id];
  });

  const banner = document.getElementById('ua-threat-alert');
  if (banner) banner.classList.add('hidden');

  const tokens = document.getElementById('ua-tokens-list');
  if (tokens) tokens.innerHTML = '<span class="text-xs text-slate-500 font-mono">No User-Agent provided.</span>';
}

// ── HTTP Header Inspector Engine ────────────────────────────────
function runHeadersAnalysis(silent = false) {
  const text = (state.rawHeaders || document.getElementById('raw-headers-input')?.value || '').trim();
  if (!text) {
    if (!silent) {
      showToast('Please enter raw HTTP headers', 'warning');
    }
    return;
  }

  state.rawHeaders = text;
  const parsed = parseHttpHeaders(text);
  state.parsedHeaders = parsed;

  const audit = auditSecurityHeaders(parsed);
  state.securityAudit = audit;

  renderSecurityAudit(audit);
  renderHeadersTable();

  if (!silent) {
    showToast(`Successfully analyzed ${parsed.length} HTTP headers`, 'success');
  }
}

function parseHttpHeaders(raw) {
  const lines = raw.split(/\r?\n/);
  const headers = [];

  lines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed) return;

    // Handle HTTP status lines like "HTTP/1.1 200 OK" or "HTTP/2 200"
    if (/^HTTP\/[1-3]/i.test(trimmed)) {
      headers.push({
        key: ':status',
        value: trimmed,
        category: 'transport',
        isSecurity: false,
        isLeak: false
      });
      return;
    }

    // Handle HTTP request lines like "GET /index.html HTTP/1.1"
    if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+/i.test(trimmed)) {
      headers.push({
        key: ':method_path',
        value: trimmed,
        category: 'transport',
        isSecurity: false,
        isLeak: false
      });
      return;
    }

    const colonIdx = trimmed.indexOf(':');
    if (colonIdx > 0) {
      const key = trimmed.slice(0, colonIdx).trim();
      const value = trimmed.slice(colonIdx + 1).trim();
      const lowerKey = key.toLowerCase();

      let category = 'general';
      let isSecurity = false;
      let isLeak = false;

      // Security category
      if (
        lowerKey.includes('content-security-policy') ||
        lowerKey === 'strict-transport-security' ||
        lowerKey === 'x-frame-options' ||
        lowerKey === 'x-content-type-options' ||
        lowerKey === 'referrer-policy' ||
        lowerKey === 'permissions-policy' ||
        lowerKey === 'feature-policy' ||
        lowerKey.startsWith('cross-origin-') ||
        lowerKey === 'x-xss-protection' ||
        lowerKey === 'x-permitted-cross-domain-policies'
      ) {
        category = 'security';
        isSecurity = true;
      }
      // Cache category
      else if (
        lowerKey === 'cache-control' ||
        lowerKey === 'etag' ||
        lowerKey === 'expires' ||
        lowerKey === 'last-modified' ||
        lowerKey === 'pragma' ||
        lowerKey === 'vary' ||
        lowerKey === 'age' ||
        lowerKey.includes('cf-cache')
      ) {
        category = 'cache';
      }
      // Transport & Connection
      else if (
        lowerKey === 'connection' ||
        lowerKey === 'keep-alive' ||
        lowerKey === 'transfer-encoding' ||
        lowerKey === 'content-encoding' ||
        lowerKey === 'content-length' ||
        lowerKey === 'host' ||
        lowerKey === 'upgrade' ||
        lowerKey === 'alt-svc' ||
        lowerKey === 'cf-ray'
      ) {
        category = 'transport';
      }
      // Auth & Cookies
      else if (
        lowerKey === 'authorization' ||
        lowerKey === 'cookie' ||
        lowerKey === 'set-cookie' ||
        lowerKey === 'www-authenticate' ||
        lowerKey === 'proxy-authenticate' ||
        lowerKey === 'x-api-key'
      ) {
        category = 'auth';
      }
      // Information Leaks
      else if (
        lowerKey === 'server' ||
        lowerKey === 'x-powered-by' ||
        lowerKey === 'x-aspnet-version' ||
        lowerKey === 'x-generator' ||
        lowerKey === 'x-runtime' ||
        lowerKey === 'x-served-by'
      ) {
        category = 'leak';
        // Flag as leak if it reveals specific software version
        if (value.length > 0 && !/^cloudflare$/i.test(value)) {
          isLeak = true;
        }
      }

      headers.push({
        key,
        value,
        category,
        isSecurity,
        isLeak
      });
    }
  });

  return headers;
}

// ── Security Headers Compliance Check & OWASP Audit ─────────────
function auditSecurityHeaders(headers) {
  const headerMap = {};
  headers.forEach(h => {
    headerMap[h.key.toLowerCase()] = h.value;
  });

  const checklist = [
    {
      id: 'csp',
      name: 'Content-Security-Policy (CSP)',
      weight: 25,
      doc: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
      evaluate: () => {
        const val = headerMap['content-security-policy'];
        if (!val) {
          return {
            status: 'missing',
            score: 0,
            value: 'Not Configured / Missing',
            tip: 'Critical: Define "Content-Security-Policy: default-src \'self\'" to mitigate XSS and code injection attacks.'
          };
        }
        if (val.includes("'unsafe-inline'") || val.includes("'unsafe-eval'")) {
          return {
            status: 'warning',
            score: 15,
            value: val,
            tip: "Warning: CSP is present, but 'unsafe-inline' or 'unsafe-eval' directives increase XSS risk."
          };
        }
        return {
          status: 'pass',
          score: 25,
          value: val,
          tip: 'Excellent: Robust Content-Security-Policy configured.'
        };
      }
    },
    {
      id: 'hsts',
      name: 'Strict-Transport-Security (HSTS)',
      weight: 20,
      doc: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
      evaluate: () => {
        const val = headerMap['strict-transport-security'];
        if (!val) {
          return {
            status: 'missing',
            score: 0,
            value: 'Not Configured / Missing',
            tip: 'Critical: Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to prevent SSL stripping and MitM attacks.'
          };
        }
        const maxAgeMatch = val.match(/max-age=(\d+)/i);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
        if (maxAge < 15552000) {
          return {
            status: 'warning',
            score: 12,
            value: val,
            tip: 'Warning: HSTS max-age duration is too short (recommended: at least 31536000 seconds / 1 year).'
          };
        }
        return {
          status: 'pass',
          score: 20,
          value: val,
          tip: 'Excellent: HTTPS connection enforcement active across domains.'
        };
      }
    },
    {
      id: 'xfo',
      name: 'X-Frame-Options',
      weight: 15,
      doc: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
      evaluate: () => {
        const val = headerMap['x-frame-options'];
        if (!val) {
          return {
            status: 'missing',
            score: 0,
            value: 'Not Configured / Missing',
            tip: 'Critical: Set "X-Frame-Options: DENY" or "SAMEORIGIN" to protect against clickjacking and UI redressing.'
          };
        }
        const upper = val.toUpperCase();
        if (upper === 'DENY' || upper === 'SAMEORIGIN') {
          return {
            status: 'pass',
            score: 15,
            value: val,
            tip: 'Excellent: Framing restricted, page protected from clickjacking.'
          };
        }
        return {
          status: 'warning',
          score: 8,
          value: val,
          tip: 'Warning: Non-standard or deprecated value detected for X-Frame-Options.'
        };
      }
    },
    {
      id: 'xcto',
      name: 'X-Content-Type-Options',
      weight: 10,
      doc: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
      evaluate: () => {
        const val = headerMap['x-content-type-options'];
        if (!val) {
          return {
            status: 'missing',
            score: 0,
            value: 'Not Configured / Missing',
            tip: 'Critical: Set "X-Content-Type-Options: nosniff" to prevent MIME-sniffing exploits.'
          };
        }
        if (val.toLowerCase().includes('nosniff')) {
          return {
            status: 'pass',
            score: 10,
            value: val,
            tip: 'Excellent: Browser MIME sniffing strictly prohibited.'
          };
        }
        return {
          status: 'warning',
          score: 5,
          value: val,
          tip: 'Warning: The value "nosniff" is strictly required.'
        };
      }
    },
    {
      id: 'rp',
      name: 'Referrer-Policy',
      weight: 10,
      doc: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
      evaluate: () => {
        const val = headerMap['referrer-policy'];
        if (!val) {
          return {
            status: 'missing',
            score: 0,
            value: 'Not Configured / Missing',
            tip: 'Recommended: Use "Referrer-Policy: strict-origin-when-cross-origin" to protect sensitive URL tokens and path parameters.'
          };
        }
        return {
          status: 'pass',
          score: 10,
          value: val,
          tip: 'Excellent: Referrer disclosure restricted across cross-origin requests.'
        };
      }
    },
    {
      id: 'pp',
      name: 'Permissions-Policy',
      weight: 10,
      doc: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
      evaluate: () => {
        const val = headerMap['permissions-policy'] || headerMap['feature-policy'];
        if (!val) {
          return {
            status: 'missing',
            score: 0,
            value: 'Not Configured / Missing',
            tip: 'Recommended: Configure Permissions-Policy to restrict browser features like camera, microphone, and geolocation.'
          };
        }
        return {
          status: 'pass',
          score: 10,
          value: val,
          tip: 'Excellent: Device APIs and sensitive features regulated by policy.'
        };
      }
    },
    {
      id: 'coop',
      name: 'Cross-Origin-Opener-Policy (COOP)',
      weight: 10,
      doc: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
      evaluate: () => {
        const val = headerMap['cross-origin-opener-policy'];
        if (!val) {
          return {
            status: 'missing',
            score: 0,
            value: 'Not Configured / Missing',
            tip: 'Recommended: Set "Cross-Origin-Opener-Policy: same-origin" to isolate window browsing context against Spectre leaks.'
          };
        }
        return {
          status: 'pass',
          score: 10,
          value: val,
          tip: 'Excellent: Browsing context isolated from cross-origin manipulation.'
        };
      }
    },
    {
      id: 'server_leak',
      name: 'Server & X-Powered-By (Information Disclosure)',
      weight: 10,
      doc: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
      evaluate: () => {
        const s = headerMap['server'];
        const p = headerMap['x-powered-by'];
        const a = headerMap['x-aspnet-version'];

        const leaked = [];
        if (s && !/^cloudflare$/i.test(s) && !/^nginx$/i.test(s)) leaked.push(`Server: ${s}`);
        if (p) leaked.push(`X-Powered-By: ${p}`);
        if (a) leaked.push(`X-AspNet-Version: ${a}`);

        if (leaked.length > 0) {
          return {
            status: 'danger',
            score: -10, // Penalty
            value: leaked.join(' | '),
            tip: 'Warning: Backend software and versions exposed! Attackers can target version-specific CVE exploits.'
          };
        }
        return {
          status: 'pass',
          score: 10,
          value: s ? `Masked (${s})` : 'Omitted (Hidden)',
          tip: 'Excellent: Server fingerprinting information suppressed.'
        };
      }
    }
  ];

  let totalScore = 0;
  let passedCount = 0;
  let warningCount = 0;
  let missingCount = 0;

  const results = checklist.map(item => {
    const res = item.evaluate();
    totalScore += res.score;
    if (res.status === 'pass') passedCount++;
    else if (res.status === 'warning') warningCount++;
    else missingCount++;

    return {
      ...item,
      ...res
    };
  });

  const finalScore = Math.max(0, Math.min(100, totalScore));

  let grade = 'F';
  let gradeColor = 'rose';
  let title = 'Critical Security Gaps';
  let desc = 'Core security headers missing. The application is vulnerable to XSS, Clickjacking, and SSL stripping.';

  if (finalScore >= 90) {
    grade = 'A+';
    gradeColor = 'emerald';
    title = 'Optimal Security Posture (Grade A+)';
    desc = 'All critical HTTP security headers configured in compliance with OWASP recommendations.';
  } else if (finalScore >= 80) {
    grade = 'A';
    gradeColor = 'emerald';
    title = 'Good Security Posture (Grade A)';
    desc = 'Essential defense headers active with minor hardening opportunities.';
  } else if (finalScore >= 65) {
    grade = 'B';
    gradeColor = 'cyan';
    title = 'Moderate Security (Grade B)';
    desc = 'Key headers missing (e.g., CSP or comprehensive HSTS configuration required).';
  } else if (finalScore >= 50) {
    grade = 'C';
    gradeColor = 'amber';
    title = 'Limited Security Posture (Grade C)';
    desc = 'Critical defenses inactive. Potential exposure to clickjacking or MIME sniffing.';
  } else if (finalScore >= 35) {
    grade = 'D';
    gradeColor = 'orange';
    title = 'Weak Security Posture (Grade D)';
    desc = 'The vast majority of recommended security headers are unconfigured.';
  }

  return {
    score: finalScore,
    grade,
    gradeColor,
    title,
    desc,
    passedCount,
    warningCount,
    missingCount,
    checklist: results
  };
}

function renderSecurityAudit(audit) {
  // Update Grade Circle
  const elGradeCircle = document.getElementById('sec-grade-circle');
  const elGradeLetter = document.getElementById('sec-grade-letter');
  const elScoreBadge = document.getElementById('sec-posture-badge');
  const elScoreTitle = document.getElementById('sec-posture-title');
  const elScoreDesc = document.getElementById('sec-posture-desc');
  const elScoreText = document.getElementById('sec-score-text');
  const elScoreBar = document.getElementById('sec-score-bar');

  const elPassed = document.getElementById('sec-count-passed');
  const elWarnings = document.getElementById('sec-count-warnings');
  const elMissing = document.getElementById('sec-count-missing');

  if (elGradeLetter) elGradeLetter.textContent = audit.grade;
  if (elScoreBadge) elScoreBadge.textContent = `${audit.score} / 100`;
  if (elScoreTitle) elScoreTitle.textContent = audit.title;
  if (elScoreDesc) elScoreDesc.textContent = audit.desc;
  if (elScoreText) elScoreText.textContent = `${audit.score}%`;
  if (elScoreBar) {
    elScoreBar.style.width = `${audit.score}%`;
    if (audit.score >= 80) {
      elScoreBar.className = 'bg-gradient-to-r from-emerald-500 to-teal-400 h-2 rounded-full transition-all duration-500';
    } else if (audit.score >= 50) {
      elScoreBar.className = 'bg-gradient-to-r from-amber-500 to-yellow-400 h-2 rounded-full transition-all duration-500';
    } else {
      elScoreBar.className = 'bg-gradient-to-r from-rose-500 to-red-400 h-2 rounded-full transition-all duration-500';
    }
  }

  if (elGradeCircle) {
    const colors = {
      emerald: 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400 shadow-emerald-500/10',
      cyan: 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400 shadow-cyan-500/10',
      amber: 'bg-amber-500/10 border-amber-500/40 text-amber-400 shadow-amber-500/10',
      orange: 'bg-orange-500/10 border-orange-500/40 text-orange-400 shadow-orange-500/10',
      rose: 'bg-rose-500/10 border-rose-500/40 text-rose-400 shadow-rose-500/10'
    };
    elGradeCircle.className = `w-16 h-16 rounded-2xl flex flex-col items-center justify-center font-extrabold text-2xl border-2 transition-all shadow-lg ${colors[audit.gradeColor] || colors.rose}`;
  }

  if (elPassed) elPassed.textContent = audit.passedCount;
  if (elWarnings) elWarnings.textContent = audit.warningCount;
  if (elMissing) elMissing.textContent = audit.missingCount;

  // Update Live Indicator Badges
  const badgeTotal = document.getElementById('badge-total-headers');
  const badgeSec = document.getElementById('badge-sec-headers');
  const badgeLeak = document.getElementById('badge-leak-headers');

  const total = state.parsedHeaders.length;
  const sec = state.parsedHeaders.filter(h => h.isSecurity).length;
  const leak = state.parsedHeaders.filter(h => h.isLeak).length;

  if (badgeTotal) badgeTotal.textContent = total;
  if (badgeSec) badgeSec.textContent = sec;
  if (badgeLeak) badgeLeak.textContent = leak;

  // Render Detailed Checklist
  const checklistContainer = document.getElementById('sec-headers-checklist');
  if (checklistContainer) {
    checklistContainer.innerHTML = audit.checklist.map(item => {
      let badgeHtml = '';
      let borderClass = 'border-slate-800';

      if (item.status === 'pass') {
        badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">✓ Configured</span>`;
        borderClass = 'border-emerald-500/20 bg-emerald-500/5';
      } else if (item.status === 'warning') {
        badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1">⚠️ Warning</span>`;
        borderClass = 'border-amber-500/20 bg-amber-500/5';
      } else if (item.status === 'danger') {
        badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">🚨 Info Leak</span>`;
        borderClass = 'border-rose-500/30 bg-rose-500/5';
      } else {
        badgeHtml = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 flex items-center gap-1">✗ Missing</span>`;
        borderClass = 'border-slate-800/80 bg-surface-900/60';
      }

      return `
        <div class="p-3 rounded-xl border ${borderClass} space-y-1.5 transition-all hover:border-slate-700">
          <div class="flex items-center justify-between gap-2 flex-wrap">
            <a href="${item.doc}" target="_blank" rel="noopener noreferrer" class="text-xs font-bold text-white hover:text-indigo-400 transition-colors flex items-center gap-1">
              <span>${escapeHtml(item.name)}</span>
              <i data-lucide="external-link" class="w-3 h-3 text-slate-500"></i>
            </a>
            <div>${badgeHtml}</div>
          </div>
          <div class="text-[11px] font-mono text-slate-300 break-all bg-surface-950/60 px-2.5 py-1 rounded border border-slate-800/80">
            ${escapeHtml(item.value)}
          </div>
          <p class="text-[11px] text-slate-400 leading-tight">
            ${escapeHtml(item.tip)}
          </p>
        </div>
      `;
    }).join('');
  }

  if (window.lucide) lucide.createIcons();
}

function renderHeadersTable() {
  const tbody = document.getElementById('headers-table-body');
  const countBadge = document.getElementById('table-headers-count');
  if (!tbody) return;

  let headers = state.parsedHeaders || [];

  // Filter by category
  if (state.activeHeaderFilter && state.activeHeaderFilter !== 'all') {
    headers = headers.filter(h => h.category === state.activeHeaderFilter);
  }

  // Filter by search query
  if (state.headersSearchTerm) {
    const term = state.headersSearchTerm;
    headers = headers.filter(h => 
      h.key.toLowerCase().includes(term) || 
      h.value.toLowerCase().includes(term)
    );
  }

  if (countBadge) {
    countBadge.textContent = `${headers.length} headers`;
  }

  if (headers.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" class="p-6 text-center text-slate-500 font-sans">
          No HTTP headers found. Check your search or filter parameters.
        </td>
      </tr>
    `;
    return;
  }

  const categoryBadges = {
    security: '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">Security</span>',
    cache: '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">Caching</span>',
    transport: '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/15 text-blue-400 border border-blue-500/30">Transport</span>',
    auth: '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/15 text-purple-400 border border-purple-500/30">Auth / Cookie</span>',
    leak: '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">Info Leak</span>',
    general: '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">General</span>'
  };

  tbody.innerHTML = headers.map((h, index) => {
    const badge = categoryBadges[h.category] || categoryBadges.general;
    const isLeakRow = h.isLeak ? 'bg-rose-500/5' : '';

    return `
      <tr class="hover:bg-surface-800/60 transition-colors ${isLeakRow}">
        <td class="p-3 font-bold text-slate-200 break-all select-all">
          <div class="flex items-center gap-1.5">
            ${h.isSecurity ? '<i data-lucide="shield-check" class="w-3.5 h-3.5 text-emerald-400 shrink-0"></i>' : ''}
            ${h.isLeak ? '<i data-lucide="alert-triangle" class="w-3.5 h-3.5 text-rose-400 shrink-0"></i>' : ''}
            <span>${escapeHtml(h.key)}</span>
          </div>
        </td>
        <td class="p-3">${badge}</td>
        <td class="p-3 text-slate-300 break-all select-all font-mono text-[11px]">
          ${escapeHtml(h.value)}
        </td>
        <td class="p-3 text-right">
          <div class="flex items-center justify-end gap-1">
            <button
              type="button"
              class="p-1 rounded text-slate-400 hover:text-white hover:bg-surface-800 transition-colors"
              title="Copy value"
              onclick="copyToClipboard('${escapeHtml(h.value.replace(/'/g, "\\'"))}', this)"
            >
              <i data-lucide="copy" class="w-3.5 h-3.5"></i>
            </button>
            <button
              type="button"
              class="p-1 rounded text-slate-400 hover:text-indigo-400 hover:bg-surface-800 transition-colors"
              title="Copy Key: Value"
              onclick="copyToClipboard('${escapeHtml((h.key + ': ' + h.value).replace(/'/g, "\\'"))}', this)"
            >
              <i data-lucide="file-text" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  if (window.lucide) lucide.createIcons();
}

function resetHeadersResults() {
  const tbody = document.getElementById('headers-table-body');
  if (tbody) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" class="p-6 text-center text-slate-500 font-sans">
          No headers provided. Paste raw HTTP headers above or select one of the presets.
        </td>
      </tr>
    `;
  }

  const checklist = document.getElementById('sec-headers-checklist');
  if (checklist) checklist.innerHTML = '';

  const badgeTotal = document.getElementById('badge-total-headers');
  const badgeSec = document.getElementById('badge-sec-headers');
  const badgeLeak = document.getElementById('badge-leak-headers');
  if (badgeTotal) badgeTotal.textContent = '0';
  if (badgeSec) badgeSec.textContent = '0';
  if (badgeLeak) badgeLeak.textContent = '0';

  const elGradeLetter = document.getElementById('sec-grade-letter');
  if (elGradeLetter) elGradeLetter.textContent = '—';
  const elScoreBadge = document.getElementById('sec-posture-badge');
  if (elScoreBadge) elScoreBadge.textContent = '0 / 100';
  const elScoreBar = document.getElementById('sec-score-bar');
  if (elScoreBar) elScoreBar.style.width = '0%';
}

function copyToClipboard(text, btnElement) {
  if (!navigator.clipboard) {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showCopyFeedback(btnElement);
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    showCopyFeedback(btnElement);
  }).catch(() => {
    showToast('Failed to copy to clipboard', 'error');
  });
}

function showCopyFeedback(btn) {
  if (!btn) {
    showToast('Copied to clipboard!', 'success');
    return;
  }

  const originalHtml = btn.innerHTML;
  btn.innerHTML = `
    <span class="text-emerald-400 flex items-center gap-1 font-bold">
      <i data-lucide="check" class="w-3.5 h-3.5"></i>
      <span>Copied!</span>
    </span>
  `;
  btn.classList.add('!border-emerald-500/50');
  if (window.lucide) lucide.createIcons({ nodes: [btn] });

  setTimeout(() => {
    btn.innerHTML = originalHtml;
    btn.classList.remove('!border-emerald-500/50');
    if (window.lucide) lucide.createIcons({ nodes: [btn] });
  }, 1800);

  showToast('Copied to clipboard!', 'success');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const colors = {
    success: 'border-emerald-500/40 bg-surface-850 text-emerald-400',
    error: 'border-rose-500/40 bg-surface-850 text-rose-400',
    warning: 'border-amber-500/40 bg-surface-850 text-amber-400',
    info: 'border-indigo-500/40 bg-surface-850 text-indigo-300'
  };

  toast.className = `p-3 rounded-xl border shadow-xl flex items-center gap-2 text-xs font-semibold animate-fade-in ${colors[type] || colors.info}`;
  toast.innerHTML = `
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 2200);
}

function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(str || '').replace(/[&<>"']/g, m => map[m]);
}

function generateUuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}
