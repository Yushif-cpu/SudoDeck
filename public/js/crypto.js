// ═══════════════════════════════════════════════════════════════
//  ThreatIntel — Dedicated Crypto & Encoding Suite Frontend
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initCryptoSuite();
});

// ── Algorithm Definitions & Metadata ────────────────────────────
const CRYPTO_CATEGORIES = {
  analyzer: {
    label: 'Smart Analyzer & Identifier Suite',
    btnText: 'Run Deep Heuristic Analysis',
  },
  hashes: {
    label: 'Cryptographic Hashes (One-Way)',
    btnText: 'Generate Cryptographic Hash',
    algorithms: [
      { id: 'sha256', name: 'SHA-256 (256-bit)', family: 'SHA-2', bits: 256, default: true },
      { id: 'md5', name: 'MD5 (128-bit)', family: 'MD', bits: 128 },
      { id: 'sha1', name: 'SHA-1 (160-bit)', family: 'SHA-1', bits: 160 },
      { id: 'sha512', name: 'SHA-512 (512-bit)', family: 'SHA-2', bits: 512 },
      { id: 'sha224', name: 'SHA-224 (224-bit)', family: 'SHA-2', bits: 224 },
      { id: 'sha384', name: 'SHA-384 (384-bit)', family: 'SHA-2', bits: 384 },
      { id: 'sha512-256', name: 'SHA-512/256 (256-bit)', family: 'SHA-2', bits: 256 },
      { id: 'sha3-256', name: 'SHA3-256 (256-bit Keccak)', family: 'SHA-3', bits: 256 },
      { id: 'sha3-512', name: 'SHA3-512 (512-bit Keccak)', family: 'SHA-3', bits: 512 },
      { id: 'sha3-224', name: 'SHA3-224 (224-bit Keccak)', family: 'SHA-3', bits: 224 },
      { id: 'sha3-384', name: 'SHA3-384 (384-bit Keccak)', family: 'SHA-3', bits: 384 },
      { id: 'blake2b512', name: 'BLAKE2b (512-bit)', family: 'BLAKE2', bits: 512 },
      { id: 'blake2s256', name: 'BLAKE2s (256-bit)', family: 'BLAKE2', bits: 256 },
      { id: 'ripemd160', name: 'RIPEMD-160 (160-bit)', family: 'RIPEMD', bits: 160 },
      { id: 'md4', name: 'MD4 (128-bit RFC 1320)', family: 'MD', bits: 128 },
      { id: 'crc32', name: 'CRC32 (32-bit Checksum)', family: 'Checksum', bits: 32 },
    ],
  },
  encodings: {
    label: 'Encoders & Converters (Reversible)',
    btnText: 'Execute Encoding / Decoding',
    algorithms: [
      { id: 'base64', name: 'Base64 (Standard RFC 4648)', default: true },
      { id: 'base64url', name: 'Base64URL (URL and Filename Safe)' },
      { id: 'base16', name: 'Base16 / Hexadecimal' },
      { id: 'base32', name: 'Base32 (RFC 4648)' },
      { id: 'base85', name: 'Base85 / Ascii85 (Adobe/btoa)' },
      { id: 'url', name: 'URL Percent-Encoding' },
      { id: 'binary', name: 'Binary (8-bit 010101...)' },
      { id: 'octal', name: 'Octal (Base-8 Bytes)' },
      { id: 'decimal', name: 'Decimal (ASCII Byte Codes)' },
      { id: 'html', name: 'HTML Character Entities' },
    ],
  },
  ciphers: {
    label: 'Classical & Historical Ciphers',
    btnText: 'Transform Classical Cipher',
    algorithms: [
      { id: 'rot13', name: 'ROT13 (Caesar Shift 13)', default: true },
      { id: 'caesar', name: 'Caesar Cipher (Custom Shift)', hasOptions: true, optionType: 'shift' },
      { id: 'morse', name: 'International Morse Code' },
      { id: 'atbash', name: 'Atbash Cipher (A ↔ Z Reverse)' },
      { id: 'vigenere', name: 'Vigenère Cipher (Key-Based)', hasOptions: true, optionType: 'key' },
    ],
  },
  'hash-all': {
    label: 'Multi-Hash Inspector (Parallel Matrix)',
    btnText: 'Inspect All 16 Hashes in Parallel',
  },
};

// ── State ───────────────────────────────────────────────────────
const state = {
  activeCategory: 'analyzer',
  activeAlgorithm: 'sha256',
  mode: 'encode', // 'encode' or 'decode'
  options: {
    shift: 3,
    key: 'SECRET',
  },
  isProcessing: false,
};

// ── Toast Notifications ─────────────────────────────────────────
function showToast(message, type = 'info', duration = 3000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icons = {
    success: 'check-circle-2',
    error: 'alert-circle',
    warning: 'alert-triangle',
    info: 'info',
  };

  toast.innerHTML = `
    <i data-lucide="${icons[type] || 'info'}" class="w-5 h-5 flex-shrink-0"></i>
    <span class="text-sm font-medium flex-1">${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);
  try {
    lucide.createIcons({ nodes: [toast] });
  } catch (_) {}

  setTimeout(() => {
    toast.style.animation = 'slideOutRight 0.3s ease-out forwards';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Copy to Clipboard ───────────────────────────────────────────
window.copyToClipboard = function(text, btn) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const original = btn.innerHTML;
    btn.classList.add('copied');
    btn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i> <span class="text-emerald-300 font-bold">Copied</span>`;
    try {
      lucide.createIcons({ nodes: [btn] });
    } catch (_) {}
    showToast('Copied to clipboard', 'success', 2000);

    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = original;
      try {
        lucide.createIcons({ nodes: [btn] });
      } catch (_) {}
    }, 2000);
  }).catch(() => {
    showToast('Failed to copy', 'error');
  });
};

window.copyPrimaryOutput = function(btn) {
  const outputEl = document.getElementById('primary-output-textarea');
  if (!outputEl) return;
  window.copyToClipboard(outputEl.value, btn);
};

window.swapOutputToInput = function() {
  const outputEl = document.getElementById('primary-output-textarea');
  const inputEl = document.getElementById('crypto-input');
  if (!outputEl || !inputEl || !outputEl.value) return;
  inputEl.value = outputEl.value;
  updateInputStats();
  if (state.activeCategory === 'encodings' || state.activeCategory === 'ciphers') {
    setMode(state.mode === 'encode' ? 'decode' : 'encode');
  }
  showToast('Output swapped to input', 'info', 1500);
};

window.setInputValue = function(text) {
  const inputEl = document.getElementById('crypto-input');
  if (!inputEl) return;
  inputEl.value = text;
  updateInputStats();
  if (state.activeCategory === 'analyzer') {
    runSmartAnalysis(text, false);
  }
  showToast('Payload transferred to input', 'info', 1500);
};

function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(str || '').replace(/[&<>"']/g, (m) => map[m]);
}

// ── Main Initialization ─────────────────────────────────────────
function initCryptoSuite() {
  const inputEl = document.getElementById('crypto-input');
  const executeBtn = document.getElementById('crypto-execute-btn');
  const clearBtn = document.getElementById('crypto-clear-btn');
  const algoSelect = document.getElementById('algorithm-select');
  const btnModeEncode = document.getElementById('btn-mode-encode');
  const btnModeDecode = document.getElementById('btn-mode-decode');
  const categoryTabs = document.querySelectorAll('.crypto-tab-btn');
  const sampleBtns = document.querySelectorAll('.quick-crypto-sample');

  // Initial category state setup
  onCategoryChange();

  // Category Tab Click
  categoryTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      categoryTabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeCategory = tab.dataset.category;
      onCategoryChange();
    });
  });

  // Algorithm Dropdown Change
  algoSelect.addEventListener('change', () => {
    state.activeAlgorithm = algoSelect.value;
    updateContextualOptions();
  });

  // Mode Selector (Encode vs Decode)
  btnModeEncode.addEventListener('click', () => setMode('encode'));
  btnModeDecode.addEventListener('click', () => setMode('decode'));

  // Live Input Stats & Real-time Auto-Analysis
  let analyzeDebounceTimer = null;
  inputEl.addEventListener('input', () => {
    updateInputStats();
    if (state.activeCategory === 'analyzer') {
      clearTimeout(analyzeDebounceTimer);
      const text = inputEl.value.trim();
      if (!text) {
        document.getElementById('crypto-placeholder-card')?.classList.remove('hidden');
        document.getElementById('crypto-analyzer-result')?.classList.add('hidden');
        return;
      }
      analyzeDebounceTimer = setTimeout(() => {
        runSmartAnalysis(inputEl.value, true);
      }, 200);
    }
  });

  // Clear Button
  clearBtn.addEventListener('click', () => {
    inputEl.value = '';
    updateInputStats();
    inputEl.focus();
    if (state.activeCategory === 'analyzer') {
      document.getElementById('crypto-placeholder-card')?.classList.remove('hidden');
      document.getElementById('crypto-analyzer-result')?.classList.add('hidden');
    }
  });

  // Sample Buttons
  sampleBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      inputEl.value = btn.dataset.text;
      updateInputStats();
      triggerProcess();
    });
  });

  // Execute Action Button
  executeBtn.addEventListener('click', triggerProcess);

  // Keyboard shortcut: Ctrl + Enter / Cmd + Enter to execute
  inputEl.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      triggerProcess();
    }
  });
}

function updateInputStats() {
  const inputEl = document.getElementById('crypto-input');
  const charCountEl = document.getElementById('input-char-count');
  const byteCountEl = document.getElementById('input-byte-count');

  const text = inputEl.value;
  const bytes = new TextEncoder().encode(text).length;

  charCountEl.textContent = `${text.length} ${text.length === 1 ? 'char' : 'chars'}`;
  byteCountEl.textContent = `${bytes} ${bytes === 1 ? 'byte' : 'bytes'}`;
}

function setMode(mode) {
  state.mode = mode;
  const btnEncode = document.getElementById('btn-mode-encode');
  const btnDecode = document.getElementById('btn-mode-decode');

  if (mode === 'encode') {
    btnEncode.className = 'flex-1 h-full rounded text-xs font-bold transition-all bg-purple-600 text-white shadow-sm flex items-center justify-center gap-1';
    btnDecode.className = 'flex-1 h-full rounded text-xs font-bold transition-all text-slate-400 hover:text-white flex items-center justify-center gap-1';
  } else {
    btnDecode.className = 'flex-1 h-full rounded text-xs font-bold transition-all bg-purple-600 text-white shadow-sm flex items-center justify-center gap-1';
    btnEncode.className = 'flex-1 h-full rounded text-xs font-bold transition-all text-slate-400 hover:text-white flex items-center justify-center gap-1';
  }

  updateExecuteButtonText();
}

function onCategoryChange() {
  const controlsToolbar = document.getElementById('controls-toolbar');
  const modeWrapper = document.getElementById('mode-selector-wrapper');
  const algoSelect = document.getElementById('algorithm-select');
  const optionsContainer = document.getElementById('contextual-options-container');
  const inputEl = document.getElementById('crypto-input');

  if (state.activeCategory === 'analyzer') {
    controlsToolbar.classList.add('hidden');
    optionsContainer.classList.add('hidden');

    // Auto trigger if there is input
    if (inputEl && inputEl.value.trim()) {
      runSmartAnalysis(inputEl.value, true);
    }
  } else if (state.activeCategory === 'hash-all') {
    controlsToolbar.classList.add('hidden');
    optionsContainer.classList.add('hidden');
  } else {
    controlsToolbar.classList.remove('hidden');
    populateAlgorithmsDropdown();

    if (state.activeCategory === 'hashes') {
      modeWrapper.classList.add('hidden');
      algoSelect.parentElement.parentElement.classList.remove('sm:col-span-2');
      algoSelect.parentElement.parentElement.classList.add('sm:col-span-3');
    } else {
      modeWrapper.classList.remove('hidden');
      algoSelect.parentElement.parentElement.classList.remove('sm:col-span-3');
      algoSelect.parentElement.parentElement.classList.add('sm:col-span-2');

      const encodeLabel = document.getElementById('mode-encode-label');
      const decodeLabel = document.getElementById('mode-decode-label');
      if (state.activeCategory === 'ciphers') {
        encodeLabel.textContent = 'Encrypt';
        decodeLabel.textContent = 'Decrypt';
      } else {
        encodeLabel.textContent = 'Encode';
        decodeLabel.textContent = 'Decode';
      }
    }

    updateContextualOptions();
  }

  updateExecuteButtonText();
}

function populateAlgorithmsDropdown() {
  const select = document.getElementById('algorithm-select');
  const catData = CRYPTO_CATEGORIES[state.activeCategory];
  if (!catData || !catData.algorithms) return;

  select.innerHTML = '';
  catData.algorithms.forEach((algo) => {
    const opt = document.createElement('option');
    opt.value = algo.id;
    opt.textContent = algo.name;
    if (algo.default) opt.selected = true;
    select.appendChild(opt);
  });

  state.activeAlgorithm = select.value;
}

function updateContextualOptions() {
  const container = document.getElementById('contextual-options-container');
  const catData = CRYPTO_CATEGORIES[state.activeCategory];
  if (!catData || !catData.algorithms) {
    container.classList.add('hidden');
    return;
  }

  const currentAlgo = catData.algorithms.find((a) => a.id === state.activeAlgorithm);
  if (!currentAlgo || !currentAlgo.hasOptions) {
    container.classList.add('hidden');
    container.innerHTML = '';
    return;
  }

  container.classList.remove('hidden');

  if (currentAlgo.optionType === 'shift') {
    container.innerHTML = `
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <label class="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
            <i data-lucide="sliders" class="w-3.5 h-3.5 text-purple-400"></i>
            Caesar Shift Key (1 - 25)
          </label>
          <span class="text-[11px] text-slate-400">Number of alphabetical positions to rotate</span>
        </div>
        <div class="flex items-center gap-3">
          <input
            type="range"
            min="1"
            max="25"
            value="${state.options.shift || 3}"
            id="caesar-range"
            class="w-36 accent-purple-500 cursor-pointer"
          />
          <input
            type="number"
            min="1"
            max="25"
            value="${state.options.shift || 3}"
            id="caesar-number"
            class="input-field w-16 text-center font-mono font-bold text-sm !py-1 !px-2 text-white bg-surface-800"
          />
        </div>
      </div>
    `;

    const range = document.getElementById('caesar-range');
    const number = document.getElementById('caesar-number');
    range.addEventListener('input', () => {
      number.value = range.value;
      state.options.shift = parseInt(range.value, 10);
    });
    number.addEventListener('input', () => {
      let val = parseInt(number.value, 10);
      if (isNaN(val)) val = 3;
      if (val < 1) val = 1;
      if (val > 25) val = 25;
      range.value = val;
      state.options.shift = val;
    });
  } else if (currentAlgo.optionType === 'key') {
    container.innerHTML = `
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <label class="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
            <i data-lucide="key" class="w-3.5 h-3.5 text-purple-400"></i>
            Vigenère Secret Keyword
          </label>
          <span class="text-[11px] text-slate-400">Alphabetic key used for polyalphabetic substitution</span>
        </div>
        <input
          type="text"
          id="vigenere-key"
          value="${escapeHtml(state.options.key || 'SECRET')}"
          placeholder="e.g. CIPHER"
          class="input-field uppercase font-mono font-bold text-sm w-44 text-white bg-surface-800 tracking-wider"
        />
      </div>
    `;

    const keyInput = document.getElementById('vigenere-key');
    keyInput.addEventListener('input', () => {
      state.options.key = keyInput.value.toUpperCase().replace(/[^A-Z]/g, '') || 'SECRET';
    });
  }

  try {
    lucide.createIcons({ nodes: [container] });
  } catch (_) {}
}

function updateExecuteButtonText() {
  const btnText = document.getElementById('execute-btn-text');
  const catData = CRYPTO_CATEGORIES[state.activeCategory];
  if (!catData) return;

  if (state.activeCategory === 'analyzer') {
    btnText.textContent = 'Run Smart Auto-Analysis';
  } else if (state.activeCategory === 'hash-all') {
    btnText.textContent = 'Calculate All 16 Hashes In Parallel';
  } else if (state.activeCategory === 'hashes') {
    btnText.textContent = `Calculate ${state.activeAlgorithm.toUpperCase()} Hash`;
  } else if (state.activeCategory === 'encodings') {
    btnText.textContent = state.mode === 'encode' ? 'Encode Payload' : 'Decode Payload';
  } else if (state.activeCategory === 'ciphers') {
    btnText.textContent = state.mode === 'encode' ? 'Encrypt Payload' : 'Decrypt Payload';
  }
}

// ── Trigger Process Execution ───────────────────────────────────
async function triggerProcess() {
  const inputEl = document.getElementById('crypto-input');
  const text = inputEl.value;
  const executeBtn = document.getElementById('crypto-execute-btn');
  const placeholderCard = document.getElementById('crypto-placeholder-card');
  const singleResult = document.getElementById('crypto-single-result');
  const multiMatrix = document.getElementById('crypto-multi-matrix');
  const analyzerResult = document.getElementById('crypto-analyzer-result');

  if (!text) {
    showToast('Please enter text to process', 'warning');
    inputEl.focus();
    return;
  }

  if (state.activeCategory === 'analyzer') {
    return runSmartAnalysis(text, false);
  }

  if (state.isProcessing) return;
  state.isProcessing = true;

  const originalBtn = executeBtn.innerHTML;
  executeBtn.disabled = true;
  executeBtn.innerHTML = `<div class="spinner"></div><span>Calculating...</span>`;

  try {
    if (state.activeCategory === 'hash-all') {
      const res = await fetch('/api/crypto/hash-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error?.message || data.error || 'Failed to calculate hashes');
      }

      placeholderCard.classList.add('hidden');
      analyzerResult.classList.add('hidden');
      singleResult.classList.add('hidden');
      multiMatrix.classList.remove('hidden');

      renderMultiHashMatrix(data.data, text);
    } else {
      const res = await fetch('/api/crypto/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text,
          category: state.activeCategory,
          algorithm: state.activeAlgorithm,
          mode: state.mode,
          options: state.options,
        }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error?.message || data.error || 'Transformation failed');
      }

      placeholderCard.classList.add('hidden');
      analyzerResult.classList.add('hidden');
      multiMatrix.classList.add('hidden');
      singleResult.classList.remove('hidden');

      renderSingleResult(data.data);
    }
  } catch (err) {
    showToast(err.message, 'error', 4000);
  } finally {
    state.isProcessing = false;
    executeBtn.disabled = false;
    executeBtn.innerHTML = originalBtn;
    try {
      lucide.createIcons({ nodes: [executeBtn] });
    } catch (_) {}
  }
}

// ── Smart Analyzer & Identifier Engine ──────────────────────────
async function runSmartAnalysis(text, isBackground = false) {
  const placeholderCard = document.getElementById('crypto-placeholder-card');
  const singleResult = document.getElementById('crypto-single-result');
  const multiMatrix = document.getElementById('crypto-multi-matrix');
  const analyzerResult = document.getElementById('crypto-analyzer-result');
  const executeBtn = document.getElementById('crypto-execute-btn');

  if (!text || !text.trim()) {
    placeholderCard.classList.remove('hidden');
    analyzerResult.classList.add('hidden');
    return;
  }

  let originalBtn = null;
  if (!isBackground && executeBtn) {
    originalBtn = executeBtn.innerHTML;
    executeBtn.disabled = true;
    executeBtn.innerHTML = `<div class="spinner"></div><span>Analyzing Heuristics...</span>`;
  }

  try {
    const res = await fetch('/api/crypto/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });

    const result = await res.json();
    if (!res.ok || !result.success) {
      throw new Error(result.error?.message || result.error || 'Heuristic analysis failed');
    }

    placeholderCard.classList.add('hidden');
    singleResult.classList.add('hidden');
    multiMatrix.classList.add('hidden');
    analyzerResult.classList.remove('hidden');

    renderSmartAnalyzer(result.data);
  } catch (err) {
    if (!isBackground) {
      showToast(err.message, 'error', 4000);
    }
  } finally {
    if (!isBackground && executeBtn && originalBtn) {
      executeBtn.disabled = false;
      executeBtn.innerHTML = originalBtn;
      try {
        lucide.createIcons({ nodes: [executeBtn] });
      } catch (_) {}
    }
  }
}

function renderSmartAnalyzer(data) {
  const container = document.getElementById('crypto-analyzer-result');
  if (!container) return;

  const primary = data.primaryType || { type: 'unknown', title: 'Undetermined Payload', confidence: 'Low', summary: 'Input did not match common cryptographic patterns.' };
  const hashCandidates = data.hashCandidates || [];
  const decodings = data.decodings || [];
  const ciphers = data.ciphers || [];

  // Theme colors for Primary Type
  const themeMap = {
    hash: { border: 'border-purple-500/40', bg: 'bg-purple-500/10', text: 'text-purple-400', badge: 'bg-purple-500/20 text-purple-300 border-purple-500/40', icon: 'hash' },
    encoder: { border: 'border-cyan-500/40', bg: 'bg-cyan-500/10', text: 'text-cyan-400', badge: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40', icon: 'binary' },
    cipher: { border: 'border-amber-500/40', bg: 'bg-amber-500/10', text: 'text-amber-400', badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40', icon: 'scroll' },
    unknown: { border: 'border-slate-700', bg: 'bg-surface-800', text: 'text-slate-400', badge: 'bg-surface-700 text-slate-300 border-slate-600', icon: 'help-circle' },
  };
  const theme = themeMap[primary.type] || themeMap.unknown;

  const confidenceBadgeMap = {
    High: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    Medium: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    Low: 'bg-slate-700 text-slate-300 border-slate-600',
  };

  container.innerHTML = `
    <!-- ── Hero Identification Summary Card ── -->
    <div class="card p-5 border ${theme.border} bg-gradient-to-r from-surface-800 via-surface-900 to-surface-800 shadow-xl space-y-4 animate-fade-in">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3.5">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl ${theme.bg} border ${theme.border} flex items-center justify-center flex-shrink-0">
            <i data-lucide="${theme.icon}" class="w-5 h-5 ${theme.text}"></i>
          </div>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-[10px] uppercase font-extrabold tracking-wider px-2 py-0.5 rounded border ${theme.badge}">
                IDENTIFIER VERDICT
              </span>
              <span class="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded border ${confidenceBadgeMap[primary.confidence] || confidenceBadgeMap.Low}">
                ${primary.confidence} Confidence
              </span>
            </div>
            <h3 class="text-base font-bold text-white mt-1 tracking-tight">
              ${escapeHtml(primary.title)}
            </h3>
          </div>
        </div>

        <div class="text-xs text-slate-400 sm:text-right font-mono">
          <div><strong class="text-cyan-400">${data.inputLength}</strong> chars • <strong class="text-purple-400">${data.inputBytes}</strong> bytes</div>
          <div class="text-[11px] text-slate-500">${data.isHexOnly ? 'Pure Hexadecimal [0-9a-fA-F]' : 'Arbitrary Character Set'}</div>
        </div>
      </div>

      <p class="text-xs text-slate-300 leading-relaxed">
        ${escapeHtml(primary.summary)}
      </p>

      <!-- Quick Metrics Bar -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-xs">
        <div class="vector-chip">
          <span class="text-[10px] uppercase font-bold text-slate-500">Hash Matches</span>
          <span class="font-mono font-bold ${hashCandidates.length > 0 ? 'text-purple-300' : 'text-slate-400'}">${hashCandidates.length} potential</span>
        </div>
        <div class="vector-chip">
          <span class="text-[10px] uppercase font-bold text-slate-500">Decoded Previews</span>
          <span class="font-mono font-bold text-cyan-400">${decodings.filter(d => d.detected).length} valid formats</span>
        </div>
        <div class="vector-chip">
          <span class="text-[10px] uppercase font-bold text-slate-500">Classical Transforms</span>
          <span class="font-mono font-bold text-amber-300">${ciphers.length} evaluated</span>
        </div>
        <div class="vector-chip">
          <span class="text-[10px] uppercase font-bold text-slate-500">Hexadecimal Purity</span>
          <span class="font-mono font-bold ${data.isHexOnly ? 'text-emerald-400' : 'text-slate-400'}">${data.isHexOnly ? '100% Hex String' : 'Mixed Encodings'}</span>
        </div>
      </div>
    </div>

    <!-- ── 1. Cryptographic Hashes (Identifier & Candidates) ── -->
    <div class="card p-5 border-slate-700/60 bg-surface-850/80 shadow-xl space-y-4 animate-fade-in">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div class="flex items-center gap-2">
          <i data-lucide="hash" class="w-4 h-4 text-purple-400"></i>
          <h4 class="text-sm font-bold text-white tracking-wide">Cryptographic Hash Fingerprints</h4>
          <span class="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
            ${hashCandidates.length} Signatures Match
          </span>
        </div>
        <span class="text-[11px] font-mono text-slate-400">Length-based & Prefix Heuristics</span>
      </div>

      ${hashCandidates.length > 0 ? `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          ${hashCandidates.map(c => `
            <div class="p-3.5 rounded-xl bg-surface-900/90 border border-slate-800 hover:border-purple-500/40 transition-all space-y-2.5 group">
              <div class="flex items-start justify-between gap-2">
                <div>
                  <div class="flex items-center gap-2">
                    <span class="font-bold text-sm text-white group-hover:text-purple-300 transition-colors">${escapeHtml(c.name)}</span>
                    <span class="px-1.5 py-0.5 text-[10px] font-mono font-bold rounded bg-surface-800 text-slate-400 border border-slate-700">${c.bits}-bit</span>
                  </div>
                  <span class="text-[11px] text-slate-400 font-mono">${escapeHtml(c.matchType)}</span>
                </div>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${c.likelihood === 'Very High' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-purple-500/20 text-purple-300 border border-purple-500/30'}">
                  ${c.likelihood}
                </span>
              </div>

              <p class="text-xs text-slate-300 leading-snug">${escapeHtml(c.notes)}</p>

              <!-- Cracking Tool Reference Chips -->
              <div class="pt-1 flex items-center gap-2 text-[10px] font-mono text-slate-400">
                <span class="bg-surface-800 px-2 py-0.5 rounded border border-slate-700/80">
                  <strong class="text-purple-400">hashcat:</strong> -m ${escapeHtml(c.hashcatMode)}
                </span>
                <span class="bg-surface-800 px-2 py-0.5 rounded border border-slate-700/80">
                  <strong class="text-cyan-400">john:</strong> ${escapeHtml(c.johnFormat)}
                </span>
              </div>
            </div>
          `).join('')}
        </div>
      ` : `
        <div class="p-4 rounded-xl bg-surface-900/60 border border-slate-800/80 text-center text-xs text-slate-400">
          <i data-lucide="info" class="w-4 h-4 mx-auto mb-1 text-slate-500"></i>
          Input does not strictly match standard raw Hex hash lengths (32, 40, 56, 64, 96, 128 hex chars) or crypt formats ($2a$, $6$, $1$).
        </div>
      `}
    </div>

    <!-- ── 2. Encoders & Converters (Decoded Previews) ── -->
    <div class="card p-5 border-slate-700/60 bg-surface-850/80 shadow-xl space-y-4 animate-fade-in">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div class="flex items-center gap-2">
          <i data-lucide="binary" class="w-4 h-4 text-cyan-400"></i>
          <h4 class="text-sm font-bold text-white tracking-wide">Encoders & Converters — Instant Decoded Previews</h4>
          <span class="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
            ${decodings.filter(d => d.detected).length} Detected Formats
          </span>
        </div>
        <span class="text-[11px] font-mono text-slate-400">Multi-Base Inspection</span>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        ${decodings.map(d => {
          const isSuccess = d.detected && d.decoded;
          return `
            <div class="p-4 rounded-xl bg-surface-900/90 border ${isSuccess ? 'border-cyan-500/30 hover:border-cyan-400/50' : 'border-slate-800/60 opacity-60'} transition-all space-y-3">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                  <span class="font-bold text-sm text-white">${escapeHtml(d.name)}</span>
                  ${isSuccess ? `
                    <span class="px-1.5 py-0.2 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                      ${d.confidence} Confidence
                    </span>
                  ` : `
                    <span class="px-1.5 py-0.2 rounded text-[10px] text-slate-500 bg-surface-800">
                      Not Format
                    </span>
                  `}
                </div>

                ${isSuccess ? `
                  <div class="flex items-center gap-1.5">
                    <button
                      type="button"
                      class="btn-secondary !text-[11px] !py-1 !px-2 flex items-center gap-1"
                      title="Transfer decoded text to input"
                      onclick="setInputValue('${escapeHtml(d.decoded).replace(/'/g, "\\'")}')"
                    >
                      <i data-lucide="arrow-up-down" class="w-3 h-3 text-cyan-400"></i>
                      <span>To Input</span>
                    </button>
                    <button
                      type="button"
                      class="btn-secondary !text-[11px] !py-1 !px-2 flex items-center gap-1"
                      title="Copy decoded text"
                      onclick="copyToClipboard('${escapeHtml(d.decoded).replace(/'/g, "\\'")}', this)"
                    >
                      <i data-lucide="copy" class="w-3 h-3"></i>
                    </button>
                  </div>
                ` : ''}
              </div>

              ${isSuccess ? `
                <div class="relative">
                  <textarea
                    readonly
                    rows="2"
                    class="input-field w-full text-xs font-mono text-cyan-300 p-2.5 bg-surface-950/80 border-slate-700/80 resize-none break-all select-all leading-relaxed"
                  >${escapeHtml(d.decoded)}</textarea>
                </div>
              ` : `
                <p class="text-xs text-slate-500 italic">Does not match valid ${escapeHtml(d.name)} structure.</p>
              `}

              <div class="flex items-center justify-between text-[11px] text-slate-400 pt-0.5">
                <span>${escapeHtml(d.notes)}</span>
                ${isSuccess && d.validUtf8 ? `
                  <span class="text-emerald-400 font-bold flex items-center gap-1">
                    <i data-lucide="check" class="w-3 h-3"></i> Valid UTF-8
                  </span>
                ` : ''}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    </div>

    <!-- ── 3. Classical Ciphers (Transform Previews) ── -->
    <div class="card p-5 border-slate-700/60 bg-surface-850/80 shadow-xl space-y-4 animate-fade-in">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div class="flex items-center gap-2">
          <i data-lucide="scroll" class="w-4 h-4 text-amber-400"></i>
          <h4 class="text-sm font-bold text-white tracking-wide">Classical Ciphers — Heuristic Decryption Previews</h4>
          <span class="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
            ${ciphers.length} Transformations
          </span>
        </div>
        <span class="text-[11px] font-mono text-slate-400">Letter-Frequency Scoring</span>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        ${ciphers.map(c => `
          <div class="p-4 rounded-xl bg-surface-900/90 border border-slate-800 hover:border-amber-500/40 transition-all space-y-2.5">
            <div class="flex items-center justify-between">
              <span class="font-bold text-xs text-white uppercase tracking-wider">${escapeHtml(c.name)}</span>
              <div class="flex items-center gap-1.5">
                <button
                  type="button"
                  class="btn-secondary !text-[11px] !py-1 !px-2 flex items-center gap-1"
                  title="Transfer to input"
                  onclick="setInputValue('${escapeHtml(c.transformed).replace(/'/g, "\\'")}')"
                >
                  <i data-lucide="arrow-up-down" class="w-3 h-3 text-amber-400"></i>
                </button>
                <button
                  type="button"
                  class="btn-secondary !text-[11px] !py-1 !px-2 flex items-center gap-1"
                  title="Copy transformed text"
                  onclick="copyToClipboard('${escapeHtml(c.transformed).replace(/'/g, "\\'")}', this)"
                >
                  <i data-lucide="copy" class="w-3 h-3"></i>
                </button>
              </div>
            </div>

            <div class="relative">
              <textarea
                readonly
                rows="3"
                class="input-field w-full text-xs font-mono text-amber-300 p-2.5 bg-surface-950/80 border-slate-700/80 resize-none break-all select-all leading-relaxed"
              >${escapeHtml(c.transformed)}</textarea>
            </div>

            <p class="text-[11px] text-slate-400 leading-snug">${escapeHtml(c.notes)}</p>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  try {
    lucide.createIcons({ nodes: [container] });
  } catch (_) {}
}

// ── Render Single Result ────────────────────────────────────────
function renderSingleResult(data) {
  const container = document.getElementById('crypto-single-result');
  if (!container) return;

  const isHash = data.category === 'hashes';
  const meta = data.meta || {};

  container.innerHTML = `
    <div class="card p-6 border-slate-700/80 bg-gradient-to-r from-surface-800 via-surface-700/50 to-surface-800 shadow-xl animate-fade-in space-y-5">

      <!-- Header Bar -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center">
            <i data-lucide="${isHash ? 'hash' : 'check'}" class="w-4 h-4 text-purple-400"></i>
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-sm font-bold text-white uppercase tracking-wider">${escapeHtml(data.algorithm)}</h3>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 uppercase">
                ${escapeHtml(data.category)}
              </span>
            </div>
            <p class="text-xs text-slate-400">
              Computed in <strong class="text-cyan-400 font-mono">${data.executionTimeMs} ms</strong>
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          ${!isHash ? `
            <button
              type="button"
              class="btn-secondary !text-xs !py-1.5 !px-3 flex items-center gap-1.5"
              onclick="swapOutputToInput()"
              title="Put output into input box to reverse"
            >
              <i data-lucide="arrow-up-down" class="w-3.5 h-3.5 text-cyan-400"></i>
              <span>Swap to Input</span>
            </button>
          ` : ''}

          <button
            type="button"
            class="btn-primary !text-xs !py-1.5 !px-3 !bg-purple-600 hover:!bg-purple-500 flex items-center gap-1.5"
            onclick="copyPrimaryOutput(this)"
          >
            <i data-lucide="copy" class="w-3.5 h-3.5"></i>
            <span>Copy Output</span>
          </button>
        </div>
      </div>

      <!-- Primary Output Box -->
      <div>
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold text-slate-400 uppercase tracking-wider">
            ${isHash ? 'Hexadecimal Digest' : 'Transformed Output'}
          </span>
          <span class="text-[11px] font-mono text-slate-500">
            ${data.outputLength} chars • ${new TextEncoder().encode(data.output).length} bytes
          </span>
        </div>
        <div class="relative">
          <textarea
            id="primary-output-textarea"
            readonly
            rows="${Math.min(10, Math.max(3, Math.ceil(data.output.length / 70)))}"
            class="input-field w-full text-sm font-mono text-cyan-300 p-3.5 bg-surface-900/90 break-all resize-y select-all leading-relaxed"
          >${escapeHtml(data.output)}</textarea>
        </div>
      </div>

      <!-- If Hash: Secondary Base64 Representation -->
      ${isHash && meta.base64 ? `
        <div class="pt-2 border-t border-slate-800/80">
          <div class="flex items-center justify-between mb-1.5">
            <span class="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <i data-lucide="binary" class="w-3.5 h-3.5 text-pink-400"></i> Base64 Digest
            </span>
            <button
              type="button"
              class="text-xs text-purple-300 hover:text-white flex items-center gap-1 font-semibold"
              onclick="copyToClipboard('${escapeHtml(meta.base64)}', this)"
            >
              <i data-lucide="copy" class="w-3 h-3"></i> Copy Base64
            </button>
          </div>
          <div class="net-val-box !py-2 !px-3 bg-surface-900/90">
            <code class="font-mono text-xs text-pink-300 break-all">${escapeHtml(meta.base64)}</code>
          </div>
        </div>
      ` : ''}

      <!-- Output Metric Chips -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-2 text-xs">
        <div class="vector-chip">
          <span class="text-[10px] uppercase font-bold text-slate-500">Input Size</span>
          <span class="font-mono font-bold text-slate-300">${data.inputLength} characters</span>
        </div>
        <div class="vector-chip">
          <span class="text-[10px] uppercase font-bold text-slate-500">Output Length</span>
          <span class="font-mono font-bold text-cyan-400">${data.outputLength} characters</span>
        </div>
        <div class="vector-chip">
          <span class="text-[10px] uppercase font-bold text-slate-500">Execution Speed</span>
          <span class="font-mono font-bold text-emerald-400">${data.executionTimeMs} ms</span>
        </div>
        <div class="vector-chip">
          <span class="text-[10px] uppercase font-bold text-slate-500">${isHash ? 'Hash Security' : 'Reversibility'}</span>
          <span class="font-mono font-bold ${isHash ? 'text-purple-300' : 'text-amber-300'}">
            ${isHash ? `${meta.bits || 256}-bit digest` : 'Fully Reversible'}
          </span>
        </div>
      </div>

    </div>
  `;

  try {
    lucide.createIcons({ nodes: [container] });
  } catch (_) {}
}

// ── Render Multi-Hash Matrix ────────────────────────────────────
function renderMultiHashMatrix(data, rawText) {
  const container = document.getElementById('crypto-multi-matrix');
  if (!container) return;

  const hashes = data.hashes || [];

  container.innerHTML = `
    <div class="card p-6 border-slate-700/80 bg-gradient-to-b from-surface-800 to-surface-900 shadow-xl animate-fade-in space-y-4">

      <!-- Matrix Header -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div class="flex items-center gap-2">
            <h3 class="text-base font-bold text-white tracking-wide">Multi-Hash Parallel Digest Matrix</h3>
            <span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
              ${hashes.length} Hashes Computed
            </span>
          </div>
          <p class="text-xs text-slate-400 mt-1">
            Input: <code class="font-mono text-cyan-300 bg-surface-900 px-1.5 py-0.5 rounded">${escapeHtml(rawText.length > 50 ? rawText.slice(0, 50) + '...' : rawText)}</code>
            (${data.inputBytes} bytes)
          </p>
        </div>

        <div>
          <input
            type="text"
            id="matrix-filter"
            placeholder="Filter hash (e.g. sha256)..."
            class="input-field text-xs !py-1.5 !px-3 font-mono w-48 text-white bg-surface-900"
          />
        </div>
      </div>

      <!-- Hash Table -->
      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs border-collapse">
          <thead>
            <tr class="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
              <th class="py-2.5 px-3">Algorithm</th>
              <th class="py-2.5 px-3">Family</th>
              <th class="py-2.5 px-3">Bits</th>
              <th class="py-2.5 px-3">Hex Digest</th>
              <th class="py-2.5 px-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody id="matrix-tbody" class="divide-y divide-slate-800/60 font-mono">
            ${hashes.map((h) => `
              <tr class="hover:bg-surface-700/40 transition-colors group matrix-row" data-search="${h.id} ${h.name.toLowerCase()} ${h.family.toLowerCase()}">
                <td class="py-2.5 px-3 font-bold text-white font-sans whitespace-nowrap">
                  ${escapeHtml(h.name)}
                </td>
                <td class="py-2.5 px-3">
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-surface-700 text-slate-300 border border-slate-700">
                    ${escapeHtml(h.family)}
                  </span>
                </td>
                <td class="py-2.5 px-3 text-cyan-400 font-bold">${h.bits}</td>
                <td class="py-2.5 px-3 max-w-xs md:max-w-md break-all text-slate-300 group-hover:text-cyan-300 transition-colors">
                  ${escapeHtml(h.hex)}
                </td>
                <td class="py-2.5 px-3 text-right whitespace-nowrap">
                  <button
                    type="button"
                    class="p-1.5 rounded bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-white border border-slate-700/60 transition-colors"
                    title="Copy Hex Digest"
                    onclick="copyToClipboard('${escapeHtml(h.hex)}', this)"
                  >
                    <i data-lucide="copy" class="w-3.5 h-3.5"></i>
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

    </div>
  `;

  // Matrix Filter live search
  const filterInput = document.getElementById('matrix-filter');
  const rows = container.querySelectorAll('.matrix-row');
  if (filterInput) {
    filterInput.addEventListener('input', () => {
      const q = filterInput.value.toLowerCase().trim();
      rows.forEach((r) => {
        const searchVal = r.dataset.search || '';
        r.classList.toggle('hidden', !searchVal.includes(q));
      });
    });
  }

  try {
    lucide.createIcons({ nodes: [container] });
  } catch (_) {}
}
