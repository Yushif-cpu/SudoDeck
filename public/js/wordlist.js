// ═══════════════════════════════════════════════════════════════
//  SudoDeck — Automated Wordlist & Mutator Engine
//  100% client-side — no data transmitted to any server
// ═══════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // ── DOM References ──────────────────────────────────────────────
  const baseWordsEl    = document.getElementById('wl-base-words');
  const seedCountEl    = document.getElementById('wl-seed-count');
  const clearSeedsBtn  = document.getElementById('wl-clear-seeds');
  const customPrefixEl = document.getElementById('wl-custom-prefix');
  const customSuffixEl = document.getElementById('wl-custom-suffix');
  const generateBtn    = document.getElementById('wl-generate-btn');
  const outputEl       = document.getElementById('wl-output');
  const copyBtn        = document.getElementById('wl-copy-btn');
  const downloadBtn    = document.getElementById('wl-download-btn');
  const clearOutputBtn = document.getElementById('wl-clear-output');
  const statsEl        = document.getElementById('wl-stats');
  const lineCountEl    = document.getElementById('wl-line-count');
  const sizeEl         = document.getElementById('wl-size');
  const uniqueCountEl  = document.getElementById('wl-unique-count');

  // ── Mutation State ──────────────────────────────────────────────
  const activeRules = new Set(['leet', 'case', 'numbers', 'specials']);

  // ── Leet-speak substitution map ─────────────────────────────────
  const LEET_MAP = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['7'],
    'l': ['1'],
    'g': ['9'],
    'b': ['8'],
  };

  // ── Common number suffixes ──────────────────────────────────────
  const NUMBER_SUFFIXES = [
    '1', '2', '3', '12', '13', '21', '23',
    '69', '77', '99', '100', '101',
    '123', '007', '111', '222', '321',
    '666', '777', '888', '999',
    '1234', '12345',
  ];

  // ── Special character suffixes ──────────────────────────────────
  const SPECIAL_SUFFIXES = [
    '!', '@', '#', '$', '%', '&', '*',
    '!!', '!@', '@#', '#$',
    '!1', '@1', '#1',
    '!@#', '!@#$',
    '.', '?', '_',
  ];

  // ── Common prefixes ─────────────────────────────────────────────
  const COMMON_PREFIXES = [
    'the', 'my', 'super', 'mega', 'x',
    'old', 'new', 'big', 'mr', 'real',
  ];

  // ── Years to append ─────────────────────────────────────────────
  const YEARS = [
    '2020', '2021', '2022', '2023', '2024',
    '2025', '2026', '20', '21', '22', '23', '24', '25', '26',
  ];


  // ═══════════════════════════════════════════════════════════════
  //  MUTATION FUNCTIONS
  // ═══════════════════════════════════════════════════════════════

  /**
   * Generate leet-speak variants of a word.
   * Creates multiple substitution variants (single & combined).
   */
  function leetSpeak(word) {
    const results = new Set();
    const lower = word.toLowerCase();

    // Single-character substitutions
    for (let i = 0; i < lower.length; i++) {
      const ch = lower[i];
      if (LEET_MAP[ch]) {
        for (const sub of LEET_MAP[ch]) {
          const variant = lower.substring(0, i) + sub + lower.substring(i + 1);
          results.add(variant);
        }
      }
    }

    // Aggressive all-at-once substitution (first variant for each letter)
    let allLeet = lower;
    for (let i = 0; i < allLeet.length; i++) {
      const ch = allLeet[i];
      if (LEET_MAP[ch]) {
        allLeet = allLeet.substring(0, i) + LEET_MAP[ch][0] + allLeet.substring(i + 1);
      }
    }
    if (allLeet !== lower) results.add(allLeet);

    // Second-variant all-at-once (where available)
    let allLeet2 = lower;
    for (let i = 0; i < allLeet2.length; i++) {
      const ch = allLeet2[i];
      if (LEET_MAP[ch] && LEET_MAP[ch][1]) {
        allLeet2 = allLeet2.substring(0, i) + LEET_MAP[ch][1] + allLeet2.substring(i + 1);
      } else if (LEET_MAP[ch]) {
        allLeet2 = allLeet2.substring(0, i) + LEET_MAP[ch][0] + allLeet2.substring(i + 1);
      }
    }
    if (allLeet2 !== lower && allLeet2 !== allLeet) results.add(allLeet2);

    return [...results];
  }

  /**
   * Generate case variants of a word.
   */
  function caseVariants(word) {
    const results = [];
    const lower = word.toLowerCase();
    const upper = word.toUpperCase();

    if (upper !== word) results.push(upper);
    if (lower !== word) results.push(lower);

    // Capitalize first letter
    const capitalized = lower.charAt(0).toUpperCase() + lower.slice(1);
    if (capitalized !== word) results.push(capitalized);

    // Invert case of first letter
    const inverted = upper.charAt(0).toLowerCase() + upper.slice(1);
    if (inverted !== word && inverted !== lower) results.push(inverted);

    // Alternating case: aBcDe
    let alt = '';
    for (let i = 0; i < lower.length; i++) {
      alt += i % 2 === 0 ? lower[i] : upper[i];
    }
    if (alt !== word) results.push(alt);

    // Alternating case inverted: AbCdE
    let altInv = '';
    for (let i = 0; i < lower.length; i++) {
      altInv += i % 2 === 0 ? upper[i] : lower[i];
    }
    if (altInv !== word && altInv !== alt) results.push(altInv);

    return results;
  }

  /**
   * Append number suffixes.
   */
  function numberSuffix(word) {
    return NUMBER_SUFFIXES.map(n => word + n);
  }

  /**
   * Append special character suffixes.
   */
  function specialSuffix(word) {
    return SPECIAL_SUFFIXES.map(s => word + s);
  }

  /**
   * Reverse the word.
   */
  function reverseWord(word) {
    const rev = word.split('').reverse().join('');
    return rev !== word ? [rev] : [];
  }

  /**
   * Duplicate the word.
   */
  function duplicateWord(word) {
    return [word + word];
  }

  /**
   * Prepend common prefixes.
   */
  function commonPrefix(word) {
    return COMMON_PREFIXES.map(p => p + word);
  }

  /**
   * Append year values.
   */
  function yearAppend(word) {
    return YEARS.map(y => word + y);
  }


  // ═══════════════════════════════════════════════════════════════
  //  CORE GENERATION ENGINE
  // ═══════════════════════════════════════════════════════════════

  function generateWordlist() {
    const rawText = baseWordsEl.value.trim();
    if (!rawText) {
      showToast('Enter at least one base word to generate.', 'warning');
      return;
    }

    const baseWords = rawText
      .split('\n')
      .map(w => w.trim())
      .filter(w => w.length > 0);

    if (baseWords.length === 0) {
      showToast('No valid base words found.', 'warning');
      return;
    }

    // Parse custom affixes
    const customPrefixes = customPrefixEl.value
      .split(',')
      .map(s => s.trim())
      .filter(s => s.length > 0);

    const customSuffixes = customSuffixEl.value
      .split(',')
      .map(s => s.trim())
      .filter(s => s.length > 0);

    // Collect all generated words
    const wordSet = new Set();

    for (const word of baseWords) {
      // Always include the original
      wordSet.add(word);

      // Apply active mutation rules
      if (activeRules.has('leet')) {
        for (const v of leetSpeak(word)) wordSet.add(v);
      }
      if (activeRules.has('case')) {
        for (const v of caseVariants(word)) wordSet.add(v);
      }
      if (activeRules.has('numbers')) {
        for (const v of numberSuffix(word)) wordSet.add(v);
      }
      if (activeRules.has('specials')) {
        for (const v of specialSuffix(word)) wordSet.add(v);
      }
      if (activeRules.has('reverse')) {
        for (const v of reverseWord(word)) wordSet.add(v);
      }
      if (activeRules.has('duplicate')) {
        for (const v of duplicateWord(word)) wordSet.add(v);
      }
      if (activeRules.has('prefix')) {
        for (const v of commonPrefix(word)) wordSet.add(v);
      }
      if (activeRules.has('year')) {
        for (const v of yearAppend(word)) wordSet.add(v);
      }

      // Custom prefixes
      for (const p of customPrefixes) {
        wordSet.add(p + word);
      }
      // Custom suffixes
      for (const s of customSuffixes) {
        wordSet.add(word + s);
      }

      // Cross-mutations: leet + numbers (limited combo for power users)
      if (activeRules.has('leet') && activeRules.has('numbers')) {
        const leetVariants = leetSpeak(word).slice(0, 3); // limit for perf
        for (const lv of leetVariants) {
          wordSet.add(lv + '1');
          wordSet.add(lv + '123');
          wordSet.add(lv + '!');
        }
      }

      // Cross: case + numbers
      if (activeRules.has('case') && activeRules.has('numbers')) {
        const cap = word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
        wordSet.add(cap + '1');
        wordSet.add(cap + '123');
        wordSet.add(cap + '!');
        wordSet.add(word.toUpperCase() + '1');
      }

      // Cross: year + specials
      if (activeRules.has('year') && activeRules.has('specials')) {
        wordSet.add(word + '2024!');
        wordSet.add(word + '2025!');
        wordSet.add(word + '2024@');
        wordSet.add(word + '2025@');
      }
    }

    // Convert to sorted array
    const result = [...wordSet];
    const outputText = result.join('\n');

    // Render to terminal
    outputEl.value = outputText;

    // Update stats
    const sizeBytes = new Blob([outputText]).size;
    lineCountEl.textContent = result.length.toLocaleString();
    uniqueCountEl.textContent = result.length.toLocaleString();
    sizeEl.textContent = formatBytes(sizeBytes);
    statsEl.classList.remove('hidden');
    statsEl.classList.add('flex');

    // Enable action buttons
    copyBtn.disabled = false;
    downloadBtn.disabled = false;
    clearOutputBtn.disabled = false;

    showToast(`Generated ${result.length.toLocaleString()} unique words from ${baseWords.length} seed(s).`, 'success');
  }


  // ═══════════════════════════════════════════════════════════════
  //  UTILITY FUNCTIONS
  // ═══════════════════════════════════════════════════════════════

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
  }

  /**
   * Minimalist toast notification.
   */
  function showToast(message, type = 'info') {
    const existing = document.getElementById('wl-toast');
    if (existing) existing.remove();

    const colors = {
      success: 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300',
      warning: 'border-amber-500/50 bg-amber-500/10 text-amber-300',
      error:   'border-rose-500/50 bg-rose-500/10 text-rose-300',
      info:    'border-cyan-500/50 bg-cyan-500/10 text-cyan-300',
    };

    const icons = {
      success: 'check-circle',
      warning: 'alert-triangle',
      error:   'x-circle',
      info:    'info',
    };

    const toast = document.createElement('div');
    toast.id = 'wl-toast';
    toast.className = `fixed bottom-6 right-6 z-[200] flex items-center gap-2.5 px-5 py-3 rounded-xl border ${colors[type]} text-xs font-medium shadow-2xl shadow-black/50 backdrop-blur-xl animate-fade-in`;
    toast.innerHTML = `
      <i data-lucide="${icons[type]}" class="w-4 h-4 shrink-0"></i>
      <span>${message}</span>
    `;
    document.body.appendChild(toast);
    if (window.lucide) lucide.createIcons({ nodes: [toast] });

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(8px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }


  // ═══════════════════════════════════════════════════════════════
  //  EVENT LISTENERS
  // ═══════════════════════════════════════════════════════════════

  // Seed word counter
  baseWordsEl.addEventListener('input', () => {
    const lines = baseWordsEl.value.split('\n').filter(l => l.trim().length > 0);
    seedCountEl.textContent = lines.length;
  });

  // Clear seeds
  clearSeedsBtn.addEventListener('click', () => {
    baseWordsEl.value = '';
    seedCountEl.textContent = '0';
    baseWordsEl.focus();
  });

  // Mutation toggle clicks
  document.querySelectorAll('.mutation-toggle').forEach(toggle => {
    toggle.addEventListener('click', () => {
      const rule = toggle.dataset.rule;
      toggle.classList.toggle('active');
      if (activeRules.has(rule)) {
        activeRules.delete(rule);
      } else {
        activeRules.add(rule);
      }
    });
  });

  // Generate button
  generateBtn.addEventListener('click', () => {
    generateBtn.disabled = true;
    const originalHtml = generateBtn.innerHTML;
    generateBtn.innerHTML = `
      <svg class="animate-spin w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
      </svg>
      <span>Generating...</span>
    `;

    // Slight delay for UI feedback
    setTimeout(() => {
      generateWordlist();
      generateBtn.innerHTML = originalHtml;
      generateBtn.disabled = false;
      if (window.lucide) lucide.createIcons({ nodes: [generateBtn] });
    }, 150);
  });

  // Copy to clipboard
  copyBtn.addEventListener('click', async () => {
    const text = outputEl.value;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const original = copyBtn.innerHTML;
      copyBtn.innerHTML = `
        <i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i>
        <span class="text-emerald-400">Copied!</span>
      `;
      if (window.lucide) lucide.createIcons({ nodes: [copyBtn] });
      setTimeout(() => {
        copyBtn.innerHTML = original;
        if (window.lucide) lucide.createIcons({ nodes: [copyBtn] });
      }, 2000);
    } catch {
      showToast('Failed to copy — try selecting text manually.', 'error');
    }
  });

  // Download as .txt
  downloadBtn.addEventListener('click', () => {
    const text = outputEl.value;
    if (!text) return;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sudodeck_wordlist_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Wordlist downloaded successfully.', 'success');
  });

  // Clear output
  clearOutputBtn.addEventListener('click', () => {
    outputEl.value = '';
    lineCountEl.textContent = '0';
    sizeEl.textContent = '0 B';
    uniqueCountEl.textContent = '0';
    statsEl.classList.add('hidden');
    statsEl.classList.remove('flex');
    copyBtn.disabled = true;
    downloadBtn.disabled = true;
    clearOutputBtn.disabled = true;
  });

  // ── Init Lucide Icons ──────────────────────────────────────────
  if (window.lucide) lucide.createIcons();

})();
