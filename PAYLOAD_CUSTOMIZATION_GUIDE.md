# SudoDeck Security Payload Manager — Developer & Customization Guide

This document provides complete instructions for engineers to add, modify, or extend custom payload wordlists, downloadable `.txt` files, and database test vectors within the SudoDeck platform.

---

## 1. Architecture Overview

The SudoDeck Payload Manager operates across two layers:
1. **Interactive Searchable Terminal (API-driven):**
   - Served via `/api/payloads` (implemented in both Express `services/payloads.service.js` and Next.js App Router `app/api/payloads/route.ts`).
   - Supports category filtering (`XSS`, `SQLi`, `Traversal`, `CSRF`), instant search, and one-click clipboard copying.
2. **Static Wordlists & Downloadable TXT Repository:**
   - Files are stored in `threat-intel-node/public/downloads/payloads/`.
   - Express statically serves everything in `public/`, making files directly accessible at `/downloads/payloads/<filename>.txt`.
   - Users can either preview files in a browser modal reader (`openTxtViewerModal`) or download them directly using HTML5 `download` anchors.

---

## 2. Directory Structure

```text
Thread Intel/
└── threat-intel-node/
    ├── app/
    │   └── api/
    │       └── payloads/
    │           └── route.ts          <-- Next.js API route definition
    ├── public/
    │   ├── downloads/
    │   │   └── payloads/             <-- Directory for raw .txt wordlists
    │   │       ├── oracle_sqli.txt
    │   │       ├── sqlite_sqli.txt
    │   │       ├── postgres_sqli.txt
    │   │       └── ...
    │   ├── js/
    │   │   └── payloads.js           <-- Client logic (modal reader, filtering, copy)
    │   └── payloads.html             <-- Payload Manager UI page
    ├── routes/
    │   └── payloads.routes.js        <-- Express router mounting /api/payloads
    └── services/
        └── payloads.service.js       <-- Core vector catalog & filtering logic
```

---

## 3. How to Add New Downloadable TXT Files

### Step 1: Place the `.txt` File in Public Downloads
Create or copy your plain text file into:
`threat-intel-node/public/downloads/payloads/<your_filename>.txt`

*Example:* `threat-intel-node/public/downloads/payloads/custom_db_test.txt`

### Step 2: Add a UI Card to `public/payloads.html`
Open `threat-intel-node/public/payloads.html` and locate the `#sqli-txt-files-section` grid. Insert a new card following this standard template:

```html
<div class="p-3.5 rounded-xl bg-[#070b14]/90 border border-slate-800 hover:border-purple-500/40 transition-all flex flex-col justify-between group">
  <div>
    <div class="flex items-start justify-between gap-2 mb-2">
      <div class="flex items-center gap-2">
        <span class="p-1.5 rounded-lg bg-purple-500/15 text-purple-400 border border-purple-500/20">
          <i data-lucide="database" class="w-4 h-4"></i>
        </span>
        <span class="text-xs font-bold font-mono text-white group-hover:text-purple-300 transition-colors">
          custom_db_test.txt
        </span>
      </div>
      <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">Database</span>
    </div>
    <p class="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
      Brief description of the test vectors or wordlist contents.
    </p>
  </div>
  <div class="flex items-center gap-2 mt-3 pt-2.5 border-t border-slate-800/80">
    <!-- Modal Preview Button -->
    <button
      type="button"
      onclick="openTxtViewerModal('custom_db_test.txt', 'Custom Database Test Vectors')"
      class="flex-1 py-1.5 px-2 rounded-lg bg-surface-800 hover:bg-purple-500/20 text-slate-300 hover:text-purple-300 border border-slate-700 hover:border-purple-500/40 text-[11px] font-mono flex items-center justify-center gap-1.5 transition-all"
    >
      <i data-lucide="eye" class="w-3.5 h-3.5"></i>
      <span>View / Read</span>
    </button>
    <!-- Direct Download Button -->
    <a
      href="/downloads/payloads/custom_db_test.txt"
      download="custom_db_test.txt"
      class="py-1.5 px-3 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-[11px] font-mono font-medium flex items-center justify-center gap-1.5 transition-all shadow-sm shadow-purple-600/30"
    >
      <i data-lucide="download" class="w-3.5 h-3.5"></i>
      <span>Download</span>
    </a>
  </div>
</div>
```

---

## 4. How to Add New Payloads to the Interactive Terminal

### Adding to Backend Service (`services/payloads.service.js`)
Locate `FALLBACK_PAYLOADS` array and append a new vector object:

```javascript
{
  id: 'sqli-custom-1',
  category: 'SQLi',
  title: 'Custom Time-based Blind SQLi Probe',
  payload: "'; WAITFOR DELAY '0:0:5'--",
  description: 'Audits thread suspension on Microsoft SQL Server targets.',
  source: 'SecLists / Custom'
}
```

---

## 5. Verification & Testing

1. Start or verify the development server:
   ```bash
   cd threat-intel-node
   npm run dev
   ```
2. Check HTTP availability of the static text file:
   ```bash
   curl -I http://localhost:3000/downloads/payloads/custom_db_test.txt
   ```
3. Open `http://localhost:3000/payloads` in a web browser:
   - Confirm the new card is rendered in the repository grid.
   - Click **"View / Read"** to verify the in-page terminal modal displays the full file contents.
   - Click **"Download"** to confirm the browser downloads the file with the correct filename and encoding.
