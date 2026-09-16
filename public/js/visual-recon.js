// ══════════════════════════════════════════════════════════════════
//  SudoDeck — Visual Recon & Image Geolocation Logic
//  Client-Side EXIF GPS reader + Tesseract.js OCR Landmark Extraction
// ══════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // DOM Elements
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const selectFileBtn = document.getElementById('select-file-btn');
  const resultsContainer = document.getElementById('results-container');
  const statusContainer = document.getElementById('status-container');
  const statusText = document.getElementById('status-text');
  const progressBar = document.getElementById('progress-bar');
  const progressPercent = document.getElementById('progress-percent');
  const errorAlert = document.getElementById('error-alert');

  // Preview elements
  const imagePreview = document.getElementById('image-preview');
  const previewFileName = document.getElementById('preview-file-name');
  const previewFileSize = document.getElementById('preview-file-size');

  // GPS elements
  const gpsBadge = document.getElementById('gps-badge');
  const gpsDetailsLocked = document.getElementById('gps-details-locked');
  const gpsDetailsNone = document.getElementById('gps-details-none');
  const coordsDisplay = document.getElementById('coords-display');
  const btnCopyCoords = document.getElementById('btn-copy-coords');
  const btnGoogleMaps = document.getElementById('btn-google-maps');
  const mapFrame = document.getElementById('map-frame');

  // OCR elements
  const ocrConfidence = document.getElementById('ocr-confidence');
  const landmarksContainer = document.getElementById('landmarks-container');
  const landmarksTags = document.getElementById('landmarks-tags');
  const ocrRawText = document.getElementById('ocr-raw-text');
  const btnCopyOcr = document.getElementById('btn-copy-ocr');

  // Metadata Table Elements
  const metaMake = document.getElementById('meta-make');
  const metaModel = document.getElementById('meta-model');
  const metaDateTime = document.getElementById('meta-datetime');
  const metaDimensions = document.getElementById('meta-dimensions');
  const metaFileSize = document.getElementById('meta-filesize');
  const metaExposure = document.getElementById('meta-exposure');
  const metaFNumber = document.getElementById('meta-fnumber');
  const metaIso = document.getElementById('meta-iso');
  const metaFocal = document.getElementById('meta-focal');
  const metaSoftware = document.getElementById('meta-software');

  // Demo buttons
  const demoGpsBtn = document.getElementById('demo-gps-btn');
  const demoOcrBtn = document.getElementById('demo-ocr-btn');

  let currentGps = null;
  let currentOcrText = '';

  // Helpers
  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const KNOWN_STORE_PATTERNS = [
    /\b(Bravo|Bazarstore|Araz|Grandmart|Neptun|Oba|Almarket|Rahat|Bolmart|Spar|Carrefour)\b/gi,
    /\b(Aptek|Pharmacy|Apotheke|Eczane|Zeferan|Zeytun|Kanun)\b/gi,
    /\b(Baku|Ganja|Sumqayit|Quba|Sheki|Lankaran|Shusha|Khankendi|Yasamal|Nasimi|Sabayil|Narimanov)\b/gi,
    /\b(Kuc|Kucesi|Küç|Küçəsi|Pr|Prospekti|Prospekt|Street|St|Ave|Avenue|Road|Rd|Bulvar|Boulevard)\b/gi,
    /\b(Bank|Kapital|Pasha|ABB|UniBank|AccessBank|ExpressBank|Yelo|Rabitabank|ATM)\b/gi,
    /\b(Metro|Stansiya|Vagzal|Airport|Aeroport|Terminal)\b/gi,
    /\b(Hotel|Resort|Plaza|Mall|Center|Centre|Restoran|Restaurant|Cafe|Coffee)\b/gi,
    /\b(SOCAR|Azpetrol|Lukoil|BP|Total|Shell)\b/gi,
  ];

  const extractLandmarks = (text) => {
    if (!text) return [];
    const landmarks = new Set();
    KNOWN_STORE_PATTERNS.forEach((pattern) => {
      const matches = text.match(pattern);
      if (matches) {
        matches.forEach((m) => landmarks.add(m.trim()));
      }
    });

    const capitalizedMatches = text.match(/\b[A-ZƏÖĞÇŞIİ][a-zəöğçşıi]{2,}(?:\s+[A-ZƏÖĞÇŞIİ][a-zəöğçşıi]{2,})*\b/g);
    if (capitalizedMatches) {
      capitalizedMatches.forEach((word) => {
        const clean = word.trim();
        if (clean.length > 3 && !['This', 'With', 'From', 'Have', 'They', 'Date'].includes(clean)) {
          landmarks.add(clean);
        }
      });
    }

    return Array.from(landmarks).slice(0, 10);
  };

  const setProgress = (percent, message) => {
    statusContainer.classList.remove('hidden');
    progressPercent.textContent = `${percent}%`;
    progressBar.style.width = `${percent}%`;
    statusText.textContent = message;
  };

  const showError = (msg) => {
    errorAlert.textContent = msg;
    errorAlert.classList.remove('hidden');
  };

  const hideError = () => {
    errorAlert.classList.add('hidden');
  };

  // Process File
  const processImage = async (file) => {
    hideError();
    if (!file || !file.type.startsWith('image/')) {
      showError('Zəhmət olmasa düzgün şəkil formatı seçin (JPEG, PNG, WEBP, TIFF, HEIC).');
      return;
    }

    resultsContainer.classList.remove('hidden');
    setProgress(15, 'Şəkil yüklənir və EXIF metadata oxunur...');

    const objectUrl = URL.createObjectURL(file);
    imagePreview.src = objectUrl;
    previewFileName.textContent = file.name;
    previewFileSize.textContent = formatBytes(file.size);
    metaFileSize.textContent = `${formatBytes(file.size)} (${file.type})`;

    // Reset fields
    currentGps = null;
    currentOcrText = '';
    metaMake.textContent = 'Məlumat yoxdur';
    metaModel.textContent = 'Məlumat yoxdur';
    metaDateTime.textContent = 'Məlumat yoxdur';
    metaDimensions.textContent = 'Hesablanır...';
    metaExposure.textContent = 'Məlumat yoxdur';
    metaFNumber.textContent = 'Məlumat yoxdur';
    metaIso.textContent = 'Məlumat yoxdur';
    metaFocal.textContent = 'Məlumat yoxdur';
    metaSoftware.textContent = 'Standart Firmware';

    // 1. Natural Dimensions
    const imgObj = new Image();
    imgObj.src = objectUrl;
    imgObj.onload = () => {
      metaDimensions.textContent = `${imgObj.naturalWidth} × ${imgObj.naturalHeight} px`;
    };

    // 2. EXIF & GPS Reader
    try {
      if (window.exifr) {
        const exifData = await window.exifr.parse(file, {
          tiff: true,
          xmp: true,
          jfif: true,
          ihdr: true,
          gps: true,
        });

        if (exifData) {
          if (exifData.Make || exifData.make) metaMake.textContent = exifData.Make || exifData.make;
          if (exifData.Model || exifData.model) metaModel.textContent = exifData.Model || exifData.model;
          if (exifData.Software || exifData.software) metaSoftware.textContent = exifData.Software || exifData.software;

          if (exifData.DateTimeOriginal) {
            metaDateTime.textContent = new Date(exifData.DateTimeOriginal).toLocaleString();
          } else if (exifData.CreateDate) {
            metaDateTime.textContent = new Date(exifData.CreateDate).toLocaleString();
          }

          if (exifData.ExposureTime) {
            metaExposure.textContent = `1/${Math.round(1 / exifData.ExposureTime)}s (${exifData.ExposureTime}s)`;
          }
          if (exifData.FNumber) {
            metaFNumber.textContent = `f/${exifData.FNumber}`;
          }
          if (exifData.ISO) {
            metaIso.textContent = `ISO ${exifData.ISO}`;
          }
          if (exifData.FocalLength) {
            metaFocal.textContent = `${exifData.FocalLength} mm`;
          }
          if (exifData.ExifImageWidth && exifData.ExifImageHeight) {
            metaDimensions.textContent = `${exifData.ExifImageWidth} × ${exifData.ExifImageHeight} px`;
          }
        }

        // GPS Check
        const gps = await window.exifr.gps(file);
        if (gps && typeof gps.latitude === 'number' && typeof gps.longitude === 'number') {
          currentGps = {
            latitude: Number(gps.latitude.toFixed(6)),
            longitude: Number(gps.longitude.toFixed(6)),
          };
          renderGps(currentGps);
        } else {
          renderNoGps();
        }
      } else {
        renderNoGps();
      }
    } catch (exifErr) {
      console.warn('EXIF parse error:', exifErr);
      renderNoGps();
    }

    // 3. OCR Text Extraction with Tesseract.js
    setProgress(35, 'Tesseract OCR mühərriki başladılır və lövhələr analiz edilir...');

    try {
      if (window.Tesseract) {
        const worker = await window.Tesseract.recognize(file, 'eng+aze+rus', {
          logger: (m) => {
            if (m.status === 'recognizing text' && typeof m.progress === 'number') {
              const pct = 35 + Math.round(m.progress * 60);
              setProgress(pct, `Şəkildəki yazılar və mağaza adları oxunur: ${Math.round(m.progress * 100)}%`);
            }
          },
        });

        const text = worker.data?.text || '';
        const confidence = Math.round(worker.data?.confidence || 0);
        currentOcrText = text.trim();

        ocrConfidence.textContent = `${confidence}%`;
        ocrRawText.textContent = currentOcrText || 'Şəkildə oxuna bilən aydın mətn tapılmadı.';

        const landmarks = extractLandmarks(currentOcrText);
        renderLandmarks(landmarks);

        setProgress(100, 'Analiz tamamlandı.');
        setTimeout(() => {
          statusContainer.classList.add('hidden');
        }, 1500);
      } else {
        ocrConfidence.textContent = 'Offline';
        ocrRawText.textContent = 'Tesseract.js OCR kitabxanası yüklənmədi.';
        setProgress(100, 'EXIF tamamlandı.');
      }
    } catch (ocrErr) {
      console.error('OCR Error:', ocrErr);
      ocrConfidence.textContent = '0%';
      ocrRawText.textContent = 'OCR oxunması zamanı xəta baş verdi: ' + ocrErr.message;
      setProgress(100, 'Tamamlandı (OCR xətası).');
    }

    if (window.lucide) {
      window.lucide.createIcons();
    }
  };

  const renderGps = (coords) => {
    gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
    gpsBadge.textContent = 'GPS LOCKED';

    gpsDetailsLocked.classList.remove('hidden');
    gpsDetailsNone.classList.add('hidden');

    coordsDisplay.textContent = `${coords.latitude}, ${coords.longitude}`;
    btnGoogleMaps.href = `https://www.google.com/maps?q=${coords.latitude},${coords.longitude}`;

    // OpenStreetMap preview
    const bboxLeft = coords.longitude - 0.008;
    const bboxBottom = coords.latitude - 0.005;
    const bboxRight = coords.longitude + 0.008;
    const bboxTop = coords.latitude + 0.005;
    mapFrame.src = `https://www.openstreetmap.org/export/embed.html?bbox=${bboxLeft}%2C${bboxBottom}%2C${bboxRight}%2C${bboxTop}&layer=mapnik&marker=${coords.latitude}%2C${coords.longitude}`;
  };

  const renderNoGps = () => {
    gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40';
    gpsBadge.textContent = 'NO EMBEDDED GPS';

    gpsDetailsLocked.classList.add('hidden');
    gpsDetailsNone.classList.remove('hidden');
  };

  const renderLandmarks = (landmarks) => {
    if (!landmarks || landmarks.length === 0) {
      landmarksContainer.classList.add('hidden');
      landmarksTags.innerHTML = '';
      return;
    }

    landmarksContainer.classList.remove('hidden');
    landmarksTags.innerHTML = '';

    landmarks.forEach((name) => {
      const tag = document.createElement('a');
      tag.href = `https://www.google.com/search?q=${encodeURIComponent(name + ' Baku')}`;
      tag.target = '_blank';
      tag.rel = 'noopener noreferrer';
      tag.className = 'inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-xs font-mono font-medium text-amber-300 hover:text-amber-200 transition-colors shadow-sm';
      tag.innerHTML = `<span>📍 ${name}</span><span class="text-[10px] text-amber-400/60">↗</span>`;
      landmarksTags.appendChild(tag);
    });
  };

  // Copy coordinates
  btnCopyCoords.addEventListener('click', () => {
    if (currentGps) {
      navigator.clipboard.writeText(`${currentGps.latitude}, ${currentGps.longitude}`);
      btnCopyCoords.textContent = '✓ Kopyalandı';
      setTimeout(() => {
        btnCopyCoords.textContent = 'Kopyala';
      }, 2000);
    }
  });

  // Copy OCR text
  btnCopyOcr.addEventListener('click', () => {
    if (currentOcrText) {
      navigator.clipboard.writeText(currentOcrText);
      btnCopyOcr.textContent = '✓ Kopyalandı';
      setTimeout(() => {
        btnCopyOcr.textContent = 'Mətni Kopyala';
      }, 2000);
    }
  });

  // Drag & drop handlers
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('border-emerald-400', 'bg-emerald-500/10');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('border-emerald-400', 'bg-emerald-500/10');
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('border-emerald-400', 'bg-emerald-500/10');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processImage(e.dataTransfer.files[0]);
    }
  });

  selectFileBtn.addEventListener('click', () => {
    fileInput.click();
  });

  dropzone.addEventListener('click', (e) => {
    if (e.target !== selectFileBtn) {
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      processImage(e.target.files[0]);
    }
  });

  // Demo Sample Loaders
  demoGpsBtn.addEventListener('click', () => {
    hideError();
    resultsContainer.classList.remove('hidden');
    setProgress(100, 'Nümunə GPS analiz məlumatları yükləndi.');
    setTimeout(() => statusContainer.classList.add('hidden'), 1000);

    imagePreview.src = 'https://images.unsplash.com/photo-1579546929518-9e396f3cc809?w=900&auto=format&fit=crop&q=80';
    previewFileName.textContent = 'target_recon_baku_boulevard.jpg';
    previewFileSize.textContent = '2.34 MB';

    metaMake.textContent = 'Apple';
    metaModel.textContent = 'iPhone 15 Pro Max';
    metaDateTime.textContent = '2026-08-14 17:42:09';
    metaDimensions.textContent = '4032 × 3024 px';
    metaFileSize.textContent = '2.34 MB (image/jpeg)';
    metaExposure.textContent = '1/1250s (0.0008s)';
    metaFNumber.textContent = 'f/1.78';
    metaIso.textContent = 'ISO 64';
    metaFocal.textContent = '24 mm';
    metaSoftware.textContent = 'iOS 18.2.1';

    currentGps = { latitude: 40.370556, longitude: 49.845833 };
    renderGps(currentGps);

    currentOcrText = 'BAKU BOULEVARD SEASIDE NATIONAL PARK\nBazarstore Express\nDeniz Mall Entrance 2\nAZ1000 Baku Azerbaijan';
    ocrConfidence.textContent = '94%';
    ocrRawText.textContent = currentOcrText;
    renderLandmarks(['Bazarstore', 'Deniz Mall', 'Baku', 'Boulevard']);
  });

  demoOcrBtn.addEventListener('click', () => {
    hideError();
    resultsContainer.classList.remove('hidden');
    setProgress(100, 'Nümunə mağaza və OCR lövhə analizi yükləndi.');
    setTimeout(() => statusContainer.classList.add('hidden'), 1000);

    imagePreview.src = 'https://images.unsplash.com/photo-1555396273-367ea4eb4db5?w=900&auto=format&fit=crop&q=80';
    previewFileName.textContent = 'commercial_strip_recon_target.jpg';
    previewFileSize.textContent = '1.74 MB';

    metaMake.textContent = 'Samsung';
    metaModel.textContent = 'Galaxy S24 Ultra';
    metaDateTime.textContent = '2026-09-02 12:15:33';
    metaDimensions.textContent = '3840 × 2160 px';
    metaFileSize.textContent = '1.74 MB (image/jpeg)';
    metaExposure.textContent = '1/640s (0.0015s)';
    metaFNumber.textContent = 'f/1.7';
    metaIso.textContent = 'ISO 50';
    metaFocal.textContent = '23 mm';
    metaSoftware.textContent = 'OneUI 6.1';

    currentGps = null;
    renderNoGps();

    currentOcrText = 'BRAVO HYPERMARKET\nZəfəran Aptek 24/7\nKapital Bank ATM 048\nFətəli Xan Xoyski Prospekti 14';
    ocrConfidence.textContent = '91%';
    ocrRawText.textContent = currentOcrText;
    renderLandmarks(['Bravo', 'Zəfəran', 'Aptek', 'Kapital Bank', 'Xoyski Prospekti']);
  });
});
