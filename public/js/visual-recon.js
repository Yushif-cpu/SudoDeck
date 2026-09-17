// ══════════════════════════════════════════════════════════════════
//  SudoDeck — Visual Recon & Image Geolocation Logic
//  Client-Side EXIF GPS + Canvas Enhancement + Tesseract OCR + Nominatim Geocoding + Sun/Shadow
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
  const btnViewOriginal = document.getElementById('btn-view-original');
  const btnViewEnhanced = document.getElementById('btn-view-enhanced');
  const previewBadgeMode = document.getElementById('preview-badge-mode');
  const btnRerunOriginalOcr = document.getElementById('btn-rerun-original-ocr');
  const btnRerunEnhancedOcr = document.getElementById('btn-rerun-enhanced-ocr');

  // GPS elements
  const gpsBadge = document.getElementById('gps-badge');
  const gpsDetailsLocked = document.getElementById('gps-details-locked');
  const gpsDetailsNone = document.getElementById('gps-details-none');
  const coordsDisplay = document.getElementById('coords-display');
  const btnCopyCoords = document.getElementById('btn-copy-coords');
  const btnGoogleMaps = document.getElementById('btn-google-maps');
  const btnOsmMaps = document.getElementById('btn-osm-maps');
  const mapFrame = document.getElementById('map-frame');

  // Sun & Shadow Chronolocation elements
  const chronoContainer = document.getElementById('chrono-container');
  const chronoTime = document.getElementById('chrono-time');
  const chronoSunAzimuth = document.getElementById('chrono-sun-azimuth');
  const chronoShadowVector = document.getElementById('chrono-shadow-vector');
  const chronoShadowRatio = document.getElementById('chrono-shadow-ratio');
  const chronoReliability = document.getElementById('chrono-reliability');
  const chronoGuidance = document.getElementById('chrono-guidance');

  // Nominatim Suggested Locations elements
  const suggestedLocationsContainer = document.getElementById('suggested-locations-container');
  const locationsGrid = document.getElementById('locations-grid');
  const locationsEmptyMsg = document.getElementById('locations-empty-msg');
  const osmSearchInput = document.getElementById('osm-search-input');
  const osmSearchBtn = document.getElementById('osm-search-btn');

  // OCR elements
  const ocrConfidence = document.getElementById('ocr-confidence');
  const landmarksContainer = document.getElementById('landmarks-container');
  const landmarksTags = document.getElementById('landmarks-tags');
  const proximityContainer = document.getElementById('proximity-container');
  const proximityTags = document.getElementById('proximity-tags');
  const ocrRawText = document.getElementById('ocr-raw-text');
  const btnCopyOcr = document.getElementById('btn-copy-ocr');
  const btnGoogleSearchText = document.getElementById('btn-google-search-text');

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

  let originalImageSrc = '';
  let enhancedImageSrc = '';
  let currentFileBlob = null;
  let currentGps = null;
  let currentOcrText = '';
  let currentLandmarks = [];
  let suggestedLocationsList = [];

  // Helpers
  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const copyToClipboard = (text, triggerBtn, successText = 'Kopyalandı!') => {
    navigator.clipboard.writeText(text).then(() => {
      const original = triggerBtn.textContent;
      triggerBtn.textContent = successText;
      triggerBtn.classList.add('text-[#00C897]', 'border-[#00C897]');
      setTimeout(() => {
        triggerBtn.textContent = original;
        triggerBtn.classList.remove('text-[#00C897]', 'border-[#00C897]');
      }, 2000);
    });
  };

  const KNOWN_STORE_PATTERNS = [
    /\b(Bravo|Bazarstore|Araz|Grandmart|Neptun|Oba|Almarket|Rahat|Bolmart|Spar|Carrefour)\b/gi,
    /\b(Aptek|Pharmacy|Apotheke|Eczane|Zeferan|Zeytun|Kanun)\b/gi,
    /\b(Baku|Bakı|Ganja|Gəncə|Sumqayit|Sumqayıt|Quba|Sheki|Şəki|Lankaran|Lənkəran|Shusha|Şuşa|Khankendi|Xankəndi|Yasamal|Nasimi|Nəsimi|Sabayil|Səbail|Narimanov|Nərimanov)\b/gi,
    /\b(Kuc|Kucesi|Küç|Küçəsi|Pr|Prospekti|Prospekt|Street|St|Ave|Avenue|Road|Rd|Bulvar|Boulevard)\b/gi,
    /\b(Bank|Kapital|Pasha|Paşa|ABB|UniBank|AccessBank|ExpressBank|Yelo|Rabitabank|ATM)\b/gi,
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

    return Array.from(landmarks).slice(0, 12);
  };

  // Degrees to Cardinal
  function degreesToCardinal(deg) {
    const directions = ['Şimal (N)', 'Şimal-Şərq (NE)', 'Şərq (E)', 'Cənub-Şərq (SE)', 'Cənub (S)', 'Cənub-Qərb (SW)', 'Qərb (W)', 'Şimal-Qərb (NW)'];
    const index = Math.round(((deg % 360) + 360) % 360 / 45) % 8;
    return directions[index];
  }

  // Calculate Solar Position & Shadow Vector
  function calculateSunAndShadow(date, lat, lon) {
    const dayOfYear = Math.floor((date.getTime() - new Date(date.getFullYear(), 0, 0).getTime()) / 86400000);
    const hours = date.getHours() + date.getMinutes() / 60 + date.getSeconds() / 3600;

    const declination = 23.45 * Math.sin(((284 + dayOfYear) / 365) * 2 * Math.PI);
    const decRad = (declination * Math.PI) / 180;
    const latRad = (lat * Math.PI) / 180;

    const solarHourAngle = (hours - 12) * 15;
    const hourAngleRad = (solarHourAngle * Math.PI) / 180;

    const sinElevation = Math.sin(latRad) * Math.sin(decRad) + Math.cos(latRad) * Math.cos(decRad) * Math.cos(hourAngleRad);
    const elevationRad = Math.asin(Math.max(-1, Math.min(1, sinElevation)));
    const sunElevationDeg = Math.round((elevationRad * 180) / Math.PI * 10) / 10;

    const cosAzimuth = (Math.sin(decRad) - Math.sin(latRad) * Math.sin(elevationRad)) / (Math.cos(latRad) * Math.cos(elevationRad));
    let azimuthDeg = (Math.acos(Math.max(-1, Math.min(1, cosAzimuth))) * 180) / Math.PI;
    if (solarHourAngle > 0) azimuthDeg = 360 - azimuthDeg;
    const sunAzimuthDeg = Math.round(azimuthDeg * 10) / 10;

    const shadowAzimuthDeg = Math.round((sunAzimuthDeg + 180) % 360 * 10) / 10;
    let shadowLengthRatio = 0;
    if (sunElevationDeg > 0) {
      shadowLengthRatio = Math.round((1 / Math.tan(elevationRad)) * 100) / 100;
    }

    return {
      sunElevationDeg,
      sunAzimuthDeg,
      shadowAzimuthDeg,
      shadowLengthRatio,
      cardinalDirection: degreesToCardinal(sunAzimuthDeg),
      shadowCardinalDirection: degreesToCardinal(shadowAzimuthDeg),
      formattedTime: date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      isNight: sunElevationDeg <= 0,
    };
  }

  // Canvas Image Enhancement
  const enhanceImageViaCanvas = (sourceUrl) => {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          if (!ctx) throw new Error('Canvas 2D context unavailable');

          let width = img.naturalWidth;
          let height = img.naturalHeight;

          if (width < 1000) {
            const scale = Math.min(2, 1600 / width);
            width = Math.round(width * scale);
            height = Math.round(height * scale);
          } else if (width > 2200) {
            const scale = 2200 / width;
            width = Math.round(width * scale);
            height = Math.round(height * scale);
          }

          canvas.width = width;
          canvas.height = height;
          ctx.drawImage(img, 0, 0, width, height);

          const imgData = ctx.getImageData(0, 0, width, height);
          const d = imgData.data;

          let minLum = 255;
          let maxLum = 0;
          for (let i = 0; i < d.length; i += 4) {
            const lum = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
            if (lum < minLum) minLum = lum;
            if (lum > maxLum) maxLum = lum;
          }

          const range = Math.max(1, maxLum - minLum);
          const contrastFactor = 1.35;

          for (let i = 0; i < d.length; i += 4) {
            let lum = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
            lum = ((lum - minLum) / range) * 255;
            lum = (lum - 128) * contrastFactor + 128;
            lum = Math.max(0, Math.min(255, lum));

            d[i] = lum;
            d[i + 1] = lum;
            d[i + 2] = lum;
          }

          ctx.putImageData(imgData, 0, 0);

          canvas.toBlob((blob) => {
            if (!blob) return reject(new Error('Canvas blob generation failed'));
            const dataUrl = canvas.toDataURL('image/png');
            resolve({ dataUrl, blob });
          }, 'image/png');
        } catch (e) {
          reject(e);
        }
      };
      img.onerror = () => reject(new Error('Image failed to load for canvas enhancement'));
      img.src = sourceUrl;
    });
  };

  // Query Nominatim Geocoding
  const queryNominatimGeocode = async (queryPhrase) => {
    if (!queryPhrase || !queryPhrase.trim()) return;
    const phrase = queryPhrase.trim();

    try {
      let results = [];
      try {
        const res = await fetch(`/api/geocode?q=${encodeURIComponent(phrase)}&limit=5`);
        if (res.ok) {
          const data = await res.json();
          if (data.results && Array.isArray(data.results)) {
            results = data.results;
          }
        }
      } catch (_) {}

      if (!results || results.length === 0) {
        const osmRes = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(phrase)}&limit=5&addressdetails=1`, {
          headers: { 'Accept-Language': 'az,en,ru' }
        });
        if (osmRes.ok) {
          const d = await osmRes.json();
          if (Array.isArray(d)) results = d;
        }
      }

      if (results && results.length > 0) {
        const existingIds = new Set(suggestedLocationsList.map(item => item.place_id));
        const fresh = results.filter(item => !existingIds.has(item.place_id));
        suggestedLocationsList = [...fresh, ...suggestedLocationsList].slice(0, 10);
        renderSuggestedLocations();
      }
    } catch (e) {
      console.warn('Geocoding notice:', e);
    }
  };

  const renderSuggestedLocations = () => {
    if (!locationsGrid || !locationsEmptyMsg) return;

    if (suggestedLocationsList.length === 0) {
      locationsGrid.classList.add('hidden');
      locationsEmptyMsg.classList.remove('hidden');
      return;
    }

    locationsEmptyMsg.classList.add('hidden');
    locationsGrid.classList.remove('hidden');
    locationsGrid.innerHTML = '';

    suggestedLocationsList.forEach((loc) => {
      const card = document.createElement('div');
      card.className = 'p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 space-y-3 transition-colors';
      card.innerHTML = `
        <div class="space-y-1">
          <div class="text-xs font-bold text-white line-clamp-2">${loc.display_name}</div>
          <div class="flex items-center gap-2 text-[10px] font-mono text-slate-400">
            <span class="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[#00C897]">
              ${loc.type || loc.category || 'landmark'}
            </span>
            <span>Lat: ${parseFloat(loc.lat).toFixed(5)}, Lon: ${parseFloat(loc.lon).toFixed(5)}</span>
          </div>
        </div>
        <div class="flex items-center gap-2 pt-1 font-mono text-xs">
          <a href="https://www.google.com/maps?q=${loc.lat},${loc.lon}" target="_blank" rel="noreferrer" class="flex-1 text-center py-1.5 rounded-lg bg-[#00C897]/15 hover:bg-[#00C897]/25 text-[#00C897] font-bold transition-colors">
            Google Maps ↗
          </a>
          <a href="https://www.openstreetmap.org/?mlat=${loc.lat}&mlon=${loc.lon}#map=16/${loc.lat}/${loc.lon}" target="_blank" rel="noreferrer" class="flex-1 text-center py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors">
            OpenStreetMap ↗
          </a>
          <button type="button" class="btn-copy-loc px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors" data-coords="${loc.lat}, ${loc.lon}">
            Kopya
          </button>
        </div>
      `;

      card.querySelector('.btn-copy-loc').addEventListener('click', (e) => {
        copyToClipboard(e.currentTarget.getAttribute('data-coords'), e.currentTarget, '✓');
      });

      locationsGrid.appendChild(card);
    });
  };

  // Render Chronolocation
  const renderChronolocation = (date, lat, lon, hasGps) => {
    if (!chronoContainer) return;
    const shadow = calculateSunAndShadow(date, lat, lon);

    chronoTime.textContent = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    chronoSunAzimuth.textContent = `${shadow.sunAzimuthDeg}° (${shadow.cardinalDirection})`;
    chronoShadowVector.textContent = `${shadow.shadowAzimuthDeg}° (${shadow.shadowCardinalDirection})`;
    chronoShadowRatio.textContent = shadow.isNight ? 'Gecə' : `~${shadow.shadowLengthRatio}x`;
    chronoReliability.textContent = hasGps ? 'High (GPS+EXIF)' : 'Estimated (Default Lat)';

    chronoGuidance.innerHTML = `📐 <strong>OSINT İpucu:</strong> Şəkildəki dirək və ya ağacların kölgəsi <span class="text-[#00C897] font-semibold">${shadow.shadowCardinalDirection}</span> tərəfinə düşür (1 m obyekt üçün kölgə ~${shadow.shadowLengthRatio} m).`;
    chronoContainer.classList.remove('hidden');
  };

  // Switch View Mode: Original vs Enhanced
  if (btnViewOriginal) {
    btnViewOriginal.addEventListener('click', () => {
      imagePreview.src = originalImageSrc;
      btnViewOriginal.classList.add('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
      btnViewOriginal.classList.remove('text-slate-400');
      btnViewEnhanced.classList.remove('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
      btnViewEnhanced.classList.add('text-slate-400');
      previewBadgeMode.textContent = '📷 Native View';
    });
  }

  if (btnViewEnhanced) {
    btnViewEnhanced.addEventListener('click', () => {
      if (enhancedImageSrc) {
        imagePreview.src = enhancedImageSrc;
        btnViewEnhanced.classList.add('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
        btnViewEnhanced.classList.remove('text-slate-400');
        btnViewOriginal.classList.remove('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
        btnViewOriginal.classList.add('text-slate-400');
        previewBadgeMode.textContent = '🔬 Canvas High-Contrast OCR Filter';
      }
    });
  }

  // Manual OCR Triggers
  if (btnRerunOriginalOcr) {
    btnRerunOriginalOcr.addEventListener('click', () => runOcrOnSource(originalImageSrc));
  }
  if (btnRerunEnhancedOcr) {
    btnRerunEnhancedOcr.addEventListener('click', () => runOcrOnSource(enhancedImageSrc || originalImageSrc));
  }

  // Custom OSM Search
  if (osmSearchBtn && osmSearchInput) {
    osmSearchBtn.addEventListener('click', () => {
      queryNominatimGeocode(osmSearchInput.value);
    });
    osmSearchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') queryNominatimGeocode(osmSearchInput.value);
    });
  }

  // Run OCR on specific image source
  const runOcrOnSource = async (src) => {
    if (!src || !window.Tesseract) return;
    statusContainer.classList.remove('hidden');
    statusText.textContent = 'Tesseract.js OCR mühərriki işləyir...';
    progressBar.style.width = '20%';
    progressPercent.textContent = '20%';

    try {
      const result = await window.Tesseract.recognize(src, 'eng+aze+rus', {
        logger: (m) => {
          if (m.status === 'recognizing text' && typeof m.progress === 'number') {
            const p = Math.min(Math.round(m.progress * 100), 98);
            progressBar.style.width = `${p}%`;
            progressPercent.textContent = `${p}%`;
            statusText.textContent = `Mətnlər və lövhələr oxunur: ${p}%`;
          }
        },
      });

      currentOcrText = result.data.text || '';
      const confidence = Math.round(result.data.confidence || 0);
      ocrConfidence.textContent = `${confidence}%`;
      ocrRawText.textContent = currentOcrText.trim() || 'Şəkildə aşkar edilən heç bir mətn tapılmadı.';

      currentLandmarks = extractLandmarks(currentOcrText);
      renderLandmarksAndProximity(currentLandmarks);

      for (const lm of currentLandmarks.slice(0, 3)) {
        await queryNominatimGeocode(lm);
      }

      progressBar.style.width = '100%';
      progressPercent.textContent = '100%';
      statusText.textContent = 'Analiz tamamlandı!';
      setTimeout(() => statusContainer.classList.add('hidden'), 2500);
    } catch (err) {
      console.error('OCR Error:', err);
      statusText.textContent = 'OCR zamanı xəta baş verdi.';
    }
  };

  const renderLandmarksAndProximity = (landmarks) => {
    if (landmarks.length > 0) {
      landmarksContainer.classList.remove('hidden');
      landmarksTags.innerHTML = '';
      landmarks.forEach((lm) => {
        const tag = document.createElement('span');
        tag.className = 'px-2.5 py-1 rounded-lg text-xs font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 flex items-center gap-1.5';
        tag.textContent = lm;
        landmarksTags.appendChild(tag);
      });

      if (proximityContainer && proximityTags) {
        proximityContainer.classList.remove('hidden');
        proximityTags.innerHTML = '';
        landmarks.forEach((lm) => {
          const item = document.createElement('div');
          item.className = 'flex items-center gap-1.5 pl-2.5 pr-1.5 py-1 rounded-xl bg-slate-900 border border-slate-700/80 text-xs font-mono';
          item.innerHTML = `
            <span class="text-white font-semibold">${lm}</span>
            <a href="https://www.google.com/maps/search/${encodeURIComponent(lm)}" target="_blank" rel="noreferrer" class="px-1.5 py-0.5 rounded bg-[#00C897]/20 hover:bg-[#00C897]/30 text-[#00C897] text-[10px] font-bold transition-colors">
              GMaps ↗
            </a>
            <button type="button" class="btn-osm-direct px-1.5 py-0.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-[10px] font-bold transition-colors" data-lm="${lm}">
              OSM 🔍
            </button>
          `;
          item.querySelector('.btn-osm-direct').addEventListener('click', (e) => {
            queryNominatimGeocode(e.currentTarget.getAttribute('data-lm'));
          });
          proximityTags.appendChild(item);
        });
      }

      if (btnGoogleSearchText) {
        btnGoogleSearchText.href = `https://www.google.com/search?q=${encodeURIComponent(landmarks.join(' '))}`;
        btnGoogleSearchText.classList.remove('hidden');
      }
    } else {
      landmarksContainer.classList.add('hidden');
      if (proximityContainer) proximityContainer.classList.add('hidden');
      if (btnGoogleSearchText) btnGoogleSearchText.classList.add('hidden');
    }
  };

  // Main File Processor
  const processFile = async (file) => {
    if (!file || !file.type.startsWith('image/')) {
      errorAlert.classList.remove('hidden');
      errorAlert.textContent = 'Zəhmət olmasa etibarlı şəkil formatı seçin (JPEG, PNG, WEBP, TIFF).';
      return;
    }

    errorAlert.classList.add('hidden');
    resultsContainer.classList.remove('hidden');
    statusContainer.classList.remove('hidden');
    statusText.textContent = 'Şəkil yüklənir və EXIF GPS oxunur...';
    progressBar.style.width = '15%';
    progressPercent.textContent = '15%';

    currentFileBlob = file;
    originalImageSrc = URL.createObjectURL(file);
    imagePreview.src = originalImageSrc;
    previewFileName.textContent = file.name;
    previewFileSize.textContent = formatBytes(file.size);
    metaFileSize.textContent = `${formatBytes(file.size)} (${file.type})`;
    previewBadgeMode.textContent = '📷 Native View';

    suggestedLocationsList = [];
    renderSuggestedLocations();

    let captureDate = new Date();
    let hasExplicitDate = false;

    // 1. EXIF via exifr
    try {
      if (window.exifr) {
        const exif = await window.exifr.parse(file, {
          tiff: true,
          xmp: true,
          gps: true,
          jfif: true,
        });

        if (exif) {
          metaMake.textContent = exif.Make || exif.make || 'Tapılmadı';
          metaModel.textContent = exif.Model || exif.model || 'Tapılmadı';
          metaSoftware.textContent = exif.Software || exif.software || 'Standart Firmware';

          if (exif.DateTimeOriginal || exif.CreateDate) {
            captureDate = new Date(exif.DateTimeOriginal || exif.CreateDate);
            hasExplicitDate = true;
            metaDateTime.textContent = captureDate.toLocaleString();
          } else {
            metaDateTime.textContent = 'Məlumat yoxdur';
          }

          if (exif.ExifImageWidth && exif.ExifImageHeight) {
            metaDimensions.textContent = `${exif.ExifImageWidth} × ${exif.ExifImageHeight} px`;
          }
          if (exif.ExposureTime) {
            metaExposure.textContent = exif.ExposureTime < 1 ? `1/${Math.round(1 / exif.ExposureTime)}s` : `${exif.ExposureTime}s`;
          }
          if (exif.FNumber) {
            metaFNumber.textContent = `f/${exif.FNumber}`;
          }
          if (exif.ISO) {
            metaIso.textContent = `ISO ${exif.ISO}`;
          }
          if (exif.FocalLength) {
            metaFocal.textContent = `${exif.FocalLength} mm`;
          }
        }

        const gps = await window.exifr.gps(file);
        if (gps && typeof gps.latitude === 'number' && typeof gps.longitude === 'number') {
          currentGps = {
            latitude: Number(gps.latitude.toFixed(6)),
            longitude: Number(gps.longitude.toFixed(6)),
          };
          coordsDisplay.textContent = `${currentGps.latitude}, ${currentGps.longitude}`;
          gpsBadge.textContent = 'GPS VERIFIED';
          gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#00C897]/20 text-[#00C897] border border-[#00C897]/40';
          gpsDetailsLocked.classList.remove('hidden');
          gpsDetailsNone.classList.add('hidden');

          btnGoogleMaps.href = `https://www.google.com/maps?q=${currentGps.latitude},${currentGps.longitude}`;
          if (btnOsmMaps) {
            btnOsmMaps.href = `https://www.openstreetmap.org/?mlat=${currentGps.latitude}&mlon=${currentGps.longitude}#map=16/${currentGps.latitude}/${currentGps.longitude}`;
          }
          mapFrame.src = `https://www.openstreetmap.org/export/embed.html?bbox=${currentGps.longitude - 0.008}%2C${currentGps.latitude - 0.005}%2C${currentGps.longitude + 0.008}%2C${currentGps.latitude + 0.005}&layer=mapnik&marker=${currentGps.latitude}%2C${currentGps.longitude}`;
        } else {
          currentGps = null;
          gpsBadge.textContent = 'NO GPS DATA';
          gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40';
          gpsDetailsLocked.classList.add('hidden');
          gpsDetailsNone.classList.remove('hidden');
        }
      }
    } catch (exifErr) {
      console.warn('EXIF read error:', exifErr);
    }

    // 2. Chronolocation
    const targetLat = currentGps ? currentGps.latitude : 40.4093;
    const targetLon = currentGps ? currentGps.longitude : 49.8671;
    renderChronolocation(captureDate, targetLat, targetLon, !!currentGps);

    // 3. Canvas Enhancement
    statusText.textContent = 'Canvas API ilə şəklin kontrastı və kənarları kəskinləşdirilir...';
    progressBar.style.width = '35%';
    progressPercent.textContent = '35%';

    let ocrInput = file;
    try {
      const { dataUrl, blob } = await enhanceImageViaCanvas(originalImageSrc);
      enhancedImageSrc = dataUrl;
      ocrInput = blob;
      if (btnViewEnhanced) btnViewEnhanced.classList.remove('hidden');
    } catch (e) {
      console.warn('Canvas enhance error, using raw:', e);
    }

    // 4. OCR Processing
    await runOcrOnSource(ocrInput);
  };

  // Copy Buttons
  if (btnCopyCoords) {
    btnCopyCoords.addEventListener('click', () => {
      if (currentGps) {
        copyToClipboard(`${currentGps.latitude}, ${currentGps.longitude}`, btnCopyCoords);
      }
    });
  }

  if (btnCopyOcr) {
    btnCopyOcr.addEventListener('click', () => {
      if (currentOcrText) {
        copyToClipboard(currentOcrText, btnCopyOcr);
      }
    });
  }

  // Select File Button
  if (selectFileBtn) {
    selectFileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.click();
    });
  }

  if (dropzone) {
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('border-[#00C897]', 'bg-[#00C897]/10');
    });
    dropzone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      dropzone.classList.remove('border-[#00C897]', 'bg-[#00C897]/10');
    });
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('border-[#00C897]', 'bg-[#00C897]/10');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        processFile(e.dataTransfer.files[0]);
      }
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        processFile(e.target.files[0]);
      }
    });
  }

  // Demo Loaders
  if (demoGpsBtn) {
    demoGpsBtn.addEventListener('click', () => {
      resultsContainer.classList.remove('hidden');
      originalImageSrc = 'https://images.unsplash.com/photo-1578632767115-351597cf2477?w=1200&auto=format&fit=crop';
      imagePreview.src = originalImageSrc;
      previewFileName.textContent = 'DJI_MAVIC3_BAKU_BAYIL.JPG';
      previewFileSize.textContent = '4.67 MB';

      metaMake.textContent = 'DJI';
      metaModel.textContent = 'Mavic 3 Enterprise';
      metaSoftware.textContent = 'v01.00.0600';
      const demoDate = new Date('2024-05-18T14:35:00');
      metaDateTime.textContent = demoDate.toLocaleString();
      metaDimensions.textContent = '4000 × 3000 px';
      metaExposure.textContent = '1/800s';
      metaFNumber.textContent = 'f/2.8';
      metaIso.textContent = 'ISO 100';
      metaFocal.textContent = '24.0 mm';
      metaFileSize.textContent = '4.67 MB (image/jpeg)';

      currentGps = { latitude: 40.358211, longitude: 49.832944 };
      coordsDisplay.textContent = '40.358211, 49.832944';
      gpsBadge.textContent = 'GPS VERIFIED';
      gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#00C897]/20 text-[#00C897] border border-[#00C897]/40';
      gpsDetailsLocked.classList.remove('hidden');
      gpsDetailsNone.classList.add('hidden');

      btnGoogleMaps.href = 'https://www.google.com/maps?q=40.358211,49.832944';
      if (btnOsmMaps) {
        btnOsmMaps.href = 'https://www.openstreetmap.org/?mlat=40.358211&mlon=49.832944#map=16/40.358211/49.832944';
      }
      mapFrame.src = `https://www.openstreetmap.org/export/embed.html?bbox=49.824944%2C40.353211%2C49.840944%2C40.363211&layer=mapnik&marker=40.358211%2C49.832944`;

      renderChronolocation(demoDate, 40.358211, 49.832944, true);

      currentOcrText = 'BAKU CRYSTAL HALL // CASPIAN SEAFRONT PROMENADE // NEFTCHILAR AVE';
      ocrConfidence.textContent = '94%';
      ocrRawText.textContent = currentOcrText;
      currentLandmarks = ['Baku', 'Caspian', 'Crystal Hall', 'Neftchilar Ave'];
      renderLandmarksAndProximity(currentLandmarks);

      suggestedLocationsList = [
        {
          place_id: 991,
          display_name: 'Bakı Kristal Zalı, Dövlət Bayrağı Meydanı, Səbail, Bakı, Azərbaycan',
          lat: '40.3475',
          lon: '49.8519',
          type: 'amenity',
          category: 'entertainment',
        },
        {
          place_id: 992,
          display_name: 'Neftçilər Prospekti, Səbail, Bakı, AZ1000, Azərbaycan',
          lat: '40.3667',
          lon: '49.8389',
          type: 'highway',
          category: 'primary',
        },
      ];
      renderSuggestedLocations();
    });
  }

  if (demoOcrBtn) {
    demoOcrBtn.addEventListener('click', () => {
      resultsContainer.classList.remove('hidden');
      originalImageSrc = 'https://images.unsplash.com/photo-1555396273-367ea4eb4db5?w=1200&auto=format&fit=crop';
      imagePreview.src = originalImageSrc;
      previewFileName.textContent = 'IMG_20240810_STORE_FRONT.JPG';
      previewFileSize.textContent = '3.05 MB';

      metaMake.textContent = 'Apple';
      metaModel.textContent = 'iPhone 15 Pro';
      metaSoftware.textContent = 'iOS 17.5.1';
      const demoDate = new Date('2024-08-10T11:15:00');
      metaDateTime.textContent = demoDate.toLocaleString();
      metaDimensions.textContent = '3840 × 2160 px';
      metaExposure.textContent = '1/250s';
      metaFNumber.textContent = 'f/1.78';
      metaIso.textContent = 'ISO 64';
      metaFocal.textContent = '24.0 mm';
      metaFileSize.textContent = '3.05 MB (image/jpeg)';

      currentGps = null;
      gpsBadge.textContent = 'NO GPS DATA';
      gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40';
      gpsDetailsLocked.classList.add('hidden');
      gpsDetailsNone.classList.remove('hidden');

      renderChronolocation(demoDate, 40.4093, 49.8671, false);

      currentOcrText = 'BRAVO SUPERMARKET // 24 SAAT APTEK ZEFERAN // NIZAMI KUCESI 142';
      ocrConfidence.textContent = '89%';
      ocrRawText.textContent = currentOcrText;
      currentLandmarks = ['Bravo', 'Bazarstore', 'Aptek', 'Zeferan', 'Nizami Kucesi', 'Baku'];
      renderLandmarksAndProximity(currentLandmarks);

      suggestedLocationsList = [
        {
          place_id: 881,
          display_name: 'Bravo Hipermarket, Heydər Əliyev prospekti, Nərimanov, Bakı, Azərbaycan',
          lat: '40.4128',
          lon: '49.8732',
          type: 'shop',
          category: 'supermarket',
        },
        {
          place_id: 882,
          display_name: 'Zəfəran Aptek, Nizami küçəsi, Nəsimi, Bakı, AZ1010, Azərbaycan',
          lat: '40.3789',
          lon: '49.8521',
          type: 'amenity',
          category: 'pharmacy',
        },
      ];
      renderSuggestedLocations();
    });
  }
});
