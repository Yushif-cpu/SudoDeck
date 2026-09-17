// ══════════════════════════════════════════════════════════════════
//  SudoDeck — Visual Recon & Image Geolocation Engine
//  Dynamic Zero-Persistence Reset + Real EXIF & OCR Geocoding
// ══════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // Safe DOM helpers
  const setText = (el, text) => {
    if (el) el.textContent = text;
  };

  const setHtml = (el, html) => {
    if (el) el.innerHTML = html;
  };

  const setDisplay = (el, isVisible) => {
    if (!el) return;
    if (isVisible) {
      el.classList.remove('hidden');
    } else {
      el.classList.add('hidden');
    }
  };

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
  const coordsAddress = document.getElementById('coords-address');
  const btnCopyCoords = document.getElementById('btn-copy-coords');
  const btnGoogleMaps = document.getElementById('btn-google-maps');
  const btnOsmMaps = document.getElementById('btn-osm-maps');
  const mapFrame = document.getElementById('map-frame');

  // Chronolocation elements
  const chronoContainer = document.getElementById('chrono-container');
  const chronoTime = document.getElementById('chrono-time');
  const chronoSunAzimuth = document.getElementById('chrono-sun-azimuth');
  const chronoShadowVector = document.getElementById('chrono-shadow-vector');
  const chronoShadowRatio = document.getElementById('chrono-shadow-ratio');
  const chronoReliability = document.getElementById('chrono-reliability');
  const chronoGuidance = document.getElementById('chrono-guidance');

  // Nominatim Suggested Locations elements
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

  // OCR Username Lead to dedicated Social Footprint page
  const ocrUsernameLead = document.getElementById('ocr-username-lead');
  const detectedUsernameVal = document.getElementById('detected-username-val');
  const btnGotoFootprint = document.getElementById('btn-goto-footprint');

  // Demo buttons
  const demoGpsBtn = document.getElementById('demo-gps-btn');
  const demoOcrBtn = document.getElementById('demo-ocr-btn');

  // Active state variables
  let originalImageSrc = '';
  let enhancedImageSrc = '';
  let currentGps = null;
  let currentOcrText = '';
  let currentLandmarks = [];
  let suggestedLocationsList = [];

  // Complete Zero-Persistence State Reset on every upload
  const resetAllState = () => {
    // 1. Clean previous blobs
    if (originalImageSrc && originalImageSrc.startsWith('blob:')) {
      try { URL.revokeObjectURL(originalImageSrc); } catch (_) {}
    }
    if (enhancedImageSrc && enhancedImageSrc.startsWith('blob:')) {
      try { URL.revokeObjectURL(enhancedImageSrc); } catch (_) {}
    }

    originalImageSrc = '';
    enhancedImageSrc = '';
    currentGps = null;
    currentOcrText = '';
    currentLandmarks = [];
    suggestedLocationsList = [];

    // 2. Reset Preview Card
    if (imagePreview) imagePreview.src = '';
    setText(previewFileName, 'target.jpg');
    setText(previewFileSize, '0 KB');
    setText(previewBadgeMode, '📷 Native View');

    // 3. Reset GPS Telemetry Panel
    setText(gpsBadge, 'ANALİZ EDİLİR...');
    if (gpsBadge) {
      gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700';
    }
    setDisplay(gpsDetailsLocked, false);
    setDisplay(gpsDetailsNone, false);
    setText(coordsDisplay, '—');
    setText(coordsAddress, '');
    setDisplay(coordsAddress, false);
    if (mapFrame) mapFrame.src = 'about:blank';
    if (btnGoogleMaps) btnGoogleMaps.href = '#';
    if (btnOsmMaps) btnOsmMaps.href = '#';

    // 4. Reset OCR & Landmarks
    setText(ocrConfidence, '0%');
    setText(ocrRawText, 'Şəkil analiz edilir...');
    setDisplay(landmarksContainer, false);
    setHtml(landmarksTags, '');
    setDisplay(proximityContainer, false);
    setHtml(proximityTags, '');
    setDisplay(btnGoogleSearchText, false);

    // 5. Reset Locations
    setDisplay(locationsGrid, false);
    setHtml(locationsGrid, '');
    setDisplay(locationsEmptyMsg, true);

    // 6. Reset Chronolocation
    setDisplay(chronoContainer, false);
    setText(chronoTime, '—');
    setText(chronoSunAzimuth, '—');
    setText(chronoShadowVector, '—');
    setText(chronoShadowRatio, '—');

    // 7. Reset Metadata Table
    setText(metaMake, 'Məlumat yoxdur');
    setText(metaModel, 'Məlumat yoxdur');
    setText(metaDateTime, 'Məlumat yoxdur');
    setText(metaDimensions, 'Məlumat yoxdur');
    setText(metaFileSize, '0 Bytes');
    setText(metaExposure, 'Məlumat yoxdur');
    setText(metaFNumber, 'Məlumat yoxdur');
    setText(metaIso, 'Məlumat yoxdur');
    setText(metaFocal, 'Məlumat yoxdur');
    setText(metaSoftware, 'Məlumat yoxdur');

    // 8. Reset Username Lead
    setDisplay(ocrUsernameLead, false);

    // 9. Reset View Switcher
    if (btnViewOriginal) {
      btnViewOriginal.classList.add('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
      btnViewOriginal.classList.remove('text-slate-400');
    }
    if (btnViewEnhanced) {
      btnViewEnhanced.classList.add('hidden', 'text-slate-400');
      btnViewEnhanced.classList.remove('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
    }
  };

  const updateProgress = (pct, msg) => {
    if (progressBar) progressBar.style.width = `${pct}%`;
    if (progressPercent) progressPercent.textContent = `${pct}%`;
    if (statusText) statusText.textContent = msg;
  };

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const copyToClipboard = (text, triggerBtn, successText = 'Kopyalandı!') => {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      if (!triggerBtn) return;
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
    /\b(Baku|Bakı|Ganja|Gəncə|Sumqayit|Sumqayıt|Quba|Sheki|Şəki|Lankaran|Lənkəran|Shusha|Şuşa|Khankendi|Xankəndi|Yasamal|Nasimi|Nəsimi|Sabayil|Səbail|Narimanov|Nərimanov|Badamdar|Bayil|Bayıl|Masazir|Masazır|Xirdalan|Xırdalan|Mardakan|Mərdəkan|Bilajari|Biləcəri|Nizami|Sahil|Koroğlu)\b/gi,
    /\b(Kuc|Kucesi|Küç|Küçəsi|Pr|Prospekti|Prospekt|Street|St|Ave|Avenue|Road|Rd|Bulvar|Boulevard|Yolu|Yol)\b/gi,
    /\b(Bank|Kapital|Pasha|Paşa|ABB|UniBank|AccessBank|ExpressBank|Yelo|Rabitabank|ATM)\b/gi,
    /\b(Metro|Stansiya|Vagzal|Vaqzal|Airport|Aeroport|Terminal)\b/gi,
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

    const capitalizedMatches = text.match(/\b[A-ZƏÖĞÇŞIİ][a-zəöğçşıi]{3,}(?:\s+[A-ZƏÖĞÇŞIİ][a-zəöğçşıi]{3,})*\b/g);
    if (capitalizedMatches) {
      capitalizedMatches.forEach((word) => {
        const clean = word.trim();
        if (clean.length > 3 && !['This', 'With', 'From', 'Have', 'They', 'Date', 'Time', 'Text', 'Camera', 'Photo', 'Native'].includes(clean)) {
          landmarks.add(clean);
        }
      });
    }

    return Array.from(landmarks).slice(0, 10);
  };

  // Extract Usernames and Handles from OCR to lead into Social Footprint tool
  const extractUsernamesFromOcr = (text) => {
    if (!text) return [];
    const usernames = new Set();

    const atMatches = text.match(/@([a-zA-Z0-9_\.]{3,24})/g);
    if (atMatches) {
      atMatches.forEach(m => usernames.add(m.replace(/^@/, '').trim()));
    }

    const byMatches = text.match(/\b(by[\._][a-zA-Z0-9_]{2,20})\b/gi);
    if (byMatches) {
      byMatches.forEach(m => usernames.add(m.trim()));
    }

    const handleMatches = text.match(/\b([a-zA-Z0-9_\.]{4,20})\b/g);
    if (handleMatches) {
      handleMatches.forEach(word => {
        if (word.includes('.') || word.includes('_')) {
          const lower = word.toLowerCase();
          if (!['jpg', 'jpeg', 'png', 'webp', 'mp4', 'www', 'com', 'org', 'net', 'http', 'https'].includes(lower)) {
            usernames.add(word);
          }
        }
      });
    }

    return Array.from(usernames).slice(0, 4);
  };

  function degreesToCardinal(deg) {
    const directions = ['Şimal (N)', 'Şimal-Şərq (NE)', 'Şərq (E)', 'Cənub-Şərq (SE)', 'Cənub (S)', 'Cənub-Qərb (SW)', 'Qərb (W)', 'Şimal-Qərb (NW)'];
    const index = Math.round(((deg % 360) + 360) % 360 / 45) % 8;
    return directions[index];
  }

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

  // Canvas Image Enhancement for sharper OCR
  const enhanceImageViaCanvas = (sourceUrl) => {
    return new Promise((resolve) => {
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          if (!ctx) return resolve(null);

          let width = img.naturalWidth || 800;
          let height = img.naturalHeight || 600;

          if (width < 1000) {
            const scale = Math.min(2, 1600 / width);
            width = Math.round(width * scale);
            height = Math.round(height * scale);
          } else if (width > 2000) {
            const scale = 2000 / width;
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
            if (!blob) return resolve(null);
            const dataUrl = canvas.toDataURL('image/png');
            resolve({ dataUrl, blob });
          }, 'image/png');
        } catch (_) {
          resolve(null);
        }
      };
      img.onerror = () => resolve(null);
      img.src = sourceUrl;
    });
  };

  // Reverse Geocode: GPS -> Exact Human Address
  const queryReverseGeocode = async (lat, lon) => {
    try {
      const res = await fetch(`/api/reverse-geocode?lat=${lat}&lon=${lon}`);
      if (res.ok) {
        const json = await res.json();
        if (json.data && json.data.display_name) {
          return json.data.display_name;
        }
      }
    } catch (_) {}

    // Fallback direct OSM
    try {
      const res = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}`, {
        headers: { 'Accept-Language': 'az,en,ru' },
      });
      if (res.ok) {
        const d = await res.json();
        return d.display_name || '';
      }
    } catch (_) {}
    return '';
  };

  // Forward Geocode: Query String -> Coordinates
  const queryNominatimGeocode = async (queryPhrase) => {
    if (!queryPhrase || !queryPhrase.trim()) return [];
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
        return results;
      }
    } catch (e) {
      console.warn('Geocoding notice:', e);
    }
    return [];
  };

  const renderSuggestedLocations = () => {
    if (!locationsGrid || !locationsEmptyMsg) return;

    if (suggestedLocationsList.length === 0) {
      setDisplay(locationsGrid, false);
      setDisplay(locationsEmptyMsg, true);
      return;
    }

    setDisplay(locationsEmptyMsg, false);
    setDisplay(locationsGrid, true);
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
          <button type="button" class="btn-preview-map flex-1 text-center py-1.5 rounded-lg bg-[#00C897]/15 hover:bg-[#00C897]/25 text-[#00C897] font-bold transition-colors">
            Xəritədə Bax 🗺️
          </button>
          <a href="https://www.google.com/maps?q=${loc.lat},${loc.lon}" target="_blank" rel="noreferrer" class="flex-1 text-center py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors">
            GMaps ↗
          </a>
          <button type="button" class="btn-copy-loc px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors" data-coords="${loc.lat}, ${loc.lon}">
            Kopya
          </button>
        </div>
      `;

      card.querySelector('.btn-preview-map').addEventListener('click', () => {
        const lat = parseFloat(loc.lat);
        const lon = parseFloat(loc.lon);
        setDisplay(gpsDetailsLocked, true);
        setDisplay(gpsDetailsNone, false);
        setText(coordsDisplay, `${lat.toFixed(6)}, ${lon.toFixed(6)}`);
        if (coordsAddress) {
          coordsAddress.textContent = `📍 Seçilmiş Məkan: ${loc.display_name}`;
          coordsAddress.classList.remove('hidden');
        }
        if (btnGoogleMaps) btnGoogleMaps.href = `https://www.google.com/maps?q=${lat},${lon}`;
        if (btnOsmMaps) btnOsmMaps.href = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`;
        if (mapFrame) {
          mapFrame.src = `https://www.openstreetmap.org/export/embed.html?bbox=${lon - 0.008}%2C${lat - 0.005}%2C${lon + 0.008}%2C${lat + 0.005}&layer=mapnik&marker=${lat}%2C${lon}`;
        }
      });

      card.querySelector('.btn-copy-loc').addEventListener('click', (e) => {
        copyToClipboard(e.currentTarget.getAttribute('data-coords'), e.currentTarget, '✓');
      });

      locationsGrid.appendChild(card);
    });
  };

  const renderChronolocation = (date, lat, lon, hasGps) => {
    if (!chronoContainer) return;
    const shadow = calculateSunAndShadow(date, lat, lon);

    setText(chronoTime, date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    setText(chronoSunAzimuth, `${shadow.sunAzimuthDeg}° (${shadow.cardinalDirection})`);
    setText(chronoShadowVector, `${shadow.shadowAzimuthDeg}° (${shadow.shadowCardinalDirection})`);
    setText(chronoShadowRatio, shadow.isNight ? 'Gecə' : `~${shadow.shadowLengthRatio}x`);
    setText(chronoReliability, hasGps ? 'High (GPS+EXIF)' : 'Estimated by Time');

    if (chronoGuidance) {
      chronoGuidance.innerHTML = `📐 <strong>OSINT İpucu:</strong> Saat ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} üçün şəkildəki dirək və hasarların kölgəsi <span class="text-[#00C897] font-semibold">${shadow.shadowCardinalDirection}</span> tərəfinə yönəlir (1 m obyekt üçün kölgə ~${shadow.shadowLengthRatio} m).`;
    }
    setDisplay(chronoContainer, true);
  };

  // View Switchers
  if (btnViewOriginal) {
    btnViewOriginal.addEventListener('click', () => {
      if (imagePreview) imagePreview.src = originalImageSrc;
      btnViewOriginal.classList.add('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
      btnViewOriginal.classList.remove('text-slate-400');
      if (btnViewEnhanced) {
        btnViewEnhanced.classList.remove('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
        btnViewEnhanced.classList.add('text-slate-400');
      }
      setText(previewBadgeMode, '📷 Native View');
    });
  }

  if (btnViewEnhanced) {
    btnViewEnhanced.addEventListener('click', () => {
      if (enhancedImageSrc && imagePreview) {
        imagePreview.src = enhancedImageSrc;
        btnViewEnhanced.classList.add('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
        btnViewEnhanced.classList.remove('text-slate-400');
        if (btnViewOriginal) {
          btnViewOriginal.classList.remove('bg-[#00C897]/20', 'text-[#00C897]', 'font-bold');
          btnViewOriginal.classList.add('text-slate-400');
        }
        setText(previewBadgeMode, '🔬 Canvas High-Contrast OCR Filter');
      }
    });
  }

  if (btnRerunOriginalOcr) {
    btnRerunOriginalOcr.addEventListener('click', () => runOcrOnSource(originalImageSrc));
  }
  if (btnRerunEnhancedOcr) {
    btnRerunEnhancedOcr.addEventListener('click', () => runOcrOnSource(enhancedImageSrc || originalImageSrc));
  }

  if (osmSearchBtn && osmSearchInput) {
    osmSearchBtn.addEventListener('click', () => queryNominatimGeocode(osmSearchInput.value));
    osmSearchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') queryNominatimGeocode(osmSearchInput.value);
    });
  }

  // Fast & Bulletproof OCR
  const runOcrOnSource = async (src) => {
    if (!src) {
      updateProgress(100, 'Analiz tamamlandı.');
      setTimeout(() => setDisplay(statusContainer, false), 1500);
      return;
    }

    updateProgress(50, 'Tesseract.js OCR mühərriki yazıları oxuyur...');

    try {
      if (window.Tesseract) {
        const ocrPromise = window.Tesseract.recognize(src, 'eng', {
          logger: (m) => {
            if (m.status === 'recognizing text' && typeof m.progress === 'number') {
              const p = Math.min(Math.round(m.progress * 100), 95);
              updateProgress(Math.max(50, p), `Mətnlər və lövhələr oxunur: ${p}%`);
            }
          },
        });

        const result = await Promise.race([
          ocrPromise,
          new Promise((_, reject) => setTimeout(() => reject(new Error('OCR Timeout')), 8000))
        ]).catch(() => null);

        if (result && result.data) {
          currentOcrText = result.data.text || '';
          const confidence = Math.round(result.data.confidence || 0);
          setText(ocrConfidence, `${confidence}%`);
          setText(ocrRawText, currentOcrText.trim() || 'Bu şəkildə aşkar edilən hər hansı mətn tapılmadı.');

          currentLandmarks = extractLandmarks(currentOcrText);
          renderLandmarksAndProximity(currentLandmarks);

          // Extract potential social handles and lead to dedicated Social Footprint page
          const foundUsernames = extractUsernamesFromOcr(currentOcrText);
          if (foundUsernames.length > 0 && ocrUsernameLead && detectedUsernameVal && btnGotoFootprint) {
            const topUser = foundUsernames[0];
            detectedUsernameVal.textContent = `@${topUser}`;
            btnGotoFootprint.href = `/social-footprint?u=${encodeURIComponent(topUser)}`;
            setDisplay(ocrUsernameLead, true);
          }

          // Geocode detected landmarks into OSM grid for user selection (without overriding real GPS)
          for (const lm of currentLandmarks.slice(0, 3)) {
            await queryNominatimGeocode(lm);
          }
        } else {
          setText(ocrConfidence, '0%');
          setText(ocrRawText, 'Bu şəkildə oxunan mətn aşkar edilmədi.');
        }
      } else {
        setText(ocrRawText, 'OCR mühərriki hazır deyil.');
      }
    } catch (err) {
      console.warn('OCR notice:', err);
      setText(ocrRawText, 'Mətn aşkar edilmədi.');
    }

    updateProgress(100, 'Analiz tamamlandı.');
    setTimeout(() => {
      setDisplay(statusContainer, false);
    }, 1500);
  };

  const renderLandmarksAndProximity = (landmarks) => {
    if (landmarks.length > 0) {
      setDisplay(landmarksContainer, true);
      if (landmarksTags) {
        landmarksTags.innerHTML = '';
        landmarks.forEach((lm) => {
          const tag = document.createElement('span');
          tag.className = 'px-2.5 py-1 rounded-lg text-xs font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 flex items-center gap-1.5';
          tag.textContent = lm;
          landmarksTags.appendChild(tag);
        });
      }

      if (proximityContainer && proximityTags) {
        setDisplay(proximityContainer, true);
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
        setDisplay(btnGoogleSearchText, true);
      }
    } else {
      setDisplay(landmarksContainer, false);
      setDisplay(proximityContainer, false);
      setDisplay(btnGoogleSearchText, false);
    }
  };

  // ── Main File Processor (Dynamic, Bulletproof & Zero Stale State) ─
  const processFile = async (file) => {
    if (!file) return;

    try {
      // STEP 1: ALWAYS RESET EVERYTHING TO ZERO FIRST!
      resetAllState();

      setDisplay(errorAlert, false);
      setDisplay(resultsContainer, true);
      setDisplay(statusContainer, true);

      updateProgress(10, 'Şəkil yüklənir...');

      originalImageSrc = URL.createObjectURL(file);
      if (imagePreview) imagePreview.src = originalImageSrc;
      setText(previewFileName, file.name);
      setText(previewFileSize, formatBytes(file.size));
      setText(metaFileSize, `${formatBytes(file.size)} (${file.type || 'image/jpeg'})`);

      let captureDate = null;
      let hasExactGps = false;

      // STEP 2: Read EXIF & GPS
      updateProgress(25, 'EXIF kamera və peyk sensoru oxunur...');
      try {
        if (window.exifr) {
          const exif = await Promise.race([
            window.exifr.parse(file, { tiff: true, xmp: true, gps: true, jfif: true }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('EXIF timeout')), 6000))
          ]).catch(() => null);

          if (exif) {
            setText(metaMake, exif.Make || exif.make || 'Tapılmadı');
            setText(metaModel, exif.Model || exif.model || 'Tapılmadı');
            setText(metaSoftware, exif.Software || exif.software || 'Tapılmadı');

            if (exif.DateTimeOriginal || exif.CreateDate) {
              captureDate = new Date(exif.DateTimeOriginal || exif.CreateDate);
              setText(metaDateTime, captureDate.toLocaleString());
            } else {
              setText(metaDateTime, 'Məlumat yoxdur');
            }

            if (exif.ExifImageWidth && exif.ExifImageHeight) {
              setText(metaDimensions, `${exif.ExifImageWidth} × ${exif.ExifImageHeight} px`);
            }
            if (exif.ExposureTime) {
              setText(metaExposure, exif.ExposureTime < 1 ? `1/${Math.round(1 / exif.ExposureTime)}s` : `${exif.ExposureTime}s`);
            }
            if (exif.FNumber) {
              setText(metaFNumber, `f/${exif.FNumber}`);
            }
            if (exif.ISO) {
              setText(metaIso, `ISO ${exif.ISO}`);
            }
            if (exif.FocalLength) {
              setText(metaFocal, `${exif.FocalLength} mm`);
            }
          }

          // Check GPS coordinates
          let gps = null;
          try {
            gps = await Promise.race([
              window.exifr.gps(file),
              new Promise((_, reject) => setTimeout(() => reject(new Error('GPS timeout')), 5000))
            ]).catch(() => null);
          } catch (_) {}

          let rawLat = null;
          let rawLon = null;

          if (gps && typeof gps.latitude === 'number' && typeof gps.longitude === 'number') {
            rawLat = gps.latitude;
            rawLon = gps.longitude;
          } else if (exif && typeof exif.latitude === 'number' && typeof exif.longitude === 'number') {
            rawLat = exif.latitude;
            rawLon = exif.longitude;
          }

          if (rawLat !== null && rawLon !== null && !isNaN(rawLat) && !isNaN(rawLon) && !(rawLat === 0 && rawLon === 0)) {
            hasExactGps = true;
            const lat = Number(rawLat.toFixed(6));
            const lon = Number(rawLon.toFixed(6));
            currentGps = { latitude: lat, longitude: lon, isExactGps: true };

            setText(coordsDisplay, `${lat}, ${lon}`);
            setText(gpsBadge, '🟢 GPS VERIFIED (100% EXIF SENSOR)');
            if (gpsBadge) {
              gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#00C897]/20 text-[#00C897] border border-[#00C897]/40';
            }
            setDisplay(gpsDetailsLocked, true);
            setDisplay(gpsDetailsNone, false);

            if (btnGoogleMaps) btnGoogleMaps.href = `https://www.google.com/maps?q=${lat},${lon}`;
            if (btnOsmMaps) btnOsmMaps.href = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`;
            if (mapFrame) {
              mapFrame.src = `https://www.openstreetmap.org/export/embed.html?bbox=${lon - 0.008}%2C${lat - 0.005}%2C${lon + 0.008}%2C${lat + 0.005}&layer=mapnik&marker=${lat}%2C${lon}`;
            }

            // Reverse geocode to exact street and building address
            queryReverseGeocode(lat, lon).then((addr) => {
              if (addr && coordsAddress) {
                coordsAddress.textContent = `📍 Dəqiq Ünvan: ${addr}`;
                coordsAddress.classList.remove('hidden');
              }
            });

            suggestedLocationsList = [{
              place_id: 1,
              display_name: `EXIF Dəqiq Məkan: ${lat}, ${lon}`,
              lat: lat.toString(),
              lon: lon.toString(),
              type: 'sensor_gps',
              category: 'satellite',
            }];
            renderSuggestedLocations();
          }
        }
      } catch (exifErr) {
        console.warn('EXIF read notice:', exifErr);
      }

      // STEP 3: If NO exact EXIF GPS:
      if (!hasExactGps) {
        setText(gpsBadge, '🟡 EXIF GPS TAPILMADI');
        if (gpsBadge) {
          gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40';
        }
        setDisplay(gpsDetailsLocked, false);
        setDisplay(gpsDetailsNone, true);
        setText(coordsDisplay, 'Mövcud Deyil (EXIF GPS yoxdur)');
        if (coordsAddress) {
          coordsAddress.textContent = '';
          coordsAddress.classList.add('hidden');
        }
        if (mapFrame) mapFrame.src = 'about:blank';
      }

      // STEP 4: Chronolocation
      if (hasExactGps && currentGps && captureDate) {
        renderChronolocation(captureDate, currentGps.latitude, currentGps.longitude, true);
      }

      // STEP 5: Canvas Enhancement
      updateProgress(40, 'Canvas API ilə şəklin kontrastı və kənarları kəskinləşdirilir...');
      let ocrInput = originalImageSrc;
      try {
        const enhanced = await enhanceImageViaCanvas(originalImageSrc);
        if (enhanced) {
          enhancedImageSrc = enhanced.dataUrl;
          ocrInput = enhanced.blob;
          setDisplay(btnViewEnhanced, true);
        }
      } catch (_) {}

      // STEP 6: OCR Processing
      await runOcrOnSource(ocrInput);

    } catch (criticalErr) {
      console.error('Critical processFile error:', criticalErr);
      updateProgress(100, 'Analiz tamamlandı.');
      setTimeout(() => setDisplay(statusContainer, false), 1500);
    }
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

  if (selectFileBtn && fileInput) {
    selectFileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.value = ''; // Clean reset on click
      fileInput.click();
    });
  }

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => {
      fileInput.value = '';
      fileInput.click();
    });
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
        fileInput.value = '';
        processFile(e.dataTransfer.files[0]);
      }
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        const file = e.target.files[0];
        fileInput.value = ''; // Reset so selecting the same or new file always triggers
        processFile(file);
      }
    });
  }

  // Demo Loaders
  if (demoGpsBtn) {
    demoGpsBtn.addEventListener('click', () => {
      resetAllState();
      setDisplay(resultsContainer, true);
      originalImageSrc = 'https://images.unsplash.com/photo-1578632767115-351597cf2477?w=1200&auto=format&fit=crop';
      if (imagePreview) imagePreview.src = originalImageSrc;
      setText(previewFileName, 'DJI_MAVIC3_BAKU_BAYIL.JPG');
      setText(previewFileSize, '4.67 MB');

      setText(metaMake, 'DJI');
      setText(metaModel, 'Mavic 3 Enterprise');
      setText(metaSoftware, 'v01.00.0600');
      const demoDate = new Date('2024-05-18T14:35:00');
      setText(metaDateTime, demoDate.toLocaleString());
      setText(metaDimensions, '4000 × 3000 px');
      setText(metaExposure, '1/800s');
      setText(metaFNumber, 'f/2.8');
      setText(metaIso, 'ISO 100');
      setText(metaFocal, '24.0 mm');
      setText(metaFileSize, '4.67 MB (image/jpeg)');

      currentGps = { latitude: 40.358211, longitude: 49.832944 };
      setText(coordsDisplay, '40.358211, 49.832944');
      if (coordsAddress) {
        coordsAddress.textContent = '📍 Dəqiq Ünvan: Dənizkənarı küçəsi, Bayıl, Səbail rayonu, Bakı, Azərbaycan';
        coordsAddress.classList.remove('hidden');
      }
      setText(gpsBadge, '🟢 GPS VERIFIED (100% EXIF SENSOR)');
      if (gpsBadge) {
        gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#00C897]/20 text-[#00C897] border border-[#00C897]/40';
      }
      setDisplay(gpsDetailsLocked, true);
      setDisplay(gpsDetailsNone, false);

      if (btnGoogleMaps) btnGoogleMaps.href = 'https://www.google.com/maps?q=40.358211,49.832944';
      if (btnOsmMaps) btnOsmMaps.href = 'https://www.openstreetmap.org/?mlat=40.358211&mlon=49.832944#map=16/40.358211/49.832944';
      if (mapFrame) {
        mapFrame.src = `https://www.openstreetmap.org/export/embed.html?bbox=49.824944%2C40.353211%2C49.840944%2C40.363211&layer=mapnik&marker=40.358211%2C49.832944`;
      }

      renderChronolocation(demoDate, 40.358211, 49.832944, true);

      currentOcrText = 'BAKU CRYSTAL HALL // CASPIAN SEAFRONT PROMENADE // NEFTCHILAR AVE';
      setText(ocrConfidence, '94%');
      setText(ocrRawText, currentOcrText);
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
      resetAllState();
      setDisplay(resultsContainer, true);
      originalImageSrc = 'https://images.unsplash.com/photo-1555396273-367ea4eb4db5?w=1200&auto=format&fit=crop';
      if (imagePreview) imagePreview.src = originalImageSrc;
      setText(previewFileName, 'IMG_20240810_STORE_FRONT.JPG');
      setText(previewFileSize, '3.05 MB');

      setText(metaMake, 'Apple');
      setText(metaModel, 'iPhone 15 Pro');
      setText(metaSoftware, 'iOS 17.5.1');
      const demoDate = new Date('2024-08-10T11:15:00');
      setText(metaDateTime, demoDate.toLocaleString());
      setText(metaDimensions, '3840 × 2160 px');
      setText(metaExposure, '1/800s');
      setText(metaFNumber, 'f/1.78');
      setText(metaIso, 'ISO 64');
      setText(metaFocal, '24.0 mm');
      setText(metaFileSize, '3.05 MB (image/jpeg)');

      setText(gpsBadge, '🟡 EXIF GPS TAPILMADI');
      if (gpsBadge) {
        gpsBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40';
      }
      setDisplay(gpsDetailsLocked, false);
      setDisplay(gpsDetailsNone, true);
      setText(coordsDisplay, 'Mövcud Deyil (EXIF GPS yoxdur)');

      currentOcrText = 'BRAVO SUPERMARKET // 24 SAAT APTEK ZEFERAN // NIZAMI KUCESI 142 // @by.orux';
      setText(ocrConfidence, '89%');
      setText(ocrRawText, currentOcrText);
      currentLandmarks = ['Bravo', 'Bazarstore', 'Aptek', 'Zeferan', 'Nizami Kucesi', 'Baku'];
      renderLandmarksAndProximity(currentLandmarks);

      // Lead into Social Footprint for detected handle
      if (ocrUsernameLead && detectedUsernameVal && btnGotoFootprint) {
        detectedUsernameVal.textContent = '@by.orux';
        btnGotoFootprint.href = '/social-footprint?u=by.orux';
        setDisplay(ocrUsernameLead, true);
      }

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
