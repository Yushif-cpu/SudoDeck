'use client';

import React, { useState, useRef, useCallback } from 'react';

// ── TypeScript Interfaces ──────────────────────────────────────────

export interface GpsCoordinates {
  latitude: number;
  longitude: number;
  altitude?: number;
}

export interface ImageMetadata {
  fileName: string;
  fileSizeBytes: number;
  fileSizeFormatted: string;
  fileType: string;
  dimensions?: { width: number; height: number };
  make?: string;
  model?: string;
  dateTime?: string;
  dateObj?: Date;
  exposureTime?: string;
  fNumber?: string;
  iso?: string;
  focalLength?: string;
  software?: string;
  lensModel?: string;
  gps?: GpsCoordinates;
}

export interface OcrResult {
  rawText: string;
  confidence: number;
  detectedLandmarks: string[];
}

export interface NominatimLocation {
  place_id: number;
  display_name: string;
  lat: string;
  lon: string;
  type?: string;
  category?: string;
  class?: string;
  importance?: number;
}

export interface SunShadowAnalysis {
  sunElevationDeg: number;
  sunAzimuthDeg: number;
  shadowAzimuthDeg: number;
  shadowLengthRatio: number;
  cardinalDirection: string;
  shadowCardinalDirection: string;
  formattedTime: string;
  isNight: boolean;
  reliability: 'High (GPS+EXIF)' | 'Medium (EXIF Time Only)' | 'Estimated';
}

export interface AnalysisState {
  status: 'idle' | 'reading-exif' | 'enhancing' | 'running-ocr' | 'geocoding' | 'completed' | 'error';
  progressMessage: string;
  ocrProgress: number;
  error?: string;
}

// ── Landmark Regex Dictionary ──────────────────────────────────────

const KNOWN_STORE_PATTERNS = [
  /\b(Bravo|Bazarstore|Araz|Grandmart|Neptun|Oba|Almarket|Rahat|Bolmart|Spar|Carrefour)\b/gi,
  /\b(Aptek|Pharmacy|Apotheke|Eczane|Zeferan|Zeytun|Kanun)\b/gi,
  /\b(Baku|Bakı|Ganja|Gəncə|Sumqayit|Sumqayıt|Quba|Sheki|Şəki|Lankaran|Lənkəran|Shusha|Şuşa|Khankendi|Xankəndi|Yasamal|Nasimi|Nəsimi|Sabayil|Səbail|Narimanov|Nərimanov)\b/gi,
  /\b(Kuc|Kucesi|Küç|Küçəsi|Pr|Prospekti|Prospekt|Street|St|Ave|Avenue|Road|Rd|Bulvar|Boulevard|Meydan|Square)\b/gi,
  /\b(Bank|Kapital|Pasha|Paşa|ABB|UniBank|AccessBank|ExpressBank|Yelo|Rabitabank|ATM)\b/gi,
  /\b(Metro|Stansiya|Vagzal|Vaqzal|Airport|Aeroport|Terminal)\b/gi,
  /\b(Hotel|Resort|Plaza|Mall|Center|Centre|Restoran|Restaurant|Cafe|Coffee)\b/gi,
  /\b(SOCAR|Azpetrol|Lukoil|BP|Total|Shell)\b/gi,
];

// Helper: Convert degrees to cardinal directions
function degreesToCardinal(deg: number): string {
  const directions = ['Şimal (N)', 'Şimal-Şərq (NE)', 'Şərq (E)', 'Cənub-Şərq (SE)', 'Cənub (S)', 'Cənub-Qərb (SW)', 'Qərb (W)', 'Şimal-Qərb (NW)'];
  const index = Math.round(((deg % 360) + 360) % 360 / 45) % 8;
  return directions[index];
}

// Helper: Approximate Solar Position & Shadow Physics
function calculateSunAndShadow(date: Date, lat: number, lon: number): SunShadowAnalysis {
  const dayOfYear = Math.floor((date.getTime() - new Date(date.getFullYear(), 0, 0).getTime()) / 86400000);
  const hours = date.getHours() + date.getMinutes() / 60 + date.getSeconds() / 3600;

  // Solar declination (degrees)
  const declination = 23.45 * Math.sin(((284 + dayOfYear) / 365) * 2 * Math.PI);
  const decRad = (declination * Math.PI) / 180;
  const latRad = (lat * Math.PI) / 180;

  // Approximate solar hour angle (15 deg per hour from solar noon)
  const solarHourAngle = (hours - 12) * 15;
  const hourAngleRad = (solarHourAngle * Math.PI) / 180;

  // Sun Elevation angle (degrees)
  const sinElevation = Math.sin(latRad) * Math.sin(decRad) + Math.cos(latRad) * Math.cos(decRad) * Math.cos(hourAngleRad);
  const elevationRad = Math.asin(Math.max(-1, Math.min(1, sinElevation)));
  const sunElevationDeg = Math.round((elevationRad * 180) / Math.PI * 10) / 10;

  // Sun Azimuth angle (degrees from North)
  const cosAzimuth = (Math.sin(decRad) - Math.sin(latRad) * Math.sin(elevationRad)) / (Math.cos(latRad) * Math.cos(elevationRad));
  let azimuthDeg = (Math.acos(Math.max(-1, Math.min(1, cosAzimuth))) * 180) / Math.PI;
  if (solarHourAngle > 0) {
    azimuthDeg = 360 - azimuthDeg;
  }
  const sunAzimuthDeg = Math.round(azimuthDeg * 10) / 10;

  // Shadow falls opposite to the sun (Azimuth + 180 mod 360)
  const shadowAzimuthDeg = Math.round((sunAzimuthDeg + 180) % 360 * 10) / 10;

  // Shadow length ratio L/h = 1 / tan(elevation)
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
    reliability: 'High (GPS+EXIF)',
  };
}

export default function VisualRecon() {
  const [imageSrc, setImageSrc] = useState<string | null>(null);
  const [enhancedImageSrc, setEnhancedImageSrc] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'original' | 'enhanced'>('original');
  const [currentFile, setCurrentFile] = useState<File | null>(null);

  const [metadata, setMetadata] = useState<ImageMetadata | null>(null);
  const [ocrResult, setOcrResult] = useState<OcrResult | null>(null);
  const [suggestedLocations, setSuggestedLocations] = useState<NominatimLocation[]>([]);
  const [sunShadow, setSunShadow] = useState<SunShadowAnalysis | null>(null);

  const [customGeocodeQuery, setCustomGeocodeQuery] = useState<string>('');
  const [isGeocodingLoading, setIsGeocodingLoading] = useState<boolean>(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const [analysisState, setAnalysisState] = useState<AnalysisState>({
    status: 'idle',
    progressMessage: '',
    ocrProgress: 0,
  });

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Helper to format byte sizes
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Helper to copy to clipboard
  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2500);
  };

  // Extract landmarks from text
  const extractLandmarks = (text: string): string[] => {
    const landmarks = new Set<string>();

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
        if (clean.length > 3 && !['This', 'With', 'From', 'Have', 'They', 'Date', 'Time'].includes(clean)) {
          landmarks.add(clean);
        }
      });
    }

    return Array.from(landmarks).slice(0, 15);
  };

  // ── Canvas Image Enhancement (Brightness, Contrast, Sharpening) ────
  const enhanceImageViaCanvas = async (sourceUrl: string): Promise<{ dataUrl: string; blob: Blob }> => {
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

          // Scale small images up for better OCR character recognition
          if (width < 1000) {
            const scale = Math.min(2, 1600 / width);
            width = Math.round(width * scale);
            height = Math.round(height * scale);
          } else if (width > 2400) {
            // Keep maximum dimension reasonable for speed
            const scale = 2400 / width;
            width = Math.round(width * scale);
            height = Math.round(height * scale);
          }

          canvas.width = width;
          canvas.height = height;

          // Draw original
          ctx.drawImage(img, 0, 0, width, height);

          // Extract pixel buffer
          const imgData = ctx.getImageData(0, 0, width, height);
          const d = imgData.data;

          // 1. Grayscale & Contrast Stretcher
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
            // Normalize & stretch contrast
            lum = ((lum - minLum) / range) * 255;
            // Contrast curve
            lum = (lum - 128) * contrastFactor + 128;
            lum = Math.max(0, Math.min(255, lum));

            d[i] = lum;
            d[i + 1] = lum;
            d[i + 2] = lum;
          }

          ctx.putImageData(imgData, 0, 0);

          // Export as PNG Blob
          canvas.toBlob((blob) => {
            if (!blob) return reject(new Error('Failed to create canvas blob'));
            const dataUrl = canvas.toDataURL('image/png');
            resolve({ dataUrl, blob });
          }, 'image/png');
        } catch (err) {
          reject(err);
        }
      };
      img.onerror = () => reject(new Error('Image failed to load for canvas enhancement'));
      img.src = sourceUrl;
    });
  };

  // ── OpenStreetMap Nominatim Geocoding Function ──────────────────────
  const queryNominatimGeocode = async (searchPhrase: string) => {
    if (!searchPhrase || !searchPhrase.trim()) return;
    setIsGeocodingLoading(true);

    try {
      // 1. First attempt via internal backend proxy (avoids CORS & rate-limiting)
      let results: NominatimLocation[] = [];
      try {
        const proxyRes = await fetch(`/api/geocode?q=${encodeURIComponent(searchPhrase.trim())}&limit=5`);
        if (proxyRes.ok) {
          const data = await proxyRes.json();
          if (data.results && Array.isArray(data.results)) {
            results = data.results;
          }
        }
      } catch (_) {
        // Fall back to direct OpenStreetMap API
      }

      // 2. Direct fallback to OpenStreetMap if proxy was empty or unavailable
      if (!results || results.length === 0) {
        const osmRes = await fetch(
          `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(searchPhrase.trim())}&limit=5&addressdetails=1`,
          {
            headers: {
              'Accept-Language': 'az,en,ru',
            },
          }
        );
        if (osmRes.ok) {
          const osmData = await osmRes.json();
          if (Array.isArray(osmData)) {
            results = osmData;
          }
        }
      }

      if (results.length > 0) {
        setSuggestedLocations((prev) => {
          const existingIds = new Set(prev.map((item) => item.place_id));
          const fresh = results.filter((item) => !existingIds.has(item.place_id));
          return [...fresh, ...prev].slice(0, 10);
        });
      }
    } catch (err) {
      console.warn('Nominatim query error:', err);
    } finally {
      setIsGeocodingLoading(false);
    }
  };

  // ── Process Selected File ──────────────────────────────────────────
  const processImageFile = async (file: File) => {
    if (!file.type.startsWith('image/')) {
      setAnalysisState({
        status: 'error',
        progressMessage: '',
        ocrProgress: 0,
        error: 'Zəhmət olmasa düzgün şəkil formatı seçin (JPEG, PNG, WEBP, TIFF, HEIC).',
      });
      return;
    }

    setCurrentFile(file);
    setMetadata(null);
    setOcrResult(null);
    setSuggestedLocations([]);
    setSunShadow(null);
    setEnhancedImageSrc(null);
    setViewMode('original');

    setAnalysisState({
      status: 'reading-exif',
      progressMessage: 'Şəkil daxilindəki EXIF və GPS koordinatları oxunur...',
      ocrProgress: 0,
    });

    const objectUrl = URL.createObjectURL(file);
    setImageSrc(objectUrl);

    const baseMeta: ImageMetadata = {
      fileName: file.name,
      fileSizeBytes: file.size,
      fileSizeFormatted: formatBytes(file.size),
      fileType: file.type,
    };

    let parsedGps: GpsCoordinates | undefined;
    let captureDate: Date | undefined;

    // 1. Read EXIF & GPS
    try {
      const exifrMod: any = await import('exifr');
      const exifr = exifrMod.default || exifrMod;

      const exifData = await exifr.parse(file, {
        tiff: true,
        xmp: true,
        icc: false,
        jfif: true,
        ihdr: true,
        gps: true,
      });

      if (exifData) {
        baseMeta.make = exifData.Make || exifData.make;
        baseMeta.model = exifData.Model || exifData.model;
        baseMeta.software = exifData.Software || exifData.software;
        baseMeta.lensModel = exifData.LensModel || exifData.lensModel;

        if (exifData.DateTimeOriginal) {
          captureDate = new Date(exifData.DateTimeOriginal);
        } else if (exifData.CreateDate) {
          captureDate = new Date(exifData.CreateDate);
        }

        if (captureDate && !isNaN(captureDate.getTime())) {
          baseMeta.dateTime = captureDate.toLocaleString();
          baseMeta.dateObj = captureDate;
        }

        if (exifData.ExposureTime) {
          baseMeta.exposureTime = exifData.ExposureTime < 1 ? `1/${Math.round(1 / exifData.ExposureTime)}s` : `${exifData.ExposureTime}s`;
        }
        if (exifData.FNumber) {
          baseMeta.fNumber = `f/${exifData.FNumber}`;
        }
        if (exifData.ISO) {
          baseMeta.iso = `ISO ${exifData.ISO}`;
        }
        if (exifData.FocalLength) {
          baseMeta.focalLength = `${exifData.FocalLength} mm`;
        }
        if (exifData.ExifImageWidth && exifData.ExifImageHeight) {
          baseMeta.dimensions = {
            width: exifData.ExifImageWidth,
            height: exifData.ExifImageHeight,
          };
        }
      }

      // Check explicit GPS
      const gpsData = await exifr.gps(file);
      if (gpsData && typeof gpsData.latitude === 'number' && typeof gpsData.longitude === 'number') {
        parsedGps = {
          latitude: Number(gpsData.latitude.toFixed(6)),
          longitude: Number(gpsData.longitude.toFixed(6)),
          altitude: typeof gpsData.altitude === 'number' ? Math.round(gpsData.altitude) : undefined,
        };
        baseMeta.gps = parsedGps;
      }
    } catch (exifErr: any) {
      console.warn('EXIF parsing notice:', exifErr?.message || exifErr);
    }

    // Natural dimensions fallback
    try {
      const img = new Image();
      img.src = objectUrl;
      await new Promise((res) => {
        img.onload = () => {
          if (!baseMeta.dimensions) {
            baseMeta.dimensions = { width: img.naturalWidth, height: img.naturalHeight };
          }
          res(true);
        };
        img.onerror = () => res(false);
      });
    } catch (_) {}

    setMetadata({ ...baseMeta });

    // 2. Solar & Shadow Analysis
    const effectiveDate = captureDate || new Date();
    const effectiveLat = parsedGps?.latitude || 40.4093; // Baku default latitude
    const effectiveLon = parsedGps?.longitude || 49.8671;
    const shadowInfo = calculateSunAndShadow(effectiveDate, effectiveLat, effectiveLon);
    if (!parsedGps) {
      shadowInfo.reliability = captureDate ? 'Medium (EXIF Time Only)' : 'Estimated';
    }
    setSunShadow(shadowInfo);

    // 3. Canvas Image Enhancement
    let ocrInput: any = file;
    setAnalysisState({
      status: 'enhancing',
      progressMessage: 'Canvas API ilə şəklin kontrastı və kənarları kəskinləşdirilir...',
      ocrProgress: 15,
    });

    try {
      const { dataUrl, blob } = await enhanceImageViaCanvas(objectUrl);
      setEnhancedImageSrc(dataUrl);
      ocrInput = blob;
    } catch (enhanceErr) {
      console.warn('Canvas enhancement skipped, using raw file:', enhanceErr);
    }

    // 4. OCR Text Extraction via tesseract.js
    setAnalysisState({
      status: 'running-ocr',
      progressMessage: 'Tesseract.js neyron modeli şəkildəki mağaza və lövhə yazılarını oxuyur...',
      ocrProgress: 30,
    });

    try {
      const tesseractMod: any = await import('tesseract.js');
      const Tesseract = tesseractMod.default || tesseractMod;

      const recognizeResult = await Tesseract.recognize(ocrInput, 'eng+aze+rus', {
        logger: (m: any) => {
          if (m.status === 'recognizing text' && typeof m.progress === 'number') {
            setAnalysisState((prev) => ({
              ...prev,
              ocrProgress: Math.min(Math.round(m.progress * 100), 98),
              progressMessage: `Mətnlər, mağaza lövhələri və küçə adları oxunur: ${Math.round(m.progress * 100)}%`,
            }));
          }
        },
      });

      const rawText = recognizeResult.data?.text || '';
      const confidence = Math.round(recognizeResult.data?.confidence || 0);
      const landmarks = extractLandmarks(rawText);

      setOcrResult({
        rawText,
        confidence,
        detectedLandmarks: landmarks,
      });

      // 5. OpenStreetMap Geocoding for extracted landmarks
      if (landmarks.length > 0) {
        setAnalysisState({
          status: 'geocoding',
          progressMessage: 'OpenStreetMap (Nominatim) ilə real coğrafi ünvanlar tapılır...',
          ocrProgress: 95,
        });

        // Query first 3 top landmarks
        for (const landmark of landmarks.slice(0, 3)) {
          await queryNominatimGeocode(landmark);
        }
      }

      setAnalysisState({
        status: 'completed',
        progressMessage: 'Analiz tamamlandı. GPS, OCR və Coğrafi Məkanlar hazırdır.',
        ocrProgress: 100,
      });
    } catch (ocrErr: any) {
      console.error('OCR processing error:', ocrErr);
      setAnalysisState({
        status: 'completed',
        progressMessage: 'EXIF tamamlandı, lakin OCR xətası baş verdi.',
        ocrProgress: 100,
      });
    }
  };

  // Re-run OCR manually on enhanced or original image
  const triggerManualOcr = async (useEnhanced: boolean) => {
    const inputSource = useEnhanced && enhancedImageSrc ? enhancedImageSrc : imageSrc;
    if (!inputSource) return;

    setAnalysisState({
      status: 'running-ocr',
      progressMessage: useEnhanced ? 'Təkmilləşdirilmiş şəkil üzərində təkrar OCR işlədilir...' : 'Orijinal şəkil üzərində OCR işlədilir...',
      ocrProgress: 20,
    });

    try {
      const tesseractMod: any = await import('tesseract.js');
      const Tesseract = tesseractMod.default || tesseractMod;

      const result = await Tesseract.recognize(inputSource, 'eng+aze+rus', {
        logger: (m: any) => {
          if (m.status === 'recognizing text' && typeof m.progress === 'number') {
            setAnalysisState((prev) => ({
              ...prev,
              ocrProgress: Math.min(Math.round(m.progress * 100), 98),
            }));
          }
        },
      });

      const rawText = result.data?.text || '';
      const confidence = Math.round(result.data?.confidence || 0);
      const landmarks = extractLandmarks(rawText);

      setOcrResult({
        rawText,
        confidence,
        detectedLandmarks: landmarks,
      });

      if (landmarks.length > 0) {
        for (const l of landmarks.slice(0, 3)) {
          await queryNominatimGeocode(l);
        }
      }

      setAnalysisState({
        status: 'completed',
        progressMessage: 'Təkrar OCR analizi tamamlandı.',
        ocrProgress: 100,
      });
    } catch (err) {
      setAnalysisState({
        status: 'error',
        progressMessage: '',
        ocrProgress: 0,
        error: 'Təkrar OCR zamanı xəta baş verdi.',
      });
    }
  };

  // Drag-and-drop handlers
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processImageFile(e.dataTransfer.files[0]);
    }
  }, []);

  // Preset demo loaders
  const loadDemoGps = () => {
    setImageSrc('https://images.unsplash.com/photo-1578632767115-351597cf2477?w=1200&auto=format&fit=crop');
    const demoDate = new Date('2024-05-18T14:35:00');
    setMetadata({
      fileName: 'DJI_MAVIC3_BAKU_BAYIL.JPG',
      fileSizeBytes: 4892011,
      fileSizeFormatted: '4.67 MB',
      fileType: 'image/jpeg',
      dimensions: { width: 4000, height: 3000 },
      make: 'DJI',
      model: 'Mavic 3 Enterprise',
      dateTime: demoDate.toLocaleString(),
      dateObj: demoDate,
      exposureTime: '1/800s',
      fNumber: 'f/2.8',
      iso: 'ISO 100',
      focalLength: '24.0 mm',
      software: 'v01.00.0600',
      gps: {
        latitude: 40.358211,
        longitude: 49.832944,
        altitude: 48,
      },
    });
    setSunShadow(calculateSunAndShadow(demoDate, 40.358211, 49.832944));
    setOcrResult({
      rawText: 'BAKU CRYSTAL HALL // CASPIAN SEAFRONT PROMENADE // NEFTCHILAR AVE',
      confidence: 94,
      detectedLandmarks: ['Baku', 'Caspian', 'Crystal Hall', 'Neftchilar Ave'],
    });
    setSuggestedLocations([
      {
        place_id: 991,
        display_name: 'Bakı Kristal Zalı, Dövlət Bayrağı Meydanı, Səbail, Bakı, Azərbaycan',
        lat: '40.3475',
        lon: '49.8519',
        type: 'amenity',
        category: 'entertainment',
        importance: 0.85,
      },
      {
        place_id: 992,
        display_name: 'Neftçilər Prospekti, Səbail, Bakı, AZ1000, Azərbaycan',
        lat: '40.3667',
        lon: '49.8389',
        type: 'highway',
        category: 'primary',
        importance: 0.75,
      },
    ]);
    setAnalysisState({
      status: 'completed',
      progressMessage: 'Nümunə GPS telemetriyası və OpenStreetMap məkanları yükləndi.',
      ocrProgress: 100,
    });
  };

  const loadDemoOcr = () => {
    setImageSrc('https://images.unsplash.com/photo-1555396273-367ea4eb4db5?w=1200&auto=format&fit=crop');
    const demoDate = new Date('2024-08-10T11:15:00');
    setMetadata({
      fileName: 'IMG_20240810_STORE_FRONT.JPG',
      fileSizeBytes: 3201400,
      fileSizeFormatted: '3.05 MB',
      fileType: 'image/jpeg',
      dimensions: { width: 3840, height: 2160 },
      make: 'Apple',
      model: 'iPhone 15 Pro',
      dateTime: demoDate.toLocaleString(),
      dateObj: demoDate,
      exposureTime: '1/250s',
      fNumber: 'f/1.78',
      iso: 'ISO 64',
      focalLength: '24.0 mm',
      software: 'iOS 17.5.1',
    });
    setSunShadow(calculateSunAndShadow(demoDate, 40.4093, 49.8671));
    setOcrResult({
      rawText: 'BRAVO SUPERMARKET // 24 SAAT APTEK ZEFERAN // NIZAMI KUCESI 142',
      confidence: 89,
      detectedLandmarks: ['Bravo', 'Bazarstore', 'Aptek', 'Zeferan', 'Nizami Kucesi', 'Baku'],
    });
    setSuggestedLocations([
      {
        place_id: 881,
        display_name: 'Bravo Hipermarket, Heydər Əliyev prospekti, Nərimanov, Bakı, Azərbaycan',
        lat: '40.4128',
        lon: '49.8732',
        type: 'shop',
        category: 'supermarket',
        importance: 0.92,
      },
      {
        place_id: 882,
        display_name: 'Zəfəran Aptek, Nizami küçəsi, Nəsimi, Bakı, AZ1010, Azərbaycan',
        lat: '40.3789',
        lon: '49.8521',
        type: 'amenity',
        category: 'pharmacy',
        importance: 0.81,
      },
    ]);
    setAnalysisState({
      status: 'completed',
      progressMessage: 'GPS koordinatı tapılmadı. OCR vasitəsilə mağaza və Nominatim koordinatları aşkarlanmışdır.',
      ocrProgress: 100,
    });
  };

  const activeImage = viewMode === 'enhanced' && enhancedImageSrc ? enhancedImageSrc : imageSrc;

  return (
    <div className="w-full space-y-6 text-slate-200 font-sans">
      
      {/* ── Top OSINT HUD Header ───────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-[#0b0f19]/90 border border-slate-800/90 shadow-2xl backdrop-blur-md">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs font-mono text-[#00C897] uppercase tracking-widest">
            <span className="w-2.5 h-2.5 rounded-full bg-[#00C897] animate-pulse shadow-[0_0_8px_#00C897]"></span>
            <span>OSINT Geo-Spatial Reconnaissance // v3.0 Ultra</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight flex items-center gap-3">
            <span>Visual Recon & Image Geolocation</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#00C897]/15 text-[#00C897] border border-[#00C897]/40 uppercase">
              100% Client-Side
            </span>
          </h1>
          <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
            EXIF GPS koordinatları, Canvas Kontrast Gücləndirilməsi, Tesseract OCR mağaza/lövhə analizi, OpenStreetMap (Nominatim) geocoding və kölgə bucağı əsaslı məkan təyini.
          </p>
        </div>

        {/* Demo Fast-Loaders */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={loadDemoGps}
            className="px-3 py-1.5 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-mono text-slate-300 hover:text-white transition-all shadow-sm"
          >
            🛰️ Nümunə GPS
          </button>
          <button
            type="button"
            onClick={loadDemoOcr}
            className="px-3 py-1.5 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-mono text-slate-300 hover:text-white transition-all shadow-sm"
          >
            🏪 Nümunə OCR
          </button>
        </div>
      </div>

      {/* ── Drag & Drop Zone ───────────────────────────────────────── */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative group cursor-pointer border-2 border-dashed rounded-2xl p-8 sm:p-12 transition-all duration-300 flex flex-col items-center justify-center text-center overflow-hidden ${
          isDragOver
            ? 'border-[#00C897] bg-[#00C897]/10 scale-[1.005]'
            : 'border-slate-800 hover:border-[#00C897]/60 bg-[#0b0f19]/70 hover:bg-[#0b0f19]'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              processImageFile(e.target.files[0]);
            }
          }}
        />

        <div className="w-16 h-16 rounded-2xl bg-[#00C897]/10 border border-[#00C897]/30 flex items-center justify-center text-[#00C897] mb-4 group-hover:scale-110 group-hover:shadow-[0_0_20px_rgba(0,200,151,0.25)] transition-all">
          <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M15 13a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
        </div>

        <div className="space-y-1 max-w-md">
          <p className="text-sm sm:text-base font-bold text-white group-hover:text-[#00C897] transition-colors">
            Şəkli bura sürükləyin və ya fayl seçin
          </p>
          <p className="text-xs text-slate-400 font-mono">
            JPEG, PNG, WEBP, TIFF, HEIC • EXIF GPS & Neural OCR
          </p>
        </div>

        {/* Live Status Bar */}
        {analysisState.status !== 'idle' && (
          <div className="mt-5 w-full max-w-md bg-slate-900/90 border border-slate-800 rounded-xl p-3 text-left space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-300">{analysisState.progressMessage}</span>
              <span className="text-[#00C897] font-bold">{analysisState.ocrProgress}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-[#00C897] to-cyan-400 transition-all duration-300 rounded-full"
                style={{ width: `${analysisState.ocrProgress}%` }}
              />
            </div>
          </div>
        )}

        {analysisState.error && (
          <div className="mt-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono">
            ⚠️ {analysisState.error}
          </div>
        )}
      </div>

      {/* ── Main Recon Dashboard (After Image Loaded) ──────────────── */}
      {imageSrc && (
        <div className="space-y-6">

          {/* Top Row: Preview & Core GPS/Reverse Search Panel */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

            {/* Left: Interactive Image Preview & Canvas Enhancement Controls (5 Cols) */}
            <div className="lg:col-span-5 rounded-2xl bg-[#0b0f19] border border-slate-800/90 p-5 space-y-4 shadow-xl">
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                  Görüntü Telemetriyası
                </h2>

                {/* View Switcher: Original vs Enhanced */}
                {enhancedImageSrc && (
                  <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-0.5 rounded-lg text-[10px] font-mono">
                    <button
                      type="button"
                      onClick={() => setViewMode('original')}
                      className={`px-2 py-1 rounded transition-colors ${
                        viewMode === 'original' ? 'bg-[#00C897]/20 text-[#00C897] font-bold' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Orijinal
                    </button>
                    <button
                      type="button"
                      onClick={() => setViewMode('enhanced')}
                      className={`px-2 py-1 rounded transition-colors ${
                        viewMode === 'enhanced' ? 'bg-[#00C897]/20 text-[#00C897] font-bold' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      ⚡ Enhanced
                    </button>
                  </div>
                )}
              </div>

              {/* Image Canvas Box */}
              <div className="relative rounded-xl overflow-hidden bg-black/80 border border-slate-800/80 aspect-video sm:aspect-square flex items-center justify-center group">
                <img
                  src={activeImage || imageSrc}
                  alt="Visual Recon Target"
                  className="w-full h-full object-contain transition-transform duration-300 group-hover:scale-[1.02]"
                />
                <div className="absolute top-2 left-2 px-2 py-1 rounded bg-black/70 backdrop-blur-md border border-white/10 text-[10px] font-mono text-slate-300">
                  {viewMode === 'enhanced' ? '🔬 Canvas High-Contrast OCR Filter' : '📷 Native View'}
                </div>
              </div>

              {/* Enhancement Action Bar */}
              <div className="grid grid-cols-2 gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => triggerManualOcr(false)}
                  disabled={analysisState.status === 'running-ocr'}
                  className="px-3 py-2 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-mono text-slate-200 hover:text-white transition-all disabled:opacity-50"
                >
                  🔄 Orijinal OCR
                </button>
                <button
                  type="button"
                  onClick={() => triggerManualOcr(true)}
                  disabled={analysisState.status === 'running-ocr'}
                  className="px-3 py-2 rounded-xl bg-[#00C897]/15 hover:bg-[#00C897]/25 border border-[#00C897]/40 text-xs font-mono text-[#00C897] font-bold transition-all disabled:opacity-50 shadow-sm"
                >
                  ⚡ Enhanced OCR
                </button>
              </div>

              {/* Reverse Visual Search Quick-Launchers */}
              <div className="pt-2 border-t border-slate-800/80 space-y-2">
                <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wide">
                  Reverse Visual Search (Fasad & Obyekt Axtarışı)
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <a
                    href="https://lens.google.com/"
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-center gap-2 px-3 py-2 rounded-xl bg-slate-800/70 hover:bg-slate-700/80 border border-slate-700 text-xs font-semibold text-white transition-all group"
                  >
                    <span>Google Lens</span>
                    <span className="text-slate-400 group-hover:translate-x-0.5 transition-transform">↗</span>
                  </a>
                  <a
                    href="https://yandex.com/images/search?rpt=imageview"
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-center gap-2 px-3 py-2 rounded-xl bg-slate-800/70 hover:bg-slate-700/80 border border-slate-700 text-xs font-semibold text-white transition-all group"
                  >
                    <span>Yandex Visual</span>
                    <span className="text-slate-400 group-hover:translate-x-0.5 transition-transform">↗</span>
                  </a>
                </div>
              </div>

            </div>

            {/* Right: GPS Location, Smart Map Proximity & Chrono Telemetry (7 Cols) */}
            <div className="lg:col-span-7 space-y-5">

              {/* 1. Direct GPS Card (If Available) */}
              {metadata?.gps ? (
                <div className="rounded-2xl bg-gradient-to-br from-[#00C897]/10 via-[#0b0f19] to-slate-900 border border-[#00C897]/40 p-5 space-y-4 shadow-2xl">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-3 h-3 rounded-full bg-[#00C897] animate-ping"></span>
                      <h3 className="text-sm font-mono font-bold text-[#00C897] uppercase tracking-wider">
                        Dəqiq GPS Koordinatları Aşkarlanmışdır
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#00C897]/20 text-[#00C897] border border-[#00C897]/30">
                      EXIF VERIFIED
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
                    <div className="p-3 rounded-xl bg-black/50 border border-slate-800 space-y-1">
                      <div className="text-[10px] text-slate-400 uppercase">Enlik (Latitude)</div>
                      <div className="text-lg font-bold text-white">{metadata.gps.latitude}° N</div>
                    </div>
                    <div className="p-3 rounded-xl bg-black/50 border border-slate-800 space-y-1">
                      <div className="text-[10px] text-slate-400 uppercase">Uzunluq (Longitude)</div>
                      <div className="text-lg font-bold text-white">{metadata.gps.longitude}° E</div>
                    </div>
                  </div>

                  {/* Primary GPS Buttons */}
                  <div className="flex flex-wrap gap-2 pt-1">
                    <a
                      href={`https://www.google.com/maps?q=${metadata.gps.latitude},${metadata.gps.longitude}`}
                      target="_blank"
                      rel="noreferrer"
                      className="flex-1 min-w-[180px] flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-[#00C897] hover:bg-[#00b588] text-slate-950 font-bold text-xs transition-all shadow-[0_0_15px_rgba(0,200,151,0.3)]"
                    >
                      <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z" />
                      </svg>
                      <span>Google Maps-də Dəqiq Yer</span>
                    </a>

                    <a
                      href={`https://www.openstreetmap.org/?mlat=${metadata.gps.latitude}&mlon=${metadata.gps.longitude}#map=16/${metadata.gps.latitude}/${metadata.gps.longitude}`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs transition-all border border-slate-700"
                    >
                      OpenStreetMap
                    </a>

                    <button
                      type="button"
                      onClick={() => copyToClipboard(`${metadata.gps?.latitude}, ${metadata.gps?.longitude}`, 'coords')}
                      className="px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-mono text-xs transition-all border border-slate-700"
                    >
                      {copiedText === 'coords' ? '✓ Kopyalandı' : 'Kopyala'}
                    </button>
                  </div>
                </div>
              ) : (
                /* No GPS Warning Badge */
                <div className="rounded-2xl bg-amber-500/10 border border-amber-500/30 p-4 flex items-start gap-3">
                  <span className="text-amber-400 text-lg mt-0.5">⚠️</span>
                  <div className="space-y-1 text-xs">
                    <div className="font-bold text-amber-300 font-mono">EXIF GPS Qeydi Tapılmadı</div>
                    <div className="text-slate-400">
                      Bu şəkildə birbaşa peyk koordinatları saxlanılmayıb. Aşağıdakı Tesseract OCR və OpenStreetMap (Nominatim) modulu ilə mağaza lövhələrindən məkan təyini həyata keçirilir.
                    </div>
                  </div>
                </div>
              )}

              {/* 2. Chronolocation & Sun / Shadow Direction Analysis */}
              {sunShadow && (
                <div className="rounded-2xl bg-[#0b0f19] border border-slate-800/90 p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-amber-400">☀️</span>
                      <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                        Chronolocation // Günəş və Kölgə İstiqaməti Analizi
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                      {sunShadow.reliability}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs">
                    <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80 space-y-0.5">
                      <div className="text-[10px] text-slate-500">Çəkiliş Vaxtı</div>
                      <div className="font-bold text-slate-200">{metadata?.dateTime ? metadata.dateTime.split(',')[1] || metadata.dateTime : sunShadow.formattedTime}</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80 space-y-0.5">
                      <div className="text-[10px] text-slate-500">Günəş Azimutu</div>
                      <div className="font-bold text-amber-300">{sunShadow.sunAzimuthDeg}° ({sunShadow.cardinalDirection})</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80 space-y-0.5">
                      <div className="text-[10px] text-slate-500">Kölgə Vektoru</div>
                      <div className="font-bold text-[#00C897]">{sunShadow.shadowAzimuthDeg}° ({sunShadow.shadowCardinalDirection})</div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80 space-y-0.5">
                      <div className="text-[10px] text-slate-500">Kölgə / Hündürlük</div>
                      <div className="font-bold text-cyan-300">
                        {sunShadow.isNight ? 'Gecə' : `~${sunShadow.shadowLengthRatio}x`}
                      </div>
                    </div>
                  </div>

                  <p className="text-[11px] text-slate-400 font-mono leading-relaxed pt-1">
                    📐 <strong>OSINT İpucu:</strong> Əgər şəkildə şaquli dirək və ya ağac varsa, onun kölgəsi <span className="text-[#00C897] font-semibold">{sunShadow.shadowCardinalDirection}</span> tərəfinə yönəlməlidir (1 metr hündürlük üçün kölgə təxminən {sunShadow.shadowLengthRatio} m).
                  </p>
                </div>
              )}

              {/* 3. Proximity & Smart Search for Recognized Landmarks */}
              {ocrResult && ocrResult.detectedLandmarks.length > 0 && (
                <div className="rounded-2xl bg-[#0b0f19] border border-slate-800/90 p-5 space-y-3">
                  <div className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                    <span className="text-[#00C897]">📍</span>
                    Smart Proximity Search (Ən Yaxın Obyekti Axtar)
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {ocrResult.detectedLandmarks.map((lm, idx) => (
                      <div
                        key={idx}
                        className="flex items-center gap-1.5 pl-2.5 pr-1.5 py-1 rounded-xl bg-slate-900 border border-slate-700/80 text-xs font-mono"
                      >
                        <span className="text-white font-semibold">{lm}</span>
                        <a
                          href={`https://www.google.com/maps/search/${encodeURIComponent(lm)}`}
                          target="_blank"
                          rel="noreferrer"
                          title="Google Maps-də Ən Yaxın Obyekti Axtar"
                          className="px-1.5 py-0.5 rounded bg-[#00C897]/20 hover:bg-[#00C897]/30 text-[#00C897] text-[10px] font-bold transition-colors"
                        >
                          GMaps ↗
                        </a>
                        <button
                          type="button"
                          onClick={() => queryNominatimGeocode(lm)}
                          title="OpenStreetMap-də Dəqiq Koordinatlarını Çək"
                          className="px-1.5 py-0.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-[10px] font-bold transition-colors"
                        >
                          OSM 🔍
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>

          </div>

          {/* ── Middle: OpenStreetMap (Nominatim) Suggested Locations ── */}
          <div className="rounded-2xl bg-[#0b0f19] border border-slate-800/90 p-6 space-y-4 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#00C897]"></span>
                  Suggested Coordinates / Locations (OpenStreetMap Nominatim OSINT)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Şəkildə oxunan mağaza, küçə və obyekt adlarının OpenStreetMap bazasındakı real coğrafi koordinatları.
                </p>
              </div>

              {/* Custom Search Input */}
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Məkan və ya mağaza adı yazın..."
                  value={customGeocodeQuery}
                  onChange={(e) => setCustomGeocodeQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      queryNominatimGeocode(customGeocodeQuery);
                    }
                  }}
                  className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-[#00C897] w-56"
                />
                <button
                  type="button"
                  onClick={() => queryNominatimGeocode(customGeocodeQuery)}
                  disabled={isGeocodingLoading}
                  className="px-3 py-1.5 rounded-xl bg-[#00C897] hover:bg-[#00b588] text-slate-950 text-xs font-mono font-bold transition-all disabled:opacity-50"
                >
                  {isGeocodingLoading ? '...' : 'Axtar'}
                </button>
              </div>
            </div>

            {suggestedLocations.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                {suggestedLocations.map((loc) => (
                  <div
                    key={loc.place_id}
                    className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 space-y-3 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1">
                        <div className="text-xs font-bold text-white line-clamp-2">
                          {loc.display_name}
                        </div>
                        <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[#00C897]">
                            {loc.type || loc.category || 'landmark'}
                          </span>
                          <span>Lat: {parseFloat(loc.lat).toFixed(5)}, Lon: {parseFloat(loc.lon).toFixed(5)}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 pt-1 font-mono text-xs">
                      <a
                        href={`https://www.google.com/maps?q=${loc.lat},${loc.lon}`}
                        target="_blank"
                        rel="noreferrer"
                        className="flex-1 text-center py-1.5 rounded-lg bg-[#00C897]/15 hover:bg-[#00C897]/25 text-[#00C897] font-bold transition-colors"
                      >
                        Google Maps ↗
                      </a>
                      <a
                        href={`https://www.openstreetmap.org/?mlat=${loc.lat}&mlon=${loc.lon}#map=16/${loc.lat}/${loc.lon}`}
                        target="_blank"
                        rel="noreferrer"
                        className="flex-1 text-center py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                      >
                        OpenStreetMap ↗
                      </a>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(`${loc.lat}, ${loc.lon}`, `osm-${loc.place_id}`)}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
                      >
                        {copiedText === `osm-${loc.place_id}` ? '✓' : 'Kopya'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800/80 text-center text-xs font-mono text-slate-500">
                Hələ ki, heç bir Nominatim məkan təklifi əlavə edilməyib. Yuxarıdakı axtarış xanasına mağaza və ya küçə adı daxil edin.
              </div>
            )}
          </div>

          {/* ── Bottom Row: Detected Text / OCR & Image Metadata Table ── */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

            {/* Left: OCR Raw Text & Detected Landmarks (6 Cols) */}
            <div className="lg:col-span-6 rounded-2xl bg-[#0b0f19] border border-slate-800/90 p-5 space-y-4 shadow-xl">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <span className="text-cyan-400">📝</span>
                  Detected Text / Landmarks (OCR Çıxarışı)
                </h3>
                {ocrResult && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                    Dəqiqlik: {ocrResult.confidence}%
                  </span>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800/80 font-mono text-xs text-slate-300 min-h-[120px] max-h-[220px] overflow-y-auto whitespace-pre-wrap leading-relaxed select-all">
                {ocrResult?.rawText ? ocrResult.rawText.trim() : 'Şəkildə oxunan mətn yoxdur və ya OCR hələ işlənməyib.'}
              </div>

              {ocrResult?.rawText && (
                <div className="flex items-center justify-between text-xs font-mono pt-1">
                  <button
                    type="button"
                    onClick={() => copyToClipboard(ocrResult.rawText, 'raw-text')}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                  >
                    {copiedText === 'raw-text' ? '✓ Mətn Kopyalandı' : 'Mətni Kopyala'}
                  </button>
                  <a
                    href={`https://www.google.com/search?q=${encodeURIComponent(ocrResult.rawText.slice(0, 100))}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[#00C897] hover:underline flex items-center gap-1"
                  >
                    <span>Google-da bu mətni axtar</span>
                    <span>↗</span>
                  </a>
                </div>
              )}
            </div>

            {/* Right: Technical Image Metadata Table (6 Cols) */}
            <div className="lg:col-span-6 rounded-2xl bg-[#0b0f19] border border-slate-800/90 p-5 space-y-4 shadow-xl">
              <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span className="text-[#00C897]">📊</span>
                Şəkil Metadata Cədvəli (Kamera & Çəkiliş Detalları)
              </h3>

              <div className="overflow-hidden rounded-xl border border-slate-800 font-mono text-xs">
                <table className="w-full text-left border-collapse">
                  <tbody>
                    <tr className="border-b border-slate-800/80 bg-slate-900/50">
                      <td className="py-2.5 px-3.5 text-slate-400 font-medium w-1/3">Fayl Adı / Format</td>
                      <td className="py-2.5 px-3.5 text-white truncate max-w-[200px]">{metadata?.fileName} ({metadata?.fileType})</td>
                    </tr>
                    <tr className="border-b border-slate-800/80">
                      <td className="py-2.5 px-3.5 text-slate-400 font-medium">Həcm və Piksellər</td>
                      <td className="py-2.5 px-3.5 text-slate-200">
                        {metadata?.fileSizeFormatted} • {metadata?.dimensions ? `${metadata.dimensions.width} × ${metadata.dimensions.height} px` : 'Məlum deyil'}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-800/80 bg-slate-900/50">
                      <td className="py-2.5 px-3.5 text-slate-400 font-medium">Kamera İstehsalçısı</td>
                      <td className="py-2.5 px-3.5 text-[#00C897] font-bold">{metadata?.make || 'Tapılmadı'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80">
                      <td className="py-2.5 px-3.5 text-slate-400 font-medium">Kamera Modeli</td>
                      <td className="py-2.5 px-3.5 text-white font-bold">{metadata?.model || 'Tapılmadı'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80 bg-slate-900/50">
                      <td className="py-2.5 px-3.5 text-slate-400 font-medium">Çəkiliş Tarixi & Saatı</td>
                      <td className="py-2.5 px-3.5 text-amber-300">{metadata?.dateTime || 'Məlumat yoxdur'}</td>
                    </tr>
                    <tr className="border-b border-slate-800/80">
                      <td className="py-2.5 px-3.5 text-slate-400 font-medium">Ekspozisiya / Diafraqma</td>
                      <td className="py-2.5 px-3.5 text-slate-300">
                        {metadata?.exposureTime || '—'} • {metadata?.fNumber || '—'} • {metadata?.iso || '—'}
                      </td>
                    </tr>
                    <tr className="border-b border-slate-800/80 bg-slate-900/50">
                      <td className="py-2.5 px-3.5 text-slate-400 font-medium">Fokus Məsafəsi</td>
                      <td className="py-2.5 px-3.5 text-slate-300">{metadata?.focalLength || '—'}</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3.5 text-slate-400 font-medium">Proqram Təminatı</td>
                      <td className="py-2.5 px-3.5 text-slate-300 truncate max-w-[200px]">{metadata?.software || 'Standart Firmware'}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}
